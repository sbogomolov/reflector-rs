//! Linux address resolution over rtnetlink (`NETLINK_ROUTE`): one `RTM_GETADDR` dump for the
//! v4/v6 addresses (each carrying its `IFA_FLAGS`, so tentative / deprecated / dadfailed are
//! filtered inline) and one `RTM_GETLINK` dump for the MAC. The netlink message framing is
//! hand-rolled — `libc` exposes it for Android only, not glibc/musl.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, OwnedFd};
use std::ptr;

use libc::c_int;

use super::{InterfaceAddresses, V6Pick, v6_rank};
use crate::net::mac::MacAddr;

const NETLINK_ROUTE: c_int = 0;
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_DUMP: u16 = 0x0300; // NLM_F_ROOT | NLM_F_MATCH
const NLMSG_DONE: u16 = 0x03;
const NLMSG_ERROR: u16 = 0x02;
/// `IFA_F_*` bits that disqualify a v6 address as a source.
const IFA_F_UNUSABLE: u32 = 0x40 | 0x20 | 0x08; // TENTATIVE | DEPRECATED | DADFAILED

/// `struct nlmsghdr`. Shared with the address monitor (`len`/`msg_type` drive its walk).
#[repr(C)]
pub(super) struct NlMsgHdr {
    pub(super) len: u32,
    pub(super) msg_type: u16,
    flags: u16,
    seq: u32,
    pid: u32,
}

/// `struct ifaddrmsg` — the body of an `RTM_*ADDR` message. A zeroed value (family
/// `AF_UNSPEC`) is the dump request body. The address monitor reads `index` from it.
#[repr(C)]
#[derive(Default)]
pub(super) struct IfAddrMsg {
    family: u8,
    prefixlen: u8,
    flags: u8,
    scope: u8,
    pub(super) index: u32,
}

/// `struct ifinfomsg` — the body of an `RTM_*LINK` message. A zeroed value is the dump
/// request body. The address monitor reads `index` from it.
#[repr(C)]
#[derive(Default)]
pub(super) struct IfInfoMsg {
    family: u8,
    pad: u8,
    dev_type: u16,
    pub(super) index: i32,
    flags: u32,
    change: u32,
}

/// `struct rtattr` — a type-length-value attribute header within a message.
#[repr(C)]
struct RtAttr {
    len: u16,
    attr_type: u16,
}

/// Iterator over the `rtattr` TLVs of a message: yields `(attr_type, value)` per attribute,
/// stopping at the first malformed length (as the kernel's own walk does).
struct RtAttrs<'a> {
    msg: &'a [u8],
    at: usize,
}

/// The `rtattr` TLVs of `msg` starting at byte offset `from`.
fn rtattrs(msg: &[u8], from: usize) -> RtAttrs<'_> {
    RtAttrs { msg, at: from }
}

impl<'a> Iterator for RtAttrs<'a> {
    type Item = (u16, &'a [u8]);

    fn next(&mut self) -> Option<Self::Item> {
        let rta = read_at::<RtAttr>(self.msg, self.at)?;
        let rta_len = rta.len as usize;
        if rta_len < size_of::<RtAttr>() || self.at + rta_len > self.msg.len() {
            return None;
        }
        let data = &self.msg[self.at + size_of::<RtAttr>()..self.at + rta_len];
        self.at += nl_align(rta_len);
        Some((rta.attr_type, data))
    }
}

/// `(n + 3) & !3` — netlink's 4-byte alignment for message and attribute lengths.
pub(super) const fn nl_align(n: usize) -> usize {
    (n + 3) & !3
}

/// Read a `repr(C)` POD `T` at `off` in `buf`, or `None` if `buf` is too short (or `off`
/// overflows). Tolerates any alignment. `T` must be a plain wire struct — no padding-sensitive
/// invariants, no `Drop`; the netlink headers/bodies all qualify.
pub(super) fn read_at<T>(buf: &[u8], off: usize) -> Option<T> {
    if off.checked_add(size_of::<T>())? > buf.len() {
        return None;
    }
    // SAFETY: the bound check guarantees a full `T` lies within `buf`; `read_unaligned` imposes
    // no alignment requirement, and `T` is a plain wire struct.
    Some(unsafe { ptr::read_unaligned(buf.as_ptr().add(off).cast::<T>()) })
}

/// Resolve interface `ifindex`'s current source addresses with two netlink dumps:
/// `RTM_GETADDR` for v4/v6 (flag-filtered, link-local > ULA > global) and `RTM_GETLINK` for
/// the MAC. `if_name` is for tracing only; the dumps are filtered by `ifindex`. A `0`
/// `ifindex` (the caller's "unknown interface" sentinel) skips the dumps.
///
/// # Errors
/// Returns an error if a netlink socket, request, or reply fails.
pub(super) fn resolve(if_name: &str, ifindex: u32) -> io::Result<InterfaceAddresses> {
    if ifindex == 0 {
        return Ok(InterfaceAddresses::default()); // unknown interface — nothing to dump
    }

    let sock = netlink_socket()?;
    let mut addrs = InterfaceAddresses::default();

    let mut v6_pick = V6Pick::default();
    dump(
        &sock,
        libc::RTM_GETADDR,
        libc::RTM_NEWADDR,
        IfAddrMsg::default(),
        |msg| {
            scan_addr(msg, if_name, ifindex, &mut addrs, &mut v6_pick);
        },
    )?;
    dump(
        &sock,
        libc::RTM_GETLINK,
        libc::RTM_NEWLINK,
        IfInfoMsg::default(),
        |msg| {
            scan_link(msg, if_name, ifindex, &mut addrs);
        },
    )?;

    Ok(addrs)
}

fn netlink_socket() -> io::Result<OwnedFd> {
    // SAFETY: `socket` returns a fresh fd or -1.
    crate::sys::owned_fd_from(unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC,
            NETLINK_ROUTE,
        )
    })
}

/// Send a dump request (`request_type` + `body`) and feed every reply of `reply_type` to
/// `on_msg`, until `NLMSG_DONE`.
fn dump<B>(
    sock: &OwnedFd,
    request_type: u16,
    reply_type: u16,
    body: B,
    mut on_msg: impl FnMut(&[u8]),
) -> io::Result<()> {
    #[repr(C)]
    struct Request<B> {
        hdr: NlMsgHdr,
        body: B,
    }
    let req = Request {
        hdr: NlMsgHdr {
            len: u32::try_from(size_of::<Request<B>>()).expect("request fits a u32"),
            msg_type: request_type,
            flags: NLM_F_REQUEST | NLM_F_DUMP,
            seq: 1,
            pid: 0,
        },
        body,
    };
    // SAFETY: `req` is fully initialized; send its bytes to the netlink socket.
    let sent = unsafe {
        libc::send(
            sock.as_raw_fd(),
            (&raw const req).cast(),
            size_of::<Request<B>>(),
            0,
        )
    };
    if sent < 0 {
        return Err(io::Error::last_os_error());
    }

    // Grows to whatever the largest datagram needs (see the peek below); reused across
    // datagrams, so it reallocates at most a few times over a dump.
    let mut buf: Vec<u8> = Vec::new();
    loop {
        // Size the next datagram before reading it: MSG_PEEK leaves it queued while MSG_TRUNC
        // reports its true length, so we read into a zero-length buffer purely to learn the
        // size — an oversized message then grows `buf` rather than being silently truncated.
        // SAFETY: a zero-length read dereferences nothing, so the null pointer is never read.
        let size = unsafe {
            libc::recv(
                sock.as_raw_fd(),
                ptr::null_mut(),
                0,
                libc::MSG_PEEK | libc::MSG_TRUNC,
            )
        };
        if size < 0 {
            return Err(io::Error::last_os_error());
        }
        // Infallible: the negative (error) case returned above, and a non-negative `isize`
        // always fits `usize`.
        let size = usize::try_from(size).expect("recv count is non-negative");
        buf.resize(size, 0);

        // SAFETY: `recv` fills up to `buf.len()` bytes of the owned buffer, which now holds
        // the whole datagram.
        let received =
            unsafe { libc::recv(sock.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
        if received < 0 {
            return Err(io::Error::last_os_error());
        }
        let received = usize::try_from(received).expect("recv count is non-negative");

        let mut offset = 0;
        while let Some(hdr) = read_at::<NlMsgHdr>(&buf[..received], offset) {
            let len = hdr.len as usize;
            if len < size_of::<NlMsgHdr>() || offset + len > received {
                break;
            }
            match hdr.msg_type {
                NLMSG_DONE => return Ok(()),
                NLMSG_ERROR => return Err(io::Error::other("netlink dump failed")),
                t if t == reply_type => on_msg(&buf[offset..offset + len]),
                _ => {}
            }
            offset += nl_align(len);
        }
    }
}

/// Parse one `RTM_NEWADDR` message; if it carries a usable address of `ifindex`, record it
/// (v4: first wins; v6: highest-ranked usable wins). `msg` spans one netlink message.
fn scan_addr(
    msg: &[u8],
    if_name: &str,
    ifindex: u32,
    addrs: &mut InterfaceAddresses,
    v6_pick: &mut V6Pick,
) {
    let body_at = nl_align(size_of::<NlMsgHdr>());
    let Some(body) = read_at::<IfAddrMsg>(msg, body_at) else {
        return;
    };
    let family = c_int::from(body.family);
    if body.index != ifindex || (family != libc::AF_INET && family != libc::AF_INET6) {
        return;
    }

    // Prefer `IFA_LOCAL` (the local address) over `IFA_ADDRESS` (the peer on point-to-point
    // links); they coincide on broadcast links. `IFA_FLAGS`, when present, is the full
    // 32-bit set and supersedes the 8-bit `ifa_flags`.
    let mut local: Option<&[u8]> = None;
    let mut address: Option<&[u8]> = None;
    let mut flags = u32::from(body.flags);
    for (attr_type, data) in rtattrs(msg, body_at + nl_align(size_of::<IfAddrMsg>())) {
        match attr_type {
            libc::IFA_ADDRESS => address = Some(data),
            libc::IFA_LOCAL => local = Some(data),
            libc::IFA_FLAGS => {
                // `IFA_FLAGS` is a `u32`; ignore a malformed attribute of any other length.
                if let Ok(bytes) = <[u8; 4]>::try_from(data) {
                    flags = u32::from_ne_bytes(bytes);
                }
            }
            _ => {}
        }
    }

    let Some(bytes) = local.or(address) else {
        return;
    };
    if family == libc::AF_INET {
        // First usable address wins: skip a tentative/deprecated/secondary v4 (the same
        // IFA_F_UNUSABLE mask the v6 branch applies) so it is never chosen as the reflection source.
        if addrs.v4.is_none()
            && flags & IFA_F_UNUSABLE == 0
            && let Ok(octets) = <[u8; 4]>::try_from(bytes)
        {
            let v4 = Ipv4Addr::from(octets);
            log::trace!("{if_name}: v4 {v4}");
            addrs.v4 = Some(v4);
        }
    } else if let Ok(octets) = <[u8; 16]>::try_from(bytes) {
        let addr = Ipv6Addr::from(octets);
        let rank = v6_rank(addr);
        let usable = flags & IFA_F_UNUSABLE == 0;
        log::trace!(
            "{if_name}: v6 {addr} flags {flags:#06x} rank {rank:?} -> {}",
            if usable { "usable" } else { "filtered" }
        );
        if usable {
            v6_pick.consider(addrs, addr);
        }
    }
}

/// Parse one `RTM_NEWLINK` message; if it is `ifindex` and carries a 6-byte `IFLA_ADDRESS`,
/// record it as the MAC. `msg` spans one netlink message.
fn scan_link(msg: &[u8], if_name: &str, ifindex: u32, addrs: &mut InterfaceAddresses) {
    let body_at = nl_align(size_of::<NlMsgHdr>());
    let Some(body) = read_at::<IfInfoMsg>(msg, body_at) else {
        return;
    };
    if u32::try_from(body.index).ok() != Some(ifindex) {
        return;
    }

    for (attr_type, data) in rtattrs(msg, body_at + nl_align(size_of::<IfInfoMsg>())) {
        if attr_type == libc::IFLA_ADDRESS
            && let Ok(mac) = <[u8; 6]>::try_from(data)
        {
            let mac = MacAddr::from(mac);
            log::trace!("{if_name}: mac {mac}");
            addrs.mac = Some(mac);
            // A link has a single L2 address; the rest of the message is irrelevant.
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serialize `[len:u16][type:u16][value]` rtattr TLVs, each padded to 4 bytes, onto `buf`.
    fn push_attrs(buf: &mut Vec<u8>, attrs: &[(u16, &[u8])]) {
        for &(attr_type, value) in attrs {
            let len = u16::try_from(size_of::<RtAttr>() + value.len()).unwrap();
            buf.extend_from_slice(&len.to_ne_bytes());
            buf.extend_from_slice(&attr_type.to_ne_bytes());
            buf.extend_from_slice(value);
            while !buf.len().is_multiple_of(4) {
                buf.push(0);
            }
        }
    }

    /// An `RTM_NEWADDR` message: a zeroed nlmsghdr, an ifaddrmsg (family/flags/index), then `attrs`.
    fn addr_msg(family: c_int, index: u32, flags: u8, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; nl_align(size_of::<NlMsgHdr>())];
        m.push(u8::try_from(family).unwrap()); // family
        m.extend_from_slice(&[0, flags, 0]); // prefixlen, flags, scope
        m.extend_from_slice(&index.to_ne_bytes()); // index
        push_attrs(&mut m, attrs);
        m
    }

    /// An `RTM_NEWLINK` message: a zeroed nlmsghdr, an ifinfomsg (index), then `attrs`.
    fn link_msg(index: i32, attrs: &[(u16, &[u8])]) -> Vec<u8> {
        let mut m = vec![0u8; nl_align(size_of::<NlMsgHdr>())];
        m.extend_from_slice(&[0, 0]); // family, pad
        m.extend_from_slice(&0u16.to_ne_bytes()); // dev_type
        m.extend_from_slice(&index.to_ne_bytes()); // index (i32)
        m.extend_from_slice(&[0u8; 8]); // flags, change
        push_attrs(&mut m, attrs);
        m
    }

    #[test]
    fn nl_align_rounds_up_to_four() {
        assert_eq!(nl_align(0), 0);
        assert_eq!(nl_align(1), 4);
        assert_eq!(nl_align(4), 4);
        assert_eq!(nl_align(5), 8);
    }

    #[test]
    fn read_at_bounds_checks_the_read() {
        let buf = [1u8, 2, 3, 4, 5];
        assert_eq!(
            read_at::<u32>(&buf, 1),
            Some(u32::from_ne_bytes([2, 3, 4, 5]))
        );
        assert_eq!(read_at::<u32>(&buf, 2), None); // 2 + 4 > 5
        assert_eq!(read_at::<u16>(&buf, usize::MAX), None); // offset overflow
    }

    #[test]
    fn rtattrs_walks_tlvs_and_stops_at_a_bad_length() {
        let mut buf = Vec::new();
        push_attrs(&mut buf, &[(1, &[0xaa, 0xbb]), (2, &[0xcc])]);
        let got: Vec<(u16, Vec<u8>)> = rtattrs(&buf, 0).map(|(t, v)| (t, v.to_vec())).collect();
        assert_eq!(got, vec![(1, vec![0xaa, 0xbb]), (2, vec![0xcc])]);

        // A final header whose length runs past the buffer ends the walk after the good attrs.
        let mut bad = buf.clone();
        bad.extend_from_slice(&[0xff, 0xff, 0x00, 0x00]); // len = 0xffff
        assert_eq!(rtattrs(&bad, 0).count(), 2);
    }

    #[test]
    fn scan_addr_records_a_usable_v4() {
        let msg = addr_msg(libc::AF_INET, 5, 0, &[(libc::IFA_ADDRESS, &[10, 0, 0, 1])]);
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(addrs.v4, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn scan_addr_prefers_ifa_local_over_ifa_address() {
        // On point-to-point links IFA_ADDRESS is the peer; IFA_LOCAL is ours.
        let msg = addr_msg(
            libc::AF_INET,
            5,
            0,
            &[
                (libc::IFA_ADDRESS, &[10, 0, 0, 2]),
                (libc::IFA_LOCAL, &[10, 0, 0, 1]),
            ],
        );
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(addrs.v4, Some(Ipv4Addr::new(10, 0, 0, 1)));
    }

    #[test]
    fn scan_addr_skips_an_unusable_v4() {
        // IFA_FLAGS carrying TENTATIVE (0x40) supersedes the 8-bit flags and disqualifies it.
        let msg = addr_msg(
            libc::AF_INET,
            5,
            0,
            &[
                (libc::IFA_ADDRESS, &[10, 0, 0, 1]),
                (libc::IFA_FLAGS, &0x40u32.to_ne_bytes()),
            ],
        );
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(addrs.v4, None);
    }

    #[test]
    fn scan_addr_ignores_a_different_ifindex() {
        let msg = addr_msg(libc::AF_INET, 99, 0, &[(libc::IFA_ADDRESS, &[10, 0, 0, 1])]);
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(addrs.v4, None);
    }

    #[test]
    fn scan_addr_records_a_usable_v6() {
        let v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let msg = addr_msg(libc::AF_INET6, 5, 0, &[(libc::IFA_ADDRESS, &v6.octets())]);
        let mut addrs = InterfaceAddresses::default();
        scan_addr(&msg, "eth0", 5, &mut addrs, &mut V6Pick::default());
        assert_eq!(addrs.v6, Some(v6));
    }

    #[test]
    fn scan_link_records_the_mac_only_for_the_right_index() {
        let mac = [0x02, 0, 0, 0, 0, 0x2a];
        let msg = link_msg(5, &[(libc::IFLA_ADDRESS, &mac)]);
        let mut addrs = InterfaceAddresses::default();
        scan_link(&msg, "eth0", 5, &mut addrs);
        assert_eq!(addrs.mac, Some(MacAddr::from(mac)));

        let mut other = InterfaceAddresses::default();
        scan_link(&msg, "eth0", 6, &mut other);
        assert_eq!(other.mac, None);
    }
}
