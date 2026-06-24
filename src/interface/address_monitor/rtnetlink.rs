//! Linux: an rtnetlink (`NETLINK_ROUTE`) socket subscribed to the address and link change
//! multicast groups. The message layer (header walk, `ifaddrmsg`/`ifinfomsg` bodies) is the
//! resolver's — reused from [`super::super::rtnetlink`] rather than duplicated.

use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::ptr;

use libc::{c_int, socklen_t};

use super::super::rtnetlink::{IfAddrMsg, IfInfoMsg, NlMsgHdr, nl_align};

const NETLINK_ROUTE: c_int = 0;

/// Holds one notification — multicast delivers one message per datagram, never a coalesced
/// dump. Sized for the largest: an `RTM_NEWLINK` carries the interface's whole attribute set
/// (stats, `IFLA_AF_SPEC`, VF info) at ~1 KB; addresses are far smaller. 8 KiB is roomy.
pub(super) const READ_BUF: usize = 8192;

/// Subscribe v4/v6 address adds+removes and link (MAC/state) changes. A MAC change arrives
/// as `RTM_NEWLINK`, not an address event, so `RTMGRP_LINK` is needed to catch it.
const SUBSCRIBED_GROUPS: u32 =
    (libc::RTMGRP_IPV4_IFADDR | libc::RTMGRP_IPV6_IFADDR | libc::RTMGRP_LINK) as u32;

/// `struct sockaddr_nl` — hand-rolled (`libc` exposes it for Android only).
#[repr(C)]
#[derive(Default)]
struct SockAddrNl {
    family: u16,
    pad: u16,
    pid: u32,
    groups: u32,
}

/// Open a `NETLINK_ROUTE` socket bound to the change groups, non-blocking + close-on-exec.
pub(super) fn open() -> io::Result<OwnedFd> {
    // SAFETY: `socket` returns a fresh fd or -1; the type arg carries CLOEXEC|NONBLOCK
    // (Linux applies both atomically, with no fcntl race).
    let raw = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
            NETLINK_ROUTE,
        )
    };
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `raw` is a fresh owned socket fd.
    let sock = unsafe { OwnedFd::from_raw_fd(raw) };
    let addr = SockAddrNl {
        family: u16::try_from(libc::AF_NETLINK).expect("AF_NETLINK fits a u16"),
        groups: SUBSCRIBED_GROUPS,
        ..SockAddrNl::default()
    };
    // SAFETY: a fully-initialized `sockaddr_nl` of its own size; `bind` reads it and
    // subscribes the multicast groups.
    let rc = unsafe {
        libc::bind(
            sock.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            socklen_t::try_from(size_of::<SockAddrNl>()).expect("sockaddr_nl fits socklen_t"),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(sock)
}

/// Walk every netlink message in one datagram; report the interface index of each
/// `RTM_{NEW,DEL}ADDR` (from its `ifaddrmsg`) and `RTM_{NEW,DEL}LINK` (from its `ifinfomsg`).
pub(super) fn for_each_change(buf: &[u8], on_change: &mut impl FnMut(u32)) {
    let mut offset = 0;
    while offset + size_of::<NlMsgHdr>() <= buf.len() {
        // SAFETY: a full header lies within `buf` (bound checked).
        let hdr = unsafe { ptr::read_unaligned(buf.as_ptr().add(offset).cast::<NlMsgHdr>()) };
        let len = hdr.len as usize;
        if len < size_of::<NlMsgHdr>() || offset + len > buf.len() {
            // Not a normal end (that's the `while` running out): a message claims a length
            // that's impossible — truncated datagram or corruption — so a change is dropped.
            log::warn!(
                "netlink message walk stopped at offset {offset}: len {len}, buffer {} B \
                 (truncated or malformed); a change may be missed",
                buf.len()
            );
            break;
        }
        let body_at = offset + nl_align(size_of::<NlMsgHdr>());
        let end = offset + len;
        match hdr.msg_type {
            libc::RTM_NEWADDR | libc::RTM_DELADDR if body_at + size_of::<IfAddrMsg>() <= end => {
                // SAFETY: the `ifaddrmsg` body lies within this message (bound checked).
                let body =
                    unsafe { ptr::read_unaligned(buf.as_ptr().add(body_at).cast::<IfAddrMsg>()) };
                report(body.index, on_change);
            }
            libc::RTM_NEWLINK | libc::RTM_DELLINK if body_at + size_of::<IfInfoMsg>() <= end => {
                // SAFETY: the `ifinfomsg` body lies within this message (bound checked).
                let body =
                    unsafe { ptr::read_unaligned(buf.as_ptr().add(body_at).cast::<IfInfoMsg>()) };
                // `ifi_index` is i32 but always a positive kernel index.
                if let Ok(index) = u32::try_from(body.index) {
                    report(index, on_change);
                }
            }
            _ => {}
        }
        offset += nl_align(len);
    }
}

/// Forward a change for `index`, unless `index` is 0 — which names no interface (kernel
/// indices are >= 1) and is the parent's "re-resolve everything" overflow signal, so a stray
/// 0 must never be forwarded.
fn report(index: u32, on_change: &mut impl FnMut(u32)) {
    if index != 0 {
        log::trace!("address monitor: change for ifindex {index}");
        on_change(index);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A netlink message: a `nlmsghdr` (len, type) followed by `body`, length-padded.
    fn message(msg_type: u16, body: &[u8]) -> Vec<u8> {
        let len = size_of::<NlMsgHdr>() + body.len();
        let mut m = vec![0u8; nl_align(len)];
        m[0..4].copy_from_slice(
            &u32::try_from(len)
                .expect("test message fits u32")
                .to_ne_bytes(),
        );
        m[4..6].copy_from_slice(&msg_type.to_ne_bytes());
        m[size_of::<NlMsgHdr>()..size_of::<NlMsgHdr>() + body.len()].copy_from_slice(body);
        m
    }

    /// An `ifaddrmsg` body carrying `ifa_index` (a `u32` at body offset 4).
    fn ifaddrmsg(index: u32) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<IfAddrMsg>()];
        b[4..8].copy_from_slice(&index.to_ne_bytes());
        b
    }

    /// An `ifinfomsg` body carrying `ifi_index` (an `i32` at body offset 4).
    fn ifinfomsg(index: i32) -> Vec<u8> {
        let mut b = vec![0u8; size_of::<IfInfoMsg>()];
        b[4..8].copy_from_slice(&index.to_ne_bytes());
        b
    }

    #[test]
    fn reports_index_of_addr_and_link_messages() {
        let mut buf = message(libc::RTM_NEWADDR, &ifaddrmsg(7));
        buf.extend(message(libc::RTM_DELLINK, &ifinfomsg(9)));
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert_eq!(seen, [7, 9]);
    }

    #[test]
    fn ignores_other_message_types() {
        // NLMSG_DONE (3) and any non-addr/link type carry no interface index for us.
        let buf = message(3, &ifaddrmsg(5));
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert!(seen.is_empty());
    }

    #[test]
    fn skips_a_body_too_short_for_its_struct() {
        // A truncated ifaddrmsg (claimed type, body shorter than ifaddrmsg) yields nothing.
        let buf = message(libc::RTM_NEWADDR, &[0u8; 2]);
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert!(seen.is_empty());
    }

    #[test]
    fn never_forwards_index_zero() {
        // 0 names no interface and is the parent's overflow sentinel, so a message carrying it
        // must not be reported (which would trigger a spurious re-resolve of everything).
        let buf = message(libc::RTM_NEWADDR, &ifaddrmsg(0));
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert!(seen.is_empty());
    }
}
