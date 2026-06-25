//! Multicast group membership for the capture interfaces. mDNS (and later SSDP) frames only reach
//! the raw capture if the kernel admits the group on the interface, which a group membership
//! programs (it also drives the IGMP/MLD join upstream). One held-not-polled `SOCK_DGRAM` socket
//! per family, **per interface**: sharding the memberships by interface holds each socket's count
//! to the number of reflected protocols (mDNS + SSDP = 2), so Linux's per-socket
//! `net.ipv4.igmp_max_memberships` cap (default 20) is unreachable at any interface count — and
//! that cap can't be raised on a locked-down router. The socket is **never bound**: unbound, it
//! holds the membership but the kernel delivers it no datagrams (UDP demux is by bound port), so
//! its receive buffer never fills (binding it would queue every group datagram, unread). Dropping
//! the socket drops its memberships.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd};

use libc::{c_int, c_void};

use crate::sys::{owned_fd_from, socklen_of};

/// `MCAST_JOIN_GROUP` (RFC 3678): protocol-independent, selects the interface strictly by index —
/// no IPv4 by-address fallback to a wrong NIC. libc defines it only on Linux; the BSDs share the
/// value 80 (verified against the Darwin SDK and the FreeBSD headers).
#[cfg(target_os = "linux")]
const MCAST_JOIN_GROUP: c_int = libc::MCAST_JOIN_GROUP;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const MCAST_JOIN_GROUP: c_int = 80;

/// `struct group_req` (RFC 3678) — absent from libc on every target, so hand-rolled. The kernel
/// reads `gr_interface` (the index) and `gr_group` (the group as a `sockaddr`). `#[repr(C)]` plus
/// `sockaddr_storage`'s alignment reproduce the C layout (4 bytes of padding after `gr_interface`).
#[repr(C)]
struct GroupReq {
    gr_interface: u32,
    gr_group: libc::sockaddr_storage,
}

/// One capture interface's multicast memberships: one unbound `SOCK_DGRAM` fd per family, opened on
/// that family's first join. The interface index is fixed at construction, so every membership on
/// these two sockets belongs to this one interface. Held for membership only.
pub(crate) struct MulticastJoiner {
    ifindex: u32,
    v4: Option<OwnedFd>,
    v6: Option<OwnedFd>,
}

impl MulticastJoiner {
    pub(crate) fn new(ifindex: u32) -> Self {
        Self {
            ifindex,
            v4: None,
            v6: None,
        }
    }

    /// Join `group` on this interface, idempotently: the kernel keys memberships by `(group,
    /// ifindex)`, so re-joining one already held is a no-op — the dynamic re-attempt after an
    /// address comes up or an interface bounces relies on this.
    ///
    /// # Errors
    /// Returns the OS error if the join socket can't be opened or the membership can't be added.
    /// `EADDRNOTAVAIL` means the interface is transiently down, so the caller should retry on the
    /// next up-event rather than treat it as fatal. (`ENOBUFS` — the per-socket membership cap —
    /// can't arise: this socket holds only this interface's few groups; see the module note.)
    pub(crate) fn join(&mut self, group: IpAddr) -> io::Result<()> {
        let (slot, family, level) = match group {
            IpAddr::V4(_) => (&mut self.v4, libc::AF_INET, libc::IPPROTO_IP),
            IpAddr::V6(_) => (&mut self.v6, libc::AF_INET6, libc::IPPROTO_IPV6),
        };
        let fd = match slot {
            Some(sock) => sock.as_raw_fd(),
            None => slot.insert(open_join_socket(family)?).as_raw_fd(),
        };
        let req = GroupReq {
            gr_interface: self.ifindex,
            gr_group: group_sockaddr(group),
        };
        // SAFETY: `req` is a fully-initialized `group_req`; we pass its address and own size as the
        // option value and length for the protocol-independent join at the family's IP level.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                level,
                MCAST_JOIN_GROUP,
                (&raw const req).cast::<c_void>(),
                socklen_of::<GroupReq>(),
            )
        };
        if rc != 0 {
            let err = io::Error::last_os_error();
            // Already a member is success — the idempotent re-attempt depends on it.
            if !already_member(&err) {
                return Err(err);
            }
        }
        Ok(())
    }
}

/// Whether `err` from a join means the membership is already held — a benign duplicate. The errno
/// isn't uniform: Linux and the BSDs' IPv4 path return `EADDRINUSE`, FreeBSD's IPv6 path `EINVAL`.
/// (`raw_os_error` is a single errno, so the or-pattern matches it against each in turn.)
fn already_member(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(libc::EADDRINUSE | libc::EINVAL))
}

/// Open an unbound `SOCK_DGRAM` socket of `family` to hold memberships, close-on-exec.
fn open_join_socket(family: c_int) -> io::Result<OwnedFd> {
    // Close-on-exec and non-blocking, like the capture sockets. We never read this one, so
    // non-blocking isn't required — but on a single-threaded reactor it keeps a stray read from
    // ever freezing the loop. Linux and FreeBSD set both flags in the socket type; macOS lacks them
    // and applies them by `fcntl`.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let sock_type = libc::SOCK_DGRAM | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(target_os = "macos")]
    let sock_type = libc::SOCK_DGRAM;
    // SAFETY: `socket` returns a fresh owned fd or -1; `owned_fd_from` takes ownership or errors.
    let fd = owned_fd_from(unsafe { libc::socket(family, sock_type, 0) })?;
    #[cfg(target_os = "macos")]
    crate::sys::set_cloexec_nonblock(fd.as_raw_fd())?;
    Ok(fd)
}

/// Write `group` into a zeroed `sockaddr_storage` as a `sockaddr_in`/`sockaddr_in6` with port 0.
/// On the BSDs the `sin*_len` byte is set, which the kernel requires for the embedded address.
fn group_sockaddr(group: IpAddr) -> libc::sockaddr_storage {
    // SAFETY: an all-zero `sockaddr_storage` is a valid (AF_UNSPEC) value; the family and address
    // are overwritten below through a correctly-typed pointer into storage large enough for them.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    match group {
        IpAddr::V4(v4) => {
            let sin = (&raw mut storage).cast::<libc::sockaddr_in>();
            // SAFETY: `storage` outlives `sin` and is larger than `sockaddr_in`.
            unsafe {
                (*sin).sin_family =
                    libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET fits sa_family_t");
                (*sin).sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.octets()),
                };
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                {
                    (*sin).sin_len =
                        u8::try_from(size_of::<libc::sockaddr_in>()).expect("sockaddr_in fits u8");
                }
            }
        }
        IpAddr::V6(v6) => {
            let sin6 = (&raw mut storage).cast::<libc::sockaddr_in6>();
            // SAFETY: `storage` outlives `sin6` and is larger than `sockaddr_in6`.
            unsafe {
                (*sin6).sin6_family =
                    libc::sa_family_t::try_from(libc::AF_INET6).expect("AF_INET6 fits sa_family_t");
                (*sin6).sin6_addr = libc::in6_addr {
                    s6_addr: v6.octets(),
                };
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                {
                    (*sin6).sin6_len = u8::try_from(size_of::<libc::sockaddr_in6>())
                        .expect("sockaddr_in6 fits u8");
                }
            }
        }
    }
    storage
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn v4_group_marshals_to_a_sockaddr_in() {
        let sa = group_sockaddr(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)));
        // SAFETY: `group_sockaddr` wrote a `sockaddr_in` into the storage for a V4 group.
        let sin = unsafe { &*(&raw const sa).cast::<libc::sockaddr_in>() };
        assert_eq!(
            sin.sin_family,
            libc::sa_family_t::try_from(libc::AF_INET).unwrap()
        );
        assert_eq!(sin.sin_addr.s_addr, u32::from_ne_bytes([224, 0, 0, 251]));
        assert_eq!(sin.sin_port, 0);
    }

    #[test]
    fn v6_group_marshals_to_a_sockaddr_in6() {
        let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
        let sa = group_sockaddr(IpAddr::V6(group));
        // SAFETY: `group_sockaddr` wrote a `sockaddr_in6` into the storage for a V6 group.
        let sin6 = unsafe { &*(&raw const sa).cast::<libc::sockaddr_in6>() };
        assert_eq!(
            sin6.sin6_family,
            libc::sa_family_t::try_from(libc::AF_INET6).unwrap()
        );
        assert_eq!(sin6.sin6_addr.s6_addr, group.octets());
    }

    #[test]
    fn already_member_only_for_the_duplicate_join_errnos() {
        let of = io::Error::from_raw_os_error;
        // The or-pattern matches a single errno against each alternative in turn.
        assert!(already_member(&of(libc::EADDRINUSE))); // Linux / BSD IPv4 duplicate
        assert!(already_member(&of(libc::EINVAL))); // FreeBSD IPv6 duplicate
        assert!(!already_member(&of(libc::ENOBUFS))); // membership cap — a real failure
        assert!(!already_member(&of(libc::EADDRNOTAVAIL))); // interface transiently down
    }

    /// The loopback interface index (loopback always exists).
    fn loopback_ifindex() -> u32 {
        let name =
            std::ffi::CString::new(crate::interface::LOOPBACK_IFACE).expect("iface has no NUL");
        // SAFETY: `name` is a valid C string.
        let idx = unsafe { libc::if_nametoindex(name.as_ptr()) };
        assert_ne!(idx, 0, "loopback must resolve to an index");
        idx
    }

    #[test]
    fn kernel_accepts_a_join_on_loopback() {
        // Exercises the full MCAST_JOIN_GROUP FFI against the kernel — the per-OS const, the
        // hand-rolled group_req layout, by-index selection. Loopback accepts the join on both Linux
        // and the BSDs (the by-index option doesn't require the interface's IFF_MULTICAST flag).
        let mut joiner = MulticastJoiner::new(loopback_ifindex());
        joiner
            .join(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)))
            .expect("kernel accepts the v4 mDNS group join");
        joiner
            .join(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)))
            .expect("kernel accepts the v6 mDNS group join");
    }
}
