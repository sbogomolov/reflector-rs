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

use crate::sys::{open_socket, sockaddr_for, socklen_of};

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
/// these two sockets belongs to this one interface. `desired` records the groups asked for so they
/// can be re-attempted when the interface re-resolves (a v4 group joined before its address existed
/// becomes joinable then). Held for membership only.
pub(crate) struct MulticastJoiner {
    ifindex: u32,
    v4: Option<OwnedFd>,
    v6: Option<OwnedFd>,
    desired: Vec<IpAddr>,
}

impl MulticastJoiner {
    pub(crate) fn new(ifindex: u32) -> Self {
        Self {
            ifindex,
            v4: None,
            v6: None,
            desired: Vec::new(),
        }
    }

    /// Join `group` on this interface and remember it, so a later interface change re-attempts it.
    /// Idempotent: the kernel keys memberships by `(group, ifindex)`, so re-joining one already held
    /// is a no-op.
    ///
    /// # Errors
    /// Returns the OS error if the join socket can't be opened or the membership can't be added.
    /// `EADDRNOTAVAIL` means the interface has no address of that family yet — the membership is
    /// recorded and [`rejoin`](Self::rejoin) retries it on the next address-up event, so the caller
    /// can treat it as deferred rather than fatal. (`ENOBUFS` — the per-socket membership cap —
    /// can't arise: this socket holds only this interface's few groups; see the module note.)
    pub(crate) fn join(&mut self, group: IpAddr) -> io::Result<()> {
        if !self.desired.contains(&group) {
            self.desired.push(group);
        }
        self.apply(group)
    }

    /// Re-attempt every desired membership after the interface re-resolves: a group that wasn't
    /// joinable before its address existed succeeds now, an already-held one is a harmless no-op.
    /// Best-effort — a still-unavailable family logs and waits for the next change.
    pub(crate) fn rejoin(&mut self) {
        for i in 0..self.desired.len() {
            let group = self.desired[i];
            if let Err(e) = self.apply(group) {
                log::debug!(
                    "re-join of {group} on ifindex {} deferred: {e}",
                    self.ifindex
                );
            }
        }
    }

    /// Issue `MCAST_JOIN_GROUP` for `group` on this interface's per-family socket.
    fn apply(&mut self, group: IpAddr) -> io::Result<()> {
        let (slot, family, level) = match group {
            IpAddr::V4(_) => (&mut self.v4, libc::AF_INET, libc::IPPROTO_IP),
            IpAddr::V6(_) => (&mut self.v6, libc::AF_INET6, libc::IPPROTO_IPV6),
        };
        let fd = match slot {
            Some(sock) => sock.as_raw_fd(),
            None => slot
                .insert(open_socket(family, libc::SOCK_DGRAM)?)
                .as_raw_fd(),
        };
        // Zero the whole struct before setting fields: a field-by-field literal leaves the 4 bytes of
        // padding after `gr_interface` uninitialised, and `setsockopt` reads the struct's full size, so a
        // syscall would be handed uninitialised bytes (Valgrind flags it, and it is plainly incorrect).
        // SAFETY: `group_req` is plain data with no invalid bit patterns; all-zero is a valid value.
        let mut req: GroupReq = unsafe { std::mem::zeroed() };
        req.gr_interface = self.ifindex;
        // The membership selects the interface by `gr_interface` (the index), so the group sockaddr
        // carries no scope id.
        req.gr_group = sockaddr_for(group, 0, 0).0;
        // SAFETY: `req` is now a fully-initialized `group_req` (its padding zeroed); we pass its address
        // and own size as the option value and length for the protocol-independent join at the family's
        // IP level.
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

/// Whether a join error means this environment can't perform the join at all, rather than a real
/// rejection — the cue for the join tests to self-skip. QEMU user-mode emulation doesn't implement the
/// `MCAST_JOIN_GROUP` setsockopt and returns `ENOPROTOOPT`; treat that and the kindred "unsupported"
/// errnos as a skip, never as a pass. This is a test seam only: at runtime these stay fatal.
#[cfg(test)]
pub(crate) fn join_unsupported(err: &io::Error) -> bool {
    matches!(
        err.raw_os_error(),
        Some(libc::ENOPROTOOPT | libc::EOPNOTSUPP | libc::ENOSYS)
    )
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

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
        // QEMU user-mode emulation doesn't implement the setsockopt, so self-skip there.
        let mut joiner = MulticastJoiner::new(loopback_ifindex());
        for group in [
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
        ] {
            match joiner.join(group) {
                Ok(()) => {}
                Err(e) if join_unsupported(&e) => {
                    eprintln!(
                        "skip kernel_accepts_a_join: MCAST_JOIN_GROUP unsupported here ({e})"
                    );
                    return;
                }
                Err(e) => panic!("kernel must accept the {group} group join: {e}"),
            }
        }
    }
}
