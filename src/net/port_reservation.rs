//! An ephemeral-UDP-port reservation: a held, never-read socket whose only job is to keep the
//! kernel's UDP demux satisfied. The SSDP search reflector re-emits an M-SEARCH from this port so
//! devices unicast their `200 OK` back to it; the port must stay claimed for the session's lifetime
//! so the kernel finds a socket for the reply and does NOT answer it with an ICMP port-unreachable.
//! The bound socket is never read — the raw capture reads the actual datagram; on Linux a drop-all
//! BPF filter makes the socket enqueue nothing. Dropping it frees the port.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use crate::sys::{open_dgram_socket, sockaddr_for, socklen_of};

/// A reservation over one OS-assigned ephemeral UDP port on an interface's source address. Owns the
/// bound socket; `Drop` frees the port.
pub(crate) struct PortReservation {
    /// Held for its lifetime to keep the port claimed; never read — the raw capture reads the reply.
    _fd: OwnedFd,
    port: u16,
}

impl PortReservation {
    /// Reserve an ephemeral port on `addr` (the egress interface's own address — the reflector sends
    /// from it and devices reply to it): open a `SOCK_DGRAM` socket, bind it to `addr:0`, and read
    /// the assigned port back. `ifindex` is the interface index, required to bind an IPv6 link-local
    /// `addr` (ignored for IPv4). On Linux a drop-all filter makes the socket enqueue nothing — the
    /// real datagram is read by the capture.
    ///
    /// # Errors
    /// Propagates the socket / filter / bind / `getsockname` syscall failure.
    pub(crate) fn create(addr: IpAddr, ifindex: u32) -> io::Result<Self> {
        let family = match addr {
            IpAddr::V4(_) => libc::AF_INET,
            IpAddr::V6(_) => libc::AF_INET6,
        };
        let fd = open_dgram_socket(family)?;
        #[cfg(target_os = "linux")]
        attach_drop_all_filter(fd.as_raw_fd())?;
        let (storage, len) = sockaddr_for(addr, 0, ifindex);
        // SAFETY: `storage` is a valid `sockaddr_in`/`sockaddr_in6` of length `len` for `fd`'s family.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&raw const storage).cast::<libc::sockaddr>(),
                len,
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
        let port = bound_port(fd.as_raw_fd())?;
        Ok(Self { _fd: fd, port })
    }

    /// The OS-assigned ephemeral port the reservation holds.
    pub(crate) fn port(&self) -> u16 {
        self.port
    }
}

/// Read back the port `fd` was bound to via `getsockname`. The port field sits at the same offset
/// (right after the family) in `sockaddr_in` and `sockaddr_in6`, so one read serves both; it is in
/// network byte order.
fn bound_port(fd: RawFd) -> io::Result<u16> {
    // SAFETY: an all-zero `sockaddr_storage` is a valid buffer; `getsockname` fills it and updates
    // `len` to the bytes written.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut len = socklen_of::<libc::sockaddr_storage>();
    // SAFETY: `storage`/`len` are a valid (sockaddr, length) out-pair for `fd`.
    let rc = unsafe {
        libc::getsockname(
            fd,
            (&raw mut storage).cast::<libc::sockaddr>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `storage` holds a bound `sockaddr_in`/`sockaddr_in6`; `sin_port` aliases the port field
    // of both (same offset after the family).
    let port = unsafe { (*(&raw const storage).cast::<libc::sockaddr_in>()).sin_port };
    Ok(u16::from_be(port))
}

/// Attach a drop-all classic-BPF filter so the bound socket enqueues nothing: the bind already
/// suppresses the ICMP port-unreachable, and the real datagram is read by the raw capture.
#[cfg(target_os = "linux")]
fn attach_drop_all_filter(fd: RawFd) -> io::Result<()> {
    // A single `BPF_RET | BPF_K` returning 0 — accept zero bytes, i.e. drop every packet.
    let drop_all = [libc::sock_filter {
        code: 0x0006,
        jt: 0,
        jf: 0,
        k: 0,
    }];
    let program = libc::sock_fprog {
        len: 1,
        filter: drop_all.as_ptr().cast_mut(),
    };
    // SAFETY: a `setsockopt` with a `sock_fprog` pointing at `drop_all`, valid for the call.
    let rc = unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw const program).cast::<libc::c_void>(),
            socklen_of::<libc::sock_fprog>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn reserves_a_nonzero_port_on_loopback() {
        let r = PortReservation::create(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
            .expect("bind an ephemeral port on loopback");
        assert_ne!(r.port(), 0, "getsockname should report the assigned port");
    }

    #[test]
    fn two_reservations_get_distinct_ports() {
        let a = PortReservation::create(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        let b = PortReservation::create(IpAddr::V4(Ipv4Addr::LOCALHOST), 0).unwrap();
        assert_ne!(a.port(), b.port());
    }
}
