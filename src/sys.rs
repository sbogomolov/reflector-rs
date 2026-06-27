//! Small platform/syscall helpers shared across subsystems. Some are unconditional (fd
//! ownership); others are `cfg`-gated to the platforms that need them — macOS lacks `pipe2`
//! and the `SOCK_*` type flags, so it applies close-on-exec / non-blocking by `fcntl`.

use std::io;
use std::net::IpAddr;
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use libc::{c_int, socklen_t};

/// Take ownership of a raw fd returned by a fd-returning syscall: a negative value is the
/// POSIX error sentinel; a non-negative one is a fresh fd we own.
///
/// # Errors
/// Returns the last OS error when `raw` is negative.
pub(crate) fn owned_fd_from(raw: RawFd) -> io::Result<OwnedFd> {
    if raw < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: a non-negative return from a fd-returning syscall is a fresh fd we exclusively own.
    Ok(unsafe { OwnedFd::from_raw_fd(raw) })
}

/// The outcome of triaging a `recv`/`read` return value via [`classify_recv`].
pub(crate) enum RecvOutcome {
    /// `n` bytes were read — possibly 0; the caller decides what an empty read means.
    Ready(usize),
    /// `EAGAIN`/`EWOULDBLOCK`: nothing available on a non-blocking fd.
    WouldBlock,
}

/// Triage a `recv`/`read` return value `n`: a non-negative count is `Ready`, a negative one is
/// `WouldBlock` on `EAGAIN`/`EWOULDBLOCK` or else a real error. `EINTR` is not special-cased: the
/// sockets are non-blocking and the shutdown signals install with `SA_RESTART`, so the restartable
/// recv/read calls auto-restart rather than surfacing `EINTR` (only the non-restartable reactor wait
/// can, and it retries itself).
///
/// # Errors
/// Returns the last OS error for any errno other than `EAGAIN`/`EWOULDBLOCK`.
pub(crate) fn classify_recv(n: isize) -> io::Result<RecvOutcome> {
    if n >= 0 {
        return Ok(RecvOutcome::Ready(
            usize::try_from(n).expect("a non-negative recv count fits usize"),
        ));
    }
    let err = io::Error::last_os_error();
    if would_block(&err) {
        return Ok(RecvOutcome::WouldBlock);
    }
    Err(err)
}

/// Whether `err` is the non-blocking "nothing right now" signal (`EAGAIN`/`EWOULDBLOCK`). The two are
/// equal on our targets, but matched as a pair — via a guard, not an or-pattern whose second arm would
/// be unreachable — for portability. Single-sources the would-block errno set across the `recv` triage
/// and the TCP `send`/`accept` paths, an OS contract rather than a per-caller detail.
pub(crate) fn would_block(err: &io::Error) -> bool {
    matches!(err.raw_os_error(), Some(e) if e == libc::EAGAIN || e == libc::EWOULDBLOCK)
}

/// The size of `T` as a `socklen_t`, for `setsockopt`/`bind` length arguments.
pub(crate) fn socklen_of<T>() -> socklen_t {
    socklen_t::try_from(size_of::<T>()).expect("option/address size fits socklen_t")
}

/// Open a socket of `family` and `base_type` (e.g. `SOCK_DGRAM`/`SOCK_STREAM`), close-on-exec and
/// non-blocking — non-blocking keeps a stray read from freezing the single-threaded reactor. Linux and
/// FreeBSD set both flags in the socket type; macOS lacks them and applies them by `fcntl`.
///
/// # Errors
/// Returns the OS error if the socket can't be opened (or, on macOS, the flags can't be set).
pub(crate) fn open_socket(family: c_int, base_type: c_int) -> io::Result<OwnedFd> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let sock_type = base_type | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(target_os = "macos")]
    let sock_type = base_type;
    // SAFETY: `socket` returns a fresh owned fd or -1; `owned_fd_from` takes ownership or errors.
    let fd = owned_fd_from(unsafe { libc::socket(family, sock_type, 0) })?;
    #[cfg(target_os = "macos")]
    set_cloexec_nonblock(fd.as_raw_fd())?;
    Ok(fd)
}

/// Marshal `addr`:`port` into a zeroed `sockaddr_storage` as a `sockaddr_in`/`sockaddr_in6`,
/// returning it with the family-specific length for a `bind`/option argument. `scope_id` (an
/// interface index) goes into `sin6_scope_id` for IPv6 — required to bind a link-local address —
/// and is ignored for IPv4. On the BSDs the `sin*_len` byte is set, which the kernel requires.
pub(crate) fn sockaddr_for(
    addr: IpAddr,
    port: u16,
    scope_id: u32,
) -> (libc::sockaddr_storage, socklen_t) {
    // SAFETY: an all-zero `sockaddr_storage` is a valid (AF_UNSPEC) value; the family and address
    // are overwritten below through a correctly-typed pointer into storage large enough for them.
    let mut storage: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let len = match addr {
        IpAddr::V4(v4) => {
            let sin = (&raw mut storage).cast::<libc::sockaddr_in>();
            // SAFETY: `storage` outlives `sin` and is larger than `sockaddr_in`.
            unsafe {
                (*sin).sin_family =
                    libc::sa_family_t::try_from(libc::AF_INET).expect("AF_INET fits sa_family_t");
                (*sin).sin_port = port.to_be();
                (*sin).sin_addr = libc::in_addr {
                    s_addr: u32::from_ne_bytes(v4.octets()),
                };
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                {
                    (*sin).sin_len =
                        u8::try_from(size_of::<libc::sockaddr_in>()).expect("sockaddr_in fits u8");
                }
            }
            socklen_of::<libc::sockaddr_in>()
        }
        IpAddr::V6(v6) => {
            let sin6 = (&raw mut storage).cast::<libc::sockaddr_in6>();
            // SAFETY: `storage` outlives `sin6` and is larger than `sockaddr_in6`.
            unsafe {
                (*sin6).sin6_family =
                    libc::sa_family_t::try_from(libc::AF_INET6).expect("AF_INET6 fits sa_family_t");
                (*sin6).sin6_port = port.to_be();
                (*sin6).sin6_addr = libc::in6_addr {
                    s6_addr: v6.octets(),
                };
                (*sin6).sin6_scope_id = scope_id;
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                {
                    (*sin6).sin6_len = u8::try_from(size_of::<libc::sockaddr_in6>())
                        .expect("sockaddr_in6 fits u8");
                }
            }
            socklen_of::<libc::sockaddr_in6>()
        }
    };
    (storage, len)
}

/// Set `FD_CLOEXEC` and `O_NONBLOCK` on `fd`, read-modify-write so any other flags survive.
///
/// # Errors
/// Returns the first failing `fcntl`'s error.
#[cfg(target_os = "macos")]
pub(crate) fn set_cloexec_nonblock(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is a valid open fd; F_GETFD returns the descriptor flags.
    let fd_flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if fd_flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is valid; F_SETFD writes the descriptor flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFD, fd_flags | libc::FD_CLOEXEC) } < 0 {
        return Err(io::Error::last_os_error());
    }
    set_nonblock(fd)
}

/// Set `O_NONBLOCK` on `fd`, read-modify-write so the other status flags survive.
///
/// # Errors
/// Returns the failing `fcntl`'s error.
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) fn set_nonblock(fd: RawFd) -> io::Result<()> {
    // SAFETY: `fd` is valid; F_GETFL returns the status flags.
    let status = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if status < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is valid; F_SETFL writes the status flags.
    if unsafe { libc::fcntl(fd, libc::F_SETFL, status | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    #[test]
    fn sockaddr_for_v4_marshals_a_sockaddr_in() {
        let (sa, len) = sockaddr_for(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 0, 0);
        assert_eq!(len, socklen_of::<libc::sockaddr_in>());
        // SAFETY: `sockaddr_for` wrote a `sockaddr_in` into the storage for a V4 address.
        let sin = unsafe { &*(&raw const sa).cast::<libc::sockaddr_in>() };
        assert_eq!(
            sin.sin_family,
            libc::sa_family_t::try_from(libc::AF_INET).unwrap()
        );
        assert_eq!(sin.sin_addr.s_addr, u32::from_ne_bytes([224, 0, 0, 251]));
        assert_eq!(sin.sin_port, 0);
    }

    #[test]
    fn sockaddr_for_v6_carries_the_scope_id() {
        let v6 = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
        let (sa, len) = sockaddr_for(IpAddr::V6(v6), 0, 7);
        assert_eq!(len, socklen_of::<libc::sockaddr_in6>());
        // SAFETY: `sockaddr_for` wrote a `sockaddr_in6` into the storage for a V6 address.
        let sin6 = unsafe { &*(&raw const sa).cast::<libc::sockaddr_in6>() };
        assert_eq!(
            sin6.sin6_family,
            libc::sa_family_t::try_from(libc::AF_INET6).unwrap()
        );
        assert_eq!(sin6.sin6_addr.s6_addr, v6.octets());
        assert_eq!(sin6.sin6_scope_id, 7);
    }
}
