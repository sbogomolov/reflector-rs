//! Small platform/syscall helpers shared across subsystems. Some are unconditional (fd
//! ownership); others are `cfg`-gated to the platforms that need them — macOS lacks `pipe2`
//! and the `SOCK_*` type flags, so it applies close-on-exec / non-blocking by `fcntl`.

use std::io;
use std::os::fd::{FromRawFd, OwnedFd, RawFd};

use libc::socklen_t;

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
    /// `EINTR`: interrupted before any data; the caller should retry.
    Interrupted,
}

/// Triage a `recv`/`read` return value `n`: a non-negative count is `Ready`, a negative one is
/// classified by errno into the non-blocking-fd contract (`Interrupted`/`WouldBlock`) or a real
/// error. Single-sources the would-block errno set — an OS contract, not a per-caller detail.
///
/// # Errors
/// Returns the last OS error for any errno other than `EINTR`/`EAGAIN`/`EWOULDBLOCK`.
pub(crate) fn classify_recv(n: isize) -> io::Result<RecvOutcome> {
    if n >= 0 {
        return Ok(RecvOutcome::Ready(
            usize::try_from(n).expect("a non-negative recv count fits usize"),
        ));
    }
    let err = io::Error::last_os_error();
    let errno = err.raw_os_error();
    if errno == Some(libc::EINTR) {
        return Ok(RecvOutcome::Interrupted);
    }
    if errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK) {
        return Ok(RecvOutcome::WouldBlock);
    }
    Err(err)
}

/// The size of `T` as a `socklen_t`, for `setsockopt`/`bind` length arguments.
pub(crate) fn socklen_of<T>() -> socklen_t {
    socklen_t::try_from(size_of::<T>()).expect("option/address size fits socklen_t")
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
