//! Small platform/syscall helpers shared across subsystems, each `cfg`-gated to the platforms
//! that need it. For now just the macOS fd setup — no `pipe2` / `SOCK_*` type flags there, so
//! close-on-exec and non-blocking go on by `fcntl`; Linux/BSD helpers can join as they arise.

#[cfg(target_os = "macos")]
use std::io;
#[cfg(target_os = "macos")]
use std::os::fd::RawFd;

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
