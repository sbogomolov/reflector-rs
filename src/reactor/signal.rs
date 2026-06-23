//! Self-pipe signal shutdown.
//!
//! A signal arrives at an arbitrary point and its handler may call only
//! async-signal-safe functions, so it cannot touch the reactor (the arena, the
//! logger, allocation — all off-limits). Instead the handler does the one safe
//! thing it needs: `write` a byte to a pipe. The pipe's read end is registered
//! with the reactor like any other fd, so the shutdown itself happens later, in
//! normal code, when the loop wakes on it. This needs no per-backend signal
//! support (no `signalfd` / `EVFILT_SIGNAL`) — the pipe is just a readable fd.

use std::io;
use std::mem;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::ptr;
use std::sync::atomic::{AtomicI32, Ordering};

use libc::c_int;

use super::{Handler, Reactor, ReadyEvent};

/// Signals that request a graceful shutdown.
const SHUTDOWN_SIGNALS: [c_int; 2] = [libc::SIGINT, libc::SIGTERM];

/// The write end of the installed self-pipe, or `-1` when none is installed. The
/// handler reads this and writes a byte; [`ShutdownPipe`] owns the fd and is the
/// only thing that sets this cell, and only one can exist at a time (single
/// reactor, single thread).
static WRITE_FD: AtomicI32 = AtomicI32::new(-1);

/// The signal handler: the one async-signal-safe action we need.
extern "C" fn on_signal(_signum: c_int) {
    let fd = WRITE_FD.load(Ordering::Relaxed);
    if fd >= 0 {
        let byte: u8 = 0;
        // SAFETY: `write` is async-signal-safe. One byte to the non-blocking
        // self-pipe; a full pipe (EAGAIN) already carries the pending wakeup, so
        // the result is intentionally ignored.
        unsafe {
            libc::write(fd, (&raw const byte).cast(), 1);
        }
    }
}

/// An installed self-pipe with the previous signal dispositions saved. Dropping it
/// restores those dispositions, unpublishes the fd, and closes the write end — in
/// that order, so no signal can reach a handler that points at a closed fd.
pub(crate) struct ShutdownPipe {
    write_fd: OwnedFd,
    saved_actions: [libc::sigaction; SHUTDOWN_SIGNALS.len()],
}

impl ShutdownPipe {
    /// Create the self-pipe, publish its write end, and install the shutdown
    /// handlers. Returns the guard plus the [`SignalPipe`] handler (owning the read
    /// end) to register with the reactor.
    ///
    /// # Errors
    /// Returns an error if the pipe cannot be created, a handler cannot be
    /// installed, or a shutdown pipe is already installed.
    pub(crate) fn install() -> io::Result<(Self, SignalPipe)> {
        let (read, write) = self_pipe()?;
        // Publish the write fd for the handler, refusing a second concurrent install.
        if WRITE_FD
            .compare_exchange(-1, write.as_raw_fd(), Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(io::Error::other(
                "shutdown signal handler already installed",
            ));
        }
        let saved = match install_handlers() {
            Ok(saved) => saved,
            Err(e) => {
                WRITE_FD.store(-1, Ordering::SeqCst);
                return Err(e);
            }
        };
        Ok((
            Self {
                write_fd: write,
                saved_actions: saved,
            },
            SignalPipe { read },
        ))
    }
}

impl Drop for ShutdownPipe {
    fn drop(&mut self) {
        // Order matters: stop signals reaching our handler, then unpublish the fd;
        // `self.write_fd` closes last (after this body), when nothing can touch it.
        restore_handlers(&self.saved_actions);
        WRITE_FD.store(-1, Ordering::SeqCst);
    }
}

/// Reactor handler for the self-pipe read end (which it owns): drains the pipe and
/// asks the reactor to stop. The bytes carry nothing beyond "a shutdown signal
/// arrived".
pub(crate) struct SignalPipe {
    read: OwnedFd,
}

impl SignalPipe {
    /// The read-end fd to watch — handed to [`Reactor::register_with_fds`] at install.
    pub(crate) fn read_fd(&self) -> RawFd {
        self.read.as_raw_fd()
    }
}

impl Handler for SignalPipe {
    fn on_readable(&mut self, _event: ReadyEvent, reactor: &mut Reactor) {
        // Drain so a level-triggered wait does not keep re-reporting it.
        let mut buf = [0u8; 16];
        let fd = self.read.as_raw_fd();
        // SAFETY: `self.read` is the registered, non-blocking read end; draining
        // stops at EOF (0) or EAGAIN (-1).
        while unsafe { libc::read(fd, buf.as_mut_ptr().cast(), buf.len()) } > 0 {}
        reactor.request_shutdown();
    }
}

/// A close-on-exec, non-blocking pipe `(read, write)`.
fn self_pipe() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [0 as RawFd; 2];

    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    let rc = {
        // SAFETY: `pipe2` fills the 2-element `fds` with two fresh owned fds and
        // applies O_CLOEXEC | O_NONBLOCK atomically.
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC | libc::O_NONBLOCK) }
    };
    #[cfg(target_os = "macos")]
    let rc = {
        // SAFETY: `pipe` fills the 2-element `fds` with two fresh owned fds; macOS
        // has no `pipe2`, so the flags are applied with `fcntl` below.
        unsafe { libc::pipe(fds.as_mut_ptr()) }
    };

    if rc != 0 {
        return Err(io::Error::last_os_error());
    }

    // SAFETY: `pipe`/`pipe2` succeeded, so both fds are fresh and owned.
    let (read, write) = unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) };

    #[cfg(target_os = "macos")]
    {
        set_cloexec_nonblock(read.as_raw_fd())?;
        set_cloexec_nonblock(write.as_raw_fd())?;
    }

    Ok((read, write))
}

/// Set `FD_CLOEXEC` and `O_NONBLOCK` on `fd` (the macOS path, lacking `pipe2`).
#[cfg(target_os = "macos")]
fn set_cloexec_nonblock(fd: RawFd) -> io::Result<()> {
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

/// Install [`on_signal`] for every shutdown signal, returning the previous
/// dispositions to restore later. Rolls back on partial failure.
fn install_handlers() -> io::Result<[libc::sigaction; SHUTDOWN_SIGNALS.len()]> {
    // SAFETY: an all-zero `sigaction` is a valid SIG_DFL disposition we overwrite.
    let mut action: libc::sigaction = unsafe { mem::zeroed() };
    // A function item can't cast straight to an integer; route through a pointer.
    action.sa_sigaction = on_signal as *const () as libc::sighandler_t;
    action.sa_flags = libc::SA_RESTART;
    // SAFETY: `sa_mask` is a valid, owned `sigset_t`.
    unsafe { libc::sigemptyset(&raw mut action.sa_mask) };

    // SAFETY: zeroed `sigaction`s, each filled by its call's oldact out-param.
    let mut saved: [libc::sigaction; SHUTDOWN_SIGNALS.len()] = unsafe { mem::zeroed() };
    for (i, &signum) in SHUTDOWN_SIGNALS.iter().enumerate() {
        // SAFETY: valid signal number with valid act / oldact pointers.
        let rc = unsafe { libc::sigaction(signum, &raw const action, &raw mut saved[i]) };
        if rc != 0 {
            let err = io::Error::last_os_error();
            restore_handlers(&saved[..i]);
            return Err(err);
        }
    }
    Ok(saved)
}

/// Restore previously-saved signal dispositions (best effort).
fn restore_handlers(saved: &[libc::sigaction]) {
    for (&signum, action) in SHUTDOWN_SIGNALS.iter().zip(saved) {
        // SAFETY: `action` is a disposition a prior `sigaction` produced.
        unsafe { libc::sigaction(signum, action, ptr::null_mut()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn self_pipe_is_cloexec_and_nonblocking() {
        let (read, write) = self_pipe().unwrap();

        // Non-blocking: reading the empty pipe returns EAGAIN rather than blocking.
        let mut buf = [0u8; 1];
        // SAFETY: read up to 1 byte into `buf` from the valid read-end fd.
        let n = unsafe { libc::read(read.as_raw_fd(), buf.as_mut_ptr().cast(), 1) };
        assert_eq!(n, -1);
        assert_eq!(
            io::Error::last_os_error().raw_os_error(),
            Some(libc::EAGAIN)
        );

        // Close-on-exec is set on both ends.
        for fd in [read.as_raw_fd(), write.as_raw_fd()] {
            // SAFETY: F_GETFD reads the descriptor flags of a valid fd.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            assert!(flags >= 0 && flags & libc::FD_CLOEXEC != 0);
        }
    }

    // The one test that touches process-global signal state, so it cannot race a
    // sibling: nothing else here installs handlers.
    #[test]
    fn installed_handler_writes_on_signal() {
        let (guard, pipe) = ShutdownPipe::install().unwrap();

        // Our handler must catch SIGINT (write a byte), not terminate the process.
        // SAFETY: `raise` just delivers a signal to the current process.
        let raised = unsafe { libc::raise(libc::SIGINT) };
        assert_eq!(raised, 0);

        let mut buf = [0u8; 4];
        // SAFETY: read up to `buf.len()` bytes into `buf` from the valid read-end fd.
        let n = unsafe { libc::read(pipe.read_fd(), buf.as_mut_ptr().cast(), buf.len()) };
        assert!(n >= 1);

        drop(guard); // restores the previous SIGINT/SIGTERM dispositions
    }
}
