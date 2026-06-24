//! Interface address-change monitoring: a routing socket whose readiness means some
//! interface's addresses (or MAC) changed, so the dispatcher should re-resolve it.
//! `NETLINK_ROUTE` on Linux, `PF_ROUTE` on the BSDs — one uniform [`AddressMonitor`] over a
//! per-platform backend, mirroring the resolver's rtnetlink/getifaddrs split.
//!
//! Best-effort: the monitor only keeps already-resolved addresses fresh. Failing to open it
//! (or a read error) degrades to the startup-resolved addresses; it never aborts the daemon.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod route;
#[cfg(target_os = "linux")]
mod rtnetlink;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
use self::route as backend;
#[cfg(target_os = "linux")]
use self::rtnetlink as backend;

/// A routing-socket monitor for interface address and link changes. The dispatcher watches
/// its fd and calls [`drain`](Self::drain) on readiness.
pub(crate) struct AddressMonitor {
    sock: OwnedFd,
    /// Reused across drains, sized once at open and never grown — each notification is a
    /// single bounded message (not a coalesced dump), so a fixed buffer fits with headroom.
    /// No data-path allocation.
    buf: Box<[u8]>,
}

impl AddressMonitor {
    /// Open and subscribe a routing socket, non-blocking and close-on-exec.
    ///
    /// # Errors
    /// Returns an error if the socket can't be opened or subscribed. A failure is the
    /// caller's cue to run without live updates, not to abort.
    pub(crate) fn open() -> io::Result<Self> {
        Ok(Self {
            sock: backend::open()?,
            buf: vec![0u8; backend::READ_BUF].into_boxed_slice(),
        })
    }

    /// The fd to watch for readiness.
    pub(crate) fn as_raw_fd(&self) -> RawFd {
        self.sock.as_raw_fd()
    }

    /// Drain every queued notification, calling `on_change(ifindex)` per affected interface —
    /// and `on_change(0)` after an overflow, meaning "re-resolve everything" (kernel indices
    /// are >= 1, so 0 is an unambiguous signal). Reads to `EAGAIN` so a level-triggered wait
    /// won't immediately re-fire.
    ///
    /// # Errors
    /// The first non-recoverable recv failure. Recoverable: `EAGAIN`/`EWOULDBLOCK` end the
    /// drain, `EINTR` retries, `ENOBUFS` reports the overflow signal and continues.
    pub(crate) fn drain(&mut self, mut on_change: impl FnMut(u32)) -> io::Result<()> {
        loop {
            // SAFETY: `recv` fills up to `buf.len()` bytes of the owned buffer.
            let n = unsafe {
                libc::recv(
                    self.sock.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                    0,
                )
            };
            if n < 0 {
                let err = io::Error::last_os_error();
                let errno = err.raw_os_error();
                if errno == Some(libc::EINTR) {
                    continue; // interrupted before any data; retry
                }
                if errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK) {
                    return Ok(()); // no more queued notifications
                }
                if errno == Some(libc::ENOBUFS) {
                    // A receive-buffer overflow dropped notifications: signal a full
                    // re-resolve, then keep draining to clear the socket.
                    on_change(0);
                    continue;
                }
                return Err(err);
            }
            let n = usize::try_from(n).expect("recv count is non-negative");
            if n == 0 {
                return Ok(()); // routing sockets don't EOF; defensive against a 0-length read
            }
            backend::for_each_change(&self.buf[..n], &mut on_change);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A freshly-opened monitor drains at once (the socket is non-blocking) without blocking
    // or erroring. Best-effort: some sandboxes deny the routing socket, where the monitor
    // degrades to no live updates — nothing to drain, so skip.
    #[test]
    fn opens_and_drains_without_blocking() {
        let mut monitor = match AddressMonitor::open() {
            Ok(monitor) => monitor,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skip: the routing socket could not be opened: {e}");
                return;
            }
            Err(e) => panic!("unexpected monitor open failure: {e}"),
        };
        monitor.drain(|_| {}).expect("drain a quiet monitor");
    }
}
