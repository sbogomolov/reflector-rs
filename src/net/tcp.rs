//! A non-blocking IPv4 TCP socket for the DIAL application proxy: listen on the source interface,
//! accept, egress-pinned connect to a device on the target interface, and stream bytes. The reactor
//! watches its fd; all operations are non-blocking and the socket is close-on-exec.

use std::io;
use std::mem::MaybeUninit;
use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::{c_int, c_void};

use crate::sys::{IoStatus, open_socket, sockaddr_for, socklen_of, would_block};

/// The listen backlog — a DIAL listener fields a few short-lived client fetches, so this is ample.
const LISTEN_BACKLOG: c_int = 16;

/// A non-blocking IPv4 TCP socket — a listener, an accepted connection, or an outbound connection that
/// may still be completing its non-blocking `connect`. Owns its fd; `Drop` closes it.
pub(crate) struct TcpSocket {
    fd: OwnedFd,
    /// Captured once at construction (the `bind` fixes it) so [`local_addr`](Self::local_addr) is a
    /// field read rather than a per-call `getsockname`.
    local_addr: SocketAddrV4,
    connecting: bool,
}

impl TcpSocket {
    /// Listen on `addr:0` — an ephemeral port on the source interface's address (not `0.0.0.0`, so only
    /// that subnet reaches it). Read the assigned port back with [`local_addr`](Self::local_addr).
    ///
    /// # Errors
    /// Propagates the socket / `setsockopt` / `bind` / `listen` syscall failure.
    pub(crate) fn listen(addr: Ipv4Addr) -> io::Result<Self> {
        let fd = open_socket(libc::AF_INET, libc::SOCK_STREAM)?;
        bind_v4(fd.as_raw_fd(), addr, 0)?;
        // SAFETY: `fd` is a valid bound socket; `listen` marks it passive.
        if unsafe { libc::listen(fd.as_raw_fd(), LISTEN_BACKLOG) } != 0 {
            return Err(io::Error::last_os_error());
        }
        let local_addr = local_addr_v4(fd.as_raw_fd())?;
        Ok(Self {
            fd,
            local_addr,
            connecting: false,
        })
    }

    /// The bound IPv4 address — for a listener, the ephemeral port to advertise. A
    /// field read of the address captured at construction, not a `getsockname`.
    pub(crate) fn local_addr(&self) -> SocketAddrV4 {
        self.local_addr
    }

    /// Accept one pending connection, or `None` if none is pending (the listener is non-blocking, and a
    /// level-triggered reactor re-fires while more wait). The accepted socket is connected,
    /// non-blocking, and close-on-exec.
    ///
    /// # Errors
    /// Propagates a non-`WouldBlock` `accept` failure.
    pub(crate) fn accept(&self) -> io::Result<Option<Self>> {
        Ok(accept_fd(self.fd.as_raw_fd())?.map(|fd| Self {
            fd,
            // shares the listener's local address — inherit rather than re-query
            local_addr: self.local_addr,
            connecting: false,
        }))
    }

    /// Open a connection to `dst`, egress-pinned to the target interface (`source` address + scope
    /// `ifindex`) so the route can't leak onto the wrong segment. Non-blocking: the socket is
    /// [`is_connecting`](Self::is_connecting) until a writable edge and [`finish_connect`](Self::finish_connect).
    ///
    /// # Errors
    /// Propagates the socket / pin / `bind` / `connect` failure (other than the in-progress sentinel).
    pub(crate) fn connect(dst: SocketAddrV4, source: Ipv4Addr, ifindex: u32) -> io::Result<Self> {
        let fd = open_socket(libc::AF_INET, libc::SOCK_STREAM)?;
        // FreeBSD has no egress-pin primitive; the source-address bind below steers egress.
        #[cfg(not(target_os = "freebsd"))]
        pin_egress(fd.as_raw_fd(), ifindex)?;
        #[cfg(target_os = "freebsd")]
        let _ = ifindex;
        bind_v4(fd.as_raw_fd(), source, 0)?;
        let local_addr = local_addr_v4(fd.as_raw_fd())?;
        let connecting = connect_v4(fd.as_raw_fd(), dst)?;
        Ok(Self {
            fd,
            local_addr,
            connecting,
        })
    }

    /// Complete a non-blocking `connect` after its writable edge: read `SO_ERROR`. Clears
    /// [`is_connecting`](Self::is_connecting) on success.
    ///
    /// # Errors
    /// The connect's error (e.g. `ECONNREFUSED`) if it failed, or the `getsockopt` failure.
    pub(crate) fn finish_connect(&mut self) -> io::Result<()> {
        let err = so_error(self.fd.as_raw_fd())?;
        if err != 0 {
            return Err(io::Error::from_raw_os_error(err));
        }
        self.connecting = false;
        Ok(())
    }

    /// Whether an outbound connection is still completing its non-blocking `connect`.
    pub(crate) fn is_connecting(&self) -> bool {
        self.connecting
    }

    /// Read into `buf`, which may be uninitialized — `recv` only ever writes the bytes it returns, so on
    /// [`IoStatus::Ready(n)`](IoStatus) the first `n` bytes of `buf` are now initialized. `buf` must be
    /// non-empty: a `recv` into a zero-length buffer also returns 0, aliasing the `Ready(0)` clean-EOF
    /// signal (the `std::io::Read::read` caveat). The peer closing its write side is then the only
    /// legitimate `Ready(0)`; the splice loop stops reading under backpressure rather than ever passing an
    /// empty slice.
    ///
    /// # Errors
    /// Propagates a real read error (other than `EAGAIN`/`EWOULDBLOCK`).
    pub(crate) fn recv(&self, buf: &mut [MaybeUninit<u8>]) -> io::Result<IoStatus> {
        debug_assert!(
            !buf.is_empty(),
            "recv into an empty buffer returns 0, aliasing EOF"
        );
        // SAFETY: `buf` is a valid writable region of `buf.len()` bytes; `recv` writes only the `n` it
        // returns, leaving the rest untouched (still uninitialized).
        let n = unsafe {
            libc::recv(
                self.fd.as_raw_fd(),
                buf.as_mut_ptr().cast::<c_void>(),
                buf.len(),
                0,
            )
        };
        IoStatus::from_syscall(n)
    }

    /// Send as much of `buf` as the socket takes now — [`IoStatus::Ready(n)`](IoStatus) for `n` bytes
    /// taken, or `WouldBlock`. A write to a peer that has reset surfaces as an error, not `SIGPIPE` —
    /// Rust ignores `SIGPIPE` process-wide, so the `send` returns `EPIPE`.
    ///
    /// # Errors
    /// Propagates a real write error (other than `EAGAIN`/`EWOULDBLOCK`).
    pub(crate) fn send(&self, buf: &[u8]) -> io::Result<IoStatus> {
        // SAFETY: `buf` is a valid readable region of `buf.len()` bytes.
        let n = unsafe {
            libc::send(
                self.fd.as_raw_fd(),
                buf.as_ptr().cast::<c_void>(),
                buf.len(),
                0,
            )
        };
        IoStatus::from_syscall(n)
    }

    /// Send from several buffers in one `writev` (scatter-gather) — [`IoStatus::Ready(n)`](IoStatus)
    /// for `n` bytes taken, or `WouldBlock`. The proxy forwards a rewritten header and a zero-copy body
    /// slice in one syscall this way, without coalescing them. Like [`send`](Self::send), a write to a
    /// reset peer surfaces as `EPIPE`, not a signal.
    ///
    /// # Errors
    /// Propagates a real write error (other than `EAGAIN`/`EWOULDBLOCK`).
    pub(crate) fn send_vectored(&self, bufs: &[io::IoSlice<'_>]) -> io::Result<IoStatus> {
        let iovcnt = c_int::try_from(bufs.len()).unwrap_or(c_int::MAX);
        // SAFETY: `io::IoSlice` is ABI-compatible with `iovec`; `bufs.as_ptr()`/`iovcnt` describe a
        // valid array of that many slices for `writev`.
        let n = unsafe {
            libc::writev(
                self.fd.as_raw_fd(),
                bufs.as_ptr().cast::<libc::iovec>(),
                iovcnt,
            )
        };
        IoStatus::from_syscall(n)
    }

    /// Best-effort `shutdown(SHUT_RDWR)` — FIN both directions now rather than waiting for `Drop`, so a
    /// proxied peer isn't left hanging. An error (e.g. already disconnected) is ignored.
    pub(crate) fn shutdown(&self) {
        // SAFETY: `fd` is a valid socket; shutdown of an already-closed peer is a harmless error.
        unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_RDWR) };
    }

    /// Best-effort `shutdown(SHUT_WR)` — FIN our write half while leaving the read half open. The DIAL
    /// proxy uses this to signal one direction's end (a half-close) without tearing down the reverse
    /// direction, which keeps delivering to the half-closing peer. An error is ignored.
    pub(crate) fn shutdown_write(&self) {
        // SAFETY: `fd` is a valid socket; shutting an already-closed write half is a harmless error.
        unsafe { libc::shutdown(self.fd.as_raw_fd(), libc::SHUT_WR) };
    }
}

impl AsRawFd for TcpSocket {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

fn bind_v4(fd: RawFd, addr: Ipv4Addr, port: u16) -> io::Result<()> {
    let (storage, len) = sockaddr_for(IpAddr::V4(addr), port, 0);
    // SAFETY: `storage` is a valid `sockaddr_in` of length `len` for `fd`'s family.
    let rc = unsafe { libc::bind(fd, (&raw const storage).cast::<libc::sockaddr>(), len) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The IPv4 address `fd` is bound to, via `getsockname`.
fn local_addr_v4(fd: RawFd) -> io::Result<SocketAddrV4> {
    // SAFETY: an all-zero `sockaddr_storage` is a valid out-buffer; `getsockname` fills it + sets `len`.
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
    // SAFETY: an AF_INET socket's name is a `sockaddr_in`.
    let sin = unsafe { &*(&raw const storage).cast::<libc::sockaddr_in>() };
    let addr = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
    Ok(SocketAddrV4::new(addr, u16::from_be(sin.sin_port)))
}

/// Accept a pending connection on listener `fd` — close-on-exec + non-blocking — or `None` on
/// `WouldBlock` (nothing pending).
fn accept_fd(fd: RawFd) -> io::Result<Option<OwnedFd>> {
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    // SAFETY: null addr/len out-pointers are valid — we don't want the peer address.
    let raw = unsafe {
        libc::accept4(
            fd,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK,
        )
    };
    #[cfg(target_os = "macos")]
    // SAFETY: as above; the flags are applied below by `fcntl`.
    let raw = unsafe { libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut()) };
    if raw < 0 {
        let err = io::Error::last_os_error();
        if would_block(&err) {
            return Ok(None);
        }
        return Err(err);
    }
    // SAFETY: a non-negative `accept` return is a fresh fd we exclusively own.
    let fd = unsafe { OwnedFd::from_raw_fd(raw) };
    #[cfg(target_os = "macos")]
    crate::sys::set_cloexec_nonblock(fd.as_raw_fd())?;
    Ok(Some(fd))
}

/// Start a non-blocking connect to `dst`. `true` if it is still in progress (`EINPROGRESS`), `false` if
/// it completed immediately (e.g. a loopback connect).
fn connect_v4(fd: RawFd, dst: SocketAddrV4) -> io::Result<bool> {
    let (storage, len) = sockaddr_for(IpAddr::V4(*dst.ip()), dst.port(), 0);
    // SAFETY: `storage` is a valid `sockaddr_in` of length `len` for `fd`.
    let rc = unsafe { libc::connect(fd, (&raw const storage).cast::<libc::sockaddr>(), len) };
    if rc == 0 {
        return Ok(false);
    }
    let err = io::Error::last_os_error();
    if err.raw_os_error() == Some(libc::EINPROGRESS) {
        return Ok(true);
    }
    Err(err)
}

/// Read the socket's pending error (`SO_ERROR`) after a non-blocking connect's writable edge.
fn so_error(fd: RawFd) -> io::Result<c_int> {
    let mut err: c_int = 0;
    let mut len = socklen_of::<c_int>();
    // SAFETY: `&err`/`&len` are a valid (value, length) out-pair of `c_int` size for `fd`.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_ERROR,
            (&raw mut err).cast::<c_void>(),
            &raw mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(err)
}

/// Constrain `fd`'s egress to interface `ifindex` so a route lookup can't leak the connect onto the
/// wrong segment; `ifindex == 0` skips the pin. Linux uses `SO_BINDTODEVICE` (needs `CAP_NET_RAW`),
/// macOS `IP_BOUND_IF`. FreeBSD has no pin primitive, so the caller skips it and relies on the
/// source-address bind.
#[cfg(not(target_os = "freebsd"))]
fn pin_egress(fd: RawFd, ifindex: u32) -> io::Result<()> {
    if ifindex == 0 {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        // `SO_BINDTODEVICE` takes the interface name.
        let mut name = [0u8; libc::IF_NAMESIZE];
        // SAFETY: `name` is a writable `IF_NAMESIZE` buffer; `if_indextoname` fills it or returns null.
        if unsafe { libc::if_indextoname(ifindex, name.as_mut_ptr().cast::<libc::c_char>()) }
            .is_null()
        {
            return Err(io::Error::last_os_error());
        }
        let name_len = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        // SAFETY: `name[..name_len]` is the interface name of the passed length for `fd`.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_BINDTODEVICE,
                name.as_ptr().cast::<c_void>(),
                libc::socklen_t::try_from(name_len).expect("interface name length fits socklen_t"),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "macos")]
    {
        let index = c_int::try_from(ifindex).map_err(|_| io::Error::other("ifindex too large"))?;
        // SAFETY: `&index` is a valid `c_int` option value for `fd`.
        let rc = unsafe {
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_BOUND_IF,
                (&raw const index).cast::<c_void>(),
                socklen_of::<c_int>(),
            )
        };
        if rc != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;

    impl TcpSocket {
        /// Ergonomic recv into an initialized `[u8]` buffer — a thin wrapper over
        /// [`recv`](TcpSocket::recv) for tests that read into plain byte buffers.
        pub(crate) fn recv_bytes(&self, buf: &mut [u8]) -> io::Result<IoStatus> {
            // SAFETY: a `&mut [u8]` is a valid `&mut [MaybeUninit<u8>]` (an initialized byte is a valid
            // `MaybeUninit`, same layout); `recv` only writes into it.
            let buf = unsafe {
                std::slice::from_raw_parts_mut(
                    buf.as_mut_ptr().cast::<MaybeUninit<u8>>(),
                    buf.len(),
                )
            };
            self.recv(buf)
        }
    }

    /// Drive a non-blocking op to completion on loopback (no reactor in the test).
    fn spin<T>(mut op: impl FnMut() -> io::Result<Option<T>>) -> T {
        for _ in 0..2000 {
            if let Some(value) = op().expect("operation errored") {
                return value;
            }
            sleep(Duration::from_millis(1));
        }
        panic!("operation did not complete on loopback within the timeout");
    }

    #[test]
    fn loopback_listen_connect_accept_stream() {
        let listener = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("listen on loopback");
        let server_addr = listener.local_addr();
        assert_ne!(server_addr.port(), 0, "an ephemeral port is assigned");

        let mut client =
            TcpSocket::connect(server_addr, Ipv4Addr::LOCALHOST, 0).expect("connect to loopback");
        let server = spin(|| listener.accept()); // completes the handshake
        client.finish_connect().expect("the connect completed");
        assert!(!client.is_connecting());

        assert!(matches!(
            client.send(b"ping").expect("send"),
            IoStatus::Ready(4)
        ));
        let mut buf = [0u8; 16];
        let n = spin(|| match server.recv_bytes(&mut buf)? {
            IoStatus::Ready(0) => panic!("unexpected EOF before the payload"),
            IoStatus::Ready(n) => Ok(Some(n)),
            IoStatus::WouldBlock => Ok(None),
        });
        assert_eq!(&buf[..n], b"ping");
    }

    #[test]
    fn loopback_send_vectored_concatenates_the_slices() {
        let listener = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("listen on loopback");
        let mut client = TcpSocket::connect(listener.local_addr(), Ipv4Addr::LOCALHOST, 0)
            .expect("connect to loopback");
        let server = spin(|| listener.accept());
        client.finish_connect().expect("the connect completed");

        // A header and a body slice go out in one writev, arriving concatenated.
        let sent = client
            .send_vectored(&[io::IoSlice::new(b"head"), io::IoSlice::new(b"body")])
            .expect("send_vectored");
        assert!(matches!(sent, IoStatus::Ready(8)));
        let mut buf = [0u8; 16];
        let n = spin(|| match server.recv_bytes(&mut buf)? {
            IoStatus::Ready(0) => panic!("unexpected EOF before the payload"),
            IoStatus::Ready(n) => Ok(Some(n)),
            IoStatus::WouldBlock => Ok(None),
        });
        assert_eq!(&buf[..n], b"headbody");
    }

    #[test]
    fn shutdown_write_half_closes_keeping_the_read_half() {
        let listener = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("listen on loopback");
        let mut client =
            TcpSocket::connect(listener.local_addr(), Ipv4Addr::LOCALHOST, 0).expect("connect");
        let server = spin(|| listener.accept());
        client.finish_connect().expect("the connect completed");

        // The client shuts down its write half: the server reads EOF.
        client.shutdown_write();
        let mut buf = [0u8; 16];
        let eof = spin(|| match server.recv_bytes(&mut buf)? {
            IoStatus::Ready(n) => Ok(Some(n)),
            IoStatus::WouldBlock => Ok(None),
        });
        assert_eq!(
            eof, 0,
            "the server sees EOF after the client's write shutdown"
        );

        // The client's read half stays open: the server's reply still arrives.
        assert!(matches!(
            server.send(b"pong").expect("send"),
            IoStatus::Ready(4)
        ));
        let n = spin(|| match client.recv_bytes(&mut buf)? {
            IoStatus::Ready(0) => panic!("the client's read half closed unexpectedly"),
            IoStatus::Ready(n) => Ok(Some(n)),
            IoStatus::WouldBlock => Ok(None),
        });
        assert_eq!(&buf[..n], b"pong");
    }
}
