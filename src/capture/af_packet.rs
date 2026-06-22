//! `AF_PACKET` packet capture (Linux).
//!
//! Opens a raw `AF_PACKET` socket, attaches a UDP-only classic-BPF filter, and
//! binds it to an interface. Unlike the BSD BPF backend, one `recv` returns exactly
//! one frame, so there is no batch to walk.
//!
//! Init order matters: the socket opens with protocol 0, capturing nothing, so the
//! filter and the loop-prevention option install *before* `bind` sets the real
//! protocol and starts delivery — there is no window in which unfiltered frames
//! (e.g. IGMP from a multicast join) queue. (The BSD backend instead binds first
//! and relies on `BIOCSETF` flushing the kernel buffer.)

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::{c_int, c_void, socklen_t};

use super::LinkType;
use super::filter::{BpfInsn, DROP_OUTGOING_PROLOGUE, ETHERNET_UDP_FILTER};

/// Receive buffer sized for one frame at a typical Ethernet MTU plus headers.
const RECV_BUFFER_SIZE: usize = 4096;

/// The fallback filter length: the egress-drop prologue plus the UDP classifier.
const DROP_OUTGOING_FILTER_LEN: usize = DROP_OUTGOING_PROLOGUE.len() + ETHERNET_UDP_FILTER.len();

/// A raw-capture handle on one interface: an owned `AF_PACKET` fd, a reused read
/// buffer, and the prebuilt `sockaddr_ll` it injects to.
pub(crate) struct Capture {
    fd: OwnedFd,
    buf: Box<[u8]>,
    send_addr: libc::sockaddr_ll,
}

impl Capture {
    /// Open an `AF_PACKET` capture bound to `if_name`.
    ///
    /// # Errors
    /// Returns an error if the interface is unknown, the socket can't be created,
    /// the filter can't be attached, or the bind fails.
    pub(crate) fn open(if_name: &str) -> io::Result<Self> {
        let ifindex = if_index(if_name)?;
        let send_addr = link_addr(ifindex);

        // Protocol 0: capture nothing until the filter + loop-prevention are in place.
        // SAFETY: a `socket` call with a valid domain/type/protocol; returns a fresh
        // fd or -1.
        let raw = unsafe {
            libc::socket(
                libc::AF_PACKET,
                libc::SOCK_RAW | libc::SOCK_NONBLOCK | libc::SOCK_CLOEXEC,
                0,
            )
        };
        if raw < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: `socket` returned a fresh owned fd.
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };

        // Loop prevention: stop the kernel from handing us our own injected frames.
        // PACKET_IGNORE_OUTGOING (Linux 4.20+) drops them at the socket; if the kernel
        // lacks it (or user-mode QEMU rejects it), prepend an in-filter drop instead.
        if set_ignore_outgoing(&fd).is_ok() {
            attach_filter(&fd, &ETHERNET_UDP_FILTER)?;
        } else {
            log::info!(
                "PACKET_IGNORE_OUTGOING unavailable; dropping our own frames in the BPF filter"
            );
            attach_filter(&fd, &drop_outgoing_filter())?;
        }

        // Start capturing: bind to the interface with ETH_P_ALL. The filter is already
        // installed, so there is no unfiltered-capture window.
        bind_interface(&fd, send_addr)?;

        log::debug!(
            "opened AF_PACKET capture on {if_name} (fd {}, ifindex {ifindex})",
            fd.as_raw_fd()
        );
        Ok(Self {
            fd,
            buf: vec![0u8; RECV_BUFFER_SIZE].into_boxed_slice(),
            send_addr,
        })
    }

    /// The link framing — always Ethernet on Linux, loopback included.
    #[allow(clippy::unused_self)] // uniform Capture API; the BPF backend reads self
    pub(crate) fn link_type(&self) -> LinkType {
        LinkType::Ethernet
    }

    /// The next captured frame, or `Ok(None)` when a read would block. Oversized
    /// frames (larger than the receive buffer) are dropped and the next is returned.
    ///
    /// # Errors
    /// Returns an error if the `recv` fails for any reason other than would-block.
    pub(crate) fn next_frame(&mut self) -> io::Result<Option<&[u8]>> {
        let len = loop {
            let Some(bytes) = self.recv_once()? else {
                return Ok(None);
            };
            // MSG_TRUNC reports the frame's real length even past the buffer, so an
            // oversized frame is detectable (and dropped) instead of silently cut.
            if bytes > self.buf.len() {
                log::warn!(
                    "dropping oversized frame: {bytes} bytes exceeds the {}-byte receive buffer",
                    self.buf.len()
                );
                continue;
            }
            break bytes;
        };
        Ok(Some(&self.buf[..len]))
    }

    /// Whether frames are buffered locally — never, for `AF_PACKET`: each `recv` is
    /// one frame, so a level-triggered wait re-fires while the socket has more.
    #[allow(clippy::unused_self)] // uniform Capture API; the BPF backend reads self
    pub(crate) fn has_buffered(&self) -> bool {
        false
    }

    /// Inject a fully-built link-layer `frame` on this interface.
    ///
    /// # Errors
    /// Returns an error if the send fails or is short.
    pub(crate) fn send(&self, frame: &[u8]) -> io::Result<()> {
        // SOCK_RAW carries the whole L2 frame, so the kernel needs only the egress
        // interface (the prebuilt `send_addr`); the destination MAC is in the frame.
        // SAFETY: `frame` is a valid readable slice; `send_addr` is a fully-initialized
        // `sockaddr_ll` of the given length.
        let sent = unsafe {
            libc::sendto(
                self.fd.as_raw_fd(),
                frame.as_ptr().cast::<c_void>(),
                frame.len(),
                0,
                (&raw const self.send_addr).cast::<libc::sockaddr>(),
                socklen_of::<libc::sockaddr_ll>(),
            )
        };
        if sent < 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(sent).expect("send result is non-negative") != frame.len() {
            return Err(io::Error::other("short send to AF_PACKET socket"));
        }
        Ok(())
    }

    /// One `recv` into the buffer, retrying on `EINTR`. Returns `Ok(None)` when it
    /// would block, or the frame's real length (which may exceed the buffer, since
    /// `MSG_TRUNC` is set — the caller treats that as an oversized frame).
    fn recv_once(&mut self) -> io::Result<Option<usize>> {
        loop {
            // SAFETY: `recv` writes up to `buf.len()` bytes into our own buffer.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast::<c_void>(),
                    self.buf.len(),
                    libc::MSG_TRUNC,
                )
            };
            if n >= 0 {
                return Ok(Some(
                    usize::try_from(n).expect("recv result is non-negative"),
                ));
            }
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error();
            if errno == Some(libc::EINTR) {
                continue;
            }
            if errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK) {
                return Ok(None);
            }
            return Err(err);
        }
    }
}

impl AsRawFd for Capture {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// [`DROP_OUTGOING_PROLOGUE`] followed by [`ETHERNET_UDP_FILTER`] — the
/// loop-prevention fallback for kernels without `PACKET_IGNORE_OUTGOING`.
fn drop_outgoing_filter() -> [BpfInsn; DROP_OUTGOING_FILTER_LEN] {
    std::array::from_fn(|i| match DROP_OUTGOING_PROLOGUE.get(i) {
        Some(&prologue_insn) => prologue_insn,
        None => ETHERNET_UDP_FILTER[i - DROP_OUTGOING_PROLOGUE.len()],
    })
}

/// A zeroed `sockaddr_ll` addressed to `ifindex` (family set, protocol left zero).
fn link_addr(ifindex: c_int) -> libc::sockaddr_ll {
    // SAFETY: all-zero is a valid `sockaddr_ll` — integer and byte-array fields only.
    let mut addr: libc::sockaddr_ll = unsafe { core::mem::zeroed() };
    addr.sll_family = u16::try_from(libc::AF_PACKET).expect("AF_PACKET fits u16");
    addr.sll_ifindex = ifindex;
    addr
}

/// Resolve an interface name to its kernel index.
fn if_index(if_name: &str) -> io::Result<c_int> {
    let cname = CString::new(if_name).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "interface name contains a NUL")
    })?;
    // SAFETY: `cname` is a valid NUL-terminated C string for the call's duration.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if index == 0 {
        // POSIX: 0 is never a valid index; `if_nametoindex` set errno.
        return Err(io::Error::last_os_error());
    }
    c_int::try_from(index).map_err(|_| io::Error::other("interface index too large"))
}

/// Ask the kernel to drop locally-sent frames on this socket (`PACKET_IGNORE_OUTGOING`).
fn set_ignore_outgoing(fd: &OwnedFd) -> io::Result<()> {
    let on: c_int = 1;
    // SAFETY: a `setsockopt` with a `c_int` option value and its matching length.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_PACKET,
            libc::PACKET_IGNORE_OUTGOING,
            (&raw const on).cast::<c_void>(),
            socklen_of::<c_int>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Attach a classic-BPF `filter` to the socket via `SO_ATTACH_FILTER`.
fn attach_filter(fd: &OwnedFd, filter: &[BpfInsn]) -> io::Result<()> {
    let program = libc::sock_fprog {
        len: u16::try_from(filter.len()).expect("filter length fits u16"),
        // BpfInsn is layout-identical to sock_filter (anchored in `filter`); the
        // kernel only reads the program, so the const-to-mut cast is sound.
        filter: filter.as_ptr().cast::<libc::sock_filter>().cast_mut(),
    };
    // SAFETY: a `setsockopt` with a `sock_fprog` pointing at `filter`, valid for the
    // duration of the call.
    let rc = unsafe {
        libc::setsockopt(
            fd.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_ATTACH_FILTER,
            (&raw const program).cast::<c_void>(),
            socklen_of::<libc::sock_fprog>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Bind to the interface in `addr`, adding the capture protocol `ETH_P_ALL`.
fn bind_interface(fd: &OwnedFd, mut addr: libc::sockaddr_ll) -> io::Result<()> {
    addr.sll_protocol = u16::try_from(libc::ETH_P_ALL)
        .expect("ETH_P_ALL fits u16")
        .to_be();
    // SAFETY: `addr` is a fully-initialized `sockaddr_ll` of the given length.
    let rc = unsafe {
        libc::bind(
            fd.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            socklen_of::<libc::sockaddr_ll>(),
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// The size of `T` as a `socklen_t`, for `setsockopt`/`bind` length arguments.
fn socklen_of<T>() -> socklen_t {
    socklen_t::try_from(size_of::<T>()).expect("option/address size fits socklen_t")
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, SocketAddrV4, UdpSocket};

    use super::*;
    use crate::capture::open_or_skip;
    use crate::net::frame;
    use crate::net::mac::MacAddr;

    #[test]
    fn drop_outgoing_filter_prepends_the_prologue() {
        let filter = drop_outgoing_filter();
        assert_eq!(
            &filter[..DROP_OUTGOING_PROLOGUE.len()],
            &DROP_OUTGOING_PROLOGUE
        );
        assert_eq!(
            &filter[DROP_OUTGOING_PROLOGUE.len()..],
            &ETHERNET_UDP_FILTER
        );
    }

    // Live capture against the real kernel: send UDP to 127.0.0.1 and capture the
    // looped frame off `lo`. Validates the open/filter/bind/recv path and that lo
    // is Ethernet-framed. PACKET_IGNORE_OUTGOING drops the TX copy; we see the RX one.
    #[test]
    fn captures_a_known_frame_on_lo() -> io::Result<()> {
        const PROBE: &[u8] = b"reflector-afpacket-capture-probe";
        let Some(mut capture) = open_or_skip("lo", "afpacket_capture")? else {
            return Ok(());
        };
        assert_eq!(capture.link_type(), LinkType::Ethernet);

        let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
        let target = receiver.local_addr().unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").unwrap();

        // An lo frame is [14-byte Ethernet][IPv4][UDP][payload]; finding our payload
        // at the tail behind an IPv4/IPv6 ethertype proves the layout decoded.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut decoded = false;
        while !decoded && std::time::Instant::now() < deadline {
            sender.send_to(PROBE, target).unwrap();
            while let Some(frame) = capture.next_frame()? {
                if frame.len() >= 14 && frame.ends_with(PROBE) {
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    assert!(ethertype == 0x0800 || ethertype == 0x86dd);
                    decoded = true;
                    break;
                }
            }
            if !decoded {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        assert!(decoded, "did not capture our UDP probe on lo");
        Ok(())
    }

    // Live send: inject a built Ethernet frame on `lo` via send(), then capture it
    // back. lo loops every transmitted frame to its input tap, and we keep the RX
    // copy (PACKET_IGNORE_OUTGOING drops only the TX copy) — so this validates that
    // send() actually puts the frame on the wire. (Whether the local IP stack then
    // delivers a raw-injected loopback frame to a socket is kernel-specific, and not
    // what send() is for: on a real interface it reaches other hosts, not us.)
    #[test]
    fn send_loops_back_on_lo() -> io::Result<()> {
        const PROBE: &[u8] = b"reflector-afpacket-send-probe";
        let Some(mut capture) = open_or_skip("lo", "afpacket_send")? else {
            return Ok(());
        };

        let src = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40000);
        let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 40001);
        let mac = MacAddr::broadcast();
        let mut buf = [0u8; 256];
        let n = frame::ethernet_ipv4_udp(mac, mac, src, dst, 64, PROBE, &mut buf)
            .expect("build Ethernet frame");

        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut looped = false;
        while !looped && std::time::Instant::now() < deadline {
            capture.send(&buf[..n]).expect("send on lo");
            while let Some(frame) = capture.next_frame()? {
                if frame.ends_with(PROBE) {
                    looped = true;
                    break;
                }
            }
            if !looped {
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        }
        assert!(
            looped,
            "did not capture our injected frame looped back on lo"
        );
        Ok(())
    }
}
