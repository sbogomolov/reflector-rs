//! The DIAL application proxy: one per device, a reactor [`Handler`] that fronts the device's HTTP
//! endpoints on the source subnet. It accepts a client on its description listener, opens an
//! egress-pinned connection to the device on the target subnet, and splices the two — rewriting
//! authorities so the device's address never leaks to the client.
//!
//! Lifecycle, dispatch, and the bidirectional byte splice: accept, egress-pinned connect, the
//! connect/idle deadlines, per-direction HTTP framing and forwarding (the request's `Host` rewritten
//! to the device), drop-and-close backpressure, teardown, and self-eviction. The response's
//! `Application-URL`/`Location` rewrite through a lazily-minted REST listener follows in the next step.

use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::net::http::framing::{HttpFraming, Kind};
use crate::net::stream_buffer::StreamBuffer;
use crate::net::tcp::TcpSocket;
use crate::reactor::{Arena, Handler, HandlerKey, Key, Reactor, ReadyEvent, RegKey};
use crate::sys::IoStatus;

/// Per-connection, per-direction receive buffer: one read chunk plus header accumulation.
const MAX_RECV: usize = 4 * 1024;
/// Per-connection, per-direction send buffer: the unsent tail held under backpressure; past it the
/// connection drops-and-closes.
const MAX_SEND: usize = 8 * 1024;
/// Cap on concurrent proxied connections (drop-new past it).
const MAX_CONNECTIONS: usize = 64;
/// A non-blocking device connect must complete within this.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// An open connection idle this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The receive buffer must exceed the framer's header cap, or the over-cap refusal can't fire before
/// the buffer fills and the always-armed reader livelocks.
const _: () = assert!(MAX_RECV > crate::net::http::framing::MAX_HEADER);

/// One direction of the duplex splice: its HTTP framer, the recv buffer (bytes read from the source
/// side), and the send buffer (the unsent tail to the destination side under backpressure).
struct Flow {
    framer: HttpFraming,
    recv: StreamBuffer,
    send: StreamBuffer,
}

impl Flow {
    fn new(kind: Kind) -> Self {
        Self {
            framer: HttpFraming::new(kind),
            recv: StreamBuffer::with_capacity(MAX_RECV),
            send: StreamBuffer::with_capacity(MAX_SEND),
        }
    }
}

/// A `Copy` handle into the proxy's connection [`Arena`] — a newtype over the arena [`Key`] so it
/// can't be confused with the reactor's keys. It is the unit that round-trips through a watched fd's
/// `user_data`: the reactor echoes it back on every event, and dispatch decodes it to find the flow.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
struct ConnectionKey(Key);

impl ConnectionKey {
    /// Pack into a watch's `user_data`.
    fn to_u64(self) -> u64 {
        self.0.to_u64()
    }

    /// Unpack from a dispatched event's `user_data`.
    fn from_u64(packed: u64) -> Self {
        Self(Key::from_u64(packed))
    }
}

/// One proxied client↔device connection. Each socket is watched under its own reg; `device_endpoint`
/// is where `device` connects and the `Host` rewrite target. `deadline` is the connect timeout while
/// the device connect is in flight, then the idle timeout. The regs are `None` only between insert and
/// watch in [`start_connection`](DialDeviceProxy::start_connection); every event sees them set.
struct Connection {
    client: TcpSocket,
    client_reg: Option<RegKey>,
    device: TcpSocket,
    device_reg: Option<RegKey>,
    device_endpoint: SocketAddrV4,
    c2u: Flow, // client -> device
    u2c: Flow, // device -> client
    deadline: Instant,
}

/// Which way bytes flow on one edge of the splice. `ClientToDevice` is the `c2u` flow — a request read
/// from the client and forwarded to the device (its `Host` rewritten); `DeviceToClient` is `u2c` — a
/// response read from the device and forwarded to the client (verbatim).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToDevice,
    DeviceToClient,
}

/// One `Direction` resolved against a connection: the socket to read from, the socket to forward to
/// (and its registration), that direction's framing and buffers, and the rewrite to apply. Built once
/// per event by [`Connection::context`] so the forward/drain paths never re-pick a side.
struct DirectionContext<'a> {
    from: &'a TcpSocket,
    to: &'a TcpSocket,
    to_reg: Option<RegKey>,
    flow: &'a mut Flow,
    host_rewrite: Option<SocketAddrV4>,
    deadline: &'a mut Instant,
}

impl Connection {
    /// The resolved view for `direction` — the sockets, registration, flow, rewrite, and deadline it
    /// touches — so the forward/drain paths operate without re-picking a side.
    fn context(&mut self, direction: Direction) -> DirectionContext<'_> {
        match direction {
            Direction::ClientToDevice => DirectionContext {
                from: &self.client,
                to: &self.device,
                to_reg: self.device_reg,
                flow: &mut self.c2u,
                host_rewrite: Some(self.device_endpoint),
                deadline: &mut self.deadline,
            },
            Direction::DeviceToClient => DirectionContext {
                from: &self.device,
                to: &self.client,
                to_reg: self.client_reg,
                flow: &mut self.u2c,
                host_rewrite: None,
                deadline: &mut self.deadline,
            },
        }
    }

    /// Forward one readable edge in `direction`, then arm the destination's write interest iff an
    /// unsent backlog remains. Returns `true` to close.
    fn forward(&mut self, direction: Direction, reactor: &mut Reactor) -> bool {
        let mut ctx = self.context(direction);
        if ctx.forward() {
            return true;
        }
        ctx.sync_write_interest(reactor)
    }

    /// A connection socket is writable: complete the device connect if still pending, drain
    /// `direction`'s send backlog, then leave its write interest armed iff a backlog remains (so a
    /// fully-drained buffer disarms — including the bare connect-completion case). Returns `true` to
    /// close.
    fn on_writable(&mut self, direction: Direction, reactor: &mut Reactor) -> bool {
        if direction == Direction::ClientToDevice && self.device.is_connecting() {
            match self.device.finish_connect() {
                Ok(()) => self.deadline = Instant::now() + IDLE_TIMEOUT,
                Err(e) => {
                    log::warn!(
                        "dial: device connect to {} failed: {e}",
                        self.device_endpoint
                    );
                    return true;
                }
            }
        }
        let mut ctx = self.context(direction);
        if ctx.drain() {
            return true;
        }
        ctx.sync_write_interest(reactor)
    }
}

impl DirectionContext<'_> {
    /// Read one chunk from the source, frame whole messages out of this direction's buffer, and forward
    /// each — rewriting `Host` when set — to the destination, buffering any unsent tail in the send
    /// buffer for the writable edge to drain. The deadline is refreshed (by the senders) only when bytes
    /// actually reach the destination, so a wedged one still ages out via the idle sweep. Returns `true`
    /// to close: peer EOF, a framing/recv/send error, or a backpressure overflow. Reactor-free, so the
    /// splice is unit-testable without standing up a reactor.
    fn forward(&mut self) -> bool {
        let tail = self.flow.recv.free_tail_mut();
        if tail.is_empty() {
            log::warn!("dial: receive buffer full of an unframable message; closing");
            return true;
        }
        let n = match self.from.recv(tail) {
            Ok(IoStatus::Ready(0)) => return true, // peer half-closed: tear the splice down
            Ok(IoStatus::Ready(n)) => n,
            Ok(IoStatus::WouldBlock) => return false, // a spurious wake, nothing new
            Err(e) => {
                log::debug!("dial: recv failed: {e}");
                return true;
            }
        };
        self.flow.recv.commit(n);
        loop {
            let framed = match self
                .flow
                .framer
                .feed(self.flow.recv.pending(), self.host_rewrite)
            {
                Ok(framed) => framed,
                Err(e) => {
                    log::debug!("dial: framing error: {e:?}");
                    return true;
                }
            };
            if framed.consumed == 0 {
                break; // an incomplete message: wait for more bytes
            }
            let consumed = framed.consumed;
            if send_framed(
                self.to,
                &mut self.flow.send,
                framed.header,
                framed.body,
                self.deadline,
            ) {
                return true;
            }
            self.flow.recv.consume(consumed);
        }
        false
    }

    /// Drain as much of this direction's send backlog as the destination will take now, refreshing the
    /// deadline on real progress. Returns `true` to close on a send error; the caller re-evaluates write
    /// interest from the buffer's emptiness.
    fn drain(&mut self) -> bool {
        if self.flow.send.is_empty() {
            return false;
        }
        match self.to.send(self.flow.send.pending()) {
            Ok(IoStatus::Ready(n)) => {
                self.flow.send.consume(n);
                if n > 0 {
                    *self.deadline = Instant::now() + IDLE_TIMEOUT;
                }
                false
            }
            Ok(IoStatus::WouldBlock) => false,
            Err(e) => {
                log::debug!("dial: draining send to peer failed: {e}");
                true
            }
        }
    }

    /// Arm the destination's write interest to match its send backlog (armed iff non-empty). Returns
    /// `true` to close: the reactor rejected the change, which would otherwise strand the buffered send
    /// with no later re-arm for a quiet reader.
    fn sync_write_interest(&self, reactor: &mut Reactor) -> bool {
        let backlog = !self.flow.send.is_empty();
        let reg = self
            .to_reg
            .expect("a persisted connection has its registration set");
        if reactor.set_write_interest(reg, backlog).is_err() {
            log::warn!("dial: updating write interest failed; closing");
            return true;
        }
        false
    }
}

/// Send `header` then `body` to `to`, preserving order: if `to` already has a backlog or is still
/// connecting, the whole message is buffered; otherwise it goes out in one scatter-gather write and
/// only the unsent tail is buffered. Refreshes `deadline` when bytes reach the socket. Returns `true`
/// to close — a send error or a buffer overflow (drop-and-close backpressure; the reader is never
/// throttled).
fn send_framed(
    to: &TcpSocket,
    to_send: &mut StreamBuffer,
    header: &[u8],
    body: &[u8],
    deadline: &mut Instant,
) -> bool {
    if !to_send.is_empty() || to.is_connecting() {
        return buffer_tail(to_send, header, body);
    }
    let total = header.len() + body.len();
    let sent = match to.send_vectored(&[io::IoSlice::new(header), io::IoSlice::new(body)]) {
        Ok(IoStatus::Ready(n)) => n,
        Ok(IoStatus::WouldBlock) => 0,
        Err(e) => {
            log::debug!("dial: send to peer failed: {e}");
            return true;
        }
    };
    if sent > 0 {
        // Bytes reached the destination — real forward progress, so hold off the idle timeout.
        *deadline = Instant::now() + IDLE_TIMEOUT;
    }
    if sent == total {
        return false;
    }
    let (header_tail, body_tail) = split_remainder(header, body, sent);
    buffer_tail(to_send, header_tail, body_tail)
}

/// Append the unsent `header`/`body` remainder to `to_send`; `true` if it overflows the cap (close).
fn buffer_tail(to_send: &mut StreamBuffer, header: &[u8], body: &[u8]) -> bool {
    if to_send.append(header).is_err() || to_send.append(body).is_err() {
        log::warn!("dial: send buffer overflow; closing");
        return true;
    }
    false
}

/// Split a `header`+`body` pair at the `sent` bytes already written front-to-back, giving the unsent
/// remainder of each. A single `writev` count can land inside either slice, so the boundary is found
/// against the header length.
fn split_remainder<'a>(header: &'a [u8], body: &'a [u8], sent: usize) -> (&'a [u8], &'a [u8]) {
    if sent >= header.len() {
        (&[], &body[sent - header.len()..])
    } else {
        (&header[sent..], body)
    }
}

/// A per-device DIAL proxy — a reactor `Handler` owning a description listener and its connections.
pub(crate) struct DialDeviceProxy {
    /// This handler's own key, learned via [`adopt_key`](Handler::adopt_key); used to watch fds it
    /// opens and to self-unregister.
    key: Option<HandlerKey>,
    /// The source-interface address the description (and REST) listener binds — clients reach the
    /// proxy here.
    source: Ipv4Addr,
    /// The target-interface address device connections bind, so the device sees a same-segment peer
    /// and replies via the target interface (on the BSDs the bind is the only egress steer).
    target: Ipv4Addr,
    /// The target interface index, egress-pinning device connections to that segment.
    target_ifindex: u32,
    /// The description listener (source side); its connections proxy to `desc_device`.
    desc: TcpSocket,
    /// The device's description endpoint (`device-ip:desc_port`) — the proxy's identity.
    desc_device: SocketAddrV4,
    /// The instant the description listener may be reaped after, once idle — the advertisement's
    /// `max-age`, refreshed on re-advertisement.
    desc_grace: Instant,
    conns: Arena<Connection>,
}

impl DialDeviceProxy {
    /// A proxy fronting `desc_device` via the source-side `desc` listener. Device connections bind the
    /// target-interface `target` and egress-pin `target_ifindex`; `desc_grace` is when the listener may
    /// be reaped after once idle.
    pub(crate) fn new(
        source: Ipv4Addr,
        target: Ipv4Addr,
        target_ifindex: u32,
        desc: TcpSocket,
        desc_device: SocketAddrV4,
        desc_grace: Instant,
    ) -> Self {
        Self {
            key: None,
            source,
            target,
            target_ifindex,
            desc,
            desc_device,
            desc_grace,
            conns: Arena::new(),
        }
    }

    /// This handler's own key. `adopt_key` sets it at registration — before the reactor dispatches any
    /// event — so every method that runs has it; its absence would be a reactor-contract violation.
    fn own_key(&self) -> HandlerKey {
        self.key
            .expect("adopt_key sets the proxy's key before any dispatch")
    }

    /// Accept one pending client on the description listener and start its proxied connection. The
    /// listener is non-blocking, so a level-triggered wait re-fires while more wait; an accept is
    /// always taken (draining the readiness) even at the connection cap, where the client is dropped.
    fn accept(&mut self, reactor: &mut Reactor) {
        let client = match self.desc.accept() {
            Ok(Some(client)) => client,
            Ok(None) => return, // spurious / already taken
            Err(e) => {
                log::warn!("dial: accept on the description listener failed: {e}");
                return;
            }
        };
        if self.conns.iter().count() >= MAX_CONNECTIONS {
            log::warn!("dial: connection cap ({MAX_CONNECTIONS}) reached; dropping a new client");
            return; // `client` drops here, closing it
        }
        let device = self.desc_device;
        self.start_connection(client, device, reactor);
    }

    /// Open an egress-pinned connection to `device_endpoint`, register both fds, and record the
    /// connection. Best-effort: a connect or watch failure drops the half-built connection.
    fn start_connection(
        &mut self,
        client: TcpSocket,
        device_endpoint: SocketAddrV4,
        reactor: &mut Reactor,
    ) {
        let key = self.own_key();
        let device = match TcpSocket::connect(device_endpoint, self.target, self.target_ifindex) {
            Ok(device) => device,
            Err(e) => {
                log::warn!("dial: connect to {device_endpoint} failed: {e}");
                return;
            }
        };
        let client_fd = client.as_raw_fd();
        let device_fd = device.as_raw_fd();
        // Insert first so the connection's arena key can tag both fds' `user_data`; the regs are
        // patched in once watching succeeds.
        let conn_key = ConnectionKey(self.conns.insert(Connection {
            client,
            client_reg: None,
            device,
            device_reg: None,
            device_endpoint,
            c2u: Flow::new(Kind::Request),
            u2c: Flow::new(Kind::Response),
            deadline: Instant::now() + CONNECT_TIMEOUT,
        }));
        let user_data = conn_key.to_u64();
        let client_reg = match reactor.watch(key, client_fd, user_data) {
            Ok(reg) => reg,
            Err(e) => {
                log::warn!("dial: watching the client fd failed: {e}");
                self.close_conn(conn_key, reactor);
                return;
            }
        };
        let device_reg = match reactor.watch(key, device_fd, user_data) {
            Ok(reg) => reg,
            Err(e) => {
                log::warn!("dial: watching the device fd failed: {e}");
                reactor.unwatch(client_reg).ok();
                self.close_conn(conn_key, reactor);
                return;
            }
        };
        // Arm the device's write interest so its connect completion (a writable edge) is delivered.
        reactor.set_write_interest(device_reg, true).ok();
        let conn = self
            .conns
            .get_mut(conn_key.0)
            .expect("the just-inserted connection is present");
        conn.client_reg = Some(client_reg);
        conn.device_reg = Some(device_reg);
        log::debug!("dial: accepted a client; connecting to {device_endpoint}");
    }

    /// A connection socket is readable: forward one edge in the matching direction; close on EOF or a
    /// fatal error.
    fn on_connection_readable(
        &mut self,
        conn_key: ConnectionKey,
        fd: RawFd,
        reactor: &mut Reactor,
    ) {
        let close = {
            let Some(conn) = self.conns.get_mut(conn_key.0) else {
                log::trace!("dial: readable event for an unknown connection; ignoring");
                return;
            };
            // The readable fd is the source: reading the client forwards to the device (c2u).
            let direction = if conn.client.as_raw_fd() == fd {
                Direction::ClientToDevice
            } else {
                Direction::DeviceToClient
            };
            conn.forward(direction, reactor)
        };
        if close {
            self.close_conn(conn_key, reactor);
        }
    }

    /// A connection socket is writable: complete the connect / drain its send backlog; close on error.
    fn on_connection_writable(
        &mut self,
        conn_key: ConnectionKey,
        fd: RawFd,
        reactor: &mut Reactor,
    ) {
        let close = {
            let Some(conn) = self.conns.get_mut(conn_key.0) else {
                // The reactor filters stale registrations, so a live write event should map to a live
                // connection; a miss means the generational key out-lived its slot — fail safe.
                log::trace!("dial: writable event for an unknown connection; ignoring");
                return;
            };
            // The writable fd is the destination: draining toward the device is the c2u flow's send.
            let direction = if conn.device.as_raw_fd() == fd {
                Direction::ClientToDevice
            } else {
                Direction::DeviceToClient
            };
            conn.on_writable(direction, reactor)
        };
        if close {
            self.close_conn(conn_key, reactor);
        }
    }

    /// Tear down the connection `conn_key` addresses: drop each watched fd's kernel interest, then
    /// shut both sockets down. Every caller holds a live key (just inserted, just matched, or from a
    /// live sweep), so the connection is present; a half-built one may have no registrations yet.
    fn close_conn(&mut self, conn_key: ConnectionKey, reactor: &mut Reactor) {
        let conn = self
            .conns
            .remove(conn_key.0)
            .expect("close_conn's callers hold a live connection key");
        if let Some(reg) = conn.client_reg {
            reactor.unwatch(reg).ok();
        }
        if let Some(reg) = conn.device_reg {
            reactor.unwatch(reg).ok();
        }
        conn.client.shutdown();
        conn.device.shutdown();
        log::debug!("dial: closed a connection to {}", conn.device_endpoint);
    }

    /// Close connections past their deadline (connect timeout or idle), then self-unregister once
    /// idle past the description grace — the device's advertised validity has lapsed with no traffic.
    fn sweep(&mut self, now: Instant, reactor: &mut Reactor) {
        let expired: Vec<(ConnectionKey, SocketAddrV4)> = self
            .conns
            .iter()
            .filter(|(_, conn)| now >= conn.deadline)
            .map(|(key, conn)| (ConnectionKey(key), conn.device_endpoint))
            .collect();
        for (conn_key, device_endpoint) in expired {
            log::debug!("dial: connection to {device_endpoint} timed out");
            self.close_conn(conn_key, reactor);
        }
        if self.conns.iter().next().is_none() && now >= self.desc_grace {
            log::debug!("dial: idle past its grace; evicting the proxy");
            reactor.unregister(self.own_key()).ok();
        }
    }
}

impl Handler for DialDeviceProxy {
    fn adopt_key(&mut self, key: HandlerKey) {
        self.key = Some(key);
    }

    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        if event.fd == self.desc.as_raw_fd() {
            self.accept(reactor);
        } else {
            self.on_connection_readable(
                ConnectionKey::from_u64(event.user_data),
                event.fd,
                reactor,
            );
        }
    }

    fn on_writable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        // Listeners never arm write interest, so a writable edge is always a connection socket.
        self.on_connection_writable(ConnectionKey::from_u64(event.user_data), event.fd, reactor);
    }

    fn next_deadline(&self) -> Option<Instant> {
        // While connections are live, wake at the soonest; otherwise wake at the description grace to
        // self-reap once the device's advertised validity has lapsed.
        self.conns
            .iter()
            .map(|(_, conn)| conn.deadline)
            .min()
            .or(Some(self.desc_grace))
    }

    fn on_deadline(&mut self, now: Instant, reactor: &mut Reactor) {
        self.sweep(now, reactor);
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::*;

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

    /// A connected loopback TCP pair: `(initiator, accepted)`.
    fn connected_pair() -> (TcpSocket, TcpSocket) {
        let listener = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("listen on loopback");
        let mut initiator =
            TcpSocket::connect(listener.local_addr(), Ipv4Addr::LOCALHOST, 0).expect("connect");
        let accepted = spin(|| listener.accept());
        initiator.finish_connect().expect("the connect completed");
        (initiator, accepted)
    }

    /// Drive `forward_dir` until the message it forwards arrives at `peer_out`, and return those bytes.
    fn drive_forward(
        from: &TcpSocket,
        to: &TcpSocket,
        flow: &mut Flow,
        rewrite: Option<SocketAddrV4>,
        peer_out: &TcpSocket,
    ) -> Vec<u8> {
        let mut deadline = Instant::now();
        let mut buf = [0u8; 1024];
        for _ in 0..2000 {
            let mut ctx = DirectionContext {
                from,
                to,
                to_reg: None,
                flow: &mut *flow,
                host_rewrite: rewrite,
                deadline: &mut deadline,
            };
            assert!(
                !ctx.forward(),
                "forward should not close on a clean message"
            );
            match peer_out.recv(&mut buf).expect("recv on the peer") {
                IoStatus::Ready(0) => panic!("unexpected EOF before the forwarded bytes"),
                IoStatus::Ready(n) => return buf[..n].to_vec(),
                IoStatus::WouldBlock => sleep(Duration::from_millis(1)),
            }
        }
        panic!("the forwarded bytes never arrived on loopback");
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack.windows(needle.len()).any(|w| w == needle)
    }

    #[test]
    fn split_remainder_when_the_header_is_fully_sent() {
        let (header, body) = split_remainder(b"head", b"body", 6); // 4 header + 2 body written
        assert_eq!(header, b"");
        assert_eq!(body, b"dy");
    }

    #[test]
    fn split_remainder_when_the_header_is_partly_sent() {
        let (header, body) = split_remainder(b"head", b"body", 2);
        assert_eq!(header, b"ad");
        assert_eq!(body, b"body");
    }

    #[test]
    fn forward_dir_frames_a_request_and_rewrites_host() {
        let (peer_in, from) = connected_pair(); // peer_in -> from (the client side)
        let (to, peer_out) = connected_pair(); // to -> peer_out (the device side)
        let device = SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 8008);
        assert!(matches!(
            peer_in
                .send(b"GET /apps HTTP/1.1\r\nHost: 192.168.1.2:80\r\n\r\n")
                .expect("send the request"),
            IoStatus::Ready(_)
        ));
        let mut flow = Flow::new(Kind::Request);
        let got = drive_forward(&from, &to, &mut flow, Some(device), &peer_out);
        assert!(
            got.starts_with(b"GET /apps HTTP/1.1\r\n"),
            "request line preserved: {:?}",
            String::from_utf8_lossy(&got)
        );
        assert!(
            contains(&got, b"Host: 10.0.0.5:8008\r\n"),
            "Host rewritten to the device: {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    #[test]
    fn forward_dir_forwards_a_response_verbatim() {
        let (peer_in, from) = connected_pair();
        let (to, peer_out) = connected_pair();
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\
             Application-URL: http://192.168.1.2:8008/apps\r\n\r\nhello";
        assert!(matches!(
            peer_in
                .send(response.as_bytes())
                .expect("send the response"),
            IoStatus::Ready(_)
        ));
        let mut flow = Flow::new(Kind::Response);
        let got = drive_forward(&from, &to, &mut flow, None, &peer_out);
        // u2c is verbatim for now: the device's Application-URL passes through untouched.
        assert!(
            contains(&got, b"Application-URL: http://192.168.1.2:8008/apps\r\n"),
            "response forwarded verbatim: {:?}",
            String::from_utf8_lossy(&got)
        );
        assert!(got.ends_with(b"hello"), "body forwarded: {got:?}");
    }
}
