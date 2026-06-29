//! One proxied client↔device connection: the bidirectional HTTP byte splice.
//!
//! Each [`Connection`] pairs two sockets with a per-direction [`Flow`] — an HTTP framer plus a receive
//! and a send buffer — and drives them on the reactor's readable/writable edges. A readable edge frames
//! whole messages out of the source, rewrites their authority headers per the direction's policy (the
//! request's `Host` to the device; the response's `Application-URL`/`Location` to the proxy's listeners,
//! so the device's address never leaks), and forwards them; a writable edge drains the backlog. Each
//! direction half-closes independently: a source's EOF flushes its remaining bytes and FINs the peer
//! while the reverse direction keeps flowing, and the connection closes once both directions are `Done`.
//! Backpressure is drop-and-close: a send-buffer overflow tears the connection down rather than
//! throttling the reader.

use std::io;
use std::net::SocketAddrV4;
use std::os::fd::{AsRawFd, RawFd};
use std::time::{Duration, Instant};

use crate::net::http::framing::{AuthorityHeader, HttpFraming, Kind, RewritePolicy};
use crate::net::stream_buffer::StreamBuffer;
use crate::net::tcp::TcpSocket;
use crate::reactor::{Reactor, RegKey};
use crate::sys::IoStatus;

/// Per-connection, per-direction receive buffer: one read chunk plus header accumulation.
const MAX_RECV: usize = 4 * 1024;
/// Per-connection, per-direction send buffer: the unsent tail held under backpressure; past it the
/// connection drops-and-closes.
const MAX_SEND: usize = 8 * 1024;
/// A non-blocking device connect must complete within this.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// An open connection idle this long is closed.
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// The receive buffer must exceed the framer's header cap, or the over-cap refusal can't fire before
/// the buffer fills and the always-armed reader livelocks.
const _: () = assert!(MAX_RECV > crate::net::http::framing::MAX_HEADER);

/// A direction's half-close progress. `Open` while both ends are live; `SourceClosed` once the source
/// sent EOF and we are flushing whatever was still buffered toward the destination; `Done` once that
/// flush completes and we have shut our write to the destination. A connection closes once both are `Done`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum FlowState {
    Open,
    SourceClosed,
    Done,
}

/// One direction of the duplex splice: its HTTP framer, the recv buffer (bytes read from the source
/// side), the send buffer (the unsent tail to the destination side under backpressure), and its
/// half-close state.
struct Flow {
    framer: HttpFraming,
    recv: StreamBuffer,
    send: StreamBuffer,
    state: FlowState,
}

impl Flow {
    /// A flow framing `kind` messages, rewriting their authority headers per `rewrite`.
    fn new(kind: Kind, rewrite: RewritePolicy) -> Self {
        Self {
            framer: HttpFraming::new(kind, rewrite),
            recv: StreamBuffer::with_capacity(MAX_RECV),
            send: StreamBuffer::with_capacity(MAX_SEND),
            state: FlowState::Open,
        }
    }
}

/// Which way bytes flow on one edge of the splice. `ClientToDevice` is the `c2u` flow — a request read
/// from the client and forwarded to the device (its `Host` rewritten to the device); `DeviceToClient`
/// is `u2c` — a response read from the device and forwarded to the client (its `Application-URL` /
/// `Location` rewritten to the proxy's listeners, so the device's address never leaks).
#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    ClientToDevice,
    DeviceToClient,
}

/// Whether to keep a connection or tear it down — the keep/close decision the per-edge handlers
/// return, clearer than a bare bool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Outcome {
    Keep,
    Close,
}

/// What one [`DirectionContext::forward`] pass concluded: more may follow (`Open`), the source
/// half-closed so flush-then-finish (`SourceEof`), or a fatal error (`Failed`).
enum Forwarded {
    Open,
    SourceEof,
    Failed,
}

/// One `Direction` resolved against a connection: the socket to read from (and its registration, to
/// disarm on half-close), the socket to forward to (and its registration), that direction's framing and
/// buffers (the framer carries its own rewrite policy), and a slot for any REST endpoint learned from a
/// response. Built once per event by [`Connection::context`] so the forward/drain paths never re-pick a side.
struct DirectionContext<'a> {
    from: &'a TcpSocket,
    from_reg: Option<RegKey>,
    to: &'a TcpSocket,
    to_reg: Option<RegKey>,
    flow: &'a mut Flow,
    learned_rest: &'a mut Option<SocketAddrV4>,
    deadline: &'a mut Instant,
}

impl DirectionContext<'_> {
    /// Read one chunk from the source, frame whole messages out of this direction's buffer, and forward
    /// each — rewriting its authority headers per this direction's policy — to the destination, buffering
    /// any unsent tail in the send buffer for the writable edge to drain. The deadline is refreshed (by
    /// the senders) only when bytes actually reach the destination, so a wedged one still ages out via
    /// the idle sweep. Returns the [`Forwarded`] outcome: a framing/recv/send error or a backpressure
    /// overflow is `Failed`; the source half-closed is `SourceEof`; otherwise `Open`. Reactor-free, so
    /// the splice is unit-testable without a reactor.
    fn forward(&mut self) -> Forwarded {
        let tail = self.flow.recv.free_tail_mut();
        if tail.is_empty() {
            log::warn!("dial: receive buffer full of an unframable message; closing");
            return Forwarded::Failed;
        }
        let n = match self.from.recv(tail) {
            Ok(IoStatus::Ready(0)) => return Forwarded::SourceEof, // the peer half-closed its write
            Ok(IoStatus::Ready(n)) => n,
            Ok(IoStatus::WouldBlock) => return Forwarded::Open, // a spurious wake, nothing new
            Err(e) => {
                log::debug!("dial: recv failed: {e}");
                return Forwarded::Failed;
            }
        };
        self.flow.recv.commit(n);
        loop {
            let framed = match self.flow.framer.feed(self.flow.recv.pending()) {
                Ok(framed) => framed,
                Err(e) => {
                    log::debug!("dial: framing error: {e:?}");
                    return Forwarded::Failed;
                }
            };
            // Learn the device REST base from a response's Application-URL (the proxy lifts it into
            // rest_endpoint); a later description fetch can move it, so the latest wins.
            if let Some(AuthorityHeader::ApplicationUrl(ep)) = framed.authority {
                *self.learned_rest = Some(ep);
            }
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
            ) == Outcome::Close
            {
                return Forwarded::Failed;
            }
            self.flow.recv.consume(consumed);
        }
        Forwarded::Open
    }

    /// The source half-closed (sent EOF): stop reading it — its FIN is now permanently readable, so
    /// disarming read interest is what keeps it from re-firing — mark the flow `SourceClosed`, then
    /// settle. The destination stays open and writable, so the reverse direction keeps delivering to the
    /// half-closing peer. `Close` if the reactor rejects the disarm.
    fn half_close(&mut self, reactor: &mut Reactor) -> Outcome {
        let reg = self
            .from_reg
            .expect("a persisted connection has its registration set");
        if reactor.set_read_interest(reg, false).is_err() {
            log::warn!("dial: disarming the half-closed source failed; closing");
            return Outcome::Close;
        }
        self.flow.state = FlowState::SourceClosed;
        self.settle(reactor)
    }

    /// Settle a flow after a forward or drain: if its source has closed and its backlog is now flushed,
    /// FIN the destination (propagating the end) and mark the flow `Done`; then arm the destination's
    /// write interest to whatever backlog remains — a fully-drained flow disarms it, so `on_writable`
    /// never re-enters here and the FIN fires exactly once. `Close` if the reactor rejects the change.
    fn settle(&mut self, reactor: &mut Reactor) -> Outcome {
        // Defer finishing while the destination is still connecting: `shutdown_write` would be an
        // `ENOTCONN` no-op (the FIN lost) and `Done` a lie. The connect-completion edge — kept armed by
        // `sync_write_interest` below — drives `finish_connect`, after which a later settle finishes.
        if self.flow.state == FlowState::SourceClosed
            && self.flow.send.is_empty()
            && !self.to.is_connecting()
        {
            self.to.shutdown_write();
            self.flow.state = FlowState::Done;
        }
        self.sync_write_interest(reactor)
    }

    /// Drain as much of this direction's send backlog as the destination will take now, refreshing the
    /// deadline on real progress. `Close` on a send error; otherwise `Keep` (the caller re-evaluates
    /// write interest from the buffer's emptiness).
    fn drain(&mut self) -> Outcome {
        if self.flow.send.is_empty() {
            return Outcome::Keep;
        }
        match self.to.send(self.flow.send.pending()) {
            Ok(IoStatus::Ready(n)) => {
                self.flow.send.consume(n);
                if n > 0 {
                    *self.deadline = Instant::now() + IDLE_TIMEOUT;
                }
                Outcome::Keep
            }
            Ok(IoStatus::WouldBlock) => Outcome::Keep,
            Err(e) => {
                log::debug!("dial: draining send to peer failed: {e}");
                Outcome::Close
            }
        }
    }

    /// Arm the destination's write interest to its send backlog (armed iff non-empty), or while it is
    /// still connecting so the connect-completion edge survives. `Close` if the reactor rejects the
    /// change, which would otherwise strand the buffered send with no later re-arm for a quiet reader.
    fn sync_write_interest(&self, reactor: &mut Reactor) -> Outcome {
        // Arm on a backlog to drain it, or while the destination is still connecting so its
        // connect-completion edge (a writable edge with no backlog) still wakes us.
        let armed = !self.flow.send.is_empty() || self.to.is_connecting();
        let reg = self
            .to_reg
            .expect("a persisted connection has its registration set");
        if reactor.set_write_interest(reg, armed).is_err() {
            log::warn!("dial: updating write interest failed; closing");
            return Outcome::Close;
        }
        Outcome::Keep
    }
}

/// One proxied client↔device connection. Each socket is watched under its own reg; `device_endpoint`
/// is where `device` connects and the `Host` rewrite target. `deadline` is the connect timeout while
/// the device connect is in flight, then the idle timeout. The regs are `None` only between insert and
/// watch in [`start_connection`](super::proxy::DialDeviceProxy), before [`attach_registrations`](Self::attach_registrations).
pub(super) struct Connection {
    client: TcpSocket,
    client_reg: Option<RegKey>,
    device: TcpSocket,
    device_reg: Option<RegKey>,
    device_endpoint: SocketAddrV4,
    c2u: Flow, // client -> device
    u2c: Flow, // device -> client
    /// The device REST endpoint just learned from a response's `Application-URL`, lifted into the proxy's
    /// `rest_endpoint` after each readable edge (`None` between).
    learned_rest: Option<SocketAddrV4>,
    deadline: Instant,
}

impl Connection {
    /// A new proxied connection from `client` to the device at `device_endpoint`. The request rewrites
    /// its `Host` to the device; the response rewrites `Application-URL` to the REST listener
    /// (`rest_listener`) and `Location` to this connection's own listener (`own_listener`), so the device
    /// never leaks. Registrations are `None` until [`attach_registrations`](Self::attach_registrations);
    /// the deadline starts as the connect timeout.
    pub(super) fn new(
        client: TcpSocket,
        device: TcpSocket,
        device_endpoint: SocketAddrV4,
        rest_listener: SocketAddrV4,
        own_listener: SocketAddrV4,
    ) -> Self {
        let c2u_rewrite = RewritePolicy {
            host: Some(device_endpoint),
            application_url: None,
            location: None,
        };
        let u2c_rewrite = RewritePolicy {
            host: None,
            application_url: Some(rest_listener),
            location: Some(own_listener),
        };
        Self {
            client,
            client_reg: None,
            device,
            device_reg: None,
            device_endpoint,
            c2u: Flow::new(Kind::Request, c2u_rewrite),
            u2c: Flow::new(Kind::Response, u2c_rewrite),
            learned_rest: None,
            deadline: Instant::now() + CONNECT_TIMEOUT,
        }
    }

    /// Record the per-fd registrations once both sockets are watched (they are `None` only between the
    /// connection's insert and that watch).
    pub(super) fn attach_registrations(&mut self, client_reg: RegKey, device_reg: RegKey) {
        self.client_reg = Some(client_reg);
        self.device_reg = Some(device_reg);
    }

    /// The device endpoint this connection targets — its `Host` rewrite target and log identity.
    pub(super) fn device_endpoint(&self) -> SocketAddrV4 {
        self.device_endpoint
    }

    /// This connection's current deadline (the connect timeout, then the idle timeout).
    pub(super) fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Take any REST endpoint just learned from a response's `Application-URL`, for the proxy to lift
    /// into its `rest_endpoint`.
    pub(super) fn take_learned_rest(&mut self) -> Option<SocketAddrV4> {
        self.learned_rest.take()
    }

    /// The readable `fd` (this connection's client or device) has bytes: forward one edge in the matching
    /// direction. The readable fd is the source, so reading the client forwards to the device (`c2u`).
    pub(super) fn readable(&mut self, fd: RawFd, reactor: &mut Reactor) -> Outcome {
        let direction = if self.client.as_raw_fd() == fd {
            Direction::ClientToDevice
        } else {
            Direction::DeviceToClient
        };
        self.forward(direction, reactor)
    }

    /// The writable `fd` can take more: complete the connect / drain its send backlog. The writable fd
    /// is the destination, so draining toward the device is the `c2u` flow's send.
    pub(super) fn writable(&mut self, fd: RawFd, reactor: &mut Reactor) -> Outcome {
        let direction = if self.device.as_raw_fd() == fd {
            Direction::ClientToDevice
        } else {
            Direction::DeviceToClient
        };
        self.on_writable(direction, reactor)
    }

    /// Drop both watched fds' kernel interest, then shut both sockets down. Consumes the connection (the
    /// caller has already removed it from the pool); a half-built one may have no registrations yet.
    pub(super) fn teardown(self, reactor: &mut Reactor) {
        if let Some(reg) = self.client_reg {
            reactor.unwatch(reg).ok();
        }
        if let Some(reg) = self.device_reg {
            reactor.unwatch(reg).ok();
        }
        self.client.shutdown();
        self.device.shutdown();
    }

    /// The resolved view for `direction` — the sockets, registration, flow, and deadline it touches — so
    /// the forward/drain paths operate without re-picking a side.
    fn context(&mut self, direction: Direction) -> DirectionContext<'_> {
        match direction {
            Direction::ClientToDevice => DirectionContext {
                from: &self.client,
                from_reg: self.client_reg,
                to: &self.device,
                to_reg: self.device_reg,
                flow: &mut self.c2u,
                learned_rest: &mut self.learned_rest,
                deadline: &mut self.deadline,
            },
            Direction::DeviceToClient => DirectionContext {
                from: &self.device,
                from_reg: self.device_reg,
                to: &self.client,
                to_reg: self.client_reg,
                flow: &mut self.u2c,
                learned_rest: &mut self.learned_rest,
                deadline: &mut self.deadline,
            },
        }
    }

    /// Fold a per-direction `outcome` into the connection's: an explicit `Close`, or close once both
    /// directions have finished their half-close (both `Done`); otherwise keep the connection.
    fn close_if_complete(&self, outcome: Outcome) -> Outcome {
        if outcome == Outcome::Close
            || (self.c2u.state == FlowState::Done && self.u2c.state == FlowState::Done)
        {
            Outcome::Close
        } else {
            Outcome::Keep
        }
    }

    /// `direction`'s source peer has fully hung up. Whatever it already sent may still be buffered toward
    /// the *other*, still-live peer, so finish delivering that (`settle` drains it asynchronously, then
    /// FINs). The reverse direction is dead — its destination is the vanished peer — so abandon it
    /// (`Done`, dropping its now-undeliverable buffer) and disarm its source read, lest a stray edge
    /// re-enter and tear us down early. Unwatch the vanished fd, whose level-triggered HUP would
    /// otherwise re-fire every wait. The connection then closes once the forward flow finishes draining.
    fn peer_gone(&mut self, direction: Direction, reactor: &mut Reactor) -> Outcome {
        // Abandon the reverse direction (its destination is the vanished peer) and resolve the reg whose
        // read to disarm — that abandoned flow's source — and the hung-up fd to unwatch. The guard routes
        // here only with a live destination reg, and the source's reg is still set (its fd just hung up,
        // and peer_gone, which takes it, runs once), so both expects hold.
        let (disarm_reg, unwatch_reg) = match direction {
            Direction::ClientToDevice => {
                self.u2c.state = FlowState::Done; // the response can't reach the gone client
                (
                    self.device_reg
                        .expect("a live destination keeps its registration"),
                    self.client_reg
                        .take()
                        .expect("the hung-up source still has its registration"),
                )
            }
            Direction::DeviceToClient => {
                self.c2u.state = FlowState::Done; // the request can't reach the gone device
                (
                    self.client_reg
                        .expect("a live destination keeps its registration"),
                    self.device_reg
                        .take()
                        .expect("the hung-up source still has its registration"),
                )
            }
        };
        // Disarm the abandoned reverse's source read and unwatch the hung-up fd. A failure is rare (a
        // reactor syscall on a live fd), but ignoring it is unsafe: a still-watched hung-up fd would
        // re-fire its HUP, re-enter here, and find its reg already taken. Wind the connection down.
        if reactor.set_read_interest(disarm_reg, false).is_err()
            || reactor.unwatch(unwatch_reg).is_err()
        {
            log::warn!("dial: winding down a hung-up peer failed; closing");
            return Outcome::Close;
        }
        if self.context(direction).settle(reactor) == Outcome::Close {
            return Outcome::Close;
        }
        self.close_if_complete(Outcome::Keep)
    }

    /// Forward one readable edge in `direction`: splice the bytes, then on the source's EOF begin its
    /// half-close (flush the rest, FIN the destination, keep the reverse direction flowing), on a fatal
    /// error tear down, otherwise arm the destination's write interest to its backlog.
    fn forward(&mut self, direction: Direction, reactor: &mut Reactor) -> Outcome {
        let mut ctx = self.context(direction);
        // A non-Open flow means we already disarmed this source's read when it half-closed, yet it woke
        // us again — only a hangup/reset does that, since epoll delivers HUP/ERR regardless of the read
        // mask. The source peer is fully gone. If its destination is gone too (a prior `peer_gone` took
        // that reg, leaving it `None`), both peers have vanished — close. Otherwise wind down, finishing
        // any backlog still owed to the live destination, rather than re-running the half-close.
        if ctx.flow.state != FlowState::Open {
            return if ctx.to_reg.is_none() {
                Outcome::Close
            } else {
                self.peer_gone(direction, reactor)
            };
        }
        let forwarded = ctx.forward();
        let outcome = match forwarded {
            Forwarded::Failed => Outcome::Close,
            Forwarded::SourceEof => ctx.half_close(reactor),
            Forwarded::Open => ctx.sync_write_interest(reactor),
        };
        self.close_if_complete(outcome)
    }

    /// A connection socket is writable: complete the device connect if still pending, drain
    /// `direction`'s send backlog, then settle its half-close (FIN the destination once a closed
    /// source's backlog has flushed) and leave its write interest armed iff a backlog remains (so a
    /// fully-drained buffer disarms — including the bare connect-completion case). Returns `Close` to
    /// tear down.
    fn on_writable(&mut self, direction: Direction, reactor: &mut Reactor) -> Outcome {
        if direction == Direction::ClientToDevice && self.device.is_connecting() {
            match self.device.finish_connect() {
                Ok(()) => self.deadline = Instant::now() + IDLE_TIMEOUT,
                Err(e) => {
                    log::warn!(
                        "dial: device connect to {} failed: {e}",
                        self.device_endpoint
                    );
                    return Outcome::Close;
                }
            }
        }
        let mut ctx = self.context(direction);
        if ctx.drain() == Outcome::Close {
            return Outcome::Close;
        }
        let outcome = ctx.settle(reactor);
        self.close_if_complete(outcome)
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
) -> Outcome {
    if !to_send.is_empty() || to.is_connecting() {
        return buffer_tail(to_send, header, body);
    }
    let total = header.len() + body.len();
    let sent = match to.send_vectored(&[io::IoSlice::new(header), io::IoSlice::new(body)]) {
        Ok(IoStatus::Ready(n)) => n,
        Ok(IoStatus::WouldBlock) => 0,
        Err(e) => {
            log::debug!("dial: send to peer failed: {e}");
            return Outcome::Close;
        }
    };
    if sent > 0 {
        // Bytes reached the destination — real forward progress, so hold off the idle timeout.
        *deadline = Instant::now() + IDLE_TIMEOUT;
    }
    if sent == total {
        return Outcome::Keep;
    }
    let (header_tail, body_tail) = split_remainder(header, body, sent);
    buffer_tail(to_send, header_tail, body_tail)
}

/// Append the unsent `header`/`body` remainder to `to_send`; `Close` if it overflows the cap.
fn buffer_tail(to_send: &mut StreamBuffer, header: &[u8], body: &[u8]) -> Outcome {
    if to_send.append(header).is_err() || to_send.append(body).is_err() {
        log::warn!("dial: send buffer overflow; closing");
        return Outcome::Close;
    }
    Outcome::Keep
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

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::*;
    use crate::reactor::{Handler, ReadyEvent};

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
        let listener =
            TcpSocket::listen(std::net::Ipv4Addr::LOCALHOST).expect("listen on loopback");
        let mut initiator =
            TcpSocket::connect(listener.local_addr(), std::net::Ipv4Addr::LOCALHOST, 0)
                .expect("connect");
        let accepted = spin(|| listener.accept());
        initiator.finish_connect().expect("the connect completed");
        (initiator, accepted)
    }

    /// Drive `forward_dir` until the message it forwards arrives at `peer_out`. Returns those bytes
    /// alongside the REST endpoint learned from an `Application-URL`, if any.
    fn drive_forward(
        from: &TcpSocket,
        to: &TcpSocket,
        flow: &mut Flow,
        peer_out: &TcpSocket,
    ) -> (Vec<u8>, Option<SocketAddrV4>) {
        let mut deadline = Instant::now();
        let mut learned_rest = None;
        let mut buf = [0u8; 1024];
        for _ in 0..2000 {
            {
                let mut ctx = DirectionContext {
                    from,
                    from_reg: None,
                    to,
                    to_reg: None,
                    flow: &mut *flow,
                    learned_rest: &mut learned_rest,
                    deadline: &mut deadline,
                };
                assert!(
                    matches!(ctx.forward(), Forwarded::Open),
                    "forward should stay open on a clean message"
                );
            }
            match peer_out.recv(&mut buf).expect("recv on the peer") {
                IoStatus::Ready(0) => panic!("unexpected EOF before the forwarded bytes"),
                IoStatus::Ready(n) => return (buf[..n].to_vec(), learned_rest),
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
    fn buffer_tail_keeps_within_cap_and_closes_on_overflow() {
        let mut send = StreamBuffer::with_capacity(4);
        assert_eq!(buffer_tail(&mut send, b"ab", b"cd"), Outcome::Keep); // fills the 4-byte cap
        assert_eq!(buffer_tail(&mut send, b"x", b""), Outcome::Close); // past it: drop-and-close
    }

    #[test]
    fn forward_dir_frames_a_request_and_rewrites_host() {
        let (peer_in, from) = connected_pair(); // peer_in -> from (the client side)
        let (to, peer_out) = connected_pair(); // to -> peer_out (the device side)
        let device = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 5), 8008);
        assert!(matches!(
            peer_in
                .send(b"GET /apps HTTP/1.1\r\nHost: 192.168.1.2:80\r\n\r\n")
                .expect("send the request"),
            IoStatus::Ready(_)
        ));
        let rewrite = RewritePolicy {
            host: Some(device),
            application_url: None,
            location: None,
        };
        let mut flow = Flow::new(Kind::Request, rewrite);
        let (got, _) = drive_forward(&from, &to, &mut flow, &peer_out);
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
    fn forward_dir_rewrites_application_url_to_the_rest_listener_and_learns_it() {
        let (peer_in, from) = connected_pair();
        let (to, peer_out) = connected_pair();
        // The DD-connection u2c policy points Application-URL at the proxy's REST listener so the
        // device's REST endpoint never reaches the client; the proxy learns that endpoint instead.
        let rest_listener = SocketAddrV4::new(std::net::Ipv4Addr::new(192, 168, 1, 1), 9000);
        let rewrite = RewritePolicy {
            host: None,
            application_url: Some(rest_listener),
            location: None,
        };
        let response = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\
             Application-URL: http://192.168.1.2:8008/apps\r\n\r\nhello";
        assert!(matches!(
            peer_in
                .send(response.as_bytes())
                .expect("send the response"),
            IoStatus::Ready(_)
        ));
        let mut flow = Flow::new(Kind::Response, rewrite);
        let (got, learned) = drive_forward(&from, &to, &mut flow, &peer_out);
        assert!(
            contains(&got, b"Application-URL: http://192.168.1.1:9000/apps\r\n"),
            "Application-URL rewritten to the REST listener: {:?}",
            String::from_utf8_lossy(&got)
        );
        assert_eq!(
            learned,
            Some(SocketAddrV4::new(
                std::net::Ipv4Addr::new(192, 168, 1, 2),
                8008
            )),
            "the device's Application-URL endpoint is learned for the REST connection"
        );
        assert!(got.ends_with(b"hello"), "body forwarded: {got:?}");
    }

    #[test]
    fn forward_dir_rewrites_a_location_redirect_to_the_desc_listener() {
        let (peer_in, from) = connected_pair();
        let (to, peer_out) = connected_pair();
        // A rare dd redirect: Location points the client back at the proxy's own desc listener, not
        // the device. It is not a REST endpoint, so nothing is learned.
        let own_listener = SocketAddrV4::new(std::net::Ipv4Addr::new(192, 168, 1, 1), 1901);
        let rewrite = RewritePolicy {
            host: None,
            application_url: None,
            location: Some(own_listener),
        };
        let response = "HTTP/1.1 302 Found\r\nContent-Length: 0\r\n\
             Location: http://192.168.1.2:8008/dd.xml\r\n\r\n";
        assert!(matches!(
            peer_in
                .send(response.as_bytes())
                .expect("send the response"),
            IoStatus::Ready(_)
        ));
        let mut flow = Flow::new(Kind::Response, rewrite);
        let (got, learned) = drive_forward(&from, &to, &mut flow, &peer_out);
        assert!(
            contains(&got, b"Location: http://192.168.1.1:1901/dd.xml\r\n"),
            "Location rewritten to the desc listener: {:?}",
            String::from_utf8_lossy(&got)
        );
        assert_eq!(learned, None, "a Location redirect is not a REST endpoint");
    }

    #[test]
    fn forward_reports_source_eof_when_the_peer_closes_its_write() {
        let (peer_in, from) = connected_pair();
        let (to, _peer_out) = connected_pair();
        drop(peer_in); // the source's peer closes → `from` observes EOF
        let mut flow = Flow::new(Kind::Request, RewritePolicy::NONE);
        let mut deadline = Instant::now();
        let mut learned_rest = None;
        let outcome = loop {
            let mut ctx = DirectionContext {
                from: &from,
                from_reg: None,
                to: &to,
                to_reg: None,
                flow: &mut flow,
                learned_rest: &mut learned_rest,
                deadline: &mut deadline,
            };
            match ctx.forward() {
                Forwarded::Open => sleep(Duration::from_millis(1)), // FIN not observed yet
                terminal => break terminal,
            }
        };
        assert!(matches!(outcome, Forwarded::SourceEof));
    }

    /// A do-nothing handler — only needed so the reactor will hand out registrations for the
    /// state-machine tests below (they drive `Connection` directly, never through dispatch).
    struct NoopHandler;
    impl Handler for NoopHandler {
        fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
    }

    /// A reactor plus a `Connection` whose client/device sockets are watched loopback pairs, with the
    /// far ends returned so a test can drive traffic and observe what the proxy forwards: `client_peer`
    /// stands in for the DIAL client, `device_peer` for the device.
    fn watched_connection() -> (Reactor, Connection, TcpSocket, TcpSocket) {
        let mut reactor = Reactor::new().expect("reactor");
        let key = reactor.register(Box::new(NoopHandler));
        let (client_peer, client) = connected_pair(); // the proxy accepted the client
        let (device, device_peer) = connected_pair(); // the proxy connected to the device
        let client_reg = reactor
            .watch(key, client.as_raw_fd(), 0)
            .expect("watch client");
        let device_reg = reactor
            .watch(key, device.as_raw_fd(), 0)
            .expect("watch device");
        let device_endpoint = SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, 5), 8008);
        // The c2u framer rewrites the request's Host to the device, as `start_connection` wires it; the
        // state-machine tests don't drive a u2c response through the rewrite, so its policy stays empty.
        let c2u_rewrite = RewritePolicy {
            host: Some(device_endpoint),
            application_url: None,
            location: None,
        };
        let conn = Connection {
            client,
            client_reg: Some(client_reg),
            device,
            device_reg: Some(device_reg),
            device_endpoint,
            learned_rest: None,
            c2u: Flow::new(Kind::Request, c2u_rewrite),
            u2c: Flow::new(Kind::Response, RewritePolicy::NONE),
            deadline: Instant::now(),
        };
        (reactor, conn, client_peer, device_peer)
    }

    /// Read `sock` until EOF, returning everything received (panics if EOF never arrives on loopback).
    fn drain_to_eof(sock: &TcpSocket) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = [0u8; 256];
        for _ in 0..2000 {
            match sock.recv(&mut buf).expect("recv") {
                IoStatus::Ready(0) => return out,
                IoStatus::Ready(n) => out.extend_from_slice(&buf[..n]),
                IoStatus::WouldBlock => sleep(Duration::from_millis(1)),
            }
        }
        panic!("EOF never arrived on loopback");
    }

    /// Drive `forward` on the client→device edge until the flow reaches `Done` (or the budget runs out).
    fn drive_c2u_to_done(conn: &mut Connection, reactor: &mut Reactor) {
        for _ in 0..2000 {
            conn.forward(Direction::ClientToDevice, reactor);
            if conn.c2u.state == FlowState::Done {
                return;
            }
            sleep(Duration::from_millis(1));
        }
        panic!("c2u never reached Done");
    }

    #[test]
    fn close_if_complete_closes_only_when_both_flows_are_done() {
        let (_reactor, mut conn, _client_peer, _device_peer) = watched_connection();
        // Both Open: keep.
        assert_eq!(conn.close_if_complete(Outcome::Keep), Outcome::Keep);
        // One side done, the other still open: keep (the half-close isn't finished).
        conn.c2u.state = FlowState::Done;
        assert_eq!(conn.close_if_complete(Outcome::Keep), Outcome::Keep);
        // Both done: close.
        conn.u2c.state = FlowState::Done;
        assert_eq!(conn.close_if_complete(Outcome::Keep), Outcome::Close);
        // An explicit Close wins regardless of the flow states.
        conn.c2u.state = FlowState::Open;
        conn.u2c.state = FlowState::Open;
        assert_eq!(conn.close_if_complete(Outcome::Close), Outcome::Close);
    }

    #[test]
    fn forward_eof_finishes_the_flow_and_fins_the_destination() {
        let (mut reactor, mut conn, client_peer, device_peer) = watched_connection();
        // The client sends a full request, then closes its write half (a FIN after the bytes).
        assert!(matches!(
            client_peer
                .send(b"GET /apps HTTP/1.1\r\nHost: 192.168.1.2:80\r\n\r\n")
                .expect("send request"),
            IoStatus::Ready(_)
        ));
        drop(client_peer);
        // The readable edges forward the request (Open), then observe EOF: Open -> SourceClosed ->
        // (empty backlog) -> Done.
        drive_c2u_to_done(&mut conn, &mut reactor);
        assert_eq!(conn.c2u.state, FlowState::Done);
        // The device received the Host-rewritten request and then our FIN (EOF terminates the drain).
        let got = drain_to_eof(&device_peer);
        assert!(
            contains(&got, b"Host: 10.0.0.5:8008\r\n"),
            "request forwarded before the FIN: {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    #[test]
    fn half_close_holds_in_source_closed_until_the_backlog_drains() {
        let (mut reactor, mut conn, _client_peer, device_peer) = watched_connection();
        // A backlog still owed to the device at the moment the client half-closes.
        conn.c2u
            .send
            .append(b"GET / HTTP/1.1\r\n\r\n")
            .expect("buffer a backlog");
        // Half-close with bytes still pending: the flow holds at SourceClosed, not Done.
        assert_eq!(
            conn.context(Direction::ClientToDevice)
                .half_close(&mut reactor),
            Outcome::Keep
        );
        assert_eq!(conn.c2u.state, FlowState::SourceClosed);
        // Draining the backlog (a writable edge) then finishes the flow.
        for _ in 0..2000 {
            conn.on_writable(Direction::ClientToDevice, &mut reactor);
            if conn.c2u.state == FlowState::Done {
                break;
            }
            sleep(Duration::from_millis(1));
        }
        assert_eq!(conn.c2u.state, FlowState::Done);
        let got = drain_to_eof(&device_peer);
        assert!(
            got.starts_with(b"GET / HTTP/1.1\r\n"),
            "the backlog reached the device before the FIN: {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    #[test]
    fn source_hangup_with_no_backlog_tears_down() {
        let (mut reactor, mut conn, _client_peer, _device_peer) = watched_connection();
        // A readable edge once the flow is past Open is a hangup on the disarmed source. With nothing
        // owed to the live peer, winding down finishes both directions at once -> close.
        conn.c2u.state = FlowState::SourceClosed;
        assert_eq!(
            conn.forward(Direction::ClientToDevice, &mut reactor),
            Outcome::Close
        );
        // Same once the flow is already Done.
        let (mut reactor, mut conn, _client_peer, _device_peer) = watched_connection();
        conn.c2u.state = FlowState::Done;
        assert_eq!(
            conn.forward(Direction::ClientToDevice, &mut reactor),
            Outcome::Close
        );
    }

    #[test]
    fn source_hangup_still_drains_the_forward_backlog() {
        let (mut reactor, mut conn, _client_peer, device_peer) = watched_connection();
        // The client half-closed with a request still buffered toward the (live) device...
        conn.c2u
            .send
            .append(b"GET /apps HTTP/1.1\r\n\r\n")
            .expect("buffer a backlog");
        conn.c2u.state = FlowState::SourceClosed;
        // ...then the client fully hangs up: a readable edge on the disarmed source.
        assert_eq!(
            conn.forward(Direction::ClientToDevice, &mut reactor),
            Outcome::Keep,
            "keep the connection to drain the request, don't drop it"
        );
        assert_eq!(
            conn.u2c.state,
            FlowState::Done,
            "the reverse direction is abandoned — the client is gone"
        );
        assert!(
            conn.client_reg.is_none(),
            "the hung-up client fd is unwatched so its HUP stops re-firing"
        );
        // Draining finishes the forward flow; the device receives the whole request, then our FIN.
        for _ in 0..2000 {
            conn.on_writable(Direction::ClientToDevice, &mut reactor);
            if conn.c2u.state == FlowState::Done {
                break;
            }
            sleep(Duration::from_millis(1));
        }
        assert_eq!(conn.c2u.state, FlowState::Done);
        let got = drain_to_eof(&device_peer);
        assert!(
            got.starts_with(b"GET /apps HTTP/1.1\r\n"),
            "the full request reached the device before the FIN: {:?}",
            String::from_utf8_lossy(&got)
        );
    }

    #[test]
    fn both_peers_hangup_closes_without_panic() {
        let (mut reactor, mut conn, _client_peer, _device_peer) = watched_connection();
        // Both directions still owe a backlog to their (about-to-vanish) peers.
        conn.c2u.send.append(b"req").expect("buffer c2u");
        conn.u2c.send.append(b"resp").expect("buffer u2c");
        conn.c2u.state = FlowState::SourceClosed;
        conn.u2c.state = FlowState::SourceClosed;
        // The client hangs up: peer_gone keeps the connection to drain the request to the live device.
        assert_eq!(
            conn.forward(Direction::ClientToDevice, &mut reactor),
            Outcome::Keep
        );
        // Then the device hangs up too — its registration is already gone, so nothing is left to
        // deliver: close, and (the regression) without panicking in settle/sync_write_interest.
        assert_eq!(
            conn.forward(Direction::DeviceToClient, &mut reactor),
            Outcome::Close
        );
    }
}
