//! The per-device DIAL proxy: a reactor [`Handler`] fronting one device's HTTP endpoints.
//!
//! [`DialDeviceProxy`] owns a source-side description listener and a REST listener plus a pool of live
//! [`Connection`]s. It accepts on either listener, opens an egress-pinned connection to the device on
//! the target subnet, and dispatches each readable/writable edge to the matching connection. The proxy's
//! own eviction (once the device's advertisement grace lapses) is owned by the
//! [`DialContext`](crate::dispatch::DialContext) registry — the proxy never sees advertisements; it only
//! sweeps its own connections past their connect/idle deadlines.

use std::fmt;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;

use crate::net::tcp::TcpSocket;
use crate::reactor::{Arena, Handler, HandlerKey, Key, Reactor, ReadyEvent};

use super::connection::{Connection, Outcome};

/// Cap on concurrent proxied connections (drop-new past it).
const MAX_CONNECTIONS: usize = 64;

/// A `Copy` handle into the proxy's connection [`Arena`] — a newtype over the arena [`Key`] so it
/// can't be confused with the reactor's keys. Round-trips through a watched fd's `user_data`: the
/// reactor echoes it back on every event, and dispatch decodes it to find the flow.
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

/// Which of a proxy's two source-side listeners — names it in a log message.
#[derive(Clone, Copy)]
pub(super) enum Listener {
    Description,
    Rest,
}

impl fmt::Display for Listener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Description => "description",
            Self::Rest => "REST",
        })
    }
}

/// A per-device DIAL proxy — a reactor `Handler` owning a description listener and its connections.
pub(super) struct DialDeviceProxy {
    /// This handler's own key, learned via [`adopt_key`](Handler::adopt_key); used to watch fds it
    /// opens.
    key: Option<HandlerKey>,
    /// The target-interface address device connections bind, so the device sees a same-segment peer
    /// and replies via the target interface (on the BSDs the bind is the only egress steer).
    target: Ipv4Addr,
    /// The target interface index, egress-pinning device connections to that segment.
    target_ifindex: u32,
    /// The description listener (source side); its connections proxy to `desc_endpoint`.
    desc: TcpSocket,
    /// The device's description endpoint (`device-ip:desc_port`) — the proxy's identity.
    desc_endpoint: SocketAddrV4,
    /// The REST listener (source side); its connections proxy to the device's REST endpoint. Eager-minted
    /// so its address is fixed and available to rewrite a description response's `Application-URL` to.
    rest: TcpSocket,
    /// The device's REST endpoint, learned (and re-learned) from a description response's `Application-URL`;
    /// `None` until the first description fetch reveals it. REST connections proxy here.
    rest_endpoint: Option<SocketAddrV4>,
    conns: Arena<Connection>,
}

impl DialDeviceProxy {
    /// A proxy fronting `desc_endpoint` via the source-side `desc` listener (already bound by the caller).
    /// Device connections bind the target-interface `target` and egress-pin `target_ifindex`.
    pub(super) fn new(
        target: Ipv4Addr,
        target_ifindex: u32,
        desc: TcpSocket,
        desc_endpoint: SocketAddrV4,
        rest: TcpSocket,
    ) -> Self {
        Self {
            key: None,
            target,
            target_ifindex,
            desc,
            desc_endpoint,
            rest,
            rest_endpoint: None,
            conns: Arena::new(),
        }
    }

    /// This handler's own key. `adopt_key` sets it at registration, before any dispatch — its absence
    /// would be a reactor-contract violation.
    fn own_key(&self) -> HandlerKey {
        self.key
            .expect("adopt_key sets the proxy's key before any dispatch")
    }

    /// Accept one pending client on `listener` if there is connection capacity, else `None`. An accept
    /// is always taken — draining the readiness — even at the shared connection cap, where the client
    /// is then dropped.
    fn accept_client(&self, listener: &TcpSocket, what: Listener) -> Option<TcpSocket> {
        let client = match listener.accept() {
            Ok(Some(client)) => client,
            Ok(None) => return None, // spurious / already taken
            Err(e) => {
                log::warn!("dial: accept on the {what} listener failed: {e}");
                return None;
            }
        };
        if self.conns.iter().count() >= MAX_CONNECTIONS {
            log::warn!("dial: connection cap ({MAX_CONNECTIONS}) reached; dropping a new client");
            return None; // `client` drops here, closing it
        }
        Some(client)
    }

    /// Accept a client on the description listener and proxy it to the device's description endpoint.
    fn accept_desc(&mut self, reactor: &mut Reactor) {
        if let Some(client) = self.accept_client(&self.desc, Listener::Description) {
            self.start_connection(client, self.desc_endpoint, self.desc.local_addr(), reactor);
        }
    }

    /// Accept a client on the REST listener and proxy it to the REST endpoint learned from a prior
    /// description fetch. A client reaching here before that fetch is dropped (the proxy minted the
    /// listener's address into the description's `Application-URL`, so this is unexpected).
    fn accept_rest(&mut self, reactor: &mut Reactor) {
        let Some(client) = self.accept_client(&self.rest, Listener::Rest) else {
            return;
        };
        let Some(device) = self.rest_endpoint else {
            log::warn!(
                "dial: REST request before the device's REST endpoint is known; dropping it"
            );
            return; // `client` drops here, closing it
        };
        self.start_connection(client, device, self.rest.local_addr(), reactor);
    }

    /// Open an egress-pinned connection to `device_endpoint`, register both fds, and record the
    /// connection. Best-effort: a connect or watch failure drops the half-built connection.
    fn start_connection(
        &mut self,
        client: TcpSocket,
        device_endpoint: SocketAddrV4,
        own_listener: SocketAddrV4,
        reactor: &mut Reactor,
    ) {
        let key = self.own_key();
        let rest_listener = self.rest.local_addr();
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
        let conn_key = ConnectionKey(self.conns.insert(Connection::new(
            client,
            device,
            device_endpoint,
            rest_listener,
            own_listener,
        )));
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
        conn.attach_registrations(client_reg, device_reg);
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
        let (outcome, learned) = {
            let Some(conn) = self.conns.get_mut(conn_key.0) else {
                log::trace!("dial: readable event for an unknown connection; ignoring");
                return;
            };
            let outcome = conn.readable(fd, reactor);
            (outcome, conn.take_learned_rest())
        };
        // A description response just revealed (or moved) the device's REST endpoint.
        if let Some(endpoint) = learned {
            self.rest_endpoint = Some(endpoint);
        }
        if outcome == Outcome::Close {
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
        let outcome = {
            let Some(conn) = self.conns.get_mut(conn_key.0) else {
                // The reactor filters stale registrations, so a live write event should map to a live
                // connection; a miss means the generational key out-lived its slot — fail safe.
                log::trace!("dial: writable event for an unknown connection; ignoring");
                return;
            };
            conn.writable(fd, reactor)
        };
        if outcome == Outcome::Close {
            self.close_conn(conn_key, reactor);
        }
    }

    /// Remove the connection `conn_key` from the pool and tear down its watches and sockets. Every caller
    /// holds a live key (just inserted, just matched, or from a live sweep), so the connection is present;
    /// a half-built one may have no registrations yet.
    fn close_conn(&mut self, conn_key: ConnectionKey, reactor: &mut Reactor) {
        let conn = self
            .conns
            .remove(conn_key.0)
            .expect("close_conn's callers hold a live connection key");
        let endpoint = conn.device_endpoint();
        conn.teardown(reactor);
        log::debug!("dial: closed a connection to {endpoint}");
    }

    /// Close connections past their deadline (connect timeout or idle). The proxy itself is evicted past
    /// its advertisement grace by the [`DialContext`](crate::dispatch::DialContext) registry, not here.
    fn sweep(&mut self, now: Instant, reactor: &mut Reactor) {
        let expired: Vec<(ConnectionKey, SocketAddrV4)> = self
            .conns
            .iter()
            .filter(|(_, conn)| now >= conn.deadline())
            .map(|(key, conn)| (ConnectionKey(key), conn.device_endpoint()))
            .collect();
        for (conn_key, device_endpoint) in expired {
            log::debug!("dial: connection to {device_endpoint} timed out");
            self.close_conn(conn_key, reactor);
        }
    }
}

impl Handler for DialDeviceProxy {
    fn adopt_key(&mut self, key: HandlerKey) {
        self.key = Some(key);
    }

    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        if event.fd == self.desc.as_raw_fd() {
            self.accept_desc(reactor);
        } else if event.fd == self.rest.as_raw_fd() {
            self.accept_rest(reactor);
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
        // Wake at the soonest connection deadline; an idle proxy has no timer of its own (the registry
        // drives its grace eviction).
        self.conns.iter().map(|(_, conn)| conn.deadline()).min()
    }

    fn on_deadline(&mut self, now: Instant, reactor: &mut Reactor) {
        self.sweep(now, reactor);
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;
    use std::time::Duration;

    use super::*;
    use crate::sys::IoStatus;

    /// A do-nothing handler — only needed so the reactor will hand out registrations and a key for the
    /// proxy tests below (they drive the proxy directly, never through dispatch).
    struct NoopHandler;
    impl Handler for NoopHandler {
        fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
    }

    /// A proxy with bound loopback desc/rest listeners, its key borrowed from a placeholder handler so
    /// `start_connection`'s watches resolve without dispatching through the reactor. Returns the proxy and
    /// its REST listener address (a client connects there to reach `accept_rest`); `rest_endpoint` starts
    /// unlearned.
    fn watched_proxy(reactor: &mut Reactor) -> (DialDeviceProxy, SocketAddrV4) {
        let key = reactor.register(Box::new(NoopHandler));
        let desc = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("desc listen");
        let rest = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("rest listen");
        let rest_addr = rest.local_addr();
        let mut proxy = DialDeviceProxy::new(
            Ipv4Addr::LOCALHOST,
            0, // no egress pin on loopback
            desc,
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 5), 8008),
            rest,
        );
        proxy.adopt_key(key);
        (proxy, rest_addr)
    }

    #[test]
    fn accept_rest_proxies_to_the_learned_rest_endpoint() {
        let mut reactor = Reactor::new().expect("reactor");
        let (mut proxy, rest_addr) = watched_proxy(&mut reactor);
        // A loopback stand-in for the device's REST endpoint a prior description fetch revealed.
        let device = TcpSocket::listen(Ipv4Addr::LOCALHOST).expect("device REST listen");
        let device_endpoint = device.local_addr();
        proxy.rest_endpoint = Some(device_endpoint);

        // A client reaches the REST listener; drive accept until the loopback handshake lands.
        let _client =
            TcpSocket::connect(rest_addr, Ipv4Addr::LOCALHOST, 0).expect("client connect");
        for _ in 0..2000 {
            proxy.accept_rest(&mut reactor);
            if proxy.conns.iter().count() == 1 {
                break;
            }
            sleep(Duration::from_millis(1));
        }

        let (_, conn) = proxy
            .conns
            .iter()
            .next()
            .expect("a REST connection was started");
        assert_eq!(
            conn.device_endpoint(),
            device_endpoint,
            "the REST connection targets the learned REST endpoint, not the description endpoint"
        );
    }

    #[test]
    fn accept_rest_drops_a_client_before_the_rest_endpoint_is_learned() {
        let mut reactor = Reactor::new().expect("reactor");
        let (mut proxy, rest_addr) = watched_proxy(&mut reactor); // rest_endpoint stays None
        let client = TcpSocket::connect(rest_addr, Ipv4Addr::LOCALHOST, 0).expect("client connect");

        // accept_rest accepts the client (draining the listener) but, with no learned endpoint, drops
        // it — so the client observes EOF and no connection is recorded.
        let mut buf = [0u8; 1];
        let mut closed = false;
        for _ in 0..2000 {
            proxy.accept_rest(&mut reactor);
            if matches!(client.recv_bytes(&mut buf), Ok(IoStatus::Ready(0))) {
                closed = true;
                break;
            }
            sleep(Duration::from_millis(1));
        }
        assert!(
            closed,
            "the proxy accepted then closed the unservable REST client"
        );
        assert_eq!(
            proxy.conns.iter().count(),
            0,
            "no connection is started before the REST endpoint is known"
        );
    }
}
