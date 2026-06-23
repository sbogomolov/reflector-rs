//! Packet dispatch: the routing layer between captures and reflectors.
//!
//! [`PacketDispatcher`] is the single owner of every interface [`Capture`] (held in a
//! generational [`Arena`], addressed by a `Copy` [`CaptureKey`]) and of the routing
//! registrations. When an interface's fd is readable, [`drain_and_route`] takes that
//! capture *out* of the arena, drains it, parses each frame into a [`Packet`], and
//! offers it to every registration whose [`Filter`] matches; a matching reflector
//! re-emits on the opposite interface via [`send`], keyed.
//!
//! Taking the ingress capture out is load-bearing: the parsed `Packet` then borrows a
//! local, not `self`, so `&mut PacketDispatcher` is free to hand to a reflector — which
//! can send on the *other* captures still in the arena, and register further work. The
//! reflector never owns an fd; the fd lives in exactly one `Capture`, reached by key.
//! (`egress == ingress` can't arise — reflectors bridge A→B, never A→A; if it did, the
//! key resolves to the taken-out `None` slot and the send is a logged drop, not UB.)
//!
//! [`drain_and_route`]: PacketDispatcher::drain_and_route
//! [`send`]: PacketDispatcher::send

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, RawFd};

use crate::capture::Capture;
use crate::net::mac::MacAddr;
use crate::net::packet::Packet;
use crate::reactor::{Arena, Handler, Key, Reactor, ReadyEvent};

/// The most frames drained per readable event before yielding, so a flooded interface
/// can't starve the others. `AF_PACKET` stops here and the level-triggered wait
/// re-reports the rest; BPF finishes its current userland batch past this, since the
/// wait won't re-fire for those already-read records.
const MAX_FRAMES_PER_EVENT: u32 = 64;

/// A `Copy` handle to a capture the dispatcher owns. A newtype over the arena key — not
/// a bare alias — so a capture key can't be passed where a reactor key is expected (a
/// different arena), where it would silently miss instead of failing to compile.
/// Reflectors hold these for the interface(s) they egress on and send by key, never
/// touching an fd directly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CaptureKey(Key);

impl CaptureKey {
    /// Pack into a `u64` for the reactor's opaque `user_data` slot, recoverable via
    /// [`from_u64`](Self::from_u64) (delegates to the arena [`Key`]).
    #[must_use]
    fn to_u64(self) -> u64 {
        self.0.to_u64()
    }

    /// Reconstruct a key packed by [`to_u64`](Self::to_u64).
    #[must_use]
    fn from_u64(packed: u64) -> Self {
        CaptureKey(Key::from_u64(packed))
    }
}

/// An optional-field packet filter (the C++ `PacketFilter` parity): an unset field
/// matches anything. A `src_mac`/`dst_mac` filter never matches a `DLT_NULL` packet,
/// which has no L2 addresses.
#[derive(Clone, Copy, Default)]
pub(crate) struct Filter {
    pub(crate) src_ip: Option<IpAddr>,
    pub(crate) dst_ip: Option<IpAddr>,
    pub(crate) src_port: Option<u16>,
    pub(crate) dst_port: Option<u16>,
    pub(crate) src_mac: Option<MacAddr>,
    pub(crate) dst_mac: Option<MacAddr>,
}

impl Filter {
    /// Whether `p` satisfies every set field.
    fn matches(&self, p: &Packet) -> bool {
        self.src_ip.is_none_or(|ip| p.source.ip() == ip)
            && self.dst_ip.is_none_or(|ip| p.dest.ip() == ip)
            && self.src_port.is_none_or(|port| p.source.port() == port)
            && self.dst_port.is_none_or(|port| p.dest.port() == port)
            && self.src_mac.is_none_or(|mac| p.src_mac == Some(mac))
            && self.dst_mac.is_none_or(|mac| p.dst_mac == Some(mac))
    }
}

/// A reflector: re-emits matching packets on its egress capture(s) via
/// `dispatcher.send(key, ..)`, and may register further work through `&mut Dispatcher`
/// / `&mut Reactor`. Called only after a registration's filter matches.
pub(crate) trait PacketHandler {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    );
}

/// One routing registration: the ingress it applies to, its filter, and the reflector
/// it gates. The handler is taken out of its slot for its call (so the dispatcher is
/// free to pass `&mut self`) — the reactor's take-out, one level down.
struct Registration {
    ingress: CaptureKey,
    filter: Filter,
    handler: Option<Box<dyn PacketHandler>>,
}

/// Owns every interface capture (take-out-able slots) and the routing registrations.
/// The sole owner of capture fds: egress goes through [`send`](Self::send), keyed.
pub(crate) struct PacketDispatcher {
    /// `Option<Capture>` over the arena's own occupied/free: the inner `None` marks a
    /// capture taken out for its drain — the slot, and every key to it, stays valid.
    captures: Arena<Option<Capture>>,
    registrations: Vec<Registration>,
}

impl PacketDispatcher {
    /// An empty dispatcher.
    pub(crate) fn new() -> Self {
        Self {
            captures: Arena::new(),
            registrations: Vec::new(),
        }
    }

    /// Hand a capture to the dispatcher; the returned key is how reflectors send on it.
    pub(crate) fn add_capture(&mut self, capture: Capture) -> CaptureKey {
        CaptureKey(self.captures.insert(Some(capture)))
    }

    /// Each capture's `(fd, user_data)` for [`Reactor::register_with_fds`]: the reactor
    /// watches them all under the dispatcher's one handler key, tagging each with its
    /// [`CaptureKey`] so `on_readable` recovers the capture without a lookup.
    pub(crate) fn capture_watches(&self) -> Vec<(RawFd, u64)> {
        self.captures
            .iter()
            .filter_map(|(key, slot)| {
                slot.as_ref()
                    .map(|capture| (capture.as_raw_fd(), CaptureKey(key).to_u64()))
            })
            .collect()
    }

    /// Register `handler`, gated by `filter`, for packets captured on `ingress`.
    pub(crate) fn register(
        &mut self,
        ingress: CaptureKey,
        filter: Filter,
        handler: Box<dyn PacketHandler>,
    ) {
        self.registrations.push(Registration {
            ingress,
            filter,
            handler: Some(handler),
        });
    }

    /// Inject `frame` on the capture `egress` addresses.
    ///
    /// # Errors
    /// Returns an error if the underlying send fails. A key resolving to a drained
    /// (taken-out) or stale slot is a logged drop, not an error and never UB.
    pub(crate) fn send(&self, egress: CaptureKey, frame: &[u8]) -> io::Result<()> {
        if let Some(Some(capture)) = self.captures.get(egress.0) {
            capture.send(frame)
        } else {
            log::warn!("egress {egress:?} unavailable (drained or stale); frame dropped");
            Ok(())
        }
    }

    /// Drain the capture `ingress` addresses and route each parsed packet. Reads up to
    /// [`MAX_FRAMES_PER_EVENT`] frames, then yields for fairness (the BPF batch
    /// exception is via `has_buffered`); a read error abandons the batch and logs.
    fn drain_and_route(&mut self, ingress: CaptureKey, reactor: &mut Reactor) {
        // Take the ingress capture OUT: the parsed Packet then borrows a local, not
        // `self`, so `&mut self` is free for routing — and the reflector can send on the
        // OTHER captures still in the arena.
        let Some(slot) = self.captures.get_mut(ingress.0) else {
            log::warn!("drain_and_route: ingress {ingress:?} is gone (stale key)");
            return;
        };
        let Some(mut capture) = slot.take() else {
            // The slot is reserved but empty — a reflector re-entered the drain on its
            // own ingress, which it shouldn't; the take-out makes it a safe no-op.
            log::warn!("drain_and_route: ingress {ingress:?} already draining; skipped");
            return;
        };
        let link = capture.link_type(); // hoisted: next_frame's borrow would pin `capture`
        let fd = capture.as_raw_fd();
        let mut drained = 0u32;
        loop {
            if drained >= MAX_FRAMES_PER_EVENT && !capture.has_buffered() {
                break;
            }
            let frame = match capture.next_frame() {
                Ok(Some(frame)) => frame,
                Ok(None) => break,
                Err(e) => {
                    log::error!("fd {fd}: capture read failed, abandoning batch: {e}");
                    break;
                }
            };
            match Packet::parse(link, frame) {
                // `packet` borrows the local `capture`, not `self`, so routing through
                // `&mut self` is legal.
                Ok(packet) => {
                    log::trace!(
                        "fd {fd}: routing {} -> {} ({} B)",
                        packet.source,
                        packet.dest,
                        packet.payload.len()
                    );
                    self.route(ingress, &packet, reactor);
                }
                Err(e) => log::trace!("fd {fd}: skip unparsable frame: {e}"),
            }
            drained += 1;
        }
        if drained > 0 {
            log::trace!("fd {fd}: drained {drained} frame(s)");
        }
        if let Some(slot) = self.captures.get_mut(ingress.0) {
            *slot = Some(capture);
        } else {
            // The ingress slot vanished while we were draining it (a reflector removed
            // the interface) — drop the capture rather than resurrect a freed slot.
            log::warn!("drain_and_route: ingress {ingress:?} vanished mid-drain; capture dropped");
        }
    }

    /// Offer `packet` (captured on `ingress`) to every matching registration, in order.
    fn route(&mut self, ingress: CaptureKey, packet: &Packet, reactor: &mut Reactor) {
        // Snapshot the length: a reflector registering mid-drain must not feed itself
        // the in-flight frame, and the bound keeps the index walk valid. Registrations
        // are append-only — so index `k` stays valid across `on_packet` and the put-back
        // lands in the right slot; a remove-mid-route API would have to defer the removal.
        let n = self.registrations.len();
        for k in 0..n {
            let applies = {
                let reg = &self.registrations[k];
                reg.ingress == ingress && reg.filter.matches(packet)
            };
            if applies {
                // Take the matched reflector out of its slot so `&mut self` is free to
                // pass into the call, then restore it. `take` never misses here: a
                // `handler` is `None` only transiently, while it's out mid-call, and
                // `route` runs only from the re-entrancy-guarded drain — so none is in
                // flight when we arrive. Clearing a `handler` in place to unregister a
                // reflector would add a second cause and panic this `expect`.
                let mut handler = self.registrations[k]
                    .handler
                    .take()
                    .expect("a matching registration has its handler present");
                handler.on_packet(packet, self, reactor);
                self.registrations[k].handler = Some(handler);
            }
        }
    }
}

impl Handler for PacketDispatcher {
    /// `event.user_data` is the ready capture's [`CaptureKey`] (tagged at registration),
    /// so drain that capture directly — no fd lookup. A bad value resolves to a stale key
    /// and is a logged drop in [`drain_and_route`](Self::drain_and_route).
    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        self.drain_and_route(CaptureKey::from_u64(event.user_data), reactor);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::open_or_skip;
    use crate::net::frame;
    use std::cell::RefCell;
    use std::net::{SocketAddr, SocketAddrV4, UdpSocket};
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    fn packet(
        source: &str,
        dest: &str,
        dst_mac: Option<MacAddr>,
        src_mac: Option<MacAddr>,
    ) -> Packet<'static> {
        Packet {
            source: source.parse().unwrap(),
            dest: dest.parse().unwrap(),
            ttl: 64,
            dst_mac,
            src_mac,
            payload: b"",
        }
    }

    #[test]
    fn wildcard_filter_matches_anything() {
        assert!(Filter::default().matches(&packet("10.0.0.1:1", "10.0.0.2:2", None, None)));
    }

    #[test]
    fn filter_matches_destination_group_and_port() {
        let f = Filter {
            dst_ip: Some("224.0.0.251".parse().unwrap()),
            dst_port: Some(5353),
            ..Filter::default()
        };
        assert!(f.matches(&packet("10.0.0.1:5353", "224.0.0.251:5353", None, None)));
        // Wrong group, and wrong port, each miss.
        assert!(!f.matches(&packet("10.0.0.1:5353", "224.0.0.252:5353", None, None)));
        assert!(!f.matches(&packet("10.0.0.1:5353", "224.0.0.251:1900", None, None)));
    }

    #[test]
    fn filter_matches_source_mac_and_excludes_others() {
        let device = MacAddr::from([0x02, 0, 0, 0, 0, 0x01]);
        let f = Filter {
            src_mac: Some(device),
            ..Filter::default()
        };
        assert!(f.matches(&packet(
            "10.0.0.1:5353",
            "10.0.0.2:5353",
            None,
            Some(device)
        )));
        // A different device, and a MAC-less (DLT_NULL) packet, both miss.
        let other = MacAddr::from([0x02, 0, 0, 0, 0, 0x02]);
        assert!(!f.matches(&packet("10.0.0.1:5353", "10.0.0.2:5353", None, Some(other))));
        assert!(!f.matches(&packet("10.0.0.1:5353", "10.0.0.2:5353", None, None)));
    }

    #[test]
    fn filter_matches_destination_mac_and_excludes_others() {
        let device = MacAddr::from([0x02, 0, 0, 0, 0, 0x0a]);
        let f = Filter {
            dst_mac: Some(device),
            ..Filter::default()
        };
        assert!(f.matches(&packet(
            "10.0.0.1:5353",
            "10.0.0.2:5353",
            Some(device),
            None
        )));
        let other = MacAddr::from([0x02, 0, 0, 0, 0, 0x0b]);
        assert!(!f.matches(&packet("10.0.0.1:5353", "10.0.0.2:5353", Some(other), None)));
        assert!(!f.matches(&packet("10.0.0.1:5353", "10.0.0.2:5353", None, None)));
    }

    // An IP filter is family-specific: a v4 criterion can't match a v6 packet, or vice
    // versa (`IpAddr`'s `PartialEq` is cross-family-aware).
    #[test]
    fn filter_ip_does_not_match_across_families() {
        let v4 = Filter {
            dst_ip: Some("224.0.0.251".parse().unwrap()),
            ..Filter::default()
        };
        assert!(!v4.matches(&packet("[fe80::1]:5353", "[ff02::fb]:5353", None, None)));
        let v6 = Filter {
            dst_ip: Some("ff02::fb".parse().unwrap()),
            ..Filter::default()
        };
        assert!(!v6.matches(&packet("10.0.0.1:5353", "224.0.0.251:5353", None, None)));
    }

    #[cfg(target_os = "linux")]
    const LOOPBACK: &str = "lo";
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    const LOOPBACK: &str = "lo0";

    const PROBE: &[u8] = b"reflector-dispatch-probe";
    /// The echo re-emits to this port — distinct from the filter's, so the looped-back
    /// echo can't re-match and amplify.
    const ECHO_DST_PORT: u16 = 1;

    /// Each entry: the payload a reflector saw, and whether its keyed egress succeeded.
    type Seen = Rc<RefCell<Vec<(Vec<u8>, bool)>>>;

    /// A reflector that re-emits each matched packet on its egress capture — by key,
    /// through the dispatcher — and records what it saw. The seam `WoL` et al. will fill.
    struct Echo {
        egress: CaptureKey,
        scratch: Box<[u8]>,
        seen: Seen,
    }

    impl PacketHandler for Echo {
        fn on_packet(
            &mut self,
            packet: &Packet,
            dispatcher: &mut PacketDispatcher,
            _reactor: &mut Reactor,
        ) {
            let (SocketAddr::V4(src), SocketAddr::V4(dst)) = (packet.source, packet.dest) else {
                return;
            };
            let mac = MacAddr::from([0xff; 6]);
            let dst = SocketAddrV4::new(*dst.ip(), ECHO_DST_PORT);
            let sent = match frame::ethernet_ipv4_udp(
                mac,
                mac,
                src,
                dst,
                packet.ttl,
                packet.payload,
                &mut self.scratch,
            ) {
                Ok(n) => dispatcher.send(self.egress, &self.scratch[..n]).is_ok(),
                Err(_) => false,
            };
            self.seen.borrow_mut().push((packet.payload.to_vec(), sent));
        }
    }

    // End-to-end over loopback: a dispatcher owning two `lo` captures drains a looped
    // UDP probe off the ingress key, routes it through the matching Echo reflector,
    // which re-emits on the *egress* key. Skips without capture access (no CAP_NET_RAW).
    #[test]
    fn routes_a_captured_packet_to_a_matching_reflector() -> io::Result<()> {
        let Some(ingress_cap) = open_or_skip(LOOPBACK, "dispatch_ingress")? else {
            return Ok(());
        };
        let Some(egress_cap) = open_or_skip(LOOPBACK, "dispatch_egress")? else {
            return Ok(());
        };

        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        let target = receiver.local_addr()?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap);
        let egress = dispatcher.add_capture(egress_cap);
        let seen = Rc::new(RefCell::new(Vec::new()));
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(target.port()),
                ..Filter::default()
            },
            Box::new(Echo {
                egress,
                scratch: vec![0u8; 2048].into_boxed_slice(),
                seen: seen.clone(),
            }),
        );

        let mut reactor = Reactor::new()?;
        sender.send_to(PROBE, target)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while seen.borrow().is_empty() && Instant::now() < deadline {
            dispatcher.drain_and_route(ingress, &mut reactor);
            if seen.borrow().is_empty() {
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        let records = seen.borrow();
        assert!(!records.is_empty(), "the reflector never fired");
        assert_eq!(records[0].0, PROBE, "reflector saw the wrong payload");
        assert!(records[0].1, "the keyed egress send failed");
        Ok(())
    }

    /// A reflector that re-enters the drain on its *own* ingress from inside the call.
    /// The upstream take-out makes that nested drain return at its guard; were the
    /// take-out removed, the nested drain would pull the next buffered frame and
    /// re-route into this handler — which is taken out for the call — panicking the
    /// `expect` in `route`.
    struct Reentrant {
        ingress: CaptureKey,
        calls: Rc<RefCell<u32>>,
    }

    impl PacketHandler for Reentrant {
        fn on_packet(
            &mut self,
            _packet: &Packet,
            dispatcher: &mut PacketDispatcher,
            reactor: &mut Reactor,
        ) {
            *self.calls.borrow_mut() += 1;
            dispatcher.drain_and_route(self.ingress, reactor);
        }
    }

    // Re-entrancy guard: a reflector re-entering the drain on its own ingress must hit
    // the take-out guard, not re-route into its taken-out handler. Two probes are
    // buffered so that, without the guard, the first packet's re-entrant drain pulls the
    // second and panics `route`'s `expect`; with it, the outer loop handles both
    // (calls == 2). Skips without capture access (no CAP_NET_RAW).
    #[test]
    fn reentrant_drain_on_the_same_ingress_hits_the_guard() -> io::Result<()> {
        let Some(ingress_cap) = open_or_skip(LOOPBACK, "dispatch_reentrant")? else {
            return Ok(());
        };

        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        let target = receiver.local_addr()?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap);
        let calls = Rc::new(RefCell::new(0u32));
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(target.port()),
                ..Filter::default()
            },
            Box::new(Reentrant {
                ingress,
                calls: calls.clone(),
            }),
        );

        let mut reactor = Reactor::new()?;
        sender.send_to(PROBE, target)?;
        sender.send_to(PROBE, target)?;
        // Let both probes land in the ring before the first drain, so the re-entrant
        // drain inside the first packet has the second frame available to mis-route.
        std::thread::sleep(Duration::from_millis(50));

        let deadline = Instant::now() + Duration::from_secs(2);
        while *calls.borrow() < 2 && Instant::now() < deadline {
            dispatcher.drain_and_route(ingress, &mut reactor);
            if *calls.borrow() < 2 {
                std::thread::sleep(Duration::from_millis(20));
            }
        }

        assert_eq!(
            *calls.borrow(),
            2,
            "both probes should route via the outer drain; the re-entrant call must no-op"
        );
        Ok(())
    }

    // End-to-end through the reactor: register the dispatcher itself as a handler watching
    // its capture fds, then let `poll_once` drive it. A looped UDP probe makes the ingress
    // capture readable; the reactor names that exact fd, the dispatcher maps it back to the
    // capture, drains it, and routes to the Echo, which re-emits on the egress key.
    // Exercises the per-fd `on_readable`. Skips without capture access (no CAP_NET_RAW).
    #[test]
    fn reactor_drives_the_dispatcher_to_route_a_packet() -> io::Result<()> {
        let Some(ingress_cap) = open_or_skip(LOOPBACK, "dispatch_reactor_in")? else {
            return Ok(());
        };
        let Some(egress_cap) = open_or_skip(LOOPBACK, "dispatch_reactor_eg")? else {
            return Ok(());
        };

        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        let target = receiver.local_addr()?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap);
        let egress = dispatcher.add_capture(egress_cap);
        let seen = Rc::new(RefCell::new(Vec::new()));
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(target.port()),
                ..Filter::default()
            },
            Box::new(Echo {
                egress,
                scratch: vec![0u8; 2048].into_boxed_slice(),
                seen: seen.clone(),
            }),
        );

        let mut reactor = Reactor::new()?;
        let watches = dispatcher.capture_watches();
        reactor.register_with_fds(Box::new(dispatcher), &watches)?;

        sender.send_to(PROBE, target)?;
        let deadline = Instant::now() + Duration::from_secs(2);
        while seen.borrow().is_empty() && Instant::now() < deadline {
            reactor.poll_once(Some(Duration::from_millis(100)))?;
        }

        let records = seen.borrow();
        assert!(
            !records.is_empty(),
            "the reflector never fired via the reactor"
        );
        assert_eq!(records[0].0, PROBE, "reflector saw the wrong payload");
        assert!(records[0].1, "the keyed egress send failed");
        Ok(())
    }
}
