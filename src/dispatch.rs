//! Packet dispatch: the routing layer between captures and reflectors.
//!
//! [`PacketDispatcher`] is the single owner of every interface [`Capture`] — each linked
//! to its interface and addressed by a `Copy` [`CaptureKey`] — and of the routing
//! registrations. When an interface's fd is readable, [`drain_and_route`] takes that
//! capture *out* of the table, drains it, parses each frame into a [`Packet`], and
//! offers it to every registration whose [`Filter`] matches; a matching reflector
//! re-emits on the opposite interface via [`send`], keyed.
//!
//! Taking the ingress capture out is load-bearing: the parsed `Packet` then borrows a
//! local, not `self`, so `&mut PacketDispatcher` is free to hand to a reflector — which
//! can send on the *other* captures still in the table, and register further work. The
//! reflector never owns an fd; the fd lives in exactly one `Capture`, reached by key.
//! (`egress == ingress` can't arise — reflectors bridge A→B, never A→A; if it did, the
//! key resolves to the taken-out `None` slot and the send is a logged drop, not UB.)
//!
//! [`drain_and_route`]: PacketDispatcher::drain_and_route
//! [`send`]: PacketDispatcher::send

mod datagram;
mod dial_context;
mod interface_table;
mod multicast;

pub(crate) use self::dial_context::DialContext;

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, RawFd};
use std::time::Instant;

use crate::capture::Capture;
use crate::interface::{AddressMonitor, InterfaceAddresses};
use crate::net::LinkType;
use crate::net::mac::MacAddr;
use crate::net::packet::Packet;
use crate::reactor::{Arena, Handler, Key, Reactor, ReadyEvent};

use self::datagram::{build_udp, ethernet_dst};
use self::interface_table::InterfaceTable;

/// The most frames drained per readable event before yielding, so a flooded interface
/// can't starve the others. `AF_PACKET` stops here and the level-triggered wait
/// re-reports the rest; BPF finishes its current userland batch past this, since the
/// wait won't re-fire for those already-read records.
const MAX_FRAMES_PER_EVENT: u32 = 64;

/// The reactor `user_data` for the address monitor's fd. A [`CaptureKey`] packs a `u32`
/// (via [`to_u64`](CaptureKey::to_u64)), so `u64::MAX` never collides with a real capture.
const MONITOR_TAG: u64 = u64::MAX;

/// The dispatcher's reused send-buffer size — a standard-MTU datagram fits. One buffer serves
/// every reflector: the single-threaded loop runs one [`send_udp_group`](PacketDispatcher::send_udp_group)
/// at a time. An oversized payload is a `BufferTooSmall` error, not a truncation. It also caps a
/// forwardable datagram, so the DIAL rewrite scratch ([`REWRITE_BUF_LEN`](crate::reflector::dial::REWRITE_BUF_LEN)) anchors to it.
pub(crate) const SCRATCH_LEN: usize = 2048;

/// A `Copy` handle to a capture the dispatcher owns: an index into the interface table's
/// captures. A newtype, not a bare alias — so it can't be passed where an [`InterfaceKey`](interface_table::InterfaceKey)
/// or a reactor key is expected, where it would silently miss instead of failing to
/// compile. Captures are insert-only, so the index is a stable identity (no generation).
/// Reflectors hold these for the interface(s) they egress on and send by key, never
/// touching an fd directly.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct CaptureKey(u32);

impl CaptureKey {
    /// Pack into the reactor's opaque `user_data` slot, recoverable via
    /// [`from_u64`](Self::from_u64). With no generation to carry, this is a trivial widen,
    /// kept as a named seam so the reactor wiring stays unchanged.
    #[must_use]
    fn to_u64(self) -> u64 {
        u64::from(self.0)
    }

    /// Reconstruct a key packed by [`to_u64`](Self::to_u64); also how a test mints a synthetic key
    /// for a capture it never opens (the value is only resolved against the table on a real drain).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    pub(crate) fn from_u64(packed: u64) -> Self {
        CaptureKey(packed as u32)
    }
}

/// A `Copy` handle to a routing registration — the generational arena [`Key`] of its slot, newtyped
/// so it can't be confused with a reactor key or a [`CaptureKey`]. Returned by
/// [`register`](PacketDispatcher::register); the SSDP search reflector will hold it to
/// [`unregister`](PacketDispatcher::unregister) a per-searcher capture when its session ends.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct RegistrationKey(Key);

/// An optional-field packet filter: an unset field
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

    /// The earliest instant this handler wants [`on_deadline`](Self::on_deadline) called, or `None`
    /// (the default) if it keeps no timer. The dispatcher reports the soonest of these to the reactor,
    /// which waits within it — so a handler tracking timed state (e.g. expiring sessions) is swept on
    /// time without polling.
    fn next_deadline(&self) -> Option<Instant> {
        None
    }

    /// `now` has reached this handler's [`next_deadline`](Self::next_deadline). As in `on_packet`, it
    /// gets `&mut PacketDispatcher` (to send / register / unregister) and `&mut Reactor`.
    fn on_deadline(
        &mut self,
        _now: Instant,
        _dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
    }
}

/// One routing registration: the ingress it applies to, its filter, and the reflector
/// it gates. The handler is taken out of its slot for its call (so the dispatcher is
/// free to pass `&mut self`) — the reactor's take-out, one level down.
struct Registration {
    ingress: CaptureKey,
    filter: Filter,
    handler: Option<Box<dyn PacketHandler>>,
}

/// Owns the interface table and the routing registrations. The sole owner of capture fds:
/// egress goes through [`send`](Self::send), keyed.
pub(crate) struct PacketDispatcher {
    table: InterfaceTable,
    registrations: Arena<Registration>,
    /// Reused scratch for [`route`](Self::route)'s per-packet snapshot of the live registration
    /// keys — taken once at the start of a route so a mid-route registration isn't fed the
    /// in-flight frame, and kept allocated across calls so the data path doesn't allocate per packet.
    route_keys: Vec<RegistrationKey>,
    /// The address-change monitor, opened best-effort in [`new`](Self::new). `None` is a
    /// degraded mode: addresses stay at their startup-resolved values.
    monitor: Option<AddressMonitor>,
    /// The DIAL proxy registry, shared across the SSDP advertisement/response reflectors. Empty unless a
    /// DIAL reflector is configured; the dispatcher evicts its past-grace proxies on the deadline sweep.
    dial: DialContext,
    /// The reused frame-build buffer shared by every reflector's send (see [`SCRATCH_LEN`]).
    scratch: Box<[u8]>,
}

impl PacketDispatcher {
    /// A dispatcher with no captures yet. Opens the address monitor up front — before the
    /// first [`add_capture`](Self::add_capture) resolve — so a change during startup is
    /// already queued rather than missed.
    pub(crate) fn new() -> Self {
        Self {
            table: InterfaceTable::new(),
            registrations: Arena::new(),
            route_keys: Vec::new(),
            monitor: Self::open_monitor(),
            dial: DialContext::new(),
            scratch: vec![0u8; SCRATCH_LEN].into_boxed_slice(),
        }
    }

    /// Open the address-change monitor. Best-effort: a failure logs and yields `None` — the
    /// daemon then runs on its startup-resolved addresses (no live updates), never aborting.
    fn open_monitor() -> Option<AddressMonitor> {
        match AddressMonitor::open() {
            Ok(monitor) => {
                log::debug!("address monitor installed");
                Some(monitor)
            }
            Err(e) => {
                log::warn!("address monitor unavailable; addresses won't refresh on change: {e}");
                None
            }
        }
    }

    /// Hand a capture to the dispatcher; the returned key is how reflectors send on it. The
    /// capture's interface is found-or-created from its [`if_name`](Capture::if_name), so
    /// captures on the same interface share one [`Interface`](crate::interface::Interface) record.
    ///
    /// # Errors
    /// Propagates a resolution syscall failure when first opening the capture's interface.
    pub(crate) fn add_capture(&mut self, capture: Capture) -> io::Result<CaptureKey> {
        let interface = self.table.find_or_add_interface(capture.if_name())?;
        let key = self.table.add_capture(capture, interface);
        if let Some(name) = self.table.interface_name(interface) {
            log::debug!("watching {name} as capture {key:?}");
        }
        Ok(key)
    }

    /// Each capture's `(fd, user_data)` for [`Reactor::register_with_fds`]: the reactor
    /// watches them all under the dispatcher's one handler key, tagging each with its
    /// [`CaptureKey`] so `on_readable` recovers the capture without a lookup. The address
    /// monitor's fd, when it opened, rides along under [`MONITOR_TAG`].
    pub(crate) fn capture_watches(&self) -> Vec<(RawFd, u64)> {
        let mut watches = self.table.capture_watches();
        if let Some(monitor) = &self.monitor {
            watches.push((monitor.as_raw_fd(), MONITOR_TAG));
        }
        watches
    }

    /// Register `handler`, gated by `filter`, for packets captured on `ingress`. The returned
    /// [`Key`] removes it again via [`unregister`](Self::unregister) — for the per-searcher response
    /// captures the SSDP search reflector creates dynamically; a static reflector ignores it.
    pub(crate) fn register(
        &mut self,
        ingress: CaptureKey,
        filter: Filter,
        handler: Box<dyn PacketHandler>,
    ) -> RegistrationKey {
        RegistrationKey(self.registrations.insert(Registration {
            ingress,
            filter,
            handler: Some(handler),
        }))
    }

    /// Remove the registration `key` addresses, freeing its slot; a stale key is a safe no-op.
    /// Tears down a per-searcher response capture when its session expires.
    pub(crate) fn unregister(&mut self, key: RegistrationKey) {
        self.registrations.remove(key.0);
    }

    /// Join `group`'s multicast membership on the interface behind `capture`, so the raw capture
    /// is admitted the group's frames. Records the group for re-attempt when the interface's
    /// addresses next change. A reflector calls this at build, once per group per interface.
    ///
    /// # Errors
    /// Propagates the join's OS error. A family with no address yet is *not* an error — it's
    /// recorded and retried on the next address-up event; only a hard failure surfaces here.
    pub(crate) fn join_group(&mut self, capture: CaptureKey, group: IpAddr) -> io::Result<()> {
        let Some(interface) = self.table.interface_of(capture) else {
            log::warn!("join_group: capture {capture:?} unknown; group {group} not joined");
            return Ok(());
        };
        self.table.join_on(interface, group)
    }

    /// Inject `frame` on the capture `egress` addresses.
    ///
    /// # Errors
    /// Returns an error if the underlying send fails. A key resolving to a drained
    /// (taken-out) or out-of-range capture is a logged drop, not an error and never UB.
    pub(crate) fn send(&self, egress: CaptureKey, frame: &[u8]) -> io::Result<()> {
        if let Some(capture) = self.table.capture(egress) {
            capture.send(frame)
        } else {
            log::warn!("egress {egress:?} unavailable (drained or unknown); frame dropped");
            Ok(())
        }
    }

    /// The current source addresses of the interface behind `egress`, for a reflector
    /// building a frame. `InterfaceAddresses` is `Copy`, so a caller reads out the fields it
    /// needs.
    pub(crate) fn egress_addrs(&self, egress: CaptureKey) -> Option<&InterfaceAddresses> {
        self.table.egress_addrs(egress)
    }

    /// The DIAL proxy registry, shared by the SSDP advertisement/response reflectors so a device gets
    /// one proxy across both paths (see [`rewrite_location`](crate::reflector::dial::rewrite_location)).
    pub(crate) fn dial_context(&mut self) -> &mut DialContext {
        &mut self.dial
    }

    /// The kernel ifindex of the interface behind `capture` — its stable identity (the address
    /// resolver caches it at open, and the joiners bake it too). The SSDP search reflector bakes the
    /// target's for its IPv6 link-local reserved-port binds. `None` if the key is unknown.
    pub(crate) fn capture_ifindex(&self, capture: CaptureKey) -> Option<u32> {
        self.table.ifindex_of(capture)
    }

    /// The link-layer framing of the capture behind `egress`, so [`send_udp_group`](Self::send_udp_group)
    /// picks the matching frame builder. `None` if the key is unknown or its capture is
    /// currently taken out (mid-drain).
    pub(crate) fn link_type(&self, egress: CaptureKey) -> Option<LinkType> {
        self.table.capture(egress).map(Capture::link_type)
    }

    /// Build a UDP datagram — sourced from the egress's own address — with `dst_mac` as the L2
    /// destination, and inject it on `egress`. The caller supplies the L2 MAC, so this serves
    /// unicast, multicast, and broadcast alike; the link framing (Ethernet vs `DLT_NULL`) follows
    /// the egress's link type, and the source port, `ttl`, and `payload` are carried verbatim.
    /// Builds into the dispatcher's reused [`scratch`](SCRATCH_LEN) buffer, so the data path never
    /// allocates. An unknown or draining egress is a logged drop, like [`send`](Self::send).
    ///
    /// # Errors
    /// Propagates a send failure, and reports a frame that can't be built from the egress's
    /// current state — no source address/MAC for the datagram, or a payload that overflows
    /// the scratch buffer or the datagram length fields.
    pub(crate) fn send_udp(
        &mut self,
        egress: CaptureKey,
        dst: SocketAddr,
        dst_mac: MacAddr,
        src_port: u16,
        ttl: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        // Copy the addresses out (they're `Copy`) so the borrow of the table ends before the
        // mutable borrow of `self.scratch`.
        let (Some(addrs), Some(link)) =
            (self.egress_addrs(egress).copied(), self.link_type(egress))
        else {
            log::warn!("egress {egress:?} unavailable (drained or unknown); datagram dropped");
            return Ok(());
        };
        let n = build_udp(
            &addrs,
            link,
            dst,
            dst_mac,
            src_port,
            ttl,
            payload,
            &mut self.scratch,
        )
        .map_err(io::Error::other)?;
        self.send(egress, &self.scratch[..n])
    }

    /// Inject a broadcast/multicast UDP datagram on `egress`, deriving the L2 destination MAC from
    /// `dst`'s address class (all-ones for the IPv4 limited broadcast, the RFC-derived group MAC
    /// for multicast) — a thin wrapper over [`send_udp`](Self::send_udp). A unicast `dst` has no
    /// derivable group MAC, so it is a [`DatagramError::UnicastDestination`](datagram::DatagramError::UnicastDestination); use `send_udp` with an
    /// explicit MAC for unicast.
    ///
    /// # Errors
    /// As [`send_udp`](Self::send_udp), plus [`DatagramError::UnicastDestination`](datagram::DatagramError::UnicastDestination) for a unicast `dst`.
    pub(crate) fn send_udp_group(
        &mut self,
        egress: CaptureKey,
        dst: SocketAddr,
        src_port: u16,
        ttl: u8,
        payload: &[u8],
    ) -> io::Result<()> {
        let dst_mac = ethernet_dst(dst.ip()).map_err(io::Error::other)?;
        self.send_udp(egress, dst, dst_mac, src_port, ttl, payload)
    }

    /// Drain the capture `ingress` addresses and route each parsed packet. Reads up to
    /// [`MAX_FRAMES_PER_EVENT`] frames, then yields for fairness (the BPF batch
    /// exception is via `has_buffered`); a read error abandons the batch and logs.
    fn drain_and_route(&mut self, ingress: CaptureKey, reactor: &mut Reactor) {
        // Take the ingress capture OUT: the parsed Packet then borrows the owned local, not
        // `self`, so `&mut self` is free for routing — and a reflector can send on the OTHER
        // captures still in the table.
        let Some(mut capture) = self.table.take(ingress) else {
            if self.table.contains(ingress) {
                // In range but already taken out: a reflector re-entered the drain on its
                // own ingress, which it shouldn't; the take-out makes it a safe no-op.
                log::warn!("drain_and_route: ingress {ingress:?} already draining; skipped");
            } else {
                // Out of range: a `user_data` that names no capture reached us (a bug).
                log::warn!("drain_and_route: ingress {ingress:?} out of range; skipped");
            }
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
        if !self.table.restore(ingress, capture) {
            log::warn!("drain_and_route: ingress {ingress:?} vanished mid-drain; capture dropped");
        }
    }

    /// Offer `packet` (captured on `ingress`) to every matching registration, in order.
    fn route(&mut self, ingress: CaptureKey, packet: &Packet, reactor: &mut Reactor) {
        // Snapshot the live registration keys into the reused buffer. Taking them once means a
        // reflector registering mid-route isn't fed the in-flight frame — its key isn't in the
        // snapshot whether it appended or reused a freed slot — and a generational key keeps the
        // put-back safe even if a registration is removed during its own call (the key goes stale
        // and the restore is a no-op). `route` never nests — a handler sends but never re-drains —
        // so one shared buffer suffices.
        self.route_keys.clear();
        self.route_keys.extend(
            self.registrations
                .iter()
                .map(|(key, _)| RegistrationKey(key)),
        );
        for i in 0..self.route_keys.len() {
            let key = self.route_keys[i];
            let applies = self
                .registrations
                .get(key.0)
                .is_some_and(|reg| reg.ingress == ingress && reg.filter.matches(packet));
            if !applies {
                continue;
            }
            // Take the matched reflector out so `&mut self` is free for the call, then restore it
            // by key. `take` never misses: a `handler` is `None` only transiently while out
            // mid-call, and `route` doesn't re-enter the same registration in one pass. A `get_mut`
            // miss on the put-back means the call removed this registration — drop it, don't revive.
            let mut handler = self
                .registrations
                .get_mut(key.0)
                .expect("a key that just matched is still live")
                .handler
                .take()
                .expect("a matching registration has its handler present");
            handler.on_packet(packet, self, reactor);
            if let Some(reg) = self.registrations.get_mut(key.0) {
                reg.handler = Some(handler);
            }
        }
    }

    /// Drain the address monitor and re-resolve each interface a notification names,
    /// coalescing duplicates so one interface re-resolves at most once per wakeup. A `0`
    /// (the overflow signal) re-resolves every interface. Best-effort: a read or resolution
    /// failure logs and is dropped — the daemon keeps its last-known addresses.
    fn refresh_changed_interfaces(&mut self, reactor: &mut Reactor) {
        let Some(monitor) = self.monitor.as_mut() else {
            return;
        };
        let mut changed: Vec<u32> = Vec::new();
        if let Err(e) = monitor.drain(|ifindex| {
            if !changed.contains(&ifindex) {
                changed.push(ifindex);
            }
        }) {
            log::warn!("address monitor read failed; skipping refresh: {e}");
            return;
        }
        // The DIAL proxies bind IPv4 only, so collect the interfaces whose v4 address actually moved — a
        // routine v6 or MAC change must not churn a proxy whose v4 (and cached LOCATION) is unchanged.
        let mut v4_moved: Vec<u32> = Vec::new();
        if changed.contains(&0) {
            // 0 is the overflow signal: notifications were dropped, so re-resolve every interface.
            log::debug!("address monitor overflow; re-resolving all interfaces");
            for (ifindex, result) in self.table.refresh_all() {
                match result {
                    Ok(change) if change.v4 => v4_moved.push(ifindex),
                    Ok(_) => {}
                    Err(e) => {
                        // The overflow already means notifications were dropped, so this is the one
                        // chance to catch a move whose event was lost — and we can't confirm the v4
                        // survived. Treat it as moved so any DIAL proxy on it re-mints rather than
                        // keeping listeners bound to (and advertising) a possibly-vanished address.
                        log::warn!(
                            "re-resolving ifindex {ifindex} failed: {e}; evicting its proxies"
                        );
                        v4_moved.push(ifindex);
                    }
                }
            }
        } else {
            for ifindex in &changed {
                match self.table.refresh_by_ifindex(*ifindex) {
                    Ok(Some(change)) => {
                        log::debug!("re-resolved interface (ifindex {ifindex}) after a change");
                        if change.v4 {
                            v4_moved.push(*ifindex);
                        }
                    }
                    Ok(None) => {} // a change on an interface we don't watch
                    Err(e) => {
                        // Same conservative stance as the overflow branch: a failed re-resolve can't
                        // confirm the bound v4 survived (a notification arrived, so something changed),
                        // so evict any proxy on it rather than risk a stale, silently-dead listener.
                        log::warn!(
                            "re-resolving ifindex {ifindex} failed: {e}; evicting its proxies"
                        );
                        v4_moved.push(*ifindex);
                    }
                }
            }
        }
        // Evict proxies whose source or target interface lost the v4 address they bound: their listeners
        // sit on a vanished address and their cached LOCATION is stale, so they must re-mint, not be reused.
        self.dial.evict_on_interface_change(reactor, |cap| {
            self.table
                .ifindex_of(cap)
                .is_some_and(|ix| v4_moved.contains(&ix))
        });
    }
}

impl Handler for PacketDispatcher {
    /// [`MONITOR_TAG`] routes to an address-monitor drain; otherwise `event.user_data` is the
    /// ready capture's [`CaptureKey`] (tagged at registration), so drain that capture
    /// directly — no fd lookup. A bad capture value resolves to a stale key and is a logged
    /// drop in [`drain_and_route`](Self::drain_and_route).
    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        if event.user_data == MONITOR_TAG {
            self.refresh_changed_interfaces(reactor);
        } else {
            self.drain_and_route(CaptureKey::from_u64(event.user_data), reactor);
        }
    }

    /// The soonest deadline any registered handler keeps — the reactor waits within it.
    fn next_deadline(&self) -> Option<Instant> {
        // O(registrations) every run-loop iteration. n stays small — a few base handlers plus the
        // live SSDP sessions (≤32) — so the scan beats a min-heap, whose O(1) peek isn't worth the
        // entry invalidation a cancelled or moved deadline would force. Revisit if timers grow.
        self.registrations
            .iter()
            .filter_map(|(_, reg)| reg.handler.as_ref().and_then(|h| h.next_deadline()))
            .chain(self.dial.next_grace()) // and the soonest DIAL proxy grace, for its eviction sweep
            .min()
    }

    /// Fire [`PacketHandler::on_deadline`] on every registration whose deadline has reached `now`,
    /// taking each handler out for its call (as `route` does) so `&mut self` is free. Reached at most
    /// about once a second and only while a handler keeps a timer, so the snapshot allocation is off
    /// the data path. A registration removed during its own call isn't restored.
    fn on_deadline(&mut self, now: Instant, reactor: &mut Reactor) {
        let due: Vec<RegistrationKey> = self
            .registrations
            .iter()
            .filter(|(_, reg)| {
                reg.handler
                    .as_ref()
                    .and_then(|h| h.next_deadline())
                    .is_some_and(|d| d <= now)
            })
            .map(|(key, _)| RegistrationKey(key))
            .collect();
        for key in due {
            // Gone if an earlier handler in this sweep unregistered it (a sibling, or itself).
            let Some(mut handler) = self
                .registrations
                .get_mut(key.0)
                .and_then(|reg| reg.handler.take())
            else {
                log::trace!("deadline sweep: handler for {key:?} gone mid-sweep, skipped");
                continue;
            };
            handler.on_deadline(now, self, reactor);
            if let Some(reg) = self.registrations.get_mut(key.0) {
                reg.handler = Some(handler);
            }
        }
        self.dial.sweep(now, reactor); // evict DIAL proxies whose advertisement grace has lapsed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::open_or_skip;
    use crate::interface::LOOPBACK_IFACE;
    use std::cell::{Cell, RefCell};
    use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4, UdpSocket};
    use std::rc::Rc;
    use std::time::{Duration, Instant};

    impl PacketDispatcher {
        /// The number of live routing registrations — a seam for the SSDP session lifecycle tests.
        pub(crate) fn registration_count(&self) -> usize {
            self.registrations.iter().count()
        }
    }

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

    /// A loopback probe rig: a bound `receiver` (its port reserved so the probe has a real
    /// destination — the probe is captured off `lo`, never recv'd), the `target` to send to,
    /// and a `sender`. The caller holds the receiver alive for the test's duration.
    fn probe_rig() -> io::Result<(UdpSocket, SocketAddr, UdpSocket)> {
        let receiver = UdpSocket::bind("127.0.0.1:0")?;
        let target = receiver.local_addr()?;
        let sender = UdpSocket::bind("127.0.0.1:0")?;
        Ok((receiver, target, sender))
    }

    /// Call `step`, then sleep 20 ms, until `done` is true or `secs` elapse — the drive loop
    /// for a non-blocking driver like `drain_and_route`. (The reactor test's `poll_once` loop
    /// blocks on its own timeout instead, so it isn't routed through here.)
    fn pump_until(secs: u64, mut done: impl FnMut() -> bool, mut step: impl FnMut()) {
        let deadline = Instant::now() + Duration::from_secs(secs);
        while !done() && Instant::now() < deadline {
            step();
            if !done() {
                std::thread::sleep(Duration::from_millis(20));
            }
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
            let dst = SocketAddr::V4(SocketAddrV4::new(*dst.ip(), ECHO_DST_PORT));
            // Re-emit through the real link-aware send so the framing matches the egress link type
            // (Ethernet vs DLT_NULL) instead of a hardcoded Ethernet frame, which a DLT_NULL loopback
            // (the BSDs) rejects.
            let sent = dispatcher
                .send_udp(
                    self.egress,
                    dst,
                    MacAddr::from([0xff; 6]),
                    src.port(),
                    packet.ttl,
                    packet.payload,
                )
                .is_ok();
            self.seen.borrow_mut().push((packet.payload.to_vec(), sent));
        }
    }

    // End-to-end over loopback: a dispatcher owning two `lo` captures drains a looped
    // UDP probe off the ingress key, routes it through the matching Echo reflector,
    // which re-emits on the *egress* key. Skips without capture access (no CAP_NET_RAW).
    #[test]
    fn routes_a_captured_packet_to_a_matching_reflector() -> io::Result<()> {
        let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_ingress")? else {
            return Ok(());
        };
        let Some(egress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_egress")? else {
            return Ok(());
        };

        let (_receiver, target, sender) = probe_rig()?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap)?;
        let egress = dispatcher.add_capture(egress_cap)?;
        // The egress capture resolves to its interface's address — the seam reflectors read.
        assert_eq!(
            dispatcher
                .egress_addrs(egress)
                .and_then(InterfaceAddresses::v4),
            Some(Ipv4Addr::LOCALHOST),
        );
        let seen = Rc::new(RefCell::new(Vec::new()));
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(target.port()),
                ..Filter::default()
            },
            Box::new(Echo {
                egress,
                seen: seen.clone(),
            }),
        );

        let mut reactor = Reactor::new()?;
        sender.send_to(PROBE, target)?;
        pump_until(
            2,
            || !seen.borrow().is_empty(),
            || dispatcher.drain_and_route(ingress, &mut reactor),
        );

        let records = seen.borrow();
        assert!(!records.is_empty(), "the reflector never fired");
        assert_eq!(records[0].0, PROBE, "reflector saw the wrong payload");
        assert!(records[0].1, "the keyed egress send failed");
        Ok(())
    }

    /// A reflector that records each matched packet's payload — for routing/registration tests
    /// that need no real egress (no capture, no send).
    struct Recorder {
        seen: Rc<RefCell<Vec<Vec<u8>>>>,
    }

    impl PacketHandler for Recorder {
        fn on_packet(&mut self, packet: &Packet, _: &mut PacketDispatcher, _: &mut Reactor) {
            self.seen.borrow_mut().push(packet.payload.to_vec());
        }
    }

    /// A synthetic v4 UDP packet for routing tests; the default filter matches it.
    fn probe_packet(payload: &[u8]) -> Packet<'_> {
        Packet {
            source: "10.0.0.1:5".parse().unwrap(),
            dest: "10.0.0.2:9".parse().unwrap(),
            ttl: 64,
            dst_mac: None,
            src_mac: None,
            payload,
        }
    }

    #[test]
    fn unregister_stops_routing_to_a_handler() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let ingress = CaptureKey::from_u64(0);
        let seen = Rc::new(RefCell::new(Vec::new()));
        let key = dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Recorder { seen: seen.clone() }),
        );
        dispatcher.route(ingress, &probe_packet(b"a"), &mut reactor);
        assert_eq!(seen.borrow().len(), 1, "the registration should route once");

        dispatcher.unregister(key);
        dispatcher.route(ingress, &probe_packet(b"b"), &mut reactor);
        assert_eq!(
            seen.borrow().len(),
            1,
            "an unregistered handler is no longer routed to"
        );
        dispatcher.unregister(key); // the now-stale key removes nothing
        Ok(())
    }

    /// A reflector carrying only a timer: reports `deadline` and counts each `on_deadline` sweep —
    /// for the dispatcher's deadline aggregation/dispatch, with no packets involved.
    struct Ticker {
        deadline: Option<Instant>,
        fired: Rc<Cell<u32>>,
    }

    impl PacketHandler for Ticker {
        fn on_packet(&mut self, _: &Packet, _: &mut PacketDispatcher, _: &mut Reactor) {}
        fn next_deadline(&self) -> Option<Instant> {
            self.deadline
        }
        fn on_deadline(&mut self, _now: Instant, _: &mut PacketDispatcher, _: &mut Reactor) {
            self.fired.set(self.fired.get() + 1);
        }
    }

    #[test]
    fn reports_the_soonest_deadline_and_sweeps_only_the_due_one() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let ingress = CaptureKey::from_u64(0);
        let base = Instant::now();
        let due = Rc::new(Cell::new(0u32));
        let future = Rc::new(Cell::new(0u32));
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Ticker {
                deadline: Some(base),
                fired: due.clone(),
            }),
        );
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Ticker {
                deadline: Some(base + Duration::from_secs(10)),
                fired: future.clone(),
            }),
        );

        // The dispatcher hands the reactor the soonest registration deadline.
        assert_eq!(dispatcher.next_deadline(), Some(base));

        // A sweep fires only the registration whose deadline has come due.
        dispatcher.on_deadline(base + Duration::from_secs(1), &mut reactor);
        assert_eq!(due.get(), 1, "the due handler is swept");
        assert_eq!(future.get(), 0, "the future handler is not");
        Ok(())
    }

    /// Registers a second recorder once, from inside its own call — the mid-route registration.
    struct Registrar {
        ingress: CaptureKey,
        late: Rc<RefCell<Vec<Vec<u8>>>>,
        done: bool,
    }

    impl PacketHandler for Registrar {
        fn on_packet(&mut self, _: &Packet, dispatcher: &mut PacketDispatcher, _: &mut Reactor) {
            if !std::mem::replace(&mut self.done, true) {
                dispatcher.register(
                    self.ingress,
                    Filter::default(),
                    Box::new(Recorder {
                        seen: self.late.clone(),
                    }),
                );
            }
        }
    }

    // route snapshots the live registration keys at the start, so a registration created during the
    // call isn't in the snapshot and doesn't receive the in-flight frame — true whether it appends
    // or reuses a freed slot (a key snapshot, unlike the old length bound, doesn't depend on index).
    #[test]
    fn a_mid_route_registration_is_not_fed_the_in_flight_frame() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let ingress = CaptureKey::from_u64(0);
        let late = Rc::new(RefCell::new(Vec::new()));
        dispatcher.register(
            ingress,
            Filter::default(),
            Box::new(Registrar {
                ingress,
                late: late.clone(),
                done: false,
            }),
        );

        dispatcher.route(ingress, &probe_packet(b"x"), &mut reactor);
        assert!(
            late.borrow().is_empty(),
            "a registration born this route must not see the in-flight frame",
        );
        // It does receive the next frame.
        dispatcher.route(ingress, &probe_packet(b"y"), &mut reactor);
        assert_eq!(late.borrow().as_slice(), [b"y".to_vec()]);
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
        let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_reentrant")? else {
            return Ok(());
        };

        let (_receiver, target, sender) = probe_rig()?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap)?;
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

        pump_until(
            2,
            || *calls.borrow() >= 2,
            || dispatcher.drain_and_route(ingress, &mut reactor),
        );

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
        let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_reactor_in")? else {
            return Ok(());
        };
        let Some(egress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_reactor_eg")? else {
            return Ok(());
        };

        let (_receiver, target, sender) = probe_rig()?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap)?;
        let egress = dispatcher.add_capture(egress_cap)?;
        let seen = Rc::new(RefCell::new(Vec::new()));
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(target.port()),
                ..Filter::default()
            },
            Box::new(Echo {
                egress,
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

    // Privilege-free: a fresh dispatcher has no captures, so an out-of-range key stands in
    // for a forged reactor `user_data`. The drain guard, `egress_addrs`, `link_type`, `send`,
    // and `send_udp_group` must each be a safe no-op (log-drop / `None` / `Ok`), never a panic —
    // the new behavior the capture-gated e2e tests above skip without `CAP_NET_RAW`.
    #[test]
    fn unknown_capture_key_is_a_safe_no_op() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new()?;
        let bogus = CaptureKey::from_u64(999);
        dispatcher.drain_and_route(bogus, &mut reactor); // out-of-range guard arm, no panic
        assert!(dispatcher.egress_addrs(bogus).is_none());
        assert!(dispatcher.link_type(bogus).is_none());
        assert!(dispatcher.send(bogus, b"x").is_ok());
        // send_udp_group on an unknown egress is the same logged drop, not a build attempt.
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        assert!(dispatcher.send_udp_group(bogus, dst, 1, 64, b"x").is_ok());
        Ok(())
    }

    /// The mid-drain probe's recording: the v4 it resolved for the ingress while drained,
    /// and whether the send to the taken-out ingress returned `Ok`.
    type ProbeResult = Rc<RefCell<Option<(Option<Ipv4Addr>, bool)>>>;

    /// Probes the take-out invariants from inside the drain: while its ingress capture is
    /// taken out, the interface link stays resident (so `egress_addrs` resolves) and a send
    /// to the taken-out capture is a logged drop (`Ok`), not a panic.
    struct MidDrainProbe {
        ingress: CaptureKey,
        result: ProbeResult,
    }

    impl PacketHandler for MidDrainProbe {
        fn on_packet(
            &mut self,
            _packet: &Packet,
            dispatcher: &mut PacketDispatcher,
            _reactor: &mut Reactor,
        ) {
            let addrs = dispatcher
                .egress_addrs(self.ingress)
                .and_then(InterfaceAddresses::v4);
            let sent_ok = dispatcher.send(self.ingress, b"x").is_ok();
            *self.result.borrow_mut() = Some((addrs, sent_ok));
        }
    }

    // The wrapper design's headline invariant: the take-out clears only the inner capture,
    // leaving the interface link resident — so `egress_addrs(ingress)` still resolves while
    // the capture is drained, and `send(ingress)` drops (`Ok`) rather than panicking. Both
    // are checked from inside the reflector's call, when the ingress entry's capture is
    // `None`. Skips without capture access (no CAP_NET_RAW).
    #[test]
    fn ingress_resolves_and_drops_while_taken_out() -> io::Result<()> {
        let Some(ingress_cap) = open_or_skip(LOOPBACK_IFACE, "dispatch_mid_drain")? else {
            return Ok(());
        };

        let (_receiver, target, sender) = probe_rig()?;

        let mut dispatcher = PacketDispatcher::new();
        let ingress = dispatcher.add_capture(ingress_cap)?;
        let result = Rc::new(RefCell::new(None));
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(target.port()),
                ..Filter::default()
            },
            Box::new(MidDrainProbe {
                ingress,
                result: result.clone(),
            }),
        );

        let mut reactor = Reactor::new()?;
        sender.send_to(PROBE, target)?;
        pump_until(
            2,
            || result.borrow().is_some(),
            || dispatcher.drain_and_route(ingress, &mut reactor),
        );

        let recorded = *result.borrow();
        let (addrs, sent_ok) = recorded.expect("the probe never fired");
        assert_eq!(
            addrs,
            Some(Ipv4Addr::LOCALHOST),
            "ingress addresses must resolve while the capture is taken out"
        );
        assert!(
            sent_ok,
            "send to the taken-out ingress must drop (Ok), not panic"
        );
        Ok(())
    }

    // new() opens the routing socket; its fd joins the watch list under the sentinel tag,
    // distinct from any capture key. Best-effort: the watch appears only if the socket opened
    // (some sandboxes deny it), so an empty watch list means skip.
    #[test]
    fn monitor_fd_is_watched_under_the_sentinel_tag() {
        let dispatcher = PacketDispatcher::new();
        let watches = dispatcher.capture_watches();
        if watches.is_empty() {
            eprintln!("skip: the routing socket could not be opened in this environment");
            return;
        }
        // No captures were added, so the monitor fd is the sole watch, under MONITOR_TAG.
        assert_eq!(watches.len(), 1, "only the monitor fd should be watched");
        assert_eq!(
            watches[0].1, MONITOR_TAG,
            "the monitor fd must carry MONITOR_TAG"
        );
    }

    // A join_group on an unknown capture is logged and skipped — not an error or a panic.
    #[test]
    fn join_group_ignores_an_unknown_capture() {
        let mut dispatcher = PacketDispatcher::new();
        let group = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
        assert!(dispatcher.join_group(CaptureKey(9999), group).is_ok());
    }
}
