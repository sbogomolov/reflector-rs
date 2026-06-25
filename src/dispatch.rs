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

use std::io;
use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::{AsRawFd, RawFd};

use thiserror::Error;

use crate::capture::Capture;
use crate::interface::{AddressMonitor, Interface, InterfaceAddresses};
use crate::net::LinkType;
use crate::net::frame::{self, FrameError};
use crate::net::mac::MacAddr;
use crate::net::packet::Packet;
use crate::reactor::{Handler, Reactor, ReadyEvent};

/// The most frames drained per readable event before yielding, so a flooded interface
/// can't starve the others. `AF_PACKET` stops here and the level-triggered wait
/// re-reports the rest; BPF finishes its current userland batch past this, since the
/// wait won't re-fire for those already-read records.
const MAX_FRAMES_PER_EVENT: u32 = 64;

/// The reactor `user_data` for the address monitor's fd. A [`CaptureKey`] packs a `u32`
/// (via [`to_u64`](CaptureKey::to_u64)), so `u64::MAX` never collides with a real capture.
const MONITOR_TAG: u64 = u64::MAX;

/// A `Copy` handle to a capture the dispatcher owns: an index into the interface table's
/// captures. A newtype, not a bare alias — so it can't be passed where an [`InterfaceKey`]
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

    /// Reconstruct a key packed by [`to_u64`](Self::to_u64).
    #[must_use]
    #[allow(clippy::cast_possible_truncation)]
    fn from_u64(packed: u64) -> Self {
        CaptureKey(packed as u32)
    }
}

/// A `Copy` handle into the interface table's interfaces — an insert-only index, like
/// [`CaptureKey`], but a distinct newtype so the two can't be confused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct InterfaceKey(u32);

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
}

/// One routing registration: the ingress it applies to, its filter, and the reflector
/// it gates. The handler is taken out of its slot for its call (so the dispatcher is
/// free to pass `&mut self`) — the reactor's take-out, one level down.
struct Registration {
    ingress: CaptureKey,
    filter: Filter,
    handler: Option<Box<dyn PacketHandler>>,
}

/// One capture plus the interface it runs on. The `capture` is `Option` so the drain can
/// take it OUT (leaving the `interface` link resident, so a capture's addresses resolve
/// even mid-drain) and restore it; `None` marks "currently draining". Never removed.
struct CaptureEntry {
    capture: Option<Capture>,
    interface: InterfaceKey,
}

/// Owns every interface and every capture, linking each capture to its interface. Plain
/// `Vec`s (not generational arenas): both are insert-only, so an index is a stable identity
/// and the inner `Option<Capture>` alone marks the take-out.
struct InterfaceTable {
    interfaces: Vec<Interface>,
    captures: Vec<CaptureEntry>,
}

impl InterfaceTable {
    fn new() -> Self {
        Self {
            interfaces: Vec::new(),
            captures: Vec::new(),
        }
    }

    /// Add an interface, returning its key. Startup-only.
    fn add_interface(&mut self, interface: Interface) -> InterfaceKey {
        let key =
            InterfaceKey(u32::try_from(self.interfaces.len()).expect("interface count fits a u32"));
        self.interfaces.push(interface);
        key
    }

    /// The key of the interface named `name`, opening and resolving it if absent — so
    /// captures on the same interface share one record (and one monitor refresh later).
    ///
    /// # Errors
    /// Propagates a resolution syscall failure when first opening the interface.
    fn find_or_add_interface(&mut self, name: &str) -> io::Result<InterfaceKey> {
        if let Some(index) = self.interfaces.iter().position(|iface| iface.name == name) {
            return Ok(InterfaceKey(
                u32::try_from(index).expect("interface count fits a u32"),
            ));
        }
        Ok(self.add_interface(Interface::open(name)?))
    }

    /// Add a capture bound to `interface`, returning its key. Startup-only.
    fn add_capture(&mut self, capture: Capture, interface: InterfaceKey) -> CaptureKey {
        let key = CaptureKey(u32::try_from(self.captures.len()).expect("capture count fits a u32"));
        self.captures.push(CaptureEntry {
            capture: Some(capture),
            interface,
        });
        key
    }

    /// The interface a capture runs on — resolves even while the capture is taken out (the
    /// link is a sibling field of the take-out `Option`).
    fn interface_of(&self, capture: CaptureKey) -> Option<InterfaceKey> {
        self.captures
            .get(capture.0 as usize)
            .map(|entry| entry.interface)
    }

    /// An interface's current source addresses, by key.
    fn addrs(&self, interface: InterfaceKey) -> Option<&InterfaceAddresses> {
        self.interfaces
            .get(interface.0 as usize)
            .map(|iface| &iface.addrs)
    }

    /// The name of the interface `interface` keys, if present.
    fn interface_name(&self, interface: InterfaceKey) -> Option<&str> {
        self.interfaces
            .get(interface.0 as usize)
            .map(|iface| iface.name.as_str())
    }

    /// The current source addresses behind a capture, in one hop.
    fn egress_addrs(&self, capture: CaptureKey) -> Option<&InterfaceAddresses> {
        self.addrs(self.interface_of(capture)?)
    }

    /// A shared borrow of a present capture, for [`send`](PacketDispatcher::send).
    fn capture(&self, capture: CaptureKey) -> Option<&Capture> {
        self.captures.get(capture.0 as usize)?.capture.as_ref()
    }

    /// Whether `capture` names a known (in-range) capture — distinguishes a forged key from
    /// one that is merely taken out, for the drain's guard.
    fn contains(&self, capture: CaptureKey) -> bool {
        (capture.0 as usize) < self.captures.len()
    }

    /// Take a capture OUT for its drain; restore with [`restore`](Self::restore). `None`
    /// means out of range, or already taken out (currently draining).
    fn take(&mut self, capture: CaptureKey) -> Option<Capture> {
        self.captures.get_mut(capture.0 as usize)?.capture.take()
    }

    /// Restore a drained capture, reporting whether its slot was present — keeping logging
    /// out of the table, like [`take`](Self::take). The miss can't actually happen (restore
    /// follows a successful `take` on a Vec that never shrinks); on one, the capture drops.
    #[must_use]
    fn restore(&mut self, capture: CaptureKey, value: Capture) -> bool {
        if let Some(entry) = self.captures.get_mut(capture.0 as usize) {
            entry.capture = Some(value);
            true
        } else {
            false
        }
    }

    /// Re-resolve the interface with kernel index `ifindex`, in place. A real index matches at
    /// most one interface — they dedup by name, and the kernel gives each a distinct index —
    /// so this finds rather than scans. Returns whether one matched; a change on an interface
    /// we don't watch is `Ok(false)`. Log-free, like [`take`](Self::take); the dispatcher
    /// reports the outcome. (The caller routes the `0` overflow-signal to [`refresh_all`], so
    /// `ifindex` is always a real index here.)
    ///
    /// [`refresh_all`]: Self::refresh_all
    ///
    /// # Errors
    /// Propagates a resolution syscall failure.
    fn refresh_by_ifindex(&mut self, ifindex: u32) -> io::Result<bool> {
        let Some(iface) = self.interfaces.iter_mut().find(|i| i.ifindex == ifindex) else {
            return Ok(false);
        };
        iface.refresh()?;
        Ok(true)
    }

    /// Re-resolve every interface in place — the response to an overflow signal, where
    /// dropped notifications mean any address could be stale.
    ///
    /// # Errors
    /// Propagates the first resolution syscall failure.
    fn refresh_all(&mut self) -> io::Result<()> {
        for iface in &mut self.interfaces {
            iface.refresh()?;
        }
        Ok(())
    }

    /// Each present capture's `(fd, user_data = CaptureKey)` for
    /// [`Reactor::register_with_fds`].
    fn capture_watches(&self) -> Vec<(RawFd, u64)> {
        self.captures
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let key = CaptureKey(u32::try_from(index).expect("capture count fits a u32"));
                entry
                    .capture
                    .as_ref()
                    .map(|capture| (capture.as_raw_fd(), key.to_u64()))
            })
            .collect()
    }
}

/// Owns the interface table and the routing registrations. The sole owner of capture fds:
/// egress goes through [`send`](Self::send), keyed.
pub(crate) struct PacketDispatcher {
    table: InterfaceTable,
    registrations: Vec<Registration>,
    /// The address-change monitor, opened best-effort in [`new`](Self::new). `None` is a
    /// degraded mode: addresses stay at their startup-resolved values.
    monitor: Option<AddressMonitor>,
}

impl PacketDispatcher {
    /// A dispatcher with no captures yet. Opens the address monitor up front — before the
    /// first [`add_capture`](Self::add_capture) resolve — so a change during startup is
    /// already queued rather than missed.
    pub(crate) fn new() -> Self {
        Self {
            table: InterfaceTable::new(),
            registrations: Vec::new(),
            monitor: Self::open_monitor(),
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
    /// captures on the same interface share one [`Interface`] record.
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

    /// The link-layer framing of the capture behind `egress`, so [`send_udp_group`](Self::send_udp_group)
    /// picks the matching frame builder. `None` if the key is unknown or its capture is
    /// currently taken out (mid-drain).
    pub(crate) fn link_type(&self, egress: CaptureKey) -> Option<LinkType> {
        self.table.capture(egress).map(Capture::link_type)
    }

    /// Build a broadcast/multicast UDP datagram — sourced from the egress's own address —
    /// and inject it on `egress`. The link framing (Ethernet vs `DLT_NULL`) follows the
    /// egress's link type and the L2 destination MAC follows `dst`'s address class; the
    /// source port, `ttl`, and `payload` are carried verbatim into the new datagram.
    /// `scratch` is a caller-owned reusable buffer, so the data path never allocates. An
    /// unknown or draining egress is a logged drop, like [`send`](Self::send).
    ///
    /// # Errors
    /// Propagates a send failure, and reports a frame that can't be built from the egress's
    /// current state — no source address/MAC for the datagram, or a payload that overflows
    /// `scratch` or the datagram length fields.
    pub(crate) fn send_udp_group(
        &self,
        egress: CaptureKey,
        dst: SocketAddr,
        src_port: u16,
        ttl: u8,
        payload: &[u8],
        scratch: &mut [u8],
    ) -> io::Result<()> {
        let (Some(addrs), Some(link)) = (self.egress_addrs(egress), self.link_type(egress)) else {
            log::warn!("egress {egress:?} unavailable (drained or unknown); datagram dropped");
            return Ok(());
        };
        let n = build_udp_group(addrs, link, dst, src_port, ttl, payload, scratch)
            .map_err(io::Error::other)?;
        self.send(egress, &scratch[..n])
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

    /// Drain the address monitor and re-resolve each interface a notification names,
    /// coalescing duplicates so one interface re-resolves at most once per wakeup. A `0`
    /// (the overflow signal) re-resolves every interface. Best-effort: a read or resolution
    /// failure logs and is dropped — the daemon keeps its last-known addresses.
    fn refresh_changed_interfaces(&mut self) {
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
        // 0 is the overflow signal: notifications were dropped, so re-resolve everything.
        if changed.contains(&0) {
            log::debug!("address monitor overflow; re-resolving all interfaces");
            if let Err(e) = self.table.refresh_all() {
                log::warn!("re-resolving all interfaces failed: {e}");
            }
            return;
        }
        for ifindex in changed {
            match self.table.refresh_by_ifindex(ifindex) {
                Ok(true) => log::debug!("re-resolved interface (ifindex {ifindex}) after a change"),
                Ok(false) => {} // a change on an interface we don't watch
                Err(e) => log::warn!("re-resolving ifindex {ifindex} failed: {e}"),
            }
        }
    }
}

/// Why [`build_udp_group`] could not assemble a frame from an egress's current state. Each is a
/// case the reflector's family/MAC gating makes unreachable in practice, but they stay
/// typed so the builder is unit-testable and a stray one logs precisely.
#[derive(Debug, Error, PartialEq, Eq)]
enum BuildError {
    /// The egress has no source address for the datagram's family.
    #[error("egress has no source address for the datagram's family")]
    NoSourceAddress,
    /// An Ethernet egress has no source MAC.
    #[error("egress has no source MAC for an Ethernet frame")]
    NoSourceMac,
    /// The destination is unicast; this layer injects only to a broadcast/multicast group.
    #[error("destination is unicast; only broadcast/multicast is injected")]
    UnicastDestination,
    /// The frame builder rejected the datagram (buffer too small, or payload too large).
    #[error(transparent)]
    Frame(#[from] FrameError),
}

/// The Ethernet destination MAC for an injected datagram to `dst`: the all-ones broadcast
/// for the IPv4 limited broadcast, the RFC-derived group MAC for any multicast destination.
/// Only broadcast/multicast destinations are injected here, so a unicast `dst` — whose MAC
/// we would have to resolve — is a [`BuildError::UnicastDestination`].
fn ethernet_dst(dst: IpAddr) -> Result<MacAddr, BuildError> {
    match dst {
        IpAddr::V4(v4) if v4.is_broadcast() => Ok(MacAddr::broadcast()),
        _ if dst.is_multicast() => Ok(MacAddr::multicast_for(dst)),
        _ => Err(BuildError::UnicastDestination),
    }
}

/// Assemble a broadcast/multicast UDP datagram for an egress with addresses `addrs` and link
/// framing `link` into `scratch`, returning its byte length. The L2 source is the egress's
/// own IP and MAC; the L2 destination MAC follows `dst`'s address class. BSD `DLT_NULL`
/// (loopback/tunnel) carries no L2 addresses, so it needs neither a source MAC nor a derived
/// destination MAC.
fn build_udp_group(
    addrs: &InterfaceAddresses,
    link: LinkType,
    dst: SocketAddr,
    src_port: u16,
    ttl: u8,
    payload: &[u8],
    scratch: &mut [u8],
) -> Result<usize, BuildError> {
    match dst {
        SocketAddr::V4(dst) => {
            let src = SocketAddrV4::new(addrs.v4.ok_or(BuildError::NoSourceAddress)?, src_port);
            match link {
                LinkType::Ethernet => Ok(frame::ethernet_ipv4_udp(
                    ethernet_dst(IpAddr::V4(*dst.ip()))?,
                    addrs.mac.ok_or(BuildError::NoSourceMac)?,
                    src,
                    dst,
                    ttl,
                    payload,
                    scratch,
                )?),
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                LinkType::DltNull => Ok(frame::dlt_null_ipv4_udp(src, dst, ttl, payload, scratch)?),
            }
        }
        SocketAddr::V6(dst) => {
            let src =
                SocketAddrV6::new(addrs.v6.ok_or(BuildError::NoSourceAddress)?, src_port, 0, 0);
            match link {
                LinkType::Ethernet => Ok(frame::ethernet_ipv6_udp(
                    ethernet_dst(IpAddr::V6(*dst.ip()))?,
                    addrs.mac.ok_or(BuildError::NoSourceMac)?,
                    src,
                    dst,
                    ttl,
                    payload,
                    scratch,
                )?),
                #[cfg(any(target_os = "macos", target_os = "freebsd"))]
                LinkType::DltNull => Ok(frame::dlt_null_ipv6_udp(src, dst, ttl, payload, scratch)?),
            }
        }
    }
}

impl Handler for PacketDispatcher {
    /// [`MONITOR_TAG`] routes to an address-monitor drain; otherwise `event.user_data` is the
    /// ready capture's [`CaptureKey`] (tagged at registration), so drain that capture
    /// directly — no fd lookup. A bad capture value resolves to a stale key and is a logged
    /// drop in [`drain_and_route`](Self::drain_and_route).
    fn on_readable(&mut self, event: ReadyEvent, reactor: &mut Reactor) {
        if event.user_data == MONITOR_TAG {
            self.refresh_changed_interfaces();
        } else {
            self.drain_and_route(CaptureKey::from_u64(event.user_data), reactor);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::open_or_skip;
    use crate::interface::LOOPBACK_IFACE;
    use crate::net::frame;
    use std::cell::RefCell;
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, UdpSocket};
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

    // --- send_udp_group frame assembly (build_udp_group / ethernet_dst) — privilege-free ---

    /// A fully-populated egress: a MAC and both families, for the builder tests.
    fn full_addrs() -> InterfaceAddresses {
        InterfaceAddresses {
            mac: Some(MacAddr::from([0x02, 0, 0, 0, 0, 0x01])),
            v4: Some(Ipv4Addr::new(192, 168, 0, 2)),
            v6: Some("fe80::2".parse().unwrap()),
        }
    }

    #[test]
    fn ethernet_dst_maps_address_classes() {
        // v4 limited broadcast -> all-ones; v4/v6 multicast -> the derived group MAC.
        assert_eq!(
            ethernet_dst(IpAddr::V4(Ipv4Addr::BROADCAST)),
            Ok(MacAddr::broadcast())
        );
        let v4_group: IpAddr = "224.0.0.251".parse().unwrap();
        assert_eq!(ethernet_dst(v4_group), Ok(MacAddr::multicast_for(v4_group)));
        let v6_group: IpAddr = "ff02::1".parse().unwrap();
        assert_eq!(ethernet_dst(v6_group), Ok(MacAddr::multicast_for(v6_group)));
        // A unicast destination (either family) has no injectable L2 address.
        assert_eq!(
            ethernet_dst("192.168.0.1".parse().unwrap()),
            Err(BuildError::UnicastDestination)
        );
        assert_eq!(
            ethernet_dst("fe80::1".parse().unwrap()),
            Err(BuildError::UnicastDestination)
        );
    }

    #[test]
    fn build_udp_group_v4_broadcast_sources_from_the_egress() {
        let addrs = full_addrs();
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut scratch = [0u8; 2048];
        let n = build_udp_group(
            &addrs,
            LinkType::Ethernet,
            dst,
            4000,
            64,
            b"wol",
            &mut scratch,
        )
        .unwrap();
        // L2 header: all-ones destination, the egress's own MAC as source.
        assert_eq!(&scratch[0..6], MacAddr::broadcast().octets().as_slice());
        assert_eq!(&scratch[6..12], addrs.mac.unwrap().octets().as_slice());
        assert!(n > 12, "frame must extend past the L2 header");
    }

    #[test]
    fn build_udp_group_v6_derives_the_multicast_mac() {
        let addrs = full_addrs();
        let dst = SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 9));
        let mut scratch = [0u8; 2048];
        build_udp_group(
            &addrs,
            LinkType::Ethernet,
            dst,
            4000,
            64,
            b"wol",
            &mut scratch,
        )
        .unwrap();
        // 33:33 + the low 32 bits of ff02::1, then the egress's own MAC as source (as v4).
        assert_eq!(&scratch[0..6], [0x33, 0x33, 0, 0, 0, 0x01].as_slice());
        assert_eq!(&scratch[6..12], addrs.mac.unwrap().octets().as_slice());
    }

    #[test]
    fn build_udp_group_needs_a_source_address_for_the_family() {
        // A v6-less egress cannot source a v6 datagram.
        let v4_only = InterfaceAddresses {
            v6: None,
            ..full_addrs()
        };
        let dst = SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 9));
        let mut scratch = [0u8; 2048];
        assert_eq!(
            build_udp_group(
                &v4_only,
                LinkType::Ethernet,
                dst,
                4000,
                64,
                b"x",
                &mut scratch
            ),
            Err(BuildError::NoSourceAddress)
        );
    }

    #[test]
    fn build_udp_group_ethernet_needs_a_source_mac() {
        let no_mac = InterfaceAddresses {
            mac: None,
            ..full_addrs()
        };
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut scratch = [0u8; 2048];
        assert_eq!(
            build_udp_group(
                &no_mac,
                LinkType::Ethernet,
                dst,
                4000,
                64,
                b"x",
                &mut scratch
            ),
            Err(BuildError::NoSourceMac)
        );
    }

    #[test]
    fn build_udp_group_rejects_a_unicast_destination() {
        let dst = SocketAddr::from((Ipv4Addr::new(192, 168, 0, 5), 9));
        let mut scratch = [0u8; 2048];
        assert_eq!(
            build_udp_group(
                &full_addrs(),
                LinkType::Ethernet,
                dst,
                4000,
                64,
                b"x",
                &mut scratch
            ),
            Err(BuildError::UnicastDestination)
        );
    }

    #[test]
    fn build_udp_group_surfaces_a_frame_error() {
        // A scratch too small for the frame is a typed BuildError::Frame, not a panic — the
        // `#[from] FrameError` conversion that send_udp_group then maps onto io::Error.
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut tiny = [0u8; 16];
        assert!(matches!(
            build_udp_group(
                &full_addrs(),
                LinkType::Ethernet,
                dst,
                4000,
                64,
                b"x",
                &mut tiny
            ),
            Err(BuildError::Frame(FrameError::BufferTooSmall { .. }))
        ));
    }

    // DLT_NULL (BSD loopback) carries no L2 header, so a MAC-less egress still builds — and
    // the frame opens with the 4-byte host-order address family, not a MAC.
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn build_udp_group_dlt_null_needs_no_mac() {
        let no_mac = InterfaceAddresses {
            mac: None,
            ..full_addrs()
        };
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut scratch = [0u8; 2048];
        build_udp_group(
            &no_mac,
            LinkType::DltNull,
            dst,
            4000,
            64,
            b"wol",
            &mut scratch,
        )
        .unwrap();
        assert_eq!(
            u32::from_ne_bytes(scratch[0..4].try_into().unwrap()),
            libc::AF_INET.cast_unsigned()
        );
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
            dispatcher.egress_addrs(egress).and_then(|a| a.v4),
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
                scratch: vec![0u8; 2048].into_boxed_slice(),
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
        assert!(
            dispatcher
                .send_udp_group(bogus, dst, 1, 64, b"x", &mut [0u8; 64])
                .is_ok()
        );
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
            let addrs = dispatcher.egress_addrs(self.ingress).and_then(|a| a.v4);
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

    // refresh_by_ifindex re-resolves only the interface(s) with the matching kernel index.
    // Resolution is unprivileged (no capture needed), so this exercises the monitor's refresh
    // path without CAP_NET_RAW.
    #[test]
    fn refresh_by_ifindex_targets_the_matching_interface() -> io::Result<()> {
        let mut dispatcher = PacketDispatcher::new();
        dispatcher.table.find_or_add_interface(LOOPBACK_IFACE)?;
        let ifindex = crate::interface::if_index(LOOPBACK_IFACE).expect("loopback has an ifindex");
        assert!(
            dispatcher.table.refresh_by_ifindex(ifindex)?,
            "the loopback interface should match its ifindex and re-resolve",
        );
        assert!(
            !dispatcher.table.refresh_by_ifindex(u32::MAX)?,
            "an ifindex we don't watch should refresh nothing",
        );
        Ok(())
    }
}
