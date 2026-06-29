//! The SSDP reflector: reflects Simple Service Discovery Protocol (`UPnP`) between the source and
//! target interfaces so service discovery crosses the link. Advertisements (`NOTIFY`) reflect
//! target → source as a plain multicast re-emit; searches (`M-SEARCH`) reflect source → target and
//! each searcher's unicast `200 OK` replies are routed back through a per-searcher session — an
//! ephemeral reserved port on the target, swept on a timer. Re-emits go to the same group at TTL 2,
//! sourced from the egress interface.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{CaptureKey, Filter, PacketDispatcher, PacketHandler, RegistrationKey};
use crate::net::mac::MacAddr;
use crate::net::packet::Packet;
use crate::net::port_reservation::PortReservation;
use crate::net::ssdp::{
    MSEARCH_MX_DEFAULT, SSDP_GROUP_V4, SSDP_GROUP_V6_LINK_LOCAL, SSDP_GROUP_V6_SITE_LOCAL,
    SSDP_PORT, SSDP_TTL, SsdpKind, classify, parse_msearch_mx,
};
use crate::reactor::Reactor;

use super::dial::{REWRITE_BUF_LEN, rewrite_location};
use super::{BuildError, InterfaceMap, egress_sources, require_bidirectional_families};

/// What a DIAL-enabled SSDP reflector needs to rewrite a device's `LOCATION` to a source-side proxy: the
/// target capture the device sits behind (for its address) and that interface's egress-pin ifindex. The
/// source side is the reflector's own egress. `None` on a reflector without `dial`.
#[derive(Clone, Copy)]
struct DialRewrite {
    target: CaptureKey,
    target_ifindex: u32,
}

/// Rewrite a target→source SSDP datagram's DIAL `LOCATION` to point at a source-side description proxy,
/// into `buf`. Returns the rewritten slice when `dial` is set and the rewrite succeeds, else `payload`
/// (forward verbatim). `egress` is the source capture the datagram reflects onto.
fn dial_rewrite<'a>(
    payload: &'a [u8],
    buf: &'a mut [u8],
    egress: CaptureKey,
    dial: Option<DialRewrite>,
    dispatcher: &mut PacketDispatcher,
    reactor: &mut Reactor,
) -> &'a [u8] {
    let Some(dial) = dial else {
        return payload;
    };
    let (Some(source), Some(target)) = (
        dispatcher.egress_addrs(egress).and_then(|a| a.v4),
        dispatcher.egress_addrs(dial.target).and_then(|a| a.v4),
    ) else {
        return payload; // a family the proxy can't bridge yet — forward unchanged
    };
    match rewrite_location(
        dispatcher.dial_context(),
        reactor,
        payload,
        egress,
        source,
        dial.target,
        target,
        dial.target_ifindex,
        buf,
    ) {
        Some(n) => &buf[..n],
        None => payload,
    }
}

/// Reflects SSDP advertisements (`NOTIFY`) captured on the target onto `egress` (the source), to the
/// message's own destination — the dispatcher's filter pins that to the group. Searches (`M-SEARCH`)
/// flow the other way through the [`SsdpSearchReflector`], so this handler only ever reflects
/// advertisements.
struct SsdpAdvertisementReflector {
    egress: CaptureKey,
    /// DIAL `LOCATION` rewriting, when the reflector has `dial` set; `None` leaves advertisements verbatim.
    dial: Option<DialRewrite>,
}

impl PacketHandler for SsdpAdvertisementReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) {
        match classify(packet.payload) {
            Some(SsdpKind::Advertisement) => {
                // A family the egress can't currently source is a quiet drop (transient address
                // loss), keeping send_udp_group's error meaning a genuine failure.
                if !egress_sources(dispatcher, self.egress, packet.dest) {
                    log::debug!(
                        "SSDP: egress has no source for {} yet; dropping advertisement from {}",
                        packet.dest,
                        packet.source
                    );
                    return;
                }
                let mut buf = [0u8; REWRITE_BUF_LEN];
                let payload = dial_rewrite(
                    packet.payload,
                    &mut buf,
                    self.egress,
                    self.dial,
                    dispatcher,
                    reactor,
                );
                match dispatcher.send_udp_group(
                    self.egress,
                    packet.dest,
                    SSDP_PORT,
                    SSDP_TTL,
                    payload,
                ) {
                    Ok(()) => log::debug!(
                        "reflected SSDP advertisement from {} to {}",
                        packet.source,
                        packet.dest
                    ),
                    Err(e) => log::warn!(
                        "SSDP: cannot reflect from {} to {}: {e}",
                        packet.source,
                        packet.dest
                    ),
                }
            }
            // A search (M-SEARCH) on this direction isn't reflected: searches flow source → target
            // through the SsdpSearchReflector.
            Some(SsdpKind::Search) => {}
            // A non-SSDP payload on the group is anomalous but harmless; drop it quietly.
            None => log::debug!(
                "SSDP: dropping non-SSDP payload ({} B) to {} from {}",
                packet.payload.len(),
                packet.dest,
                packet.source
            ),
        }
    }
}

/// One M-SEARCH session's reply path: a standalone leaf that re-emits each unicast `200 OK` — captured
/// at the session's reserved port on the target — onto `egress` (the source), back to the single
/// `searcher` that searched. It carries everything a reply needs, so no session lookup is required:
/// the reply goes to the searcher's captured frame MAC (no ARP/ND) and is sourced from the responding
/// device's own reply port (preserved from the captured packet). The [`SsdpSearchReflector`] creates
/// one per session and drops it when the session expires.
struct SsdpResponseReflector {
    searcher: SocketAddr,
    searcher_mac: MacAddr,
    egress: CaptureKey,
    /// DIAL `LOCATION` rewriting, inherited from the search reflector that opened this session.
    dial: Option<DialRewrite>,
}

impl PacketHandler for SsdpResponseReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        reactor: &mut Reactor,
    ) {
        // The dispatcher's filter already pinned this capture to the reserved port, so every packet
        // here is a unicast reply for this searcher — nothing to classify. A family the source can't
        // currently send is a quiet drop (transient address loss), as in the advertisement direction.
        if !egress_sources(dispatcher, self.egress, self.searcher) {
            log::debug!(
                "SSDP: egress has no source for searcher {} yet; dropping response from {}",
                self.searcher,
                packet.source
            );
            return;
        }
        let mut buf = [0u8; REWRITE_BUF_LEN];
        let payload = dial_rewrite(
            packet.payload,
            &mut buf,
            self.egress,
            self.dial,
            dispatcher,
            reactor,
        );
        match dispatcher.send_udp(
            self.egress,
            self.searcher,
            self.searcher_mac,
            packet.source.port(),
            SSDP_TTL,
            payload,
        ) {
            Ok(()) => log::debug!(
                "reflected SSDP response from {} to searcher {}",
                packet.source,
                self.searcher
            ),
            Err(e) => log::warn!(
                "SSDP: cannot reflect response to searcher {}: {e}",
                self.searcher
            ),
        }
    }
}

/// A session outlives the searcher's MX window by this grace, since a device's 200-OK may lag the
/// search (mirrors the C++).
const SESSION_GRACE: Duration = Duration::from_secs(2);
/// In-flight session cap, so a burst of searchers can't exhaust ephemeral ports or registrations.
/// At the cap a new M-SEARCH is dropped (no live session is evicted early).
const MAX_SESSIONS: usize = 32;

/// One in-flight M-SEARCH. The searcher (`ip:port`) is the dedup key; `expiry` is when the session
/// lapses; `reservation` holds the ephemeral target port the 200-OKs arrive on for the session's life
/// (dropping it frees the port); `response_key` is the per-session response capture. A
/// `RegistrationKey` is not a RAII guard, so eviction and rollback `unregister` it by hand.
struct Session {
    searcher: SocketAddr,
    expiry: Instant,
    reservation: PortReservation,
    response_key: RegistrationKey,
}

/// Reflects M-SEARCH searches source → target and routes each unicast 200-OK reply back to its
/// searcher. Registered per group on the source and owns the sessions for searches to that group —
/// one reflector per group, so the cap and table are per-group (our one-handler-per-registration
/// split, vs the C++'s single shared table). On a search it dedups against live sessions (a
/// retransmit refreshes the window and re-reflects from the same reserved port), else opens a session
/// — reserve an ephemeral port on the target, register an [`SsdpResponseReflector`] for its replies —
/// and reflects the search from that port. The deadline timer sweeps expired sessions.
struct SsdpSearchReflector {
    /// The source capture: this reflector's ingress, and the egress its response leaves reply on.
    source: CaptureKey,
    /// The target capture: where the search is re-emitted and the 200-OKs are captured.
    target: CaptureKey,
    /// The target interface's index, for the IPv6 link-local reserved-port bind.
    target_ifindex: u32,
    /// The configured device MAC, scoping the response capture as the advertisement direction is.
    device_mac: Option<MacAddr>,
    /// DIAL `LOCATION` rewriting, stamped into each session's [`SsdpResponseReflector`].
    dial: Option<DialRewrite>,
    sessions: Vec<Session>,
}

impl SsdpSearchReflector {
    fn new(
        source: CaptureKey,
        target: CaptureKey,
        target_ifindex: u32,
        device_mac: Option<MacAddr>,
        dial: Option<DialRewrite>,
    ) -> Self {
        Self {
            source,
            target,
            target_ifindex,
            device_mac,
            dial,
            sessions: Vec::new(),
        }
    }

    /// Open a session for a new searcher: reserve an ephemeral port on the target's own address of the
    /// search's family and register the 200-OK capture there — before the caller reflects, so a fast
    /// responder can't beat the capture. `None` (logged) if the cap is hit, the frame carries no
    /// source MAC to reply to, the target has no address of that family, or the reservation fails.
    fn make_session(
        &self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        expiry: Instant,
    ) -> Option<Session> {
        if self.sessions.len() >= MAX_SESSIONS {
            log::warn!(
                "SSDP: dropping M-SEARCH from {}: {MAX_SESSIONS} sessions in flight (cap)",
                packet.source
            );
            return None;
        }
        let Some(searcher_mac) = packet.src_mac else {
            log::warn!(
                "SSDP: cannot reflect M-SEARCH from {}: frame has no source MAC to reply to",
                packet.source
            );
            return None;
        };
        // The 200-OKs come to the target's own address of the search's family, at the reserved port.
        let our_addr = match packet.dest.ip() {
            IpAddr::V4(_) => dispatcher
                .egress_addrs(self.target)
                .and_then(|a| a.v4)
                .map(IpAddr::V4),
            IpAddr::V6(_) => dispatcher
                .egress_addrs(self.target)
                .and_then(|a| a.v6)
                .map(IpAddr::V6),
        };
        let Some(our_addr) = our_addr else {
            log::warn!(
                "SSDP: cannot reflect M-SEARCH from {}: target has no source address for {}",
                packet.source,
                packet.dest.ip()
            );
            return None;
        };
        let reservation = match PortReservation::create(our_addr, self.target_ifindex) {
            Ok(reservation) => reservation,
            Err(e) => {
                log::warn!(
                    "SSDP: port reservation for searcher {} failed: {e}",
                    packet.source
                );
                return None;
            }
        };
        // Register before the reflect so a fast responder's reply is captured, not ICMP-rejected.
        let response_key = dispatcher.register(
            self.target,
            Filter {
                dst_ip: Some(our_addr),
                dst_port: Some(reservation.port()),
                src_mac: self.device_mac,
                ..Filter::default()
            },
            Box::new(SsdpResponseReflector {
                searcher: packet.source,
                searcher_mac,
                egress: self.source,
                dial: self.dial,
            }),
        );
        Some(Session {
            searcher: packet.source,
            expiry,
            reservation,
            response_key,
        })
    }
}

impl PacketHandler for SsdpSearchReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
        match classify(packet.payload) {
            Some(SsdpKind::Search) => {}
            // Advertisements flow the other way (the advertisement reflector); only searches here.
            Some(SsdpKind::Advertisement) => return,
            None => {
                log::debug!(
                    "SSDP: dropping non-SSDP payload ({} B) on the search path from {}",
                    packet.payload.len(),
                    packet.source
                );
                return;
            }
        }
        let mx = parse_msearch_mx(packet.payload).unwrap_or_else(|| {
            log::info!(
                "SSDP: M-SEARCH from {} has no usable MX; using the default {MSEARCH_MX_DEFAULT}s window",
                packet.source
            );
            MSEARCH_MX_DEFAULT
        });
        let expiry = Instant::now() + Duration::from_secs(u64::from(mx)) + SESSION_GRACE;

        // A retransmit from a known searcher reuses its session: refresh the window and re-reflect
        // from the same reserved port. A new searcher opens a fresh session.
        if let Some(session) = self
            .sessions
            .iter_mut()
            .find(|s| s.searcher == packet.source)
        {
            let port = session.reservation.port();
            match dispatcher.send_udp_group(
                self.target,
                packet.dest,
                port,
                SSDP_TTL,
                packet.payload,
            ) {
                Ok(()) => {
                    session.expiry = expiry;
                    log::debug!(
                        "re-reflected M-SEARCH from {} to {} on reserved port {port} (MX {mx}s)",
                        packet.source,
                        packet.dest
                    );
                }
                Err(e) => log::warn!(
                    "SSDP: cannot reflect M-SEARCH from {} to {}: {e}",
                    packet.source,
                    packet.dest
                ),
            }
            return;
        }

        let Some(session) = self.make_session(packet, dispatcher, expiry) else {
            return; // make_session logged the cause
        };
        let port = session.reservation.port();
        match dispatcher.send_udp_group(self.target, packet.dest, port, SSDP_TTL, packet.payload) {
            Ok(()) => {
                self.sessions.push(session);
                log::debug!(
                    "reflected M-SEARCH from {} to {} on reserved port {port} (MX {mx}s); opened a session, {} active",
                    packet.source,
                    packet.dest,
                    self.sessions.len()
                );
            }
            Err(e) => {
                // Roll back the response capture just registered; the reservation drops with `session`.
                log::warn!(
                    "SSDP: cannot reflect M-SEARCH from {} to {}: {e}",
                    packet.source,
                    packet.dest
                );
                dispatcher.unregister(session.response_key);
            }
        }
    }

    fn next_deadline(&self) -> Option<Instant> {
        self.sessions.iter().map(|s| s.expiry).min()
    }

    fn on_deadline(
        &mut self,
        now: Instant,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
        self.sessions.retain(|session| {
            if session.expiry <= now {
                dispatcher.unregister(session.response_key);
                log::debug!(
                    "evicted SSDP session for searcher {} on reserved port {}",
                    session.searcher,
                    session.reservation.port()
                );
                false
            } else {
                true
            }
        });
    }
}

/// Build the SSDP reflector for `reflector` and register both directions on `dispatcher` — a no-op
/// when SSDP isn't enabled. For each address family in use it joins every group on BOTH interfaces and
/// registers two handlers per group: advertisements target → source ([`SsdpAdvertisementReflector`]),
/// and searches source → target with their unicast 200-OK replies ([`SsdpSearchReflector`]). A
/// required family must be sendable on BOTH interfaces, since the reflector re-emits on both.
///
/// # Errors
/// [`BuildError::UnknownInterface`] for an unopened source/target, or
/// [`BuildError::RequiredFamilyUnavailable`] if either interface can't send a required family.
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    let Some(ssdp) = &reflector.ssdp else {
        return Ok(());
    };
    let source = interfaces
        .key_for(reflector.source_if.as_str())
        .ok_or_else(|| BuildError::UnknownInterface(reflector.source_if.as_str().to_owned()))?;
    let target = interfaces
        .key_for(reflector.target_if.as_str())
        .ok_or_else(|| BuildError::UnknownInterface(reflector.target_if.as_str().to_owned()))?;

    // The full reflector re-emits on both interfaces (advertisements on source, searches and their
    // unicast responses on target), so a required family must be sendable on BOTH.
    require_bidirectional_families(
        dispatcher,
        reflector.address_family,
        source,
        reflector.source_if.as_str(),
        target,
        reflector.target_if.as_str(),
    )?;

    // The reserved-port bind for an IPv6 link-local target source needs the target's scope id; use
    // the ifindex the capture already cached (the single source of truth the joiners bake too).
    let target_ifindex = dispatcher.capture_ifindex(target).unwrap_or(0);

    // With `dial`, the target→source reflectors rewrite a device's DIAL `LOCATION` to a source-side
    // proxy (IPv4 only; a non-rewritable LOCATION passes through). The device sits behind `target`.
    let dial = ssdp.dial.then_some(DialRewrite {
        target,
        target_ifindex,
    });

    for group in used_groups(reflector.address_family) {
        let group_ip = group.ip();
        // Advertisements are captured on the target and searches on the source, so join the group on
        // BOTH. A family with no address yet is recorded and re-attempted on the next address change.
        if let Err(e) = dispatcher.join_group(target, group_ip) {
            log::debug!("SSDP: join {group_ip} on target deferred: {e}");
        }
        if let Err(e) = dispatcher.join_group(source, group_ip) {
            log::debug!("SSDP: join {group_ip} on source deferred: {e}");
        }
        // target -> source: reflect advertisements, optionally only from the configured device's MAC.
        dispatcher.register(
            target,
            Filter {
                dst_ip: Some(group_ip),
                dst_port: Some(SSDP_PORT),
                src_mac: reflector.mac,
                ..Filter::default()
            },
            Box::new(SsdpAdvertisementReflector {
                egress: source,
                dial,
            }),
        );
        // source -> target: reflect searches (unfiltered — any source client may search) and route
        // each searcher's unicast 200-OK replies back through a per-searcher session.
        dispatcher.register(
            source,
            Filter {
                dst_ip: Some(group_ip),
                dst_port: Some(SSDP_PORT),
                ..Filter::default()
            },
            Box::new(SsdpSearchReflector::new(
                source,
                target,
                target_ifindex,
                reflector.mac,
                dial,
            )),
        );
    }
    log::info!(
        "SSDP reflector \"{}\": {} <-> {} (advertisements + searches{})",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str(),
        if dial.is_some() { " + DIAL" } else { "" }
    );
    Ok(())
}

/// The SSDP group address(es) (at port 1900) family `family` re-emits to: one IPv4 group, and —
/// unlike mDNS — BOTH IPv6 scopes (link-local `ff02::c` and site-local `ff05::c`).
fn used_groups(family: AddressFamily) -> Vec<SocketAddr> {
    let mut groups = Vec::with_capacity(3);
    if family.uses_ipv4() {
        groups.push(SocketAddr::from((SSDP_GROUP_V4, SSDP_PORT)));
    }
    if family.uses_ipv6() {
        groups.push(SocketAddr::from((SSDP_GROUP_V6_LINK_LOCAL, SSDP_PORT)));
        groups.push(SocketAddr::from((SSDP_GROUP_V6_SITE_LOCAL, SSDP_PORT)));
    }
    groups
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn used_groups_follows_the_address_family() {
        let v4 = SocketAddr::from((SSDP_GROUP_V4, SSDP_PORT));
        let link_local = SocketAddr::from((SSDP_GROUP_V6_LINK_LOCAL, SSDP_PORT));
        let site_local = SocketAddr::from((SSDP_GROUP_V6_SITE_LOCAL, SSDP_PORT));
        // Default and Dual reflect both families; IPv6 uses both scopes (link-local + site-local).
        assert_eq!(
            used_groups(AddressFamily::Default),
            vec![v4, link_local, site_local]
        );
        assert_eq!(
            used_groups(AddressFamily::Dual),
            vec![v4, link_local, site_local]
        );
        assert_eq!(used_groups(AddressFamily::Ipv4), vec![v4]);
        assert_eq!(
            used_groups(AddressFamily::Ipv6),
            vec![link_local, site_local]
        );
    }

    /// Push a session for `searcher` onto `reflector`: a real loopback port reservation plus a
    /// registered response capture, so eviction has a registration to tear down. (`PortReservation`
    /// binds a socket directly, so no capture / `CAP_NET_RAW` is needed.)
    fn push_session(
        reflector: &mut SsdpSearchReflector,
        dispatcher: &mut PacketDispatcher,
        searcher: &str,
        expiry: Instant,
    ) {
        let searcher: SocketAddr = searcher.parse().unwrap();
        let (target, source) = (reflector.target, reflector.source);
        let reservation = PortReservation::create(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
            .expect("reserve a loopback port");
        let response_key = dispatcher.register(
            target,
            Filter::default(),
            Box::new(SsdpResponseReflector {
                searcher,
                searcher_mac: MacAddr::from([0; 6]),
                egress: source,
                dial: None,
            }),
        );
        reflector.sessions.push(Session {
            searcher,
            expiry,
            reservation,
            response_key,
        });
    }

    #[test]
    fn next_deadline_is_the_soonest_session_expiry() {
        let mut dispatcher = PacketDispatcher::new();
        let mut reflector = SsdpSearchReflector::new(
            CaptureKey::from_u64(1),
            CaptureKey::from_u64(0),
            0,
            None,
            None,
        );
        assert_eq!(
            reflector.next_deadline(),
            None,
            "no sessions means no timer"
        );
        let base = Instant::now();
        push_session(
            &mut reflector,
            &mut dispatcher,
            "10.0.0.1:5",
            base + Duration::from_secs(5),
        );
        push_session(
            &mut reflector,
            &mut dispatcher,
            "10.0.0.2:5",
            base + Duration::from_secs(2),
        );
        assert_eq!(
            reflector.next_deadline(),
            Some(base + Duration::from_secs(2))
        );
    }

    #[test]
    fn on_deadline_evicts_expired_sessions_and_unregisters_their_captures() {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new().unwrap();
        let mut reflector = SsdpSearchReflector::new(
            CaptureKey::from_u64(1),
            CaptureKey::from_u64(0),
            0,
            None,
            None,
        );
        let base = Instant::now();
        push_session(&mut reflector, &mut dispatcher, "10.0.0.1:5", base); // already due
        push_session(
            &mut reflector,
            &mut dispatcher,
            "10.0.0.2:5",
            base + Duration::from_secs(10),
        ); // live
        assert_eq!(dispatcher.registration_count(), 2);

        reflector.on_deadline(base + Duration::from_secs(1), &mut dispatcher, &mut reactor);

        assert_eq!(
            reflector.sessions.len(),
            1,
            "the expired session is dropped"
        );
        assert_eq!(
            reflector.sessions[0].searcher,
            "10.0.0.2:5".parse::<SocketAddr>().unwrap()
        );
        assert_eq!(
            dispatcher.registration_count(),
            1,
            "its response capture is unregistered with it"
        );
        assert_eq!(
            reflector.next_deadline(),
            Some(base + Duration::from_secs(10))
        );
    }

    #[test]
    fn a_retransmit_reuses_its_session_and_refreshes_the_window() {
        let mut dispatcher = PacketDispatcher::new();
        let mut reactor = Reactor::new().unwrap();
        // A synthetic target: send_udp_group on an unknown egress drops the datagram and returns Ok,
        // so the re-reflect "succeeds" with no real capture — this exercises only the bookkeeping.
        let mut reflector = SsdpSearchReflector::new(
            CaptureKey::from_u64(1),
            CaptureKey::from_u64(0),
            0,
            None,
            None,
        );
        let base = Instant::now();
        push_session(&mut reflector, &mut dispatcher, "10.0.0.7:50000", base);
        assert_eq!(dispatcher.registration_count(), 1);

        let packet = Packet {
            source: "10.0.0.7:50000".parse().unwrap(),
            dest: SocketAddr::from((SSDP_GROUP_V4, SSDP_PORT)),
            ttl: SSDP_TTL,
            dst_mac: None,
            src_mac: Some(MacAddr::from([0x02, 0, 0, 0, 0, 1])),
            payload: b"M-SEARCH * HTTP/1.1\r\nMX: 2\r\n\r\n",
        };
        reflector.on_packet(&packet, &mut dispatcher, &mut reactor);

        assert_eq!(
            reflector.sessions.len(),
            1,
            "a retransmit reuses its session, not a new one"
        );
        assert_eq!(
            dispatcher.registration_count(),
            1,
            "no second response capture is registered"
        );
        assert!(
            reflector.sessions[0].expiry > base,
            "the session's window is refreshed"
        );
    }
}
