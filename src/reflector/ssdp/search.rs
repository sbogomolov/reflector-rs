//! The SSDP search direction: reflect `M-SEARCH` source → target and route each searcher's unicast
//! `200 OK` replies back through a per-searcher session.

use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use crate::dispatch::{CaptureKey, Filter, PacketDispatcher, PacketHandler, RegistrationKey};
use crate::interface::{InterfaceAddresses, Ipv6Scope};
use crate::net::mac::{MacAddr, MacSet};
use crate::net::packet::Packet;
use crate::net::port_reservation::PortReservation;
use crate::net::ssdp::{MSEARCH_MX_DEFAULT, SSDP_TTL, SsdpKind, classify, parse_msearch_mx};
use crate::reactor::Reactor;
use crate::reflector::dial::REWRITE_BUF_LEN;
use crate::reflector::egress_sources;

use super::{DialRewrite, dial_rewrite};

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

/// Reflects M-SEARCH searches source → target and routes each unicast 200-OK reply back to its
/// searcher. Registered per group on the source and owns the sessions for searches to that group —
/// one reflector per group, so the cap and table are per-group (our one-handler-per-registration
/// split, vs the C++'s single shared table). On a search it dedups against live sessions (a
/// retransmit refreshes the window and re-reflects from the same reserved port), else opens a session
/// — reserve an ephemeral port on the target, register an [`SsdpResponseReflector`] for its replies —
/// and reflects the search from that port. The deadline timer sweeps expired sessions.
pub(super) struct SsdpSearchReflector {
    /// The source capture: this reflector's ingress, and the egress its response leaves reply on.
    source: CaptureKey,
    /// The target capture: where the search is re-emitted and the 200-OKs are captured.
    target: CaptureKey,
    /// The target interface's index, for the IPv6 link-local reserved-port bind.
    target_ifindex: u32,
    /// The configured device allow-set, scoping the response capture as the advertisement direction is.
    device_macs: Option<MacSet>,
    /// DIAL `LOCATION` rewriting, stamped into each session's [`SsdpResponseReflector`].
    dial: Option<DialRewrite>,
    sessions: Vec<Session>,
}

impl SsdpSearchReflector {
    pub(super) fn new(
        source: CaptureKey,
        target: CaptureKey,
        target_ifindex: u32,
        device_macs: Option<MacSet>,
        dial: Option<DialRewrite>,
    ) -> Self {
        Self {
            source,
            target,
            target_ifindex,
            device_macs,
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
        // The 200-OKs come to the address the reflected M-SEARCH is sourced from, at the reserved
        // port — so this must be the same scope-matched pick `build_udp` makes for `packet.dest`,
        // or the device replies to a source the response capture below isn't watching.
        let our_addr = match packet.dest.ip() {
            IpAddr::V4(_) => dispatcher
                .egress_addrs(self.target)
                .and_then(InterfaceAddresses::v4)
                .map(IpAddr::V4),
            IpAddr::V6(dst6) => dispatcher
                .egress_addrs(self.target)
                .and_then(|a| a.v6(Ipv6Scope::of(dst6)))
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
                src_mac: self.device_macs.clone(),
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

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;
    use crate::net::ssdp::{SSDP_GROUP_V4, SSDP_PORT};

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
