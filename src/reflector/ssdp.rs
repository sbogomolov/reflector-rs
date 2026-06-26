//! The SSDP reflector: reflects Simple Service Discovery Protocol (`UPnP`) between the source and
//! target interfaces so service discovery crosses the link. This stage reflects advertisements
//! (`NOTIFY`, target → source) only; the M-SEARCH search/unicast-response path lands in a later
//! step. Each re-emit goes to the same group at TTL 2, sourced from the egress interface. The
//! dispatcher's filter pins the group, so a handler only classifies the message and re-emits.

use std::net::SocketAddr;

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{CaptureKey, Filter, PacketDispatcher, PacketHandler};
use crate::interface::InterfaceAddresses;
use crate::net::mac::MacAddr;
use crate::net::packet::Packet;
use crate::net::ssdp::{
    SSDP_GROUP_V4, SSDP_GROUP_V6_LINK_LOCAL, SSDP_GROUP_V6_SITE_LOCAL, SSDP_PORT, SSDP_TTL,
    SsdpKind, classify,
};
use crate::reactor::Reactor;

use super::{BuildError, InterfaceMap, IpFamily, egress_sources, missing_required_family};

/// Reflects SSDP advertisements (`NOTIFY`) captured on the target onto `egress` (the source), to the
/// message's own destination — the dispatcher's filter pins that to the group. Searches (`M-SEARCH`)
/// flow the other way through a separate search reflector (a later step), so this handler only ever
/// reflects advertisements.
struct SsdpAdvertisementReflector {
    egress: CaptureKey,
}

impl PacketHandler for SsdpAdvertisementReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
        match classify(packet.payload) {
            Some(SsdpKind::Advertisement) => {
                // A family the egress can't currently source is a quiet drop (transient address
                // loss), keeping send_udp_group's error meaning a genuine failure.
                if !egress_sources(dispatcher, self.egress, packet.dest) {
                    return;
                }
                match dispatcher.send_udp_group(
                    self.egress,
                    packet.dest,
                    SSDP_PORT,
                    SSDP_TTL,
                    packet.payload,
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
            // through the search reflector (a later step).
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
/// device's own reply port (preserved from the captured packet). The search reflector (a later step)
/// creates one per session and drops it when the session expires.
#[allow(dead_code)] // registered by the SSDP search reflector (a later step)
struct SsdpResponseReflector {
    searcher: SocketAddr,
    searcher_mac: MacAddr,
    egress: CaptureKey,
}

impl PacketHandler for SsdpResponseReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
        // The dispatcher's filter already pinned this capture to the reserved port, so every packet
        // here is a unicast reply for this searcher — nothing to classify. A family the source can't
        // currently send is a quiet drop (transient address loss), as in the advertisement direction.
        if !egress_sources(dispatcher, self.egress, self.searcher) {
            return;
        }
        match dispatcher.send_udp(
            self.egress,
            self.searcher,
            self.searcher_mac,
            packet.source.port(),
            SSDP_TTL,
            packet.payload,
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

/// Build the SSDP reflector for `reflector` and register its advertisement reflector on `dispatcher` —
/// a no-op when SSDP isn't enabled. For each address family in use it joins every group on the
/// target (where advertisements are captured) and registers one handler: advertisements
/// target → source. A required family must be sendable on BOTH interfaces, since the full reflector
/// re-emits on both.
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
    if ssdp.dial {
        log::warn!(
            "SSDP reflector \"{}\": DIAL is not yet implemented; reflecting without LOCATION rewrite",
            reflector.name.as_str()
        );
    }
    let source = interfaces
        .key_for(reflector.source_if.as_str())
        .ok_or_else(|| BuildError::UnknownInterface(reflector.source_if.as_str().to_owned()))?;
    let target = interfaces
        .key_for(reflector.target_if.as_str())
        .ok_or_else(|| BuildError::UnknownInterface(reflector.target_if.as_str().to_owned()))?;

    // The full reflector re-emits on both interfaces (advertisements on source, searches and their
    // unicast responses on target), so a required family must be sendable on BOTH — feed
    // missing_required_family an AND-combined view of their addresses.
    let src = dispatcher.egress_addrs(source).copied().unwrap_or_default();
    let tgt = dispatcher.egress_addrs(target).copied().unwrap_or_default();
    let both = InterfaceAddresses {
        v4: src.v4.and(tgt.v4),
        v6: src.v6.and(tgt.v6),
        mac: tgt.mac, // unused by the family check
    };
    if let Some(family) = missing_required_family(reflector.address_family, &both) {
        let interface = match family {
            IpFamily::V4 if src.v4.is_none() => &reflector.source_if,
            IpFamily::V6 if src.v6.is_none() => &reflector.source_if,
            _ => &reflector.target_if,
        };
        return Err(BuildError::RequiredFamilyUnavailable {
            interface: interface.as_str().to_owned(),
            family,
        });
    }

    for group in used_groups(reflector.address_family) {
        let group_ip = group.ip();
        // Advertisements are captured on the target, so join there. A family with no address yet is
        // recorded and re-attempted on the next address change. (A later step joins the source too,
        // for M-SEARCH capture.)
        if let Err(e) = dispatcher.join_group(target, group_ip) {
            log::debug!("SSDP: join {group_ip} deferred: {e}");
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
            Box::new(SsdpAdvertisementReflector { egress: source }),
        );
    }
    log::info!(
        "SSDP reflector \"{}\": {} <- {} (advertisements)",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str()
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
}
