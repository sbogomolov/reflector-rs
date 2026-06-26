//! The mDNS reflector: reflects multicast DNS between the source and target interfaces so service
//! discovery crosses the link. For each address family it registers two directional handlers —
//! queries flow source → target, responses target → source — which, atop the capture's own-egress
//! drop, breaks the reflection loop. Each re-emits to the same group at TTL 255 (RFC 6762 §11),
//! sourced from the egress interface. The dispatcher's filter pins the group, so a handler only
//! classifies the message and re-emits.

use std::net::SocketAddr;

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{CaptureKey, Filter, PacketDispatcher, PacketHandler};
use crate::interface::InterfaceAddresses;
use crate::net::mdns::{MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT, MDNS_TTL, MdnsKind, classify};
use crate::net::packet::Packet;
use crate::reactor::Reactor;

use super::{BuildError, InterfaceMap, IpFamily, egress_sources, missing_required_family};

/// A built mDNS reflector for one direction of one family: re-emits each message of its `kind` (query
/// or response) captured on its ingress onto `egress`, to the message's own destination. The
/// dispatcher's filter pins that to the group, so the handler only classifies and re-emits.
struct MdnsReflector {
    egress: CaptureKey,
    kind: MdnsKind,
}

impl PacketHandler for MdnsReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
        match classify(packet.payload) {
            // A non-DNS payload on the group is anomalous but harmless; drop it quietly.
            None => log::debug!(
                "mDNS: dropping non-DNS payload ({} B) to {} from {}",
                packet.payload.len(),
                packet.dest,
                packet.source
            ),
            Some(kind) if kind == self.kind => {
                // A family the egress can't currently source is a quiet drop (transient address
                // loss), keeping send_udp_group's error meaning a genuine failure.
                if !egress_sources(dispatcher, self.egress, packet.dest) {
                    return;
                }
                match dispatcher.send_udp_group(
                    self.egress,
                    packet.dest,
                    MDNS_PORT,
                    MDNS_TTL,
                    packet.payload,
                ) {
                    Ok(()) => log::debug!(
                        "reflected mDNS {:?} from {} to {}",
                        self.kind,
                        packet.source,
                        packet.dest
                    ),
                    Err(e) => log::warn!(
                        "mDNS: cannot reflect from {} to {}: {e}",
                        packet.source,
                        packet.dest
                    ),
                }
            }
            // The other direction's traffic. Dropping it is the loop-breaker: a reflected query
            // re-emitted on the target is still a query, so the target's response-only handler
            // ignores it (and vice versa).
            Some(_) => {}
        }
    }
}

/// Build the mDNS reflector for `reflector` and register its directional handlers on `dispatcher` —
/// a no-op when mDNS isn't enabled. For each address family in use it joins the group on both
/// interfaces (so each capture is admitted the group's frames) and registers two handlers: queries
/// source → target, responses target → source. A required family must be sendable on BOTH
/// interfaces, since both re-emit.
///
/// # Errors
/// [`BuildError::UnknownInterface`] for an unopened source/target, or
/// [`BuildError::RequiredFamilyUnavailable`] if either interface can't send a required family.
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    if !reflector.mdns {
        return Ok(());
    }
    let source = interfaces
        .key_for(reflector.source_if.as_str())
        .ok_or_else(|| BuildError::UnknownInterface(reflector.source_if.as_str().to_owned()))?;
    let target = interfaces
        .key_for(reflector.target_if.as_str())
        .ok_or_else(|| BuildError::UnknownInterface(reflector.target_if.as_str().to_owned()))?;

    // Both interfaces re-emit (queries on target, responses on source), so a required family must
    // be sendable on BOTH — feed missing_required_family an AND-combined view of their addresses.
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
        // Join on both interfaces. A family with no address yet is recorded and re-attempted on
        // the next address change, so a deferred join logs rather than fails the build.
        for capture in [source, target] {
            if let Err(e) = dispatcher.join_group(capture, group_ip) {
                log::debug!("mDNS: join {group_ip} deferred: {e}");
            }
        }
        // source → target: reflect queries (any client on source may ask).
        dispatcher.register(
            source,
            Filter {
                dst_ip: Some(group_ip),
                dst_port: Some(MDNS_PORT),
                ..Filter::default()
            },
            Box::new(MdnsReflector {
                egress: target,
                kind: MdnsKind::Query,
            }),
        );
        // target → source: reflect responses, optionally only from the configured device's MAC.
        dispatcher.register(
            target,
            Filter {
                dst_ip: Some(group_ip),
                dst_port: Some(MDNS_PORT),
                src_mac: reflector.mac,
                ..Filter::default()
            },
            Box::new(MdnsReflector {
                egress: source,
                kind: MdnsKind::Response,
            }),
        );
    }
    log::info!(
        "mDNS reflector \"{}\": {} <-> {}",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str()
    );
    Ok(())
}

/// The mDNS group address (at port 5353) each family `family` uses re-emits to.
fn used_groups(family: AddressFamily) -> Vec<SocketAddr> {
    let mut groups = Vec::with_capacity(2);
    if family.uses_ipv4() {
        groups.push(SocketAddr::from((MDNS_GROUP_V4, MDNS_PORT)));
    }
    if family.uses_ipv6() {
        groups.push(SocketAddr::from((MDNS_GROUP_V6, MDNS_PORT)));
    }
    groups
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn used_groups_follows_the_address_family() {
        let v4 = SocketAddr::from((MDNS_GROUP_V4, MDNS_PORT));
        let v6 = SocketAddr::from((MDNS_GROUP_V6, MDNS_PORT));
        // Default and Dual reflect both families; the single-family policies, only their own.
        assert_eq!(used_groups(AddressFamily::Default), vec![v4, v6]);
        assert_eq!(used_groups(AddressFamily::Dual), vec![v4, v6]);
        assert_eq!(used_groups(AddressFamily::Ipv4), vec![v4]);
        assert_eq!(used_groups(AddressFamily::Ipv6), vec![v6]);
    }
}
