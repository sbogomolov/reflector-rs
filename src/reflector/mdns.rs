//! The mDNS reflector: reflects multicast DNS between the source and target interfaces so service
//! discovery crosses the link. For each address family it registers two directional
//! [`SimpleReflector`]s — queries flow source → target, responses target → source — which, atop the
//! capture's own-egress drop, breaks the reflection loop. Each re-emits to the same group at TTL 255
//! (RFC 6762 §11), sourced from the egress interface; the dispatcher's filter pins the group, so the
//! reflector only gates on the query/response classifier.

use std::net::SocketAddr;

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{Filter, IpSet, PacketDispatcher};
use crate::net::mdns::{MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT, MDNS_TTL, MdnsKind, classify};

use super::{BuildError, InterfaceMap, SimpleReflector, Verdict, require_bidirectional_families};

/// The directional gate for the source → target reflector: reflect queries, skip responses (they
/// flow the other way), and treat a too-short / non-DNS payload on the group as junk.
fn query_verdict(payload: &[u8]) -> Verdict {
    match classify(payload) {
        Some(MdnsKind::Query) => Verdict::Reflect,
        Some(MdnsKind::Response) => Verdict::Skip,
        None => Verdict::Junk,
    }
}

/// The directional gate for the target → source reflector: the mirror of [`query_verdict`].
fn response_verdict(payload: &[u8]) -> Verdict {
    match classify(payload) {
        Some(MdnsKind::Query) => Verdict::Skip,
        Some(MdnsKind::Response) => Verdict::Reflect,
        None => Verdict::Junk,
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
    let source = interfaces.require(reflector.source_if.as_str())?;
    let target = interfaces.require(reflector.target_if.as_str())?;

    // Both interfaces re-emit (queries on target, responses on source), so a required family must
    // be sendable on BOTH.
    require_bidirectional_families(
        dispatcher,
        reflector.address_family,
        source,
        reflector.source_if.as_str(),
        target,
        reflector.target_if.as_str(),
    )?;

    // Join every group on both interfaces. A family with no address yet is recorded and re-attempted
    // on the next address change, so a deferred join logs rather than fails the build.
    let groups = used_groups(reflector.address_family);
    for group in &groups {
        for capture in [source, target] {
            if let Err(e) = dispatcher.join_group(capture, group.ip()) {
                log::debug!("mDNS: join {} deferred: {e}", group.ip());
            }
        }
    }
    // One handler per direction spans every group; its filter matches the group set at the mDNS port.
    let group_ips: IpSet = groups.iter().map(SocketAddr::ip).collect();
    // source → target: reflect queries (any client on source may ask).
    dispatcher.register(
        source,
        Filter {
            dst_ip: Some(group_ips.clone()),
            dst_port: Some(MDNS_PORT.into()),
            ..Filter::default()
        },
        Box::new(SimpleReflector::new(
            target,
            "mDNS query",
            MDNS_PORT,
            MDNS_TTL,
            query_verdict,
        )),
    );
    // target → source: reflect responses, optionally only from the configured device's MAC.
    dispatcher.register(
        target,
        Filter {
            dst_ip: Some(group_ips),
            dst_port: Some(MDNS_PORT.into()),
            src_mac: reflector.macs.clone(),
            ..Filter::default()
        },
        Box::new(SimpleReflector::new(
            source,
            "mDNS response",
            MDNS_PORT,
            MDNS_TTL,
            response_verdict,
        )),
    );
    log::info!(
        "mDNS reflector \"{}\": {} <-> {}",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str()
    );
    Ok(())
}

/// The mDNS group socket addresses `family` reflects to.
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

    #[test]
    fn verdicts_gate_by_direction() {
        // A 12-byte DNS header: QR bit (offset 2, 0x80) clear = query, set = response; shorter = junk.
        let query = [0u8; 12];
        let mut response = [0u8; 12];
        response[2] = 0x80;
        assert_eq!(query_verdict(&query), Verdict::Reflect);
        assert_eq!(query_verdict(&response), Verdict::Skip);
        assert_eq!(query_verdict(&[0u8; 4]), Verdict::Junk);
        assert_eq!(response_verdict(&query), Verdict::Skip);
        assert_eq!(response_verdict(&response), Verdict::Reflect);
        assert_eq!(response_verdict(&[0u8; 4]), Verdict::Junk);
    }
}
