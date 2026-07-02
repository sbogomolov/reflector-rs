//! The SSDP reflector: reflects Simple Service Discovery Protocol (`UPnP`) between the source and
//! target interfaces so service discovery crosses the link. Advertisements (`NOTIFY`) reflect
//! target → source as a plain multicast re-emit (the [`advertisement`] module); searches (`M-SEARCH`)
//! reflect source → target and each searcher's unicast `200 OK` replies are routed back through a
//! per-searcher session (the [`search`] module). Re-emits go to the same group at TTL 2, sourced from
//! the egress interface. With `dial`, a target→source datagram's DIAL `LOCATION` is rewritten to a
//! source-side proxy ([`dial_rewrite`]).

mod advertisement;
mod search;

use std::net::SocketAddr;

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{CaptureKey, Filter, IpSet, PacketDispatcher};
use crate::interface::InterfaceAddresses;
use crate::net::ssdp::{
    SSDP_GROUP_V4, SSDP_GROUP_V6_LINK_LOCAL, SSDP_GROUP_V6_SITE_LOCAL, SSDP_PORT,
};
use crate::reactor::Reactor;

use self::advertisement::SsdpAdvertisementReflector;
use self::search::SsdpSearchReflector;
use super::dial::{ProxyPlacement, rewrite_location};
use super::{BuildError, InterfaceMap, require_bidirectional_families};

/// What a DIAL-enabled SSDP reflector needs to rewrite a device's `LOCATION` to a source-side proxy: the
/// target capture the device sits behind (for its address) and that interface's egress-pin ifindex. The
/// source side is the reflector's own egress. `None` on a reflector without `dial`.
#[derive(Clone, Copy)]
struct DialRewrite {
    target: CaptureKey,
    target_ifindex: u32,
}

/// Rewrite a target→source SSDP datagram's DIAL `LOCATION` to a source-side description proxy, into
/// `buf`. Returns the rewritten slice when `dial` is set and the rewrite succeeds, else `payload`
/// (forward verbatim). `egress` is the source capture the datagram reflects onto. Shared by the
/// advertisement and search-response directions, which both rewrite a device's `LOCATION`.
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
        dispatcher
            .egress_addrs(egress)
            .and_then(InterfaceAddresses::v4),
        dispatcher
            .egress_addrs(dial.target)
            .and_then(InterfaceAddresses::v4),
    ) else {
        return payload; // a family the proxy can't bridge yet — forward unchanged
    };
    let placement = ProxyPlacement {
        source_capture: egress,
        source,
        target_capture: dial.target,
        target,
        target_ifindex: dial.target_ifindex,
    };
    match rewrite_location(dispatcher.dial_context(), reactor, payload, placement, buf) {
        Some(n) => &buf[..n],
        None => payload,
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
    let source = interfaces.require(reflector.source_if.as_str())?;
    let target = interfaces.require(reflector.target_if.as_str())?;

    // Re-emits on both interfaces (advertisements on source, searches and their responses on target),
    // so a required family must be sendable on BOTH.
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

    // With `dial`, target→source reflectors rewrite a device's DIAL `LOCATION` to a source-side proxy
    // (IPv4 only; a non-rewritable LOCATION passes through). The device sits behind `target`.
    let dial = ssdp.dial.then_some(DialRewrite {
        target,
        target_ifindex,
    });

    // Advertisements are captured on target, searches on source — join every group on both. A family
    // with no address yet is recorded and re-attempted on the next address change.
    let groups = used_groups(reflector.address_family);
    for group in &groups {
        if let Err(e) = dispatcher.join_group(target, group.ip()) {
            log::debug!("SSDP: join {} on target deferred: {e}", group.ip());
        }
        if let Err(e) = dispatcher.join_group(source, group.ip()) {
            log::debug!("SSDP: join {} on source deferred: {e}", group.ip());
        }
    }
    // One handler per direction spans every group; its filter matches the group set at the SSDP port.
    let group_ips: IpSet = groups.iter().map(SocketAddr::ip).collect();
    // target -> source: advertisements, optionally filtered to the configured device's MAC.
    dispatcher.register(
        target,
        Filter {
            dst_ip: Some(group_ips.clone()),
            dst_port: Some(SSDP_PORT.into()),
            src_mac: reflector.macs.clone(),
            ..Filter::default()
        },
        Box::new(SsdpAdvertisementReflector::new(source, dial)),
    );
    // source -> target: searches (unfiltered — any source client may search); each searcher's
    // unicast 200-OK replies route back through a per-searcher session.
    dispatcher.register(
        source,
        Filter {
            dst_ip: Some(group_ips),
            dst_port: Some(SSDP_PORT.into()),
            ..Filter::default()
        },
        Box::new(SsdpSearchReflector::new(
            source,
            target,
            target_ifindex,
            reflector.macs.clone(),
            dial,
        )),
    );
    log::info!(
        "SSDP reflector \"{}\": {} <-> {} (advertisements + searches{})",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str(),
        if dial.is_some() { " + DIAL" } else { "" }
    );
    Ok(())
}

/// The SSDP groups `family` re-emits to: one IPv4 group, and — unlike mDNS — BOTH IPv6 scopes
/// (link-local `ff02::c` and site-local `ff05::c`).
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
