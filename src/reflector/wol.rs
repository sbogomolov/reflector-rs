//! The Wake-on-LAN reflector: re-broadcasts magic packets seen on the source interface onto
//! the target interface, so a wake sent on one link reaches a sleeping device on another.
//!
//! A magic packet is 6 bytes of `0xFF` followed by the target device's MAC repeated 16 times
//! (102 bytes); a trailing `SecureOn` password, if present, is forwarded verbatim. The reflector
//! validates the payload, then re-emits it on the target interface as a v4 limited broadcast /
//! v6 link-local all-nodes multicast, sourced from that interface's own address.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::config::{AddressFamily, Reflector};
use crate::dispatch::{CaptureKey, Filter, PacketDispatcher, PacketHandler};
use crate::net::mac::MacSet;
use crate::net::packet::Packet;
use crate::reactor::Reactor;

use super::{BuildError, InterfaceMap, egress_sources, missing_required_family};

/// The all-ones prefix that opens a magic packet.
const PREFIX_LEN: usize = 6;
const MAC_LEN: usize = 6;
/// The target MAC repeats this many times after the prefix.
const MAC_REPS: usize = 16;
/// The smallest valid magic packet: the prefix plus the 16 MAC repetitions.
const MAGIC_LEN: usize = PREFIX_LEN + MAC_REPS * MAC_LEN;

/// The IPv6 link-local all-nodes multicast group (`ff02::1`): every node on the link, the v6
/// equivalent of the IPv4 limited broadcast a magic packet re-emits to.
const V6_ALL_NODES: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);

/// A built Wake-on-LAN reflector: re-emits each validated magic packet on its `egress` interface.
/// One is registered per configured port.
struct WolReflector {
    egress: CaptureKey,
    /// Optional device allow-set; `None` reflects a wake for any device.
    target_macs: Option<MacSet>,
    /// IP-version policy: which families this reflector re-emits.
    family: AddressFamily,
}

impl PacketHandler for WolReflector {
    fn on_packet(
        &mut self,
        packet: &Packet,
        dispatcher: &mut PacketDispatcher,
        _reactor: &mut Reactor,
    ) {
        if !is_magic_packet(packet.payload, self.target_macs.as_ref()) {
            log::debug!("WoL: ignoring non-magic packet from {}", packet.source);
            return;
        }
        let Some(dst) = wol_destination(self.family, packet) else {
            log::debug!(
                "WoL: {} is not a handled address family; ignoring",
                packet.source
            );
            return;
        };
        // A family the egress can't currently source is a quiet drop (a transient address loss);
        // that keeps send_udp_group's error meaning a genuine build/send failure.
        if !egress_sources(dispatcher, self.egress, dst) {
            log::debug!(
                "WoL: egress has no source for {dst} yet; dropping wake from {}",
                packet.source
            );
            return;
        }
        match dispatcher.send_udp_group(
            self.egress,
            dst,
            packet.source.port(),
            packet.ttl,
            packet.payload,
        ) {
            Ok(()) => log::debug!("reflected WoL packet from {} to {dst}", packet.source),
            Err(e) => log::warn!(
                "WoL: cannot reflect packet from {} to {dst}: {e}",
                packet.source
            ),
        }
    }
}

/// Whether `payload` opens with a Wake-on-LAN magic packet for an acceptable target: the
/// `6×0xFF` prefix followed by one MAC repeated 16 times. Trailing bytes (a `SecureOn` password)
/// are ignored — only the leading [`MAGIC_LEN`] are inspected — and the caller forwards them
/// as-is. When `targets` is set, the repeated MAC must be a member, so only those devices'
/// wakes are reflected.
fn is_magic_packet(payload: &[u8], targets: Option<&MacSet>) -> bool {
    let Some(magic) = payload.get(..MAGIC_LEN) else {
        return false;
    };
    if magic[..PREFIX_LEN] != [0xff; PREFIX_LEN] {
        return false;
    }
    let mac = &magic[PREFIX_LEN..PREFIX_LEN + MAC_LEN];
    // The other 15 repetitions must all equal the first.
    if !magic[PREFIX_LEN + MAC_LEN..]
        .chunks_exact(MAC_LEN)
        .all(|rep| rep == mac)
    {
        return false;
    }
    // A configured allow-set narrows the reflector to those devices' wakes.
    targets.is_none_or(|targets| targets.iter().any(|target| mac == target.octets()))
}

/// The link-wide destination a magic packet captured as `packet` re-emits to under `family`: the
/// IPv4 limited broadcast or the IPv6 link-local all-nodes group, at the captured destination
/// port. `None` when `family` doesn't handle the packet's IP version, so the reflector ignores it.
fn wol_destination(family: AddressFamily, packet: &Packet) -> Option<SocketAddr> {
    match packet.dest {
        SocketAddr::V4(dest) if family.uses_ipv4() => {
            Some(SocketAddr::from((Ipv4Addr::BROADCAST, dest.port())))
        }
        SocketAddr::V6(dest) if family.uses_ipv6() => {
            Some(SocketAddr::from((V6_ALL_NODES, dest.port())))
        }
        _ => None,
    }
}

/// Build the Wake-on-LAN reflector(s) for `reflector` and register them on `dispatcher` — a no-op
/// when Wake-on-LAN isn't enabled for it. Registers one handler per configured port (the dispatcher
/// filters a single port each), all re-emitting on the target interface.
///
/// # Errors
/// [`BuildError::UnknownInterface`] if no capture was opened for the source/target, or
/// [`BuildError::RequiredFamilyUnavailable`] if the target can't currently send a required family.
pub(crate) fn build(
    reflector: &Reflector,
    interfaces: &InterfaceMap,
    dispatcher: &mut PacketDispatcher,
) -> Result<(), BuildError> {
    let Some(wol) = &reflector.wol else {
        return Ok(());
    };
    let ingress = interfaces.require(reflector.source_if.as_str())?;
    let egress = interfaces.require(reflector.target_if.as_str())?;

    let addrs = dispatcher.egress_addrs(egress).copied().unwrap_or_default();
    if let Some(family) = missing_required_family(reflector.address_family, &addrs) {
        return Err(BuildError::RequiredFamilyUnavailable {
            interface: reflector.target_if.as_str().to_owned(),
            family,
        });
    }

    for port in wol.ports.iter() {
        dispatcher.register(
            ingress,
            Filter {
                dst_port: Some(port.get()),
                ..Filter::default()
            },
            Box::new(WolReflector {
                egress,
                target_macs: reflector.macs.clone(),
                family: reflector.address_family,
            }),
        );
    }
    log::info!(
        "WoL reflector \"{}\": {} -> {} on {} port(s)",
        reflector.name.as_str(),
        reflector.source_if.as_str(),
        reflector.target_if.as_str(),
        wol.ports.len()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mac::MacAddr;

    const DEVICE: [u8; 6] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06];

    /// A well-formed magic packet for `mac`, plus optional `trailer` (`SecureOn`) bytes.
    fn magic_packet(mac: [u8; 6], trailer: &[u8]) -> Vec<u8> {
        let mut p = vec![0xff; PREFIX_LEN];
        for _ in 0..MAC_REPS {
            p.extend_from_slice(&mac);
        }
        p.extend_from_slice(trailer);
        p
    }

    #[test]
    fn accepts_any_device_when_unfiltered() {
        assert!(is_magic_packet(&magic_packet(DEVICE, &[]), None));
    }

    #[test]
    fn accepts_a_secureon_trailer() {
        // Bytes past the 102 are a SecureOn password: ignored here, forwarded by the caller.
        let packet = magic_packet(DEVICE, &[0xde, 0xad, 0xbe, 0xef]);
        assert!(is_magic_packet(&packet, None));
    }

    #[test]
    fn filters_to_the_configured_device() {
        let packet = magic_packet(DEVICE, &[]);
        let allowed = MacSet::from(MacAddr::from(DEVICE));
        assert!(is_magic_packet(&packet, Some(&allowed)));
        let others = MacSet::from(MacAddr::from([0xaa; 6]));
        assert!(!is_magic_packet(&packet, Some(&others)));
    }

    #[test]
    fn filters_to_any_of_several_configured_devices() {
        let packet = magic_packet(DEVICE, &[]);
        let set = MacSet::try_from(vec![MacAddr::from([0xaa; 6]), MacAddr::from(DEVICE)]).unwrap();
        assert!(is_magic_packet(&packet, Some(&set)));
        let disjoint =
            MacSet::try_from(vec![MacAddr::from([0xaa; 6]), MacAddr::from([0xbb; 6])]).unwrap();
        assert!(!is_magic_packet(&packet, Some(&disjoint)));
    }

    #[test]
    fn rejects_a_short_payload() {
        let packet = magic_packet(DEVICE, &[]);
        assert!(!is_magic_packet(&packet[..MAGIC_LEN - 1], None));
        assert!(!is_magic_packet(&[], None));
    }

    #[test]
    fn rejects_a_broken_prefix() {
        let mut packet = magic_packet(DEVICE, &[]);
        packet[0] = 0xfe;
        assert!(!is_magic_packet(&packet, None));
    }

    #[test]
    fn rejects_inconsistent_repetitions() {
        let mut packet = magic_packet(DEVICE, &[]);
        // Corrupt the 7th repetition so it no longer matches the first.
        packet[PREFIX_LEN + 6 * MAC_LEN] ^= 0xff;
        assert!(!is_magic_packet(&packet, None));
    }

    /// A packet whose `dest` (the captured Wake-on-LAN port) drives the re-emit destination.
    fn packet_to(dest: &str) -> Packet<'static> {
        Packet {
            source: "10.0.0.1:5".parse().unwrap(),
            dest: dest.parse().unwrap(),
            ttl: 64,
            dst_mac: None,
            src_mac: None,
            payload: b"",
        }
    }

    #[test]
    fn wol_destination_targets_the_link_for_used_families() {
        let v4 = packet_to("10.0.0.2:9");
        let v6 = packet_to("[fe80::2]:9");
        // Dual handles both: v4 -> limited broadcast, v6 -> ff02::1, at the captured dst port.
        assert_eq!(
            wol_destination(AddressFamily::Dual, &v4),
            Some("255.255.255.255:9".parse().unwrap())
        );
        assert_eq!(
            wol_destination(AddressFamily::Dual, &v6),
            Some("[ff02::1]:9".parse().unwrap())
        );
        // A single-family policy ignores the other family.
        assert_eq!(wol_destination(AddressFamily::Ipv4, &v6), None);
        assert_eq!(wol_destination(AddressFamily::Ipv6, &v4), None);
    }
}
