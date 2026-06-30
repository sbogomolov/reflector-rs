//! Assembling a UDP datagram for an egress: pick the L2 destination MAC and the frame builder for the
//! egress's link type, sourcing from the egress's own address. The adapter over [`net::frame`](crate::net::frame)
//! the dispatcher's send path uses.

use std::net::{IpAddr, SocketAddr, SocketAddrV4, SocketAddrV6};

use thiserror::Error;

use crate::interface::{InterfaceAddresses, Ipv6Scope};
use crate::net::LinkType;
use crate::net::frame::{self, FrameError};
use crate::net::mac::MacAddr;

/// Why a datagram could not be assembled for an egress: from [`build_udp`] (no source address or
/// MAC, or a frame overflow) or [`ethernet_dst`] (a unicast destination). Each is a case the
/// reflector's family/MAC gating makes unreachable in practice, but they stay typed so the
/// builder is unit-testable and a stray one logs precisely.
#[derive(Debug, Error, PartialEq, Eq)]
pub(super) enum DatagramError {
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
/// we would have to resolve — is a [`DatagramError::UnicastDestination`].
pub(super) fn ethernet_dst(dst: IpAddr) -> Result<MacAddr, DatagramError> {
    match dst {
        IpAddr::V4(v4) if v4.is_broadcast() => Ok(MacAddr::broadcast()),
        _ if dst.is_multicast() => Ok(MacAddr::multicast_for(dst)),
        _ => Err(DatagramError::UnicastDestination),
    }
}

/// Assemble a UDP datagram for an egress with addresses `addrs` and link framing `link` into
/// `scratch`, returning its byte length. The L2 source is the egress's own IP and MAC; the L2
/// destination is the caller-supplied `dst_mac` (so this serves unicast, multicast, and broadcast
/// alike). BSD `DLT_NULL` (loopback/tunnel) carries no L2 addresses, so it ignores `dst_mac` and
/// needs no source MAC.
// A frame builder takes the full wire spec (egress addrs + link, dst addr + MAC, port, ttl,
// payload, buffer); bundling any of these would obscure more than the arg count costs.
#[allow(clippy::too_many_arguments)]
pub(super) fn build_udp(
    addrs: &InterfaceAddresses,
    link: LinkType,
    dst: SocketAddr,
    dst_mac: MacAddr,
    src_port: u16,
    ttl: u8,
    payload: &[u8],
    scratch: &mut [u8],
) -> Result<usize, DatagramError> {
    match dst {
        SocketAddr::V4(dst) => {
            let src =
                SocketAddrV4::new(addrs.v4().ok_or(DatagramError::NoSourceAddress)?, src_port);
            match link {
                LinkType::Ethernet => Ok(frame::ethernet_ipv4_udp(
                    dst_mac,
                    addrs.mac().ok_or(DatagramError::NoSourceMac)?,
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
            // Source the datagram from an address matching the destination's scope, so a site-local
            // group (`ff05::c`) isn't sourced from a link-local address.
            let src_ip = addrs
                .v6(Ipv6Scope::of(*dst.ip()))
                .ok_or(DatagramError::NoSourceAddress)?;
            let src = SocketAddrV6::new(src_ip, src_port, 0, 0);
            match link {
                LinkType::Ethernet => Ok(frame::ethernet_ipv6_udp(
                    dst_mac,
                    addrs.mac().ok_or(DatagramError::NoSourceMac)?,
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

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;

    /// A fully-populated egress: a MAC, v4, a link-local v6, and a routable v6, for the builder tests.
    fn full_addrs() -> InterfaceAddresses {
        InterfaceAddresses::new(
            Some(MacAddr::from([0x02, 0, 0, 0, 0, 0x01])),
            Some(Ipv4Addr::new(192, 168, 0, 2)),
            Some("fe80::2".parse().unwrap()),
            Some("2001:db8::2".parse().unwrap()),
        )
    }

    #[test]
    fn build_udp_sources_a_site_local_group_from_the_routable_address() {
        // A site-local SSDP group (ff05::c) must be sourced from the routable address, not the
        // link-local one — the per-scope selection.
        let addrs = full_addrs();
        let dst = SocketAddr::from((Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x0c), 1900));
        let mut scratch = [0u8; 2048];
        let n = build_udp(
            &addrs,
            LinkType::Ethernet,
            dst,
            MacAddr::multicast_for(dst.ip()),
            4000,
            2,
            b"ssdp",
            &mut scratch,
        )
        .unwrap();
        // The IPv6 source address sits at bytes [22..38] of the frame (14 Ethernet + offset 8 into
        // the v6 header). A site-local destination is sourced from the routable v6, not fe80::2.
        assert_eq!(
            &scratch[22..38],
            "2001:db8::2"
                .parse::<Ipv6Addr>()
                .unwrap()
                .octets()
                .as_slice(),
            "ff05::c sourced from the routable address"
        );
        assert!(n > 38);
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
            Err(DatagramError::UnicastDestination)
        );
        assert_eq!(
            ethernet_dst("fe80::1".parse().unwrap()),
            Err(DatagramError::UnicastDestination)
        );
    }

    #[test]
    fn build_udp_v4_broadcast_sources_from_the_egress() {
        let addrs = full_addrs();
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut scratch = [0u8; 2048];
        let n = build_udp(
            &addrs,
            LinkType::Ethernet,
            dst,
            MacAddr::broadcast(),
            4000,
            64,
            b"wol",
            &mut scratch,
        )
        .unwrap();
        // L2 header: the supplied destination MAC, the egress's own MAC as source.
        assert_eq!(&scratch[0..6], MacAddr::broadcast().octets().as_slice());
        assert_eq!(&scratch[6..12], addrs.mac().unwrap().octets().as_slice());
        assert!(n > 12, "frame must extend past the L2 header");
    }

    #[test]
    fn build_udp_v6_writes_the_supplied_mac() {
        let addrs = full_addrs();
        let group = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1);
        let dst = SocketAddr::from((group, 9));
        let mut scratch = [0u8; 2048];
        build_udp(
            &addrs,
            LinkType::Ethernet,
            dst,
            MacAddr::multicast_for(IpAddr::V6(group)),
            4000,
            64,
            b"wol",
            &mut scratch,
        )
        .unwrap();
        // 33:33 + the low 32 bits of ff02::1 (the supplied MAC), then the egress's own MAC.
        assert_eq!(&scratch[0..6], [0x33, 0x33, 0, 0, 0, 0x01].as_slice());
        assert_eq!(&scratch[6..12], addrs.mac().unwrap().octets().as_slice());
    }

    #[test]
    fn build_udp_assembles_a_unicast_frame() {
        // The unicast path the M-SEARCH 200-OK reply will use: an explicit dst MAC, a unicast dst
        // (build_udp doesn't derive the MAC, so unicast is fine — unlike send_udp_group).
        let addrs = full_addrs();
        let searcher_mac = MacAddr::from([0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f]);
        let dst = SocketAddr::from((Ipv4Addr::new(192, 168, 0, 5), 9));
        let mut scratch = [0u8; 2048];
        let n = build_udp(
            &addrs,
            LinkType::Ethernet,
            dst,
            searcher_mac,
            4000,
            64,
            b"ok",
            &mut scratch,
        )
        .unwrap();
        // The supplied unicast MAC is the L2 destination; the egress's own MAC is the source.
        assert_eq!(&scratch[0..6], searcher_mac.octets().as_slice());
        assert_eq!(&scratch[6..12], addrs.mac().unwrap().octets().as_slice());
        assert!(n > 12);
    }

    #[test]
    fn build_udp_needs_a_source_address_for_the_family() {
        // A v6-less egress cannot source a v6 datagram.
        let v4_only = InterfaceAddresses::new(
            Some(MacAddr::from([0x02, 0, 0, 0, 0, 0x01])),
            Some(Ipv4Addr::new(192, 168, 0, 2)),
            None,
            None,
        );
        let dst = SocketAddr::from((Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 1), 9));
        let mut scratch = [0u8; 2048];
        assert_eq!(
            build_udp(
                &v4_only,
                LinkType::Ethernet,
                dst,
                MacAddr::broadcast(),
                4000,
                64,
                b"x",
                &mut scratch
            ),
            Err(DatagramError::NoSourceAddress)
        );
    }

    #[test]
    fn build_udp_ethernet_needs_a_source_mac() {
        let no_mac = InterfaceAddresses::new(
            None,
            Some(Ipv4Addr::new(192, 168, 0, 2)),
            Some("fe80::2".parse().unwrap()),
            Some("2001:db8::2".parse().unwrap()),
        );
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut scratch = [0u8; 2048];
        assert_eq!(
            build_udp(
                &no_mac,
                LinkType::Ethernet,
                dst,
                MacAddr::broadcast(),
                4000,
                64,
                b"x",
                &mut scratch
            ),
            Err(DatagramError::NoSourceMac)
        );
    }

    #[test]
    fn build_udp_surfaces_a_frame_error() {
        // A scratch too small for the frame is a typed DatagramError::Frame, not a panic — the
        // `#[from] FrameError` conversion that send_udp then maps onto io::Error.
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut tiny = [0u8; 16];
        assert!(matches!(
            build_udp(
                &full_addrs(),
                LinkType::Ethernet,
                dst,
                MacAddr::broadcast(),
                4000,
                64,
                b"x",
                &mut tiny
            ),
            Err(DatagramError::Frame(FrameError::BufferTooSmall { .. }))
        ));
    }

    // DLT_NULL (BSD loopback) carries no L2 header, so a MAC-less egress still builds — the frame
    // opens with the 4-byte host-order address family, not a MAC, and the supplied dst MAC is
    // ignored (there is no L2 header to place it in).
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    #[test]
    fn build_udp_dlt_null_needs_no_mac() {
        let no_mac = InterfaceAddresses::new(
            None,
            Some(Ipv4Addr::new(192, 168, 0, 2)),
            Some("fe80::2".parse().unwrap()),
            Some("2001:db8::2".parse().unwrap()),
        );
        let dst = SocketAddr::from((Ipv4Addr::BROADCAST, 9));
        let mut scratch = [0u8; 2048];
        build_udp(
            &no_mac,
            LinkType::DltNull,
            dst,
            MacAddr::broadcast(),
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
}
