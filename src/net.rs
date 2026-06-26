//! The wire layer: everything that touches on-the-wire packet formats — link-layer
//! framing, IP/UDP checksums, and building and parsing frames.

mod checksum;
pub(crate) mod frame;
pub(crate) mod mac;
pub(crate) mod mdns;
pub(crate) mod packet;
// The SSDP search reflector (a later step) is the only consumer; until it lands this is unused.
#[allow(dead_code)]
pub(crate) mod port_reservation;
pub(crate) mod ssdp;

/// The link-layer framing of a captured or injected frame. The capture layer reports
/// it per interface; [`frame`] adds the matching link header and [`packet`] strips it
/// before parsing L3: a 14-byte Ethernet header, or — on BSD — `DLT_NULL`'s 4-byte
/// host-order address family (loopback/tunnel interfaces). Linux frames every
/// interface, loopback included, as Ethernet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkType {
    Ethernet,
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    DltNull,
}

/// IANA protocol number for UDP.
const IP_PROTO_UDP: u8 = 17;

/// Ethernet link header: dst MAC(6) + src MAC(6) + ethertype(2).
const ETHERNET_HEADER_SIZE: usize = 14;
/// BSD `DLT_NULL` link header: a 4-byte address family in host byte order (`lo0`).
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const DLT_NULL_HEADER_SIZE: usize = 4;
/// IPv4 header without options (the minimum), the fixed IPv6 base header, and the
/// fixed UDP header.
const IPV4_HEADER_SIZE: usize = 20;
const IPV6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;
