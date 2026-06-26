//! mDNS wire constants and the query/response classifier — the reflector's directional gate.

use std::net::{Ipv4Addr, Ipv6Addr};

/// The mDNS UDP port (RFC 6762).
pub(crate) const MDNS_PORT: u16 = 5353;
/// mDNS messages carry IP TTL 255 so a receiver can verify the message originated on the local
/// link — a lower TTL means it was routed, and is rejected (RFC 6762 §11). The reflector re-emits a
/// fresh link-local message, so it sets 255 rather than preserving the captured TTL.
pub(crate) const MDNS_TTL: u8 = 255;
/// The IPv4 mDNS multicast group.
pub(crate) const MDNS_GROUP_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
/// The IPv6 link-local mDNS multicast group.
pub(crate) const MDNS_GROUP_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);

/// An mDNS message is a query or a response, per the QR bit of its DNS header. Unsolicited
/// announcements are responses too (RFC 6762 §8.3), so this split is exactly the reflector's
/// directional gate: queries reflect source → target, responses target → source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum MdnsKind {
    Query,
    Response,
}

/// The fixed DNS header is 12 bytes (RFC 1035 §4.1.1).
const DNS_HEADER_LEN: usize = 12;
/// The high byte of the flags field (header offset 2); the QR bit is its top bit.
const FLAGS_HIGH: usize = 2;
const QR_BIT: u8 = 0x80;

/// Classify a payload by the QR bit of its fixed 12-byte DNS header. `None` when the payload is too
/// short to hold that header — anomalous on the dedicated mDNS group, so the caller surfaces it.
/// Header-only: no question or record parsing.
pub(crate) fn classify(payload: &[u8]) -> Option<MdnsKind> {
    if payload.len() < DNS_HEADER_LEN {
        return None;
    }
    Some(if payload[FLAGS_HIGH] & QR_BIT != 0 {
        MdnsKind::Response
    } else {
        MdnsKind::Query
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal DNS message: a 12-byte header with `flags_high` at offset 2, plus a `tail`.
    fn message(flags_high: u8, tail: &[u8]) -> Vec<u8> {
        let mut m = vec![0u8; DNS_HEADER_LEN];
        m[FLAGS_HIGH] = flags_high;
        m.extend_from_slice(tail);
        m
    }

    #[test]
    fn classifies_by_the_qr_bit_only() {
        assert_eq!(classify(&message(0x00, b"")), Some(MdnsKind::Query)); // QR=0
        assert_eq!(classify(&message(0x84, b"q")), Some(MdnsKind::Response)); // QR=1, AA
        // Only the QR bit is read; the other flag bits don't change the verdict.
        assert_eq!(classify(&message(0x7f, b"")), Some(MdnsKind::Query));
        assert_eq!(classify(&message(0xff, b"")), Some(MdnsKind::Response));
    }

    #[test]
    fn rejects_a_payload_too_short_for_a_dns_header() {
        assert_eq!(classify(b""), None);
        assert_eq!(classify(&[0u8; DNS_HEADER_LEN - 1]), None); // one byte short
        // Exactly the header length suffices (an all-zero header is a query).
        assert_eq!(classify(&[0u8; DNS_HEADER_LEN]), Some(MdnsKind::Query));
    }
}
