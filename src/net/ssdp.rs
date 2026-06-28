//! SSDP wire constants and the search/advertisement classifier — the reflector's directional gate.

pub(crate) mod dial;

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::net::http::strip_prefix_ignore_ascii_case;

/// The SSDP UDP port (`UPnP` Device Architecture).
pub(crate) const SSDP_PORT: u16 = 1900;
/// SSDP messages default to IP TTL 2 (`UPnP` Device Architecture). The reflector re-emits a fresh
/// message onto the other link rather than preserving the captured TTL, so it sets 2.
pub(crate) const SSDP_TTL: u8 = 2;
/// The IPv4 SSDP multicast group.
pub(crate) const SSDP_GROUP_V4: Ipv4Addr = Ipv4Addr::new(239, 255, 255, 250);
/// The IPv6 link-local SSDP multicast group (`ff02::c`).
pub(crate) const SSDP_GROUP_V6_LINK_LOCAL: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0x0c);
/// The IPv6 site-local SSDP multicast group (`ff05::c`); SSDP joins both v6 scopes.
pub(crate) const SSDP_GROUP_V6_SITE_LOCAL: Ipv6Addr = Ipv6Addr::new(0xff05, 0, 0, 0, 0, 0, 0, 0x0c);

/// An SSDP message is a search or an advertisement, per its HTTPU request line. This split is the
/// reflector's directional gate: searches (`M-SEARCH`) reflect source → target, advertisements
/// (`NOTIFY` — both `ssdp:alive` and `ssdp:byebye`) reflect target → source.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SsdpKind {
    Search,
    Advertisement,
}

/// The HTTPU request-line method tokens (method + SP) classify discriminates on.
const MSEARCH_PREFIX: &[u8] = b"M-SEARCH ";
const NOTIFY_PREFIX: &[u8] = b"NOTIFY ";

/// Classify a payload by its leading HTTPU request line: an `M-SEARCH` is a search, a `NOTIFY` an
/// advertisement. `None` for anything else — a unicast `HTTP/1.1 200 OK` search response (handled
/// off this multicast path) or junk on the group — which the caller drops. Only the method token is
/// read; the trailing space pins it so a longer word (`NOTIFYING`) is not a match. No header parsing.
pub(crate) fn classify(payload: &[u8]) -> Option<SsdpKind> {
    if payload.starts_with(MSEARCH_PREFIX) {
        Some(SsdpKind::Search)
    } else if payload.starts_with(NOTIFY_PREFIX) {
        Some(SsdpKind::Advertisement)
    } else {
        None
    }
}

/// The fallback M-SEARCH response window (seconds) the caller applies when [`parse_msearch_mx`]
/// finds no usable MX. A multicast M-SEARCH MUST carry MX (`UPnP` Device Architecture 2.0), so an
/// absent or unparseable one is a non-conformant searcher — reflected anyway with this window.
pub(crate) const MSEARCH_MX_DEFAULT: u8 = 3;

/// MX is clamped to `[1, 5]` seconds (`UPnP` Device Architecture 2.0).
const MX_MIN: u8 = 1;
const MX_MAX: u8 = 5;

/// Parse an M-SEARCH's `MX:` header — the searcher's maximum response wait, in seconds — clamped to
/// `[1, 5]`. Scans the payload's CRLF-delimited lines for the first `MX:` field (case-insensitive
/// name; an M-SEARCH carries no body, so there is no header/body boundary to stop at) and reads its
/// leading integer. The first `MX:` line is decisive. Returns `None` when MX is absent or its value
/// isn't a number; the caller substitutes [`MSEARCH_MX_DEFAULT`] and logs the non-conformance.
pub(crate) fn parse_msearch_mx(payload: &[u8]) -> Option<u8> {
    for line in payload.split(|&b| b == b'\n') {
        // Lines are CRLF-delimited; drop the trailing CR left by splitting on LF.
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(value) = strip_prefix_ignore_ascii_case(line, b"MX:") else {
            continue;
        };
        // Skip leading spaces, then the leading run of digits — a trailing non-digit doesn't void a
        // valid leading number. Empty or out-of-`u32`-range reads as "present but unparseable".
        let value = value.trim_ascii_start();
        let end = value
            .iter()
            .position(|b| !b.is_ascii_digit())
            .unwrap_or(value.len());
        let mx = std::str::from_utf8(&value[..end])
            .ok()?
            .parse::<u32>()
            .ok()?;
        return Some(
            u8::try_from(mx.clamp(u32::from(MX_MIN), u32::from(MX_MAX))).unwrap_or(MX_MAX),
        );
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_by_the_request_line_method() {
        assert_eq!(classify(b"M-SEARCH * HTTP/1.1\r\n"), Some(SsdpKind::Search));
        assert_eq!(
            classify(b"NOTIFY * HTTP/1.1\r\n"),
            Some(SsdpKind::Advertisement)
        );
    }

    #[test]
    fn rejects_non_search_non_notify() {
        // A unicast search response travels off the multicast path; on the group it isn't reflected.
        assert_eq!(classify(b"HTTP/1.1 200 OK\r\n"), None);
        assert_eq!(classify(b""), None);
        assert_eq!(classify(b"GARBAGE"), None);
        // The method token must be whole: the prefix without its trailing space is not a match.
        assert_eq!(classify(b"NOTIFYING * HTTP/1.1\r\n"), None);
        assert_eq!(classify(b"M-SEARCHED"), None);
    }

    /// A well-formed M-SEARCH with the given MX field value.
    fn msearch(mx: &str) -> Vec<u8> {
        format!(
            "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n\
             MAN: \"ssdp:discover\"\r\nMX: {mx}\r\nST: ssdp:all\r\n\r\n"
        )
        .into_bytes()
    }

    #[test]
    fn parses_and_clamps_the_mx_window() {
        assert_eq!(parse_msearch_mx(&msearch("3")), Some(3));
        assert_eq!(parse_msearch_mx(&msearch("1")), Some(1));
        assert_eq!(parse_msearch_mx(&msearch("5")), Some(5));
        // Out of range clamps into [1, 5] (0 -> 1; anything above 5, including a value too big for a
        // u8, -> 5).
        assert_eq!(parse_msearch_mx(&msearch("0")), Some(1));
        assert_eq!(parse_msearch_mx(&msearch("10")), Some(5));
        assert_eq!(parse_msearch_mx(&msearch("900")), Some(5));
    }

    #[test]
    fn mx_field_name_is_case_insensitive_and_space_tolerant() {
        assert_eq!(
            parse_msearch_mx(b"M-SEARCH * HTTP/1.1\r\nmx:2\r\n\r\n"),
            Some(2)
        );
        assert_eq!(
            parse_msearch_mx(b"M-SEARCH * HTTP/1.1\r\nMx:   4\r\n\r\n"),
            Some(4)
        );
    }

    #[test]
    fn absent_or_unparseable_mx_is_none() {
        // No MX header at all.
        assert_eq!(
            parse_msearch_mx(b"M-SEARCH * HTTP/1.1\r\nST: ssdp:all\r\n\r\n"),
            None
        );
        // MX present but not a number, and present but empty.
        assert_eq!(
            parse_msearch_mx(b"M-SEARCH * HTTP/1.1\r\nMX: soon\r\n\r\n"),
            None
        );
        assert_eq!(
            parse_msearch_mx(b"M-SEARCH * HTTP/1.1\r\nMX:\r\n\r\n"),
            None
        );
        // The first MX line is decisive: a bad one isn't rescued by a later valid one.
        assert_eq!(
            parse_msearch_mx(b"M-SEARCH * HTTP/1.1\r\nMX: x\r\nMX: 3\r\n\r\n"),
            None
        );
    }
}
