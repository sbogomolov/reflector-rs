//! SSDP wire constants and the search/advertisement classifier — the reflector's directional gate.

use std::net::{Ipv4Addr, Ipv6Addr};

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
/// reflector's directional gate: searches (`M-SEARCH`) relay source → target, advertisements
/// (`NOTIFY` — both `ssdp:alive` and `ssdp:byebye`) relay target → source.
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
        // A unicast search response travels off the multicast path; on the group it isn't relayed.
        assert_eq!(classify(b"HTTP/1.1 200 OK\r\n"), None);
        assert_eq!(classify(b""), None);
        assert_eq!(classify(b"GARBAGE"), None);
        // The method token must be whole: the prefix without its trailing space is not a match.
        assert_eq!(classify(b"NOTIFYING * HTTP/1.1\r\n"), None);
        assert_eq!(classify(b"M-SEARCHED"), None);
    }
}
