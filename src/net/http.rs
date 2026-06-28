//! HTTP/1.1 message helpers for the TCP path: the IPv4 authority parser shared by the DIAL proxy's
//! `Host` / `Application-URL` / `Location` rewrites and the SSDP `LOCATION` rewrite, plus the
//! case-insensitive header-prefix match they — and SSDP, which is HTTP-over-UDP — use to find header
//! lines. The streaming message framer is in the [`framing`] submodule.

pub(crate) mod framing;

use std::net::{Ipv4Addr, SocketAddrV4};

/// A device HTTP authority parsed from a header value, plus the byte span of its `host[:port]` text
/// within the value it came from — so a caller splices a replacement over exactly that span. The
/// reflector's HTTP/DIAL rewrites are IPv4-only, so the endpoint is a [`SocketAddrV4`].
pub(crate) struct Authority {
    pub(crate) endpoint: SocketAddrV4,
    pub(crate) offset: usize,
    pub(crate) len: usize,
}

/// Parse a device authority from `value`. `bare` (a `Host` header) treats the whole value as the
/// authority; else `value` must be an `http://host[:port]...` URL (no `https`). The host must be an
/// IPv4 literal (a hostname or IPv6 is rejected — DIAL is IPv4-only); the port defaults to 80, or an
/// explicit one must be the whole field and in `1..=65535`. `offset`/`len` are relative to `value`.
pub(crate) fn parse_authority(value: &[u8], bare: bool) -> Option<Authority> {
    let (rest, auth_offset) = if bare {
        (value, 0)
    } else {
        let rest = strip_prefix_ignore_ascii_case(value, b"http://")?;
        (rest, value.len() - rest.len())
    };
    let len = rest
        .iter()
        .position(|&b| matches!(b, b'/' | b' ' | b'\t' | b'\r'))
        .unwrap_or(rest.len());
    let authority = &rest[..len];
    let (host, port) = match authority.iter().rposition(|&b| b == b':') {
        Some(colon) => {
            let port = std::str::from_utf8(&authority[colon + 1..])
                .ok()?
                .parse::<u16>()
                .ok()?;
            if port == 0 {
                return None;
            }
            (&authority[..colon], port)
        }
        None => (authority, 80),
    };
    let addr = std::str::from_utf8(host).ok()?.parse::<Ipv4Addr>().ok()?;
    Some(Authority {
        endpoint: SocketAddrV4::new(addr, port),
        offset: auth_offset,
        len,
    })
}

/// `line` with `prefix` removed if it begins with it (ASCII case-insensitive), else `None`.
pub(crate) fn strip_prefix_ignore_ascii_case<'a>(
    line: &'a [u8],
    prefix: &[u8],
) -> Option<&'a [u8]> {
    let (head, rest) = line.split_at_checked(prefix.len())?;
    head.eq_ignore_ascii_case(prefix).then_some(rest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_an_http_url_authority() {
        // Default port (80) with the host:port span relative to `value`.
        let a = parse_authority(b"http://10.0.0.7/dd.xml", false).unwrap();
        assert_eq!(a.endpoint, "10.0.0.7:80".parse().unwrap());
        assert_eq!(
            &b"http://10.0.0.7/dd.xml"[a.offset..a.offset + a.len],
            b"10.0.0.7"
        );
        // Explicit port.
        let a = parse_authority(b"http://192.168.1.50:8080/x", false).unwrap();
        assert_eq!(a.endpoint, "192.168.1.50:8080".parse().unwrap());
    }

    #[test]
    fn parse_authority_handles_a_bare_host_value() {
        let a = parse_authority(b"192.168.1.5:1900", true).unwrap();
        assert_eq!(a.endpoint, "192.168.1.5:1900".parse().unwrap());
        assert_eq!((a.offset, a.len), (0, "192.168.1.5:1900".len()));
    }

    #[test]
    fn rejects_non_http_non_ipv4_or_malformed_authorities() {
        assert!(parse_authority(b"https://10.0.0.1/x", false).is_none()); // not http
        assert!(parse_authority(b"http://tv.local/x", false).is_none()); // hostname, not IPv4
        assert!(parse_authority(b"http://10.0.0.1:0/x", false).is_none()); // port 0
        assert!(parse_authority(b"http://10.0.0.1:80x/x", false).is_none()); // trailing junk on port
    }

    #[test]
    fn strip_prefix_matches_case_insensitively() {
        assert_eq!(
            strip_prefix_ignore_ascii_case(b"Host: x", b"host:"),
            Some(&b" x"[..])
        );
        assert!(strip_prefix_ignore_ascii_case(b"X", b"host:").is_none()); // shorter than the prefix
        assert!(strip_prefix_ignore_ascii_case(b"HosX: x", b"host:").is_none()); // mismatch
    }
}
