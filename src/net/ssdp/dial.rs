//! DIAL (Discovery and Launch) discovery detection and `LOCATION`-authority parsing — the SSDP-side
//! inputs the DIAL proxy hook needs.

use crate::net::http::{Authority, parse_authority, strip_prefix_ignore_ascii_case};

/// The DIAL service-type URN; the trailing `:1` version is dropped so any version matches.
const DIAL_SERVICE_TYPE: &[u8] = b"urn:dial-multiscreen-org:service:dial";

/// Whether `payload` is a DIAL discovery message — the service-type URN appears anywhere (`ST` /
/// `NT` / `USN`), ASCII-case-insensitively. Gates a `LOCATION` rewrite.
pub(crate) fn is_dial_service_message(payload: &[u8]) -> bool {
    contains_ignore_ascii_case(payload, DIAL_SERVICE_TYPE)
}

/// Parse the device authority from a DIAL discovery message's `LOCATION:` header, the byte span
/// mapped into the whole `payload` so the SSDP path splices a reflector authority over it. The
/// `LOCATION` must be a rewritable `http://ipv4[:port]` URL; `None` otherwise (forward unchanged).
pub(crate) fn parse_dial_location_authority(payload: &[u8]) -> Option<Authority> {
    for line in payload.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(url) = strip_prefix_ignore_ascii_case(line, b"LOCATION:") else {
            continue;
        };
        let url = url.trim_ascii_start();
        if url.is_empty() {
            return None;
        }
        let found = parse_authority(url, false)?;
        // `url` is a subslice of `payload`, so the distance between their starts is `url`'s offset
        // within `payload`; add the authority's offset within `url`.
        let url_offset = url.as_ptr().addr() - payload.as_ptr().addr();
        return Some(Authority {
            endpoint: found.endpoint,
            offset: url_offset + found.offset,
            len: found.len,
        });
    }
    None
}

/// The raw, trimmed `LOCATION:` header value (the URL), or `None` if the message carries none — for the
/// debug log when [`parse_dial_location_authority`] rejects the URL as non-rewritable.
pub(crate) fn dial_location_value(payload: &[u8]) -> Option<&[u8]> {
    payload.split(|&b| b == b'\n').find_map(|line| {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let url = strip_prefix_ignore_ascii_case(line, b"LOCATION:")?.trim_ascii_start();
        (!url.is_empty()).then_some(url)
    })
}

/// The advertisement's freshness lifetime from a `CACHE-CONTROL: max-age=<seconds>` header — the
/// seconds the proxy's description listener may treat the device as present. `max-age` is matched
/// case-insensitively among comma-separated directives; `None` (caller falls back to its default grace)
/// if the header or a parseable `max-age` is absent.
pub(crate) fn parse_cache_control_max_age(payload: &[u8]) -> Option<u32> {
    for line in payload.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        if let Some(value) = strip_prefix_ignore_ascii_case(line, b"CACHE-CONTROL:") {
            return max_age_seconds(value);
        }
    }
    None
}

/// The `max-age` delta-seconds from a `CACHE-CONTROL` value, scanning its comma-separated directives.
fn max_age_seconds(value: &[u8]) -> Option<u32> {
    for directive in value.split(|&b| b == b',') {
        if let Some(digits) = strip_prefix_ignore_ascii_case(directive.trim_ascii(), b"max-age=") {
            return std::str::from_utf8(digits).ok()?.parse::<u32>().ok();
        }
    }
    None
}

/// Whether `haystack` contains `needle` as an ASCII-case-insensitive substring.
fn contains_ignore_ascii_case(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || haystack
            .windows(needle.len())
            .any(|window| window.eq_ignore_ascii_case(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_the_dial_service_urn_case_insensitively() {
        assert!(is_dial_service_message(
            b"NOTIFY * HTTP/1.1\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\n\r\n"
        ));
        // Case-insensitive and version-agnostic (any trailing version).
        assert!(is_dial_service_message(
            b"ST: URN:Dial-MultiScreen-Org:Service:Dial:2\r\n"
        ));
        assert!(!is_dial_service_message(
            b"ST: urn:schemas-upnp-org:device:MediaServer:1\r\n"
        ));
        assert!(!is_dial_service_message(b""));
    }

    #[test]
    fn parses_a_location_authority_with_a_payload_relative_span() {
        let payload =
            b"HTTP/1.1 200 OK\r\nLOCATION: http://192.168.1.50:8080/dd.xml\r\nST: x\r\n\r\n";
        let a = parse_dial_location_authority(payload).expect("a rewritable http LOCATION");
        assert_eq!(a.endpoint, "192.168.1.50:8080".parse().unwrap());
        // The span covers exactly the host:port text within the whole payload.
        assert_eq!(&payload[a.offset..a.offset + a.len], b"192.168.1.50:8080");
    }

    #[test]
    fn location_port_defaults_to_80_when_omitted() {
        let payload = b"NOTIFY * HTTP/1.1\r\nLOCATION:http://10.0.0.7/dd.xml\r\n\r\n";
        let a = parse_dial_location_authority(payload).unwrap();
        assert_eq!(a.endpoint, "10.0.0.7:80".parse().unwrap());
        assert_eq!(&payload[a.offset..a.offset + a.len], b"10.0.0.7");
    }

    #[test]
    fn rejects_unrewritable_locations() {
        // Not http; not an IPv4 literal; IPv6 (DIAL is IPv4-only); bad port; absent.
        assert!(parse_dial_location_authority(b"LOCATION: https://10.0.0.1/x\r\n").is_none());
        assert!(parse_dial_location_authority(b"LOCATION: http://tv.local/x\r\n").is_none());
        assert!(parse_dial_location_authority(b"LOCATION: http://[fe80::1]:8/x\r\n").is_none());
        assert!(parse_dial_location_authority(b"LOCATION: http://10.0.0.1:0/x\r\n").is_none());
        assert!(parse_dial_location_authority(b"LOCATION: http://10.0.0.1:80x/x\r\n").is_none());
        assert!(parse_dial_location_authority(b"NOTIFY * HTTP/1.1\r\nNT: foo\r\n\r\n").is_none());
    }

    #[test]
    fn dial_location_value_returns_the_raw_url() {
        // Even a non-rewritable LOCATION yields its raw value, so the rewrite hook can log it.
        assert_eq!(
            dial_location_value(b"NOTIFY * HTTP/1.1\r\nLOCATION: https://tv.local/x\r\n\r\n"),
            Some(&b"https://tv.local/x"[..])
        );
        assert!(dial_location_value(b"NOTIFY * HTTP/1.1\r\nNT: foo\r\n\r\n").is_none());
    }

    #[test]
    fn parses_cache_control_max_age() {
        let payload = b"NOTIFY * HTTP/1.1\r\nCACHE-CONTROL: max-age=1800\r\nNT: x\r\n\r\n";
        assert_eq!(parse_cache_control_max_age(payload), Some(1800));
    }

    #[test]
    fn max_age_is_case_insensitive_and_directive_tolerant() {
        // Header name and directive case-insensitive; no space after the colon; among other directives.
        assert_eq!(
            parse_cache_control_max_age(b"Cache-Control:no-cache, Max-Age=600\r\n"),
            Some(600)
        );
        assert_eq!(
            parse_cache_control_max_age(b"CACHE-CONTROL:max-age=42\r\n"),
            Some(42)
        );
    }

    #[test]
    fn cache_control_without_a_parseable_max_age_is_none() {
        assert_eq!(parse_cache_control_max_age(b"NT: foo\r\n\r\n"), None); // header absent
        assert_eq!(
            parse_cache_control_max_age(b"CACHE-CONTROL: no-cache\r\n"),
            None // no max-age directive
        );
        assert_eq!(
            parse_cache_control_max_age(b"CACHE-CONTROL: max-age=\r\n"),
            None
        ); // empty value
        assert_eq!(
            parse_cache_control_max_age(b"CACHE-CONTROL: max-age=abc\r\n"),
            None // non-numeric
        );
    }

    #[test]
    fn empty_location_value_is_none() {
        assert!(parse_dial_location_authority(b"NOTIFY * HTTP/1.1\r\nLOCATION:\r\n\r\n").is_none());
        assert!(dial_location_value(b"NOTIFY * HTTP/1.1\r\nLOCATION:   \r\n\r\n").is_none());
    }
}
