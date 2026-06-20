//! Build the IP + UDP datagrams we inject on the egress path.
//!
//! Each builder writes the IPv4/IPv6 header and the UDP header + payload into a
//! caller-provided buffer (no allocation on the data path) and returns the byte
//! count, filling the IPv4-header and UDP checksums via [`crate::checksum`]. The
//! L2 framing (Ethernet / loopback) wraps these and is added separately.

use std::net::{SocketAddrV4, SocketAddrV6};

use thiserror::Error;

use crate::checksum;

const IPV4_HEADER_SIZE: usize = 20;
const IPV6_HEADER_SIZE: usize = 40;
const UDP_HEADER_SIZE: usize = 8;
const IP_PROTO_UDP: u8 = 17;
/// Don't-Fragment, in the IPv4 flags + fragment-offset field. These one-hop
/// link-local datagrams are never fragmented, so DF is set and a zero IP
/// identification stays RFC 6864-conformant.
const IPV4_FLAG_DF: u16 = 0x4000;

/// Why building a UDP frame failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum FrameError {
    /// `out` cannot hold the frame.
    #[error("output buffer too small: need {needed} bytes, have {available}")]
    BufferTooSmall { needed: usize, available: usize },
    /// The datagram overflows the 16-bit IP/UDP length fields.
    #[error("payload of {payload} bytes is too large for a UDP datagram")]
    PayloadTooLarge { payload: usize },
}

/// Write an IPv4 + UDP datagram (headers and `payload`, with the IPv4-header and
/// UDP checksums filled) into `out`, returning the number of bytes written.
///
/// `out` is written from offset 0; a caller prepending an L2 header passes the
/// sub-slice that follows it.
///
/// # Errors
/// [`FrameError::PayloadTooLarge`] if the datagram overflows the 16-bit length
/// fields, or [`FrameError::BufferTooSmall`] if `out` cannot hold the frame.
pub fn ipv4_udp(
    src: SocketAddrV4,
    dst: SocketAddrV4,
    ttl: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, FrameError> {
    let udp_length = datagram_length(payload)?;
    let frame_size = IPV4_HEADER_SIZE + usize::from(udp_length);
    // The IPv4 total-length field is also 16-bit and spans header + datagram.
    let total_length = u16::try_from(frame_size).map_err(|_| FrameError::PayloadTooLarge {
        payload: payload.len(),
    })?;
    let out = checked_out(out, frame_size)?;

    out[..IPV4_HEADER_SIZE + UDP_HEADER_SIZE].fill(0);
    out[IPV4_HEADER_SIZE + UDP_HEADER_SIZE..].copy_from_slice(payload);

    out[0] = 0x45; // version 4, IHL 5 (no options)
    out[2..4].copy_from_slice(&total_length.to_be_bytes());
    out[6..8].copy_from_slice(&IPV4_FLAG_DF.to_be_bytes());
    out[8] = ttl;
    out[9] = IP_PROTO_UDP;
    out[12..16].copy_from_slice(&src.ip().octets());
    out[16..20].copy_from_slice(&dst.ip().octets());
    let ip_checksum = checksum::ipv4_header(&out[..IPV4_HEADER_SIZE]);
    out[10..12].copy_from_slice(&ip_checksum.to_be_bytes());

    let udp = IPV4_HEADER_SIZE;
    write_udp_header(&mut out[udp..], src.port(), dst.port(), udp_length);
    let udp_checksum = checksum::udp_v4(*src.ip(), *dst.ip(), &out[udp..]);
    out[udp + 6..udp + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    Ok(frame_size)
}

/// Write an IPv6 + UDP datagram (headers and `payload`, with the UDP checksum
/// filled) into `out`, returning the number of bytes written. The IPv6 header
/// carries no checksum of its own.
///
/// `out` is written from offset 0; a caller prepending an L2 header passes the
/// sub-slice that follows it.
///
/// # Errors
/// [`FrameError::PayloadTooLarge`] if the datagram overflows the 16-bit length
/// fields, or [`FrameError::BufferTooSmall`] if `out` cannot hold the frame.
pub fn ipv6_udp(
    src: SocketAddrV6,
    dst: SocketAddrV6,
    hop_limit: u8,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, FrameError> {
    let udp_length = datagram_length(payload)?;
    let frame_size = IPV6_HEADER_SIZE + usize::from(udp_length);
    let out = checked_out(out, frame_size)?;

    out[..IPV6_HEADER_SIZE + UDP_HEADER_SIZE].fill(0);
    out[IPV6_HEADER_SIZE + UDP_HEADER_SIZE..].copy_from_slice(payload);

    out[0] = 0x60; // version 6, zero traffic class / flow label
    out[4..6].copy_from_slice(&udp_length.to_be_bytes()); // payload length
    out[6] = IP_PROTO_UDP; // next header
    out[7] = hop_limit;
    out[8..24].copy_from_slice(&src.ip().octets());
    out[24..40].copy_from_slice(&dst.ip().octets());

    let udp = IPV6_HEADER_SIZE;
    write_udp_header(&mut out[udp..], src.port(), dst.port(), udp_length);
    let udp_checksum = checksum::udp_v6(*src.ip(), *dst.ip(), &out[udp..]);
    out[udp + 6..udp + 8].copy_from_slice(&udp_checksum.to_be_bytes());

    Ok(frame_size)
}

/// The UDP datagram length (header + `payload`) as a `u16`, or
/// [`FrameError::PayloadTooLarge`] if it overflows the 16-bit length field.
fn datagram_length(payload: &[u8]) -> Result<u16, FrameError> {
    u16::try_from(UDP_HEADER_SIZE + payload.len()).map_err(|_| FrameError::PayloadTooLarge {
        payload: payload.len(),
    })
}

/// Truncate `out` to exactly `frame_size`, or report it as too small.
fn checked_out(out: &mut [u8], frame_size: usize) -> Result<&mut [u8], FrameError> {
    if out.len() < frame_size {
        return Err(FrameError::BufferTooSmall {
            needed: frame_size,
            available: out.len(),
        });
    }
    Ok(&mut out[..frame_size])
}

/// Write the UDP source/destination ports and length into `udp` (the datagram,
/// header first). The checksum field (bytes 6-7) is left for the caller to fill.
fn write_udp_header(udp: &mut [u8], src_port: u16, dst_port: u16, length: u16) {
    udp[0..2].copy_from_slice(&src_port.to_be_bytes());
    udp[2..4].copy_from_slice(&dst_port.to_be_bytes());
    udp[4..6].copy_from_slice(&length.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn ipv4_udp_writes_expected_frame() {
        let src = SocketAddrV4::new(Ipv4Addr::new(192, 168, 0, 1), 5353);
        let dst = SocketAddrV4::new(Ipv4Addr::new(224, 0, 0, 251), 5353);
        let payload = [0xde, 0xad, 0xbe, 0xef];
        let mut buf = [0xAAu8; 64]; // sentinel: every frame byte must be overwritten

        let n = ipv4_udp(src, dst, 1, &payload, &mut buf).unwrap();
        assert_eq!(n, IPV4_HEADER_SIZE + UDP_HEADER_SIZE + payload.len());
        let frame = &buf[..n];
        let udp = IPV4_HEADER_SIZE;

        // IPv4 header — every byte.
        assert_eq!(frame[0], 0x45); // version 4, IHL 5
        assert_eq!(frame[1], 0); // DSCP / ECN
        assert_eq!(
            u16::from_be_bytes([frame[2], frame[3]]),
            u16::try_from(n).unwrap()
        ); // total length
        assert_eq!(&frame[4..6], [0u8, 0].as_slice()); // identification
        assert_eq!(u16::from_be_bytes([frame[6], frame[7]]), IPV4_FLAG_DF); // flags + fragment
        assert_eq!(frame[8], 1); // ttl
        assert_eq!(frame[9], IP_PROTO_UDP);
        assert_eq!(
            u16::from_be_bytes([frame[10], frame[11]]),
            checksum::ipv4_header(&frame[..IPV4_HEADER_SIZE])
        ); // header checksum
        assert_eq!(&frame[12..16], src.ip().octets().as_slice());
        assert_eq!(&frame[16..20], dst.ip().octets().as_slice());

        // UDP header + payload — every byte.
        assert_eq!(u16::from_be_bytes([frame[udp], frame[udp + 1]]), src.port());
        assert_eq!(
            u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]),
            dst.port()
        );
        assert_eq!(
            u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]),
            u16::try_from(UDP_HEADER_SIZE + payload.len()).unwrap()
        ); // UDP length
        assert_eq!(
            u16::from_be_bytes([frame[udp + 6], frame[udp + 7]]),
            checksum::udp_v4(*src.ip(), *dst.ip(), &frame[udp..])
        ); // UDP checksum
        assert_eq!(&frame[udp + UDP_HEADER_SIZE..], &payload);
    }

    #[test]
    fn ipv6_udp_writes_expected_frame() {
        let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb), 5353, 0, 0);
        let payload = [0xaa, 0xbb, 0xcc];
        let mut buf = [0xAAu8; 80]; // sentinel: every frame byte must be overwritten

        let n = ipv6_udp(src, dst, 255, &payload, &mut buf).unwrap();
        assert_eq!(n, IPV6_HEADER_SIZE + UDP_HEADER_SIZE + payload.len());
        let frame = &buf[..n];
        let udp = IPV6_HEADER_SIZE;

        // IPv6 header — every byte.
        assert_eq!(frame[0], 0x60); // version 6
        assert_eq!(&frame[1..4], [0u8; 3].as_slice()); // traffic class + flow label
        assert_eq!(
            u16::from_be_bytes([frame[4], frame[5]]),
            u16::try_from(UDP_HEADER_SIZE + payload.len()).unwrap()
        ); // payload length
        assert_eq!(frame[6], IP_PROTO_UDP); // next header
        assert_eq!(frame[7], 255); // hop limit
        assert_eq!(&frame[8..24], src.ip().octets().as_slice());
        assert_eq!(&frame[24..40], dst.ip().octets().as_slice());

        // UDP header + payload — every byte.
        assert_eq!(u16::from_be_bytes([frame[udp], frame[udp + 1]]), src.port());
        assert_eq!(
            u16::from_be_bytes([frame[udp + 2], frame[udp + 3]]),
            dst.port()
        );
        assert_eq!(
            u16::from_be_bytes([frame[udp + 4], frame[udp + 5]]),
            u16::try_from(UDP_HEADER_SIZE + payload.len()).unwrap()
        ); // UDP length
        assert_eq!(
            u16::from_be_bytes([frame[udp + 6], frame[udp + 7]]),
            checksum::udp_v6(*src.ip(), *dst.ip(), &frame[udp..])
        ); // UDP checksum
        assert_eq!(&frame[udp + UDP_HEADER_SIZE..], &payload);
    }

    #[test]
    fn ipv4_buffer_too_small_is_reported() {
        let src = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
        let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2);
        let mut buf = [0u8; 16]; // < 28-byte minimum frame
        assert!(matches!(
            ipv4_udp(src, dst, 1, &[], &mut buf),
            Err(FrameError::BufferTooSmall {
                needed: 28,
                available: 16
            })
        ));
    }

    #[test]
    fn ipv6_buffer_too_small_is_reported() {
        let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 2, 0, 0);
        let mut buf = [0u8; 16]; // < 48-byte minimum frame
        assert!(matches!(
            ipv6_udp(src, dst, 1, &[], &mut buf),
            Err(FrameError::BufferTooSmall {
                needed: 48,
                available: 16
            })
        ));
    }

    // Distinct overflow checks: IPv4 trips the total-length field (header + datagram),
    // IPv6 trips the UDP length field alone (shared `datagram_length`).
    #[test]
    fn ipv4_payload_too_large_is_reported() {
        let src = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1);
        let dst = SocketAddrV4::new(Ipv4Addr::LOCALHOST, 2);
        let payload = vec![0u8; 65_508]; // 20 + 8 + 65508 overflows the IPv4 total-length field
        let mut buf = [0u8; 64];
        assert!(matches!(
            ipv4_udp(src, dst, 1, &payload, &mut buf),
            Err(FrameError::PayloadTooLarge { payload: 65_508 })
        ));
    }

    #[test]
    fn ipv6_payload_too_large_is_reported() {
        let src = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 1, 0, 0);
        let dst = SocketAddrV6::new(Ipv6Addr::LOCALHOST, 2, 0, 0);
        let payload = vec![0u8; 65_528]; // 8 + 65528 overflows the UDP length field
        let mut buf = [0u8; 64];
        assert!(matches!(
            ipv6_udp(src, dst, 1, &payload, &mut buf),
            Err(FrameError::PayloadTooLarge { payload: 65_528 })
        ));
    }
}
