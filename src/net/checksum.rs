//! RFC 1071 Internet checksum, computed only on the egress (raw-inject) path.
//!
//! When we build a frame to inject ourselves, the kernel UDP/IP stack is out of
//! the loop, so the IPv4 header and UDP checksums are filled in by hand. The
//! capture path never verifies checksums — a re-injected packet gets fresh ones.

use std::net::{Ipv4Addr, Ipv6Addr};

/// Internet checksum of an IPv4 header.
///
/// `header` is the full IHL-sized header. Its own checksum field (bytes 10-11)
/// is treated as zero, so its current contents don't affect the result — there
/// is no need to pre-zero it, and re-checksumming a header that already carries
/// one just works.
///
/// # Panics
/// Panics if `header` is shorter than 12 bytes (no room for the checksum field).
#[must_use]
pub fn ipv4_header(header: &[u8]) -> u16 {
    // Sum the header with its checksum field (bytes 10-11) skipped.
    let sum = sum_words(&header[..10], 0);
    let sum = sum_words(&header[12..], sum);
    fold(sum)
}

/// UDP checksum over the IPv4 pseudo-header and the UDP datagram.
///
/// `udp` is the contiguous UDP header plus payload. Its own checksum field
/// (bytes 6-7) is treated as zero — no need to pre-zero it. A computed `0x0000`
/// is returned as `0xffff` (RFC 768).
///
/// # Panics
/// Panics if `udp` is shorter than the 8-byte UDP header.
#[must_use]
pub fn udp_v4(src: Ipv4Addr, dst: Ipv4Addr, udp: &[u8]) -> u16 {
    // Pseudo-header: src(4) dst(4) zero(1) protocol(1) length(2).
    let mut pseudo = [0u8; 12];
    pseudo[0..4].copy_from_slice(&src.octets());
    pseudo[4..8].copy_from_slice(&dst.octets());
    pseudo[9] = super::IP_PROTO_UDP;
    pseudo[10..12].copy_from_slice(&udp_length(udp).to_be_bytes());
    udp_checksum(&pseudo, udp)
}

/// UDP checksum over the IPv6 pseudo-header and the UDP datagram.
///
/// As [`udp_v4`], but with the 40-byte IPv6 pseudo-header. `udp` is the
/// contiguous UDP header plus payload; its checksum field (bytes 6-7) is treated
/// as zero, and a computed `0x0000` is returned as `0xffff` (RFC 768).
///
/// # Panics
/// Panics if `udp` is shorter than the 8-byte UDP header.
#[must_use]
pub fn udp_v6(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> u16 {
    // Pseudo-header: src(16) dst(16) length(4) zero(3) next_header(1).
    let mut pseudo = [0u8; 40];
    pseudo[0..16].copy_from_slice(&src.octets());
    pseudo[16..32].copy_from_slice(&dst.octets());
    pseudo[32..36].copy_from_slice(&u32::from(udp_length(udp)).to_be_bytes());
    pseudo[39] = super::IP_PROTO_UDP;
    udp_checksum(&pseudo, udp)
}

/// Sum the pseudo-header and the datagram — with the UDP checksum field (bytes
/// 6-7) skipped — then fold and apply the RFC 768 zero map.
fn udp_checksum(pseudo: &[u8], udp: &[u8]) -> u16 {
    let sum = sum_words(pseudo, 0);
    let sum = sum_words(&udp[..6], sum);
    let sum = sum_words(&udp[8..], sum);
    match fold(sum) {
        0 => 0xffff,
        checksum => checksum,
    }
}

/// Sum `data`'s 16-bit big-endian words into a 32-bit accumulator seeded with
/// `seed`; a trailing odd byte is treated as the high byte of a final word.
/// `seed` lets callers chain segments (pseudo-header, then datagram).
fn sum_words(data: &[u8], seed: u32) -> u32 {
    let mut words = data.chunks_exact(2);
    let mut sum = seed;
    for word in &mut words {
        sum += u32::from(u16::from_be_bytes([word[0], word[1]]));
    }
    if let [tail] = words.remainder() {
        sum += u32::from(*tail) << 8;
    }
    sum
}

/// Fold the carries of a 32-bit accumulator into 16 bits, then take the one's
/// complement. Two folds always suffice: after the first the high half is at
/// most 1, which the second carries in.
fn fold(sum: u32) -> u16 {
    let sum = (sum & 0xffff) + (sum >> 16);
    let sum = (sum & 0xffff) + (sum >> 16);
    !u16::try_from(sum).expect("two folds reduce the accumulator below 2^16")
}

/// The UDP datagram length, for the pseudo-header's length field.
fn udp_length(udp: &[u8]) -> u16 {
    u16::try_from(udp.len()).expect("UDP datagram length fits in u16")
}

#[cfg(test)]
mod tests {
    use super::*;

    // The canonical IPv4 header example, checksum field (bytes 10-11) zeroed;
    // its checksum is the well-known 0xb861.
    const IPV4_HEADER: [u8; 20] = [
        0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40, 0x11, 0x00, 0x00, 0xc0, 0xa8, 0x00,
        0x01, 0xc0, 0xa8, 0x00, 0xc7,
    ];

    #[test]
    fn ipv4_header_matches_known_vector() {
        assert_eq!(ipv4_header(&IPV4_HEADER), 0xb861);
    }

    #[test]
    fn ipv4_header_ignores_the_checksum_field() {
        let mut header = IPV4_HEADER;
        header[10] = 0xab;
        header[11] = 0xcd;
        // Bytes 10-11 are summed as zero, so a stale checksum field is harmless.
        assert_eq!(ipv4_header(&header), 0xb861);
    }

    #[test]
    fn sum_words_pads_an_odd_tail_high() {
        // One word then a lone byte: 0x1234 + (0x56 << 8) = 0x6834.
        assert_eq!(sum_words(&[0x12, 0x34, 0x56], 0), 0x6834);
    }

    #[test]
    fn udp_v4_matches_hand_computed_vector() {
        let src = Ipv4Addr::new(192, 168, 0, 1);
        let dst = Ipv4Addr::new(192, 168, 0, 199);
        let udp = [0x12, 0x34, 0x56, 0x78, 0x00, 0x08, 0x00, 0x00];
        assert_eq!(udp_v4(src, dst, &udp), 0x1519);
    }

    #[test]
    fn udp_v4_ignores_the_checksum_field() {
        let src = Ipv4Addr::new(192, 168, 0, 1);
        let dst = Ipv4Addr::new(192, 168, 0, 199);
        // Odd-length datagram (1-byte payload) also exercises the odd tail.
        let mut udp = [0x12, 0x34, 0x56, 0x78, 0x00, 0x09, 0x00, 0x00, 0xaa];
        let zeroed = udp_v4(src, dst, &udp);
        udp[6] = 0xde;
        udp[7] = 0xad;
        assert_eq!(udp_v4(src, dst, &udp), zeroed);
    }

    #[test]
    fn udp_v4_zero_checksum_maps_to_ffff() {
        // Crafted so the folded sum is 0xffff and the complement (0) is remapped
        // to 0xffff per RFC 768.
        let zero = Ipv4Addr::UNSPECIFIED;
        assert_eq!(udp_v4(zero, zero, &[0xff, 0xe6, 0, 0, 0, 0, 0, 0]), 0xffff);
    }

    #[test]
    fn udp_v6_matches_hand_computed_vector() {
        let src = Ipv6Addr::LOCALHOST; // ::1
        let dst = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2); // ::2
        let udp = [0x12, 0x34, 0x56, 0x78, 0x00, 0x08, 0x00, 0x00];
        assert_eq!(udp_v6(src, dst, &udp), 0x972f);
    }

    #[test]
    fn udp_v6_ignores_the_checksum_field() {
        let src = Ipv6Addr::LOCALHOST;
        let dst = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2);
        let mut udp = [0x12, 0x34, 0x56, 0x78, 0x00, 0x09, 0x00, 0x00, 0xaa];
        let zeroed = udp_v6(src, dst, &udp);
        udp[6] = 0xde;
        udp[7] = 0xad;
        assert_eq!(udp_v6(src, dst, &udp), zeroed);
    }

    #[test]
    fn udp_v6_zero_checksum_maps_to_ffff() {
        let zero = Ipv6Addr::UNSPECIFIED;
        assert_eq!(udp_v6(zero, zero, &[0xff, 0xe6, 0, 0, 0, 0, 0, 0]), 0xffff);
    }
}
