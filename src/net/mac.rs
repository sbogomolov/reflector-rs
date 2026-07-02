//! MAC (link-layer) addressing: the 48-bit address type, its text form, and the
//! L2 destination MACs derived from multicast / broadcast IP addresses.

use std::fmt;
use std::net::IpAddr;
use std::ops::Deref;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// A 48-bit IEEE 802 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct MacAddr([u8; 6]);

impl MacAddr {
    /// The six address bytes, in transmission order.
    #[must_use]
    pub(crate) const fn octets(self) -> [u8; 6] {
        self.0
    }

    /// The L2 broadcast address, `ff:ff:ff:ff:ff:ff`.
    #[must_use]
    pub(crate) const fn broadcast() -> Self {
        MacAddr([0xff; 6])
    }

    /// The L2 destination MAC for a multicast IP `addr`: IPv4 maps to `01:00:5e`
    /// plus the low 23 address bits (RFC 1112), IPv6 to `33:33` plus the low 32
    /// bits (RFC 2464).
    ///
    /// # Panics
    /// Panics in debug builds if `addr` is not a multicast address.
    #[must_use]
    pub(crate) fn multicast_for(addr: IpAddr) -> Self {
        debug_assert!(
            addr.is_multicast(),
            "multicast_for requires a multicast address"
        );
        match addr {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                MacAddr([0x01, 0x00, 0x5e, o[1] & 0x7f, o[2], o[3]])
            }
            IpAddr::V6(v6) => {
                let o = v6.octets();
                MacAddr([0x33, 0x33, o[12], o[13], o[14], o[15]])
            }
        }
    }
}

/// The six bytes, in transmission order, *are* the address — mirroring `Ipv4Addr`'s
/// `From<[u8; 4]>`; used to read a MAC off the wire.
impl From<[u8; 6]> for MacAddr {
    fn from(octets: [u8; 6]) -> Self {
        MacAddr(octets)
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [b0, b1, b2, b3, b4, b5] = self.0;
        write!(f, "{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}")
    }
}

/// Error returned when a string is not a valid [`MacAddr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected six colon-separated hex octets")]
pub(crate) struct ParseMacAddrError;

impl FromStr for MacAddr {
    type Err = ParseMacAddrError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let mut bytes = [0u8; 6];
        let mut parts = s.split(':');
        for slot in &mut bytes {
            let part = parts.next().ok_or(ParseMacAddrError)?;
            // Exactly two hex digits. The is_ascii_hexdigit guard is load-bearing: u8::from_str_radix
            // accepts a leading '+' (e.g. "+a" parses to 10), so the length check alone would admit a
            // malformed octet like "+a:+b:+c:+d:+e:+f".
            if part.len() != 2 || !part.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(ParseMacAddrError);
            }
            *slot = u8::from_str_radix(part, 16).map_err(|_| ParseMacAddrError)?;
        }
        if parts.next().is_some() {
            return Err(ParseMacAddrError);
        }
        Ok(MacAddr(bytes))
    }
}

impl<'de> Deserialize<'de> for MacAddr {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// A non-empty, duplicate-free set of MAC addresses: a device allow-filter.
///
/// The set is always non-empty (mirroring [`WolPorts`](crate::config::WolPorts));
/// "match any device" is expressed by an absent (`None`) filter at the use site,
/// not by an empty set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct MacSet(Vec<MacAddr>);

impl Deref for MacSet {
    type Target = [MacAddr];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Error returned when a value is not a valid [`MacSet`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum MacSetError {
    #[error("macs must not be empty")]
    Empty,
    #[error("macs contains duplicate address {0}")]
    Duplicate(MacAddr),
    /// A comma-separated token was not a valid MAC address.
    #[error("macs has an invalid address \"{0}\"")]
    BadMac(String),
}

/// A single address is a valid one-element set.
impl From<MacAddr> for MacSet {
    fn from(mac: MacAddr) -> Self {
        MacSet(vec![mac])
    }
}

impl TryFrom<Vec<MacAddr>> for MacSet {
    type Error = MacSetError;

    fn try_from(macs: Vec<MacAddr>) -> Result<Self, Self::Error> {
        if macs.is_empty() {
            return Err(MacSetError::Empty);
        }
        for (i, mac) in macs.iter().enumerate() {
            if macs[..i].contains(mac) {
                return Err(MacSetError::Duplicate(*mac));
            }
        }
        Ok(Self(macs))
    }
}

impl FromStr for MacSet {
    type Err = MacSetError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let macs = s
            .split(',')
            .map(|token| {
                let token = token.trim();
                token
                    .parse::<MacAddr>()
                    .map_err(|_| MacSetError::BadMac(token.to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        MacSet::try_from(macs)
    }
}

impl<'de> Deserialize<'de> for MacSet {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<MacAddr>::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn mac_parses_via_fromstr() {
        let upper = "B0:37:95:C5:60:BE".parse::<MacAddr>().unwrap();
        let lower = "b0:37:95:c5:60:be".parse::<MacAddr>().unwrap();
        let mixed = "b0:37:95:C5:60:bE".parse::<MacAddr>().unwrap();
        assert_eq!(upper, lower);
        assert_eq!(upper, mixed);
        assert_eq!(upper.to_string(), "b0:37:95:c5:60:be");
        assert_eq!("zz".parse::<MacAddr>(), Err(ParseMacAddrError));
    }

    #[test]
    fn mac_rejects_sign_prefixed_octets() {
        // u8::from_str_radix accepts a leading '+', so without an explicit hex-digit guard each "+x"
        // octet would parse and a fully sign-prefixed MAC would be admitted. It must be rejected.
        assert_eq!(
            "+a:+b:+c:+d:+e:+f".parse::<MacAddr>(),
            Err(ParseMacAddrError)
        );
    }

    #[test]
    fn broadcast_is_all_ones() {
        assert_eq!(MacAddr::broadcast().octets(), [0xff; 6]);
    }

    #[test]
    fn ipv4_multicast_maps_to_01_00_5e() {
        // 224.0.0.251 (mDNS) -> 01:00:5e:00:00:fb.
        let mac = MacAddr::multicast_for(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)));
        assert_eq!(mac.octets(), [0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb]);
    }

    #[test]
    fn ipv4_multicast_clears_top_bit_of_byte_1() {
        // 239.255.255.250 (SSDP): byte 1 = 0xff -> 0x7f (only the low 23 bits map).
        let mac = MacAddr::multicast_for(IpAddr::V4(Ipv4Addr::new(239, 255, 255, 250)));
        assert_eq!(mac.octets(), [0x01, 0x00, 0x5e, 0x7f, 0xff, 0xfa]);
    }

    #[test]
    fn ipv6_multicast_maps_to_33_33() {
        // ff02::fb (mDNS) -> 33:33:00:00:00:fb (low 32 bits).
        let mac = MacAddr::multicast_for(IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)));
        assert_eq!(mac.octets(), [0x33, 0x33, 0x00, 0x00, 0x00, 0xfb]);
    }

    #[test]
    fn ipv6_multicast_maps_the_low_32_bits() {
        // Distinct bytes 12..16 pin the mapping (ff02::fb alone can't).
        let mac = MacAddr::multicast_for(IpAddr::V6(Ipv6Addr::new(
            0xff02, 0, 0, 0, 0, 0, 0xdead, 0xbeef,
        )));
        assert_eq!(mac.octets(), [0x33, 0x33, 0xde, 0xad, 0xbe, 0xef]);
    }

    #[test]
    #[cfg_attr(
        not(debug_assertions),
        ignore = "multicast_for's guard is a debug_assert!, compiled out in release"
    )]
    #[should_panic(expected = "multicast_for requires a multicast address")]
    fn multicast_for_panics_on_a_non_multicast_address() {
        let _ = MacAddr::multicast_for(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1)));
    }

    #[test]
    fn from_str_rejects_malformed() {
        for s in [
            "",
            "01:02:03",             // too few
            "01:02:03:04:05:06:07", // too many
            "1:2:3:4:5:6",          // one-digit octets
            "100:02:03:04:05:06",   // three-digit octet
            "01::03:04:05:06",      // empty octet
        ] {
            assert_eq!(s.parse::<MacAddr>(), Err(ParseMacAddrError), "{s:?}");
        }
    }

    #[test]
    fn mac_display_zero_pads_octets() {
        let mac = MacAddr::from([0x01, 0x02, 0x03, 0x04, 0x05, 0x0a]);
        assert_eq!(mac.to_string(), "01:02:03:04:05:0a");
    }

    #[test]
    fn mac_set_parses_a_csv_via_fromstr() {
        let set = "aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02"
            .parse::<MacSet>()
            .unwrap();
        assert_eq!(set.len(), 2);
        assert!(set.contains(&MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x01])));
        assert!(set.contains(&MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x02])));
        assert!(!set.contains(&MacAddr::from([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x03])));
    }

    #[test]
    fn mac_set_from_a_single_address() {
        let mac = MacAddr::from([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        let set = MacSet::from(mac);
        assert_eq!(&*set, &[mac]);
    }

    #[test]
    fn mac_set_rejects_duplicates_and_bad_and_empty() {
        assert!(matches!(
            "aa:bb:cc:dd:ee:01,aa:bb:cc:dd:ee:01".parse::<MacSet>(),
            Err(MacSetError::Duplicate(_))
        ));
        assert!(matches!(
            "aa:bb:cc:dd:ee:01,zz".parse::<MacSet>(),
            Err(MacSetError::BadMac(bad)) if bad == "zz"
        ));
        // FromStr can't yield an empty list, so Empty is reachable only via TryFrom.
        assert!(matches!(
            MacSet::try_from(Vec::<MacAddr>::new()),
            Err(MacSetError::Empty)
        ));
    }
}
