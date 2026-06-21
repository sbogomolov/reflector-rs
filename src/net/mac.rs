//! MAC (link-layer) addressing: the 48-bit address type, its text form, and the
//! L2 destination MACs derived from multicast / broadcast IP addresses.

use std::fmt;
use std::net::IpAddr;
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
            if part.len() != 2 {
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
}
