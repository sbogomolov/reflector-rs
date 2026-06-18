//! Strongly-typed configuration values.
//!
//! Each type parses from a string via `FromStr` (used by the environment layer,
//! with variable-named errors) and deserializes via a matching `Deserialize` that
//! delegates to the same `FromStr` (used by the TOML layer, with located errors).
//! The newtypes make illegal values unrepresentable.

use std::fmt;
use std::num::NonZeroU16;
use std::ops::Deref;
use std::str::FromStr;

use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// Minimum severity a log record must have to be emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum LogLevel {
    Debug,
    #[default]
    Info,
    Warning,
    Error,
}

/// Error returned when a string is not a valid [`LogLevel`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected one of: debug, info, warning, error")]
pub struct ParseLogLevelError;

impl FromStr for LogLevel {
    type Err = ParseLogLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "debug" => Ok(Self::Debug),
            "info" => Ok(Self::Info),
            "warning" => Ok(Self::Warning),
            "error" => Ok(Self::Error),
            _ => Err(ParseLogLevelError),
        }
    }
}

impl<'de> Deserialize<'de> for LogLevel {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Which IP versions a reflector operates on.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressFamily {
    #[default]
    Default,
    Dual,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    /// Whether this family handles IPv4 traffic.
    #[must_use]
    pub fn uses_ipv4(self) -> bool {
        matches!(self, Self::Default | Self::Dual | Self::Ipv4)
    }

    /// Whether this family handles IPv6 traffic.
    #[must_use]
    pub fn uses_ipv6(self) -> bool {
        matches!(self, Self::Default | Self::Dual | Self::Ipv6)
    }
}

/// Error returned when a string is not a valid [`AddressFamily`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected one of: default, dual, ipv4, ipv6")]
pub struct ParseAddressFamilyError;

impl FromStr for AddressFamily {
    type Err = ParseAddressFamilyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "default" => Ok(Self::Default),
            "dual" => Ok(Self::Dual),
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            _ => Err(ParseAddressFamilyError),
        }
    }
}

impl<'de> Deserialize<'de> for AddressFamily {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// A 48-bit IEEE 802 MAC address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr([u8; 6]);

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [b0, b1, b2, b3, b4, b5] = self.0;
        write!(f, "{b0:02x}:{b1:02x}:{b2:02x}:{b3:02x}:{b4:02x}:{b5:02x}")
    }
}

/// Error returned when a string is not a valid [`MacAddr`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected six colon-separated hex octets")]
pub struct ParseMacAddrError;

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

/// A non-empty network interface name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InterfaceName(String);

impl InterfaceName {
    /// The interface name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error returned when a string is not a valid [`InterfaceName`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("interface name must not be empty")]
pub struct ParseInterfaceNameError;

impl FromStr for InterfaceName {
    type Err = ParseInterfaceNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.is_empty() {
            return Err(ParseInterfaceNameError);
        }
        Ok(Self(s.to_owned()))
    }
}

impl<'de> Deserialize<'de> for InterfaceName {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// A reflector's display name: surrounding whitespace trimmed, never empty.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReflectorName(String);

impl ReflectorName {
    /// The name as a string slice.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReflectorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Error returned when a string is not a valid [`ReflectorName`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("reflector name must not be empty or whitespace-only")]
pub struct ParseReflectorNameError;

impl FromStr for ReflectorName {
    type Err = ParseReflectorNameError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let trimmed = s.trim();
        if trimmed.is_empty() {
            return Err(ParseReflectorNameError);
        }
        Ok(Self(trimmed.to_owned()))
    }
}

/// A non-empty, duplicate-free list of Wake-on-LAN destination ports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WolPorts(Vec<NonZeroU16>);

impl Default for WolPorts {
    fn default() -> Self {
        const PORTS: [NonZeroU16; 2] = [NonZeroU16::new(7).unwrap(), NonZeroU16::new(9).unwrap()];
        Self(PORTS.to_vec())
    }
}

impl Deref for WolPorts {
    type Target = [NonZeroU16];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/// Error returned when a string or list is not a valid [`WolPorts`].
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum WolPortsError {
    /// The list was empty.
    #[error("wol_ports must not be empty")]
    Empty,
    /// The same port appeared more than once.
    #[error("wol_ports contains duplicate port {0}")]
    Duplicate(u16),
    /// A comma-separated token was not a port in 1..=65535.
    #[error("wol_ports has an invalid port \"{0}\"")]
    BadPort(String),
}

impl TryFrom<Vec<NonZeroU16>> for WolPorts {
    type Error = WolPortsError;

    fn try_from(ports: Vec<NonZeroU16>) -> Result<Self, Self::Error> {
        if ports.is_empty() {
            return Err(WolPortsError::Empty);
        }
        for (i, port) in ports.iter().enumerate() {
            if ports[..i].contains(port) {
                return Err(WolPortsError::Duplicate(port.get()));
            }
        }
        Ok(Self(ports))
    }
}

impl FromStr for WolPorts {
    type Err = WolPortsError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let ports = s
            .split(',')
            .map(|token| {
                let token = token.trim();
                token
                    .parse::<NonZeroU16>()
                    .map_err(|_| WolPortsError::BadPort(token.to_owned()))
            })
            .collect::<Result<Vec<_>, _>>()?;
        WolPorts::try_from(ports)
    }
}

impl<'de> Deserialize<'de> for WolPorts {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Vec::<NonZeroU16>::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn log_level_parses_via_fromstr() {
        assert_eq!("debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("INFO".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("Warning".parse::<LogLevel>().unwrap(), LogLevel::Warning);
        assert_eq!("ERROR".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert_eq!("verbose".parse::<LogLevel>(), Err(ParseLogLevelError));
    }

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
    fn interface_name_parses_via_fromstr() {
        assert_eq!("en0".parse::<InterfaceName>().unwrap().as_str(), "en0");
        assert_eq!("".parse::<InterfaceName>(), Err(ParseInterfaceNameError));
    }

    #[test]
    fn reflector_name_parses_via_fromstr() {
        assert_eq!("  tv  ".parse::<ReflectorName>().unwrap().as_str(), "tv");
        assert_eq!("".parse::<ReflectorName>(), Err(ParseReflectorNameError));
        assert_eq!("   ".parse::<ReflectorName>(), Err(ParseReflectorNameError));
    }

    #[test]
    fn wol_ports_parse_via_fromstr() {
        let ports = "7, 9, 4000".parse::<WolPorts>().unwrap();
        assert_eq!(
            ports.iter().map(|p| p.get()).collect::<Vec<_>>(),
            [7, 9, 4000]
        );
        assert!(matches!(
            "7,7".parse::<WolPorts>(),
            Err(WolPortsError::Duplicate(7))
        ));
        assert!(matches!(
            "0".parse::<WolPorts>(),
            Err(WolPortsError::BadPort(_))
        ));
        assert!(matches!(
            "abc".parse::<WolPorts>(),
            Err(WolPortsError::BadPort(_))
        ));
        assert_eq!(
            WolPorts::default()
                .iter()
                .map(|p| p.get())
                .collect::<Vec<_>>(),
            [7, 9]
        );
    }
}
