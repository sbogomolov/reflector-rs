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

/// Minimum severity a record must have to be logged; `Off` disables logging
/// entirely. Ordered most-restrictive to most-verbose, mirroring `log`'s filter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum LogLevel {
    Off,
    Error,
    Warning,
    #[default]
    Info,
    Debug,
    Trace,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected one of: off, error, warning, info, debug, trace")]
pub(crate) struct ParseLogLevelError;

impl FromStr for LogLevel {
    type Err = ParseLogLevelError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "off" => Ok(Self::Off),
            "error" => Ok(Self::Error),
            "warning" => Ok(Self::Warning),
            "info" => Ok(Self::Info),
            "debug" => Ok(Self::Debug),
            "trace" => Ok(Self::Trace),
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
pub(crate) enum AddressFamily {
    #[default]
    Default,
    Dual,
    Ipv4,
    Ipv6,
}

impl AddressFamily {
    #[must_use]
    pub(crate) fn uses_ipv4(self) -> bool {
        matches!(self, Self::Default | Self::Dual | Self::Ipv4)
    }

    #[must_use]
    pub(crate) fn uses_ipv6(self) -> bool {
        matches!(self, Self::Default | Self::Dual | Self::Ipv6)
    }

    /// A v4 source must be present at startup, else the reflector fails to build. Same set as
    /// `uses_ipv4` — v4 is the baseline — but distinct: `Default` requires v4 while treating v6
    /// as best-effort.
    #[must_use]
    pub(crate) fn requires_ipv4(self) -> bool {
        matches!(self, Self::Default | Self::Dual | Self::Ipv4)
    }

    /// A v6 source must be present at startup, else the reflector fails to build — only `Dual`
    /// and `Ipv6`. Unlike `uses_ipv6`, `Default` reflects v6 when available but starts without it.
    #[must_use]
    pub(crate) fn requires_ipv6(self) -> bool {
        matches!(self, Self::Dual | Self::Ipv6)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected one of: default, dual, ipv4, ipv6")]
pub(crate) struct ParseAddressFamilyError;

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

/// A non-empty network interface name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct InterfaceName(String);

impl InterfaceName {
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for InterfaceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("interface name must not be empty")]
pub(crate) struct ParseInterfaceNameError;

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
pub(crate) struct ReflectorName(String);

impl ReflectorName {
    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ReflectorName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("reflector name must not be empty or whitespace-only")]
pub(crate) struct ParseReflectorNameError;

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
pub(crate) struct WolPorts(Vec<NonZeroU16>);

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

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum WolPortsError {
    #[error("wol_ports must not be empty")]
    Empty,
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
    fn address_family_uses_and_requires() {
        use AddressFamily as F;
        // Uses: which families the reflector handles. Default and Dual handle both.
        assert_eq!(
            (F::Default.uses_ipv4(), F::Default.uses_ipv6()),
            (true, true)
        );
        assert_eq!((F::Dual.uses_ipv4(), F::Dual.uses_ipv6()), (true, true));
        assert_eq!((F::Ipv4.uses_ipv4(), F::Ipv4.uses_ipv6()), (true, false));
        assert_eq!((F::Ipv6.uses_ipv4(), F::Ipv6.uses_ipv6()), (false, true));
        // Requires: which must be present at startup. Default requires v4 only (v6 best-effort).
        assert_eq!(
            (F::Default.requires_ipv4(), F::Default.requires_ipv6()),
            (true, false)
        );
        assert_eq!(
            (F::Dual.requires_ipv4(), F::Dual.requires_ipv6()),
            (true, true)
        );
        assert_eq!(
            (F::Ipv4.requires_ipv4(), F::Ipv4.requires_ipv6()),
            (true, false)
        );
        assert_eq!(
            (F::Ipv6.requires_ipv4(), F::Ipv6.requires_ipv6()),
            (false, true)
        );
    }

    #[test]
    fn log_level_parses_via_fromstr() {
        assert_eq!("off".parse::<LogLevel>().unwrap(), LogLevel::Off);
        assert_eq!("ERROR".parse::<LogLevel>().unwrap(), LogLevel::Error);
        assert_eq!("Warning".parse::<LogLevel>().unwrap(), LogLevel::Warning);
        assert_eq!("INFO".parse::<LogLevel>().unwrap(), LogLevel::Info);
        assert_eq!("debug".parse::<LogLevel>().unwrap(), LogLevel::Debug);
        assert_eq!("Trace".parse::<LogLevel>().unwrap(), LogLevel::Trace);
        assert_eq!("verbose".parse::<LogLevel>(), Err(ParseLogLevelError));
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

    #[test]
    fn address_family_parses_via_fromstr() {
        use AddressFamily as F;
        assert_eq!("default".parse::<F>().unwrap(), F::Default);
        assert_eq!("DUAL".parse::<F>().unwrap(), F::Dual);
        assert_eq!("ipv4".parse::<F>().unwrap(), F::Ipv4);
        assert_eq!("IPv6".parse::<F>().unwrap(), F::Ipv6);
        assert_eq!("both".parse::<F>(), Err(ParseAddressFamilyError));
    }

    #[test]
    fn wol_ports_reject_an_empty_list() {
        // FromStr can't yield an empty list, so Empty is reachable only via the TryFrom path.
        assert!(matches!(
            WolPorts::try_from(Vec::<NonZeroU16>::new()),
            Err(WolPortsError::Empty)
        ));
    }
}
