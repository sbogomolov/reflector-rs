//! Configuration loading and validation.
//!
//! TOML is deserialized into a permissive raw form
//! ([`RawConfig`]/[`RawReflector`]) and then validated into the strongly-typed
//! [`Config`] the rest of the program uses. The typed values make illegal
//! states unrepresentable (for example, [`Wol::ports`] exists only when WoL is
//! enabled).
//!
//! Errors split cleanly in two: value-level problems (wrong type, bad port,
//! unparseable enum/MAC) are produced by the deserializer and surface as
//! [`ConfigError::Parse`]; cross-field and cross-reflector rules are checked
//! during validation and surface as their own typed variants.
//!
//! Reflectors are nested under a `reflectors` table (`[reflectors.<name>]`)
//! rather than top-level tables: this keeps the deserializer off
//! `#[serde(flatten)]`, which would otherwise discard the line/column of every
//! value error.

use std::collections::BTreeMap;
use std::fmt;
use std::num::NonZeroU16;
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
    pub fn uses_ipv4(self) -> bool {
        matches!(self, Self::Default | Self::Dual | Self::Ipv4)
    }

    /// Whether this family handles IPv6 traffic.
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
        let [a, b, c, d, e, g] = self.0;
        write!(f, "{a:02x}:{b:02x}:{c:02x}:{d:02x}:{e:02x}:{g:02x}")
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

/// Wake-on-LAN settings (present only when WoL is enabled for the reflector).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wol {
    /// UDP destination ports whose magic packets are relayed.
    pub ports: Vec<NonZeroU16>,
}

/// SSDP settings (present only when SSDP is enabled for the reflector).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ssdp {
    /// Whether the DIAL HTTP proxy is layered on top of SSDP.
    pub dial: bool,
}

/// One reflector: bridges `source_if` → `target_if` for the enabled protocols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reflector {
    /// Name of the reflector (its key under `[reflectors.<name>]`), used in logs.
    pub name: String,
    /// Interface to listen on.
    pub source_if: String,
    /// Interface to emit on (always different from `source_if`).
    pub target_if: String,
    /// Optional MAC filter; `None` matches any device.
    pub mac: Option<MacAddr>,
    /// IP-version policy for this reflector.
    pub address_family: AddressFamily,
    /// Wake-on-LAN settings, or `None` when WoL is disabled.
    pub wol: Option<Wol>,
    /// Whether mDNS reflection is enabled.
    pub mdns: bool,
    /// SSDP settings, or `None` when SSDP is disabled.
    pub ssdp: Option<Ssdp>,
}

/// A fully-validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Minimum severity to log.
    pub log_level: LogLevel,
    /// Whether to periodically log memory-footprint diagnostics.
    pub debug_memory: bool,
    /// The configured reflectors.
    pub reflectors: Vec<Reflector>,
}

impl Config {
    /// Read and validate a configuration from a TOML file.
    pub fn from_toml_file(path: &str) -> Result<Self, ConfigError> {
        let text = std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
            path: path.to_owned(),
            source,
        })?;
        Self::from_toml_str(&text)
    }

    /// Parse and validate a configuration from TOML text.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        // First `?`: value-level errors (serde). Second call: cross-field rules.
        let raw: RawConfig = toml::from_str(text)?;
        Config::try_from(raw)
    }
}

/// Everything that can make a configuration invalid.
///
/// [`ConfigError::Parse`] carries value-level errors from the deserializer
/// (wrong type, bad port, unparseable enum/MAC); the remaining variants are the
/// cross-field and cross-reflector rules the deserializer cannot express.
#[derive(Debug, Error)]
pub enum ConfigError {
    /// The text was not valid TOML, or a value had the wrong type/range.
    #[error("invalid configuration: {0}")]
    Parse(#[from] toml::de::Error),

    /// The configuration file could not be read.
    #[error("cannot read config file \"{path}\": {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },

    /// No reflectors were defined.
    #[error("must define at least one reflector")]
    NoReflectors,

    /// `source_if` and `target_if` were the same interface.
    #[error("reflector \"{name}\" source_if and target_if must differ (both are \"{value}\")")]
    SameInterface { name: String, value: String },

    /// The reflector enabled none of WoL, mDNS, or SSDP.
    #[error("reflector \"{name}\" enables no protocol (set wol, mdns, or ssdp)")]
    NoProtocol { name: String },

    /// `wol_ports` was set without enabling WoL.
    #[error("reflector \"{name}\" sets wol_ports but does not enable wol")]
    WolPortsWithoutWol { name: String },

    /// `dial` was set without enabling SSDP.
    #[error("reflector \"{name}\" sets dial but does not enable ssdp")]
    DialWithoutSsdp { name: String },

    /// `dial` was enabled but the address family excludes IPv4.
    #[error("reflector \"{name}\" enables dial but the address family has no IPv4 (DIAL is IPv4-only)")]
    DialRequiresIpv4 { name: String },
}

// ----- raw (serde) layer ---------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    log_level: LogLevel,
    #[serde(default)]
    debug_memory: bool,
    #[serde(default)]
    reflectors: BTreeMap<String, RawReflector>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReflector {
    #[serde(deserialize_with = "de_interface")]
    source_if: String,
    #[serde(deserialize_with = "de_interface")]
    target_if: String,
    mac: Option<MacAddr>,
    #[serde(default)]
    wol: bool,
    #[serde(default)]
    mdns: bool,
    #[serde(default)]
    ssdp: bool,
    #[serde(default)]
    dial: bool,
    #[serde(default, deserialize_with = "de_wol_ports")]
    wol_ports: Option<Vec<NonZeroU16>>,
    #[serde(default)]
    address_family: AddressFamily,
}

// ----- raw -> validated ----------------------------------------------------

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, ConfigError> {
        let mut reflectors = Vec::with_capacity(raw.reflectors.len());
        for (name, raw_reflector) in raw.reflectors {
            reflectors.push(Reflector::from_raw(name, raw_reflector)?);
        }
        if reflectors.is_empty() {
            return Err(ConfigError::NoReflectors);
        }

        Ok(Config {
            log_level: raw.log_level,
            debug_memory: raw.debug_memory,
            reflectors,
        })
    }
}

impl Reflector {
    fn from_raw(name: String, raw: RawReflector) -> Result<Self, ConfigError> {
        let source_if = raw.source_if;
        let target_if = raw.target_if;
        if source_if == target_if {
            return Err(ConfigError::SameInterface {
                name,
                value: source_if,
            });
        }

        if !raw.wol && !raw.mdns && !raw.ssdp {
            return Err(ConfigError::NoProtocol { name });
        }
        if raw.wol_ports.is_some() && !raw.wol {
            return Err(ConfigError::WolPortsWithoutWol { name });
        }
        if raw.dial && !raw.ssdp {
            return Err(ConfigError::DialWithoutSsdp { name });
        }

        let wol = if raw.wol {
            let ports = raw.wol_ports.unwrap_or_else(default_wol_ports);
            Some(Wol { ports })
        } else {
            None
        };

        let ssdp = if raw.ssdp {
            if raw.dial && !raw.address_family.uses_ipv4() {
                return Err(ConfigError::DialRequiresIpv4 { name });
            }
            Some(Ssdp { dial: raw.dial })
        } else {
            None
        };

        Ok(Reflector {
            name,
            source_if,
            target_if,
            mac: raw.mac,
            address_family: raw.address_family,
            wol,
            mdns: raw.mdns,
            ssdp,
        })
    }
}

// ----- helpers -------------------------------------------------------------

fn de_interface<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    if value.is_empty() {
        return Err(serde::de::Error::custom("interface name must not be empty"));
    }
    Ok(value)
}

fn de_wol_ports<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<NonZeroU16>>, D::Error> {
    let ports = Vec::<NonZeroU16>::deserialize(deserializer)?;
    if ports.is_empty() {
        return Err(serde::de::Error::custom("wol_ports must not be empty"));
    }
    for (i, port) in ports.iter().enumerate() {
        if ports[..i].contains(port) {
            return Err(serde::de::Error::custom(format!(
                "wol_ports contains duplicate port {}",
                port.get()
            )));
        }
    }
    Ok(Some(ports))
}

fn default_wol_ports() -> Vec<NonZeroU16> {
    const PORTS: [NonZeroU16; 2] = [NonZeroU16::new(7).unwrap(), NonZeroU16::new(9).unwrap()];
    PORTS.to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn err(text: &str) -> ConfigError {
        Config::from_toml_str(text).unwrap_err()
    }

    #[test]
    fn minimal_reflector_uses_defaults() {
        let cfg = Config::from_toml_str(
            r#"
            [reflectors.discovery]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            "#,
        )
        .unwrap();
        assert_eq!(cfg.log_level, LogLevel::Info);
        assert!(!cfg.debug_memory);
        assert_eq!(cfg.reflectors.len(), 1);
        let r = &cfg.reflectors[0];
        assert_eq!(r.name, "discovery");
        assert_eq!(r.source_if, "lan");
        assert_eq!(r.target_if, "iot");
        assert!(r.mdns);
        assert!(r.mac.is_none());
        assert_eq!(r.address_family, AddressFamily::Default);
        assert!(r.wol.is_none());
        assert!(r.ssdp.is_none());
    }

    #[test]
    fn full_reflector_parses() {
        let cfg = Config::from_toml_str(
            r#"
            log_level = "DEBUG"
            debug_memory = true

            [reflectors.tv]
            source_if = "en0"
            target_if = "lo0"
            mac = "B0:37:95:C5:60:BE"
            wol = true
            mdns = true
            ssdp = true
            dial = true
            wol_ports = [7, 9, 4000]
            address_family = "dual"
            "#,
        )
        .unwrap();
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert!(cfg.debug_memory);
        assert_eq!(cfg.reflectors.len(), 1);
        let r = &cfg.reflectors[0];
        assert_eq!(r.name, "tv");
        assert_eq!(r.source_if, "en0");
        assert_eq!(r.target_if, "lo0");
        assert_eq!(r.mac.unwrap().to_string(), "b0:37:95:c5:60:be");
        let wol = r.wol.as_ref().unwrap();
        assert!(r.mdns);
        let ssdp = r.ssdp.unwrap();
        assert!(ssdp.dial);
        assert_eq!(wol.ports.iter().map(|p| p.get()).collect::<Vec<_>>(), [7, 9, 4000]);
        assert_eq!(r.address_family, AddressFamily::Dual);
    }

    #[test]
    fn wol_defaults_to_ports_7_and_9() {
        let cfg = Config::from_toml_str(
            r#"
            [reflectors.w]
            source_if = "a"
            target_if = "b"
            wol = true
            "#,
        )
        .unwrap();
        let ports: Vec<u16> = cfg.reflectors[0]
            .wol
            .as_ref()
            .unwrap()
            .ports
            .iter()
            .map(|p| p.get())
            .collect();
        assert_eq!(ports, [7, 9]);
    }

    #[test]
    fn multiple_reflectors_parse() {
        let cfg = Config::from_toml_str(
            r#"
            [reflectors.zebra]
            source_if = "a"
            target_if = "b"
            mdns = true

            [reflectors.alpha]
            source_if = "a"
            target_if = "b"
            mdns = true
            "#,
        )
        .unwrap();
        let mut names: Vec<&str> = cfg.reflectors.iter().map(|r| r.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["alpha", "zebra"]);
    }

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
    fn empty_config_is_rejected() {
        assert!(matches!(err(""), ConfigError::NoReflectors));
    }

    #[test]
    fn invalid_log_level() {
        let text = r#"
            log_level = "verbose"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn reflector_with_no_protocol() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
        "#;
        assert!(matches!(err(text), ConfigError::NoProtocol { name } if name == "x"));
    }

    #[test]
    fn source_and_target_must_differ() {
        let text = r#"
            [reflectors.x]
            source_if = "same"
            target_if = "same"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::SameInterface { value, .. } if value == "same"));
    }

    #[test]
    fn missing_source_if() {
        let text = r#"
            [reflectors.x]
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn empty_source_if() {
        let text = r#"
            [reflectors.x]
            source_if = ""
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn missing_target_if() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn empty_target_if() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = ""
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn wol_ports_without_wol() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            wol_ports = [7]
        "#;
        assert!(matches!(err(text), ConfigError::WolPortsWithoutWol { .. }));
    }

    #[test]
    fn dial_without_ssdp() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            dial = true
        "#;
        assert!(matches!(err(text), ConfigError::DialWithoutSsdp { .. }));
    }

    #[test]
    fn dial_requires_ipv4() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            ssdp = true
            dial = true
            address_family = "ipv6"
        "#;
        assert!(matches!(err(text), ConfigError::DialRequiresIpv4 { .. }));
    }

    #[test]
    fn wol_port_zero_rejected() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = [0]
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn duplicate_wol_port_rejected() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = [7, 7]
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn empty_wol_ports_rejected() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = []
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn wol_port_out_of_range_rejected() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            wol = true
            wol_ports = [70000]
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn invalid_mac() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            mac = "zz:zz:zz:zz:zz:zz"
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn invalid_address_family() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            address_family = "ipv5"
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn unknown_reflector_key_rejected() {
        let text = r#"
            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
            typo = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn unknown_top_level_key_rejected() {
        let text = r#"
            log_levle = "info"

            [reflectors.x]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn top_level_reflector_table_is_rejected() {
        // Reflectors must be nested under [reflectors.<name>], not top-level tables.
        let text = r#"
            [tv]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }
}
