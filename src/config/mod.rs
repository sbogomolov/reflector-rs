//! Configuration loading and validation.
//!
//! TOML is deserialized into a raw form (`RawConfig`/`RawReflector`) and then
//! validated into the strongly-typed [`Config`] the rest of the program uses. The
//! typed values make illegal states unrepresentable (for example, [`Wol::ports`]
//! exists only when `WoL` is enabled, and [`InterfaceName`]/[`WolPorts`] can't be
//! empty).
//!
//! The pieces live in submodules: value types in `value`, errors in `error`, the
//! serde layer in `raw`, and the environment parser in `env`. Each value type is
//! a `FromStr` type with a matching `Deserialize`, so the same validation serves
//! both the TOML path (via serde, with located errors) and the environment path
//! (via `FromStr`, with variable-named errors). Cross-field and cross-reflector
//! rules live in the `TryFrom` conversions here, and file and environment settings
//! are combined in [`Config::from_sources`].
//!
//! Reflectors are nested under a `reflectors` table (`[reflectors.<name>]`)
//! rather than top-level tables: this keeps the deserializer off
//! `#[serde(flatten)]`, which would otherwise discard the line/column of every
//! value error.

mod env;
mod error;
mod raw;
mod value;

pub use error::{ConfigError, ParseBoolError, ParseValueError, Protocol, RequiredField};
pub use value::{
    AddressFamily, InterfaceName, LogLevel, MacAddr, ParseAddressFamilyError,
    ParseInterfaceNameError, ParseLogLevelError, ParseMacAddrError, ParseReflectorNameError,
    ReflectorName, WolPorts, WolPortsError,
};

use std::str::FromStr;

use raw::{RawConfig, RawReflector};

/// Wake-on-LAN settings (present only when `WoL` is enabled for the reflector).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wol {
    /// UDP destination ports whose magic packets are relayed.
    pub ports: WolPorts,
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
    /// Display name (from the `[reflectors.<name>]` key or `REFLECTOR_<tag>_NAME`),
    /// used in logs; trimmed and never empty.
    pub name: ReflectorName,
    /// Interface to listen on.
    pub source_if: InterfaceName,
    /// Interface to emit on (always different from `source_if`).
    pub target_if: InterfaceName,
    /// Optional MAC filter; `None` matches any device.
    pub mac: Option<MacAddr>,
    /// IP-version policy for this reflector.
    pub address_family: AddressFamily,
    /// Wake-on-LAN settings, or `None` when `WoL` is disabled.
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
    /// Parse and validate a configuration from TOML text.
    ///
    /// # Errors
    /// Returns [`ConfigError::Parse`] for malformed TOML or out-of-range values,
    /// or a cross-field [`ConfigError`] variant if validation fails.
    pub fn from_toml_str(text: &str) -> Result<Self, ConfigError> {
        // First `?`: value-level errors (serde). Second call: cross-field rules.
        let raw: RawConfig = toml::from_str(text)?;
        Config::try_from(raw)
    }

    /// Load from an optional TOML file plus `REFLECTOR_*` environment variables.
    ///
    /// The file (if given) is read first; environment variables then override the
    /// global settings and contribute additional reflectors. This is the entry
    /// point the binary uses, passing [`std::env::vars`].
    ///
    /// # Errors
    /// Returns [`ConfigError::ReadFile`] if the file cannot be read, or any
    /// parse/merge/validation error from [`Config::from_sources`].
    pub fn load(
        path: Option<&str>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let text = path.map(read_config_file).transpose()?;
        Self::from_sources(text.as_deref(), env)
    }

    /// Build a configuration from optional TOML text plus environment variables.
    ///
    /// Environment variables take precedence over the file for the global
    /// settings; reflectors from the two sources are combined, and a name defined
    /// by both is rejected. Kept free of I/O so it can be exercised directly.
    ///
    /// # Errors
    /// Returns [`ConfigError::Parse`] for malformed TOML, an `Env*` variant for a
    /// malformed or invalid environment variable, [`ConfigError::DuplicateReflector`]
    /// when a name is defined by both sources, or any cross-field [`ConfigError`].
    pub fn from_sources(
        toml_text: Option<&str>,
        env: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, ConfigError> {
        let mut raw: RawConfig = match toml_text {
            Some(text) => toml::from_str(text)?,
            None => RawConfig::default(),
        };
        raw.merge_env(env::parse_env(env)?)?;
        Config::try_from(raw)
    }
}

/// Read a configuration file, mapping I/O failure to [`ConfigError::ReadFile`].
fn read_config_file(path: &str) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.to_owned(),
        source,
    })
}

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, ConfigError> {
        let mut reflectors = Vec::with_capacity(raw.reflectors.len());
        for (name, raw_reflector) in raw.reflectors {
            reflectors.push(Reflector::try_from((name, raw_reflector))?);
        }
        if reflectors.is_empty() {
            return Err(ConfigError::NoReflectors);
        }
        check_conflicts(&reflectors)?;

        Ok(Config {
            log_level: raw.log_level.unwrap_or_default(),
            debug_memory: raw.debug_memory.unwrap_or_default(),
            reflectors,
        })
    }
}

impl TryFrom<(String, RawReflector)> for Reflector {
    type Error = ConfigError;

    fn try_from((key, raw): (String, RawReflector)) -> Result<Self, ConfigError> {
        // Display name: the env `NAME` override (already validated) or the
        // identity key (file table key / env tag), validated here.
        let name = match raw.name {
            Some(name) => name,
            None => ReflectorName::from_str(&key)
                .map_err(|_| ConfigError::EmptyReflectorName { key: key.clone() })?,
        };
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
            let ports = raw.wol_ports.unwrap_or_default();
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

impl Reflector {
    /// The protocol on which `self` and `other` would reflect the same packet
    /// twice, if any: same direction, overlapping MAC selection and address
    /// family, and a shared enabled protocol (for `WoL`, also a shared port).
    fn conflicts_with(&self, other: &Reflector) -> Option<Protocol> {
        if self.source_if != other.source_if || self.target_if != other.target_if {
            return None;
        }
        if !macs_overlap(self.mac, other.mac)
            || !families_overlap(self.address_family, other.address_family)
        {
            return None;
        }
        if let (Some(a), Some(b)) = (&self.wol, &other.wol)
            && a.ports.iter().any(|port| b.ports.contains(port))
        {
            return Some(Protocol::Wol);
        }
        if self.mdns && other.mdns {
            return Some(Protocol::Mdns);
        }
        if self.ssdp.is_some() && other.ssdp.is_some() {
            return Some(Protocol::Ssdp);
        }
        None
    }
}

/// Two MAC selections overlap when both name the same address or either is
/// absent (an absent filter matches any device).
fn macs_overlap(a: Option<MacAddr>, b: Option<MacAddr>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a == b,
        _ => true,
    }
}

/// Two address families overlap when they both carry the same IP version.
fn families_overlap(a: AddressFamily, b: AddressFamily) -> bool {
    (a.uses_ipv4() && b.uses_ipv4()) || (a.uses_ipv6() && b.uses_ipv6())
}

/// Reject any pair of reflectors that would reflect the same packet twice.
fn check_conflicts(reflectors: &[Reflector]) -> Result<(), ConfigError> {
    for (i, a) in reflectors.iter().enumerate() {
        for b in &reflectors[i + 1..] {
            if let Some(protocol) = a.conflicts_with(b) {
                return Err(ConfigError::ConflictingReflectors {
                    protocol,
                    first: a.name.clone(),
                    second: b.name.clone(),
                    source_if: a.source_if.clone(),
                    target_if: a.target_if.clone(),
                });
            }
        }
    }
    Ok(())
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
        assert_eq!(r.name.as_str(), "discovery");
        assert_eq!(r.source_if.as_str(), "lan");
        assert_eq!(r.target_if.as_str(), "iot");
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
        assert_eq!(r.name.as_str(), "tv");
        assert_eq!(r.source_if.as_str(), "en0");
        assert_eq!(r.target_if.as_str(), "lo0");
        assert_eq!(r.mac.unwrap().to_string(), "b0:37:95:c5:60:be");
        let wol = r.wol.as_ref().unwrap();
        assert!(r.mdns);
        let ssdp = r.ssdp.unwrap();
        assert!(ssdp.dial);
        assert_eq!(
            wol.ports.iter().map(|p| p.get()).collect::<Vec<_>>(),
            [7, 9, 4000]
        );
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
            target_if = "c"
            mdns = true
            "#,
        )
        .unwrap();
        let mut names: Vec<&str> = cfg.reflectors.iter().map(|r| r.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["alpha", "zebra"]);
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
        assert!(matches!(err(text), ConfigError::NoProtocol { name } if name.as_str() == "x"));
    }

    #[test]
    fn source_and_target_must_differ() {
        let text = r#"
            [reflectors.x]
            source_if = "same"
            target_if = "same"
            mdns = true
        "#;
        assert!(
            matches!(err(text), ConfigError::SameInterface { value, .. } if value.as_str() == "same")
        );
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

    #[test]
    fn empty_file_reflector_key_rejected() {
        let text = r#"
            [reflectors.""]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::EmptyReflectorName { .. }));
    }

    #[test]
    fn whitespace_file_reflector_key_rejected() {
        let text = r#"
            [reflectors."   "]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        assert!(matches!(err(text), ConfigError::EmptyReflectorName { .. }));
    }

    #[test]
    fn conflicting_mdns_reflectors_rejected() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Mdns,
                ..
            }
        ));
    }

    #[test]
    fn reverse_direction_does_not_conflict() {
        // lan->iot and iot->lan reflect opposite directions; not a duplicate.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "iot"
            target_if = "lan"
            mdns = true
        "#;
        assert!(Config::from_toml_str(text).is_ok());
    }

    #[test]
    fn different_protocols_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            wol = true
        "#;
        assert!(Config::from_toml_str(text).is_ok());
    }

    #[test]
    fn distinct_macs_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            mac = "00:00:00:00:00:01"

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            mac = "00:00:00:00:00:02"
        "#;
        assert!(Config::from_toml_str(text).is_ok());
    }

    #[test]
    fn omitted_mac_conflicts_with_any() {
        // An absent MAC filter matches any device, so it overlaps a specific one.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            mac = "00:00:00:00:00:01"

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Mdns,
                ..
            }
        ));
    }

    #[test]
    fn disjoint_address_families_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            address_family = "ipv4"

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            address_family = "ipv6"
        "#;
        assert!(Config::from_toml_str(text).is_ok());
    }

    #[test]
    fn overlapping_wol_ports_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [7, 9]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [9, 4000]
        "#;
        assert!(matches!(
            err(text),
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Wol,
                ..
            }
        ));
    }

    #[test]
    fn disjoint_wol_ports_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [7, 9]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            wol = true
            wol_ports = [4000]
        "#;
        assert!(Config::from_toml_str(text).is_ok());
    }
}
