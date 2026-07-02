//! Configuration loading and validation.
//!
//! TOML is deserialized into a raw form (`RawConfig`/`RawReflector`) and then
//! validated into the strongly-typed [`Config`]. Typed values make illegal states
//! unrepresentable ([`Wol::ports`] exists only when `WoL` is enabled;
//! [`InterfaceName`]/[`WolPorts`] can't be empty).
//!
//! Submodules: value types in `value`, errors in `error`, the serde layer in
//! `raw`, the environment parser in `env`. Each value type pairs `FromStr` with a
//! matching `Deserialize`, so one validation serves both the TOML path (serde,
//! located errors) and the environment path (`FromStr`, variable-named errors).
//! Cross-field and cross-reflector rules live in the `TryFrom` conversions here;
//! sources are combined in [`Config::from_sources`].
//!
//! Reflectors nest under `[reflectors.<name>]` rather than top-level tables to keep
//! the deserializer off `#[serde(flatten)]`, which would discard the line/column of
//! every value error.

mod env;
mod error;
mod raw;
mod value;

pub(crate) use self::error::{ConfigError, Protocol};
pub(crate) use self::value::{AddressFamily, InterfaceName, LogLevel, ReflectorName, WolPorts};

use std::str::FromStr;

use serde::Deserialize;

use self::raw::{RawConfig, RawReflector};
use crate::net::mac::MacSet;

/// Wake-on-LAN settings (present only when `WoL` is enabled for the reflector).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Wol {
    /// UDP destination ports whose magic packets are reflected.
    pub(crate) ports: WolPorts,
}

/// SSDP settings (present only when SSDP is enabled for the reflector).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ssdp {
    /// Whether the DIAL HTTP proxy is layered on top of SSDP.
    pub(crate) dial: bool,
}

/// One reflector: bridges `source_if` → `target_if` for the enabled protocols.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Reflector {
    /// Display name for logs, from the `[reflectors.<name>]` key or
    /// `REFLECTOR_<tag>_NAME`.
    pub(crate) name: ReflectorName,
    /// Interface to listen on.
    pub(crate) source_if: InterfaceName,
    /// Interface to emit on (always different from `source_if`).
    pub(crate) target_if: InterfaceName,
    /// Optional device allow-filter; `None` matches any device, `Some` a non-empty set.
    pub(crate) macs: Option<MacSet>,
    /// IP-version policy for this reflector.
    pub(crate) address_family: AddressFamily,
    /// Wake-on-LAN settings, or `None` when `WoL` is disabled.
    pub(crate) wol: Option<Wol>,
    pub(crate) mdns: bool,
    /// SSDP settings, or `None` when SSDP is disabled.
    pub(crate) ssdp: Option<Ssdp>,
}

impl Reflector {
    /// The protocol on which `self` and `other` would reflect the same packet
    /// twice, if any: same direction, overlapping MAC selection and address
    /// family, and a shared enabled protocol (for `WoL`, also a shared port).
    fn conflicts_with(&self, other: &Reflector) -> Option<Protocol> {
        if self.source_if != other.source_if || self.target_if != other.target_if {
            return None;
        }
        if !macs_overlap(self.macs.as_ref(), other.macs.as_ref())
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

impl TryFrom<(String, RawReflector)> for Reflector {
    type Error = ConfigError;

    fn try_from((key, raw): (String, RawReflector)) -> Result<Self, ConfigError> {
        // Env `NAME` override is already validated; the identity key (file table
        // key / env tag) is validated here.
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
            macs: raw.macs,
            address_family: raw.address_family,
            wol,
            mdns: raw.mdns,
            ssdp,
        })
    }
}

/// A fully-validated configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Config {
    /// Minimum severity to log.
    pub(crate) log_level: LogLevel,
    /// Whether to periodically log memory-footprint diagnostics.
    pub(crate) debug_memory: bool,
    pub(crate) reflectors: Vec<Reflector>,
}

impl Config {
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
    pub(crate) fn from_sources(
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

impl TryFrom<RawConfig> for Config {
    type Error = ConfigError;

    fn try_from(raw: RawConfig) -> Result<Self, ConfigError> {
        let mut reflectors = Vec::with_capacity(raw.reflectors.len());
        for (name, raw_reflector) in raw.reflectors {
            let reflector = Reflector::try_from((name, raw_reflector))?;
            log::debug!(
                "reflector {}: {} -> {} [{}] family={:?}",
                reflector.name,
                reflector.source_if,
                reflector.target_if,
                protocol_list(&reflector),
                reflector.address_family,
            );
            reflectors.push(reflector);
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

/// Reads only the top-level `log_level`, ignoring everything else (no
/// `deny_unknown_fields`), so [`resolve_log_level`] can extract the level without
/// validating the reflector tables.
#[derive(Deserialize)]
struct LogLevelProbe {
    #[serde(default)]
    log_level: Option<LogLevel>,
}

/// Read a configuration file, mapping I/O failure to [`ConfigError::ReadFile`].
pub(crate) fn read_config_file(path: &str) -> Result<String, ConfigError> {
    std::fs::read_to_string(path).map_err(|source| ConfigError::ReadFile {
        path: path.to_owned(),
        source,
    })
}

/// Resolve just the log level from the environment and TOML text, before the full
/// configuration is parsed — so the logger can be raised to the configured
/// verbosity and the rest of loading logged at that level. Environment overrides
/// the file, which overrides the default.
///
/// Deliberately lightweight: it reads only `REFLECTOR_LOG_LEVEL` and the file's
/// top-level `log_level`, never touching the reflector tables, so it can't fail
/// on a reflector error that should instead surface (logged) from the full parse.
///
/// # Errors
/// Returns [`ConfigError::Parse`] for malformed TOML, or [`ConfigError::EnvBadValue`]
/// if `REFLECTOR_LOG_LEVEL` is not a valid level.
pub(crate) fn resolve_log_level(
    toml_text: Option<&str>,
    env: &[(String, String)],
) -> Result<LogLevel, ConfigError> {
    if let Some(level) = env::log_level_from_env(env)? {
        return Ok(level);
    }
    if let Some(text) = toml_text {
        let probe: LogLevelProbe = toml::from_str(text)?;
        if let Some(level) = probe.log_level {
            return Ok(level);
        }
    }
    Ok(LogLevel::default())
}

/// The enabled protocols of `reflector` as a comma-separated summary — with
/// `WoL` ports and the SSDP DIAL flag — for logging.
fn protocol_list(reflector: &Reflector) -> String {
    let mut protocols: Vec<String> = Vec::new();
    if let Some(wol) = &reflector.wol {
        let ports: Vec<String> = wol.ports.iter().map(ToString::to_string).collect();
        protocols.push(format!("wol({})", ports.join(",")));
    }
    if reflector.mdns {
        protocols.push("mdns".to_owned());
    }
    if let Some(ssdp) = &reflector.ssdp {
        protocols.push(if ssdp.dial {
            "ssdp+dial".to_owned()
        } else {
            "ssdp".to_owned()
        });
    }
    protocols.join(", ")
}

/// Two MAC selections overlap when they share at least one address, or either is
/// absent (an absent filter matches any device).
fn macs_overlap(a: Option<&MacSet>, b: Option<&MacSet>) -> bool {
    match (a, b) {
        (Some(a), Some(b)) => a.iter().any(|mac| b.contains(mac)),
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
    log::debug!("no reflector conflicts");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_toml(text: &str) -> Result<Config, ConfigError> {
        Config::from_sources(Some(text), Vec::<(String, String)>::new())
    }

    fn err(text: &str) -> ConfigError {
        from_toml(text).unwrap_err()
    }

    #[test]
    fn minimal_reflector_uses_defaults() {
        let cfg = from_toml(
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
        assert!(r.macs.is_none());
        assert_eq!(r.address_family, AddressFamily::Default);
        assert!(r.wol.is_none());
        assert!(r.ssdp.is_none());
    }

    #[test]
    fn full_reflector_parses() {
        let cfg = from_toml(
            r#"
            log_level = "DEBUG"
            debug_memory = true

            [reflectors.tv]
            source_if = "en0"
            target_if = "lo0"
            macs = ["B0:37:95:C5:60:BE"]
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
        let macs = r.macs.as_ref().unwrap();
        assert_eq!(macs.len(), 1);
        assert_eq!(macs[0].to_string(), "b0:37:95:c5:60:be");
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
        let cfg = from_toml(
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
        let cfg = from_toml(
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
            macs = ["zz:zz:zz:zz:zz:zz"]
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
        assert!(from_toml(text).is_ok());
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
        assert!(from_toml(text).is_ok());
    }

    #[test]
    fn distinct_macs_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:02"]
        "#;
        assert!(from_toml(text).is_ok());
    }

    #[test]
    fn omitted_macs_conflicts_with_any() {
        // An absent MAC filter matches any device, so it overlaps a specific one.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01"]

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
    fn macs_list_parses() {
        let cfg = from_toml(
            r#"
            [reflectors.tv]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01", "00:00:00:00:00:02"]
            "#,
        )
        .unwrap();
        let macs = cfg.reflectors[0].macs.as_ref().unwrap();
        assert_eq!(macs.len(), 2);
        assert!(macs.contains(&"00:00:00:00:00:01".parse().unwrap()));
        assert!(macs.contains(&"00:00:00:00:00:02".parse().unwrap()));
    }

    #[test]
    fn legacy_mac_field_is_now_unknown() {
        // `mac` was replaced by `macs` in 0.9.0; deny_unknown_fields rejects the old key.
        let text = r#"
            [reflectors.tv]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            mac = "02:42:ac:11:00:09"
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn empty_macs_list_rejected() {
        let text = r#"
            [reflectors.tv]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = []
        "#;
        assert!(matches!(err(text), ConfigError::Parse(_)));
    }

    #[test]
    fn overlapping_macs_sets_conflict() {
        // The two allow-sets share 00:..:02, so both would reflect that device's mDNS.
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01", "00:00:00:00:00:02"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:02", "00:00:00:00:00:03"]
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
    fn disjoint_macs_sets_do_not_conflict() {
        let text = r#"
            [reflectors.a]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:01", "00:00:00:00:00:02"]

            [reflectors.b]
            source_if = "lan"
            target_if = "iot"
            mdns = true
            macs = ["00:00:00:00:00:03", "00:00:00:00:00:04"]
        "#;
        assert!(from_toml(text).is_ok());
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
        assert!(from_toml(text).is_ok());
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
        assert!(from_toml(text).is_ok());
    }
}
