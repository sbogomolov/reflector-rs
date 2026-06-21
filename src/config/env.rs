//! Environment-variable configuration (`REFLECTOR_*`).
//!
//! [`parse_env`] turns the variables into the same [`RawConfig`] the TOML path
//! produces, so the validation downstream is shared. Each value is parsed through
//! its [`FromStr`] type, with failures tagged by the originating variable name.

use std::collections::BTreeMap;
use std::str::FromStr;

use super::error::{ConfigError, ParseBoolError, ParseValueError, RequiredField};
use super::raw::{RawConfig, RawReflector};
use super::value::{AddressFamily, InterfaceName, LogLevel, ReflectorName, WolPorts};
use crate::net::mac::MacAddr;

/// Accumulates a reflector's fields as its `REFLECTOR_<tag>_<param>` variables
/// are seen, then converts to a [`RawReflector`] once all are consumed.
#[derive(Debug, Default)]
struct PartialReflector {
    name: Option<ReflectorName>,
    source_if: Option<InterfaceName>,
    target_if: Option<InterfaceName>,
    mac: Option<MacAddr>,
    wol: Option<bool>,
    mdns: Option<bool>,
    ssdp: Option<bool>,
    dial: Option<bool>,
    wol_ports: Option<WolPorts>,
    address_family: Option<AddressFamily>,
}

impl PartialReflector {
    /// Route one lowercased `param` to its field, parsing `value`. `var` is the
    /// full variable name, used only to label errors.
    fn set(&mut self, param: &str, value: &str, var: &str) -> Result<(), ConfigError> {
        match param {
            "name" => self.name = Some(env_value(value, var)?),
            "source_if" => self.source_if = Some(env_value(value, var)?),
            "target_if" => self.target_if = Some(env_value(value, var)?),
            "mac" => self.mac = Some(env_value(value, var)?),
            "wol_ports" => self.wol_ports = Some(env_value(value, var)?),
            "address_family" => self.address_family = Some(env_value(value, var)?),
            "wol" => self.wol = Some(env_bool(value, var)?),
            "mdns" => self.mdns = Some(env_bool(value, var)?),
            "ssdp" => self.ssdp = Some(env_bool(value, var)?),
            "dial" => self.dial = Some(env_bool(value, var)?),
            _ => {
                return Err(ConfigError::EnvUnknownParam {
                    var: var.to_owned(),
                    param: param.to_owned(),
                });
            }
        }
        Ok(())
    }

    /// Finalize into a [`RawReflector`], requiring the two interface fields.
    fn into_raw(self, name: &str) -> Result<RawReflector, ConfigError> {
        Ok(RawReflector {
            name: self.name,
            source_if: self.source_if.ok_or_else(|| ConfigError::EnvMissingField {
                name: name.to_owned(),
                field: RequiredField::SourceIf,
            })?,
            target_if: self.target_if.ok_or_else(|| ConfigError::EnvMissingField {
                name: name.to_owned(),
                field: RequiredField::TargetIf,
            })?,
            mac: self.mac,
            wol: self.wol.unwrap_or(false),
            mdns: self.mdns.unwrap_or(false),
            ssdp: self.ssdp.unwrap_or(false),
            dial: self.dial.unwrap_or(false),
            wol_ports: self.wol_ports,
            address_family: self.address_family.unwrap_or_default(),
        })
    }
}

/// Parse `REFLECTOR_*` variables into the raw configuration they describe.
///
/// `REFLECTOR_LOG_LEVEL` and `REFLECTOR_DEBUG_MEMORY` set the globals; every other
/// `REFLECTOR_<tag>_<param>` contributes to the reflector keyed by the lowercased
/// `tag`. Variables without the prefix are ignored.
pub(super) fn parse_env(
    vars: impl IntoIterator<Item = (String, String)>,
) -> Result<RawConfig, ConfigError> {
    let mut log_level = None;
    let mut debug_memory = None;
    let mut partials: BTreeMap<String, PartialReflector> = BTreeMap::new();

    for (key, value) in vars {
        let Some(rest) = key.strip_prefix("REFLECTOR_") else {
            continue;
        };
        match rest {
            "LOG_LEVEL" => {
                log::trace!("env {key} = {value}");
                log_level = Some(env_value(&value, &key)?);
                continue;
            }
            "DEBUG_MEMORY" => {
                log::trace!("env {key} = {value}");
                debug_memory = Some(env_bool(&value, &key)?);
                continue;
            }
            _ => {}
        }

        let (tag, param) = rest
            .split_once('_')
            .ok_or_else(|| ConfigError::EnvMalformedVar { var: key.clone() })?;
        if tag.is_empty() || !tag.bytes().all(|b| b.is_ascii_alphanumeric()) {
            return Err(ConfigError::EnvInvalidTag {
                var: key.clone(),
                tag: tag.to_owned(),
            });
        }
        let tag = tag.to_ascii_lowercase();
        if tag == "log" || tag == "debug" {
            return Err(ConfigError::EnvReservedTag { var: key.clone() });
        }
        let param = param.to_ascii_lowercase();
        log::trace!("env {key}: reflector {tag} {param} = {value}");
        partials.entry(tag).or_default().set(&param, &value, &key)?;
    }

    let mut reflectors = BTreeMap::new();
    for (name, partial) in partials {
        let raw = partial.into_raw(&name)?;
        reflectors.insert(name, raw);
    }
    Ok(RawConfig {
        log_level,
        debug_memory,
        reflectors,
    })
}

/// Resolve `REFLECTOR_LOG_LEVEL` alone, ignoring the rest of the environment.
///
/// Used to raise the logger to the configured verbosity *before* the full parse
/// runs, so that parse (env merge, reflector build) can be logged at that level.
pub(super) fn log_level_from_env(
    vars: &[(String, String)],
) -> Result<Option<LogLevel>, ConfigError> {
    vars.iter()
        .find(|(key, _)| key == "REFLECTOR_LOG_LEVEL")
        .map(|(key, value)| env_value::<LogLevel>(value, key))
        .transpose()
}

/// Parse an environment value through its `FromStr` type, tagging a failure with
/// the originating variable name.
fn env_value<T>(value: &str, var: &str) -> Result<T, ConfigError>
where
    T: FromStr,
    T::Err: Into<ParseValueError>,
{
    value.parse::<T>().map_err(|e| ConfigError::EnvBadValue {
        var: var.to_owned(),
        value: value.to_owned(),
        source: e.into(),
    })
}

/// Parse a boolean environment value (`true`/`false`/`1`/`0`, case-insensitive).
fn env_bool(value: &str, var: &str) -> Result<bool, ConfigError> {
    let parsed = match value.to_ascii_lowercase().as_str() {
        "true" | "1" => true,
        "false" | "0" => false,
        _ => {
            return Err(ConfigError::EnvBadValue {
                var: var.to_owned(),
                value: value.to_owned(),
                source: ParseBoolError.into(),
            });
        }
    };
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use crate::config::error::{ParseValueError, RequiredField};
    use crate::config::{Config, ConfigError, LogLevel, Protocol};

    fn env(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
        pairs
            .iter()
            .map(|&(k, v)| (k.to_owned(), v.to_owned()))
            .collect()
    }

    fn from_env(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        Config::from_sources(None, env(pairs))
    }

    #[test]
    fn env_only_minimal_reflector() {
        let cfg = from_env(&[
            ("REFLECTOR_TV_SOURCE_IF", "lan"),
            ("REFLECTOR_TV_TARGET_IF", "iot"),
            ("REFLECTOR_TV_MDNS", "true"),
            ("PATH", "/usr/bin"), // non-REFLECTOR vars are ignored
        ])
        .unwrap();
        assert_eq!(cfg.reflectors.len(), 1);
        let r = &cfg.reflectors[0];
        assert_eq!(r.name.as_str(), "tv");
        assert_eq!(r.source_if.as_str(), "lan");
        assert_eq!(r.target_if.as_str(), "iot");
        assert!(r.mdns);
    }

    #[test]
    fn env_globals_and_bool_forms() {
        let cfg = from_env(&[
            ("REFLECTOR_LOG_LEVEL", "debug"),
            ("REFLECTOR_DEBUG_MEMORY", "1"),
            ("REFLECTOR_TV_SOURCE_IF", "a"),
            ("REFLECTOR_TV_TARGET_IF", "b"),
            ("REFLECTOR_TV_WOL", "1"),
            ("REFLECTOR_TV_MDNS", "false"),
        ])
        .unwrap();
        assert_eq!(cfg.log_level, LogLevel::Debug);
        assert!(cfg.debug_memory);
        let r = &cfg.reflectors[0];
        assert!(r.wol.is_some());
        assert!(!r.mdns);
    }

    #[test]
    fn env_name_overrides_label_not_key() {
        let cfg = from_env(&[
            ("REFLECTOR_TV_SOURCE_IF", "a"),
            ("REFLECTOR_TV_TARGET_IF", "b"),
            ("REFLECTOR_TV_MDNS", "true"),
            ("REFLECTOR_TV_NAME", "Living Room"),
        ])
        .unwrap();
        assert_eq!(cfg.reflectors[0].name.as_str(), "Living Room");
    }

    #[test]
    fn env_wol_ports_csv() {
        let cfg = from_env(&[
            ("REFLECTOR_TV_SOURCE_IF", "a"),
            ("REFLECTOR_TV_TARGET_IF", "b"),
            ("REFLECTOR_TV_WOL", "true"),
            ("REFLECTOR_TV_WOL_PORTS", "7, 9, 4000"),
        ])
        .unwrap();
        let ports: Vec<u16> = cfg.reflectors[0]
            .wol
            .as_ref()
            .unwrap()
            .ports
            .iter()
            .map(|p| p.get())
            .collect();
        assert_eq!(ports, [7, 9, 4000]);
    }

    #[test]
    fn env_reuses_cross_field_validation() {
        let e = from_env(&[
            ("REFLECTOR_TV_SOURCE_IF", "a"),
            ("REFLECTOR_TV_TARGET_IF", "a"),
            ("REFLECTOR_TV_MDNS", "true"),
        ])
        .unwrap_err();
        assert!(matches!(e, ConfigError::SameInterface { value, .. } if value.as_str() == "a"));
    }

    #[test]
    fn env_overrides_file_globals() {
        let toml = r#"
            log_level = "info"
            [reflectors.tv]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        let cfg =
            Config::from_sources(Some(toml), env(&[("REFLECTOR_LOG_LEVEL", "error")])).unwrap();
        assert_eq!(cfg.log_level, LogLevel::Error);
    }

    #[test]
    fn env_adds_reflector_alongside_file() {
        let toml = r#"
            [reflectors.tv]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        let cfg = Config::from_sources(
            Some(toml),
            env(&[
                ("REFLECTOR_RADIO_SOURCE_IF", "c"),
                ("REFLECTOR_RADIO_TARGET_IF", "d"),
                ("REFLECTOR_RADIO_MDNS", "true"),
            ]),
        )
        .unwrap();
        let mut names: Vec<&str> = cfg.reflectors.iter().map(|r| r.name.as_str()).collect();
        names.sort_unstable();
        assert_eq!(names, ["radio", "tv"]);
    }

    #[test]
    fn duplicate_reflector_across_sources_rejected() {
        let toml = r#"
            [reflectors.tv]
            source_if = "a"
            target_if = "b"
            mdns = true
        "#;
        // Lowercased env tag "TV" collides with file key "tv".
        let e = Config::from_sources(
            Some(toml),
            env(&[
                ("REFLECTOR_TV_SOURCE_IF", "c"),
                ("REFLECTOR_TV_TARGET_IF", "d"),
                ("REFLECTOR_TV_MDNS", "true"),
            ]),
        )
        .unwrap_err();
        assert!(matches!(e, ConfigError::DuplicateReflector { name } if name == "tv"));
    }

    #[test]
    fn env_malformed_var_rejected() {
        // No underscore to split into <tag>_<param>.
        assert!(matches!(
            from_env(&[("REFLECTOR_TV", "x")]).unwrap_err(),
            ConfigError::EnvMalformedVar { .. }
        ));
    }

    #[test]
    fn env_invalid_tag_rejected() {
        // Empty tag.
        assert!(matches!(
            from_env(&[("REFLECTOR__SOURCE_IF", "x")]).unwrap_err(),
            ConfigError::EnvInvalidTag { .. }
        ));
        // Non-alphanumeric tag.
        assert!(matches!(
            from_env(&[("REFLECTOR_T-V_SOURCE_IF", "x")]).unwrap_err(),
            ConfigError::EnvInvalidTag { tag, .. } if tag == "T-V"
        ));
    }

    #[test]
    fn env_reserved_tag_rejected() {
        assert!(matches!(
            from_env(&[("REFLECTOR_LOG_SOMETHING", "x")]).unwrap_err(),
            ConfigError::EnvReservedTag { .. }
        ));
    }

    #[test]
    fn env_unknown_param_rejected() {
        assert!(matches!(
            from_env(&[
                ("REFLECTOR_TV_SOURCE_IF", "a"),
                ("REFLECTOR_TV_BOGUS", "1"),
            ])
            .unwrap_err(),
            ConfigError::EnvUnknownParam { param, .. } if param == "bogus"
        ));
    }

    #[test]
    fn env_bad_value_is_structured() {
        assert!(matches!(
            from_env(&[
                ("REFLECTOR_TV_SOURCE_IF", ""),
                ("REFLECTOR_TV_TARGET_IF", "b"),
                ("REFLECTOR_TV_MDNS", "true"),
            ])
            .unwrap_err(),
            ConfigError::EnvBadValue {
                source: ParseValueError::Interface(_),
                ..
            }
        ));
        assert!(matches!(
            from_env(&[("REFLECTOR_TV_MAC", "zz")]).unwrap_err(),
            ConfigError::EnvBadValue {
                source: ParseValueError::Mac(_),
                ..
            }
        ));
        assert!(matches!(
            from_env(&[("REFLECTOR_TV_WOL", "maybe")]).unwrap_err(),
            ConfigError::EnvBadValue {
                value,
                source: ParseValueError::Bool(_),
                ..
            } if value == "maybe"
        ));
    }

    #[test]
    fn env_reflector_missing_required_field() {
        assert!(matches!(
            from_env(&[
                ("REFLECTOR_TV_TARGET_IF", "b"),
                ("REFLECTOR_TV_MDNS", "true"),
            ])
            .unwrap_err(),
            ConfigError::EnvMissingField {
                field: RequiredField::SourceIf,
                ..
            }
        ));
    }

    #[test]
    fn env_only_no_reflectors_rejected() {
        assert!(matches!(
            Config::from_sources(None, env(&[("REFLECTOR_LOG_LEVEL", "info")])).unwrap_err(),
            ConfigError::NoReflectors
        ));
    }

    #[test]
    fn env_name_is_trimmed() {
        let cfg = from_env(&[
            ("REFLECTOR_TV_SOURCE_IF", "a"),
            ("REFLECTOR_TV_TARGET_IF", "b"),
            ("REFLECTOR_TV_MDNS", "true"),
            ("REFLECTOR_TV_NAME", "  Living Room  "),
        ])
        .unwrap();
        assert_eq!(cfg.reflectors[0].name.as_str(), "Living Room");
    }

    #[test]
    fn conflict_detected_across_sources() {
        let toml = r#"
            [reflectors.tv]
            source_if = "lan"
            target_if = "iot"
            mdns = true
        "#;
        // Env reflector "radio" bridges the same interfaces with mDNS.
        let e = Config::from_sources(
            Some(toml),
            env(&[
                ("REFLECTOR_RADIO_SOURCE_IF", "lan"),
                ("REFLECTOR_RADIO_TARGET_IF", "iot"),
                ("REFLECTOR_RADIO_MDNS", "true"),
            ]),
        )
        .unwrap_err();
        assert!(matches!(
            e,
            ConfigError::ConflictingReflectors {
                protocol: Protocol::Mdns,
                ..
            }
        ));
    }

    #[test]
    fn env_whitespace_name_rejected() {
        assert!(matches!(
            from_env(&[
                ("REFLECTOR_TV_SOURCE_IF", "a"),
                ("REFLECTOR_TV_TARGET_IF", "b"),
                ("REFLECTOR_TV_MDNS", "true"),
                ("REFLECTOR_TV_NAME", "   "),
            ])
            .unwrap_err(),
            ConfigError::EnvBadValue {
                source: ParseValueError::ReflectorName(_),
                ..
            }
        ));
    }
}
