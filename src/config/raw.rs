//! The raw, deserialized configuration, before validation.
//!
//! TOML deserializes into [`RawConfig`]/[`RawReflector`]; the environment layer
//! produces the same shape. [`RawConfig::merge_env`] overlays the environment
//! layer onto the file layer before the whole thing is validated into the typed
//! model.

use std::collections::BTreeMap;

use serde::Deserialize;

use super::error::ConfigError;
use super::value::{AddressFamily, InterfaceName, LogLevel, ReflectorName, WolPorts};
use crate::net::mac::MacSet;

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawConfig {
    pub(super) log_level: Option<LogLevel>,
    pub(super) debug_memory: Option<bool>,
    #[serde(default)]
    pub(super) reflectors: BTreeMap<String, RawReflector>,
}

#[expect(
    clippy::struct_excessive_bools,
    reason = "independent toggles, not a state machine"
)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RawReflector {
    /// Display name; set only by the environment layer (`REFLECTOR_<tag>_NAME`).
    /// File reflectors take their name from the `[reflectors.<name>]` table key.
    #[serde(skip)]
    pub(super) name: Option<ReflectorName>,
    pub(super) source_if: InterfaceName,
    pub(super) target_if: InterfaceName,
    pub(super) macs: Option<MacSet>,
    #[serde(default)]
    pub(super) wol: bool,
    #[serde(default)]
    pub(super) mdns: bool,
    #[serde(default)]
    pub(super) ssdp: bool,
    #[serde(default)]
    pub(super) dial: bool,
    pub(super) wol_ports: Option<WolPorts>,
    #[serde(default)]
    pub(super) address_family: AddressFamily,
}

impl RawConfig {
    /// Overlay environment-derived settings: env globals win, env reflectors are
    /// added, and a reflector named by both sources is rejected.
    pub(super) fn merge_env(&mut self, env: RawConfig) -> Result<(), ConfigError> {
        self.log_level = env.log_level.or(self.log_level);
        self.debug_memory = env.debug_memory.or(self.debug_memory);
        for (name, reflector) in env.reflectors {
            // Compare folded: an env tag is already lowercase and unpadded, but a TOML table key is
            // stored verbatim, so `[reflectors.TV]` (or `"  tv  "`) and env `REFLECTOR_TV_*` name the
            // same reflector and must collide rather than silently produce two.
            if self
                .reflectors
                .keys()
                .any(|k| k.trim().eq_ignore_ascii_case(&name))
            {
                return Err(ConfigError::DuplicateReflector { name });
            }
            self.reflectors.insert(name, reflector);
        }
        Ok(())
    }
}
