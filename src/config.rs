//! Configuration loading and validation.
//!
//! TOML is deserialized into a raw form ([`RawConfig`]/[`RawReflector`]) and then
//! validated into the strongly-typed [`Config`] the rest of the program uses. The
//! typed values make illegal states unrepresentable (for example, [`Wol::ports`]
//! exists only when `WoL` is enabled, and [`InterfaceName`]/[`WolPorts`] can't be
//! empty).
//!
//! Each value type is a `FromStr` type with a matching `Deserialize`, so the same
//! validation serves both the TOML path (via serde, with located errors) and the
//! environment path (via `FromStr`, with variable-named errors). Cross-field and
//! cross-reflector rules live in the `TryFrom` conversions, and file and
//! environment settings are combined in [`Config::from_sources`].
//!
//! Reflectors are nested under a `reflectors` table (`[reflectors.<name>]`)
//! rather than top-level tables: this keeps the deserializer off
//! `#[serde(flatten)]`, which would otherwise discard the line/column of every
//! value error.

use std::collections::BTreeMap;
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
        raw.merge_env(parse_env(env)?)?;
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

    /// A reflector's name (file table key) was empty or whitespace-only.
    #[error("reflector name \"{key}\" is empty or whitespace-only")]
    EmptyReflectorName { key: String },

    /// `source_if` and `target_if` were the same interface.
    #[error("reflector \"{name}\" source_if and target_if must differ (both are \"{value}\")")]
    SameInterface {
        name: ReflectorName,
        value: InterfaceName,
    },

    /// The reflector enabled none of `WoL`, mDNS, or SSDP.
    #[error("reflector \"{name}\" enables no protocol (set wol, mdns, or ssdp)")]
    NoProtocol { name: ReflectorName },

    /// `wol_ports` was set without enabling `WoL`.
    #[error("reflector \"{name}\" sets wol_ports but does not enable wol")]
    WolPortsWithoutWol { name: ReflectorName },

    /// `dial` was set without enabling SSDP.
    #[error("reflector \"{name}\" sets dial but does not enable ssdp")]
    DialWithoutSsdp { name: ReflectorName },

    /// `dial` was enabled but the address family excludes IPv4.
    #[error("reflector \"{name}\" enables dial but the address family has no IPv4 (DIAL is IPv4-only)")]
    DialRequiresIpv4 { name: ReflectorName },

    /// A reflector was defined by both the configuration file and the environment.
    #[error("reflector \"{name}\" is defined in both the configuration file and the environment")]
    DuplicateReflector { name: String },

    /// An environment variable was not of the form `REFLECTOR_<tag>_<param>`.
    #[error("environment variable \"{var}\" is malformed (expected REFLECTOR_<tag>_<param>)")]
    EnvMalformedVar { var: String },

    /// An environment variable's reflector tag was empty or non-alphanumeric.
    #[error("environment variable \"{var}\" has invalid tag \"{tag}\" (tags must be non-empty and alphanumeric)")]
    EnvInvalidTag { var: String, tag: String },

    /// An environment variable used a reserved tag (`LOG` and `DEBUG` name globals).
    #[error("environment variable \"{var}\" uses a reserved tag (log and debug are globals)")]
    EnvReservedTag { var: String },

    /// An environment variable named a parameter no reflector has.
    #[error("environment variable \"{var}\" sets unknown parameter \"{param}\"")]
    EnvUnknownParam { var: String, param: String },

    /// An environment value could not be parsed.
    #[error("environment variable \"{var}\" has invalid value \"{value}\": {source}")]
    EnvBadValue {
        var: String,
        value: String,
        source: ParseValueError,
    },

    /// An environment-defined reflector is missing a required field.
    #[error("reflector \"{name}\" (from the environment) has no {field}")]
    EnvMissingField { name: String, field: RequiredField },
}

// ----- raw (serde) layer ---------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    log_level: Option<LogLevel>,
    debug_memory: Option<bool>,
    #[serde(default)]
    reflectors: BTreeMap<String, RawReflector>,
}

#[expect(clippy::struct_excessive_bools, reason = "independent toggles, not a state machine")]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawReflector {
    /// Display name; set only by the environment layer (`REFLECTOR_<tag>_NAME`).
    /// File reflectors take their name from the `[reflectors.<name>]` table key.
    #[serde(skip)]
    name: Option<ReflectorName>,
    source_if: InterfaceName,
    target_if: InterfaceName,
    mac: Option<MacAddr>,
    #[serde(default)]
    wol: bool,
    #[serde(default)]
    mdns: bool,
    #[serde(default)]
    ssdp: bool,
    #[serde(default)]
    dial: bool,
    wol_ports: Option<WolPorts>,
    #[serde(default)]
    address_family: AddressFamily,
}

// ----- raw -> validated ----------------------------------------------------

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

// ----- environment layer ---------------------------------------------------

/// A required reflector field, named in [`ConfigError::EnvMissingField`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequiredField {
    /// The listen interface (`source_if`).
    SourceIf,
    /// The emit interface (`target_if`).
    TargetIf,
}

impl fmt::Display for RequiredField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SourceIf => "source_if",
            Self::TargetIf => "target_if",
        })
    }
}

/// Error returned when a string is not a recognized boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected true, false, 1, or 0")]
pub struct ParseBoolError;

/// Any value-level parse failure an environment variable can carry.
///
/// Aggregating the per-type errors keeps [`ConfigError::EnvBadValue`] structured
/// (matchable in tests) while still attaching the originating variable name.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ParseValueError {
    /// A `LOG_LEVEL` value was not a valid log level.
    #[error(transparent)]
    LogLevel(#[from] ParseLogLevelError),
    /// An `ADDRESS_FAMILY` value was not a valid address family.
    #[error(transparent)]
    AddressFamily(#[from] ParseAddressFamilyError),
    /// A `MAC` value was not a valid MAC address.
    #[error(transparent)]
    Mac(#[from] ParseMacAddrError),
    /// A `SOURCE_IF`/`TARGET_IF` value was not a valid interface name.
    #[error(transparent)]
    Interface(#[from] ParseInterfaceNameError),
    /// A `WOL_PORTS` value was not a valid port list.
    #[error(transparent)]
    WolPorts(#[from] WolPortsError),
    /// A `NAME` value was empty or whitespace-only.
    #[error(transparent)]
    ReflectorName(#[from] ParseReflectorNameError),
    /// A boolean value was not `true`/`false`/`1`/`0`.
    #[error(transparent)]
    Bool(#[from] ParseBoolError),
}

impl RawConfig {
    /// Overlay environment-derived settings: env globals win, env reflectors are
    /// added, and a reflector named by both sources is rejected.
    fn merge_env(&mut self, env: RawConfig) -> Result<(), ConfigError> {
        self.log_level = env.log_level.or(self.log_level);
        self.debug_memory = env.debug_memory.or(self.debug_memory);
        for (name, reflector) in env.reflectors {
            if self.reflectors.contains_key(&name) {
                return Err(ConfigError::DuplicateReflector { name });
            }
            self.reflectors.insert(name, reflector);
        }
        Ok(())
    }
}

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
fn parse_env(vars: impl IntoIterator<Item = (String, String)>) -> Result<RawConfig, ConfigError> {
    let mut log_level = None;
    let mut debug_memory = None;
    let mut partials: BTreeMap<String, PartialReflector> = BTreeMap::new();

    for (key, value) in vars {
        let Some(rest) = key.strip_prefix("REFLECTOR_") else {
            continue;
        };
        match rest {
            "LOG_LEVEL" => {
                log_level = Some(env_value(&value, &key)?);
                continue;
            }
            "DEBUG_MEMORY" => {
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
        partials
            .entry(tag)
            .or_default()
            .set(&param.to_ascii_lowercase(), &value, &key)?;
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
    fn interface_name_parses_via_fromstr() {
        assert_eq!("en0".parse::<InterfaceName>().unwrap().as_str(), "en0");
        assert_eq!("".parse::<InterfaceName>(), Err(ParseInterfaceNameError));
    }

    #[test]
    fn wol_ports_parse_via_fromstr() {
        let ports = "7, 9, 4000".parse::<WolPorts>().unwrap();
        assert_eq!(ports.iter().map(|p| p.get()).collect::<Vec<_>>(), [7, 9, 4000]);
        assert!(matches!("7,7".parse::<WolPorts>(), Err(WolPortsError::Duplicate(7))));
        assert!(matches!("0".parse::<WolPorts>(), Err(WolPortsError::BadPort(_))));
        assert!(matches!("abc".parse::<WolPorts>(), Err(WolPortsError::BadPort(_))));
        assert_eq!(WolPorts::default().iter().map(|p| p.get()).collect::<Vec<_>>(), [7, 9]);
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

    // ----- environment layer -----

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

    #[test]
    fn reflector_name_parses_via_fromstr() {
        assert_eq!("  tv  ".parse::<ReflectorName>().unwrap().as_str(), "tv");
        assert_eq!("".parse::<ReflectorName>(), Err(ParseReflectorNameError));
        assert_eq!("   ".parse::<ReflectorName>(), Err(ParseReflectorNameError));
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
}
