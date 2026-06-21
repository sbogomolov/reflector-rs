//! Configuration error types.
//!
//! [`ConfigError`] is the module's public failure surface. [`ParseValueError`]
//! aggregates the per-value parse errors so a bad environment value stays
//! matchable while still naming the variable that carried it.

use std::fmt;

use thiserror::Error;

use super::value::{
    InterfaceName, ParseAddressFamilyError, ParseInterfaceNameError, ParseLogLevelError,
    ParseReflectorNameError, ReflectorName, WolPortsError,
};
use crate::net::mac::ParseMacAddrError;

/// Everything that can make a configuration invalid.
///
/// [`ConfigError::Parse`] carries value-level errors from the deserializer
/// (wrong type, bad port, unparseable enum/MAC); the remaining variants are the
/// cross-field and cross-reflector rules the deserializer cannot express.
#[derive(Debug, Error)]
pub(crate) enum ConfigError {
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
    #[error(
        "reflector \"{name}\" enables dial but the address family has no IPv4 (DIAL is IPv4-only)"
    )]
    DialRequiresIpv4 { name: ReflectorName },

    /// A reflector was defined by both the configuration file and the environment.
    #[error("reflector \"{name}\" is defined in both the configuration file and the environment")]
    DuplicateReflector { name: String },

    /// Two reflectors would reflect the same protocol's packets twice.
    #[error(
        "reflectors \"{first}\" and \"{second}\" both reflect {protocol} on {source_if} -> {target_if} with overlapping MAC selection and address family"
    )]
    ConflictingReflectors {
        protocol: Protocol,
        first: ReflectorName,
        second: ReflectorName,
        source_if: InterfaceName,
        target_if: InterfaceName,
    },

    /// An environment variable was not of the form `REFLECTOR_<tag>_<param>`.
    #[error("environment variable \"{var}\" is malformed (expected REFLECTOR_<tag>_<param>)")]
    EnvMalformedVar { var: String },

    /// An environment variable's reflector tag was empty or non-alphanumeric.
    #[error(
        "environment variable \"{var}\" has invalid tag \"{tag}\" (tags must be non-empty and alphanumeric)"
    )]
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

/// A required reflector field, named in [`ConfigError::EnvMissingField`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RequiredField {
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

/// A reflected discovery protocol, named in [`ConfigError::ConflictingReflectors`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Protocol {
    /// Wake-on-LAN.
    Wol,
    /// Multicast DNS.
    Mdns,
    /// Simple Service Discovery Protocol.
    Ssdp,
}

impl fmt::Display for Protocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Wol => "WoL",
            Self::Mdns => "mDNS",
            Self::Ssdp => "SSDP",
        })
    }
}

/// Any value-level parse failure an environment variable can carry.
///
/// Aggregating the per-type errors keeps [`ConfigError::EnvBadValue`] structured
/// (matchable in tests) while still attaching the originating variable name.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub(crate) enum ParseValueError {
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

/// Error returned when a string is not a recognized boolean.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected true, false, 1, or 0")]
pub(crate) struct ParseBoolError;
