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
use crate::net::mac::MacSetError;

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

    #[error("cannot read config file \"{path}\": {source}")]
    ReadFile {
        path: String,
        source: std::io::Error,
    },

    #[error("must define at least one reflector")]
    NoReflectors,

    /// key is the file table key, not a validated [`ReflectorName`].
    #[error("reflector name \"{key}\" is empty or whitespace-only")]
    EmptyReflectorName { key: String },

    #[error("reflector \"{name}\" source_if and target_if must differ (both are \"{value}\")")]
    SameInterface {
        name: ReflectorName,
        value: InterfaceName,
    },

    #[error("reflector \"{name}\" enables no protocol (set wol, mdns, or ssdp)")]
    NoProtocol { name: ReflectorName },

    #[error("reflector \"{name}\" sets wol_ports but does not enable wol")]
    WolPortsWithoutWol { name: ReflectorName },

    #[error("reflector \"{name}\" sets dial but does not enable ssdp")]
    DialWithoutSsdp { name: ReflectorName },

    #[error(
        "reflector \"{name}\" enables dial but the address family has no IPv4 (DIAL is IPv4-only)"
    )]
    DialRequiresIpv4 { name: ReflectorName },

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

    #[error("environment variable \"{var}\" is malformed (expected REFLECTOR_<tag>_<param>)")]
    EnvMalformedVar { var: String },

    #[error(
        "environment variable \"{var}\" has invalid tag \"{tag}\" (tags must be non-empty and alphanumeric)"
    )]
    EnvInvalidTag { var: String, tag: String },

    #[error("environment variable \"{var}\" uses a reserved tag (log and debug are globals)")]
    EnvReservedTag { var: String },

    #[error("environment variable \"{var}\" sets unknown parameter \"{param}\"")]
    EnvUnknownParam { var: String, param: String },

    #[error("environment variable \"{var}\" has invalid value \"{value}\": {source}")]
    EnvBadValue {
        var: String,
        value: String,
        source: ParseValueError,
    },

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
    Wol,
    Mdns,
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
    /// `LOG_LEVEL`.
    #[error(transparent)]
    LogLevel(#[from] ParseLogLevelError),
    /// `ADDRESS_FAMILY`.
    #[error(transparent)]
    AddressFamily(#[from] ParseAddressFamilyError),
    /// `MACS`.
    #[error(transparent)]
    Macs(#[from] MacSetError),
    /// `SOURCE_IF`/`TARGET_IF`.
    #[error(transparent)]
    Interface(#[from] ParseInterfaceNameError),
    /// `WOL_PORTS`.
    #[error(transparent)]
    WolPorts(#[from] WolPortsError),
    /// `NAME`.
    #[error(transparent)]
    ReflectorName(#[from] ParseReflectorNameError),
    #[error(transparent)]
    Bool(#[from] ParseBoolError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("expected true, false, 1, or 0")]
pub(crate) struct ParseBoolError;
