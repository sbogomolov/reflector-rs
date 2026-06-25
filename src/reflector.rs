//! The reflectors: per-protocol packet handlers that re-emit matched traffic on the opposite
//! interface. Each implements the dispatcher's `PacketHandler` and is registered by `run()`
//! from config. Wake-on-LAN is the first; mDNS and SSDP follow.

use std::fmt;

use thiserror::Error;

use crate::dispatch::CaptureKey;

pub(crate) mod wol;

/// A concrete IP version — the family a reflector requires of an interface. Distinct from the
/// config's `AddressFamily` policy (which may name both at once).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum IpFamily {
    V4,
    V6,
}

impl fmt::Display for IpFamily {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::V4 => "IPv4",
            Self::V6 => "IPv6",
        })
    }
}

/// Maps each configured interface name to the capture `run()` opened for it, so a reflector's
/// `source_if` / `target_if` resolve to the ingress / egress [`CaptureKey`]s. `run()` opens one
/// capture per distinct interface and records it here; the per-protocol `build` functions look
/// names up. A plain `Vec` — only ever a handful of interfaces.
#[derive(Default)]
pub(crate) struct InterfaceMap(Vec<(String, CaptureKey)>);

impl InterfaceMap {
    /// Record the capture `run()` opened for `name`.
    pub(crate) fn insert(&mut self, name: String, key: CaptureKey) {
        self.0.push((name, key));
    }

    /// The capture key recorded for `name`, or `None` if none was.
    pub(crate) fn key_for(&self, name: &str) -> Option<CaptureKey> {
        self.0.iter().find(|(n, _)| n == name).map(|&(_, key)| key)
    }
}

/// Why a reflector could not be built from its config.
#[derive(Debug, Error, PartialEq, Eq)]
pub(crate) enum BuildError {
    /// Names a `source_if` / `target_if` that `run()` opened no capture for — a wiring bug.
    #[error("no capture for interface \"{0}\"")]
    UnknownInterface(String),
    /// The target interface can't currently send a family the reflector requires, so it would
    /// reflect nothing for that family — a startup failure rather than a silent half-run.
    #[error("target interface \"{interface}\" cannot send {family}, required by the reflector")]
    RequiredFamilyUnavailable { interface: String, family: IpFamily },
}
