//! The reflectors: per-protocol packet handlers that re-emit matched traffic on the opposite
//! interface. Each implements the dispatcher's `PacketHandler` and is registered by `run()`
//! from config. Wake-on-LAN is the first; mDNS and SSDP follow.

use std::fmt;
use std::net::SocketAddr;

use thiserror::Error;

use crate::config::AddressFamily;
use crate::dispatch::{CaptureKey, PacketDispatcher};
use crate::interface::InterfaceAddresses;

pub(crate) mod dial;
pub(crate) mod mdns;
pub(crate) mod ssdp;
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

/// Whether `egress` currently has a source address of `dst`'s family — what `send_udp_group` needs
/// to build the frame. The per-packet gate a reflector applies before re-emitting, so a family
/// whose address has gone away is dropped rather than mis-sent.
fn egress_sources(dispatcher: &PacketDispatcher, egress: CaptureKey, dst: SocketAddr) -> bool {
    dispatcher
        .egress_addrs(egress)
        .is_some_and(|addrs| match dst {
            SocketAddr::V4(_) => addrs.v4.is_some(),
            SocketAddr::V6(_) => addrs.v6.is_some(),
        })
}

/// The family `addrs` cannot source but `family` requires, if any — the startup check's verdict.
/// `None` means every required family is available (a v6-best-effort `Default` with no v6 passes).
fn missing_required_family(family: AddressFamily, addrs: &InterfaceAddresses) -> Option<IpFamily> {
    if family.requires_ipv4() && addrs.v4.is_none() {
        Some(IpFamily::V4)
    } else if family.requires_ipv6() && addrs.v6.is_none() {
        Some(IpFamily::V6)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use super::*;

    #[test]
    fn missing_required_family_enforces_the_requires_policy() {
        let none = InterfaceAddresses::default();
        let v4_only = InterfaceAddresses {
            v4: Some(Ipv4Addr::LOCALHOST),
            ..Default::default()
        };
        // Default requires v4 only: a v4-less egress fails on v4, a v6-less one passes.
        assert_eq!(
            missing_required_family(AddressFamily::Default, &none),
            Some(IpFamily::V4)
        );
        assert_eq!(
            missing_required_family(AddressFamily::Default, &v4_only),
            None
        );
        // Dual requires both: a v4-only egress still misses v6.
        assert_eq!(
            missing_required_family(AddressFamily::Dual, &v4_only),
            Some(IpFamily::V6)
        );
        // Ipv6 requires v6.
        assert_eq!(
            missing_required_family(AddressFamily::Ipv6, &v4_only),
            Some(IpFamily::V6)
        );
    }
}
