//! Interface address resolution: the source MAC / IPv4 / IPv6 an interface currently has.
//! A reflector re-emits from these, so they must be read fresh (the address monitor keeps
//! them current). Any may be absent — a loopback / `DLT_NULL` link has no MAC, and a link
//! may be v4-only or v6-only.
//!
//! Resolution lives on [`Interface`] (built by [`open`](Interface::open), kept current by
//! [`refresh`](Interface::refresh)), dispatching to one backend per platform: pure rtnetlink
//! on Linux (one `RTM_GETADDR` dump for the addresses, one `RTM_GETLINK` for the MAC),
//! `getifaddrs` plus `SIOCGIFAFLAG_IN6` on the BSDs. Each yields the same
//! [`InterfaceAddresses`].

use std::fmt;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};

use crate::net::mac::MacAddr;

mod address_monitor;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod getifaddrs;
#[cfg(target_os = "linux")]
mod rtnetlink;

pub(crate) use self::address_monitor::AddressMonitor;

/// An interface's current source addresses; any may be absent.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct InterfaceAddresses {
    pub(crate) mac: Option<MacAddr>,
    pub(crate) v4: Option<Ipv4Addr>,
    pub(crate) v6: Option<Ipv6Addr>,
}

impl fmt::Display for InterfaceAddresses {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mac ")?;
        match self.mac {
            Some(mac) => write!(f, "{mac}")?,
            None => f.write_str("none")?,
        }
        f.write_str(", v4 ")?;
        match self.v4 {
            Some(v4) => write!(f, "{v4}")?,
            None => f.write_str("none")?,
        }
        f.write_str(", v6 ")?;
        match self.v6 {
            Some(v6) => write!(f, "{v6}"),
            None => f.write_str("none"),
        }
    }
}

/// Which source fields a [`refresh`](Interface::refresh) found changed — one flag per
/// [`InterfaceAddresses`] field, so a caller reacts only to the family it depends on (the DIAL proxies
/// bind IPv4, so they re-mint only when `v4` moves, not on a routine v6 or MAC change).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct AddressChange {
    pub(crate) mac: bool,
    pub(crate) v4: bool,
    pub(crate) v6: bool,
}

/// One configured interface: its name (kept for re-resolution), kernel ifindex (the address
/// monitor's lookup key), and current source addresses. Built by [`open`](Self::open); the
/// monitor later refreshes `addrs` in place.
pub(crate) struct Interface {
    pub(crate) name: String,
    pub(crate) ifindex: u32,
    pub(crate) addrs: InterfaceAddresses,
}

impl Interface {
    /// Build an interface record: cache `name`'s kernel ifindex (0 if unknown — never matches
    /// a real event), then [`refresh`](Self::refresh) its current source addresses.
    ///
    /// # Errors
    /// Propagates a resolution syscall failure.
    pub(crate) fn open(name: &str) -> io::Result<Self> {
        let mut iface = Self {
            name: name.to_owned(),
            ifindex: if_index(name).unwrap_or(0),
            addrs: InterfaceAddresses::default(),
        };
        iface.refresh()?;
        Ok(iface)
    }

    /// Re-resolve this interface's addresses in place (at open, and after an address-change
    /// notification) via the platform backend. The cached `ifindex` — a stable identity for
    /// the interface's lifetime — keys the Linux dump; the BSD `getifaddrs` walk matches by
    /// name. The backend logs each address (and every v6's flag status) at `trace`. Returns which
    /// source fields changed from the previous resolution, so a caller can react to exactly the
    /// family it depends on.
    ///
    /// # Errors
    /// Propagates a resolution syscall failure.
    pub(crate) fn refresh(&mut self) -> io::Result<AddressChange> {
        #[cfg(any(target_os = "macos", target_os = "freebsd"))]
        let addrs = self::getifaddrs::resolve(&self.name)?;
        #[cfg(target_os = "linux")]
        let addrs = self::rtnetlink::resolve(&self.name, self.ifindex)?;
        log::debug!("{}: resolved {addrs}", self.name);
        let change = AddressChange {
            mac: log_field_change(&self.name, "MAC", self.addrs.mac, addrs.mac),
            v4: log_field_change(&self.name, "IPv4", self.addrs.v4, addrs.v4),
            v6: log_field_change(&self.name, "IPv6", self.addrs.v6, addrs.v6),
        };
        self.addrs = addrs;
        Ok(change)
    }
}

/// The kernel ifindex of `name`, or `None` if it names no interface (a NUL in the name, or
/// an unknown name). Address-change events report an ifindex; an [`Interface`] caches its
/// own so a notification maps back to it.
pub(crate) fn if_index(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: `cname` is a valid NUL-terminated C string for the call's duration.
    let index = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    (index != 0).then_some(index)
}

/// Log a single source field's transition at `info` — the address churn an operator (and the
/// address-change e2e) wants visible — returning whether it changed at all, so the caller acts on
/// exactly the families that moved. Nothing is logged when the field is unchanged.
fn log_field_change<A: PartialEq + fmt::Display>(
    iface: &str,
    family: &str,
    old: Option<A>,
    new: Option<A>,
) -> bool {
    match (old, new) {
        (None, Some(now)) => log::info!("interface {iface}: gained {family} {now}"),
        (Some(was), None) => log::info!("interface {iface}: lost {family} (was {was})"),
        (Some(was), Some(now)) if was != now => {
            log::info!("interface {iface}: {family} changed {was} -> {now}");
        }
        _ => return false,
    }
    true
}

/// Rank an IPv6 source candidate: link-local > ULA > global > other. The reflector reflects
/// link-local service traffic, so a link-local source is preferred; a global address is
/// the fallback when no link-local is usable.
fn v6_rank(addr: Ipv6Addr) -> u8 {
    let o = addr.octets();
    if o[0] == 0xff || addr.is_unspecified() || addr.is_loopback() {
        0 // multicast / :: / ::1 — never a real source
    } else if o[0] == 0xfe && (o[1] & 0xc0) == 0x80 {
        3 // link-local fe80::/10
    } else if (o[0] & 0xfe) == 0xfc {
        2 // unique local fc00::/7
    } else {
        1 // global / other
    }
}

// The loopback interface for tests: `lo` on Linux, `lo0` on the BSDs. An unhandled target
// fails to compile rather than silently guess (`any(macos, freebsd)`, not the looser `not(linux)`).
#[cfg(all(test, target_os = "linux"))]
pub(crate) const LOOPBACK_IFACE: &str = "lo";
#[cfg(all(test, any(target_os = "macos", target_os = "freebsd")))]
pub(crate) const LOOPBACK_IFACE: &str = "lo0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_loopback_v4() {
        // Every host's loopback has 127.0.0.1; resolution needs no privileges, so this
        // exercises the full backend (the v4 path, and on Linux the rtnetlink round-trip).
        let addrs = Interface::open(LOOPBACK_IFACE).unwrap().addrs;
        assert_eq!(addrs.v4, Some(Ipv4Addr::LOCALHOST));
    }

    #[test]
    fn refresh_reports_which_source_fields_changed() {
        let mut iface = Interface::open(LOOPBACK_IFACE).unwrap();
        // Re-resolving an interface whose addresses are already current reports nothing moved.
        assert_eq!(iface.refresh().unwrap(), AddressChange::default());
        // With a stale v4 cached, the next resolve (back to the real 127.0.0.1) reports a v4 move — and
        // only v4. This is the flag the DIAL eviction gates on.
        iface.addrs.v4 = Some(Ipv4Addr::new(10, 0, 0, 1));
        assert_eq!(
            iface.refresh().unwrap(),
            AddressChange {
                v4: true,
                ..AddressChange::default()
            },
        );
        // A stale v6 is reported independently of v4 — so a routine v6 rotation can't masquerade as the
        // v4 change that would evict a DIAL proxy.
        iface.addrs.v6 = Some("2001:db8::1".parse().unwrap());
        let change = iface.refresh().unwrap();
        assert!(change.v6, "the differing v6 is reported");
        assert!(!change.v4, "but it does not look like a v4 change");
    }

    #[test]
    fn unknown_interface_has_no_addresses() {
        let addrs = Interface::open("nonexistent-xyz-999").unwrap().addrs;
        assert_eq!(addrs, InterfaceAddresses::default());
    }

    #[test]
    fn v6_rank_orders_link_local_above_ula_above_global() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let ula: Ipv6Addr = "fc00::1".parse().unwrap();
        let global: Ipv6Addr = "2001:db8::1".parse().unwrap();
        assert!(v6_rank(ll) > v6_rank(ula));
        assert!(v6_rank(ula) > v6_rank(global));
        assert!(v6_rank(global) > v6_rank(Ipv6Addr::LOCALHOST));
    }

    // Opt-in diagnostic: trace-log every address (and each v6's flag status) the resolver
    // finds on a real interface. Run with, e.g.:
    //   REFLECTOR_TEST_IFACE=en0 cargo test -- --nocapture resolve_traces_test_interface
    #[test]
    fn resolve_traces_test_interface() {
        let Some(iface) = std::env::var_os("REFLECTOR_TEST_IFACE") else {
            eprintln!("skip: set REFLECTOR_TEST_IFACE to inspect an interface");
            return;
        };
        let iface = iface.to_string_lossy();
        crate::logging::init();
        crate::logging::set_level(crate::config::LogLevel::Trace);
        let addrs = Interface::open(&iface).expect("open failed").addrs;
        eprintln!("resolved {iface}: {addrs}");
    }
}
