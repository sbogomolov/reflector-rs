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

/// An interface's current source addresses; any may be absent. The fields are private so a sender
/// reaches a v6 source only through [`v6`](Self::v6), naming the destination's scope: the stored
/// best-overall source (link-local preferred) and best-non-link-local one (ULA or global) can't be
/// grabbed directly and mismatched against the destination.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct InterfaceAddresses {
    mac: Option<MacAddr>,
    v4: Option<Ipv4Addr>,
    v6: Option<Ipv6Addr>,
    v6_routable: Option<Ipv6Addr>,
}

impl InterfaceAddresses {
    /// The source MAC, if the link has one (a `DLT_NULL` / loopback link has none).
    pub(crate) fn mac(&self) -> Option<MacAddr> {
        self.mac
    }

    /// The IPv4 source address, if any. IPv4 is scopeless, so — unlike
    /// [`v6`](Self::v6) — it needs no destination argument.
    pub(crate) fn v4(&self) -> Option<Ipv4Addr> {
        self.v4
    }

    /// The best v6 source for a destination of `dest_scope`: a link-local source for a link-local
    /// destination, a routable (ULA/global) source for a wider one. Falls back to the other scope's
    /// address when the matching one is absent — a scope mismatch, but better than dropping the send
    /// (and what the single-address pick did before `v6_routable` existed).
    pub(crate) fn v6(&self, dest_scope: Ipv6Scope) -> Option<Ipv6Addr> {
        match dest_scope {
            Ipv6Scope::LinkLocal => self.v6,
            Ipv6Scope::Routable => self.v6_routable.or(self.v6),
        }
    }

    /// Whether the interface can currently source IPv4 — the per-family availability gate.
    pub(crate) fn has_v4(&self) -> bool {
        self.v4.is_some()
    }

    /// Whether the interface can currently source IPv6, in any scope. The best-overall source is set
    /// whenever any usable v6 address exists, so this answers "is there a v6 source at all".
    pub(crate) fn has_v6(&self) -> bool {
        self.v6.is_some()
    }
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
            Some(v6) => write!(f, "{v6}")?,
            None => f.write_str("none")?,
        }
        f.write_str(", v6-routable ")?;
        match self.v6_routable {
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

/// An IPv6 destination's scope, coarsened to what matters for source selection: a link-local
/// destination (`fe80::/10`, or a link-local-scoped multicast group like `ff02::`) wants a link-local
/// source; anything wider wants a routable one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ipv6Scope {
    LinkLocal,
    /// Site-local, ULA, or global — anything routed beyond the local link (not necessarily a GUA).
    Routable,
}

impl Ipv6Scope {
    /// The scope of `addr`: link-local if it's a link-local-scoped multicast group or a link-local
    /// unicast address ([`Ipv6Addr::is_unicast_link_local`]), else routable. Only the multicast side is
    /// hand-rolled, because `Ipv6Addr::multicast_scope` is unstable (feature `ip`).
    pub(crate) fn of(addr: Ipv6Addr) -> Self {
        if is_multicast_link_local(addr) || addr.is_unicast_link_local() {
            Self::LinkLocal
        } else {
            Self::Routable
        }
    }
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
        // Both v6 transitions are logged (the `let`s run before the `||`), and either folds into the
        // single `v6` change bit, since no caller distinguishes the two v6 sources.
        let v6 = log_field_change(&self.name, "IPv6", self.addrs.v6, addrs.v6);
        let v6_routable = log_field_change(
            &self.name,
            "IPv6 routable",
            self.addrs.v6_routable,
            addrs.v6_routable,
        );
        let change = AddressChange {
            mac: log_field_change(&self.name, "MAC", self.addrs.mac, addrs.mac),
            v4: log_field_change(&self.name, "IPv4", self.addrs.v4, addrs.v4),
            v6: v6 || v6_routable,
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

/// An IPv6 source candidate's rank, ordered worst-to-best so a higher variant outranks a lower one
/// (the derived `Ord` follows declaration order). The reflector reflects link-local service traffic, so
/// a link-local source is preferred, then ULA, then global; a multicast / `::` / `::1` address is never
/// a source.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Debug)]
enum V6Rank {
    #[default]
    NotASource,
    Global,
    UniqueLocal,
    LinkLocal,
}

/// Rank an IPv6 source candidate by how good a source it is (see [`V6Rank`]).
fn v6_rank(addr: Ipv6Addr) -> V6Rank {
    if addr.is_multicast() || addr.is_unspecified() || addr.is_loopback() {
        V6Rank::NotASource // multicast / :: / ::1 — never a real source
    } else if addr.is_unicast_link_local() {
        V6Rank::LinkLocal // fe80::/10
    } else if addr.is_unique_local() {
        V6Rank::UniqueLocal // fc00::/7
    } else {
        V6Rank::Global
    }
}

/// Whether `addr` is a link-local-scoped multicast group (`ff02::`): a multicast address (`ff00::/8`)
/// whose scope nibble is `2`. Hand-rolled because `Ipv6Addr::multicast_scope` — the natural fit — is
/// unstable (feature `ip`), unlike the unicast/ULA classifiers we take from std. The `is_multicast`
/// check isn't a redundant guard: the scope nibble alone also matches unicasts like `fd02::` or `2012::`.
fn is_multicast_link_local(addr: Ipv6Addr) -> bool {
    addr.is_multicast() && (addr.octets()[1] & 0x0f) == 0x02
}

/// Picks the best v6 source addresses while a backend scans an interface's usable addresses: the
/// highest-ranked overall ([`v6`](InterfaceAddresses::v6), link-local preferred) and the highest-ranked
/// non-link-local ([`v6_routable`](InterfaceAddresses::v6_routable), for site-local/global sends). Both
/// platform backends feed it their usable candidates, so the per-scope pick lives in one place.
#[derive(Default)]
pub(super) struct V6Pick {
    best_rank: V6Rank,
    best_routable_rank: V6Rank,
}

impl V6Pick {
    /// Consider a usable v6 source `addr`, updating `addrs` if it outranks the current pick(s).
    pub(super) fn consider(&mut self, addrs: &mut InterfaceAddresses, addr: Ipv6Addr) {
        let rank = v6_rank(addr);
        if rank == V6Rank::NotASource {
            return; // multicast / :: / ::1
        }
        if addrs.v6.is_none() || rank > self.best_rank {
            addrs.v6 = Some(addr);
            self.best_rank = rank;
        }
        // The best non-link-local source (ranked below LinkLocal), for site-local/global destinations.
        if rank < V6Rank::LinkLocal
            && (addrs.v6_routable.is_none() || rank > self.best_routable_rank)
        {
            addrs.v6_routable = Some(addr);
            self.best_routable_rank = rank;
        }
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

    impl InterfaceAddresses {
        /// Construct a record directly, for tests in other modules (the fields are private, so they
        /// can't use a struct literal). Production builds these through the platform resolvers.
        pub(crate) fn new(
            mac: Option<MacAddr>,
            v4: Option<Ipv4Addr>,
            v6: Option<Ipv6Addr>,
            v6_routable: Option<Ipv6Addr>,
        ) -> Self {
            Self {
                mac,
                v4,
                v6,
                v6_routable,
            }
        }
    }

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

    #[test]
    fn ipv6_scope_of_reads_multicast_and_unicast() {
        // Link-local-scoped multicast (ff02::) and link-local unicast (fe80::) are LinkLocal; the
        // site-local SSDP group (ff05::) and a global address are wider (Routable).
        assert_eq!(
            Ipv6Scope::of("ff02::c".parse().unwrap()),
            Ipv6Scope::LinkLocal
        );
        assert_eq!(
            Ipv6Scope::of("fe80::1".parse().unwrap()),
            Ipv6Scope::LinkLocal
        );
        assert_eq!(
            Ipv6Scope::of("ff05::c".parse().unwrap()),
            Ipv6Scope::Routable
        );
        assert_eq!(
            Ipv6Scope::of("2001:db8::1".parse().unwrap()),
            Ipv6Scope::Routable
        );
        // A ULA whose second byte's low nibble is 2 (fd02::) must not be mistaken for a link-local
        // multicast group — the `is_multicast` half of is_multicast_link_local guards exactly this.
        assert_eq!(
            Ipv6Scope::of("fd02::1".parse().unwrap()),
            Ipv6Scope::Routable
        );
    }

    #[test]
    fn v6_picks_by_scope_and_falls_back() {
        let both = InterfaceAddresses {
            v6: Some("fe80::1".parse().unwrap()),
            v6_routable: Some("2001:db8::1".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(both.v6(Ipv6Scope::LinkLocal), both.v6);
        assert_eq!(both.v6(Ipv6Scope::Routable), both.v6_routable);
        // No routable address: a wider destination falls back to the link-local one (prior behavior).
        let link_only = InterfaceAddresses {
            v6: Some("fe80::1".parse().unwrap()),
            ..Default::default()
        };
        assert_eq!(link_only.v6(Ipv6Scope::Routable), link_only.v6);
        // No v6 at all: nothing to source.
        assert_eq!(InterfaceAddresses::default().v6(Ipv6Scope::Routable), None);
    }

    #[test]
    fn v6_pick_tracks_best_overall_and_best_routable() {
        let mut addrs = InterfaceAddresses::default();
        let mut pick = V6Pick::default();
        pick.consider(&mut addrs, "2001:db8::1".parse().unwrap()); // global
        pick.consider(&mut addrs, "fc00::1".parse().unwrap()); // ULA — outranks global
        pick.consider(&mut addrs, "fe80::1".parse().unwrap()); // link-local — best overall
        assert_eq!(
            addrs.v6,
            Some("fe80::1".parse::<Ipv6Addr>().unwrap()),
            "best overall is the link-local"
        );
        assert_eq!(
            addrs.v6_routable,
            Some("fc00::1".parse::<Ipv6Addr>().unwrap()),
            "best non-link-local is the ULA"
        );
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
