//! The dispatcher's interface table: every interface (with its multicast joiner) and every capture,
//! linking each capture to its interface, all addressed by `Copy` index keys.

use std::io;
use std::net::IpAddr;
use std::os::fd::{AsRawFd, RawFd};

use crate::capture::Capture;
use crate::interface::{AddressChange, Interface, InterfaceAddresses};

use super::CaptureKey;
use super::multicast::MulticastJoiner;

/// A `Copy` handle into the interface table's interface entries — an insert-only index, like
/// [`CaptureKey`], but a distinct newtype so the two can't be confused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) struct InterfaceKey(u32);

/// One capture plus the interface it runs on. The `capture` is `Option` so the drain can
/// take it OUT (leaving the `interface` link resident, so a capture's addresses resolve
/// even mid-drain) and restore it; `None` marks "currently draining". Never removed.
struct CaptureEntry {
    capture: Option<Capture>,
    interface: InterfaceKey,
}

/// One interface paired with its multicast joiner. Bundling them makes the two impossible to
/// desync (one push adds both) and bakes the relationship the joiner relies on: it carries the
/// interface's ifindex, stable for the interface's lifetime, and a refresh re-attempts its joins.
struct InterfaceEntry {
    interface: Interface,
    joiner: MulticastJoiner,
}

/// Owns every interface and every capture, linking each capture to its interface. Plain
/// `Vec`s (not generational arenas): both are insert-only, so an index is a stable identity
/// and the inner `Option<Capture>` alone marks the take-out.
pub(super) struct InterfaceTable {
    /// One entry per interface, indexed by [`InterfaceKey`].
    entries: Vec<InterfaceEntry>,
    captures: Vec<CaptureEntry>,
}

impl InterfaceTable {
    pub(super) fn new() -> Self {
        Self {
            entries: Vec::new(),
            captures: Vec::new(),
        }
    }

    /// Add an interface, returning its key. Startup-only.
    fn add_interface(&mut self, interface: Interface) -> InterfaceKey {
        let key =
            InterfaceKey(u32::try_from(self.entries.len()).expect("interface count fits a u32"));
        let joiner = MulticastJoiner::new(interface.ifindex);
        self.entries.push(InterfaceEntry { interface, joiner });
        key
    }

    /// Join `group`'s multicast membership on `interface`, recording it for re-attempt on a later
    /// address change. # Errors: propagates the joiner's OS error (an unavailable family is
    /// deferred to [`rejoin`](MulticastJoiner::rejoin), not an error).
    pub(super) fn join_on(&mut self, interface: InterfaceKey, group: IpAddr) -> io::Result<()> {
        // Startup-only with a freshly-minted key, so the index is always in range.
        self.entries[interface.0 as usize].joiner.join(group)
    }

    /// The key of the interface named `name`, opening and resolving it if absent — so
    /// captures on the same interface share one record (and one monitor refresh later).
    ///
    /// # Errors
    /// Propagates a resolution syscall failure when first opening the interface.
    pub(super) fn find_or_add_interface(&mut self, name: &str) -> io::Result<InterfaceKey> {
        if let Some(index) = self
            .entries
            .iter()
            .position(|entry| entry.interface.name == name)
        {
            return Ok(InterfaceKey(
                u32::try_from(index).expect("interface count fits a u32"),
            ));
        }
        Ok(self.add_interface(Interface::open(name)?))
    }

    /// Add a capture bound to `interface`, returning its key. Startup-only.
    pub(super) fn add_capture(&mut self, capture: Capture, interface: InterfaceKey) -> CaptureKey {
        let key = CaptureKey(u32::try_from(self.captures.len()).expect("capture count fits a u32"));
        self.captures.push(CaptureEntry {
            capture: Some(capture),
            interface,
        });
        key
    }

    /// The interface a capture runs on — resolves even while the capture is taken out (the
    /// link is a sibling field of the take-out `Option`).
    pub(super) fn interface_of(&self, capture: CaptureKey) -> Option<InterfaceKey> {
        self.captures
            .get(capture.0 as usize)
            .map(|entry| entry.interface)
    }

    /// An interface's current source addresses, by key.
    fn addrs(&self, interface: InterfaceKey) -> Option<&InterfaceAddresses> {
        self.entries
            .get(interface.0 as usize)
            .map(|entry| &entry.interface.addrs)
    }

    /// The kernel ifindex of the interface `capture` runs on — its stable identity, cached at open.
    pub(super) fn ifindex_of(&self, capture: CaptureKey) -> Option<u32> {
        let interface = self.interface_of(capture)?;
        self.entries
            .get(interface.0 as usize)
            .map(|entry| entry.interface.ifindex)
    }

    /// The name of the interface `interface` keys, if present.
    pub(super) fn interface_name(&self, interface: InterfaceKey) -> Option<&str> {
        self.entries
            .get(interface.0 as usize)
            .map(|entry| entry.interface.name.as_str())
    }

    /// The current source addresses behind a capture, in one hop.
    pub(super) fn egress_addrs(&self, capture: CaptureKey) -> Option<&InterfaceAddresses> {
        self.addrs(self.interface_of(capture)?)
    }

    /// A shared borrow of a present capture, for [`send`](super::PacketDispatcher::send).
    pub(super) fn capture(&self, capture: CaptureKey) -> Option<&Capture> {
        self.captures.get(capture.0 as usize)?.capture.as_ref()
    }

    /// Whether `capture` names a known (in-range) capture — distinguishes a forged key from
    /// one that is merely taken out, for the drain's guard.
    pub(super) fn contains(&self, capture: CaptureKey) -> bool {
        (capture.0 as usize) < self.captures.len()
    }

    /// Take a capture OUT for its drain; restore with [`restore`](Self::restore). `None`
    /// means out of range, or already taken out (currently draining).
    pub(super) fn take(&mut self, capture: CaptureKey) -> Option<Capture> {
        self.captures.get_mut(capture.0 as usize)?.capture.take()
    }

    /// Restore a drained capture, reporting whether its slot was present — keeping logging
    /// out of the table, like [`take`](Self::take). The miss can't actually happen (restore
    /// follows a successful `take` on a Vec that never shrinks); on one, the capture drops.
    #[must_use]
    pub(super) fn restore(&mut self, capture: CaptureKey, value: Capture) -> bool {
        if let Some(entry) = self.captures.get_mut(capture.0 as usize) {
            entry.capture = Some(value);
            true
        } else {
            false
        }
    }

    /// Re-resolve the interface with kernel index `ifindex`, in place. A real index matches at
    /// most one interface — they dedup by name, and the kernel gives each a distinct index —
    /// so this finds rather than scans. Returns the fields that changed if one matched, or `None`
    /// for a change on an interface we don't watch. Log-free, like [`take`](Self::take); the
    /// dispatcher reports the outcome. (The caller routes the `0` overflow-signal to
    /// [`refresh_all`], so `ifindex` is always a real index here.)
    ///
    /// [`refresh_all`]: Self::refresh_all
    ///
    /// # Errors
    /// Propagates a resolution syscall failure.
    pub(super) fn refresh_by_ifindex(&mut self, ifindex: u32) -> io::Result<Option<AddressChange>> {
        let Some(entry) = self
            .entries
            .iter_mut()
            .find(|entry| entry.interface.ifindex == ifindex)
        else {
            return Ok(None);
        };
        let change = entry.interface.refresh()?;
        // Re-resolved addresses may have made a deferred join (a v4 group that had no address)
        // viable; re-attempt this interface's memberships.
        entry.joiner.rejoin();
        Ok(Some(change))
    }

    /// Re-resolve every interface in place — the response to an overflow signal, where dropped
    /// notifications mean any address could be stale. Returns each interface's ifindex paired with its
    /// refresh outcome (best-effort: a per-interface failure is reported, not fatal), so the caller logs
    /// failures and reacts to exactly the interfaces whose addresses moved. Log-free, like
    /// [`refresh_by_ifindex`](Self::refresh_by_ifindex).
    pub(super) fn refresh_all(&mut self) -> Vec<(u32, io::Result<AddressChange>)> {
        let results: Vec<(u32, io::Result<AddressChange>)> = self
            .entries
            .iter_mut()
            .map(|entry| (entry.interface.ifindex, entry.interface.refresh()))
            .collect();
        for entry in &mut self.entries {
            entry.joiner.rejoin();
        }
        results
    }

    /// Each present capture's `(fd, user_data = CaptureKey)` for
    /// [`Reactor::register_with_fds`](crate::reactor::Reactor::register_with_fds).
    pub(super) fn capture_watches(&self) -> Vec<(RawFd, u64)> {
        self.captures
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                let key = CaptureKey(u32::try_from(index).expect("capture count fits a u32"));
                entry
                    .capture
                    .as_ref()
                    .map(|capture| (capture.as_raw_fd(), key.to_u64()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use std::net::{Ipv4Addr, Ipv6Addr};

    use super::*;
    use crate::dispatch::multicast::join_unsupported;
    use crate::interface::{LOOPBACK_IFACE, if_index};

    // refresh_by_ifindex re-resolves only the interface(s) with the matching kernel index, reporting
    // the changed fields (`None` for an unwatched index). Resolution is unprivileged (no capture
    // needed), so this exercises the monitor's refresh path without CAP_NET_RAW.
    #[test]
    fn refresh_by_ifindex_targets_the_matching_interface() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        table.find_or_add_interface(LOOPBACK_IFACE)?;
        let ifindex = if_index(LOOPBACK_IFACE).expect("loopback has an ifindex");
        let change = table
            .refresh_by_ifindex(ifindex)?
            .expect("the loopback interface matches its ifindex and re-resolves");
        assert!(
            !change.v4,
            "re-resolving the unchanged loopback reports no v4 move — the bit the DIAL eviction gates on",
        );
        assert!(
            table.refresh_by_ifindex(u32::MAX)?.is_none(),
            "an ifindex we don't watch should refresh nothing",
        );
        Ok(())
    }

    // join_on records a group on the interface's joiner and joins it; a later refresh re-attempts
    // the recorded memberships idempotently. Unprivileged: loopback accepts the join and resolving
    // the interface needs no CAP_NET_RAW.
    #[test]
    fn join_on_records_a_membership_and_refresh_re_attempts_it() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let iface = table.find_or_add_interface(LOOPBACK_IFACE)?;
        for group in [
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            IpAddr::V6(Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb)),
        ] {
            // QEMU user-mode emulation doesn't implement the join setsockopt; self-skip there.
            if let Err(e) = table.join_on(iface, group) {
                if join_unsupported(&e) {
                    eprintln!("skip join_on_records: MCAST_JOIN_GROUP unsupported here ({e})");
                    return Ok(());
                }
                return Err(e);
            }
        }
        // The recorded memberships survive a refresh, re-attempted idempotently (each interface
        // resolves cleanly).
        let results = table.refresh_all();
        assert!(
            results.iter().all(|(_, r)| r.is_ok()),
            "re-resolving every interface succeeds",
        );
        Ok(())
    }

    #[test]
    fn find_or_add_interface_dedups_by_name() -> io::Result<()> {
        let mut table = InterfaceTable::new();
        let first = table.find_or_add_interface(LOOPBACK_IFACE)?;
        let second = table.find_or_add_interface(LOOPBACK_IFACE)?;
        assert_eq!(first, second, "the same name resolves to one interface key");
        Ok(())
    }

    #[test]
    fn capture_accessors_reject_an_out_of_range_key() {
        let mut table = InterfaceTable::new();
        let forged = CaptureKey(0); // nothing added yet
        assert!(!table.contains(forged));
        assert!(table.interface_of(forged).is_none());
        assert!(table.ifindex_of(forged).is_none());
        assert!(table.capture(forged).is_none());
        assert!(table.egress_addrs(forged).is_none());
        assert!(table.take(forged).is_none());
    }
}
