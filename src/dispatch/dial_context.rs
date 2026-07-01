//! The registry of minted DIAL proxies — one proxy per device, shared across the SSDP advertisement
//! and search-response paths.

use std::net::SocketAddrV4;
use std::time::Instant;

use crate::reactor::{HandlerKey, Reactor};

use super::CaptureKey;

/// Cap on concurrent minted DIAL proxies — a burst of advertised devices can't exhaust source-side
/// listeners or reactor slots. At the cap a new device's `LOCATION` is reflected unchanged (visible but
/// unproxied) rather than evicting a live proxy.
const MAX_DIAL_PROXIES: usize = 32;

/// One minted DIAL description proxy, keyed by `(source, endpoint)`:
/// - `target` — capture the device connections egress on; a change on either interface evicts the proxy.
/// - `handler` — the proxy's reactor key; goes stale once the proxy is evicted.
/// - `desc_addr` — source-side description-listener spliced into the device's `LOCATION`.
/// - `desc_grace` — eviction deadline, refreshed to each advertisement's `max-age` so a cached
///   `LOCATION` keeps resolving while the device is advertised.
struct DialEntry {
    source: CaptureKey,
    target: CaptureKey,
    endpoint: SocketAddrV4,
    handler: HandlerKey,
    desc_addr: SocketAddrV4,
    desc_grace: Instant,
}

/// The registry of minted DIAL proxies, owned by the [`PacketDispatcher`](super::PacketDispatcher) so the
/// SSDP advertisement and search-response paths — separate handlers — share one proxy per device. The
/// DIAL hook (`reflector::dial::rewrite_location`) reuses a live proxy found here (refreshing its grace)
/// or records a freshly-minted one; an evicted proxy's entry is pruned on the next lookup or capacity check.
pub(crate) struct DialContext {
    proxies: Vec<DialEntry>,
}

impl DialContext {
    pub(crate) fn new() -> Self {
        Self {
            proxies: Vec::new(),
        }
    }

    /// The live proxy's description-listener address for `(source, endpoint)`, refreshing its grace to
    /// `desc_grace` (a re-advertisement extends the device's validity). `None` if none is registered; a
    /// stale entry — its proxy evicted, so its [`HandlerKey`] no longer resolves — is pruned and treated
    /// as absent.
    pub(crate) fn lookup(
        &mut self,
        source: CaptureKey,
        endpoint: SocketAddrV4,
        reactor: &Reactor,
        desc_grace: Instant,
    ) -> Option<SocketAddrV4> {
        let pos = self
            .proxies
            .iter()
            .position(|p| p.source == source && p.endpoint == endpoint)?;
        if reactor.is_registered(self.proxies[pos].handler) {
            self.proxies[pos].desc_grace = desc_grace;
            Some(self.proxies[pos].desc_addr)
        } else {
            log::trace!("dial: pruning the stale proxy entry for {endpoint}");
            self.proxies.swap_remove(pos);
            None
        }
    }

    /// Whether another proxy may be minted: prune every evicted entry, then check the cap.
    pub(crate) fn has_capacity(&mut self, reactor: &Reactor) -> bool {
        self.proxies.retain(|p| reactor.is_registered(p.handler));
        self.proxies.len() < MAX_DIAL_PROXIES
    }

    /// Record a freshly-minted proxy and its grace, replacing any prior entry for `(source, endpoint)`
    /// — a re-mint after the old proxy was evicted.
    pub(crate) fn insert(
        &mut self,
        source: CaptureKey,
        target: CaptureKey,
        endpoint: SocketAddrV4,
        handler: HandlerKey,
        desc_addr: SocketAddrV4,
        desc_grace: Instant,
    ) {
        if let Some(entry) = self
            .proxies
            .iter_mut()
            .find(|p| p.source == source && p.endpoint == endpoint)
        {
            entry.target = target;
            entry.handler = handler;
            entry.desc_addr = desc_addr;
            entry.desc_grace = desc_grace;
        } else {
            self.proxies.push(DialEntry {
                source,
                target,
                endpoint,
                handler,
                desc_addr,
                desc_grace,
            });
        }
    }

    /// The soonest grace deadline across recorded proxies — when [`sweep`](Self::sweep) next has work,
    /// folded into the dispatcher's [`next_deadline`](super::PacketHandler::next_deadline). `None` when empty.
    pub(crate) fn next_grace(&self) -> Option<Instant> {
        self.proxies.iter().map(|p| p.desc_grace).min()
    }

    /// Evict every proxy `evict` selects: unregister it from the reactor — tearing down its listeners and
    /// connections — and drop its entry. `reason` names why, for the log. A surviving entry whose proxy is
    /// already gone is pruned too, so a stale [`HandlerKey`] never lingers.
    fn evict_where(
        &mut self,
        reactor: &mut Reactor,
        reason: &str,
        evict: impl Fn(&DialEntry) -> bool,
    ) {
        self.proxies.retain(|p| {
            if evict(p) {
                match reactor.unregister(p.handler) {
                    Ok(_) => log::debug!("dial: evicted the proxy for {} {reason}", p.endpoint),
                    Err(e) => {
                        log::warn!(
                            "dial: evicting the proxy for {} {reason} failed: {e}",
                            p.endpoint
                        );
                    }
                }
                false // drop the entry whether or not the teardown cleanly succeeded
            } else {
                reactor.is_registered(p.handler) // drop an already-evicted entry
            }
        });
    }

    /// Evict every proxy whose grace has lapsed (`now` past its `desc_grace`).
    pub(crate) fn sweep(&mut self, now: Instant, reactor: &mut Reactor) {
        self.evict_where(reactor, "past its grace", |p| now >= p.desc_grace);
    }

    /// Evict every proxy whose source or target capture is on a changed interface (`on_changed`): an
    /// address move there stranded the proxy's listeners or its device-connect egress, so it must re-mint
    /// against the current addresses on the next advertisement rather than be reused.
    pub(crate) fn evict_on_interface_change(
        &mut self,
        reactor: &mut Reactor,
        on_changed: impl Fn(CaptureKey) -> bool,
    ) {
        self.evict_where(reactor, "after its interface's address changed", |p| {
            on_changed(p.source) || on_changed(p.target)
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    impl DialContext {
        /// The number of recorded proxies — a seam for the DIAL hook's tests in `reflector::dial`.
        pub(crate) fn proxy_count(&self) -> usize {
            self.proxies.len()
        }

        /// The recorded proxies' handler keys — a seam to simulate an eviction.
        pub(crate) fn handler_keys(&self) -> Vec<HandlerKey> {
            self.proxies.iter().map(|p| p.handler).collect()
        }

        /// The recorded grace for `(source, endpoint)` — a seam to assert a re-advertisement refreshed it.
        pub(crate) fn grace_of(
            &self,
            source: CaptureKey,
            endpoint: SocketAddrV4,
        ) -> Option<Instant> {
            self.proxies
                .iter()
                .find(|p| p.source == source && p.endpoint == endpoint)
                .map(|p| p.desc_grace)
        }
    }

    use std::time::Duration;

    use crate::reactor::{Handler, ReadyEvent};

    struct Dummy;
    impl Handler for Dummy {
        fn on_readable(&mut self, _event: ReadyEvent, _reactor: &mut Reactor) {}
    }

    fn ep(n: u8) -> SocketAddrV4 {
        SocketAddrV4::new(std::net::Ipv4Addr::new(10, 0, 0, n), 8008)
    }

    #[test]
    fn next_grace_reports_the_soonest_or_none_when_empty() {
        let mut reactor = Reactor::new().unwrap();
        let mut ctx = DialContext::new();
        assert_eq!(ctx.next_grace(), None);

        let base = Instant::now();
        let hk1 = reactor.register(Box::new(Dummy));
        ctx.insert(
            CaptureKey(0),
            CaptureKey(1),
            ep(1),
            hk1,
            ep(9),
            base + Duration::from_secs(10),
        );
        let hk2 = reactor.register(Box::new(Dummy));
        ctx.insert(
            CaptureKey(0),
            CaptureKey(1),
            ep(2),
            hk2,
            ep(9),
            base + Duration::from_secs(5),
        );
        assert_eq!(ctx.next_grace(), Some(base + Duration::from_secs(5)));
    }

    #[test]
    fn lookup_finds_a_live_proxy_and_prunes_an_evicted_one() {
        let mut reactor = Reactor::new().unwrap();
        let mut ctx = DialContext::new();
        let hk = reactor.register(Box::new(Dummy));
        let base = Instant::now();
        ctx.insert(CaptureKey(0), CaptureKey(1), ep(1), hk, ep(9), base);

        // Live: found, and its grace is refreshed to the new deadline.
        let refreshed = base + Duration::from_secs(30);
        assert_eq!(
            ctx.lookup(CaptureKey(0), ep(1), &reactor, refreshed),
            Some(ep(9))
        );
        assert_eq!(ctx.grace_of(CaptureKey(0), ep(1)), Some(refreshed));

        // Evicted: the stale entry is pruned and reported absent.
        reactor.unregister(hk).unwrap();
        assert_eq!(ctx.lookup(CaptureKey(0), ep(1), &reactor, base), None);
        assert_eq!(ctx.proxy_count(), 0);
    }
}
