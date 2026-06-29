//! The SSDP-side entry to the DIAL proxy: rewrite a discovery message's `LOCATION` to a minted proxy.
//!
//! [`rewrite_location`] is what the SSDP reflector calls on every advertisement / search response: it
//! detects a DIAL discovery message, parses its `LOCATION` authority, and rewrites that `LOCATION` to a
//! source-side description proxy — minting and registering one (via the
//! [`DialContext`](crate::dispatch::DialContext) registry) if none is live for the device, and refreshing
//! its grace either way. Minting is the means; the rewrite is the purpose.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::os::fd::AsRawFd;
use std::time::{Duration, Instant};

use crate::dispatch::{CaptureKey, DialContext};
use crate::net::ssdp::dial::{
    dial_location_value, is_dial_service_message, parse_cache_control_max_age,
    parse_dial_location_authority,
};
use crate::net::tcp::TcpSocket;
use crate::reactor::Reactor;

use super::proxy::{DialDeviceProxy, Listener};

/// The description-listener grace when an advertisement carries no `CACHE-CONTROL: max-age` — the
/// UDA-recommended minimum device validity (DIAL's own example advertises `max-age=1800`).
const DEFAULT_DESC_GRACE: Duration = Duration::from_mins(30);

/// Bytes a reflector reserves on the stack to rewrite one SSDP datagram into. Anchored to the
/// dispatcher's send frame buffer ([`SCRATCH_LEN`](crate::dispatch::SCRATCH_LEN)): the reflector builds
/// its outgoing frame there, so a datagram that doesn't fit it can't be forwarded at all — sizing the
/// rewrite scratch to it holds any rewritten datagram the reflector could send. A `LOCATION` rewrite can
/// grow the datagram; one that still overruns this falls back to verbatim rather than truncating.
pub(crate) const REWRITE_BUF_LEN: usize = crate::dispatch::SCRATCH_LEN;

/// Where a minted DIAL description proxy sits across the two interfaces, resolved per datagram: it
/// binds its source-side listeners on `source`, egress-pins device connections to
/// `target`/`target_ifindex`, and is evicted if either `source_capture`'s or `target_capture`'s
/// IPv4 address later changes. Bundling the two same-typed capture/address pairs keeps them from
/// being transposed at the call.
#[derive(Clone, Copy)]
pub(crate) struct ProxyPlacement {
    pub(crate) source_capture: CaptureKey,
    pub(crate) source: Ipv4Addr,
    pub(crate) target_capture: CaptureKey,
    pub(crate) target: Ipv4Addr,
    pub(crate) target_ifindex: u32,
}

/// Rewrite a DIAL discovery message's `LOCATION` to point at a source-side description proxy, minting and
/// registering the proxy if one isn't already live for this device and refreshing its grace either way.
/// On a rewrite the rewritten datagram is written into `out` and its length returned; `None` means
/// forward `payload` unchanged — it isn't a DIAL message, its `LOCATION` isn't a rewritable IPv4 `http`
/// URL, the proxy cap was reached / a mint failed (the device stays visible but unproxied), or the
/// rewrite wouldn't fit `out`. `out` is the caller's reused scratch (size it [`REWRITE_BUF_LEN`]); the
/// rewritten datagram is sent immediately, so it need not outlive the call. `placement` says where the
/// proxy lives across the two interfaces (see [`ProxyPlacement`]).
pub(crate) fn rewrite_location(
    ctx: &mut DialContext,
    reactor: &mut Reactor,
    payload: &[u8],
    placement: ProxyPlacement,
    out: &mut [u8],
) -> Option<usize> {
    use std::io::Write;
    if !is_dial_service_message(payload) {
        return None;
    }
    let Some(location) = parse_dial_location_authority(payload) else {
        // The message is DIAL but its LOCATION isn't a rewritable IPv4 http URL (https, a hostname,
        // an IPv6 literal, a bad port). It's forwarded verbatim with no proxy minted — exactly the
        // "device discovered but never proxied" case, so name the offending URL for a debug session.
        log::debug!(
            "dial: LOCATION {} is not a rewritable IPv4 http URL; forwarding the message unproxied",
            dial_location_value(payload).map_or_else(|| "(absent)".into(), String::from_utf8_lossy)
        );
        return None;
    };
    // The grace is refreshed on every advertisement / search response, so a re-advertised device's
    // cached LOCATION keeps resolving for another max-age.
    let max_age = parse_cache_control_max_age(payload).map_or(DEFAULT_DESC_GRACE, |seconds| {
        Duration::from_secs(u64::from(seconds))
    });
    let desc_grace = Instant::now() + max_age;
    let desc_addr = if let Some(addr) = ctx.lookup(
        placement.source_capture,
        location.endpoint,
        reactor,
        desc_grace,
    ) {
        // An existing proxy already fronts this device; its grace just refreshed.
        log::trace!(
            "dial: reusing the proxy for {}; grace refreshed to {max_age:?}",
            location.endpoint
        );
        addr
    } else {
        mint_proxy(ctx, reactor, placement, location.endpoint, desc_grace)?
    };
    // Write the rewritten datagram into `out` — prefix, the proxy authority, suffix. The rewrite can
    // grow the datagram, so a short buffer errors (the caller forwards verbatim) rather than truncating.
    let capacity = out.len();
    let mut cursor: &mut [u8] = out;
    let fits = cursor.write_all(&payload[..location.offset]).is_ok()
        && write!(cursor, "{desc_addr}").is_ok()
        && cursor
            .write_all(&payload[location.offset + location.len..])
            .is_ok();
    if !fits {
        log::warn!(
            "dial: rewritten LOCATION for {} exceeds the {capacity} B buffer; forwarding verbatim",
            location.endpoint
        );
        return None;
    }
    Some(capacity - cursor.len())
}

/// Mint a description proxy for `endpoint`, register it on `reactor`, and record it in `ctx`; returns the
/// source-side description-listener address to rewrite the `LOCATION` to. `None` (logged) at the proxy
/// cap or on a listen/register failure, leaving the `LOCATION` unrewritten.
fn mint_proxy(
    ctx: &mut DialContext,
    reactor: &mut Reactor,
    placement: ProxyPlacement,
    endpoint: SocketAddrV4,
    desc_grace: Instant,
) -> Option<SocketAddrV4> {
    if !ctx.has_capacity(reactor) {
        log::warn!("dial: proxy cap reached; reflecting {endpoint}'s LOCATION unchanged");
        return None;
    }
    let desc = listen_or_warn(placement.source, Listener::Description)?;
    let rest = listen_or_warn(placement.source, Listener::Rest)?;
    let desc_addr = desc.local_addr();
    let watches = [(desc.as_raw_fd(), 0), (rest.as_raw_fd(), 0)];
    let proxy = DialDeviceProxy::new(
        placement.target,
        placement.target_ifindex,
        desc,
        endpoint,
        rest,
    );
    let handler = match reactor.register_with_fds(Box::new(proxy), &watches) {
        Ok(handler) => handler,
        Err(e) => {
            log::warn!("dial: registering the proxy for {endpoint} failed: {e}");
            return None; // the proxy drops, closing both listeners
        }
    };
    ctx.insert(
        placement.source_capture,
        placement.target_capture,
        endpoint,
        handler,
        desc_addr,
        desc_grace,
    );
    log::debug!("dial: minted a proxy for {endpoint} via description listener {desc_addr}");
    Some(desc_addr)
}

/// Bind a source-side listener, logging and yielding `None` on failure; `what` names it for the log.
fn listen_or_warn(source: Ipv4Addr, what: Listener) -> Option<TcpSocket> {
    match TcpSocket::listen(source) {
        Ok(listener) => Some(listener),
        Err(e) => {
            log::warn!("dial: binding the {what} listener on {source} failed: {e}");
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use std::thread::sleep;

    use super::*;

    /// A DIAL advertisement whose `LOCATION` names the device endpoint `10.0.0.5:8008`.
    const DIAL_ADVERT: &[u8] =
        b"NOTIFY * HTTP/1.1\r\nNT: urn:dial-multiscreen-org:service:dial:1\r\n\
        LOCATION: http://10.0.0.5:8008/dd.xml\r\nCACHE-CONTROL: max-age=1800\r\n\r\n";

    /// The device endpoint `DIAL_ADVERT` resolves to (with [`advert_source`], the `DialContext` key).
    const ADVERT_ENDPOINT: &str = "10.0.0.5:8008";

    /// The source capture `rewrite_advert` keys its proxy under.
    fn advert_source() -> CaptureKey {
        CaptureKey::from_u64(7)
    }

    /// The target capture `rewrite_advert`'s proxy egresses device connections on.
    fn advert_target() -> CaptureKey {
        CaptureKey::from_u64(8)
    }

    /// Rewrite `payload` like a reflector would (into a [`REWRITE_BUF_LEN`] stack buffer), returning the
    /// rewritten datagram, or `None` to forward verbatim.
    fn rewrite_advert(
        ctx: &mut DialContext,
        reactor: &mut Reactor,
        payload: &[u8],
    ) -> Option<Vec<u8>> {
        let mut buf = [0u8; REWRITE_BUF_LEN];
        let placement = ProxyPlacement {
            source_capture: advert_source(),
            source: Ipv4Addr::LOCALHOST,
            target_capture: advert_target(),
            target: Ipv4Addr::LOCALHOST,
            target_ifindex: 0,
        };
        let n = rewrite_location(ctx, reactor, payload, placement, &mut buf)?;
        Some(buf[..n].to_vec())
    }

    #[test]
    fn rewrite_location_mints_a_proxy_and_rewrites_to_its_desc_listener() {
        let mut reactor = Reactor::new().expect("reactor");
        let mut ctx = DialContext::new();
        let rewritten = rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT)
            .expect("a DIAL LOCATION is rewritten");
        let text = String::from_utf8_lossy(&rewritten);
        assert!(
            text.contains("LOCATION: http://127.0.0.1:"),
            "LOCATION points at the source-side proxy: {text}"
        );
        assert!(
            !text.contains("10.0.0.5:8008"),
            "the device address no longer leaks: {text}"
        );
        assert_eq!(ctx.proxy_count(), 1, "exactly one proxy minted");
        assert!(
            reactor.is_registered(ctx.handler_keys()[0]),
            "the minted proxy is registered in the reactor"
        );
    }

    #[test]
    fn rewrite_location_reuses_a_live_proxy_for_the_same_device() {
        let mut reactor = Reactor::new().expect("reactor");
        let mut ctx = DialContext::new();
        let first = rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT).expect("first");
        let second = rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT).expect("second");
        assert_eq!(first, second, "the same proxy (and desc port) is reused");
        assert_eq!(ctx.proxy_count(), 1, "no second proxy is minted");
    }

    #[test]
    fn rewrite_location_refreshes_the_grace_on_every_advertisement() {
        let mut reactor = Reactor::new().expect("reactor");
        let mut ctx = DialContext::new();
        let endpoint = ADVERT_ENDPOINT.parse().unwrap();
        assert!(rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT).is_some());
        let first_grace = ctx
            .grace_of(advert_source(), endpoint)
            .expect("a grace was recorded");
        sleep(Duration::from_millis(5)); // let the monotonic clock advance
        // A re-advertisement reuses the proxy but pushes its grace forward.
        assert!(rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT).is_some());
        let second_grace = ctx
            .grace_of(advert_source(), endpoint)
            .expect("grace still recorded");
        assert!(
            second_grace > first_grace,
            "the grace is refreshed on reuse"
        );
        assert_eq!(ctx.proxy_count(), 1, "still one proxy");
    }

    #[test]
    fn rewrite_location_remints_after_the_proxy_is_evicted() {
        let mut reactor = Reactor::new().expect("reactor");
        let mut ctx = DialContext::new();
        let first = rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT).expect("first");
        // The registry evicts the proxy (unregisters it); its generational key goes stale.
        reactor
            .unregister(ctx.handler_keys()[0])
            .expect("unregister the proxy");
        let reminted = rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT).expect("re-minted");
        assert_ne!(
            first, reminted,
            "a fresh proxy on a new port replaces the evicted one"
        );
        assert_eq!(
            ctx.proxy_count(),
            1,
            "the stale entry is replaced, not duplicated"
        );
    }

    #[test]
    fn an_interface_change_evicts_a_proxy_by_source_or_target() {
        let mut reactor = Reactor::new().expect("reactor");
        let mut ctx = DialContext::new();
        rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT).expect("minted");
        let handler = ctx.handler_keys()[0];

        // A change on an unrelated interface leaves the proxy alone.
        ctx.evict_on_interface_change(&mut reactor, |c| c == CaptureKey::from_u64(99));
        assert_eq!(
            ctx.proxy_count(),
            1,
            "an unrelated interface change spares it"
        );
        assert!(reactor.is_registered(handler));

        // A change on its source interface evicts and unregisters it.
        ctx.evict_on_interface_change(&mut reactor, |c| c == advert_source());
        assert_eq!(ctx.proxy_count(), 0, "a source interface change evicts it");
        assert!(!reactor.is_registered(handler), "and unregisters it");

        // A re-mint is evicted just the same by a change on its target interface.
        rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT).expect("re-minted");
        let handler = ctx.handler_keys()[0];
        ctx.evict_on_interface_change(&mut reactor, |c| c == advert_target());
        assert_eq!(
            ctx.proxy_count(),
            0,
            "a target interface change evicts it too"
        );
        assert!(!reactor.is_registered(handler));
    }

    #[test]
    fn evict_on_interface_change_prunes_an_already_evicted_entry() {
        let mut reactor = Reactor::new().expect("reactor");
        let mut ctx = DialContext::new();
        rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT).expect("minted");
        // The proxy is torn down out from under the registry (e.g. by the grace sweep on a prior tick).
        reactor
            .unregister(ctx.handler_keys()[0])
            .expect("unregister the proxy");
        // An interface change matching no live proxy still prunes the now-stale entry.
        ctx.evict_on_interface_change(&mut reactor, |_| false);
        assert_eq!(ctx.proxy_count(), 0, "the already-evicted entry is pruned");
    }

    #[test]
    fn rewrite_location_forwards_non_dial_and_unrewritable_messages_unchanged() {
        let mut reactor = Reactor::new().expect("reactor");
        let mut ctx = DialContext::new();
        // Not a DIAL service message — left alone despite a rewritable LOCATION.
        let upnp = b"NOTIFY * HTTP/1.1\r\nNT: urn:schemas-upnp-org:device:MediaServer:1\r\n\
            LOCATION: http://10.0.0.5:8008/dd.xml\r\n\r\n";
        assert!(rewrite_advert(&mut ctx, &mut reactor, upnp).is_none());
        // DIAL, but the LOCATION isn't a rewritable IPv4 http URL.
        let bad = b"NOTIFY * HTTP/1.1\r\nNT: urn:dial-multiscreen-org:service:dial\r\n\
            LOCATION: https://tv.local/dd.xml\r\n\r\n";
        assert!(rewrite_advert(&mut ctx, &mut reactor, bad).is_none());
        assert_eq!(ctx.proxy_count(), 0, "nothing is minted for either");
    }

    #[test]
    fn dial_context_sweep_evicts_a_proxy_past_its_grace() {
        let mut reactor = Reactor::new().expect("reactor");
        let mut ctx = DialContext::new();
        assert!(rewrite_advert(&mut ctx, &mut reactor, DIAL_ADVERT).is_some());
        let key = ctx.handler_keys()[0];
        // Within its grace (the advert's max-age is 1800s), the proxy survives the sweep.
        ctx.sweep(Instant::now(), &mut reactor);
        assert_eq!(ctx.proxy_count(), 1, "a proxy within its grace survives");
        assert!(reactor.is_registered(key));
        // Past the grace, the sweep evicts it and unregisters it from the reactor.
        ctx.sweep(Instant::now() + Duration::from_secs(2000), &mut reactor);
        assert_eq!(ctx.proxy_count(), 0, "the past-grace proxy is evicted");
        assert!(
            !reactor.is_registered(key),
            "and torn down from the reactor"
        );
    }
}
