//! The DIAL application proxy: one per device, fronting the device's HTTP endpoints on the source
//! subnet so a controller on one segment can drive a media device on another without the device's
//! address ever leaking. Split into three layers:
//!
//! - [`connection`]: the per-connection bidirectional HTTP byte splice — framing, authority rewriting,
//!   independent per-direction half-close, and drop-and-close backpressure.
//! - [`proxy`]: the per-device reactor [`Handler`](crate::reactor::Handler) that accepts clients, opens
//!   egress-pinned device connections, and owns a pool of them.
//! - [`rewrite`]: the SSDP-side entry — [`rewrite_location`] rewrites a DIAL discovery message's
//!   `LOCATION` to a source-side proxy, minting and registering one on demand.
//!
//! The proxy's lifetime (eviction once the advertisement grace lapses) is owned by the
//! [`DialContext`](crate::dispatch::DialContext) registry, not the proxy itself, since the proxy never
//! sees the advertisements that refresh it.

mod connection;
mod proxy;
mod rewrite;

pub(crate) use self::rewrite::{ProxyPlacement, REWRITE_BUF_LEN, rewrite_location};
