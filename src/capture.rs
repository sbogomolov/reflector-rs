//! Raw L2 packet capture: a per-interface handle the reactor can poll.
//!
//! One backend per platform behind a uniform `Capture` — BPF on macOS/FreeBSD,
//! `AF_PACKET` on Linux. The handle owns a pollable fd, reads link-layer frames
//! into a reused buffer (no per-frame allocation), and injects built frames.
//! The BPF backend covers macOS/FreeBSD; the Linux `AF_PACKET` backend follows.
//! The facade re-exports the platform `Capture` once a consumer (the reactor
//! handler) is wired.

mod filter;

#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bpf;
