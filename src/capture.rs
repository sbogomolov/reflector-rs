//! Raw L2 packet capture: a per-interface handle the reactor can poll.
//!
//! One backend per platform behind a uniform `Capture` — BPF on macOS/FreeBSD,
//! `AF_PACKET` on Linux. The handle owns a pollable fd, reads link-layer frames
//! into a reused buffer (no per-frame allocation), and injects built frames. Each
//! backend exposes the same surface (`open` / `next_frame` / `has_buffered` /
//! `send` / `link_type` / `AsRawFd`); the facade re-exports the platform `Capture`
//! once a consumer (the reactor handler) is wired.

mod filter;

#[cfg(target_os = "linux")]
mod af_packet;
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
mod bpf;

/// The link-layer framing a `Capture` reports for its interface. It selects the
/// capture filter and tells a consumer how to strip the link header before parsing
/// L3: a 14-byte Ethernet header, or — on BSD — `DLT_NULL`'s 4-byte host-order
/// address family (loopback/tunnel interfaces), then the IP packet. Linux frames
/// every interface, loopback included, as Ethernet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinkType {
    Ethernet,
    #[cfg(any(target_os = "macos", target_os = "freebsd"))]
    DltNull,
}

// The platform `Capture` under one name, so the shared test helper and tests below
// need not name the backend. Test-only for now; the reactor handler will promote
// this to a real `pub(crate)` re-export once it consumes `Capture`.
#[cfg(all(test, target_os = "linux"))]
use self::af_packet::Capture;
#[cfg(all(test, any(target_os = "macos", target_os = "freebsd")))]
use self::bpf::Capture;

/// Open a capture on `if_name`, returning `Ok(None)` (and noting why) when the host
/// can't — no BPF access / `CAP_NET_RAW`, or the interface is absent. A real error
/// is returned for the caller to propagate with `?`. Shared by the backend tests and
/// the live test below.
#[cfg(test)]
fn open_or_skip(if_name: &str, what: &str) -> std::io::Result<Option<Capture>> {
    match Capture::open(if_name) {
        Ok(capture) => Ok(Some(capture)),
        Err(e)
            if matches!(
                e.kind(),
                std::io::ErrorKind::PermissionDenied | std::io::ErrorKind::NotFound
            ) || e.raw_os_error() == Some(libc::EACCES)
                || e.raw_os_error() == Some(libc::EPERM) =>
        {
            eprintln!("skip {what}: cannot capture on {if_name} ({e})");
            Ok(None)
        }
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::{LinkType, open_or_skip};

    // Live capture against a real interface (`REFLECTOR_TEST_IFACE`) — backend-neutral
    // because a real interface is Ethernet-framed on both backends (BPF reports
    // DLT_EN10MB, AF_PACKET delivers the Ethernet header). Validates the open/filter/
    // recv path and the frame layout; skips when the env var is unset or capture isn't
    // permitted.
    #[test]
    fn live_capture_decodes_real_frames() -> std::io::Result<()> {
        let Some(iface) = std::env::var_os("REFLECTOR_TEST_IFACE") else {
            eprintln!("skip live_capture: set REFLECTOR_TEST_IFACE to an Ethernet interface");
            return Ok(());
        };
        let iface = iface.to_string_lossy();
        let Some(mut capture) = open_or_skip(&iface, "live_capture")? else {
            return Ok(());
        };
        assert_eq!(capture.link_type(), LinkType::Ethernet);

        // Poll briefly for ambient UDP traffic and validate each frame's layout: every
        // frame the kernel filter passed must be an IPv4/IPv6 Ethernet frame, so a
        // mis-sliced header would corrupt these.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut validated = 0u32;
        while validated < 8 && std::time::Instant::now() < deadline {
            match capture.next_frame()? {
                Some(frame) => {
                    assert!(frame.len() >= 14, "frame shorter than an Ethernet header");
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    assert!(
                        ethertype == 0x0800 || ethertype == 0x86dd,
                        "filter passed a non-IP ethertype {ethertype:#06x}",
                    );
                    validated += 1;
                }
                None => std::thread::sleep(std::time::Duration::from_millis(50)),
            }
        }
        eprintln!("live_capture: validated {validated} frame(s) on {iface}");
        Ok(())
    }
}
