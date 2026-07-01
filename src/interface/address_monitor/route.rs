//! macOS/FreeBSD: a `PF_ROUTE` socket delivers routing messages; the address and link ones
//! carry the affected interface's index. We read only that index, at its fixed offset in the
//! message — the same "trust the offset, not the whole libc struct" approach as
//! [`super::super::getifaddrs`]'s MAC read, since the `ifa_msghdr`/`if_msghdr` tails diverge
//! across the BSDs.

use std::io;
#[cfg(target_os = "macos")]
use std::os::fd::AsRawFd;
use std::os::fd::OwnedFd;

use libc::c_int;

/// Holds one routing message: a fixed header plus a few small sockaddrs (the `RTAX_*` slots),
/// a few hundred bytes — none of Linux rtnetlink's attribute lists, so smaller than the
/// `rtnetlink` backend's 8 KiB suffices.
pub(super) const READ_BUF: usize = 2048;

/// `ifam_index` (in `ifa_msghdr`) and `ifm_index` (in `if_msghdr`) are both a `u16` at this
/// offset; the asserts pin it against the libc layout.
const INDEX_OFFSET: usize = 12;
const _: () = assert!(std::mem::offset_of!(libc::ifa_msghdr, ifam_index) == INDEX_OFFSET);
const _: () = assert!(std::mem::offset_of!(libc::if_msghdr, ifm_index) == INDEX_OFFSET);

/// Open a `PF_ROUTE` socket, non-blocking + close-on-exec.
pub(super) fn open() -> io::Result<OwnedFd> {
    // FreeBSD accepts CLOEXEC|NONBLOCK in the socket type; macOS needs a follow-up fcntl.
    #[cfg(target_os = "freebsd")]
    let socktype = libc::SOCK_RAW | libc::SOCK_CLOEXEC | libc::SOCK_NONBLOCK;
    #[cfg(target_os = "macos")]
    let socktype = libc::SOCK_RAW;
    // SAFETY: `socket` returns a fresh fd or -1.
    let sock = crate::sys::owned_fd_from(unsafe { libc::socket(libc::PF_ROUTE, socktype, 0) })?;
    // macOS lacks the `SOCK_*` type-arg flags, so apply close-on-exec + non-blocking by fcntl.
    #[cfg(target_os = "macos")]
    crate::sys::set_cloexec_nonblock(sock.as_raw_fd())?;
    Ok(sock)
}

/// Walk every routing message in `buf`; report the interface index of each `RTM_NEWADDR` /
/// `RTM_DELADDR` (address change) and `RTM_IFINFO` (link/MAC change). Every routing message
/// begins with `u16 msglen; u8 version; u8 type`.
pub(super) fn for_each_change(buf: &[u8], on_change: &mut impl FnMut(u32)) {
    let mut offset = 0;
    while offset + 4 <= buf.len() {
        let msglen = usize::from(u16::from_ne_bytes([buf[offset], buf[offset + 1]]));
        let msg_type = c_int::from(buf[offset + 3]);
        if msglen < 4 || offset + msglen > buf.len() {
            // Not a normal end (that's the `while` running out): a message claims a length
            // that's impossible — truncated datagram or corruption — so a change is dropped.
            log::warn!(
                "routing message walk stopped at offset {offset}: msglen {msglen}, buffer {} B \
                 (truncated or malformed); a change may be missed",
                buf.len()
            );
            break;
        }
        if matches!(
            msg_type,
            libc::RTM_NEWADDR | libc::RTM_DELADDR | libc::RTM_IFINFO
        ) && msglen >= INDEX_OFFSET + 2
        {
            let index =
                u16::from_ne_bytes([buf[offset + INDEX_OFFSET], buf[offset + INDEX_OFFSET + 1]]);
            // 0 names no interface (kernel indices are >= 1) and is the parent's "re-resolve
            // everything" overflow signal, so a stray 0 must never be forwarded.
            if index != 0 {
                log::trace!("address monitor: change for ifindex {index}");
                on_change(u32::from(index));
            }
        }
        offset += msglen;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A routing message of `msglen` bytes: header (msglen, type) plus `index` at its fixed
    /// offset, the rest zero.
    fn message(msg_type: c_int, index: u16, msglen: usize) -> Vec<u8> {
        let mut m = vec![0u8; msglen];
        m[0..2].copy_from_slice(
            &u16::try_from(msglen)
                .expect("test msglen fits u16")
                .to_ne_bytes(),
        );
        m[3] = u8::try_from(msg_type).expect("test rtm_type fits u8");
        m[INDEX_OFFSET..INDEX_OFFSET + 2].copy_from_slice(&index.to_ne_bytes());
        m
    }

    #[test]
    fn reports_index_of_address_and_link_messages() {
        let mut buf = message(libc::RTM_NEWADDR, 7, 20);
        buf.extend(message(libc::RTM_IFINFO, 9, 24));
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert_eq!(seen, [7, 9]);
    }

    #[test]
    fn ignores_unsubscribed_types() {
        // RTM_ADD (a route was added) is neither an address nor a link change.
        let buf = message(libc::RTM_ADD, 5, 20);
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert!(seen.is_empty());
    }

    #[test]
    fn ignores_message_too_short_for_the_index() {
        // A subscribed type whose length stops before the index field (offset 12) must not
        // be read past. Built by hand: the helper would write an index this message can't hold.
        let mut buf = vec![0u8; INDEX_OFFSET];
        buf[0..2].copy_from_slice(&u16::try_from(INDEX_OFFSET).unwrap().to_ne_bytes());
        buf[3] = u8::try_from(libc::RTM_NEWADDR).unwrap();
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert!(seen.is_empty());
    }

    #[test]
    fn never_forwards_index_zero() {
        // 0 names no interface and is the parent's overflow sentinel, so a message carrying it
        // must not be reported (which would trigger a spurious re-resolve of everything).
        let buf = message(libc::RTM_NEWADDR, 0, 20);
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert!(seen.is_empty());
    }

    #[test]
    fn stops_at_a_message_claiming_a_length_past_the_buffer() {
        let mut buf = message(libc::RTM_NEWADDR, 7, 20);
        buf[0..2].copy_from_slice(&9999u16.to_ne_bytes()); // msglen past the datagram
        let mut seen = Vec::new();
        for_each_change(&buf, &mut |i| seen.push(i));
        assert!(seen.is_empty());
    }
}
