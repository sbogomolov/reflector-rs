//! BPF packet capture (macOS; FreeBSD to follow).
//!
//! Opens `/dev/bpfN`, binds it to an interface, installs a UDP-only classic-BPF
//! filter, and reads link-layer frames. One `read` returns a *batch* of frames,
//! each prefixed by a variable-length [`BpfHdr`] and padded so the next record
//! starts on a `BPF_ALIGNMENT` boundary; [`Capture::next_frame`] walks that batch.
//!
//! Init order matters: bind (`BIOCSETIF`) happens *before* the filter
//! (`BIOCSETF`), which is safe only because `BIOCSETF` flushes the kernel buffer
//! — so the brief pre-filter window leaves nothing behind. (Linux's
//! `SO_ATTACH_FILTER` does not flush, so its backend filters before bind instead.)

use std::io;
use std::ops::Range;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use libc::{c_uint, c_ulong, c_void};

use super::filter::{BpfInsn, ETHERNET_UDP_FILTER};

// --- ioctl request encoding (4.4BSD <sys/ioccom.h>; macOS and FreeBSD) -------
const IOC_OUT: c_ulong = 0x4000_0000; // copies out (kernel -> user)
const IOC_IN: c_ulong = 0x8000_0000; // copies in (user -> kernel)
const IOCPARM_MASK: c_ulong = 0x1fff;

const fn ioc(inout: c_ulong, group: u8, num: u8, len: usize) -> c_ulong {
    inout | (((len as c_ulong) & IOCPARM_MASK) << 16) | ((group as c_ulong) << 8) | num as c_ulong
}
const fn iow(group: u8, num: u8, len: usize) -> c_ulong {
    ioc(IOC_IN, group, num, len)
}
const fn ior(group: u8, num: u8, len: usize) -> c_ulong {
    ioc(IOC_OUT, group, num, len)
}

// Anchor the encoding to values libc provides as ground truth: if a direction
// bit or the field arithmetic were wrong, these fail to compile. BIOCSSEESENT
// pins the IOC_IN (`iow`) path, BIOCGSEESENT the IOC_OUT (`ior`) path.
const _: () = assert!(iow(b'B', 119, size_of::<c_uint>()) == libc::BIOCSSEESENT);
const _: () = assert!(ior(b'B', 118, size_of::<c_uint>()) == libc::BIOCGSEESENT);

const BIOCGBLEN: c_ulong = ior(b'B', 102, size_of::<c_uint>());
const BIOCSETF: c_ulong = iow(b'B', 103, size_of::<BpfProgram>());
const BIOCGDLT: c_ulong = ior(b'B', 106, size_of::<c_uint>());
const BIOCSETIF: c_ulong = iow(b'B', 108, size_of::<libc::ifreq>());
const BIOCIMMEDIATE: c_ulong = iow(b'B', 112, size_of::<c_uint>());
// BIOCSSEESENT is provided by libc.

/// `struct bpf_program` — the filter handed to `BIOCSETF`.
#[repr(C)]
struct BpfProgram {
    bf_len: c_uint,
    bf_insns: *mut BpfInsn,
}

/// The per-record header BPF prefixes each frame with. On 64-bit macOS the
/// timestamp here is 32-bit (a `timeval32`), not the native `timeval`; the field
/// widths set the offsets of the fields we actually read. The `bh_` prefix
/// mirrors the C struct, so allow the field-naming lint.
#[repr(C)]
#[allow(clippy::struct_field_names)]
struct BpfHdr {
    bh_tstamp_sec: i32,
    bh_tstamp_usec: i32,
    bh_caplen: u32,  // bytes captured into the buffer
    bh_datalen: u32, // the frame's original length (caplen < datalen => truncated)
    bh_hdrlen: u16,  // offset from the record start to the packet bytes
}

const fn bpf_wordalign(x: usize) -> usize {
    let align = libc::BPF_ALIGNMENT as usize;
    (x + (align - 1)) & !(align - 1)
}

/// A raw-capture handle on one interface: an owned BPF fd plus a reused read
/// buffer and a cursor over the current batch.
pub(crate) struct Capture {
    fd: OwnedFd,
    buf: Box<[u8]>,
    filled: usize,
    offset: usize,
}

impl Capture {
    /// Open a BPF capture bound to `if_name`.
    ///
    /// # Errors
    /// Returns an error if no BPF device is available, the interface can't be
    /// bound, the link type isn't Ethernet (`DLT_NULL` loopback isn't supported
    /// yet), or any setup ioctl fails.
    pub(crate) fn open(if_name: &str) -> io::Result<Self> {
        let fd = open_bpf_device()?;

        // Bind to the interface. Capture begins here; the filter installed below
        // flushes the buffer, so nothing slips through unfiltered.
        // SAFETY: all-zero is a valid `ifreq` — `ifr_name` is a byte array and the
        // `ifr_ifru` union holds only integers/pointers/sockaddr, none with an
        // invalid zero bit pattern.
        let mut ifr: libc::ifreq = unsafe { core::mem::zeroed() };
        let name = if_name.as_bytes();
        if name.len() >= ifr.ifr_name.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "interface name too long",
            ));
        }
        // SAFETY: `ifr_name` is a `[c_char; IFNAMSIZ]`; we checked `name` fits with
        // room for the zero terminator the zeroed `ifr` already provides.
        unsafe {
            std::ptr::copy_nonoverlapping(
                name.as_ptr(),
                ifr.ifr_name.as_mut_ptr().cast::<u8>(),
                name.len(),
            );
        }
        ioctl(&fd, BIOCSETIF, (&raw mut ifr).cast())?;

        // Require Ethernet; DLT_NULL loopback (a different header + filter) is deferred.
        let mut dlt: c_uint = 0;
        ioctl(&fd, BIOCGDLT, (&raw mut dlt).cast())?;
        if dlt != libc::DLT_EN10MB {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!(
                    "BPF link type {dlt} unsupported (need DLT_EN10MB; loopback not yet supported)"
                ),
            ));
        }

        // Deliver each frame as it arrives instead of blocking until the buffer fills.
        let mut immediate: c_uint = 1;
        ioctl(&fd, BIOCIMMEDIATE, (&raw mut immediate).cast())?;

        // Don't hand us our own injected frames (loop prevention between mirrored
        // reflector pairs).
        let mut see_sent: c_uint = 0;
        ioctl(&fd, libc::BIOCSSEESENT, (&raw mut see_sent).cast())?;

        // Install the UDP filter (and flush whatever queued before it).
        let filter = ETHERNET_UDP_FILTER;
        let mut program = BpfProgram {
            bf_len: c_uint::try_from(filter.len()).expect("filter length fits c_uint"),
            bf_insns: filter.as_ptr().cast_mut(),
        };
        ioctl(&fd, BIOCSETF, (&raw mut program).cast())?;

        // Size the read buffer to the kernel's preferred BPF buffer length.
        let mut blen: c_uint = 0;
        ioctl(&fd, BIOCGBLEN, (&raw mut blen).cast())?;

        set_nonblocking(&fd)?;

        log::debug!(
            "opened BPF capture on {if_name} (fd {}, {blen}-byte buffer)",
            fd.as_raw_fd()
        );
        Ok(Self {
            fd,
            buf: vec![0u8; blen as usize].into_boxed_slice(),
            filled: 0,
            offset: 0,
        })
    }

    /// The next captured frame, refilling from the kernel when the current batch
    /// is drained. Returns `Ok(None)` when nothing more is ready (the batch is
    /// empty and a read would block). Truncated/oversized records are skipped.
    ///
    /// # Errors
    /// Returns an error if the read fails, or the kernel batch is malformed (the
    /// rest of that batch is then abandoned).
    pub(crate) fn next_frame(&mut self) -> io::Result<Option<&[u8]>> {
        let range = loop {
            if self.offset >= self.filled && !self.refill()? {
                return Ok(None);
            }
            let start = self.offset;
            let (record, advance) = match parse_record(&self.buf[start..self.filled]) {
                Ok(parsed) => parsed,
                Err(e) => {
                    self.offset = self.filled; // abandon the malformed batch
                    return Err(e);
                }
            };
            self.offset = start + advance;
            match record {
                Record::Frame(frame) => break (start + frame.start)..(start + frame.end),
                Record::Oversized { datalen } => log::warn!(
                    "dropping oversized frame: {datalen} bytes exceeds the {}-byte capture buffer",
                    self.buf.len()
                ),
            }
        };
        Ok(Some(&self.buf[range]))
    }

    /// Whether the current batch still holds unread records — the cue to keep
    /// draining, since a level-triggered wait won't re-fire until new kernel data.
    pub(crate) fn has_buffered(&self) -> bool {
        self.offset < self.filled
    }

    /// Inject a fully-built link-layer `frame` on this interface.
    ///
    /// # Errors
    /// Returns an error if the write fails or is short.
    pub(crate) fn send(&self, frame: &[u8]) -> io::Result<()> {
        // SAFETY: `frame` is a valid readable slice; the BPF fd accepts full frames.
        let written =
            unsafe { libc::write(self.fd.as_raw_fd(), frame.as_ptr().cast(), frame.len()) };
        if written < 0 {
            return Err(io::Error::last_os_error());
        }
        if usize::try_from(written).expect("write result is non-negative") != frame.len() {
            return Err(io::Error::other("short write to BPF device"));
        }
        Ok(())
    }

    /// Read one kernel batch into `buf`. Returns `false` if nothing is available
    /// (would block) or the device reported EOF.
    fn refill(&mut self) -> io::Result<bool> {
        let bytes = loop {
            // SAFETY: writing up to `buf.len()` bytes into our own buffer.
            let n = unsafe {
                libc::read(
                    self.fd.as_raw_fd(),
                    self.buf.as_mut_ptr().cast(),
                    self.buf.len(),
                )
            };
            if n >= 0 {
                break usize::try_from(n).expect("read result is non-negative");
            }
            let err = io::Error::last_os_error();
            let errno = err.raw_os_error();
            if errno == Some(libc::EINTR) {
                continue;
            }
            if errno == Some(libc::EAGAIN) || errno == Some(libc::EWOULDBLOCK) {
                return Ok(false);
            }
            return Err(err);
        };
        if bytes == 0 {
            return Ok(false);
        }
        self.filled = bytes;
        self.offset = 0;
        Ok(true)
    }
}

impl AsRawFd for Capture {
    fn as_raw_fd(&self) -> RawFd {
        self.fd.as_raw_fd()
    }
}

/// Outcome of parsing one BPF record: a good frame's byte range, or an oversized
/// capture to drop (carrying its original length, for the warning).
enum Record {
    Frame(Range<usize>),
    Oversized { datalen: u32 },
}

/// Parse the BPF record at the front of `record` — the still-unread slice of the
/// current batch — returning it plus how many bytes to advance past it (its
/// `BpfHdr` + frame, padded to `BPF_ALIGNMENT`). The frame range is relative to
/// `record`. Pure (no I/O) so the batch walk — the fiddliest part — is
/// unit-testable against synthetic buffers.
fn parse_record(record: &[u8]) -> io::Result<(Record, usize)> {
    if size_of::<BpfHdr>() > record.len() {
        return Err(io::Error::other("BPF batch ended mid-header"));
    }
    // SAFETY: the bound above keeps the header within `record`; `BpfHdr` is plain
    // repr(C) data and `read_unaligned` tolerates any record alignment.
    let header = unsafe { record.as_ptr().cast::<BpfHdr>().read_unaligned() };

    let frame_start = header.bh_hdrlen as usize;
    let frame_end = frame_start + header.bh_caplen as usize;
    if frame_end > record.len() {
        return Err(io::Error::other("BPF frame extends past batch end"));
    }
    let advance = bpf_wordalign(frame_end);
    if advance == 0 {
        // A record that doesn't advance would stall the drain loop forever. The
        // kernel never emits one (bh_hdrlen is always >= the header size), so
        // treat it as a malformed batch.
        return Err(io::Error::other("BPF record did not advance"));
    }

    if header.bh_datalen > header.bh_caplen {
        // Captured fewer bytes than the frame's real length; don't parse a partial frame.
        return Ok((
            Record::Oversized {
                datalen: header.bh_datalen,
            },
            advance,
        ));
    }
    Ok((Record::Frame(frame_start..frame_end), advance))
}

/// Open the first available `/dev/bpfN`.
fn open_bpf_device() -> io::Result<OwnedFd> {
    for n in 0..256 {
        let path = format!("/dev/bpf{n}\0");
        // SAFETY: `path` is NUL-terminated.
        let raw = unsafe { libc::open(path.as_ptr().cast(), libc::O_RDWR) };
        if raw >= 0 {
            // SAFETY: `open` returned a fresh owned fd.
            return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
        }
        // EBUSY just means this device is taken; try the next. Anything else is real.
        if io::Error::last_os_error().raw_os_error() != Some(libc::EBUSY) {
            return Err(io::Error::last_os_error());
        }
    }
    Err(io::Error::other("all /dev/bpf devices are busy"))
}

/// Set `O_NONBLOCK` on `fd`.
fn set_nonblocking(fd: &OwnedFd) -> io::Result<()> {
    let raw = fd.as_raw_fd();
    // SAFETY: `fd` is valid; F_GETFL returns the current status flags.
    let flags = unsafe { libc::fcntl(raw, libc::F_GETFL) };
    if flags < 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: `fd` is valid; F_SETFL writes the status flags.
    if unsafe { libc::fcntl(raw, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// One `ioctl` with a typed-but-opaque argument pointer, mapping failure to an error.
fn ioctl(fd: &OwnedFd, request: c_ulong, arg: *mut c_void) -> io::Result<()> {
    // SAFETY: `request` matches `arg`'s type per the BIOC* definitions; `fd` is valid.
    if unsafe { libc::ioctl(fd.as_raw_fd(), request, arg) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::mem::offset_of;

    use super::*;

    /// Append one synthetic BPF record (header + frame + word-align padding) to
    /// `batch`. Serializes the header field-by-field at its repr(C) offsets rather
    /// than transmuting a `BpfHdr` (whose tail padding would be uninitialized).
    fn push_record(batch: &mut Vec<u8>, caplen: u32, datalen: u32, fill: u8) {
        let hdrlen = u16::try_from(size_of::<BpfHdr>()).expect("header fits u16");
        let mut header = [0u8; size_of::<BpfHdr>()];
        header[offset_of!(BpfHdr, bh_caplen)..][..4].copy_from_slice(&caplen.to_ne_bytes());
        header[offset_of!(BpfHdr, bh_datalen)..][..4].copy_from_slice(&datalen.to_ne_bytes());
        header[offset_of!(BpfHdr, bh_hdrlen)..][..2].copy_from_slice(&hdrlen.to_ne_bytes());
        batch.extend_from_slice(&header);
        batch.extend(std::iter::repeat_n(fill, caplen as usize));
        while !batch.len().is_multiple_of(libc::BPF_ALIGNMENT as usize) {
            batch.push(0);
        }
    }

    #[test]
    fn wordalign_rounds_up_to_alignment() {
        assert_eq!(bpf_wordalign(0), 0);
        assert_eq!(bpf_wordalign(1), 4);
        assert_eq!(bpf_wordalign(4), 4);
        assert_eq!(bpf_wordalign(5), 8);
    }

    #[test]
    fn walks_a_multi_frame_batch() {
        let mut batch = Vec::new();
        push_record(&mut batch, 3, 3, 0xaa); // frame 1: 3 bytes of 0xaa
        push_record(&mut batch, 5, 5, 0xbb); // frame 2: 5 bytes of 0xbb (after padding)
        push_record(&mut batch, 1, 1, 0xcc); // frame 3: 1 byte of 0xcc

        let mut offset = 0;
        let mut frames: Vec<Vec<u8>> = Vec::new();
        while offset < batch.len() {
            let (record, advance) = parse_record(&batch[offset..]).unwrap();
            if let Record::Frame(frame) = record {
                frames.push(batch[offset + frame.start..offset + frame.end].to_vec());
            }
            offset += advance;
        }
        assert_eq!(frames, vec![vec![0xaa; 3], vec![0xbb; 5], vec![0xcc; 1]]);
    }

    #[test]
    fn skips_a_truncated_record() {
        let mut batch = Vec::new();
        push_record(&mut batch, 4, 9, 0xaa); // captured 4 of a 9-byte frame -> skip
        push_record(&mut batch, 2, 2, 0xbb); // good frame after it

        let (first, advance) = parse_record(&batch).unwrap();
        assert!(matches!(first, Record::Oversized { .. }));
        let (second, _) = parse_record(&batch[advance..]).unwrap();
        match second {
            Record::Frame(frame) => {
                assert_eq!(
                    &batch[advance + frame.start..advance + frame.end],
                    &[0xbb, 0xbb]
                );
            }
            Record::Oversized { .. } => panic!("second record should be a frame"),
        }
    }

    #[test]
    fn rejects_a_header_past_the_batch_end() {
        let batch = vec![0u8; size_of::<BpfHdr>() - 1];
        assert!(parse_record(&batch).is_err());
    }

    #[test]
    fn rejects_a_non_advancing_record() {
        // bh_hdrlen == 0 && bh_caplen == 0 would leave the cursor in place and spin
        // the drain loop; parse_record must reject it instead.
        let mut batch = [0u8; size_of::<BpfHdr>()];
        batch[offset_of!(BpfHdr, bh_datalen)..][..4].copy_from_slice(&1u32.to_ne_bytes());
        assert!(parse_record(&batch).is_err());
    }

    // Live capture against the real kernel — validates the ioctl sequence and that
    // the BpfHdr layout matches what the kernel writes (the synthetic tests only
    // check the walk against our own layout). Dynamically skips when BPF is
    // unavailable (no access, or REFLECTOR_TEST_IFACE unset); fails on real errors.
    #[test]
    fn live_capture_decodes_real_frames() {
        let Some(iface) = std::env::var_os("REFLECTOR_TEST_IFACE") else {
            eprintln!("skip live_capture: set REFLECTOR_TEST_IFACE to an Ethernet interface");
            return;
        };
        let iface = iface.to_string_lossy();
        let mut capture = match Capture::open(&iface) {
            Ok(capture) => capture,
            Err(e)
                if e.kind() == io::ErrorKind::PermissionDenied
                    || e.raw_os_error() == Some(libc::EACCES) =>
            {
                eprintln!("skip live_capture: no BPF access ({e})");
                return;
            }
            Err(e) => panic!("Capture::open({iface}) failed: {e}"),
        };

        // Poll briefly for ambient UDP traffic and validate each frame's layout:
        // every frame the kernel filter passed must be an IPv4/IPv6 Ethernet frame,
        // so a wrong `BpfHdr` layout (mis-sliced offsets) would corrupt these.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
        let mut validated = 0u32;
        while validated < 8 && std::time::Instant::now() < deadline {
            match capture.next_frame() {
                Ok(Some(frame)) => {
                    assert!(frame.len() >= 14, "frame shorter than an Ethernet header");
                    let ethertype = u16::from_be_bytes([frame[12], frame[13]]);
                    assert!(
                        ethertype == 0x0800 || ethertype == 0x86dd,
                        "filter passed a non-IP ethertype {ethertype:#06x}",
                    );
                    validated += 1;
                }
                Ok(None) => std::thread::sleep(std::time::Duration::from_millis(50)),
                Err(e) => panic!("next_frame failed: {e}"),
            }
        }
        eprintln!("live_capture: validated {validated} frame(s) on {iface}");
    }
}
