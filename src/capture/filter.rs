//! Classic-BPF filter programs.
//!
//! The instruction encoding is shared between Linux (`SO_ATTACH_FILTER`) and the
//! BSD BPF device (`BIOCSETF`): [`BpfInsn`] is layout-identical to libc's
//! `sock_filter` and `bpf_insn`, so the same array installs on either backend.

/// One classic-BPF instruction (`{ u16 code; u8 jt; u8 jf; u32 k }`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BpfInsn {
    pub(crate) code: u16,
    pub(crate) jt: u8,
    pub(crate) jf: u8,
    pub(crate) k: u32,
}

// On Linux the same array installs via `SO_ATTACH_FILTER` as a `sock_filter`
// program; anchor the layout to libc where it provides the type.
#[cfg(target_os = "linux")]
const _: () = assert!(size_of::<BpfInsn>() == size_of::<libc::sock_filter>());

const fn insn(code: u16, jt: u8, jf: u8, k: u32) -> BpfInsn {
    BpfInsn { code, jt, jf, k }
}

/// Accept IPv4 UDP or IPv6 UDP on an Ethernet link, drop everything else
/// in-kernel (no VLAN tags, no IPv6 extension headers). Direction filtering
/// (loop prevention) is layered on per-backend (`BIOCSSEESENT` on BPF), not
/// encoded here.
///
/// ```text
/// ldh [12]                 load ethertype
/// jeq 0x0800 -> IPv4@5     else fall through
/// jeq 0x86dd -> IPv6 fall  else drop@8
/// ldb [20]                 IPv6 next-header
/// jeq 17     -> accept@7   else drop@8
/// ldb [23]                 IPv4 protocol
/// jeq 17     -> accept@7   else drop@8
/// ret 0xffffffff           accept
/// ret 0                    drop
/// ```
pub(crate) const ETHERNET_UDP_FILTER: [BpfInsn; 9] = [
    insn(0x0028, 0, 0, 0x0000_000c), // BPF_LD|BPF_H|BPF_ABS  [12] ethertype
    insn(0x0015, 3, 0, 0x0000_0800), // BPF_JMP|BPF_JEQ|BPF_K 0x0800 IPv4
    insn(0x0015, 0, 5, 0x0000_86dd), // BPF_JMP|BPF_JEQ|BPF_K 0x86dd IPv6
    insn(0x0030, 0, 0, 0x0000_0014), // BPF_LD|BPF_B|BPF_ABS  [20] IPv6 next-header
    insn(0x0015, 2, 3, 0x0000_0011), // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0030, 0, 0, 0x0000_0017), // BPF_LD|BPF_B|BPF_ABS  [23] IPv4 protocol
    insn(0x0015, 0, 1, 0x0000_0011), // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0006, 0, 0, 0xffff_ffff), // BPF_RET|BPF_K accept
    insn(0x0006, 0, 0, 0x0000_0000), // BPF_RET|BPF_K drop
];

/// Prepended to [`ETHERNET_UDP_FILTER`] on Linux kernels without
/// `PACKET_IGNORE_OUTGOING`: the `SKF_AD_PKTTYPE` ancillary load reads
/// `skb->pkt_type`, and frames we sent (`PACKET_OUTGOING`) are dropped — so the
/// capture socket never re-receives its own injections.
///
/// ```text
/// ldb #pkttype                  skb->pkt_type via the ancillary offset
/// jeq PACKET_OUTGOING -> drop@2    else fall through to the classifier
/// ret 0                         drop
/// ```
#[cfg(target_os = "linux")]
pub(crate) const DROP_OUTGOING_PROLOGUE: [BpfInsn; 3] = [
    // BPF_LD|BPF_B|BPF_ABS: A = pkt_type, from the negative ancillary offset.
    insn(
        0x0030,
        0,
        0,
        (libc::SKF_AD_OFF + libc::SKF_AD_PKTTYPE).cast_unsigned(),
    ),
    // Our TX (PACKET_OUTGOING): jt=0 -> drop; else jf=1 -> the classifier below.
    // (`u32::from` isn't const-stable, so widen the u8 constant with `as`.)
    insn(0x0015, 0, 1, libc::PACKET_OUTGOING as u32),
    insn(0x0006, 0, 0, 0x0000_0000), // BPF_RET|BPF_K drop
];

/// Convert a host-order address family to the value a `BPF_LD|BPF_W|BPF_ABS` load
/// compares against. The classic-BPF VM assembles a loaded word big-endian
/// regardless of host, but a `DLT_NULL` frame stores the family in host order — so
/// on a little-endian host the `jeq` constant is the byte-swapped family, and on a
/// big-endian host it is the family unchanged (load and data already agree).
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
const fn host_af_to_bpf_be(af: libc::c_int) -> u32 {
    af.cast_unsigned().to_be()
}

/// Accept IPv4 UDP or IPv6 UDP on a `DLT_NULL` link (BSD `lo0`), drop
/// everything else in-kernel. The link header is a 4-byte host-order address
/// family, then the IP packet — so the field offsets differ from Ethernet's.
///
/// ```text
/// ld  [0]                  load the 4-byte address family
/// jeq AF_INET  -> IPv4@5   else fall through
/// jeq AF_INET6 -> IPv6 fall  else drop@8
/// ldb [10]                 IPv6 next-header (4 + 6)
/// jeq 17       -> accept@7   else drop@8
/// ldb [13]                 IPv4 protocol (4 + 9)
/// jeq 17       -> accept@7   else drop@8
/// ret 0xffffffff           accept
/// ret 0                    drop
/// ```
#[cfg(any(target_os = "macos", target_os = "freebsd"))]
pub(crate) const DLT_NULL_UDP_FILTER: [BpfInsn; 9] = [
    insn(0x0020, 0, 0, 0x0000_0000), // BPF_LD|BPF_W|BPF_ABS  [0] address family
    insn(0x0015, 3, 0, host_af_to_bpf_be(libc::AF_INET)), // BPF_JMP|BPF_JEQ|BPF_K AF_INET
    insn(0x0015, 0, 5, host_af_to_bpf_be(libc::AF_INET6)), // BPF_JMP|BPF_JEQ|BPF_K AF_INET6
    insn(0x0030, 0, 0, 0x0000_000a), // BPF_LD|BPF_B|BPF_ABS  [10] IPv6 next-header
    insn(0x0015, 2, 3, 0x0000_0011), // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0030, 0, 0, 0x0000_000d), // BPF_LD|BPF_B|BPF_ABS  [13] IPv4 protocol
    insn(0x0015, 0, 1, 0x0000_0011), // BPF_JMP|BPF_JEQ|BPF_K 17 UDP
    insn(0x0006, 0, 0, 0xffff_ffff), // BPF_RET|BPF_K accept
    insn(0x0006, 0, 0, 0x0000_0000), // BPF_RET|BPF_K drop
];

#[cfg(all(test, any(target_os = "macos", target_os = "freebsd")))]
mod tests {
    use super::*;

    #[test]
    fn dlt_null_family_constants_match_a_bpf_word_load() {
        // The DLT_NULL frame stores the family in host byte order; the BPF VM loads
        // that word big-endian. The filter's jeq constant must equal that view, or
        // it matches no frame at all.
        for af in [libc::AF_INET, libc::AF_INET6] {
            let as_the_vm_loads_it = u32::from_be_bytes(af.cast_unsigned().to_ne_bytes());
            assert_eq!(host_af_to_bpf_be(af), as_the_vm_loads_it);
        }
    }
}
