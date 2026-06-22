//! Classic-BPF filter programs.
//!
//! The instruction encoding is shared between Linux (`SO_ATTACH_FILTER`) and the
//! BSD BPF device (`BIOCSETF`): [`BpfInsn`] is layout-identical to libc's
//! `sock_filter` and `bpf_insn`, so the same array installs on either backend.

/// One classic-BPF instruction (`{ u16 code; u8 jt; u8 jf; u32 k }`).
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct BpfInsn {
    pub(crate) code: u16,
    pub(crate) jt: u8,
    pub(crate) jf: u8,
    pub(crate) k: u32,
}

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
