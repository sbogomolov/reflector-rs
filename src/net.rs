//! The wire layer: everything that touches on-the-wire packet formats —
//! IP/UDP checksums and frame building today, MAC addressing and raw capture to
//! come.

mod checksum;
pub(crate) mod frame;
pub(crate) mod mac;

/// IANA protocol number for UDP.
const IP_PROTO_UDP: u8 = 17;
