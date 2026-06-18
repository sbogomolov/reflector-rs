//! ruflector — reflects link-local service traffic (Wake-on-LAN, mDNS, SSDP,
//! and an optional DIAL proxy) between two network interfaces.
//!
//! The behavior lives in this library crate so it stays testable in-process;
//! the binary (`src/main.rs`) is a thin shim over [`run`].

pub mod config;
mod error;

pub use error::{Error, Result};

use config::Config;

/// Run the reflector to completion.
///
/// `args` is the process argument list with argv[0] already stripped. The first
/// argument, if present, is a TOML config path; `REFLECTOR_*` environment
/// variables are merged on top (and can configure reflectors on their own).
///
/// # Errors
/// Returns [`Error`] if configuration loading or validation fails.
pub fn run(args: &[String]) -> Result<()> {
    let config = Config::load(args.first().map(String::as_str), std::env::vars())?;
    let count = config.reflectors.len();
    println!(
        "loaded {count} reflector{}",
        if count == 1 { "" } else { "s" }
    );
    Ok(())
}
