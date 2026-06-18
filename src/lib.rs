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
/// `args` is the process argument list with argv[0] already stripped. With a
/// path argument, configuration is loaded from that TOML file.
pub fn run(args: &[String]) -> Result<()> {
    match args.first() {
        Some(path) => {
            let config = Config::from_toml_file(path)?;
            let count = config.reflectors.len();
            println!(
                "loaded {count} reflector{}",
                if count == 1 { "" } else { "s" }
            );
        }
        None => println!("TODO: environment-only configuration (next increment)"),
    }
    Ok(())
}
