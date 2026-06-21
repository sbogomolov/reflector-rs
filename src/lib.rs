//! reflector — reflects link-local service traffic (Wake-on-LAN, mDNS, SSDP,
//! and an optional DIAL proxy) between two network interfaces.
//!
//! The behavior lives in this library crate so it stays testable in-process;
//! the binary (`src/main.rs`) is a thin shim over [`run`].

mod config;
mod error;
mod logging;
// net and reactor have no in-crate caller yet (`run` drives the reactor and the
// reflectors use net in later steps); allow dead code until they are wired.
#[allow(dead_code)]
mod net;
#[allow(dead_code)]
mod reactor;

pub use self::error::{Error, Result};
pub use self::logging::init as init_logging;

use self::config::Config;

/// Run the reflector to completion.
///
/// `args` is the process argument list with argv[0] already stripped. The first
/// argument, if present, is a TOML config path; `REFLECTOR_*` environment
/// variables are merged on top (and can configure reflectors on their own).
///
/// # Errors
/// Returns [`Error`] if configuration loading or validation fails.
pub fn run(args: &[String]) -> Result<()> {
    let path = args.first().map(String::as_str);
    let toml_text = path.map(config::read_config_file).transpose()?;
    let env: Vec<(String, String)> = std::env::vars().collect();

    // Resolve the log level first, from a minimal read of env + file, so the full
    // parse below is logged at the configured verbosity (see resolve_log_level).
    logging::set_level(config::resolve_log_level(toml_text.as_deref(), &env)?);
    if let Some(path) = path {
        log::debug!("loading configuration from {path} with REFLECTOR_* overrides");
    } else {
        log::debug!("loading configuration from REFLECTOR_* environment only");
    }

    let config = Config::from_sources(toml_text.as_deref(), env)?;
    let count = config.reflectors.len();
    log::info!(
        "loaded {count} reflector{}",
        if count == 1 { "" } else { "s" }
    );
    Ok(())
}
