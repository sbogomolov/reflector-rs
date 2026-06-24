//! reflector — reflects link-local service traffic (Wake-on-LAN, mDNS, SSDP,
//! and an optional DIAL proxy) between two network interfaces.
//!
//! The behavior lives in this library crate so it stays testable in-process;
//! the binary (`src/main.rs`) is a thin shim over [`run`].

mod config;
mod error;
mod logging;
mod sys;
// `net`/`capture`/`dispatch` have no caller until the reflectors are built, and a
// few reactor APIs (set_write_interest, is_registered) have none until then. Allow
// dead code until the data path lands.
#[allow(dead_code)]
mod capture;
#[allow(dead_code)]
mod dispatch;
#[allow(dead_code)]
mod interface;
#[allow(dead_code)]
mod net;
#[allow(dead_code)]
mod reactor;

pub use self::error::{Error, Result};
pub use self::logging::init as init_logging;

use self::config::Config;
use self::reactor::Reactor;

/// Run the reflector to completion.
///
/// `args` is the process argument list with argv[0] already stripped. The first
/// argument, if present, is a TOML config path; `REFLECTOR_*` environment
/// variables are merged on top (and can configure reflectors on their own).
///
/// # Errors
/// Returns [`Error`] if configuration loading or validation fails, or if the
/// reactor cannot be created or its event loop fails.
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

    // The capture layer and reflectors will register their fds here; for now the
    // reactor carries only its shutdown self-pipe, so run() blocks until a signal.
    let mut reactor = Reactor::new()?;
    log::info!("running; press Ctrl-C or send SIGTERM to stop");
    reactor.run()?;
    log::info!("stopped");
    Ok(())
}
