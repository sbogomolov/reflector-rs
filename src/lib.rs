//! reflector — reflects link-local service traffic (Wake-on-LAN, mDNS, SSDP,
//! and an optional DIAL proxy) between two network interfaces.
//!
//! The behavior lives in this library crate so it stays testable in-process;
//! the binary (`src/main.rs`) is a thin shim over [`run`].

mod capture;
mod config;
mod dispatch;
mod error;
mod interface;
mod logging;
mod net;
mod reactor;
mod reflector;
mod sys;

pub use self::error::{Error, Result};
pub use self::logging::init as init_logging;

use self::capture::Capture;
use self::config::Config;
use self::dispatch::PacketDispatcher;
use self::reactor::Reactor;
use self::reflector::InterfaceMap;

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

    // Build the data path: one capture per interface, the reflectors that bridge them, then
    // hand the dispatcher to the reactor to drive until a shutdown signal.
    let mut dispatcher = PacketDispatcher::new();
    let interfaces = open_captures(&config, &mut dispatcher)?;
    for reflector in &config.reflectors {
        crate::reflector::wol::build(reflector, &interfaces, &mut dispatcher)
            .map_err(|e| Error::reflector(reflector.name.as_str(), e))?;
        crate::reflector::mdns::build(reflector, &interfaces, &mut dispatcher)
            .map_err(|e| Error::reflector(reflector.name.as_str(), e))?;
        crate::reflector::ssdp::build(reflector, &interfaces, &mut dispatcher)
            .map_err(|e| Error::reflector(reflector.name.as_str(), e))?;
    }

    let mut reactor = Reactor::new()?;
    let watches = dispatcher.capture_watches();
    reactor.register_with_fds(Box::new(dispatcher), &watches)?;
    log::info!("running; press Ctrl-C or send SIGTERM to stop");
    reactor.run()?;
    log::info!("stopped");
    Ok(())
}

/// Open one capture per distinct interface — the `source ∪ target` of every reflector, in
/// first-seen order — recording each in an [`InterfaceMap`] for the per-protocol builders.
/// Fail-closed: a capture that can't open (missing `CAP_NET_RAW`, an absent interface) aborts
/// startup, since a daemon that looks healthy but reflects nothing is the worse failure.
fn open_captures(config: &Config, dispatcher: &mut PacketDispatcher) -> Result<InterfaceMap> {
    let mut interfaces = InterfaceMap::default();
    for reflector in &config.reflectors {
        for name in [reflector.source_if.as_str(), reflector.target_if.as_str()] {
            if interfaces.key_for(name).is_some() {
                continue;
            }
            let capture = Capture::open(name).map_err(|e| Error::capture(name, e))?;
            let key = dispatcher
                .add_capture(capture)
                .map_err(|e| Error::capture(name, e))?;
            interfaces.insert(name.to_owned(), key);
        }
    }
    Ok(interfaces)
}
