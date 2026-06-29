//! The crate-wide error type.
//!
//! Every fallible operation returns [`Result<T>`] and `?` propagates failures up
//! to [`crate::run`]. [`struct@Error`] is opaque: `main` prints its `Display` text to
//! stderr, and tests assert on the subsystems' structured errors directly rather
//! than reaching through it.

use std::fmt;
use std::io;

use thiserror::Error;

use crate::config::ConfigError;
use crate::reflector::BuildError;

/// Crate-wide result alias, so signatures read `Result<T>` instead of
/// `Result<T, crate::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Anything that can go wrong while configuring or running the reflector.
///
/// Opaque on purpose: callers only print it (`Display`). The structured cause
/// stays crate-internal — each subsystem keeps its own matchable error type, and
/// `?` lifts those in through `From`.
#[derive(Debug)]
pub struct Error(ErrorKind);

/// The private cause behind an [`struct@Error`]: one variant per subsystem, each
/// wrapping that subsystem's error with `#[from]`.
#[derive(Debug, Error)]
enum ErrorKind {
    /// Configuration could not be loaded or failed validation.
    #[error("config: {0}")]
    Config(#[from] ConfigError),
    /// A capture could not be opened (no `CAP_NET_RAW`, or the interface is absent) or its
    /// interface could not be resolved. Built explicitly — not via the blanket `From` below —
    /// so capture setup reads as such, not as a reactor failure.
    #[error("cannot capture on {iface}: {source}")]
    Capture { iface: String, source: io::Error },
    /// A reflector could not be built from its config (an unknown interface, or a target that
    /// can't currently send a required family).
    #[error("reflector \"{name}\": {source}")]
    Reflector { name: String, source: BuildError },
    /// A reactor or syscall failure. The reactor is currently the crate's only
    /// source of a raw `io::Error`, so the blanket `From` below lands here.
    #[error("reactor: {0}")]
    Reactor(#[from] io::Error),
}

impl Error {
    /// A capture on `iface` could not be set up (open or interface resolution failed).
    pub(crate) fn capture(iface: &str, source: io::Error) -> Self {
        Self(ErrorKind::Capture {
            iface: iface.to_owned(),
            source,
        })
    }

    /// The reflector named `name` could not be built.
    pub(crate) fn reflector(name: &str, source: BuildError) -> Self {
        Self(ErrorKind::Reflector {
            name: name.to_owned(),
            source,
        })
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.0.source()
    }
}

impl From<ConfigError> for Error {
    fn from(source: ConfigError) -> Self {
        Self(ErrorKind::Config(source))
    }
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Self(ErrorKind::Reactor(source))
    }
}
