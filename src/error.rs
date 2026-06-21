//! The crate-wide error type.
//!
//! Every fallible operation returns [`Result<T>`] and `?` propagates failures up
//! to [`crate::run`]. [`Error`] is opaque: `main` prints its `Display` text to
//! stderr, and tests assert on the subsystems' structured errors directly rather
//! than reaching through it.

use std::fmt;

use thiserror::Error;

use crate::config::ConfigError;

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

/// The private cause behind an [`Error`]: one variant per subsystem, each
/// wrapping that subsystem's error with `#[from]`.
#[derive(Debug, Error)]
enum ErrorKind {
    /// Configuration could not be loaded or failed validation.
    #[error("config: {0}")]
    Config(#[from] ConfigError),
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
