//! The crate-wide error type.
//!
//! Every fallible operation returns [`Result<T>`] and `?` propagates failures
//! up to [`crate::run`]. The `Display` text is the user-facing message `main`
//! prints to stderr; tests assert on the structured variants, not on its
//! wording.

use thiserror::Error;

use crate::config::ConfigError;

/// Crate-wide result alias, so signatures read `Result<T>` instead of
/// `Result<T, crate::Error>`.
pub type Result<T> = std::result::Result<T, Error>;

/// Everything that can go wrong while configuring or running the reflector.
///
/// Each subsystem contributes a variant, usually wrapping its own structured
/// error with `#[from]` so `?` converts automatically.
#[derive(Debug, Error)]
pub enum Error {
    /// Configuration could not be loaded or failed validation.
    #[error("config: {0}")]
    Config(#[from] ConfigError),
}
