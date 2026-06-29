//! Process-wide logging built on the [`log`] facade.
//!
//! Subsystems log through the `log` macros (`log::info!`, `log::warn!`, …), which
//! capture the call site's module path as the record's target. [`init`] installs
//! this module's [`StderrLogger`] as the one global logger and sets the severity
//! threshold from the configured [`LogLevel`]. That threshold is the crate-wide
//! filter the macros apply *before* a record reaches us, so below-threshold calls
//! cost only a level comparison.
//!
//! Records are written to stderr (leaving stdout for program output) as
//! `<utc> <LEVEL> <target>: <message>`, with a UTC ISO-8601 timestamp.

use std::fmt;
use std::io::Write;
use std::time::{SystemTime, UNIX_EPOCH};

use log::{LevelFilter, Log, Metadata, Record};

use crate::config::LogLevel;

/// The installed logger. A unit struct: the only mutable state is `log`'s global
/// max level, set once by [`init`].
struct StderrLogger;

static LOGGER: StderrLogger = StderrLogger;

impl Log for StderrLogger {
    fn enabled(&self, metadata: &Metadata) -> bool {
        metadata.level() <= log::max_level()
    }

    fn log(&self, record: &Record) {
        // The trait doesn't guarantee `enabled` runs first, so filter here too.
        if !self.enabled(record.metadata()) {
            return;
        }
        let mut stderr = std::io::stderr();
        writeln!(
            stderr,
            "{} {:>5} {}: {}",
            Utc::now(),
            record.level(),
            record.target(),
            record.args(),
        )
        .ok();
    }

    fn flush(&self) {
        std::io::stderr().flush().ok();
    }
}

/// A civil UTC date-time, rendered as ISO 8601 (e.g. `2026-06-19T18:49:58Z`).
struct Utc {
    year: u64,
    month: u64,
    day: u64,
    hour: u64,
    minute: u64,
    second: u64,
}

impl Utc {
    /// The current wall-clock instant as UTC. A clock set before the Unix epoch
    /// renders as the epoch rather than failing.
    fn now() -> Self {
        let secs = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        Self::from_unix(secs)
    }

    /// Convert Unix seconds to civil UTC via Howard Hinnant's `civil_from_days`.
    /// All arithmetic stays unsigned: seconds since the epoch are non-negative, so
    /// the algorithm's negative-day branch can't be reached and is omitted.
    fn from_unix(secs: u64) -> Self {
        let hour = secs % 86_400 / 3_600;
        let minute = secs % 3_600 / 60;
        let second = secs % 60;

        // Shift the epoch to 0000-03-01 so a 400-year era ends on a leap day, then
        // unwind era → year-of-era → day-of-year. Bracketed ranges aid verification.
        let z = secs / 86_400 + 719_468;
        let era = z / 146_097;
        let doe = z - era * 146_097; // [0, 146096]
        let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365; // [0, 399]
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
        let mp = (5 * doy + 2) / 153; // [0, 11]
        let day = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
        let month = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
        let year = era * 400 + yoe + u64::from(month <= 2);

        Self {
            year,
            month,
            day,
            hour,
            minute,
            second,
        }
    }
}

impl fmt::Display for Utc {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            self.year, self.month, self.day, self.hour, self.minute, self.second,
        )
    }
}

/// Install the global logger backend with the default severity threshold.
///
/// Installing a process-global logger is the binary's responsibility, not a
/// library's, so this is called once from `main`; `set_level` then applies the
/// configured threshold once the configuration has been loaded.
///
/// # Panics
/// Panics if called more than once in the process — a second call would try to
/// replace the already-installed global logger.
pub fn init() {
    log::set_logger(&LOGGER).expect("logging::init called more than once");
    log::set_max_level(LevelFilter::from(LogLevel::default()));
}

/// Set the minimum severity that will be logged. Cheap and idempotent — the
/// library calls this once the configured level is known.
pub(crate) fn set_level(level: LogLevel) {
    log::set_max_level(LevelFilter::from(level));
}

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Off => LevelFilter::Off,
            LogLevel::Error => LevelFilter::Error,
            LogLevel::Warning => LevelFilter::Warn,
            LogLevel::Info => LevelFilter::Info,
            LogLevel::Debug => LevelFilter::Debug,
            LogLevel::Trace => LevelFilter::Trace,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn epoch_renders_as_iso() {
        assert_eq!(Utc::from_unix(0).to_string(), "1970-01-01T00:00:00Z");
    }

    #[test]
    fn last_second_before_midnight() {
        assert_eq!(Utc::from_unix(86_399).to_string(), "1970-01-01T23:59:59Z");
    }

    #[test]
    fn billennium_is_2001() {
        // 1e9 seconds after the epoch is the well-known 2001-09-09T01:46:40Z.
        assert_eq!(
            Utc::from_unix(1_000_000_000).to_string(),
            "2001-09-09T01:46:40Z"
        );
    }

    #[test]
    fn leap_day_2000_exists() {
        // 2000 is divisible by 400, so it is a leap year and Feb 29 is valid.
        assert_eq!(
            Utc::from_unix(951_782_400).to_string(),
            "2000-02-29T00:00:00Z"
        );
    }

    #[test]
    fn log_levels_map_to_filters() {
        assert_eq!(LevelFilter::from(LogLevel::Off), LevelFilter::Off);
        assert_eq!(LevelFilter::from(LogLevel::Error), LevelFilter::Error);
        assert_eq!(LevelFilter::from(LogLevel::Warning), LevelFilter::Warn);
        assert_eq!(LevelFilter::from(LogLevel::Info), LevelFilter::Info);
        assert_eq!(LevelFilter::from(LogLevel::Debug), LevelFilter::Debug);
        assert_eq!(LevelFilter::from(LogLevel::Trace), LevelFilter::Trace);
    }
}
