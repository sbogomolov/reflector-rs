# ruflector

## Hard invariants
- Single-threaded event loop — no threads, no locks. Single-thread reactor
  (`mio` or hand-rolled), never a multi-thread async runtime.
- Footprint-sensitive (embedded ARM, MikroTik). Mind data-path allocations.
- Must cross-compile to linux/arm/v7, linux/arm/v5, and static FreeBSD (amd64/arm64).
- Error `Display` text is user-facing (printed to stderr) — keep it clear. Test
  structured error variants (`matches!`), not Display substrings.
- lib/bin split: logic in the `ruflector` library (`src/lib.rs`); thin binary (`src/main.rs`).

## Build / test
- Keep `cargo clippy --all-targets -- -D warnings` clean.
- `cargo run` — no path arg: config from env only; with a path arg: TOML merged
  with `REFLECTOR_*` env.
