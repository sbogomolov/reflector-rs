# reflector

## Hard invariants

- Single-threaded event loop — no threads, no locks. Single-thread reactor
  (`mio` or hand-rolled), never a multi-thread async runtime.
- Footprint-sensitive (embedded ARM, MikroTik). Mind data-path allocations.
- Must cross-compile to linux/arm/v7, linux/arm/v5, and static FreeBSD (amd64/arm64).
- Error `Display` text is user-facing (printed to stderr) — keep it clear. Test
  structured error variants (`matches!`), not Display substrings.
- lib/bin split: logic in the `reflector` library (`src/lib.rs`); thin binary (`src/main.rs`).

## Build / test

- Keep `cargo clippy --all-targets -- -D warnings` clean.
- Keep `cargo fmt --check` clean (run `cargo fmt` to fix).
- Platform `cfg` code (the epoll backend now, AF_PACKET capture later) isn't built
  on the macOS dev host — verify it on Linux with `./docker_test.sh` (forwards to
  cargo, e.g. `./docker_test.sh clippy --all-targets -- -D warnings`). Check both
  host and Linux when touching `cfg(target_os)` code.
- `cargo run` — no path arg: config from env only; with a path arg: TOML merged
  with `REFLECTOR_*` env.
- Test-only seams (`cfg(test)` accessor methods, consts) go in an `impl` block
  inside `mod tests`, never as `#[cfg(test)]` members of a production `impl`.

## Intra-file layout

- Order within a file: module doc → imports → consts/statics → types (most
  depended-on first, each immediately followed by its inherent impl, then its
  trait impls) → free fns (after the types they serve) → `#[cfg(test)] mod tests`
  last.
- A const/static bound to a single item lives beside it, not in the top block: a
  private const used by one fn, or a `const _: () = assert!(...)` layout check
  beside the type it guards. A const built from a local type/builder likewise
  follows them rather than leading the file.
