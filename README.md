# reflector

Reflects link-local service traffic between two network interfaces. Useful when devices that need to
talk to each other sit on different L2 segments that don't forward each other's broadcasts or
multicasts — the classic case being a router with a wired LAN on one side and a Wi-Fi or IoT VLAN on
the other, where (say) a phone on Wi-Fi can't discover or cast to a TV on the LAN.

It reflects three link-local protocols, and layers an optional DIAL proxy on top of SSDP:

- **Wake-on-LAN** — magic packets sent on one interface are re-emitted on another, so a sender can
  wake a host on a different segment.
- **multicast DNS (mDNS)** — service-discovery traffic is relayed between the two interfaces, so
  clients on one segment can discover responders on the other.
- **SSDP (UPnP/DLNA)** — discovery traffic is relayed both ways, so a caster on one segment can find
  renderers (TVs, media servers) on the other.
- **DIAL proxy** *(optional, builds on SSDP)* — a "cast to TV" device serves its REST API only to its
  own subnet; the proxy bridges that gap so a client on the other segment can actually launch apps on
  it. It is not a separate reflector — it augments an SSDP entry, enabled with `dial = true`. See
  [DIAL](#dial).

Each named entry bridges one `source_if` → `target_if` interface pair and enables any combination of
these. The same shape serves one or a few specific devices (`macs`) or a whole network (omit it).

## Contents

- [Platform support](#platform-support)
- [Build](#build)
- [Run](#run) — [privileges](#runtime-privileges), [Docker](#run-in-docker), [MikroTik](#on-mikrotik-routeros)
- [Configuration](#configuration) — [env vars](#environment-variables), [`macs`](#the-macs-field), [`address_family`](#address_family), [per-protocol behavior](#per-protocol-behavior), [DIAL](#dial), [duplicate detection](#duplicate-detection)
- [Tests](#tests)
- [Release](#release)
- [License](#license)

## Platform support

reflector runs on **Linux, macOS, and FreeBSD**.

**Docker** — a multi-arch image is published to `ghcr.io/sbogomolov/reflector` for `linux/amd64`,
`linux/arm64`, `linux/arm/v7`, and `linux/arm/v5`; Docker pulls the variant matching the host. The
32-bit ARM variants reach low-end embedded routers and SBCs, down to soft-float ARMv5 — handy for
running it on the router that bridges the two segments.

**FreeBSD** isn't a Docker target (Docker shares the host's Linux kernel), so each release also ships
a standalone **static** binary for `amd64` and `arm64`, built on FreeBSD 14.

CI runs the unit suite on Ubuntu 24.04 (x64 and arm64), macOS 15, and FreeBSD 14 (amd64, in a VM),
plus the cross-compiled `linux/arm/v7` and `linux/arm/v5` builds whose suites run under QEMU — each in
both debug and release. `clippy` and the rustdoc link gate run per target, the Docker e2e suite runs
the data path across two bridges, and a Valgrind e2e job runs the daemon under memcheck.

## Build

Prerequisites: a Rust toolchain. `rust-toolchain.toml` pins **stable** with the `rustfmt` and `clippy`
components, so with [`rustup`](https://rustup.rs) the right toolchain (and any missing component) is
installed on the first `cargo` invocation. The crate is edition 2024 (Rust ≥ 1.85), with a 1.93 MSRV.

```sh
cargo build            # debug binary at target/debug/reflector
cargo build --release  # optimized binary at target/release/reflector
```

The release profile enables LTO, a single codegen unit, and symbol stripping for a small footprint
(the binary targets embedded ARM, so the data path avoids allocations). The only dependencies are
`thiserror`, `serde`, `toml`, `log`, and `libc`; cargo fetches them, no system packages needed.

The platform backends are `cfg(target_os)`-gated — rtnetlink/epoll/`AF_PACKET` on Linux,
`getifaddrs`/kqueue/BPF on macOS and FreeBSD — so the other OS's code isn't built on the host. To
exercise the Linux paths from a macOS/FreeBSD dev box, `./docker_test.sh` forwards to `cargo` inside a
`rust:slim` container:

```sh
./docker_test.sh test                                  # cargo test on Linux
./docker_test.sh clippy --all-targets -- -D warnings   # Linux lints
```

### Docker build

The runtime image is a single static musl binary on `scratch` — no shell, no package manager. A bare
build produces a single-arch image for the host:

```sh
docker build -t reflector .
```

The Dockerfile's builder runs on the build host and cross-compiles with LLVM's `lld` (no QEMU), so a
multi-arch image builds on one machine:

```sh
docker buildx build --platform linux/amd64,linux/arm64,linux/arm/v7,linux/arm/v5 -t reflector .
```

Releases publish that multi-arch manifest to GHCR automatically (see [Release](#release)).

## Run

```sh
./target/release/reflector [config.toml]
```

Configuration comes from a TOML file, from environment variables, or from both. With a path argument
the file is read and merged with any `REFLECTOR_*` environment variables; with **no argument** the
configuration comes entirely from the environment (see [Environment variables](#environment-variables)).
The process logs to stderr with UTC timestamps and shuts down cleanly on `SIGINT` / `SIGTERM`.

### Runtime privileges

The reflector opens one L2 packet-capture socket per interface: it both observes incoming packets and
re-injects reflected ones through that same socket (the sender doesn't bind a port, so no port
privileges are involved). mDNS and SSDP additionally join their multicast group(s) on it, which needs
no privilege beyond opening the socket. That capture socket drives the requirements below.

#### Linux

Capture and injection use `AF_PACKET`; the DIAL proxy's TCP connect pins its interface with
`SO_BINDTODEVICE`. Both require `CAP_NET_RAW`. Either run as root or grant the capability once:

```sh
sudo setcap cap_net_raw=eip ./target/release/reflector
```

#### macOS

Capture and injection use BPF (`/dev/bpf*`); the DIAL proxy's connect uses `IP_BOUND_IF`, which needs
no extra privilege. BPF devices are owned by `root:wheel` with mode `0600` on a default install, so out
of the box the reflector must run as root. To run unprivileged, install Wireshark's `ChmodBPF` helper —
it creates an `access_bpf` group, adds the current user to it, and re-applies the right permissions to
`/dev/bpf*` on every boot:

```sh
open "/Applications/Wireshark.app/Contents/Resources/Extras/Install ChmodBPF.pkg"
```

Log out and back in after installing for the group membership to take effect.

#### FreeBSD

Capture and injection use BPF (`/dev/bpf*`), like macOS; FreeBSD has no `IP_BOUND_IF`, so the DIAL
proxy's connect pins its interface by binding the source address — no port privileges are needed. BPF
devices are root-only by default, so out of the box the reflector must run as root. To run
unprivileged, grant a group read/write on `/dev/bpf*` with a devfs ruleset (`/etc/devfs.rules` +
`devfs_system_ruleset` in `/etc/rc.conf`) and add the user to that group.

### Run in Docker

Prebuilt multi-arch images are published to `ghcr.io/sbogomolov/reflector`, tagged `latest` and per
release version, for `linux/amd64`, `linux/arm64`, `linux/arm/v7`, and `linux/arm/v5`; Docker pulls the
variant matching the host. The image is a single static binary on `scratch` — no shell, no package
manager. Its entrypoint is the reflector with no default argument, so it configures itself from
`REFLECTOR_*` [environment variables](#environment-variables); pass a config file path to use a file
instead.

Because the reflector captures at L2 on each interface, the container must be **on the real segments it
bridges**, not on a default NAT bridge network (which would hide that traffic from it). On a Linux host,
`--network host` is the simplest way. Configure it with `-e` variables:

```sh
docker run --rm \
    --network host \
    -e REFLECTOR_TV_SOURCE_IF=eth0 \
    -e REFLECTOR_TV_TARGET_IF=eth1 \
    -e REFLECTOR_TV_MDNS=true \
    ghcr.io/sbogomolov/reflector:latest
```

`CAP_NET_RAW` is required (see [Runtime privileges](#runtime-privileges)) and is in Docker's default
capability set, so the command above works as-is. For least privilege, drop everything else and grant
just that one:

```sh
docker run --rm \
    --network host \
    --cap-drop ALL --cap-add NET_RAW \
    -e REFLECTOR_TV_SOURCE_IF=eth0 \
    -e REFLECTOR_TV_TARGET_IF=eth1 \
    -e REFLECTOR_TV_MDNS=true \
    ghcr.io/sbogomolov/reflector:latest
```

To use a config file instead of (or alongside) the environment, mount it and pass its path as the
argument. This form also shows running it as a service — `-d` with a restart policy:

```sh
docker run -d --name reflector --restart unless-stopped \
    --network host \
    --cap-drop ALL --cap-add NET_RAW \
    -v /path/to/config.toml:/etc/reflector/config.toml:ro \
    ghcr.io/sbogomolov/reflector:latest /etc/reflector/config.toml
```

#### On MikroTik RouterOS

The `arm64`, `arm/v7`, and `arm/v5` variants let the reflector run on the router itself through the
RouterOS *Container* feature, bridging two of the router's VLANs without a separate host. Since it has
to see both segments, give the container **two `veth` interfaces, one bridged into each VLAN**, and name
them as the entry's `source_if` / `target_if`:

```toml
[reflectors.livingroom-tv]
source_if = "veth-lan"   # veth bridged into the LAN VLAN
target_if = "veth-iot"   # veth bridged into the IoT VLAN
macs      = ["B0:37:95:C5:60:BE"] # optional; scope to specific device(s) (omit for the whole VLAN)
wol       = true         # enable Wake-on-LAN, disabled by default
mdns      = true         # enable mDNS, disabled by default
ssdp      = true         # enable SSDP, disabled by default
dial      = true         # enable the DIAL proxy, disabled by default
```

On RouterOS, setting the container's environment variables is usually easier than mounting a file: the
entry above becomes `REFLECTOR_TV_SOURCE_IF=veth-lan`, `REFLECTOR_TV_TARGET_IF=veth-iot`,
`REFLECTOR_TV_MACS=B0:37:95:C5:60:BE`, `REFLECTOR_TV_WOL=true`, and so on (see
[Environment variables](#environment-variables)). To use the file instead, mount it to
`/etc/reflector/config.toml` and set that path as the container's command argument. For the RouterOS
side — enabling container mode, creating the `veth`s, and attaching each to its VLAN — see MikroTik's
[Container documentation](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container).

## Configuration

`config.toml` contains optional top-level settings plus at least one reflector entry. Entries are tables
under `reflectors`, keyed by name (`[reflectors.<name>]`) — the name is the label used in logs — each
describing one `source_if` → `target_if` bridge that enables any combination of the protocols. The
top-level settings are `log_level` and `debug_memory`:

```toml
log_level = "info"               # optional; one of debug | info | warning | error (default: info)
debug_memory = false             # optional; periodically log RSS + heap stats for footprint debugging (default false)

[reflectors.tv]
source_if = "en0"                # required; interface to listen on (must differ from target_if)
target_if = "lo0"                # required; interface to emit reflected traffic on
macs      = ["B0:37:95:C5:60:BE"] # optional; device(s) to scope to (see below). Omit for a whole network.
wol       = true                 # optional; enable Wake-on-LAN reflection (default false)
mdns      = true                 # optional; enable mDNS reflection (default false)
ssdp      = true                 # optional; enable SSDP reflection (default false)
dial      = true                 # optional; enable the DIAL app proxy (requires ssdp; IPv4-only; default false)
wol_ports = [7, 9]               # optional; WoL UDP ports (default [7, 9]); only valid when wol = true
address_family = "default"       # optional; default | dual | ipv4 | ipv6 (default "default")
```

An entry must enable at least one protocol and expands into one reflector per enabled protocol, all
sharing the entry's interfaces, MAC selection, and `address_family`. The same shape serves one or a few
specific devices (set `macs`) or a whole network (omit it). No IP addresses ever
appear in the config. `dial` is not a
separate reflector — it augments the entry's SSDP reflector with the DIAL application proxy (so it
requires `ssdp`; see [DIAL](#dial)).

### Environment variables

Every setting can also come from the environment, which is convenient for containers. A file argument is
then optional; with none, the environment is the whole configuration. Variables are named
`REFLECTOR_<TAG>_<PARAM>`:

- `<TAG>` ties one entry's parameters together — any alphanumeric string (`1`, `2`, `TV`, …). It also
  becomes the entry's name (and thus its log label) unless a `NAME` parameter overrides it.
- `<PARAM>` is `NAME` or any field from the entry table above (`SOURCE_IF`, `TARGET_IF`, `MACS`,
  `WOL`, `MDNS`, `SSDP`, `DIAL`, `WOL_PORTS`, `ADDRESS_FAMILY`), case-insensitive.

The globals are `REFLECTOR_LOG_LEVEL` and `REFLECTOR_DEBUG_MEMORY`, so `LOG` and `DEBUG` are reserved
tags. Booleans are `true`/`false` or `1`/`0`; `WOL_PORTS` and `MACS` are comma-separated (`7,9` /
`B0:...,C4:...`). The
`[reflectors.tv]` entry above looks like this in the environment:

```sh
REFLECTOR_LOG_LEVEL=info
REFLECTOR_TV_SOURCE_IF=en0
REFLECTOR_TV_TARGET_IF=lo0
REFLECTOR_TV_MACS=B0:37:95:C5:60:BE
REFLECTOR_TV_WOL=true
REFLECTOR_TV_MDNS=true
REFLECTOR_TV_SSDP=true
REFLECTOR_TV_DIAL=true
```

When a file and environment variables are both given they are merged: each contributes entries to one
combined configuration, and `REFLECTOR_LOG_LEVEL` / `REFLECTOR_DEBUG_MEMORY` override the file's
`log_level` / `debug_memory`. The [duplicate detection](#duplicate-detection) below applies across both
sources. An unknown `<PARAM>`, a non-alphanumeric or reserved tag, and a tag with no parameter are all
rejected at startup.

### The `macs` field

`macs` is an optional list naming the device(s) an entry is scoped to — coherently across WoL, mDNS,
and SSDP, because a device's NIC MAC is both the target of its Wake-on-LAN magic packet and the L2
source of its mDNS/SSDP advertisements. A single device is just a one-entry list
(`macs = ["B0:37:95:C5:60:BE"]`); list several to scope one entry to a set of devices
(`macs = ["B0:37:95:C5:60:BE", "C4:9D:8F:11:22:33"]`). Below, "the allow-set" means the configured
devices:

- **WoL** re-emits only magic packets whose payload targets a device in the allow-set.
- **mDNS / SSDP** relay, in the target→source direction, only frames whose L2 source MAC is in the
  allow-set (exposing just those devices); the source→target direction is never MAC-filtered. For SSDP
  the same filter scopes the proxied unicast `200 OK` replies — only the allow-set's responses are
  carried back to a searcher.

Omit `macs` for a network-level entry: WoL proxies every valid magic packet, and mDNS/SSDP reflect all
traffic in both directions.

### `address_family`

`"default"` attempts both IPv4 and IPv6, requires IPv4, and treats IPv6 as best-effort; `"dual"`
requires both; `"ipv4"` / `"ipv6"` use only one. It applies to every protocol the entry enables. A
**required** family that can't be initialized for an entry fails startup; a best-effort one that can't
(IPv6 under `"default"`) is skipped and the entry keeps running on the family it has.

mDNS and SSDP are bidirectional, so a handled family must have a source address on **both** interfaces
(the target re-emits relayed queries/searches, the source re-emits relayed responses/advertisements).
This condition is re-checked continuously at runtime (see
[Reacting to address changes](#reacting-to-address-changes) below): a family is torn down if either
interface loses its address and brought back up once both can send it again.

### Reacting to address changes

The reflector watches the kernel for interface address changes (a `NETLINK_ROUTE` socket on Linux, a
`PF_ROUTE` socket on the BSDs) and adapts at runtime, without a restart. mDNS and SSDP bring a family up
— joining its multicast group(s) and installing its capture registrations — once that family becomes
reflectable (a source address for it is present on **both** interfaces), and tear it down when either
interface loses the address; the family resumes automatically when the address returns. WoL keeps its
captures installed and instead checks reachability per packet, so it has nothing to join or leave.
Either way, a best-effort IPv6 family that had no address at startup begins reflecting as soon as one
appears. Gaining a family logs at `info`; losing a *required* family logs at `error`, an optional one at
`info`. The monitor is best-effort: if it cannot start, the reflector logs a warning and runs without
address refresh.

### Per-protocol behavior

| Protocol | Port(s) | Group / destination | Relay direction |
|---|---|---|---|
| WoL | `wol_ports` (default 7, 9) | `255.255.255.255` (v4) / `ff02::1` (v6) | magic packets source → target |
| mDNS | 5353 | `224.0.0.251` / `ff02::fb` | queries source→target, responses target→source |
| SSDP | 1900 | `239.255.255.250` / `ff02::c` + `ff05::c` | M-SEARCH source→target, NOTIFY target→source |
| DIAL | 1900 + ephemeral TCP | (uses SSDP discovery) | terminating HTTP reverse proxy (IPv4 only) |

WoL matching requires the magic-packet sequence (six `0xFF` bytes followed by the target MAC repeated 16
times) at the start of the UDP payload; trailing bytes such as a SecureOn password are ignored when
matching and forwarded as-is. mDNS responses include unsolicited announcements (so they flow
target→source too); mDNS/SSDP datagrams are re-emitted verbatim to the same group (SSDP at hop limit 2).
A site-local SSDP group (`ff05::c`) is sourced from a routable address, not the interface's link-local.

For SSDP, multicast reflection delivers **passive** discovery — devices' periodic `NOTIFY ssdp:alive`
advertisements reach the source segment so clients see them. **Active** discovery works end to end as
well: a client's `M-SEARCH` is relayed to the target segment from a reserved ephemeral port, and the
device's unicast `HTTP/1.1 200 OK` reply to that port is proxied back across to the original searcher.
The proxy is always on whenever `ssdp` is enabled — it keeps one short-lived session per in-flight
search (expiring shortly after the search's `MX` window) and needs no configuration. Reaching a
device's `LOCATION` URL and driving an app launch across segments is the job of the optional DIAL proxy
below.

### DIAL

DIAL (DIscovery And Launch — the protocol behind "cast to TV" for YouTube, Netflix, etc.) lets a phone
or laptop find a smart TV and launch an app on it. The catch: a DIAL device restricts its description
and REST endpoints to its **own subnet**, so a client on a different segment discovers the device but
cannot drive it. Setting `dial = true` on an SSDP entry makes the reflector bridge that gap.

It is a **terminating HTTP reverse proxy**. When a DIAL `LOCATION` (in a relayed `NOTIFY` or `M-SEARCH`
`200 OK`) crosses target→source, the reflector mints a per-device ephemeral TCP listener on
`source_if`'s address and rewrites the `LOCATION` authority to point at that listener. A source-side
client then connects to the reflector, which opens an upstream connection to the device **bound to
`target_if`'s address** — so the device sees an on-subnet client and serves it. Along the way it
rewrites the four authority-bearing headers (`LOCATION`, the description's `Application-URL`, request
`Host`, and response `Location`) from the device's authority to a reflector authority and back; HTTP
bodies stream through untouched. App launch (`POST`) and stop (`DELETE`) work end to end.

`dial = true` requires `ssdp` and is **IPv4-only** (the DIAL spec ties the device authority to an IPv4
address); an `ipv6`-only entry with `dial = true` is rejected at startup. It is the only DIAL knob —
every cap and timeout is a fixed constant. The proxy degrades benignly: a `LOCATION`/`Application-URL`
the reflector can't rewrite (an `https` URL, a hostname instead of an IPv4 literal, a listener cap/bind
failure) is forwarded unchanged and logged, leaving on-subnet discovery unaffected.

### Duplicate detection

Entry names must be unique across the file and the environment — a name that appears twice (including the
same name from both sources) is rejected at startup. Beyond that, two entries that enable the same
protocol are rejected as a duplicate of that protocol only when they could reflect the same packet
twice: same `source_if`, same `target_if`, overlapping MAC selection, overlapping address-family
handling, and — for WoL — at least one shared port. MAC selection overlaps when the entries' allow-sets
share at least one device, or when either omits its MAC filter (any device). Address-family handling overlaps when both can
handle the same IP version: an `ipv4`-only and an `ipv6`-only entry never overlap, while `default`/`dual`
overlap with either. Entries that differ in interface, MAC, address family (or WoL ports), or that
enable *different* protocols, coexist.

## Tests

```sh
cargo test                 # the unit suite
cargo clippy --all-targets -- -D warnings
cargo fmt --check
cargo doc --no-deps --document-private-items   # the rustdoc intra-doc link gate
```

A subset of tests does privileged work — real packet capture, or binding a socket to an interface — and
needs the same privileges the reflector itself does (see [Runtime privileges](#runtime-privileges)).
Each probes for the privilege and self-skips cleanly when it's missing, so a default `cargo test` run is
green on an under-privileged box.

The platform backends are `cfg(target_os)`-gated, so `cargo test` on the host only exercises that OS's
paths. `./docker_test.sh` forwards to `cargo` inside a `rust:slim` container to run the Linux paths from
a macOS/FreeBSD dev box (e.g. `./docker_test.sh test`).

### End-to-end tests

The end-to-end suite drives the real data path: it runs the reflector image across two Docker bridges
and verifies traffic is reflected, multi-protocol. It's opt-in (it builds/runs containers and creates
temporary Docker networks):

```sh
python3 e2e/run.py                # build the image and run the full suite
python3 e2e/run.py --valgrind     # run the daemon under Valgrind memcheck
python3 e2e/run.py --case reflects_matching_magic_packet   # one case
```

`--valgrind` runs the reflector under memcheck (the `runtime-valgrind` image: a glibc release binary
with debug symbols) and fails the run on any leak, leaked fd, or memcheck error. The runner builds
`reflector:e2e` by default, uses `python:3.13-alpine` for UDP-probe containers, can print reflector logs
with `--show-reflector-logs`, and leaves Docker resources behind on failure with `--keep-on-failure`.

## Release

The `[package]` version in `Cargo.toml` is the single source of truth: `version.sh` extracts it, and
`release.sh` (the git tag), the published image tag, and the GitHub release name all derive from it. To
cut a release:

- Bump the version in `Cargo.toml` and merge it to `origin/main`.
- From a clean `main` in sync with `origin/main`, run `./release.sh`.

`./release.sh` does only the local half: it waits for CI (`ci.yml`) to pass on the release commit, prints
the detected version and asks for confirmation, then tags `v<version>` and pushes it. Pushing the tag
hands off to the `release.yml` workflow, which does everything else — it re-checks CI and that the tag
matches `Cargo.toml`, builds the per-arch binaries (Linux amd64/arm64/armv7/armv5, macOS arm64, FreeBSD
amd64/arm64), publishes the multi-arch image to GHCR in one buildx build, and creates the GitHub release
with the binaries and their `SHA256SUMS` attached and generated notes. `release.sh` needs only the GitHub
CLI (`gh`, authenticated) for its CI check; nothing else runs locally.

## License

Copyright 2026 Sergii Bogomolov.

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
