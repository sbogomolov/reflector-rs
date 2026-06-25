# syntax=docker/dockerfile:1
# Build the reflector as a fully static musl binary and ship it on scratch — nothing else to carry
# or to grow CVEs. Architecture-agnostic: buildx's TARGETARCH/TARGETVARIANT select the musl target,
# and the builder runs on the native build host (BUILDPLATFORM) and cross-compiles, so the arm
# images don't crawl under QEMU. The crate is pure Rust (libc FFI only), so LLVM's lld cross-links
# it for any arch with no per-arch gcc toolchain — just the one lld package.

FROM --platform=$BUILDPLATFORM docker.io/library/rust:slim AS builder
ARG TARGETARCH
ARG TARGETVARIANT
WORKDIR /src

RUN set -eux; \
    case "${TARGETARCH}" in \
        amd64) triple=x86_64-unknown-linux-musl ;; \
        arm64) triple=aarch64-unknown-linux-musl ;; \
        arm) \
            case "${TARGETVARIANT}" in \
                v7) triple=armv7-unknown-linux-musleabihf ;; \
                v5) triple=arm-unknown-linux-musleabi ;; \
                *)  echo "unsupported arm variant: ${TARGETVARIANT}" >&2; exit 1 ;; \
            esac ;; \
        *) echo "unsupported architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    echo "${triple}" > /triple; \
    rustup target add "${triple}"

# Link the musl targets with LLVM's lld (cross-capable, unlike the host gcc). Scoped to musl via
# cfg, so the host's build scripts and proc-macros still link with the default toolchain.
RUN apt-get update && apt-get install -y --no-install-recommends lld && rm -rf /var/lib/apt/lists/*
RUN mkdir -p .cargo && cat > .cargo/config.toml <<'EOF'
[target.'cfg(target_env = "musl")']
linker = "ld.lld"
rustflags = ["-C", "linker-flavor=ld.lld"]
EOF

COPY Cargo.toml Cargo.lock ./
COPY src/ ./src/
RUN --mount=type=cache,target=/usr/local/cargo/registry \
    triple="$(cat /triple)"; \
    cargo build --release --locked --target "${triple}"; \
    install -D "target/${triple}/release/reflector" /out/reflector

FROM scratch AS runtime
COPY --from=builder /out/reflector /usr/local/bin/reflector
ENTRYPOINT ["/usr/local/bin/reflector"]
