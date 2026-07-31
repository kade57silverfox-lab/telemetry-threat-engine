# Multi-stage build: compile in a full Rust image, ship only the binary in
# a minimal runtime image so the deployed artifact isn't dragging along an
# entire Rust toolchain.

FROM rust:1.75-slim AS builder
WORKDIR /build
COPY engine/Cargo.toml engine/Cargo.lock ./
# Cache dependency compilation separately from source changes: this layer
# only invalidates when Cargo.toml/Cargo.lock change, not on every source edit.
RUN mkdir src && echo "fn main() {}" > src/main.rs \
    && cargo build --release \
    && rm -rf src

COPY engine/src ./src
# Touch main.rs so cargo actually recompiles the real source instead of
# reusing the dummy build's cached binary.
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /build/target/release/threat-engine /usr/local/bin/threat-engine

ENV RUST_LOG=info
EXPOSE 8080
# API_TOKEN must be set at runtime: `docker run -e API_TOKEN=... ...`
ENTRYPOINT ["/usr/local/bin/threat-engine"]
