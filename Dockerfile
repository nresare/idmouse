# SPDX-License-Identifier: MIT
# Copyright (c) 2026 idelephant contributors

# Adapted from https://github.com/LukeMathWalker/cargo-chef
FROM lukemathwalker/cargo-chef:latest-rust-1 AS chef
WORKDIR /build

FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder
COPY --from=planner /build/recipe.json recipe.json
# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json
# Build application
COPY . .
RUN cargo build --locked --release

# We do not need the Rust toolchain to run the binary!
FROM gcr.io/distroless/cc-debian13:nonroot

COPY --from=builder /build/target/release/idmouse /

ENTRYPOINT ["/idmouse"]
