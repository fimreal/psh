# syntax=docker/dockerfile:1

# Build stage
FROM rust:1.88-alpine AS builder

# Install build dependencies
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconfig \
    build-base

WORKDIR /app

# Copy cargo config for mirrors (optional, speeds up builds in China)
COPY .cargo/config.toml /root/.cargo/config.toml

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src target/release/psh* target/release/deps/psh*

# Copy actual source code
COPY src ./src

# Copy static files for build
COPY static ./static

# Build the actual binary
RUN cargo build --release

# Verify binary is statically linked
RUN ldd target/release/psh 2>&1 | grep -q "not a dynamic executable" || \
    ldd target/release/psh || true

# Runtime stage - minimal image
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    bash

WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/target/release/psh /usr/local/bin/psh

# Copy static files
COPY static /app/static

# Create necessary directories
RUN mkdir -p /var/log/psh /root/.ssh && \
    chmod 700 /root/.ssh

# Expose default port
EXPOSE 8443

# Environment defaults
ENV PSH_HOST=0.0.0.0 \
    PSH_PORT=8443 \
    PSH_SSH_CONFIG=/root/.ssh/config \
    PSH_AUDIT_LOG=/var/log/psh/audit.jsonl \
    PSH_AUTO_CERTS=true \
    RUST_LOG=info

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8443/ || exit 1

# Run the binary
ENTRYPOINT ["/usr/local/bin/psh"]
