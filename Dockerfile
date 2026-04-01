# Build stage
FROM rust:1.85-alpine AS builder

RUN apk add --no-cache musl-dev openssl-dev pkgconfig

WORKDIR /app

# Copy manifests
COPY Cargo.toml ./

# Create dummy main.rs to cache dependencies
RUN mkdir src && \
    echo "fn main() {}" > src/main.rs && \
    cargo build --release && \
    rm -rf src

# Copy actual source
COPY src ./src

# Build for real
RUN cargo build --release

# Runtime stage
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

# Copy binary
COPY --from=builder /app/target/release/psh /usr/local/bin/psh

# Copy static files
COPY static /app/static

# Create log directory
RUN mkdir -p /var/log/psh

# Expose port
EXPOSE 8443

# Environment defaults
ENV PSH_HOST=0.0.0.0
ENV PSH_PORT=8443
ENV PSH_SSH_CONFIG=/root/.ssh/config
ENV PSH_AUDIT_LOG=/var/log/psh/audit.jsonl
ENV PSH_AUTO_CERTS=true

# Run
ENTRYPOINT ["/usr/local/bin/psh"]