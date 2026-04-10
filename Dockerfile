# syntax=docker/dockerfile:1

# Build stage - builds ALL platforms
FROM golang:1.22-alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

# Run tests
RUN go test -v ./...

# Build all platforms (linux for docker, darwin for release)
RUN set -e; \
    for platform in "linux/amd64" "linux/arm64" "darwin/arm64"; do \
      GOOS="${platform%%/*}"; \
      GOARCH="${platform##*/}"; \
      echo "Building for $GOOS/$GOARCH..."; \
      CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o "/build/psh-${GOOS}-${GOARCH}" ./cmd/psh; \
    done

# Export stage - used by `docker buildx --output` to extract binaries
FROM scratch AS export
COPY --from=builder /build/ /

# Runtime stage - minimal scratch image
FROM scratch AS runtime

# Copy CA certificates and timezone data
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo

WORKDIR /app

# Copy the TARGET platform binary (buildx sets TARGETOS/TARGETARCH)
ARG TARGETOS
ARG TARGETARCH
COPY --from=builder /build/psh-${TARGETOS}-${TARGETARCH} /psh

# Copy static files
COPY static /app/static

EXPOSE 8443

ENV PSH_HOST=0.0.0.0 \
    PSH_PORT=8443 \
    PSH_SSH_CONFIG=/root/.ssh/config \
    PSH_AUTO_CERTS=true

# For scratch image, use K8s livenessProbe instead of HEALTHCHECK
# livenessProbe:
#   httpGet:
#     path: /
#     port: 8443

ENTRYPOINT ["/psh"]
