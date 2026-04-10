# syntax=docker/dockerfile:1

FROM golang:1.22-alpine AS builder

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /psh ./cmd/psh

FROM scratch

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /psh /psh
COPY static /app/static

WORKDIR /app
EXPOSE 8443

ENV PSH_HOST=0.0.0.0 \
    PSH_PORT=8443 \
    PSH_SSH_CONFIG=/root/.ssh/config \
    PSH_AUTO_CERTS=true

ENTRYPOINT ["/psh"]
