# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- Web API: gin trusted-proxy handling is now fail-closed — `X-Forwarded-For`
  is ignored by default, so clients can no longer spoof their IP to bypass
  login lockout and rate limiting; configure real reverse-proxy addresses via
  `--trusted-proxies` / `TRUSTED_PROXIES`
- Login lockout map: stale entries are now evicted based on last activity,
  including entries that never triggered a lockout (previously an attacker
  rotating spoofed source IPs could exhaust memory remotely)
- WebSocket concurrency slots are acquired/released around the whole request
  lifecycle in middleware; failed auth or upgrade no longer permanently leaks
  a slot for the client IP
- Audit log: fixed periodic flush timer not being re-armed, which delayed
  low-traffic events indefinitely
- API/MCP sessions: session state fields are now mutex-guarded (data race);
  sessions are bound to their creator (API key / MCP client) and can neither
  be driven nor listed by other identities; API key lookup is constant-time
- `--api-exec-timeout` is now actually honored as the exec timeout cap
  (previously shadowed by an unrelated constant)
- Auth cookie is now `SameSite=Lax` and `Secure` outside dev mode
- Cross-origin policy is deny-by-default: with no `--allowed-origins`
  configured, cross-origin requests and WebSocket handshakes are rejected
  instead of being allowed from anywhere
- Outbound SSH targets are re-checked at dial time against loopback and
  link-local ranges (including cloud metadata 169.254.169.254) plus the user
  blacklist, on the RESOLVED address — closing DNS-rebinding TOCTOU bypasses;
  IPv6 loopback/link-local are now blocked too

### Added
- psh-mcp remote transport mode (`--transport sse`): resident HTTP/SSE MCP
  server (MCP spec 2024-11-05) with bearer-token auth (fail-closed), TLS /
  auto self-signed certs, health check endpoint and graceful shutdown
- Multi-architecture Docker support (amd64, arm64)
- Automated CI/CD pipeline with Gitea Actions
- Binary releases for Linux and macOS (amd64, arm64)
- SHA256 checksums for all release binaries
- Health check in Docker image

### Fixed
- psh-mcp SSE mode hardening (code review follow-ups): `POST /messages` now
  acknowledges immediately (202) and executes tools asynchronously with a
  bounded dispatch queue; added SSE connection cap (`PSH_MCP_MAX_CONNECTIONS`,
  429 on overflow), per-connection in-flight limits, SSE write deadlines and
  POST body size/read-timeout limits to shed slow clients; authentication
  failures are logged and audited; fixed shutdown data race and made graceful-
  shutdown timeout no longer produce a failure exit code
- Per-connection request cap is now a hard atomic reservation covering queued
  AND executing jobs, so one connection can no longer hog the global dispatch
  queue; the dispatch queue is sized from `PSH_MCP_MAX_CONNECTIONS`
- `X-Forwarded-Proto`/`X-Forwarded-Host` are no longer trusted by default;
  opt in with `PSH_MCP_TRUST_PROXY_HEADERS=true` behind a trusted proxy
  (proto value validated)

## [0.1.0] - 2025-04-10

### Added
- Initial release
- Web-based SSH terminal with xterm.js
- JWT-based authentication
- Multi-host SSH management via SSH config
- Auto-generated TLS certificates
- Audit logging for all SSH sessions
- WebSocket-based real-time terminal communication
- Responsive web UI
- Docker support with minimal Alpine image

### Security
- JWT token authentication
- TLS/HTTPS encryption
- Password-protected access
- Audit trail for compliance

### Technical Details
- Built with Go
- Pure Go SSH client (golang.org/x/crypto)
- No external C dependencies
- Cross-platform support

[Unreleased]: https://git.epurs.com/gitops/psh/compare/v0.1.0...HEAD
[0.1.0]: https://git.epurs.com/gitops/psh/releases/tag/v0.1.0
