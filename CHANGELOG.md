# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Multi-architecture Docker support (amd64, arm64)
- Automated CI/CD pipeline with Gitea Actions
- Binary releases for Linux and macOS (amd64, arm64)
- SHA256 checksums for all release binaries
- Health check in Docker image

## [0.1.0] - 2024-01-01

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

[Unreleased]: https://github.com/your-org/psh/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/psh/releases/tag/v0.1.0
