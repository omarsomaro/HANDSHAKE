# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Initial release of Handshacke P2P communication framework
- Deterministic P2P communication without servers
- Multi-transport NAT traversal (LAN, UPnP, STUN, Relay, Tor)
- Noise protocol encryption (XChaCha20-Poly1305)
- Real TLS DPI evasion
- WebSocket/QUIC/HTTP2 mimicry
- TCP and ICMP hole punching
- Academic security case study
- Operational threat model analysis
- QUIC RFC9000 transport module (optional)
- WebRTC DataChannel transport module (optional)
- Hybrid post-quantum key exchange module (optional)
- Feature flags for heavy dependencies
- High-level integration tests (crypto/Noise/QUIC/WebRTC)
- Architecture and feature flag documentation
- GitHub Actions CI workflow

### Security
- Initial security audit completed
- See [docs/threat_model_visibility.md](docs/threat_model_visibility.md) for details

## [0.1.0] - 2025-01-22

### Initial Release
- Core P2P communication engine
- Multi-transport coordination (ICE)
- Cryptographic handshake via Noise protocol
- Initial command-line interface
- Basic documentation

[Unreleased]: https://github.com/omarsomaro/handshake/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/omarsomaro/handshake/releases/tag/v0.1.0
