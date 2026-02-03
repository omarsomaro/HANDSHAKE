# Handshacke

Deterministic P2P communication without servers.

Handshacke is a P2P communication system that uses deterministic cryptographic rendezvous to establish secure connections without any central servers, DNS lookups, or traditional discovery protocols.

Repository: https://github.com/omarsomaro/HANDSHAKE
License: MIT
Latest Version: 0.1.0

## Key Features

- Zero-discovery P2P (shared passphrase rendezvous)
- Deterministic parameter derivation (port, keys, tags)
- Transport cascade: LAN -> WAN (UPnP/NAT-PMP) -> Tor fallback
- ICE multipath with adaptive transport selection
- Memory-safe crypto: XChaCha20-Poly1305 + HMAC with key zeroization
- Early-drop filtering + rate limiting (DoS resistance)
- Replay protection (sliding window)
- Multi-protocol DPI evasion: Real TLS, WebSocket, QUIC, HTTP/2 mimicry
- Optional QUIC (RFC 9000) and WebRTC DataChannel
- Optional post-quantum hybrid key exchange (feature: pq)
- Desktop GUI (Tauri) with guided connection flows
- Threat model and security analysis in docs

## Installation

### Requirements
- Rust 1.70+
- Network access (no firewall blocking required ports)
- Node.js 18+ (only for the GUI)

### Build from Source
```
git clone https://github.com/omarsomaro/HANDSHAKE.git
cd HANDSHAKE
cargo build --release
```

Binaries:
- target/release/handshacke (daemon)
- target/release/hs-cli (CLI client)

### Pre-built Binaries
Coming soon.

## Quick Start

### 1) Headless (daemon + CLI/API)

Build and run the daemon:
```
cargo run --release
```

API starts on http://127.0.0.1:3000

Send messages with the CLI (two terminals, same passphrase):
```
# Terminal 1
cargo run --bin hs-cli -- "mysecretpassphrase" "Hello from peer A!"

# Terminal 2
cargo run --bin hs-cli -- "mysecretpassphrase" "Hello back from peer B!"
```

### 2) Desktop GUI (Tauri)

The GUI launches the daemon as a sidecar. You need the daemon binary in the Tauri bin folder:

```
# Build the core binary
cargo build --release

# Copy into the Tauri sidecar location
# Windows: copy target/release/handshacke.exe -> ui/src-tauri/bin/handshacke.exe
# macOS/Linux: copy target/release/handshacke -> ui/src-tauri/bin/handshacke

cd ui
npm install
npm run dev
```

For a packaged desktop build:
```
cd ui
npm run build
```

See docs/gui_flows.md for the exact user flows supported by the GUI.

### 3) Web Client (legacy/debug)

Open client.html in your browser and use the same passphrase on two instances.

## Library Usage

```rust
use handshacke::prelude::*;

let cfg = Config::from_env();
// Use establish_connection_from_offer(...) or connect_to(...) based on your flow.
```

## API Endpoints

Security note: the API is not designed to be exposed without authentication. Keep it bound to 127.0.0.1 unless you explicitly accept the risk.

See SECURITY.md for API security considerations.

Connection Management
- POST /v1/connect - Establish P2P connection
- GET /v1/status - Get connection status
- POST /v1/disconnect - Close connection

Messaging
- GET /v1/recv - SSE stream for incoming messages
- POST /v1/send - Send encrypted packet

Crypto Operations
- POST /v1/set_passphrase - Set encryption passphrase
- POST /v1/seal - Encrypt data to packet
- POST /v1/open - Decrypt packet to data

## Security

See docs/threat_model_visibility.md for visibility analysis by transport layer.

See docs/casestudy.md for academic security analysis.

See SECURITY.md for vulnerability reporting and security policy.

Key Security Properties
- Content confidentiality (Noise + XChaCha20-Poly1305)
- Perfect forward secrecy (Noise)
- Zero persistence (keys in RAM only)
- DoS resistance (early-drop + rate limiting)

Security Trade-offs
- LAN: exposed to local network
- UPnP/NAT-PMP: gateway sees mappings
- Tor: strong anonymity, higher latency
- Relay: centralized metadata (use via Tor to hide IP)

## How It Works

1) Deterministic parameters

```rust
// Both peers derive identical parameters from the shared passphrase
let params = derive_from_passphrase("shared_secret");
```

2) Transport cascade
- LAN: UDP broadcast discovery
- WAN: UPnP/NAT-PMP port forwarding
- Tor: stream fallback when direct WAN fails

Optional transports
- QUIC (RFC 9000): framed stream over UDP
- WebRTC DataChannel: browser-compatible transport

3) Message flow
```
[Message] -> Encrypt -> Tag + Nonce + Ciphertext -> UDP -> Peer
[Peer] -> Tag Filter -> Rate Limit -> Decrypt -> Replay Check -> Display
```

## Network Compatibility

- LAN: direct UDP broadcast
- Home networks: UPnP automatic port forwarding
- Corporate/CGNAT: NAT-PMP fallback
- Restrictive NATs: Tor fallback and assisted hole punching
- IPv4/IPv6: dual-stack (IPv4 primary)
- Censorship: Tor integration available
- Interoperability: optional QUIC and WebRTC transports

## Architecture

- docs/architecture.md
- docs/transport_matrix.md
- docs/feature_flags.md
- docs/gui_flows.md

## Performance

- Early drop filtering at line speed
- RAM-only operation
- Direct UDP when possible (no relay servers unless Tor)

## Development

See CONTRIBUTING.md for contribution guidelines.

### Development Setup
```
# Setup hooks
git config commit.gpgsign true  # If using GPG
cargo install cargo-audit  # For security audits
```

### Running Tests
```
# Unit tests
cargo test

# Feature combinations
cargo test --no-default-features
cargo test --no-default-features --features pq
cargo test --no-default-features --features quic
cargo test --no-default-features --features webrtc

# Check code quality
cargo fmt -- --check
cargo clippy -- -D warnings

# Security audit
cargo audit
```

See docs/testing.md for the full test matrix and ignored tests.

## License

MIT License - See LICENSE

## Contributing

Contributions welcome. Please read CONTRIBUTING.md.

## Security

For security issues, see SECURITY.md. Do NOT report vulnerabilities in public issues.

## Issues

Report bugs via https://github.com/omarsomaro/HANDSHAKE/issues

## Roadmap

- Pre-built binaries for major platforms
- Mobile app (iOS/Android)
- Plugin system for custom transports
- Performance benchmarks
- GUI polish and onboarding improvements

## Mission

Handshacke enables private, serverless communication that respects user privacy and resists censorship.

## References

- docs/threat_model_visibility.md - Operational threat model
- docs/casestudy.md - Academic security analysis
- docs/testing.md - Test matrix and ignored tests
- SECURITY.md - Security policy

---

Repository: https://github.com/omarsomaro/HANDSHAKE
Issues: https://github.com/omarsomaro/HANDSHAKE/issues
Security: security@handshake-p2p.dev
