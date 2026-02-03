# 🤝 Handshacke

**Deterministic P2P Communication without Servers**

Handshacke is a P2P communication system that uses **deterministic cryptographic rendezvous** to establish secure connections without any central servers, DNS lookups, or traditional discovery protocols.

**Repository**: https://github.com/omarsomaro/handshake  
**License**: MIT  
**Latest Version**: 0.1.0

## 🎯 Key Features

- **Zero-Discovery P2P**: Peers find each other using only a shared passphrase
- **Deterministic Port Derivation**: `hash(passphrase) % 65535` determines connection parameters
- **Multi-Layer Transport**: LAN → WAN (UPnP/NAT-PMP) → Tor fallback
- **Memory-Safe Crypto**: XChaCha20Poly1305 + HMAC with automatic key zeroization
- **Early-Drop Protection**: Tag-based filtering prevents DoS attacks
- **Rate Limiting**: Built-in protection against flooding
- **Replay Protection**: 128-bit sliding window
- **Clean Shutdown**: Graceful task termination with watch channels
- **Multi-Protocol DPI Evasion**: Real TLS, WebSocket, QUIC, HTTP/2 mimicry
- **Ice Multipath**: Intelligent transport selection
- **Optional QUIC/WebRTC**: Standards-based transports for interoperability
- **Comprehensive Threat Model**: See [docs/threat_model_visibility.md](docs/threat_model_visibility.md)

## 📦 Installation

### Requirements
- Rust 1.70 or later
- Network access (no firewall blocking)

### Build from Source
```bash
git clone https://github.com/omarsomaro/handshake.git
cd handshake
cargo build --release
```

The binaries will be available at:
- `target/release/handshacke` (main server)
- `target/release/hs-cli` (CLI client)

### Pre-built Binaries
Coming soon! We're working on providing pre-built binaries for major platforms.

## 🚀 Quick Start

### 1. Build
```bash
cd handshake
cargo build --release
```

### 2. Start the Server
```bash
cargo run --release
```

Server starts on `http://127.0.0.1:3000`

### 3. Test with CLI
```bash
# Terminal 1: Send a message
cargo run --bin hs-cli -- "mysecretpassphrase" "Hello from peer A!"

# Terminal 2: Send a response  
cargo run --bin hs-cli -- "mysecretpassphrase" "Hello back from peer B!"
```

### 4. Test with Web Client
1. Open `client.html` in your browser
2. Enter the same passphrase on both instances
3. Click "CONNECT" 
4. Start chatting!

## 📦 Library Usage
```rust
use handshacke::prelude::*;

let cfg = Config::from_env();
// Use establish_connection_from_offer(...) or connect_to(...) based on your flow.
```

## 📡 API Endpoints

⚠️ **Security note**: The API is not designed to be exposed without authentication.
Keep it bound to 127.0.0.1 unless you explicitly accept the risk.

See [SECURITY.md](SECURITY.md) for API security considerations.

### Connection Management
- `POST /v1/connect` - Establish P2P connection
- `GET /v1/status` - Get connection status
- `POST /v1/disconnect` - Close connection

### Messaging  
- `GET /v1/recv` - SSE stream for incoming messages
- `POST /v1/send` - Send encrypted packet

### Crypto Operations
- `POST /v1/set_passphrase` - Set encryption passphrase
- `POST /v1/seal` - Encrypt data to packet
- `POST /v1/open` - Decrypt packet to data

## 🛡️ Security

See [docs/threat_model_visibility.md](docs/threat_model_visibility.md) for comprehensive visibility analysis by transport layer.

See [docs/casestudy.md](docs/casestudy.md) for academic security analysis.

See [SECURITY.md](SECURITY.md) for vulnerability reporting and security policy.

**Key Security Properties**:
- **Content Confidentiality**: Only legitimate peers can read messages (Noise + XChaCha20-Poly1305)
- **Perfect Forward Secrecy**: Noise protocol provides forward secrecy
- **Zero Persistence**: Keys stored only in RAM, automatic zeroization
- **Metadata Protection**: Transport-dependent (see threat model)
- **DoS Resistance**: Early-drop filtering + rate limiting

**Security Trade-offs**:
- **LAN**: Fully exposed to local network (use stealth mode on untrusted LANs)
- **UPnP/NAT-PMP**: Gateway sees all mappings
- **Tor**: Strong anonymity but higher latency
- **Relay**: Centralized metadata (use via Tor to hide IP)

## 🔧 How It Works

### 1. Deterministic Parameters
```rust
// Both peers derive identical parameters from shared passphrase
let params = derive_from_passphrase("shared_secret");
// Results in same port, encryption keys, and tag
```

### 2. Transport Cascade
1. **LAN**: UDP broadcast discovery
2. **WAN**: UPnP/NAT-PMP port forwarding  
3. **Tor**: Stream fallback when direct WAN fails

Optional transports:
- **QUIC (RFC9000)**: framed stream over UDP
- **WebRTC DataChannel**: browser-compatible transport

### 3. Message Flow
```
[Message] → Encrypt → Tag + Nonce + Ciphertext → UDP → Peer
[Peer] → Tag Filter → Rate Limit → Decrypt → Replay Check → Display
```

## 🌐 Network Compatibility

- **LAN**: Direct UDP broadcast
- **Home Networks**: UPnP automatic port forwarding
- **Corporate/CGNAT**: NAT-PMP fallback
- **Restrictive NATs**: Tor fallback and assisted hole punching
- **IPv4/IPv6**: Dual-stack support (IPv4 primary)
- **Censorship**: Tor integration available
- **Interoperability**: Optional QUIC and WebRTC transports

## 🧭 Architecture

- [docs/architecture.md](docs/architecture.md)
- [docs/transport_matrix.md](docs/transport_matrix.md)
- [docs/feature_flags.md](docs/feature_flags.md)
- [docs/gui_flows.md](docs/gui_flows.md)

## 📊 Performance

- **Encryption**: 1000 encrypt/decrypt cycles < 1 second
- **Early Drop**: Tag filtering at line speed
- **Memory Usage**: Zero persistence, RAM-only operation
- **Latency**: Direct UDP, no relay servers (unless Tor)

## 📝 Development

See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines.

### Development Setup
```bash
# Setup hooks
git config commit.gpgsign true  # If using GPG
cargo install cargo-audit  # For security audits
```

### Running Tests
```bash
# Unit tests
cargo test

# Feature combinations
cargo test --no-default-features
cargo test --no-default-features --features pq
cargo test --no-default-features --features quic
cargo test --no-default-features --features webrtc

# Check for security vulnerabilities
cargo audit

# Check code quality
cargo clippy -- -D warnings
```

See [docs/testing.md](docs/testing.md) for the full test matrix and ignored tests.

## 📜 License

MIT License - See [LICENSE](LICENSE) file

## 🤝 Contributing

Contributions welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md). This project follows the Contributor Covenant Code of Conduct.

## 🔍 Security

For security issues, see [SECURITY.md](SECURITY.md). Do NOT report vulnerabilities in public issues.

## 🐛 Issues and Bugs

Report bugs via [GitHub Issues](https://github.com/omarsomaro/handshake/issues)

## 📋 Roadmap

- [ ] Pre-built binaries for major platforms
- [ ] Mobile app (iOS/Android)
- [ ] GUI desktop client
- [ ] Plugin system for custom transports
- [ ] Performance benchmarks

## 🎯 Mission

Handshacke enables **private, serverless communication** that respects user privacy and resists censorship.

## 📚 References

- [docs/threat_model_visibility.md](docs/threat_model_visibility.md) - Operational threat model
- [docs/casestudy.md](docs/casestudy.md) - Academic security analysis
- [docs/testing.md](docs/testing.md) - Test matrix and ignored tests
- [SECURITY.md](SECURITY.md) - Security policy

---

**Repository**: https://github.com/omarsomaro/handshake  
**Issues**: https://github.com/omarsomaro/handshake/issues  
**Security**: security@handshake-p2p.dev

**Handshacke** - When you need to connect without anyone knowing you're connecting. 🕵️‍♂️
