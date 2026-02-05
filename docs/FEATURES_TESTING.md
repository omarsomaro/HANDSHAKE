# Features & Testing (Current)

This guide reflects the **current** Handshacke feature set and test flows.

## ✅ Core Flows to Validate

### 1) Offer QR (endpoint-based)
**Goal**: quick pairing without typing addresses.

**Host**
```
POST /v1/offer
```
Show offer as QR. Confirm endpoints include LAN/WAN and (optional) Tor.

**Client**
```
POST /v1/connect { "offer": "<offer>" }
```

Expected:
- Connects on the best path (LAN/WAN/STUN/ICE)
- UI shows mode and endpoints

### 2) Hybrid QR (resume + fallback)
**Goal**: fast re-join + deterministic fallback.

**Host**
```
POST /v1/qr/hybrid
```

**Client**
```
POST /v1/connect { "qr": "<hybrid_qr>" }
```

Expected:
- Resume attempted first
- Fallback to classic offer if resume fails
- UI shows resume status

### 3) Phrase / Easy Tor
**Goal**: privacy-first pairing via Tor.

**Host**
```
POST /v1/phrase/open
```

**Client**
```
POST /v1/phrase/join { "invite": "<hs1:...>", "passphrase": "..." }
```

Expected:
- Tor-only connection, `mode=phrase_tor`

### 4) Target direct (UDP/TCP fallback)
**Goal**: connect when you know the exact IP:port.

```
POST /v1/connect { "passphrase": "...", "target": "ip:port" }
```

Expected:
- UDP path attempted
- If UDP blocked, TCP fallback (mode `wan_tcp`)

## 🌐 NAT / Network Scenarios

### Symmetric NAT fast-path
Expected:
- Skip direct/UPnP/STUN
- Prefer relay/Tor

### UDP blocked firewall
Expected:
- TCP fallback is attempted
- Warning suggests Offer/Hybrid QR + Tor relay

### IPv6-first dual stack
Expected:
- IPv6 endpoints used when available
- IPv4 fallback works

## 🔒 Security / Crypto

### PQ fallback
Expected:
- If PQ handshake fails or is unavailable, classic Noise XX is used

### Key rotation
Expected:
- Session keys rotate by time and/or message count
- Grace window allows decrypting with previous key

## 🧪 Diagnostics

```
GET /v1/metrics
```
Expected:
- nat_type set when detection succeeds
- transport_mode matches current path

## 🧪 Pluggable Transports

```
GET /v1/pluggable/check
```
Expected:
- real_tls / websocket / http2 / quic status shown
- HTTP/2 and QUIC marked mimicry-only

## 🔧 Suggested Log Filter
```
RUST_LOG=handshacke=debug,info cargo run --release
```

## ✅ Release Checklist (Current)
- [ ] Offer QR flow validated
- [ ] Hybrid QR flow validated
- [ ] Phrase/Tor flow validated
- [ ] Target direct TCP fallback validated
- [ ] Symmetric NAT fast-path validated
- [ ] IPv6-first behavior validated
- [ ] Pluggable status endpoint validated
- [ ] Metrics endpoint validated
