# Architecture

This document describes the core architecture and the responsibilities of each layer.

## Goals
- Deterministic rendezvous without centralized discovery
- Strong confidentiality and replay protection
- Multiple transport options with graceful fallback
- Clear separation between transport and session security

## Layers
1) Offer and rendezvous
   - Deterministic parameters derived from passphrase
   - Offer commit (HMAC) for integrity
   - Optional Tor endpoint encryption
   - Hybrid QR: resume token + deterministic fallback offer

2) Transport
   - LAN, WAN direct, WAN assist, Tor fallback
   - STUN discovery and hole punching (QR/offer aware)
   - TCP fallback when UDP is blocked (target connect)
   - Multipath/ICE racing for best path
   - Pluggable transports for DPI evasion
   - Optional QUIC and WebRTC for standards-based connectivity

3) Session security
   - Noise XX handshake upgrade
   - PQ hybrid only on stream transports (if enabled) with classic fallback
   - Key rotation with grace window

4) Messaging
   - Framed streams for reliability
   - Tag-based early drop and rate limiting
   - Replay window protection

## Primary flow (host and client)
1) Both peers derive the same rendezvous parameters from a passphrase
2) Host publishes an OfferPayload
3) Client receives offer and starts multipath/ICE connect
4) Connection is established on best transport
5) Noise handshake upgrades the session key
6) App data uses the session key with replay protection

## QR Reasoning (Why QR Is Primary for UX)
- QR payloads are **time-limited rendezvous envelopes**, not passwords.
- They encode endpoints + timing so peers align without manual typing.
- Hybrid QR improves reliability by combining resume tokens with deterministic fallback.
- Phrase QR keeps Tor invite separate from the passphrase for privacy.

## Invariants and limits
- UDP packets: bounded by MAX_UDP_PACKET_BYTES
- Stream frames (TCP/Tor/QUIC): bounded by MAX_TCP_FRAME_BYTES
- WebRTC messages: bounded by WEBRTC_MAX_MESSAGE_BYTES

## Extension points
- Add new transports via transport modules and Connection variants
- Add new pluggable transports via transport/pluggable
- Add alternative offer encodings or rendezvous strategies
