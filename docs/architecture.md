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

2) Transport
   - LAN, WAN direct, WAN assist, Tor fallback
   - Multipath/ICE racing for best path
   - Pluggable transports for DPI evasion
   - Optional QUIC and WebRTC for standards-based connectivity

3) Session security
   - Noise XX handshake upgrade
   - PQ hybrid only on stream transports (if enabled)

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

## Invariants and limits
- UDP packets: bounded by MAX_UDP_PACKET_BYTES
- Stream frames (TCP/Tor/QUIC): bounded by MAX_TCP_FRAME_BYTES
- WebRTC messages: bounded by WEBRTC_MAX_MESSAGE_BYTES

## Extension points
- Add new transports via transport modules and Connection variants
- Add new pluggable transports via transport/pluggable
- Add alternative offer encodings or rendezvous strategies
