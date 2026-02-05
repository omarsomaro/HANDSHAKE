# Pluggable Transports Integration Kit

This project exposes pluggable transports as a **framework** module. Some modes require external server-side infrastructure to be truly effective or even functional. This document provides the minimum integration data to make them plug-and-play.

## Quick Matrix

Protocol | External Infra Required | Why
---|---|---
HttpsLike | No (peer-to-peer) | Fake TLS-like handshake; both peers must speak it
FtpData | No (peer-to-peer) | Fake FTP data channel; both peers must speak it
DnsTunnel | Optional | Works P2P, but realistic DNS requires authoritative server
WebSocket | Yes | Requires server-side WS handshake + framing
HTTP/2 | Yes | Mimicry-only; requires H2 preface + frame handling
QUIC (mimic) | Yes | Mimicry-only; requires QUIC-like response to Initial packets
RealTls | Yes | Requires valid certificate for SNI domain or a bridge

## Environment Variables

Use these to enable and configure the desired mode:

- `HANDSHACKE_PLUGGABLE_TRANSPORT=none|httpslike|ftpdata|dnstunnel|websocket|quic`
- `HANDSHACKE_REALTLS_DOMAIN=example.com` (only for RealTls)
- `HANDSHACKE_REALTLS_DOMAINS=example.com,api.example.com`
- `HANDSHACKE_REALTLS_MIMIC_PINS=domain|enforce:BASE64,BASE64;domain|warn:BASE64`
- `HANDSHACKE_WS_HOST=example.com` (WebSocket Host override)

API:
- `GET /v1/pluggable/check` (runtime checklist)

## External Infrastructure: What You Must Provide

### 1) RealTls
You must operate a server endpoint with a **valid certificate** for the SNI domain used.

Requirements:
- Publicly reachable host on `:443`
- Certificate valid for `HANDSHACKE_REALTLS_DOMAIN`
- Accepts TLS client connections
- Optionally forwards traffic to your internal P2P relay

Mimicry pinning:
- `HANDSHACKE_REALTLS_MIMIC_PINS` verifies issuer SPKI hashes for the target domain.
- This is for DPI evasion plausibility, not peer authentication.

### 2) WebSocket Mimic
You must provide a WebSocket endpoint that:
- Responds with `101 Switching Protocols`
- Supports WS framing (binary frames)
- Forwards payloads to your peer or relay

Suggested endpoint fields:
- Host: `wss://your-domain:443`
- Path: `/ws`
- Headers: standard WS upgrade

### 3) HTTP/2 Mimic
You must provide an H2 endpoint that:
- Accepts client connection preface
- Handles SETTINGS + DATA frames
- Forwards payloads to your peer or relay

### 4) QUIC Mimic
You must provide a QUIC-like server that:
- Responds to Initial packets
- Handles CHLO/SHLO (or your custom variant)
- Forwards payloads to your peer or relay

## Suggested Integration Flow

1. Run your relay / server-side mimic endpoint.
2. Enable desired transport via env vars.
3. Confirm API reports the protocol as enabled.
4. Test with a controlled peer before production use.

## Notes

- These transports are **experimental** and may be fingerprintable if misconfigured.
- Real TLS does **not** work without valid certificates.
- DNS tunnel looks realistic only when backed by an authoritative DNS server.
- HTTP/2 and QUIC are mimicry-only and do not implement full protocol security.
