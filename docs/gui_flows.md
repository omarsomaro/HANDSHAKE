# GUI Flows (Spec)

This document defines the exact steps the GUI should expose for each mode.
All steps are derived from the current API behavior.

## 1) Classic Cascade (passphrase, no offer)
Use when you want automatic LAN/WAN/Assist/Tor fallback.

Host:
1. Enter passphrase
2. Choose Local Role = Host (or leave Auto)
3. Optional: set WAN mode (Direct/Auto/Tor) and Tor role
4. Click Connect (API: POST /v1/connect with passphrase + local_role)
5. If WAN direct is selected and succeeds, status becomes "listening"

Client:
1. Enter the same passphrase
2. Choose Local Role = Client (or leave Auto)
3. Optional: set WAN mode (Auto recommended)
4. Click Connect (API: POST /v1/connect with passphrase + local_role)
5. App attempts LAN -> WAN direct -> Assist -> Tor fallback

Inputs:
- passphrase (required)
- wan_mode (Direct | Auto | Tor)
- tor_role (Client | Host)
- target_onion (required if wan_mode=Tor and tor_role=Client)

Notes:
- Assist relays are used only if configured in env.
- Tor is used only if configured and permitted by wan_mode/tor_role.

## 2) Offer QR (endpoint-based)
Use when you want a single payload (QR) to carry all connection info.

Host:
1. Generate Offer (API: POST /v1/offer)
2. Optional: include_tor=true to embed Tor endpoint
3. Show the offer string as QR

Client:
1. Scan QR (offer string)
2. Click Connect (API: POST /v1/connect with offer)
3. Connection uses the offer endpoints and fallback rules

Inputs (host):
- passphrase (optional)
- ttl_s (optional)
- include_tor (optional)

Inputs (client):
- offer (required)
- local_role (optional override)

Notes:
- Passphrase is not required on the client when offer is provided.
- Tor is attempted only if the offer contains Tor data.
- Offer QR does NOT include the passphrase.
- Offer is enriched with STUN public endpoint hints when available.

Example payload (redacted):
```
offer: HSK1:AAEAA... (base64 string)
expires_at_ms: 1738790000000
endpoints: [Lan 192.168.1.20:51234, Wan 203.0.113.22:51234, tor]
```

## 3) Hybrid QR (resume + fallback)
Use when you want fast re-join with deterministic fallback.

Host:
1. Generate Hybrid QR (API: POST /v1/qr/hybrid)
2. Optional: include_tor=true to embed Tor endpoint
3. Show the Hybrid QR

Client:
1. Scan Hybrid QR
2. Click Connect (API: POST /v1/connect with qr)
3. Resume is attempted first, fallback to classic offer if resume fails

Inputs (host):
- passphrase (optional)
- ttl_s (optional)
- resume_ttl_s (optional)
- qr_ttl_s (optional)
- include_tor (optional)
- relay_hints (optional)

Inputs (client):
- qr (required)
- local_role (optional override)

Notes:
- Hybrid QR does NOT include the passphrase.
- Hybrid QR contains both a resume token and the deterministic offer.
- Expose expiry for QR and resume separately in the UI.

Example payload (redacted):
```
qr: HSKH1:AAEAA... (base64 string)
offer: HSK1:AAEAA... (embedded fallback offer)
expires_at_ms: 1738790000000
resume_expires_at_ms: 1738793600000
endpoints: [Lan 192.168.1.20:51234, Wan 203.0.113.22:51234, tor]
```

## 4) Target Connect (direct)
Use when you know the exact peer address.

Client:
1. Enter passphrase
2. Enter target (ip:port)
3. Click Connect (API: POST /v1/connect with passphrase + target)

Optional Tor target:
- If target is onion, use target_onion and set wan_mode=Tor, tor_role=Client.

Inputs:
- passphrase (required)
- target OR target_onion
- wan_mode/tor_role if Tor is used

Warnings:
- Direct target is fragile behind restrictive NAT/firewall.
- Prefer Offer/Hybrid QR with Tor relay when possible.

## 5) Phrase / Easy Tor (secure, no cascade)
Use for maximum privacy and simplicity. No LAN/WAN cascade.

Host:
1. Enter passphrase
2. Click "Open Phrase" (API: POST /v1/phrase/open)
3. Show invite (hs1:...) as QR

Client:
1. Scan invite
2. Enter the same passphrase
3. Click "Join Phrase" (API: POST /v1/phrase/join with invite + passphrase)

Notes:
- This flow uses Tor hidden services only.
- Requires Tor to be available (internal or external).

Example invite (redacted):
```
hs1:AAAA.... (phrase invite string)
```

## 6) Guaranteed Relay
Use when you want deterministic connectivity via a relay.

Host/Client (symmetric):
1. Enter passphrase
2. Select egress (public or tor)
3. Click Connect (API: POST /v1/connect with product_mode=guaranteed)

Inputs:
- passphrase (required)
- guaranteed_egress (public | tor)
- guaranteed_relay_url (optional override; otherwise env)

## Optional Mode Toggles (Environment)
These are not separate flows, but optional toggles:

- Pluggable transport:
  HANDSHACKE_PLUGGABLE_TRANSPORT = https | ftp | dns | websocket | quic | none
  HANDSHACKE_REALTLS_DOMAIN or HANDSHACKE_REALTLS_DOMAINS for Real TLS
  HANDSHACKE_REALTLS_MIMIC_PINS for mimicry pinning
  HANDSHACKE_WS_HOST for WebSocket host override

- Stealth discovery:
  HANDSHACKE_STEALTH_MODE = active | passive | mdns
  HANDSHACKE_STEALTH_PORT to enable stealth port randomization in offer

## Status/UX expectations
- Connected: mode string returned by API (lan/wan/stun/wan_tcp/wan_tor/quic/webrtc/phrase_tor)
- Listening: WAN direct host waiting for inbound
- Error: explicit error message on failure
- Resume status: returned by API when Hybrid QR is used

QR UX notes:
- Always display QR expiry (Offer) and both QR/resume expiry (Hybrid).
- Always explain that QR **does not** contain the passphrase.
- If NAT is Symmetric or UDP is blocked, guide user toward Offer/Hybrid QR + Tor relay.
