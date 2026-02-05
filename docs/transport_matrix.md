# Transport Matrix

This matrix summarizes current transport options and their trade-offs.

Legend:
- Reliability: low / medium / high
- Privacy: low / medium / high
- Status: stable / experimental

| Transport           | Reliability | Privacy | NAT/Firewall | Status       | Notes |
|--------------------|-------------|---------|--------------|--------------|-------|
| LAN (UDP broadcast) | high        | low     | LAN only     | stable       | Fastest path on local networks |
| WAN Direct (UDP)   | medium      | low     | UPnP/NAT-PMP | stable       | Requires port mapping on gateway |
| STUN Hole Punch    | medium      | low     | NAT-dependent | stable      | Uses public endpoint hints and coordinated punch |
| WAN Assist (UDP)   | medium      | medium  | relay helps  | stable       | Relay adds metadata exposure |
| WAN TCP Fallback   | low         | low     | UDP blocked  | stable       | Target connect fallback when UDP is blocked |
| Tor (stream)       | medium      | high    | works widely | stable       | Higher latency, best anonymity |
| Guaranteed Relay   | high        | medium  | works widely | stable       | Relay-backed deterministic connectivity |
| QUIC (RFC9000)     | high        | medium  | UDP required | experimental | Framed streams over QUIC |
| WebRTC DataChannel | high        | medium  | ICE/STUN     | experimental | Great for browser interop |

Notes:
- QUIC/WebRTC are optional features.
- Noise PQ hybrid is enabled only on stream transports when the pq feature is on (with classic fallback).
- Symmetric NAT fast-paths to relay/Tor to avoid futile direct attempts.

QR flow notes:
- Offer QR: endpoints + rendezvous params (no passphrase).
- Hybrid QR: resume token + fallback offer.
- Phrase QR: Tor-only invite (no passphrase).
