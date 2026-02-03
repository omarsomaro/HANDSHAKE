# Handshacke user flows (current codebase)

## Core runtime (API server)
1) Start core server:
   - `handshacke` (no subcommand)
   - Starts API server at `HANDSHACKE_API_BIND` (default `127.0.0.1:3000`).

### Auto-role determination (passphrase mode)
- If `local_role` is provided, it overrides everything.
- Otherwise, if `tor_role=host` → `NoiseRole::Responder`.
- Otherwise, if `tor_role=client` → `NoiseRole::Initiator`.
- WAN listening always uses `NoiseRole::Responder`.

2) Connect with passphrase (no offer):
   - API: `POST /v1/connect` with `passphrase`.
   - If `target` is provided: active dial to a specific peer (WAN UDP or Tor onion).
   - If no `target`:
     - LAN/WAN/Tor path via `transport::establish_connection` (per `wan_mode`).
     - LAN returns immediately as connected (broadcast + reply).
     - WAN Direct returns `listening` and spawns a background accept that waits for the first Noise handshake.
     - This `listening` state happens when WAN Direct is selected (either `wan_mode=direct` or `wan_mode=auto` with Direct mapping success).

3) Connect with Offer (v2 capability token):
   - API: `POST /v1/connect` with `offer`.
   - Offer is decoded and verified (ver/ttl/commit).
   - Happy-eyeballs across endpoints; winner completes Noise upgrade + SessionKey.

4) Generate Offer:
   - API: `POST /v1/offer` with optional `passphrase`, `ttl_s`, `role_hint`, `include_tor`.
   - Includes LAN endpoints by local IP, WAN endpoint if UPnP/NAT-PMP mapping succeeds, Tor endpoint if configured.

5) Send/receive data:
   - API: `POST /v1/send` to push app bytes.
   - API: `GET /v1/recv` SSE stream to receive bytes.

6) Disconnect:
   - API: `POST /v1/disconnect` to stop tasks and clear crypto state.

## CLI flows (hs-cli)
1) Host + offer (QR string):
   - `hs-cli host [--passphrase] [--include-tor] [--ttl_s <sec>]`
   - Calls `/v1/connect` with `passphrase` and `local_role=host`.
   - Calls `/v1/offer` with same passphrase and prints the Offer string.

2) Join from offer:
   - `hs-cli join <offer>`
   - Calls `/v1/connect` with `offer` and follows happy-eyeballs.

## Tor helper CLI (onionize)
1) Host mode (spawn Tor, create onion):
   - `handshacke onionize --host --port <p> --start-tor`
   - Creates ephemeral torrc and HiddenServiceDir, prints onion address.

2) Client mode (prepare Tor settings):
   - `handshacke onionize --client <onion:port> [--start-tor]`
   - Verifies SOCKS5 or starts Tor child.
   - Prints environment config to use for Tor client mode.

# How Handshacke finds a peer (all discovery paths)

1) LAN broadcast discovery (UDP)
   - Uses LAN broadcast to send a discovery packet.
   - Responder replies directly (unicast).
   - Noise upgrade happens after discovery; session_key is used for app traffic.

2) WAN Direct passive listening (UPnP/NAT-PMP/PCP mapping)
   - Host: `try_direct_port_forward` maps UDP port.
   - API returns `status: listening`.
   - Background accept waits for first valid Noise handshake packet on the mapped port.

3) WAN Direct active dial (explicit target)
   - Client: `POST /v1/connect` with `passphrase` + `target`.
   - Creates UDP socket, sends probe burst, waits for reply.
   - On early-drop tag match, starts Noise upgrade.

4) Tor transport (SOCKS5)
   - Client: connect to onion target via SOCKS5 (`wan_tor::try_tor_connect`).
   - Host: Tor HiddenService forwards to local listener.
   - Noise upgrade happens after TCP connect; framing is used on the stream.

5) Offer v2 happy-eyeballs (multi-endpoint race)
   - Offer includes LAN/WAN/Tor endpoints and TTL.
   - Client races endpoints concurrently and keeps the first one that completes Noise upgrade.
   - Others are cancelled.

6) Direct target with onion (Tor)
   - `target` accepts `*.onion:port` and goes through Tor SOCKS5.
   - Same as Tor transport, but bypasses Offer.
