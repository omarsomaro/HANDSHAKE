# Handshacke Desktop UI (Tauri v2)

This desktop UI spawns and controls the local `handshacke` daemon as a sidecar.
The API is bound to localhost by default and the bearer token is read from the
file specified in `HANDSHACKE_API_TOKEN_FILE`.

## Setup (Windows)

1) Build the daemon binary:

```bash
cd ..
cargo build --release
```

2) Copy the daemon into the sidecar folder:

```bash
mkdir ui\\src-tauri\\bin
copy ..\\target\\release\\handshacke.exe ui\\src-tauri\\bin\\handshacke.exe
```

3) Install UI dependencies:

```bash
cd ui
npm install
```

4) Run the desktop app:

```bash
npm run dev
```

## Build (Windows)

```bash
cd ui
npm run build
```

## Token file storage

The daemon writes a random bearer token to the file specified by
`HANDSHACKE_API_TOKEN_FILE`. The UI sets this path under the app data directory.
On Windows, file ACLs are not forced by the app; ensure the directory is private.
When the daemon stops, the file is removed.

## Behavior notes

- The GUI never logs the passphrase.
- The token is read from the file and kept in memory only.
- If `api_bind` is `0.0.0.0`, `--unsafe-expose-api` is required and a warning is shown.

## GUI overview

The desktop UI is a full-power Tauri v2 app, not a thin client. It ships a
native Rust backend that spawns the `handshacke` daemon as a sidecar and a
React frontend that drives the API via bearer token.

### Tech stack

- **Backend (Rust)**: Tauri v2 commands (`start_daemon`, `stop_daemon`, `daemon_status`)
- **Frontend (TypeScript/React)**: Vite + React UI in `src/App.tsx`
- **Plugins**: `@tauri-apps/plugin-shell` (sidecar spawn), `@tauri-apps/plugin-fs` (token file)

### Components

- **Sidecar daemon control**: starts `handshacke.exe` with `HANDSHACKE_API_TOKEN_FILE`
- **Auth pipeline**: reads token from file and attaches `Authorization: Bearer`
- **START AUTO flow**: start daemon → load token → set passphrase → connect → SSE + polling
- **Invite UI**: generates offers and renders QR codes
