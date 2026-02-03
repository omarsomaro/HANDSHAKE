use axum::http::header::AUTHORIZATION;
use axum::http::StatusCode;
use axum::http::{Request, StatusCode as AxumStatusCode};
use axum::{
    extract::{ConnectInfo, Extension, State},
    middleware::{from_fn_with_state, Next},
    response::{
        sse::{Event, Sse},
        IntoResponse,
    },
    routing::{get, post},
    Json, Router,
};
use base64::{engine::general_purpose, Engine as _};
use secrecy::SecretString;
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::{net::SocketAddr, sync::Arc, time::Duration};
use subtle::ConstantTimeEq;
use tokio::{
    sync::{mpsc, RwLock},
    time::{interval, timeout},
};
use tower::ServiceBuilder;
use tower_http::{
    cors::{Any, CorsLayer},
    trace::TraceLayer,
};

use crate::onion::validate_onion_addr;
use crate::phrase::PhraseInvite;
use crate::transport::assist_inbox::{AssistInbox, AssistInboxRequest};
use crate::{
    config::{
        Config, GuaranteedEgress, ProductMode, TorRole, WanMode, DEFAULT_CHANNEL_CAPACITY,
        UDP_MAX_PACKET_SIZE,
    },
    crypto::{
        deserialize_cipher_packet_with_limit, now_ms, now_us, open, seal, serialize_cipher_packet,
        CipherPacket, ClearPayload, MAX_TCP_FRAME_BYTES, MAX_UDP_PACKET_BYTES,
    },
    derive::{derive_from_secret, derive_tag8_from_key},
    offer::{OfferPayload, RoleHint},
    protocol::Control,
    security::{RateLimiter, TimeValidator},
    state::{AppState, CryptoTimer, DebugMetrics},
    transport::{self, Connection},
};

const PHRASE_VIRT_PORT: u16 = 443;

#[derive(Debug, Serialize)]
pub struct ApiError {
    pub code: u16,
    pub message: String,
}

impl ApiError {
    pub fn bad_request(msg: &str) -> Self {
        Self {
            code: StatusCode::BAD_REQUEST.as_u16(),
            message: msg.to_string(),
        }
    }

    pub fn operation_failed() -> Self {
        Self {
            code: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            message: "operation failed".to_string(),
        }
    }
}

impl From<anyhow::Error> for ApiError {
    fn from(err: anyhow::Error) -> Self {
        tracing::error!("API error: {:?}", err);
        Self::operation_failed()
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> axum::response::Response {
        let code = StatusCode::from_u16(self.code).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        (code, Json(self)).into_response()
    }
}

#[derive(Debug, Deserialize)]
pub struct ConnectionRequest {
    pub passphrase: Option<String>,
    pub offer: Option<String>,
    pub local_role: Option<RoleHint>,
    pub target: Option<String>,
    #[serde(default)]
    pub wan_mode: WanMode,
    #[serde(default)]
    pub tor_role: TorRole,
    #[serde(default)]
    pub product_mode: ProductMode,
    #[serde(default)]
    pub guaranteed_egress: GuaranteedEgress,
    pub guaranteed_relay_url: Option<String>,
    /// Required if wan_mode=Tor && role=Client. Format: "abc...xyz.onion:PORT"
    pub target_onion: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ConnectionResponse {
    pub status: String,
    pub port: Option<u16>,
    pub mode: String,
    pub peer: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct SendRequest {
    pub packet_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct PhraseOpenRequest {
    pub passphrase: String,
}

#[derive(Debug, Deserialize)]
pub struct PhraseJoinRequest {
    pub invite: String,
    pub passphrase: String,
}

#[derive(Debug, Serialize)]
pub struct PhraseOpenResponse {
    pub onion: String,
    pub virt_port: u16,
    pub invite: String,
}

#[derive(Debug, Serialize)]
pub struct PhraseStatusResponse {
    pub status: String,
    pub onion: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SetPass {
    passphrase: String,
}

#[derive(Debug, Deserialize)]
struct SealReq {
    data_b64: String,
}

#[derive(Debug, Deserialize)]
struct OpenReq {
    packet_b64: String,
}

#[derive(Debug, Serialize)]
struct SealRes {
    packet_b64: String,
}

#[derive(Debug, Serialize)]
struct OpenRes {
    data_b64: String,
}

#[derive(Debug, Serialize)]
struct SetPassRes {
    status: String,
    port: u16,
    tag16: u16,
}
#[derive(Clone)]
pub struct Streams {
    pub tx: mpsc::Sender<Vec<u8>>,                            // RX→SSE
    pub rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>, // RX→SSE
    pub tx_out: mpsc::Sender<Vec<u8>>,                        // /send → sender task
}

#[derive(Clone)]
pub struct ApiState {
    pub app: AppState,
    pub streams: Streams,
}

impl Streams {
    pub fn new() -> (Self, mpsc::Receiver<Vec<u8>>) {
        let (tx, rx) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        (
            Self {
                tx,
                rx: Arc::new(tokio::sync::Mutex::new(rx)),
                tx_out,
            },
            rx_out,
        )
    }
}

type ConnectResult = Result<Json<ConnectionResponse>, ApiError>;

fn connect_err(code: StatusCode, msg: &str) -> ApiError {
    ApiError {
        code: code.as_u16(),
        message: msg.to_string(),
    }
}

pub async fn create_api_server(
    state: AppState,
    streams: Streams,
    bind: String,
    api_token: Option<String>,
) -> anyhow::Result<()> {
    /// Request for simultaneous open sync
    #[derive(Debug, Deserialize)]
    struct SimultaneousOpenRequest {
        my_offer: String,    // Base64 encoded OfferPayload
        their_hash: String,  // Base64 encoded offer hash (32 bytes)
        relay_onion: String, // Relay onion address
    }

    /// Response for simultaneous open sync
    #[derive(Debug, Serialize)]
    struct SimultaneousOpenResponse {
        success: bool,
        offset_ms: Option<i64>,
        rendezvous_at: Option<u64>,
        error: Option<String>,
    }

    /// Handle /v1/rendezvous/sync - Coordinate simultaneous open via relay
    async fn handle_simultaneous_open_sync(
        ConnectInfo(addr): ConnectInfo<SocketAddr>,
        Extension(state): Extension<Arc<ApiState>>,
        Json(req): Json<SimultaneousOpenRequest>,
    ) -> Result<Json<SimultaneousOpenResponse>, StatusCode> {
        if !state.app.api_allow(addr.ip(), 1.0).await {
            return Err(StatusCode::TOO_MANY_REQUESTS);
        }

        // Create config local (like handle_connect line 418)
        let cfg = Config::from_env();

        // Decode offer
        let offer_bytes = match general_purpose::STANDARD.decode(&req.my_offer) {
            Ok(b) => b,
            Err(e) => {
                return Ok(Json(SimultaneousOpenResponse {
                    success: false,
                    offset_ms: None,
                    rendezvous_at: None,
                    error: Some(format!("Invalid offer encoding: {}", e)),
                }));
            }
        };

        let my_offer: OfferPayload = match bincode::deserialize(&offer_bytes) {
            Ok(o) => o,
            Err(e) => {
                return Ok(Json(SimultaneousOpenResponse {
                    success: false,
                    offset_ms: None,
                    rendezvous_at: None,
                    error: Some(format!("Invalid offer: {}", e)),
                }));
            }
        };

        // Decode hash (32 bytes)
        let their_hash = match general_purpose::STANDARD.decode(&req.their_hash) {
            Ok(h) if h.len() == 32 => {
                let mut hash = [0u8; 32];
                hash.copy_from_slice(&h);
                hash
            }
            _ => {
                return Ok(Json(SimultaneousOpenResponse {
                    success: false,
                    offset_ms: None,
                    rendezvous_at: None,
                    error: Some("Invalid hash: must be 32 bytes".to_string()),
                }));
            }
        };

        // Use the WAN assist coordination module
        let result = crate::transport::wan_assist::coordination::try_simultaneous_or_sequential(
            &my_offer,
            their_hash,
            &[req.relay_onion],
            &cfg, // Use the cfg created above
        )
        .await;

        match result {
            Ok(_conn) => {
                Ok(Json(SimultaneousOpenResponse {
                    success: true,
                    offset_ms: my_offer.ntp_offset,
                    rendezvous_at: Some(my_offer.timestamp + 30000), // 30 seconds
                    error: None,
                }))
            }
            Err(e) => Ok(Json(SimultaneousOpenResponse {
                success: false,
                offset_ms: my_offer.ntp_offset,
                rendezvous_at: None,
                error: Some(e.to_string()),
            })),
        }
    }

    async fn handle_pluggable_protocols() -> impl axum::response::IntoResponse {
        axum::Json(serde_json::json!({
            "protocols": ["websocket", "quic", "http2", "none"]
        }))
    }

    let state = std::sync::Arc::new(ApiState {
        app: state,
        streams,
    });
    let mut app = Router::new()
        .route("/v1/connect", post(handle_connect))
        .route("/v1/status", get(handle_status))
        .route("/v1/send", post(handle_send))
        .route("/v1/recv", get(handle_recv_sse))
        .route("/v1/set_passphrase", post(handle_set_passphrase))
        .route("/v1/seal", post(handle_seal))
        .route("/v1/open", post(handle_open))
        .route("/v1/disconnect", post(handle_disconnect))
        .route("/v1/metrics", get(handle_metrics))
        .route("/v1/pluggable/protocols", get(handle_pluggable_protocols))
        .route("/v1/rendezvous/sync", post(handle_simultaneous_open_sync))
        .route("/v1/circuit", get(handle_circuit_status))
        .route("/v1/offer", post(crate::api_offer::handle_offer_generate))
        .route("/v1/phrase/open", post(handle_phrase_open))
        .route("/v1/phrase/close", post(handle_phrase_close))
        .route("/v1/phrase/join", post(handle_phrase_join))
        .route("/v1/phrase/status", get(handle_phrase_status))
        .layer(Extension(state))
        .layer(ServiceBuilder::new().layer(TraceLayer::new_for_http()));

    if let Some(token) = api_token {
        let token = std::sync::Arc::new(token);
        app = app.layer(from_fn_with_state(token, require_bearer));
    } else {
        let cors = CorsLayer::new()
            .allow_methods(Any)
            .allow_headers(Any)
            .allow_origin(Any);
        app = app.layer(cors);
    }

    let listener = tokio::net::TcpListener::bind(&bind).await?;
    tracing::info!("API server listening on http://{}", bind);
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;
    Ok(())
}

async fn require_bearer(
    State(token): State<std::sync::Arc<String>>,
    req: Request<axum::body::Body>,
    next: Next,
) -> axum::response::Response {
    let Some(auth_header) = req.headers().get(AUTHORIZATION) else {
        return AxumStatusCode::UNAUTHORIZED.into_response();
    };
    let Ok(auth_str) = auth_header.to_str() else {
        return AxumStatusCode::UNAUTHORIZED.into_response();
    };
    let expected = format!("Bearer {}", token.as_str());
    let auth_bytes = auth_str.as_bytes();
    let expected_bytes = expected.as_bytes();
    if auth_bytes.len() != expected_bytes.len() || !bool::from(auth_bytes.ct_eq(expected_bytes)) {
        return AxumStatusCode::UNAUTHORIZED.into_response();
    }
    next.run(req).await
}

async fn handle_connect(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<ConnectionRequest>,
) -> ConnectResult {
    let app = state.app.clone();
    let streams = state.streams.clone();
    if !app.api_allow(addr.ip(), 5.0).await {
        return Err(connect_err(StatusCode::TOO_MANY_REQUESTS, "rate limit"));
    }
    if req.offer.is_some() && req.passphrase.is_some() {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "provide either passphrase or offer, not both",
        ));
    }
    if req.offer.is_some() && req.target.is_some() {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "target not allowed with offer",
        ));
    }
    if req.target.is_some() && req.passphrase.is_none() {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "passphrase required for target connect",
        ));
    }

    let product_mode = req.product_mode;

    // Validate A/B request semantics
    if product_mode == ProductMode::Guaranteed && req.target_onion.is_some() {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "target_onion not allowed in guaranteed mode",
        ));
    }

    // Validate Tor config (Classic only)
    if product_mode == ProductMode::Classic
        && req.wan_mode == WanMode::Auto
        && req.tor_role == TorRole::Host
    {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "Auto mode is only valid with TorRole::Client",
        ));
    }
    if product_mode == ProductMode::Classic
        && (req.wan_mode == WanMode::Tor || req.wan_mode == WanMode::Auto)
        && req.tor_role == TorRole::Client
        && req.target_onion.is_none()
    {
        return Err(connect_err(
            StatusCode::BAD_REQUEST,
            "target_onion required for Tor Client mode",
        ));
    }

    // Validate target_onion format if provided (Classic only)
    if product_mode == ProductMode::Classic {
        if let Some(ref onion) = req.target_onion {
            if !onion.contains(':') || !onion.contains(".onion") {
                return Err(connect_err(
                    StatusCode::BAD_REQUEST,
                    "target_onion must be in format 'address.onion:PORT'",
                ));
            }
        }
    }

    // Guaranteed mode: relay-backed transport with optional Tor egress.
    if product_mode == ProductMode::Guaranteed {
        if req.offer.is_some() || req.target.is_some() || req.target_onion.is_some() {
            return Err(connect_err(
                StatusCode::BAD_REQUEST,
                "offer/target not allowed in guaranteed mode",
            ));
        }
        let passphrase = match req.passphrase {
            Some(p) => SecretString::from(p),
            None => return Err(connect_err(StatusCode::BAD_REQUEST, "passphrase required")),
        };
        let mut cfg = Config::from_env();
        if let Some(url) = req.guaranteed_relay_url.clone() {
            if !url.trim().is_empty() {
                cfg.guaranteed_relay_url = url;
            }
        }

        let params = derive_from_secret(&passphrase);
        let io = match crate::transport::guaranteed::establish_connection_guaranteed(
            &params,
            &cfg,
            req.guaranteed_egress,
        )
        .await
        {
            Ok(io) => io,
            Err(e) => {
                tracing::error!("Guaranteed connect failed: {:?}", e);
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let noise_role = match req.local_role {
            Some(RoleHint::Host) => crate::session_noise::NoiseRole::Responder,
            Some(RoleHint::Client) => crate::session_noise::NoiseRole::Initiator,
            None => crate::session_noise::NoiseRole::Initiator,
        };

        let params_noise = match crate::session_noise::pq_noise_params() {
            Ok(p) => p,
            Err(_) => crate::session_noise::classic_noise_params()
                .map_err(|_| connect_err(StatusCode::BAD_GATEWAY, "operation failed"))?,
        };

        let session_key = match crate::session_noise::run_noise_upgrade_io(
            noise_role,
            {
                let io = io.clone();
                move |data: Vec<u8>| {
                    let io = io.clone();
                    async move { io.send(data).await }
                }
            },
            {
                let io = io.clone();
                move || {
                    let io = io.clone();
                    async move { io.recv().await }
                }
            },
            &params.key_enc,
            params.tag16,
            params.tag8,
            params_noise,
            io.max_packet_limit(),
        )
        .await
        {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("Guaranteed noise handshake failed: {:?}", e);
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let session_cipher_params = (session_key, params.tag16, params.tag8);
        tracing::info!("Guaranteed noise upgrade completed");

        let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        app.set_tx_out(tx_out.clone()).await;

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        app.set_stop_tx(stop_tx).await;

        let updated_streams = Streams {
            tx: streams.tx,
            rx: streams.rx,
            tx_out,
        };

        let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
        let rl = RateLimiter::new(
            cfg.rate_limit_capacity,
            cfg.rate_limit_max_requests,
            rl_duration,
        );

        let stop_rx1 = stop_rx.clone();
        let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop_io(
            io.clone(),
            updated_streams.clone(),
            session_cipher_params,
            rl,
            stop_rx1,
        )
        .await;

        let stop_rx2 = stop_rx.clone();
        let metrics = app.get_metrics().await;
        let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop_io(
            io,
            rx_out,
            stop_rx2,
            metrics,
            session_cipher_params,
            match noise_role {
                crate::session_noise::NoiseRole::Initiator => 0x01,
                crate::session_noise::NoiseRole::Responder => 0x02,
            },
        )
        .await;

        let mut s = app.get_connection_state().await;
        s.port = None;
        s.mode = Some("guaranteed".into());
        s.status = crate::state::ConnectionStatus::Connected;
        s.peer_address = None;
        app.set_connection_state(s).await;

        return Ok(Json(ConnectionResponse {
            status: "connected".into(),
            port: None,
            mode: "guaranteed".into(),
            peer: None,
        }));
    }

    let mut cfg = Config::from_env();
    cfg.wan_mode = req.wan_mode;
    cfg.tor_role = req.tor_role;
    if let Some(onion) = req.target_onion.clone() {
        cfg.tor_onion_addr = Some(onion);
    }

    if let Some(offer_b64) = req.offer {
        let offer = match OfferPayload::decode(&offer_b64) {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!("Offer decode failed: {:?}", e);
                return Err(connect_err(StatusCode::BAD_REQUEST, "invalid request"));
            }
        };
        let time_validator = TimeValidator::new();
        if let Err(e) = offer.verify(&time_validator) {
            tracing::warn!("Offer verify failed: {:?}", e);
            return Err(connect_err(StatusCode::BAD_REQUEST, "invalid request"));
        }

        let local_role = req.local_role.unwrap_or(match offer.role_hint {
            RoleHint::Host => RoleHint::Client,
            RoleHint::Client => RoleHint::Host,
        });

        let result = match transport::establish_connection_from_offer(
            &offer,
            &cfg,
            local_role.clone(),
        )
        .await
        {
            Ok(r) => r,
            Err(e) => {
                tracing::error!("Offer connect failed: {:?}", e);
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
        let rl = RateLimiter::new(
            cfg.rate_limit_capacity,
            cfg.rate_limit_max_requests,
            rl_duration,
        );

        let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        app.set_tx_out(tx_out.clone()).await;
        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        app.set_stop_tx(stop_tx).await;

        let updated_streams = Streams {
            tx: streams.tx,
            rx: streams.rx,
            tx_out,
        };

        tracing::info!("Noise upgrade completed, session key installed");

        let stop_rx1 = stop_rx.clone();
        let tag8 = derive_tag8_from_key(&offer.rendezvous.key_enc);
        let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
            result.conn.clone(),
            updated_streams.clone(),
            (result.session_key, offer.rendezvous.tag16, tag8),
            rl,
            stop_rx1,
        )
        .await;

        let stop_rx2 = stop_rx.clone();
        let metrics = app.get_metrics().await;
        let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
            result.conn,
            rx_out,
            stop_rx2,
            metrics,
            (result.session_key, offer.rendezvous.tag16, tag8),
            match local_role {
                RoleHint::Host => 0x02,
                RoleHint::Client => 0x01,
            },
        )
        .await;

        let mode = result.mode.clone();
        let peer = result.peer.clone();
        let mut s = app.get_connection_state().await;
        s.port = Some(offer.rendezvous.port);
        s.mode = Some(mode.clone());
        s.status = crate::state::ConnectionStatus::Connected;
        s.peer_address = peer.clone();
        app.set_connection_state(s).await;

        return Ok(Json(ConnectionResponse {
            status: "connected".into(),
            port: Some(offer.rendezvous.port),
            mode,
            peer,
        }));
    }

    let passphrase = match req.passphrase {
        Some(p) => SecretString::from(p),
        None => {
            return Err(connect_err(StatusCode::BAD_REQUEST, "passphrase required"));
        }
    };

    let params = derive_from_secret(&passphrase);

    if !cfg.assist_relays.is_empty() {
        let is_host = match req.local_role {
            Some(RoleHint::Host) => true,
            Some(RoleHint::Client) => false,
            None => req.tor_role == TorRole::Host,
        };
        let state_snapshot = app.get_connection_state().await;
        if is_host && state_snapshot.status == crate::state::ConnectionStatus::Disconnected {
            for relay in cfg.assist_relays.clone() {
                let (inbox, mut rx) = AssistInbox::new(relay.clone(), params.clone());
                tokio::spawn(async move {
                    while let Some(req) = rx.recv().await {
                        match req {
                            AssistInboxRequest::V4(req) => {
                                tracing::info!("Assist request received: {:?}", req.request_id);
                            }
                            AssistInboxRequest::V5(req) => {
                                tracing::info!("Assist request v5 received: {:?}", req.request_id);
                            }
                        }
                    }
                });
                let cfg_clone = cfg.clone();
                tokio::spawn(async move {
                    let _ = inbox.run(&cfg_clone).await;
                });
            }
        }
    }
    if let Some(target) = req.target.clone() {
        let conn = match transport::connect_to(&target, &params, &cfg).await {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Target connect failed: {:?}", e);
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
        let rl = RateLimiter::new(
            cfg.rate_limit_capacity,
            cfg.rate_limit_max_requests,
            rl_duration,
        );

        let noise_role = match req.local_role {
            Some(RoleHint::Host) => crate::session_noise::NoiseRole::Responder,
            Some(RoleHint::Client) => crate::session_noise::NoiseRole::Initiator,
            None => crate::session_noise::NoiseRole::Initiator,
        };

        let session_key = match crate::session_noise::run_noise_upgrade(
            noise_role,
            &conn,
            &params.key_enc,
            params.tag16,
            params.tag8,
        )
        .await
        {
            Ok(k) => k,
            Err(e) => {
                tracing::error!("Noise handshake failed: {:?}", e);
                return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
            }
        };

        let session_cipher_params = (session_key, params.tag16, params.tag8);
        tracing::info!("Noise upgrade completed, session key installed");

        let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
        app.set_tx_out(tx_out.clone()).await;

        let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
        app.set_stop_tx(stop_tx).await;

        let updated_streams = Streams {
            tx: streams.tx,
            rx: streams.rx,
            tx_out,
        };

        let mode = match &conn {
            Connection::Lan(_, _) => "lan",
            Connection::Wan(_, _) => "wan",
            Connection::WanTorStream { .. } => "wan_tor",
            Connection::Quic(_) => "quic",
            Connection::WebRtc(_) => "webrtc",
        }
        .to_string();

        let stop_rx1 = stop_rx.clone();

        let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
            conn.clone(),
            updated_streams.clone(),
            session_cipher_params,
            rl,
            stop_rx1,
        )
        .await;

        let stop_rx2 = stop_rx.clone();

        let metrics = app.get_metrics().await;
        let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
            conn,
            rx_out,
            stop_rx2,
            metrics,
            session_cipher_params,
            match noise_role {
                crate::session_noise::NoiseRole::Initiator => 0x01,
                crate::session_noise::NoiseRole::Responder => 0x02,
            },
        )
        .await;

        let peer = Some(target.clone());
        let mut s = app.get_connection_state().await;
        s.port = Some(params.port);
        s.mode = Some(mode.clone());
        s.status = crate::state::ConnectionStatus::Connected;
        s.peer_address = peer.clone();
        app.set_connection_state(s).await;

        return Ok(Json(ConnectionResponse {
            status: "connected".into(),
            port: Some(params.port),
            mode,
            peer,
        }));
    }

    match transport::establish_connection(&params, &cfg).await {
        Ok(conn) => {
            let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
            let rl = RateLimiter::new(
                cfg.rate_limit_capacity,
                cfg.rate_limit_max_requests,
                rl_duration,
            );

            // Determine Noise Role based on local role override or config
            let noise_role = match req.local_role {
                Some(RoleHint::Host) => crate::session_noise::NoiseRole::Responder,
                Some(RoleHint::Client) => crate::session_noise::NoiseRole::Initiator,
                None => {
                    if req.tor_role == TorRole::Host {
                        crate::session_noise::NoiseRole::Responder
                    } else {
                        crate::session_noise::NoiseRole::Initiator
                    }
                }
            };

            if let Connection::Wan(sock, _) = &conn {
                let state_snapshot = app.get_connection_state().await;
                if state_snapshot.status == crate::state::ConnectionStatus::Connecting
                    || state_snapshot.status == crate::state::ConnectionStatus::Connected
                {
                    let mode = state_snapshot.mode.clone().unwrap_or_else(|| "wan".into());
                    return Ok(Json(ConnectionResponse {
                        status: format!("{:?}", state_snapshot.status).to_lowercase(),
                        port: state_snapshot.port,
                        mode,
                        peer: state_snapshot.peer_address,
                    }));
                }

                let sock = sock.clone();
                let params_bg = params.clone();
                let cfg = cfg.clone();
                let state_bg = app.clone();
                let streams_bg = streams.clone();
                let noise_role = crate::session_noise::NoiseRole::Responder;
                tokio::spawn(async move {
                    if let Err(e) = accept_wan_direct_and_spawn(
                        sock, params_bg, cfg, state_bg, streams_bg, noise_role,
                    )
                    .await
                    {
                        tracing::error!("WAN listen failed: {}", e);
                    }
                });

                let mut s = app.get_connection_state().await;
                s.port = Some(params.port);
                s.mode = Some("wan".into());
                s.status = crate::state::ConnectionStatus::Connecting;
                s.peer_address = None;
                app.set_connection_state(s).await;

                return Ok(Json(ConnectionResponse {
                    status: "listening".into(),
                    port: Some(params.port),
                    mode: "wan".into(),
                    peer: None,
                }));
            }

            // Perform Noise Session Upgrade
            let session_key = match crate::session_noise::run_noise_upgrade(
                noise_role,
                &conn,
                &params.key_enc,
                params.tag16,
                params.tag8,
            )
            .await
            {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("Noise handshake failed: {:?}", e);
                    return Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"));
                }
            };

            let session_cipher_params = (session_key, params.tag16, params.tag8);
            tracing::info!("Noise upgrade completed, session key installed");

            // Crea canale per sender task
            let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
            app.set_tx_out(tx_out.clone()).await;

            // Crea canale per shutdown
            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            app.set_stop_tx(stop_tx).await;

            // Sostituisci il tx_out in streams con quello appena creato
            let updated_streams = Streams {
                tx: streams.tx,
                rx: streams.rx,
                tx_out,
            };

            let mode = match &conn {
                Connection::Lan(_, _) => "lan",
                Connection::Wan(_, _) => "wan",
                Connection::WanTorStream { .. } => "wan_tor",
                Connection::Quic(_) => "quic",
                Connection::WebRtc(_) => "webrtc",
            }
            .to_string();

            // Avvia tasks con controlli di sicurezza
            let stop_rx1 = stop_rx.clone();

            let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
                conn.clone(),
                updated_streams.clone(),
                session_cipher_params, // Updated
                rl,
                stop_rx1,
            )
            .await;

            let stop_rx2 = stop_rx.clone();

            let peer_addr = conn.peer_addr().map(|addr| addr.to_string());
            let metrics = app.get_metrics().await;
            let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
                conn,
                rx_out,
                stop_rx2,
                metrics,
                session_cipher_params, // Updated
                match noise_role {
                    crate::session_noise::NoiseRole::Initiator => 0x01,
                    crate::session_noise::NoiseRole::Responder => 0x02,
                },
            )
            .await;

            // Aggiorna stato
            let mut s = app.get_connection_state().await;
            s.port = Some(params.port);
            s.mode = Some(mode.clone());
            s.status = crate::state::ConnectionStatus::Connected;
            s.peer_address = peer_addr.clone();
            app.set_connection_state(s).await;

            Ok(Json(ConnectionResponse {
                status: "connected".into(),
                port: Some(params.port),
                mode,
                peer: peer_addr,
            }))
        }
        Err(e) => {
            let mut s = app.get_connection_state().await;
            s.status = crate::state::ConnectionStatus::Error(e.to_string());
            app.set_connection_state(s).await;

            tracing::error!("Connect failed: {:?}", e);
            Err(connect_err(StatusCode::BAD_GATEWAY, "operation failed"))
        }
    }
}

async fn accept_wan_direct_and_spawn(
    sock: Arc<tokio::net::UdpSocket>,
    params: crate::derive::RendezvousParams,
    cfg: Config,
    state: AppState,
    streams: Streams,
    noise_role: crate::session_noise::NoiseRole,
) -> anyhow::Result<()> {
    let (peer, first_pkt) =
        match wait_for_first_handshake_packet(&sock, &params, cfg.wan_accept_timeout_ms).await {
            Ok(v) => v,
            Err(e) => {
                let mut s = state.get_connection_state().await;
                if s.mode.as_deref() == Some("wan")
                    && s.status == crate::state::ConnectionStatus::Connecting
                {
                    s.status = crate::state::ConnectionStatus::Disconnected;
                    s.mode = None;
                    s.peer_address = None;
                    state.set_connection_state(s).await;
                }
                return Err(e);
            }
        };
    let first = Arc::new(RwLock::new(Some(first_pkt)));
    let sock_send = sock.clone();
    let send = move |data: Vec<u8>| {
        let sock_send = sock_send.clone();
        async move {
            sock_send.send_to(&data, peer).await?;
            Ok(())
        }
    };
    let sock_recv = sock.clone();
    let recv = move || {
        let first = first.clone();
        let sock_recv = sock_recv.clone();
        async move {
            if let Some(pkt) = first.write().await.take() {
                return Ok(pkt);
            }
            loop {
                let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
                let (n, from) = sock_recv.recv_from(&mut buf).await?;
                if from != peer {
                    continue;
                }
                return Ok(buf[..n].to_vec());
            }
        }
    };

    let noise_params = crate::session_noise::classic_noise_params()?;
    let session_key = match crate::session_noise::run_noise_upgrade_io(
        noise_role,
        send,
        recv,
        &params.key_enc,
        params.tag16,
        params.tag8,
        noise_params,
        MAX_UDP_PACKET_BYTES,
    )
    .await
    {
        Ok(k) => k,
        Err(e) => {
            let mut s = state.get_connection_state().await;
            if s.mode.as_deref() == Some("wan")
                && s.status == crate::state::ConnectionStatus::Connecting
            {
                s.status = crate::state::ConnectionStatus::Disconnected;
                s.mode = None;
                s.peer_address = None;
                state.set_connection_state(s).await;
            }
            return Err(e);
        }
    };

    let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
    let rl = RateLimiter::new(
        cfg.rate_limit_capacity,
        cfg.rate_limit_max_requests,
        rl_duration,
    );

    let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
    state.set_tx_out(tx_out.clone()).await;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    state.set_stop_tx(stop_tx).await;

    let updated_streams = Streams {
        tx: streams.tx,
        rx: streams.rx,
        tx_out,
    };

    let conn = Connection::Wan(sock.clone(), peer);
    let session_cipher_params = (session_key, params.tag16, params.tag8);
    tracing::info!("Noise upgrade completed, session key installed");

    let stop_rx1 = stop_rx.clone();
    let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
        conn.clone(),
        updated_streams.clone(),
        session_cipher_params,
        rl,
        stop_rx1,
    )
    .await;

    let stop_rx2 = stop_rx.clone();
    let metrics = state.get_metrics().await;
    let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
        conn,
        rx_out,
        stop_rx2,
        metrics,
        session_cipher_params,
        match noise_role {
            crate::session_noise::NoiseRole::Initiator => 0x01,
            crate::session_noise::NoiseRole::Responder => 0x02,
        },
    )
    .await;

    let mut s = state.get_connection_state().await;
    s.port = Some(params.port);
    s.mode = Some("wan".into());
    s.status = crate::state::ConnectionStatus::Connected;
    s.peer_address = Some(peer.to_string());
    state.set_connection_state(s).await;

    Ok(())
}

async fn wait_for_first_handshake_packet(
    sock: &tokio::net::UdpSocket,
    params: &crate::derive::RendezvousParams,
    timeout_ms: u64,
) -> anyhow::Result<(std::net::SocketAddr, Vec<u8>)> {
    let timeout_ms = timeout_ms.max(1);
    timeout(Duration::from_millis(timeout_ms), async {
        let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
        loop {
            let (n, from) = sock.recv_from(&mut buf).await?;
            if crate::security::early_drop_packet(&buf[..n], params.tag16, params.tag8) {
                continue;
            }
            let pkt = match deserialize_cipher_packet_with_limit(&buf[..n], MAX_UDP_PACKET_BYTES) {
                Ok(p) => p,
                Err(_) => continue,
            };
            let clear = match open(&params.key_enc, &pkt, params.tag16, params.tag8) {
                Some(c) => c,
                None => continue,
            };
            let ctrl: Control = match bincode::deserialize(&clear.data) {
                Ok(c) => c,
                Err(_) => continue,
            };
            if matches!(ctrl, Control::NoiseHandshake(_)) {
                return Ok((from, buf[..n].to_vec()));
            }
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("WAN listen timeout"))?
}

async fn handle_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<ConnectionResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let s = state.app.get_connection_state().await;
    Ok(Json(ConnectionResponse {
        status: format!("{:?}", s.status),
        port: s.port,
        mode: s.mode.unwrap_or_else(|| "unknown".into()),
        peer: s.peer_address,
    }))
}

async fn handle_send(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<SendRequest>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return axum::http::StatusCode::TOO_MANY_REQUESTS;
    }
    let Ok(bytes) = general_purpose::STANDARD.decode(&req.packet_b64) else {
        return axum::http::StatusCode::BAD_REQUEST;
    };
    if bytes.len() < 4 {
        return axum::http::StatusCode::BAD_REQUEST;
    }

    if let Some(tx_out) = state.app.get_tx_out().await {
        if tx_out.send(bytes).await.is_err() {
            return axum::http::StatusCode::SERVICE_UNAVAILABLE;
        }
        axum::http::StatusCode::OK
    } else {
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    }
}

async fn handle_recv_sse(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let rx = state.streams.rx.clone();
    let mut ticker = interval(Duration::from_millis(5000)); // keepalive ogni 5s

    let stream = async_stream::stream! {
        loop {
            tokio::select! {
                maybe = async {
                    let mut guard = rx.lock().await;
                    guard.recv().await
                } => {
                    if let Some(bytes) = maybe {
                        let ev = Event::default().data(general_purpose::STANDARD.encode(bytes));
                        yield Ok::<Event, Infallible>(ev);
                    } else {
                        break;
                    }
                }
                _ = ticker.tick() => {
                    yield Ok::<Event, Infallible>(Event::default().event("keepalive").data("ok"));
                }
            }
        }
    };

    Sse::new(stream)
        .keep_alive(axum::response::sse::KeepAlive::new())
        .into_response()
}

async fn handle_set_passphrase(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<SetPass>,
) -> Result<Json<SetPassRes>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let secret = SecretString::from(req.passphrase);
    let params = derive_from_secret(&secret);
    state
        .app
        .set_crypto_params(params.key_enc, params.tag16, params.tag8)
        .await;
    Ok(Json(SetPassRes {
        status: "ok".to_string(),
        port: params.port,
        tag16: params.tag16,
    }))
}

async fn handle_seal(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<SealReq>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let (key_enc, tag16, tag8) = match state.app.get_crypto_params().await {
        Some(p) => p,
        None => return axum::http::StatusCode::PRECONDITION_REQUIRED.into_response(),
    };

    let data = match general_purpose::STANDARD.decode(&req.data_b64) {
        Ok(d) => d,
        Err(_) => return axum::http::StatusCode::BAD_REQUEST.into_response(),
    };

    let clear = ClearPayload {
        ts_ms: now_ms(),
        seq: now_us(),
        data,
    };

    // Utility endpoint: not for protocol frames. Uses random nonce.
    // Measure encrypt timing for metrics
    let timer = CryptoTimer::start();
    let pkt = match seal(&key_enc, tag16, tag8, &clear) {
        Ok(p) => {
            // Record successful encryption timing
            let metrics = state.app.get_metrics().await;
            metrics.record_encrypt_time(timer.elapsed()).await;
            p
        }
        Err(_) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };

    let packet_b64 = match serialize_cipher_packet(&pkt) {
        Ok(bytes) => general_purpose::STANDARD.encode(bytes),
        Err(_) => return axum::http::StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    Json(SealRes { packet_b64 }).into_response()
}

async fn handle_open(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<OpenReq>,
) -> impl IntoResponse {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return axum::http::StatusCode::TOO_MANY_REQUESTS.into_response();
    }
    let (key_enc, tag16, tag8) = match state.app.get_crypto_params().await {
        Some(p) => p,
        None => return axum::http::StatusCode::PRECONDITION_REQUIRED.into_response(),
    };

    let bytes = match general_purpose::STANDARD.decode(&req.packet_b64) {
        Ok(b) => b,
        Err(_) => return axum::http::StatusCode::BAD_REQUEST.into_response(),
    };

    let pkt: CipherPacket = match deserialize_cipher_packet_with_limit(&bytes, MAX_TCP_FRAME_BYTES)
    {
        Ok(p) => p,
        Err(_) => return axum::http::StatusCode::BAD_REQUEST.into_response(),
    };

    // Measure decrypt timing for metrics
    let timer = CryptoTimer::start();
    if let Some(clear) = open(&key_enc, &pkt, tag16, tag8) {
        // Record successful decryption timing
        let metrics = state.app.get_metrics().await;
        metrics.record_decrypt_time(timer.elapsed()).await;
        Json(OpenRes {
            data_b64: general_purpose::STANDARD.encode(clear.data),
        })
        .into_response()
    } else {
        // Record failed decryption (potential attack)
        let metrics = state.app.get_metrics().await;
        metrics.record_connection_error().await;
        axum::http::StatusCode::UNAUTHORIZED.into_response()
    }
}

async fn handle_disconnect(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<ConnectionResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    state.app.stop_all().await;
    state.app.clear_crypto_params().await;

    let mut current_state = state.app.get_connection_state().await;
    current_state.status = crate::state::ConnectionStatus::Disconnected;
    state.app.set_connection_state(current_state).await;

    Ok(Json(ConnectionResponse {
        status: "disconnected".into(),
        port: None,
        mode: "none".into(),
        peer: None,
    }))
}

async fn handle_phrase_open(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<PhraseOpenRequest>,
) -> Result<Json<PhraseOpenResponse>, StatusCode> {
    let app = state.app.clone();
    let streams = state.streams.clone();
    if !app.api_allow(addr.ip(), 2.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    if req.passphrase.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if app.get_phrase_status().await != crate::state::PhraseStatus::Closed {
        return Err(StatusCode::CONFLICT);
    }
    app.set_phrase_status(crate::state::PhraseStatus::Opening)
        .await;

    let cfg = Config::from_env();
    let passphrase = req.passphrase;
    let secret = SecretString::from(passphrase);
    let params = derive_from_secret(&secret);
    let listener = tokio::net::TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let local_port = listener
        .local_addr()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?
        .port();
    let listener = Arc::new(listener);

    let tor = app
        .get_or_start_tor(&cfg)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let onion = {
        let tor = tor.lock().await;
        tor.add_onion_with_port(PHRASE_VIRT_PORT, local_port)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?
    };

    app.set_phrase_onion(Some(onion.clone())).await;
    app.set_phrase_listener(Some(listener.clone())).await;
    app.set_phrase_status(crate::state::PhraseStatus::Open)
        .await;

    let invite = PhraseInvite {
        ver: 1,
        product: "A".to_string(),
        policy: "tor".to_string(),
        onion: onion.clone(),
        virt_port: PHRASE_VIRT_PORT,
    };
    let invite_str = invite
        .encode()
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;

    let state_bg = app.clone();
    let streams_bg = streams.clone();
    let accept_task = tokio::spawn(async move {
        loop {
            if state_bg.get_phrase_status().await == crate::state::PhraseStatus::Closed {
                break;
            }
            let (stream, _peer) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!("Phrase accept failed: {:?}", e);
                    continue;
                }
            };
            let (reader, writer) = stream.into_split();
            let conn = Connection::WanTorStream {
                reader: Arc::new(tokio::sync::Mutex::new(reader)),
                writer: Arc::new(tokio::sync::Mutex::new(writer)),
            };

            let noise_role = crate::session_noise::NoiseRole::Responder;
            let session_key = match crate::session_noise::run_noise_upgrade(
                noise_role,
                &conn,
                &params.key_enc,
                params.tag16,
                params.tag8,
            )
            .await
            {
                Ok(k) => k,
                Err(e) => {
                    tracing::error!("Noise handshake failed: {:?}", e);
                    continue;
                }
            };

            let session_cipher_params = (session_key, params.tag16, params.tag8);
            tracing::info!("Noise upgrade completed, session key installed");

            let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
            state_bg.set_tx_out(tx_out.clone()).await;

            let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
            state_bg.set_stop_tx(stop_tx).await;

            let updated_streams = Streams {
                tx: streams_bg.tx,
                rx: streams_bg.rx,
                tx_out,
            };

            let mode = "phrase_tor".to_string();
            let stop_rx1 = stop_rx.clone();
            let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
            let rl = RateLimiter::new(
                cfg.rate_limit_capacity,
                cfg.rate_limit_max_requests,
                rl_duration,
            );
            let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
                conn.clone(),
                updated_streams.clone(),
                session_cipher_params,
                rl,
                stop_rx1,
            )
            .await;

            let stop_rx2 = stop_rx.clone();
            let metrics = state_bg.get_metrics().await;
            let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
                conn,
                rx_out,
                stop_rx2,
                metrics,
                session_cipher_params,
                match noise_role {
                    crate::session_noise::NoiseRole::Initiator => 0x01,
                    crate::session_noise::NoiseRole::Responder => 0x02,
                },
            )
            .await;

            let mut s = state_bg.get_connection_state().await;
            s.port = Some(local_port);
            s.mode = Some(mode);
            s.status = crate::state::ConnectionStatus::Connected;
            s.peer_address = None;
            state_bg.set_connection_state(s).await;

            state_bg
                .set_phrase_status(crate::state::PhraseStatus::Connected)
                .await;
            break;
        }
    });
    app.set_phrase_accept_task(Some(accept_task)).await;

    Ok(Json(PhraseOpenResponse {
        onion,
        virt_port: PHRASE_VIRT_PORT,
        invite: invite_str,
    }))
}

async fn handle_phrase_close(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<axum::http::StatusCode, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }

    if let Some(task) = state.app.take_phrase_accept_task().await {
        task.abort();
    }
    state.app.take_phrase_listener().await;
    state.app.stop_all().await;

    if let Some(onion) = state.app.get_phrase_onion().await {
        if let Ok(tor) = state.app.get_or_start_tor(&Config::from_env()).await {
            let tor = tor.lock().await;
            let _ = tor.del_onion(&onion).await; // Log errors in cleanup
        }
    }
    state.app.set_phrase_onion(None).await;
    state
        .app
        .set_phrase_status(crate::state::PhraseStatus::Closed)
        .await;
    let mut s = state.app.get_connection_state().await;
    s.status = crate::state::ConnectionStatus::Disconnected;
    state.app.set_connection_state(s).await;

    Ok(axum::http::StatusCode::OK)
}

async fn handle_phrase_join(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
    Json(req): Json<PhraseJoinRequest>,
) -> Result<Json<ConnectionResponse>, StatusCode> {
    let app = state.app.clone();
    let streams = state.streams.clone();
    if !app.api_allow(addr.ip(), 2.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let invite = PhraseInvite::decode(&req.invite).map_err(|_| StatusCode::BAD_REQUEST)?;
    if invite.ver != 1 || invite.product != "A" || invite.policy != "tor" {
        return Err(StatusCode::BAD_REQUEST);
    }
    let target = format!("{}:{}", invite.onion, invite.virt_port);
    if validate_onion_addr(&target).is_err() {
        return Err(StatusCode::BAD_REQUEST);
    }
    if req.passphrase.trim().is_empty() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let cfg = Config::from_env();
    let tor = app
        .get_or_start_tor(&cfg)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let socks_addr = {
        let tor = tor.lock().await;
        tor.socks_addr()
    };

    let passphrase = req.passphrase;
    let secret = SecretString::from(passphrase);
    let params = derive_from_secret(&secret);

    app.set_phrase_status(crate::state::PhraseStatus::Opening)
        .await;
    let stream =
        crate::transport::wan_tor::try_tor_connect(&socks_addr, &target, None, Some(&target))
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
    let (reader, writer) = stream.into_split();
    let conn = Connection::WanTorStream {
        reader: Arc::new(tokio::sync::Mutex::new(reader)),
        writer: Arc::new(tokio::sync::Mutex::new(writer)),
    };

    let noise_role = crate::session_noise::NoiseRole::Initiator;
    let session_key = match crate::session_noise::run_noise_upgrade(
        noise_role,
        &conn,
        &params.key_enc,
        params.tag16,
        params.tag8,
    )
    .await
    {
        Ok(k) => k,
        Err(_) => {
            app.set_phrase_status(crate::state::PhraseStatus::Error("handshake_failed".into()))
                .await;
            return Err(StatusCode::BAD_GATEWAY);
        }
    };

    let session_cipher_params = (session_key, params.tag16, params.tag8);
    tracing::info!("Noise upgrade completed, session key installed");

    let (tx_out, rx_out) = mpsc::channel(DEFAULT_CHANNEL_CAPACITY);
    app.set_tx_out(tx_out.clone()).await;

    let (stop_tx, stop_rx) = tokio::sync::watch::channel(false);
    app.set_stop_tx(stop_tx).await;

    let updated_streams = Streams {
        tx: streams.tx,
        rx: streams.rx,
        tx_out,
    };

    let mode = "phrase_tor".to_string();
    let stop_rx1 = stop_rx.clone();
    let rl_duration = Duration::from_secs(cfg.rate_limit_time_window_s.max(1));
    let rl = RateLimiter::new(
        cfg.rate_limit_capacity,
        cfg.rate_limit_max_requests,
        rl_duration,
    );
    let _rx_handle = crate::transport::tasks::spawn_receiver_task_with_stop(
        conn.clone(),
        updated_streams.clone(),
        session_cipher_params,
        rl,
        stop_rx1,
    )
    .await;

    let stop_rx2 = stop_rx.clone();
    let metrics = app.get_metrics().await;
    let _tx_handle = crate::transport::tasks::spawn_sender_task_with_stop(
        conn,
        rx_out,
        stop_rx2,
        metrics,
        session_cipher_params,
        match noise_role {
            crate::session_noise::NoiseRole::Initiator => 0x01,
            crate::session_noise::NoiseRole::Responder => 0x02,
        },
    )
    .await;

    let mut s = app.get_connection_state().await;
    s.port = Some(params.port);
    s.mode = Some(mode.clone());
    s.status = crate::state::ConnectionStatus::Connected;
    s.peer_address = Some(invite.onion);
    app.set_connection_state(s).await;

    app.set_phrase_status(crate::state::PhraseStatus::Connected)
        .await;

    Ok(Json(ConnectionResponse {
        status: "connected".into(),
        port: Some(params.port),
        mode,
        peer: None,
    }))
}

async fn handle_phrase_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<PhraseStatusResponse>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let status = match state.app.get_phrase_status().await {
        crate::state::PhraseStatus::Closed => "closed".to_string(),
        crate::state::PhraseStatus::Opening => "opening".to_string(),
        crate::state::PhraseStatus::Open => "open".to_string(),
        crate::state::PhraseStatus::Connected => "connected".to_string(),
        crate::state::PhraseStatus::Error(e) => format!("error:{e}"),
    };
    Ok(Json(PhraseStatusResponse {
        status,
        onion: state.app.get_phrase_onion().await,
    }))
}

/// Handle /v1/metrics - In-memory debugging metrics (zero persistence)
async fn handle_metrics(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<DebugMetrics>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    let metrics = state.app.get_metrics().await;
    let debug_metrics = DebugMetrics::from_collector(&metrics).await;

    Ok(Json(debug_metrics))
}

/// Handle /v1/circuit - Circuit breaker status for debugging
async fn handle_circuit_status(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Extension(state): Extension<Arc<ApiState>>,
) -> Result<Json<crate::state::CircuitBreakerStatus>, StatusCode> {
    if !state.app.api_allow(addr.ip(), 1.0).await {
        return Err(StatusCode::TOO_MANY_REQUESTS);
    }
    // For now return placeholder - ConnectionManager integration is next step
    use crate::state::{CircuitBreakerStatus, CircuitState};

    let placeholder_status = CircuitBreakerStatus {
        state: CircuitState::Closed,
        failure_count: 0,
        success_count: 0,
        next_attempt_in: None,
    };

    Ok(Json(placeholder_status))
}

/// Response for pluggable protocols listing
#[derive(Debug, Serialize)]
#[allow(dead_code)]
struct PluggableProtocolsResponse {
    protocols: Vec<String>,
    enabled: bool,
}
