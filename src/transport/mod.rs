//! Transport layer: LAN -> WAN (Direct/Assist/Tor) with optional QUIC/WebRTC

pub mod lan;
pub mod wan;
pub mod tasks;
pub mod framing;
pub mod wan_assist;
pub mod assist_inbox;
pub mod io;
pub mod guaranteed;
pub mod pluggable;
pub mod stealth;
pub mod dandelion;
pub mod ice;
pub mod nat_detection;
pub mod multipath;
pub mod tcp_hole_punch;
pub mod icmp_hole_punch;
pub mod quic_rfc9000;
pub mod webrtc;

pub use wan::wan_direct;
pub use wan::wan_tor;
pub use tcp_hole_punch::TcpHolePunch;
pub use icmp_hole_punch::IcmpHolePunch;

use crate::config::{
    Config,
    WanMode,
    UDP_MAX_PACKET_SIZE,
    WAN_ASSIST_GLOBAL_TIMEOUT_SECS,
};
use crate::derive::RendezvousParams;
use crate::offer::{OfferPayload, RoleHint};
use crate::session_noise::NoiseRole;
use crate::security::early_drop_packet;
use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::UdpSocket;
use tokio::net::tcp::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::Mutex as TokioMutex;
use tokio::time::{sleep, timeout, Duration};

use wan::WanConnection;

/// Connection type established by transport layer
#[derive(Clone)]
pub enum Connection {
    /// LAN broadcast UDP
    Lan(Arc<UdpSocket>, SocketAddr),
    /// WAN Direct via UPnP/NAT-PMP
    Wan(Arc<UdpSocket>, SocketAddr),
    /// WAN via Tor stream (framed TCP)
    WanTorStream {
        reader: Arc<TokioMutex<OwnedReadHalf>>,
        writer: Arc<TokioMutex<OwnedWriteHalf>>,
    },
    /// QUIC RFC9000 stream (framed)
    Quic(Arc<crate::transport::quic_rfc9000::QuinnTransport>),
    /// WebRTC DataChannel (message-based)
    WebRtc(Arc<crate::transport::webrtc::WebRtcTransport>),
// Tun variant removed - Noise is now a session layer
}

impl Connection {
    /// Get UDP socket (only for UDP connections)
    pub fn get_socket(&self) -> Option<Arc<UdpSocket>> {
        match self {
            Connection::Lan(sock, _) => Some(sock.clone()),
            Connection::Wan(sock, _) => Some(sock.clone()),
            Connection::WanTorStream { .. } => None,
            Connection::Quic(_) => None,
            Connection::WebRtc(_) => None,
        }
    }
    
    /// Check if this is a Tor stream connection
    pub fn is_tor_stream(&self) -> bool {
        matches!(self, Connection::WanTorStream { .. })
    }

    /// Check if this is any stream-like transport
    pub fn is_stream(&self) -> bool {
        matches!(
            self,
            Connection::WanTorStream { .. } | Connection::Quic(_) | Connection::WebRtc(_)
        )
    }
    
    /// Get Tor stream (only for Tor connections)
    pub fn get_tor_stream(&self) -> Option<(Arc<TokioMutex<OwnedReadHalf>>, Arc<TokioMutex<OwnedWriteHalf>>)> {
        match self {
            Connection::WanTorStream { reader, writer } => Some((reader.clone(), writer.clone())),
            _ => None,
        }
    }

    pub fn peer_addr(&self) -> Option<SocketAddr> {
        match self {
            Connection::Lan(_, addr) => Some(*addr),
            Connection::Wan(_, addr) => Some(*addr),
            Connection::WanTorStream { .. } => None,
            Connection::Quic(quic) => Some(quic.peer_addr()),
            Connection::WebRtc(_) => None,
        }
    }
}

/// Establish connection with cascade strategy: LAN → WAN → TUN
/// 
/// For WAN mode, uses config to determine Direct vs Tor transport.
pub async fn establish_connection(p: &RendezvousParams, cfg: &Config) -> Result<Connection> {
    // 1. LAN
    if let Ok((sock, peer_addr)) = lan::try_lan_broadcast(p.port).await {
        tracing::info!("LAN mode active on port: {}", p.port);
        return Ok(Connection::Lan(Arc::new(sock), peer_addr));
    }

    // 2. WAN Direct
    if cfg.wan_mode != WanMode::Tor {
        match wan::wan_direct::try_direct_port_forward(p.port).await {
            Ok((sock, ext_addr)) => {
                tracing::info!("WAN Direct mode active. Port forwarded to {}", ext_addr);
                return Ok(Connection::Wan(Arc::new(sock), ext_addr));
            }
            Err(e) => tracing::warn!("WAN Direct failed: {}", e),
        }
    }

    // 3. WAN ASSIST (max 2 relay, 1 tentativo, 5s totali)
    if !cfg.assist_relays.is_empty() {
        let assist_start = tokio::time::Instant::now();
        let mut attempts = 0;

        for relay in cfg.assist_relays.iter().take(2) {
            if assist_start.elapsed() > Duration::from_secs(WAN_ASSIST_GLOBAL_TIMEOUT_SECS) {
                tracing::warn!("WAN Assist: global timeout exceeded");
                break;
            }

            attempts += 1;
            match timeout(Duration::from_secs(2), wan_assist::try_assisted_punch(p, &[relay.clone()], cfg)).await {
                Ok(Ok(conn)) => {
                    tracing::info!("WAN Assist: success after {} attempts", attempts);
                    return Ok(conn);
                }
                Ok(Err(e)) => tracing::warn!("Relay {} failed: {}", relay, e),
                Err(_) => tracing::warn!("Relay {} timeout", relay),
            }
        }
        tracing::warn!("WAN Assist: all {} attempts failed, falling back to Tor", attempts);
    }

    // 4. Tor fallback
    match wan::try_tor_mode(cfg).await {
        Ok(wan_conn) => Ok(connection_from_wan(wan_conn).await?),
        Err(e) => {
            tracing::warn!("Tor failed: {}", e);
            anyhow::bail!("Connection failed: no reachable transport found (LAN/WAN failed)")
        }
    }
}

async fn connection_from_wan(wan_conn: WanConnection) -> Result<Connection> {
    match wan_conn {
        WanConnection::Direct(sock, ext_addr) => {
            tracing::info!("WAN Direct mode active. Port forwarded to {}", ext_addr);
            Ok(Connection::Wan(Arc::new(sock), ext_addr))
        }
        WanConnection::TorClient(stream) => {
            tracing::info!("WAN Tor Client mode active");
            let (reader, writer) = stream.into_split();
            Ok(Connection::WanTorStream {
                reader: Arc::new(TokioMutex::new(reader)),
                writer: Arc::new(TokioMutex::new(writer)),
            })
        }
        WanConnection::TorHost(listener) => {
            tracing::info!("WAN Tor Host mode: waiting for connection...");
            let (stream, peer_addr) = listener.accept().await?;
            tracing::info!("Tor Host: accepted connection from {}", peer_addr);
            let (reader, writer) = stream.into_split();
            Ok(Connection::WanTorStream {
                reader: Arc::new(TokioMutex::new(reader)),
                writer: Arc::new(TokioMutex::new(writer)),
            })
        }
    }
}

/// Active dial to a specific target (WAN Direct or Tor).
pub async fn connect_to(target: &str, params: &RendezvousParams, cfg: &Config) -> Result<Connection> {
    if target.contains(".onion") {
        let stream = crate::transport::wan::wan_tor::try_tor_connect(&cfg.tor_socks_addr, target, None, Some(target)).await?;
        let (reader, writer) = stream.into_split();
        return Ok(Connection::WanTorStream {
            reader: Arc::new(TokioMutex::new(reader)),
            writer: Arc::new(TokioMutex::new(writer)),
        });
    }

    let peer: SocketAddr = target.parse()?;
    let sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).await?;
    sock.connect(peer).await?;

    let probe = build_probe_packet(params.tag16);
    let burst = cfg.wan_probe_burst.max(1).min(10); // Limit max burst to prevent amplification
    
    // Rate limiting: max 1 probe per 100ms per target to prevent amplification attacks
    let probe_interval = cfg.wan_probe_interval_ms.max(100);
    for i in 0..burst {
        sock.send(&probe).await?;
        if i + 1 < burst {
            sleep(Duration::from_millis(probe_interval)).await;
        }
    }

    let mut buf = vec![0u8; 1024];
    let timeout_ms = cfg.wan_connect_timeout_ms.max(1).min(10000); // Cap timeout to prevent resource exhaustion
    
    match timeout(Duration::from_millis(timeout_ms), sock.recv_from(&mut buf)).await {
        Ok(Ok((n, from))) if from == peer && n >= 8 && n <= UDP_MAX_PACKET_SIZE => {
            // Additional validation: ensure response is reasonable size
            if !early_drop_packet(&buf[..n], params.tag16, params.tag8) {
                tracing::debug!("UDP hole punching successful with {} bytes from {}", n, from);
                return Ok(Connection::Wan(Arc::new(sock), peer));
            }
        }
        Ok(Ok((n, from))) => {
            tracing::warn!("Invalid UDP response: {} bytes from {} (expected {})", n, from, peer);
        }
        Ok(Err(e)) => {
            tracing::debug!("UDP receive error: {}", e);
        }
        Err(_) => {
            tracing::debug!("UDP receive timeout");
        }
    }

    Err(anyhow::anyhow!("Connection timeout to {}", target))
}

fn build_probe_packet(tag16: u16) -> Vec<u8> {
    let mut v = Vec::with_capacity(1400);
    v.extend_from_slice(&tag16.to_le_bytes());
    v.extend_from_slice(b"PROBE");
    
    // Pad to MTU for constant-size probe packets
    crate::crypto::pad_to_mtu(&mut v);
    v
}

pub struct OfferConnectResult {
    pub conn: Connection,
    pub session_key: [u8; 32],
    pub mode: String,
    pub peer: Option<String>,
}

pub async fn establish_connection_from_offer(
    offer: &OfferPayload,
    cfg: &Config,
    local_role: RoleHint,
) -> Result<OfferConnectResult> {
    let noise_role = match local_role {
        RoleHint::Host => NoiseRole::Responder,
        RoleHint::Client => NoiseRole::Initiator,
    };

    let offer_hash = crate::crypto::hash_offer(offer);
    let params = crate::derive::RendezvousParams {
        port: offer.rendezvous.port,
        key_enc: offer.rendezvous.key_enc,
        key_mac: [0u8; 32],
        tag16: offer.rendezvous.tag16,
        tag8: crate::derive::derive_tag8_from_key(&offer.rendezvous.key_enc),
        version: crate::offer::OFFER_VERSION,
    };

    let (conn, _peer_addr) = crate::transport::ice::multipath_race_connect(
        offer,
        offer_hash,
        params,
        cfg.clone(),
        noise_role,
    )
    .await?;

    let mode = match &conn {
        Connection::Lan(_, _) => "lan",
        Connection::Wan(_, _) => "wan",
        Connection::WanTorStream { .. } => "wan_tor",
        Connection::Quic(_) => "quic",
        Connection::WebRtc(_) => "webrtc",
    }
    .to_string();

    let peer = match &conn {
        Connection::Lan(_, addr) | Connection::Wan(_, addr) => Some(addr.to_string()),
        Connection::WanTorStream { .. } => offer.tor_onion_addr()?,
        Connection::Quic(_) => conn.peer_addr().map(|addr| addr.to_string()),
        Connection::WebRtc(_) => None,
    };

    let session_key = crate::session_noise::run_noise_upgrade(
        noise_role,
        &conn,
        &offer.rendezvous.key_enc,
        offer.rendezvous.tag16,
        crate::derive::derive_tag8_from_key(&offer.rendezvous.key_enc),
    )
    .await?;

    Ok(OfferConnectResult {
        conn,
        session_key,
        mode,
        peer,
    })
}

