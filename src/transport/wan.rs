//! WAN transport router: Direct or Tor mode
//!
//! Routes to wan_direct (UPnP/NAT-PMP) or wan_tor (SOCKS5) based on config.

#[path = "wan_direct.rs"]
pub mod wan_direct;
#[path = "wan_tor.rs"]
pub mod wan_tor;

use crate::config::{Config, TorRole, WanMode};
use anyhow::{bail, Result};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// WAN connection result
pub enum WanConnection {
    /// Direct NAT traversal (UPnP/NAT-PMP/PCP)
    Direct(UdpSocket, SocketAddr),
    /// Tor client (connected to peer's onion)
    TorClient(TcpStream),
    /// Tor host (listening for incoming connections)
    TorHost(TcpListener),
}

/// Validate configuration for Tor mode
fn validate_tor_config(cfg: &Config) -> Result<()> {
    // Auto + Host = invalid
    if cfg.wan_mode == WanMode::Auto && cfg.tor_role == TorRole::Host {
        bail!("Invalid config: WanMode::Auto is only valid with TorRole::Client");
    }

    // Tor Client needs target_onion
    if (cfg.wan_mode == WanMode::Tor || cfg.wan_mode == WanMode::Auto)
        && cfg.tor_role == TorRole::Client
        && cfg.tor_onion_addr.is_none()
    {
        bail!("Tor Client mode requires tor_onion_addr");
    }

    Ok(())
}

/// Attempt WAN connection based on config
///
/// Note: `port` is used for Direct mode only. In Tor mode, port is extracted from target_onion.
pub async fn try_wan(cfg: &Config, port: u16) -> Result<WanConnection> {
    validate_tor_config(cfg)?;

    match cfg.wan_mode {
        WanMode::Direct => {
            let (sock, addr) = wan_direct::try_direct_port_forward(port).await?;
            Ok(WanConnection::Direct(sock, addr))
        }

        WanMode::Tor => try_tor_mode(cfg).await,

        WanMode::Auto => {
            // Try Direct first, fallback to Tor
            match wan_direct::try_direct_port_forward(port).await {
                Ok((sock, addr)) => {
                    tracing::info!("Auto mode: Direct WAN succeeded");
                    Ok(WanConnection::Direct(sock, addr))
                }
                Err(e) => {
                    tracing::warn!("Auto mode: Direct failed ({}), trying Tor", e);
                    try_tor_mode(cfg).await
                }
            }
        }
    }
}

/// Execute Tor mode based on role
pub async fn try_tor_mode(cfg: &Config) -> Result<WanConnection> {
    match cfg.tor_role {
        TorRole::Client => {
            let target = cfg
                .tor_onion_addr
                .as_ref()
                .ok_or_else(|| anyhow::anyhow!("target_onion required for Tor Client"))?;
            let stream =
                wan_tor::try_tor_connect(&cfg.tor_socks_addr, target, None, Some(target)).await?;
            Ok(WanConnection::TorClient(stream))
        }
        TorRole::Host => {
            let listener = wan_tor::try_tor_listen(&cfg.tor_listen_addr).await?;
            Ok(WanConnection::TorHost(listener))
        }
    }
}
