//! Local Stealth Mode - IDS/Firewall Evasion
//!
//! Provides passive LAN discovery to avoid triggering IDS alerts.
//! Instead of broadcasting, listens passively for peer discovery.

use anyhow::{Context, Result};
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::time::{timeout, Duration};
use tracing::info;

use crate::derive::RendezvousParams;

/// Stealth discovery mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum StealthMode {
    /// Normal broadcast (default)
    Active,
    /// Passive listening (no broadcast)
    Passive,
    /// mDNS-based discovery (uses multicast DNS)
    Mdns,
}

/// Attempt stealth LAN connection
pub async fn try_lan_stealth(
    port: u16,
    mode: StealthMode,
    params: &RendezvousParams,
) -> Result<(UdpSocket, SocketAddr)> {
    match mode {
        StealthMode::Active => {
            // Fallback to normal broadcast
            crate::transport::lan::try_lan_broadcast(port).await
        }
        StealthMode::Passive => {
            try_passive_discovery(port, params).await
        }
        StealthMode::Mdns => {
            try_mdns_discovery(port, params).await
        }
    }
}

/// Passive discovery: wait for peer broadcast without sending
async fn try_passive_discovery(port: u16, _params: &RendezvousParams) -> Result<(UdpSocket, SocketAddr)> {
    info!("Stealth: passive discovery on port {}", port);
    
    // Bind to port but don't broadcast
    let sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port)))
        .await
        .context("Stealth bind failed")?;
    
    // Set socket to non-broadcast mode
    sock.set_broadcast(false)?;
    
    // Listen for discovery packets (without sending ours)
    let start = tokio::time::Instant::now();
    let deadline = Duration::from_secs(5); // Longer timeout for passive
    
    let mut buf = vec![0u8; 1024];
    while start.elapsed() < deadline {
        match timeout(Duration::from_millis(100), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, addr))) => {
                // Check if it's a valid discovery packet
                if n > 16 && &buf[..14] == b"HS_DISCOVERY" {
                    info!("Stealth: received discovery from {}", addr);
                    
                    // Send ACK immediately (stealth on ingress only)
                    let mut ack = Vec::with_capacity(15);
                    ack.extend_from_slice(b"HS_DISCOVERY_ACK");
                    let _ = sock.send_to(&ack, addr).await;
                    
                    return Ok((sock, addr));
                }
            }
            _ => continue,
        }
    }
    
    anyhow::bail!("Stealth passive discovery timeout")
}

/// mDNS-based discovery
async fn try_mdns_discovery(port: u16, _params: &RendezvousParams) -> Result<(UdpSocket, SocketAddr)> {
    use std::net::{Ipv4Addr, IpAddr};
    
    info!("Stealth: mDNS discovery on port {}", port);
    
    // Bind to mDNS multicast address
    let sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port)))
        .await
        .context("mDNS bind failed")?;
    
    // Join mDNS multicast group (224.0.0.251)
    sock.join_multicast_v4(
        Ipv4Addr::new(224, 0, 0, 251),
        Ipv4Addr::UNSPECIFIED,
    )?;
    
    sock.set_multicast_loop_v4(true)?;
    
    // Send mDNS query for handshacke service
    let mdns_query = build_mdns_query();
    let mdns_addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)), 5353);
    sock.send_to(&mdns_query, mdns_addr).await?;
    
    // Listen for responses
    let start = tokio::time::Instant::now();
    let deadline = Duration::from_secs(3);
    
    let mut buf = vec![0u8; 1024];
    while start.elapsed() < deadline {
        match timeout(Duration::from_millis(100), sock.recv_from(&mut buf)).await {
            Ok(Ok((n, addr))) => {
                if parse_mdns_response(&buf[..n], port).is_some() {
                    info!("mDNS: discovered peer at {}", addr);
                    return Ok((sock, addr));
                }
            }
            _ => continue,
        }
    }
    
    anyhow::bail!("mDNS discovery timeout")
}

/// Build mDNS query for handshacke service
fn build_mdns_query() -> Vec<u8> {
    let mut query = Vec::new();
    
    // Transaction ID
    query.extend_from_slice(&rand::random::<u16>().to_be_bytes());
    
    // Flags: standard query
    query.extend_from_slice(&[0x00, 0x00]);
    
    // Questions: 1
    query.extend_from_slice(&[0x00, 0x01]);
    
    // Answers: 0
    query.extend_from_slice(&[0x00, 0x00]);
    
    // Authority: 0
    query.extend_from_slice(&[0x00, 0x00]);
    
    // Additional: 0
    query.extend_from_slice(&[0x00, 0x00]);
    
    // Query name: _handshacke._udp.local
    query.push(11); // length
    query.extend_from_slice(b"handshacke");
    query.push(4); // length
    query.extend_from_slice(b"_udp");
    query.push(5); // length
    query.extend_from_slice(b"local");
    query.push(0); // terminator
    
    // Query type: PTR (0x000C)
    query.extend_from_slice(&[0x00, 0x0C]);
    
    // Query class: IN (0x0001)
    query.extend_from_slice(&[0x00, 0x01]);
    
    query
}

/// Parse mDNS response and extract port
fn parse_mdns_response(buf: &[u8], expected_port: u16) -> Option<SocketAddr> {
    if buf.len() < 12 {
        return None;
    }
    
    // Check if it's a response (flags bit 15 = 1)
    let flags = u16::from_be_bytes([buf[2], buf[3]]);
    if flags & 0x8000 == 0 {
        return None; // Not a response
    }
    
    // Look for port in TXT record (simplified parsing)
    let txt_marker = b"port=";
    if let Some(pos) = buf.windows(txt_marker.len()).position(|w| w == txt_marker) {
        let rest = &buf[pos + txt_marker.len()..];
        if let Some(port_end) = rest.iter().position(|b| *b == 0) {
            let port_str = std::str::from_utf8(&rest[..port_end]).ok()?;
            let port: u16 = port_str.parse().ok()?;
            if port == expected_port {
                return Some(SocketAddr::from(([127, 0, 0, 1], port)));
            }
        }
    }
    
    None
}

/// Toggle stealth mode via environment variable
pub fn stealth_mode_from_env() -> StealthMode {
    match std::env::var("HANDSHACKE_STEALTH_MODE").as_deref() {
        Ok("passive") => StealthMode::Passive,
        Ok("mdns") => StealthMode::Mdns,
        Ok("active") | _ => StealthMode::Active,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_mdns_query_build() {
        let query = build_mdns_query();
        assert!(query.len() > 30);
        let marker = b"handshacke";
        assert!(query.windows(marker.len()).any(|w| w == marker));
    }
    
    #[test]
    fn test_parse_mdns_response() {
        let buf = b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00\x0bhandshacke\x04_udp\x05local\x00\x00\x0c\x00\x01port=12345\x00";
        let result = parse_mdns_response(&buf[..], 12345);
        assert!(result.is_some());
    }
}
