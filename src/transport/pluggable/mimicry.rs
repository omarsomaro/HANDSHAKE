//! Protocol mimicry framework for advanced DPI evasion
//!
//! Mimics real protocols like WebSocket, QUIC, HTTP/2, etc. with realistic
//! byte patterns, timing, and protocol semantics.

use anyhow::{Result, bail};
use async_trait::async_trait;
use tokio::net::TcpStream;

/// Trait for protocol mimics
#[async_trait]
pub trait ProtocolMimicry: Send + Sync {
    /// Protocol name (e.g., "websocket", "quic")
    fn name(&self) -> &'static str;
    
    /// Establish connection with protocol-specific handshake
    async fn establish(&mut self, stream: &mut TcpStream) -> Result<()>;
    
    /// Send data with protocol framing
    async fn send(&mut self, stream: &mut TcpStream, data: &[u8]) -> Result<()>;
    
    /// Receive data with protocol parsing
    async fn recv(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> Result<usize>;
}

/// Protocol mimic registry
pub struct ProtocolRegistry {
    protocol: Box<dyn ProtocolMimicry>,
}

impl ProtocolRegistry {
    /// Create new protocol mimic
    pub fn new(protocol: Box<dyn ProtocolMimicry>) -> Self {
        Self { protocol }
    }
    
    /// Get protocol name
    pub fn name(&self) -> &'static str {
        self.protocol.name()
    }
    
    /// Establish connection
    pub async fn establish(&mut self, stream: &mut TcpStream) -> Result<()> {
        self.protocol.establish(stream).await
    }
    
    /// Send data
    pub async fn send(&mut self, stream: &mut TcpStream, data: &[u8]) -> Result<()> {
        self.protocol.send(stream, data).await
    }
    
    /// Receive data
    pub async fn recv(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> Result<usize> {
        self.protocol.recv(stream, buf).await
    }
}

/// List all available protocol mimics
pub fn list_protocols() -> Vec<&'static str> {
    vec![
        "websocket",
        "quic",
        "http2",
    ]
}

/// Create protocol mimic by name
pub fn create_protocol(name: &str) -> Result<Box<dyn ProtocolMimicry>> {
    match name {
        "websocket" => Ok(Box::new(super::ws_mimic::WebSocketMimic::new())),
        "quic" => Ok(Box::new(super::quic_mimic::QuicMimic::new(super::quic_mimic::QuicVersion::Q050)?)),
        "http2" => Ok(Box::new(super::http2_mimic::Http2Mimic::new())),
        _ => bail!("Unknown protocol: {}", name),
    }
}

/// Common utility functions
pub mod util {
    use rand::RngCore;
    use std::time::Duration;
    
    /// Generate pseudo-random bytes
    pub fn random_bytes(len: usize) -> Vec<u8> {
        let mut buf = vec![0u8; len];
        rand::thread_rng().fill_bytes(&mut buf);
        buf
    }
    
    /// Calculate CRC32
    pub fn crc32(data: &[u8]) -> u32 {
        let mut crc = 0u32;
        for &byte in data {
            crc = crc.wrapping_add(byte as u32);
            crc = (crc << 1) | (crc >> 31); // Rotate
        }
        crc
    }
    
    /// Encode to base64url without padding
    pub fn base64url_encode(data: &[u8]) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
        URL_SAFE_NO_PAD.encode(data)
    }
    
    /// Delay for realistic timing
    pub async fn realistic_delay(ms: u64) {
        tokio::time::sleep(Duration::from_millis(ms)).await;
    }
}

/// Utility module re-export
pub use util::*;

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_list_protocols() {
        let protocols = list_protocols();
        assert!(protocols.contains(&"websocket"));
        assert!(protocols.contains(&"quic"));
    }
    
    #[test]
    fn test_create_protocol() {
        let ws = create_protocol("websocket");
        assert!(ws.is_ok());
        assert_eq!(ws.unwrap().name(), "websocket");
        
        let quic = create_protocol("quic");
        assert!(quic.is_ok());
        assert_eq!(quic.unwrap().name(), "quic");
    }
}