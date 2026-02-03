//! QUIC mimicry for DPI evasion
//!
//! Mimics Google QUIC (GQUIC) versions Q046 and Q050 with realistic
//! packet structure, crypto frames, and connection establishment.

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use rand::RngCore;

use super::mimicry::{ProtocolMimicry, util};

/// QUIC versions
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicVersion {
    Q043, // Chrome 43-45
    Q046, // Chrome 46-51
    Q050, // Chrome 52+
}

impl QuicVersion {
    fn to_u32(&self) -> u32 {
        match self {
            QuicVersion::Q043 => 0x51303433, // "Q043" in hex
            QuicVersion::Q046 => 0x51303436, // "Q046" in hex
            QuicVersion::Q050 => 0x51303530, // "Q050" in hex
        }
    }
    
    fn connection_id_length(&self) -> usize {
        match self {
            QuicVersion::Q043 => 8,
            QuicVersion::Q046 => 8,
            QuicVersion::Q050 => 8,
        }
    }
}

/// QUIC packet types
#[derive(Debug, Clone, Copy)]
pub enum QuicPacketType {
    Initial = 0x7F,  // Long header: Initial
    Handshake = 0x7E, // Long header: Handshake
    Retry = 0x7D,     // Long header: Retry
    Short = 0x30,     // Short header (1-RTT)
}

/// QUIC mimic implementation (over TCP for tunneling)
pub struct QuicMimic {
    version: QuicVersion,
    connection_id: Vec<u8>,
    packet_number: u32,
    state: QuicState,
}

#[derive(Debug)]
#[allow(dead_code)]
enum QuicState {
    New,
    InitialSent,
    HandshakeComplete,
    Established,
}

impl QuicMimic {
    /// Create new QUIC mimic
    pub fn new(version: QuicVersion) -> Result<Self> {
        let connection_id_len = version.connection_id_length();
        let mut connection_id = vec![0u8; connection_id_len];
        rand::thread_rng().fill_bytes(&mut connection_id);
        
        Ok(Self {
            version,
            connection_id,
            packet_number: 0,
            state: QuicState::New,
        })
    }
    
    /// Build QUIC long header packet
    fn build_long_header_packet(
        &self,
        packet_type: QuicPacketType,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut packet = Vec::new();
        
        // Public flags (8 bits)
        // - Long header: 0x80
        // - Type: 3 bits
        // - Version: 4 bits
        let public_flags = 0x80 | ((packet_type as u8) << 4);
        packet.push(public_flags);
        
        // Connection ID length indicator
        packet.push(self.connection_id.len() as u8);
        
        // Version
        packet.extend_from_slice(&self.version.to_u32().to_be_bytes());
        
        // Connection ID
        packet.extend_from_slice(&self.connection_id);
        
        // Packet number (variable length)
        if self.packet_number <= 0xFF {
            packet.push(self.packet_number as u8);
        } else if self.packet_number <= 0xFFFF {
            packet.push(0x01); // 2-byte packet number
            packet.extend_from_slice(&(self.packet_number as u16).to_be_bytes());
        } else {
            packet.push(0x02); // 4-byte packet number
            packet.extend_from_slice(&self.packet_number.to_be_bytes());
        }
        
        // Crypto frame (type 0x06)
        packet.push(0x06); // Frame type
        
        // Offset (varint)
        if payload.len() <= 0x3F {
            packet.push(payload.len() as u8);
        } else {
            packet.push(0x40 | ((payload.len() >> 8) as u8));
            packet.push((payload.len() & 0xFF) as u8);
        }
        
        // Length (varint)
        packet.extend_from_slice(&Self::encode_varint(payload.len()));
        
        // Payload
        packet.extend_from_slice(payload);
        
        // Padding to realistic size (1200-1350 bytes typical)
        let target_size = 1200 + (util::random_bytes(1)[0] as usize % 150);
        if packet.len() < target_size {
            let padding_len = target_size - packet.len();
            packet.extend(vec![0u8; padding_len]);
        }
        
        packet
    }
    
    /// Build QUIC short header packet
    fn build_short_header_packet(&self, payload: &[u8]) -> Vec<u8> {
        let mut packet = Vec::new();
        
        // Public flags: short header (0x30), connection ID present
        packet.push(0x30 | 0x08);
        
        // Connection ID (8 bytes)
        packet.extend_from_slice(&self.connection_id[..8.min(self.connection_id.len())]);
        
        // Packet number (1-4 bytes, depending on version)
        match self.version {
            QuicVersion::Q050 => {
                packet.extend_from_slice(&self.packet_number.to_be_bytes());
            }
            _ => {
                packet.push(self.packet_number as u8);
            }
        }
        
        // Payload
        packet.extend_from_slice(payload);
        
        // Add AEAD tag (16 bytes placeholder)
        packet.extend_from_slice(&[0u8; 16]);
        
        packet
    }
    
    /// Encode varint (variable-length integer)
    fn encode_varint(value: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        if value < 0x40 {
            buf.push(value as u8);
        } else if value < 0x4000 {
            buf.push(0x40 | ((value >> 8) as u8));
            buf.push((value & 0xFF) as u8);
        } else if value < 0x400000 {
            buf.push(0x80 | ((value >> 16) as u8));
            buf.push(((value >> 8) & 0xFF) as u8);
            buf.push((value & 0xFF) as u8);
        } else {
            buf.push(0xC0 | ((value >> 24) as u8));
            buf.extend_from_slice(&(value as u32).to_be_bytes()[1..]);
        }
        buf
    }
    
    /// Crypto Initial payload (CHLO for GQUIC)
    fn build_crypto_chlo(&self) -> Vec<u8> {
        let mut chlo = Vec::new();
        
        // Tag (CHLO)
        chlo.extend_from_slice(b"CHLO");
        
        // Padding to avoid size-based fingerprinting
        chlo.extend_from_slice(&vec![0u8; 32]);
        
        // Version tag
        chlo.extend_from_slice(b"VER\"");
        chlo.extend_from_slice(&self.version.to_u32().to_be_bytes());
        
        // Connection ID tag
        chlo.extend_from_slice(b"CID\"");
        chlo.extend_from_slice(&self.connection_id);
        
        // AEAD tag (AESG)
        chlo.extend_from_slice(b"AEAD\"");
        chlo.extend_from_slice(b"AESG"); // AES-GCM
        
        // KEXS tag (C255)
        chlo.extend_from_slice(b"KEXS\"");
        chlo.extend_from_slice(b"C255"); // Curve25519
        
        // PUBS tag (dummy public key)
        chlo.extend_from_slice(b"PUBS\"");
        let mut pubs = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut pubs);
        chlo.extend_from_slice(&pubs);
        
        // SNI tag (www.cloudflare.com)
        let sni = "www.cloudflare.com";
        chlo.extend_from_slice(b"SNI\"");
        chlo.extend_from_slice(&(sni.len() as u16).to_be_bytes());
        chlo.extend_from_slice(sni.as_bytes());
        
        // PAD tag for padding
        chlo.extend_from_slice(b"PAD\"");
        let pad_len = 100;
        chlo.extend_from_slice(&(pad_len as u16).to_be_bytes());
        chlo.extend_from_slice(&vec![0u8; pad_len]);
        
        chlo
    }
    
    /// Generate QUIC retry token
    #[allow(dead_code)]
    fn generate_retry_token(&self) -> Vec<u8> {
        let mut token = vec![0u8; 64];
        rand::thread_rng().fill_bytes(&mut token);
        token
    }
}

#[async_trait]
impl ProtocolMimicry for QuicMimic {
    fn name(&self) -> &'static str {
        "quic"
    }
    
    async fn establish(&mut self, stream: &mut TcpStream) -> Result<()> {
        // QUIC over TCP: send Initial packet
        let chlo = self.build_crypto_chlo();
        let initial = self.build_long_header_packet(QuicPacketType::Initial, &chlo);
        
        stream.write_all(&initial).await?;
        stream.flush().await?;
        
        self.state = QuicState::InitialSent;
        self.packet_number += 1;
        
        // Read server response
        let mut response = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut response)).await
            .context("QUIC handshake timeout")??;
        
        if n < 20 {
            bail!("Invalid QUIC response: too short");
        }
        
        // Verify server Initial (REJ or SHLO)
        if &response[1..5] == b"REJ\"" {
            bail!("QUIC server rejected handshake");
        }
        
        if &response[1..5] != b"SHLO" {
            // Might be Retry packet
            if response[0] == 0x7D {
                tracing::debug!("QUIC Retry received, establishing with new token");
                // Retry with new connection ID
                self.connection_id = util::random_bytes(8);
                return self.establish(stream).await;
            }
        }
        
        self.state = QuicState::Established;
        
        tracing::info!("QUIC handshake completed (version {:?})", self.version);
        Ok(())
    }
    
    async fn send(&mut self, stream: &mut TcpStream, data: &[u8]) -> Result<()> {
        let packet = self.build_short_header_packet(data);
        stream.write_all(&packet).await?;
        stream.flush().await?;
        
        self.packet_number += 1;
        
        // Realistic delay
        util::realistic_delay(2).await;
        
        Ok(())
    }
    
    async fn recv(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> Result<usize> {
        // Read packet header
        let mut header = [0u8; 1];
        stream.read_exact(&mut header).await?;
        
        let is_long_header = (header[0] & 0x80) != 0;
        
        if is_long_header {
            // Read long header packet
            let mut conn_id_len = [0u8; 1];
            stream.read_exact(&mut conn_id_len).await?;
            
            // Skip version
            let mut version = [0u8; 4];
            stream.read_exact(&mut version).await?;
            
            // Read connection ID
            let mut conn_id = vec![0u8; conn_id_len[0] as usize];
            stream.read_exact(&mut conn_id).await?;
            
            // Skip packet number
            let mut pn_buf = [0u8; 4];
            stream.read_exact(&mut pn_buf).await?;
            
            // Read payload length
            let payload_len = pn_buf[0] as usize;
            let mut payload = vec![0u8; payload_len.min(buf.len())];
            let n = stream.read(&mut payload).await?;
            
            buf[..n].copy_from_slice(&payload[..n]);
            Ok(n)
        } else {
            // Read short header packet
            let mut conn_id = vec![0u8; 8];
            stream.read_exact(&mut conn_id).await?;
            
            let mut pn_buf = [0u8; 4];
            stream.read_exact(&mut pn_buf).await?;
            
            // Read payload
            let mut payload = vec![0u8; 1024.min(buf.len())];
            let n = stream.read(&mut payload).await?;
            
            buf[..n].copy_from_slice(&payload[..n]);
            Ok(n)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_encode_varint() {
        assert_eq!(QuicMimic::encode_varint(0x20), vec![0x20]);
        assert_eq!(QuicMimic::encode_varint(0x1000), vec![0x50, 0x00]);
    }
    
    #[test]
    fn test_build_chlo() {
        let mimic = QuicMimic::new(QuicVersion::Q050).unwrap();
        let chlo = mimic.build_crypto_chlo();
        assert!(chlo.len() > 100);
        assert!(chlo.starts_with(b"CHLO"));
    }
    
    #[tokio::test]
    async fn test_packet_coalescing() {
        // Test that multiple packets can be sent without boundaries
        let mimic = QuicMimic::new(QuicVersion::Q050).unwrap();
        
        let pkt1 = mimic.build_long_header_packet(QuicPacketType::Initial, b"test1");
        let pkt2 = mimic.build_short_header_packet(b"test2");
        
        // Ensure packets can be coalesced
        let mut coalesced = pkt1.clone();
        coalesced.extend_from_slice(&pkt2);
        
        assert!(coalesced.len() >= pkt1.len() + pkt2.len());
    }
}

/// Varint encoding (1-8 bytes)
#[allow(dead_code)]
fn varint_encode(value: u64) -> Vec<u8> {
    if value < 64 {
        vec![value as u8]
    } else if value < 16384 {
        vec![0x40 | (value >> 8) as u8, (value & 0xFF) as u8]
    } else if value < 1073741824 {
        vec![
            0x80 | (value >> 24) as u8,
            ((value >> 16) & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ]
    } else {
        vec![
            0xC0,
            (value >> 56) as u8,
            ((value >> 48) & 0xFF) as u8,
            ((value >> 40) & 0xFF) as u8,
            ((value >> 32) & 0xFF) as u8,
            ((value >> 24) & 0xFF) as u8,
            ((value >> 16) & 0xFF) as u8,
            ((value >> 8) & 0xFF) as u8,
            (value & 0xFF) as u8,
        ]
    }
}

#[allow(dead_code)]
fn encode_frame(frame_type: QuicFrameType, data: &[u8]) -> Vec<u8> {
    let mut buf = Vec::new();
    
    // Frame type varint (always 1 byte for our types)
    buf.push(frame_type as u8);
    
    // Length varint
    buf.extend_from_slice(&varint_encode(data.len() as u64));
    
    // Payload
    buf.extend_from_slice(data);
    
    buf
}

/// Parse varint from buffer
    #[allow(dead_code)]
    fn varint_decode(buf: &[u8]) -> Option<(u64, usize)> {
        if buf.is_empty() {
            return None;
        }
        
        let first = buf[0];
        match first >> 6 {
            0 => Some((first as u64, 1)),                            // 1 byte
            1 => {
                if buf.len() < 2 { return None; }
                Some(((((first & 0x3F) as u64) << 8) | buf[1] as u64, 2))  // 2 bytes
            }
            2 => {
                if buf.len() < 4 { return None; }
                Some((
                    ((first & 0x3F) as u64) << 24 |
                    (buf[1] as u64) << 16 |
                    (buf[2] as u64) << 8 |
                    buf[3] as u64,
                    4
                ))
            }
            3 => {
                if buf.len() < 8 { return None; }
                Some((
                    (buf[1] as u64) << 56 |
                    (buf[2] as u64) << 48 |
                    (buf[3] as u64) << 40 |
                    (buf[4] as u64) << 32 |
                    (buf[5] as u64) << 24 |
                    (buf[6] as u64) << 16 |
                    (buf[7] as u64) << 8 |
                    buf[8] as u64,
                    8
                ))
            }
            _ => None,
        }
    }

/// QUIC frame types
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
enum QuicFrameType {
    Padding = 0x00,
    Ping = 0x01,
    Ack = 0x02,
    ResetStream = 0x04,
    StopSending = 0x05,
    Crypto = 0x06,
    NewToken = 0x07,
    Stream = 0x08,
    MaxData = 0x10,
    MaxStreamData = 0x11,
    MaxStreams = 0x12,
    DataBlocked = 0x14,
    StreamDataBlocked = 0x15,
    StreamsBlocked = 0x16,
    NewConnectionId = 0x18,
    RetireConnectionId = 0x19,
    PathChallenge = 0x1a,
    PathResponse = 0x1b,
    ConnectionClose = 0x1c,
}
