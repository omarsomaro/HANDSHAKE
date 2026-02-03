//! WebSocket mimicry for DPI evasion

// Add sha1 imports at the top if not present
//!
//! Mimics Chrome's WebSocket implementation with real handshake,
//! frame masking, and ping/pong keepalive.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use sha1::{Digest, Sha1};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::mimicry::{util, ProtocolMimicry};

/// WebSocket frame types
#[derive(Debug, Clone, Copy)]
pub enum FrameType {
    Continuation = 0x0,
    Text = 0x1,
    Binary = 0x2,
    Close = 0x8,
    Ping = 0x9,
    Pong = 0xA,
}

impl FrameType {
    fn from_u8(value: u8) -> Option<Self> {
        match value & 0x0F {
            0x0 => Some(Self::Continuation),
            0x1 => Some(Self::Text),
            0x2 => Some(Self::Binary),
            0x8 => Some(Self::Close),
            0x9 => Some(Self::Ping),
            0xA => Some(Self::Pong),
            _ => None,
        }
    }
}

/// WebSocket mimic implementation
pub struct WebSocketMimic {
    state: WebSocketState,
    key: String,
}

#[derive(Debug)]
#[allow(dead_code)]
enum WebSocketState {
    New,
    Handshaking,
    Open,
}

impl WebSocketMimic {
    pub fn new() -> Self {
        Self {
            state: WebSocketState::New,
            key: String::new(),
        }
    }

    /// Generate Sec-WebSocket-Key
    fn generate_key() -> String {
        let key_bytes = util::random_bytes(16);
        STANDARD.encode(key_bytes)
    }

    /// Calculate Sec-WebSocket-Accept from key
    fn calculate_accept(key: &str) -> String {
        let magic = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        let mut hasher = Sha1::new();
        hasher.update(key.as_bytes());
        hasher.update(magic.as_bytes());
        let result = hasher.finalize();
        STANDARD.encode(result)
    }

    /// Parse HTTP response headers
    fn parse_http_headers(response: &str) -> Result<HashMap<String, String>> {
        let mut headers = HashMap::new();
        for line in response.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                headers.insert(key.trim().to_lowercase(), value.trim().to_string());
            }
        }
        Ok(headers)
    }

    /// Mask WebSocket frame payload (client → server)
    fn mask_payload(payload: &[u8], mask_key: &[u8; 4]) -> Vec<u8> {
        payload
            .iter()
            .enumerate()
            .map(|(i, &byte)| byte ^ mask_key[i % 4])
            .collect()
    }
}

#[async_trait]
impl ProtocolMimicry for WebSocketMimic {
    fn name(&self) -> &'static str {
        "websocket"
    }

    async fn establish(&mut self, stream: &mut TcpStream) -> Result<()> {
        // Generate client handshake
        self.key = Self::generate_key();
        let host = "www.cloudflare.com:80"; // Mimic popular host
        let path = "/ws"; // Common WebSocket path

        let handshake = format!(
            "GET {} HTTP/1.1\r\n\
             Host: {}\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Key: {}\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Extensions: permessage-deflate; client_max_window_bits\r\n\
             User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36\r\n\r\n",
            path, host, self.key
        );

        stream.write_all(handshake.as_bytes()).await?;

        // Read response
        let mut response = vec![0u8; 4096];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut response))
            .await
            .context("WebSocket handshake timeout")??;

        let response_str = String::from_utf8_lossy(&response[..n]);

        // Verify 101 Switching Protocols
        if !response_str.starts_with("HTTP/1.1 101") {
            bail!(
                "Invalid WebSocket handshake response: {}",
                response_str.lines().next().unwrap_or("no response")
            );
        }

        // Verify Sec-WebSocket-Accept
        let headers = Self::parse_http_headers(&response_str)?;
        let accept = headers
            .get("sec-websocket-accept")
            .ok_or_else(|| anyhow::anyhow!("Missing Sec-WebSocket-Accept"))?;

        let expected_accept = Self::calculate_accept(&self.key);
        if accept != &expected_accept {
            bail!(
                "Invalid Sec-WebSocket-Accept: got {}, expected {}",
                accept,
                expected_accept
            );
        }

        self.state = WebSocketState::Open;

        tracing::info!("WebSocket handshake completed");
        Ok(())
    }

    async fn send(&mut self, stream: &mut TcpStream, data: &[u8]) -> Result<()> {
        // Build frame
        let mut frame = Vec::new();

        // First byte: FIN=1, RSV=000, opcode=Binary (0x2)
        frame.push(0x82);

        // Payload length encoding (Chrome-like)
        let payload_len = data.len();
        if payload_len <= 125 {
            frame.push((payload_len as u8) | 0x80); // mask=1
        } else if payload_len <= 65535 {
            frame.push(126 | 0x80); // mask=1, ext len
            frame.extend_from_slice(&(payload_len as u16).to_be_bytes());
        } else {
            frame.push(127 | 0x80); // mask=1, ext len
            frame.extend_from_slice(&(payload_len as u64).to_be_bytes());
        }

        // Masking key (random)
        let mask_key = util::random_bytes(4);
        frame.extend_from_slice(&mask_key);

        // Masked payload
        let masked_payload = Self::mask_payload(data, &mask_key.try_into().unwrap());
        frame.extend_from_slice(&masked_payload);

        // Send frame
        stream.write_all(&frame).await?;
        stream.flush().await?;

        // Realistic delay
        util::realistic_delay(5).await;

        Ok(())
    }

    async fn recv(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> Result<usize> {
        // Read frame header
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await?;

        let _fin = (header[0] & 0x80) != 0;
        let opcode =
            FrameType::from_u8(header[0]).ok_or_else(|| anyhow::anyhow!("Invalid frame opcode"))?;

        let masked = (header[1] & 0x80) != 0;
        let mut payload_len = (header[1] & 0x7F) as usize;

        // Extended payload length
        if payload_len == 126 {
            let mut len_buf = [0u8; 2];
            stream.read_exact(&mut len_buf).await?;
            payload_len = u16::from_be_bytes(len_buf) as usize;
        } else if payload_len == 127 {
            let mut len_buf = [0u8; 8];
            stream.read_exact(&mut len_buf).await?;
            payload_len = u64::from_be_bytes(len_buf) as usize;
        }

        // Masking key
        let mut mask_key = [0u8; 4];
        if masked {
            stream.read_exact(&mut mask_key).await?;
        }

        // Read payload
        let mut payload = vec![0u8; payload_len.min(buf.len())];
        stream.read_exact(&mut payload).await?;

        // Unmask if needed
        if masked {
            payload = Self::mask_payload(&payload, &mask_key);
        }

        // Handle control frames
        match opcode {
            FrameType::Ping => {
                // Send Pong
                let pong_frame = vec![0x8A, 0x80, 0x00, 0x00, 0x00, 0x00]; // Pong with zero mask
                stream.write_all(&pong_frame).await?;
                stream.flush().await?;

                // Return as received but don't pass to app
                buf.copy_from_slice(&payload);
                Ok(payload.len())
            }
            FrameType::Pong => {
                // Just acknowledge
                Ok(0)
            }
            FrameType::Close => {
                bail!("WebSocket close received");
            }
            _ => {
                buf.copy_from_slice(&payload);
                Ok(payload.len())
            }
        }
    }
}

impl Default for WebSocketMimic {
    fn default() -> Self {
        Self::new()
    }
}

use std::collections::HashMap;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key() {
        let key1 = WebSocketMimic::generate_key();
        let key2 = WebSocketMimic::generate_key();
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), 24); // base64 of 16 bytes
    }

    #[test]
    fn test_calculate_accept() {
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = WebSocketMimic::calculate_accept(key);
        assert_eq!(accept, "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }

    #[test]
    fn test_mask_payload() {
        let payload = b"Hello";
        let mask_key = [0x12, 0x34, 0x56, 0x78];
        let masked = WebSocketMimic::mask_payload(payload, &mask_key);
        let unmasked = WebSocketMimic::mask_payload(&masked, &mask_key);
        assert_eq!(payload, &unmasked[..]);
    }
}
