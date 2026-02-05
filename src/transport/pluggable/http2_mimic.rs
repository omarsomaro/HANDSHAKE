//! HTTP/2 mimicry for DPI evasion
//!
//! Mimics standard HTTP/2 client with proper preface and headers.

use anyhow::{bail, Context, Result};
use async_trait::async_trait;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use super::mimicry::{util, ProtocolMimicry};

/// HTTP/2 settings
pub struct Http2Mimic {
    stream_id: u32,
    state: Http2State,
}

#[derive(Debug)]
#[allow(dead_code)]
enum Http2State {
    New,
    PrefaceSent,
    Established,
}

impl Http2Mimic {
    pub fn new() -> Self {
        Self {
            stream_id: 1,
            state: Http2State::New,
        }
    }

    /// Build HTTP/2 connection preface
    fn build_connection_preface() -> Vec<u8> {
        // "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".to_vec()
    }

    /// Build HTTP/2 settings frame
    fn build_settings_frame() -> Vec<u8> {
        let mut frame = Vec::new();

        // Frame header (9 bytes)
        frame.extend_from_slice(&0u32.to_be_bytes()[1..]); // Length: 0 (empty settings)
        frame.push(0x04); // Type: SETTINGS
        frame.push(0x00); // Flags: none
        frame.extend_from_slice(&0u32.to_be_bytes()); // Stream ID: 0

        // No settings (empty)
        frame
    }

    /// Build HTTP/2 data frame
    fn build_data_frame(stream_id: u32, data: &[u8], end_stream: bool) -> Vec<u8> {
        let mut frame = Vec::new();

        let flags = if end_stream { 0x01 } else { 0x00 }; // END_STREAM

        // Frame header
        frame.extend_from_slice(&((data.len() as u32).to_be_bytes()[1..])); // Length
        frame.push(0x00); // Type: DATA
        frame.push(flags); // Flags
        frame.extend_from_slice(&stream_id.to_be_bytes()); // Stream ID

        // Payload
        frame.extend_from_slice(data);

        frame
    }

    /// Parse HTTP/2 frame header
    fn parse_frame_header(header: &[u8; 9]) -> (usize, u8, u8, u32) {
        let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
        let frame_type = header[3];
        let flags = header[4];
        let stream_id = u32::from_be_bytes([header[5], header[6], header[7], header[8]]);
        (length, frame_type, flags, stream_id)
    }
}

impl Default for Http2Mimic {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl ProtocolMimicry for Http2Mimic {
    fn name(&self) -> &'static str {
        "http2"
    }

    async fn establish(&mut self, stream: &mut TcpStream) -> Result<()> {
        // Send connection preface
        let preface = Self::build_connection_preface();
        stream.write_all(&preface).await?;

        // Send client SETTINGS
        let settings = Self::build_settings_frame();
        stream.write_all(&settings).await?;

        // Send WINDOW_UPDATE (increase flow control window)
        let mut window_update = vec![0u8; 13];
        window_update[0..3].copy_from_slice(&4u32.to_be_bytes()[1..]); // Length: 4
        window_update[3] = 0x08; // Type: WINDOW_UPDATE
        window_update[4] = 0x00; // Flags: none
        window_update[9..13].copy_from_slice(&(1u32 << 31).to_be_bytes()); // Increment: 2^31
        stream.write_all(&window_update).await?;

        // Read first server frame (should be SETTINGS)
        let mut header = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut header))
            .await
            .context("HTTP/2 preface timeout")??;
        let (length, frame_type, _flags, stream_id) = Self::parse_frame_header(&header);
        if frame_type != 0x04 || stream_id != 0 {
            bail!("Invalid HTTP/2 server preface: expected SETTINGS");
        }
        if length > 0 {
            let mut payload = vec![0u8; length];
            stream.read_exact(&mut payload).await?;
        }

        self.state = Http2State::Established;

        tracing::info!("HTTP/2 connection established");
        Ok(())
    }

    async fn send(&mut self, stream: &mut TcpStream, data: &[u8]) -> Result<()> {
        let frame = Self::build_data_frame(self.stream_id, data, false);
        stream.write_all(&frame).await?;
        stream.flush().await?;

        self.stream_id += 2; // Next client-initiated stream

        util::realistic_delay(5).await;

        Ok(())
    }

    async fn recv(&mut self, stream: &mut TcpStream, buf: &mut [u8]) -> Result<usize> {
        // Read frame header
        let mut header = [0u8; 9];
        stream.read_exact(&mut header).await?;

        let (length, frame_type, _flags, _stream_id) = Self::parse_frame_header(&header);

        if frame_type != 0x00 {
            // Skip non-DATA frames
            tracing::debug!("Skipping HTTP/2 frame type: {}", frame_type);
            let mut skip_buf = vec![0u8; length];
            stream.read_exact(&mut skip_buf).await?;
            return Ok(0);
        }

        // Read DATA payload
        let mut payload = vec![0u8; length.min(buf.len())];
        let n = stream.read(&mut payload).await?;

        buf[..n].copy_from_slice(&payload[..n]);
        Ok(n)
    }
}

#[allow(dead_code)]
fn encode_hpack_header(name: &str, value: &str) -> Vec<u8> {
    let mut buf = Vec::new();

    if name == ":method" && value == "GET" {
        // Indexed header (0x82 = :method: GET from static table)
        buf.push(0x82);
    } else if name == ":path" && value == "/" {
        // Indexed header (0x84 = :path: / from static table)
        buf.push(0x84);
    } else if name == ":scheme" && value == "https" {
        // Indexed header (0x87 = :scheme: https from static table)
        buf.push(0x87);
    } else if name == "content-type" && value == "application/octet-stream" {
        // Indexed header (0x24 from static table)
        buf.push(0x24);
    } else {
        // Literal header without indexing
        buf.push(0x00); // Literal without indexing
        buf.extend_from_slice(&(name.len() as u8).to_be_bytes());
        buf.extend_from_slice(name.as_bytes());
        buf.extend_from_slice(&(value.len() as u8).to_be_bytes());
        buf.extend_from_slice(value.as_bytes());
    }

    buf
}

/// Build HEADERS frame
#[allow(dead_code)]
fn build_headers_frame(
    stream_id: u32,
    headers: &[(&str, &str)],
    end_stream: bool,
    end_headers: bool,
) -> Vec<u8> {
    let mut payload = Vec::new();

    // Encode all headers
    for (name, value) in headers {
        payload.extend_from_slice(&encode_hpack_header(name, value));
    }

    // Build frame header
    let mut frame = Vec::new();

    // Length (3 bytes)
    frame.extend_from_slice(&((payload.len() as u32).to_be_bytes()[1..]));

    // Type (HEADERS = 0x01)
    frame.push(0x01);

    // Flags
    let mut flags = 0u8;
    if end_stream {
        flags |= 0x01; // END_STREAM
    }
    if end_headers {
        flags |= 0x04; // END_HEADERS
    }
    frame.push(flags);

    // Stream ID (4 bytes, highest bit always 0 for client)
    frame.extend_from_slice(&stream_id.to_be_bytes());

    // Payload
    frame.extend_from_slice(&payload);

    frame
}

/// Parse HPACK header (simplified - assumes single byte length prefixed strings)
#[allow(dead_code)]
fn parse_hpack_header(data: &mut &[u8]) -> Result<(String, String)> {
    if data.len() < 2 {
        bail!("Invalid HPACK data: too short");
    }

    // Check for indexed header
    if data[0] & 0x80 != 0 {
        // Indexed header field
        let index = data[0] & 0x7F;
        *data = &data[1..];

        // Static table mapping (simplified)
        let (name, value) = match index {
            2 => (":method".to_string(), "GET".to_string()),
            4 => (":path".to_string(), "/".to_string()),
            7 => (":scheme".to_string(), "http".to_string()),
            8 => (":scheme".to_string(), "https".to_string()),
            20 => (
                "content-type".to_string(),
                "application/octet-stream".to_string(),
            ),
            _ => (format!("unknown-{}", index), "".to_string()),
        };

        return Ok((name, value));
    }

    // Literal header without indexing
    if data[0] == 0x00 {
        *data = &data[1..];

        // Read name length and value
        if data.is_empty() {
            bail!("Invalid HPACK: no name length");
        }
        let name_len = data[0] as usize;
        *data = &data[1..];

        if data.len() < name_len {
            bail!("Invalid HPACK: name truncated");
        }
        let name = String::from_utf8_lossy(&data[..name_len]).to_string();
        *data = &data[name_len..];

        // Read value length and value
        if data.is_empty() {
            bail!("Invalid HPACK: no value length");
        }
        let value_len = data[0] as usize;
        *data = &data[1..];

        if data.len() < value_len {
            bail!("Invalid HPACK: value truncated");
        }
        let value = String::from_utf8_lossy(&data[..value_len]).to_string();
        *data = &data[value_len..];

        return Ok((name, value));
    }

    bail!("Unsupported HPACK encoding: {:02x}", data[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_preface() {
        let preface = Http2Mimic::build_connection_preface();
        assert_eq!(preface, b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n");
    }

    #[test]
    fn test_data_frame() {
        let frame = Http2Mimic::build_data_frame(1, b"test", true);
        assert_eq!(frame.len(), 9 + 4); // header 9 + data 4
        assert_eq!(&frame[9..13], b"test");
    }
}
