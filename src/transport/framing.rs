//! TCP framing: length-prefix protocol for sending packets over streams
//!
//! Format: [4-byte BE length][payload]
//! Guards against memory bombs with MAX_FRAME limit.

use anyhow::{Context, Result, bail};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum frame size (1MB) to prevent memory bombs
pub const MAX_FRAME: usize = crate::crypto::MAX_TCP_FRAME_BYTES as usize;

/// Write a framed message: [4-byte BE length][payload]
pub async fn write_frame<S>(stream: &mut S, data: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    if data.len() > MAX_FRAME {
        bail!("Frame too large: {} bytes (max {})", data.len(), MAX_FRAME);
    }
    
    let len = data.len() as u32;
    stream.write_all(&len.to_be_bytes()).await
        .context("Failed to write frame length")?;
    stream.write_all(data).await
        .context("Failed to write frame payload")?;
    stream.flush().await
        .context("Failed to flush stream")?;
    
    Ok(())
}

/// Read a framed message, returns payload
/// 
/// Returns Err on:
/// - EOF during read (connection closed)
/// - len == 0 (invalid frame)
/// - len > MAX_FRAME (memory bomb protection)
pub async fn read_frame<S>(stream: &mut S) -> Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    
    match stream.read_exact(&mut len_buf).await {
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            bail!("Connection closed");
        },
        Err(e) => return Err(e).context("Failed to read frame length"),
    }
    
    let len = u32::from_be_bytes(len_buf) as usize;
    
    if len == 0 {
        bail!("Invalid frame: zero length");
    }
    
    if len > MAX_FRAME {
        bail!("Frame too large: {} bytes (max {})", len, MAX_FRAME);
    }
    
    let mut payload = vec![0u8; len];
    match stream.read_exact(&mut payload).await {
        Ok(_) => {},
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
            bail!("Connection closed during frame read");
        },
        Err(e) => return Err(e).context("Failed to read frame payload"),
    }
    
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_max_frame_constant() {
        assert_eq!(MAX_FRAME, 1_048_576);
    }
}
