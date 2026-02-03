use std::future::Future;
use std::pin::Pin;

use anyhow::Result;

use super::Connection;

/// Transport IO abstraction for sending/receiving raw frames.
pub trait TransportIo: Send + Sync {
    fn max_packet_limit(&self) -> u64;
    fn rate_limit_addr(&self) -> std::net::SocketAddr;
    fn send<'a>(&'a self, data: Vec<u8>) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;
    fn recv<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;
}

/// Adapter that exposes Connection as TransportIo without changing core logic.
pub struct ConnectionIo {
    conn: Connection,
}

impl ConnectionIo {
    pub fn new(conn: Connection) -> Self {
        Self { conn }
    }
}

impl TransportIo for ConnectionIo {
    fn max_packet_limit(&self) -> u64 {
        match &self.conn {
            Connection::WebRtc(_) => crate::transport::webrtc::WEBRTC_MAX_MESSAGE_BYTES as u64,
            _ if self.conn.is_stream() => crate::crypto::MAX_TCP_FRAME_BYTES,
            _ => crate::crypto::MAX_UDP_PACKET_BYTES,
        }
    }

    fn rate_limit_addr(&self) -> std::net::SocketAddr {
        self.conn
            .peer_addr()
            .unwrap_or_else(|| "0.0.0.0:0".parse().unwrap())
    }

    fn send<'a>(&'a self, data: Vec<u8>) -> Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>> {
        let conn = self.conn.clone();
        Box::pin(async move {
            match conn {
                Connection::Lan(sock, addr) | Connection::Wan(sock, addr) => {
                    sock.send_to(&data, addr).await?;
                }
                Connection::WanTorStream { writer, .. } => {
                    let mut guard = writer.lock().await;
                    crate::transport::framing::write_frame(&mut *guard, &data).await?;
                }
                Connection::Quic(quic) => {
                    quic.send(&data).await?;
                }
                Connection::WebRtc(webrtc) => {
                    webrtc.send(&data).await?;
                }
            }
            Ok(())
        })
    }

    fn recv<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        let conn = self.conn.clone();
        Box::pin(async move {
            match conn {
                Connection::Lan(sock, _) | Connection::Wan(sock, _) => {
                    let mut buf = vec![0u8; crate::config::UDP_MAX_PACKET_SIZE];
                    let (n, _) = sock.recv_from(&mut buf).await?;
                    Ok(buf[..n].to_vec())
                }
                Connection::WanTorStream { reader, .. } => {
                    let mut guard = reader.lock().await;
                    crate::transport::framing::read_frame(&mut *guard).await
                }
                Connection::Quic(quic) => quic.recv().await,
                Connection::WebRtc(webrtc) => webrtc.recv().await,
            }
        })
    }
}
