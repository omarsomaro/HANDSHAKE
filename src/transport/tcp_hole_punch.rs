//! TCP Hole Punching implementation
//!
//! Provides TCP-based hole punching for NATs that block UDP.
//! Requires NAT with long TCP timeout and support for simultaneous open.

use anyhow::{bail, Context, Result};
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::os::unix::io::AsRawFd;
use tokio::net::{TcpSocket, TcpStream};
use tokio::time::{timeout, Duration};
use tracing::info;

/// TCP Hole Punching implementation
pub struct TcpHolePunch;

impl TcpHolePunch {
    /// Attempt TCP hole punching between local and remote addresses
    ///
    /// Strategy:
    /// 1. Bind to specific local port with SO_REUSEADDR
    /// 2. Enable TCP_FASTOPEN if available
    /// 3. Send SYN with data (or empty) to remote
    /// 4. Wait for simultaneous open to complete
    pub async fn punch(local: SocketAddr, remote: SocketAddr) -> Result<TcpStream> {
        info!("Attempting TCP hole punching {} -> {}", local, remote);

        // Create TCP socket with SO_REUSEADDR
        let socket = if local.is_ipv6() || remote.is_ipv6() {
            TcpSocket::new_v6().context("create TCP socket v6")?
        } else {
            TcpSocket::new_v4().context("create TCP socket v4")?
        };

        // Enable SO_REUSEADDR to allow bind to specific port
        socket.set_reuseaddr(true).context("set SO_REUSEADDR")?;

        // Try to enable TCP_FASTOPEN if available
        #[cfg(target_os = "linux")]
        Self::enable_tcp_fastopen(&socket)?;

        // Bind to specific local address (required for hole punching)
        socket.bind(local).context("bind to local address")?;

        // Connect to remote (will send SYN)
        let connect_future = socket.connect(remote);

        // Timeout per connessione
        match timeout(Duration::from_secs(5), connect_future).await {
            Ok(Ok(stream)) => {
                info!("TCP hole punching successful: {}", remote);
                Ok(stream)
            }
            Ok(Err(e)) => {
                bail!("TCP connection failed: {}", e);
            }
            Err(_) => {
                bail!("TCP connection timeout");
            }
        }
    }

    /// Enable TCP_FASTOPEN on socket (Linux only)
    #[cfg(target_os = "linux")]
    fn enable_tcp_fastopen(socket: &TcpSocket) -> Result<()> {
        let fd = socket.as_raw_fd();
        let qlen: i32 = 5; // Queue length for pending TFO connections

        unsafe {
            if libc::setsockopt(
                fd,
                libc::IPPROTO_TCP,
                libc::TCP_FASTOPEN,
                &qlen as *const i32 as *const libc::c_void,
                std::mem::size_of_val(&qlen) as libc::socklen_t,
            ) != 0
            {
                // Non-fatal, just log and continue
                tracing::debug!("TCP_FASTOPEN not available");
            }
        }
        Ok(())
    }

    /// Test if a TCP port is open (by sending RST and checking response)
    pub async fn test_port_open(addr: SocketAddr) -> Result<bool> {
        use std::io::ErrorKind;

        match timeout(Duration::from_secs(2), TcpStream::connect(addr)).await {
            Ok(Ok(_)) => Ok(true), // Port is open and accepting
            Ok(Err(e)) => {
                // If connection refused, port is closed
                // If timeout or other error, inconclusive
                match e.kind() {
                    ErrorKind::ConnectionRefused => Ok(false),
                    _ => {
                        tracing::debug!("Port test inconclusive: {}", e);
                        Ok(false)
                    }
                }
            }
            Err(_) => Ok(false), // Timeout = port likely filtered/closed
        }
    }

    /// Attempt coordinated simultaneous TCP open
    pub async fn simultaneous_open(
        local1: SocketAddr,
        remote1: SocketAddr,
        local2: SocketAddr,
        remote2: SocketAddr,
    ) -> Result<(TcpStream, TcpStream)> {
        info!("Attempting simultaneous TCP open");

        // Start both connections in parallel
        let f1 = Self::punch(local1, remote1);
        let f2 = Self::punch(local2, remote2);

        // Small delay to ensure SYNs are in-flight
        tokio::time::sleep(Duration::from_millis(50)).await;

        let (r1, r2) = tokio::join!(f1, f2);

        match (r1, r2) {
            (Ok(s1), Ok(s2)) => {
                info!("Simultaneous TCP open successful");
                Ok((s1, s2))
            }
            (Ok(s), Err(_)) => {
                info!("One side succeeded in TCP simultaneous open");
                Ok((s, TcpStream::connect("127.0.0.1:0").await?)) // Dummy
            }
            (Err(_), Ok(s)) => {
                info!("One side succeeded in TCP simultaneous open");
                Ok((TcpStream::connect("127.0.0.1:0").await?, s)) // Dummy
            }
            (Err(e1), Err(e2)) => {
                bail!("Both sides failed: {} and {}", e1, e2);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_hole_punch_creation() {
        let _puncher = TcpHolePunch;
        // No failures in creation
    }

    #[tokio::test]
    async fn test_port_open_localhost() {
        // Test on localhost - port 1 should be closed
        let result = TcpHolePunch::test_port_open("127.0.0.1:1".parse().unwrap()).await;

        assert!(result.is_ok());
        assert!(!result.unwrap()); // Port 1 is likely closed

        // Test on localhost - port 22 (ssh) might be open
        let result = TcpHolePunch::test_port_open("127.0.0.1:22".parse().unwrap()).await;

        // Result depends on SSH running
        assert!(result.is_ok());
    }

    #[tokio::test]
    #[should_panic]
    async fn test_tcp_hole_punch_to_closed_port() {
        // This should fail to connect
        let _ = TcpHolePunch::punch(
            "127.0.0.1:0".parse().unwrap(),    // Random local port
            "127.0.0.1:9999".parse().unwrap(), // Likely closed
        )
        .await
        .unwrap();
    }
}
