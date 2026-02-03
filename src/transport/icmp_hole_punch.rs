//! ICMP Hole Punching implementation
//!
//! Uses ICMP Echo Requests to create UDP pinholes on NATs that
//! block UDP but allow ICMP. Requires CAP_NET_RAW capability.
//!
//! SECURITY NOTE: This requires CAP_NET_RAW and raw socket privileges.

use anyhow::{bail, Context, Result};
use socket2::{Domain, Protocol, Socket, Type};
use std::mem::MaybeUninit;
use std::net::{Ipv4Addr, SocketAddrV4};
use tokio::time::{timeout, Duration};
use tracing::{info, warn};

/// ICMP Hole Punching implementation
pub struct IcmpHolePunch;

/// ICMP Echo Request/Reply header
#[repr(C, packed)]
#[allow(dead_code)]
struct IcmpEchoHeader {
    msg_type: u8,    // 8 = Echo Request, 0 = Echo Reply
    code: u8,        // 0
    checksum: u16,   // 1's complement sum
    identifier: u16, // ID (usiamo port number)
    sequence: u16,   // Sequence number
}

impl IcmpHolePunch {
    /// Attempt ICMP hole punching
    ///
    /// This sends an ICMP Echo Request to the target. Many NATs will
    /// open a UDP pinhole for the source port when they see ICMP traffic.
    ///
    /// SECURITY: Requires CAP_NET_RAW capability on Linux.
    pub async fn punch(remote_ip: Ipv4Addr, local_port: u16) -> Result<()> {
        info!(
            "Attempting ICMP hole punching to {}:{}",
            remote_ip, local_port
        );

        // Create raw ICMP socket
        let socket =
            Self::create_raw_icmp_socket().context("create raw ICMP socket - check CAP_NET_RAW")?;

        // Build ICMP Echo Request
        let echo = Self::build_echo_request(local_port, 1);

        // Send to remote
        let remote_addr = SocketAddrV4::new(remote_ip, 0); // Port ignored for ICMP
        socket
            .send_to(&echo, &remote_addr.into())
            .context("send ICMP Echo Request")?;

        info!("ICMP Echo Request sent to {}", remote_ip);

        // Wait for Echo Reply (with timeout)
        let mut recv_buf: Vec<MaybeUninit<u8>> = vec![MaybeUninit::uninit(); 1024];

        match timeout(Duration::from_secs(3), async {
            loop {
                let (n, from) = socket.recv_from(&mut recv_buf).context("receive ICMP")?;

                // Safety: recv_from ha inizializzato i primi n bytes
                let recv_buf_init =
                    unsafe { std::slice::from_raw_parts(recv_buf.as_ptr() as *const u8, n) };

                if let Some(reply_port) = Self::parse_echo_reply(recv_buf_init) {
                    if reply_port == local_port {
                        info!(
                            "ICMP Echo Reply received from {:?}, UDP pinhole likely open",
                            from
                        );
                        return Ok::<(), anyhow::Error>(());
                    }
                }
            }
        })
        .await
        {
            Ok(Ok(())) => Ok(()),
            Ok(Err(e)) => bail!("ICMP receive error: {}", e),
            Err(_) => {
                warn!("ICMP timeout - no reply received, but pinhole may still be open");
                Ok(()) // Non-fatal, NAT might still have opened pinhole
            }
        }
    }

    /// Create raw ICMP socket (requires privileges)
    fn create_raw_icmp_socket() -> Result<Socket> {
        // Try to create raw socket
        match Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::ICMPV4)) {
            Ok(socket) => {
                // Bind to any interface
                socket
                    .bind(&"0.0.0.0:0".parse::<SocketAddrV4>().unwrap().into())
                    .context("bind ICMP socket")?;

                // Set non-blocking
                socket.set_nonblocking(true).context("set non-blocking")?;

                Ok(socket)
            }
            Err(e) => {
                bail!(
                    "Failed to create raw ICMP socket: {} - check CAP_NET_RAW capability",
                    e
                );
            }
        }
    }

    /// Build ICMP Echo Request packet
    fn build_echo_request(identifier: u16, sequence: u16) -> Vec<u8> {
        let mut packet = Vec::with_capacity(64);

        // ICMP Header
        packet.push(8); // Type: Echo Request
        packet.push(0); // Code: 0
        packet.push(0); // Checksum placeholder
        packet.push(0);

        // Identifier and sequence
        packet.extend_from_slice(&identifier.to_be_bytes());
        packet.extend_from_slice(&sequence.to_be_bytes());

        // Payload - "HS_INIT" marker
        packet.extend_from_slice(b"HS_INIT");

        // Calculate checksum
        let checksum = Self::icmp_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        packet
    }

    /// Parse ICMP Echo Reply to extract identifier
    fn parse_echo_reply(packet: &[u8]) -> Option<u16> {
        if packet.len() < 8 {
            return None;
        }

        let msg_type = packet[0];
        let code = packet[1];

        // Verify it's an Echo Reply
        if msg_type != 0 || code != 0 {
            return None;
        }

        // Verify checksum: valid packets yield 0 after recompute
        if Self::icmp_checksum(packet) != 0 {
            warn!("ICMP checksum mismatch");
            return None;
        }

        // Extract identifier (local port)
        Some(u16::from_be_bytes([packet[4], packet[5]]))
    }

    /// Calculate ICMP checksum (RFC 1071)
    fn icmp_checksum(packet: &[u8]) -> u16 {
        let mut sum = 0u32;
        let mut i = 0;

        // Sum 16-bit words
        while i + 1 < packet.len() {
            let word = u16::from_be_bytes([packet[i], packet[i + 1]]);
            sum = sum.wrapping_add(word as u32);
            i += 2;
        }

        // Add leftover byte
        if i < packet.len() {
            sum = sum.wrapping_add((packet[i] as u32) << 8);
        }

        // Fold 32-bit sum to 16 bits
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        !sum as u16
    }

    /// Check if we have CAP_NET_RAW capability
    pub fn check_capabilities() -> bool {
        match Self::create_raw_icmp_socket() {
            Ok(_) => {
                info!("ICMP hole punching capability available");
                true
            }
            Err(e) => {
                warn!("ICMP hole punching not available: {}", e);
                false
            }
        }
    }

    /// Attempt UDP hole punching via ICMP trigger
    ///
    /// Some NATs will open a UDP pinhole when they see outbound ICMP,
    /// even if they block UDP initially.
    pub async fn trigger_udp_hole(
        local_udp: &tokio::net::UdpSocket,
        remote_ip: Ipv4Addr,
    ) -> Result<()> {
        // Bind UDP socket to specific port if not already
        let local_addr = local_udp.local_addr().context("get local UDP address")?;

        // Extract port
        let local_port = match local_addr {
            std::net::SocketAddr::V4(v4) => v4.port(),
            _ => bail!("IPv6 not supported for ICMP hole punching"),
        };

        // Send ICMP to trigger NAT
        Self::punch(remote_ip, local_port).await?;

        // Now the NAT should have a pinhole for this UDP port
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_icmp_checksum() {
        let packet = vec![
            8, 0, 0, 0, // Echo Request
            0x12, 0x34, // Identifier
            0x00, 0x01, // Sequence
            b'H', b'S', b'_', b'I', b'N', b'I', b'T',
        ];

        let checksum = IcmpHolePunch::icmp_checksum(&packet);
        assert_ne!(checksum, 0);

        // Packet with correct checksum should verify
        let mut verified = packet.clone();
        verified[2..4].copy_from_slice(&checksum.to_be_bytes());
        assert_eq!(IcmpHolePunch::icmp_checksum(&verified), 0);
    }

    #[test]
    fn test_build_echo_request() {
        let request = IcmpHolePunch::build_echo_request(12345, 1);
        assert_eq!(request[0], 8); // Echo Request type
        assert_eq!(request[1], 0); // Code 0
        assert!(request.len() >= 15); // Header + payload marker
    }

    #[test]
    fn test_parse_echo_reply() {
        let mut packet = vec![
            0, 0, 0, 0, // Echo Reply (type 0)
            0x12, 0x34, // Identifier = 4660
            0x00, 0x01, // Sequence
        ];

        // Calculate and set checksum
        let checksum = IcmpHolePunch::icmp_checksum(&packet);
        packet[2..4].copy_from_slice(&checksum.to_be_bytes());

        let id = IcmpHolePunch::parse_echo_reply(&packet);
        assert_eq!(id, Some(4660));
    }

    #[test]
    fn test_check_capabilities() {
        // This will fail without root/CAP_NET_RAW
        let has_cap = IcmpHolePunch::check_capabilities();
        if !has_cap {
            println!("ICMP hole punching not available - run with CAP_NET_RAW");
        }
    }
}
