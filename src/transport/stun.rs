//! STUN client for public endpoint discovery and basic hole punching.
//!
//! RFC 5389 Binding Request/Response (XOR-MAPPED-ADDRESS).

use anyhow::{anyhow, bail, Context, Result};
use rand::RngCore;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;

use crate::transport::nat_detection::{NatDetector, NatType};

const STUN_MAGIC_COOKIE: u32 = 0x2112A442;
const DEFAULT_TIMEOUT_MS: u64 = 3000;

pub struct StunClient {
    servers: Vec<SocketAddr>,
    timeout_ms: u64,
}

#[derive(Debug, Clone)]
pub struct StunDiscovery {
    pub public_addr: SocketAddr,
    pub nat_type: NatType,
    pub server_used: SocketAddr,
    pub socket: Arc<UdpSocket>,
}

impl StunClient {
    pub fn new(servers: Vec<String>) -> Result<Self> {
        let mut parsed = Vec::new();
        for s in servers {
            let s = s.trim();
            if s.is_empty() {
                continue;
            }
            let addr: SocketAddr = s.parse().context("parse STUN server")?;
            parsed.push(addr);
        }
        if parsed.is_empty() {
            bail!("No STUN servers configured");
        }
        Ok(Self {
            servers: parsed,
            timeout_ms: DEFAULT_TIMEOUT_MS,
        })
    }

    pub fn with_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.timeout_ms = timeout_ms.max(100);
        self
    }

    pub async fn discover(&self, local_port: u16) -> Result<StunDiscovery> {
        for server in &self.servers {
            let bind_addr = if server.is_ipv6() {
                SocketAddr::from(([0u16; 8], local_port))
            } else {
                SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), local_port)
            };
            let sock = match UdpSocket::bind(bind_addr).await {
                Ok(s) => s,
                Err(_) => UdpSocket::bind("0.0.0.0:0")
                    .await
                    .context("bind STUN socket")?,
            };
            let sock = Arc::new(sock);

            let tx_id = random_tx_id();
            let req = build_binding_request(tx_id);
            sock.send_to(&req, server)
                .await
                .context("send STUN request")?;

            let mut buf = vec![0u8; 512];
            let (n, from) = match tokio::time::timeout(
                Duration::from_millis(self.timeout_ms),
                sock.recv_from(&mut buf),
            )
            .await
            {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    tracing::warn!("STUN recv error from {}: {}", server, e);
                    continue;
                }
                Err(_) => {
                    tracing::warn!("STUN timeout for {}", server);
                    continue;
                }
            };

            if from != *server {
                tracing::warn!("STUN response from unexpected server {}", from);
                continue;
            }

            let public_addr = parse_xor_mapped_address(&buf[..n], &tx_id)?;
            let nat_type = if self.servers.len() >= 2 {
                let detector =
                    NatDetector::new(self.servers.iter().map(|s| s.to_string()).collect());
                detector.detect_nat_type().await.unwrap_or(NatType::Unknown)
            } else {
                NatType::Unknown
            };

            return Ok(StunDiscovery {
                public_addr,
                nat_type,
                server_used: *server,
                socket: sock,
            });
        }

        Err(anyhow!("STUN discovery failed: all servers exhausted"))
    }

    pub async fn hole_punch(
        &self,
        my_public: SocketAddr,
        peer_public: SocketAddr,
    ) -> Result<UdpSocket> {
        let sock = UdpSocket::bind(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            my_public.port(),
        ))
        .await
        .context("bind hole punch socket")?;
        sock.connect(peer_public).await?;

        let burst = 5usize;
        for i in 0..burst {
            let payload = build_probe_payload();
            let _ = sock.send(&payload).await;
            if i + 1 < burst {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let mut buf = vec![0u8; 1500];
        match tokio::time::timeout(Duration::from_millis(self.timeout_ms), sock.recv(&mut buf))
            .await
        {
            Ok(Ok(_n)) => Ok(sock),
            Ok(Err(e)) => Err(anyhow!("hole punch recv failed: {}", e)),
            Err(_) => Err(anyhow!("hole punch timeout")),
        }
    }

    pub async fn hole_punch_with_socket(
        &self,
        sock: Arc<UdpSocket>,
        peer_public: SocketAddr,
    ) -> Result<Arc<UdpSocket>> {
        sock.connect(peer_public).await?;

        let burst = 5usize;
        for i in 0..burst {
            let payload = build_probe_payload();
            let _ = sock.send(&payload).await;
            if i + 1 < burst {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }

        let mut buf = vec![0u8; 1500];
        match tokio::time::timeout(Duration::from_millis(self.timeout_ms), sock.recv(&mut buf))
            .await
        {
            Ok(Ok(_n)) => Ok(sock),
            Ok(Err(e)) => Err(anyhow!("hole punch recv failed: {}", e)),
            Err(_) => Err(anyhow!("hole punch timeout")),
        }
    }
}

fn random_tx_id() -> [u8; 12] {
    let mut tx_id = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut tx_id);
    tx_id
}

fn build_binding_request(tx_id: [u8; 12]) -> Vec<u8> {
    let mut req = vec![0u8; 20];
    // Message Type: Binding Request (0x0001)
    req[0] = 0x00;
    req[1] = 0x01;
    // Message Length: 0
    req[2] = 0x00;
    req[3] = 0x00;
    // Magic Cookie
    req[4] = 0x21;
    req[5] = 0x12;
    req[6] = 0xa4;
    req[7] = 0x42;
    // Transaction ID
    req[8..20].copy_from_slice(&tx_id);
    req
}

fn parse_xor_mapped_address(response: &[u8], tx_id: &[u8; 12]) -> Result<SocketAddr> {
    if response.len() < 20 {
        bail!("STUN response too short");
    }
    if response[0] != 0x01 || response[1] != 0x01 {
        bail!("Not a STUN Binding Response");
    }

    let message_len = u16::from_be_bytes([response[2], response[3]]) as usize;
    if response.len() < 20 + message_len {
        bail!("STUN response truncated");
    }

    let mut offset = 20;
    while offset + 4 <= response.len() {
        let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
        let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
        let padded_len = attr_len.div_ceil(4) * 4;

        if (attr_type == 0x0020 || attr_type == 0x0001)
            && offset + 4 + attr_len <= response.len()
            && attr_len >= 8
        {
            let family = response[offset + 5];
            if family == 0x01 {
                let port = u16::from_be_bytes([response[offset + 6], response[offset + 7]]);
                let ip = Ipv4Addr::new(
                    response[offset + 8],
                    response[offset + 9],
                    response[offset + 10],
                    response[offset + 11],
                );

                let (port, ip) = if attr_type == 0x0020 {
                    let xored_port = port ^ ((STUN_MAGIC_COOKIE >> 16) as u16);
                    let xored_ip = Ipv4Addr::new(
                        ip.octets()[0] ^ ((STUN_MAGIC_COOKIE >> 24) as u8),
                        ip.octets()[1] ^ ((STUN_MAGIC_COOKIE >> 16) as u8),
                        ip.octets()[2] ^ ((STUN_MAGIC_COOKIE >> 8) as u8),
                        ip.octets()[3] ^ (STUN_MAGIC_COOKIE as u8),
                    );
                    (xored_port, xored_ip)
                } else {
                    (port, ip)
                };

                return Ok(SocketAddr::V4(SocketAddrV4::new(ip, port)));
            } else if family == 0x02 && attr_len >= 20 {
                let port = u16::from_be_bytes([response[offset + 6], response[offset + 7]]);
                let mut addr_bytes = [0u8; 16];
                addr_bytes.copy_from_slice(&response[offset + 8..offset + 24]);

                if attr_type == 0x0020 {
                    // XOR with magic cookie + transaction ID
                    let mut xor_bytes = [0u8; 16];
                    xor_bytes[..4].copy_from_slice(&STUN_MAGIC_COOKIE.to_be_bytes());
                    xor_bytes[4..].copy_from_slice(tx_id);
                    for i in 0..16 {
                        addr_bytes[i] ^= xor_bytes[i];
                    }
                }

                let port = if attr_type == 0x0020 {
                    port ^ ((STUN_MAGIC_COOKIE >> 16) as u16)
                } else {
                    port
                };

                let ip = std::net::Ipv6Addr::from(addr_bytes);
                return Ok(SocketAddr::new(IpAddr::V6(ip), port));
            }
        }

        offset += 4 + padded_len;
    }

    bail!("No XOR-MAPPED-ADDRESS found in STUN response")
}

fn build_probe_payload() -> Vec<u8> {
    let mut v = Vec::with_capacity(128);
    v.extend_from_slice(b"HS-STUN-PUNCH");
    v.resize(128, 0u8);
    v
}
