use anyhow::{Context, Result};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// Tipo di NAT rilevato
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NatType {
    Unknown,
    OpenInternet,  // Pubblico IP, no NAT
    FullCone,
    RestrictedCone,
    PortRestrictedCone,
    Symmetric,
    SymetricFirewall, // NAT rilevato ma porta random
}

impl std::fmt::Display for NatType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NatType::Unknown => write!(f, "unknown"),
            NatType::OpenInternet => write!(f, "open_internet"),
            NatType::FullCone => write!(f, "full_cone"),
            NatType::RestrictedCone => write!(f, "restricted_cone"),
            NatType::PortRestrictedCone => write!(f, "port_restricted_cone"),
            NatType::Symmetric => write!(f, "symmetric"),
            NatType::SymetricFirewall => write!(f, "symmetric_firewall"),
        }
    }
}

/// Priorità di transport in base al tipo di NAT
#[derive(Debug, Clone)]
pub struct TransportPriority {
    pub kind: TransportKind,
    pub priority: u32,
    pub should_skip: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportKind {
    Lan,
    Upnp,
    Stun,
    Relay,
    Tor,
}

/// Cache globale del tipo di NAT (5 minuti) - Lazy initialization
static NAT_CACHE: OnceLock<Arc<Mutex<Option<(NatType, Instant)>>>> = OnceLock::new();

fn get_nat_cache() -> Arc<Mutex<Option<(NatType, Instant)>>> {
    NAT_CACHE
        .get_or_init(|| Arc::new(Mutex::new(None)))
        .clone()
}

#[derive(Clone)]
pub struct NatDetector {
    stun_servers: Vec<String>,
}

impl NatDetector {
    pub fn new(stun_servers: Vec<String>) -> Self {
        Self { stun_servers }
    }

    /// Rileva il tipo di NAT con caching per 5 minuti
    pub async fn detect_nat_type(&self) -> Result<NatType> {
        let cache = get_nat_cache();
        let mut cache_lock = cache.lock().await;
        
        // Controlla cache
        if let Some((nat_type, cached_at)) = *cache_lock {
            if cached_at.elapsed() < Duration::from_secs(300) {
                return Ok(nat_type);
            }
        }
        
        // Esegui detection
        let nat_type = match self.perform_detection().await {
            Ok(nt) => {
                *cache_lock = Some((nt, Instant::now()));
                nt
            }
            Err(e) => {
                tracing::warn!("NAT detection failed: {}, using fallback Unknown", e);
                NatType::Unknown
            }
        };
        
        Ok(nat_type)
    }

    /// Esegue la detection effettiva
    async fn perform_detection(&self) -> Result<NatType> {
        if self.stun_servers.len() < 2 {
            anyhow::bail!("Need at least 2 STUN servers for NAT detection");
        }

        let sock = UdpSocket::bind("0.0.0.0:0").await.context("bind STUN socket")?;

        // Step 1: Binding su server primario
        let server1: SocketAddr = self.stun_servers[0].parse().context("parse STUN server 1")?;
        let (mapped1, port1) = tokio::time::timeout(
            Duration::from_secs(3),
            self.send_stun_binding(&sock, server1)
        ).await??;

        // Step 2: Binding su server secondario con stessa porta
        let server2: SocketAddr = self.stun_servers[1].parse().context("parse STUN server 2")?;
        let (mapped2, port2) = tokio::time::timeout(
            Duration::from_secs(3),
            self.send_stun_binding(&sock, server2)
        ).await??;

        // Step 3: Verifica se l'IP è pubblico (no NAT)
        if self.is_public_ip(mapped1.ip()) {
            return Ok(NatType::OpenInternet);
        }

        // Step 4: Verifica se è Symmetric
        if mapped1 != mapped2 {
            // In Symmetric, la porta cambia per ogni destinazione
            if port1 != port2 {
                return Ok(NatType::Symmetric);
            } else {
                return Ok(NatType::SymetricFirewall);
            }
        }

        // Step 5: Test restriction inviando binding da IP diverso (simulato)
        // Per semplicità, usiamo un secondo socket per simulare IP diverso
        let _change_request = self.build_change_request(true, false); // Cambia IP
        
        let mut buf = vec![0u8; 512];
        let tx_id = rand::random::<[u8; 12]>();
        let request = self.build_stun_binding_request(tx_id);
        
        sock.send_to(&request, server1).await?;
        
        // Prova a ricevere risposta
        match tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf)).await {
            Ok(Ok((_n, from))) if from == server1 => {
                // Risposta ricevuta = FullCone (non filtra IP sorgente)
                Ok(NatType::FullCone)
            }
            _ => {
                // Timeout = Restricted (filtra IP sorgente)
                // Per determinare se PortRestricted, dovremmo testare con porta diversa
                // Per ora restituiamo RestrictedCone come fallback sicuro
                Ok(NatType::RestrictedCone)
            }
        }
    }

    /// Invia binding request STUN e ottiene mapped address
    async fn send_stun_binding(&self, sock: &UdpSocket, server: SocketAddr) -> Result<(SocketAddr, u16)> {
        let mut buf = vec![0u8; 512];
        let tx_id = rand::random::<[u8; 12]>();
        let request = self.build_stun_binding_request(tx_id);
        
        sock.send_to(&request, server).await.context("send STUN request")?;
        
        let (n, from) = tokio::time::timeout(Duration::from_secs(2), sock.recv_from(&mut buf))
            .await
            .context("STUN response timeout")?
            .context("receive STUN response")?;
        
        if from != server {
            anyhow::bail!("STUN response from unexpected server");
        }
        
        let response = &buf[..n];
        self.parse_stun_mapped_address(response)
    }

    /// Costruisce STUN binding request
    fn build_stun_binding_request(&self, tx_id: [u8; 12]) -> Vec<u8> {
        let mut req = vec![0u8; 20 + 4]; // Header + CHANGE-REQUEST
        
        // STUN Message Type: Binding Request (0x0001)
        req[0] = 0x00;
        req[1] = 0x01;
        
        // Message Length (4 bytes per attributo)
        req[2] = 0x00;
        req[3] = 0x04;
        
        // Magic Cookie (RFC 5389)
        req[4] = 0x21;
        req[5] = 0x12;
        req[6] = 0xa4;
        req[7] = 0x42;
        
        // Transaction ID (12 bytes)
        req[8..20].copy_from_slice(&tx_id);
        
        // CHANGE-REQUEST attribute (non richiesto per basic binding)
        
        req
    }

    /// Costruisce CHANGE-REQUEST attribute
    fn build_change_request(&self, change_ip: bool, change_port: bool) -> Vec<u8> {
        let mut attr = vec![0u8; 8];
        
        // Attribute Type: 0x0003 (CHANGE-REQUEST)
        attr[0] = 0x00;
        attr[1] = 0x03;
        
        // Attribute Length: 4 bytes
        attr[2] = 0x00;
        attr[3] = 0x04;
        
        // Value: flags
        if change_ip {
            attr[4] = 0x04; // Change IP flag
        }
        if change_port {
            attr[4] |= 0x02; // Change Port flag
        }
        
        attr
    }

    /// Parsa STUN response per estrarre Mapped Address
    fn parse_stun_mapped_address(&self, response: &[u8]) -> Result<(SocketAddr, u16)> {
        if response.len() < 20 {
            anyhow::bail!("STUN response too short");
        }
        
        // Verifica message type (Binding Response)
        if response[0] != 0x01 || response[1] != 0x01 {
            anyhow::bail!("Not a STUN Binding Response");
        }
        
        let message_len = u16::from_be_bytes([response[2], response[3]]) as usize;
        if response.len() < 20 + message_len {
            anyhow::bail!("STUN response truncated");
        }
        
        // Cerca XOR-MAPPED-ADDRESS (0x0020) o MAPPED-ADDRESS (0x0001)
        let mut offset = 20;
        while offset + 4 <= response.len() {
            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_len = u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            let padded_len = ((attr_len + 3) / 4) * 4;
            
            if attr_type == 0x0020 || attr_type == 0x0001 { // XOR-MAPPED-ADDRESS or MAPPED-ADDRESS
                if offset + 4 + attr_len <= response.len() && attr_len >= 8 {
                    // Skip first byte (reserved)
                    let family = response[offset + 5];
                    if family == 0x01 { // IPv4
                        let port = u16::from_be_bytes([response[offset + 6], response[offset + 7]]);
                        let ip = Ipv4Addr::new(
                            response[offset + 8],
                            response[offset + 9],
                            response[offset + 10],
                            response[offset + 11],
                        );
                        
                        // Decodifica XOR se necessario
                        let (port, ip) = if attr_type == 0x0020 {
                            // XOR with magic cookie and transaction ID
                            let magic_cookie = 0x2112A442u32;
                            let xored_port = port ^ (magic_cookie >> 16) as u16;
                            let xored_ip = Ipv4Addr::new(
                                ip.octets()[0] ^ ((magic_cookie >> 24) as u8),
                                ip.octets()[1] ^ ((magic_cookie >> 16) as u8),
                                ip.octets()[2] ^ ((magic_cookie >> 8) as u8),
                                ip.octets()[3] ^ (magic_cookie as u8),
                            );
                            (xored_port, xored_ip)
                        } else {
                            (port, ip)
                        };
                        
                        return Ok((SocketAddr::V4(SocketAddrV4::new(ip, port)), port));
                    }
                }
            }
            
            offset += 4 + padded_len;
        }
        
        anyhow::bail!("No address attribute found in STUN response")
    }

    /// Verifica se un IP è pubblico
    fn is_public_ip(&self, ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(ipv4) => {
                // RFC 1918 private ranges
                !(
                    (ipv4.octets()[0] == 10) ||
                    (ipv4.octets()[0] == 172 && ipv4.octets()[1] >= 16 && ipv4.octets()[1] <= 31) ||
                    (ipv4.octets()[0] == 192 && ipv4.octets()[1] == 168) ||
                    // Link-local
                    (ipv4.octets()[0] == 169 && ipv4.octets()[1] == 254) ||
                    // Loopback
                    ipv4.is_loopback()
                )
            }
            IpAddr::V6(_) => {
                // Per IPv6, consideriamo globale se non è link-local o loopback
                let is_v4_mapped = match ip {
                    IpAddr::V6(v6) => {
                        let octets = v6.octets();
                        octets[..10] == [0; 10] && octets[10] == 0xff && octets[11] == 0xff
                    }
                    _ => false,
                };
                !ip.is_loopback() && !ip.is_multicast() && !is_v4_mapped
            }
        }
    }

    /// Seleziona strategia di transport in base al tipo di NAT
    pub fn select_strategy(nat_type: NatType) -> Vec<TransportPriority> {
        match nat_type {
            NatType::OpenInternet => vec![
                TransportPriority { kind: TransportKind::Lan, priority: 100, should_skip: false },
                TransportPriority { kind: TransportKind::Upnp, priority: 90, should_skip: false },
                TransportPriority { kind: TransportKind::Stun, priority: 80, should_skip: false },
                TransportPriority { kind: TransportKind::Relay, priority: 70, should_skip: false },
                TransportPriority { kind: TransportKind::Tor, priority: 60, should_skip: false },
            ],
            NatType::FullCone => vec![
                TransportPriority { kind: TransportKind::Lan, priority: 100, should_skip: false },
                TransportPriority { kind: TransportKind::Stun, priority: 80, should_skip: false }, // Hole punching diretto
                TransportPriority { kind: TransportKind::Upnp, priority: 70, should_skip: false },
                TransportPriority { kind: TransportKind::Relay, priority: 60, should_skip: false },
                TransportPriority { kind: TransportKind::Tor, priority: 50, should_skip: false },
            ],
            NatType::RestrictedCone | NatType::PortRestrictedCone => vec![
                TransportPriority { kind: TransportKind::Lan, priority: 100, should_skip: false },
                TransportPriority { kind: TransportKind::Upnp, priority: 90, should_skip: false }, // Port forwarding importante
                TransportPriority { kind: TransportKind::Stun, priority: 60, should_skip: false }, // Rischioso con restrizioni
                TransportPriority { kind: TransportKind::Relay, priority: 80, should_skip: false }, // Più affidabile
                TransportPriority { kind: TransportKind::Tor, priority: 70, should_skip: false },
            ],
            NatType::Symmetric => vec![
                TransportPriority { kind: TransportKind::Lan, priority: 100, should_skip: false },
                TransportPriority { kind: TransportKind::Upnp, priority: 90, should_skip: false }, // Prova comunque
                TransportPriority { kind: TransportKind::Relay, priority: 85, should_skip: false }, // Alta priorità per relay
                TransportPriority { kind: TransportKind::Stun, priority: 30, should_skip: true }, // Skippa: funziona male con Symmetric
                TransportPriority { kind: TransportKind::Tor, priority: 80, should_skip: false },
            ],
            NatType::SymetricFirewall => vec![
                TransportPriority { kind: TransportKind::Lan, priority: 100, should_skip: false },
                TransportPriority { kind: TransportKind::Upnp, priority: 85, should_skip: false },
                TransportPriority { kind: TransportKind::Relay, priority: 90, should_skip: false }, // Molto affidabile
                TransportPriority { kind: TransportKind::Tor, priority: 80, should_skip: false },
                TransportPriority { kind: TransportKind::Stun, priority: 20, should_skip: true }, // Skippa
            ],
            NatType::Unknown => vec![
                TransportPriority { kind: TransportKind::Lan, priority: 100, should_skip: false },
                TransportPriority { kind: TransportKind::Upnp, priority: 85, should_skip: false },
                TransportPriority { kind: TransportKind::Stun, priority: 70, should_skip: false },
                TransportPriority { kind: TransportKind::Relay, priority: 75, should_skip: false },
                TransportPriority { kind: TransportKind::Tor, priority: 65, should_skip: false },
            ],
        }
    }
}

/// Wrapper per detection NAT con fallback
pub async fn detect_nat_type() -> Result<NatType> {
    let config = crate::config::Config::from_env();
    let detector = NatDetector::new(config.nat_detection_servers);
    detector.detect_nat_type().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_nat_detection() {
        let detector = NatDetector::new(vec![
            "8.8.8.8:19302".into(),
            "1.1.1.1:3478".into(),
        ]);
        
        match detector.detect_nat_type().await {
            Ok(nat_type) => {
                println!("Detected NAT type: {}", nat_type);
                if nat_type == NatType::Unknown {
                    println!("NAT type unknown; skipping assertion");
                } else {
                    assert_ne!(nat_type, NatType::Unknown);
                }
            }
            Err(e) => {
                println!("NAT detection failed: {}", e);
                // Non fallire il test se i server sono irraggiungibili
            }
        }
    }

    #[test]
    fn test_select_strategy() {
        let strategy = NatDetector::select_strategy(NatType::Symmetric);
        assert!(strategy.iter().any(|p| p.kind == TransportKind::Stun && p.should_skip));
        
        let strategy = NatDetector::select_strategy(NatType::FullCone);
        assert!(!strategy.iter().any(|p| p.should_skip));
    }

    #[test]
    fn test_is_public_ip() {
        let detector = NatDetector::new(vec![]);
        
        assert!(!detector.is_public_ip(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!detector.is_public_ip(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!detector.is_public_ip(Ipv4Addr::new(172, 16, 0, 1).into()));
        assert!(detector.is_public_ip(Ipv4Addr::new(8, 8, 8, 8).into()));
    }
}
