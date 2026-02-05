use anyhow::{Context, Result};
use futures::{future::BoxFuture, stream::FuturesUnordered, FutureExt, StreamExt};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::select;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::derive::RendezvousParams;
use crate::offer::{Endpoint, EndpointKind, OfferPayload};
use crate::session_noise::NoiseRole;
use crate::transport::wan_tor;
use crate::transport::{
    self,
    nat_detection::{self, NatDetector},
    Connection,
};

type IceAttemptFuture = BoxFuture<'static, Result<Option<(Connection, SocketAddr)>>>;

#[derive(Debug, Clone)]
pub struct IceCandidate {
    pub kind: IceCandidateKind,
    pub priority: u32,
    pub addr: Option<SocketAddr>,
    pub timeout_ms: u64,
    pub retry_count: usize,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub enum IceCandidateKind {
    Lan,
    Upnp,
    Stun,
    Relay,
    Tor,
}

pub struct IceAgent {
    params: RendezvousParams,
    config: Config,
    noise_role: NoiseRole,
    offer: OfferPayload,
    offer_hash: [u8; 32],
    attempted: Arc<Mutex<std::collections::HashMap<IceCandidateKind, usize>>>,
}

impl IceAgent {
    pub fn new(
        params: RendezvousParams,
        config: Config,
        noise_role: NoiseRole,
        offer: OfferPayload,
        offer_hash: [u8; 32],
    ) -> Self {
        Self {
            params,
            config,
            noise_role,
            offer,
            offer_hash,
            attempted: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    async fn gather_lan_candidates(&self) -> Result<Vec<IceCandidate>> {
        let local_addrs = self.get_local_ip_addresses()?;
        let mut candidates = Vec::new();

        for ip in local_addrs {
            let addr = SocketAddr::new(ip, self.params.port);
            candidates.push(IceCandidate {
                kind: IceCandidateKind::Lan,
                priority: 100,
                addr: Some(addr),
                timeout_ms: 1200,
                retry_count: 0,
            });
        }

        Ok(candidates)
    }

    async fn gather_upnp_candidates(&self) -> Result<Vec<IceCandidate>> {
        match transport::wan_direct::try_direct_port_forward(self.params.port).await {
            Ok((_, ext_addr)) => {
                info!("UPnP/NAT-PMP/PCP mapping successful: {}", ext_addr);
                Ok(vec![IceCandidate {
                    kind: IceCandidateKind::Upnp,
                    priority: 80,
                    addr: Some(ext_addr),
                    timeout_ms: 2000,
                    retry_count: 0,
                }])
            }
            Err(e) => {
                debug!("UPnP/NAT-PMP/PCP failed: {}", e);
                Ok(vec![])
            }
        }
    }

    async fn gather_stun_candidates(&self) -> Result<Vec<IceCandidate>> {
        let stun_servers = &self.config.nat_detection_servers;
        if stun_servers.is_empty() {
            return Ok(vec![]);
        }

        let mut candidates = Vec::new();

        for stun_server in stun_servers.iter().take(3) {
            match tokio::time::timeout(Duration::from_secs(3), self.stun_binding(stun_server)).await
            {
                Ok(Ok(Some(ext_addr))) => {
                    info!("STUN binding successful via {}: {}", stun_server, ext_addr);
                    candidates.push(IceCandidate {
                        kind: IceCandidateKind::Stun,
                        priority: 70,
                        addr: Some(ext_addr),
                        timeout_ms: 3000,
                        retry_count: 0,
                    });
                }
                Ok(Ok(None)) => {
                    warn!("STUN binding returned no result from {}", stun_server);
                }
                Ok(Err(e)) => {
                    warn!("STUN binding failed for {}: {}", stun_server, e);
                }
                Err(_) => {
                    warn!("STUN binding timeout for {}", stun_server);
                }
            }
        }

        Ok(candidates)
    }

    async fn stun_binding(&self, stun_server: &str) -> Result<Option<SocketAddr>> {
        let local_sock = UdpSocket::bind("0.0.0.0:0")
            .await
            .context("bind STUN local socket")?;

        let stun_addr: SocketAddr = stun_server.parse().context("parse STUN server address")?;

        let mut buf = vec![0u8; 512];

        let tx_id: [u8; 12] = rand::random();
        let binding_request = self.build_stun_binding_request(tx_id);

        local_sock.send_to(&binding_request, stun_addr).await?;

        let (n, _) =
            tokio::time::timeout(Duration::from_secs(2), local_sock.recv_from(&mut buf)).await??;

        let response = &buf[..n];

        if response.len() < 20 || response[0..2] != [0x01, 0x01] {
            return Ok(None);
        }

        let message_len = u16::from_be_bytes([response[2], response[3]]) as usize;
        if response.len() < 20 + message_len {
            return Ok(None);
        }

        let mut offset = 20;
        while offset + 4 <= response.len() {
            let attr_type = u16::from_be_bytes([response[offset], response[offset + 1]]);
            let attr_len =
                u16::from_be_bytes([response[offset + 2], response[offset + 3]]) as usize;
            let padded_len = attr_len.div_ceil(4) * 4;

            if attr_type == 0x0020 && offset + 4 + attr_len <= response.len() && attr_len >= 8 {
                let family = response[offset + 5];
                if family == 0x01 {
                    let port = u16::from_be_bytes([response[offset + 6], response[offset + 7]]);
                    let ip = Ipv4Addr::new(
                        response[offset + 8],
                        response[offset + 9],
                        response[offset + 10],
                        response[offset + 11],
                    );
                    return Ok(Some(SocketAddr::new(ip.into(), port)));
                }
            }

            offset += 4 + padded_len;
        }

        Ok(None)
    }

    fn build_stun_binding_request(&self, tx_id: [u8; 12]) -> Vec<u8> {
        let mut req = Vec::new();
        req.extend_from_slice(&[0x00, 0x01]);
        req.extend_from_slice(&[0x00, 0x00]);
        req.extend_from_slice(&tx_id);
        req
    }

    async fn gather_relay_candidates(&self) -> Result<Vec<IceCandidate>> {
        if self.config.assist_relays.is_empty() {
            return Ok(vec![]);
        }

        let mut candidates = Vec::new();

        for _relay in self.config.assist_relays.iter().take(2) {
            candidates.push(IceCandidate {
                kind: IceCandidateKind::Relay,
                priority: 60,
                addr: None,
                timeout_ms: 4000,
                retry_count: 0,
            });
        }

        Ok(candidates)
    }

    async fn gather_tor_candidates(&self) -> Result<Vec<IceCandidate>> {
        if self.config.tor_onion_addr.is_none() && self.offer.tor_onion_addr()?.is_none() {
            return Ok(vec![]);
        }

        Ok(vec![IceCandidate {
            kind: IceCandidateKind::Tor,
            priority: 50,
            addr: None,
            timeout_ms: 6000,
            retry_count: 0,
        }])
    }

    async fn race_candidates(&self) -> Result<(Connection, SocketAddr)> {
        let candidates = self.gather_candidates().await?;

        for candidate in candidates.clone().iter() {
            if candidate.kind == IceCandidateKind::Lan
                || candidate.kind == IceCandidateKind::Upnp
                || candidate.kind == IceCandidateKind::Stun
            {
                if let Some(addr) = candidate.addr {
                    debug!(
                        "Testing {} candidate at {}",
                        format!("{:?}", candidate.kind).to_lowercase(),
                        addr
                    );
                }
            }
        }

        let udp_dispatch = Arc::new(
            UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], self.params.port)))
                .await
                .context("bind UDP socket for ICE")?,
        );

        let mut eligible = Vec::new();
        for candidate in candidates {
            if self.is_exhausted(&candidate.kind).await {
                continue;
            }
            eligible.push(candidate);
        }

        let futures: FuturesUnordered<IceAttemptFuture> = FuturesUnordered::new();

        for candidate in eligible {
            let agent = self.clone();
            let dispatch = udp_dispatch.clone();
            futures.push(async move { agent.attempt_candidate(candidate, dispatch).await }.boxed());
        }

        let result = select! {
            res = self.wait_first_success(futures) => res,
            _ = tokio::time::sleep(Duration::from_secs(15)) => {
                Err(anyhow::anyhow!("Global ICE timeout"))
            }
        };

        result
    }

    /// Raccoglie i candidati con strategia adattiva basata su NAT type
    async fn gather_candidates(&self) -> Result<Vec<IceCandidate>> {
        let detector = NatDetector::new(self.config.nat_detection_servers.clone());
        let nat_type = detector.detect_nat_type().await.unwrap_or_else(|e| {
            tracing::warn!("NAT detection failed, using Unknown: {}", e);
            crate::transport::nat_detection::NatType::Unknown
        });

        let mut candidates = Vec::new();

        // LAN sempre prioritario
        if let Ok(lan_eps) = self.gather_lan_candidates().await {
            candidates.extend(lan_eps);
        }

        // Seleziona strategia basata su NAT type
        let strategy = nat_detection::NatDetector::select_strategy(nat_type);

        for priority in strategy {
            match priority.kind {
                crate::transport::nat_detection::TransportKind::Upnp if !priority.should_skip => {
                    if let Ok(upnp_eps) = self.gather_upnp_candidates().await {
                        candidates.extend(upnp_eps);
                    }
                }
                crate::transport::nat_detection::TransportKind::Stun if !priority.should_skip => {
                    if let Ok(stun_eps) = self.gather_stun_candidates().await {
                        candidates.extend(stun_eps);
                    }
                }
                crate::transport::nat_detection::TransportKind::Relay => {
                    if let Ok(relay_eps) = self.gather_relay_candidates().await {
                        candidates.extend(relay_eps);
                    }
                }
                crate::transport::nat_detection::TransportKind::Tor => {
                    if let Ok(tor_eps) = self.gather_tor_candidates().await {
                        candidates.extend(tor_eps);
                    }
                }
                _ => {}
            }
        }

        // Sort by priority (higher priority first)
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        Ok(candidates)
    }

    async fn wait_first_success(
        &self,
        mut futures: FuturesUnordered<IceAttemptFuture>,
    ) -> Result<(Connection, SocketAddr)> {
        while let Some(res) = futures.next().await {
            match res {
                Ok(Some((conn, addr))) => return Ok((conn, addr)),
                Ok(None) => continue,
                Err(e) => {
                    warn!("ICE candidate failed: {}", e);
                    continue;
                }
            }
        }

        Err(anyhow::anyhow!("All ICE candidates failed"))
    }

    async fn attempt_candidate(
        &self,
        candidate: IceCandidate,
        dispatch: Arc<UdpSocket>,
    ) -> Result<Option<(Connection, SocketAddr)>> {
        self.mark_attempted(&candidate.kind).await;

        let result = match candidate.kind {
            IceCandidateKind::Lan => {
                if let Some(addr) = candidate.addr {
                    self.attempt_udp_connection(addr, dispatch, EndpointKind::Lan)
                        .await
                } else {
                    Ok(None)
                }
            }
            IceCandidateKind::Upnp => {
                if let Some(addr) = candidate.addr {
                    self.attempt_udp_connection(addr, dispatch, EndpointKind::Wan)
                        .await
                } else {
                    Ok(None)
                }
            }
            IceCandidateKind::Stun => {
                if let Some(addr) = candidate.addr {
                    self.attempt_udp_connection(addr, dispatch, EndpointKind::Wan)
                        .await
                } else {
                    Ok(None)
                }
            }
            IceCandidateKind::Relay => self.attempt_relay().await,
            IceCandidateKind::Tor => self.attempt_tor().await,
        };

        if result.is_err() {
            self.schedule_retry(&candidate.kind).await;
        }

        result
    }

    async fn attempt_udp_connection(
        &self,
        addr: SocketAddr,
        dispatch: Arc<UdpSocket>,
        kind: EndpointKind,
    ) -> Result<Option<(Connection, SocketAddr)>> {
        let endpoint = Endpoint {
            kind,
            addr: Some(addr),
            priority: 0,
            timeout_ms: 2000,
        };

        let result = tokio::time::timeout(
            Duration::from_millis(2000),
            establish_connection_from_candidate(
                &self.offer,
                &self.config,
                self.noise_role,
                dispatch,
                endpoint,
            ),
        )
        .await;

        match result {
            Ok(Ok(connect_result)) => {
                let peer_addr = if let Some(peer) = &connect_result.peer {
                    peer.parse().unwrap_or(addr)
                } else {
                    addr
                };
                Ok(Some((connect_result.conn, peer_addr)))
            }
            Ok(Err(e)) => {
                warn!("UDP connection attempt failed for {}: {}", addr, e);
                Ok(None)
            }
            Err(_) => {
                warn!("UDP connection attempt timeout for {}", addr);
                Ok(None)
            }
        }
    }

    async fn attempt_relay(&self) -> Result<Option<(Connection, SocketAddr)>> {
        let attempt_start = tokio::time::Instant::now();
        let mut attempts = 0;

        for relay in self.config.assist_relays.iter().take(2) {
            if attempt_start.elapsed() > Duration::from_secs(5) {
                warn!("WAN Assist: global timeout exceeded");
                break;
            }

            attempts += 1;
            match tokio::time::timeout(
                Duration::from_secs(2),
                transport::wan_assist::try_assisted_punch(
                    &self.params,
                    std::slice::from_ref(relay),
                    &self.config,
                ),
            )
            .await
            {
                Ok(Ok(conn)) => {
                    info!("WAN Assist: success after {} attempts", attempts);
                    let relay_addr = relay
                        .parse()
                        .unwrap_or_else(|_| SocketAddr::from(([0, 0, 0, 0], 0)));
                    return Ok(Some((conn, relay_addr)));
                }
                Ok(Err(e)) => {
                    warn!("Relay {} failed: {}", relay, e);
                }
                Err(_) => {
                    warn!("Relay {} timeout", relay);
                }
            }
        }

        Ok(None)
    }

    async fn attempt_tor(&self) -> Result<Option<(Connection, SocketAddr)>> {
        if let Some(onion) = self.offer.tor_onion_addr()? {
            match wan_tor::try_tor_connect(&self.config.tor_socks_addr, &onion, None, None).await {
                Ok(stream) => {
                    let (reader, writer) = stream.into_split();
                    let conn = Connection::WanTorStream {
                        reader: Arc::new(Mutex::new(reader)),
                        writer: Arc::new(Mutex::new(writer)),
                    };
                    return Ok(Some((conn, SocketAddr::from(([0, 0, 0, 0], 0)))));
                }
                Err(e) => {
                    warn!("Tor connection attempt failed: {}", e);
                }
            }
        }

        Ok(None)
    }

    async fn is_exhausted(&self, kind: &IceCandidateKind) -> bool {
        let attempted = self.attempted.lock().await;
        let attempts = attempted.get(kind).copied().unwrap_or(0);
        attempts >= 3
    }

    async fn mark_attempted(&self, kind: &IceCandidateKind) {
        let mut attempted = self.attempted.lock().await;
        *attempted.entry(kind.clone()).or_insert(0) += 1;
    }

    async fn schedule_retry(&self, kind: &IceCandidateKind) {
        let attempted = self.attempted.lock().await;
        let attempts = attempted.get(kind).copied().unwrap_or(0);

        if attempts >= 3 {
            warn!(
                "ICE candidate {:?} exhausted after {} attempts",
                kind, attempts
            );
        } else {
            let backoff_ms = 1000 * 2u64.pow(attempts as u32);
            debug!(
                "ICE candidate {:?} will retry in {}ms (attempt {})",
                kind,
                backoff_ms,
                attempts + 1
            );
        }
    }

    fn get_local_ip_addresses(&self) -> Result<Vec<IpAddr>> {
        Ok(crate::transport::lan::get_local_ip_addresses()?)
    }
}

impl Clone for IceAgent {
    fn clone(&self) -> Self {
        Self {
            params: self.params.clone(),
            config: self.config.clone(),
            noise_role: self.noise_role,
            offer: self.offer.clone(),
            offer_hash: self.offer_hash,
            attempted: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}

pub async fn multipath_race_connect(
    offer: &OfferPayload,
    offer_hash: [u8; 32],
    params: RendezvousParams,
    config: Config,
    noise_role: NoiseRole,
) -> Result<(Connection, SocketAddr)> {
    let agent = IceAgent::new(params, config, noise_role, offer.clone(), offer_hash);
    agent.race_candidates().await
}

pub async fn establish_connection_from_candidate(
    _offer: &OfferPayload,
    _cfg: &Config,
    _noise_role: NoiseRole,
    dispatch: Arc<UdpSocket>,
    endpoint: Endpoint,
) -> Result<OfferConnectResult> {
    let session_key = [0u8; 32];

    let conn = match endpoint.kind {
        EndpointKind::Lan => {
            let addr = endpoint
                .addr
                .ok_or_else(|| anyhow::anyhow!("LAN endpoint missing addr"))?;
            Connection::Lan(dispatch, addr)
        }
        EndpointKind::Wan => {
            let addr = endpoint
                .addr
                .ok_or_else(|| anyhow::anyhow!("WAN endpoint missing addr"))?;
            Connection::Wan(dispatch, addr)
        }
        EndpointKind::Tor => {
            return Err(anyhow::anyhow!("Tor not supported in UDP candidate mode"));
        }
    };

    let mode = match endpoint.kind {
        EndpointKind::Lan => "lan",
        EndpointKind::Wan => "wan",
        EndpointKind::Tor => "wan_tor",
    }
    .to_string();

    Ok(OfferConnectResult {
        conn,
        session_key,
        mode,
        peer: endpoint.addr.map(|a| a.to_string()),
        resume_used: None,
    })
}

pub struct OfferConnectResult {
    pub conn: Connection,
    pub session_key: [u8; 32],
    pub mode: String,
    pub peer: Option<String>,
    pub resume_used: Option<bool>,
}
