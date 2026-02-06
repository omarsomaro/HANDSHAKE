use anyhow::{Context, Result};
use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use tracing::{debug, info, warn};

use crate::config::Config;
use crate::derive::RendezvousParams;
use crate::offer::{EndpointKind, OfferPayload};
use crate::resume::ResumeParams;
use crate::session_noise::NoiseRole;
use crate::transport::wan_tor;
use crate::transport::{self, Connection};

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
        let _ = offer_hash; // retained for compatibility; can be removed in next cleanup patch
        Self {
            params,
            config,
            noise_role,
            offer,
            attempted: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    fn gather_peer_candidates(&self) -> Vec<IceCandidate> {
        // IMPORTANT: candidates are *peer* targets from the offer, not local IPs.
        let mut out = Vec::new();
        let mut seen = HashSet::<(IceCandidateKind, SocketAddr)>::new();

        for ep in &self.offer.endpoints {
            match (ep.kind.clone(), ep.addr) {
                (EndpointKind::Lan, Some(addr)) => {
                    if addr.ip().is_unspecified() || addr.port() == 0 {
                        continue;
                    }
                    if seen.insert((IceCandidateKind::Lan, addr)) {
                        out.push(IceCandidate {
                            kind: IceCandidateKind::Lan,
                            priority: 100 + ep.priority as u32,
                            addr: Some(addr),
                            timeout_ms: ep.timeout_ms.max(1500),
                            retry_count: 0,
                        });
                    }
                }
                (EndpointKind::Wan, Some(addr)) => {
                    if addr.ip().is_unspecified() || addr.port() == 0 {
                        continue;
                    }
                    // Treat offer WAN endpoint as a direct UDP target.
                    if seen.insert((IceCandidateKind::Stun, addr)) {
                        out.push(IceCandidate {
                            kind: IceCandidateKind::Stun,
                            priority: 90 + ep.priority as u32,
                            addr: Some(addr),
                            timeout_ms: ep.timeout_ms.max(self.config.wan_connect_timeout_ms),
                            retry_count: 0,
                        });
                    }
                }
                (EndpointKind::Tor, _) => {
                    // Tor has no SocketAddr target; handled by gather_tor_candidates().
                }
                _ => {}
            }
        }

        if let Some(addr) = self.offer.stun_public_addr {
            if !addr.ip().is_unspecified()
                && addr.port() != 0
                && seen.insert((IceCandidateKind::Stun, addr))
            {
                out.push(IceCandidate {
                    kind: IceCandidateKind::Stun,
                    priority: 70,
                    addr: Some(addr),
                    timeout_ms: self.config.wan_connect_timeout_ms.max(3000),
                    retry_count: 0,
                });
            }
        }

        out
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

    async fn connect_first_validated(
        &self,
        resume: Option<&ResumeParams>,
    ) -> Result<crate::transport::OfferConnectResult> {
        let mut candidates = self.gather_candidates().await?;
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));

        for c in &candidates {
            if matches!(c.kind, IceCandidateKind::Lan | IceCandidateKind::Stun) {
                if let Some(addr) = c.addr {
                    debug!(
                        "Testing {} candidate at {}",
                        format!("{:?}", c.kind).to_lowercase(),
                        addr
                    );
                }
            }
        }

        let mut udp_dispatch: Option<Arc<UdpSocket>> = None;

        // NOTE: We intentionally validate a candidate by completing the resume/noise handshake.
        // Parallel UDP attempts would contend on a single recv_from() socket, so we do priority-ordered attempts.
        let global_deadline = tokio::time::Instant::now() + Duration::from_secs(15);
        for candidate in candidates {
            if tokio::time::Instant::now() >= global_deadline {
                break;
            }

            if self.is_exhausted(&candidate.kind).await {
                continue;
            }
            self.mark_attempted(&candidate.kind).await;

            let attempt = match candidate.kind {
                IceCandidateKind::Lan => match candidate.addr {
                    Some(addr) => {
                        let dispatch =
                            bind_udp_dispatch(&mut udp_dispatch, self.params.port).await?;
                        self.attempt_udp_handshake(
                            addr,
                            dispatch,
                            EndpointKind::Lan,
                            candidate.timeout_ms,
                            resume,
                            "lan",
                        )
                        .await?
                    }
                    None => None,
                },
                IceCandidateKind::Stun | IceCandidateKind::Upnp => match candidate.addr {
                    Some(addr) => {
                        let dispatch =
                            bind_udp_dispatch(&mut udp_dispatch, self.params.port).await?;
                        self.attempt_udp_handshake(
                            addr,
                            dispatch,
                            EndpointKind::Wan,
                            candidate.timeout_ms.max(self.config.wan_connect_timeout_ms),
                            resume,
                            "wan",
                        )
                        .await?
                    }
                    None => None,
                },
                IceCandidateKind::Relay => self.attempt_relay_handshake(resume).await?,
                IceCandidateKind::Tor => self.attempt_tor_handshake(resume).await?,
            };

            if let Some(ok) = attempt {
                return Ok(ok);
            }

            self.schedule_retry(&candidate.kind).await;
        }

        Err(anyhow::anyhow!("All ICE candidates failed"))
    }

    async fn gather_candidates(&self) -> Result<Vec<IceCandidate>> {
        let mut candidates = self.gather_peer_candidates();
        candidates.extend(self.gather_relay_candidates().await?);
        candidates.extend(self.gather_tor_candidates().await?);
        candidates.sort_by(|a, b| b.priority.cmp(&a.priority));
        Ok(candidates)
    }

    async fn attempt_udp_handshake(
        &self,
        addr: SocketAddr,
        dispatch: Arc<UdpSocket>,
        kind: EndpointKind,
        timeout_ms: u64,
        resume: Option<&ResumeParams>,
        mode: &str,
    ) -> Result<Option<crate::transport::OfferConnectResult>> {
        let conn = match kind {
            EndpointKind::Lan => Connection::Lan(dispatch, addr),
            EndpointKind::Wan => Connection::Wan(dispatch, addr),
            EndpointKind::Tor => {
                return Ok(None);
            }
        };

        let timeout_ms = timeout_ms.max(2000).min(20_000);
        let tag8 = self.params.tag8;
        let key_enc = self.offer.rendezvous.key_enc;
        let tag16 = self.offer.rendezvous.tag16;
        let noise_role = self.noise_role;

        let handshake = async {
            if let Some(resume) = resume {
                crate::session_noise::run_resume_or_noise(
                    noise_role, &conn, &key_enc, tag16, tag8, resume,
                )
                .await
            } else {
                let sk = crate::session_noise::run_noise_upgrade(
                    noise_role, &conn, &key_enc, tag16, tag8,
                )
                .await?;
                Ok((sk, false))
            }
        };

        match tokio::time::timeout(Duration::from_millis(timeout_ms), handshake).await {
            Ok(Ok((session_key, resume_used))) => Ok(Some(crate::transport::OfferConnectResult {
                conn,
                session_key,
                mode: mode.to_string(),
                peer: Some(addr.to_string()),
                resume_used: Some(resume_used),
            })),
            Ok(Err(e)) => {
                warn!("UDP candidate {} handshake failed: {}", addr, e);
                Ok(None)
            }
            Err(_) => {
                warn!("UDP candidate {} handshake timeout", addr);
                Ok(None)
            }
        }
    }

    async fn attempt_relay_handshake(
        &self,
        resume: Option<&ResumeParams>,
    ) -> Result<Option<crate::transport::OfferConnectResult>> {
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
                    let tag8 = self.params.tag8;
                    let key_enc = self.offer.rendezvous.key_enc;
                    let tag16 = self.offer.rendezvous.tag16;
                    let noise_role = self.noise_role;

                    let handshake = async {
                        if let Some(resume) = resume {
                            crate::session_noise::run_resume_or_noise(
                                noise_role, &conn, &key_enc, tag16, tag8, resume,
                            )
                            .await
                        } else {
                            let sk = crate::session_noise::run_noise_upgrade(
                                noise_role, &conn, &key_enc, tag16, tag8,
                            )
                            .await?;
                            Ok((sk, false))
                        }
                    };

                    match tokio::time::timeout(Duration::from_secs(8), handshake).await {
                        Ok(Ok((session_key, resume_used))) => {
                            return Ok(Some(crate::transport::OfferConnectResult {
                                conn,
                                session_key,
                                mode: "relay".to_string(),
                                peer: Some(relay.to_string()),
                                resume_used: Some(resume_used),
                            }));
                        }
                        Ok(Err(e)) => warn!("Relay handshake failed via {}: {}", relay, e),
                        Err(_) => warn!("Relay handshake timeout via {}", relay),
                    }
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

    async fn attempt_tor_handshake(
        &self,
        resume: Option<&ResumeParams>,
    ) -> Result<Option<crate::transport::OfferConnectResult>> {
        if let Some(onion) = self.offer.tor_onion_addr()? {
            match wan_tor::try_tor_connect(&self.config.tor_socks_addr, &onion, None, None).await {
                Ok(stream) => {
                    let (reader, writer) = stream.into_split();
                    let conn = Connection::WanTorStream {
                        reader: Arc::new(Mutex::new(reader)),
                        writer: Arc::new(Mutex::new(writer)),
                    };

                    let tag8 = self.params.tag8;
                    let key_enc = self.offer.rendezvous.key_enc;
                    let tag16 = self.offer.rendezvous.tag16;
                    let noise_role = self.noise_role;

                    let handshake = async {
                        if let Some(resume) = resume {
                            crate::session_noise::run_resume_or_noise(
                                noise_role, &conn, &key_enc, tag16, tag8, resume,
                            )
                            .await
                        } else {
                            let sk = crate::session_noise::run_noise_upgrade(
                                noise_role, &conn, &key_enc, tag16, tag8,
                            )
                            .await?;
                            Ok((sk, false))
                        }
                    };

                    match tokio::time::timeout(Duration::from_secs(12), handshake).await {
                        Ok(Ok((session_key, resume_used))) => {
                            return Ok(Some(crate::transport::OfferConnectResult {
                                conn,
                                session_key,
                                mode: "wan_tor".to_string(),
                                peer: Some(onion),
                                resume_used: Some(resume_used),
                            }));
                        }
                        Ok(Err(e)) => warn!("Tor handshake failed: {}", e),
                        Err(_) => warn!("Tor handshake timeout"),
                    }
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
}

async fn bind_udp_dispatch(slot: &mut Option<Arc<UdpSocket>>, port: u16) -> Result<Arc<UdpSocket>> {
    if let Some(sock) = slot.as_ref() {
        return Ok(sock.clone());
    }
    let sock = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], port)))
        .await
        .context("bind UDP socket for ICE")?;
    let sock = Arc::new(sock);
    *slot = Some(sock.clone());
    Ok(sock)
}

pub async fn multipath_race_connect(
    offer: &OfferPayload,
    offer_hash: [u8; 32],
    params: RendezvousParams,
    config: Config,
    noise_role: NoiseRole,
) -> Result<(Connection, SocketAddr)> {
    let res =
        multipath_race_connect_with_resume(offer, offer_hash, params, config, noise_role, None)
            .await?;

    let peer_addr = res
        .conn
        .peer_addr()
        .or_else(|| res.peer.as_ref().and_then(|s| s.parse().ok()))
        .unwrap_or_else(|| SocketAddr::from(([0, 0, 0, 0], 0)));

    Ok((res.conn, peer_addr))
}

pub async fn multipath_race_connect_with_resume(
    offer: &OfferPayload,
    offer_hash: [u8; 32],
    params: RendezvousParams,
    config: Config,
    noise_role: NoiseRole,
    resume: Option<ResumeParams>,
) -> Result<crate::transport::OfferConnectResult> {
    let agent = IceAgent::new(params, config, noise_role, offer.clone(), offer_hash);
    agent.connect_first_validated(resume.as_ref()).await
}
