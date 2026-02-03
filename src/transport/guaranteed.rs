//! Guaranteed transport (A): relay-backed, deterministic connectivity.

use std::sync::Arc;

use anyhow::{Context, Result};
use base64::{engine::general_purpose, Engine as _};
use reqwest::Url;

use crate::config::{Config, GuaranteedEgress};
use crate::derive::RendezvousParams;
use crate::transport::io::TransportIo;

#[derive(Clone)]
struct RelayIo {
    client: reqwest::Client,
    relay_url: Url,
    topics: Vec<String>,
    wait_ms: u64,
}

impl RelayIo {
    fn new(
        client: reqwest::Client,
        relay_url: Url,
        topics: Vec<String>,
        wait_ms: u64,
    ) -> Self {
        Self {
            client,
            relay_url,
            topics,
            wait_ms,
        }
    }
}

impl TransportIo for RelayIo {
    fn max_packet_limit(&self) -> u64 {
        crate::crypto::MAX_TCP_FRAME_BYTES
    }

    fn rate_limit_addr(&self) -> std::net::SocketAddr {
        let topic = self.topics.first().cloned().unwrap_or_default();
        let hash = blake3::hash(topic.as_bytes());
        let bytes = hash.as_bytes();
        // TODO: replace SocketAddr hack with a topic-hash limiter.
        let ip = std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
        std::net::SocketAddr::new(std::net::IpAddr::V4(ip), 0)
    }

    fn send<'a>(
        &'a self,
        data: Vec<u8>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>> {
        let client = self.client.clone();
        let relay_url = self.relay_url.clone();
        let topics = self.topics.clone();
        Box::pin(async move {
            let mut sent = false;
            for topic in topics {
                if topic.is_empty() {
                    continue;
                }
                let url = relay_url.join("v1/relay/send")?;
                let payload = RelaySend {
                    topic,
                    data_b64: general_purpose::STANDARD.encode(&data),
                };
                let res = client.post(url).json(&payload).send().await?;
                if !res.status().is_success() {
                    anyhow::bail!("relay send failed: {}", res.status());
                }
                sent = true;
            }
            if !sent {
                anyhow::bail!("relay topic missing");
            }
            Ok(())
        })
    }

    fn recv<'a>(
        &'a self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        let client = self.client.clone();
        let relay_url = self.relay_url.clone();
        let topics = self.topics.clone();
        let wait_ms = self.wait_ms;
        Box::pin(async move {
            for topic in topics {
                if topic.is_empty() {
                    continue;
                }
                let mut url = relay_url.join("v1/relay/recv")?;
                {
                    let mut pairs = url.query_pairs_mut();
                    pairs.append_pair("topic", &topic);
                    pairs.append_pair("wait_ms", &wait_ms.to_string());
                }
                let res = client.get(url).send().await?;
                if res.status().as_u16() == 204 {
                    continue;
                }
                if !res.status().is_success() {
                    anyhow::bail!("relay recv failed: {}", res.status());
                }
                let msg: RelayRecv = res.json().await?;
                let data = general_purpose::STANDARD.decode(&msg.data_b64)?;
                return Ok(data);
            }
            Ok(Vec::new())
        })
    }
}

#[derive(serde::Serialize)]
struct RelaySend {
    topic: String,
    data_b64: String,
}

#[derive(serde::Deserialize)]
struct RelayRecv {
    data_b64: String,
}

fn derive_relay_topics(
    key_enc: &[u8; 32],
    tag16: u16,
    window_ms: u64,
) -> Vec<String> {
    let window_ms = window_ms.max(60_000);
    let now_ms = crate::crypto::now_ms();
    let epoch = if window_ms == 0 { 0 } else { now_ms / window_ms };
    let mut topics = Vec::with_capacity(2);
    for e in [epoch, epoch.saturating_sub(1)] {
        let mut hasher = blake3::Hasher::new();
        hasher.update(b"hs/relay/topic/v2");
        hasher.update(b"guaranteed");
        hasher.update(&tag16.to_be_bytes());
        hasher.update(key_enc);
        hasher.update(&e.to_be_bytes());
        topics.push(hasher.finalize().to_hex().to_string());
    }
    topics
}

fn build_relay_client(cfg: &Config, egress: GuaranteedEgress) -> Result<reqwest::Client> {
    let mut builder = reqwest::Client::builder();
    if egress == GuaranteedEgress::Tor {
        let proxy = reqwest::Proxy::all(format!("socks5h://{}", cfg.tor_socks_addr))
            .context("invalid Tor SOCKS proxy")?;
        builder = builder.proxy(proxy);
    }
    Ok(builder.build()?)
}

/// Establish a Guaranteed (A) connection using relay-backed IO.
pub async fn establish_connection_guaranteed(
    params: &RendezvousParams,
    cfg: &Config,
    egress: GuaranteedEgress,
) -> Result<Arc<dyn TransportIo>> {
    if cfg.guaranteed_relay_url.is_empty() {
        anyhow::bail!("Guaranteed mode requires HANDSHACKE_GUARANTEED_RELAY_URL");
    }
    let relay_url = Url::parse(&cfg.guaranteed_relay_url)
        .context("Invalid HANDSHACKE_GUARANTEED_RELAY_URL")?;
    let client = build_relay_client(cfg, egress)?;
    let topics = derive_relay_topics(
        &params.key_enc,
        params.tag16,
        cfg.guaranteed_topic_window_ms,
    );
    Ok(Arc::new(RelayIo::new(
        client,
        relay_url,
        topics,
        cfg.guaranteed_relay_wait_ms,
    )))
}
