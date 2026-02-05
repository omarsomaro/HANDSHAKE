use crate::crypto::now_ms;
use crate::offer::{Endpoint, EndpointKind, OfferPayload};
use anyhow::{bail, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use bincode::Options;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

pub const HYBRID_QR_VERSION: u8 = 1;
pub const DEFAULT_RESUME_TTL_MS: u64 = 15 * 60 * 1000;
pub const DEFAULT_QR_TTL_MS: u64 = 60 * 60 * 1000;

pub const CAP_TOR: u32 = 1 << 0;
pub const CAP_UDP: u32 = 1 << 1;
pub const CAP_QUIC: u32 = 1 << 2;
pub const CAP_WEBRTC: u32 = 1 << 3;

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct ResumeParams {
    pub token_id: u64,
    pub resume_secret: [u8; 32],
    pub resume_expires_at_ms: u64,
}

impl ResumeParams {
    pub fn new(ttl_ms: u64) -> Self {
        let mut secret = [0u8; 32];
        let mut token_buf = [0u8; 8];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        rand::rngs::OsRng.fill_bytes(&mut token_buf);
        let token_id = u64::from_be_bytes(token_buf);
        let expires_at = now_ms().saturating_add(ttl_ms.max(1000));
        Self {
            token_id,
            resume_secret: secret,
            resume_expires_at_ms: expires_at,
        }
    }

    pub fn is_expired(&self) -> bool {
        now_ms() > self.resume_expires_at_ms
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Zeroize, ZeroizeOnDrop)]
pub struct HybridQrPayload {
    pub ver: u8,
    pub created_at_ms: u64,
    pub expires_at_ms: u64,
    pub offer: String,
    pub resume_token_id: u64,
    pub resume_secret: [u8; 32],
    pub resume_expires_at_ms: u64,
    pub caps: u32,
    pub relay_hints: Vec<String>,
    pub checksum: [u8; 32],
}

impl HybridQrPayload {
    pub fn new(
        offer: String,
        offer_expires_at_ms: u64,
        resume: ResumeParams,
        caps: u32,
        relay_hints: Vec<String>,
    ) -> Self {
        let created_at_ms = now_ms();
        let expires_at_ms = offer_expires_at_ms.min(resume.resume_expires_at_ms);
        let mut payload = Self {
            ver: HYBRID_QR_VERSION,
            created_at_ms,
            expires_at_ms,
            offer,
            resume_token_id: resume.token_id,
            resume_secret: resume.resume_secret,
            resume_expires_at_ms: resume.resume_expires_at_ms,
            caps,
            relay_hints,
            checksum: [0u8; 32],
        };
        if let Ok(checksum) = payload.compute_checksum() {
            payload.checksum = checksum;
        }
        payload
    }

    pub fn encode(&self) -> Result<String> {
        let bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .with_limit(crate::crypto::MAX_TCP_FRAME_BYTES)
            .serialize(self)?;
        Ok(general_purpose::URL_SAFE_NO_PAD.encode(&bytes))
    }

    pub fn decode(s: &str) -> Result<Self> {
        let bytes = general_purpose::URL_SAFE_NO_PAD
            .decode(s)
            .context("Hybrid QR base64 decode failed")?;
        let payload: Self = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .with_limit(crate::crypto::MAX_TCP_FRAME_BYTES)
            .deserialize(&bytes)
            .context("Hybrid QR deserialize failed")?;
        payload.verify()?;
        Ok(payload)
    }

    pub fn verify(&self) -> Result<()> {
        if self.ver != HYBRID_QR_VERSION {
            bail!("Hybrid QR version mismatch: {}", self.ver);
        }
        let expected = self.compute_checksum()?;
        if self.checksum != expected {
            bail!("Hybrid QR checksum invalid");
        }
        if now_ms() > self.expires_at_ms {
            bail!("Hybrid QR expired");
        }
        Ok(())
    }

    fn compute_checksum(&self) -> Result<[u8; 32]> {
        let mut tmp = self.clone();
        tmp.checksum = [0u8; 32];
        let bytes = bincode::DefaultOptions::new()
            .with_fixint_encoding()
            .with_little_endian()
            .with_limit(crate::crypto::MAX_TCP_FRAME_BYTES)
            .serialize(&tmp)?;
        let mut ctx = blake3::Hasher::new();
        ctx.update(b"handshacke-qr-v1\0");
        ctx.update(&bytes);
        let hash = ctx.finalize();
        Ok(*hash.as_bytes())
    }

    pub fn resume_params(&self) -> ResumeParams {
        ResumeParams {
            token_id: self.resume_token_id,
            resume_secret: self.resume_secret,
            resume_expires_at_ms: self.resume_expires_at_ms,
        }
    }
}

pub fn caps_from_offer(offer: &OfferPayload) -> u32 {
    let mut caps = 0u32;
    if offer
        .endpoints
        .iter()
        .any(|e| matches!(e.kind, EndpointKind::Tor))
    {
        caps |= CAP_TOR;
    }
    if offer
        .endpoints
        .iter()
        .any(|e| matches!(e.kind, EndpointKind::Lan | EndpointKind::Wan))
    {
        caps |= CAP_UDP;
    }
    // QUIC/WebRTC are not encoded in offer endpoints (yet).
    caps
}

pub fn caps_from_endpoints(endpoints: &[Endpoint]) -> u32 {
    let mut caps = 0u32;
    if endpoints
        .iter()
        .any(|e| matches!(e.kind, EndpointKind::Tor))
    {
        caps |= CAP_TOR;
    }
    if endpoints
        .iter()
        .any(|e| matches!(e.kind, EndpointKind::Lan | EndpointKind::Wan))
    {
        caps |= CAP_UDP;
    }
    caps
}
