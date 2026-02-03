//! Control protocol per WAN Assist (hole punching coordinato)
//! Zero-infrastructure, ephemeral, zero-trust

use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// A → C: chiedi assistenza per hole punching verso B
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssistRequest {
    pub request_id: [u8; 8],                // nonce per correlazione
    pub target_ref: TargetRef,              // come C raggiunge B
    pub my_udp_candidates: Vec<SocketAddr>, // endpoint che A crede di avere
    pub ttl_ms: u16,                        // timeout richiesta
    pub mac: [u8; 32],                      // HMAC per autenticazione
}

/// Come identificare B (routabile, non solo tag16)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub enum TargetRef {
    /// B ha onion temporaneo per assist (offerto nell'offer)
    TargetOnion(String),
    /// C ha già sessione attiva con B
    RelaySession([u8; 16]),
    /// Solo debug: C conosce già B per quel tag16
    Tag16Only(u16),
}

/// C → A: istruzioni per coordinare il punch
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssistGo {
    pub request_id: [u8; 8],
    pub peer_udp_candidates: Vec<SocketAddr>, // endpoint che B ha dichiarato
    pub go_after_ms: u16,                     // relativo (0..65535)
    pub burst_duration_ms: u16,               // quanto tenere burst attivo
    pub punch_profile: PunchProfile,
}

/// Profilo di punch (robusto ma non aggressivo)
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct PunchProfile {
    pub pps: u16,        // packets per second (es. 30)
    pub jitter_ms: u16,  // ±jitter per pacchetto (es. 50)
    pub probe_size: u16, // bytes per probe (es. 64)
}

/// Calcola HMAC su AssistRequest (deterministico, no bincode)
pub fn compute_assist_mac(key_enc: &[u8; 32], request: &AssistRequest) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    use std::net::IpAddr;
    type HmacSha256 = Hmac<Sha256>;
    const MAX_UDP_CANDIDATES: usize = 10;

    let mut mac = HmacSha256::new_from_slice(key_enc).expect("HMAC init failed");
    mac.update(b"assist-mac-v1");
    mac.update(&request.request_id);

    // Serializza target_ref manualmente
    match &request.target_ref {
        TargetRef::TargetOnion(onion) => {
            mac.update(b"onion");
            mac.update(onion.as_bytes());
        }
        TargetRef::RelaySession(id) => {
            mac.update(b"session");
            mac.update(id);
        }
        TargetRef::Tag16Only(tag) => {
            mac.update(b"tag");
            mac.update(&tag.to_be_bytes());
        }
    }

    // Serializza candidati: ip:port,deterministico
    for addr in request.my_udp_candidates.iter().take(MAX_UDP_CANDIDATES) {
        match addr.ip() {
            IpAddr::V4(ip) => {
                mac.update(b"v4");
                mac.update(&ip.octets());
            }
            IpAddr::V6(ip) => {
                mac.update(b"v6");
                mac.update(&ip.octets());
            }
        }
        mac.update(&addr.port().to_be_bytes());
    }

    mac.update(&request.ttl_ms.to_le_bytes());
    mac.finalize().into_bytes().into()
}
