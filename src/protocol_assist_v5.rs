// ==============================
// protocol_assist_v5_patched.rs
// ==============================
// Handshacke - WAN Assist V5 (IP-blinded relay) - Versione patchata
//

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::protocol_assist::PunchProfile;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20::ChaCha20;
use hkdf::Hkdf;
use rand::Rng;
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// Fixed number of candidates on-wire (shape protection)
pub const ASSIST_V5_CANDIDATES: usize = 8;

/// 24-byte fixed layout (before obfuscation)
#[derive(Debug, Copy, Clone, Serialize, Deserialize, Zeroize, Default)]
pub struct BlindedCandidate(pub [u8; 24]);

#[derive(Serialize, Deserialize, Debug, Clone, Zeroize, ZeroizeOnDrop)]
pub struct AssistRequestV5 {
    pub request_id: [u8; 8],
    pub blinded_candidates: [BlindedCandidate; ASSIST_V5_CANDIDATES], // always 8
    pub ttl_ms: u16,

    // 🌻 Dandelion: se true, relay aggrega e ritarda per anti-correlation
    pub dandelion_stem: bool,

    // 🌻 Dandelion: tag per raggruppare batch (None = relay genera)
    pub dandelion_tag: Option<[u8; 8]>,

    pub mac: [u8; 32],
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct AssistGoV5 {
    pub request_id: [u8; 8],
    pub peer_candidates: [BlindedCandidate; ASSIST_V5_CANDIDATES],
    pub go_after_ms: u16,
    pub burst_duration_ms: u16,
    pub punch_profile: PunchProfile,
    pub ttl_ms: u16,
    pub mac: [u8; 32],
}

// ================ PATCH 1: NONCE MIGLIORATO ================

/// Nonce deterministco ma imprevedibile per il relay
pub fn derive_entry_nonce_v5_improved(
    request_id: &[u8; 8],
    idx: usize,
    obf_key: &[u8; 32],
) -> [u8; 12] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(obf_key).expect("HMAC init failed");
    mac.update(b"assist/nonce/v5");
    mac.update(request_id);
    mac.update(&(idx as u32).to_le_bytes());

    let full = mac.finalize().into_bytes(); // 32B
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&full[..12]);
    nonce
}

// ================ PATCH 2 & 3: PACK/UNPACK CON PADDING KEYED ================

/// Pack SocketAddr into 24 bytes con padding dipendente da key e nonce
fn pack_addr24(addr: &SocketAddr, obf_key: &[u8; 32], nonce12: &[u8; 12]) -> [u8; 24] {
    let mut out = [0u8; 24];

    match addr.ip() {
        IpAddr::V4(v4) => {
            out[0] = 4;
            out[1..11].fill(0);
            out[11] = 0xff;
            out[12] = 0xff;
            out[13..17].copy_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out[0] = 6;
            out[1..17].copy_from_slice(&v6.octets());
        }
    }

    out[17..19].copy_from_slice(&addr.port().to_be_bytes());

    // Keyed padding (deterministic ma dipendente da nonce)
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(obf_key).expect("HMAC init failed");
    mac.update(b"assist/pad/v5");
    mac.update(nonce12);
    mac.update(&out[..19]);
    let pad = mac.finalize().into_bytes(); // 32B
    out[19..24].copy_from_slice(&pad[..5]);

    out
}

/// Unpack 24 bytes into SocketAddr (versione originale)
fn unpack_addr24(buf: &[u8; 24]) -> Option<SocketAddr> {
    let ip = match buf[0] {
        4 => {
            let v4 = Ipv4Addr::new(buf[13], buf[14], buf[15], buf[16]);
            IpAddr::V4(v4)
        }
        6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&buf[1..17]);
            IpAddr::V6(Ipv6Addr::from(o))
        }
        _ => return None,
    };

    let port = u16::from_be_bytes([buf[17], buf[18]]);
    Some(SocketAddr::new(ip, port))
}

impl BlindedCandidate {
    pub fn blind(addr: &SocketAddr, obf_key: &[u8; 32], nonce12: &[u8; 12]) -> Self {
        let mut buf = pack_addr24(addr, obf_key, nonce12);
        let mut cipher = ChaCha20::new(obf_key.into(), nonce12.into());
        cipher.apply_keystream(&mut buf);
        Self(buf)
    }

    pub fn unblind(&self, obf_key: &[u8; 32], nonce12: &[u8; 12]) -> Option<SocketAddr> {
        let mut buf = self.0;
        let mut cipher = ChaCha20::new(obf_key.into(), nonce12.into());
        cipher.apply_keystream(&mut buf);
        unpack_addr24(&buf)
    }
}

// ================ PATCH 4: VALIDAZIONE POLICY-BASED ================

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CandidatePolicy {
    /// Accept private + public (but still reject loopback/unspecified/etc.)
    Any,
    /// Reject RFC1918/ULA/documentation/linklocal
    StrictWan,
}

pub fn is_usable_candidate(addr: &SocketAddr, policy: CandidatePolicy) -> bool {
    if addr.port() == 0 {
        return false;
    }

    let ip = addr.ip();
    if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
        return false;
    }

    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();

            // link-local 169.254/16
            if o[0] == 169 && o[1] == 254 {
                return false;
            }

            // doc ranges RFC5737
            let is_doc = (o[0] == 192 && o[1] == 0 && o[2] == 2)
                || (o[0] == 198 && o[1] == 51 && o[2] == 100)
                || (o[0] == 203 && o[1] == 0 && o[2] == 113);
            if is_doc {
                return false;
            }

            // reserved 240/4
            if o[0] >= 240 {
                return false;
            }

            if let CandidatePolicy::StrictWan = policy {
                // RFC1918 private ranges rejected only in StrictWan
                let is_rfc1918 = o[0] == 10
                    || (o[0] == 172 && (16..=31).contains(&o[1]))
                    || (o[0] == 192 && o[1] == 168);
                if is_rfc1918 {
                    return false;
                }
            }
        }
        IpAddr::V6(v6) => {
            let s = v6.segments();

            // link-local fe80::/10
            if (s[0] & 0xffc0) == 0xfe80 {
                return false;
            }

            // documentation 2001:db8::/32
            if s[0] == 0x2001 && s[1] == 0x0db8 {
                return false;
            }

            // multicast ff00::/8
            if (s[0] & 0xff00) == 0xff00 {
                return false;
            }

            if let CandidatePolicy::StrictWan = policy {
                // ULA fc00::/7 rejected only in StrictWan
                if (s[0] & 0xfe00) == 0xfc00 {
                    return false;
                }
            }
        }
    }

    true
}

// ================ FUNZIONI AUSILIARIE ================

/// Domain separated obfuscation key for v5 assist.
pub fn derive_obfuscation_key_v5(key_enc: &[u8; 32], tag16: u16) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(b"hs/assist/ip-blind/v5"), key_enc);
    let mut out = [0u8; 32];
    let mut info = Vec::with_capacity(3 + 2);
    info.extend_from_slice(b"obf");
    info.extend_from_slice(&tag16.to_be_bytes());
    hk.expand(&info, &mut out).expect("HKDF expand failed");
    out
}

/// Nonce originale per compatibilità (non usato nella versione migliorata)
pub fn derive_entry_nonce_v5(request_id: &[u8; 8], idx: usize) -> [u8; 12] {
    let hk = Hkdf::<Sha256>::new(None, request_id);
    let mut nonce = [0u8; 12];
    let mut info = Vec::with_capacity(14);
    info.extend_from_slice(b"assist/nonce/v5");
    info.extend_from_slice(&(idx as u32).to_le_bytes());
    hk.expand(&info, &mut nonce).expect("HKDF expand failed");
    nonce
}

// ================ GENERAZIONE DUMMY ================

/// Improved dummy generation that's cryptographically indistinguishable from real
pub fn generate_dummy_candidate(idx: usize) -> SocketAddr {
    let mut rng = rand::thread_rng();

    // Use different RFC ranges for variety but ensure they fail validation
    match idx % 4 {
        0 => {
            // RFC 5737: 192.0.2.0/24 (TEST-NET-1)
            let ip = Ipv4Addr::new(192, 0, 2, rng.gen_range(1..=254));
            SocketAddr::new(IpAddr::V4(ip), 0) // port 0 = invalid
        }
        1 => {
            // RFC 5737: 198.51.100.0/24 (TEST-NET-2)
            let ip = Ipv4Addr::new(198, 51, 100, rng.gen_range(1..=254));
            SocketAddr::new(IpAddr::V4(ip), 0)
        }
        2 => {
            // RFC 5737: 203.0.113.0/24 (TEST-NET-3)
            let ip = Ipv4Addr::new(203, 0, 113, rng.gen_range(1..=254));
            SocketAddr::new(IpAddr::V4(ip), 0)
        }
        _ => {
            // IPv6 dummy: 2001:db8::/32 (Documentation)
            let segments = [
                0x2001,
                0x0db8,
                rng.gen_range(0..=0xFFFF),
                rng.gen_range(0..=0xFFFF),
                rng.gen_range(0..=0xFFFF),
                rng.gen_range(0..=0xFFFF),
                rng.gen_range(0..=0xFFFF),
                rng.gen_range(0..=0xFFFF),
            ];
            let ip = Ipv6Addr::from(segments);
            SocketAddr::new(IpAddr::V6(ip), 0)
        }
    }
}

// ================ SHUFFLED CANDIDATES (PATCH 5) ================

/// Build blinded candidates with shuffled order to hide real count
pub fn make_blinded_candidates_v5_shuffled(
    real_addrs: &[SocketAddr],
    obf_key: &[u8; 32],
    request_id: &[u8; 8],
) -> [BlindedCandidate; ASSIST_V5_CANDIDATES] {
    let mut out = [BlindedCandidate::default(); ASSIST_V5_CANDIDATES];
    let mut positions: Vec<usize> = (0..ASSIST_V5_CANDIDATES).collect();

    // Shuffle positions
    let mut rng = rand::thread_rng();
    for i in (1..ASSIST_V5_CANDIDATES).rev() {
        let j = rng.gen_range(0..=i);
        positions.swap(i, j);
    }

    // Place real candidates at random positions
    let take_n = real_addrs.len().min(ASSIST_V5_CANDIDATES);
    for i in 0..take_n {
        let pos = positions[i];
        let nonce = derive_entry_nonce_v5_improved(request_id, pos, obf_key);
        out[pos] = BlindedCandidate::blind(&real_addrs[i], obf_key, &nonce);
    }

    // Fill remaining positions with dummies
    for &pos in positions.iter().skip(take_n) {
        let dummy = generate_dummy_candidate(pos);
        let nonce = derive_entry_nonce_v5_improved(request_id, pos, obf_key);
        out[pos] = BlindedCandidate::blind(&dummy, obf_key, &nonce);
    }

    out
}

// ================ ANTI-CLUSTERING ================

/// Prevent real candidates from being clustered together
pub fn make_blinded_candidates_v5_anti_cluster(
    real_addrs: &[SocketAddr],
    obf_key: &[u8; 32],
    request_id: &[u8; 8],
) -> [BlindedCandidate; ASSIST_V5_CANDIDATES] {
    let mut out = [BlindedCandidate::default(); ASSIST_V5_CANDIDATES];
    let real_count = real_addrs.len().min(ASSIST_V5_CANDIDATES);

    // Spread real candidates evenly
    let step = if real_count > 0 {
        ASSIST_V5_CANDIDATES / real_count
    } else {
        ASSIST_V5_CANDIDATES
    };

    for (i, addr) in real_addrs.iter().take(real_count).enumerate() {
        let pos = (i * step) % ASSIST_V5_CANDIDATES;
        let nonce = derive_entry_nonce_v5_improved(request_id, pos, obf_key);
        out[pos] = BlindedCandidate::blind(addr, obf_key, &nonce);
    }

    // Fill gaps with dummies
    for (i, slot) in out.iter_mut().enumerate().take(ASSIST_V5_CANDIDATES) {
        if slot.0 == [0u8; 24] {
            let dummy = generate_dummy_candidate(i);
            let nonce = derive_entry_nonce_v5_improved(request_id, i, obf_key);
            *slot = BlindedCandidate::blind(&dummy, obf_key, &nonce);
        }
    }

    out
}

// ================ MAC FUNCTIONS ================

/// Compute HMAC over V5 request
pub fn compute_assist_mac_v5(key_enc: &[u8; 32], req: &AssistRequestV5) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key_enc).expect("HMAC init failed");
    mac.update(b"assist-mac-v5");
    mac.update(&req.request_id);
    for c in &req.blinded_candidates {
        mac.update(&c.0);
    }
    mac.update(&req.ttl_ms.to_le_bytes());
    mac.update(&[req.dandelion_stem as u8]);
    if let Some(tag) = &req.dandelion_tag {
        mac.update(tag);
    } else {
        mac.update(&[0u8; 8]);
    }
    mac.finalize().into_bytes().into()
}

pub fn verify_assist_mac_v5(key_enc: &[u8; 32], req: &AssistRequestV5) -> bool {
    let want = compute_assist_mac_v5(key_enc, req);
    bool::from(want.ct_eq(&req.mac))
}

pub fn compute_assist_go_mac_v5(key_enc: &[u8; 32], go: &AssistGoV5) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key_enc).expect("HMAC init failed");
    mac.update(b"assist-go-mac-v5");
    mac.update(&go.request_id);
    for c in &go.peer_candidates {
        mac.update(&c.0);
    }
    mac.update(&go.go_after_ms.to_le_bytes());
    mac.update(&go.burst_duration_ms.to_le_bytes());
    mac.update(&bincode::serialize(&go.punch_profile).expect("punch_profile serialize"));
    mac.update(&go.ttl_ms.to_le_bytes());
    mac.finalize().into_bytes().into()
}

pub fn verify_assist_go_mac_v5(key_enc: &[u8; 32], go: &AssistGoV5) -> bool {
    let want = compute_assist_go_mac_v5(key_enc, go);
    bool::from(want.ct_eq(&go.mac))
}

// ================ RATE LIMITING ================

// NOTE: Simple rate limiter removed. Use crate::security::rate_limiting::TokenBucketLimiter for production.

// ================ TESTS ================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_nonce_improved() {
        let obf_key = [42u8; 32];
        let request_id = [1u8; 8];

        let nonce1 = derive_entry_nonce_v5_improved(&request_id, 0, &obf_key);
        let nonce2 = derive_entry_nonce_v5_improved(&request_id, 1, &obf_key);
        let nonce3 = derive_entry_nonce_v5_improved(&request_id, 0, &obf_key); // stesso idx

        assert_ne!(nonce1, nonce2, "Nonce diversi per idx diversi");
        assert_eq!(nonce1, nonce3, "Nonce uguali per stessi parametri");

        // Cambia key → nonce diverso
        let obf_key2 = [43u8; 32];
        let nonce4 = derive_entry_nonce_v5_improved(&request_id, 0, &obf_key2);
        assert_ne!(nonce1, nonce4, "Nonce diverso per key diversa");
    }

    #[test]
    fn test_padding_keyed() {
        let addr: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let obf_key = [1u8; 32];
        let nonce = [2u8; 12];

        let packed1 = pack_addr24(&addr, &obf_key, &nonce);
        let packed2 = pack_addr24(&addr, &obf_key, &nonce);
        assert_eq!(packed1, packed2, "Stesso output per stessi input");

        // Cambia nonce → padding diverso
        let nonce2 = [3u8; 12];
        let packed3 = pack_addr24(&addr, &obf_key, &nonce2);
        assert_ne!(
            &packed1[19..],
            &packed3[19..],
            "Padding diverso per nonce diverso"
        );

        // Cambia key → padding diverso
        let obf_key2 = [4u8; 32];
        let packed4 = pack_addr24(&addr, &obf_key2, &nonce);
        assert_ne!(
            &packed1[19..],
            &packed4[19..],
            "Padding diverso per key diversa"
        );
    }

    #[test]
    fn test_policy_based_validation() {
        let public: SocketAddr = "8.8.8.8:53".parse().unwrap();
        let private: SocketAddr = "192.168.1.1:80".parse().unwrap();
        let link_local: SocketAddr = "169.254.1.1:80".parse().unwrap();
        let doc: SocketAddr = "192.0.2.1:80".parse().unwrap();

        // Policy::Any accetta privati ma rifiuta link-local e doc
        assert!(is_usable_candidate(&public, CandidatePolicy::Any));
        assert!(is_usable_candidate(&private, CandidatePolicy::Any));
        assert!(!is_usable_candidate(&link_local, CandidatePolicy::Any));
        assert!(!is_usable_candidate(&doc, CandidatePolicy::Any));

        // Policy::StrictWan rifiuta tutto tranne public
        assert!(is_usable_candidate(&public, CandidatePolicy::StrictWan));
        assert!(!is_usable_candidate(&private, CandidatePolicy::StrictWan));
        assert!(!is_usable_candidate(
            &link_local,
            CandidatePolicy::StrictWan
        ));
        assert!(!is_usable_candidate(&doc, CandidatePolicy::StrictWan));
    }

    #[test]
    fn test_blind_unblind_roundtrip() {
        let key_enc = [42u8; 32];
        let tag16 = 0x1234;
        let obf_key = derive_obfuscation_key_v5(&key_enc, tag16);
        let request_id = [7u8; 8];

        let addr: SocketAddr = "[2001:4860:4860::8888]:53".parse().unwrap();
        let idx = 3;
        let nonce = derive_entry_nonce_v5_improved(&request_id, idx, &obf_key);

        let blinded = BlindedCandidate::blind(&addr, &obf_key, &nonce);
        let unblinded = blinded.unblind(&obf_key, &nonce).unwrap();

        assert_eq!(addr, unblinded);
    }

    #[test]
    fn test_shuffled_candidates() {
        let key_enc = [1u8; 32];
        let obf_key = derive_obfuscation_key_v5(&key_enc, 0x9999);
        let request_id = [2u8; 8];

        let addrs: Vec<SocketAddr> =
            vec!["8.8.8.8:53".parse().unwrap(), "1.1.1.1:53".parse().unwrap()];

        let candidates = make_blinded_candidates_v5_shuffled(&addrs, &obf_key, &request_id);

        // Verifica che abbiamo esattamente 8 candidati
        assert_eq!(candidates.len(), ASSIST_V5_CANDIDATES);

        // Verifica che tutti i candidati siano non-zero (properly blinded)
        for cand in &candidates {
            assert_ne!(cand.0, [0u8; 24]);
        }

        // Verifica che possiamo unblind e validare
        let mut found_real = 0;
        for (idx, cand) in candidates.iter().enumerate() {
            let nonce = derive_entry_nonce_v5_improved(&request_id, idx, &obf_key);
            if let Some(addr) = cand.unblind(&obf_key, &nonce) {
                if is_usable_candidate(&addr, CandidatePolicy::StrictWan) {
                    found_real += 1;
                }
            }
        }
        assert_eq!(found_real, 2, "Dovremmo trovare 2 indirizzi reali");
    }

    #[test]
    fn test_mac_verify_v5() {
        let key_enc = [9u8; 32];
        let request_id = [3u8; 8];
        let obf_key = derive_obfuscation_key_v5(&key_enc, 0x7777);
        let addrs: Vec<SocketAddr> = vec!["8.8.8.8:53".parse().unwrap()];
        let blinded = make_blinded_candidates_v5_shuffled(&addrs, &obf_key, &request_id);
        let mut req = AssistRequestV5 {
            request_id,
            blinded_candidates: blinded,
            ttl_ms: 1000,
            dandelion_stem: false,
            dandelion_tag: Some([42u8; 8]),
            mac: [0u8; 32],
        };
        req.mac = compute_assist_mac_v5(&key_enc, &req);
        assert!(verify_assist_mac_v5(&key_enc, &req));

        let go = AssistGoV5 {
            request_id,
            peer_candidates: blinded,
            go_after_ms: 10,
            burst_duration_ms: 250,
            punch_profile: PunchProfile {
                pps: 10,
                jitter_ms: 5,
                probe_size: 16,
            },
            ttl_ms: 1000,
            mac: [0u8; 32],
        };
        let mut go2 = go.clone();
        go2.mac = compute_assist_go_mac_v5(&key_enc, &go2);
        assert!(verify_assist_go_mac_v5(&key_enc, &go2));
    }
}
