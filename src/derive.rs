use hkdf::Hkdf;
use sha2::{Sha256, Digest};
use zeroize::Zeroize;
use argon2::{Argon2, password_hash::{PasswordHasher, Salt}};
use base64::{engine::general_purpose, Engine as _};
use unicode_normalization::UnicodeNormalization;
use crate::config::{MIN_EPHEMERAL_PORT, MAX_PORT};
use secrecy::{ExposeSecret, SecretString};
use rand::RngCore;

#[derive(Debug, Clone, Zeroize)]
#[zeroize(drop)]
pub struct RendezvousParams {
    pub port: u16,
    pub key_enc: [u8; 32],
    pub key_mac: [u8; 32],
    pub tag16: u16,
    pub tag8: u8,
    pub version: u8,
}

/// Deriva parametri deterministici da una passphrase con Argon2id hardening
/// CRITICAL: Mantiene determinismo (stessa passphrase = stessi parametri)
#[allow(dead_code)]
pub(crate) fn derive_from_passphrase(passphrase: &str) -> RendezvousParams {
    derive_from_passphrase_v2(passphrase)
}

pub fn derive_from_secret(passphrase: &SecretString) -> RendezvousParams {
    derive_from_passphrase_v2(passphrase.expose_secret())
}

fn canonicalize_passphrase_bytes(passphrase: &str) -> Vec<u8> {
    let s = passphrase.strip_prefix('\u{FEFF}').unwrap_or(passphrase);
    let s = s.replace("\r\n", "\n").replace('\r', "\n");
    let s = s.trim_end_matches('\n');
    let nfc: String = s.nfc().collect();
    nfc.into_bytes()
}

/// V2: Argon2id + HKDF deterministico (production-ready)
/// Standard mode: usa salt deterministico per determinismo passphrase
pub fn derive_from_passphrase_v2(passphrase: &str) -> RendezvousParams {
    derive_from_passphrase_v2_with_salt(passphrase, None)
}

/// V2 Stealth mode: usa ephemeral salt per port randomization
/// Salva il salt in offer.per_ephemeral_salt per recostruire stessi parametri
pub fn derive_from_passphrase_v2_stealth(passphrase: &str, salt_override: &[u8; 16]) -> (RendezvousParams, [u8; 16]) {
    // Se salt_override è fornito, usa quello (per recostruire)
    // Altrimenti, genera random (per creare nuovo)
    let salt_to_use = if salt_override.iter().any(|&b| b != 0) {
        *salt_override
    } else {
        let mut new_salt = [0u8; 16];
        rand::rngs::OsRng.fill_bytes(&mut new_salt);
        new_salt
    };
    
    let params = derive_from_passphrase_v2_with_salt(passphrase, Some(&salt_to_use));
    (params, salt_to_use)
}

/// Core V2 derivation with optional salt override
fn derive_from_passphrase_v2_with_salt(passphrase: &str, salt_override: Option<&[u8; 16]>) -> RendezvousParams {
    // Canonical bytes: NFC + newline canonicalization + no trim
    let mut pass_bytes = canonicalize_passphrase_bytes(passphrase);

    // 1. Derive salt: deterministico se salt_override None, altrimenti usa override
    let salt_bytes = if let Some(salt) = salt_override {
        *salt
    } else {
        derive_argon2_salt_v2(&pass_bytes)
    };
    
    let salt_b64 = general_purpose::STANDARD_NO_PAD.encode(&salt_bytes);
    let salt = Salt::from_b64(&salt_b64).expect("valid base64 salt");
    
    // 2. Argon2id con parametri bilanciati
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(
            8192, 3, 1, Some(32),
        ).expect("valid argon2 params")
    );
    
    // 3. Deriva master key
    let master_key = argon2
        .hash_password(&pass_bytes, salt)
        .expect("argon2 hash")
        .hash
        .expect("hash present");
    
    // 4. HKDF expansion
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut port_key = [0u8; 2];
    let mut key_enc = [0u8; 32];
    let mut key_mac = [0u8; 32];
    let mut tag = [0u8; 2];

    hk.expand(b"hs/port/v2", &mut port_key).expect("HKDF expand failed");
    hk.expand(b"hs/enc/v2", &mut key_enc).expect("HKDF expand failed");
    hk.expand(b"hs/mac/v2", &mut key_mac).expect("HKDF expand failed");
    hk.expand(b"hs/tag/v2", &mut tag).expect("HKDF expand failed");

    // 5. Calcola parametri
    let port = MIN_EPHEMERAL_PORT + (u16::from_be_bytes(port_key) % (MAX_PORT - MIN_EPHEMERAL_PORT));
    let tag16 = u16::from_be_bytes(tag);
    let tag8 = derive_tag8_from_key(&key_enc);
    
    let result = RendezvousParams {
        port,
        key_enc,
        key_mac,
        tag16,
        tag8,
        version: 2,
    };
    
    // 6. Zeroize
    use zeroize::Zeroize;
    port_key.zeroize();
    tag.zeroize();
    pass_bytes.zeroize();
    
    result
}

fn derive_argon2_salt_v2(pass_bytes: &[u8]) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::new(Some(b"handshacke/hkdf-salt"), pass_bytes);
    let mut out = [0u8; 16];
    hk.expand(b"hs/argon2-salt/v2", &mut out)
        .expect("hkdf expand");
    out
}

/// V1: Backward compatibility (solo SHA256+HKDF)
#[allow(dead_code)]
pub fn derive_from_passphrase_v1(passphrase: &str) -> RendezvousParams {
    let mut hasher = Sha256::new();
    hasher.update(passphrase.as_bytes());
    let seed = hasher.finalize();

    let hk = Hkdf::<Sha256>::new(None, &seed);
    let mut port_key = [0u8; 2];
    let mut key_enc = [0u8; 32];
    let mut key_mac = [0u8; 32];
    let mut tag = [0u8; 2];

    hk.expand(b"hs/port/v1", &mut port_key).expect("HKDF expand failed");
    hk.expand(b"hs/enc/v1", &mut key_enc).expect("HKDF expand failed");
    hk.expand(b"hs/mac/v1", &mut key_mac).expect("HKDF expand failed");
    hk.expand(b"hs/tag/v1", &mut tag).expect("HKDF expand failed");

    let port = MIN_EPHEMERAL_PORT + (u16::from_be_bytes(port_key) % (MAX_PORT - MIN_EPHEMERAL_PORT));
    let tag16 = u16::from_be_bytes(tag);
    let tag8 = derive_tag8_from_key(&key_enc);

    RendezvousParams {
        port,
        key_enc,
        key_mac,
        tag16,
        tag8,
        version: 1,
    }
}

pub(crate) fn derive_tag8_from_key(key_enc: &[u8; 32]) -> u8 {
    use hmac::{Hmac, Mac};
    type HmacSha256 = Hmac<Sha256>;

    let mut mac = HmacSha256::new_from_slice(key_enc).expect("HMAC init failed");
    mac.update(b"hs/tag8/v1");
    let full = mac.finalize().into_bytes();
    // Anti-ambiguity guard: tag8 must never equal PROTOCOL_VERSION_V1,
    // so byte[2] == PROTOCOL_VERSION_V1 uniquely signals a legacy V1 frame.
    let mut tag8 = full[0];
    if tag8 == crate::crypto::PROTOCOL_VERSION_V1 {
        tag8 = full[1];
        if tag8 == crate::crypto::PROTOCOL_VERSION_V1 {
            tag8 = full[2] ^ 0x5a;
            if tag8 == crate::crypto::PROTOCOL_VERSION_V1 {
                tag8 ^= 0xff;
            }
        }
    }
    tag8
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_determinism_v2() {
        // Test V2 (Argon2id) determinism
        let params1 = derive_from_passphrase_v2("gattosegreto123");
        let params2 = derive_from_passphrase_v2("gattosegreto123");
        
        assert_eq!(params1.port, params2.port);
        assert_eq!(params1.key_enc, params2.key_enc);
        assert_eq!(params1.key_mac, params2.key_mac);
        assert_eq!(params1.tag16, params2.tag16);
        assert_eq!(params1.tag8, params2.tag8);
        assert_eq!(params1.version, 2);

        let params3 = derive_from_passphrase_v2("passworddiversa");
        assert_ne!(params1.port, params3.port);
        assert_ne!(params1.tag16, params3.tag16);
        assert_ne!(params1.tag8, params3.tag8);
    }
    
    #[test]
    fn test_determinism_v1_compatibility() {
        // Test V1 (SHA256) still works 
        let params1 = derive_from_passphrase_v1("gattosegreto123");
        let params2 = derive_from_passphrase_v1("gattosegreto123");
        
        assert_eq!(params1.port, params2.port);
        assert_eq!(params1.key_enc, params2.key_enc);
        assert_eq!(params1.version, 1);
    }
    
    #[test]
    fn test_v1_v2_different() {
        // V1 e V2 devono produrre parametri diversi (diversi domini)
        let params_v1 = derive_from_passphrase_v1("test123");
        let params_v2 = derive_from_passphrase_v2("test123");
        
        assert_ne!(params_v1.port, params_v2.port);
        assert_ne!(params_v1.key_enc, params_v2.key_enc);
        assert_ne!(params_v1.tag16, params_v2.tag16);
        assert_ne!(params_v1.tag8, params_v2.tag8);
        assert_eq!(params_v1.version, 1);
        assert_eq!(params_v2.version, 2);
    }

    #[test]
    fn test_port_range() {
        for i in 0..100 {
            let params = derive_from_passphrase(&format!("test{}", i));
            assert!(params.port >= MIN_EPHEMERAL_PORT);
            assert!(params.port <= MAX_PORT);
        }
    }
}
