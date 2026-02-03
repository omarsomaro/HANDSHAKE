#![cfg(feature = "pq")]

use handshacke::crypto::post_quantum::{kyber_ciphertext_bytes, HybridKeyExchange};

#[test]
fn test_hybrid_kex_ciphertext_and_tamper() {
    let (alice, alice_pub) = HybridKeyExchange::generate_keypair();
    let (bob, bob_pub) = HybridKeyExchange::generate_keypair();

    let (ct, alice_key) = alice.encapsulate(&bob_pub).expect("encapsulate");
    assert_eq!(ct.len(), kyber_ciphertext_bytes());

    let mut ct_bad = ct.clone();
    ct_bad[0] ^= 0x01;
    let bob_key_bad = bob.decapsulate(&alice_pub, &ct_bad).expect("decapsulate");
    assert_ne!(
        alice_key, bob_key_bad,
        "tampered ciphertext must not yield same key"
    );

    let short_ct = vec![0u8; 32];
    let err = bob.decapsulate(&alice_pub, &short_ct).unwrap_err();
    assert!(err.to_string().contains("Kyber ciphertext length mismatch"));
}
