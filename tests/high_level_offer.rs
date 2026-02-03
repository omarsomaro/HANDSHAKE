use handshacke::offer::{
    Endpoint, EndpointKind, OfferPayload, RendezvousInfo, RoleHint, DEFAULT_TTL_SECONDS,
};
use handshacke::security::TimeValidator;

fn sample_onion() -> String {
    let host = "a".repeat(56);
    format!("{}.onion:1234", host)
}

#[test]
fn test_offer_encode_decode_verify_roundtrip() {
    let rendezvous = RendezvousInfo {
        port: 9999,
        tag16: 0x1234,
        key_enc: [7u8; 32],
    };
    let endpoints = vec![Endpoint {
        kind: EndpointKind::Lan,
        addr: Some("127.0.0.1:9999".parse().unwrap()),
        priority: 1,
        timeout_ms: 1000,
    }];

    let onion = sample_onion();
    let offer = OfferPayload::new(
        RoleHint::Host,
        endpoints.clone(),
        Some(onion.clone()),
        rendezvous,
        DEFAULT_TTL_SECONDS,
    )
    .expect("offer new");

    let encoded = offer.encode().expect("offer encode");
    let decoded = OfferPayload::decode(&encoded).expect("offer decode");
    let validator = TimeValidator::new();
    decoded.verify(&validator).expect("offer verify");

    assert_eq!(decoded.endpoints.len(), endpoints.len());
    let tor = decoded
        .tor_onion_addr()
        .expect("tor onion addr")
        .expect("tor onion present");
    assert_eq!(tor, onion);

    let mut tampered = decoded.clone();
    tampered.ttl_s = tampered.ttl_s.saturating_add(1);
    assert!(
        tampered.verify(&validator).is_err(),
        "tampered offer must fail verify"
    );
}
