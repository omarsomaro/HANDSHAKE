use crate::protocol_assist::{AssistGo, AssistRequest};
use crate::protocol_assist_v5::{AssistGoV5, AssistRequestV5};
use serde::{Deserialize, Serialize};

/// Control protocol for differentiating Handshake vs App data
///
/// This enum is serialized and encrypted as the "ClearPayload" body.
/// It wraps the actual inner content.
#[derive(Serialize, Deserialize, Debug)]
pub enum Control {
    /// Noise handshake message (ephemeral, before session key)
    NoiseHandshake(Vec<u8>),
    /// Session key exchange (Noise channel post-handshake)
    SessionKey([u8; 32]),
    /// Session key ack (best-effort)
    SessionKeyAck(u64),
    /// Resume handshake hello (pre-Noise, base-key protected)
    ResumeHello {
        token_id: u64,
        client_nonce: [u8; 32],
        ts_ms: u64,
    },
    /// Resume handshake accept (pre-Noise, base-key protected)
    ResumeAccept {
        token_id: u64,
        server_nonce: [u8; 32],
    },
    /// Application data (after session key established)
    App(Vec<u8>),
    /// Assist request (A -> C)
    AssistRequest(AssistRequest),
    /// Assist go (C -> A)
    AssistGo(AssistGo),
    /// Assist request v5 (IP-blinded)
    AssistRequestV5(AssistRequestV5),
    /// Assist go v5 (IP-blinded)
    AssistGoV5(AssistGoV5),
}
