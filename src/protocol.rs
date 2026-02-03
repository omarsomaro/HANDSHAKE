use serde::{Serialize, Deserialize};
use crate::protocol_assist::{AssistRequest, AssistGo};
use crate::protocol_assist_v5::{AssistRequestV5, AssistGoV5};

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
