use crate::config::UDP_MAX_PACKET_SIZE;
#[cfg(feature = "pq")]
use crate::crypto::post_quantum::NOISE_PARAMS_PQ;
use crate::crypto::{
    self, deserialize_cipher_packet_with_limit, open, seal_with_nonce, ClearPayload, NonceSeq,
    MAX_TCP_FRAME_BYTES, MAX_UDP_PACKET_BYTES, NONCE_DOMAIN_NOISE,
};
use crate::protocol::Control;
use crate::transport::Connection;
use anyhow::{anyhow, bail, Result};
use rand::RngCore;
use snow::{Builder, HandshakeState};
use std::future::Future;

const NOISE_PARAMS_CLASSIC: &str = "Noise_XX_25519_ChaChaPoly_BLAKE2s";
const MAX_NOISE_MESSAGE_BYTES: usize = 8 * 1024;

/// Protocol state validation to prevent state machine attacks
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolState {
    Handshake,
    Transport,
    Closed,
}

/// Comprehensive protocol validation result
pub struct ProtocolValidation {
    pub is_valid: bool,
    pub state: ProtocolState,
    pub error: Option<String>,
}

/// Validate protocol transition and message in current state
pub fn validate_protocol_transition(
    current_state: ProtocolState,
    message_type: &crate::protocol::Control,
    is_handshake_complete: bool,
) -> ProtocolValidation {
    use crate::protocol::Control;

    match (current_state, message_type) {
        // Valid handshake messages during handshake
        (ProtocolState::Handshake, Control::NoiseHandshake(_)) => ProtocolValidation {
            is_valid: true,
            state: ProtocolState::Handshake,
            error: None,
        },
        // SessionKey only valid after handshake complete
        (ProtocolState::Handshake, Control::SessionKey(_)) => {
            if is_handshake_complete {
                ProtocolValidation {
                    is_valid: true,
                    state: ProtocolState::Handshake,
                    error: None,
                }
            } else {
                ProtocolValidation {
                    is_valid: false,
                    state: ProtocolState::Handshake,
                    error: Some("SessionKey received before handshake completion".to_string()),
                }
            }
        }
        // Invalid messages during handshake
        (ProtocolState::Handshake, Control::App(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("Application data received during handshake".to_string()),
        },
        (ProtocolState::Handshake, Control::AssistRequest(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("AssistRequest received during handshake".to_string()),
        },
        (ProtocolState::Handshake, Control::AssistGo(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("AssistGo received during handshake".to_string()),
        },
        (ProtocolState::Handshake, Control::AssistRequestV5(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("AssistRequestV5 received during handshake".to_string()),
        },
        (ProtocolState::Handshake, Control::AssistGoV5(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Handshake,
            error: Some("AssistGoV5 received during handshake".to_string()),
        },
        // Invalid messages during transport
        (ProtocolState::Transport, Control::NoiseHandshake(_)) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Transport,
            error: Some("Handshake message received in transport mode".to_string()),
        },
        // Valid messages during transport
        (ProtocolState::Transport, Control::App(_)) => ProtocolValidation {
            is_valid: true,
            state: ProtocolState::Transport,
            error: None,
        },
        (ProtocolState::Transport, Control::SessionKey(_)) => ProtocolValidation {
            is_valid: true,
            state: ProtocolState::Transport,
            error: None,
        },
        (ProtocolState::Transport, Control::AssistRequest(_) | Control::AssistGo(_)) => {
            ProtocolValidation {
                is_valid: true,
                state: ProtocolState::Transport,
                error: None,
            }
        }
        (ProtocolState::Transport, Control::AssistRequestV5(_) | Control::AssistGoV5(_)) => {
            ProtocolValidation {
                is_valid: true,
                state: ProtocolState::Transport,
                error: None,
            }
        }
        // Invalid messages on closed connection
        (ProtocolState::Closed, _) => ProtocolValidation {
            is_valid: false,
            state: ProtocolState::Closed,
            error: Some("Message received on closed connection".to_string()),
        },
    }
}

impl ProtocolState {
    /// Check if current state allows message transmission
    pub fn can_send_message(&self, message_type: &crate::protocol::Control) -> bool {
        use crate::protocol::Control;
        matches!(
            (self, message_type),
            (ProtocolState::Handshake, Control::NoiseHandshake(_))
                | (ProtocolState::Transport, _)
        )
    }

    /// Check if current state allows message reception
    pub fn can_receive_message(&self, message_type: &crate::protocol::Control) -> bool {
        use crate::protocol::Control;
        matches!(
            (self, message_type),
            (ProtocolState::Handshake, Control::NoiseHandshake(_))
                | (ProtocolState::Transport, _)
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub enum NoiseRole {
    Initiator,
    Responder,
}

/// Abstract raw packet sending over any connection type
async fn send_raw(conn: &Connection, data: Vec<u8>) -> Result<()> {
    match conn {
        Connection::Lan(sock, addr) | Connection::Wan(sock, addr) => {
            sock.send_to(&data, *addr).await?;
        }
        Connection::WanTorStream { writer, .. } => {
            let mut guard = writer.lock().await;
            crate::transport::framing::write_frame(&mut *guard, &data).await?;
        }
        Connection::Quic(quic) => {
            quic.send(&data).await?;
        }
        Connection::WebRtc(webrtc) => {
            webrtc.send(&data).await?;
        }
    }
    Ok(())
}

/// Abstract raw packet receiving over any connection type
async fn recv_raw(conn: &Connection) -> Result<Vec<u8>> {
    match conn {
        Connection::Lan(sock, _) | Connection::Wan(sock, _) => {
            let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
            let (n, _) = sock.recv_from(&mut buf).await?;
            Ok(buf[..n].to_vec())
        }
        Connection::WanTorStream { reader, .. } => {
            let mut guard = reader.lock().await;
            crate::transport::framing::read_frame(&mut *guard).await
        }
        Connection::Quic(quic) => quic.recv().await,
        Connection::WebRtc(webrtc) => webrtc.recv().await,
    }
}

fn max_packet_limit(conn: &Connection) -> u64 {
    match conn {
        Connection::WebRtc(_) => crate::transport::webrtc::WEBRTC_MAX_MESSAGE_BYTES as u64,
        _ if conn.is_stream() => MAX_TCP_FRAME_BYTES,
        _ => MAX_UDP_PACKET_BYTES,
    }
}

fn select_noise_params(conn: &Connection) -> Result<snow::params::NoiseParams> {
    if conn.is_stream() {
        #[cfg(feature = "pq")]
        {
            tracing::info!("Noise PQ enabled for stream connection");
            pq_noise_params()
        }
        #[cfg(not(feature = "pq"))]
        {
            tracing::info!("Noise PQ feature disabled; using classic XX");
            classic_noise_params()
        }
    } else {
        tracing::info!("Noise PQ disabled for UDP; using classic XX to fit MTU");
        classic_noise_params()
    }
}

fn parse_noise_params(params_str: &str, needs_pq: bool) -> Result<snow::params::NoiseParams> {
    params_str.parse().map_err(|e| {
        if needs_pq {
            anyhow!(
                "Noise params parse failed for {}: {}. Ensure snow features hfs + pqclean_kyber1024 are enabled.",
                params_str,
                e
            )
        } else {
            anyhow!("Noise params parse failed for {}: {}.", params_str, e)
        }
    })
}

pub fn classic_noise_params() -> Result<snow::params::NoiseParams> {
    parse_noise_params(NOISE_PARAMS_CLASSIC, false)
}

pub fn pq_noise_params() -> Result<snow::params::NoiseParams> {
    #[cfg(feature = "pq")]
    {
        parse_noise_params(NOISE_PARAMS_PQ, true)
    }
    #[cfg(not(feature = "pq"))]
    {
        bail!("PQ feature disabled; enable with --features pq");
    }
}

/// Run Noise handshake upgrade over an established connection.
///
/// Messages are encrypted with the `base_key` (derived from passphrase)
/// wrapping a `Control::NoiseHandshake` payload.
pub async fn run_noise_upgrade(
    role: NoiseRole,
    conn: &Connection,
    base_key: &[u8; 32],
    tag16: u16,
    tag8: u8,
) -> Result<[u8; 32]> {
    let limit = max_packet_limit(conn);
    let params = select_noise_params(conn)?;
    run_noise_upgrade_io(
        role,
        |data: Vec<u8>| async move { send_raw(conn, data).await },
        || async move { recv_raw(conn).await },
        base_key,
        tag16,
        tag8,
        params,
        limit,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn run_noise_upgrade_io<FSend, FRecv, FS, FR>(
    role: NoiseRole,
    send: FSend,
    mut recv: FRecv,
    base_key: &[u8; 32],
    tag16: u16,
    tag8: u8,
    params: snow::params::NoiseParams,
    limit: u64,
) -> Result<[u8; 32]>
where
    FSend: Fn(Vec<u8>) -> FS + Send + Sync,
    FS: Future<Output = Result<()>> + Send,
    FRecv: FnMut() -> FR + Send,
    FR: Future<Output = Result<Vec<u8>>> + Send,
{
    tracing::info!("Starting Noise session upgrade...");

    let builder = Builder::new(params);
    let keypair = builder.generate_keypair()?;
    let builder = builder.local_private_key(&keypair.private);
    let mut noise: HandshakeState = match role {
        NoiseRole::Initiator => builder.build_initiator()?,
        NoiseRole::Responder => builder.build_responder()?,
    };

    let mut buf = vec![0u8; MAX_NOISE_MESSAGE_BYTES];
    let role_byte = match role {
        NoiseRole::Initiator => 0x01,
        NoiseRole::Responder => 0x02,
    };
    let mut nonce_seq = NonceSeq::new_boot_random(base_key, NONCE_DOMAIN_NOISE, role_byte);

    loop {
        if noise.is_handshake_finished() {
            break;
        }

        if noise.is_my_turn() {
            let len = noise.write_message(&[], &mut buf)?;
            if len == 0 || len > MAX_NOISE_MESSAGE_BYTES {
                bail!("Noise handshake message size invalid");
            }
            let noise_msg = buf[..len].to_vec();

            let ctrl = Control::NoiseHandshake(noise_msg);
            let payload_bytes = bincode::serialize(&ctrl)?;

            let (nonce, seq) = nonce_seq.next_nonce_and_seq()?;
            let clear = ClearPayload {
                ts_ms: crypto::now_ms(),
                seq,
                data: payload_bytes,
            };
            let pkt = seal_with_nonce(base_key, tag16, tag8, &clear, &nonce)?;
            let raw_bytes = crypto::serialize_cipher_packet(&pkt)?;

            send(raw_bytes).await?;
            tracing::debug!("Sent Noise handshake message ({} bytes)", len);
        } else {
            let raw_bytes = recv().await?;

            // Importante: controllo dimensione dal primo file
            if raw_bytes.len() > limit as usize {
                bail!("Message too large: {} > {} bytes", raw_bytes.len(), limit);
            }

            let pkt = deserialize_cipher_packet_with_limit(&raw_bytes, limit)?;
            let clear = open(base_key, &pkt, tag16, tag8).ok_or_else(|| {
                anyhow!("Noise handshake: Invalid base packet tag or decryption failed")
            })?;

            let ctrl: Control = bincode::deserialize(&clear.data)?;

            // Usa la validazione del protocollo
            let validation = validate_protocol_transition(
                ProtocolState::Handshake,
                &ctrl,
                false, // handshake non ancora completato
            );

            if !validation.is_valid {
                bail!(
                    "Protocol violation: {}",
                    validation.error.unwrap_or_default()
                );
            }

            match ctrl {
                Control::NoiseHandshake(msg) => {
                    if msg.is_empty() || msg.len() > MAX_NOISE_MESSAGE_BYTES {
                        bail!("NoiseHandshake too large");
                    }
                    noise.read_message(&msg, &mut [])?;
                    tracing::debug!("Received Noise handshake message ({} bytes)", msg.len());
                }
                // Questi casi ora sono gestiti da validate_protocol_transition
                _ => unreachable!(), // Non dovrebbe mai succedere grazie alla validazione
            }
        }
    }

    let mut transport = noise.into_transport_mode()?;

    match role {
        NoiseRole::Initiator => {
            // Usa OsRng dal primo file (più sicuro di thread_rng)
            let mut session_key = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut session_key);

            let ctrl = Control::SessionKey(session_key);
            let payload_bytes = bincode::serialize(&ctrl)?;

            let len = transport.write_message(&payload_bytes, &mut buf)?;
            send(buf[..len].to_vec()).await?;
            tracing::debug!("Session key sent over Noise channel ({} bytes)", len);

            tracing::info!("Noise session upgrade completed successfully.");
            Ok(session_key)
        }
        NoiseRole::Responder => {
            let raw = recv().await?;
            let len = transport.read_message(&raw, &mut buf)?;
            let ctrl: Control = bincode::deserialize(&buf[..len])?;

            // Validazione per il SessionKey
            let validation = validate_protocol_transition(
                ProtocolState::Handshake,
                &ctrl,
                true, // handshake completato
            );

            if !validation.is_valid {
                bail!(
                    "Protocol violation: {}",
                    validation.error.unwrap_or_default()
                );
            }

            match ctrl {
                Control::SessionKey(sk) => {
                    tracing::debug!("Session key received over Noise channel");
                    tracing::info!("Noise session upgrade completed successfully.");
                    Ok(sk)
                }
                _ => unreachable!(), // Non dovrebbe mai succedere grazie alla validazione
            }
        }
    }
}
