use crate::{
    transport::Connection, 
    api::Streams, 
    crypto::{open, seal_with_nonce, deserialize_cipher_packet_with_limit, serialize_cipher_packet, ClearPayload, now_ms, MAX_UDP_PACKET_BYTES, MAX_CLEAR_PAYLOAD_BYTES, NonceSeq, NONCE_DOMAIN_APP}, 
    security::RateLimiter,
    state::MetricsCollector,
    protocol::Control,
};
use crate::config::UDP_MAX_PACKET_SIZE;
use tokio::sync::mpsc;
use std::sync::Arc;
use crate::transport::io::{TransportIo, ConnectionIo};
use bincode::Options;

fn is_valid_app_role(role: u8) -> bool {
    matches!(role, 0x01 | 0x02)
}

fn deserialize_control_limited(data: &[u8]) -> Result<Control, bincode::Error> {
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_little_endian()
        .with_limit(MAX_CLEAR_PAYLOAD_BYTES as u64)
        .deserialize::<Control>(data)
}

/// Task di ricezione con shutdown channel
pub async fn spawn_receiver_task_with_stop(
    connection: Connection,
    streams: Streams,
    cipher_params: ([u8; 32], u16, u8),
    rate_limiter: RateLimiter,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    if connection.is_stream() {
        let io = Arc::new(ConnectionIo::new(connection));
        return spawn_receiver_task_with_stop_io(io, streams, cipher_params, rate_limiter, stop).await;
    }

    tokio::spawn(async move {
        let (key_enc, tag16, tag8) = cipher_params;
        let sock = match connection.get_socket() {
            Some(s) => s,
            None => return,
        };
        let mut buf = vec![0u8; UDP_MAX_PACKET_SIZE];
        let mut rw = crate::crypto::replay::ReplayWindow::new();

        loop {
            tokio::select! {
                _ = stop.changed() => {
                    tracing::info!("Receiver task stopping");
                    break;
                },
                result = sock.recv_from(&mut buf) => {
                    match result {
                        Ok((n, source)) => {
                            // 1. Early drop by tag
                            if crate::security::early_drop_packet(&buf[..n], tag16, tag8) {
                                continue;
                            }
                            // 2. Rate limit
                            if !rate_limiter.check(source).await {
                                tracing::warn!("Rate limit exceeded for {}", source);
                                continue;
                            }
                            // 3. Process packet
                            if let Ok(cipher_packet) = deserialize_cipher_packet_with_limit(&buf[..n], MAX_UDP_PACKET_BYTES) {
                                if let Some(clear_payload) = open(&key_enc, &cipher_packet, tag16, tag8) {
                                    if rw.accept(clear_payload.seq).unwrap_or(false) {
                                        // Handle Control Packet
                                        if let Ok(ctrl) = deserialize_control_limited(&clear_payload.data) {
                                            match ctrl {
                                                Control::App(msg) => {
                                                     if streams.tx.send(msg).await.is_err() {
                                                         break;
                                                     }
                                                },
                                                Control::NoiseHandshake(_) => {
                                                    // Ignore post-handshake noise messages
                                                }
                                                Control::SessionKey(_) => {
                                                    // Ignore post-handshake session key exchange
                                                }
                                                Control::AssistRequest(_) => {
                                                    // Ignore assist control on app channel
                                                }
                                                Control::AssistGo(_) => {
                                                    // Ignore assist control on app channel
                                                }
                                                Control::AssistRequestV5(_) => {
                                                    // Ignore assist control on app channel
                                                }
                                                Control::AssistGoV5(_) => {
                                                    // Ignore assist control on app channel
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("RX error: {:?}", e);
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    })
}

/// Task di ricezione con shutdown channel per TransportIo (Guaranteed)
pub async fn spawn_receiver_task_with_stop_io(
    io: Arc<dyn TransportIo>,
    streams: Streams,
    cipher_params: ([u8; 32], u16, u8),
    rate_limiter: RateLimiter,
    mut stop: tokio::sync::watch::Receiver<bool>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (key_enc, tag16, tag8) = cipher_params;
        let mut rw = crate::crypto::replay::ReplayWindow::new();
        let relay_addr = io.rate_limit_addr();
        let limit = io.max_packet_limit();

        loop {
            tokio::select! {
                _ = stop.changed() => {
                    tracing::info!("Receiver task stopping");
                    break;
                },
                result = io.recv() => {
                    match result {
                        Ok(bytes) => {
                            if bytes.is_empty() {
                                continue;
                            }
                            if crate::security::early_drop_packet(&bytes, tag16, tag8) {
                                continue;
                            }
                            if !rate_limiter.check(relay_addr).await {
                                tracing::warn!("Rate limit exceeded for relay stream ({})", relay_addr);
                                continue;
                            }
                            if let Ok(cipher_packet) = deserialize_cipher_packet_with_limit(&bytes, limit) {
                                if let Some(clear_payload) = open(&key_enc, &cipher_packet, tag16, tag8) {
                                    if rw.accept(clear_payload.seq).unwrap_or(false) {
                                        if let Ok(ctrl) = deserialize_control_limited(&clear_payload.data) {
                                            match ctrl {
                                                Control::App(msg) => {
                                                    if streams.tx.send(msg).await.is_err() {
                                                        break;
                                                    }
                                                },
                                                Control::NoiseHandshake(_) => {}
                                                Control::SessionKey(_) => {}
                                                Control::AssistRequest(_) => {}
                                                Control::AssistGo(_) => {}
                                                Control::AssistRequestV5(_) => {}
                                                Control::AssistGoV5(_) => {}
                                            }
                                        }
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            tracing::error!("RX error: {:?}", e);
                            tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
                        }
                    }
                }
            }
        }
    })
}

/// Task di invio con shutdown channel + metriche + Session Encryption
pub async fn spawn_sender_task_with_stop(
    connection: Connection,
    mut rx_out: mpsc::Receiver<Vec<u8>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    metrics: MetricsCollector,
    cipher_params: ([u8; 32], u16, u8),
    app_role: u8,
) -> tokio::task::JoinHandle<()> {
    if connection.is_stream() {
        let io = Arc::new(ConnectionIo::new(connection));
        return spawn_sender_task_with_stop_io(io, rx_out, stop, metrics, cipher_params, app_role).await;
    }

    tokio::spawn(async move {
        let (key_enc, tag16, tag8) = cipher_params;
        debug_assert!(is_valid_app_role(app_role));
        let mut nonce_seq = NonceSeq::new(&key_enc, NONCE_DOMAIN_APP, app_role);
        
        loop {
            tokio::select! {
                _ = stop.changed() => {
                    tracing::info!("Sender task stopping");
                    break;
                },
                maybe = rx_out.recv() => {
                    if let Some(data) = maybe {
                        // 1. Wrap in Control::App
                        let ctrl = Control::App(data);
                        let payload_bytes = match bincode::serialize(&ctrl) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        // 2. Encrypt with session key
                        let (nonce, seq) = match nonce_seq.next_nonce_and_seq() {
                            Ok(result) => result,
                            Err(e) => {
                                tracing::error!("Nonce generation failed: {:?}", e);
                                continue;
                            }
                        };
                        let clear = ClearPayload {
                            ts_ms: now_ms(),
                            seq,
                            data: payload_bytes,
                        };
                        
                        let pkt = match seal_with_nonce(&key_enc, tag16, tag8, &clear, &nonce) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };
                        
                        let raw_bytes = match serialize_cipher_packet(&pkt) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        // 3. Send
                        let sock = match connection.get_socket() {
                            Some(s) => s,
                            None => break,
                        };
                        let remote_addr = match &connection {
                            Connection::Lan(_, peer) => *peer,
                            Connection::Wan(_, addr) => *addr,
                            Connection::WanTorStream { .. } => unreachable!(),
                            Connection::Quic(_) => unreachable!(),
                            Connection::WebRtc(_) => unreachable!(),
                        };
                        match sock.send_to(&raw_bytes, remote_addr).await {
                            Ok(sent) => {
                                metrics.record_packet_sent(sent).await;
                                tracing::debug!("Sent {} bytes", sent);
                            }
                            Err(e) => {
                                metrics.record_connection_error().await;
                                tracing::error!("TX error: {:?}", e);
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        tracing::debug!("Sender task terminated");
    })
}

/// Task di invio con shutdown channel + metriche per TransportIo (Guaranteed)
pub async fn spawn_sender_task_with_stop_io(
    io: Arc<dyn TransportIo>,
    mut rx_out: mpsc::Receiver<Vec<u8>>,
    mut stop: tokio::sync::watch::Receiver<bool>,
    metrics: MetricsCollector,
    cipher_params: ([u8; 32], u16, u8),
    app_role: u8,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let (key_enc, tag16, tag8) = cipher_params;
        debug_assert!(is_valid_app_role(app_role));
        let mut nonce_seq = NonceSeq::new(&key_enc, NONCE_DOMAIN_APP, app_role);

        loop {
            tokio::select! {
                _ = stop.changed() => {
                    tracing::info!("Sender task stopping");
                    break;
                },
                maybe = rx_out.recv() => {
                    if let Some(data) = maybe {
                        let ctrl = Control::App(data);
                        let payload_bytes = match bincode::serialize(&ctrl) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        let (nonce, seq) = match nonce_seq.next_nonce_and_seq() {
                            Ok(result) => result,
                            Err(e) => {
                                tracing::error!("Nonce generation failed: {:?}", e);
                                continue;
                            }
                        };
                        let clear = ClearPayload {
                            ts_ms: now_ms(),
                            seq,
                            data: payload_bytes,
                        };

                        let pkt = match seal_with_nonce(&key_enc, tag16, tag8, &clear, &nonce) {
                            Ok(p) => p,
                            Err(_) => continue,
                        };

                        let raw_bytes = match serialize_cipher_packet(&pkt) {
                            Ok(b) => b,
                            Err(_) => continue,
                        };

                        let len = raw_bytes.len();
                        match io.send(raw_bytes).await {
                            Ok(()) => {
                                metrics.record_packet_sent(len).await;
                                tracing::debug!("Sent {} bytes (Guaranteed)", len);
                            }
                            Err(e) => {
                                metrics.record_connection_error().await;
                                tracing::error!("TX error: {:?}", e);
                            }
                        }
                    } else {
                        break;
                    }
                }
            }
        }
        tracing::debug!("Sender task terminated");
    })
}

// Deprecated V1 and test tasks removed for brevity/safety - users should rely on secure task

#[cfg(test)]
mod tests {
    use super::is_valid_app_role;

    #[test]
    fn test_app_role_is_binary_choice() {
        assert!(is_valid_app_role(0x01));
        assert!(is_valid_app_role(0x02));
        assert!(!is_valid_app_role(0x00));
        assert!(!is_valid_app_role(0x03));
        assert!(!is_valid_app_role(0xff));
    }
}
