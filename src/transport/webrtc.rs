#[cfg(feature = "webrtc")]
mod imp {
    use anyhow::{Result, anyhow, bail};
    use bytes::Bytes;
    use serde_json;
    use std::sync::{Arc, atomic::{AtomicBool, Ordering}};
    use tokio::sync::{mpsc, Mutex, Notify};
    use tokio::time::{timeout, Duration};

    use crate::config::Config;

    use ::webrtc::api::APIBuilder;
    use ::webrtc::api::media_engine::MediaEngine;
    use ::webrtc::api::interceptor_registry::register_default_interceptors;
    use ::webrtc::interceptor::registry::Registry;
    use ::webrtc::data_channel::data_channel_message::DataChannelMessage;
    use ::webrtc::data_channel::RTCDataChannel;
    use ::webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
    use ::webrtc::ice_transport::ice_server::RTCIceServer;
    use ::webrtc::peer_connection::configuration::RTCConfiguration;
    use ::webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
    use ::webrtc::peer_connection::RTCPeerConnection;

    const DATA_CHANNEL_LABEL: &str = "handshacke";
    const ICE_CHANNEL_CAPACITY: usize = 64;
    const DATA_CHANNEL_CAPACITY: usize = 1024;
    pub const WEBRTC_MAX_MESSAGE_BYTES: usize = 16 * 1024;

    #[derive(Clone)]
    pub struct WebRtcTransport {
        peer_connection: Arc<RTCPeerConnection>,
        data_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
        rx: Arc<Mutex<Option<mpsc::Receiver<Vec<u8>>>>>,
        ice_rx: Arc<Mutex<mpsc::Receiver<String>>>,
        dc_ready: Arc<AtomicBool>,
        dc_notify: Arc<Notify>,
    }

    impl WebRtcTransport {
    pub async fn create_offer(cfg: &Config) -> Result<(Self, String)> {
            let api = build_api()?;
            let pc = Arc::new(api.new_peer_connection(rtc_config_from_config(cfg)).await?);

            let ice_rx = setup_ice_candidate_channel(&pc);
            let data_channel = pc.create_data_channel(DATA_CHANNEL_LABEL, None).await?;
            let rx = setup_data_channel(&data_channel);
            let dc_ready = Arc::new(AtomicBool::new(true));
            let dc_notify = Arc::new(Notify::new());
            dc_notify.notify_waiters();

            let offer = pc.create_offer(None).await?;
            pc.set_local_description(offer.clone()).await?;

            Ok((
                Self {
                    peer_connection: pc,
                    data_channel: Arc::new(Mutex::new(Some(data_channel))),
                    rx: Arc::new(Mutex::new(Some(rx))),
                    ice_rx: Arc::new(Mutex::new(ice_rx)),
                    dc_ready,
                    dc_notify,
                },
                offer.sdp,
            ))
        }

        pub async fn connect_with_offer(cfg: &Config, offer_sdp: &str) -> Result<(Self, String)> {
            let api = build_api()?;
            let pc = Arc::new(api.new_peer_connection(rtc_config_from_config(cfg)).await?);

            let data_channel = Arc::new(Mutex::new(None));
            let rx = Arc::new(Mutex::new(None));
            let dc_ready = Arc::new(AtomicBool::new(false));
            let dc_notify = Arc::new(Notify::new());
            let data_channel_cb = Arc::clone(&data_channel);
            let rx_cb = Arc::clone(&rx);
            let dc_ready_cb = Arc::clone(&dc_ready);
            let dc_notify_cb = Arc::clone(&dc_notify);
            pc.on_data_channel(Box::new(move |dc: Arc<RTCDataChannel>| {
                let data_channel_cb = Arc::clone(&data_channel_cb);
                let rx_cb = Arc::clone(&rx_cb);
                let dc_ready_cb = Arc::clone(&dc_ready_cb);
                let dc_notify_cb = Arc::clone(&dc_notify_cb);
                Box::pin(async move {
                    let rx = setup_data_channel(&dc);
                    {
                        let mut guard = data_channel_cb.lock().await;
                        if guard.is_none() {
                            *guard = Some(dc);
                        }
                    }
                    {
                        let mut guard = rx_cb.lock().await;
                        if guard.is_none() {
                            *guard = Some(rx);
                        }
                    }
                    dc_ready_cb.store(true, Ordering::Release);
                    dc_notify_cb.notify_waiters();
                })
            }));

            let ice_rx = setup_ice_candidate_channel(&pc);

            let offer = RTCSessionDescription::offer(offer_sdp.to_string())?;
            pc.set_remote_description(offer).await?;
            let answer = pc.create_answer(None).await?;
            pc.set_local_description(answer.clone()).await?;

            Ok((
                Self {
                    peer_connection: pc,
                    data_channel,
                    rx,
                    ice_rx: Arc::new(Mutex::new(ice_rx)),
                    dc_ready,
                    dc_notify,
                },
                answer.sdp,
            ))
        }

        pub async fn set_remote_answer(&self, answer_sdp: &str) -> Result<()> {
            let answer = RTCSessionDescription::answer(answer_sdp.to_string())?;
            self.peer_connection.set_remote_description(answer).await?;
            Ok(())
        }

        pub async fn add_ice_candidate(&self, candidate_json: &str) -> Result<()> {
            let cand: RTCIceCandidateInit = serde_json::from_str(candidate_json)
                .map_err(|e| anyhow!("Invalid ICE candidate json: {}", e))?;
            self.peer_connection.add_ice_candidate(cand).await?;
            Ok(())
        }

        pub async fn next_ice_candidate(&self) -> Option<String> {
            let mut rx = self.ice_rx.lock().await;
            rx.recv().await
        }

    pub async fn send(&self, data: &[u8]) -> Result<()> {
            self.wait_data_channel().await?;
            if data.len() > WEBRTC_MAX_MESSAGE_BYTES {
                bail!(
                    "WebRTC message too large: {} > {} bytes",
                    data.len(),
                    WEBRTC_MAX_MESSAGE_BYTES
                );
            }
            let payload = Bytes::copy_from_slice(data);
            let dc = self.data_channel.lock().await;
            let dc = dc.as_ref().ok_or_else(|| anyhow!("WebRTC data channel not ready"))?;
            dc.send(&payload).await?;
            Ok(())
        }

        pub async fn recv(&self) -> Result<Vec<u8>> {
            self.wait_data_channel().await?;
            let mut rx = self.rx.lock().await;
            let rx = rx.as_mut().ok_or_else(|| anyhow!("WebRTC data channel not ready"))?;
            match rx.recv().await {
                Some(data) => Ok(data),
                None => bail!("WebRTC data channel closed"),
            }
        }
    }

    impl WebRtcTransport {
        async fn wait_data_channel(&self) -> Result<()> {
            if self.dc_ready.load(Ordering::Acquire) {
                return Ok(());
            }
            timeout(Duration::from_secs(15), self.dc_notify.notified())
                .await
                .map_err(|_| anyhow!("WebRTC data channel timeout"))?;
            if self.dc_ready.load(Ordering::Acquire) {
                Ok(())
            } else {
                bail!("WebRTC data channel not ready")
            }
        }
    }

    fn rtc_config_from_config(cfg: &Config) -> RTCConfiguration {
        let urls: Vec<String> = cfg
            .nat_detection_servers
            .iter()
            .map(|s| {
                if s.starts_with("stun:") || s.starts_with("turn:") {
                    s.to_string()
                } else {
                    format!("stun:{}", s)
                }
            })
            .collect();

        let ice_servers = if urls.is_empty() {
            vec![]
        } else {
            vec![RTCIceServer {
                urls,
                ..Default::default()
            }]
        };

        RTCConfiguration {
            ice_servers,
            ..Default::default()
        }
    }

    fn setup_data_channel(dc: &Arc<RTCDataChannel>) -> mpsc::Receiver<Vec<u8>> {
        let (tx, rx) = mpsc::channel(DATA_CHANNEL_CAPACITY);
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(msg.data.to_vec()).await;
            })
        }));
        rx
    }

    fn setup_ice_candidate_channel(pc: &Arc<RTCPeerConnection>) -> mpsc::Receiver<String> {
        let (tx, rx) = mpsc::channel(ICE_CHANNEL_CAPACITY);
        let tx_ice = tx.clone();
        pc.on_ice_candidate(Box::new(move |cand| {
            let tx_ice = tx_ice.clone();
            Box::pin(async move {
                if let Some(cand) = cand {
                    if let Ok(json) = cand.to_json() {
                        if let Ok(text) = serde_json::to_string(&json) {
                            let _ = tx_ice.send(text).await;
                        }
                    }
                }
            })
        }));
        rx
    }

    fn build_api() -> Result<::webrtc::api::API> {
        let mut m = MediaEngine::default();
        m.register_default_codecs()?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut m)?;
        Ok(APIBuilder::new()
            .with_media_engine(m)
            .with_interceptor_registry(registry)
            .build())
    }
}

#[cfg(not(feature = "webrtc"))]
mod imp {
    use anyhow::{Result, bail};
    use crate::config::Config;

    pub const WEBRTC_MAX_MESSAGE_BYTES: usize = 16 * 1024;

    #[derive(Clone)]
    pub struct WebRtcTransport;

    impl WebRtcTransport {
        pub async fn create_offer(_cfg: &Config) -> Result<(Self, String)> {
            bail!("webrtc feature disabled; enable with --features webrtc")
        }

        pub async fn connect_with_offer(_cfg: &Config, _offer_sdp: &str) -> Result<(Self, String)> {
            bail!("webrtc feature disabled; enable with --features webrtc")
        }

        pub async fn set_remote_answer(&self, _answer_sdp: &str) -> Result<()> {
            bail!("webrtc feature disabled; enable with --features webrtc")
        }

        pub async fn add_ice_candidate(&self, _candidate_json: &str) -> Result<()> {
            bail!("webrtc feature disabled; enable with --features webrtc")
        }

        pub async fn next_ice_candidate(&self) -> Option<String> {
            None
        }

        pub async fn send(&self, _data: &[u8]) -> Result<()> {
            bail!("webrtc feature disabled; enable with --features webrtc")
        }

        pub async fn recv(&self) -> Result<Vec<u8>> {
            bail!("webrtc feature disabled; enable with --features webrtc")
        }
    }
}

pub use imp::*;
