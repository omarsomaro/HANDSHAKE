use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::{Mutex, mpsc};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::task::JoinHandle;
use zeroize::Zeroize;
use crate::security::RateLimiter;

pub mod metrics;
pub mod connection_manager;

pub use metrics::{MetricsCollector, ConnectionMetrics, DebugMetrics, CryptoTimer};
pub use connection_manager::{
    ConnectionManager, CircuitState, ConnectionFsmState, 
    CircuitBreakerStatus, ConnectionCircuitBreaker
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionState {
    pub status: ConnectionStatus,
    pub mode: Option<String>,
    pub port: Option<u16>,
    pub peer_address: Option<String>,
    pub bytes_sent: u64,
    pub bytes_received: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionStatus {
    Disconnected,
    Connecting,
    Connected,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PhraseStatus {
    Closed,
    Opening,
    Open,
    Connected,
    Error(String),
}

impl Default for ConnectionState {
    fn default() -> Self {
        Self {
            status: ConnectionStatus::Disconnected,
            mode: None,
            port: None,
            peer_address: None,
            bytes_sent: 0,
            bytes_received: 0,
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    inner: Arc<Mutex<InnerState>>,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerState {
                connection_state: ConnectionState::default(),
                tx_out: None,
                key_enc: None,
                tag16: None,
                tag8: None,
                port: None,
                wan_keepalive_socket: None,
                stop_tx: None,
                api_rate_limiter: RateLimiter::new(10_000, 200, Duration::from_secs(4)),
                metrics: MetricsCollector::new(),
                phrase_status: PhraseStatus::Closed,
                phrase_onion: None,
                phrase_listener: None,
                phrase_accept_task: None,
                tor_session: None,
            })),
        }
    }
}

struct InnerState {
    connection_state: ConnectionState,
    tx_out: Option<mpsc::Sender<Vec<u8>>>,
    #[allow(dead_code)]
    key_enc: Option<[u8; 32]>,
    tag16: Option<u16>,
    tag8: Option<u8>,
    #[allow(dead_code)]
    port: Option<u16>,
    wan_keepalive_socket: Option<Arc<UdpSocket>>,
    stop_tx: Option<tokio::sync::watch::Sender<bool>>,
    api_rate_limiter: RateLimiter,
    metrics: MetricsCollector, // In-memory metrics (zero persistence)
    phrase_status: PhraseStatus,
    phrase_onion: Option<String>,
    phrase_listener: Option<Arc<TcpListener>>,
    phrase_accept_task: Option<JoinHandle<()>>,
    tor_session: Option<Arc<tokio::sync::Mutex<crate::tor::managed::ManagedTor>>>,
}

impl Drop for InnerState {
    fn drop(&mut self) {
        // Zeroize sensitive data
        if let Some(mut key) = self.key_enc.take() {
            key.zeroize();
        }
    }
}

impl AppState {
    pub async fn set_connection_state(&self, state: ConnectionState) {
        let mut inner = self.inner.lock().await;
        inner.connection_state = state;
    }

    pub async fn get_connection_state(&self) -> ConnectionState {
        let inner = self.inner.lock().await;
        inner.connection_state.clone()
    }

    pub async fn update_stats(&self, sent: u64, received: u64) {
        let mut inner = self.inner.lock().await;
        inner.connection_state.bytes_sent += sent;
        inner.connection_state.bytes_received += received;
    }

    pub async fn set_tx_out(&self, tx: mpsc::Sender<Vec<u8>>) {
        let mut inner = self.inner.lock().await;
        inner.tx_out = Some(tx);
    }

    pub async fn get_tx_out(&self) -> Option<mpsc::Sender<Vec<u8>>> {
        let inner = self.inner.lock().await;
        inner.tx_out.clone()
    }

    pub async fn set_crypto_params(&self, key: [u8; 32], tag16: u16, tag8: u8) {
        let mut inner = self.inner.lock().await;
        inner.key_enc = Some(key);
        inner.tag16 = Some(tag16);
        inner.tag8 = Some(tag8);
    }

    pub async fn get_crypto_params(&self) -> Option<([u8; 32], u16, u8)> {
        let inner = self.inner.lock().await;
        Some((inner.key_enc?, inner.tag16?, inner.tag8?))
    }

    pub async fn clear_crypto_params(&self) {
        let mut inner = self.inner.lock().await;
        if let Some(mut k) = inner.key_enc.take() { 
            use zeroize::Zeroize; 
            k.zeroize(); 
        }
        inner.tag16 = None;
        inner.tag8 = None;
    }

    /// Get metrics collector (in-memory only)
    pub async fn get_metrics(&self) -> MetricsCollector {
        let inner = self.inner.lock().await;
        inner.metrics.clone()
    }

    pub async fn api_allow(&self, ip: IpAddr, cost: f64) -> bool {
        let limiter = {
            let inner = self.inner.lock().await;
            inner.api_rate_limiter.clone()
        };
        limiter.check_cost(SocketAddr::new(ip, 0), cost).await
    }

    pub async fn set_stop_tx(&self, tx: tokio::sync::watch::Sender<bool>) {
        let mut inner = self.inner.lock().await;
        inner.stop_tx = Some(tx);
    }

    pub async fn set_wan_keepalive_socket(&self, sock: Arc<UdpSocket>) {
        let mut inner = self.inner.lock().await;
        inner.wan_keepalive_socket = Some(sock);
    }

    pub async fn clear_wan_keepalive_socket(&self) {
        let mut inner = self.inner.lock().await;
        inner.wan_keepalive_socket = None;
    }

    pub async fn stop_all(&self) {
        let inner = self.inner.lock().await;
        if let Some(stop_tx) = &inner.stop_tx {
            let _ = stop_tx.send(true);
        }
    }

    pub async fn get_stop_rx(&self) -> Option<tokio::sync::watch::Receiver<bool>> {
        let inner = self.inner.lock().await;
        inner.stop_tx.as_ref().map(|tx| tx.subscribe())
    }

    pub async fn set_phrase_status(&self, status: PhraseStatus) {
        let mut inner = self.inner.lock().await;
        inner.phrase_status = status;
    }

    pub async fn get_phrase_status(&self) -> PhraseStatus {
        let inner = self.inner.lock().await;
        inner.phrase_status.clone()
    }

    pub async fn set_phrase_onion(&self, onion: Option<String>) {
        let mut inner = self.inner.lock().await;
        inner.phrase_onion = onion;
    }

    pub async fn get_phrase_onion(&self) -> Option<String> {
        let inner = self.inner.lock().await;
        inner.phrase_onion.clone()
    }

    pub async fn set_phrase_listener(&self, listener: Option<Arc<TcpListener>>) {
        let mut inner = self.inner.lock().await;
        inner.phrase_listener = listener;
    }

    pub async fn take_phrase_listener(&self) -> Option<Arc<TcpListener>> {
        let mut inner = self.inner.lock().await;
        inner.phrase_listener.take()
    }

    pub async fn set_phrase_accept_task(&self, task: Option<JoinHandle<()>>) {
        let mut inner = self.inner.lock().await;
        inner.phrase_accept_task = task;
    }

    pub async fn take_phrase_accept_task(&self) -> Option<JoinHandle<()>> {
        let mut inner = self.inner.lock().await;
        inner.phrase_accept_task.take()
    }

    pub async fn get_or_start_tor(
        &self,
        cfg: &crate::config::Config,
    ) -> anyhow::Result<Arc<tokio::sync::Mutex<crate::tor::managed::ManagedTor>>> {
        let existing = {
            let inner = self.inner.lock().await;
            inner.tor_session.clone()
        };
        if let Some(tor) = existing {
            return Ok(tor);
        }

        let tor = crate::tor::managed::ManagedTor::start(cfg.tor_bin_path.as_deref()).await?;
        let tor = Arc::new(tokio::sync::Mutex::new(tor));

        let mut inner = self.inner.lock().await;
        if let Some(existing) = &inner.tor_session {
            return Ok(existing.clone());
        }
        inner.tor_session = Some(tor.clone());
        Ok(tor)
    }
}
