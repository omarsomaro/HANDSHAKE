use serde::{Deserialize, Serialize};
/// In-Memory Metrics per Handshacke - Zero Persistence Philosophy
///
/// Traccia solo in RAM per debugging locale e optimization.
/// NO telemetria, NO log persistenti, NO export remoto.
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Metriche complete di connessione (solo RAM)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionMetrics {
    // Traffic Stats
    pub packets_sent: u64,
    pub packets_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,

    // Performance Stats
    pub avg_encrypt_us: f64, // Latenza media encrypt/decrypt
    pub avg_decrypt_us: f64,
    pub packet_loss_rate: f64, // % pacchetti persi

    // Security Stats
    pub replay_attacks_blocked: u64,
    pub rate_limit_violations: u64,
    pub invalid_tags_dropped: u64,
    pub version_mismatches: u64,

    // Connection Health
    pub uptime_seconds: u64,
    pub last_activity: Option<u64>, // timestamp
    pub connection_errors: u64,

    // Transport Layer
    pub transport_mode: String,   // "lan", "wan", "tun"
    pub nat_type: Option<String>, // UPnP detection result
}

impl Default for ConnectionMetrics {
    fn default() -> Self {
        Self {
            packets_sent: 0,
            packets_received: 0,
            bytes_sent: 0,
            bytes_received: 0,
            avg_encrypt_us: 0.0,
            avg_decrypt_us: 0.0,
            packet_loss_rate: 0.0,
            replay_attacks_blocked: 0,
            rate_limit_violations: 0,
            invalid_tags_dropped: 0,
            version_mismatches: 0,
            uptime_seconds: 0,
            last_activity: None,
            connection_errors: 0,
            transport_mode: "unknown".into(),
            nat_type: None,
        }
    }
}

/// Aggregatore di metriche in tempo reale (thread-safe)
#[derive(Clone)]
pub struct MetricsCollector {
    metrics: Arc<RwLock<ConnectionMetrics>>,
    start_time: Instant,
    // Sliding window per performance (ultimi 100 samples)
    encrypt_samples: Arc<RwLock<Vec<f64>>>,
    decrypt_samples: Arc<RwLock<Vec<f64>>>,
}

impl MetricsCollector {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(RwLock::new(ConnectionMetrics::default())),
            start_time: Instant::now(),
            encrypt_samples: Arc::new(RwLock::new(Vec::with_capacity(100))),
            decrypt_samples: Arc::new(RwLock::new(Vec::with_capacity(100))),
        }
    }

    /// Aggiorna traffic stats
    pub async fn record_packet_sent(&self, size: usize) {
        let mut metrics = self.metrics.write().await;
        metrics.packets_sent += 1;
        metrics.bytes_sent += size as u64;
        metrics.last_activity = Some(crate::crypto::now_ms());
    }

    pub async fn record_packet_received(&self, size: usize) {
        let mut metrics = self.metrics.write().await;
        metrics.packets_received += 1;
        metrics.bytes_received += size as u64;
        metrics.last_activity = Some(crate::crypto::now_ms());
    }

    /// Aggiorna performance crypto (sliding window)
    pub async fn record_encrypt_time(&self, duration: Duration) {
        let micros = duration.as_micros() as f64;

        // Update sliding window
        {
            let mut samples = self.encrypt_samples.write().await;
            if samples.len() >= 100 {
                samples.remove(0); // FIFO
            }
            samples.push(micros);
        }

        // Update average
        let avg = self.calculate_average(&self.encrypt_samples).await;
        let mut metrics = self.metrics.write().await;
        metrics.avg_encrypt_us = avg;
    }

    pub async fn record_decrypt_time(&self, duration: Duration) {
        let micros = duration.as_micros() as f64;

        {
            let mut samples = self.decrypt_samples.write().await;
            if samples.len() >= 100 {
                samples.remove(0);
            }
            samples.push(micros);
        }

        let avg = self.calculate_average(&self.decrypt_samples).await;
        let mut metrics = self.metrics.write().await;
        metrics.avg_decrypt_us = avg;
    }

    /// Aggiorna security stats
    pub async fn record_replay_blocked(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.replay_attacks_blocked += 1;
    }

    pub async fn record_rate_limit_violation(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.rate_limit_violations += 1;
    }

    pub async fn record_invalid_tag_dropped(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.invalid_tags_dropped += 1;
    }

    pub async fn record_version_mismatch(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.version_mismatches += 1;
    }

    pub async fn record_connection_error(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.connection_errors += 1;
    }

    /// Set transport info
    pub async fn set_transport_mode(&self, mode: &str, nat_type: Option<String>) {
        let mut metrics = self.metrics.write().await;
        metrics.transport_mode = mode.to_string();
        metrics.nat_type = nat_type;
    }

    /// Calcola packet loss rate (approssimato)
    pub async fn update_packet_loss_rate(&self) {
        let metrics_guard = self.metrics.read().await;
        let sent = metrics_guard.packets_sent;
        let received = metrics_guard.packets_received;
        drop(metrics_guard);

        if sent > 0 {
            // Approssimazione semplice (assume traffico bidirezionale simmetrico)
            let expected = sent;
            let actual = received;
            let loss_rate = if expected > actual {
                ((expected - actual) as f64 / expected as f64) * 100.0
            } else {
                0.0
            };

            let mut metrics = self.metrics.write().await;
            metrics.packet_loss_rate = loss_rate.min(100.0);
        }
    }

    /// Get snapshot corrente (zero-copy quando possibile)
    pub async fn get_snapshot(&self) -> ConnectionMetrics {
        let mut snapshot = self.metrics.read().await.clone();

        // Aggiorna uptime in tempo reale
        snapshot.uptime_seconds = self.start_time.elapsed().as_secs();

        snapshot
    }

    /// Reset metrics (clean slate)
    pub async fn reset(&self) {
        *self.metrics.write().await = ConnectionMetrics::default();
        *self.encrypt_samples.write().await = Vec::with_capacity(100);
        *self.decrypt_samples.write().await = Vec::with_capacity(100);
    }

    // Helper: calcola media sliding window
    async fn calculate_average(&self, samples: &Arc<RwLock<Vec<f64>>>) -> f64 {
        let samples_guard = samples.read().await;
        if samples_guard.is_empty() {
            0.0
        } else {
            samples_guard.iter().sum::<f64>() / samples_guard.len() as f64
        }
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new()
    }
}

/// Utility per timing crypto operations
pub struct CryptoTimer {
    start: Instant,
}

impl CryptoTimer {
    pub fn start() -> Self {
        Self {
            start: Instant::now(),
        }
    }

    pub fn elapsed(&self) -> Duration {
        self.start.elapsed()
    }
}

/// Metriche aggregate per debugging (formato human-readable)
#[derive(Debug, Serialize)]
pub struct DebugMetrics {
    pub connection: ConnectionMetrics,
    pub throughput_mbps: f64,
    pub health_score: u8, // 0-100
    pub status: String,
}

impl DebugMetrics {
    pub async fn from_collector(collector: &MetricsCollector) -> Self {
        let metrics = collector.get_snapshot().await;

        // Calcola throughput (MB/s negli ultimi uptime)
        let throughput_mbps = if metrics.uptime_seconds > 0 {
            let total_bytes = (metrics.bytes_sent + metrics.bytes_received) as f64;
            let mbytes = total_bytes / (1024.0 * 1024.0);
            mbytes / metrics.uptime_seconds as f64
        } else {
            0.0
        };

        // Health score euristico (0-100)
        let health_score = Self::calculate_health_score(&metrics);

        let status = if health_score >= 80 {
            "Healthy".into()
        } else if health_score >= 50 {
            "Degraded".into()
        } else {
            "Poor".into()
        };

        Self {
            connection: metrics,
            throughput_mbps,
            health_score,
            status,
        }
    }

    fn calculate_health_score(metrics: &ConnectionMetrics) -> u8 {
        let mut score = 100u8;

        // Penalizza packet loss
        if metrics.packet_loss_rate > 10.0 {
            score = score.saturating_sub(30);
        } else if metrics.packet_loss_rate > 5.0 {
            score = score.saturating_sub(15);
        }

        // Penalizza latenza crypto alta
        if metrics.avg_decrypt_us > 1000.0 {
            // >1ms
            score = score.saturating_sub(20);
        }

        // Penalizza security violations
        let total_violations = metrics.replay_attacks_blocked
            + metrics.rate_limit_violations
            + metrics.invalid_tags_dropped;

        if total_violations > metrics.packets_received / 10 {
            // >10% attack rate
            score = score.saturating_sub(40);
        }

        // Penalizza connection errors
        if metrics.connection_errors > 5 {
            score = score.saturating_sub(25);
        }

        score
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_metrics_basic() {
        let collector = MetricsCollector::new();

        // Record some traffic
        collector.record_packet_sent(100).await;
        collector.record_packet_received(80).await;

        let snapshot = collector.get_snapshot().await;
        assert_eq!(snapshot.packets_sent, 1);
        assert_eq!(snapshot.bytes_sent, 100);
        assert_eq!(snapshot.packets_received, 1);
        assert_eq!(snapshot.bytes_received, 80);
    }

    #[tokio::test]
    async fn test_crypto_timing() {
        let collector = MetricsCollector::new();

        // Simulate encrypt timing
        let timer = CryptoTimer::start();
        tokio::time::sleep(Duration::from_micros(100)).await;
        collector.record_encrypt_time(timer.elapsed()).await;

        let snapshot = collector.get_snapshot().await;
        assert!(snapshot.avg_encrypt_us > 0.0);
    }

    #[tokio::test]
    async fn test_debug_metrics() {
        let collector = MetricsCollector::new();

        // Add some activity
        for _ in 0..20 {
            collector.record_packet_sent(50).await;
            collector.record_packet_received(50).await;
        }
        collector.record_replay_blocked().await;

        let debug = DebugMetrics::from_collector(&collector).await;
        assert_eq!(debug.status, "Healthy");
        assert!(debug.health_score > 50);
    }
}
