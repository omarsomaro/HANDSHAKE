use std::net::SocketAddr;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{Instant, Duration};
use lru_time_cache::LruCache;

pub mod rate_limiting;
pub mod time_validation;

pub use rate_limiting::{TokenBucketLimiter, DoSProtector, DoSMetrics, RateLimiterMetrics};
pub use time_validation::TimeValidator;

/// Rate limiter token bucket con cleanup LRU per protezione DoS
#[derive(Clone)]
pub struct RateLimiter {
    buckets: Arc<RwLock<LruCache<SocketAddr, TokenBucket>>>,
    bucket_capacity: f64,
    refill_per_sec: f64,
}

impl RateLimiter {
    pub fn new(capacity: usize, max_requests: u32, time_window: Duration) -> Self {
        let window_secs = time_window.as_secs_f64().max(0.001);
        Self {
            buckets: Arc::new(RwLock::new(LruCache::with_capacity(capacity))),
            bucket_capacity: max_requests as f64,
            refill_per_sec: max_requests as f64 / window_secs,
        }
    }

    /// Controlla se un indirizzo puo inviare un altro messaggio
    pub async fn check(&self, addr: SocketAddr) -> bool {
        self.check_cost(addr, 1.0).await
    }

    pub async fn check_cost(&self, addr: SocketAddr, cost: f64) -> bool {
        if cost <= 0.0 {
            tracing::error!("Invalid rate limit cost {}", cost);
            return false;
        }
        let now = Instant::now();
        let mut cache = self.buckets.write().await;

        if cache.get(&addr).is_none() {
            cache.insert(addr, TokenBucket::new(self.bucket_capacity, now));
        }

        let bucket = match cache.get_mut(&addr) {
            Some(b) => b,
            None => return false,
        };

        bucket.refill(self.refill_per_sec, self.bucket_capacity, now);
        if bucket.tokens >= cost {
            bucket.tokens -= cost;
            true
        } else {
            false
        }
    }
}

#[derive(Clone)]
struct TokenBucket {
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            last_refill: now,
        }
    }

    fn refill(&mut self, refill_per_sec: f64, capacity: f64, now: Instant) {
        let elapsed = now.duration_since(self.last_refill).as_secs_f64();
        self.tokens = (self.tokens + elapsed * refill_per_sec).min(capacity);
        self.last_refill = now;
    }
}

/// Early drop di pacchetti basato su tag - filtro velocissimo pre-parsing
pub fn early_drop_packet(packet: &[u8], expected_tag16: u16, expected_tag8: u8) -> bool {
    // Controllo velocissimo: il pacchetto inizia con il nostro tag?
    // Questo filtra il 99% del traffico non desiderato prima di qualsiasi parsing.
    if packet.len() < 3 {
        return true;
    }
    let tag16 = u16::from_le_bytes([packet[0], packet[1]]);
    if tag16 != expected_tag16 {
        return true;
    }

    let third = packet[2];
    if third == crate::crypto::PROTOCOL_VERSION_V1 {
        return false;
    }

    if packet.len() < 4 {
        return true;
    }
    let tag8 = third;
    if tag8 != expected_tag8 {
        return true;
    }
    let version = packet[3];
    if version < crate::crypto::MIN_SUPPORTED_VERSION || version > crate::crypto::MAX_SUPPORTED_VERSION {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    use crate::crypto::{ClearPayload, seal, now_ms, now_us, serialize_cipher_packet};

    #[tokio::test]
    async fn test_rate_limiter() {
        let limiter = RateLimiter::new(100, 3, Duration::from_secs(1));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 1234);

        // Prime 3 richieste dovrebbero passare
        assert!(limiter.check(addr).await);
        assert!(limiter.check(addr).await);
        assert!(limiter.check(addr).await);

        // Quarta richiesta dovrebbe essere rifiutata
        assert!(!limiter.check(addr).await);

        // Dopo aver aspettato, dovrebbe resettare
        tokio::time::sleep(Duration::from_secs(2)).await;
        assert!(limiter.check(addr).await);
    }

    #[test]
    fn test_early_drop_packet() {
        let expected_tag = 0x1337u16;
        
        // Pacchetto V1 con tag corretto
        let good_v1_packet = [0x37, 0x13, 0x01, 0x02, 0x03];
        assert!(!early_drop_packet(&good_v1_packet, expected_tag, 0x42));

        // Pacchetto V2 con tag16 + tag8 corretti
        let good_v2_packet = [0x37, 0x13, 0x42, 0x02, 0x03];
        assert!(!early_drop_packet(&good_v2_packet, expected_tag, 0x42));

        // Pacchetto V2 con tag8 errato
        let wrong_tag8_packet = [0x37, 0x13, 0x99, 0x02, 0x03];
        assert!(early_drop_packet(&wrong_tag8_packet, expected_tag, 0x42));

        // Pacchetto con tag sbagliato
        let bad_packet = [0x42, 0x42, 0x01, 0x02, 0x03];
        assert!(early_drop_packet(&bad_packet, expected_tag, 0x42));

        // Pacchetto troppo corto
        let short_packet = [0x13];
        assert!(early_drop_packet(&short_packet, expected_tag, 0x42));

        // Pacchetto vuoto
        let empty_packet = [];
        assert!(early_drop_packet(&empty_packet, expected_tag, 0x42));
    }

    #[test]
    fn test_early_drop_with_serialized_packet() {
        let key = [42u8; 32];
        let tag = 0x1337u16;
        let payload = ClearPayload {
            ts_ms: now_ms(),
            seq: now_us(),
            data: b"hello".to_vec(),
        };

        let pkt = seal(&key, tag, 0x42, &payload).unwrap();
        let bytes = serialize_cipher_packet(&pkt).unwrap();
        assert!(!early_drop_packet(&bytes, tag, 0x42));
    }
}
