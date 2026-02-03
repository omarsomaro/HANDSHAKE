//! Dandelion Relay - Anti-correlation aggregation for WAN Assist
//!
//! Aggregates multiple requests into batches to prevent timing correlation attacks
//! where a compromised relay could deanonymize which client is talking to which peer.

use std::collections::HashMap;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use rand::Rng;
use crate::protocol_assist_v5::AssistRequestV5;
use std::sync::Arc;

/// Dandelion batch aggregation state
#[derive(Clone)]
pub struct DandelionAggregator {
    // Pending requests per batch tag
    batches: Arc<Mutex<HashMap<[u8; 8], Batch>>>,
}

struct Batch {
    requests: Vec<(AssistRequestV5, SocketAddr)>,
    deadline: Instant,
}

type SocketAddr = std::net::SocketAddr;

impl DandelionAggregator {
    pub fn new() -> Self {
        Self {
            batches: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Add request to batch. Returns true if this was the first request in the batch (sets deadline)
    pub async fn add_request(&self, tag: [u8; 8], request: AssistRequestV5, from: SocketAddr) -> bool {
        let mut batches = self.batches.lock().await;
        
        let is_first = !batches.contains_key(&tag);
        
        let batch = batches.entry(tag).or_insert_with(|| {
            // Random delay 5-15 seconds
            let delay_secs = if cfg!(test) {
                1
            } else {
                rand::thread_rng().gen_range(5..15)
            };
            Batch {
                requests: Vec::new(),
                deadline: Instant::now() + Duration::from_secs(delay_secs),
            }
        });
        
        batch.requests.push((request, from));
        is_first
    }

    /// Get all batches that are ready to be forwarded (deadline passed)
    pub async fn ready_batches(&self) -> Vec<(Vec<(AssistRequestV5, SocketAddr)>, [u8; 8])> {
        let mut batches = self.batches.lock().await;
        let now = Instant::now();
        
        let mut ready = Vec::new();
        let mut to_remove = Vec::new();
        
        for (tag, batch) in batches.iter() {
            if now >= batch.deadline {
                ready.push((batch.requests.clone(), *tag));
                to_remove.push(*tag);
            }
        }
        
        // Clean up sent batches
        for tag in to_remove {
            batches.remove(&tag);
        }
        
        ready
    }

    /// Get current batch size for a tag
    pub async fn batch_size(&self, tag: [u8; 8]) -> usize {
        let batches = self.batches.lock().await;
        batches.get(&tag).map(|b| b.requests.len()).unwrap_or(0)
    }
}

impl Default for DandelionAggregator {
    fn default() -> Self {
        Self::new()
    }
}

/// Generate a dandelion tag from a request or use provided one
pub fn dandelion_tag_for_request(req: &AssistRequestV5) -> [u8; 8] {
    if let Some(tag) = req.dandelion_tag {
        return tag;
    }
    
    // Generate deterministic tag from request_id
    // Use first 8 bytes of SHA256(request_id) for determinism
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(req.request_id);
    let hash = hasher.finalize();
    let mut tag = [0u8; 8];
    tag.copy_from_slice(&hash[..8]);
    tag
}

/// Configuration for Dandelion mode
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum DandelionMode {
    Off,        // No aggregation, immediate forwarding
    LowLatency, // 2-5s delay, small batches
    HighSecurity, // 10-15s delay, larger batches
}

impl DandelionMode {
    pub fn from_env() -> Self {
        match std::env::var("HANDSHACKE_DANDELION_MODE").as_deref() {
            Ok("high") | Ok("highsecurity") => DandelionMode::HighSecurity,
            Ok("low") | Ok("lowlatency") => DandelionMode::LowLatency,
            _ => DandelionMode::Off,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_dandelion_batching() {
        let aggregator = DandelionAggregator::new();
        let tag = [0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF];
        
        // Add multiple requests to same batch
        for i in 0..3 {
            let mut req = AssistRequestV5 {
                request_id: [i; 8],
                blinded_candidates: Default::default(),
                ttl_ms: 5000,
                dandelion_stem: true,
                dandelion_tag: Some(tag),
                mac: [0u8; 32],
            };
            
            // Compute dummy MAC
            let mut mac = [0u8; 32];
            mac[0] = i;
            req.mac = mac;
            
            let port = 1000u16 + i as u16;
            let addr = std::net::SocketAddr::from(([127, 0, 0, 1], port));
            aggregator.add_request(tag, req, addr).await;
        }
        
        // Should be empty immediately (not ready)
        let ready = aggregator.ready_batches().await;
        assert!(ready.is_empty());
        
        // Wait for deadline
        tokio::time::sleep(Duration::from_secs(6)).await;
        
        // Now should be ready
        let ready = aggregator.ready_batches().await;
        assert_eq!(ready.len(), 1);
        assert_eq!(ready[0].0.len(), 3);
    }
}
