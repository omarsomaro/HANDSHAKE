//! Multipath connection coordination for simultaneous transport
//!
//! Supports redundant and split mode for reliability and bandwidth aggregation

use anyhow::{Result, bail};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

use crate::transport::Connection;

/// Multipath connection scheduler policy
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum SchedulerPolicy {
    /// Send identical data on all paths, receive from first
    Redundant,
    /// Split data 70/30 for bandwidth aggregation
    Split,
}

impl Default for SchedulerPolicy {
    fn default() -> Self {
        Self::Redundant
    }
}

/// Path routing policy for data distribution
#[derive(Debug, Clone)]
pub enum RoutingPolicy {
    /// Send to primary path only
    Primary,
    /// Send to all active paths (redundant)
    All,
    /// Split based on ratio
    Split {
        primary_ratio: f32, // 0.0-1.0
    },
}

/// Path metadata and quality metrics
#[derive(Debug, Clone)]
pub struct PathMetadata {
    pub name: String,
    pub rtt_ms: u64,
    pub loss_rate: f32, // 0.0-1.0
    pub active: bool,
    pub created_at: std::time::Instant,
}

impl Default for PathMetadata {
    fn default() -> Self {
        Self {
            name: "default".to_string(),
            rtt_ms: 100,
            loss_rate: 0.0,
            active: true,
            created_at: std::time::Instant::now(),
        }
    }
}

impl PathMetadata {
    pub fn score(&self) -> f32 {
        if !self.active {
            return 0.0;
        }
        // Higher RTT and loss rate = lower score
        let rtt_penalty = 1.0 / (1.0 + (self.rtt_ms as f32 / 100.0));
        let loss_penalty = 1.0 - self.loss_rate.min(1.0);
        rtt_penalty * loss_penalty
    }
}

/// Handle for a single transport path
#[allow(dead_code)]
pub struct TransportHandle {
    transport: Connection,
    metadata: Arc<Mutex<PathMetadata>>,
}

impl TransportHandle {
    pub fn new(transport: Connection, metadata: PathMetadata) -> Self {
        Self {
            transport,
            metadata: Arc::new(Mutex::new(metadata)),
        }
    }
    
    pub async fn metadata(&self) -> PathMetadata {
        self.metadata.lock().await.clone()
    }
    
    pub async fn update_metadata<F>(&self, f: F)
    where
        F: FnOnce(&mut PathMetadata),
    {
        let mut meta = self.metadata.lock().await;
        f(&mut meta);
    }
}

/// Multipath connection coordinator
#[allow(dead_code)]
pub struct MultipathConnection {
    paths: Vec<TransportHandle>,
    scheduler: SchedulerPolicy,
    primary_idx: usize,
    switch_threshold_ms: u64,
}

impl MultipathConnection {
    /// Create new multipath connection
    pub fn new(scheduler: SchedulerPolicy, switch_threshold_ms: u64) -> Self {
        Self {
            paths: Vec::new(),
            scheduler,
            primary_idx: 0,
            switch_threshold_ms,
        }
    }
    
    /// Add a new path to the connection
    pub fn add_path(&mut self, transport: Connection, metadata: PathMetadata) {
        let handle = TransportHandle::new(transport, metadata);
        self.paths.push(handle);
        
        // Set primary if this is the first path
        if self.paths.len() == 1 {
            self.primary_idx = 0;
        }
    }
    
    /// Update path quality metrics
    pub async fn update_path_quality(
        &mut self,
        path_idx: usize,
        rtt_ms: u64,
        loss_rate: f32,
    ) -> Result<()> {
        if path_idx >= self.paths.len() {
            bail!("Path index {} out of bounds", path_idx);
        }
        
        let handle = &self.paths[path_idx];
        handle.update_metadata(|meta| {
            meta.rtt_ms = rtt_ms;
            meta.loss_rate = loss_rate.min(1.0).max(0.0);
        }).await;
        
        // Auto-switch to better path if needed
        if path_idx != self.primary_idx {
            let primary_score = self.paths[self.primary_idx].metadata().await.score();
            let new_score = self.paths[path_idx].metadata().await.score();
            
            // Switch if significantly better
            if new_score > primary_score * 1.2 {
                tracing::info!("Switching primary path from {} to {}", self.primary_idx, path_idx);
                self.primary_idx = path_idx;
            }
        }
        
        Ok(())
    }
    
    /// Send data using multipath coordination
    pub async fn send_multipath(
        &self,
        data: &[u8],
        routing: &RoutingPolicy,
    ) -> Result<()> {
        if self.paths.is_empty() {
            bail!("No active paths");
        }
        
        // Single path optimization
        if self.paths.len() == 1 {
            return self.send_single_path(0, data).await;
        }
        
        match self.scheduler {
            SchedulerPolicy::Redundant => {
                match routing {
                    RoutingPolicy::All => {
                        // Send to all active paths
                        let mut futures = Vec::new();
                        for (idx, path) in self.paths.iter().enumerate() {
                            let meta = path.metadata().await;
                            if meta.active {
                                futures.push(self.send_single_path(idx, data));
                            }
                        }
                        
                        // Wait for at least one success
                        let results = futures::future::join_all(futures).await;
                        if let Some(Ok(_)) = results.iter().find(|r| r.is_ok()) {
                            Ok(())
                        } else {
                            bail!("All paths failed: {:?}", results)
                        }
                    }
                    _ => {
                        // Default to primary
                        self.send_single_path(self.primary_idx, data).await
                    }
                }
            }
            SchedulerPolicy::Split => {
                self.send_split(data, routing).await
            }
        }
    }
    
    /// Send to a single path
    async fn send_single_path(&self, path_idx: usize, data: &[u8]) -> Result<()> {
        // Placeholder - in real implementation, this would use the transport
        tracing::debug!("Sending {} bytes to path {}", data.len(), path_idx);
        Ok(())
    }
    
    /// Split data using FEC for bandwidth aggregation
    async fn send_split(&self, data: &[u8], routing: &RoutingPolicy) -> Result<()> {
        let primary_ratio = match routing {
            RoutingPolicy::Split { primary_ratio } => *primary_ratio,
            _ => 0.7, // Default 70/30 split
        };
        
        let primary_len = (data.len() as f32 * primary_ratio) as usize;
        let primary_chunk = &data[..primary_len.min(data.len())];
        let secondary_chunk = &data[primary_len.min(data.len())..];
        
        // Send primary chunk on primary path
        if !primary_chunk.is_empty() {
            self.send_single_path(self.primary_idx, primary_chunk).await?;
        }
        
        // Send secondary chunk on best backup path
        if !secondary_chunk.is_empty() {
            if let Some(backup_idx) = self.find_best_backup_path().await {
                self.send_single_path(backup_idx, secondary_chunk).await?;
            }
        }
        
        Ok(())
    }
    
    /// Find best backup path (lowest RTT, highest score)
    async fn find_best_backup_path(&self) -> Option<usize> {
        let mut best_idx = None;
        let mut best_score = 0.0;
        
        for (idx, path) in self.paths.iter().enumerate() {
            if idx == self.primary_idx {
                continue;
            }
            
            let meta = path.metadata().await;
            if !meta.active {
                continue;
            }
            
            let score = meta.score();
            if score > best_score {
                best_score = score;
                best_idx = Some(idx);
            }
        }
        
        best_idx
    }
    
    /// Receive data from any path
    pub async fn recv_multipath(
        &self,
        buf: &mut [u8],
    ) -> Result<(usize, usize)> { // (bytes_received, path_index)
        if self.paths.is_empty() {
            bail!("No active paths");
        }
        
        // Single path optimization
        if self.paths.len() == 1 {
            return self.recv_single_path(0, buf).await.map(|n| (n, 0));
        }

        // Try active paths in priority order with a timeout per path.
        let mut indices = (0..self.paths.len()).collect::<Vec<_>>();
        indices.sort_by_key(|idx| if *idx == self.primary_idx { 0 } else { 1 });

        for idx in indices {
            let meta = self.paths[idx].metadata().await;
            if !meta.active {
                continue;
            }

            let recv_result = tokio::time::timeout(
                Duration::from_secs(30),
                self.recv_single_path(idx, buf),
            )
            .await;

            match recv_result {
                Ok(Ok(n)) => return Ok((n, idx)),
                Ok(Err(e)) => {
                    tracing::debug!("Receive failed on path {}: {}", idx, e);
                    continue;
                }
                Err(_) => {
                    tracing::debug!("Receive timeout on path {}", idx);
                    continue;
                }
            }
        }

        bail!("Receive timeout on all paths")
    }
    
    /// Receive from single path
    async fn recv_single_path(&self, path_idx: usize, _buf: &mut [u8]) -> Result<usize> {
        // Placeholder - in real implementation, this would use the transport
        tracing::debug!("Receiving from path {}", path_idx);
        Ok(0)
    }
    
    /// Get number of active paths
    pub async fn active_paths(&self) -> usize {
        let mut count = 0;
        for path in &self.paths {
            let meta = path.metadata().await;
            if meta.active {
                count += 1;
            }
        }
        count
    }
    
    /// Get primary path index
    pub fn primary_path(&self) -> usize {
        self.primary_idx
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_scheduler_policy() {
        let policy = SchedulerPolicy::Redundant;
        assert_eq!(policy, SchedulerPolicy::Redundant);
    }
    
    #[tokio::test]
    async fn test_path_metadata_score() {
        let meta = PathMetadata {
            name: "test".to_string(),
            rtt_ms: 50,
            loss_rate: 0.0,
            active: true,
            created_at: std::time::Instant::now(),
        };
        
        let score = meta.score();
        assert!(score > 0.6); // Low RTT, no loss = high score
    }
    
    #[tokio::test]
    async fn test_multipath_basic() {
        let multi = MultipathConnection::new(SchedulerPolicy::Redundant, 50);
        assert_eq!(multi.active_paths().await, 0);
        assert_eq!(multi.primary_path(), 0);
    }
}
