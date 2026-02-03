//! Real TLS transport for DPI evasion
//!
//! Fetches real certificate chains from target domains and performs
//! actual TLS handshakes to evade deep inspection.

use anyhow::{Context, Result, bail};
use rustls::{ClientConfig, RootCertStore};
use rustls::pki_types::ServerName;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::{TlsConnector, client::TlsStream};
use std::collections::HashMap;
use tokio::sync::Mutex;

/// Cached certificate chain
#[derive(Clone)]
pub struct CertChain {
    pub domain: Arc<str>,
    pub fetched_at: Instant,
    pub certificates: Vec<Vec<u8>>,
}

/// Global certificate cache (24h TTL)
static CERT_CACHE: once_cell::sync::Lazy<Arc<Mutex<HashMap<String, CertChain>>>> =
    once_cell::sync::Lazy::new(|| Arc::new(Mutex::new(HashMap::new())));

/// Real TLS transport for DPI evasion
pub struct RealTlsChannel {
    stream: Option<TlsStream<TcpStream>>,
    domain: Arc<str>,
}

impl RealTlsChannel {
    /// Create new RealTlsChannel with domain
    pub fn new(domain: impl Into<Arc<str>>) -> Self {
        Self {
            domain: domain.into(),
            stream: None,
        }
    }
    
    /// Build rustls client config
    fn build_tls_config() -> Result<Arc<ClientConfig>> {
        let mut root_store = RootCertStore::empty();
        root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        
        Ok(Arc::new(ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth()))
    }
    
    /// Fetch certificate chain from domain (cached for 24h)
    async fn fetch_cert_chain(domain: Arc<str>) -> Result<CertChain> {
        let cache = CERT_CACHE.lock().await;
        
        // Check cache
        if let Some(cached) = cache.get(domain.as_ref()) {
            if cached.fetched_at.elapsed() < Duration::from_secs(86400) {
                return Ok(cached.clone());
            }
        }
        drop(cache);
        
        // Connect to domain and perform handshake to get cert chain
        tracing::debug!("Fetching certificate chain for {}", domain);
        let addr = format!("{}:443", domain);
        let tcp_stream = TcpStream::connect(&addr).await
            .context("TCP connect to domain")?;
        
        let config = Self::build_tls_config()?;
        let connector = TlsConnector::from(config);
        let domain_name = ServerName::try_from(domain.to_string())
            .map_err(|e| anyhow::anyhow!("Invalid domain name: {}", e))?;
        
        // Perform full handshake to get peer certificates
        let tls_stream = connector.connect(domain_name, tcp_stream).await
            .context("TLS handshake")?;
        
        // Extract certificates
        let (_, conn) = tls_stream.get_ref();
        let certificates: Vec<Vec<u8>> = conn.peer_certificates()
            .map(|certs| certs.iter().map(|cert| cert.as_ref().to_vec()).collect())
            .unwrap_or_default();
        
        if certificates.is_empty() {
            bail!("No certificates received from {}", domain);
        }
        
        let cert_chain = CertChain {
            domain: Arc::clone(&domain),
            fetched_at: Instant::now(),
            certificates,
        };
        
        // Store in cache
        let mut cache = CERT_CACHE.lock().await;
        cache.insert(domain.to_string(), cert_chain.clone());
        
        Ok(cert_chain)
    }
    
    /// Perform real TLS handshake
    pub async fn establish<T: Into<Arc<str>>>(&mut self, peer_addr: T) -> Result<()> {
        let peer_addr = peer_addr.into();
        
        // Fetch certificate chain first (validates domain is reachable)
        Self::fetch_cert_chain(Arc::clone(&self.domain)).await
            .context("fetch certificate chain")?;
        
        // Connect to peer
        let tcp_stream = TcpStream::connect(peer_addr.as_ref()).await
            .context("TCP connect to peer")?;
        
        // Disable TCP_NODELAY for handshake (batch packets)
        tcp_stream.set_nodelay(false)?;
        
        // Perform TLS handshake
        let config = Self::build_tls_config()?;
        let connector = TlsConnector::from(config);
        let domain_name = ServerName::try_from(self.domain.to_string())
            .map_err(|e| anyhow::anyhow!("Invalid domain name: {}", e))?;
        
        let tls_stream = connector.connect(domain_name, tcp_stream).await
            .context("TLS handshake with peer")?;
        
        // Enable TCP_NODELAY after handshake (efficient data transfer)
        let (tcp, _) = tls_stream.get_ref();
        tcp.set_nodelay(true)?;
        
        self.stream = Some(tls_stream);
        
        tracing::info!("Real TLS established to peer {} (SNI: {})", peer_addr, self.domain);
        Ok(())
    }
}

// Implement TransportChannel trait
#[async_trait::async_trait]
impl crate::transport::pluggable::TransportChannel for RealTlsChannel {
    async fn read_message(&mut self) -> Result<Vec<u8>> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| anyhow::anyhow!("TLS not established"))?;
        
        // Read length prefix
        let mut len_buf = [0u8; 4];
        stream.read_exact(&mut len_buf).await?;
        let len = u32::from_be_bytes(len_buf) as usize;
        
        // Read message
        let mut msg = vec![0u8; len];
        stream.read_exact(&mut msg).await?;
        Ok(msg)
    }

    async fn write_message(&mut self, data: &[u8]) -> Result<()> {
        let stream = self.stream.as_mut()
            .ok_or_else(|| anyhow::anyhow!("TLS not established"))?;
        
        // Write length prefix + data
        let len = data.len() as u32;
        stream.write_all(&len.to_be_bytes()).await?;
        stream.write_all(data).await?;
        stream.flush().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    fn install_crypto_provider() {
        static INSTALL: Once = Once::new();
        INSTALL.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }
    
    #[tokio::test]
    async fn test_fetch_cert_chain() {
        install_crypto_provider();
        let domains = vec![
            "www.cloudflare.com",
            "api.google.com",
            "www.google.com",
        ];
        
        for domain in domains {
            match RealTlsChannel::fetch_cert_chain(Arc::from(domain)).await {
                Ok(chain) => {
                    println!("Fetched {} certificates for {}", chain.certificates.len(), domain);
                    assert!(!chain.certificates.is_empty());
                }
                Err(e) => {
                    println!("Failed to fetch certs for {}: {}", domain, e);
                }
            }
        }
    }
}

// Re-export for integration
pub use RealTlsChannel as TlsChannel;
