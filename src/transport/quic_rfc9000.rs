#[cfg(feature = "quic")]
mod imp {
    use anyhow::{anyhow, bail, Result};
    use quinn::{ClientConfig, Endpoint, ServerConfig};
    use rcgen::generate_simple_self_signed;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
    use rustls::RootCertStore;
    use std::net::SocketAddr;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    #[derive(Clone)]
    pub struct QuinnTransport {
        endpoint: Arc<Endpoint>,
        connection: Arc<quinn::Connection>,
        send: Arc<Mutex<Option<quinn::SendStream>>>,
        recv: Arc<Mutex<Option<quinn::RecvStream>>>,
        peer: SocketAddr,
    }

    impl QuinnTransport {
        pub async fn connect(
            addr: SocketAddr,
            server_name: &str,
            client_config: ClientConfig,
        ) -> Result<Self> {
            let bind: SocketAddr = "[::]:0".parse()?;
            let mut endpoint = Endpoint::client(bind)?;
            endpoint.set_default_client_config(client_config);

            let connection = endpoint
                .connect(addr, server_name)?
                .await
                .map_err(|e| anyhow!("QUIC connect failed: {}", e))?;

            Ok(Self {
                endpoint: Arc::new(endpoint),
                connection: Arc::new(connection),
                send: Arc::new(Mutex::new(None)),
                recv: Arc::new(Mutex::new(None)),
                peer: addr,
            })
        }

        pub async fn accept(bind: SocketAddr, server_config: ServerConfig) -> Result<Self> {
            let endpoint = Endpoint::server(server_config, bind)?;
            let connecting = endpoint
                .accept()
                .await
                .ok_or_else(|| anyhow!("QUIC endpoint closed"))?;
            let connection = connecting
                .await
                .map_err(|e| anyhow!("QUIC accept failed: {}", e))?;
            let peer = connection.remote_address();

            Ok(Self {
                endpoint: Arc::new(endpoint),
                connection: Arc::new(connection),
                send: Arc::new(Mutex::new(None)),
                recv: Arc::new(Mutex::new(None)),
                peer,
            })
        }

        pub async fn send(&self, data: &[u8]) -> Result<()> {
            // Lazy-open a local bidirectional stream on first send.
            let mut guard = self.send.lock().await;
            if guard.is_none() {
                let (send, _recv) = self
                    .connection
                    .open_bi()
                    .await
                    .map_err(|e| anyhow!("QUIC open_bi failed: {}", e))?;
                *guard = Some(send);
            }

            let send = guard
                .as_mut()
                .ok_or_else(|| anyhow!("QUIC send stream missing"))?;
            crate::transport::framing::write_frame(send, data).await
        }

        pub async fn recv(&self) -> Result<Vec<u8>> {
            // Lazy-accept a peer-initiated bidirectional stream on first receive.
            let mut guard = self.recv.lock().await;
            if guard.is_none() {
                let (_send, recv) = self
                    .connection
                    .accept_bi()
                    .await
                    .map_err(|e| anyhow!("QUIC accept_bi failed: {}", e))?;
                *guard = Some(recv);
            }

            let recv = guard
                .as_mut()
                .ok_or_else(|| anyhow!("QUIC recv stream missing"))?;
            crate::transport::framing::read_frame(recv).await
        }

        pub fn peer_addr(&self) -> SocketAddr {
            self.peer
        }

        pub fn local_addr(&self) -> Result<SocketAddr> {
            self.endpoint
                .local_addr()
                .map_err(|e| anyhow!("QUIC local_addr failed: {}", e))
        }
    }

    pub fn make_self_signed_configs(
        server_name: &str,
    ) -> Result<(ServerConfig, ClientConfig, Vec<u8>)> {
        let cert = generate_simple_self_signed(vec![server_name.to_string()])?;
        let cert_der = cert.serialize_der()?;
        let key_der = cert.serialize_private_key_der();

        let cert_chain = vec![CertificateDer::from(cert_der.clone())];
        let key = PrivateKeyDer::from(PrivatePkcs8KeyDer::from(key_der));
        let server_config = ServerConfig::with_single_cert(cert_chain.clone(), key)?;

        let mut roots = RootCertStore::empty();
        roots.add(cert_chain[0].clone())?;
        let client_config = ClientConfig::with_root_certificates(roots.into())?;

        Ok((server_config, client_config, cert_der))
    }

    pub fn make_client_config_from_der(cert_der: &[u8]) -> Result<ClientConfig> {
        let mut roots = RootCertStore::empty();
        let cert = CertificateDer::from(cert_der.to_vec());
        if roots.add(cert).is_err() {
            bail!("Invalid certificate DER");
        }
        let client_config = ClientConfig::with_root_certificates(roots.into())?;
        Ok(client_config)
    }
}

#[cfg(not(feature = "quic"))]
mod imp {
    use anyhow::{bail, Result};
    use std::net::SocketAddr;

    #[derive(Clone, Debug)]
    pub struct ClientConfig;

    #[derive(Clone, Debug)]
    pub struct ServerConfig;

    #[derive(Clone)]
    pub struct QuinnTransport;

    impl QuinnTransport {
        pub async fn connect(
            _addr: SocketAddr,
            _server_name: &str,
            _client_config: ClientConfig,
        ) -> Result<Self> {
            bail!("quic feature disabled; enable with --features quic")
        }

        pub async fn accept(_bind: SocketAddr, _server_config: ServerConfig) -> Result<Self> {
            bail!("quic feature disabled; enable with --features quic")
        }

        pub async fn send(&self, _data: &[u8]) -> Result<()> {
            bail!("quic feature disabled; enable with --features quic")
        }

        pub async fn recv(&self) -> Result<Vec<u8>> {
            bail!("quic feature disabled; enable with --features quic")
        }

        pub fn peer_addr(&self) -> SocketAddr {
            SocketAddr::from(([0, 0, 0, 0], 0))
        }

        pub fn local_addr(&self) -> Result<SocketAddr> {
            bail!("quic feature disabled; enable with --features quic")
        }
    }

    pub fn make_self_signed_configs(
        _server_name: &str,
    ) -> Result<(ServerConfig, ClientConfig, Vec<u8>)> {
        bail!("quic feature disabled; enable with --features quic")
    }

    pub fn make_client_config_from_der(_cert_der: &[u8]) -> Result<ClientConfig> {
        bail!("quic feature disabled; enable with --features quic")
    }
}

pub use imp::*;
