use anyhow::Result;
use rand::RngCore;
use std::net::{IpAddr, SocketAddr};
use tokio::time::{Duration, Instant};

const DISCOVERY_PREFIX: &[u8] = b"HS_DISCOVERY";
const ACK_PREFIX: &[u8] = b"HS_DISCOVERY_ACK";
const NONCE_LEN: usize = 16;
use tokio::net::UdpSocket;

/// Tenta connessione LAN via broadcast UDP
pub async fn try_lan_broadcast(port: u16) -> Result<(UdpSocket, SocketAddr)> {
    let bind_addr = SocketAddr::from(([0, 0, 0, 0], port));
    let sock = UdpSocket::bind(bind_addr).await?;

    // Imposta broadcast per discovery
    sock.set_broadcast(true)?;

    // Prova a inviare un pacchetto di discovery
    let broadcast_addr = SocketAddr::from(([255, 255, 255, 255], port));
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut discovery_packet = Vec::with_capacity(DISCOVERY_PREFIX.len() + NONCE_LEN);
    discovery_packet.extend_from_slice(DISCOVERY_PREFIX);
    discovery_packet.extend_from_slice(&nonce);

    // Timeout per la risposta
    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        sock.send_to(&discovery_packet, broadcast_addr),
    )
    .await??;

    let peer = listen_for_discovery(&sock, nonce).await?;

    tracing::debug!("LAN discovery broadcast sent on port {}", port);
    Ok((sock, peer))
}

/// Restituisce indirizzi IP locali non-loopback
pub fn get_local_ip_addresses() -> anyhow::Result<Vec<IpAddr>> {
    let mut addrs = Vec::new();
    for iface in if_addrs::get_if_addrs()? {
        let ip = iface.ip();
        if ip.is_loopback() {
            continue;
        }
        match ip {
            IpAddr::V4(_) => addrs.insert(0, ip),
            IpAddr::V6(_) => addrs.push(ip),
        }
    }
    Ok(addrs)
}

/// Ascolta per pacchetti di discovery LAN
pub async fn listen_for_discovery(
    sock: &UdpSocket,
    own_nonce: [u8; NONCE_LEN],
) -> Result<SocketAddr> {
    let mut buf = [0u8; 1024];
    let deadline = Instant::now() + Duration::from_secs(5);

    loop {
        tokio::select! {
            _ = tokio::time::sleep_until(deadline.into()) => {
                return Err(anyhow::anyhow!("LAN discovery timeout"));
            }
            res = sock.recv_from(&mut buf) => {
                let (len, addr) = res?;

        if len >= ACK_PREFIX.len() + NONCE_LEN
            && &buf[..ACK_PREFIX.len()] == ACK_PREFIX
        {
            let ack_nonce = &buf[ACK_PREFIX.len()..ACK_PREFIX.len() + NONCE_LEN];
            if ack_nonce == &own_nonce {
                tracing::debug!("Discovery ACK received from {}", addr);
                return Ok(addr);
            }
        }

        if len >= DISCOVERY_PREFIX.len() + NONCE_LEN
            && &buf[..DISCOVERY_PREFIX.len()] == DISCOVERY_PREFIX
        {
            let their_nonce = &buf[DISCOVERY_PREFIX.len()..DISCOVERY_PREFIX.len() + NONCE_LEN];
            if their_nonce != &own_nonce {
                let mut ack = Vec::with_capacity(ACK_PREFIX.len() + NONCE_LEN);
                ack.extend_from_slice(ACK_PREFIX);
                ack.extend_from_slice(their_nonce);
                let _ = sock.send_to(&ack, addr).await;
            }
            continue;
        }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_lan_discovery_roundtrip_ack() {
        let sock_a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr_a = sock_a.local_addr().unwrap();

        let mut nonce_a = [0u8; NONCE_LEN];
        rand::thread_rng().fill_bytes(&mut nonce_a);

        std::thread::spawn(move || {
            let sender = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
            let mut final_ack = Vec::new();
            final_ack.extend_from_slice(ACK_PREFIX);
            final_ack.extend_from_slice(&nonce_a);

            std::thread::sleep(std::time::Duration::from_millis(50));
            for _ in 0..50 {
                let _ = sender.send_to(&final_ack, addr_a);
                std::thread::sleep(std::time::Duration::from_millis(50));
            }
        });

        let found = listen_for_discovery(&sock_a, nonce_a).await.unwrap();
        assert_eq!(found.ip(), addr_a.ip());
    }
}
