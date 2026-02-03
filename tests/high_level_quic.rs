#![cfg(feature = "quic")]

use handshacke::transport::quic_rfc9000::{make_self_signed_configs, QuinnTransport};
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};

fn unused_udp_port() -> u16 {
    let sock = UdpSocket::bind("127.0.0.1:0").expect("bind udp");
    sock.local_addr().expect("local addr").port()
}

#[tokio::test]
async fn test_quinn_transport_loopback() {
    let port = unused_udp_port();
    let bind = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);

    let (server_config, client_config, _cert) =
        make_self_signed_configs("localhost").expect("self-signed config");

    let server_task =
        tokio::spawn(async move { QuinnTransport::accept(bind, server_config).await });

    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let client = QuinnTransport::connect(bind, "localhost", client_config)
        .await
        .expect("quic connect");

    client.send(b"ping").await.expect("client send");

    let server = server_task
        .await
        .expect("server task")
        .expect("quic accept");

    let msg = server.recv().await.expect("server recv");
    assert_eq!(msg, b"ping");

    server.send(b"pong").await.expect("server send");
    let msg = client.recv().await.expect("client recv");
    assert_eq!(msg, b"pong");
}
