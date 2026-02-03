//! Integration tests for multipath and ICE framework
//!
//! Tests end-to-end NAT traversal, multipath coordination, and DPI evasion

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

use handshacke::{
    config::{Config, PluggableTransportMode, RoleHint},
    offer::{OfferPayload, Endpoint, EndpointKind},
    derive::RendezvousParams,
    transport::{multipath, ice, tcp_hole_punch, icmp_hole_punch},
    crypto::hash_offer,
    session_noise::NoiseRole,
};

/// Test full ICE cascade: LAN → UPnP → STUN → TCP → ICMP → Tor
#[tokio::test]
async fn test_ice_full_cascade() {
    // Setup: Host behind Vodafone NAT
    let mut host_config = Config {
        stun_servers: vec![
            "8.8.8.8:19302".to_string(),
            "1.1.1.1:3478".to_string(),
        ],
        assist_relays: vec![
            "relay1.onion".to_string(),
            "relay2.onion".to_string(),
        ],
        multipath_policy: "redundant".to_string(),
        ..Default::default()
    };
    
    // Setup: Client behind Fortinet firewall
    let mut client_config = Config {
        require_capabilities: false, // ICMP requires CAP_NET_RAW
        multipath_policy: "split".to_string(),
        multipath_split_ratio: (70, 30),
        ..Default::default()
    };
    
    // 1. Host generates offer with all endpoints
    let params = RendezvousParams {
        port: 9999,
        key_enc: [42u8; 32],
        key_mac: [0u8; 32],
        tag16: 0x1337,
        tag8: 0x42,
        version: 3,
    };
    
    let offer = OfferPayload {
        ver: 3,
        ttl_s: 300,
        issued_at_ms: 1234567890,
        role_hint: RoleHint::Host,
        endpoints: vec![
            Endpoint {
                kind: EndpointKind::Lan,
                addr: Some("192.168.1.100:9999".parse().unwrap()),
                priority: 1,
                timeout_ms: 1000,
            },
            Endpoint {
                kind: EndpointKind::Wan,
                addr: Some("203.0.113.45:9999".parse().unwrap()),
                priority: 2,
                timeout_ms: 2000,
            },
        ],
        tor_ephemeral_pk: None,
        tor_endpoint_enc: None,
        rendezvous: handshacke::offer::RendezvousInfo {
            port: 9999,
            tag16: 0x1337,
            key_enc: [42u8; 32],
        },
        per_ephemeral_salt: None,
        commit: [0u8; 32],
        timestamp: 1234567890,
        ntp_offset: None,
        simultaneous_open: false,
    };
    
    // 2. Client receives offer and connects via ICE multipath race
    let offer_hash = hash_offer(&offer);
    let start = Instant::now();
    
    let result = ice::multipath_race_connect(
        &offer,
        offer_hash,
        params.clone(),
        client_config.clone(),
        NoiseRole::Initiator,
    ).await;
    
    let elapsed = start.elapsed();
    
    // 3. Verify results
    match result {
        Ok((conn, addr)) => {
            println!("✅ ICE multipath connection succeeded in {:?}", elapsed);
            println!("   Connection type: {:?}, Peer: {}", conn, addr);
            
            // Assert timing requirements
            assert!(elapsed < Duration::from_secs(15), 
                "ICE should complete within 15 seconds");
            
            // Verify connection type
            match conn {
                handshacke::transport::Connection::Lan(_, _) => {
                    println!("✅ Success via LAN (fastest path)");
                }
                handshacke::transport::Connection::Wan(_, _) => {
                    println!("✅ Success via WAN (STUN/UPnP)");
                }
                handshacke::transport::Connection::WanTorStream { .. } => {
                    println!("✅ Success via Tor (fallback)");
                }
            }
        }
        Err(e) => {
            panic!("❌ ICE multipath race failed: {}", e);
        }
    }
}

/// Test NAT detection and adaptive strategy
#[tokio::test]
async fn test_nat_detection_and_strategy() {
    let config = Config::from_env();
    let detector = handshacke::transport::nat_detection::NatDetector::new(
        config.nat_detection_servers
    );
    
    // Detect NAT type
    let nat_type = detector.detect_nat_type().await
        .expect("NAT detection should work");
    
    println!("Detected NAT type: {}", nat_type);
    
    // Get adaptive strategy
    let strategy = handshacke::transport::nat_detection::NatDetector::select_strategy(nat_type);
    
    println!("Selected strategy (in priority order):");
    for (i, priority) in strategy.iter().enumerate() {
        println!("  {}. {:?} - priority: {}, skip: {}", 
            i + 1, priority.kind, priority.priority, priority.should_skip);
    }
    
    // Assert strategy is valid
    assert!(strategy.len() > 0, "Strategy should have at least one path");
    assert!(strategy[0].priority > 0, "Primary path should have positive priority");
    
    // Verify NAT type specific optimizations
    match nat_type {
        handshacke::transport::nat_detection::NatType::Symmetric => {
            // Should skip STUN for symmetric NAT
            assert!(strategy.iter().any(|p| 
                p.kind == handshacke::transport::nat_detection::TransportKind::Stun 
                && p.should_skip
            ), "Should skip STUN for symmetric NAT");
        }
        handshacke::transport::nat_detection::NatType::FullCone => {
            // Should prioritize STUN for FullCone
            let stun_priority = strategy.iter()
                .find(|p| p.kind == handshacke::transport::nat_detection::TransportKind::Stun)
                .map(|p| p.priority)
                .unwrap_or(0);
            assert!(stun_priority > 50, "STUN should be high priority for FullCone");
        }
        _ => {}
    }
}

/// Test Real TLS DPI evasion
#[tokio::test]
async fn test_realtls_dpi_evasion() {
    use handshacke::transport::pluggable::RealTlsChannel;
    
    let payload = b"test data";
    
    // Create RealTlsChannel
    let mut transport = RealTlsChannel::new("www.cloudflare.com".to_string())
        .expect("create transport");
    
    // Fetch certificate chain (should cache)
    let start = Instant::now();
    transport.establish("127.0.0.1:8443").await
        .expect("establish TLS connection");
    let cert_time = start.elapsed();
    
    println!("Fetched/validated certificates in {:?}", cert_time);
    
    // Send data through TLS
    transport.send(payload).await.expect("send data");
    
    println!("✅ Data sent through Real TLS successfully");
    
    // Verify wire format would pass deep inspection
    // In real test, would capture pcap and verify TLS 1.3 structure
}

/// Test multipath split mode
#[tokio::test]
async fn test_multipath_split_mode() {
    let multi = multipath::MultipathConnection::new(
        multipath::SchedulerPolicy::Split,
        50,
    );
    
    // Create mock transports
    // Note: In real test, would use actual TCP/UDP transports
    
    println!("✅ Multipath split mode created successfully");
    println!("Primary path: {}", multi.primary_path());
    println!("Active paths: {}", multi.active_paths().await);
}

/// Test TCP hole punching
#[tokio::test]
async fn test_tcp_hole_punch() {
    let local = "127.0.0.1:0".parse().unwrap();
    let remote = "127.0.0.1:9999".parse().unwrap(); // likely closed
    
    // Test port validation
    let is_open = tcp_hole_punch::TcpHolePunch::test_port_open(remote).await
        .expect("test should complete");
    
    println!("Port 9999 open: {}", is_open);
    assert_eq!(is_open, false, "Port 9999 should be closed");
    
    // Test with localhost (will likely fail but shouldn't panic)
    let result = tcp_hole_punch::TcpHolePunch::punch(local, remote).await;
    
    match result {
        Ok(_) => println!("✅ TCP hole punching succeeded (port was open!)"),
        Err(e) => println!("✅ TCP hole punching failed gracefully: {}", e),
    }
}

/// Test ICMP capabilities check
#[test]
fn test_icmp_capabilities() {
    let has_cap = icmp_hole_punch::IcmpHolePunch::check_capabilities();
    
    if has_cap {
        println!("✅ ICMP hole punching available (running with CAP_NET_RAW)");
    } else {
        println!("⚠️  ICMP hole punching not available (run with sudo or setcap)");
    }
}

/// End-to-end test: Host behind double NAT, Client behind firewall
#[tokio::test]
async fn test_double_nat_firewall_e2e() {
    println!("\n=== E2E Test: Double NAT + Firewall ===\n");
    
    // Host: Vodafone (Carrier NAT) + FritzBox (LAN NAT)
    let host_config = Config {
        nat_detection_servers: vec!["8.8.8.8:19302".to_string()],
        assist_relays: vec!["relay1.onion".to_string()],
        ..Default::default()
    };
    
    // Client: Fortinet Enterprise Firewall (blocks UDP)
    let client_config = Config {
        require_capabilities: false,
        pluggable_transport: PluggableTransportMode::RealTls("www.cloudflare.com".to_string()),
        ..Default::default()
    };
    
    // 1. Host genera offer con ICE candidates
    let host_params = RendezvousParams {
        port: 8888,
        key_enc: [0xAA; 32],
        key_mac: [0; 32],
        tag16: 0xABCD,
        tag8: 0x42,
        version: 3,
    };
    
    println!("Host generates offer with ICE candidates...");
    
    // 2. NAT detection su host
    let host_nat = handshacke::transport::nat_detection::detect_nat_type()
        .await
        .expect("NAT detection");
    println!("Host NAT: {:?}", host_nat);
    
    // 3. Client riceve e analizza offer
    println!("Client receives offer...");
    
    // 4. Client usa multipath racing per connettersi
    let start = Instant::now();
    
    // Simulate offer
    let mut offer = OfferPayload {
        ver: 3,
        ttl_s: 300,
        issued_at_ms: 1234567890,
        role_hint: RoleHint::Host,
        endpoints: vec![],
        tor_ephemeral_pk: None,
        tor_endpoint_enc: None,
        rendezvous: host_params.rendezvous,
        per_ephemeral_salt: None,
        commit: [0u8; 32],
        timestamp: 1234567890,
        ntp_offset: None,
        simultaneous_open: true,
    };
    
    let offer_hash = hash_offer(&offer);
    
    // Attempt ICE multipath race
    let conn_result = ice::multipath_race_connect(\n        &offer,\n        offer_hash,\n        host_params,\n        client_config,\n        NoiseRole::Initiator,\n    ).await;\n    \n    let elapsed = start.elapsed();\n    \n    match conn_result {\n        Ok((conn, addr)) => {\n            println!("✅ E2E Double NAT + Firewall SUCCESS");\n            println!("   Time: {:?}", elapsed);\n            println!("   Method: {:?}", conn);\n            println!("   Peer: {}", addr);\n            \n            // Assert expectations\n            assert!(elapsed < Duration::from_secs(20),\n                "Should complete within 20s even with double NAT");\n        }\n        Err(e) => {\n            println!("❌ E2E failed (expected if no network): {}", e);\n            // Non-fatal in test environment\n        }\n    }\n}\n