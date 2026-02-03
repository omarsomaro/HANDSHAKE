#![cfg(feature = "webrtc")]

use handshacke::config::Config;
use handshacke::transport::webrtc::WebRtcTransport;
use std::sync::Arc;
use tokio::time::{timeout, Duration, Instant};

async fn forward_ice(from: Arc<WebRtcTransport>, to: Arc<WebRtcTransport>, duration: Duration) {
    let deadline = Instant::now() + duration;
    loop {
        if Instant::now() >= deadline {
            break;
        }

        match timeout(Duration::from_millis(200), from.next_ice_candidate()).await {
            Ok(Some(cand)) => {
                let _ = to.add_ice_candidate(&cand).await;
            }
            Ok(None) => {}
            Err(_) => {}
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires ICE/UDP environment; run with `cargo test --test high_level_webrtc -- --ignored`"]
async fn test_webrtc_loopback_data_channel() {
    let mut cfg = Config::from_env();
    cfg.nat_detection_servers.clear();

    let (offerer, offer_sdp) = WebRtcTransport::create_offer(&cfg)
        .await
        .expect("create offer");
    let (answerer, answer_sdp) = WebRtcTransport::connect_with_offer(&cfg, &offer_sdp)
        .await
        .expect("connect with offer");
    offerer
        .set_remote_answer(&answer_sdp)
        .await
        .expect("set remote answer");

    let offerer = Arc::new(offerer);
    let answerer = Arc::new(answerer);

    let fwd_a = tokio::spawn(forward_ice(
        offerer.clone(),
        answerer.clone(),
        Duration::from_secs(2),
    ));
    let fwd_b = tokio::spawn(forward_ice(
        answerer.clone(),
        offerer.clone(),
        Duration::from_secs(2),
    ));
    let _ = tokio::join!(fwd_a, fwd_b);

    tokio::time::sleep(Duration::from_millis(200)).await;

    offerer.send(b"ping").await.expect("offerer send");
    let msg = timeout(Duration::from_secs(10), answerer.recv())
        .await
        .expect("answerer recv timeout")
        .expect("answerer recv");
    assert_eq!(msg, b"ping");

    answerer.send(b"pong").await.expect("answerer send");
    let msg = timeout(Duration::from_secs(10), offerer.recv())
        .await
        .expect("offerer recv timeout")
        .expect("offerer recv");
    assert_eq!(msg, b"pong");
}
