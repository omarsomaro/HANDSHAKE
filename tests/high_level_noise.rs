use anyhow::anyhow;
use handshacke::crypto::MAX_TCP_FRAME_BYTES;
use handshacke::session_noise::{classic_noise_params, run_noise_upgrade_io, NoiseRole};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[tokio::test]
async fn test_noise_upgrade_in_memory_roundtrip() {
    let (a_to_b_tx, a_to_b_rx) = mpsc::channel::<Vec<u8>>(16);
    let (b_to_a_tx, b_to_a_rx) = mpsc::channel::<Vec<u8>>(16);

    let a_send = {
        let tx = a_to_b_tx.clone();
        move |data: Vec<u8>| {
            let tx = tx.clone();
            async move {
                tx.send(data).await.map_err(|_| anyhow!("channel closed"))?;
                Ok(())
            }
        }
    };
    let a_recv = {
        let rx = Arc::new(Mutex::new(b_to_a_rx));
        move || {
            let rx = Arc::clone(&rx);
            async move {
                let mut guard = rx.lock().await;
                guard.recv().await.ok_or_else(|| anyhow!("channel closed"))
            }
        }
    };
    let b_send = {
        let tx = b_to_a_tx.clone();
        move |data: Vec<u8>| {
            let tx = tx.clone();
            async move {
                tx.send(data).await.map_err(|_| anyhow!("channel closed"))?;
                Ok(())
            }
        }
    };
    let b_recv = {
        let rx = Arc::new(Mutex::new(a_to_b_rx));
        move || {
            let rx = Arc::clone(&rx);
            async move {
                let mut guard = rx.lock().await;
                guard.recv().await.ok_or_else(|| anyhow!("channel closed"))
            }
        }
    };

    let base_key = [9u8; 32];
    let tag16 = 0x2222;
    let tag8 = 0x42;

    let a_task = tokio::spawn(async move {
        let params = classic_noise_params().expect("noise params");
        run_noise_upgrade_io(
            NoiseRole::Initiator,
            a_send,
            a_recv,
            &base_key,
            tag16,
            tag8,
            params,
            MAX_TCP_FRAME_BYTES,
        )
        .await
    });

    let b_task = tokio::spawn(async move {
        let params = classic_noise_params().expect("noise params");
        run_noise_upgrade_io(
            NoiseRole::Responder,
            b_send,
            b_recv,
            &base_key,
            tag16,
            tag8,
            params,
            MAX_TCP_FRAME_BYTES,
        )
        .await
    });

    let a_key = a_task
        .await
        .expect("initiator task")
        .expect("initiator key");
    let b_key = b_task
        .await
        .expect("responder task")
        .expect("responder key");
    assert_eq!(a_key, b_key, "noise session keys must match");
}
