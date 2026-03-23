use super::relay_bidirectional;
use crate::stats::Stats;
use crate::stream::BufferPool;
use std::sync::{Arc, Mutex};
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::sync::{Barrier, watch};
use tokio::time::{Duration, Instant, timeout};

fn quota_test_guard() -> impl Drop {
    super::quota_user_lock_test_scope()
}

fn percentile_index(len: usize, percentile: usize) -> usize {
    ((len * percentile) / 100).min(len.saturating_sub(1))
}

#[tokio::test]
async fn micro_benchmark_pipeline_release_to_delivery_latency_stays_bounded() {
    let _guard = quota_test_guard();

    let rounds = 64usize;
    let user = format!("relay-pipeline-latency-single-{}", std::process::id());
    let mut samples_ms = Vec::with_capacity(rounds);

    for round in 0..rounds {
        let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
        let held_guard = held
            .try_lock()
            .expect("test must hold shared cross-mode lock before round");

        let stats = Arc::new(Stats::new());
        let (mut client_peer, relay_client) = duplex(1024);
        let (relay_server, mut server_peer) = duplex(1024);
        let (client_reader, client_writer) = tokio::io::split(relay_client);
        let (server_reader, server_writer) = tokio::io::split(relay_server);

        let relay_user = user.clone();
        let relay_stats = Arc::clone(&stats);
        let relay_task = tokio::spawn(async move {
            relay_bidirectional(
                client_reader,
                client_writer,
                server_reader,
                server_writer,
                256,
                256,
                &relay_user,
                relay_stats,
                Some(2048),
                Arc::new(BufferPool::new()),
            )
            .await
        });

        server_peer
            .write_all(&[(round as u8) ^ 0xA5])
            .await
            .expect("server write should queue before release");

        let release_at = Instant::now();
        drop(held_guard);

        let mut one = [0u8; 1];
        timeout(Duration::from_millis(450), client_peer.read_exact(&mut one))
            .await
            .expect("client must receive queued byte after release")
            .expect("queued byte read must succeed");
        samples_ms.push(release_at.elapsed().as_millis() as u64);

        drop(client_peer);
        drop(server_peer);

        let relay_result = timeout(Duration::from_secs(1), relay_task)
            .await
            .expect("relay task must complete")
            .expect("relay task must not panic");
        assert!(relay_result.is_ok());
    }

    samples_ms.sort_unstable();
    let p50_ms = samples_ms[percentile_index(samples_ms.len(), 50)];
    let p95_ms = samples_ms[percentile_index(samples_ms.len(), 95)];

    assert!(
        p50_ms <= 45,
        "single-flow release latency p50 must stay bounded; p50_ms={p50_ms}, samples={samples_ms:?}"
    );
    assert!(
        p95_ms <= 130,
        "single-flow release latency p95 must stay bounded; p95_ms={p95_ms}, samples={samples_ms:?}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_128_waiter_pipeline_release_latency_p95_stays_bounded() {
    let _guard = quota_test_guard();

    let waiters = 128usize;
    let user = format!("relay-pipeline-latency-fanout-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold shared lock before fanout release benchmark");

    let ready_barrier = Arc::new(Barrier::new(waiters + 1));
    let release_at = Arc::new(Mutex::new(None::<Instant>));
    let (release_tx, release_rx) = watch::channel(false);
    let mut tasks = Vec::with_capacity(waiters);

    for idx in 0..waiters {
        let user = user.clone();
        let barrier = Arc::clone(&ready_barrier);
        let release_at = Arc::clone(&release_at);
        let mut release_rx = release_rx.clone();

        tasks.push(tokio::spawn(async move {
            let stats = Arc::new(Stats::new());
            let (mut client_peer, relay_client) = duplex(512);
            let (relay_server, mut server_peer) = duplex(512);
            let (client_reader, client_writer) = tokio::io::split(relay_client);
            let (server_reader, server_writer) = tokio::io::split(relay_server);

            let relay_user = user;
            let relay_stats = Arc::clone(&stats);
            let relay_task = tokio::spawn(async move {
                relay_bidirectional(
                    client_reader,
                    client_writer,
                    server_reader,
                    server_writer,
                    256,
                    256,
                    &relay_user,
                    relay_stats,
                    Some(2048),
                    Arc::new(BufferPool::new()),
                )
                .await
            });

            server_peer
                .write_all(&[(idx as u8) ^ 0x5A])
                .await
                .expect("fanout server write should queue before release");

            barrier.wait().await;
            release_rx
                .changed()
                .await
                .expect("release signal should remain available");

            let started = {
                let guard = release_at.lock().unwrap_or_else(|poison| poison.into_inner());
                guard.expect("release timestamp must be populated before signal")
            };

            let mut one = [0u8; 1];
            timeout(Duration::from_millis(900), client_peer.read_exact(&mut one))
                .await
                .expect("fanout waiter must receive queued byte after release")
                .expect("fanout waiter read must succeed");

            drop(client_peer);
            drop(server_peer);

            let relay_result = timeout(Duration::from_secs(2), relay_task)
                .await
                .expect("fanout relay task must complete")
                .expect("fanout relay task must not panic");
            assert!(relay_result.is_ok());

            started.elapsed().as_millis() as u64
        }));
    }

    ready_barrier.wait().await;
    {
        let mut guard = release_at.lock().unwrap_or_else(|poison| poison.into_inner());
        *guard = Some(Instant::now());
    }
    drop(held_guard);
    release_tx
        .send(true)
        .expect("release broadcast must succeed");

    let mut samples_ms = Vec::with_capacity(waiters);
    timeout(Duration::from_secs(8), async {
        for task in tasks {
            let elapsed = task.await.expect("fanout waiter must not panic");
            samples_ms.push(elapsed);
        }
    })
    .await
    .expect("fanout benchmark must complete in bounded time");

    samples_ms.sort_unstable();
    let p50_ms = samples_ms[percentile_index(samples_ms.len(), 50)];
    let p95_ms = samples_ms[percentile_index(samples_ms.len(), 95)];
    let max_ms = *samples_ms.last().unwrap_or(&0);

    assert!(
        p50_ms <= 120,
        "fanout release latency p50 must stay bounded; p50_ms={p50_ms}, p95_ms={p95_ms}, max_ms={max_ms}"
    );
    assert!(
        p95_ms <= 260,
        "fanout release latency p95 must stay bounded; p50_ms={p50_ms}, p95_ms={p95_ms}, max_ms={max_ms}"
    );
    assert!(
        max_ms <= 700,
        "fanout release latency max must stay bounded; p50_ms={p50_ms}, p95_ms={p95_ms}, max_ms={max_ms}"
    );
}