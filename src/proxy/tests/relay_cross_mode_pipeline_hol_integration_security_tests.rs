use super::relay_bidirectional;
use crate::stats::Stats;
use crate::stream::BufferPool;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};
use tokio::time::{Duration, timeout};

fn quota_test_guard() -> impl Drop {
    super::quota_user_lock_test_scope()
}

#[tokio::test]
async fn negative_same_user_pipeline_stalls_while_middle_lock_is_held() {
    let _guard = quota_test_guard();

    let user = format!("relay-pipeline-stall-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold shared cross-mode lock");

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
            Some(1024),
            Arc::new(BufferPool::new()),
        )
        .await
    });

    server_peer
        .write_all(&[0xA1])
        .await
        .expect("server write should enqueue while relay is stalled");

    let mut one = [0u8; 1];
    let blocked_read = timeout(Duration::from_millis(40), client_peer.read_exact(&mut one)).await;
    assert!(
        blocked_read.is_err(),
        "same-user relay must remain blocked while cross-mode lock is held"
    );

    drop(held_guard);

    timeout(Duration::from_millis(400), client_peer.read_exact(&mut one))
        .await
        .expect("blocked relay must resume after cross-mode lock release")
        .expect("resumed relay must deliver queued byte");
    assert_eq!(one, [0xA1]);

    drop(client_peer);
    drop(server_peer);

    let relay_result = timeout(Duration::from_secs(1), relay_task)
        .await
        .expect("relay task must complete")
        .expect("relay task must not panic");
    assert!(relay_result.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_other_user_pipeline_progresses_while_blocked_user_is_stalled() {
    let _guard = quota_test_guard();

    let blocked_user = format!("relay-pipeline-blocked-{}", std::process::id());
    let free_user = format!("relay-pipeline-free-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&blocked_user);
    let held_guard = held
        .try_lock()
        .expect("test must hold blocked user's shared cross-mode lock");

    let stats_blocked = Arc::new(Stats::new());
    let stats_free = Arc::new(Stats::new());

    let (mut blocked_client, blocked_relay_client) = duplex(1024);
    let (blocked_relay_server, mut blocked_server) = duplex(1024);
    let (blocked_client_reader, blocked_client_writer) = tokio::io::split(blocked_relay_client);
    let (blocked_server_reader, blocked_server_writer) = tokio::io::split(blocked_relay_server);

    let (mut free_client, free_relay_client) = duplex(1024);
    let (free_relay_server, mut free_server) = duplex(1024);
    let (free_client_reader, free_client_writer) = tokio::io::split(free_relay_client);
    let (free_server_reader, free_server_writer) = tokio::io::split(free_relay_server);

    let blocked_task = {
        let user = blocked_user.clone();
        let stats = Arc::clone(&stats_blocked);
        tokio::spawn(async move {
            relay_bidirectional(
                blocked_client_reader,
                blocked_client_writer,
                blocked_server_reader,
                blocked_server_writer,
                256,
                256,
                &user,
                stats,
                Some(1024),
                Arc::new(BufferPool::new()),
            )
            .await
        })
    };

    let free_task = {
        let user = free_user.clone();
        let stats = Arc::clone(&stats_free);
        tokio::spawn(async move {
            relay_bidirectional(
                free_client_reader,
                free_client_writer,
                free_server_reader,
                free_server_writer,
                256,
                256,
                &user,
                stats,
                Some(1024),
                Arc::new(BufferPool::new()),
            )
            .await
        })
    };

    blocked_server
        .write_all(&[0xB1])
        .await
        .expect("blocked user server write should queue");
    free_server
        .write_all(&[0xC1])
        .await
        .expect("free user server write should queue");

    let mut blocked_buf = [0u8; 1];
    let mut free_buf = [0u8; 1];

    let blocked_stalled = timeout(
        Duration::from_millis(40),
        blocked_client.read_exact(&mut blocked_buf),
    )
    .await;
    assert!(
        blocked_stalled.is_err(),
        "blocked user must remain stalled while its lock is held"
    );

    timeout(Duration::from_millis(250), free_client.read_exact(&mut free_buf))
        .await
        .expect("free user must make progress while other user is blocked")
        .expect("free user read must succeed");
    assert_eq!(free_buf, [0xC1]);

    drop(held_guard);

    timeout(Duration::from_millis(400), blocked_client.read_exact(&mut blocked_buf))
        .await
        .expect("blocked user must resume after release")
        .expect("blocked user resumed read must succeed");
    assert_eq!(blocked_buf, [0xB1]);

    drop(blocked_client);
    drop(blocked_server);
    drop(free_client);
    drop(free_server);

    assert!(
        timeout(Duration::from_secs(1), blocked_task)
            .await
            .expect("blocked relay task must complete")
            .expect("blocked relay task must not panic")
            .is_ok()
    );
    assert!(
        timeout(Duration::from_secs(1), free_task)
            .await
            .expect("free relay task must complete")
            .expect("free relay task must not panic")
            .is_ok()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_jittered_hold_release_cycles_preserve_pipeline_liveness() {
    let _guard = quota_test_guard();

    let mut seed = 0x5EED_C0DE_2026_0323u64;
    for round in 0..24u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let hold_ms = 2 + (seed % 10);
        let user = format!("relay-pipeline-fuzz-{}-{round}", std::process::id());
        let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
        let held_guard = held
            .try_lock()
            .expect("test must hold lock during fuzz round");

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
                Some(1024),
                Arc::new(BufferPool::new()),
            )
            .await
        });

        server_peer
            .write_all(&[0xD1])
            .await
            .expect("server write should queue in fuzz round");

        let mut one = [0u8; 1];
        let stalled = timeout(Duration::from_millis(30), client_peer.read_exact(&mut one)).await;
        assert!(stalled.is_err(), "held phase must stall same-user relay");

        tokio::time::sleep(Duration::from_millis(hold_ms)).await;
        drop(held_guard);

        timeout(Duration::from_millis(400), client_peer.read_exact(&mut one))
            .await
            .expect("released phase must resume same-user relay")
            .expect("released phase read must succeed");
        assert_eq!(one, [0xD1]);

        drop(client_peer);
        drop(server_peer);

        assert!(
            timeout(Duration::from_secs(1), relay_task)
                .await
                .expect("fuzz relay task must complete")
                .expect("fuzz relay task must not panic")
                .is_ok()
        );
    }
}