use super::*;
use crate::crypto::{AesCtr, SecureRandom};
use crate::stats::Stats;
use crate::stream::CryptoWriter;
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::{Duration, timeout};

fn make_crypto_writer<W>(writer: W) -> CryptoWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(writer, AesCtr::new(&key, iv), 8 * 1024)
}

#[tokio::test]
async fn positive_quota_limited_me_to_client_write_updates_counters_exactly_once() {
    let stats = Stats::new();
    let user = format!("middle-cross-matrix-positive-{}", std::process::id());
    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[1, 2, 3, 4]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        &user,
        Some(128),
        0,
        &bytes_me2c,
        10_001,
        false,
        false,
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(stats.get_user_total_octets(&user), 4);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 4);
}

#[tokio::test]
async fn negative_held_cross_mode_lock_blocks_quota_limited_me_to_client_path() {
    let stats = Stats::new();
    let user = format!("middle-cross-matrix-negative-{}", std::process::id());
    let held = cross_mode_quota_user_lock_for_tests(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold lock before ME->C call");

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let blocked = timeout(
        Duration::from_millis(25),
        process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0x41]),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            &user,
            Some(256),
            0,
            &bytes_me2c,
            10_002,
            false,
            false,
        ),
    )
    .await;

    assert!(blocked.is_err());
    drop(held_guard);
}

#[tokio::test]
async fn edge_quota_none_bypasses_cross_mode_lock_guard_in_me_to_client_path() {
    let stats = Stats::new();
    let user = format!("middle-cross-matrix-edge-none-{}", std::process::id());
    let held = cross_mode_quota_user_lock_for_tests(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold lock while quota is disabled");

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let outcome = timeout(
        Duration::from_millis(80),
        process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0x11, 0x22]),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            &user,
            None,
            0,
            &bytes_me2c,
            10_003,
            false,
            false,
        ),
    )
    .await
    .expect("quota-none path must not wait on cross-mode lock");

    assert!(outcome.is_ok());
    drop(held_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_same_user_parallel_quota_limited_writes_stay_hard_capped() {
    let stats = Arc::new(Stats::new());
    let user = format!("middle-cross-matrix-adversarial-{}", std::process::id());
    let limit = 64u64;
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let mut tasks = Vec::new();

    for idx in 0..256u64 {
        let stats = Arc::clone(&stats);
        let bytes_me2c = Arc::clone(&bytes_me2c);
        let user = user.clone();
        tasks.push(tokio::spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            process_me_writer_response(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xEE]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                stats.as_ref(),
                &user,
                Some(limit),
                0,
                bytes_me2c.as_ref(),
                11_000 + idx,
                false,
                false,
            )
            .await
        }));
    }

    let mut ok = 0usize;
    for task in tasks {
        match task.await.expect("task must not panic") {
            Ok(_) => ok += 1,
            Err(ProxyError::DataQuotaExceeded { .. }) => {}
            Err(other) => panic!("unexpected error in adversarial parallel case: {other:?}"),
        }
    }

    assert_eq!(ok, limit as usize);
    assert_eq!(stats.get_user_total_octets(&user), limit);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), limit);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_shared_lock_blocks_direct_relay_and_middle_relay_for_same_user() {
    let user = format!("middle-cross-matrix-integration-{}", std::process::id());
    let relay_lock = crate::proxy::relay::cross_mode_quota_user_lock_for_tests(&user);
    let middle_lock = cross_mode_quota_user_lock_for_tests(&user);
    assert!(
        Arc::ptr_eq(&relay_lock, &middle_lock),
        "relay and middle-relay must share the same cross-mode lock identity"
    );

    let held_guard = relay_lock
        .try_lock()
        .expect("test must hold shared cross-mode lock");

    let stats = Stats::new();
    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let middle_blocked = timeout(
        Duration::from_millis(25),
        process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0x92]),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            &user,
            Some(1024),
            0,
            &bytes_me2c,
            12_001,
            false,
            false,
        ),
    )
    .await;
    assert!(middle_blocked.is_err());

    drop(held_guard);

    let middle_ready = timeout(
        Duration::from_millis(250),
        process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0x94]),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            &user,
            Some(1024),
            0,
            &bytes_me2c,
            12_002,
            false,
            false,
        ),
    )
    .await
    .expect("middle path must complete after release");

    assert!(middle_ready.is_ok());
}

#[tokio::test]
async fn light_fuzz_mixed_payload_sizes_with_periodic_lock_holds_keeps_accounting_consistent() {
    let stats = Stats::new();
    let user = format!("middle-cross-matrix-fuzz-{}", std::process::id());
    let bytes_me2c = AtomicU64::new(0);
    let mut seed = 0xC0DE_1234_55AA_9988u64;

    for case in 0..96u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let hold = (seed & 0x03) == 0;
        let mut held_lock = None;
        let maybe_guard = if hold {
            held_lock = Some(cross_mode_quota_user_lock_for_tests(&user));
            Some(
                held_lock
                    .as_ref()
                    .expect("held lock should be present")
                    .try_lock()
                    .expect("cross-mode lock should be acquirable in fuzz round"),
            )
        } else {
            None
        };

        let payload_len = ((seed >> 8) as usize % 8) + 1;
        let payload = vec![(seed & 0xff) as u8; payload_len];
        let before = stats.get_user_total_octets(&user);
        let mut writer = make_crypto_writer(tokio::io::sink());
        let mut frame_buf = Vec::new();

        let timed = timeout(
            Duration::from_millis(20),
            process_me_writer_response(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from(payload),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                &stats,
                &user,
                Some(1024),
                0,
                &bytes_me2c,
                13_000 + case as u64,
                false,
                false,
            ),
        )
        .await;

        if hold {
            assert!(timed.is_err(), "held-lock fuzz round must block within timeout");
            assert_eq!(stats.get_user_total_octets(&user), before);
        } else {
            let done = timed.expect("unheld fuzz round must complete in time");
            assert!(done.is_ok());
        }

        drop(maybe_guard);
        drop(held_lock);
        assert_eq!(bytes_me2c.load(Ordering::Relaxed), stats.get_user_total_octets(&user));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_held_user_lock_does_not_block_other_users_me_to_client_writes() {
    let held_user = format!("middle-cross-matrix-stress-held-{}", std::process::id());
    let free_user = format!("middle-cross-matrix-stress-free-{}", std::process::id());

    let held = cross_mode_quota_user_lock_for_tests(&held_user);
    let held_guard = held
        .try_lock()
        .expect("test must hold lock for blocked user");

    let mut tasks = Vec::new();
    for idx in 0..64u64 {
        let user = free_user.clone();
        tasks.push(tokio::spawn(async move {
            let stats = Stats::new();
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            let bytes_me2c = AtomicU64::new(0);
            process_me_writer_response(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xA0]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                &stats,
                &user,
                Some(1),
                0,
                &bytes_me2c,
                14_000 + idx,
                false,
                false,
            )
            .await
        }));
    }

    timeout(Duration::from_secs(2), async {
        for task in tasks {
            let done = task.await.expect("free-user task must not panic");
            assert!(done.is_ok());
        }
    })
    .await
    .expect("free-user tasks should complete without waiting for held user's lock");

    drop(held_guard);
}
