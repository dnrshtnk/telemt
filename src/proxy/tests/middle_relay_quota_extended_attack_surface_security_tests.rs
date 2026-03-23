use super::*;
use crate::crypto::{AesCtr, SecureRandom};
use crate::error::ProxyError;
use crate::stats::Stats;
use crate::stream::CryptoWriter;
use bytes::Bytes;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock, Mutex};
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};

fn make_crypto_writer<W>(writer: W) -> CryptoWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(writer, AesCtr::new(&key, iv), 8 * 1024)
}

fn lookup_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn positive_me2c_quota_counts_bytes_exactly_once() {
    let _guard = lookup_test_lock().lock().unwrap();
    let stats = Stats::new();
    let user = format!("quota-middle-ext-positive-{}", std::process::id());
    let lock = Arc::new(AsyncMutex::new(()));

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let result = process_me_writer_response_with_cross_mode_lock(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[1, 2, 3, 4, 5]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        &user,
        Some(64),
        0,
        Some(&lock),
        &bytes_me2c,
        70_001,
        false,
        false,
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(stats.get_user_total_octets(&user), 5);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 5);
}

#[tokio::test]
async fn negative_held_crossmode_lock_blocks_me2c_write() {
    let _guard = lookup_test_lock().lock().unwrap();
    let stats = Stats::new();
    let user = format!("quota-middle-ext-negative-{}", std::process::id());

    let lock = Arc::new(AsyncMutex::new(()));
    let _held = lock.try_lock().expect("lock must be held");

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let blocked = timeout(
        Duration::from_millis(25),
        process_me_writer_response_with_cross_mode_lock(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0xFE]),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            &user,
            Some(16),
            0,
            Some(&lock),
            &bytes_me2c,
            70_101,
            false,
            false,
        ),
    )
    .await;

    assert!(blocked.is_err());
    assert_eq!(stats.get_user_total_octets(&user), 0);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn edge_zero_quota_zero_payload_is_fail_closed() {
    let _guard = lookup_test_lock().lock().unwrap();
    let stats = Stats::new();
    let user = format!("quota-middle-ext-edge-{}", std::process::id());

    let lock = Arc::new(AsyncMutex::new(()));
    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let result = process_me_writer_response_with_cross_mode_lock(
        MeResponse::Data {
            flags: 0,
            data: Bytes::new(),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        &user,
        Some(0),
        0,
        Some(&lock),
        &bytes_me2c,
        70_201,
        false,
        false,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
    assert_eq!(stats.get_user_total_octets(&user), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_parallel_me2c_race_falls_back_to_quota_error() {
    let _guard = lookup_test_lock().lock().unwrap();
    let stats = Arc::new(Stats::new());
    let user = format!("quota-middle-ext-blackhat-{}", std::process::id());
    let quota = 64u64;
    let lock = Arc::new(AsyncMutex::new(()));
    let bytes_me2c = Arc::new(AtomicU64::new(0));

    let mut set = JoinSet::new();
    for i in 0..256u64 {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        let lock = Arc::clone(&lock);
        let bytes_me2c = Arc::clone(&bytes_me2c);

        set.spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            let payload = vec![((i & 0xFF) as u8); (i % 4 + 1) as usize];

            process_me_writer_response_with_cross_mode_lock(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from(payload),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                stats.as_ref(),
                &user,
                Some(quota),
                0,
                Some(&lock),
                bytes_me2c.as_ref(),
                70_301 + i,
                false,
                false,
            )
            .await
        });
    }

    let mut succeeded = 0usize;
    while let Some(done) = set.join_next().await {
        match done.expect("task must not panic") {
            Ok(_) => succeeded += 1,
            Err(ProxyError::DataQuotaExceeded { .. }) => {}
            Err(other) => panic!("unexpected error {other:?}"),
        }
    }

    assert_eq!(stats.get_user_total_octets(&user), bytes_me2c.load(Ordering::Relaxed));
    assert!(stats.get_user_total_octets(&user) <= quota);
    assert!(succeeded <= quota as usize);
}

#[tokio::test]
async fn integration_shared_prefetched_lock_blocks_then_releases_writer() {
    let stats = Stats::new();
    let user = format!("quota-middle-ext-integration-{}", std::process::id());
    let lock = Arc::new(AsyncMutex::new(()));
    let held = lock
        .try_lock()
        .expect("integration test must hold prefetched lock first");

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let blocked = timeout(
        Duration::from_millis(25),
        process_me_writer_response_with_cross_mode_lock(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0xA1]),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            &user,
            Some(8),
            0,
            Some(&lock),
            &bytes_me2c,
            70_360,
            false,
            false,
        ),
    )
    .await;
    assert!(blocked.is_err());

    drop(held);

    let after_release = timeout(
        Duration::from_millis(150),
        process_me_writer_response_with_cross_mode_lock(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0xA2]),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            &user,
            Some(8),
            0,
            Some(&lock),
            &bytes_me2c,
            70_361,
            false,
            false,
        ),
    )
    .await
    .expect("writer should progress once the shared lock is released");

    assert!(after_release.is_ok());
}

#[tokio::test]
async fn light_fuzz_small_payloads_toggle_lock_state_stays_consistent() {
    let _guard = lookup_test_lock().lock().unwrap();
    let stats = Stats::new();
    let user = format!("quota-middle-ext-fuzz-{}", std::process::id());
    let mut seed = 0xCAFE_BABE_1234u64;
    let bytes_me2c = AtomicU64::new(0);

    for case in 0..48u32 {
        seed ^= seed << 5;
        seed ^= seed >> 12;
        seed ^= seed << 13;
        let hold = (seed & 0x1) == 0;

        let lock = Arc::new(AsyncMutex::new(()));
        let maybe_guard = if hold {
            Some(lock.try_lock().unwrap())
        } else {
            None
        };

        let mut writer = make_crypto_writer(tokio::io::sink());
        let mut frame_buf = Vec::new();

        let result = timeout(
            Duration::from_millis(30),
            process_me_writer_response_with_cross_mode_lock(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from(vec![(seed & 0xFF) as u8; ((seed as usize % 5) + 1)]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                &stats,
                &user,
                Some(128),
                0,
                Some(&lock),
                &bytes_me2c,
                70_401 + case as u64,
                false,
                false,
            ),
        )
        .await;

        if hold {
            assert!(result.is_err());
        } else {
            assert!(result.unwrap().is_ok());
        }

        drop(maybe_guard);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_free_users_during_held_user_lock_maintains_liveness() {
    let _guard = lookup_test_lock().lock().unwrap();
    let held = Arc::new(AsyncMutex::new(()));
    let _held_guard = held.try_lock().unwrap();

    let mut set = JoinSet::new();
    for i in 0..48u64 {
        set.spawn(async move {
            let stats = Stats::new();
            let user = format!("quota-middle-ext-stress-free-{i}");
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            let bytes_me2c = AtomicU64::new(0);
            let free_lock = Arc::new(AsyncMutex::new(()));

            process_me_writer_response_with_cross_mode_lock(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xEE]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                &stats,
                &user,
                Some(1),
                0,
                Some(&free_lock),
                &bytes_me2c,
                70_500 + i,
                false,
                false,
            )
            .await
        });
    }

    timeout(Duration::from_secs(2), async {
        while let Some(task) = set.join_next().await {
            task.unwrap().unwrap();
        }
    })
    .await
    .unwrap();
}
