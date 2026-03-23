use super::*;
use crate::crypto::{AesCtr, SecureRandom};
use crate::stats::Stats;
use crate::stream::CryptoWriter;
use bytes::Bytes;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
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

fn lookup_counter_test_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

#[tokio::test]
async fn positive_prefetched_cross_mode_lock_multi_frame_accounting_is_exact() {
    let _guard = lookup_counter_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    let stats = Stats::new();
    let user = format!("quota-extreme-positive-{}", std::process::id());
    let lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    crate::proxy::quota_lock_registry::reset_cross_mode_quota_user_lock_lookup_count_for_tests();

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    for idx in 0..12u64 {
        let payload = vec![0x5A; ((idx % 4) + 1) as usize];
        let result = process_me_writer_response_with_cross_mode_lock(
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
            Some(512),
            0,
            Some(&lock),
            &bytes_me2c,
            31_000 + idx,
            false,
            false,
        )
        .await;

        assert!(result.is_ok());
    }

    assert_eq!(
        crate::proxy::quota_lock_registry::cross_mode_quota_user_lock_lookup_count_for_user_for_tests(&user),
        0,
        "prefetched lock path must avoid hot-path registry lookups"
    );
    assert_eq!(
        stats.get_user_total_octets(&user),
        bytes_me2c.load(Ordering::Relaxed),
        "forensics and quota accounting must remain synchronized"
    );
}

#[tokio::test]
async fn negative_held_prefetched_lock_blocks_writer_without_accounting_mutation() {
    let _guard = lookup_counter_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    let stats = Stats::new();
    let user = format!("quota-extreme-negative-{}", std::process::id());
    let lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold lock before calling ME->C writer");

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let blocked = timeout(
        Duration::from_millis(25),
        process_me_writer_response_with_cross_mode_lock(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[1, 2, 3]),
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
            31_100,
            false,
            false,
        ),
    )
    .await;

    assert!(blocked.is_err());
    assert_eq!(stats.get_user_total_octets(&user), 0);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 0);

    drop(held_guard);
}

#[tokio::test]
async fn edge_zero_quota_and_zero_payload_is_fail_closed() {
    let _guard = lookup_counter_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    let stats = Stats::new();
    let user = format!("quota-extreme-edge-{}", std::process::id());
    let lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);

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
        31_200,
        false,
        false,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
    assert_eq!(stats.get_user_total_octets(&user), 0);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_blackhat_parallel_quota_race_never_overshoots_soft_cap() {
    let _guard = lookup_counter_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    let stats = Arc::new(Stats::new());
    let user = format!("quota-extreme-blackhat-{}", std::process::id());
    let quota = 80u64;
    let overshoot = 7u64;
    let soft_limit = quota + overshoot;
    let lock = Arc::new(crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user));
    let bytes_me2c = Arc::new(AtomicU64::new(0));

    let mut set = JoinSet::new();
    for idx in 0..256u64 {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        let lock = Arc::clone(&lock);
        let bytes_me2c = Arc::clone(&bytes_me2c);

        set.spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            let len = ((idx % 5) + 1) as usize;
            let payload = vec![0xAA; len];

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
                overshoot,
                Some(&lock),
                bytes_me2c.as_ref(),
                31_300 + idx,
                false,
                false,
            )
            .await
        });
    }

    while let Some(done) = set.join_next().await {
        match done.expect("task must not panic") {
            Ok(_) | Err(ProxyError::DataQuotaExceeded { .. }) => {}
            Err(other) => panic!("unexpected error variant under black-hat race: {other:?}"),
        }
    }

    let total = stats.get_user_total_octets(&user);
    assert!(
        total <= soft_limit,
        "parallel adversarial race must stay under soft cap"
    );
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), total);
}

#[tokio::test]
async fn integration_without_prefetched_lock_uses_registry_lookup_path() {
    let _guard = lookup_counter_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    let stats = Stats::new();
    let user = format!("quota-extreme-integration-{}", std::process::id());
    crate::proxy::quota_lock_registry::reset_cross_mode_quota_user_lock_lookup_count_for_tests();

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    for idx in 0..3u64 {
        let result = process_me_writer_response_with_cross_mode_lock(
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
            Some(16),
            0,
            None,
            &bytes_me2c,
            31_400 + idx,
            false,
            false,
        )
        .await;

        assert!(result.is_ok());
    }

    assert_eq!(
        crate::proxy::quota_lock_registry::cross_mode_quota_user_lock_lookup_count_for_user_for_tests(&user),
        3,
        "control path should perform one lock-registry lookup per call"
    );
}

#[tokio::test]
async fn light_fuzz_quota_matrix_preserves_fail_closed_accounting() {
    let _guard = lookup_counter_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    let stats = Stats::new();
    let user = format!("quota-extreme-fuzz-{}", std::process::id());
    let lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let bytes_me2c = AtomicU64::new(0);
    let mut seed = 0xA11C_55EE_2026_0323u64;

    for idx in 0..512u64 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let quota = 24 + (seed & 0x3f);
        let overshoot = (seed >> 13) & 0x0f;
        let len = ((seed >> 19) & 0x07) + 1;

        let mut writer = make_crypto_writer(tokio::io::sink());
        let mut frame_buf = Vec::new();
        let before = stats.get_user_total_octets(&user);

        let result = process_me_writer_response_with_cross_mode_lock(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from(vec![0x11; len as usize]),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            &user,
            Some(quota),
            overshoot,
            Some(&lock),
            &bytes_me2c,
            31_500 + idx,
            false,
            false,
        )
        .await;

        let after = stats.get_user_total_octets(&user);
        if result.is_ok() {
            assert!(after >= before);
        } else {
            assert!(matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
            assert_eq!(after, before);
        }
        assert_eq!(bytes_me2c.load(Ordering::Relaxed), after);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_prefetched_lock_high_fanout_exact_quota_success_count() {
    let _guard = lookup_counter_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    let stats = Arc::new(Stats::new());
    let user = format!("quota-extreme-stress-{}", std::process::id());
    let quota = 96u64;
    let lock: Arc<AsyncMutex<()>> = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let bytes_me2c = Arc::new(AtomicU64::new(0));

    crate::proxy::quota_lock_registry::reset_cross_mode_quota_user_lock_lookup_count_for_tests();

    let mut set = JoinSet::new();
    for idx in 0..384u64 {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        let lock = Arc::clone(&lock);
        let bytes_me2c = Arc::clone(&bytes_me2c);

        set.spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            process_me_writer_response_with_cross_mode_lock(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xFF]),
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
                31_600 + idx,
                false,
                false,
            )
            .await
        });
    }

    let mut success = 0usize;
    while let Some(done) = set.join_next().await {
        match done.expect("task must not panic") {
            Ok(_) => success += 1,
            Err(ProxyError::DataQuotaExceeded { .. }) => {}
            Err(other) => panic!("unexpected error variant in stress fanout: {other:?}"),
        }
    }

    assert_eq!(success, quota as usize);
    assert_eq!(stats.get_user_total_octets(&user), quota);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), quota);
    assert_eq!(
        crate::proxy::quota_lock_registry::cross_mode_quota_user_lock_lookup_count_for_user_for_tests(&user),
        0,
        "stress prefetched path must not use lock registry lookups"
    );
}
