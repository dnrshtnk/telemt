use super::*;
use crate::crypto::{AesCtr, SecureRandom};
use crate::stats::Stats;
use crate::stream::CryptoWriter;
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

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
async fn tdd_prefetched_cross_mode_lock_avoids_per_frame_registry_lookup_in_me_to_client_writer() {
    let _guard = lookup_counter_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    let stats = Stats::new();
    let user = format!("middle-cross-mode-lookup-{}", std::process::id());
    let cross_mode_lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);

    crate::proxy::quota_lock_registry::reset_cross_mode_quota_user_lock_lookup_count_for_tests();

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    for idx in 0..8u64 {
        let outcome = process_me_writer_response_with_cross_mode_lock(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0xAB]),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            &user,
            Some(1024),
            0,
            Some(&cross_mode_lock),
            &bytes_me2c,
            20_000 + idx,
            false,
            false,
        )
        .await;

        assert!(outcome.is_ok());
    }

    assert_eq!(
        crate::proxy::quota_lock_registry::cross_mode_quota_user_lock_lookup_count_for_user_for_tests(&user),
        0,
        "prefetched lock path must not re-query lock registry per frame"
    );
    assert_eq!(stats.get_user_total_octets(&user), 8);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 8);
}

#[tokio::test]
async fn control_without_prefetched_lock_still_uses_registry_lookup_path() {
    let _guard = lookup_counter_test_lock()
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());

    let stats = Stats::new();
    let user = format!("middle-cross-mode-lookup-control-{}", std::process::id());

    crate::proxy::quota_lock_registry::reset_cross_mode_quota_user_lock_lookup_count_for_tests();

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let outcome = process_me_writer_response_with_cross_mode_lock(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[0xCD]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        &user,
        Some(1024),
        0,
        None,
        &bytes_me2c,
        20_100,
        false,
        false,
    )
    .await;

    assert!(outcome.is_ok());
    assert_eq!(
        crate::proxy::quota_lock_registry::cross_mode_quota_user_lock_lookup_count_for_user_for_tests(&user),
        1,
        "fallback path without prefetched lock should perform a registry lookup"
    );
}
