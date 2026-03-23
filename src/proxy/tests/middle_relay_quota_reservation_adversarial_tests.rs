use super::*;
use crate::crypto::{AesCtr, SecureRandom};
use crate::stats::Stats;
use crate::stream::CryptoWriter;
use bytes::Bytes;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::task::{Context, Poll};
use tokio::io::AsyncWrite;
use tokio::task::JoinSet;

fn make_crypto_writer<W>(writer: W) -> CryptoWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(writer, AesCtr::new(&key, iv), 8 * 1024)
}

struct FailingWriter;

impl AsyncWrite for FailingWriter {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        Poll::Ready(Err(std::io::Error::other("forced writer failure")))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

struct FailAfterBudgetWriter {
    remaining: usize,
    written: usize,
}

impl FailAfterBudgetWriter {
    fn new(remaining: usize) -> Self {
        Self {
            remaining,
            written: 0,
        }
    }
}

impl AsyncWrite for FailAfterBudgetWriter {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::result::Result<usize, std::io::Error>> {
        if self.remaining == 0 {
            return Poll::Ready(Err(std::io::Error::other("forced short-write exhaustion")));
        }

        let n = self.remaining.min(buf.len());
        self.remaining -= n;
        self.written += n;
        Poll::Ready(Ok(n))
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<std::result::Result<(), std::io::Error>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test]
async fn positive_exact_quota_boundary_allows_last_frame_and_blocks_next() {
    let stats = Stats::new();
    let user = "quota-boundary-user";
    let bytes_me2c = AtomicU64::new(0);

    stats.add_user_octets_from(user, 5);

    let mut writer_one = make_crypto_writer(tokio::io::sink());
    let mut frame_buf_one = Vec::new();
    let first = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[1, 2, 3]),
        },
        &mut writer_one,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf_one,
        &stats,
        user,
        Some(8),
        0,
        &bytes_me2c,
        7101,
        false,
        false,
    )
    .await;

    assert!(first.is_ok(), "frame that reaches boundary must be allowed");
    assert_eq!(stats.get_user_total_octets(user), 8);

    let mut writer_two = make_crypto_writer(tokio::io::sink());
    let mut frame_buf_two = Vec::new();
    let second = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[9]),
        },
        &mut writer_two,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf_two,
        &stats,
        user,
        Some(8),
        0,
        &bytes_me2c,
        7102,
        false,
        false,
    )
    .await;

    assert!(
        matches!(second, Err(ProxyError::DataQuotaExceeded { .. })),
        "frame after boundary must be rejected"
    );
    assert_eq!(stats.get_user_total_octets(user), 8);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 3);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_parallel_reservation_stress_never_overshoots_quota_or_counters() {
    let stats = Arc::new(Stats::new());
    let user = "reservation-stress-user";
    let quota_limit = 64u64;
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let mut tasks = JoinSet::new();

    for idx in 0..256u64 {
        let user_owned = user.to_string();
        let stats_ref = Arc::clone(&stats);
        let bytes_ref = Arc::clone(&bytes_me2c);

        tasks.spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            process_me_writer_response(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xAB]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                stats_ref.as_ref(),
                &user_owned,
                Some(quota_limit),
                0,
                bytes_ref.as_ref(),
                7200 + idx,
                false,
                false,
            )
            .await
        });
    }

    let mut ok = 0usize;
    let mut denied = 0usize;
    while let Some(joined) = tasks.join_next().await {
        match joined.expect("reservation stress task must not panic") {
            Ok(_) => ok += 1,
            Err(ProxyError::DataQuotaExceeded { .. }) => denied += 1,
            Err(other) => panic!("unexpected error in stress case: {other:?}"),
        }
    }

    let total = stats.get_user_total_octets(user);
    assert_eq!(
        total, quota_limit,
        "quota must be exactly exhausted without overshoot"
    );
    assert_eq!(
        bytes_me2c.load(Ordering::Relaxed),
        total,
        "ME->C forensic bytes must track committed quota usage"
    );
    assert_eq!(ok, quota_limit as usize, "exactly quota_limit tasks must succeed");
    assert_eq!(
        denied,
        256usize - (quota_limit as usize),
        "remaining tasks must be exactly denied without silently swallowing state"
    );
}

#[tokio::test]
async fn light_fuzz_random_frame_sizes_preserve_quota_and_counter_consistency() {
    let stats = Stats::new();
    let user = "reservation-fuzz-user";
    let quota_limit = 128u64;
    let bytes_me2c = AtomicU64::new(0);
    let mut seed = 0xC0FE_EE11_8899_2211u64;

    for conn in 0..512u64 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;
        let len = ((seed & 0x0f) + 1) as usize;
        let payload = vec![0x5A; len];

        let mut writer = make_crypto_writer(tokio::io::sink());
        let mut frame_buf = Vec::new();
        let result = process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from(payload),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            user,
            Some(quota_limit),
            0,
            &bytes_me2c,
            7300 + conn,
            false,
            false,
        )
        .await;

        if let Err(err) = result {
            assert!(
                matches!(err, ProxyError::DataQuotaExceeded { .. }),
                "fuzz run produced unexpected error variant: {err:?}"
            );
        }
    }

    let total = stats.get_user_total_octets(user);
    assert!(total <= quota_limit);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), total);
}

#[tokio::test]
async fn positive_soft_overshoot_allows_burst_inside_soft_cap_then_blocks() {
    let stats = Stats::new();
    let user = "soft-cap-boundary-user";
    let bytes_me2c = AtomicU64::new(0);
    let quota_limit = 10u64;
    let overshoot = 3u64;

    stats.add_user_octets_from(user, 10);

    let mut writer_one = make_crypto_writer(tokio::io::sink());
    let mut frame_buf_one = Vec::new();
    let first = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[1, 2, 3]),
        },
        &mut writer_one,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf_one,
        &stats,
        user,
        Some(quota_limit),
        overshoot,
        &bytes_me2c,
        7401,
        false,
        false,
    )
    .await;
    assert!(first.is_ok(), "soft-cap buffer should allow reaching limit+overshoot");
    assert_eq!(stats.get_user_total_octets(user), 13);

    let mut writer_two = make_crypto_writer(tokio::io::sink());
    let mut frame_buf_two = Vec::new();
    let second = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[9]),
        },
        &mut writer_two,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf_two,
        &stats,
        user,
        Some(quota_limit),
        overshoot,
        &bytes_me2c,
        7402,
        false,
        false,
    )
    .await;
    assert!(matches!(second, Err(ProxyError::DataQuotaExceeded { .. })));
    assert_eq!(stats.get_user_total_octets(user), 13);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 3);
}

#[tokio::test]
async fn negative_soft_overshoot_rejects_when_payload_exceeds_remaining_soft_budget() {
    let stats = Stats::new();
    let user = "soft-cap-remaining-user";
    let bytes_me2c = AtomicU64::new(0);
    let quota_limit = 10u64;
    let overshoot = 4u64;

    stats.add_user_octets_from(user, 12);

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[1, 2, 3]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(quota_limit),
        overshoot,
        &bytes_me2c,
        7501,
        false,
        false,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
    assert_eq!(stats.get_user_total_octets(user), 12);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn negative_write_failure_rolls_back_reservation_under_soft_cap_mode() {
    let stats = Stats::new();
    let user = "soft-cap-rollback-user";
    let bytes_me2c = AtomicU64::new(0);
    let mut writer = make_crypto_writer(FailingWriter);
    let mut frame_buf = Vec::new();

    stats.add_user_octets_from(user, 9);

    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[1, 2, 3]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(10),
        8,
        &bytes_me2c,
        7601,
        false,
        false,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::Io(_))));
    assert_eq!(stats.get_user_total_octets(user), 9);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_parallel_soft_cap_stress_never_exceeds_soft_limit() {
    let stats = Arc::new(Stats::new());
    let user = "soft-cap-stress-user";
    let quota_limit = 40u64;
    let overshoot = 5u64;
    let soft_limit = quota_limit + overshoot;
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let mut tasks = JoinSet::new();

    for idx in 0..256u64 {
        let user_owned = user.to_string();
        let stats_ref = Arc::clone(&stats);
        let bytes_ref = Arc::clone(&bytes_me2c);
        tasks.spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            process_me_writer_response(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0x42]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                stats_ref.as_ref(),
                &user_owned,
                Some(quota_limit),
                overshoot,
                bytes_ref.as_ref(),
                7700 + idx,
                false,
                false,
            )
            .await
        });
    }

    while let Some(joined) = tasks.join_next().await {
        match joined.expect("soft-cap stress task must not panic") {
            Ok(_) | Err(ProxyError::DataQuotaExceeded { .. }) => {}
            Err(other) => panic!("unexpected error in soft-cap stress case: {other:?}"),
        }
    }

    let total = stats.get_user_total_octets(user);
    assert!(total <= soft_limit, "soft-cap stress must never overshoot soft limit");
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), total);
}

#[tokio::test]
async fn light_fuzz_soft_cap_matrix_keeps_counters_and_limits_consistent() {
    let stats = Stats::new();
    let user = "soft-cap-fuzz-user";
    let bytes_me2c = AtomicU64::new(0);
    let mut seed = 0x9E37_79B9_7F4A_7C15u64;

    for conn in 0..1024u64 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let quota_limit = 32 + (seed & 0x3f);
        let overshoot = seed.rotate_left(13) & 0x0f;
        let len = ((seed >> 3) & 0x07) + 1;
        let payload = vec![0xA5; len as usize];
        let before = stats.get_user_total_octets(user);

        let mut writer = make_crypto_writer(tokio::io::sink());
        let mut frame_buf = Vec::new();
        let result = process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from(payload),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            user,
            Some(quota_limit),
            overshoot,
            &bytes_me2c,
            7800 + conn,
            false,
            false,
        )
        .await;

        if let Err(ref err) = result {
            assert!(
                matches!(err, ProxyError::DataQuotaExceeded { .. }),
                "soft-cap fuzz produced unexpected error variant: {err:?}"
            );
        }

        let after = stats.get_user_total_octets(user);
        let soft_limit = quota_limit.saturating_add(overshoot);
        match result {
            Ok(_) => {
                assert_eq!(after, before.saturating_add(len));
                assert!(after <= soft_limit, "accepted write must stay within active soft cap");
            }
            Err(_) => {
                assert_eq!(after, before, "rejected write must not mutate quota state");
            }
        }
        assert_eq!(
            bytes_me2c.load(Ordering::Relaxed),
            after,
            "soft-cap fuzz must keep counters synchronized"
        );
    }
}

#[tokio::test]
async fn positive_no_quota_limit_accumulates_data_octets_exactly() {
    let stats = Stats::new();
    let user = "no-quota-user";
    let bytes_me2c = AtomicU64::new(0);
    let mut expected = 0u64;

    for (idx, len) in [1usize, 2, 3, 5, 8, 13, 21].iter().copied().enumerate() {
        let mut writer = make_crypto_writer(tokio::io::sink());
        let mut frame_buf = Vec::new();
        let payload = vec![0x41; len];
        let result = process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from(payload),
            },
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            user,
            None,
            0,
            &bytes_me2c,
            7900 + idx as u64,
            false,
            false,
        )
        .await;

        assert!(result.is_ok());
        expected += len as u64;
    }

    assert_eq!(stats.get_user_total_octets(user), expected);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), expected);
}

#[tokio::test]
async fn negative_zero_quota_rejects_non_empty_payload() {
    let stats = Stats::new();
    let user = "zero-quota-user";
    let bytes_me2c = AtomicU64::new(0);

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[0xAA]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(0),
        0,
        &bytes_me2c,
        8001,
        false,
        false,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
    assert_eq!(stats.get_user_total_octets(user), 0);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn edge_zero_length_payload_with_zero_quota_is_fail_closed() {
    let stats = Stats::new();
    let user = "zero-len-zero-quota-user";
    let bytes_me2c = AtomicU64::new(0);

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::new(),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(0),
        0,
        &bytes_me2c,
        8002,
        false,
        false,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
    assert_eq!(stats.get_user_total_octets(user), 0);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn positive_ack_response_does_not_touch_quota_counters() {
    let stats = Stats::new();
    let user = "ack-accounting-user";
    let bytes_me2c = AtomicU64::new(11);
    stats.add_user_octets_to(user, 23);

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let result = process_me_writer_response(
        MeResponse::Ack(0x33445566),
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(24),
        0,
        &bytes_me2c,
        8003,
        true,
        true,
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(stats.get_user_total_octets(user), 23);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 11);
}

#[tokio::test]
async fn edge_close_response_is_accounting_noop() {
    let stats = Stats::new();
    let user = "close-accounting-user";
    let bytes_me2c = AtomicU64::new(19);
    stats.add_user_octets_to(user, 31);

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let result = process_me_writer_response(
        MeResponse::Close,
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(40),
        3,
        &bytes_me2c,
        8004,
        false,
        true,
    )
    .await;

    assert!(result.is_ok());
    assert_eq!(stats.get_user_total_octets(user), 31);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 19);
}

#[tokio::test]
async fn negative_preloaded_above_soft_cap_rejects_even_single_byte() {
    let stats = Stats::new();
    let user = "preloaded-over-soft-cap-user";
    let bytes_me2c = AtomicU64::new(0);
    let quota_limit = 20u64;
    let overshoot = 2u64;
    stats.add_user_octets_to(user, quota_limit + overshoot + 1);

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[1]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(quota_limit),
        overshoot,
        &bytes_me2c,
        8005,
        false,
        false,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 0);
    assert_eq!(stats.get_user_total_octets(user), quota_limit + overshoot + 1);
}

#[tokio::test]
async fn adversarial_fail_writer_path_never_desynchronizes_quota_accounting() {
    let stats = Stats::new();
    let user = "partial-write-rollback-user";
    let bytes_me2c = AtomicU64::new(0);
    let mut writer = make_crypto_writer(FailAfterBudgetWriter::new(7));
    let mut frame_buf = Vec::new();
    let payload_len = 16 * 1024u64;

    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from(vec![0x42; 16 * 1024]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(payload_len),
        0,
        &bytes_me2c,
        8006,
        false,
        false,
    )
    .await;

    let total_after = stats.get_user_total_octets(user);
    let forensic_after = bytes_me2c.load(Ordering::Relaxed);
    assert_eq!(forensic_after, total_after);
    assert!(
        total_after == 0 || total_after == payload_len,
        "writer failure path must either roll back fully or commit exactly one payload"
    );

    // Regardless of whether I/O failure surfaced immediately or was deferred,
    // accounting must remain fail-closed and prevent silent overshoot.
    let mut writer_two = make_crypto_writer(tokio::io::sink());
    let mut frame_buf_two = Vec::new();
    let second = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[0x99]),
        },
        &mut writer_two,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf_two,
        &stats,
        user,
        Some(payload_len),
        0,
        &bytes_me2c,
        8007,
        false,
        false,
    )
    .await;

    if total_after == payload_len {
        assert!(matches!(second, Err(ProxyError::DataQuotaExceeded { .. })));
    } else {
        assert!(second.is_ok());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_oversized_frames_fail_closed_without_counter_leak() {
    let stats = Arc::new(Stats::new());
    let user = "parallel-fail-rollback-user";
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let mut tasks = JoinSet::new();

    for idx in 0..256u64 {
        let user_owned = user.to_string();
        let stats_ref = Arc::clone(&stats);
        let bytes_ref = Arc::clone(&bytes_me2c);
        tasks.spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            process_me_writer_response(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from(vec![0xEE; 12 * 1024]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                stats_ref.as_ref(),
                &user_owned,
                Some(512),
                0,
                bytes_ref.as_ref(),
                8100 + idx,
                false,
                false,
            )
            .await
        });
    }

    while let Some(joined) = tasks.join_next().await {
        let result = joined.expect("parallel fail writer task must not panic");
        assert!(matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
    }

    assert_eq!(stats.get_user_total_octets(user), 0);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn integration_mixed_data_ack_close_sequence_preserves_data_only_accounting() {
    let stats = Stats::new();
    let user = "mixed-sequence-user";
    let bytes_me2c = AtomicU64::new(0);

    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();

    let data_one = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[1, 2, 3]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(32),
        0,
        &bytes_me2c,
        8201,
        false,
        false,
    )
    .await;
    assert!(data_one.is_ok());

    let ack = process_me_writer_response(
        MeResponse::Ack(0x0102_0304),
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(32),
        0,
        &bytes_me2c,
        8202,
        true,
        true,
    )
    .await;
    assert!(ack.is_ok());

    let data_two = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[4, 5]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(32),
        0,
        &bytes_me2c,
        8203,
        false,
        true,
    )
    .await;
    assert!(data_two.is_ok());

    let close = process_me_writer_response(
        MeResponse::Close,
        &mut writer,
        ProtoTag::Intermediate,
        &SecureRandom::new(),
        &mut frame_buf,
        &stats,
        user,
        Some(32),
        0,
        &bytes_me2c,
        8204,
        false,
        true,
    )
    .await;
    assert!(close.is_ok());

    assert_eq!(stats.get_user_total_octets(user), 5);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 5);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_parallel_multi_user_quota_isolation_no_cross_user_leakage() {
    let stats = Arc::new(Stats::new());
    let user_a = "quota-isolation-a";
    let user_b = "quota-isolation-b";
    let limit_a = 50u64;
    let limit_b = 80u64;
    let bytes_a = Arc::new(AtomicU64::new(0));
    let bytes_b = Arc::new(AtomicU64::new(0));

    let mut tasks = JoinSet::new();
    for idx in 0..200u64 {
        let stats_ref = Arc::clone(&stats);
        let bytes_ref = Arc::clone(&bytes_a);
        tasks.spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            process_me_writer_response(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xA1]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                stats_ref.as_ref(),
                user_a,
                Some(limit_a),
                0,
                bytes_ref.as_ref(),
                8300 + idx,
                false,
                false,
            )
            .await
        });
    }

    for idx in 0..220u64 {
        let stats_ref = Arc::clone(&stats);
        let bytes_ref = Arc::clone(&bytes_b);
        tasks.spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            process_me_writer_response(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xB2]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                stats_ref.as_ref(),
                user_b,
                Some(limit_b),
                0,
                bytes_ref.as_ref(),
                8500 + idx,
                false,
                false,
            )
            .await
        });
    }

    while let Some(joined) = tasks.join_next().await {
        let result = joined.expect("quota isolation task must not panic");
        assert!(result.is_ok() || matches!(result, Err(ProxyError::DataQuotaExceeded { .. })));
    }

    assert_eq!(stats.get_user_total_octets(user_a), limit_a);
    assert_eq!(stats.get_user_total_octets(user_b), limit_b);
    assert_eq!(bytes_a.load(Ordering::Relaxed), limit_a);
    assert_eq!(bytes_b.load(Ordering::Relaxed), limit_b);
}

#[tokio::test]
async fn light_fuzz_mixed_me_responses_preserve_quota_and_counter_invariants() {
    let stats = Stats::new();
    let user = "mixed-fuzz-user";
    let bytes_me2c = AtomicU64::new(0);
    let quota_limit = 96u64;
    let mut seed = 0xDEAD_BEEF_2026_0323u64;

    for idx in 0..2048u64 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let choice = (seed & 0x03) as u8;
        let response = if choice == 0 {
            MeResponse::Ack((seed >> 8) as u32)
        } else if choice == 1 {
            MeResponse::Close
        } else {
            let len = ((seed >> 16) & 0x07) as usize;
            let mut payload = vec![0u8; len];
            payload.fill((seed & 0xff) as u8);
            MeResponse::Data {
                flags: 0,
                data: Bytes::from(payload),
            }
        };

        let mut writer = make_crypto_writer(tokio::io::sink());
        let mut frame_buf = Vec::new();
        let result = process_me_writer_response(
            response,
            &mut writer,
            ProtoTag::Intermediate,
            &SecureRandom::new(),
            &mut frame_buf,
            &stats,
            user,
            Some(quota_limit),
            0,
            &bytes_me2c,
            8800 + idx,
            (idx & 1) == 0,
            (idx & 2) == 0,
        )
        .await;

        if let Err(err) = result {
            assert!(
                matches!(err, ProxyError::DataQuotaExceeded { .. }),
                "mixed fuzz produced unexpected error variant: {err:?}"
            );
        }

        let total = stats.get_user_total_octets(user);
        assert!(
            total <= quota_limit,
            "mixed fuzz must keep usage at or below quota limit"
        );
        assert_eq!(bytes_me2c.load(Ordering::Relaxed), total);
    }
}