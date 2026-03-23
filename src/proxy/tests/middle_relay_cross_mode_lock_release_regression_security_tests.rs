use super::*;
use crate::crypto::{AesCtr, SecureRandom};
use crate::stats::Stats;
use crate::stream::CryptoWriter;
use bytes::Bytes;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use tokio::io::AsyncWrite;
use tokio::sync::Notify;
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

#[derive(Default)]
struct BlockingWriteState {
    write_entered: AtomicBool,
    released: AtomicBool,
    write_waker: Mutex<Option<Waker>>,
    write_entered_notify: Notify,
}

struct BlockingWrite {
    state: Arc<BlockingWriteState>,
}

impl BlockingWrite {
    fn new(state: Arc<BlockingWriteState>) -> Self {
        Self { state }
    }
}

impl AsyncWrite for BlockingWrite {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.state.write_entered.store(true, Ordering::Release);
        self.state.write_entered_notify.notify_waiters();

        if self.state.released.load(Ordering::Acquire) {
            return Poll::Ready(Ok(buf.len()));
        }

        if let Ok(mut slot) = self.state.write_waker.lock() {
            *slot = Some(cx.waker().clone());
        }

        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn wait_until_blocking_write_entered(state: &Arc<BlockingWriteState>) {
    for _ in 0..8 {
        if state.write_entered.load(Ordering::Acquire) {
            return;
        }
        let _ = timeout(Duration::from_millis(25), state.write_entered_notify.notified()).await;
    }

    panic!("blocking writer did not enter poll_write in bounded time");
}

fn release_blocking_write(state: &Arc<BlockingWriteState>) {
    state.released.store(true, Ordering::Release);
    if let Ok(mut slot) = state.write_waker.lock()
        && let Some(waker) = slot.take()
    {
        waker.wake();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adversarial_blocked_write_releases_cross_mode_lock_and_preserves_fail_closed_quota() {
    let stats = Arc::new(Stats::new());
    let user = format!("middle-cross-release-regression-{}", std::process::id());
    let cross_mode_lock = Arc::new(cross_mode_quota_user_lock_for_tests(&user));
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let writer_state = Arc::new(BlockingWriteState::default());

    let first = {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        let cross_mode_lock = Arc::clone(&cross_mode_lock);
        let bytes_me2c = Arc::clone(&bytes_me2c);
        let writer_state = Arc::clone(&writer_state);
        tokio::spawn(async move {
            let mut writer = make_crypto_writer(BlockingWrite::new(writer_state));
            let mut frame_buf = Vec::new();
            process_me_writer_response_with_cross_mode_lock(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xAA, 0xBB, 0xCC, 0xDD]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                stats.as_ref(),
                &user,
                Some(4),
                0,
                Some(&cross_mode_lock),
                bytes_me2c.as_ref(),
                41_000,
                false,
                false,
            )
            .await
        })
    };

    wait_until_blocking_write_entered(&writer_state).await;

    let guard = timeout(Duration::from_millis(40), cross_mode_lock.lock())
        .await
        .expect("cross-mode lock must be released while first write is pending");
    drop(guard);

    let second = {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        let cross_mode_lock = Arc::clone(&cross_mode_lock);
        let bytes_me2c = Arc::clone(&bytes_me2c);
        tokio::spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            timeout(
                Duration::from_millis(150),
                process_me_writer_response_with_cross_mode_lock(
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
                    Some(4),
                    0,
                    Some(&cross_mode_lock),
                    bytes_me2c.as_ref(),
                    41_001,
                    false,
                    false,
                ),
            )
            .await
        })
    };

    let second_result = second
        .await
        .expect("second task must not panic")
        .expect("second write must not block on cross-mode lock");
    assert!(
        matches!(second_result, Err(ProxyError::DataQuotaExceeded { .. })),
        "second write must fail closed due to first write reservation"
    );

    release_blocking_write(&writer_state);

    let first_result = timeout(Duration::from_millis(300), first)
        .await
        .expect("first task timed out")
        .expect("first task must not panic");
    assert!(first_result.is_ok());

    assert_eq!(stats.get_user_total_octets(&user), 4);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 4);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_pending_write_does_not_starve_same_user_waiters_after_quota_boundary() {
    let stats = Arc::new(Stats::new());
    let user = format!("middle-cross-release-stress-{}", std::process::id());
    let cross_mode_lock = Arc::new(cross_mode_quota_user_lock_for_tests(&user));
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let writer_state = Arc::new(BlockingWriteState::default());

    let first = {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        let cross_mode_lock = Arc::clone(&cross_mode_lock);
        let bytes_me2c = Arc::clone(&bytes_me2c);
        let writer_state = Arc::clone(&writer_state);
        tokio::spawn(async move {
            let mut writer = make_crypto_writer(BlockingWrite::new(writer_state));
            let mut frame_buf = Vec::new();
            process_me_writer_response_with_cross_mode_lock(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0x01, 0x02]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &SecureRandom::new(),
                &mut frame_buf,
                stats.as_ref(),
                &user,
                Some(3),
                0,
                Some(&cross_mode_lock),
                bytes_me2c.as_ref(),
                41_100,
                false,
                false,
            )
            .await
        })
    };

    wait_until_blocking_write_entered(&writer_state).await;

    let mut set = JoinSet::new();
    for idx in 0..48u64 {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        let cross_mode_lock = Arc::clone(&cross_mode_lock);
        let bytes_me2c = Arc::clone(&bytes_me2c);
        set.spawn(async move {
            let mut writer = make_crypto_writer(tokio::io::sink());
            let mut frame_buf = Vec::new();
            timeout(
                Duration::from_millis(200),
                process_me_writer_response_with_cross_mode_lock(
                    MeResponse::Data {
                        flags: 0,
                        data: Bytes::from_static(&[0x10]),
                    },
                    &mut writer,
                    ProtoTag::Intermediate,
                    &SecureRandom::new(),
                    &mut frame_buf,
                    stats.as_ref(),
                    &user,
                    Some(3),
                    0,
                    Some(&cross_mode_lock),
                    bytes_me2c.as_ref(),
                    41_200 + idx,
                    false,
                    false,
                ),
            )
            .await
        });
    }

    let mut ok = 0usize;
    let mut quota_exceeded = 0usize;
    while let Some(done) = set.join_next().await {
        let timed = done.expect("waiter task must not panic");
        let result = timed.expect("waiter must not block behind pending first write");
        match result {
            Ok(_) => ok += 1,
            Err(ProxyError::DataQuotaExceeded { .. }) => quota_exceeded += 1,
            Err(other) => panic!("unexpected error in waiter: {other:?}"),
        }
    }

    assert_eq!(ok, 1, "exactly one waiter should consume remaining one-byte quota");
    assert_eq!(quota_exceeded, 47);

    release_blocking_write(&writer_state);

    let first_result = timeout(Duration::from_millis(300), first)
        .await
        .expect("first task timed out")
        .expect("first task must not panic");
    assert!(first_result.is_ok());

    assert_eq!(stats.get_user_total_octets(&user), 3);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 3);
}
