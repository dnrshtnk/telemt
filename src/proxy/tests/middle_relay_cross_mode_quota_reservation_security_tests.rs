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

#[tokio::test]
async fn adversarial_held_cross_mode_lock_blocks_me_to_client_quota_reservation_path() {
    let stats = Stats::new();
    let user = format!("middle-me2c-cross-mode-held-{}", std::process::id());
    let held = cross_mode_quota_user_lock_for_tests(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold shared cross-mode lock before ME->C write path");

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
            Some(1024),
            0,
            &bytes_me2c,
            9901,
            false,
            false,
        ),
    )
    .await;

    assert!(
        blocked.is_err(),
        "ME->C quota reservation path must be serialized by held shared cross-mode lock"
    );

    drop(held_guard);

    let released = timeout(
        Duration::from_millis(250),
        process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0x42]),
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
            9902,
            false,
            false,
        ),
    )
    .await
    .expect("ME->C write must complete after cross-mode lock release");

    assert!(released.is_ok());
}

#[tokio::test]
async fn business_uncontended_cross_mode_lock_allows_me_to_client_quota_reservation() {
    let stats = Stats::new();
    let user = format!("middle-me2c-cross-mode-free-{}", std::process::id());
    let mut writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf = Vec::new();
    let bytes_me2c = AtomicU64::new(0);

    let outcome = timeout(
        Duration::from_millis(250),
        process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0x55, 0x66]),
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
            9903,
            false,
            false,
        ),
    )
    .await
    .expect("uncontended ME->C path should not stall");

    assert!(outcome.is_ok());
    assert_eq!(stats.get_user_total_octets(&user), 2);
    assert_eq!(bytes_me2c.load(std::sync::atomic::Ordering::Relaxed), 2);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adversarial_cross_mode_lock_is_released_before_me_to_client_write_await() {
    let stats = Arc::new(Stats::new());
    let user = format!("middle-me2c-lock-drop-before-write-{}", std::process::id());
    let cross_mode_lock = cross_mode_quota_user_lock_for_tests(&user);
    let bytes_me2c = Arc::new(AtomicU64::new(0));
    let writer_state = Arc::new(BlockingWriteState::default());

    let worker = {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        let cross_mode_lock = Arc::clone(&cross_mode_lock);
        let bytes_me2c = Arc::clone(&bytes_me2c);
        let writer_state = Arc::clone(&writer_state);
        tokio::spawn(async move {
            let mut writer = make_crypto_writer(BlockingWrite::new(writer_state));
            let mut frame_buf = Vec::new();
            let rng = SecureRandom::new();
            process_me_writer_response_with_cross_mode_lock(
                MeResponse::Data {
                    flags: 0,
                    data: Bytes::from_static(&[0xDE, 0xAD, 0xBE, 0xEF]),
                },
                &mut writer,
                ProtoTag::Intermediate,
                &rng,
                &mut frame_buf,
                stats.as_ref(),
                &user,
                Some(1024),
                0,
                Some(&cross_mode_lock),
                bytes_me2c.as_ref(),
                9910,
                false,
                false,
            )
            .await
        })
    };

    wait_until_blocking_write_entered(&writer_state).await;

    let acquired_guard = timeout(Duration::from_millis(40), cross_mode_lock.lock())
        .await
        .expect("cross-mode lock must be free while ME->C write is pending");
    drop(acquired_guard);

    release_blocking_write(&writer_state);

    let result = timeout(Duration::from_millis(300), worker)
        .await
        .expect("ME->C worker timed out after releasing blocking writer")
        .expect("ME->C worker must not panic");

    assert!(result.is_ok());
    assert_eq!(stats.get_user_total_octets(&user), 4);
    assert_eq!(bytes_me2c.load(Ordering::Relaxed), 4);
}
