use super::*;
use crate::crypto::{AesCtr, SecureRandom};
use crate::stats::Stats;
use crate::stream::CryptoWriter;
use bytes::Bytes;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll, Waker};
use tokio::io::AsyncWrite;
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
struct GateState {
    open: AtomicBool,
    parked_waker: std::sync::Mutex<Option<Waker>>,
}

impl GateState {
    fn open(&self) {
        self.open.store(true, Ordering::Relaxed);
        if let Ok(mut guard) = self.parked_waker.lock()
            && let Some(w) = guard.take()
        {
            w.wake();
        }
    }

    fn has_waiter(&self) -> bool {
        self.parked_waker
            .lock()
            .map(|guard| guard.is_some())
            .unwrap_or(false)
    }
}

#[derive(Default)]
struct GateWriter {
    gate: Arc<GateState>,
}

impl GateWriter {
    fn new(gate: Arc<GateState>) -> Self {
        Self { gate }
    }
}

impl AsyncWrite for GateWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.gate.open.load(Ordering::Relaxed) {
            return Poll::Ready(Ok(buf.len()));
        }

        if let Ok(mut guard) = self.gate.parked_waker.lock() {
            *guard = Some(cx.waker().clone());
        }
        Poll::Pending
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

struct FailingWriter;

impl AsyncWrite for FailingWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "injected writer failure",
        )))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn adversarial_same_user_slow_writer_must_not_hol_block_peer_connection() {
    let stats = Stats::new();
    let bytes_me2c = AtomicU64::new(0);
    let rng = SecureRandom::new();
    let quota_limit = Some(1024);
    let user = "hol-quota-user";

    let gate = Arc::new(GateState::default());

    let mut blocked_writer = make_crypto_writer(GateWriter::new(Arc::clone(&gate)));
    let slow_task = tokio::spawn(async move {
        let mut frame_buf = Vec::new();
        process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0x10, 0x20, 0x30, 0x40]),
            },
            &mut blocked_writer,
            ProtoTag::Intermediate,
            &rng,
            &mut frame_buf,
            &stats,
            user,
            quota_limit,
            0,
            &bytes_me2c,
            7001,
            false,
            false,
        )
        .await
    });

    timeout(Duration::from_millis(100), async {
        loop {
            if gate.has_waiter() {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("first writer must reach backpressure and park");

    let stats_fast = Stats::new();
    let bytes_fast = AtomicU64::new(0);
    let rng_fast = SecureRandom::new();
    let mut fast_writer = make_crypto_writer(tokio::io::sink());
    let mut frame_buf_fast = Vec::new();

    timeout(
        Duration::from_millis(50),
        process_me_writer_response(
            MeResponse::Data {
                flags: 0,
                data: Bytes::from_static(&[0x41]),
            },
            &mut fast_writer,
            ProtoTag::Intermediate,
            &rng_fast,
            &mut frame_buf_fast,
            &stats_fast,
            user,
            quota_limit,
            0,
            &bytes_fast,
            7002,
            false,
            false,
        ),
    )
    .await
    .expect("peer connection must not be blocked by same-user stalled write")
    .expect("fast peer write must succeed");

    gate.open();
    let slow_result = timeout(Duration::from_secs(1), slow_task)
        .await
        .expect("stalled task must complete once gate opens")
        .expect("stalled task must not panic");
    assert!(slow_result.is_ok());
}

#[tokio::test]
async fn negative_write_failure_rolls_back_pre_accounted_quota_and_forensics_bytes() {
    let stats = Stats::new();
    let user = "rollback-user";
    stats.add_user_octets_from(user, 7);

    let bytes_me2c = AtomicU64::new(0);
    let rng = SecureRandom::new();
    let mut writer = make_crypto_writer(FailingWriter);
    let mut frame_buf = Vec::new();

    let result = process_me_writer_response(
        MeResponse::Data {
            flags: 0,
            data: Bytes::from_static(&[1, 2, 3, 4]),
        },
        &mut writer,
        ProtoTag::Intermediate,
        &rng,
        &mut frame_buf,
        &stats,
        user,
        Some(64),
        0,
        &bytes_me2c,
        7003,
        false,
        false,
    )
    .await;

    assert!(matches!(result, Err(ProxyError::Io(_))));
    assert_eq!(
        stats.get_user_total_octets(user),
        7,
        "failed client write must not overcharge user quota accounting"
    );
    assert_eq!(
        bytes_me2c.load(Ordering::Relaxed),
        0,
        "failed client write must not inflate ME->C forensic byte counter"
    );
}