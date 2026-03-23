use super::*;
use crate::stats::Stats;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, Instant, timeout};

#[derive(Default)]
struct WakeCounter {
    wakes: AtomicUsize,
}

impl std::task::Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.wakes.fetch_add(1, Ordering::Relaxed);
    }
}

fn quota_test_guard() -> impl Drop {
    super::quota_user_lock_test_scope()
}

#[tokio::test]
async fn positive_uncontended_dual_lock_writer_has_zero_retry_attempt() {
    let _guard = quota_test_guard();

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        format!("dual-lock-alt-positive-{}", std::process::id()),
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        Instant::now(),
    );

    let write = io.write_all(&[0xAA, 0xBB]).await;
    assert!(write.is_ok(), "uncontended write must complete");
    assert_eq!(
        io.quota_write_retry_attempt, 0,
        "uncontended write must not advance retry backoff"
    );
}

#[tokio::test]
async fn adversarial_alternating_local_and_cross_mode_contention_preserves_backoff_growth() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-alt-adversarial-{}", std::process::id());
    let local_lock = quota_user_lock(&user);
    let cross_mode_lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);

    let mut local_guard = Some(
        local_lock
            .try_lock()
            .expect("test must hold local quota lock initially"),
    );
    let mut cross_guard = None;

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let first = Pin::new(&mut io).poll_write(&mut cx, &[0x11]);
    assert!(first.is_pending(), "held local lock must block first poll");

    let mut observed_wakes = 0usize;
    for idx in 0..18usize {
        tokio::time::sleep(Duration::from_millis(6)).await;

        if idx % 2 == 0 {
            drop(local_guard.take());
            cross_guard = Some(
                cross_mode_lock
                    .try_lock()
                    .expect("cross-mode lock should be acquirable while local lock released"),
            );
        } else {
            drop(cross_guard.take());
            local_guard = Some(
                local_lock
                    .try_lock()
                    .expect("local lock should be acquirable while cross lock released"),
            );
        }

        let wakes = wake_counter.wakes.load(Ordering::Relaxed);
        if wakes > observed_wakes {
            observed_wakes = wakes;
            let pending = Pin::new(&mut io).poll_write(&mut cx, &[0x12]);
            assert!(
                pending.is_pending(),
                "alternating contention must keep write pending while one lock is held"
            );
        }
    }

    assert!(
        io.quota_write_retry_attempt >= 2,
        "alternating contention must still ramp retry backoff; got {}",
        io.quota_write_retry_attempt
    );
    assert!(
        wake_counter.wakes.load(Ordering::Relaxed) <= 32,
        "alternating contention must stay wake-rate-limited"
    );

    drop(local_guard);
    drop(cross_guard);
    let ready = Pin::new(&mut io).poll_write(&mut cx, &[0x13]);
    assert!(ready.is_ready(), "writer must resume after both locks released");
}

#[tokio::test]
async fn edge_retry_scheduler_resets_after_alternating_contention_clears() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-alt-edge-reset-{}", std::process::id());
    let local_lock = quota_user_lock(&user);
    let local_guard = local_lock
        .try_lock()
        .expect("test must hold local lock for edge scenario");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let first = Pin::new(&mut io).poll_write(&mut cx, &[0x21]);
    assert!(first.is_pending());
    tokio::time::sleep(Duration::from_millis(15)).await;
    if wake_counter.wakes.load(Ordering::Relaxed) > 0 {
        let next = Pin::new(&mut io).poll_write(&mut cx, &[0x22]);
        assert!(next.is_pending());
    }

    drop(local_guard);

    let ready = Pin::new(&mut io).poll_write(&mut cx, &[0x23]);
    assert!(ready.is_ready());
    assert_eq!(
        io.quota_write_retry_attempt, 0,
        "successful dual-lock acquisition must reset retry scheduler"
    );
    assert!(!io.quota_write_wake_scheduled);
    assert!(io.quota_write_retry_sleep.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_cross_mode_waiters_remain_live_under_alternating_contention_then_resume() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-alt-integration-{}", std::process::id());
    let local_lock = quota_user_lock(&user);
    let cross_mode_lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);

    let mut waiters = Vec::new();
    for _ in 0..16usize {
        let user = user.clone();
        waiters.push(tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                user,
                Some(2048),
                Arc::new(AtomicBool::new(false)),
                Instant::now(),
            );
            timeout(Duration::from_secs(2), io.write_all(&[0x31])).await
        }));
    }

    let mut local_guard = Some(
        local_lock
            .try_lock()
            .expect("integration toggle must acquire local lock first"),
    );
    let mut cross_guard = None;

    for idx in 0..24usize {
        tokio::time::sleep(Duration::from_millis(4)).await;
        if idx % 2 == 0 {
            drop(local_guard.take());
            cross_guard = cross_mode_lock.try_lock().ok();
        } else {
            drop(cross_guard.take());
            local_guard = local_lock.try_lock().ok();
        }
    }

    drop(local_guard);
    drop(cross_guard);

    for waiter in waiters {
        let done = waiter.await.expect("waiter task must not panic");
        assert!(
            done.is_ok(),
            "waiter must finish once alternating contention window ends"
        );
        assert!(done.expect("waiter timeout must not fire").is_ok());
    }
}

#[tokio::test]
async fn light_fuzz_alternating_contention_matrix_preserves_lock_gating() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-alt-fuzz-{}", std::process::id());
    let local_lock = quota_user_lock(&user);
    let cross_mode_lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let mut seed = 0xD00D_BAAD_F00D_2026u64;

    for _round in 0..64u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let hold_mode = (seed % 3) as u8;
        let local_guard = if hold_mode == 0 {
            Some(
                local_lock
                    .try_lock()
                    .expect("fuzz local lock should be acquirable"),
            )
        } else {
            None
        };
        let cross_guard = if hold_mode == 1 {
            Some(
                cross_mode_lock
                    .try_lock()
                    .expect("fuzz cross lock should be acquirable"),
            )
        } else {
            None
        };

        let mut io = StatsIo::new(
            tokio::io::sink(),
            Arc::new(SharedCounters::new()),
            Arc::new(Stats::new()),
            user.clone(),
            Some(1024),
            Arc::new(AtomicBool::new(false)),
            Instant::now(),
        );

        let write = timeout(Duration::from_millis(35), io.write_all(&[0x51])).await;
        if hold_mode == 2 {
            assert!(write.is_ok(), "unheld fuzz round must make progress");
            assert!(write.expect("unheld round timeout").is_ok());
        } else {
            assert!(
                write.is_err(),
                "held-lock fuzz round must remain pending inside bounded window"
            );
        }

        drop(local_guard);
        drop(cross_guard);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_fanout_alternating_contention_recovers_without_hanging() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-alt-stress-{}", std::process::id());
    let local_lock = quota_user_lock(&user);
    let cross_mode_lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);

    let mut waiters = Vec::new();
    for _ in 0..48usize {
        let user = user.clone();
        waiters.push(tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                user,
                Some(4096),
                Arc::new(AtomicBool::new(false)),
                Instant::now(),
            );
            timeout(Duration::from_secs(3), io.write_all(&[0xA0, 0xA1])).await
        }));
    }

    let mut local_guard = Some(
        local_lock
            .try_lock()
            .expect("stress toggle must acquire local lock first"),
    );
    let mut cross_guard = None;
    for idx in 0..40usize {
        tokio::time::sleep(Duration::from_millis(3)).await;
        if idx % 2 == 0 {
            drop(local_guard.take());
            cross_guard = cross_mode_lock.try_lock().ok();
        } else {
            drop(cross_guard.take());
            local_guard = local_lock.try_lock().ok();
        }
    }

    drop(local_guard);
    drop(cross_guard);

    for waiter in waiters {
        let done = waiter.await.expect("stress waiter task must not panic");
        assert!(done.is_ok(), "stress waiter timed out under alternating contention");
        assert!(done.expect("stress waiter timeout should not fire").is_ok());
    }
}
