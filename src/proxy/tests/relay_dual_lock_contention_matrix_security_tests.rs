use super::*;
use crate::stats::Stats;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
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

fn build_context() -> (Arc<WakeCounter>, Context<'static>) {
    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let leaked_waker: &'static Waker = Box::leak(Box::new(waker));
    (wake_counter, Context::from_waker(leaked_waker))
}

#[tokio::test]
async fn positive_uncontended_dual_locks_writer_completes_without_retry_state() {
    let _guard = quota_test_guard();

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        format!("dual-lock-positive-{}", std::process::id()),
        Some(4096),
        Arc::new(AtomicBool::new(false)),
        Instant::now(),
    );

    let (_wake_counter, mut cx) = build_context();
    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x01, 0x02, 0x03]);
    assert!(poll.is_ready());
    assert_eq!(io.quota_write_retry_attempt, 0);
    assert!(!io.quota_write_wake_scheduled);
    assert!(io.quota_write_retry_sleep.is_none());
}

#[tokio::test]
async fn negative_local_lock_contention_read_retry_attempt_ramps() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-local-contention-{}", std::process::id());
    let held = quota_user_lock(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold local quota lock before polling");

    let mut io = StatsIo::new(
        tokio::io::empty(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        Instant::now(),
    );

    let (wake_counter, mut cx) = build_context();
    let mut one = [0u8; 1];
    let mut buf = ReadBuf::new(&mut one);
    let first = Pin::new(&mut io).poll_read(&mut cx, &mut buf);
    assert!(first.is_pending());

    let started = Instant::now();
    let mut observed = 0usize;
    while started.elapsed() < Duration::from_millis(120) {
        let wakes = wake_counter.wakes.load(Ordering::Relaxed);
        if wakes > observed {
            observed = wakes;
            let mut step_buf = ReadBuf::new(&mut one);
            let next = Pin::new(&mut io).poll_read(&mut cx, &mut step_buf);
            assert!(next.is_pending());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    assert!(
        io.quota_read_retry_attempt >= 2,
        "retry attempt must ramp under sustained local-lock contention; got {}",
        io.quota_read_retry_attempt
    );

    drop(held_guard);
}

#[tokio::test]
async fn edge_cross_mode_contention_release_resets_retry_scheduler_on_success() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-reset-{}", std::process::id());
    let cross_mode = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let held_guard = cross_mode
        .try_lock()
        .expect("test must hold cross-mode lock before polling");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        Instant::now(),
    );

    let (wake_counter, mut cx) = build_context();
    let first = Pin::new(&mut io).poll_write(&mut cx, &[0x10]);
    assert!(first.is_pending());

    tokio::time::sleep(Duration::from_millis(20)).await;
    if wake_counter.wakes.load(Ordering::Relaxed) > 0 {
        let next = Pin::new(&mut io).poll_write(&mut cx, &[0x11]);
        assert!(next.is_pending());
    }

    drop(held_guard);
    let ready = Pin::new(&mut io).poll_write(&mut cx, &[0x12]);
    assert!(ready.is_ready());
    assert_eq!(io.quota_write_retry_attempt, 0);
    assert!(!io.quota_write_wake_scheduled);
    assert!(io.quota_write_retry_sleep.is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_cross_mode_hold_blocks_many_waiters_without_usage_leak() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-adversarial-{}", std::process::id());
    let stats = Arc::new(Stats::new());
    let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold cross-mode lock before launching waiters");

    let mut tasks = Vec::new();
    for _ in 0..24usize {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        tasks.push(tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                stats,
                user,
                Some(1024),
                Arc::new(AtomicBool::new(false)),
                Instant::now(),
            );
            timeout(Duration::from_millis(40), io.write_all(&[0x33])).await
        }));
    }

    for task in tasks {
        let timed = task.await.expect("waiter task must not panic");
        assert!(timed.is_err(), "held cross-mode lock must keep waiter pending");
    }

    assert_eq!(stats.get_user_total_octets(&user), 0);
    drop(held_guard);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_waiters_resume_after_cross_mode_release() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-integration-{}", std::process::id());
    let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold cross-mode lock before starting waiter");

    let task = tokio::spawn({
        let user = user.clone();
        async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                user,
                Some(1024),
                Arc::new(AtomicBool::new(false)),
                Instant::now(),
            );
            io.write_all(&[0x44]).await
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;
    drop(held_guard);

    let done = timeout(Duration::from_secs(1), task)
        .await
        .expect("waiter task must complete after release")
        .expect("waiter task must not panic");
    assert!(done.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn light_fuzz_randomized_lock_holds_preserve_liveness_and_quota_bounds() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-fuzz-{}", std::process::id());
    let stats = Arc::new(Stats::new());
    let mut seed = 0xA55A_55AA_C3D2_E1F0u64;

    for _round in 0..48u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let hold_mode = (seed % 3) as u8;
        let mut local_lock = None;
        let mut cross_lock = None;
        let mut local_guard = None;
        let mut cross_guard = None;

        if hold_mode == 0 {
            local_lock = Some(quota_user_lock(&user));
            local_guard = Some(
                local_lock
                    .as_ref()
                    .expect("local lock should be present")
                    .try_lock()
                    .expect("local lock should be acquirable in fuzz round"),
            );
        } else if hold_mode == 1 {
            cross_lock = Some(crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(
                &user,
            ));
            cross_guard = Some(
                cross_lock
                    .as_ref()
                    .expect("cross lock should be present")
                    .try_lock()
                    .expect("cross lock should be acquirable in fuzz round"),
            );
        }

        let mut io = StatsIo::new(
            tokio::io::sink(),
            Arc::new(SharedCounters::new()),
            Arc::clone(&stats),
            user.clone(),
            Some(4096),
            Arc::new(AtomicBool::new(false)),
            Instant::now(),
        );

        let write = timeout(Duration::from_millis(25), io.write_all(&[0x7A])).await;
        if hold_mode == 2 {
            assert!(write.is_ok(), "unheld round must make progress");
        } else {
            assert!(write.is_err(), "held-lock round must stay blocked within timeout");
        }

        drop(local_guard);
        drop(cross_guard);
        drop(local_lock);
        drop(cross_lock);
    }

    assert!(stats.get_user_total_octets(&user) <= 4096);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_fanout_waiters_complete_after_release_without_panics() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-stress-{}", std::process::id());
    let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold cross-mode lock before stress fanout");

    let waiters = 64usize;
    let mut tasks = Vec::new();
    for _ in 0..waiters {
        let user = user.clone();
        tasks.push(tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::empty(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                user,
                Some(1024),
                Arc::new(AtomicBool::new(false)),
                Instant::now(),
            );
            let mut one = [0u8; 1];
            io.read(&mut one).await
        }));
    }

    tokio::time::sleep(Duration::from_millis(12)).await;
    drop(held_guard);

    timeout(Duration::from_secs(2), async {
        for task in tasks {
            let result = task.await.expect("stress waiter task must not panic");
            assert!(result.is_ok());
        }
    })
    .await
    .expect("all stress waiters must complete after release");
}
