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

fn build_context() -> (Arc<WakeCounter>, Context<'static>) {
    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let leaked_waker: &'static Waker = Box::leak(Box::new(waker));
    (wake_counter, Context::from_waker(leaked_waker))
}

fn sleep_slot_ptr(slot: &Option<Pin<Box<tokio::time::Sleep>>>) -> usize {
    slot.as_ref()
        .map(|sleep| (&**sleep) as *const tokio::time::Sleep as usize)
        .unwrap_or(0)
}

#[tokio::test]
async fn tdd_single_pending_timer_does_not_allocate_on_each_repoll() {
    let _guard = quota_test_guard();

    let user = format!("retry-alloc-single-pending-{}", std::process::id());
    let lock = quota_user_lock(&user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold local lock to force retry scheduling");

    reset_quota_retry_sleep_allocs_for_tests();

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        Some(2048),
        Arc::new(AtomicBool::new(false)),
        Instant::now(),
    );

    let (_wake_counter, mut cx) = build_context();

    let first = Pin::new(&mut io).poll_write(&mut cx, &[0xA1]);
    assert!(first.is_pending());
    let allocs_after_first = quota_retry_sleep_allocs_for_tests();
    let ptr_after_first = sleep_slot_ptr(&io.quota_write_retry_sleep);

    let second = Pin::new(&mut io).poll_write(&mut cx, &[0xA2]);
    assert!(second.is_pending());
    let allocs_after_second = quota_retry_sleep_allocs_for_tests();
    let ptr_after_second = sleep_slot_ptr(&io.quota_write_retry_sleep);

    assert_eq!(allocs_after_first, 1, "first pending poll must allocate one timer");
    assert_eq!(
        allocs_after_second, 1,
        "repoll while the same timer is pending must not allocate again"
    );
    assert_eq!(
        ptr_after_first, ptr_after_second,
        "repoll while pending should retain the same timer allocation"
    );

    drop(held_guard);
}

#[tokio::test]
async fn tdd_retry_cycle_allocates_once_per_fired_timer_cycle_not_per_poll() {
    let _guard = quota_test_guard();

    let user = format!("retry-alloc-per-cycle-{}", std::process::id());
    let lock = quota_user_lock(&user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold local lock to keep write path pending");

    reset_quota_retry_sleep_allocs_for_tests();

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

    let mut polls = 0u64;
    let mut observed_wakes = 0usize;
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(70) {
        let poll = Pin::new(&mut io).poll_write(&mut cx, &[0xB1]);
        polls = polls.saturating_add(1);
        assert!(poll.is_pending());

        let wakes = wake_counter.wakes.load(Ordering::Relaxed);
        if wakes > observed_wakes {
            observed_wakes = wakes;
        }

        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let allocs = quota_retry_sleep_allocs_for_tests();
    assert!(allocs >= 2, "multiple fired cycles should allocate multiple timers");
    assert!(
        allocs < polls,
        "timer allocations must be bounded by cycles, not by every repoll (allocs={allocs}, polls={polls})"
    );

    drop(held_guard);
}

#[tokio::test]
async fn adversarial_backoff_latency_envelope_stays_bounded_under_contention() {
    let _guard = quota_test_guard();

    let user = format!("retry-latency-envelope-{}", std::process::id());
    let lock = quota_user_lock(&user);
    let held_guard = lock
        .try_lock()
        .expect("test must hold local lock for sustained contention");

    reset_quota_retry_sleep_allocs_for_tests();

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

    let first = Pin::new(&mut io).poll_write(&mut cx, &[0xC1]);
    assert!(first.is_pending());

    let started = Instant::now();
    let mut last_wakes = 0usize;
    let mut wake_instants = Vec::new();

    while started.elapsed() < Duration::from_millis(120) {
        let wakes = wake_counter.wakes.load(Ordering::Relaxed);
        if wakes > last_wakes {
            last_wakes = wakes;
            wake_instants.push(Instant::now());
            let pending = Pin::new(&mut io).poll_write(&mut cx, &[0xC2]);
            assert!(pending.is_pending());
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    let mut max_gap = Duration::from_millis(0);
    for idx in 1..wake_instants.len() {
        let gap = wake_instants[idx].saturating_duration_since(wake_instants[idx - 1]);
        if gap > max_gap {
            max_gap = gap;
        }
    }

    assert!(
        max_gap <= Duration::from_millis(35),
        "retry wake gap must remain bounded in test profile; observed max gap={max_gap:?}"
    );
    assert!(
        quota_retry_sleep_allocs_for_tests() <= 16,
        "allocation cycles must remain bounded during a short contention window"
    );

    drop(held_guard);
}

#[tokio::test]
async fn micro_benchmark_release_to_completion_latency_stays_bounded() {
    let _guard = quota_test_guard();

    let rounds = 96usize;
    let mut samples_ms = Vec::with_capacity(rounds);

    for round in 0..rounds {
        let user = format!("retry-release-latency-{}-{round}", std::process::id());
        let lock = quota_user_lock(&user);
        let held_guard = lock
            .try_lock()
            .expect("test must hold local lock before spawning blocked writer");

        let writer = tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                user,
                Some(2048),
                Arc::new(AtomicBool::new(false)),
                Instant::now(),
            );
            io.write_all(&[0xD1]).await
        });

        tokio::time::sleep(Duration::from_millis(2)).await;
        let release_at = Instant::now();
        drop(held_guard);

        let done = timeout(Duration::from_millis(120), writer)
            .await
            .expect("blocked writer must complete after release")
            .expect("writer task must not panic");
        assert!(done.is_ok());

        samples_ms.push(release_at.elapsed().as_millis() as u64);
    }

    samples_ms.sort_unstable();
    let p95_idx = ((samples_ms.len() * 95) / 100).min(samples_ms.len().saturating_sub(1));
    let p95_ms = samples_ms[p95_idx];

    assert!(
        p95_ms <= 40,
        "contention release->completion p95 must stay bounded; p95_ms={p95_ms}, samples={samples_ms:?}"
    );
}
