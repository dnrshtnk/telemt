use super::*;
use crate::stats::Stats;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Waker};
use tokio::time::{Duration, Instant};

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
async fn adversarial_cross_mode_only_contention_backoff_attempt_must_ramp() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-backoff-{}", std::process::id());
    let cross_mode_lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let held_cross_mode_guard = cross_mode_lock
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

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let first = Pin::new(&mut io).poll_write(&mut cx, &[0xAA]);
    assert!(first.is_pending(), "held cross-mode lock must block writer");

    let started = Instant::now();
    let mut last_wakes = 0usize;
    while started.elapsed() < Duration::from_millis(120) {
        let wakes = wake_counter.wakes.load(Ordering::Relaxed);
        if wakes > last_wakes {
            last_wakes = wakes;
            let next = Pin::new(&mut io).poll_write(&mut cx, &[0xAB]);
            assert!(next.is_pending(), "writer must remain blocked while lock is held");
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }

    assert!(
        io.quota_write_retry_attempt >= 2,
        "retry attempt must ramp under sustained second-lock contention; got {}",
        io.quota_write_retry_attempt
    );

    drop(held_cross_mode_guard);
}
