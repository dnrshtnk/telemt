use super::*;
use crate::stats::Stats;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll, Waker};
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::sync::Barrier;
use tokio::time::{Duration, timeout};

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
async fn positive_cross_mode_uncontended_writer_progresses() {
    let _guard = quota_test_guard();

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        "cross-mode-tdd-uncontended".to_string(),
        Some(4096),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let result = io.write_all(&[0x11, 0x22]).await;
    assert!(result.is_ok(), "uncontended writer must progress");
}

#[tokio::test]
async fn adversarial_held_cross_mode_lock_blocks_writer_even_if_local_lock_free() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-tdd-held-{}", std::process::id());
    let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold cross-mode lock before polling writer");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        Some(4096),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let wake_counter = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wake_counter));
    let mut cx = Context::from_waker(&waker);

    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0xAA]);
    assert!(poll.is_pending(), "writer must not bypass held cross-mode lock");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_parallel_waiters_resume_after_cross_mode_release() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-tdd-resume-{}", std::process::id());
    let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold cross-mode lock before launching waiters");

    let stats = Arc::new(Stats::new());
    let mut waiters = Vec::new();
    for _ in 0..16 {
        let stats = Arc::clone(&stats);
        let user = user.clone();
        waiters.push(tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                stats,
                user,
                Some(4096),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            io.write_all(&[0x7F]).await
        }));
    }

    tokio::time::sleep(Duration::from_millis(5)).await;
    drop(held_guard);

    timeout(Duration::from_secs(1), async {
        for waiter in waiters {
            let result = waiter.await.expect("waiter task must not panic");
            assert!(result.is_ok(), "waiter must complete after cross-mode release");
        }
    })
    .await
    .expect("all waiters must complete in bounded time");
}

#[tokio::test]
async fn adversarial_cross_mode_contention_wake_budget_stays_bounded() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-tdd-wakes-{}", std::process::id());
    let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold cross-mode lock before polling");

    let stats = Arc::new(Stats::new());
    let mut ios = Vec::new();
    let mut counters = Vec::new();
    for _ in 0..20 {
        ios.push(StatsIo::new(
            tokio::io::sink(),
            Arc::new(SharedCounters::new()),
            Arc::clone(&stats),
            user.clone(),
            Some(2048),
            Arc::new(AtomicBool::new(false)),
            tokio::time::Instant::now(),
        ));
    }

    for io in &mut ios {
        let wake_counter = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&wake_counter));
        let mut cx = Context::from_waker(&waker);
        let poll = Pin::new(io).poll_write(&mut cx, &[0x33]);
        assert!(poll.is_pending());
        counters.push(wake_counter);
    }

    tokio::time::sleep(Duration::from_millis(25)).await;
    let total_wakes: usize = counters
        .iter()
        .map(|counter| counter.wakes.load(Ordering::Relaxed))
        .sum();

    assert!(
        total_wakes <= 20 * 4,
        "cross-mode contention should not create wake storms; wakes={total_wakes}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn light_fuzz_cross_mode_release_timing_preserves_read_write_liveness() {
    let _guard = quota_test_guard();

    let mut seed = 0xC0DE_BAAD_2026_0322u64;
    for round in 0..16u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let sleep_ms = 2 + (seed as u64 % 8);
        let user = format!("cross-mode-tdd-fuzz-{}-{round}", std::process::id());
        let held = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
        let held_guard = held
            .try_lock()
            .expect("test must hold cross-mode lock in fuzz round");

        let stats = Arc::new(Stats::new());
        let user_reader = user.clone();
        let reader_task = tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::empty(),
                Arc::new(SharedCounters::new()),
                Arc::clone(&stats),
                user_reader,
                Some(4096),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            let mut one = [0u8; 1];
            io.read(&mut one).await
        });

        let user_writer = user.clone();
        let writer_task = tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                user_writer,
                Some(4096),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            io.write_all(&[0x44]).await
        });

        tokio::time::sleep(Duration::from_millis(sleep_ms)).await;
        drop(held_guard);

        let read_done = timeout(Duration::from_millis(350), reader_task)
            .await
            .expect("reader task must complete after release")
            .expect("reader task must not panic");
        assert!(read_done.is_ok());

        let write_done = timeout(Duration::from_millis(350), writer_task)
            .await
            .expect("writer task must complete after release")
            .expect("writer task must not panic");
        assert!(write_done.is_ok());
    }
}

#[tokio::test]
async fn integration_middle_lock_blocks_relay_reader_for_same_user() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-middle-reader-block-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold middle-relay shared lock");

    let mut io = StatsIo::new(
        tokio::io::empty(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let (_wake_counter, mut cx) = build_context();
    let mut one = [0u8; 1];
    let mut buf = ReadBuf::new(&mut one);
    let poll = Pin::new(&mut io).poll_read(&mut cx, &mut buf);
    assert!(poll.is_pending());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn integration_middle_lock_release_unblocks_relay_reader() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-middle-reader-release-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold middle-relay shared lock");

    let task = tokio::spawn({
        let user = user.clone();
        async move {
            let mut io = StatsIo::new(
                tokio::io::empty(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                user,
                Some(1024),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            let mut one = [0u8; 1];
            io.read(&mut one).await
        }
    });

    tokio::time::sleep(Duration::from_millis(5)).await;
    drop(held_guard);

    let done = timeout(Duration::from_millis(300), task)
        .await
        .expect("reader task must complete after release")
        .expect("reader task must not panic");
    assert!(done.is_ok());
}

#[tokio::test]
async fn business_different_user_middle_lock_does_not_block_relay_writer() {
    let _guard = quota_test_guard();

    let held_user = format!("cross-mode-middle-held-{}", std::process::id());
    let active_user = format!("cross-mode-middle-active-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&held_user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold middle-relay lock for other user");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        active_user,
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let (_wake_counter, mut cx) = build_context();
    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x61]);
    assert!(matches!(poll, Poll::Ready(Ok(1))));
}

#[tokio::test]
async fn edge_quota_none_bypasses_cross_mode_lock_even_when_held() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-none-limit-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold lock while quota is disabled");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        None,
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let (_wake_counter, mut cx) = build_context();
    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x62, 0x63]);
    assert!(matches!(poll, Poll::Ready(Ok(2))));
}

#[tokio::test]
async fn edge_quota_exceeded_flag_short_circuits_before_lock_path() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-pre-exceeded-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold shared lock before poll");

    let quota_exceeded = Arc::new(AtomicBool::new(true));
    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        Some(1024),
        Arc::clone(&quota_exceeded),
        tokio::time::Instant::now(),
    );

    let (_wake_counter, mut cx) = build_context();
    let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x64]);
    assert!(matches!(poll, Poll::Ready(Err(ref e)) if is_quota_io_error(e)));
}

#[tokio::test]
async fn adversarial_repoll_while_middle_lock_held_keeps_pending_without_usage_leak() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-repoll-held-{}", std::process::id());
    let stats = Arc::new(Stats::new());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
    let _held_guard = held
        .try_lock()
        .expect("test must hold lock for repoll sequence");

    let mut io = StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::clone(&stats),
        user.clone(),
        Some(1024),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    );

    let (_wake_counter, mut cx) = build_context();
    for _ in 0..8 {
        let poll = Pin::new(&mut io).poll_write(&mut cx, &[0x65]);
        assert!(poll.is_pending());
    }

    assert_eq!(stats.get_user_total_octets(&user), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_same_user_mixed_read_write_waiters_resume_after_release() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-mixed-resume-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold lock before spawning mixed waiters");

    let mut tasks = Vec::new();
    for i in 0..12usize {
        let user = user.clone();
        tasks.push(tokio::spawn(async move {
            if i % 2 == 0 {
                let mut io = StatsIo::new(
                    tokio::io::empty(),
                    Arc::new(SharedCounters::new()),
                    Arc::new(Stats::new()),
                    user,
                    Some(1024),
                    Arc::new(AtomicBool::new(false)),
                    tokio::time::Instant::now(),
                );
                let mut b = [0u8; 1];
                io.read(&mut b).await.map(|_| ())
            } else {
                let mut io = StatsIo::new(
                    tokio::io::sink(),
                    Arc::new(SharedCounters::new()),
                    Arc::new(Stats::new()),
                    user,
                    Some(1024),
                    Arc::new(AtomicBool::new(false)),
                    tokio::time::Instant::now(),
                );
                io.write_all(&[0x66]).await
            }
        }));
    }

    tokio::time::sleep(Duration::from_millis(8)).await;
    drop(held_guard);

    timeout(Duration::from_secs(1), async {
        for task in tasks {
            let result = task.await.expect("mixed waiter task must not panic");
            assert!(result.is_ok());
        }
    })
    .await
    .expect("all mixed waiters must finish after release");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn integration_one_user_blocked_other_user_progresses_under_middle_lock() {
    let _guard = quota_test_guard();

    let blocked_user = format!("cross-mode-blocked-{}", std::process::id());
    let free_user = format!("cross-mode-free-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&blocked_user);
    let held_guard = held
        .try_lock()
        .expect("test must hold blocked user lock");

    let blocked_task = tokio::spawn({
        let blocked_user = blocked_user.clone();
        async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                blocked_user,
                Some(1024),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            io.write_all(&[0x77]).await
        }
    });

    let free_task = tokio::spawn({
        let free_user = free_user.clone();
        async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                free_user,
                Some(1024),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            io.write_all(&[0x78]).await
        }
    });

    let free_done = timeout(Duration::from_millis(250), free_task)
        .await
        .expect("free user must not be blocked")
        .expect("free user task must not panic");
    assert!(free_done.is_ok());

    drop(held_guard);
    let blocked_done = timeout(Duration::from_secs(1), blocked_task)
        .await
        .expect("blocked user must resume after release")
        .expect("blocked user task must not panic");
    assert!(blocked_done.is_ok());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_middle_lock_release_allows_high_waiter_fanout_completion() {
    let _guard = quota_test_guard();

    let user = format!("cross-mode-fanout-{}", std::process::id());
    let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
    let held_guard = held
        .try_lock()
        .expect("test must hold lock before fanout");

    let waiters = 48usize;
    let gate = Arc::new(Barrier::new(waiters + 1));
    let mut tasks = Vec::new();
    for _ in 0..waiters {
        let user = user.clone();
        let gate = Arc::clone(&gate);
        tasks.push(tokio::spawn(async move {
            let mut io = StatsIo::new(
                tokio::io::sink(),
                Arc::new(SharedCounters::new()),
                Arc::new(Stats::new()),
                user,
                Some(1024),
                Arc::new(AtomicBool::new(false)),
                tokio::time::Instant::now(),
            );
            gate.wait().await;
            io.write_all(&[0x79]).await
        }));
    }

    gate.wait().await;
    tokio::time::sleep(Duration::from_millis(10)).await;
    drop(held_guard);

    timeout(Duration::from_secs(2), async {
        for task in tasks {
            let result = task.await.expect("fanout task must not panic");
            assert!(result.is_ok());
        }
    })
    .await
    .expect("fanout waiters must complete after release");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn light_fuzz_middle_lock_hold_release_cycles_preserve_same_user_liveness() {
    let _guard = quota_test_guard();

    let mut seed = 0xA11C_EE55_2026_0323u64;
    for round in 0..20u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let hold_ms = 2 + (seed % 10);
        let user = format!("cross-mode-middle-fuzz-{}-{round}", std::process::id());
        let held = crate::proxy::middle_relay::cross_mode_quota_user_lock_for_tests(&user);
        let held_guard = held
            .try_lock()
            .expect("test must hold lock in fuzz round");

        let writer = tokio::spawn({
            let user = user.clone();
            async move {
                let mut io = StatsIo::new(
                    tokio::io::sink(),
                    Arc::new(SharedCounters::new()),
                    Arc::new(Stats::new()),
                    user,
                    Some(1024),
                    Arc::new(AtomicBool::new(false)),
                    tokio::time::Instant::now(),
                );
                io.write_all(&[0x7A]).await
            }
        });

        tokio::time::sleep(Duration::from_millis(hold_ms)).await;
        drop(held_guard);

        let done = timeout(Duration::from_millis(400), writer)
            .await
            .expect("writer must complete after lock release")
            .expect("writer task must not panic");
        assert!(done.is_ok());
    }
}
