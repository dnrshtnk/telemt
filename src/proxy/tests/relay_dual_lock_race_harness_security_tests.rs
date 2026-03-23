use super::*;
use crate::stats::Stats;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use tokio::io::AsyncWriteExt;
use tokio::time::{Duration, timeout};

fn quota_test_guard() -> impl Drop {
    super::quota_user_lock_test_scope()
}

fn make_stats_io(user: String) -> StatsIo<tokio::io::Sink> {
    StatsIo::new(
        tokio::io::sink(),
        Arc::new(SharedCounters::new()),
        Arc::new(Stats::new()),
        user,
        Some(4096),
        Arc::new(AtomicBool::new(false)),
        tokio::time::Instant::now(),
    )
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn light_fuzz_1024_round_hold_release_cycles_preserve_same_user_liveness() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-race-fuzz-{}", std::process::id());
    let mut seed = 0xD1CE_BAAD_5EED_1234u64;

    for round in 0..1024u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let hold = (seed & 1) == 0;
        let hold_ms = (seed % 3) as u64;

        let maybe_lock = if hold {
            Some(crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(
                &user,
            ))
        } else {
            None
        };

        let maybe_guard = maybe_lock.as_ref().map(|lock| {
            lock.try_lock()
                .expect("cross-mode lock must be acquirable in fuzz round")
        });

        if hold {
            let mut blocked_io = make_stats_io(user.clone());
            let blocked = timeout(Duration::from_millis(5), blocked_io.write_all(&[0xA5])).await;
            assert!(
                blocked.is_err(),
                "held round must block waiter before lock release (round={round})"
            );

            if hold_ms > 0 {
                tokio::time::sleep(Duration::from_millis(hold_ms)).await;
            }
        } else {
            let mut free_io = make_stats_io(user.clone());
            let free = timeout(Duration::from_millis(120), free_io.write_all(&[0xA5])).await;
            assert!(
                free.is_ok(),
                "unheld round must complete promptly (round={round})"
            );
            assert!(free.expect("unheld round should complete").is_ok());
        }

        drop(maybe_guard);

        let done = timeout(Duration::from_millis(350), async {
            let user = user.clone();
            let mut io = make_stats_io(user);
            io.write_all(&[0xA6]).await
        })
        .await
        .expect("post-release write must complete in bounded time");
        assert!(done.is_ok());
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_jittered_three_waiter_rounds_do_not_starve_after_release() {
    let _guard = quota_test_guard();

    let user = format!("dual-lock-race-stress-{}", std::process::id());
    let mut seed = 0xC0FF_EE77_4444_9999u64;

    for round in 0..256u32 {
        seed ^= seed << 7;
        seed ^= seed >> 9;
        seed ^= seed << 8;

        let hold_ms = (seed % 4) as u64;
        let lock = crate::proxy::quota_lock_registry::cross_mode_quota_user_lock(&user);
        let guard = lock
            .try_lock()
            .expect("cross-mode lock must be acquirable at round start");

        let mut waiters = Vec::new();
        for _ in 0..3usize {
            let user = user.clone();
            waiters.push(tokio::spawn(async move {
                let mut io = make_stats_io(user);
                io.write_all(&[0x55]).await
            }));
        }

        tokio::time::sleep(Duration::from_millis(hold_ms)).await;
        drop(guard);

        timeout(Duration::from_secs(1), async {
            for waiter in waiters {
                let done = waiter.await.expect("waiter task must not panic");
                assert!(
                    done.is_ok(),
                    "waiter must complete after release (round={round})"
                );
            }
        })
        .await
        .expect("all waiters must complete in bounded time after release");
    }
}
