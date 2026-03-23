use super::*;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::task::JoinSet;
use tokio::time::{Duration, timeout};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_background_evictor_with_high_churn_keeps_cache_bounded_and_live() {
    let _guard = quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let evictor = spawn_quota_user_lock_evictor_for_tests(Duration::from_millis(5));

    let mut tasks = JoinSet::new();
    for worker in 0..24u32 {
        tasks.spawn(async move {
            for round in 0..320u32 {
                let user = format!(
                    "quota-evict-stress-user-{}-{}-{}",
                    std::process::id(),
                    worker,
                    round
                );
                let lock = quota_user_lock(&user);
                if round % 19 == 0 {
                    tokio::task::yield_now().await;
                }
                drop(lock);
            }
        });
    }

    while let Some(done) = tasks.join_next().await {
        done.expect("stress worker must not panic");
    }

    quota_user_lock_evict();
    tokio::time::sleep(Duration::from_millis(20)).await;

    assert!(
        map.len() <= QUOTA_USER_LOCKS_MAX,
        "quota lock map must remain bounded after churn + eviction"
    );

    let sanity_user = format!("quota-evict-stress-sanity-{}", std::process::id());
    let sanity_lock = quota_user_lock(&sanity_user);
    assert!(
        map.get(&sanity_user).is_some(),
        "sanity user should be cacheable after eviction reclaimed stale entries"
    );

    drop(sanity_lock);
    evictor.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn adversarial_held_lock_survives_repeated_eviction_then_reclaims_after_release() {
    let _guard = quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let held_user = format!("quota-evict-held-survive-{}", std::process::id());
    let held = quota_user_lock(&held_user);

    let evictor = spawn_quota_user_lock_evictor_for_tests(Duration::from_millis(3));

    for idx in 0..512u32 {
        let user = format!("quota-evict-held-churn-{}-{}", std::process::id(), idx);
        let temp = quota_user_lock(&user);
        drop(temp);
        if idx % 32 == 0 {
            tokio::task::yield_now().await;
        }
    }

    let reacquired = quota_user_lock(&held_user);
    assert!(
        Arc::ptr_eq(&held, &reacquired),
        "held user lock identity must remain stable across repeated evictions"
    );
    assert!(
        map.get(&held_user).is_some(),
        "held user entry must not be reclaimed while externally referenced"
    );

    drop(reacquired);
    drop(held);

    timeout(Duration::from_millis(300), async {
        loop {
            if map.get(&held_user).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("released held lock must be reclaimed by periodic evictor");

    evictor.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stress_saturation_then_periodic_eviction_recovers_cacheability_without_inline_retain() {
    let _guard = quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let mut retained = Vec::with_capacity(QUOTA_USER_LOCKS_MAX);
    let prefix = format!("quota-evict-saturated-{}", std::process::id());
    for idx in 0..QUOTA_USER_LOCKS_MAX {
        retained.push(quota_user_lock(&format!("{prefix}-{idx}")));
    }

    assert_eq!(map.len(), QUOTA_USER_LOCKS_MAX);

    let overflow_user = format!("quota-evict-overflow-user-{}", std::process::id());
    let overflow_before = quota_user_lock(&overflow_user);
    assert!(
        map.get(&overflow_user).is_none(),
        "saturated map must initially route new user to overflow stripe"
    );

    drop(retained);

    let evictor = spawn_quota_user_lock_evictor_for_tests(Duration::from_millis(4));

    timeout(Duration::from_millis(400), async {
        loop {
            if map.len() < QUOTA_USER_LOCKS_MAX {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("periodic evictor must reclaim stale saturated entries");

    let overflow_after = quota_user_lock(&overflow_user);
    assert!(
        map.get(&overflow_user).is_some(),
        "after eviction, overflow user should become cacheable again"
    );
    assert!(
        Arc::strong_count(&overflow_after) >= 2,
        "cacheable lock should be held by map and caller"
    );

    drop(overflow_before);
    drop(overflow_after);
    evictor.abort();
}
