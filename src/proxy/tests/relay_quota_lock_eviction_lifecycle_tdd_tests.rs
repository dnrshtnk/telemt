use super::*;
use dashmap::DashMap;
use std::sync::Arc;
use tokio::time::{Duration, timeout};

#[test]
fn tdd_explicit_quota_lock_evict_reclaims_only_unheld_entries() {
    let _guard = quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let held_user = format!("quota-evict-held-{}", std::process::id());
    let stale_a_user = format!("quota-evict-stale-a-{}", std::process::id());
    let stale_b_user = format!("quota-evict-stale-b-{}", std::process::id());

    let held = quota_user_lock(&held_user);
    let stale_a = quota_user_lock(&stale_a_user);
    let stale_b = quota_user_lock(&stale_b_user);

    assert!(map.get(&held_user).is_some());
    assert!(map.get(&stale_a_user).is_some());
    assert!(map.get(&stale_b_user).is_some());

    drop(stale_a);
    drop(stale_b);

    quota_user_lock_evict();

    assert!(
        map.get(&held_user).is_some(),
        "held entry must survive eviction"
    );
    assert!(
        map.get(&stale_a_user).is_none(),
        "unheld stale entry must be reclaimed"
    );
    assert!(
        map.get(&stale_b_user).is_none(),
        "unheld stale entry must be reclaimed"
    );

    drop(held);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tdd_periodic_quota_lock_evictor_reclaims_stale_entries_off_hot_path() {
    let _guard = quota_user_lock_test_scope();
    let map = QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    map.clear();

    let held_user = format!("quota-evict-loop-held-{}", std::process::id());
    let stale_user = format!("quota-evict-loop-stale-{}", std::process::id());

    let held = quota_user_lock(&held_user);
    let stale = quota_user_lock(&stale_user);

    assert_eq!(map.len(), 2);
    drop(stale);

    let evictor = spawn_quota_user_lock_evictor_for_tests(Duration::from_millis(5));

    timeout(Duration::from_millis(200), async {
        loop {
            if map.get(&stale_user).is_none() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .expect("periodic quota lock evictor must reclaim stale entry");

    evictor.abort();

    assert!(map.get(&held_user).is_some());
    assert!(map.get(&stale_user).is_none());

    drop(held);
}
