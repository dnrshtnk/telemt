use dashmap::DashMap;
use std::sync::{Arc, OnceLock};
use tokio::sync::Mutex;

#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};

#[cfg(test)]
const CROSS_MODE_QUOTA_USER_LOCKS_MAX: usize = 64;
#[cfg(not(test))]
const CROSS_MODE_QUOTA_USER_LOCKS_MAX: usize = 4_096;
#[cfg(test)]
const CROSS_MODE_QUOTA_OVERFLOW_LOCK_STRIPES: usize = 16;
#[cfg(not(test))]
const CROSS_MODE_QUOTA_OVERFLOW_LOCK_STRIPES: usize = 256;

static CROSS_MODE_QUOTA_USER_LOCKS: OnceLock<DashMap<String, Arc<Mutex<()>>>> = OnceLock::new();
static CROSS_MODE_QUOTA_USER_OVERFLOW_LOCKS: OnceLock<Vec<Arc<Mutex<()>>>> = OnceLock::new();

#[cfg(test)]
static CROSS_MODE_QUOTA_USER_LOCK_LOOKUPS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static CROSS_MODE_QUOTA_USER_LOOKUPS_BY_USER: OnceLock<DashMap<String, usize>> = OnceLock::new();

fn cross_mode_quota_overflow_user_lock(user: &str) -> Arc<Mutex<()>> {
    let stripes = CROSS_MODE_QUOTA_USER_OVERFLOW_LOCKS.get_or_init(|| {
        (0..CROSS_MODE_QUOTA_OVERFLOW_LOCK_STRIPES)
            .map(|_| Arc::new(Mutex::new(())))
            .collect()
    });

    let hash = crc32fast::hash(user.as_bytes()) as usize;
    Arc::clone(&stripes[hash % stripes.len()])
}

pub(crate) fn cross_mode_quota_user_lock(user: &str) -> Arc<Mutex<()>> {
    #[cfg(test)]
    {
        CROSS_MODE_QUOTA_USER_LOCK_LOOKUPS.fetch_add(1, Ordering::Relaxed);
        let lookups = CROSS_MODE_QUOTA_USER_LOOKUPS_BY_USER.get_or_init(DashMap::new);
        let mut entry = lookups.entry(user.to_string()).or_insert(0);
        *entry += 1;
    }

    let locks = CROSS_MODE_QUOTA_USER_LOCKS.get_or_init(DashMap::new);
    if let Some(existing) = locks.get(user) {
        return Arc::clone(existing.value());
    }

    if locks.len() >= CROSS_MODE_QUOTA_USER_LOCKS_MAX {
        locks.retain(|_, value| Arc::strong_count(value) > 1);
    }

    if locks.len() >= CROSS_MODE_QUOTA_USER_LOCKS_MAX {
        return cross_mode_quota_overflow_user_lock(user);
    }

    let created = Arc::new(Mutex::new(()));
    match locks.entry(user.to_string()) {
        dashmap::mapref::entry::Entry::Occupied(entry) => Arc::clone(entry.get()),
        dashmap::mapref::entry::Entry::Vacant(entry) => {
            entry.insert(Arc::clone(&created));
            created
        }
    }
}

#[cfg(test)]
pub(crate) fn reset_cross_mode_quota_user_lock_lookup_count_for_tests() {
    CROSS_MODE_QUOTA_USER_LOCK_LOOKUPS.store(0, Ordering::Relaxed);
    let lookups = CROSS_MODE_QUOTA_USER_LOOKUPS_BY_USER.get_or_init(DashMap::new);
    lookups.clear();
}

#[cfg(test)]
pub(crate) fn cross_mode_quota_user_lock_lookup_count_for_tests() -> usize {
    CROSS_MODE_QUOTA_USER_LOCK_LOOKUPS.load(Ordering::Relaxed)
}

#[cfg(test)]
pub(crate) fn cross_mode_quota_user_lock_lookup_count_for_user_for_tests(user: &str) -> usize {
    let lookups = CROSS_MODE_QUOTA_USER_LOOKUPS_BY_USER.get_or_init(DashMap::new);
    lookups.get(user).map(|entry| *entry).unwrap_or(0)
}

#[cfg(test)]
#[path = "tests/quota_lock_registry_cross_mode_adversarial_tests.rs"]
mod quota_lock_registry_cross_mode_adversarial_tests;
