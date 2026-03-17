use super::*;
use crate::config::{UpstreamConfig, UpstreamType};
use crate::crypto::{AesCtr, SecureRandom};
use crate::protocol::constants::ProtoTag;
use crate::proxy::route_mode::{RelayRouteMode, RouteRuntimeController};
use crate::stats::Stats;
use crate::stream::{BufferPool, CryptoReader, CryptoWriter};
use crate::transport::UpstreamManager;
use std::fs;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tokio::io::duplex;
use tokio::net::TcpListener;

fn make_crypto_reader<R>(reader: R) -> CryptoReader<R>
where
    R: tokio::io::AsyncRead + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoReader::new(reader, AesCtr::new(&key, iv))
}

fn make_crypto_writer<W>(writer: W) -> CryptoWriter<W>
where
    W: tokio::io::AsyncWrite + Unpin,
{
    let key = [0u8; 32];
    let iv = 0u128;
    CryptoWriter::new(writer, AesCtr::new(&key, iv), 8 * 1024)
}

fn nonempty_line_count(text: &str) -> usize {
    text.lines().filter(|line| !line.trim().is_empty()).count()
}

#[test]
fn unknown_dc_log_is_deduplicated_per_dc_idx() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    assert!(should_log_unknown_dc(777));
    assert!(
        !should_log_unknown_dc(777),
        "same unknown dc_idx must not be logged repeatedly"
    );
    assert!(
        should_log_unknown_dc(778),
        "different unknown dc_idx must still be loggable"
    );
}

#[test]
fn unknown_dc_log_respects_distinct_limit() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    for dc in 1..=UNKNOWN_DC_LOG_DISTINCT_LIMIT {
        assert!(
            should_log_unknown_dc(dc as i16),
            "expected first-time unknown dc_idx to be loggable"
        );
    }

    assert!(
        !should_log_unknown_dc(i16::MAX),
        "distinct unknown dc_idx entries above limit must not be logged"
    );
}

#[test]
fn unknown_dc_log_fails_closed_when_dedup_lock_is_poisoned() {
    let poisoned = Arc::new(std::sync::Mutex::new(std::collections::HashSet::<i16>::new()));
    let poisoned_for_thread = poisoned.clone();

    let _ = std::thread::spawn(move || {
        let _guard = poisoned_for_thread
            .lock()
            .expect("poison setup lock must be available");
        panic!("intentional poison for fail-closed regression");
    })
    .join();

    assert!(
        !should_log_unknown_dc_with_set(poisoned.as_ref(), 4242),
        "poisoned unknown-DC dedup lock must fail closed"
    );
}

#[test]
fn stress_unknown_dc_log_concurrent_unique_churn_respects_cap() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    let accepted = Arc::new(AtomicUsize::new(0));
    let mut workers = Vec::new();

    // Adversarial model: many concurrent peers rotate dc_idx values rapidly.
    for worker in 0..16usize {
        let accepted = Arc::clone(&accepted);
        workers.push(std::thread::spawn(move || {
            let base = (worker * 2048) as i32;
            for offset in 0..512i32 {
                let raw = base + offset;
                let dc = (raw % i16::MAX as i32) as i16;
                if should_log_unknown_dc(dc) {
                    accepted.fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    for worker in workers {
        worker.join().expect("worker thread must not panic");
    }

    assert_eq!(
        accepted.load(Ordering::Relaxed),
        UNKNOWN_DC_LOG_DISTINCT_LIMIT,
        "concurrent unique churn must never admit more than the configured distinct cap"
    );
}

#[test]
fn light_fuzz_unknown_dc_log_mixed_duplicates_never_exceeds_cap() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    // Deterministic xorshift sequence for reproducible mixed duplicate fuzzing.
    let mut s: u64 = 0xA5A5_5A5A_C3C3_3C3C;
    let mut admitted = 0usize;

    for _ in 0..20_000 {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;

        let dc = (s as i16).wrapping_sub(i16::MAX / 2);
        if should_log_unknown_dc(dc) {
            admitted += 1;
        }
    }

    assert!(
        admitted <= UNKNOWN_DC_LOG_DISTINCT_LIMIT,
        "mixed-duplicate fuzzed inputs must not admit more than cap"
    );
}

#[test]
fn unknown_dc_log_path_sanitizer_rejects_parent_traversal_inputs() {
    assert!(
        sanitize_unknown_dc_log_path("../unknown-dc.txt").is_none(),
        "parent traversal paths must be rejected"
    );
    assert!(
        sanitize_unknown_dc_log_path("logs/../unknown-dc.txt").is_none(),
        "embedded parent traversal must be rejected"
    );
    assert!(
        sanitize_unknown_dc_log_path("./../unknown-dc.txt").is_none(),
        "relative parent traversal must be rejected"
    );
}

#[test]
fn unknown_dc_log_path_sanitizer_accepts_absolute_paths_with_existing_parent() {
    let absolute = std::env::temp_dir().join("unknown-dc.txt");
    let absolute_str = absolute
        .to_str()
        .expect("temp absolute path must be valid UTF-8");

    let sanitized = sanitize_unknown_dc_log_path(absolute_str)
        .expect("absolute paths with existing parent must be accepted");
    assert_eq!(sanitized, absolute);
}

#[test]
fn unknown_dc_log_path_sanitizer_rejects_absolute_parent_traversal() {
    assert!(
        sanitize_unknown_dc_log_path("/tmp/../etc/passwd").is_none(),
        "absolute parent traversal must be rejected"
    );
}

#[test]
fn unknown_dc_log_path_sanitizer_accepts_safe_relative_path() {
    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!("telemt-unknown-dc-log-{}", std::process::id()));
    fs::create_dir_all(&base).expect("temp test directory must be creatable");

    let candidate = base.join("unknown-dc.txt");
    let candidate_relative = format!("target/telemt-unknown-dc-log-{}/unknown-dc.txt", std::process::id());

    let sanitized = sanitize_unknown_dc_log_path(&candidate_relative)
        .expect("safe relative path with existing parent must be accepted");
    assert_eq!(sanitized, candidate);
}

#[test]
fn unknown_dc_log_path_sanitizer_rejects_empty_or_dot_only_inputs() {
    assert!(
        sanitize_unknown_dc_log_path("").is_none(),
        "empty path must be rejected"
    );
    assert!(
        sanitize_unknown_dc_log_path(".").is_none(),
        "dot-only path without filename must be rejected"
    );
}

#[test]
fn unknown_dc_log_path_sanitizer_accepts_directory_only_as_filename_projection() {
    let sanitized = sanitize_unknown_dc_log_path("target/")
        .expect("directory-only input is interpreted as filename projection in current sanitizer");
    assert!(
        sanitized.ends_with("target"),
        "directory-only input should resolve to canonical parent plus filename projection"
    );
}

#[test]
fn unknown_dc_log_path_sanitizer_accepts_dot_prefixed_relative_path() {
    let rel_dir = format!("target/telemt-unknown-dc-dot-{}", std::process::id());
    let abs_dir = std::env::current_dir()
        .expect("cwd must be available")
        .join(&rel_dir);
    fs::create_dir_all(&abs_dir).expect("dot-prefixed test directory must be creatable");

    let rel_candidate = format!("./{rel_dir}/unknown-dc.log");
    let expected = abs_dir.join("unknown-dc.log");
    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("dot-prefixed safe path must be accepted");
    assert_eq!(sanitized, expected);
}

#[test]
fn light_fuzz_unknown_dc_path_parentdir_inputs_always_rejected() {
    let mut s: u64 = 0xD00D_BAAD_1234_5678;
    for _ in 0..4096 {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let a = (s as usize) % 32;
        let b = ((s >> 8) as usize) % 32;
        let candidate = format!("target/{a}/../{b}/unknown-dc.log");
        assert!(
            sanitize_unknown_dc_log_path(&candidate).is_none(),
            "parent-dir candidate must be rejected: {candidate}"
        );
    }
}

#[test]
fn unknown_dc_log_path_sanitizer_rejects_nonexistent_parent_directory() {
    let rel_candidate = format!(
        "target/telemt-unknown-dc-missing-{}/nested/unknown-dc.txt",
        std::process::id()
    );

    assert!(
        sanitize_unknown_dc_log_path(&rel_candidate).is_none(),
        "path with missing parent must be rejected to avoid implicit directory creation"
    );
}

#[cfg(unix)]
#[test]
fn unknown_dc_log_path_sanitizer_accepts_symlinked_parent_inside_workspace() {
    use std::os::unix::fs::symlink;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!("telemt-unknown-dc-log-symlink-internal-{}", std::process::id()));
    let real_parent = base.join("real_parent");
    fs::create_dir_all(&real_parent).expect("real parent dir must be creatable");

    let symlink_parent = base.join("internal_link");
    let _ = fs::remove_file(&symlink_parent);
    symlink(&real_parent, &symlink_parent).expect("internal symlink must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-log-symlink-internal-{}/internal_link/unknown-dc.txt",
        std::process::id()
    );

    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("symlinked parent that resolves inside workspace must be accepted");
    assert!(
        sanitized.starts_with(&real_parent),
        "sanitized path must resolve to canonical internal parent"
    );
}

#[cfg(unix)]
#[test]
fn unknown_dc_log_path_sanitizer_accepts_symlink_parent_escape_as_canonical_path() {
    use std::os::unix::fs::symlink;

    let base = std::env::current_dir()
        .expect("cwd must be available")
        .join("target")
        .join(format!("telemt-unknown-dc-log-symlink-{}", std::process::id()));
    fs::create_dir_all(&base).expect("symlink test directory must be creatable");

    let symlink_parent = base.join("escape_link");
    let _ = fs::remove_file(&symlink_parent);
    symlink("/tmp", &symlink_parent).expect("symlink parent must be creatable");

    let rel_candidate = format!(
        "target/telemt-unknown-dc-log-symlink-{}/escape_link/unknown-dc.txt",
        std::process::id()
    );

    let sanitized = sanitize_unknown_dc_log_path(&rel_candidate)
        .expect("symlinked parent must canonicalize to target path");
    assert!(
        sanitized.starts_with(Path::new("/tmp")),
        "sanitized path must resolve to canonical symlink target"
    );
}

#[tokio::test]
async fn unknown_dc_absolute_log_path_writes_one_entry() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    let dc_idx: i16 = 31_001;
    let file_path = std::env::temp_dir().join(format!(
        "telemt-unknown-dc-abs-{}-{}.log",
        std::process::id(),
        dc_idx
    ));
    let _ = fs::remove_file(&file_path);

    let mut cfg = ProxyConfig::default();
    cfg.general.unknown_dc_file_log_enabled = true;
    cfg.general.unknown_dc_log_path = Some(
        file_path
            .to_str()
            .expect("temp file path must be valid UTF-8")
            .to_string(),
    );

    let _ = get_dc_addr_static(dc_idx, &cfg).expect("fallback routing must still work");

    let mut content = None;
    for _ in 0..20 {
        if let Ok(text) = fs::read_to_string(&file_path) {
            content = Some(text);
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    let text = content.expect("absolute unknown-DC log path must produce exactly one log write");
    assert!(
        text.contains(&format!("dc_idx={dc_idx}")),
        "absolute unknown-DC integration log must contain requested dc_idx"
    );
}

#[tokio::test]
async fn unknown_dc_safe_relative_log_path_writes_one_entry() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    let dc_idx: i16 = 31_002;
    let rel_dir = format!("target/telemt-unknown-dc-int-{}", std::process::id());
    let rel_file = format!("{rel_dir}/unknown-dc.log");
    let abs_dir = std::env::current_dir()
        .expect("cwd must be available")
        .join(&rel_dir);
    fs::create_dir_all(&abs_dir).expect("integration test log directory must be creatable");
    let abs_file = abs_dir.join("unknown-dc.log");
    let _ = fs::remove_file(&abs_file);

    let mut cfg = ProxyConfig::default();
    cfg.general.unknown_dc_file_log_enabled = true;
    cfg.general.unknown_dc_log_path = Some(rel_file);

    let _ = get_dc_addr_static(dc_idx, &cfg).expect("fallback routing must still work");

    let mut content = None;
    for _ in 0..20 {
        if let Ok(text) = fs::read_to_string(&abs_file) {
            content = Some(text);
            break;
        }
        tokio::time::sleep(Duration::from_millis(15)).await;
    }

    let text = content.expect("safe relative path must produce exactly one log write");
    assert!(
        text.contains(&format!("dc_idx={dc_idx}")),
        "unknown-DC integration log must contain requested dc_idx"
    );
}

#[tokio::test]
async fn unknown_dc_same_index_burst_writes_only_once() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    let dc_idx: i16 = 31_010;
    let rel_dir = format!("target/telemt-unknown-dc-same-{}", std::process::id());
    let rel_file = format!("{rel_dir}/unknown-dc.log");
    let abs_dir = std::env::current_dir().unwrap().join(&rel_dir);
    fs::create_dir_all(&abs_dir).expect("same-index log directory must be creatable");
    let abs_file = abs_dir.join("unknown-dc.log");
    let _ = fs::remove_file(&abs_file);

    let mut cfg = ProxyConfig::default();
    cfg.general.unknown_dc_file_log_enabled = true;
    cfg.general.unknown_dc_log_path = Some(rel_file);

    for _ in 0..64 {
        let _ = get_dc_addr_static(dc_idx, &cfg).expect("fallback routing must still work");
    }

    let mut content = None;
    for _ in 0..30 {
        if let Ok(text) = fs::read_to_string(&abs_file) {
            content = Some(text);
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let text = content.expect("same-index burst must produce at least one log write");
    assert_eq!(
        nonempty_line_count(&text),
        1,
        "same unknown dc index must be deduplicated to one file line"
    );
}

#[tokio::test]
async fn unknown_dc_distinct_burst_is_hard_capped_on_file_writes() {
    let _guard = unknown_dc_test_lock()
        .lock()
        .expect("unknown dc test lock must be available");
    clear_unknown_dc_log_cache_for_testing();

    let rel_dir = format!("target/telemt-unknown-dc-cap-{}", std::process::id());
    let rel_file = format!("{rel_dir}/unknown-dc.log");
    let abs_dir = std::env::current_dir().unwrap().join(&rel_dir);
    fs::create_dir_all(&abs_dir).expect("cap log directory must be creatable");
    let abs_file = abs_dir.join("unknown-dc.log");
    let _ = fs::remove_file(&abs_file);

    let mut cfg = ProxyConfig::default();
    cfg.general.unknown_dc_file_log_enabled = true;
    cfg.general.unknown_dc_log_path = Some(rel_file);

    for i in 0..(UNKNOWN_DC_LOG_DISTINCT_LIMIT + 128) {
        let dc_idx = 20_000i16.wrapping_add(i as i16);
        let _ = get_dc_addr_static(dc_idx, &cfg).expect("fallback routing must still work");
    }

    let mut final_text = String::new();
    for _ in 0..80 {
        if let Ok(text) = fs::read_to_string(&abs_file) {
            final_text = text;
            if nonempty_line_count(&final_text) >= UNKNOWN_DC_LOG_DISTINCT_LIMIT {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let line_count = nonempty_line_count(&final_text);
    assert!(
        line_count > 0,
        "distinct unknown-dc burst must write at least one line"
    );
    assert!(
        line_count <= UNKNOWN_DC_LOG_DISTINCT_LIMIT,
        "distinct unknown-dc writes must stay within dedup hard cap"
    );
}

#[test]
fn fallback_dc_never_panics_with_single_dc_list() {
    let mut cfg = ProxyConfig::default();
    cfg.network.prefer = 6;
    cfg.network.ipv6 = Some(true);
    cfg.default_dc = Some(42);

    let addr = get_dc_addr_static(999, &cfg).expect("fallback dc must resolve safely");
    let expected = SocketAddr::new(TG_DATACENTERS_V6[0], TG_DATACENTER_PORT);
    assert_eq!(addr, expected);
}

#[tokio::test]
async fn direct_relay_abort_midflight_releases_route_gauge() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (stream, _) = tg_listener.accept().await.unwrap();
        let _hold_stream = stream;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats.clone(),
    ));

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "abort-direct-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50000".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_direct(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xabad1dea,
    ));

    let started = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_current_connections_direct() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await;
    assert!(started.is_ok(), "direct relay must increment route gauge before abort");

    relay_task.abort();
    let joined = relay_task.await;
    assert!(joined.is_err(), "aborted direct relay task must return join error");

    tokio::time::sleep(Duration::from_millis(20)).await;
    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "route gauge must be released when direct relay task is aborted mid-flight"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[tokio::test]
async fn direct_relay_cutover_midflight_releases_route_gauge() {
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let (stream, _) = tg_listener.accept().await.unwrap();
        let _hold_stream = stream;
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats.clone(),
    ));

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let (server_side, client_side) = duplex(64 * 1024);
    let (server_reader, server_writer) = tokio::io::split(server_side);
    let client_reader = make_crypto_reader(server_reader);
    let client_writer = make_crypto_writer(server_writer);

    let success = HandshakeSuccess {
        user: "cutover-direct-user".to_string(),
        dc_idx: 2,
        proto_tag: ProtoTag::Intermediate,
        dec_key: [0u8; 32],
        dec_iv: 0,
        enc_key: [0u8; 32],
        enc_iv: 0,
        peer: "127.0.0.1:50002".parse().unwrap(),
        is_tls: false,
    };

    let relay_task = tokio::spawn(handle_via_direct(
        client_reader,
        client_writer,
        success,
        upstream_manager,
        stats.clone(),
        config,
        buffer_pool,
        rng,
        route_runtime.subscribe(),
        route_snapshot,
        0xface_cafe,
    ));

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if stats.get_current_connections_direct() == 1 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("direct relay must increment route gauge before cutover");

    assert!(
        route_runtime.set_mode(RelayRouteMode::Middle).is_some(),
        "cutover must advance route generation"
    );

    let relay_result = tokio::time::timeout(Duration::from_secs(6), relay_task)
        .await
        .expect("direct relay must terminate after cutover")
        .expect("direct relay task must not panic");
    assert!(
        relay_result.is_err(),
        "cutover should terminate direct relay session"
    );
    assert!(
        matches!(
            relay_result,
            Err(ProxyError::Proxy(ref msg)) if msg == ROUTE_SWITCH_ERROR_MSG
        ),
        "client-visible cutover error must stay generic and avoid route-internal metadata"
    );

    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "route gauge must be released when direct relay exits on cutover"
    );

    drop(client_side);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}

#[tokio::test]
async fn direct_relay_cutover_storm_multi_session_keeps_generic_errors_and_releases_gauge() {
    let session_count = 6usize;
    let tg_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tg_addr = tg_listener.local_addr().unwrap();

    let tg_accept_task = tokio::spawn(async move {
        let mut held_streams = Vec::with_capacity(session_count);
        for _ in 0..session_count {
            let (stream, _) = tg_listener.accept().await.unwrap();
            held_streams.push(stream);
        }
        tokio::time::sleep(Duration::from_secs(60)).await;
        drop(held_streams);
    });

    let stats = Arc::new(Stats::new());
    let mut config = ProxyConfig::default();
    config
        .dc_overrides
        .insert("2".to_string(), vec![tg_addr.to_string()]);
    let config = Arc::new(config);

    let upstream_manager = Arc::new(UpstreamManager::new(
        vec![UpstreamConfig {
            upstream_type: UpstreamType::Direct {
                interface: None,
                bind_addresses: None,
            },
            weight: 1,
            enabled: true,
            scopes: String::new(),
            selected_scope: String::new(),
        }],
        1,
        1,
        1,
        1,
        false,
        stats.clone(),
    ));

    let rng = Arc::new(SecureRandom::new());
    let buffer_pool = Arc::new(BufferPool::new());
    let route_runtime = Arc::new(RouteRuntimeController::new(RelayRouteMode::Direct));
    let route_snapshot = route_runtime.snapshot();

    let mut relay_tasks = Vec::with_capacity(session_count);
    let mut client_sides = Vec::with_capacity(session_count);

    for idx in 0..session_count {
        let (server_side, client_side) = duplex(64 * 1024);
        client_sides.push(client_side);
        let (server_reader, server_writer) = tokio::io::split(server_side);
        let client_reader = make_crypto_reader(server_reader);
        let client_writer = make_crypto_writer(server_writer);

        let success = HandshakeSuccess {
            user: format!("cutover-storm-direct-user-{idx}"),
            dc_idx: 2,
            proto_tag: ProtoTag::Intermediate,
            dec_key: [0u8; 32],
            dec_iv: 0,
            enc_key: [0u8; 32],
            enc_iv: 0,
            peer: SocketAddr::new(
                std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)),
                51000 + idx as u16,
            ),
            is_tls: false,
        };

        relay_tasks.push(tokio::spawn(handle_via_direct(
            client_reader,
            client_writer,
            success,
            upstream_manager.clone(),
            stats.clone(),
            config.clone(),
            buffer_pool.clone(),
            rng.clone(),
            route_runtime.subscribe(),
            route_snapshot,
            0xA000_0000 + idx as u64,
        )));
    }

    tokio::time::timeout(Duration::from_secs(4), async {
        loop {
            if stats.get_current_connections_direct() == session_count as u64 {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("all direct sessions must become active before cutover storm");

    let route_runtime_flipper = route_runtime.clone();
    let flipper = tokio::spawn(async move {
        for step in 0..64u32 {
            let mode = if (step & 1) == 0 {
                RelayRouteMode::Middle
            } else {
                RelayRouteMode::Direct
            };
            let _ = route_runtime_flipper.set_mode(mode);
            tokio::time::sleep(Duration::from_millis(15)).await;
        }
    });

    for relay_task in relay_tasks {
        let relay_result = tokio::time::timeout(Duration::from_secs(10), relay_task)
            .await
            .expect("direct relay task must finish under cutover storm")
            .expect("direct relay task must not panic");

        assert!(
            matches!(
                relay_result,
                Err(ProxyError::Proxy(ref msg)) if msg == ROUTE_SWITCH_ERROR_MSG
            ),
            "storm-cutover termination must remain generic for all direct sessions"
        );
    }

    flipper.abort();
    let _ = flipper.await;

    assert_eq!(
        stats.get_current_connections_direct(),
        0,
        "direct route gauge must return to zero after cutover storm"
    );

    drop(client_sides);
    tg_accept_task.abort();
    let _ = tg_accept_task.await;
}
