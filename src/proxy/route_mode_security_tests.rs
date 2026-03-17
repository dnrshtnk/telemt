use super::*;

#[test]
fn cutover_stagger_delay_is_deterministic_for_same_inputs() {
    let d1 = cutover_stagger_delay(0x0123_4567_89ab_cdef, 42);
    let d2 = cutover_stagger_delay(0x0123_4567_89ab_cdef, 42);
    assert_eq!(
        d1, d2,
        "stagger delay must be deterministic for identical session/generation inputs"
    );
}

#[test]
fn cutover_stagger_delay_stays_within_budget_bounds() {
    // Black-hat model: censors trigger many cutovers and correlate disconnect timing.
    // Keep delay inside a narrow coarse window to avoid long-tail spikes.
    for generation in [0u64, 1, 2, 3, 16, 128, u32::MAX as u64, u64::MAX] {
        for session_id in [
            0u64,
            1,
            2,
            0xdead_beef,
            0xfeed_face_cafe_babe,
            u64::MAX,
        ] {
            let delay = cutover_stagger_delay(session_id, generation);
            assert!(
                (1000..=1999).contains(&delay.as_millis()),
                "stagger delay must remain in fixed 1000..=1999ms budget"
            );
        }
    }
}

#[test]
fn cutover_stagger_delay_changes_with_generation_for_same_session() {
    let session_id = 0x0123_4567_89ab_cdef;
    let first = cutover_stagger_delay(session_id, 100);
    let second = cutover_stagger_delay(session_id, 101);
    assert_ne!(
        first, second,
        "adjacent cutover generations should decorrelate disconnect delays"
    );
}

#[test]
fn route_runtime_set_mode_is_idempotent_for_same_mode() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Direct);
    let first = runtime.snapshot();
    let changed = runtime.set_mode(RelayRouteMode::Direct);
    let second = runtime.snapshot();

    assert!(
        changed.is_none(),
        "setting already-active mode must not produce a cutover event"
    );
    assert_eq!(
        first.generation, second.generation,
        "idempotent mode set must not bump generation"
    );
}

#[test]
fn affected_cutover_state_triggers_only_for_newer_generation() {
    let runtime = RouteRuntimeController::new(RelayRouteMode::Direct);
    let rx = runtime.subscribe();
    let initial = runtime.snapshot();

    assert!(
        affected_cutover_state(&rx, RelayRouteMode::Direct, initial.generation).is_none(),
        "current generation must not be considered a cutover for existing session"
    );

    let next = runtime
        .set_mode(RelayRouteMode::Middle)
        .expect("mode change must produce cutover state");
    let seen = affected_cutover_state(&rx, RelayRouteMode::Direct, initial.generation)
        .expect("newer generation must be observed as cutover");

    assert_eq!(seen.generation, next.generation);
    assert_eq!(seen.mode, RelayRouteMode::Middle);
}

#[test]
fn light_fuzz_cutover_stagger_delay_distribution_stays_in_fixed_window() {
    // Deterministic xorshift fuzzing keeps this test stable across runs.
    let mut s: u64 = 0x9E37_79B9_7F4A_7C15;

    for _ in 0..20_000 {
        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let session_id = s;

        s ^= s << 7;
        s ^= s >> 9;
        s ^= s << 8;
        let generation = s;

        let delay = cutover_stagger_delay(session_id, generation);
        assert!(
            (1000..=1999).contains(&delay.as_millis()),
            "fuzzed inputs must always map into fixed stagger window"
        );
    }
}
