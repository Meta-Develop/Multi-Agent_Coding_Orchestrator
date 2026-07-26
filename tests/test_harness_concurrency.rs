use std::{
    sync::atomic::{AtomicUsize, Ordering},
    thread,
    time::Duration,
};

const PINNED_TEST_THREADS: usize = 3;
static ACTIVE_TESTS: AtomicUsize = AtomicUsize::new(0);

struct ActiveTestGuard;

impl ActiveTestGuard {
    fn enter() -> (Self, usize) {
        let active = ACTIVE_TESTS.fetch_add(1, Ordering::SeqCst) + 1;
        (Self, active)
    }
}

impl Drop for ActiveTestGuard {
    fn drop(&mut self) {
        ACTIVE_TESTS.fetch_sub(1, Ordering::SeqCst);
    }
}

fn hold_test_lane() {
    assert_eq!(
        std::env::var("RUST_TEST_THREADS").as_deref(),
        Ok("3"),
        "Cargo must force the repository-wide libtest width"
    );
    let (_guard, active) = ActiveTestGuard::enter();
    assert!(
        active <= PINNED_TEST_THREADS,
        "libtest admitted {active} concurrent tests; expected at most {PINNED_TEST_THREADS}"
    );
    thread::sleep(Duration::from_millis(250));
}

#[test]
fn pinned_lane_one() {
    hold_test_lane();
}

#[test]
fn pinned_lane_two() {
    hold_test_lane();
}

#[test]
fn pinned_lane_three() {
    hold_test_lane();
}

#[test]
fn pinned_lane_four() {
    hold_test_lane();
}

#[test]
fn pinned_lane_five() {
    hold_test_lane();
}

#[test]
fn pinned_lane_six() {
    hold_test_lane();
}
