//! Replace only attachment with a known child that cannot spawn descendants.
//! The submitting provider's callback and production rollback/wait remain real.

use super::*;

thread_local! {
    static ENABLED: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

pub(super) fn enabled() -> bool {
    ENABLED.with(std::cell::Cell::get)
}

pub(crate) fn with_paused_child<T>(run: impl FnOnce() -> T) -> T {
    struct Restore(bool);
    impl Drop for Restore {
        fn drop(&mut self) {
            ENABLED.with(|slot| slot.set(self.0));
        }
    }
    let _restore = Restore(ENABLED.with(|slot| slot.replace(true)));
    run()
}

#[test]
fn paused_child() {
    let Some(root) = env::var_os("MACO_TEST_PAUSED_START_GATE_CHILD") else {
        return;
    };
    fs::write(PathBuf::from(root).join("ready"), b"ready").unwrap();
    // No submitted command, credentials, or process-spawning code is present.
    let mut byte = [0u8; 1];
    let _ = std::io::Read::read(&mut std::io::stdin(), &mut byte);
}

pub(super) fn run(
    spec: &ProcessSpec,
    start_gate: Option<&mut ProcessStartGateCallback<'_>>,
) -> Result<SettledProcessCapture, ProcessRunError> {
    let prepare = start_gate.expect("paused fixture requires the production start callback");
    let root = tempfile::tempdir().expect("paused child directory");
    struct OwnedChild(Child);
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
    let mut child = OwnedChild(
        Command::new(env::current_exe().unwrap())
            .args([
                "--exact",
                "process_runner::start_gate_fixture_tests::paused_child",
            ])
            .env_clear()
            .env("MACO_TEST_PAUSED_START_GATE_CHILD", root.path())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn owned paused child"),
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    while !root.path().join("ready").exists() {
        assert!(
            Instant::now() < deadline,
            "fixture never reached its pause barrier"
        );
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "fixture exited before its pause barrier"
        );
        thread::sleep(Duration::from_millis(5));
    }
    let context = ContainedProcessStartGate {
        runtime_directory: root.path(),
        cgroup_path: root.path(),
    };
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| prepare(&context)))
        .unwrap_or_else(|_| Err("pre-start owner callback panicked; details redacted".into()));
    let cleanup_error = child.0.kill().err().map(|error| error.to_string());
    // Empty-tree proof is scoped to this exact no-descendant fixture and is
    // accepted by the shared rollback code only after its wait confirms exit.
    let cleanup = TreeCleanup {
        error: cleanup_error,
        process_tree: ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::DirectChild),
        side_effects: SideEffectConfinementEvidence::TrustedBestEffort(
            SideEffectConfinementProfileKind::TrustedCompatibility,
        ),
        read_only: None,
    };
    let message = result.expect_err("fixture callback unexpectedly admitted a target");
    Err(start_gate_rollback_failure(
        &mut child.0,
        &spec.label,
        spec.command_display(),
        message,
        cleanup,
    ))
}
