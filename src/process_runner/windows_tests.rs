use super::*;
use std::os::windows::io::AsRawHandle;
use windows_sys::Win32::{
    Foundation::{
        GetHandleInformation, GetLastError, ERROR_INVALID_HANDLE, HANDLE_FLAG_INHERIT, WAIT_OBJECT_0,
    },
    System::{
        Console::{GetConsoleCP, GetConsoleProcessList, GetConsoleWindow},
        JobObjects::IsProcessInJob,
        Threading::{GetCurrentProcess, WaitForSingleObject},
    },
};

const FIXTURE_REPORT: &str = "MACO_WINDOWS_JOB_FIXTURE_REPORT";
const FIXTURE_TEST: &str = "process_runner::windows_tests::windows_job_child_fixture";

// This console-subsystem test executable is the harmless child. It reports OS state,
// then blocks on its captured stdin until the owner exits or terminates it.
#[test]
fn windows_job_child_fixture() {
    let Some(report) = env::var_os(FIXTURE_REPORT).map(PathBuf::from) else {
        return;
    };
    let mut in_job = 0;
    // SAFETY: the pseudo-handle is valid, null selects any Job, and `in_job` is writable.
    assert_ne!(
        unsafe { IsProcessInJob(GetCurrentProcess(), std::ptr::null_mut(), &mut in_job) },
        0
    );
    let mut console_process_ids = [0; 1];
    // SAFETY: the nonnull buffer holds one process ID; a larger required count also
    // proves attachment, so this measurement never allocates or retries.
    let console_process_count =
        unsafe { GetConsoleProcessList(console_process_ids.as_mut_ptr(), 1) };
    let console_process_list_error = if console_process_count == 0 {
        // SAFETY: capture the failing call's thread-local error before another API.
        unsafe { GetLastError() }
    } else {
        0
    };
    // SAFETY: these APIs only read the calling process's console state.
    let state = unsafe {
        serde_json::json!({
            "console_window": !GetConsoleWindow().is_null(),
            "console_code_page": GetConsoleCP(),
            "console_process_count": console_process_count,
            "console_process_list_error": console_process_list_error,
            "in_job": in_job != 0,
        })
    };
    fs::write(
        &report,
        serde_json::to_vec(&state).expect("serialize OS state"),
    )
    .expect("write OS state");
    fs::write(report.with_extension("ready"), b"ready").expect("publish completed report");
    let mut input = String::new();
    std::io::stdin()
        .read_to_string(&mut input)
        .expect("read fixture stdin");
    assert_eq!(input, "fixture-input\n");
    println!("fixture-stdout");
    eprintln!("fixture-stderr");
}

struct FixtureChild(Child);

impl Drop for FixtureChild {
    fn drop(&mut self) {
        // Reap this exact child even when an assertion fails before Job attachment.
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn suspended_fixture(
    report: &Path,
    cancellation: &ProcessCancellation,
) -> (FixtureChild, AttachedProcessTree) {
    let spec = ProcessSpec::direct(
        "Windows Job fixture",
        env::current_exe().expect("test executable"),
        ["--exact", FIXTURE_TEST, "--nocapture"],
        report.parent().expect("fixture directory"),
        4096,
    );
    // Exercise the existing compatibility backend, not writable-provider admission.
    let mut prepared = PreparedProcessTree::prepare(
        ContainmentPolicy::TrustedBestEffort,
        &SideEffectConfinementProfile::TrustedCompatibility,
        "Windows Job fixture",
        FIXTURE_TEST,
        None,
        cancellation,
    )
    .expect("prepare owned Job");
    let mut command = prepared
        .build_command(&spec)
        .expect("build production command");
    command
        .env(FIXTURE_REPORT, report)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = FixtureChild(command.spawn().expect("spawn suspended fixture"));
    let attached = prepared
        .attach(
            &mut child.0,
            "Windows Job fixture",
            FIXTURE_TEST,
            None,
            cancellation,
        )
        .expect("assign suspended fixture");
    let ProcessTreeBackend::WindowsJob(job) = &attached.backend;
    let mut in_owned_job = 0;
    // SAFETY: both handles are live; the output points to writable storage.
    assert_ne!(
        unsafe {
            IsProcessInJob(
                child.0.as_raw_handle().cast(),
                job.handle.raw(),
                &mut in_owned_job,
            )
        },
        0
    );
    assert_ne!(
        in_owned_job, 0,
        "child must belong to this exact Job before resume"
    );
    let mut handle_flags = 0;
    // SAFETY: the Job is live and `handle_flags` is valid writable storage.
    assert_ne!(
        unsafe { GetHandleInformation(job.handle.raw(), &mut handle_flags) },
        0
    );
    assert_eq!(
        handle_flags & HANDLE_FLAG_INHERIT,
        0,
        "Job handle must not escape to child"
    );
    assert!(
        !report.exists(),
        "fixture must not execute before the resume gate"
    );
    (child, attached)
}

fn assert_windowless_report(report: &Path, child: &mut Child) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !report.with_extension("ready").exists() {
        assert!(
            child.try_wait().expect("poll fixture").is_none(),
            "fixture exited before OS report"
        );
        assert!(Instant::now() < deadline, "fixture OS report timed out");
        thread::sleep(Duration::from_millis(10));
    }
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(report).expect("read OS state")).expect("OS state JSON");
    eprintln!("fixture-console-state: {state}");
    assert_eq!(
        state["console_window"], false,
        "child must have no console window"
    );
    assert_eq!(
        state["console_process_count"], 0,
        "child must not have any console process list"
    );
    assert_eq!(
        state["console_process_list_error"], ERROR_INVALID_HANDLE,
        "console absence must not be inferred from an unrelated query failure"
    );
    assert_eq!(
        state["console_code_page"], 0,
        "child must have no console attachment"
    );
    assert_eq!(
        state["in_job"], true,
        "fixture must begin execution inside a Job"
    );
}

fn wait_for_fixture_exit(child: &mut Child) -> ExitStatus {
    // SAFETY: the child process handle remains live for the bounded wait.
    assert_eq!(
        unsafe { WaitForSingleObject(child.as_raw_handle().cast(), 10_000) },
        WAIT_OBJECT_0
    );
    child.wait().expect("reap fixture")
}

#[test]
fn windows_job_launch_is_windowless_and_preserves_captured_stdio() {
    let temp = tempfile::tempdir().expect("fixture directory");
    let report = temp.path().join("state.json");
    let cancellation = ProcessCancellation::new();
    let (mut child, attached) = suspended_fixture(&report, &cancellation);
    let mut tree = attached
        .release(
            &mut child.0,
            "Windows Job fixture",
            FIXTURE_TEST,
            None,
            &cancellation,
        )
        .expect("resume owned fixture");
    assert_windowless_report(&report, &mut child.0);
    child
        .0
        .stdin
        .take()
        .expect("stdin pipe")
        .write_all(b"fixture-input\n")
        .expect("write input");
    assert!(wait_for_fixture_exit(&mut child.0).success());
    let cleanup = tree.cleanup(&mut child.0, true, "Windows Job fixture", "normal exit");
    assert!(cleanup.error.is_none(), "{:?}", cleanup.error);
    assert_eq!(
        cleanup.process_tree,
        ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::WindowsJobObject)
    );
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .0
        .stdout
        .take()
        .expect("stdout pipe")
        .read_to_string(&mut stdout)
        .expect("read stdout");
    child
        .0
        .stderr
        .take()
        .expect("stderr pipe")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    assert!(stdout.contains("fixture-stdout"));
    assert!(stderr.contains("fixture-stderr"));
}

#[test]
fn windows_job_close_terminates_the_owned_child() {
    let temp = tempfile::tempdir().expect("fixture directory");
    let report = temp.path().join("state.json");
    let cancellation = ProcessCancellation::new();
    let (mut child, attached) = suspended_fixture(&report, &cancellation);
    let tree = attached
        .release(
            &mut child.0,
            "Windows Job fixture",
            FIXTURE_TEST,
            None,
            &cancellation,
        )
        .expect("resume owned fixture");
    assert_windowless_report(&report, &mut child.0);
    assert!(child.0.try_wait().expect("poll blocked child").is_none());
    // Keep stdin open: only closing the non-inherited Job should release this wait.
    drop(tree);
    assert!(!wait_for_fixture_exit(&mut child.0).success());
}

#[test]
fn windows_job_cancel_before_resume_never_executes_the_child() {
    let temp = tempfile::tempdir().expect("fixture directory");
    let report = temp.path().join("state.json");
    let cancellation = ProcessCancellation::new();
    let (mut child, attached) = suspended_fixture(&report, &cancellation);
    cancellation.cancel();
    let error = match attached.release(
        &mut child.0,
        "Windows Job fixture",
        FIXTURE_TEST,
        None,
        &cancellation,
    ) {
        Err(error) => error,
        Ok(_) => panic!("cancelled fixture was resumed"),
    };
    match error {
        ProcessRunError::Cancelled {
            evidence: Some(evidence),
            ..
        } => {
            assert_eq!(
                evidence.process_tree,
                ProcessTreeEvidence::VerifiedEmpty(ContainmentBackend::WindowsJobObject)
            );
        }
        other => panic!("unexpected cancellation error: {other:?}"),
    }
    assert!(!wait_for_fixture_exit(&mut child.0).success());
    assert!(!report.exists(), "cancelled fixture executed before resume");
}
