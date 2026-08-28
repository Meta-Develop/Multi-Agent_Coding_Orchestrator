use super::*;
use crate::worktree::{WorktreeCreateOptions, WorktreeManager};
use git2::{Oid, Signature};
use tempfile::TempDir;

#[test]
fn sha256_matches_standard_vector() {
    assert_eq!(
        sha256_hex(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn supervisor_invocation_scratch_names_require_the_full_canonical_grammar() {
    let valid = [
        "incoming",
        "capture",
        "incoming-assignment-0001-attempt-01",
        "capture-assignment-12345-attempt-123",
        "incoming-assignment-0000-auditor",
        "capture-assignment-12345-auditor",
    ];
    for name in valid {
        assert!(
            is_supervisor_invocation_scratch_name(Path::new(name)),
            "canonical invocation scratch was rejected: {name}"
        );
    }

    let invalid = [
        "foreign-incoming",
        "incoming-extra",
        "capture-assignment-0001",
        "incoming-assignment-1-attempt-01",
        "incoming-assignment-0001-attempt-1",
        "incoming-assignment-00x1-attempt-01",
        "incoming-assignment-0001-attempt-01-extra",
        "capture-assignment-0001-auditor-extra",
    ];
    for name in invalid {
        assert!(
            !is_supervisor_invocation_scratch_name(Path::new(name)),
            "near-match invocation scratch was accepted: {name}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn terminal_supervisor_cleanup_preserves_foreign_leak_and_finalization_cause() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("supervisor-owned-and-foreign-scratch").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id,
        "maco-supervise",
    )
    .expect("reserve supervise writer");
    writer
        .write_json(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            &serde_json::json!({"status":"failed"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write final report");
    let incoming = writer
        .create_scratch_dir("incoming-assignment-0001-attempt-01")
        .expect("reserve incoming invocation scratch");
    let capture = writer
        .create_scratch_dir("capture-assignment-0001-attempt-01")
        .expect("reserve capture invocation scratch");
    let foreign = writer
        .create_scratch_dir("foreign-leak")
        .expect("reserve foreign scratch fixture");
    fs::write(foreign.path().join("sentinel"), b"preserve\n")
        .expect("write foreign scratch sentinel");
    let run = writer.run_dir().to_path_buf();

    assert_eq!(
        writer
            .discard_supervisor_invocation_scratches_after_quiescence(
                ArtifactScratchQuiescence::Verified,
            )
            .expect("discard verified-quiescent invocation scratches"),
        2
    );
    assert!(!incoming.path().exists());
    assert!(!capture.path().exists());
    assert_eq!(
        fs::read(foreign.path().join("sentinel")).expect("read preserved foreign sentinel"),
        b"preserve\n"
    );

    let error = writer
        .finalize(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            false,
        )
        .expect_err("foreign scratch must keep finalization fail closed");
    assert_eq!(
        error.to_string(),
        "artifact run has 1 outstanding scratch directory; discard every scratch tree before finalization"
    );
    assert!(!run.join(FINALIZATION_MARKER).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn live_scratch_blocks_marker_and_discarded_scratch_finalizes_marker_last() {
    use std::os::unix::fs::symlink;

    let (temp, repo) = committed_repo();
    let blocked_run_id = RunId::new("scratch-live-blocked").expect("run id");
    let mut blocked = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Autopilot,
        blocked_run_id.clone(),
        "autopilot",
    )
    .expect("reserve blocked writer");
    blocked
        .write_json(
            "final-report.json",
            &serde_json::json!({"status":"done"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write blocked report");
    let blocked_scratch = blocked
        .create_scratch_dir("incoming")
        .expect("reserve live scratch");
    fs::write(blocked_scratch.path().join("pending"), b"pending\n")
        .expect("write pending child output");
    let blocked_error = blocked
        .finalize("final-report.json", false)
        .expect_err("live scratch must block finalization");
    assert!(blocked_error.to_string().contains("outstanding scratch"));
    assert!(
        !run_dir(&repo, RunArtifactFamily::Autopilot, &blocked_run_id)
            .join(FINALIZATION_MARKER)
            .exists()
    );

    let run_id = RunId::new("scratch-discarded").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Autopilot,
        run_id.clone(),
        "autopilot",
    )
    .expect("reserve writer");
    writer
        .write_json(
            "final-report.json",
            &serde_json::json!({"status":"done"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write report");
    let scratch = writer
        .create_scratch_dir("incoming")
        .expect("reserve scratch");
    assert_eq!(mode(scratch.path()), 0o700);
    assert_eq!(
        identity_for_path(scratch.path()).expect("scratch identity"),
        *scratch.identity()
    );

    let sentinel = temp.path().join("external-sentinel");
    fs::write(&sentinel, b"keep\n").expect("write external sentinel");
    symlink(&sentinel, scratch.path().join("sentinel-link")).expect("scratch symlink");
    fs::hard_link(&sentinel, scratch.path().join("sentinel-hardlink")).expect("scratch hardlink");
    let fifo =
        CString::new(scratch.path().join("child-fifo").as_os_str().as_bytes()).expect("FIFO path");
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let run = writer.run_dir().to_path_buf();
    writer
        .discard_scratch(&scratch)
        .expect("discard hostile child tree without following links");
    assert!(!scratch.path().exists());
    assert_eq!(fs::read(&sentinel).expect("read sentinel"), b"keep\n");
    assert!(!run.join(FINALIZATION_MARKER).exists());
    let finalization = writer
        .finalize("final-report.json", false)
        .expect("finalize after scratch discard");
    assert!(run.join(FINALIZATION_MARKER).exists());
    assert_eq!(finalization.files.len(), 1);
    assert_eq!(finalization.files[0].path, Path::new("final-report.json"));
    ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
        .expect("final marker authenticates the exact post-discard manifest");
}

#[cfg(target_os = "linux")]
#[test]
fn scratch_names_manifest_overlap_and_count_are_bounded() {
    use std::os::unix::ffi::OsStringExt;

    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("scratch-validation").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Inbox, run_id, "inbox")
        .expect("reserve writer");
    let invalid = [
        PathBuf::new(),
        PathBuf::from("."),
        PathBuf::from("./incoming"),
        PathBuf::from("incoming/"),
        PathBuf::from("../incoming"),
        PathBuf::from("nested/incoming"),
        PathBuf::from("/absolute"),
        PathBuf::from(".artifact.lock"),
        PathBuf::from("contains space"),
        PathBuf::from("contains/slash"),
        PathBuf::from("x".repeat(MAX_ARTIFACT_SCRATCH_NAME_BYTES + 1)),
        PathBuf::from(std::ffi::OsString::from_vec(vec![0xff])),
    ];
    for name in invalid {
        assert!(
            writer.create_scratch_dir(&name).is_err(),
            "invalid scratch name was accepted: {}",
            name.display()
        );
    }
    assert!(writer.outstanding_scratches.is_empty());

    writer
        .write_bytes(
            "manifested/first.txt",
            b"first\n",
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write nested manifested artifact");
    assert!(writer.create_scratch_dir("manifested").is_err());
    writer
        .write_bytes(
            "exact-name",
            b"manifested\n",
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write exact manifested artifact");
    assert!(writer.create_scratch_dir("exact-name").is_err());

    let scratch = writer
        .create_scratch_dir("incoming")
        .expect("create valid scratch");
    assert!(writer
        .write_bytes(
            "incoming",
            b"overlap\n",
            ArtifactFileDisposition::PrivateEvidence,
        )
        .is_err());
    assert!(writer
        .write_bytes(
            "incoming/nested.txt",
            b"overlap\n",
            ArtifactFileDisposition::PrivateEvidence,
        )
        .is_err());
    writer.discard_scratch(&scratch).expect("discard scratch");

    let mut scratches = Vec::new();
    for index in 0..MAX_ARTIFACT_SCRATCH_DIRECTORIES {
        scratches.push(
            writer
                .create_scratch_dir(format!("scratch-{index}"))
                .expect("scratch within limit"),
        );
    }
    let limit_error = writer
        .create_scratch_dir("one-too-many")
        .expect_err("scratch count must be bounded");
    assert!(limit_error.to_string().contains("scratch-directory limit"));
    for scratch in &scratches {
        writer
            .discard_scratch(scratch)
            .expect("discard bounded scratch");
    }
    assert!(writer.outstanding_scratches.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn scratch_capability_is_run_bound_and_rebinding_fails_closed() {
    let (_temp, repo) = committed_repo();
    let run_a = RunId::new("scratch-capability-a").expect("run id");
    let run_b = RunId::new("scratch-capability-b").expect("run id");
    let mut writer_a =
        ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Consult, run_a, "consult")
            .expect("reserve writer A");
    let mut writer_b =
        ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Consult, run_b, "consult")
            .expect("reserve writer B");
    let scratch = writer_a
        .create_scratch_dir("incoming")
        .expect("reserve scratch A");

    let cross_error = writer_b
        .discard_scratch(&scratch)
        .expect_err("writer B must reject writer A capability");
    assert!(cross_error
        .to_string()
        .contains("different run reservation"));
    assert!(scratch.path().exists());

    let moved = writer_a.run_dir().join("moved-original");
    fs::rename(scratch.path(), &moved).expect("move original scratch inode");
    fs::create_dir(scratch.path()).expect("create substitute scratch");
    fs::write(scratch.path().join("substitute-sentinel"), b"keep\n")
        .expect("write substitute sentinel");
    let rebind_error = writer_a
        .discard_scratch(&scratch)
        .expect_err("rebound scratch name must fail closed");
    assert!(
        rebind_error.to_string().contains("no longer identifies")
            || rebind_error.to_string().contains("identity")
    );
    assert!(scratch.path().join("substitute-sentinel").exists());
    assert!(moved.exists());
    assert_eq!(writer_a.outstanding_scratches.len(), 1);

    fs::remove_dir_all(scratch.path()).expect("remove substitute");
    fs::rename(&moved, scratch.path()).expect("restore original binding");
    writer_a
        .discard_scratch(&scratch)
        .expect("discard restored original scratch");
    assert!(writer_a.outstanding_scratches.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn scratch_cleanup_depth_budget_failure_remains_tracked_and_resumes() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("scratch-depth-budget").expect("run id");
    let mut writer =
        ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Supervise, run_id, "supervise")
            .expect("reserve writer");
    writer
        .write_json(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            &serde_json::json!({"status":"done"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write final report");
    let scratch = writer
        .create_scratch_dir("incoming")
        .expect("reserve scratch");
    let mut nested = scratch.path().to_path_buf();
    for _ in 0..130 {
        nested.push("d");
        fs::create_dir(&nested).expect("create bounded-depth fixture");
    }

    let error = writer
        .discard_scratch(&scratch)
        .expect_err("over-depth tree must fail closed");
    assert!(format!("{error:#}").contains("maximum depth"));
    assert_eq!(writer.outstanding_scratches.len(), 1);
    assert!(!scratch.path().exists(), "source is durably quarantined");
    assert!(!writer.run_dir().join(FINALIZATION_MARKER).exists());

    let quarantine = quarantined_scratch_path(writer.run_dir(), scratch.identity())
        .expect("identity-bound scratch quarantine");
    fs::remove_dir_all(quarantine.join("d")).expect("shorten hostile tree for retry");
    writer
        .discard_scratch(&scratch)
        .expect("resume identity-bound quarantine cleanup");
    assert!(writer.outstanding_scratches.is_empty());
    writer
        .finalize(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            false,
        )
        .expect("finalize after resumed cleanup");
}

#[cfg(target_os = "linux")]
#[test]
fn scratch_cleanup_refuses_mounted_descendant_when_mount_is_available() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("scratch-mount-boundary").expect("run id");
    let mut writer =
        ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Consult, run_id, "consult")
            .expect("reserve writer");
    let scratch = writer
        .create_scratch_dir("incoming")
        .expect("reserve scratch");
    let mount_point = scratch.path().join("mounted-proc");
    fs::create_dir(&mount_point).expect("mount point");
    let source = CString::new("/proc").expect("mount source");
    let target = CString::new(mount_point.as_os_str().as_bytes()).expect("mount target");
    let mounted = unsafe {
        libc::mount(
            source.as_ptr(),
            target.as_ptr(),
            std::ptr::null(),
            libc::MS_BIND,
            std::ptr::null(),
        )
    };
    if mounted != 0 {
        writer
            .discard_scratch(&scratch)
            .expect("discard fixture when mount privilege is unavailable");
        return;
    }

    let mut guard = ScratchMountGuard {
        run: writer.run_dir().to_path_buf(),
        scratch_identity: scratch.identity().clone(),
        mount_name: "mounted-proc".to_string(),
        active: true,
    };
    let error = writer
        .discard_scratch(&scratch)
        .expect_err("mounted descendant must fail closed");
    assert!(format!("{error:#}").contains("filesystem boundary"));
    assert_eq!(writer.outstanding_scratches.len(), 1);
    guard.unmount().expect("detach test bind mount");
    writer
        .discard_scratch(&scratch)
        .expect("resume cleanup after mounted descendant is detached");
}

#[test]
fn scratch_cleanup_unsupported_platform_fallback_is_fail_closed() {
    let error = unsupported_artifact_scratch_cleanup()
        .expect_err("unsupported platforms must never use recursive path deletion");
    assert!(error.to_string().contains("unsupported on this platform"));
    assert!(error.to_string().contains("refusing recursive deletion"));
}

#[cfg(unix)]
#[test]
fn json_line_appends_remain_manifested_and_finalize() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("append-json-lines").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "supervise",
    )
    .expect("reserve writer");
    let path = Path::new("events/orchestration.jsonl");

    let first = writer
        .append_json_line(
            path,
            &serde_json::json!({"kind":"spawn","node":"worker-1"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("append first event");
    let second = writer
        .append_json_line(
            path,
            &serde_json::json!({"kind":"accept","node":"worker-1"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("append second event");
    let expected = concat!(
        "{\"kind\":\"spawn\",\"node\":\"worker-1\"}\n",
        "{\"kind\":\"accept\",\"node\":\"worker-1\"}\n"
    )
    .as_bytes();
    assert_eq!(
        fs::read(writer.run_dir().join(path)).expect("read journal"),
        expected
    );
    assert_eq!(
        first.bytes,
        u64::try_from(
            expected
                .iter()
                .position(|byte| *byte == b'\n')
                .expect("first line")
                + 1
        )
        .expect("first line length")
    );
    assert_eq!(
        second.bytes,
        u64::try_from(expected.len()).expect("journal length")
    );
    assert_eq!(second.sha256, sha256_hex(expected));
    assert_eq!(writer.total_bytes, second.bytes);
    assert_eq!(writer.files.get(path), Some(&second));

    writer
        .write_json(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            &serde_json::json!({"status":"succeeded"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write final report");
    let finalization = writer
        .finalize(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            false,
        )
        .expect("finalize appended journal");
    let finalized_record = finalization
        .files
        .iter()
        .find(|record| record.path == path)
        .expect("journal record");
    assert_eq!(finalized_record, &second);

    let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized run");
    let journal = reader.read(path).expect("read finalized journal");
    let records = journal
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_slice::<Value>(line).expect("valid JSONL record"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["kind"], "spawn");
    assert_eq!(records[1]["kind"], "accept");
}

#[cfg(unix)]
#[test]
fn write_bytes_rejects_disposition_change_without_mutation() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("write-disposition").expect("run id");
    let mut writer =
        ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Supervise, run_id, "supervise")
            .expect("reserve writer");
    let path = Path::new("notes/private.txt");
    let first = writer
        .write_bytes(
            path,
            b"private evidence\n",
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write private evidence");
    let before = fs::read(writer.run_dir().join(path)).expect("read before mismatch");

    let error = writer
        .write_bytes(
            path,
            b"now publishable\n",
            ArtifactFileDisposition::Publishable,
        )
        .expect_err("disposition change must fail");
    assert!(error.to_string().contains("cannot change file disposition"));
    assert_eq!(
        fs::read(writer.run_dir().join(path)).expect("read after mismatch"),
        before
    );
    assert_eq!(writer.files.get(path), Some(&first));
    assert_eq!(writer.total_bytes, first.bytes);

    let rewritten = writer
        .write_bytes(
            path,
            b"still private\n",
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("same-disposition overwrite");
    assert_eq!(
        rewritten.disposition,
        ArtifactFileDisposition::PrivateEvidence
    );
    assert_eq!(
        fs::read(writer.run_dir().join(path)).expect("read same-disposition overwrite"),
        b"still private\n"
    );
}

#[cfg(unix)]
#[test]
fn json_line_append_rejects_disposition_change_without_mutation() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("append-disposition").expect("run id");
    let mut writer =
        ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Supervise, run_id, "supervise")
            .expect("reserve writer");
    let path = Path::new("events/orchestration.jsonl");
    let first = writer
        .append_json_line(
            path,
            &serde_json::json!({"kind":"spawn"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("append first event");
    let before = fs::read(writer.run_dir().join(path)).expect("read before mismatch");

    let error = writer
        .append_json_line(
            path,
            &serde_json::json!({"kind":"accept"}),
            ArtifactFileDisposition::Publishable,
        )
        .expect_err("disposition change must fail");
    assert!(error.to_string().contains("cannot change file disposition"));
    assert_eq!(
        fs::read(writer.run_dir().join(path)).expect("read after mismatch"),
        before
    );
    assert_eq!(writer.files.get(path), Some(&first));
    assert_eq!(writer.total_bytes, first.bytes);
}

#[cfg(unix)]
#[test]
fn partial_json_line_append_is_completed_before_later_append_and_finalize() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("append-recovery").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "supervise",
    )
    .expect("reserve writer");
    let path = Path::new("events/orchestration.jsonl");
    set_artifact_append_fault(ArtifactAppendFaultPoint::PartialWrite);
    let error = writer
        .append_json_line(
            path,
            &serde_json::json!({"kind":"spawn","node":"worker-1"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect_err("injected partial write failure");
    assert!(error
        .to_string()
        .contains("injected partial artifact append"));
    writer
        .append_json_line(
            path,
            &serde_json::json!({"kind":"accept","node":"worker-1"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("append after recovered partial write");
    let journal = fs::read(writer.run_dir().join(path)).expect("read recovered journal");
    assert_eq!(
        journal,
        concat!(
            "{\"kind\":\"spawn\",\"node\":\"worker-1\"}\n",
            "{\"kind\":\"accept\",\"node\":\"worker-1\"}\n"
        )
        .as_bytes()
    );
    for line in journal
        .split(|byte| *byte == b'\n')
        .filter(|line| !line.is_empty())
    {
        serde_json::from_slice::<Value>(line).expect("recovered JSONL line is complete");
    }
    let record = writer.files.get(path).expect("reconciled record");
    assert_eq!(record.bytes, u64::try_from(journal.len()).expect("length"));
    assert_eq!(record.sha256, sha256_hex(&journal));
    assert_eq!(writer.total_bytes, record.bytes);

    writer
        .write_json(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            &serde_json::json!({"status":"succeeded"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write final report");
    writer
        .finalize(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            false,
        )
        .expect("finalize after recovered append failure");
    ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized recovered run");
}

#[cfg(unix)]
#[test]
fn authenticated_resume_binding_reopens_only_the_exact_unfinalized_manifest() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("artifact-resume-exact").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "supervise",
    )
    .expect("reserve writer");
    writer
        .write_bytes(
            "evidence/completed.txt",
            b"completed once\n",
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write completed evidence");
    let binding = writer.resume_binding().expect("capture resume binding");
    drop(writer);

    let mut tampered = binding.clone();
    tampered.files[0].sha256 = "0".repeat(64);
    let error = match ArtifactRunWriter::reopen_unfinalized(&repo, &tampered) {
        Ok(_) => panic!("tampered manifest binding must fail closed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("digest/length"));

    let mut resumed = ArtifactRunWriter::reopen_unfinalized(&repo, &binding)
        .expect("reopen exact authenticated binding");
    assert_eq!(
        fs::read(resumed.run_dir().join("evidence/completed.txt"))
            .expect("read completed evidence"),
        b"completed once\n"
    );
    resumed
        .write_json(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            &serde_json::json!({"status":"succeeded"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write resumed final report");
    resumed
        .finalize(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            false,
        )
        .expect("finalize resumed writer");
    ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
        .expect("open finalized resumed run");
}

#[cfg(unix)]
#[test]
fn authenticated_resume_recovers_only_checkpoint_planned_extra_file() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("artifact-resume-recovery").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Supervise,
        run_id.clone(),
        "supervise",
    )
    .expect("reserve writer");
    writer
        .write_bytes(
            "evidence/completed.txt",
            b"completed once\n",
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write completed evidence");
    let binding = writer.resume_binding().expect("capture resume binding");
    let report_path = RunArtifactFamily::Supervise.final_report_relative_path();
    let planned_report = b"{\n  \"status\": \"succeeded\"\n}\n";
    writer
        .write_bytes(
            &report_path,
            planned_report,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("simulate report write after planned checkpoint");
    drop(writer);

    let wrong = ArtifactRecoveryFile {
        relative: &report_path,
        contents: b"different\n",
        disposition: ArtifactFileDisposition::PrivateEvidence,
    };
    let error = match ArtifactRunWriter::reopen_unfinalized_with_recovery(&repo, &binding, &[wrong])
    {
        Ok(_) => panic!("mismatched planned bytes must fail closed"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("do not match"));

    let recovery = ArtifactRecoveryFile {
        relative: &report_path,
        contents: planned_report,
        disposition: ArtifactFileDisposition::PrivateEvidence,
    };
    let resumed = ArtifactRunWriter::reopen_unfinalized_with_recovery(&repo, &binding, &[recovery])
        .expect("recover exact checkpoint-planned report");
    resumed
        .finalize(&report_path, false)
        .expect("finalize recovered report");
    let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
        .expect("open recovered finalized run");
    assert_eq!(
        reader.read(&report_path).expect("read recovered report"),
        planned_report
    );
}

#[cfg(unix)]
#[test]
fn failed_append_recovery_syncs_file_and_new_parent_before_finalization() {
    for (index, fault) in [
        ArtifactAppendFaultPoint::AfterWriteBeforeFileSync,
        ArtifactAppendFaultPoint::AfterFileSyncBeforeParentSync,
    ]
    .into_iter()
    .enumerate()
    {
        let (_temp, repo) = committed_repo();
        let run_id = RunId::new(format!("append-sync-recovery-{index}")).expect("run id");
        let mut writer = ArtifactRunWriter::reserve(
            &repo,
            RunArtifactFamily::Supervise,
            run_id.clone(),
            "supervise",
        )
        .expect("reserve writer");
        let path = Path::new("events/orchestration.jsonl");
        set_artifact_append_fault(fault);
        let error = writer
            .append_json_line(
                path,
                &serde_json::json!({"kind":"spawn","node":"worker-1"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect_err("injected durability-boundary failure");
        assert!(error
            .to_string()
            .contains("injected artifact append failure"));
        assert!(writer.poisoned_appends.is_empty());
        let journal = fs::read(writer.run_dir().join(path)).expect("read recovered journal");
        serde_json::from_slice::<Value>(journal.strip_suffix(b"\n").expect("newline"))
            .expect("recovered journal line");

        writer
            .write_json(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                &serde_json::json!({"status":"succeeded"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("write final report");
        writer
            .finalize(
                RunArtifactFamily::Supervise.final_report_relative_path(),
                false,
            )
            .expect("finalize after durability recovery");
        ArtifactRunReader::open(&repo, RunArtifactFamily::Supervise, &run_id)
            .expect("open finalized recovered run");
    }
}

#[cfg(unix)]
#[test]
fn writer_finalizes_private_artifacts_and_public_evidence_cannot_forge_mac() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("secure-run").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Autopilot,
        run_id.clone(),
        "autopilot",
    )
    .expect("reserve writer");
    writer
        .write_json(
            "final-report.json",
            &serde_json::json!({"status": "succeeded", "success": true}),
            ArtifactFileDisposition::Publishable,
        )
        .expect("write report");
    writer
        .write_bytes(
            "details/evidence.txt",
            b"verified\n",
            ArtifactFileDisposition::Publishable,
        )
        .expect("write evidence");
    let finalization = writer
        .finalize("final-report.json", true)
        .expect("finalize");
    assert!(finalization.publishable);

    let reader = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
        .expect("strict reader");
    assert_eq!(
        reader.read("details/evidence.txt").expect("read"),
        b"verified\n"
    );
    let summary = latest_run(&repo, RunArtifactFamily::Autopilot)
        .expect("latest")
        .run
        .expect("run");
    assert!(summary.finalized);
    assert!(summary.publishable);
    assert!(summary.provenance_valid);
    assert!(summary.artifact_digests_verified);
    assert_eq!(summary.final_report_status, "succeeded");
    assert_eq!(summary.final_report_success, Some(true));
    assert!(summary.final_report_readable);
    assert!(!summary.final_report_corrupt);

    let run = run_dir(&repo, RunArtifactFamily::Autopilot, &run_id);
    assert_eq!(mode(&run), 0o700);
    assert_eq!(mode(&run.join("final-report.json")), 0o600);
    assert_eq!(mode(&run.join(FINALIZATION_MARKER)), 0o600);
    let repository = discover_artifact_repository(&repo).expect("repository");
    let key_path = repository
        .common_dir
        .join("maco/state")
        .join(authentication_key_file_name());
    let key_lock_path = repository
        .common_dir
        .join("maco/state")
        .join(authentication_key_lock_name());
    assert_eq!(mode(&key_path), 0o600);
    assert_eq!(mode(&key_lock_path), 0o600);

    let marker_path = run.join(FINALIZATION_MARKER);
    let original_marker = fs::read(&marker_path).expect("marker");
    let mut forged: ArtifactFinalization =
        serde_json::from_slice(&original_marker).expect("marker JSON");
    forged.provenance.producer = "legacy-writer".to_string();
    forged.checksum = finalization_checksum(&forged).expect("public checksum");
    forged.hmac_sha256 = "00".repeat(32);
    fs::write(
        &marker_path,
        serde_json::to_vec_pretty(&forged).expect("forged marker"),
    )
    .expect("write public-evidence forgery");
    let marker_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
        .err()
        .expect("forged MAC");
    assert!(marker_error
        .to_string()
        .contains("HMAC verification failed"));

    let mut uppercase: ArtifactFinalization =
        serde_json::from_slice(&original_marker).expect("marker JSON");
    uppercase.hmac_sha256.replace_range(..1, "A");
    fs::write(
        &marker_path,
        serde_json::to_vec_pretty(&uppercase).expect("uppercase marker"),
    )
    .expect("write uppercase MAC");
    let uppercase_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
        .err()
        .expect("uppercase MAC");
    assert!(uppercase_error.to_string().contains("HMAC is malformed"));

    let mut oversized: ArtifactFinalization =
        serde_json::from_slice(&original_marker).expect("marker JSON");
    oversized.hmac_sha256 = "0".repeat(65);
    fs::write(
        &marker_path,
        serde_json::to_vec_pretty(&oversized).expect("oversized marker"),
    )
    .expect("write oversized MAC");
    let oversized_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
        .err()
        .expect("oversized MAC");
    assert!(oversized_error.to_string().contains("HMAC is malformed"));
    fs::write(&marker_path, original_marker).expect("restore marker");

    let original_key = fs::read(&key_path).expect("MAC key");
    let moved_key = key_path.with_file_name("artifact-key.original");
    fs::rename(&key_path, &moved_key).expect("move MAC key");
    let missing_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
        .err()
        .expect("missing key");
    assert!(missing_error.to_string().contains("MAC key is missing"));
    assert!(
        !key_path.exists(),
        "reader must never recreate a missing key"
    );
    let rekey_error = open_artifact_auth_writer(&repository)
        .err()
        .expect("rekey refusal");
    assert!(rekey_error
        .to_string()
        .contains("existing final marker is present"));
    fs::rename(&moved_key, &key_path).expect("restore MAC key");
    ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id).expect("restored key");

    fs::write(&key_path, vec![0xa5; authentication_key_length()]).expect("corrupt bound key");
    let corrupt_key_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
        .err()
        .expect("corrupt key");
    assert!(corrupt_key_error.to_string().contains("key binding"));
    fs::write(&key_path, &original_key).expect("restore bound key contents");
    ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
        .expect("restored key contents");

    let moved_key = key_path.with_file_name("artifact-key.bound-original");
    fs::rename(&key_path, &moved_key).expect("move bound key");
    write_private(&key_path, &original_key);
    let rebound_key_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
        .err()
        .expect("rebound key");
    assert!(rebound_key_error.to_string().contains("key binding"));
    fs::remove_file(&key_path).expect("remove replacement key");
    fs::rename(&moved_key, &key_path).expect("restore bound key");

    let lock_path = run.join(RUN_LOCK_FILE);
    let original_lock_path = run.join("artifact-writer-lock.original");
    fs::rename(&lock_path, &original_lock_path).expect("move bound writer lock");
    fs::write(&lock_path, b"").expect("replacement lock");
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o600))
        .expect("replacement lock mode");
    let evidence_error = ArtifactRunReader::open(&repo, RunArtifactFamily::Autopilot, &run_id)
        .err()
        .expect("writer evidence");
    assert!(evidence_error.to_string().contains("lock identity"));
}

#[cfg(unix)]
#[test]
fn existing_marker_refuses_replaced_key_for_new_finalization() {
    let (_temp, repo) = committed_repo();
    let first_run = RunId::new("key-anchor-run").expect("run id");
    finalize_private_test_run(&repo, RunArtifactFamily::Autopilot, &first_run, "autopilot");
    let repository = discover_artifact_repository(&repo).expect("repository");
    let key_path = repository
        .common_dir
        .join("maco/state")
        .join(authentication_key_file_name());
    let original_key = key_path.with_file_name("artifact-key.pre-replacement");
    fs::rename(&key_path, &original_key).expect("move original key");
    write_private(&key_path, &vec![0xa5; authentication_key_length()]);

    let second_run = RunId::new("replacement-key-run").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Autopilot,
        second_run.clone(),
        "autopilot",
    )
    .expect("reserve second writer");
    writer
        .write_json(
            "final-report.json",
            &serde_json::json!({"status":"done"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write second report");
    let error = writer
        .finalize("final-report.json", false)
        .expect_err("replacement key must not establish a new signing epoch");
    assert!(error
        .to_string()
        .contains("does not match existing marker binding"));
    assert!(!run_dir(&repo, RunArtifactFamily::Autopilot, &second_run)
        .join(FINALIZATION_MARKER)
        .exists());
}

#[cfg(unix)]
#[test]
fn missing_common_key_scans_main_and_every_registered_linked_worktree() {
    let (temp, repo) = committed_repo();
    let linked = WorktreeManager::new(&repo)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "artifact-linked".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(temp.path().join("worktrees")),
        })
        .expect("create linked worktree");
    let first_run = RunId::new("main-key-anchor").expect("run id");
    finalize_private_test_run(&repo, RunArtifactFamily::Inbox, &first_run, "inbox");
    let repository = discover_artifact_repository(&repo).expect("repository");
    let key_path = repository
        .common_dir
        .join("maco/state")
        .join(authentication_key_file_name());
    let original_key = key_path.with_file_name("artifact-key.missing-linked-test");
    fs::rename(&key_path, &original_key).expect("remove shared key");

    let linked_run = RunId::new("linked-rekey-attempt").expect("run id");
    let mut writer =
        ArtifactRunWriter::reserve(&linked.path, RunArtifactFamily::Inbox, linked_run, "inbox")
            .expect("reserve linked writer");
    writer
        .write_json(
            "final-report.json",
            &serde_json::json!({"status":"done"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write linked report");
    let error = writer
        .finalize("final-report.json", false)
        .expect_err("marker in main worktree must prevent linked-worktree rekey");
    assert!(error
        .to_string()
        .contains("existing final marker is present"));
    assert!(!key_path.exists(), "refused rekey must not create a key");
}

#[cfg(unix)]
#[test]
fn stale_registered_worktree_refuses_first_key_creation() {
    let (temp, repo) = committed_repo();
    let linked = WorktreeManager::new(&repo)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "artifact-stale".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(temp.path().join("worktrees")),
        })
        .expect("create linked worktree");
    fs::remove_dir_all(&linked.path).expect("make registration stale");
    let repository = discover_artifact_repository(&repo).expect("repository");
    let key_path = repository
        .common_dir
        .join("maco/state")
        .join(authentication_key_file_name());
    let original_key = fs::read(&key_path).expect("managed worktree registry created auth key");

    let error = open_artifact_auth_writer(&repository)
        .err()
        .expect("stale worktree registration must fail closed");
    assert!(error.to_string().contains("stale or invalid"));
    assert_eq!(
        fs::read(&key_path).expect("auth key remains present"),
        original_key
    );
}

#[test]
fn first_key_marker_scan_has_a_global_entry_budget() {
    let (_temp, repo) = committed_repo();
    let repository = discover_artifact_repository(&repo).expect("repository");
    let root =
        open_or_create_run_root(&repository, RunArtifactFamily::Consult).expect("artifact root");
    for index in 0..=MAX_RUN_ROOT_ENTRIES.saturating_mul(8) {
        fs::create_dir(root.path().join(format!("scan-budget-{index}")))
            .expect("marker-scan entry");
    }
    let key_path = repository
        .common_dir
        .join("maco/state")
        .join(authentication_key_file_name());

    let error = open_artifact_auth_writer(&repository)
        .err()
        .expect("marker scan budget must fail closed");
    assert!(error.to_string().contains("global entry budget"));
    assert!(!key_path.exists());
}

#[test]
fn retention_count_age_and_size_limits_report_exact_dry_run_bytes() {
    let (_temp, repo) = committed_repo();
    for (run_id, transcript) in [
        ("retention-a", b"aaa\n".as_slice()),
        ("retention-b", b"bbbbbb\n".as_slice()),
        ("retention-c", b"ccccccccc\n".as_slice()),
    ] {
        finalize_test_run_with_log(
            &repo,
            RunArtifactFamily::Consult,
            &RunId::new(run_id).expect("run id"),
            transcript,
        );
    }
    let repository = discover_artifact_repository(&repo).expect("repository");
    let root = open_existing_run_root(&repository, RunArtifactFamily::Consult).expect("root");
    let items = retention_items(&repository, &root, ArtifactRetentionFamily::Consult)
        .expect("retention inventory");
    let scanned_bytes = items.iter().map(|item| item.bytes).sum::<u64>();
    let compressible_log_bytes = items
        .iter()
        .map(|item| item.compressible_log_bytes)
        .sum::<u64>();
    let newest_bytes = items[0].bytes;
    let newest_log = fs::read(items[0].absolute_path.join("events.jsonl"))
        .expect("newest transcript before prune");
    let policy = ArtifactRetentionPolicy {
        max_count: 2,
        max_age: None,
        max_total_bytes: Some(newest_bytes),
        unfinalized_grace: Some(Duration::from_secs(60)),
        reclaim_unverifiable: false,
        external_writers_stopped: false,
    };

    let dry = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Consult,
        ArtifactRetentionFamily::Consult,
        &policy,
        true,
        SystemTime::now(),
    )
    .expect("dry-run retention");
    assert_eq!(dry.scanned_bytes, scanned_bytes);
    assert_eq!(dry.retained_bytes, scanned_bytes);
    assert_eq!(dry.reclaimed_bytes, 0);
    assert_eq!(
        dry.compression_strategy,
        ArtifactCompressionStrategy::NoneRequiresWriterMigration
    );
    assert_eq!(dry.compressible_log_bytes, compressible_log_bytes);
    assert_eq!(dry.compressed_bytes, 0);
    assert_eq!(dry.entries[0].action, RunArtifactPruneAction::Keep);
    assert!(dry.entries[1]
        .selected_by
        .contains(&ArtifactRetentionLimit::MaxTotalBytes));
    assert!(dry.entries[2]
        .selected_by
        .contains(&ArtifactRetentionLimit::MaxCount));
    let would_reclaim = dry
        .entries
        .iter()
        .filter(|entry| entry.action == RunArtifactPruneAction::WouldDelete)
        .map(|entry| entry.bytes)
        .sum::<u64>();
    assert_eq!(dry.would_reclaim_bytes, would_reclaim);
    assert_eq!(dry.projected_retained_bytes, scanned_bytes - would_reclaim);
    for item in &items {
        assert!(item.absolute_path.exists(), "dry-run removed an artifact");
    }
    assert_eq!(
        fs::read(items[0].absolute_path.join("events.jsonl")).expect("newest transcript"),
        newest_log,
        "the explicit no-compression policy must not rewrite retained logs"
    );

    let applied = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Consult,
        ArtifactRetentionFamily::Consult,
        &policy,
        false,
        SystemTime::now(),
    )
    .expect("apply retention");
    assert_eq!(applied.reclaimed_bytes, dry.would_reclaim_bytes);
    assert_eq!(applied.retained_bytes, dry.projected_retained_bytes);
    assert_eq!(applied.projected_retained_bytes, applied.retained_bytes);
    assert_eq!(applied.deleted_count, 2);
    assert_eq!(
        fs::read(items[0].absolute_path.join("events.jsonl")).expect("retained transcript"),
        newest_log,
        "apply must not rewrite retained logs"
    );
}

#[test]
fn max_age_reclaims_a_finalized_run_inside_the_count_limit() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("age-limited").expect("run id");
    finalize_private_test_run(&repo, RunArtifactFamily::Inbox, &run_id, "inbox");
    let policy = ArtifactRetentionPolicy {
        max_count: 10,
        max_age: Some(Duration::from_secs(24 * 60 * 60)),
        max_total_bytes: None,
        unfinalized_grace: Some(Duration::from_secs(7 * 24 * 60 * 60)),
        reclaim_unverifiable: false,
        external_writers_stopped: false,
    };
    let report = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Inbox,
        ArtifactRetentionFamily::Inbox,
        &policy,
        true,
        SystemTime::now() + Duration::from_secs(2 * 24 * 60 * 60),
    )
    .expect("age dry-run");
    assert_eq!(
        report.entries[0].action,
        RunArtifactPruneAction::WouldDelete
    );
    assert_eq!(
        report.entries[0].selected_by,
        vec![ArtifactRetentionLimit::MaxAge]
    );
    assert!(run_dir(&repo, RunArtifactFamily::Inbox, &run_id).exists());
}

#[test]
fn expired_unfinalized_runs_are_reclaimed_but_fresh_and_active_runs_are_pinned() {
    let (_temp, repo) = committed_repo();
    let active_id = RunId::new("active-unfinalized").expect("run id");
    let mut active = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Autopilot,
        active_id.clone(),
        "autopilot",
    )
    .expect("active writer");
    active
        .write_bytes(
            "events.jsonl",
            b"active\n",
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("active transcript");
    let policy = ArtifactRetentionPolicy {
        max_count: 10,
        max_age: None,
        max_total_bytes: None,
        unfinalized_grace: Some(Duration::from_secs(7 * 24 * 60 * 60)),
        reclaim_unverifiable: false,
        external_writers_stopped: false,
    };

    let fresh = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Autopilot,
        ArtifactRetentionFamily::Autopilot,
        &policy,
        false,
        SystemTime::now(),
    )
    .expect("fresh refusal");
    assert_eq!(fresh.deleted_count, 0);
    assert_eq!(fresh.entries[0].action, RunArtifactPruneAction::Keep);

    let active_report = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Autopilot,
        ArtifactRetentionFamily::Autopilot,
        &policy,
        false,
        SystemTime::now() + Duration::from_secs(8 * 24 * 60 * 60),
    )
    .expect("active refusal");
    assert_eq!(active_report.deleted_count, 0);
    assert!(active_report.entries[0]
        .selected_by
        .contains(&ArtifactRetentionLimit::UnfinalizedGrace));
    assert!(active_report.entries[0]
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("writer lock is held")));
    drop(active);

    let expired = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Autopilot,
        ArtifactRetentionFamily::Autopilot,
        &policy,
        false,
        SystemTime::now() + Duration::from_secs(8 * 24 * 60 * 60),
    )
    .expect("expired reclamation");
    assert_eq!(expired.deleted_count, 1);
    assert_eq!(expired.reclaimed_bytes, active_report.scanned_bytes);
    assert!(!run_dir(&repo, RunArtifactFamily::Autopilot, &active_id).exists());
}

#[test]
fn program_logs_are_covered_and_dry_run_bytes_match_apply() {
    let (_temp, repo) = committed_repo();
    let maco = repo.join(".maco");
    let old = maco.join("program-a");
    let newest = maco.join("program-z");
    fs::create_dir_all(old.join("logs")).expect("old program logs");
    fs::write(old.join("logs/old.jsonl"), b"old-log\n").expect("old log");
    fs::create_dir_all(newest.join("logs")).expect("new program logs");
    fs::write(newest.join("logs/new.jsonl"), b"new-log-longer\n").expect("new log");
    fs::write(maco.join("unrelated-sentinel"), b"keep\n").expect("sentinel");
    let policy = ArtifactRetentionPolicy {
        max_count: usize::MAX,
        max_age: None,
        max_total_bytes: None,
        unfinalized_grace: Some(Duration::from_secs(7 * 24 * 60 * 60)),
        reclaim_unverifiable: false,
        external_writers_stopped: true,
    };

    let dry = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Program,
        ArtifactRetentionFamily::Program,
        &policy,
        true,
        SystemTime::now() + Duration::from_secs(8 * 24 * 60 * 60),
    )
    .expect("program dry-run");
    assert_eq!(dry.family, ArtifactRetentionFamily::Program);
    assert_eq!(dry.run_root, PathBuf::from(".maco"));
    assert_eq!(
        dry.scanned_bytes,
        b"old-log\n".len() as u64 + b"new-log-longer\n".len() as u64
    );
    assert_eq!(dry.compressible_log_bytes, dry.scanned_bytes);
    assert_eq!(dry.would_reclaim_bytes, dry.scanned_bytes);
    assert!(dry.entries.iter().all(|entry| entry
        .selected_by
        .contains(&ArtifactRetentionLimit::UnfinalizedGrace)));
    assert!(old.exists());
    assert!(newest.exists());
    assert!(
        !maco.join(RETENTION_LOCK_FILE).exists(),
        "dry-run must not create coordination metadata"
    );
    assert!(
        !maco.join(RETENTION_QUARANTINE_DIRECTORY).exists(),
        "dry-run must not create a quarantine"
    );

    let applied = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Program,
        ArtifactRetentionFamily::Program,
        &policy,
        false,
        SystemTime::now() + Duration::from_secs(8 * 24 * 60 * 60),
    )
    .expect("program apply");
    assert_eq!(applied.reclaimed_bytes, dry.would_reclaim_bytes);
    assert!(!old.exists());
    assert!(!newest.exists());
    assert_eq!(
        fs::read(maco.join("unrelated-sentinel")).expect("sentinel"),
        b"keep\n"
    );
}

#[test]
fn noncooperating_artifacts_require_writer_stop_acknowledgement() {
    let (_temp, repo) = committed_repo();
    let program = repo.join(".maco/program-live");
    fs::create_dir_all(program.join("logs")).expect("program logs");
    fs::write(program.join("logs/events.jsonl"), b"events\n").expect("program log");
    let mut policy = ArtifactRetentionPolicy {
        max_count: 0,
        max_age: None,
        max_total_bytes: None,
        unfinalized_grace: Some(Duration::ZERO),
        reclaim_unverifiable: false,
        external_writers_stopped: false,
    };

    for dry_run in [true, false] {
        let refused = prune_artifacts_at(
            &repo,
            ArtifactRetentionFamily::Program,
            ArtifactRetentionFamily::Program,
            &policy,
            dry_run,
            SystemTime::now(),
        )
        .expect("external refusal");
        assert_eq!(
            refused.entries[0].action,
            RunArtifactPruneAction::RefuseUnfinalized
        );
        assert!(refused.entries[0]
            .reason
            .as_deref()
            .is_some_and(|reason| reason.contains("writers are stopped")));
        assert_eq!(refused.would_reclaim_bytes, 0);
        assert_eq!(refused.reclaimed_bytes, 0);
        assert!(program.exists());
    }

    policy.external_writers_stopped = true;
    let dry = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Program,
        ArtifactRetentionFamily::Program,
        &policy,
        true,
        SystemTime::now(),
    )
    .expect("acknowledged dry-run");
    assert_eq!(dry.entries[0].action, RunArtifactPruneAction::WouldDelete);
    let applied = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Program,
        ArtifactRetentionFamily::Program,
        &policy,
        false,
        SystemTime::now(),
    )
    .expect("acknowledged apply");
    assert_eq!(applied.reclaimed_bytes, dry.would_reclaim_bytes);
    assert!(!program.exists());

    let legacy_id = RunId::new("legacy-no-lock").expect("run id");
    ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &legacy_id)
        .expect("legacy run directory");
    let legacy = run_dir(&repo, RunArtifactFamily::Inbox, &legacy_id);
    fs::write(legacy.join("events.jsonl"), b"legacy\n").expect("legacy log");
    policy.external_writers_stopped = false;
    let refused = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Inbox,
        ArtifactRetentionFamily::Inbox,
        &policy,
        false,
        SystemTime::now(),
    )
    .expect("legacy refusal");
    assert!(refused.entries[0]
        .reason
        .as_deref()
        .is_some_and(|reason| reason.contains("no cooperative writer lock")));
    assert!(legacy.exists());

    policy.external_writers_stopped = true;
    let applied = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Inbox,
        ArtifactRetentionFamily::Inbox,
        &policy,
        false,
        SystemTime::now(),
    )
    .expect("legacy acknowledged apply");
    assert_eq!(applied.deleted_count, 1);
    assert!(!legacy.exists());
}

#[test]
fn unverifiable_finalization_requires_explicit_reclaim_opt_in() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("corrupt-finalization").expect("run id");
    finalize_private_test_run(&repo, RunArtifactFamily::Inbox, &run_id, "inbox");
    let run = run_dir(&repo, RunArtifactFamily::Inbox, &run_id);
    fs::write(run.join(FINALIZATION_MARKER), b"not-json\n").expect("corrupt marker");
    let now = SystemTime::now() + Duration::from_secs(8 * 24 * 60 * 60);
    let mut policy = ArtifactRetentionPolicy {
        max_count: usize::MAX,
        max_age: None,
        max_total_bytes: None,
        unfinalized_grace: Some(Duration::from_secs(7 * 24 * 60 * 60)),
        reclaim_unverifiable: false,
        external_writers_stopped: false,
    };

    let refused = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Inbox,
        ArtifactRetentionFamily::Inbox,
        &policy,
        true,
        now,
    )
    .expect("unverifiable refusal");
    assert_eq!(
        refused.entries[0].action,
        RunArtifactPruneAction::RefuseUnfinalized
    );
    assert!(refused.entries[0]
        .selected_by
        .contains(&ArtifactRetentionLimit::UnfinalizedGrace));
    assert!(run.exists());

    policy.reclaim_unverifiable = true;
    let dry = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Inbox,
        ArtifactRetentionFamily::Inbox,
        &policy,
        true,
        now,
    )
    .expect("unverifiable opted-in dry-run");
    assert_eq!(dry.entries[0].action, RunArtifactPruneAction::WouldDelete);
    let applied = prune_artifacts_at(
        &repo,
        ArtifactRetentionFamily::Inbox,
        ArtifactRetentionFamily::Inbox,
        &policy,
        false,
        now,
    )
    .expect("unverifiable opted-in apply");
    assert_eq!(applied.reclaimed_bytes, dry.would_reclaim_bytes);
    assert!(!run.exists());
}

#[test]
fn legacy_direct_writer_is_visible_but_never_finalized_or_publishable() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("legacy-run").expect("run id");
    ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &run_id).expect("reserve");
    fs::write(
        final_report_path(&repo, RunArtifactFamily::Inbox, &run_id),
        b"{\"status\":\"succeeded\",\"success\":true}\n",
    )
    .expect("legacy report");

    let summary = latest_run(&repo, RunArtifactFamily::Inbox)
        .expect("latest")
        .run
        .expect("run");
    assert_active_unfinalized_summary(&summary, true);
    assert!(!summary.finalized);
    assert!(!summary.publishable);
    assert!(!summary.provenance_valid);
    assert!(!summary.artifact_digests_verified);
    assert!(ArtifactRunReader::open(&repo, RunArtifactFamily::Inbox, &run_id).is_err());
    let prune =
        prune_runs(&repo, RunArtifactFamily::Inbox, 0, false).expect("legacy prune refusal report");
    assert_eq!(prune.deleted_count, 0);
    assert_eq!(prune.refused_unfinalized_count, 1);
    assert_eq!(
        prune.entries[0].action,
        RunArtifactPruneAction::RefuseUnfinalized
    );
    assert!(run_dir(&repo, RunArtifactFamily::Inbox, &run_id).exists());
}

#[test]
fn marker_missing_report_bytes_are_never_parsed_or_exposed() {
    let (_temp, repo) = committed_repo();
    let secret = "marker-missing-secret-value";
    let absolute = repo.display().to_string();
    let fixtures = [
        (
            "valid-unfinalized",
            format!("{{\"status\":\"{secret}\",\"success\":true,\"path\":{absolute:?}}}\n"),
        ),
        (
            "malformed-unfinalized",
            format!("{{not-json:{secret}:{absolute}\n"),
        ),
        ("secret-unfinalized", format!("{secret}\n{absolute}\n")),
    ];

    for (run_id, contents) in fixtures {
        let run_id = RunId::new(run_id).expect("run id");
        ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &run_id).expect("reserve");
        fs::write(
            final_report_path(&repo, RunArtifactFamily::Inbox, &run_id),
            contents,
        )
        .expect("unfinalized report fixture");
    }

    let list = list_runs(&repo, RunArtifactFamily::Inbox).expect("list unfinalized runs");
    assert_eq!(list.runs.len(), 3);
    for summary in &list.runs {
        assert_active_unfinalized_summary(summary, true);
    }
    let serialized = serde_json::to_string(&list).expect("serialize public listing");
    assert!(!serialized.contains(secret));
    assert!(!serialized.contains(&absolute));
    assert!(!serialized.contains("not-json"));
}

#[test]
fn metadata_only_listing_never_creates_a_missing_report_parent() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("missing-consult-parent").expect("run id");
    ensure_run_dir_available(&repo, RunArtifactFamily::Consult, &run_id).expect("reserve");
    let trusted = run_dir(&repo, RunArtifactFamily::Consult, &run_id).join("trusted");
    assert!(!trusted.exists());

    let summary = latest_run(&repo, RunArtifactFamily::Consult)
        .expect("metadata-only latest")
        .run
        .expect("run");
    assert_active_unfinalized_summary(&summary, false);
    assert!(
        !trusted.exists(),
        "metadata-only listing must not create a missing report parent"
    );
}

#[cfg(unix)]
#[test]
fn marker_missing_symlink_and_special_reports_are_metadata_only() {
    use std::os::unix::fs::symlink;

    let (temp, repo) = committed_repo();
    let secret = "external-final-report-secret";
    let external = temp.path().join("external-final-report.json");
    write_private(&external, secret.as_bytes());

    let symlink_id = RunId::new("unfinalized-symlink-report").expect("run id");
    ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &symlink_id).expect("reserve");
    symlink(
        &external,
        final_report_path(&repo, RunArtifactFamily::Inbox, &symlink_id),
    )
    .expect("symlink report");

    let fifo_id = RunId::new("unfinalized-fifo-report").expect("run id");
    ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &fifo_id).expect("reserve");
    let fifo_path = final_report_path(&repo, RunArtifactFamily::Inbox, &fifo_id);
    let fifo = CString::new(fifo_path.as_os_str().as_bytes()).expect("FIFO path");
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    let directory_id = RunId::new("unfinalized-directory-report").expect("run id");
    ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &directory_id).expect("reserve");
    fs::create_dir(final_report_path(
        &repo,
        RunArtifactFamily::Inbox,
        &directory_id,
    ))
    .expect("directory report");

    let list = list_runs(&repo, RunArtifactFamily::Inbox).expect("metadata-only listing");
    assert_eq!(list.runs.len(), 3);
    for summary in &list.runs {
        assert_active_unfinalized_summary(summary, true);
    }
    let serialized = serde_json::to_string(&list).expect("serialize public listing");
    assert!(!serialized.contains(secret));
    assert!(!serialized.contains(&external.display().to_string()));
    assert!(!serialized.contains(&repo.display().to_string()));
}

#[cfg(unix)]
#[test]
fn present_but_invalid_marker_never_falls_back_to_report_parsing() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("invalid-marker-valid-report").expect("run id");
    ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &run_id).expect("reserve");
    let secret = "invalid-marker-secret-value";
    let absolute = repo.display().to_string();
    write_private(
            &final_report_path(&repo, RunArtifactFamily::Inbox, &run_id),
            format!(
                "{{\"status\":\"succeeded\",\"success\":true,\"secret\":\"{secret}\",\"path\":{absolute:?}}}\n"
            )
            .as_bytes(),
        );
    write_private(
        &run_dir(&repo, RunArtifactFamily::Inbox, &run_id).join(FINALIZATION_MARKER),
        format!("{{invalid-marker:{secret}:{absolute}\n").as_bytes(),
    );

    let summary = latest_run(&repo, RunArtifactFamily::Inbox)
        .expect("latest")
        .run
        .expect("run");
    assert!(summary.final_report_exists);
    assert_eq!(summary.final_report_status, "unverifiable_finalization");
    assert_eq!(summary.final_report_success, None);
    assert!(!summary.final_report_readable);
    assert!(summary.final_report_corrupt);
    assert_eq!(summary.final_report_error, None);
    assert!(!summary.finalized);
    assert!(!summary.publishable);
    assert!(!summary.provenance_valid);
    assert!(!summary.artifact_digests_verified);
    assert_eq!(
        summary.finalization_error.as_deref(),
        Some("artifact finalization marker is present but verification failed")
    );
    let serialized = serde_json::to_string(&summary).expect("serialize public summary");
    assert!(!serialized.contains(secret));
    assert!(!serialized.contains(&absolute));
}

#[test]
fn oversized_report_and_run_root_entry_budget_fail_boundedly() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("large-run").expect("run id");
    ensure_run_dir_available(&repo, RunArtifactFamily::Consult, &run_id).expect("reserve");
    let report = final_report_path(&repo, RunArtifactFamily::Consult, &run_id);
    let report_parent = report.parent().expect("consult report parent");
    fs::create_dir_all(report_parent).expect("consult report directory");
    #[cfg(unix)]
    fs::set_permissions(report_parent, fs::Permissions::from_mode(0o700))
        .expect("private consult report directory");
    fs::write(
        report,
        vec![b'x'; usize::try_from(MAX_ARTIFACT_FILE_BYTES).expect("limit") + 1],
    )
    .expect("oversized report");
    let summary = latest_run(&repo, RunArtifactFamily::Consult)
        .expect("latest")
        .run
        .expect("run");
    assert_active_unfinalized_summary(&summary, true);

    let root = run_root(&repo, RunArtifactFamily::Consult);
    for index in 0..MAX_RUN_ROOT_ENTRIES {
        fs::create_dir(root.join(format!("extra-{index}"))).expect("extra run");
    }
    assert!(list_runs(&repo, RunArtifactFamily::Consult)
        .expect_err("entry budget")
        .to_string()
        .contains("entry budget"));
}

#[cfg(unix)]
#[test]
fn prune_refuses_finalized_runs_tampered_with_symlink_hardlink_and_fifo() {
    use std::os::unix::fs::symlink;

    for kind in ["symlink", "hardlink", "fifo"] {
        let (temp, repo) = committed_repo();
        let run_id = RunId::new(format!("unsafe-{kind}")).expect("run id");
        let mut writer =
            ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Inbox, run_id.clone(), "inbox")
                .expect("writer");
        writer
            .write_json(
                "final-report.json",
                &serde_json::json!({"status":"done"}),
                ArtifactFileDisposition::PrivateEvidence,
            )
            .expect("report");
        writer
            .finalize("final-report.json", false)
            .expect("finalize");
        let run = run_dir(&repo, RunArtifactFamily::Inbox, &run_id);
        let external = temp.path().join(format!("external-{kind}"));
        fs::write(&external, b"keep\n").expect("external");
        match kind {
            "symlink" => symlink(&external, run.join("unsafe-entry")).expect("symlink"),
            "hardlink" => fs::hard_link(&external, run.join("unsafe-entry")).expect("hardlink"),
            "fifo" => {
                let path = CString::new(run.join("unsafe-entry").as_os_str().as_bytes())
                    .expect("FIFO path");
                assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
            }
            _ => unreachable!(),
        }
        let report =
            prune_runs(&repo, RunArtifactFamily::Inbox, 0, false).expect("tampered run refusal");
        assert_eq!(report.deleted_count, 0);
        assert_eq!(report.refused_unfinalized_count, 1);
        assert_eq!(
            report.entries[0].action,
            RunArtifactPruneAction::RefuseUnfinalized
        );
        assert!(external.exists());
        assert!(run.exists(), "tampered run must never be deleted");
    }
}

#[cfg(unix)]
#[test]
fn prune_rejects_device_nodes_when_platform_allows_creating_one() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("unsafe-device").expect("run id");
    let mut writer =
        ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Inbox, run_id.clone(), "inbox")
            .expect("writer");
    writer
        .write_json(
            "final-report.json",
            &serde_json::json!({"status":"done"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("report");
    writer
        .finalize("final-report.json", false)
        .expect("finalize");
    let device = run_dir(&repo, RunArtifactFamily::Inbox, &run_id).join("device");
    let path = CString::new(device.as_os_str().as_bytes()).expect("device path");
    let result = unsafe { libc::mknod(path.as_ptr(), libc::S_IFCHR | 0o600, libc::makedev(1, 3)) };
    if result != 0 {
        return;
    }
    let report =
        prune_runs(&repo, RunArtifactFamily::Inbox, 0, false).expect("device refusal report");
    assert_eq!(report.deleted_count, 0);
    assert_eq!(report.refused_unfinalized_count, 1);
    assert!(device.exists());
}

#[cfg(unix)]
#[test]
fn identity_bound_quarantine_refuses_aba_substitution() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("aba-run").expect("run id");
    ensure_run_dir_available(&repo, RunArtifactFamily::Inbox, &run_id).expect("reserve");
    let repository = discover_artifact_repository(&repo).expect("repository");
    let root = open_existing_run_root(&repository, RunArtifactFamily::Inbox).expect("root");
    let original = root
        .bind_existing_managed_direct_child_directory(run_id.as_str())
        .expect("binding");
    let original_identity = original.identity().clone();
    fs::rename(original.path(), root.path().join("moved-original")).expect("move original");
    fs::create_dir(root.path().join(run_id.as_str())).expect("substitute");
    let quarantine = open_or_create_quarantine(&root).expect("quarantine");
    let error = rename_bound_directory(
        &root,
        run_id.as_str().as_ref(),
        &original_identity,
        &quarantine,
        "quarantine-aba".as_ref(),
    )
    .expect_err("ABA substitution must fail");
    assert!(error.to_string().contains("identity changed"));
    assert!(root.path().join(run_id.as_str()).exists());
    assert!(root.path().join("moved-original").exists());
}

#[cfg(unix)]
#[test]
fn rebound_artifact_root_run_and_key_locks_fail_closed() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("rebound-run-lock").expect("run id");
    let mut writer =
        ArtifactRunWriter::reserve(&repo, RunArtifactFamily::Autopilot, run_id, "autopilot")
            .expect("writer");
    let run_lock_path = writer.run_lock.lock.path().to_path_buf();
    let old_run_lock = run_lock_path.with_file_name("artifact.lock.original");
    fs::rename(&run_lock_path, &old_run_lock).expect("move run lock");
    write_private(&run_lock_path, b"");
    let replacement_run_lock =
        BoundArtifactLock::acquire(&writer.run, RUN_LOCK_FILE).expect("replacement run lock");
    let run_error = writer
        .write_bytes(
            "final-report.json",
            b"{}\n",
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect_err("rebound run lock must fail");
    assert!(
        run_error.to_string().contains("lock path was rebound")
            || run_error
                .to_string()
                .contains("does not name its opened descriptor")
    );
    assert!(!writer.run.path().join("final-report.json").exists());
    drop(replacement_run_lock);

    let repository = discover_artifact_repository(&repo).expect("repository");
    let key_writer = open_artifact_auth_writer(&repository).expect("key writer");
    let key_lock_path = key_writer.lock_path().to_path_buf();
    let old_key_lock = key_lock_path.with_file_name("artifact-key.lock.original");
    fs::rename(&key_lock_path, &old_key_lock).expect("move key lock");
    write_private(&key_lock_path, b"");
    let replacement_key_lock = BoundStateLock::acquire(
        key_writer.authenticator().state_root(),
        authentication_key_lock_name(),
    )
    .expect("replacement key lock");
    let key_error = key_writer.verify().expect_err("rebound key lock must fail");
    assert!(
        key_error.to_string().contains("lock path was rebound")
            || key_error
                .to_string()
                .contains("does not name its opened descriptor")
    );
    drop(replacement_key_lock);

    let root =
        open_or_create_run_root(&repository, RunArtifactFamily::Consult).expect("consult root");
    let root_lock = BoundArtifactLock::acquire(&root, ROOT_LOCK_FILE).expect("root lock");
    let root_lock_path = root_lock.lock.path().to_path_buf();
    let old_root_lock = root_lock_path.with_file_name("runs.lock.original");
    fs::rename(&root_lock_path, &old_root_lock).expect("move root lock");
    write_private(&root_lock_path, b"");
    let replacement_root_lock =
        BoundArtifactLock::acquire(&root, ROOT_LOCK_FILE).expect("replacement root lock");
    let root_error = root_lock
        .verify(&root)
        .expect_err("rebound root lock must fail");
    assert!(
        root_error.to_string().contains("lock path was rebound")
            || root_error
                .to_string()
                .contains("does not name its opened descriptor")
    );
    drop(replacement_root_lock);
}

#[test]
fn finalized_prune_waits_for_active_artifact_writer_lock() {
    use std::{sync::mpsc, thread, time::Duration};

    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("active-lock-run").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Autopilot,
        run_id.clone(),
        "autopilot",
    )
    .expect("writer");
    writer
        .write_json(
            "final-report.json",
            &serde_json::json!({"status":"done"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("report");
    writer
        .finalize("final-report.json", false)
        .expect("finalize");
    let repository = discover_artifact_repository(&repo).expect("repository");
    let root = open_existing_run_root(&repository, RunArtifactFamily::Autopilot).expect("run root");
    let run = root
        .bind_existing_direct_child_directory(run_id.as_str())
        .expect("run binding");
    let run = SafeRoot::open_existing(run.path()).expect("run");
    let held = BoundArtifactLock::acquire(&run, RUN_LOCK_FILE).expect("held run lock");

    let (sender, receiver) = mpsc::channel();
    let prune_repo = repo.clone();
    let worker = thread::spawn(move || {
        let result = prune_runs(&prune_repo, RunArtifactFamily::Autopilot, 0, false);
        sender.send(result).expect("send prune result");
    });
    thread::sleep(Duration::from_millis(100));
    assert!(matches!(
        receiver.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
    drop(held);
    let report = receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("prune completion")
        .expect("prune report");
    assert_eq!(report.deleted_count, 1);
    worker.join().expect("prune worker");
}

#[test]
fn normal_prune_removes_run_and_leaves_empty_quarantine() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("prune-run").expect("run id");
    let mut writer = ArtifactRunWriter::reserve(
        &repo,
        RunArtifactFamily::Autopilot,
        run_id.clone(),
        "autopilot",
    )
    .expect("writer");
    writer
        .write_json(
            "final-report.json",
            &serde_json::json!({"status":"done"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("report");
    writer
        .finalize("final-report.json", false)
        .expect("finalize");
    let report = prune_runs(&repo, RunArtifactFamily::Autopilot, 0, false).expect("prune");
    assert_eq!(report.deleted_count, 1);
    assert_eq!(report.refused_unfinalized_count, 0);
    assert!(!run_dir(&repo, RunArtifactFamily::Autopilot, &run_id).exists());
    let quarantine = run_root(&repo, RunArtifactFamily::Autopilot).join(QUARANTINE_DIRECTORY);
    assert_eq!(fs::read_dir(quarantine).expect("quarantine").count(), 0);
}

#[cfg(unix)]
#[test]
fn prune_refuses_run_lock_replacement_immediately_after_flock() {
    let (_temp, repo) = committed_repo();
    let run_id = RunId::new("prune-after-flock-rebind").expect("run id");
    finalize_private_test_run(&repo, RunArtifactFamily::Autopilot, &run_id, "autopilot");
    crate::safe_state::set_kernel_lock_after_flock_hook(|path| {
        if path.file_name() != Some(OsStr::new(RUN_LOCK_FILE)) {
            return false;
        }
        let original = path.with_file_name("artifact.lock.after-flock-original");
        fs::rename(path, &original).expect("move acquired writer lock");
        write_private(path, b"");
        true
    });

    let error = prune_runs(&repo, RunArtifactFamily::Autopilot, 0, false)
        .expect_err("post-flock lock replacement must abort prune");
    assert!(
        error
            .to_string()
            .contains("does not name its opened descriptor")
            || error.to_string().contains("was rebound"),
        "unexpected error: {error:#}"
    );
    assert!(run_dir(&repo, RunArtifactFamily::Autopilot, &run_id).exists());
}

#[cfg(target_os = "linux")]
fn quarantined_scratch_path(run: &Path, expected: &FileIdentity) -> Option<PathBuf> {
    let entries = fs::read_dir(run).ok()?;
    for entry in entries {
        let entry = entry.ok()?;
        let metadata = fs::symlink_metadata(entry.path()).ok()?;
        if metadata.file_type().is_dir()
            && identity_for_path(entry.path()).ok().as_ref() == Some(expected)
        {
            return Some(entry.path());
        }
    }
    None
}

#[cfg(target_os = "linux")]
struct ScratchMountGuard {
    run: PathBuf,
    scratch_identity: FileIdentity,
    mount_name: String,
    active: bool,
}

#[cfg(target_os = "linux")]
impl ScratchMountGuard {
    fn unmount(&mut self) -> Result<()> {
        let scratch = quarantined_scratch_path(&self.run, &self.scratch_identity)
            .context("mounted scratch directory is no longer identity-bound in its run")?;
        let mount_point = scratch.join(&self.mount_name);
        let target = CString::new(mount_point.as_os_str().as_bytes())
            .context("mounted scratch path contains a NUL byte")?;
        if unsafe { libc::umount2(target.as_ptr(), libc::MNT_DETACH) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to detach scratch boundary test mount");
        }
        self.active = false;
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl Drop for ScratchMountGuard {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let Some(scratch) = quarantined_scratch_path(&self.run, &self.scratch_identity) else {
            return;
        };
        let mount_point = scratch.join(&self.mount_name);
        let Ok(target) = CString::new(mount_point.as_os_str().as_bytes()) else {
            return;
        };
        unsafe {
            libc::umount2(target.as_ptr(), libc::MNT_DETACH);
        }
    }
}

fn finalize_private_test_run(
    repo: &Path,
    family: RunArtifactFamily,
    run_id: &RunId,
    producer: &str,
) {
    let mut writer = ArtifactRunWriter::reserve(repo, family, run_id.clone(), producer)
        .expect("reserve test writer");
    writer
        .write_json(
            family.final_report_relative_path(),
            &serde_json::json!({"status":"done"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write test report");
    writer
        .finalize(family.final_report_relative_path(), false)
        .expect("finalize test run");
}

fn finalize_test_run_with_log(
    repo: &Path,
    family: RunArtifactFamily,
    run_id: &RunId,
    transcript: &[u8],
) {
    let mut writer = ArtifactRunWriter::reserve(repo, family, run_id.clone(), family.label())
        .expect("reserve logged test writer");
    writer
        .write_bytes(
            "events.jsonl",
            transcript,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write test transcript");
    writer
        .write_json(
            family.final_report_relative_path(),
            &serde_json::json!({"status":"done"}),
            ArtifactFileDisposition::PrivateEvidence,
        )
        .expect("write test report");
    writer
        .finalize(family.final_report_relative_path(), false)
        .expect("finalize logged test run");
}

fn committed_repo() -> (TempDir, PathBuf) {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let workdir = repo.workdir().expect("workdir");
    fs::write(workdir.join("README.md"), "# Test\n").expect("README");
    let mut index = repo.index().expect("index");
    index.add_path(Path::new("README.md")).expect("add");
    index.write().expect("index write");
    let tree_id = index.write_tree().expect("tree id");
    let tree = repo.find_tree(tree_id).expect("tree");
    let signature = Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    let oid: Oid = repo
        .commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit");
    assert!(!oid.is_zero());
    drop(tree);
    drop(repo);
    (temp, repo_path)
}

#[cfg(unix)]
fn write_private(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("private file");
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("private mode");
}

fn assert_active_unfinalized_summary(summary: &RunArtifactSummary, report_exists: bool) {
    assert_eq!(summary.final_report_exists, report_exists);
    assert_eq!(summary.final_report_status, "active");
    assert_eq!(summary.final_report_success, None);
    assert!(!summary.final_report_readable);
    assert!(!summary.final_report_corrupt);
    assert_eq!(summary.final_report_error, None);
    assert!(!summary.finalized);
    assert!(!summary.publishable);
    assert!(!summary.provenance_valid);
    assert!(!summary.artifact_digests_verified);
    assert_eq!(
        summary.finalization_error.as_deref(),
        Some("artifact run is active or unfinalized; finalization marker is missing")
    );
}

#[cfg(unix)]
fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path)
        .expect("metadata")
        .permissions()
        .mode()
        & 0o777
}
