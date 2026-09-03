use super::*;
use crate::megafile::{FileSizeSample, MegafileRecordKind, MegafileThresholdCalibration};
use crate::worktree::WorktreeCreateOptions;
use git2::Signature;
use std::process::{Command, Stdio};
use std::sync::{mpsc, Mutex};

static VALIDATION_ENVIRONMENT_TEST_LOCK: Mutex<()> = Mutex::new(());

const ARBITRATION_PATCH_A: &[u8] = b"diff --git a/shared.txt b/shared.txt\nindex 1111111..2222222 100644\n--- a/shared.txt\n+++ b/shared.txt\n@@ -1 +1,2 @@\n base\n+side-a\n";
const ARBITRATION_PATCH_B: &[u8] = b"diff --git a/shared.txt b/shared.txt\nindex 1111111..3333333 100644\n--- a/shared.txt\n+++ b/shared.txt\n@@ -1 +1,2 @@\n base\n+side-b\n";
const ARBITRATION_PATCH_BOTH: &[u8] = b"diff --git a/shared.txt b/shared.txt\nindex 1111111..4444444 100644\n--- a/shared.txt\n+++ b/shared.txt\n@@ -1 +1,3 @@\n base\n+side-a\n+side-b\n";
const ARBITRATION_BASE: &str = "1111111111111111111111111111111111111111";

#[derive(Clone)]
struct FakeArbitrationEnvironment {
    prepared: PreparedMergeArbitration,
    candidate_diff: Vec<u8>,
    validation_status: ValidationStatus,
}

impl ArbitrationEnvironment for FakeArbitrationEnvironment {
    fn prepare(&self, _options: &MergeArbitrationOptions) -> Result<PreparedMergeArbitration> {
        Ok(self.prepared.clone())
    }

    fn materialize_candidate(
        &self,
        prepared: &PreparedMergeArbitration,
        _proposal: &ArbitrationProposal,
    ) -> Result<MergeApplyPreview> {
        Ok(fake_arbitration_preview(
            prepared,
            self.candidate_diff.clone(),
        ))
    }

    fn validate_candidate(
        &self,
        _preview: &MergeApplyPreview,
        _commands: &[CandidateValidationCommand],
    ) -> Result<Vec<ValidationReport>> {
        Ok(vec![ValidationReport {
            name: "fake candidate validation".to_string(),
            status: self.validation_status,
            message: None,
            paths: vec![PathBuf::from("shared.txt")],
        }])
    }

    fn current_primary_state_sha256(&self, prepared: &PreparedMergeArbitration) -> Result<String> {
        Ok(prepared.primary_state_sha256.clone())
    }
}

struct TrustedStaticArbitrationRunner {
    proposal: ArbitrationProposal,
}

impl ArbitrationRunner for TrustedStaticArbitrationRunner {
    fn run(&self, _request: &ArbitrationRunnerRequest) -> Result<ArbitrationRunnerResult> {
        Ok(ArbitrationRunnerResult {
            proposal: self.proposal.clone(),
            execution: ArbitrationRunnerExecution {
                kind: "trusted_fake_test".to_string(),
                trusted_local_boundary: true,
                command: Vec::new(),
                exit_code: Some(0),
                timed_out: false,
            },
        })
    }
}

fn fake_arbitration_prepared(
    repo: &Path,
    sides: [ArbitrationSide; 2],
    source_diffs: [Vec<u8>; 2],
) -> PreparedMergeArbitration {
    let side_evidence = std::array::from_fn(|index| ArbitrationSideEvidence {
        participant: sides[index].clone(),
        head_oid: if index == 0 {
            "2222222222222222222222222222222222222222".to_string()
        } else {
            "3333333333333333333333333333333333333333".to_string()
        },
        tree_oid: if index == 0 {
            "4444444444444444444444444444444444444444".to_string()
        } else {
            "5555555555555555555555555555555555555555".to_string()
        },
        base_oid: ARBITRATION_BASE.to_string(),
        diff_sha256: sha256_hex(&source_diffs[index]),
        diff_bytes: source_diffs[index].len(),
        diff: String::from_utf8_lossy(&source_diffs[index]).into_owned(),
        changed_paths: vec![PathBuf::from("shared.txt")],
        candidate_binding: None,
    });
    let input = ArbitrationInput {
        version: ARBITRATION_INPUT_VERSION,
        arbiter_id: "neutral-arbiter".to_string(),
        reviewed_base_oid: ARBITRATION_BASE.to_string(),
        neutral_worktree: ArbitrationNeutralWorktree {
            agent_id: "neutral-arbiter".to_string(),
            path: repo.join("neutral-worktree"),
            branch: "maco/neutral-arbiter".to_string(),
            exact_base_oid: ARBITRATION_BASE.to_string(),
            inherited_claim: false,
        },
        sides: side_evidence,
        relevant_path_claims: Vec::new(),
        relevant_semantic_intents: Vec::new(),
        semantic_classification: SemanticConflictClassification::no_conflict(),
    };
    let mut input_json = serde_json::to_vec_pretty(&input).expect("serialize fake input");
    input_json.push(b'\n');
    PreparedMergeArbitration {
        input,
        input_sha256: sha256_hex(&input_json),
        input_json,
        primary_repo_root: repo.to_path_buf(),
        primary_state_sha256: sha256_hex(b"stable primary"),
        source_diffs,
    }
}

fn fake_arbitration_preview(
    prepared: &PreparedMergeArbitration,
    raw_diff: Vec<u8>,
) -> MergeApplyPreview {
    let metadata = WorktreeMergeMetadata {
        agent_id: prepared.input.arbiter_id.clone(),
        worktree_path: prepared.input.neutral_worktree.path.clone(),
        branch: prepared.input.neutral_worktree.branch.clone(),
        primary_repo_root: prepared.primary_repo_root.clone(),
        primary_head: Some(ARBITRATION_BASE.to_string()),
        agent_head: Some(ARBITRATION_BASE.to_string()),
        merge_base: Some(ARBITRATION_BASE.to_string()),
        base_matches_primary: Some(true),
    };
    let binding =
        candidate_validation_binding(&metadata, &raw_diff).expect("fake candidate binding");
    let candidate = MergeCandidate {
        metadata,
        claimed_paths: vec![PathBuf::from("shared.txt")],
        changed_paths: vec![PathBuf::from("shared.txt")],
        changes: vec![ChangedPath {
            path: PathBuf::from("shared.txt"),
            kind: ChangeKind::Modified,
        }],
        unclaimed_changed_paths: Vec::new(),
        diff: DiffOutput {
            summary: summarize_text(
                &String::from_utf8_lossy(&raw_diff),
                DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
            ),
            full: Some(String::from_utf8_lossy(&raw_diff).into_owned()),
        },
        validations: Vec::new(),
        validation_binding: binding,
        validation_evidence: ValidationEvidenceBundle::default(),
        raw_diff,
        snapshot_tree: Oid::from_str(ARBITRATION_BASE).expect("fake tree"),
    };
    MergeApplyPreview {
        candidate,
        safety: MergeApplySafety {
            primary_state_unchanged: passed_safety_check(),
            dirty_primary: passed_safety_check(),
            stale_base: passed_safety_check(),
            apply_check: passed_safety_check(),
            unclaimed_edits: passed_safety_check(),
            validation: passed_safety_check(),
            validation_evidence: ValidationEvidenceCheck {
                status: SafetyCheckStatus::Passed,
                binding_status: ValidationBindingStatus::NotRequired,
                message: None,
                paths: Vec::new(),
            },
            megafile: passed_safety_check(),
            megafile_warnings: Vec::new(),
            megafile_decomposition_target: None,
            megafile_decomposition_evidence: None,
            megafile_blocking: false,
            validation_required: false,
            candidate_validation_commands: Vec::new(),
            force_options: MergeForceOptions::default(),
            apply_mode: ApplyMode::Direct,
            semantic_conflicts: SemanticConflictClassification::no_conflict(),
            readiness: ApplyReadiness {
                status: ApplyReadinessStatus::Safe,
                blockers: Vec::new(),
                forced: Vec::new(),
                details: Vec::new(),
            },
        },
    }
}

fn fake_arbitration_options(repo: &Path, run_id: &str) -> MergeArbitrationOptions {
    MergeArbitrationOptions {
        repo: repo.to_path_buf(),
        run_id: RunId::new(run_id).expect("fake run id"),
        arbiter_agent_id: "neutral-arbiter".to_string(),
        sides: [
            ArbitrationSideSpec::Agent {
                agent_id: "agent-a".to_string(),
                claimed_paths: vec![PathBuf::from("shared.txt")],
            },
            ArbitrationSideSpec::Agent {
                agent_id: "agent-b".to_string(),
                claimed_paths: vec![PathBuf::from("shared.txt")],
            },
        ],
        validation_commands: vec![CandidateValidationCommand {
            command: "fake validation".to_string(),
        }],
        approve: true,
        codex_bin: PathBuf::from("unused"),
        timeout: Duration::from_secs(1),
        worktree_root: None,
        machine_global_config: repo.join("unused-machine-global.json"),
        machine_global_runtime_root_id: "runtime".to_string(),
    }
}

#[test]
fn arbitration_strict_parser_and_static_runner_are_bounded_and_non_authoritative() {
    let digest = "1".repeat(64);
    let bytes = serde_json::to_vec(&serde_json::json!({
        "version": 1,
        "input_sha256": digest,
        "disposition": "escalated",
        "rationale": "human review required",
        "candidate_patch": null,
    }))
    .expect("proposal JSON");
    let runner = StaticArbitrationRunner::from_bytes(bytes).expect("static runner");
    let result = runner
        .run(&ArbitrationRunnerRequest {
            prompt_path: PathBuf::from("prompt"),
            output_schema_path: PathBuf::from("schema"),
            output_last_message_path: PathBuf::from("output"),
            json_log_path: PathBuf::from("log"),
            neutral_worktree_path: PathBuf::from("neutral"),
            hidden_primary_root: PathBuf::from("primary"),
            run_id: "run".to_string(),
            arbiter_id: "neutral-arbiter".to_string(),
        })
        .expect("static result");
    assert!(!result.execution.trusted_local_boundary);

    let missing = br#"{"version":1,"input_sha256":"1111111111111111111111111111111111111111111111111111111111111111","disposition":"escalated","rationale":"review"}"#;
    assert!(parse_arbitration_proposal(missing)
        .expect_err("missing candidate field")
        .to_string()
        .contains("candidate_patch"));
    assert!(
        parse_arbitration_proposal(&vec![b'x'; MAX_ARBITRATION_PROPOSAL_BYTES + 1])
            .expect_err("oversized proposal")
            .to_string()
            .contains("exceeds")
    );
}

#[test]
fn arbitration_prompt_cap_fits_existing_external_runner_boundary() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut prepared = fake_arbitration_prepared(
        temp.path(),
        [
            ArbitrationSide::Agent {
                id: "agent-a".to_string(),
            },
            ArbitrationSide::Primary,
        ],
        [ARBITRATION_PATCH_A.to_vec(), ARBITRATION_PATCH_B.to_vec()],
    );
    prepared.input_json = vec![b'x'; MAX_ARBITRATION_INPUT_BYTES];
    assert!(arbitration_prompt(&prepared).len() <= MAX_ARBITRATION_PROMPT_BYTES);
}

#[test]
fn arbitration_preservation_counts_duplicate_occurrences() {
    let duplicate = b"diff --git a/shared.txt b/shared.txt\nindex 1111111..2222222 100644\n--- a/shared.txt\n+++ b/shared.txt\n@@ -1 +1,3 @@\n base\n+repeat\n+repeat\n";
    let one_duplicate = b"diff --git a/shared.txt b/shared.txt\nindex 1111111..2222222 100644\n--- a/shared.txt\n+++ b/shared.txt\n@@ -1 +1,2 @@\n base\n+repeat\n";
    let sides = [
        ArbitrationSideEvidence {
            participant: ArbitrationSide::Agent {
                id: "agent-a".to_string(),
            },
            head_oid: "2".repeat(40),
            tree_oid: "3".repeat(40),
            base_oid: ARBITRATION_BASE.to_string(),
            diff_sha256: sha256_hex(duplicate),
            diff_bytes: duplicate.len(),
            diff: String::from_utf8_lossy(duplicate).into_owned(),
            changed_paths: vec![PathBuf::from("shared.txt")],
            candidate_binding: None,
        },
        ArbitrationSideEvidence {
            participant: ArbitrationSide::Agent {
                id: "agent-b".to_string(),
            },
            head_oid: "4".repeat(40),
            tree_oid: "5".repeat(40),
            base_oid: ARBITRATION_BASE.to_string(),
            diff_sha256: sha256_hex(ARBITRATION_PATCH_B),
            diff_bytes: ARBITRATION_PATCH_B.len(),
            diff: String::from_utf8_lossy(ARBITRATION_PATCH_B).into_owned(),
            changed_paths: vec![PathBuf::from("shared.txt")],
            candidate_binding: None,
        },
    ];
    let proofs = prove_both_sides_preserved(
        &sides,
        &[duplicate.to_vec(), ARBITRATION_PATCH_B.to_vec()],
        one_duplicate,
    )
    .expect("preservation proof");
    assert!(!proofs[0].preserved);
    assert_eq!(proofs[0].required_additions, 2);
    assert_eq!(proofs[0].preserved_additions, 1);
}

#[test]
fn fake_arbitration_exercises_accepted_rejected_and_escalated_journals_without_primary_apply() {
    let cases = [
        (
            "fake-arbitration-accepted",
            ARBITRATION_PATCH_BOTH.to_vec(),
            ValidationStatus::Passed,
            true,
            ArbitrationOutcome::Accepted,
        ),
        (
            "fake-arbitration-discarded",
            ARBITRATION_PATCH_A.to_vec(),
            ValidationStatus::Passed,
            true,
            ArbitrationOutcome::Rejected,
        ),
        (
            "fake-arbitration-validation",
            ARBITRATION_PATCH_BOTH.to_vec(),
            ValidationStatus::Failed,
            true,
            ArbitrationOutcome::Rejected,
        ),
        (
            "fake-arbitration-unapproved",
            ARBITRATION_PATCH_BOTH.to_vec(),
            ValidationStatus::Passed,
            false,
            ArbitrationOutcome::Escalated,
        ),
    ];
    for (run_id, candidate_diff, validation_status, approve, expected) in cases {
        let temp = tempfile::tempdir().expect("tempdir");
        WorktreeManager::init_repository(temp.path(), "main").expect("init fake repo");
        let prepared = fake_arbitration_prepared(
            temp.path(),
            [
                ArbitrationSide::Agent {
                    id: "agent-a".to_string(),
                },
                ArbitrationSide::Agent {
                    id: "agent-b".to_string(),
                },
            ],
            [ARBITRATION_PATCH_A.to_vec(), ARBITRATION_PATCH_B.to_vec()],
        );
        let environment = FakeArbitrationEnvironment {
            prepared: prepared.clone(),
            candidate_diff,
            validation_status,
        };
        let runner = TrustedStaticArbitrationRunner {
            proposal: ArbitrationProposal {
                version: ARBITRATION_PROPOSAL_VERSION,
                input_sha256: prepared.input_sha256.clone(),
                disposition: ArbitrationProposalDisposition::Proposed,
                rationale: "bounded fake rationale".to_string(),
                candidate_patch: Some(
                    "fake patch bytes are materialized by the fake environment".to_string(),
                ),
            },
        };
        let mut options = fake_arbitration_options(temp.path(), run_id);
        options.approve = approve;
        let report =
            arbitrate_merge_with_environment(options, &runner, &environment).expect("report");
        assert_eq!(report.outcome, expected);
        assert!(!report.primary_mutated);
        assert!(report.later_ordinary_merge_apply_required);
        assert_eq!(primary_repo_path_for_verification(&prepared), temp.path());
    }
}

#[test]
fn static_fake_cannot_claim_accepted_arbitration_authority() {
    let temp = tempfile::tempdir().expect("tempdir");
    WorktreeManager::init_repository(temp.path(), "main").expect("init fake repo");
    let prepared = fake_arbitration_prepared(
        temp.path(),
        [
            ArbitrationSide::Agent {
                id: "agent-a".to_string(),
            },
            ArbitrationSide::Primary,
        ],
        [ARBITRATION_PATCH_A.to_vec(), ARBITRATION_PATCH_B.to_vec()],
    );
    let environment = FakeArbitrationEnvironment {
        prepared: prepared.clone(),
        candidate_diff: ARBITRATION_PATCH_BOTH.to_vec(),
        validation_status: ValidationStatus::Passed,
    };
    let output = serde_json::to_vec(&ArbitrationProposal {
        version: ARBITRATION_PROPOSAL_VERSION,
        input_sha256: prepared.input_sha256,
        disposition: ArbitrationProposalDisposition::Proposed,
        rationale: "static fake proposal".to_string(),
        candidate_patch: Some("fake patch".to_string()),
    })
    .expect("static output");
    let runner = StaticArbitrationRunner::from_bytes(output).expect("static runner");
    let mut options = fake_arbitration_options(temp.path(), "static-fake-nonauthoritative");
    options.sides[1] = ArbitrationSideSpec::Primary;
    let report =
        arbitrate_merge_with_environment(options, &runner, &environment).expect("static report");
    assert_eq!(report.outcome, ArbitrationOutcome::Escalated);
    assert!(!report.approved);
    assert!(!report.runner.trusted_local_boundary);
    assert!(matches!(report.sides[1], ArbitrationSide::Primary));
}

#[test]
fn arbitration_tampered_input_digest_is_rejected_before_candidate_evaluation() {
    let temp = tempfile::tempdir().expect("tempdir");
    WorktreeManager::init_repository(temp.path(), "main").expect("init fake repo");
    let prepared = fake_arbitration_prepared(
        temp.path(),
        [
            ArbitrationSide::Agent {
                id: "agent-a".to_string(),
            },
            ArbitrationSide::Agent {
                id: "agent-b".to_string(),
            },
        ],
        [ARBITRATION_PATCH_A.to_vec(), ARBITRATION_PATCH_B.to_vec()],
    );
    let environment = FakeArbitrationEnvironment {
        prepared,
        candidate_diff: ARBITRATION_PATCH_BOTH.to_vec(),
        validation_status: ValidationStatus::Passed,
    };
    let runner = TrustedStaticArbitrationRunner {
        proposal: ArbitrationProposal {
            version: ARBITRATION_PROPOSAL_VERSION,
            input_sha256: "f".repeat(64),
            disposition: ArbitrationProposalDisposition::Proposed,
            rationale: "tampered input binding".to_string(),
            candidate_patch: Some("fake patch".to_string()),
        },
    };
    let error = arbitrate_merge_with_environment(
        fake_arbitration_options(temp.path(), "tampered-input"),
        &runner,
        &environment,
    )
    .expect_err("tampered digest");
    assert!(error.to_string().contains("does not match"));
}

fn exact_test_validation_binding() -> CandidateValidationBinding {
    CandidateValidationBinding {
        version: VALIDATION_BINDING_VERSION,
        agent_id: "agent-a".to_string(),
        primary_head: Some("1111111111111111111111111111111111111111".to_string()),
        agent_head: Some("2222222222222222222222222222222222222222".to_string()),
        merge_base: Some("1111111111111111111111111111111111111111".to_string()),
        diff_oid: "3333333333333333333333333333333333333333".to_string(),
    }
}

fn passed_test_validation_report() -> ValidationReport {
    ValidationReport {
        name: " unit ".to_string(),
        status: ValidationStatus::Passed,
        message: None,
        paths: vec![
            PathBuf::from("src/../README.md"),
            PathBuf::from("README.md"),
        ],
    }
}

#[test]
fn exact_bound_validation_factory_canonicalizes_passed_evidence() {
    let binding = exact_test_validation_binding();

    let bound =
        ValidationEvidenceBundle::bound_to(binding.clone(), vec![passed_test_validation_report()])
            .expect("construct exact bound evidence");

    assert_eq!(bound.binding(), &binding);
    assert_eq!(bound.evidence().groups.len(), 1);
    let group = &bound.evidence().groups[0];
    assert_eq!(group.binding.as_ref(), Some(&binding));
    assert_eq!(group.reports.len(), 1);
    assert_eq!(group.reports[0].name, "unit");
    assert_eq!(group.reports[0].paths, vec![PathBuf::from("README.md")]);
}

#[test]
fn exact_bound_validation_factory_rejects_malformed_or_nonpassing_input() {
    assert!(
        ValidationEvidenceBundle::bound_to(exact_test_validation_binding(), Vec::new())
            .expect_err("empty evidence must be refused")
            .to_string()
            .contains("at least one passed")
    );

    let mut malformed = exact_test_validation_binding();
    malformed.version = VALIDATION_BINDING_VERSION + 1;
    assert!(
        ValidationEvidenceBundle::bound_to(malformed, vec![passed_test_validation_report()])
            .expect_err("malformed binding must be refused")
            .to_string()
            .contains("unsupported validation binding version")
    );

    let mut malformed_oid = exact_test_validation_binding();
    malformed_oid.diff_oid = "ABC".to_string();
    let malformed_oid_error =
        ValidationEvidenceBundle::bound_to(malformed_oid, vec![passed_test_validation_report()])
            .expect_err("malformed binding OID must be refused");
    assert!(
        format!("{malformed_oid_error:#}").contains("canonical 40-character lowercase"),
        "unexpected error: {malformed_oid_error:#}"
    );

    let mut skipped = passed_test_validation_report();
    skipped.status = ValidationStatus::Skipped;
    assert!(
        ValidationEvidenceBundle::bound_to(exact_test_validation_binding(), vec![skipped])
            .expect_err("nonpassing report must be refused")
            .to_string()
            .contains("only passed validation reports")
    );

    let mut absolute = passed_test_validation_report();
    absolute.paths = vec![PathBuf::from("/private/result")];
    let absolute_error =
        ValidationEvidenceBundle::bound_to(exact_test_validation_binding(), vec![absolute])
            .expect_err("absolute evidence path must be refused");
    assert!(
        format!("{absolute_error:#}").contains("repository-relative"),
        "unexpected error: {absolute_error:#}"
    );
}

#[test]
fn exact_bound_validation_upgrade_rejects_legacy_and_multiple_groups() {
    let report = passed_test_validation_report();
    assert!(ValidationEvidenceBundle::legacy(vec![report.clone()])
        .try_into_exact_bound()
        .expect_err("legacy evidence must not become bound")
        .to_string()
        .contains("legacy unbound"));

    let first =
        ValidationEvidenceBundle::bound_to(exact_test_validation_binding(), vec![report.clone()])
            .expect("first bound evidence");
    let mut combined = first.evidence().clone();
    combined.extend(
        ValidationEvidenceBundle::bound_to(exact_test_validation_binding(), vec![report])
            .expect("second bound evidence")
            .evidence()
            .clone(),
    );
    assert!(combined
        .try_into_exact_bound()
        .expect_err("multi-group evidence must be refused")
        .to_string()
        .contains("exactly one bound group"));
}

fn create_managed_merge_fixture(
    root: &Path,
) -> (PathBuf, WorktreeManager, WorktreeRecord, WorktreeRecord) {
    let repo_path = root.join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
    fs::write(repo_path.join("README.md"), "# Test\n").expect("write README");
    let repo = crate::git_repository::open(&repo_path).expect("open repository");
    let mut index = repo.index().expect("open index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage README");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let signature = Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit fixture");
    drop(tree);
    drop(repo);

    let manager = WorktreeManager::new(&repo_path);
    let agent_a = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create agent-a worktree");
    let agent_b = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-b".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create agent-b worktree");
    (repo_path, manager, agent_a, agent_b)
}

fn create_semantic_merge_fixture(root: &Path, files: &[(&str, &str)]) -> (PathBuf, WorktreeRecord) {
    let repo_path = root.join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
    for (path, contents) in files {
        let path = repo_path.join(path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create semantic fixture parent");
        }
        fs::write(path, contents).expect("write semantic fixture file");
    }
    let repo = crate::git_repository::open(&repo_path).expect("open repository");
    commit_all_for_semantic_test(&repo, "initial semantic fixture")
        .expect("commit semantic fixture");
    drop(repo);

    let manager = WorktreeManager::new(&repo_path);
    let agent = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: None,
        })
        .expect("create semantic agent worktree");
    (repo_path, agent)
}

fn commit_all_for_semantic_test(repo: &Repository, message: &str) -> Result<Oid> {
    let mut index = repo.index().context("open semantic fixture index")?;
    index
        .add_all(["*"].iter(), git2::IndexAddOption::DEFAULT, None)
        .context("stage semantic fixture")?;
    index.write().context("write semantic fixture index")?;
    let tree_id = index.write_tree().context("write semantic fixture tree")?;
    let tree = repo
        .find_tree(tree_id)
        .context("find semantic fixture tree")?;
    let signature =
        Signature::now("maco test", "maco-test@example.invalid").context("signature")?;
    let parent = repo.head().ok().and_then(|head| head.peel_to_commit().ok());
    let parents = parent.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parents,
    )
    .context("commit semantic fixture")
}

fn semantic_preview_options(repo_path: &Path, claim: &str) -> MergePreviewOptions {
    MergePreviewOptions {
        collect: MergeCollectOptions {
            repo: repo_path.to_path_buf(),
            agent_id: "agent-a".to_string(),
            claimed_paths: vec![PathBuf::from(claim)],
            include_full_diff: false,
            diff_summary_char_limit: DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
            validations: Vec::new(),
        },
        forces: MergeForceOptions::default(),
        require_validation: false,
    }
}

fn megafile_test_policy(block: bool, decomposition_target: Option<&str>) -> MegafileMergePolicy {
    MegafileMergePolicy {
        block,
        decomposition_target: decomposition_target.map(PathBuf::from),
        decomposition_run_id: None,
        thresholds: MegafileThresholds {
            calibration: MegafileThresholdCalibration::Configured,
            file_bytes: 1,
            collision_count: 1,
            ..MegafileThresholds::provisional_bootstrap()
        },
    }
}

fn seed_megafile(repo_path: &Path, policy: &MegafileMergePolicy) {
    MegafileStore::open_with_thresholds(repo_path, policy.thresholds.clone())
        .expect("open megafile store")
        .record_file_samples([FileSizeSample {
            path: PathBuf::from("README.md"),
            bytes: 7,
            lines: 1,
        }])
        .expect("seed megafile");
}

fn megafile_preview_options(
    repo_path: &Path,
    claims: Vec<PathBuf>,
    validations: Vec<ValidationReport>,
    require_validation: bool,
) -> MergePreviewOptions {
    MergePreviewOptions {
        collect: MergeCollectOptions {
            repo: repo_path.to_path_buf(),
            agent_id: "agent-a".to_string(),
            claimed_paths: claims,
            include_full_diff: true,
            diff_summary_char_limit: DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
            validations,
        },
        forces: MergeForceOptions::default(),
        require_validation,
    }
}

fn newest_numeric_state_json(root: &Path) -> Option<PathBuf> {
    let mut pending = vec![root.to_path_buf()];
    let mut candidates = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory).expect("read authenticated state directory") {
            let entry = entry.expect("state directory entry");
            let file_type = entry.file_type().expect("state entry type");
            let path = entry.path();
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && path.extension().and_then(OsStr::to_str) == Some("json")
                && path
                    .file_stem()
                    .and_then(OsStr::to_str)
                    .is_some_and(|stem| {
                        !stem.is_empty() && stem.bytes().all(|byte| byte.is_ascii_digit())
                    })
            {
                candidates.push(path);
            }
        }
    }
    candidates.sort();
    candidates.pop()
}

#[test]
fn megafile_policy_is_warn_only_by_default_and_reuses_typed_blocker_detail() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, agent) =
        create_semantic_merge_fixture(temp.path(), &[("README.md", "# Test\n")]);
    fs::write(agent.path.join("README.md"), "# Candidate\n").expect("edit candidate");
    let policy = megafile_test_policy(false, None);
    seed_megafile(&repo_path, &policy);
    let validation = ValidationReport {
        name: "megafile-unit".to_string(),
        status: ValidationStatus::Passed,
        message: None,
        paths: vec![PathBuf::from("README.md")],
    };

    let warning = preview_merge_apply_with_megafile_policy(
        megafile_preview_options(
            &repo_path,
            vec![PathBuf::from("README.md")],
            Vec::new(),
            false,
        ),
        ValidationEvidenceBundle::legacy(vec![validation.clone()]),
        policy.clone(),
    )
    .expect("warn-only preview");
    assert_eq!(warning.safety.readiness.status, ApplyReadinessStatus::Safe);
    assert!(!warning.safety.megafile_blocking);
    assert_eq!(warning.safety.megafile_warnings.len(), 1);
    assert_eq!(
        warning.safety.megafile_warnings[0].path,
        PathBuf::from("README.md")
    );

    let blocked = preview_merge_apply_with_megafile_policy(
        megafile_preview_options(
            &repo_path,
            vec![PathBuf::from("README.md")],
            Vec::new(),
            false,
        ),
        ValidationEvidenceBundle::legacy(vec![validation]),
        MegafileMergePolicy {
            block: true,
            ..policy
        },
    )
    .expect("blocking preview");
    assert_eq!(
        blocked.safety.readiness.status,
        ApplyReadinessStatus::Blocked
    );
    let detail = blocked
        .safety
        .readiness
        .details
        .iter()
        .find(|detail| detail.kind == ApplyBlocker::ExcludedReference)
        .expect("megafile blocker detail");
    assert_eq!(detail.paths, vec![PathBuf::from("README.md")]);
    assert!(detail
        .message
        .as_deref()
        .is_some_and(|message| message.contains("threshold-crossing megafiles")));
    assert_eq!(detail.validation_reports[0].name, "megafile-unit");
    assert!(detail.validation_commands.is_empty());
    assert!(detail
        .next_safe_operation
        .as_deref()
        .is_some_and(|operation| operation.contains("megafile_decomposition assignment")));
}

#[test]
fn decomposition_bypass_requires_finalized_evidence_and_diff_backed_structure() {
    skip_without_containment!();
    let bare_temp = tempfile::tempdir().expect("bare tempdir");
    let (bare_repo, bare_agent) =
        create_semantic_merge_fixture(bare_temp.path(), &[("README.md", "# Test\n")]);
    fs::write(bare_agent.path.join("README.md"), "x\n").expect("shrink bare target");
    fs::create_dir_all(bare_agent.path.join("src")).expect("create bare replacement parent");
    fs::write(bare_agent.path.join("src/readme_part.md"), "part\n")
        .expect("write bare replacement");
    let bare_policy = megafile_test_policy(true, Some("README.md"));
    seed_megafile(&bare_repo, &bare_policy);
    let bare_error = preview_merge_apply_with_megafile_policy(
        megafile_preview_options(
            &bare_repo,
            vec![
                PathBuf::from("README.md"),
                PathBuf::from("src/readme_part.md"),
            ],
            Vec::new(),
            false,
        ),
        ValidationEvidenceBundle::default(),
        bare_policy,
    )
    .expect_err("bare decomposition target must not self-authorize");
    assert!(format!("{bare_error:#}").contains("requires a finalized supervise run id"));

    let grown_temp = tempfile::tempdir().expect("grown tempdir");
    let (grown_repo, grown_agent) =
        create_semantic_merge_fixture(grown_temp.path(), &[("README.md", "# Test\n")]);
    fs::write(
        grown_agent.path.join("README.md"),
        "# Candidate target grew\n",
    )
    .expect("grow target");
    fs::write(grown_agent.path.join("unrelated.txt"), "unrelated\n")
        .expect("write unrelated claimed file");
    let grown_run = RunId::new("grown-target-evidence").expect("grown run id");
    crate::supervise::write_test_finalized_megafile_decomposition_evidence(
        &grown_repo,
        grown_run.clone(),
        "agent-a",
        "worker-a",
        PathBuf::from("README.md"),
        vec![PathBuf::from("unrelated.txt")],
    )
    .expect("write grown evidence");
    let mut grown_policy = megafile_test_policy(true, Some("README.md"));
    grown_policy.decomposition_run_id = Some(grown_run);
    seed_megafile(&grown_repo, &grown_policy);
    let grown_error = preview_merge_apply_with_megafile_policy(
        megafile_preview_options(
            &grown_repo,
            vec![PathBuf::from("README.md"), PathBuf::from("unrelated.txt")],
            Vec::new(),
            false,
        ),
        ValidationEvidenceBundle::default(),
        grown_policy,
    )
    .expect_err("grown target plus unrelated file must not qualify");
    assert!(format!("{grown_error:#}").contains("did not shrink"));

    let existing_temp = tempfile::tempdir().expect("existing replacement tempdir");
    let (existing_repo, existing_agent) = create_semantic_merge_fixture(
        existing_temp.path(),
        &[
            ("README.md", "# Test target contents\n"),
            ("existing.md", "old\n"),
        ],
    );
    fs::write(existing_agent.path.join("README.md"), "x\n").expect("shrink target");
    fs::write(existing_agent.path.join("existing.md"), "modified\n")
        .expect("modify existing pseudo replacement");
    let existing_run = RunId::new("existing-replacement-evidence").expect("existing run id");
    crate::supervise::write_test_finalized_megafile_decomposition_evidence(
        &existing_repo,
        existing_run.clone(),
        "agent-a",
        "worker-a",
        PathBuf::from("README.md"),
        vec![PathBuf::from("existing.md")],
    )
    .expect("write existing replacement evidence");
    let mut existing_policy = megafile_test_policy(true, Some("README.md"));
    existing_policy.decomposition_run_id = Some(existing_run);
    seed_megafile(&existing_repo, &existing_policy);
    let existing_error = preview_merge_apply_with_megafile_policy(
        megafile_preview_options(
            &existing_repo,
            vec![PathBuf::from("README.md"), PathBuf::from("existing.md")],
            Vec::new(),
            false,
        ),
        ValidationEvidenceBundle::default(),
        existing_policy,
    )
    .expect_err("modified existing file must not qualify as a replacement");
    assert!(format!("{existing_error:#}").contains("is not newly added"));

    let empty_temp = tempfile::tempdir().expect("empty replacement tempdir");
    let (empty_repo, empty_agent) = create_semantic_merge_fixture(
        empty_temp.path(),
        &[("README.md", "# Test target contents\n")],
    );
    fs::write(empty_agent.path.join("README.md"), "x\n").expect("shrink empty-case target");
    fs::write(empty_agent.path.join("empty.md"), "").expect("write empty replacement");
    let empty_run = RunId::new("empty-replacement-evidence").expect("empty run id");
    crate::supervise::write_test_finalized_megafile_decomposition_evidence(
        &empty_repo,
        empty_run.clone(),
        "agent-a",
        "worker-a",
        PathBuf::from("README.md"),
        vec![PathBuf::from("empty.md")],
    )
    .expect("write empty replacement evidence");
    let mut empty_policy = megafile_test_policy(true, Some("README.md"));
    empty_policy.decomposition_run_id = Some(empty_run);
    seed_megafile(&empty_repo, &empty_policy);
    let empty_error = preview_merge_apply_with_megafile_policy(
        megafile_preview_options(
            &empty_repo,
            vec![PathBuf::from("README.md"), PathBuf::from("empty.md")],
            Vec::new(),
            false,
        ),
        ValidationEvidenceBundle::default(),
        empty_policy,
    )
    .expect_err("empty replacement must not qualify");
    assert!(format!("{empty_error:#}").contains("is empty"));
}

#[test]
fn decomposition_completion_is_persisted_only_after_successful_merge() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, agent) =
        create_semantic_merge_fixture(temp.path(), &[("README.md", "# Test\n")]);
    fs::write(agent.path.join("README.md"), "x\n").expect("shrink target");
    fs::create_dir_all(agent.path.join("src")).expect("create replacement parent");
    fs::write(agent.path.join("src/readme_part.md"), "extracted\n").expect("write replacement");
    let run_id = RunId::new("accepted-decomposition").expect("run id");
    crate::supervise::write_test_finalized_megafile_decomposition_evidence(
        &repo_path,
        run_id.clone(),
        "agent-a",
        "worker-a",
        PathBuf::from("README.md"),
        vec![PathBuf::from("src/readme_part.md")],
    )
    .expect("write finalized decomposition evidence");
    let mut policy = megafile_test_policy(true, Some("README.md"));
    policy.decomposition_run_id = Some(run_id);
    seed_megafile(&repo_path, &policy);
    let claims = vec![
        PathBuf::from("README.md"),
        PathBuf::from("src/readme_part.md"),
    ];

    let blocked = merge_apply_report_with_megafile_policy(
        MergeApplyOptions {
            preview: megafile_preview_options(&repo_path, claims.clone(), Vec::new(), true),
            candidate_validation_commands: Vec::new(),
            reviewed_watermark: None,
        },
        ValidationEvidenceBundle::default(),
        policy.clone(),
    )
    .expect("validation-blocked decomposition");
    assert_eq!(blocked.status, MergeApplyReportStatus::Blocked);
    assert!(blocked.accepted_decomposition.is_none());
    assert!(
        !MegafileStore::open_with_thresholds(&repo_path, policy.thresholds.clone())
            .expect("reopen store")
            .report()
            .expect("report before merge")
            .records
            .iter()
            .any(|record| matches!(
                record.kind,
                MegafileRecordKind::AcceptedDecomposition { .. }
            ))
    );

    let applied = merge_apply_report_with_megafile_policy(
        MergeApplyOptions {
            preview: megafile_preview_options(&repo_path, claims, Vec::new(), false),
            candidate_validation_commands: Vec::new(),
            reviewed_watermark: None,
        },
        ValidationEvidenceBundle::default(),
        policy.clone(),
    )
    .expect("apply typed decomposition");
    assert_eq!(applied.status, MergeApplyReportStatus::Applied);
    assert_eq!(
        applied
            .accepted_decomposition
            .as_ref()
            .map(|assessment| assessment.accepted_decompositions),
        Some(1)
    );
    let records = MegafileStore::open_with_thresholds(&repo_path, policy.thresholds)
        .expect("reopen store after merge")
        .report()
        .expect("report after merge")
        .records;
    let accepted = records
        .iter()
        .filter_map(|record| match &record.kind {
            MegafileRecordKind::AcceptedDecomposition { replacement_paths } => {
                Some(replacement_paths)
            }
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(accepted, vec![&vec![PathBuf::from("src/readme_part.md")]]);
}

#[test]
fn decomposition_rejects_same_path_content_substitution_after_finalized_review() {
    skip_without_containment!();
    for changed_file in ["target", "replacement"] {
        let temp = tempfile::tempdir().expect("tempdir");
        let (repo_path, agent) =
            create_semantic_merge_fixture(temp.path(), &[("README.md", "# Test\n")]);
        fs::write(agent.path.join("README.md"), "x\n").expect("shrink target");
        fs::create_dir_all(agent.path.join("src")).expect("create replacement parent");
        fs::write(agent.path.join("src/readme_part.md"), "reviewed\n")
            .expect("write reviewed replacement");
        let run_id = RunId::new(format!("content-substitution-{changed_file}")).expect("run id");
        crate::supervise::write_test_finalized_megafile_decomposition_evidence(
            &repo_path,
            run_id.clone(),
            "agent-a",
            "worker-a",
            PathBuf::from("README.md"),
            vec![PathBuf::from("src/readme_part.md")],
        )
        .expect("write content-bound finalized evidence");

        match changed_file {
            "target" => {
                fs::write(agent.path.join("README.md"), "y\n").expect("substitute target bytes");
            }
            "replacement" => {
                fs::write(agent.path.join("src/readme_part.md"), "substituted\n")
                    .expect("substitute replacement bytes");
            }
            _ => unreachable!(),
        }

        let mut policy = megafile_test_policy(true, Some("README.md"));
        policy.decomposition_run_id = Some(run_id);
        seed_megafile(&repo_path, &policy);
        let claims = vec![
            PathBuf::from("README.md"),
            PathBuf::from("src/readme_part.md"),
        ];
        let error = merge_apply_report_with_megafile_policy(
            MergeApplyOptions {
                preview: megafile_preview_options(&repo_path, claims, Vec::new(), false),
                candidate_validation_commands: Vec::new(),
                reviewed_watermark: None,
            },
            ValidationEvidenceBundle::default(),
            policy.clone(),
        )
        .expect_err("post-review same-path content substitution must be rejected");
        assert!(
                format!("{error:#}").contains(
                    "current decomposition candidate content binding does not match the exact supervisor-inspected candidate"
                ),
                "unexpected {changed_file} substitution error: {error:#}"
            );
        assert!(
            !MegafileStore::open_with_thresholds(&repo_path, policy.thresholds)
                .expect("reopen store after rejected substitution")
                .report()
                .expect("report after rejected substitution")
                .records
                .iter()
                .any(|record| matches!(
                    record.kind,
                    MegafileRecordKind::AcceptedDecomposition { .. }
                )),
            "{changed_file} substitution recorded decomposition completion"
        );
    }
}

#[test]
fn collision_decision_is_persisted_without_weakening_merge_blockers() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, agent) =
        create_semantic_merge_fixture(temp.path(), &[("README.md", "# Test\n")]);
    fs::write(agent.path.join("README.md"), "# Candidate\n").expect("edit candidate");
    fs::write(repo_path.join("README.md"), "# Primary\n").expect("edit primary");
    let policy = megafile_test_policy(false, None);

    let report = merge_apply_report_with_megafile_policy(
        MergeApplyOptions {
            preview: megafile_preview_options(
                &repo_path,
                vec![PathBuf::from("README.md")],
                Vec::new(),
                false,
            ),
            candidate_validation_commands: Vec::new(),
            reviewed_watermark: None,
        },
        ValidationEvidenceBundle::default(),
        policy.clone(),
    )
    .expect("blocked collision report");
    assert_eq!(report.status, MergeApplyReportStatus::Blocked);
    assert_eq!(
        report.recorded_collision_paths,
        vec![PathBuf::from("README.md")]
    );
    assert!(report
        .preview
        .safety
        .readiness
        .blockers
        .contains(&ApplyBlocker::DirtyPrimary));
    let assessment = MegafileStore::open_with_thresholds(&repo_path, policy.thresholds)
        .expect("open collision store")
        .assess_path("README.md")
        .expect("assess collision path")
        .expect("collision assessment");
    assert_eq!(assessment.collisions_in_window, 1);
}

#[test]
fn authenticated_megafile_failure_refuses_merge_before_primary_mutation() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, agent) =
        create_semantic_merge_fixture(temp.path(), &[("README.md", "# Test\n")]);
    fs::write(agent.path.join("README.md"), "# Candidate\n").expect("edit candidate");
    let policy = megafile_test_policy(false, None);
    seed_megafile(&repo_path, &policy);
    let snapshot = newest_numeric_state_json(
        &repo_path.join(".git/maco/state/authenticated-megafile-history-v1"),
    )
    .expect("authenticated megafile snapshot");
    fs::write(snapshot, b"{\"tampered\":true}\n").expect("tamper authenticated snapshot");

    let error = merge_apply_report_with_megafile_policy(
        MergeApplyOptions {
            preview: megafile_preview_options(
                &repo_path,
                vec![PathBuf::from("README.md")],
                Vec::new(),
                false,
            ),
            candidate_validation_commands: Vec::new(),
            reviewed_watermark: None,
        },
        ValidationEvidenceBundle::default(),
        policy,
    )
    .expect_err("tampered telemetry must refuse merge");
    assert!(format!("{error:#}").contains("authenticated megafile telemetry"));
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md")).expect("read primary"),
        "# Test\n"
    );
}

#[test]
fn semantic_conflicts_report_same_function_and_dependent_files() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, agent) = create_semantic_merge_fixture(
        temp.path(),
        &[
            ("src/lib.rs", "pub mod consumer;\npub mod shared;\n"),
            ("src/shared.rs", "pub fn compute() -> i32 {\n    1\n}\n"),
            (
                "src/consumer.rs",
                "use crate::shared::compute;\n\npub fn consume() -> i32 { compute() }\n",
            ),
        ],
    );
    fs::write(
        agent.path.join("src/shared.rs"),
        "pub fn compute() -> i32 {\n    2\n}\n",
    )
    .expect("edit candidate function");
    fs::write(
        repo_path.join("src/shared.rs"),
        "pub fn compute() -> i32 {\n    3\n}\n",
    )
    .expect("edit primary function");
    let primary = crate::git_repository::open(&repo_path).expect("open primary");
    commit_all_for_semantic_test(&primary, "change primary function")
        .expect("commit primary function");

    let preview = preview_merge_apply(semantic_preview_options(&repo_path, "src/shared.rs"))
        .expect("preview semantic conflict");
    let semantic = &preview.safety.semantic_conflicts;
    assert!(semantic.advisory);
    assert_eq!(
        semantic.status,
        SemanticConflictClassificationStatus::Classified
    );
    assert!(!semantic.degraded);
    assert_eq!(semantic.risk, SemanticConflictRisk::Medium);
    assert_eq!(
        semantic.conflict_paths,
        vec![PathBuf::from("src/shared.rs")]
    );
    let overlap = semantic.overlaps.first().expect("semantic overlap");
    assert_eq!(overlap.kind, SemanticConflictOverlapKind::SymbolLevel);
    assert!(overlap
        .common_symbols
        .iter()
        .any(|symbol| symbol.name == "compute"));
    assert!(overlap
        .impacted_files
        .contains(&PathBuf::from("src/consumer.rs")));
    assert_eq!(
        preview.safety.readiness.status,
        ApplyReadinessStatus::Blocked
    );
    assert!(preview
        .safety
        .readiness
        .blockers
        .contains(&ApplyBlocker::ApplyCheckFailed));
    let preview_json = serde_json::to_value(&preview).expect("serialize semantic preview");
    assert_eq!(
        preview_json["safety"]["semantic_conflicts"]["overlaps"][0]["kind"],
        "symbol_level"
    );

    let report = merge_apply_report(MergeApplyOptions {
        preview: semantic_preview_options(&repo_path, "src/shared.rs"),
        candidate_validation_commands: Vec::new(),
        reviewed_watermark: None,
    })
    .expect("build blocked apply report");
    assert_eq!(report.status, MergeApplyReportStatus::Blocked);
    assert_eq!(
        report.preview.safety.semantic_conflicts.overlaps[0].kind,
        SemanticConflictOverlapKind::SymbolLevel
    );
    let report_json = serde_json::to_value(&report).expect("serialize semantic apply report");
    assert!(
        report_json.get("lifecycle").is_none(),
        "manual merge JSON must remain unchanged when lifecycle automation is disabled"
    );
    assert_eq!(
        report_json["preview"]["safety"]["semantic_conflicts"]["advisory"],
        true
    );
}

#[test]
fn semantic_conflicts_classify_import_only_as_low_risk() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, agent) = create_semantic_merge_fixture(
        temp.path(),
        &[
            (
                "src/lib.rs",
                "use crate::alpha::item;\n\npub mod alpha;\npub mod beta;\n\npub fn call() {}\n",
            ),
            ("src/alpha.rs", "pub fn item() {}\npub fn renamed() {}\n"),
            ("src/beta.rs", "pub fn item() {}\n"),
        ],
    );
    fs::write(
        agent.path.join("src/lib.rs"),
        "use crate::beta::item;\n\npub mod alpha;\npub mod beta;\n\npub fn call() {}\n",
    )
    .expect("edit candidate import");
    fs::write(
        repo_path.join("src/lib.rs"),
        "use crate::alpha::renamed;\n\npub mod alpha;\npub mod beta;\n\npub fn call() {}\n",
    )
    .expect("edit primary import");
    let primary = crate::git_repository::open(&repo_path).expect("open primary");
    commit_all_for_semantic_test(&primary, "change primary import").expect("commit primary import");

    let preview = preview_merge_apply(semantic_preview_options(&repo_path, "src/lib.rs"))
        .expect("preview import conflict");
    let semantic = &preview.safety.semantic_conflicts;
    assert_eq!(
        semantic.status,
        SemanticConflictClassificationStatus::Classified
    );
    assert!(!semantic.degraded);
    assert_eq!(semantic.risk, SemanticConflictRisk::Low);
    let overlap = semantic.overlaps.first().expect("import overlap");
    assert_eq!(overlap.kind, SemanticConflictOverlapKind::ImportOnly);
    assert_eq!(overlap.risk, SemanticConflictRisk::Low);
    assert!(overlap.primary.import_only);
    assert!(overlap.candidate.import_only);
    assert!(!overlap.primary.touched_imports.is_empty());
    assert!(!overlap.candidate.touched_imports.is_empty());
}

#[test]
fn semantic_conflicts_report_signature_and_impl_overlap() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, agent) = create_semantic_merge_fixture(
            temp.path(),
            &[(
                "src/lib.rs",
                "pub struct Worker;\n\nimpl Worker {\n    pub fn run(&self, value: i32) -> i32 { value }\n}\n",
            )],
        );
    fs::write(
            agent.path.join("src/lib.rs"),
            "pub struct Worker;\n\nimpl Worker {\n    pub fn run(&self, value: i64) -> i32 { value as i32 }\n}\n",
        )
        .expect("edit candidate signature");
    fs::write(
            repo_path.join("src/lib.rs"),
            "pub struct Worker;\n\nimpl Worker {\n    pub fn run(&self, value: i32) -> i64 { value as i64 }\n}\n",
        )
        .expect("edit primary signature");
    let primary = crate::git_repository::open(&repo_path).expect("open primary");
    commit_all_for_semantic_test(&primary, "change primary signature")
        .expect("commit primary signature");

    let preview = preview_merge_apply(semantic_preview_options(&repo_path, "src/lib.rs"))
        .expect("preview signature conflict");
    let overlap = preview
        .safety
        .semantic_conflicts
        .overlaps
        .first()
        .expect("signature overlap");
    assert_eq!(overlap.kind, SemanticConflictOverlapKind::SignatureLevel);
    assert_eq!(overlap.risk, SemanticConflictRisk::High);
    assert!(overlap
        .common_symbols
        .iter()
        .any(|symbol| symbol.name == "run"));
    assert!(overlap
        .common_impls
        .iter()
        .any(|symbol| symbol.impl_target.as_deref() == Some("Worker")));
    assert!(overlap
        .common_modules
        .iter()
        .any(|module| module == "crate"));
}

#[test]
fn semantic_conflicts_mark_unresolved_paths_as_degraded() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, agent) = create_semantic_merge_fixture(
        temp.path(),
        &[
            ("README.md", "# Base\n"),
            ("src/lib.rs", "pub fn ok() {}\n"),
        ],
    );
    fs::write(agent.path.join("README.md"), "# Candidate\n").expect("edit candidate readme");
    fs::write(repo_path.join("README.md"), "# Primary\n").expect("edit primary readme");
    let primary = crate::git_repository::open(&repo_path).expect("open primary");
    commit_all_for_semantic_test(&primary, "change primary readme").expect("commit primary readme");

    let preview = preview_merge_apply(semantic_preview_options(&repo_path, "README.md"))
        .expect("preview unresolved conflict");
    let semantic = &preview.safety.semantic_conflicts;
    assert_eq!(
        semantic.status,
        SemanticConflictClassificationStatus::Degraded
    );
    assert!(semantic.degraded);
    assert_eq!(semantic.risk, SemanticConflictRisk::Unknown);
    assert_eq!(semantic.confidence, SemanticConflictConfidence::None);
    assert_eq!(
        semantic.overlaps[0].kind,
        SemanticConflictOverlapKind::Unresolved
    );
    assert!(!semantic.overlaps[0].notes.is_empty());
}

#[test]
fn candidate_collection_holds_read_lease_until_snapshot_finishes() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, agent_b) = create_managed_merge_fixture(temp.path());
    fs::write(agent_a.path.join("README.md"), "# Agent change\n").expect("edit agent worktree");
    let (ready_tx, ready_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let collector_repo = repo_path.clone();
    let collector = std::thread::spawn(move || {
        collect_agent_result_with_evidence_after_lease(
            MergeCollectOptions {
                repo: collector_repo,
                agent_id: "agent-a".to_string(),
                claimed_paths: vec![PathBuf::from("README.md")],
                include_full_diff: false,
                diff_summary_char_limit: DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
                validations: Vec::new(),
            },
            ValidationEvidenceBundle::default(),
            || {
                ready_tx.send(()).expect("publish acquired read lease");
                release_rx.recv().expect("release collector");
            },
        )
    });

    ready_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("collector acquired read lease");
    let writer_error = manager
        .acquire_write_execution_lease("agent-a")
        .expect_err("collector read lease must exclude a writer");
    assert!(writer_error.to_string().contains("exclusive write lease"));
    let removal_error = manager
        .remove("agent-a", true, false)
        .expect_err("collector read lease must exclude removal");
    assert!(removal_error
        .to_string()
        .contains("active cooperative execution lease"));

    let unrelated = manager
        .acquire_write_execution_lease("agent-b")
        .expect("unrelated worktree writer remains available");
    assert_eq!(unrelated.path(), agent_b.path);
    drop(unrelated);

    release_tx.send(()).expect("release collector");
    let candidate = collector
        .join()
        .expect("join collector")
        .expect("collect candidate");
    assert_eq!(candidate.changed_paths, vec![PathBuf::from("README.md")]);
    let released = manager
        .acquire_write_execution_lease("agent-a")
        .expect("collector releases read lease after snapshot");
    drop(released);
    let removed = manager
        .remove("agent-a", true, false)
        .expect("collector releases removal authority after snapshot");
    assert!(!removed.path.exists());
}

#[test]
fn required_process_output_rejects_unverified_side_effect_evidence() {
    let output = ProcessOutput {
        status: None,
        duration: Duration::ZERO,
        timed_out: false,
        process_tree: ContainmentEvidence::VerifiedEmpty(
            crate::process_runner::ContainmentBackend::DirectChild,
        ),
        side_effects: crate::process_runner::SideEffectConfinementEvidence::Unverified(
            crate::process_runner::SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        ),
        stdout: crate::process_runner::CapturedBytes::default(),
        stderr: crate::process_runner::CapturedBytes::default(),
        process_error: None,
        stdin_error: None,
    };

    let error = require_verified_process_output(
        "test command",
        &output,
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
    )
    .unwrap_err();

    assert!(error.to_string().contains("without exact verified"));
}

#[test]
fn required_network_output_rejects_even_verified_wrong_profile() {
    let output = ProcessOutput {
        status: None,
        duration: Duration::ZERO,
        timed_out: false,
        process_tree: ContainmentEvidence::VerifiedEmpty(
            crate::process_runner::ContainmentBackend::DirectChild,
        ),
        side_effects: crate::process_runner::SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        ),
        stdout: crate::process_runner::CapturedBytes::default(),
        stderr: crate::process_runner::CapturedBytes::default(),
        process_error: None,
        stdin_error: None,
    };
    assert!(require_verified_process_output(
        "network test command",
        &output,
        SideEffectConfinementProfileKind::TrustedFixedNetwork,
    )
    .is_err());
}

#[test]
fn local_git_timeout_override_reaches_candidate_snapshot_diff_deadline() {
    let local_git = MergeLocalGitOptions::from_seconds(900).expect("parse raised budget");
    let base = Oid::from_str("1111111111111111111111111111111111111111").expect("base oid");
    let snapshot = Oid::from_str("2222222222222222222222222222222222222222").expect("snapshot oid");

    let diff = collect_snapshot_diff_with_runner(
        base,
        snapshot,
        local_git,
        |operation, stdin, label, effective_timeout, deadline_knobs| {
            assert_eq!(effective_timeout, Duration::from_secs(900));
            assert_eq!(
                deadline_knobs,
                Some((
                    LOCAL_GIT_PROCESS_TIMEOUT_FLAG,
                    LOCAL_GIT_PROCESS_TIMEOUT_ENV,
                ))
            );
            assert_eq!(label, "collect candidate snapshot diff");
            assert_eq!(operation.first(), Some(&"diff"));
            assert!(matches!(stdin, StdinMode::Null));
            Ok(RequiredCommandOutput {
                success: true,
                stdout: b"raised-budget-diff".to_vec(),
                stderr: Vec::new(),
            })
        },
    )
    .expect("collect snapshot diff");

    assert_eq!(diff, b"raised-budget-diff");
}

#[test]
fn local_git_timeout_reaches_apply_validation_recapture_boundary() {
    let local_git = MergeLocalGitOptions::from_seconds(900).expect("parse raised budget");
    let mut captures = 0;

    let captured = capture_matching_candidate_validation_snapshot(local_git, |effective| {
        captures += 1;
        assert_eq!(effective, local_git);
        Ok(Some(b"stable-validation-snapshot".to_vec()))
    })
    .expect("capture matching validation snapshots");

    assert_eq!(captures, 2);
    assert_eq!(captured, b"stable-validation-snapshot");
}

#[test]
fn local_git_timeout_reaches_megafile_recapture_boundary() {
    let local_git = MergeLocalGitOptions::from_seconds(900).expect("parse raised budget");
    let mut captures = 0;

    let captured = capture_matching_decomposition_snapshot(local_git, |effective| {
        captures += 1;
        assert_eq!(effective, local_git);
        Ok(Some(b"stable-decomposition-snapshot".to_vec()))
    })
    .expect("capture matching decomposition snapshots");

    assert_eq!(captures, 2);
    assert_eq!(captured, b"stable-decomposition-snapshot");
}

#[test]
fn default_only_candidate_snapshot_diff_omits_knob_hint() {
    let base = Oid::from_str("1111111111111111111111111111111111111111").expect("base oid");
    let snapshot = Oid::from_str("2222222222222222222222222222222222222222").expect("snapshot oid");

    let diff = collect_snapshot_diff_with_runner(
        base,
        snapshot,
        MergeLocalGitOptions::default(),
        |_, _, _, effective_timeout, deadline_knobs| {
            assert_eq!(effective_timeout, Duration::from_secs(120));
            assert_eq!(deadline_knobs, None);
            Ok(RequiredCommandOutput {
                success: true,
                stdout: b"default-budget-diff".to_vec(),
                stderr: Vec::new(),
            })
        },
    )
    .expect("collect default snapshot diff");

    assert_eq!(diff, b"default-budget-diff");
}

#[test]
fn local_git_timeout_default_and_invalid_overrides_are_typed() {
    assert_eq!(
        parse_local_git_process_timeout(None).expect("default timeout"),
        Duration::from_secs(120)
    );
    assert_eq!(
        MergeLocalGitOptions::default().candidate_snapshot_diff_timeout,
        Duration::from_secs(120)
    );
    assert_eq!(
        MergeLocalGitOptions::default().candidate_snapshot_diff_deadline_knobs,
        None
    );
    assert_eq!(
        parse_local_git_process_timeout(Some("86400")).expect("maximum timeout"),
        Duration::from_secs(86_400)
    );
    assert!(matches!(
        parse_local_git_process_timeout(Some("0")),
        Err(LocalGitProcessTimeoutError::OutOfRange { seconds: 0, .. })
    ));
    assert!(matches!(
        parse_local_git_process_timeout(Some("86401")),
        Err(LocalGitProcessTimeoutError::OutOfRange {
            seconds: 86401,
            max_seconds: 86400,
        })
    ));
}

#[test]
fn local_git_deadline_diagnostic_names_effective_budget_and_knob() {
    let output = ProcessOutput {
        status: None,
        duration: Duration::from_secs(900),
        timed_out: true,
        process_tree: ContainmentEvidence::VerifiedEmpty(
            crate::process_runner::ContainmentBackend::DirectChild,
        ),
        side_effects: SideEffectConfinementEvidence::Verified(
            SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        ),
        stdout: crate::process_runner::CapturedBytes::default(),
        stderr: crate::process_runner::CapturedBytes::default(),
        process_error: None,
        stdin_error: None,
    };

    let error = require_verified_process_output_with_deadline_hint(
        "collect candidate snapshot diff",
        &output,
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        Some((
            Duration::from_secs(900),
            LOCAL_GIT_PROCESS_TIMEOUT_FLAG,
            LOCAL_GIT_PROCESS_TIMEOUT_ENV,
        )),
    )
    .expect_err("deadline must fail");
    let message = error.to_string();
    assert!(message.contains("effective 900-second"));
    assert!(message.contains(LOCAL_GIT_PROCESS_TIMEOUT_FLAG));
    assert!(message.contains(LOCAL_GIT_PROCESS_TIMEOUT_ENV));

    let generic_error = require_verified_process_output_with_deadline_hint(
        "other local Git operation",
        &output,
        SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        None,
    )
    .expect_err("generic deadline must fail");
    let generic_message = generic_error.to_string();
    assert_eq!(
        generic_message,
        "other local Git operation exceeded its total operation deadline"
    );
    assert!(!generic_message.contains(LOCAL_GIT_PROCESS_TIMEOUT_FLAG));
    assert!(!generic_message.contains(LOCAL_GIT_PROCESS_TIMEOUT_ENV));
}

#[test]
fn trusted_network_environment_and_stdin_fail_closed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let global_config = temp.path().join("global-config");
    write_private_file(&global_config, b"").expect("global config");
    let mut environment = minimal_network_environment().expect("minimal environment");
    environment.insert(
        "GIT_CONFIG_GLOBAL".to_string(),
        global_config.to_string_lossy().into_owned(),
    );
    validate_fixed_network_environment(&environment, temp.path())
        .expect("exact network environment");
    environment.insert(
        "HTTPS_PROXY".to_string(),
        "https://proxy.invalid".to_string(),
    );
    assert!(validate_fixed_network_environment(&environment, temp.path()).is_err());
    environment.remove("HTTPS_PROXY");

    let git = resolve_trusted_executable("git").expect("trusted git");
    assert!(validate_fixed_network_command(
        "network stdin test",
        &git,
        &[OsString::from("ls-remote")],
        temp.path(),
        &environment,
        &StdinMode::Inherit,
        Duration::from_secs(1),
        1024,
        0,
    )
    .is_err());
}

fn private_runtime_test_root(temp: &tempfile::TempDir) -> PathBuf {
    let root = temp.path().join("runtime");
    create_private_directory(&root).expect("create private runtime test root");
    root
}

fn rewrite_private_runtime_owner(path: &Path, owner: &PrivateRuntimeOwner) {
    let mut bytes = serde_json::to_vec(owner).expect("serialize private runtime owner");
    bytes.push(b'\n');
    let owner_path = owner.kind.owner_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .truncate(true)
        .open(&owner_path)
        .expect("open private runtime owner for rewrite");
    file.write_all(&bytes)
        .expect("rewrite private runtime owner");
    file.sync_all().expect("persist rewritten runtime owner");
}

fn private_runtime_owner_for_test(kind: PrivateRuntimeKind, nonce: &str) -> PrivateRuntimeOwner {
    PrivateRuntimeOwner {
        version: PRIVATE_RUNTIME_OWNER_VERSION,
        pid: std::process::id(),
        process_start: private_runtime_current_process_start_identity()
            .expect("current process identity"),
        boot_id: private_runtime_boot_id().expect("current boot identity"),
        created_unix_seconds: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("current time")
            .as_secs(),
        kind,
        nonce: nonce.to_string(),
    }
}

fn create_incomplete_private_runtime(
    root: &Path,
    kind: PrivateRuntimeKind,
    nonce: &str,
    create_validation_git: bool,
    write_owner_temp: bool,
    publish_owner: bool,
) -> PathBuf {
    let owner = private_runtime_owner_for_test(kind, nonce);
    let path = root.join(format!("{}{}-{}", kind.prefix(), owner.pid, owner.nonce));
    reserve_owner_only_directory(&path).expect("reserve incomplete private runtime");
    let owner_path = kind.owner_path(&path);
    let parent = owner_path.parent().expect("owner parent");
    if create_validation_git && kind == PrivateRuntimeKind::CandidateValidation {
        create_private_directory(parent).expect("create incomplete validation gitdir");
    }
    if write_owner_temp || publish_owner {
        if kind == PrivateRuntimeKind::CandidateValidation && !parent.exists() {
            create_private_directory(parent).expect("create owner parent");
        }
        let mut bytes = serde_json::to_vec(&owner).expect("serialize owner");
        bytes.push(b'\n');
        let temporary = parent.join(format!(".{PRIVATE_RUNTIME_OWNER_FILE}.{nonce}.tmp"));
        write_private_file(&temporary, &bytes).expect("write owner temp");
        if publish_owner {
            fs::rename(&temporary, &owner_path).expect("publish owner");
        }
    }
    path
}

#[test]
fn successful_status_cannot_bypass_nonverified_containment_seam() {
    let error = require_verified_containment(
        "synthetic successful command",
        ContainmentEvidence::TrustedBestEffort(
            crate::process_runner::ContainmentBackend::UnixProcessGroup,
        ),
    )
    .expect_err("non-verified containment must be rejected");
    assert!(error.to_string().contains("without verified-empty"));
}

#[test]
fn candidate_validation_total_deadline_returns_failed_report() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let started = std::time::Instant::now();
    let report = run_candidate_validation_command_with_timeout(
        temp.path(),
        &temp.path().join("validation-environment"),
        &CandidateValidationCommand {
            command: "sleep 2".to_string(),
        },
        0,
        &[PathBuf::from("README.md")],
        Duration::from_millis(100),
    );
    assert_eq!(report.status, ValidationStatus::Failed);
    assert_eq!(report.paths, vec![PathBuf::from("README.md")]);
    assert!(started.elapsed() < Duration::from_secs(10));
    assert!(report
        .message
        .as_deref()
        .is_some_and(|message| message.contains("deadline") || message.contains("timed out")));
}

#[test]
fn candidate_validation_clears_shell_startup_and_private_network_environment() {
    skip_without_containment!();
    let _environment_guard = VALIDATION_ENVIRONMENT_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let temp = tempfile::tempdir().expect("tempdir");
    let bash_startup = temp.path().join("bash-startup");
    let sh_startup = temp.path().join("sh-startup");
    let marker = temp.path().join("startup-ran");
    fs::write(
        &bash_startup,
        format!("printf injected > '{}'\n", marker.display()),
    )
    .expect("write bash startup");
    fs::write(
        &sh_startup,
        format!("printf injected > '{}'\n", marker.display()),
    )
    .expect("write sh startup");
    let old_bash_env = env::var_os("BASH_ENV");
    let old_env = env::var_os("ENV");
    let old_token = env::var_os("OPENAI_API_KEY");
    // SAFETY: these tests restore the process environment before returning and the values are
    // used only to verify the child allowlist. The test suite does not otherwise rely on them.
    unsafe {
        env::set_var("BASH_ENV", &bash_startup);
        env::set_var("ENV", &sh_startup);
        env::set_var("OPENAI_API_KEY", "validation-secret-value");
    }
    let command = if cfg!(unix) {
        "bash -c 'test -z \"$OPENAI_API_KEY\" && test -z \"$BASH_ENV\" && test -z \"$ENV\"'"
    } else {
        "exit 0"
    };
    let report = run_candidate_validation_command_with_timeout(
        temp.path(),
        &temp.path().join("validation-environment"),
        &CandidateValidationCommand {
            command: command.to_string(),
        },
        0,
        &[],
        Duration::from_secs(10),
    );
    // SAFETY: restore the exact previous process environment values.
    unsafe {
        restore_test_environment("BASH_ENV", old_bash_env);
        restore_test_environment("ENV", old_env);
        restore_test_environment("OPENAI_API_KEY", old_token);
    }
    assert_eq!(report.status, ValidationStatus::Passed, "{report:?}");
    assert!(!marker.exists(), "shell startup injection must not execute");
}

#[test]
fn candidate_validation_redacts_registered_private_output() {
    let _environment_guard = VALIDATION_ENVIRONMENT_TEST_LOCK
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let temp = tempfile::tempdir().expect("tempdir");
    let old_secret = env::var_os("MACO_VALIDATION_TEST_SECRET");
    let old_openai_key = env::var_os("OPENAI_API_KEY");
    let old_aws_key = env::var_os("AWS_ACCESS_KEY_ID");
    // SAFETY: the environment value is scoped to this test and restored below.
    unsafe {
        env::set_var(
            "MACO_VALIDATION_TEST_SECRET",
            "candidate-validation-super-secret",
        );
        env::set_var("OPENAI_API_KEY", "openai-validation-private-key");
        env::set_var("AWS_ACCESS_KEY_ID", "aws-validation-access-key");
    }
    let report = run_candidate_validation_command_with_timeout(
            temp.path(),
            &temp.path().join("validation-environment"),
            &CandidateValidationCommand {
                command: "printf '%s %s %s\\n' candidate-validation-super-secret openai-validation-private-key aws-validation-access-key >&2; exit 1".to_string(),
            },
            0,
            &[PathBuf::from("README.md")],
            Duration::from_secs(10),
        );
    // SAFETY: restore the exact previous process environment value.
    unsafe {
        restore_test_environment("MACO_VALIDATION_TEST_SECRET", old_secret);
        restore_test_environment("OPENAI_API_KEY", old_openai_key);
        restore_test_environment("AWS_ACCESS_KEY_ID", old_aws_key);
    }
    let message = report.message.expect("failed validation message");
    assert_eq!(report.status, ValidationStatus::Failed);
    assert!(!message.contains("candidate-validation-super-secret"));
    assert!(!message.contains("openai-validation-private-key"));
    assert!(!message.contains("aws-validation-access-key"));
    assert!(message.contains("<redacted:validation-private-env>"));
}

#[test]
fn repository_index_digest_rejects_oversized_file_before_reading() {
    let temp = tempfile::tempdir().expect("tempdir");
    let index = temp.path().join("index");
    let file = fs::File::create(&index).expect("create sparse index");
    file.set_len(REPOSITORY_INDEX_MAX_BYTES + 1)
        .expect("size sparse index");

    let error = hash_optional_file(&index).expect_err("oversized index must fail closed");

    assert!(error.to_string().contains("bounded real regular file"));
}

unsafe fn restore_test_environment(key: &str, value: Option<OsString>) {
    match value {
        Some(value) => {
            // SAFETY: caller guarantees serialized restoration of the test process environment.
            unsafe { env::set_var(key, value) }
        }
        None => {
            // SAFETY: caller guarantees serialized restoration of the test process environment.
            unsafe { env::remove_var(key) }
        }
    }
}

#[test]
fn candidate_capture_quota_rejects_oversized_changed_file_before_git_spawn() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = Repository::init(temp.path()).expect("init repo");
    let oversized = temp.path().join("oversized.bin");
    let file = fs::File::create(&oversized).expect("create oversized file");
    file.set_len(VALIDATION_RAW_MAX_SINGLE_FILE_BYTES + 1)
        .expect("size oversized file");

    let error = snapshot_worktree_candidate(&repo, temp.path(), None)
        .expect_err("oversized candidate must fail");

    assert!(error.to_string().contains("single-file limit"));
}

fn passed_validation_evidence_check() -> ValidationEvidenceCheck {
    ValidationEvidenceCheck {
        status: SafetyCheckStatus::Passed,
        binding_status: ValidationBindingStatus::Bound,
        message: None,
        paths: Vec::new(),
    }
}

#[test]
fn classifies_unclaimed_paths_by_repo_relative_claim_coverage() {
    let changed = vec![
        PathBuf::from("README.md"),
        PathBuf::from("src/lib.rs"),
        PathBuf::from("src/nested/mod.rs"),
        PathBuf::from("tests/smoke.rs"),
    ];
    let claims = vec![PathBuf::from("README.md"), PathBuf::from("src")];

    assert_eq!(
        unclaimed_paths(&changed, &claims),
        vec![PathBuf::from("tests/smoke.rs")]
    );
}

#[test]
fn normalizes_and_collapses_claim_paths() {
    let paths = normalize_claim_paths(vec![
        PathBuf::from("src/lib.rs"),
        PathBuf::from("src"),
        PathBuf::from("README.md"),
        PathBuf::from("src/../README.md"),
    ])
    .expect("normalize paths");

    assert_eq!(
        paths,
        vec![PathBuf::from("README.md"), PathBuf::from("src")]
    );
}

#[test]
fn candidate_capture_retries_until_two_complete_snapshots_match() {
    let mut captures = vec![Some(1_u8), Some(2), Some(3), Some(3)].into_iter();

    let captured =
        capture_two_matching(|| Ok(captures.next().flatten())).expect("capture should stabilize");

    assert_eq!(captured, 3);
}

#[test]
fn candidate_capture_fails_closed_after_bounded_instability() {
    let mut captures = vec![Some(1_u8), Some(2), Some(1), Some(2), Some(1), Some(2)].into_iter();

    let error = capture_two_matching(|| Ok(captures.next().flatten()))
        .expect_err("capture should remain unstable");

    assert!(error.to_string().contains("state changed"));
}

#[test]
fn safety_classification_blocks_unforced_failures() {
    let failed = SafetyCheck {
        status: SafetyCheckStatus::Failed,
        message: None,
        paths: vec![PathBuf::from("README.md")],
    };
    let passed = SafetyCheck {
        status: SafetyCheckStatus::Passed,
        message: None,
        paths: Vec::new(),
    };
    let evidence = passed_validation_evidence_check();
    let checks = SafetyChecks {
        primary_state_unchanged: &passed,
        dirty_primary: &failed,
        stale_base: &passed,
        apply_check: &passed,
        unclaimed_edits: &failed,
        validation: &passed,
        validation_evidence: &evidence,
        megafile: &passed,
        validations: &[],
        require_validation: false,
        validation_commands: &[],
        validation_related_paths: &[],
    };

    let readiness = classify_apply_safety(checks, &MergeForceOptions::default());

    assert_eq!(readiness.status, ApplyReadinessStatus::Blocked);
    assert_eq!(
        readiness.blockers,
        vec![ApplyBlocker::DirtyPrimary, ApplyBlocker::UnclaimedEdits]
    );
    assert!(readiness.forced.is_empty());
    assert_eq!(readiness.details.len(), 2);
    assert_eq!(readiness.details[0].kind, ApplyBlocker::DirtyPrimary);
    assert_eq!(
        readiness.details[0].disposition,
        ApplyBlockerDisposition::Blocked
    );
    assert_eq!(readiness.details[0].check_status, SafetyCheckStatus::Failed);
    assert_eq!(readiness.details[0].paths, vec![PathBuf::from("README.md")]);
}

#[test]
fn safety_classification_marks_allowed_risks_as_forced() {
    let failed = SafetyCheck {
        status: SafetyCheckStatus::Failed,
        message: None,
        paths: Vec::new(),
    };
    let passed = SafetyCheck {
        status: SafetyCheckStatus::Passed,
        message: None,
        paths: Vec::new(),
    };
    let evidence = passed_validation_evidence_check();
    let checks = SafetyChecks {
        primary_state_unchanged: &passed,
        dirty_primary: &failed,
        stale_base: &failed,
        apply_check: &passed,
        unclaimed_edits: &passed,
        validation: &passed,
        validation_evidence: &evidence,
        megafile: &passed,
        validations: &[],
        require_validation: false,
        validation_commands: &[],
        validation_related_paths: &[],
    };

    let readiness = classify_apply_safety(
        checks,
        &MergeForceOptions {
            allow_dirty_primary: true,
            allow_stale_base: true,
            ..MergeForceOptions::default()
        },
    );

    assert_eq!(readiness.status, ApplyReadinessStatus::Forced);
    assert!(readiness.blockers.is_empty());
    assert_eq!(
        readiness.forced,
        vec![ApplyBlocker::DirtyPrimary, ApplyBlocker::StaleBase]
    );
    assert_eq!(
        readiness.details[0].disposition,
        ApplyBlockerDisposition::Forced
    );
}

#[test]
fn apply_check_failures_are_not_forceable_by_policy_flags() {
    let failed = SafetyCheck {
        status: SafetyCheckStatus::Failed,
        message: None,
        paths: Vec::new(),
    };
    let passed = SafetyCheck {
        status: SafetyCheckStatus::Passed,
        message: None,
        paths: Vec::new(),
    };
    let evidence = passed_validation_evidence_check();
    let checks = SafetyChecks {
        primary_state_unchanged: &passed,
        dirty_primary: &passed,
        stale_base: &passed,
        apply_check: &failed,
        unclaimed_edits: &passed,
        validation: &passed,
        validation_evidence: &evidence,
        megafile: &passed,
        validations: &[],
        require_validation: false,
        validation_commands: &[],
        validation_related_paths: &[],
    };

    let readiness = classify_apply_safety(
        checks,
        &MergeForceOptions {
            allow_apply_conflicts: true,
            ..MergeForceOptions::default()
        },
    );

    assert_eq!(readiness.status, ApplyReadinessStatus::Blocked);
    assert_eq!(readiness.blockers, vec![ApplyBlocker::ApplyCheckFailed]);
}

#[test]
fn primary_state_drift_is_a_distinct_unforceable_blocker() {
    let failed = SafetyCheck {
        status: SafetyCheckStatus::Failed,
        message: Some(
            "primary repository state changed after the merge safety preview (HEAD)".to_string(),
        ),
        paths: Vec::new(),
    };
    let passed = SafetyCheck {
        status: SafetyCheckStatus::Passed,
        message: None,
        paths: Vec::new(),
    };
    let evidence = passed_validation_evidence_check();
    let checks = SafetyChecks {
        primary_state_unchanged: &failed,
        dirty_primary: &passed,
        stale_base: &passed,
        apply_check: &passed,
        unclaimed_edits: &passed,
        validation: &passed,
        validation_evidence: &evidence,
        megafile: &passed,
        validations: &[],
        require_validation: false,
        validation_commands: &[],
        validation_related_paths: &[],
    };

    let readiness = classify_apply_safety(
        checks,
        &MergeForceOptions {
            allow_dirty_primary: true,
            allow_stale_base: true,
            allow_apply_conflicts: true,
            allow_unclaimed_edits: true,
            ..MergeForceOptions::default()
        },
    );

    assert_eq!(readiness.status, ApplyReadinessStatus::Blocked);
    assert_eq!(readiness.blockers, vec![ApplyBlocker::PrimaryStateChanged]);
    assert!(readiness.forced.is_empty());
    assert_eq!(
        gate_check_source_for_apply_blocker(ApplyBlocker::PrimaryStateChanged),
        GateCheckSource::PrimaryDrift
    );
    assert_eq!(
        blocker_label(ApplyBlocker::PrimaryStateChanged),
        "primary_state_changed"
    );
}

#[test]
fn repo_common_lock_persists_file_and_kernel_unlocks_on_drop() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let lock = RepoCommonLock::acquire(&repo_path, "merge-apply").expect("acquire lock");
    let path = repo_path
        .join(".git/maco/state")
        .join(REPOSITORY_MUTATION_LOCK_FILE);
    let contender = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .expect("open stable lock file");
    assert!(matches!(
        contender.try_lock().expect_err("kernel lock must contend"),
        fs::TryLockError::WouldBlock
    ));

    drop(lock);
    contender.try_lock().expect("kernel lock released on drop");
    contender.unlock().expect("unlock contender");

    assert!(path.exists());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        assert_eq!(
            fs::metadata(&path)
                .expect("lock metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        for directory in [
            repo_path.join(".git/maco"),
            repo_path.join(".git/maco/state"),
        ] {
            assert_eq!(
                fs::metadata(directory)
                    .expect("managed directory metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }
}

#[test]
fn initialized_repository_fingerprint_ignores_ignored_output() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let repo = Repository::init(temp.path()).expect("init repo");
    fs::write(temp.path().join(".gitignore"), "ignored/\n").expect("write ignore");
    fs::write(temp.path().join("tracked.txt"), "tracked\n").expect("write tracked");
    let mut index = repo.index().expect("open index");
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .expect("add files");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let signature = Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    repo.commit(Some("HEAD"), &signature, &signature, "initial", &tree, &[])
        .expect("commit");

    let before = validation_repository_fingerprint_with_local_git_options(
        &repo,
        temp.path(),
        None,
        MergeLocalGitOptions::default(),
        0,
    )
    .expect("baseline fingerprint");
    fs::create_dir(temp.path().join("ignored")).expect("create ignored output");
    fs::write(
        temp.path().join("ignored/build.bin"),
        vec![7_u8; 1024 * 1024],
    )
    .expect("write ignored output");
    let after = validation_repository_fingerprint_with_local_git_options(
        &repo,
        temp.path(),
        None,
        MergeLocalGitOptions::default(),
        0,
    )
    .expect("updated fingerprint");

    assert_eq!(before, after);
}

#[test]
fn initialized_submodule_marker_directory_is_not_recursively_hashed() {
    let temp = tempfile::tempdir().expect("tempdir");
    let marker = temp.path().join(".git");
    fs::create_dir(&marker).expect("create marker directory");
    let large = fs::File::create(marker.join("large-object")).expect("create large object");
    large
        .set_len(VALIDATION_RAW_MAX_SINGLE_FILE_BYTES + 1)
        .expect("size large object");

    let fingerprint =
        validation_submodule_marker_fingerprint(&marker).expect("fingerprint marker identity only");

    assert_eq!(fingerprint.entries.len(), 1);
    assert_eq!(
        fingerprint.entries[0].kind,
        ValidationFilesystemEntryKind::Directory
    );
}

#[test]
fn uninitialized_submodule_raw_fingerprint_fails_with_typed_size_limit() {
    let temp = tempfile::tempdir().expect("tempdir");
    let large = fs::File::create(temp.path().join("large.bin")).expect("create large file");
    large
        .set_len(VALIDATION_RAW_MAX_SINGLE_FILE_BYTES + 1)
        .expect("size large file");

    let error = validation_filesystem_fingerprint(temp.path())
        .expect_err("oversized raw fallback must fail closed");

    assert!(matches!(
        error.downcast_ref::<ValidationFilesystemFingerprintError>(),
        Some(ValidationFilesystemFingerprintError::SingleFileTooLarge { .. })
    ));
}

#[test]
fn candidate_validation_sandbox_is_removed_when_patch_apply_fails() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    fs::create_dir(&repo_path).expect("create repo dir");
    let repo = Repository::init(&repo_path).expect("init repo");
    fs::write(repo_path.join("README.md"), "# Smoke\n").expect("write readme");
    let mut index = repo.index().expect("open index");
    index.add_path(Path::new("README.md")).expect("add readme");
    index.write().expect("write index");
    let tree_id = index.write_tree().expect("write tree");
    let tree = repo.find_tree(tree_id).expect("find tree");
    let signature =
        Signature::now("maco test", "maco-test@example.invalid").expect("create signature");
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "initial commit",
        &tree,
        &[],
    )
    .expect("commit");

    let passed = SafetyCheck {
        status: SafetyCheckStatus::Passed,
        message: None,
        paths: Vec::new(),
    };
    let preview = MergeApplyPreview {
        candidate: MergeCandidate {
            metadata: WorktreeMergeMetadata {
                agent_id: "agent-a".to_string(),
                worktree_path: repo_path.clone(),
                branch: "maco/agent-a".to_string(),
                primary_repo_root: repo_path.clone(),
                primary_head: None,
                agent_head: None,
                merge_base: None,
                base_matches_primary: Some(true),
            },
            claimed_paths: vec![PathBuf::from("README.md")],
            changed_paths: vec![PathBuf::from("README.md")],
            changes: vec![ChangedPath {
                path: PathBuf::from("README.md"),
                kind: ChangeKind::Modified,
            }],
            unclaimed_changed_paths: Vec::new(),
            diff: DiffOutput {
                summary: OutputSummary {
                    text: "invalid patch".to_string(),
                    truncated: false,
                },
                full: Some("this is not a patch\n".to_string()),
            },
            validations: Vec::new(),
            validation_binding: CandidateValidationBinding {
                version: VALIDATION_BINDING_VERSION,
                agent_id: "agent-a".to_string(),
                primary_head: None,
                agent_head: None,
                merge_base: None,
                diff_oid: Oid::hash_object(ObjectType::Blob, b"this is not a patch\n")
                    .expect("hash invalid patch")
                    .to_string(),
            },
            validation_evidence: ValidationEvidenceBundle::default(),
            raw_diff: b"this is not a patch\n".to_vec(),
            snapshot_tree: tree_id,
        },
        safety: MergeApplySafety {
            primary_state_unchanged: passed.clone(),
            dirty_primary: passed.clone(),
            stale_base: passed.clone(),
            apply_check: passed.clone(),
            unclaimed_edits: passed.clone(),
            validation: passed,
            validation_evidence: passed_validation_evidence_check(),
            megafile: SafetyCheck {
                status: SafetyCheckStatus::Passed,
                message: None,
                paths: Vec::new(),
            },
            megafile_warnings: Vec::new(),
            megafile_decomposition_target: None,
            megafile_decomposition_evidence: None,
            megafile_blocking: false,
            validation_required: false,
            candidate_validation_commands: Vec::new(),
            force_options: MergeForceOptions::default(),
            apply_mode: ApplyMode::Direct,
            semantic_conflicts: SemanticConflictClassification::no_conflict(),
            readiness: ApplyReadiness {
                status: ApplyReadinessStatus::Safe,
                blockers: Vec::new(),
                forced: Vec::new(),
                details: Vec::new(),
            },
        },
    };

    let result = CandidateValidationSandbox::create_with_local_git_options(
        &preview,
        MergeLocalGitOptions::default(),
    );

    assert!(result.is_err());
    let output = Command::new("git")
        .arg("-C")
        .arg(&repo_path)
        .args(["worktree", "list", "--porcelain"])
        .output()
        .expect("list worktrees");
    assert!(output.status.success());
    let worktrees = String::from_utf8_lossy(&output.stdout);
    assert!(
        !worktrees.contains("maco-candidate-validation-"),
        "{worktrees}"
    );
}

#[test]
fn truncates_output_by_char_boundary() {
    let summary = summarize_text("aé日b", 3);

    assert_eq!(summary.text, "aé日");
    assert!(summary.truncated);

    let untruncated = summarize_text("abc", 3);
    assert_eq!(untruncated.text, "abc");
    assert!(!untruncated.truncated);
}

#[test]
fn native_executable_magic_accepts_thin_and_fat_macho() {
    for magic in [
        [0xfe, 0xed, 0xfa, 0xce],
        [0xce, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xcf],
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xca, 0xfe, 0xba, 0xbe],
        [0xbe, 0xba, 0xfe, 0xca],
        [0xca, 0xfe, 0xba, 0xbf],
        [0xbf, 0xba, 0xfe, 0xca],
    ] {
        assert!(is_native_executable_magic(magic));
    }
    assert!(!is_native_executable_magic(*b"#!/b"));
}

#[test]
fn network_environment_classifies_command_execution_overrides_as_injection() {
    for key in [
        "GIT_SSH",
        "GIT_SSH_COMMAND",
        "GIT_ASKPASS",
        "SSH_ASKPASS",
        "GIT_PROXY_COMMAND",
        "GIT_CURL_VERBOSE",
    ] {
        assert!(is_git_injection_environment_key(key), "missed {key}");
    }
}

#[cfg(unix)]
#[test]
fn trusted_executable_validation_rejects_user_owned_path_shadow() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let shadow = temp.path().join("git");
    fs::write(&shadow, b"\x7fELFfake").expect("write shadow");
    fs::set_permissions(&shadow, fs::Permissions::from_mode(0o755)).expect("chmod shadow");

    assert!(validate_trusted_unix_executable(&shadow).is_err());
    assert!(resolve_trusted_executable("git").is_ok());
}

#[cfg(unix)]
#[test]
fn trusted_executable_candidates_exclude_direct_nix_store_path_entries() {
    let candidates = trusted_executable_entry_candidates("git");
    assert_eq!(
        candidates,
        [
            PathBuf::from("/run/current-system/sw/bin/git"),
            PathBuf::from("/usr/bin/git"),
            PathBuf::from("/bin/git"),
        ]
    );
    assert!(candidates
        .iter()
        .all(|candidate| !candidate.starts_with("/nix/store")));
}

#[cfg(unix)]
#[test]
fn trusted_runtime_is_owner_only_and_ignores_ambient_temp_paths() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempfile::tempdir().expect("repo tempdir");
    let runtime = trusted_runtime_root(temp.path()).expect("trusted runtime");
    let metadata = fs::symlink_metadata(&runtime).expect("runtime metadata");
    // SAFETY: geteuid has no arguments and returns the effective numeric uid.
    let uid = unsafe { libc::geteuid() };
    assert_eq!(metadata.uid(), uid);
    assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    assert!(!runtime.starts_with(temp.path()));
}

#[cfg(unix)]
#[test]
fn private_runtime_all_kinds_publish_owner_retain_live_and_reuse_lock_inode() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = tempfile::tempdir().expect("tempdir");
    let root = private_runtime_test_root(&temp);
    let mut lock_inode = None;
    for kind in [
        PrivateRuntimeKind::CandidateCapture,
        PrivateRuntimeKind::CandidateValidation,
        PrivateRuntimeKind::PublicationGit,
        PrivateRuntimeKind::GhConfig,
    ] {
        let runtime = PrivateRuntimeDirectory::create_in_root(&root, kind).expect("create runtime");
        let owner_path = kind.owner_path(runtime.path());
        let owner_metadata = fs::symlink_metadata(&owner_path).expect("owner metadata");
        assert_eq!(owner_metadata.permissions().mode() & 0o777, 0o600);
        let (owner, _) =
            read_private_runtime_owner(runtime.path(), kind).expect("read runtime owner");
        assert_eq!(owner.kind, kind);
        assert_eq!(owner.pid, std::process::id());
        if kind == PrivateRuntimeKind::CandidateValidation {
            assert_eq!(
                owner_path.parent(),
                Some(runtime.path().join(".git").as_path())
            );
        } else {
            assert_eq!(owner_path.parent(), Some(runtime.path()));
        }

        let report = scavenge_private_runtime_orphans(&root).expect("scan live runtime");
        assert_eq!(
            report,
            PrivateRuntimeScavengeReport {
                removed: 0,
                retained: 0,
            }
        );
        assert!(runtime.path().exists());
        let path = runtime.path().to_path_buf();
        drop(runtime);
        assert!(!path.exists());

        let lock = fs::symlink_metadata(root.join(PRIVATE_RUNTIME_LOCK_FILE))
            .expect("persistent runtime lock");
        assert_eq!(lock.nlink(), 1);
        match lock_inode {
            Some(inode) => assert_eq!(lock.ino(), inode),
            None => lock_inode = Some(lock.ino()),
        }
    }
}

#[cfg(unix)]
#[test]
fn private_runtime_root_lock_serializes_concurrent_creators() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = private_runtime_test_root(&temp);
    let held = PrivateRuntimeRootLock::acquire(&root).expect("hold runtime lock");
    let (sender, receiver) = std::sync::mpsc::channel();
    let child_root = root.clone();
    let worker = std::thread::spawn(move || {
        let result = PrivateRuntimeDirectory::create_in_root(
            &child_root,
            PrivateRuntimeKind::CandidateCapture,
        )
        .map(|runtime| {
            let path = runtime.path().to_path_buf();
            drop(runtime);
            path
        });
        sender.send(result).expect("send creator result");
    });
    assert!(matches!(
        receiver.recv_timeout(Duration::from_millis(150)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    drop(held);
    let path = receiver
        .recv_timeout(Duration::from_secs(5))
        .expect("creator completed after unlock")
        .expect("creator result");
    worker.join().expect("join creator");
    assert!(!path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn private_runtime_scavenger_reclaims_reused_and_missing_pid_but_retains_live_owner() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = private_runtime_test_root(&temp);

    let live = PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::CandidateCapture)
        .expect("create live runtime");
    let live_path = live.path().to_path_buf();
    let report = scavenge_private_runtime_orphans(&root).expect("scan live owner");
    assert_eq!(report.removed, 0);
    assert!(live_path.exists());

    let reused = PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::PublicationGit)
        .expect("create reused PID fixture");
    let reused_path = reused.path().to_path_buf();
    let mut reused_owner = reused.owner.clone();
    let Some(ProcessStartIdentity::LinuxProcStartTicks(start)) =
        reused_owner.process_start.as_mut()
    else {
        panic!("Linux owner omitted start ticks");
    };
    *start = start.saturating_add(1);
    rewrite_private_runtime_owner(&reused_path, &reused_owner);
    let report = scavenge_private_runtime_orphans(&root).expect("reclaim reused PID owner");
    assert_eq!(report.removed, 1);
    assert!(!reused_path.exists());

    let missing = PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::GhConfig)
        .expect("create missing PID fixture");
    let missing_path = missing.path().to_path_buf();
    let report = scavenge_private_runtime_orphans_with(
        &root,
        private_runtime_boot_id().expect("boot id").as_deref(),
        |_| Ok(None),
    )
    .expect("reclaim missing PID owner");
    assert_eq!(report.removed, 2);
    assert!(!missing_path.exists());
    assert!(!live_path.exists());
    std::mem::forget((live, reused, missing));
}

#[cfg(unix)]
#[test]
fn private_runtime_scavenger_retains_corrupt_unknown_and_unverifiable_entries_per_directory() {
    use std::os::unix::ffi::OsStringExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = private_runtime_test_root(&temp);
    let corrupt =
        PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::CandidateCapture)
            .expect("create corrupt fixture");
    let corrupt_path = corrupt.path().to_path_buf();
    fs::write(
        PrivateRuntimeKind::CandidateCapture.owner_path(&corrupt_path),
        b"{broken",
    )
    .expect("corrupt owner");
    std::mem::forget(corrupt);

    let unknown = root.join("maco-publication-git-not-a-valid-reservation");
    create_private_directory(&unknown).expect("create unknown managed entry");
    let mut non_utf8_name = PrivateRuntimeKind::CandidateValidation
        .prefix()
        .as_bytes()
        .to_vec();
    non_utf8_name.extend_from_slice(b"1-20000-0-");
    non_utf8_name.push(0xff);
    let non_utf8 = root.join(OsString::from_vec(non_utf8_name));
    create_private_directory(&non_utf8).expect("create non-UTF-8 managed entry");
    let unverifiable = PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::GhConfig)
        .expect("create unverifiable fixture");
    let unverifiable_path = unverifiable.path().to_path_buf();
    std::mem::forget(unverifiable);

    let report = scavenge_private_runtime_orphans_with(
        &root,
        private_runtime_boot_id().expect("boot id").as_deref(),
        |_| bail!("synthetic identity lookup failure"),
    )
    .expect("per-directory failures must not abort bounded scan");
    assert_eq!(report.removed, 0);
    assert_eq!(report.retained, 4);
    assert!(corrupt_path.exists());
    assert!(unknown.exists());
    assert!(non_utf8.exists());
    assert!(unverifiable_path.exists());

    let fresh =
        PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::CandidateValidation)
            .expect("retained entries must not globally block a fresh reservation");
    assert!(fresh.path().exists());
}

#[cfg(unix)]
#[test]
fn private_runtime_scavenger_recovers_each_owner_publication_crash_point() {
    let temp = tempfile::tempdir().expect("tempdir");
    let root = private_runtime_test_root(&temp);
    let kinds = [
        PrivateRuntimeKind::CandidateCapture,
        PrivateRuntimeKind::CandidateValidation,
        PrivateRuntimeKind::PublicationGit,
        PrivateRuntimeKind::GhConfig,
    ];
    let mut paths = Vec::new();
    for (kind_index, kind) in kinds.into_iter().enumerate() {
        paths.push(create_incomplete_private_runtime(
            &root,
            kind,
            &format!("{}-0", 10_000 + kind_index),
            false,
            false,
            false,
        ));
        if kind == PrivateRuntimeKind::CandidateValidation {
            paths.push(create_incomplete_private_runtime(
                &root, kind, "11000-0", true, false, false,
            ));
        }
        paths.push(create_incomplete_private_runtime(
            &root,
            kind,
            &format!("{}-1", 12_000 + kind_index),
            kind == PrivateRuntimeKind::CandidateValidation,
            true,
            false,
        ));
        paths.push(create_incomplete_private_runtime(
            &root,
            kind,
            &format!("{}-2", 13_000 + kind_index),
            kind == PrivateRuntimeKind::CandidateValidation,
            true,
            true,
        ));
    }
    let report = scavenge_private_runtime_orphans_with(
        &root,
        private_runtime_boot_id().expect("boot id").as_deref(),
        |_| Ok(None),
    )
    .expect("recover interrupted reservations");
    assert_eq!(report.removed, paths.len());
    assert_eq!(report.retained, 0);
    assert!(paths.iter().all(|path| !path.exists()));
}

#[cfg(target_os = "linux")]
#[test]
fn private_runtime_parent_sigkill_residue_is_reclaimed_on_next_entry() {
    const CHILD_ROOT: &str = "MACO_TEST_PRIVATE_RUNTIME_CHILD_ROOT";
    const CHILD_READY: &str = "MACO_TEST_PRIVATE_RUNTIME_CHILD_READY";
    if let (Some(root), Some(ready)) = (env::var_os(CHILD_ROOT), env::var_os(CHILD_READY)) {
        let runtime = PrivateRuntimeDirectory::create_in_root(
            Path::new(&root),
            PrivateRuntimeKind::CandidateCapture,
        )
        .expect("child creates private runtime");
        fs::write(&ready, runtime.path().as_os_str().as_encoded_bytes())
            .expect("publish child runtime path");
        loop {
            std::thread::park_timeout(Duration::from_secs(60));
        }
    }

    use std::os::unix::ffi::OsStringExt;
    let temp = tempfile::tempdir().expect("tempdir");
    let root = private_runtime_test_root(&temp);
    let ready = temp.path().join("ready");
    let executable = env::current_exe().expect("current test executable");
    let mut child = Command::new(executable)
        .args([
            "--exact",
            "merge::tests::private_runtime_parent_sigkill_residue_is_reclaimed_on_next_entry",
            "--nocapture",
        ])
        .env(CHILD_ROOT, &root)
        .env(CHILD_READY, &ready)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn private runtime crash child");
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while !ready.exists() {
        assert!(
            std::time::Instant::now() < deadline,
            "private runtime crash child did not publish its path"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
    let path = PathBuf::from(OsString::from_vec(
        fs::read(&ready).expect("read child runtime path"),
    ));
    assert!(path.exists());
    // SAFETY: child.id identifies the live subprocess created above.
    assert_eq!(unsafe { libc::kill(child.id() as i32, libc::SIGKILL) }, 0);
    child.wait().expect("reap crash child");
    let report = scavenge_private_runtime_orphans(&root).expect("reclaim crashed owner");
    assert_eq!(report.removed, 1);
    assert_eq!(report.retained, 0);
    assert!(!path.exists());
}

#[cfg(unix)]
#[test]
fn private_runtime_fd_cleanup_never_follows_symlink_or_hardlink_outside_root() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let root = private_runtime_test_root(&temp);
    let outside = temp.path().join("outside");
    create_private_directory(&outside).expect("create outside directory");
    let marker = outside.join("marker");
    fs::write(&marker, "preserve\n").expect("write outside marker");
    let hardlink_target = outside.join("hardlink-target");
    fs::write(&hardlink_target, "preserve hardlink\n").expect("write hardlink target");

    let runtime =
        PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::CandidateCapture)
            .expect("create stale runtime");
    let runtime_path = runtime.path().to_path_buf();
    symlink(&outside, runtime_path.join("escape")).expect("create escape symlink");
    fs::hard_link(&hardlink_target, runtime_path.join("hardlink"))
        .expect("create outside hardlink");
    std::mem::forget(runtime);
    let report = scavenge_private_runtime_orphans_with(
        &root,
        private_runtime_boot_id().expect("boot id").as_deref(),
        |_| Ok(None),
    )
    .expect("reclaim runtime containing links");
    assert_eq!(report.removed, 1);
    assert_eq!(
        fs::read_to_string(&marker).expect("outside marker"),
        "preserve\n"
    );
    assert_eq!(
        fs::read_to_string(&hardlink_target).expect("outside hardlink target"),
        "preserve hardlink\n"
    );

    let top_level = root.join(format!(
        "{}{}-14000-0",
        PrivateRuntimeKind::GhConfig.prefix(),
        std::process::id()
    ));
    symlink(&outside, &top_level).expect("create top-level managed symlink");
    let report = scavenge_private_runtime_orphans(&root).expect("retain top-level symlink");
    assert_eq!(report.retained, 1);
    assert!(top_level.symlink_metadata().is_ok());
    assert!(marker.exists());
}

#[cfg(unix)]
#[test]
fn private_runtime_fd_cleanup_race_never_escapes_managed_directory() {
    use std::{
        os::unix::fs::symlink,
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc,
        },
    };

    let temp = tempfile::tempdir().expect("tempdir");
    let root = private_runtime_test_root(&temp);
    let outside = temp.path().join("outside-race");
    create_private_directory(&outside).expect("create outside race directory");
    let marker = outside.join("marker");
    fs::write(&marker, "outside survives\n").expect("write outside race marker");

    let runtime =
        PrivateRuntimeDirectory::create_in_root(&root, PrivateRuntimeKind::CandidateCapture)
            .expect("create race runtime");
    let runtime_path = runtime.path().to_path_buf();
    let race = runtime_path.join("race");
    let holding = runtime_path.join("holding");
    create_private_directory(&race).expect("create raced child");
    fs::write(race.join("inside"), "inside\n").expect("write raced child content");
    std::mem::forget(runtime);

    let running = Arc::new(AtomicBool::new(true));
    let worker_running = Arc::clone(&running);
    let worker_outside = outside.clone();
    let worker = std::thread::spawn(move || {
        while worker_running.load(Ordering::Acquire) {
            if fs::rename(&race, &holding).is_ok() {
                if symlink(&worker_outside, &race).is_ok() {
                    std::thread::yield_now();
                    let _ = fs::remove_file(&race);
                }
                let _ = fs::rename(&holding, &race);
            } else {
                std::thread::yield_now();
            }
        }
    });
    let report = scavenge_private_runtime_orphans_with(
        &root,
        private_runtime_boot_id().expect("boot id").as_deref(),
        |_| Ok(None),
    )
    .expect("race cleanup remains bounded");
    running.store(false, Ordering::Release);
    worker.join().expect("join race worker");
    assert_eq!(report.removed + report.retained, 1);
    assert_eq!(
        fs::read_to_string(&marker).expect("outside race marker"),
        "outside survives\n"
    );
}

#[cfg(unix)]
#[test]
fn private_runtime_scan_entry_and_tree_depth_bounds_fail_before_deletion() {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };

    let temp = tempfile::tempdir().expect("tempdir");
    let root = private_runtime_test_root(&temp);
    for index in 0..=PRIVATE_RUNTIME_SCAN_MAX_DIRECTORIES {
        let path = root.join(format!(
            "{}{}-{}-0",
            PrivateRuntimeKind::CandidateCapture.prefix(),
            std::process::id(),
            20_000 + index
        ));
        create_private_directory(&path).expect("create bounded scan fixture");
    }
    let error = scavenge_private_runtime_orphans(&root)
        .expect_err("managed directory count overflow must fail");
    assert!(error.to_string().contains("unbounded scavenging"));

    let tree_root = temp.path().join("tree");
    create_private_directory(&tree_root).expect("create bounded tree root");
    create_private_directory(&tree_root.join("child")).expect("create bounded child");
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW);
    let tree = options.open(&tree_root).expect("open bounded tree");
    let device = tree.metadata().expect("tree metadata").dev() as libc::dev_t;
    let mut entries = 1;
    let error =
        validate_private_runtime_contents_unix(tree.as_raw_fd(), device, &mut entries, 1, 16, 0)
            .expect_err("entry overflow must fail before deletion");
    assert!(error.to_string().contains("bounded directory-entry limit"));
    assert!(tree_root.join("child").exists());

    let mut entries = 1;
    let error =
        validate_private_runtime_contents_unix(tree.as_raw_fd(), device, &mut entries, 16, 0, 0)
            .expect_err("depth overflow must fail before deletion");
    assert!(error.to_string().contains("depth limit"));
    assert!(tree_root.join("child").exists());
}

#[test]
fn parses_git_apply_paths_from_standard_errors() {
    let stderr = "\
error: patch failed: README.md:1
error: README.md: patch does not apply
error: src/lib.rs: does not match index
";

    assert_eq!(
        parse_git_apply_error_paths(stderr),
        vec![PathBuf::from("README.md"), PathBuf::from("src/lib.rs")]
    );
}

#[test]
fn localized_git_apply_messages_do_not_parse() {
    let stderr = "\
Fehler: Patch fehlgeschlagen: README.md:1
error: README.md: Patch lässt sich nicht anwenden
";
    assert!(parse_git_apply_error_paths(stderr).is_empty());
}

#[test]
fn isolated_git_environment_pins_c_locale() {
    let mut inherited = BTreeMap::from([
        ("LANG".to_string(), "de_DE.UTF-8".to_string()),
        ("LC_ALL".to_string(), "de_DE.UTF-8".to_string()),
        ("LC_CTYPE".to_string(), "de_DE.UTF-8".to_string()),
        ("LC_MESSAGES".to_string(), "de_DE.UTF-8".to_string()),
    ]);
    pin_parsed_git_locale(&mut inherited);
    assert_eq!(inherited.get("LC_ALL").map(String::as_str), Some("C"));
    assert_eq!(inherited.get("LANG").map(String::as_str), Some("C"));
    assert!(!inherited.contains_key("LC_CTYPE"));
    assert!(!inherited.contains_key("LC_MESSAGES"));

    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let environment = capture_git_environment(&repo_path).expect("capture git environment");
    assert_eq!(environment.get("LC_ALL").map(String::as_str), Some("C"));
    assert_eq!(environment.get("LANG").map(String::as_str), Some("C"));
}

#[test]
fn isolated_git_workspace_profile_exposes_primary_common_dir() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let context = TemporaryIndex::create(repo.commondir()).expect("create isolated index");
    let common_dir = std::fs::canonicalize(repo.commondir()).expect("canonicalize commondir");
    let objects = std::fs::canonicalize(common_dir.join("objects")).expect("canonicalize objects");
    let profile =
        isolated_git_workspace_profile(&context, &repo_path).expect("isolated git profile");
    let visible = profile.visible_read_only_roots();
    assert!(
        visible.contains(&objects),
        "isolated git profile must expose the primary object store, got {visible:?}"
    );
    assert!(
        visible.contains(&common_dir),
        "isolated git profile must expose the primary Git common dir, got {visible:?}"
    );
    if let Ok(sensitive) = crate::artifacts::state_auth::sensitive_state_root(&common_dir) {
        assert!(
            profile.hidden_roots().contains(&sensitive),
            "isolated git profile must hide repository sensitive state"
        );
    }
}

#[test]
fn validation_reports_accept_external_and_summary_shapes() {
    let value = serde_json::json!({
        "agents": [
            {
                "id": "agent-a",
                "validation": [
                    {
                        "name": "unit",
                        "status": "failed",
                        "message": "tests failed",
                        "paths": ["src/lib.rs"]
                    }
                ]
            },
            {
                "id": "agent-b",
                "validation": [
                    {"name": "fmt", "status": "succeeded"}
                ]
            }
        ]
    });

    let reports = validation_reports_from_json_for_agent(&value, Some("agent-a"))
        .expect("parse agent validation reports");

    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].name, "unit");
    assert_eq!(reports[0].status, ValidationStatus::Failed);
    assert_eq!(reports[0].message.as_deref(), Some("tests failed"));
    assert_eq!(reports[0].paths, vec![PathBuf::from("src/lib.rs")]);
}

#[test]
fn validation_reports_do_not_treat_agent_summary_as_validation() {
    let value = serde_json::json!({
        "agents": [
            {
                "id": "agent-a",
                "paths": ["README.md"],
                "command": "cargo test",
                "status": "succeeded"
            }
        ]
    });

    let reports = validation_reports_from_json_for_agent(&value, Some("agent-a"))
        .expect("parse empty validation reports");

    assert!(reports.is_empty());
}

#[test]
fn validation_check_uses_explicit_paths_for_failures() {
    let validation = validation_check(
        &[ValidationReport {
            name: "unit".to_string(),
            status: ValidationStatus::Failed,
            message: Some("failed".to_string()),
            paths: vec![PathBuf::from("src/lib.rs")],
        }],
        false,
    );

    assert_eq!(validation.status, SafetyCheckStatus::Failed);
    assert_eq!(validation.paths, vec![PathBuf::from("src/lib.rs")]);
}
