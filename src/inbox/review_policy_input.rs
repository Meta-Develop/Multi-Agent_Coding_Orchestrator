//! Explicit operator-owned policy input for authenticated GitHub review triage.

use super::{review_loop::ReviewLoopPolicy, InboxConfig};
#[cfg(unix)]
use super::{source_repository_binding_context, MAX_CONFIG_BYTES};
use crate::publication::forge_transport::ForgeRepository;
#[cfg(unix)]
use crate::publication::forge_transport::ProviderObjectId;
#[cfg(unix)]
use crate::{
    artifacts::state_auth::sha256_hex,
    safe_state::{BoundedRegularReader, SafeRoot},
};
#[cfg(unix)]
use anyhow::Context;
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;
#[cfg(unix)]
use std::{fs, path::Component};

const REVIEW_POLICY_INPUT_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct OperatorReviewPolicyInput {
    version: u32,
    repository: ForgeRepository,
    policy: ReviewLoopPolicy,
}

#[derive(Debug, Clone, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReviewPolicyBinding {
    version: u32,
    repository: ForgeRepository,
    raw_sha256: String,
    policy_sha256: String,
}

#[derive(Debug, Clone)]
pub(super) struct BoundReviewPolicy {
    raw: Vec<u8>,
    input: OperatorReviewPolicyInput,
    binding: ReviewPolicyBinding,
}

#[derive(Debug)]
pub(super) struct ReviewPolicyRepositoryMismatch;

impl std::fmt::Display for ReviewPolicyRepositoryMismatch {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(
            "authenticated GitHub repository identity differs from the operator review policy",
        )
    }
}

impl std::error::Error for ReviewPolicyRepositoryMismatch {}

impl BoundReviewPolicy {
    pub(super) fn load(repo: &Path, config: &InboxConfig, path: &Path) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (repo, config, path);
            bail!("operator review-policy input is unsupported without Unix no-follow ownership checks");
        }

        #[cfg(unix)]
        {
            if !path.is_absolute()
                || path
                    .components()
                    .any(|part| matches!(part, Component::CurDir | Component::ParentDir))
            {
                bail!("operator review-policy path must be absolute and normalized");
            }
            let parent = path
                .parent()
                .context("operator review-policy path has no parent")?;
            path.file_name()
                .context("operator review-policy path has no file name")?;
            let canonical_parent = fs::canonicalize(parent)
                .context("failed to resolve operator review-policy parent")?;
            if canonical_parent != parent {
                bail!("operator review-policy path cannot traverse linked directories");
            }
            let canonical_repo =
                fs::canonicalize(repo).context("failed to resolve inbox repository")?;
            if canonical_parent.starts_with(&canonical_repo) {
                bail!("operator review-policy file must be outside the source repository");
            }
            let root = SafeRoot::open_existing(&canonical_parent)
                .context("failed to bind operator review-policy directory")?;
            let raw = BoundedRegularReader::read_tree_no_follow_validated(
                path,
                MAX_CONFIG_BYTES,
                verify_operator_file_mode,
            )
            .context("failed to read bounded no-follow operator review-policy file")?;
            root.verify()?;
            let input: OperatorReviewPolicyInput = serde_json::from_slice(&raw)
                .context("operator review-policy input is not strict valid JSON")?;
            if input.version != REVIEW_POLICY_INPUT_VERSION
                || input.repository.provider_id() != "github"
            {
                bail!("operator review-policy version or provider is unsupported");
            }
            verify_github_node_id(input.repository.provider_repository_id())?;
            for actor in input.policy.trusted_feedback_actors() {
                verify_github_node_id(actor.identity().provider_actor_id())?;
            }
            for check in input.policy.required_checks() {
                for actor in check.trusted_actors() {
                    verify_github_node_id(actor.provider_actor_id())?;
                }
            }
            let source = source_repository_binding_context(repo, config, true)?;
            if input.repository.canonical_locator() != source.selector.as_str() {
                bail!(
                    "operator review-policy repository selector differs from the canonical origin"
                );
            }
            let binding = ReviewPolicyBinding {
                version: REVIEW_POLICY_INPUT_VERSION,
                repository: input.repository.clone(),
                raw_sha256: sha256_hex(&raw),
                policy_sha256: input.policy.canonical_sha256()?,
            };
            Ok(Self {
                raw,
                input,
                binding,
            })
        }
    }

    pub(super) fn repository(&self) -> &ForgeRepository {
        &self.input.repository
    }

    pub(super) fn policy(&self) -> &ReviewLoopPolicy {
        &self.input.policy
    }

    pub(super) fn raw(&self) -> &[u8] {
        &self.raw
    }

    pub(super) fn binding(&self) -> &ReviewPolicyBinding {
        &self.binding
    }

    pub(super) fn verify_repository(&self, observed: &ForgeRepository) -> Result<()> {
        if observed != self.repository() {
            return Err(ReviewPolicyRepositoryMismatch.into());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn verify_github_node_id(id: &ProviderObjectId) -> Result<()> {
    let digest = id.stable_id().strip_prefix("node:sha256:");
    if id.provider_id() != "github"
        || !digest.is_some_and(|value| {
            value.len() == 64
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        })
    {
        bail!("operator review-policy identity requires a canonical hashed GitHub node id");
    }
    Ok(())
}

#[cfg(unix)]
fn verify_operator_file_mode(metadata: &fs::Metadata) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    if !metadata.file_type().is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("operator review-policy file must be an owned regular single-link file without group/world write access");
    }
    Ok(())
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use crate::worktree::WorktreeManager;
    use crate::{
        inbox::{
            review_loop::{
                RequiredCheck, TrustedActorBinding, TrustedActorIdentity, TrustedActorRole,
            },
            run_inbox, scan_inbox, watch_inbox, InboxItemKind, InboxPermissionMode,
            InboxRunOptions, InboxScanOptions, InboxWatchOptions,
        },
        orchestrator::RunId,
        publication::forge_transport::{ProviderObjectId, ProviderObjectKind, ReportedActorKind},
    };
    use git2::Repository;
    use tempfile::TempDir;

    fn repository(id: &str) -> ForgeRepository {
        ForgeRepository::new(
            "github",
            "github.com/example/project",
            ProviderObjectId::new(
                "github",
                ProviderObjectKind::Repository,
                format!("node:sha256:{}", sha256_hex(id.as_bytes())),
            )
            .unwrap(),
        )
        .unwrap()
    }

    fn input(repository: ForgeRepository) -> OperatorReviewPolicyInput {
        let human = TrustedActorIdentity::new(
            ProviderObjectId::new(
                "github",
                ProviderObjectKind::Actor,
                format!("node:sha256:{}", sha256_hex(b"U_reviewer")),
            )
            .unwrap(),
            "reviewer",
            ReportedActorKind::Human,
        )
        .unwrap();
        let check_bot = TrustedActorIdentity::new(
            ProviderObjectId::new(
                "github",
                ProviderObjectKind::Actor,
                format!("node:sha256:{}", sha256_hex(b"B_ci")),
            )
            .unwrap(),
            "ci-bot",
            ReportedActorKind::Bot,
        )
        .unwrap();
        OperatorReviewPolicyInput {
            version: REVIEW_POLICY_INPUT_VERSION,
            repository,
            policy: ReviewLoopPolicy::new(
                vec![
                    TrustedActorBinding::new(human, TrustedActorRole::HumanBlocking).unwrap(),
                    TrustedActorBinding::new(check_bot.clone(), TrustedActorRole::BotAdvisory)
                        .unwrap(),
                ],
                vec![RequiredCheck::new("ci", vec![check_bot]).unwrap()],
                1,
                2,
            )
            .unwrap(),
        }
    }

    fn fixture() -> (TempDir, std::path::PathBuf, std::path::PathBuf) {
        let temp = TempDir::new().unwrap();
        let repo = temp.path().join("source");
        WorktreeManager::init_repository(&repo, "main").unwrap();
        let git = Repository::open(&repo).unwrap();
        git.remote("origin", "https://github.com/example/project.git")
            .unwrap();
        let policy_file = temp.path().join("review-policy.json");
        let canonical_policy_file = fs::canonicalize(temp.path())
            .unwrap()
            .join("review-policy.json");
        (
            temp,
            repo,
            if policy_file == canonical_policy_file {
                policy_file
            } else {
                canonical_policy_file
            },
        )
    }

    #[test]
    fn frozen_operator_limit_gates_only_real_github_pr_repair() {
        use super::super::{
            repair_attempts::{reserve_if_applicable, RepairAttemptAdmission},
            source_repository_binding_context, GithubCheckSummary, GithubPrSourceTrust,
            GithubReviewFeedbackSummary, InboxItemKind, InboxSourceProvider,
            InboxSourceSnapshotBinding, RawPrCandidate,
        };
        let (_temp, repo, path) = fixture();
        fs::write(
            &path,
            serde_json::to_vec(&input(repository("R_actual"))).unwrap(),
        )
        .unwrap();
        let config = InboxConfig::default();
        let policy = BoundReviewPolicy::load(&repo, &config, &path).unwrap();
        let source = source_repository_binding_context(&repo, &config, true).unwrap();
        let head = "a".repeat(40);
        let base = "b".repeat(40);
        let raw = RawPrCandidate {
            provider: InboxSourceProvider::Github,
            number: 73,
            title: "Repair requested".to_string(),
            body: "CI failed".to_string(),
            url: Some("https://github.com/example/project/pull/73".to_string()),
            author: Some("author".to_string()),
            labels: Vec::new(),
            updated_at: "2026-09-14T00:00:00Z".to_string(),
            state: "OPEN".to_string(),
            content_digest: sha256_hex(b"content"),
            action_revision_digest: sha256_hex(b"action"),
            head_ref: Some("repair".to_string()),
            base_ref: Some("main".to_string()),
            head_oid: head.clone(),
            base_oid: base.clone(),
            is_draft: false,
            source_trust: GithubPrSourceTrust::TrustedTargetRepository,
            head_repository: Some("example/project".to_string()),
            changed_files: vec![std::path::PathBuf::from("src/lib.rs")],
            checks: vec![GithubCheckSummary {
                name: "ci".to_string(),
                status: Some("completed".to_string()),
                conclusion: Some("failure".to_string()),
                details_url: None,
                summary: "failed".to_string(),
            }],
            review_feedback: GithubReviewFeedbackSummary {
                review_decision: Some("CHANGES_REQUESTED".to_string()),
                requested_changes: true,
                unresolved_thread_count: None,
                reviewer_logins: Vec::new(),
                summaries: Vec::new(),
            },
        };
        let item = super::super::pr_item(raw, &config, &source, &Default::default()).unwrap();
        let head_oid = git2::Oid::from_str(&head).unwrap();
        let first_run = RunId::new("real-repair-one").unwrap();
        assert_eq!(
            reserve_if_applicable(&repo, &item, None, &first_run, 1, Some(head_oid)).unwrap(),
            RepairAttemptAdmission::NotApplicable
        );
        let mut fake = item.clone();
        fake.source_snapshot = InboxSourceSnapshotBinding::for_pull_request(
            InboxSourceProvider::Fake,
            "fake",
            ".",
            source.identity.clone(),
            73,
            "2026-09-14T00:00:00Z",
            "OPEN",
            head.clone(),
            base,
            sha256_hex(b"content"),
            sha256_hex(b"action"),
        )
        .unwrap();
        assert_eq!(
            reserve_if_applicable(&repo, &fake, Some(&policy), &first_run, 1, Some(head_oid))
                .unwrap(),
            RepairAttemptAdmission::NotApplicable
        );
        let mut issue = item.clone();
        issue.kind = InboxItemKind::Issue;
        assert_eq!(
            reserve_if_applicable(&repo, &issue, Some(&policy), &first_run, 1, Some(head_oid))
                .unwrap(),
            RepairAttemptAdmission::NotApplicable
        );
        assert!(reserve_if_applicable(
            &repo,
            &item,
            Some(&policy),
            &first_run,
            1,
            Some(git2::Oid::from_str(&"c".repeat(40)).unwrap()),
        )
        .is_err());
        let source_snapshot_sha256 =
            sha256_hex(&serde_json::to_vec(&item.source_snapshot).unwrap());
        assert!(matches!(
            reserve_if_applicable(&repo, &item, Some(&policy), &first_run, 1, Some(head_oid))
                .unwrap(),
            RepairAttemptAdmission::Reserved(ref receipt)
                if receipt.attempt_number == 1
                    && receipt.source_snapshot_sha256 == source_snapshot_sha256
        ));
        let second_run = RunId::new("real-repair-two").unwrap();
        assert!(matches!(
            reserve_if_applicable(&repo, &item, Some(&policy), &second_run, 1, Some(head_oid))
                .unwrap(),
            RepairAttemptAdmission::Reserved(ref receipt) if receipt.attempt_number == 2
        ));
        assert_eq!(
            reserve_if_applicable(
                &repo,
                &item,
                Some(&policy),
                &RunId::new("real-repair-three").unwrap(),
                1,
                Some(head_oid),
            )
            .unwrap(),
            RepairAttemptAdmission::Exhausted {
                spent: 2,
                max_attempts: 2,
            }
        );
    }

    #[test]
    fn exact_operator_policy_freezes_raw_and_effective_binding() {
        let (_temp, repo, path) = fixture();
        let document = input(repository("R_actual"));
        let original = serde_json::to_vec(&document).unwrap();
        fs::write(&path, &original).unwrap();
        let bound = BoundReviewPolicy::load(&repo, &InboxConfig::default(), &path).unwrap();
        assert_eq!(bound.raw(), original);
        assert_eq!(bound.binding.raw_sha256, sha256_hex(&original));
        assert_eq!(
            bound.binding.policy_sha256,
            document.policy.canonical_sha256().unwrap()
        );
        bound.verify_repository(&repository("R_actual")).unwrap();
        assert!(bound.verify_repository(&repository("R_other")).is_err());
        fs::write(&path, b"invalid later input").unwrap();
        assert_eq!(bound.raw(), original);
        assert_eq!(bound.policy(), &document.policy);

        let run_id = RunId::new("one-frozen-policy-run").unwrap();
        let report = super::super::run_inbox_with_bound_policy_and_resolver(
            InboxRunOptions {
                repo: repo.clone(),
                run_id: run_id.clone(),
                github: true,
                permission_mode: Some(InboxPermissionMode::GithubRead),
                dry_run: true,
                max_items: None,
                codex_bin: None,
                machine_global: None,
                review_policy_file: Some(path.clone()),
            },
            None,
            super::super::InboxConfigOverrides {
                fixed_scan_items: Some(Vec::new()),
                ..Default::default()
            },
            None,
            Some(&bound),
            |_, _| Ok(repository("R_actual")),
        )
        .expect("frozen policy is reused after source file changed");
        assert_eq!(report.selected_item_count, 0);
        let reader = crate::artifacts::ArtifactRunReader::open(
            &repo,
            crate::artifacts::RunArtifactFamily::Inbox,
            &run_id,
        )
        .unwrap();
        assert_eq!(reader.read("review-policy-input.json").unwrap(), original);

        let watch_run_id = RunId::new("same-frozen-policy-watch-iteration").unwrap();
        let watch_report = super::super::run_github_watch_iteration_with(
            InboxRunOptions {
                repo: repo.clone(),
                run_id: watch_run_id.clone(),
                github: true,
                permission_mode: Some(InboxPermissionMode::GithubRead),
                dry_run: true,
                max_items: None,
                codex_bin: None,
                machine_global: None,
                review_policy_file: Some(path),
            },
            |_, _, _, _| {
                Ok((
                    "github.com/example/project".to_string(),
                    serde_json::json!([]),
                ))
            },
            |_, _| unreachable!("empty discovery cannot produce an intake"),
            |options, overrides| {
                super::super::run_inbox_with_bound_policy_and_resolver(
                    options,
                    None,
                    super::super::InboxConfigOverrides {
                        fixed_scan_items: Some(Vec::new()),
                        ..overrides
                    },
                    None,
                    Some(&bound),
                    |_, _| Ok(repository("R_actual")),
                )
            },
            Some(&bound),
        )
        .expect("watch iteration reuses the same frozen policy");
        assert_eq!(watch_report.selected_item_count, 0);
        let watch_reader = crate::artifacts::ArtifactRunReader::open(
            &repo,
            crate::artifacts::RunArtifactFamily::Inbox,
            &watch_run_id,
        )
        .unwrap();
        assert_eq!(
            watch_reader.read("review-policy-input.json").unwrap(),
            original
        );
    }

    #[test]
    fn foreign_malformed_and_weakened_inputs_refuse_before_observation() {
        let (_temp, repo, path) = fixture();
        let mut foreign = input(repository("R_actual"));
        foreign.repository = ForgeRepository::new(
            "github",
            "github.com/foreign/project",
            ProviderObjectId::new(
                "github",
                ProviderObjectKind::Repository,
                format!("node:sha256:{}", sha256_hex(b"R_foreign")),
            )
            .unwrap(),
        )
        .unwrap();
        fs::write(&path, serde_json::to_vec(&foreign).unwrap()).unwrap();
        assert!(BoundReviewPolicy::load(&repo, &InboxConfig::default(), &path).is_err());
        let run_id = RunId::new("foreign-policy-before-run").unwrap();
        let error = run_inbox(InboxRunOptions {
            repo: repo.clone(),
            run_id: run_id.clone(),
            github: true,
            permission_mode: Some(InboxPermissionMode::GithubRead),
            dry_run: true,
            max_items: None,
            codex_bin: None,
            machine_global: None,
            review_policy_file: Some(path.clone()),
        })
        .expect_err("foreign selector must fail before provider and run reservation");
        assert!(format!("{error:#}").contains("repository selector"));
        assert!(!repo.join(".maco/inbox/runs").join(run_id.as_str()).exists());
        assert!(scan_inbox(InboxScanOptions {
            repo: repo.clone(),
            github: true,
            permission_mode: Some(InboxPermissionMode::GithubRead),
            max_items: None,
            action_policy_override: None,
            review_policy_file: Some(path.clone()),
        })
        .is_err());
        assert!(watch_inbox(InboxWatchOptions {
            repo: repo.clone(),
            poll_seconds: 1,
            once: true,
            github: true,
            permission_mode: Some(InboxPermissionMode::GithubRead),
            dry_run: true,
            max_items: None,
            codex_bin: None,
            machine_global: None,
            review_policy_file: Some(path.clone()),
        })
        .is_err());

        let mut unknown = serde_json::to_value(input(repository("R_actual"))).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
        assert!(BoundReviewPolicy::load(&repo, &InboxConfig::default(), &path).is_err());

        unknown.as_object_mut().unwrap().remove("unexpected");
        unknown["policy"]["minimum_approvals"] = serde_json::json!(0);
        fs::write(&path, serde_json::to_vec(&unknown).unwrap()).unwrap();
        assert!(BoundReviewPolicy::load(&repo, &InboxConfig::default(), &path).is_err());

        let valid = serde_json::to_string(&input(repository("R_actual"))).unwrap();
        let duplicate_version = valid.replacen('{', "{\"version\":1,", 1);
        fs::write(&path, duplicate_version).unwrap();
        assert!(BoundReviewPolicy::load(&repo, &InboxConfig::default(), &path).is_err());
    }

    #[test]
    fn wrong_provider_repository_id_refuses_empty_and_issue_only_runs_before_reservation() {
        let (_temp, repo, path) = fixture();
        fs::write(
            &path,
            serde_json::to_vec(&input(repository("R_expected"))).unwrap(),
        )
        .unwrap();
        let bound = BoundReviewPolicy::load(&repo, &InboxConfig::default(), &path).unwrap();
        let issue = scan_inbox(InboxScanOptions {
            repo: repo.clone(),
            github: false,
            permission_mode: None,
            max_items: None,
            action_policy_override: None,
            review_policy_file: None,
        })
        .unwrap()
        .items
        .into_iter()
        .find(|item| item.kind == InboxItemKind::Issue)
        .expect("fake issue fixture");
        for (run_id, fixed_scan_items) in [
            ("wrong-repo-empty", Vec::new()),
            ("wrong-repo-issue-only", vec![issue]),
        ] {
            let run_id = RunId::new(run_id).unwrap();
            let error = super::super::run_inbox_with_bound_policy_and_resolver(
                InboxRunOptions {
                    repo: repo.clone(),
                    run_id: run_id.clone(),
                    github: true,
                    permission_mode: Some(InboxPermissionMode::GithubRead),
                    dry_run: true,
                    max_items: None,
                    codex_bin: None,
                    machine_global: None,
                    review_policy_file: Some(path.clone()),
                },
                None,
                super::super::InboxConfigOverrides {
                    fixed_scan_items: Some(fixed_scan_items),
                    ..Default::default()
                },
                None,
                Some(&bound),
                |_, selector| {
                    assert_eq!(selector, "github.com/example/project");
                    Ok(repository("R_other"))
                },
            )
            .expect_err(
                "wrong authenticated provider repository ID must refuse before reservation",
            );
            assert!(error.is::<ReviewPolicyRepositoryMismatch>());
            assert!(!repo.join(".maco/inbox/runs").join(run_id.as_str()).exists());
        }
    }

    #[test]
    fn repository_file_and_symlink_cannot_become_operator_policy() {
        use std::os::unix::fs::symlink;
        let (_temp, repo, path) = fixture();
        let original = serde_json::to_vec(&input(repository("R_actual"))).unwrap();
        fs::write(&path, &original).unwrap();
        let inside = repo.join("review-policy.json");
        fs::write(&inside, &original).unwrap();
        assert!(BoundReviewPolicy::load(&repo, &InboxConfig::default(), &inside).is_err());
        let link = path.parent().unwrap().join("linked-policy.json");
        symlink(&path, &link).unwrap();
        assert!(BoundReviewPolicy::load(&repo, &InboxConfig::default(), &link).is_err());
    }
}

#[cfg(all(test, not(unix)))]
mod unsupported_platform_tests {
    use super::*;

    #[test]
    fn explicit_policy_fails_closed_without_unix_file_authority() {
        assert!(BoundReviewPolicy::load(
            Path::new("."),
            &InboxConfig::default(),
            Path::new("review-policy.json"),
        )
        .is_err());
    }
}
