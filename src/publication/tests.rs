use super::*;
#[cfg(target_os = "linux")]
use crate::worktree::{WorktreeCreateOptions, WorktreeRecord};
use std::{
    sync::{mpsc, Arc, Mutex},
    time::Duration,
};

// Lifecycle ordering is asserted by the channel event, not by elapsed time. This generous
// bound is only a suite liveness fuse above the longest 120-second local snapshot command;
// expiry means the expected event was never published, not that scheduling was milliseconds
// late.
const TEST_EVENT_TIMEOUT: Duration = Duration::from_secs(180);

fn recv_test_event<T>(receiver: &mpsc::Receiver<T>, context: &str) -> T {
    receiver
        .recv_timeout(TEST_EVENT_TIMEOUT)
        .unwrap_or_else(|error| panic!("{context} within the test liveness bound: {error}"))
}

#[cfg(unix)]
#[test]
fn git_identity_helpers_fail_closed_on_non_utf8_names_and_urls() -> Result<()> {
    let branch_repo = tempfile::tempdir()?;
    let repository = Repository::init(branch_repo.path())?;
    assert_eq!(current_branch_name(&repository)?, None);
    fs::write(repository.path().join("HEAD"), b"ref: refs/heads/non\xff\n")?;
    assert!(current_branch_name(&repository).is_err());

    let remote_repo = tempfile::tempdir()?;
    let repository = Repository::init(remote_repo.path())?;
    fs::write(
            repository.path().join("config"),
            b"[core]\n\trepositoryformatversion = 0\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/non\xff\n",
        )?;
    let error = remote_url(&repository, "origin").expect_err("non-UTF-8 URL must fail");
    assert!(error
        .to_string()
        .contains("remote 'origin' URL is not valid UTF-8"));
    Ok(())
}

#[derive(Default)]
struct FakeExternalRemote {
    receipts: Vec<ExternalEffectReceipt>,
    invoke_calls: usize,
}

struct FakeExternalProvider {
    remote: Arc<Mutex<FakeExternalRemote>>,
    response_loss: bool,
    lookup_error: bool,
    block_invoke: Option<(mpsc::Sender<()>, mpsc::Receiver<()>)>,
}

impl FakeExternalProvider {
    fn new(remote: Arc<Mutex<FakeExternalRemote>>) -> Self {
        Self {
            remote,
            response_loss: false,
            lookup_error: false,
            block_invoke: None,
        }
    }

    fn exact_receipt(request: &ExternalEffectRequest) -> ExternalEffectReceipt {
        ExternalEffectReceipt {
            version: EXTERNAL_EFFECT_VERSION,
            transport_provider: request.transport_provider.clone(),
            repository_identity: request.repository_identity.clone(),
            repository_selector: request.repository_selector.clone(),
            effect_id: request.effect_id.clone(),
            operation: request.operation,
            source_provenance_digest: request
                .source
                .as_ref()
                .map(|source| source.provenance_digest.clone()),
            provider_id: "fake-object-1".to_string(),
            url: "https://example.invalid/acme/repo/effects/1".to_string(),
            repository: request.repository_selector.clone(),
            marker: request.marker.clone(),
            target: request.target.clone(),
            payload: request.payload.clone(),
            target_digest: request.target_digest.clone(),
            payload_digest: request.payload_digest.clone(),
        }
    }
}

impl ExternalEffectProvider for FakeExternalProvider {
    fn preflight_before_start(&mut self, _request: &ExternalEffectRequest) -> Result<()> {
        Ok(())
    }

    fn lookup(&mut self, _request: &ExternalEffectRequest) -> Result<Vec<ExternalEffectReceipt>> {
        if self.lookup_error {
            bail!("injected lookup failure");
        }
        Ok(self
            .remote
            .lock()
            .expect("fake remote lock")
            .receipts
            .clone())
    }

    fn invoke(&mut self, request: &ExternalEffectRequest) -> Result<ExternalEffectReceipt> {
        let receipt = Self::exact_receipt(request);
        {
            let mut remote = self.remote.lock().expect("fake remote lock");
            remote.invoke_calls += 1;
            remote.receipts.push(receipt.clone());
        }
        if let Some((started, release)) = self.block_invoke.take() {
            started
                .send(())
                .expect("signal blocked provider invocation");
            recv_test_event(&release, "release blocked provider invocation");
        }
        if self.response_loss {
            bail!("injected provider response loss");
        }
        Ok(receipt)
    }

    fn verify(
        &mut self,
        request: &ExternalEffectRequest,
        receipt: &ExternalEffectReceipt,
    ) -> Result<ExternalEffectReceipt> {
        validate_external_effect_receipt(request, receipt)?;
        let remote = self.remote.lock().expect("fake remote lock");
        if remote.receipts.as_slice() != [receipt.clone()] {
            bail!("fake remote receipt was missing, duplicated, or mutated");
        }
        Ok(receipt.clone())
    }
}

fn fake_effect_repo() -> tempfile::TempDir {
    let temp = tempfile::tempdir().expect("effect repo tempdir");
    WorktreeManager::init_repository(temp.path(), "main").expect("init effect repo");
    temp
}

fn fake_source_guard(updated_at: &str, content: char, action: char) -> ExternalSourceGuard {
    ExternalSourceGuard::new(
        "github",
        "github.example",
        "github.example/acme/repo",
        stable_external_digest(b"fake-source-repository"),
        ExternalSourceObjectKind::PullRequest,
        17,
        updated_at,
        "OPEN",
        Some("1".repeat(40)),
        Some("2".repeat(40)),
        content.to_string().repeat(64),
        action.to_string().repeat(64),
    )
    .expect("fake source guard")
}

fn fake_effect_request(
    repo: &Path,
    source: ExternalSourceGuard,
    body: &str,
) -> ExternalEffectRequest {
    let auth = repository_auth_writer(repo)
        .expect("effect repository auth writer")
        .into_authenticator()
        .expect("effect repository authenticator");
    let repository_identity = auth.binding().repository_id.clone();
    drop(auth);
    ExternalEffectRequest::new(
        "github",
        "github.example/acme/repo",
        &repository_identity,
        Some(source),
        ExternalEffectOperation::GithubPullRequestComment,
        serde_json::json!({"source": 17, "kind": "pull_request"}),
        serde_json::json!({"body": body}),
    )
    .expect("fake external effect request")
}

#[test]
fn external_effect_production_shapes_bind_source_and_transport_providers_separately() {
    let source = fake_source_guard("2026-07-13T00:00:00Z", '3', '4');
    let repository_identity = stable_external_digest(b"production-shape-repository");
    let git_push = ExternalEffectRequest::new(
        "git",
        "github.example/acme/repo",
        &repository_identity,
        Some(source.clone()),
        ExternalEffectOperation::GitPush,
        serde_json::json!({"remote_ref": "refs/heads/maco/effects/1"}),
        serde_json::json!({"expected_oid": "1".repeat(40)}),
    )
    .expect("source-backed Git transport request");
    let github_pr = ExternalEffectRequest::new(
        "github",
        "github.example/acme/repo",
        &repository_identity,
        Some(source.clone()),
        ExternalEffectOperation::GithubPullRequest,
        serde_json::json!({"base": "main"}),
        serde_json::json!({"draft": true}),
    )
    .expect("source-backed GitHub PR transport request");
    let github_comment = ExternalEffectRequest::new(
        "github",
        "github.example/acme/repo",
        &repository_identity,
        Some(source),
        ExternalEffectOperation::GithubPullRequestComment,
        serde_json::json!({"number": 17}),
        serde_json::json!({"body": "done"}),
    )
    .expect("source-backed GitHub comment transport request");

    assert_eq!(git_push.transport_provider, "git");
    assert_eq!(github_pr.transport_provider, "github");
    assert_eq!(github_comment.transport_provider, "github");
    assert_eq!(git_push.source.as_ref().unwrap().provider, "github");
    assert_eq!(github_pr.source.as_ref().unwrap().provider, "github");
    assert_ne!(git_push.effect_id, github_pr.effect_id);
    assert!(ExternalEffectRequest::new(
        "github",
        "github.example/acme/repo",
        &repository_identity,
        git_push.source,
        ExternalEffectOperation::GitPush,
        serde_json::json!({}),
        serde_json::json!({}),
    )
    .is_err());
}

fn seed_effect_phase(
    repo: &Path,
    request: &ExternalEffectRequest,
    phase: EffectPhase,
    receipt: Option<ExternalEffectReceipt>,
) {
    let auth = repository_auth_writer(repo)
        .expect("seed auth writer")
        .into_authenticator()
        .expect("seed authenticator");
    let planned = ExternalEffectRecord {
        version: EXTERNAL_EFFECT_VERSION,
        request: request.clone(),
        receipt: None,
    };
    let mut wal: EffectWal =
        EffectWal::create_planned(auth, &request.logical_id, &request.effect_id, &planned)
            .expect("seed planned effect");
    if matches!(
        phase,
        EffectPhase::Started | EffectPhase::Observed | EffectPhase::Completed
    ) {
        wal.started(&request.effect_id, &planned)
            .expect("seed started effect");
    }
    if matches!(phase, EffectPhase::Observed | EffectPhase::Completed) {
        let observed = ExternalEffectRecord {
            version: EXTERNAL_EFFECT_VERSION,
            request: request.clone(),
            receipt,
        };
        wal.observed(&request.effect_id, &observed)
            .expect("seed observed effect");
    }
}

#[test]
fn external_effect_started_recovery_is_lookup_only_and_ambiguity_fails_closed() {
    for count in [0_usize, 1, 2] {
        let repo = fake_effect_repo();
        let request = fake_effect_request(
            repo.path(),
            fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
            "comment",
        );
        seed_effect_phase(repo.path(), &request, EffectPhase::Started, None);
        let receipt = FakeExternalProvider::exact_receipt(&request);
        let remote = Arc::new(Mutex::new(FakeExternalRemote {
            receipts: vec![receipt.clone(); count],
            invoke_calls: 0,
        }));
        let mut provider = FakeExternalProvider::new(remote.clone());
        let result =
            execute_external_effect_exactly_once(repo.path(), request.clone(), &mut provider);
        if count == 1 {
            assert_eq!(result.expect("exactly one recovery receipt"), receipt);
        } else {
            assert!(result.is_err());
        }
        assert_eq!(remote.lock().expect("remote lock").invoke_calls, 0);
    }

    let repo = fake_effect_repo();
    let request = fake_effect_request(
        repo.path(),
        fake_source_guard("2026-07-13T00:00:00Z", '7', '8'),
        "lookup error",
    );
    seed_effect_phase(repo.path(), &request, EffectPhase::Started, None);
    let remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
    let mut provider = FakeExternalProvider::new(remote.clone());
    provider.lookup_error = true;
    assert!(execute_external_effect_exactly_once(repo.path(), request, &mut provider).is_err());
    assert_eq!(remote.lock().expect("remote lock").invoke_calls, 0);
}

#[test]
fn external_effect_observed_resume_and_response_loss_never_resend() {
    let observed_repo = fake_effect_repo();
    let observed_request = fake_effect_request(
        observed_repo.path(),
        fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
        "observed",
    );
    let observed_receipt = FakeExternalProvider::exact_receipt(&observed_request);
    seed_effect_phase(
        observed_repo.path(),
        &observed_request,
        EffectPhase::Observed,
        Some(observed_receipt.clone()),
    );
    let observed_remote = Arc::new(Mutex::new(FakeExternalRemote {
        receipts: vec![observed_receipt.clone()],
        invoke_calls: 0,
    }));
    let mut observed_provider = FakeExternalProvider::new(observed_remote.clone());
    assert_eq!(
        execute_external_effect_exactly_once(
            observed_repo.path(),
            observed_request,
            &mut observed_provider,
        )
        .expect("observed recovery"),
        observed_receipt
    );
    assert_eq!(
        observed_remote
            .lock()
            .expect("observed remote")
            .invoke_calls,
        0
    );

    let loss_repo = fake_effect_repo();
    let loss_request = fake_effect_request(
        loss_repo.path(),
        fake_source_guard("2026-07-13T00:00:00Z", '5', '6'),
        "lost response",
    );
    let loss_remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
    let mut loss_provider = FakeExternalProvider::new(loss_remote.clone());
    loss_provider.response_loss = true;
    execute_external_effect_exactly_once(loss_repo.path(), loss_request, &mut loss_provider)
        .expect("response loss reconciled by lookup");
    let loss_remote = loss_remote.lock().expect("loss remote");
    assert_eq!(loss_remote.invoke_calls, 1);
    assert_eq!(loss_remote.receipts.len(), 1);
}

#[test]
fn external_effect_completed_reverifies_remote_and_reuses_after_volatile_source_change() {
    let repo = fake_effect_repo();
    let first = fake_effect_request(
        repo.path(),
        fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
        "stable comment",
    );
    let remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
    let mut provider = FakeExternalProvider::new(remote.clone());
    let receipt = execute_external_effect_exactly_once(repo.path(), first.clone(), &mut provider)
        .expect("initial effect");
    assert_eq!(remote.lock().expect("remote").invoke_calls, 1);
    let repository = crate::git_repository::open(repo.path()).expect("open effect repository");
    assert!(!repository
        .commondir()
        .join("maco/state/publication-transactions")
        .exists());

    let next_run = fake_effect_request(
        repo.path(),
        fake_source_guard("2026-07-13T00:01:00Z", '5', '4'),
        "stable comment",
    );
    assert_eq!(first.effect_id, next_run.effect_id);
    assert_eq!(first.marker, next_run.marker);
    assert!(same_external_effect_contract(&first, &next_run));
    assert_eq!(
        execute_external_effect_exactly_once(repo.path(), next_run, &mut provider)
            .expect("completed effect reused after updatedAt-only change"),
        receipt
    );
    assert_eq!(remote.lock().expect("remote").invoke_calls, 1);

    remote.lock().expect("remote").receipts.clear();
    assert!(
        execute_external_effect_exactly_once(repo.path(), first.clone(), &mut provider).is_err()
    );
    let mut mutated = receipt;
    mutated.url.push_str("-mutated");
    remote.lock().expect("remote").receipts = vec![mutated];
    assert!(execute_external_effect_exactly_once(repo.path(), first, &mut provider).is_err());
    assert_eq!(remote.lock().expect("remote").invoke_calls, 1);
}

#[test]
fn external_effect_call_uses_snapshot_metadata_without_legacy_effect_metadata() {
    let repo = fake_effect_repo();
    let request = fake_effect_request(
        repo.path(),
        fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
        "snapshot-backed effect",
    );
    let remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
    let mut provider = FakeExternalProvider::new(remote);
    execute_external_effect_exactly_once(repo.path(), request, &mut provider)
        .expect("snapshot-backed external effect");

    let repository = crate::git_repository::open(repo.path()).expect("open effect repository");
    let root = repository
        .commondir()
        .join("maco/state")
        .join(crate::effect_wal::EFFECT_WAL_ROOT_NAME);
    let names = std::fs::read_dir(root)
        .expect("effect snapshot root")
        .map(|entry| {
            entry
                .expect("effect snapshot entry")
                .file_name()
                .into_string()
                .expect("UTF-8 effect snapshot entry")
        })
        .collect::<Vec<_>>();
    assert!(names
        .iter()
        .any(|name| name.starts_with(".snapshot-locator-")));
    assert!(!names.iter().any(|name| {
        name.starts_with(".effect-locator-")
            || name.starts_with(".effect-init-")
            || name.starts_with(".effect-store-")
    }));
}

#[test]
fn external_effect_planned_payload_and_stable_source_revision_are_exact() {
    let repo = fake_effect_repo();
    let first = fake_effect_request(
        repo.path(),
        fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
        "first payload",
    );
    let same_next_run = fake_effect_request(
        repo.path(),
        fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
        "first payload",
    );
    assert_eq!(first, same_next_run);
    let marked =
        external_effect_marked_body("PR body", &first.marker).expect("stable marker-bound PR body");
    assert_eq!(marked.matches(&first.marker).count(), 1);
    assert!(!marked.contains("maco-publication-marker"));
    let first_ref = format!("refs/heads/maco/effects/{}", &first.effect_id[..32]);
    let next_ref = format!("refs/heads/maco/effects/{}", &same_next_run.effect_id[..32]);
    assert_eq!(first_ref, next_ref);
    let changed_payload = fake_effect_request(
        repo.path(),
        fake_source_guard("2026-07-13T00:01:00Z", '5', '4'),
        "changed payload",
    );
    assert_eq!(first.effect_id, changed_payload.effect_id);
    assert!(!same_external_effect_contract(&first, &changed_payload));
    let remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
    let mut provider = FakeExternalProvider::new(remote.clone());
    execute_external_effect_exactly_once(repo.path(), first.clone(), &mut provider)
        .expect("first exact payload");
    assert!(
        execute_external_effect_exactly_once(repo.path(), changed_payload, &mut provider).is_err()
    );
    assert_eq!(remote.lock().expect("remote").invoke_calls, 1);

    let changed_action = fake_effect_request(
        repo.path(),
        fake_source_guard("2026-07-13T00:01:00Z", '5', '6'),
        "first payload",
    );
    assert_ne!(first.effect_id, changed_action.effect_id);
    assert_ne!(first.logical_id, changed_action.logical_id);
}

#[cfg(target_os = "linux")]
#[test]
fn concurrent_external_effect_calls_cannot_double_invoke() {
    let repo = fake_effect_repo();
    let request = fake_effect_request(
        repo.path(),
        fake_source_guard("2026-07-13T00:00:00Z", '3', '4'),
        "concurrent",
    );
    let remote = Arc::new(Mutex::new(FakeExternalRemote::default()));
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let mut first_provider = FakeExternalProvider::new(remote.clone());
    first_provider.block_invoke = Some((started_tx, release_rx));
    let first_repo = repo.path().to_path_buf();
    let first_request = request.clone();
    let (completed_tx, completed_rx) = mpsc::channel();
    let _first = std::thread::spawn(move || {
        let result =
            execute_external_effect_exactly_once(&first_repo, first_request, &mut first_provider);
        let _ = completed_tx.send(result);
    });
    recv_test_event(&started_rx, "first provider reached invocation");
    let mut contender = FakeExternalProvider::new(remote.clone());
    assert!(execute_external_effect_exactly_once(repo.path(), request, &mut contender).is_err());
    release_tx.send(()).expect("release first provider");
    recv_test_event(&completed_rx, "first provider completed after release").expect("first effect");
    assert_eq!(remote.lock().expect("remote").invoke_calls, 1);
}

#[test]
fn external_source_guard_separates_full_freshness_from_action_revision_and_accepts_40_hex_oids() {
    let identity = external_source_repository_identity(7, 11);
    assert_eq!(identity.len(), 64);
    assert_ne!(identity, external_source_repository_identity(7, 12));
    assert_ne!(identity, external_source_repository_identity(8, 11));
    assert!(ExternalSourceGuard::new(
        "github",
        "github.example",
        "github.example/acme/repo",
        "maco-v1-collision-prone-identity",
        ExternalSourceObjectKind::Issue,
        1,
        "2026-07-13T00:00:00Z",
        "OPEN",
        None,
        None,
        "1".repeat(64),
        "2".repeat(64),
    )
    .is_err());
    assert!(ExternalSourceGuard::new(
        "github",
        "other.example",
        "github.example/acme/repo",
        identity.clone(),
        ExternalSourceObjectKind::Issue,
        1,
        "2026-07-13T00:00:00Z",
        "OPEN",
        None,
        None,
        "1".repeat(64),
        "2".repeat(64),
    )
    .is_err());
    assert!(
        validate_github_source_repository_binding("github.example", "other.example/acme/repo")
            .is_err()
    );
    assert!(ExternalSourceGuard::new(
        "github",
        "github.example",
        "github.example/acme/repo/extra",
        identity.clone(),
        ExternalSourceObjectKind::Issue,
        1,
        "2026-07-13T00:00:00Z",
        "OPEN",
        None,
        None,
        "1".repeat(64),
        "2".repeat(64),
    )
    .is_err());
    assert!(ExternalSourceGuard::new(
        "github",
        "github.example",
        "github.example/acme/repo",
        identity.clone(),
        ExternalSourceObjectKind::Issue,
        1,
        "2026-07-13T00:00:00Z",
        "MERGED",
        None,
        None,
        "1".repeat(64),
        "2".repeat(64),
    )
    .is_err());
    let original = serde_json::json!({
        "number": 7,
        "title": "stable title",
        "body": "stable body",
        "url": "https://github.example/acme/repo/pull/7",
        "author": {"login": "author"},
        "labels": [{"name": "bug"}],
        "updatedAt": "2026-07-13T00:00:00Z",
        "state": "OPEN",
        "headRefName": "feature",
        "baseRefName": "main",
        "headRefOid": "1".repeat(40),
        "baseRefOid": "2".repeat(40),
        "isDraft": false,
        "headRepository": {"nameWithOwner": "acme/repo"},
        "isCrossRepository": false,
        "files": [{"path": "src/lib.rs"}],
        "reviewDecision": "",
        "latestReviews": [],
        "statusCheckRollup": []
    });
    let expected = github_source_guard_from_value(
        "github.example",
        "github.example/acme/repo",
        &stable_external_digest(b"source-repo"),
        ExternalSourceObjectKind::PullRequest,
        &original,
    )
    .expect("original guard");
    let mut volatile = original.clone();
    volatile["updatedAt"] = serde_json::json!("2026-07-13T00:01:00Z");
    volatile["statusCheckRollup"] = serde_json::json!([{"name": "maco", "status": "SUCCESS"}]);
    let volatile_guard = github_source_guard_from_value(
        "github.example",
        "github.example/acme/repo",
        &stable_external_digest(b"source-repo"),
        ExternalSourceObjectKind::PullRequest,
        &volatile,
    )
    .expect("volatile guard");
    assert_ne!(expected.provenance_digest, volatile_guard.provenance_digest);
    assert_eq!(
        expected.action_revision_digest,
        volatile_guard.action_revision_digest
    );
    assert!(revalidate_external_source_value(&expected, &volatile).is_err());

    let mut forked = original.clone();
    forked["headRepository"] = serde_json::json!({"nameWithOwner": "contributor/repo"});
    forked["isCrossRepository"] = serde_json::json!(true);
    let forked_guard = github_source_guard_from_value(
        "github.example",
        "github.example/acme/repo",
        &stable_external_digest(b"source-repo"),
        ExternalSourceObjectKind::PullRequest,
        &forked,
    )
    .expect("forked guard");
    assert_ne!(
        expected.action_revision_digest,
        forked_guard.action_revision_digest
    );

    let mut changed = volatile;
    changed["title"] = serde_json::json!("changed title");
    let changed_guard = github_source_guard_from_value(
        "github.example",
        "github.example/acme/repo",
        &stable_external_digest(b"source-repo"),
        ExternalSourceObjectKind::PullRequest,
        &changed,
    )
    .expect("changed guard");
    assert_ne!(
        expected.action_revision_digest,
        changed_guard.action_revision_digest
    );
}

#[test]
fn github_source_guard_requires_exact_typed_fields_and_only_documented_nulls() {
    let valid = serde_json::json!({
        "number": 7,
        "title": "title",
        "body": "",
        "url": "https://github.example/acme/repo/pull/7",
        "author": null,
        "labels": [],
        "updatedAt": "2026-07-13T00:00:00Z",
        "state": "OPEN",
        "headRefName": "feature",
        "baseRefName": "main",
        "headRefOid": "1".repeat(40),
        "baseRefOid": "2".repeat(40),
        "isDraft": false,
        "headRepository": {"nameWithOwner": "acme/repo"},
        "isCrossRepository": false,
        "files": [],
        "reviewDecision": null,
        "latestReviews": [],
        "statusCheckRollup": []
    });
    let parse = |value: &serde_json::Value| {
        github_source_guard_from_value(
            "github.example",
            "github.example/acme/repo",
            &stable_external_digest(b"strict-source-repository"),
            ExternalSourceObjectKind::PullRequest,
            value,
        )
    };
    parse(&valid).expect("documented explicit nulls");

    for field in [
        "number",
        "title",
        "body",
        "url",
        "author",
        "labels",
        "updatedAt",
        "state",
        "headRefName",
        "baseRefName",
        "headRefOid",
        "baseRefOid",
        "isDraft",
        "headRepository",
        "isCrossRepository",
        "files",
        "reviewDecision",
        "latestReviews",
        "statusCheckRollup",
    ] {
        let mut missing = valid.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(parse(&missing).is_err(), "missing {field} was accepted");
    }
    for (field, wrong) in [
        ("body", serde_json::json!(null)),
        ("author", serde_json::json!("reviewer")),
        ("labels", serde_json::json!(null)),
        ("labels", serde_json::json!([null])),
        ("isDraft", serde_json::json!(null)),
        ("headRepository", serde_json::json!("acme/repo")),
        ("isCrossRepository", serde_json::json!(null)),
        ("files", serde_json::json!({})),
        ("files", serde_json::json!([null])),
        ("reviewDecision", serde_json::json!(false)),
        ("latestReviews", serde_json::json!(null)),
        ("latestReviews", serde_json::json!([null])),
        ("statusCheckRollup", serde_json::json!({})),
        ("statusCheckRollup", serde_json::json!([null])),
    ] {
        let mut malformed = valid.clone();
        malformed[field] = wrong;
        assert!(
            parse(&malformed).is_err(),
            "wrong type for {field} was accepted"
        );
    }
}

#[test]
fn github_issue_effect_contract_rejects_closed_or_mutated_remote() {
    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "acme".to_string(),
        name: "repo".to_string(),
    };
    let provider = GithubIssueExternalEffectProvider {
            worktree_path: Path::new("."),
            repository: &repository,
            title: "title",
            marked_body: "body\n\n<!-- maco-external-effect:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -->".to_string(),
            labels: &["bug".to_string()],
            expected_author: "publisher",
        };
    let exact = GithubIssueEffectObserved {
        number: 7,
        url: "https://github.example/acme/repo/issues/7".to_string(),
        title: "title".to_string(),
        body: provider.marked_body.clone(),
        labels: vec!["bug".to_string()],
        author: "publisher".to_string(),
        state: "OPEN".to_string(),
    };
    assert!(provider.matches_contract(&exact).expect("exact issue"));
    let mut closed = exact.clone();
    closed.state = "CLOSED".to_string();
    assert!(!provider.matches_contract(&closed).expect("closed issue"));
    let mut wrong_url_number = exact.clone();
    wrong_url_number.url = "https://github.example/acme/repo/issues/8".to_string();
    assert!(provider.matches_contract(&wrong_url_number).is_err());
    let mut mutated = exact;
    mutated.body.push_str("mutated");
    assert!(!provider.matches_contract(&mutated).expect("mutated issue"));

    let over_limit = serde_json::Value::Array(
        std::iter::repeat_n(
            serde_json::json!({
                "number": 7,
                "url": "https://github.example/acme/repo/issues/7",
                "title": "title",
                "body": provider.marked_body,
                "labels": [{"name": "bug"}],
                "author": {"login": "publisher"},
                "state": "OPEN"
            }),
            MAX_GITHUB_EFFECT_CANDIDATES + 1,
        )
        .collect(),
    );
    assert!(github_issue_effect_list_from_json(&over_limit).is_err());
}

#[test]
fn github_comment_paginated_parser_finds_candidates_after_first_hundred() {
    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "acme".to_string(),
        name: "repo".to_string(),
    };
    let source = ExternalSourceGuard::new(
        "github",
        "github.example",
        "github.example/acme/repo",
        stable_external_digest(b"paginated-comment-source"),
        ExternalSourceObjectKind::Issue,
        7,
        "2026-07-13T00:00:00Z",
        "OPEN",
        None,
        None,
        "1".repeat(64),
        "2".repeat(64),
    )
    .expect("comment source guard");
    let page_one = (1_u64..=100)
        .map(|id| {
            serde_json::json!({
                "id": id,
                "html_url": format!("https://github.example/acme/repo/issues/7#issuecomment-{id}"),
                "body": format!("ordinary comment {id}"),
                "user": {"login": "publisher"}
            })
        })
        .collect::<Vec<_>>();
    let marker = "<!-- maco-external-effect:v2:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa -->";
    let pages = serde_json::json!([
        page_one,
        [{
            "id": 101,
            "html_url": "https://github.example/acme/repo/issues/7#issuecomment-101",
            "body": marker,
            "user": {"login": "publisher"}
        }]
    ]);
    let comments = github_comment_candidates_from_slurped_json(&pages, &repository, &source)
        .expect("parse all comment pages");
    assert_eq!(comments.len(), 101);
    assert_eq!(comments.last().expect("last comment").body, marker);

    let mismatched_id = serde_json::json!([[{
        "id": 102,
        "html_url": "https://github.example/acme/repo/issues/7#issuecomment-103",
        "body": marker,
        "user": {"login": "publisher"}
    }]]);
    assert!(
        github_comment_candidates_from_slurped_json(&mismatched_id, &repository, &source).is_err()
    );

    let too_many_pages = serde_json::Value::Array(
        std::iter::repeat_n(serde_json::json!([]), MAX_GITHUB_COMMENT_PAGES + 1).collect(),
    );
    assert!(
        github_comment_candidates_from_slurped_json(&too_many_pages, &repository, &source).is_err()
    );
}

#[test]
fn legacy_plaintext_publication_journal_requires_explicit_migration_without_mutation() {
    let repo = fake_effect_repo();
    let repository = crate::git_repository::open(repo.path()).expect("open legacy test repo");
    let legacy_root = repository
        .commondir()
        .join("maco/state/publication-transactions/legacy");
    fs::create_dir_all(&legacy_root).expect("create legacy journal directory");
    let legacy_record = legacy_root.join("00000000000000000001.json");
    fs::write(&legacy_record, b"legacy plaintext must remain untouched\n")
        .expect("write legacy record");
    let error = refuse_legacy_publication_journals(&repository)
        .expect_err("legacy journal must require migration");
    assert!(error.to_string().contains("explicit signed migration"));
    assert!(error.to_string().contains("maco state migrate"));
    assert_eq!(
        fs::read(&legacy_record).expect("legacy record remains"),
        b"legacy plaintext must remain untouched\n"
    );
}

#[cfg(unix)]
#[test]
fn signed_state_migration_unblocks_legacy_publication_journals_without_deleting_them() {
    let repo = fake_effect_repo();
    let repository = crate::git_repository::open(repo.path()).expect("open legacy test repo");
    let legacy_root = repository
        .commondir()
        .join("maco/state/publication-transactions/legacy");
    fs::create_dir_all(&legacy_root).expect("create legacy journal directory");
    let legacy_record = legacy_root.join("00000000000000000001.json");
    fs::write(&legacy_record, b"legacy plaintext must remain untouched\n")
        .expect("write legacy record");

    refuse_legacy_publication_journals(&repository)
        .expect_err("unsigned leftover journals must still refuse");

    let applied = crate::state_migration::migrate_repository_state(repo.path(), true)
        .expect("signed migration of leftover publication journals");
    assert_eq!(
        applied.status,
        crate::state_migration::StateMigrationStatus::Applied
    );

    refuse_legacy_publication_journals(&repository)
        .expect("signed migration must unblock authenticated external effects");
    assert_eq!(
        fs::read(&legacy_record).expect("legacy record remains after retirement"),
        b"legacy plaintext must remain untouched\n"
    );
}

#[test]
fn prepared_change_kinds_allow_only_untracked_to_added_transition() {
    let untracked = vec![merge::ChangedPath {
        path: PathBuf::from("new.txt"),
        kind: merge::ChangeKind::Untracked,
    }];
    let added = vec![merge::ChangedPath {
        path: PathBuf::from("new.txt"),
        kind: merge::ChangeKind::Added,
    }];
    let changed_path = vec![merge::ChangedPath {
        path: PathBuf::from("other.txt"),
        kind: merge::ChangeKind::Added,
    }];

    assert!(prepared_change_kinds_match(&untracked, &added));
    assert!(!prepared_change_kinds_match(&added, &untracked));
    assert!(!prepared_change_kinds_match(&untracked, &changed_path));
}

#[cfg(target_os = "linux")]
fn create_publication_lease_fixture(
    root: &Path,
) -> (PathBuf, WorktreeManager, WorktreeRecord, WorktreeRecord) {
    let repo_path = root.join("repo");
    let worktree_root = root.join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repository");
    fs::write(repo_path.join("README.md"), "# Publication fixture\n")
        .expect("write fixture README");
    let repo = crate::git_repository::open(&repo_path).expect("open fixture repository");
    let mut config = repo.config().expect("open fixture config");
    config
        .set_str("user.name", "maco test")
        .expect("configure test name");
    config
        .set_str("user.email", "maco-test@example.invalid")
        .expect("configure test email");
    drop(config);
    let mut index = repo.index().expect("open fixture index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage fixture README");
    index.write().expect("write fixture index");
    let tree_id = index.write_tree().expect("write fixture tree");
    let tree = repo.find_tree(tree_id).expect("find fixture tree");
    let signature =
        git2::Signature::now("maco test", "maco-test@example.invalid").expect("fixture signature");
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
            worktree_root: Some(worktree_root.clone()),
        })
        .expect("create agent-a worktree");
    let agent_b = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-b".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root),
        })
        .expect("create agent-b worktree");
    (repo_path, manager, agent_a, agent_b)
}

#[cfg(target_os = "linux")]
fn fake_publication_options(repo: &Path, agent_id: &str) -> PrPublicationOptions {
    PrPublicationOptions {
        repo: repo.to_path_buf(),
        agent_id: agent_id.to_string(),
        claimed_paths: vec![PathBuf::from("README.md")],
        validations: Vec::new(),
        forge: ForgeKind::Fake,
        draft: true,
        from_branch: None,
        squash_onto: None,
        exclude_paths: Vec::new(),
    }
}

#[cfg(target_os = "linux")]
fn commit_agent_readme(worktree: &Path, contents: &str, message: &str) -> Oid {
    fs::write(worktree.join("README.md"), contents).expect("write committed README");
    let repo = crate::git_repository::open(worktree).expect("open agent repository");
    let mut index = repo.index().expect("open agent index");
    index
        .add_path(Path::new("README.md"))
        .expect("stage agent README");
    index.write().expect("write agent index");
    let tree_id = index.write_tree().expect("write agent tree");
    let tree = repo.find_tree(tree_id).expect("find agent tree");
    let parent = repo
        .head()
        .expect("agent HEAD")
        .peel_to_commit()
        .expect("agent parent commit");
    let signature = repo.signature().expect("agent signature");
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &[&parent],
    )
    .expect("commit agent README")
}

#[cfg(target_os = "linux")]
fn passed_prepared_validation() -> ValidationReport {
    ValidationReport {
        name: "prepared-unit".to_string(),
        status: merge::ValidationStatus::Passed,
        message: None,
        paths: vec![PathBuf::from("README.md")],
    }
}

#[cfg(target_os = "linux")]
fn publication_transactions_path(repo: &Path) -> PathBuf {
    repo.join(".git/maco/state/publication-transactions")
}

#[cfg(target_os = "linux")]
fn reset_fake_pr_url_calls() {
    FAKE_PR_URL_CALLS.with(|calls| calls.set(0));
}

#[cfg(target_os = "linux")]
fn fake_pr_url_calls() -> usize {
    FAKE_PR_URL_CALLS.with(std::cell::Cell::get)
}

#[cfg(target_os = "linux")]
#[test]
fn prepare_dirty_candidate_commits_exact_content_without_external_effects() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
    fs::write(agent_a.path.join("README.md"), "# Prepared dirty\n").expect("edit dirty candidate");
    let before_head = crate::git_repository::open(&agent_a.path)
        .expect("open agent repository")
        .head()
        .expect("agent HEAD")
        .target()
        .expect("direct agent HEAD");
    let write_lease = manager
        .acquire_write_execution_lease("agent-a")
        .expect("publication write lease");
    let options = fake_publication_options(&repo_path, "agent-a");
    reset_fake_pr_url_calls();

    let prepared = prepare_pr_candidate_with_write_lease(options, &write_lease)
        .expect("prepare dirty candidate");

    assert_eq!(prepared.status, PrPublicationStatus::Preview);
    assert!(!prepared.pushed);
    assert!(!prepared.created);
    assert!(prepared.pr_url.is_none());
    assert!(prepared.publication_receipt.is_none());
    let prepared_commit = prepared.commit_id.as_deref().expect("prepared commit id");
    assert_ne!(prepared_commit, before_head.to_string());
    assert_eq!(prepared.head_id.as_deref(), Some(prepared_commit));
    assert_eq!(
        prepared
            .preview
            .candidate
            .validation_binding
            .agent_head
            .as_deref(),
        Some(prepared_commit)
    );
    assert!(!has_uncommitted_changes(&agent_a.path).expect("clean prepared worktree"));
    assert!(!publication_transactions_path(&repo_path).exists());
    assert_eq!(fake_pr_url_calls(), 0);
}

#[cfg(target_os = "linux")]
#[test]
fn prepare_already_clean_candidate_preserves_existing_commit() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
    let existing = commit_agent_readme(&agent_a.path, "# Already clean\n", "clean candidate");
    let write_lease = manager
        .acquire_write_execution_lease("agent-a")
        .expect("publication write lease");
    let mut options = fake_publication_options(&repo_path, "agent-a");
    options.forge = ForgeKind::Github;

    let prepared = prepare_pr_candidate_with_write_lease(options, &write_lease)
        .expect("prepare clean candidate without invoking GitHub");

    assert_eq!(prepared.status, PrPublicationStatus::Preview);
    assert_eq!(
        prepared.commit_id.as_deref(),
        Some(existing.to_string()).as_deref()
    );
    assert_eq!(prepared.head_id, prepared.commit_id);
    assert!(!has_uncommitted_changes(&agent_a.path).expect("clean candidate remains clean"));
    assert!(!publication_transactions_path(&repo_path).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn prepare_refuses_drift_before_creating_local_commit() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
    fs::write(agent_a.path.join("README.md"), "# Reviewed candidate\n")
        .expect("write reviewed candidate");
    let before_head = crate::git_repository::open(&agent_a.path)
        .expect("open agent repository")
        .head()
        .expect("agent HEAD")
        .target()
        .expect("direct agent HEAD");
    let write_lease = manager
        .acquire_write_execution_lease("agent-a")
        .expect("publication write lease");
    let drift_path = agent_a.path.join("README.md");

    let error = prepare_pr_candidate_with_write_lease_after_preview(
        fake_publication_options(&repo_path, "agent-a"),
        &write_lease,
        move |_| {
            fs::write(drift_path, "# Drifted candidate\n").expect("inject candidate drift");
        },
    )
    .expect_err("candidate drift must fail preparation");

    assert!(error
        .to_string()
        .contains("changed before candidate preparation"));
    assert_eq!(
        crate::git_repository::open(&agent_a.path)
            .expect("reopen agent repository")
            .head()
            .expect("agent HEAD after drift")
            .target(),
        Some(before_head)
    );
    assert!(!publication_transactions_path(&repo_path).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn strict_prepared_publish_blocks_candidate_drift_before_effects() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
    fs::write(agent_a.path.join("README.md"), "# Prepared candidate\n")
        .expect("write prepared candidate");
    let write_lease = manager
        .acquire_write_execution_lease("agent-a")
        .expect("publication write lease");
    let prepared = prepare_pr_candidate_with_write_lease(
        fake_publication_options(&repo_path, "agent-a"),
        &write_lease,
    )
    .expect("prepare candidate");
    let bound = ValidationEvidenceBundle::bound_to(
        prepared.preview.candidate.validation_binding.clone(),
        vec![passed_prepared_validation()],
    )
    .expect("bind prepared validation");
    commit_agent_readme(&agent_a.path, "# Later reviewed drift\n", "candidate drift");
    let mut options = fake_publication_options(&repo_path, "agent-a");
    options.forge = ForgeKind::Github;

    let report = publish_prepared_pr_with_write_lease(options, &bound, &write_lease)
        .expect("strict publication reports candidate mismatch");

    assert_eq!(report.status, PrPublicationStatus::Blocked);
    assert_eq!(
        report.preview.safety.validation_evidence.binding_status,
        merge::ValidationBindingStatus::Mismatched
    );
    assert!(!report.pushed);
    assert!(!report.created);
    assert!(report.pr_url.is_none());
    assert!(!publication_transactions_path(&repo_path).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn strict_prepared_publish_accepts_matching_bound_evidence() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
    fs::write(agent_a.path.join("README.md"), "# Matching candidate\n")
        .expect("write matching candidate");
    let write_lease = manager
        .acquire_write_execution_lease("agent-a")
        .expect("publication write lease");
    let options = fake_publication_options(&repo_path, "agent-a");
    let prepared = prepare_pr_candidate_with_write_lease(options.clone(), &write_lease)
        .expect("prepare matching candidate");
    let bound = ValidationEvidenceBundle::bound_to(
        prepared.preview.candidate.validation_binding.clone(),
        vec![passed_prepared_validation()],
    )
    .expect("bind matching validation");
    reset_fake_pr_url_calls();

    let report = publish_prepared_pr_with_write_lease(options, &bound, &write_lease)
        .expect("publish matching prepared candidate");

    assert_eq!(report.status, PrPublicationStatus::Published);
    assert_eq!(
        report.preview.safety.validation_evidence.binding_status,
        merge::ValidationBindingStatus::Bound
    );
    assert!(report.created);
    assert!(!report.pushed);
    assert_eq!(fake_pr_url_calls(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn prepare_holds_and_releases_worktree_and_repository_locks() {
    skip_without_containment!();
    enum PreparationEvent {
        LocksHeld,
        Completed(Box<Result<PrPublicationReport>>),
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, agent_b) = create_publication_lease_fixture(temp.path());
    fs::write(agent_a.path.join("README.md"), "# Lock candidate\n").expect("write lock candidate");
    let (event_tx, event_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let publisher_repo = repo_path.clone();
    let publisher_manager = manager.clone();
    let publisher = std::thread::spawn(move || {
        let write_lease = publisher_manager
            .acquire_write_execution_lease("agent-a")
            .expect("publisher write lease");
        let result = prepare_pr_candidate_with_write_lease_after_preview(
            fake_publication_options(&publisher_repo, "agent-a"),
            &write_lease,
            |_| {
                event_tx
                    .send(PreparationEvent::LocksHeld)
                    .expect("signal held preparation locks");
                recv_test_event(&release_rx, "release preparation locks");
            },
        );
        let _ = event_tx.send(PreparationEvent::Completed(Box::new(result)));
    });

    match recv_test_event(&event_rx, "observe preparation lifecycle") {
        PreparationEvent::LocksHeld => {}
        PreparationEvent::Completed(result) => {
            panic!("preparation completed before the strict pre-publication lock point: {result:?}")
        }
    }
    manager
        .acquire_read_execution_lease("agent-a")
        .expect_err("preparation writer excludes readers");
    manager
        .acquire_write_execution_lease("agent-a")
        .expect_err("preparation writer excludes writers");
    manager
        .remove("agent-a", true, false)
        .expect_err("preparation writer excludes removal");
    match RepoCommonLock::acquire(&repo_path, "merge-apply") {
        Ok(_) => panic!("preparation must retain repository mutation lock"),
        Err(error) => assert!(format!("{error:#}").contains("kernel lock is held")),
    }
    let unrelated = manager
        .acquire_write_execution_lease("agent-b")
        .expect("unrelated worktree remains available");
    assert_eq!(unrelated.path(), agent_b.path);
    drop(unrelated);

    release_tx.send(()).expect("release preparation");
    match recv_test_event(&event_rx, "observe preparation completion") {
        PreparationEvent::Completed(result) => {
            (*result).expect("complete preparation");
        }
        PreparationEvent::LocksHeld => panic!("preparation published its lock point twice"),
    }
    publisher.join().expect("join preparation");
    drop(
        manager
            .acquire_read_execution_lease("agent-a")
            .expect("preparation releases worktree lock"),
    );
    drop(
        RepoCommonLock::acquire(&repo_path, "merge-apply")
            .expect("preparation releases repository lock"),
    );
}

#[cfg(target_os = "linux")]
#[test]
fn borrowed_write_lease_publishes_without_nested_read_lease() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
    fs::write(agent_a.path.join("README.md"), "# Borrowed authority\n")
        .expect("edit agent worktree");
    let write_lease = manager
        .acquire_write_execution_lease("agent-a")
        .expect("caller-held write lease");

    let report = publish_pr_with_write_lease(
        fake_publication_options(&repo_path, "agent-a"),
        &write_lease,
    )
    .expect("publish beneath caller-held write lease");

    assert_eq!(report.status, PrPublicationStatus::Published);
    assert!(report.created);
    assert_eq!(write_lease.record().name, "agent-a");
    manager
        .acquire_read_execution_lease("agent-a")
        .expect_err("caller retains write authority after publication returns");
}

#[cfg(target_os = "linux")]
#[test]
fn standalone_publish_excludes_same_worktree_for_full_lifecycle() {
    skip_without_containment!();
    enum PublicationEvent {
        LocksHeld,
        Completed(Box<Result<PrPublicationReport>>),
    }

    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, agent_b) = create_publication_lease_fixture(temp.path());
    fs::write(agent_a.path.join("README.md"), "# Lifecycle authority\n")
        .expect("edit agent worktree");
    let (event_tx, event_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let publish_repo = repo_path.clone();
    let publisher = std::thread::spawn(move || {
        let result = publish_pr_with_validation_evidence_after_lock(
            fake_publication_options(&publish_repo, "agent-a"),
            false,
            ValidationEvidenceBundle::default(),
            || {
                event_tx
                    .send(PublicationEvent::LocksHeld)
                    .expect("signal held publication locks");
                recv_test_event(&release_rx, "release publication");
            },
        );
        let _ = event_tx.send(PublicationEvent::Completed(Box::new(result)));
    });

    match recv_test_event(&event_rx, "observe publication lifecycle") {
        PublicationEvent::LocksHeld => {}
        PublicationEvent::Completed(result) => {
            panic!("publication completed before its lifecycle lock point: {result:?}")
        }
    }
    manager
        .acquire_read_execution_lease("agent-a")
        .expect_err("publication writer excludes concurrent reader");
    manager
        .acquire_write_execution_lease("agent-a")
        .expect_err("publication writer excludes concurrent writer");
    let removal_error = manager
        .remove("agent-a", true, false)
        .expect_err("publication writer excludes managed removal");
    assert!(removal_error
        .to_string()
        .contains("active cooperative execution lease"));
    match RepoCommonLock::acquire(&repo_path, "merge-apply") {
        Ok(_) => panic!("publication must hold repository mutation lock"),
        Err(error) => assert!(format!("{error:#}").contains("kernel lock is held")),
    }

    let unrelated = manager
        .acquire_write_execution_lease("agent-b")
        .expect("unrelated worktree remains available");
    assert_eq!(unrelated.path(), agent_b.path);
    drop(unrelated);

    release_tx.send(()).expect("release publication lifecycle");
    let report = match recv_test_event(&event_rx, "observe publication completion") {
        PublicationEvent::Completed(result) => (*result).expect("complete fake publication"),
        PublicationEvent::LocksHeld => panic!("publication published its lock point twice"),
    };
    publisher.join().expect("join publisher");
    assert_eq!(report.status, PrPublicationStatus::Published);
    drop(
        manager
            .acquire_read_execution_lease("agent-a")
            .expect("publication releases worktree lease on return"),
    );
    drop(
        RepoCommonLock::acquire(&repo_path, "merge-apply")
            .expect("publication releases repository lock on return"),
    );
}

#[cfg(target_os = "linux")]
#[test]
fn borrowed_publication_rejects_agent_and_repository_mismatch() {
    let first = tempfile::tempdir().expect("first tempdir");
    let second = tempfile::tempdir().expect("second tempdir");
    let (first_repo, first_manager, _, _) = create_publication_lease_fixture(first.path());
    let (second_repo, _, _, _) = create_publication_lease_fixture(second.path());
    let write_lease = first_manager
        .acquire_write_execution_lease("agent-a")
        .expect("first repository write lease");

    let agent_error = preview_pr_with_validation_evidence_and_write_lease(
        fake_publication_options(&first_repo, "agent-b"),
        false,
        ValidationEvidenceBundle::default(),
        &write_lease,
    )
    .expect_err("lease for another agent must be rejected");
    assert!(agent_error
        .to_string()
        .contains("belongs to agent 'agent-a'"));

    let repo_error = publish_pr_with_write_lease(
        fake_publication_options(&second_repo, "agent-a"),
        &write_lease,
    )
    .expect_err("lease for another repository must be rejected");
    assert!(repo_error
        .to_string()
        .contains("different managed repository"));
}

#[cfg(target_os = "linux")]
#[test]
fn standalone_publication_error_releases_both_locks() {
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
    fs::write(agent_a.path.join("README.md"), "# Invalid claim\n").expect("edit agent worktree");
    let mut options = fake_publication_options(&repo_path, "agent-a");
    options.claimed_paths = vec![PathBuf::from("../escape")];

    publish_pr_with_validation_evidence(options, false, ValidationEvidenceBundle::default())
        .expect_err("invalid claim must fail publication");

    drop(
        manager
            .acquire_read_execution_lease("agent-a")
            .expect("error releases standalone write lease"),
    );
    drop(
        RepoCommonLock::acquire(&repo_path, "merge-apply")
            .expect("error releases repository mutation lock"),
    );
}

#[cfg(target_os = "linux")]
#[test]
fn standalone_preview_coexists_with_reader_and_does_not_commit() {
    skip_without_containment!();
    let temp = tempfile::tempdir().expect("tempdir");
    let (repo_path, manager, agent_a, _) = create_publication_lease_fixture(temp.path());
    fs::write(agent_a.path.join("README.md"), "# Shared preview\n").expect("edit agent worktree");
    let agent_repo = crate::git_repository::open(&agent_a.path).expect("open agent repository");
    let before_head = agent_repo
        .head()
        .expect("agent HEAD")
        .target()
        .expect("direct agent HEAD");
    let existing_reader = manager
        .acquire_read_execution_lease("agent-a")
        .expect("existing shared reader");

    // This deliberately remains a real-process integration test: preview must traverse the
    // isolated Git snapshot path while a reader is held. That path has a 120-second command
    // margin. Expiry means the host could not complete one local Git snapshot command inside
    // that wide bound; it is not interpreted as a publication-lock ordering failure.
    let report = preview_pr_with_validation_evidence(
        fake_publication_options(&repo_path, "agent-a"),
        false,
        ValidationEvidenceBundle::default(),
    )
    .expect("standalone preview shares immutable authority");

    assert_eq!(report.status, PrPublicationStatus::Preview);
    assert_eq!(
        agent_repo
            .head()
            .expect("agent HEAD after preview")
            .target()
            .expect("direct agent HEAD after preview"),
        before_head
    );
    assert!(has_uncommitted_changes(&agent_a.path).expect("dirty preview worktree"));
    manager
        .acquire_write_execution_lease("agent-a")
        .expect_err("existing reader remains held after shared preview");
    drop(existing_reader);
}

fn test_publication_pr_marker() -> String {
    "ab".repeat(PUBLICATION_PR_MARKER_BYTES)
}

fn test_publication_pr_body() -> String {
    pr_body_with_publication_marker("test publication body", &test_publication_pr_marker())
        .expect("marker-bound test PR body")
}

fn enterprise_test_value(host: &str, key: &str) -> Option<String> {
    match key {
        "GH_HOST" => Some(host.to_string()),
        "GH_ENTERPRISE_TOKEN" => Some("test-token".to_string()),
        _ => None,
    }
}

fn test_observe_operation() -> PublicationGitOperation {
    PublicationGitOperation::observe("refs/heads/test").expect("test observation operation")
}

fn completed_github_journal(sequence: u64) -> PublicationTransactionJournal {
    let marker = test_publication_pr_marker();
    let body = test_publication_pr_body();
    PublicationTransactionJournal {
        version: PUBLICATION_JOURNAL_VERSION,
        transaction_id: "completed-test-transaction".to_string(),
        sequence,
        agent_id: "agent-a".to_string(),
        forge: ForgeKind::Github,
        expected_oid: "1111111111111111111111111111111111111111".to_string(),
        expected_base_oid: Some("3333333333333333333333333333333333333333".to_string()),
        remote_name: "origin".to_string(),
        remote_binding_digest: "2222222222222222222222222222222222222222".to_string(),
        remote_display: "https://example.invalid/owner/repo.git".to_string(),
        remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
        remote_branch: "maco/review/agent-a/test".to_string(),
        github_repository: Some(GithubRepositoryIdentity {
            host: "example.invalid".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        }),
        pr_marker_nonce: Some(marker),
        expected_pr_title: Some("Agent agent-a changes".to_string()),
        expected_pr_body: Some(body.clone()),
        expected_pr_author: Some("publisher".to_string()),
        base: "main".to_string(),
        draft: true,
        phase: PublicationTransactionPhase::Completed,
        push_observed_oid: Some("1111111111111111111111111111111111111111".to_string()),
        pr_url: Some("https://example.invalid/owner/repo/pull/7".to_string()),
        pr_head_oid: Some("1111111111111111111111111111111111111111".to_string()),
        pr_base: Some("main".to_string()),
        pr_state: Some("OPEN".to_string()),
        pr_is_draft: Some(true),
        pr_number: Some(7),
        pr_title: Some("Agent agent-a changes".to_string()),
        pr_body: Some(body),
        pr_head_ref_name: Some("maco/review/agent-a/test".to_string()),
        pr_head_repository_owner: Some("owner".to_string()),
        pr_head_repository_name: Some("repo".to_string()),
        pr_is_cross_repository: Some(false),
        pr_author: Some("publisher".to_string()),
        create_attempted: true,
        created_by_transaction: true,
        observed_existing_pr: false,
        last_error: None,
        updated_unix_seconds: sequence,
    }
}

fn prepared_github_transaction(directory: &Path, create_attempted: bool) -> PublicationTransaction {
    let mut journal = completed_github_journal(0);
    journal.transaction_id = "prepared-test-transaction".to_string();
    journal.phase = PublicationTransactionPhase::PushObserved;
    journal.pr_url = None;
    journal.pr_head_oid = None;
    journal.pr_base = None;
    journal.pr_state = None;
    journal.pr_is_draft = None;
    journal.pr_number = None;
    journal.pr_title = None;
    journal.pr_body = None;
    journal.pr_head_ref_name = None;
    journal.pr_head_repository_owner = None;
    journal.pr_head_repository_name = None;
    journal.pr_is_cross_repository = None;
    journal.pr_author = None;
    journal.create_attempted = create_attempted;
    journal.created_by_transaction = false;
    journal.observed_existing_pr = false;
    PublicationTransaction {
        directory: directory.to_path_buf(),
        journal,
        remote_url: "https://example.invalid/owner/repo.git".to_string(),
        push_effect_request: None,
        pr_effect_request: None,
    }
}

fn exact_github_receipt(journal: &PublicationTransactionJournal) -> GithubPrResult {
    GithubPrResult {
        url: "https://example.invalid/owner/repo/pull/7".to_string(),
        head_oid: journal.expected_oid.clone(),
        base_oid: journal.expected_base_oid.clone().expect("base oid"),
        number: 7,
        base_ref_name: journal.base.clone(),
        state: "OPEN".to_string(),
        is_draft: journal.draft,
        title: journal.expected_pr_title.clone().expect("expected title"),
        body: journal.expected_pr_body.clone().expect("expected body"),
        head_ref_name: journal.remote_branch.clone(),
        head_repository_owner: "owner".to_string(),
        head_repository_name: "repo".to_string(),
        is_cross_repository: false,
        author: journal.expected_pr_author.clone().expect("expected author"),
        created: false,
    }
}

struct ScriptedGithubApi {
    lists: std::collections::VecDeque<Vec<GithubPrResult>>,
    views: std::collections::VecDeque<GithubPrResult>,
    create_output: Option<GithubCreateOutput>,
    create_calls: usize,
    created_title: Option<String>,
    created_body: Option<String>,
}

impl ScriptedGithubApi {
    fn new(
        lists: impl IntoIterator<Item = Vec<GithubPrResult>>,
        views: impl IntoIterator<Item = GithubPrResult>,
    ) -> Self {
        Self {
            lists: lists.into_iter().collect(),
            views: views.into_iter().collect(),
            create_output: Some(GithubCreateOutput {
                stdout: Vec::new(),
                stderr: Vec::new(),
            }),
            create_calls: 0,
            created_title: None,
            created_body: None,
        }
    }
}

impl GithubApi for ScriptedGithubApi {
    fn list(
        &mut self,
        _worktree_path: &Path,
        _branch: &str,
        _repository: &GithubRepositoryIdentity,
    ) -> Result<Vec<GithubPrResult>> {
        self.lists
            .pop_front()
            .context("scripted GitHub API omitted a list response")
    }

    fn view(
        &mut self,
        _worktree_path: &Path,
        _selector: &str,
        _repository: &GithubRepositoryIdentity,
    ) -> Result<GithubPrResult> {
        self.views
            .pop_front()
            .context("scripted GitHub API omitted a view response")
    }

    fn create(
        &mut self,
        _worktree_path: &Path,
        _branch: &str,
        _base: &str,
        title: &str,
        body: &str,
        _draft: bool,
        _repository: &GithubRepositoryIdentity,
    ) -> Result<GithubCreateOutput> {
        self.create_calls += 1;
        self.created_title = Some(title.to_string());
        self.created_body = Some(body.to_string());
        self.create_output
            .take()
            .context("scripted GitHub API omitted a create response")
    }
}

#[test]
fn github_reconciliation_rejects_preexisting_branch_pr_as_a_front_run() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut transaction = prepared_github_transaction(temp.path(), false);
    let receipt = exact_github_receipt(&transaction.journal);
    let mut api = ScriptedGithubApi::new([vec![receipt]], []);
    let error = reconcile_github_pr_with_api_and_remote_check(
        temp.path(),
        &mut transaction,
        &mut api,
        |_, _, _| Ok(()),
    )
    .expect_err("a PR predating the create intent must fail closed");
    assert!(error.to_string().contains("front-run"));
    assert_eq!(api.create_calls, 0);
    assert!(!transaction.journal.create_attempted);
    assert!(transaction.journal.pr_url.is_none());
}

#[test]
fn github_crash_reconciliation_accepts_only_exact_marker_and_provenance() {
    let wrong = tempfile::tempdir().expect("wrong tempdir");
    let mut wrong_transaction = prepared_github_transaction(wrong.path(), true);
    let mut wrong_receipt = exact_github_receipt(&wrong_transaction.journal);
    wrong_receipt.body = pr_body_with_publication_marker(
        "test publication body",
        &"cd".repeat(PUBLICATION_PR_MARKER_BYTES),
    )
    .expect("different marker body");
    let mut wrong_api = ScriptedGithubApi::new([vec![wrong_receipt.clone()]], [wrong_receipt]);
    let error = reconcile_github_pr_with_api_and_remote_check(
        wrong.path(),
        &mut wrong_transaction,
        &mut wrong_api,
        |_, _, _| Ok(()),
    )
    .expect_err("a different marker must never be adopted after a crash");
    assert!(error.to_string().contains("marker-bound"));
    assert!(wrong_transaction.journal.pr_url.is_none());

    let exact = tempfile::tempdir().expect("exact tempdir");
    let exact_journal = exact.path().join("journal");
    merge::create_private_directory(&exact_journal).expect("exact journal directory");
    let mut exact_transaction = prepared_github_transaction(&exact_journal, true);
    let exact_receipt = exact_github_receipt(&exact_transaction.journal);
    let mut exact_api = ScriptedGithubApi::new([vec![exact_receipt.clone()]], [exact_receipt]);
    let reconciled = reconcile_github_pr_with_api_and_remote_check(
        exact.path(),
        &mut exact_transaction,
        &mut exact_api,
        |_, _, _| Ok(()),
    )
    .expect("exact marker-bound receipt is the transaction's crash outcome");
    assert!(reconciled.created);
    assert_eq!(exact_api.create_calls, 0);
    assert!(exact_transaction.journal.created_by_transaction);
    assert!(!exact_transaction.journal.observed_existing_pr);
    validate_publication_journal(&exact_transaction.journal)
        .expect("reconciled receipt journal is exact");
}

#[test]
fn github_create_recovery_binds_exact_title_body_author_and_head_repository() {
    let temp = tempfile::tempdir().expect("tempdir");
    let journal_directory = temp.path().join("journal");
    merge::create_private_directory(&journal_directory).expect("journal directory");
    let mut transaction = prepared_github_transaction(&journal_directory, false);
    let receipt = exact_github_receipt(&transaction.journal);
    let mut api = ScriptedGithubApi::new([Vec::new(), vec![receipt.clone()]], [receipt.clone()]);
    let mut remote_checks = 0usize;
    let result = reconcile_github_pr_with_api_and_remote_check(
        temp.path(),
        &mut transaction,
        &mut api,
        |_, _, _| {
            remote_checks += 1;
            Ok(())
        },
    )
    .expect("recover exact receipt after an ambiguous create response");

    assert_eq!(api.create_calls, 1);
    assert_eq!(remote_checks, 3);
    assert_eq!(
        api.created_title.as_deref(),
        transaction.journal.expected_pr_title.as_deref()
    );
    assert_eq!(
        api.created_body.as_deref(),
        transaction.journal.expected_pr_body.as_deref()
    );
    assert_eq!(result.author, "publisher");
    assert_eq!(result.head_repository_owner, "owner");
    assert_eq!(result.head_repository_name, "repo");
    assert!(!result.is_cross_repository);
    assert!(transaction.journal.created_by_transaction);
    validate_publication_journal(&transaction.journal).expect("created receipt journal is exact");
}

fn write_test_journal_record(directory: &Path, journal: &PublicationTransactionJournal) {
    let mut bytes = serde_json::to_vec(journal).expect("serialize test journal");
    bytes.push(b'\n');
    merge::write_private_file(
        &directory.join(format!("{:020}.json", journal.sequence)),
        &bytes,
    )
    .expect("write private test journal");
}

#[test]
fn publication_journal_retains_only_latest_32_of_100_retries() {
    let temp = tempfile::tempdir().expect("tempdir");
    let journal_directory = temp.path().join("journal");
    merge::create_private_directory(&journal_directory).expect("private journal directory");
    let remote_display = "https://example.invalid/repo";
    let remote_binding_digest = "2222222222222222222222222222222222222222".to_string();
    let mut transaction = PublicationTransaction {
        directory: journal_directory.clone(),
        journal: PublicationTransactionJournal {
            version: PUBLICATION_JOURNAL_VERSION,
            transaction_id: "test-transaction".to_string(),
            sequence: 0,
            agent_id: "agent-a".to_string(),
            forge: ForgeKind::Github,
            expected_oid: "1111111111111111111111111111111111111111".to_string(),
            expected_base_oid: Some("3333333333333333333333333333333333333333".to_string()),
            remote_name: "origin".to_string(),
            remote_binding_digest,
            remote_display: remote_display.to_string(),
            remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
            remote_branch: "maco/review/agent-a/test".to_string(),
            github_repository: Some(GithubRepositoryIdentity {
                host: "example.invalid".to_string(),
                owner: "owner".to_string(),
                name: "repo".to_string(),
            }),
            pr_marker_nonce: Some(test_publication_pr_marker()),
            expected_pr_title: Some("Agent agent-a changes".to_string()),
            expected_pr_body: Some(test_publication_pr_body()),
            expected_pr_author: Some("publisher".to_string()),
            base: "main".to_string(),
            draft: true,
            phase: PublicationTransactionPhase::Prepared,
            push_observed_oid: None,
            pr_url: None,
            pr_head_oid: None,
            pr_base: None,
            pr_state: None,
            pr_is_draft: None,
            pr_number: None,
            pr_title: None,
            pr_body: None,
            pr_head_ref_name: None,
            pr_head_repository_owner: None,
            pr_head_repository_name: None,
            pr_is_cross_repository: None,
            pr_author: None,
            create_attempted: false,
            created_by_transaction: false,
            observed_existing_pr: false,
            last_error: None,
            updated_unix_seconds: 0,
        },
        remote_url: "https://example.invalid/owner/repo.git".to_string(),
        push_effect_request: None,
        pr_effect_request: None,
    };

    for retry in 0..100 {
        transaction.journal.last_error = Some(format!("retry {retry}"));
        transaction.persist().expect("persist retry");
    }

    let records = fs::read_dir(&journal_directory)
        .expect("read journal dir")
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().extension().and_then(|ext| ext.to_str()) == Some("json"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 32);
    let latest = load_latest_publication_journal(&journal_directory)
        .expect("load latest")
        .expect("journal exists");
    assert_eq!(latest.sequence, 100);
    assert_eq!(latest.last_error.as_deref(), Some("retry 99"));
    let mut previous = latest.clone();
    previous.phase = PublicationTransactionPhase::PushObserved;
    previous.push_observed_oid = Some(previous.expected_oid.clone());
    let mut regressed = previous.clone();
    regressed.sequence += 1;
    regressed.phase = PublicationTransactionPhase::Prepared;
    assert!(
        validate_publication_journal_transition(&previous, &regressed)
            .expect_err("phase regression must fail")
            .to_string()
            .contains("phase regressed")
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for record in records {
            let mode = record
                .metadata()
                .expect("record metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }
}

#[test]
fn publication_journal_rejects_every_noncanonical_json_record() {
    let temp = tempfile::tempdir().expect("tempdir");
    let journal_directory = temp.path().join("journal");
    merge::create_private_directory(&journal_directory).expect("private journal directory");
    merge::write_private_file(&journal_directory.join("unexpected.json"), b"{}\n")
        .expect("write private unexpected JSON record");

    assert!(load_latest_publication_journal(&journal_directory)
        .expect_err("noncanonical JSON record must fail")
        .to_string()
        .contains("canonical sequence"));
}

#[test]
fn publication_journal_rejects_oversized_hardlinked_and_excess_records() {
    let temp = tempfile::tempdir().expect("tempdir");

    let oversized_directory = temp.path().join("oversized");
    merge::create_private_directory(&oversized_directory)
        .expect("private oversized journal directory");
    let oversized_path = oversized_directory.join("00000000000000000001.json");
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let oversized = options
        .open(&oversized_path)
        .expect("create oversized journal");
    oversized
        .set_len(PUBLICATION_JOURNAL_MAX_RECORD_BYTES + 1)
        .expect("size oversized journal");
    assert!(load_latest_publication_journal(&oversized_directory)
        .expect_err("oversized journal must fail")
        .to_string()
        .contains("invalid size"));

    let linked_directory = temp.path().join("linked");
    merge::create_private_directory(&linked_directory).expect("private linked journal directory");
    let linked_path = linked_directory.join("00000000000000000001.json");
    merge::write_private_file(&linked_path, b"{}\n").expect("write linked journal source");
    fs::hard_link(&linked_path, temp.path().join("journal-hardlink")).expect("link journal record");
    assert!(load_latest_publication_journal(&linked_directory)
        .expect_err("hardlinked journal must fail")
        .to_string()
        .contains("multiple links"));

    let excess_directory = temp.path().join("excess");
    merge::create_private_directory(&excess_directory).expect("private excess journal directory");
    for sequence in 1..=(PUBLICATION_JOURNAL_MAX_RECORDS as u64 + 1) {
        write_test_journal_record(&excess_directory, &completed_github_journal(sequence));
    }
    assert!(load_latest_publication_journal(&excess_directory)
        .expect_err("excess journal records must fail")
        .to_string()
        .contains("record safety limit"));

    let entry_directory = temp.path().join("entries");
    merge::create_private_directory(&entry_directory)
        .expect("private entry-bound journal directory");
    for entry in 0..=PUBLICATION_JOURNAL_MAX_DIRECTORY_ENTRIES {
        merge::write_private_file(&entry_directory.join(format!("entry-{entry}")), b"x")
            .expect("write bounded journal directory entry");
    }
    assert!(load_latest_publication_journal(&entry_directory)
        .expect_err("excess journal directory entries must fail")
        .to_string()
        .contains("entry safety limit"));
}

#[cfg(unix)]
#[test]
fn publication_journal_rejects_symlinked_and_exposed_records() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = tempfile::tempdir().expect("tempdir");
    let symlink_directory = temp.path().join("symlink");
    merge::create_private_directory(&symlink_directory).expect("private symlink journal directory");
    let target = temp.path().join("target.json");
    merge::write_private_file(&target, b"{}\n").expect("write journal target");
    symlink(&target, symlink_directory.join("00000000000000000001.json"))
        .expect("symlink journal record");
    assert!(load_latest_publication_journal(&symlink_directory)
        .expect_err("symlinked journal must fail")
        .to_string()
        .contains("real regular file"));

    let exposed_directory = temp.path().join("exposed");
    merge::create_private_directory(&exposed_directory).expect("private exposed journal directory");
    let exposed = exposed_directory.join("00000000000000000001.json");
    merge::write_private_file(&exposed, b"{}\n").expect("write exposed journal");
    fs::set_permissions(&exposed, fs::Permissions::from_mode(0o644)).expect("expose journal mode");
    assert!(load_latest_publication_journal(&exposed_directory)
        .expect_err("exposed journal must fail")
        .to_string()
        .contains("unsafe mode"));
}

#[test]
fn publication_journal_rejects_sequence_gaps_and_receipt_changes() {
    let temp = tempfile::tempdir().expect("tempdir");
    let journal_directory = temp.path().join("journal");
    merge::create_private_directory(&journal_directory).expect("private journal directory");
    write_test_journal_record(&journal_directory, &completed_github_journal(1));
    write_test_journal_record(&journal_directory, &completed_github_journal(3));
    assert!(load_latest_publication_journal(&journal_directory)
        .expect_err("retained journal gap must fail")
        .to_string()
        .contains("not contiguous"));

    let previous = completed_github_journal(1);
    let mut changed = completed_github_journal(2);
    changed.pr_url = Some("https://example.invalid/owner/repo/pull/8".to_string());
    changed.pr_number = Some(8);
    validate_publication_journal(&changed).expect("changed receipt is independently valid");
    assert!(validate_publication_journal_transition(&previous, &changed)
        .expect_err("receipt identity change must fail")
        .to_string()
        .contains("immutable PR receipt"));
}

#[test]
fn publication_journal_enforces_completed_github_receipt_contract() {
    let valid = completed_github_journal(1);
    validate_publication_journal(&valid).expect("valid completed receipt");

    let mut wrong_head = valid.clone();
    wrong_head.pr_head_oid = Some("4444444444444444444444444444444444444444".to_string());
    assert!(validate_publication_journal(&wrong_head)
        .expect_err("wrong persisted head must fail")
        .to_string()
        .contains("PR head"));

    let mut wrong_base = valid.clone();
    wrong_base.pr_base = Some("release".to_string());
    assert!(validate_publication_journal(&wrong_base)
        .expect_err("wrong persisted base must fail")
        .to_string()
        .contains("PR base"));

    let mut missing_number = valid.clone();
    missing_number.pr_number = None;
    assert!(validate_publication_journal(&missing_number)
        .expect_err("missing persisted PR number must fail")
        .to_string()
        .contains("number"));

    let mut wrong_draft = valid;
    wrong_draft.pr_is_draft = Some(false);
    assert!(validate_publication_journal(&wrong_draft)
        .expect_err("changed persisted draft state must fail")
        .to_string()
        .contains("draft state"));
}

#[test]
fn github_receipt_requires_matching_base_and_open_state() {
    let remote_display = "https://example.invalid/repo";
    let remote_binding_digest = "2222222222222222222222222222222222222222".to_string();
    let journal = PublicationTransactionJournal {
        version: PUBLICATION_JOURNAL_VERSION,
        transaction_id: "receipt-contract".to_string(),
        sequence: 1,
        agent_id: "agent-a".to_string(),
        forge: ForgeKind::Github,
        expected_oid: "1111111111111111111111111111111111111111".to_string(),
        expected_base_oid: Some("3333333333333333333333333333333333333333".to_string()),
        remote_name: "origin".to_string(),
        remote_binding_digest,
        remote_display: remote_display.to_string(),
        remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
        remote_branch: "maco/review/agent-a/test".to_string(),
        github_repository: Some(GithubRepositoryIdentity {
            host: "example.invalid".to_string(),
            owner: "owner".to_string(),
            name: "repo".to_string(),
        }),
        pr_marker_nonce: Some(test_publication_pr_marker()),
        expected_pr_title: Some("Agent agent-a changes".to_string()),
        expected_pr_body: Some(test_publication_pr_body()),
        expected_pr_author: Some("publisher".to_string()),
        base: "main".to_string(),
        draft: true,
        phase: PublicationTransactionPhase::Prepared,
        push_observed_oid: None,
        pr_url: None,
        pr_head_oid: None,
        pr_base: None,
        pr_state: None,
        pr_is_draft: None,
        pr_number: None,
        pr_title: None,
        pr_body: None,
        pr_head_ref_name: None,
        pr_head_repository_owner: None,
        pr_head_repository_name: None,
        pr_is_cross_repository: None,
        pr_author: None,
        create_attempted: false,
        created_by_transaction: false,
        observed_existing_pr: false,
        last_error: None,
        updated_unix_seconds: 1,
    };
    let mut receipt = GithubPrResult {
        url: "https://example.invalid/owner/repo/pull/1".to_string(),
        head_oid: journal.expected_oid.clone(),
        base_oid: journal.expected_base_oid.clone().expect("base oid"),
        number: 1,
        base_ref_name: "release".to_string(),
        state: "OPEN".to_string(),
        is_draft: true,
        title: "Agent agent-a changes".to_string(),
        body: test_publication_pr_body(),
        head_ref_name: "maco/review/agent-a/test".to_string(),
        head_repository_owner: "owner".to_string(),
        head_repository_name: "repo".to_string(),
        is_cross_repository: false,
        author: "publisher".to_string(),
        created: false,
    };
    assert!(validate_github_receipt_contract(&receipt, &journal)
        .expect_err("wrong base must fail")
        .to_string()
        .contains("baseRefName"));
    receipt.base_ref_name = "main".to_string();
    receipt.state = "CLOSED".to_string();
    assert!(validate_github_receipt_contract(&receipt, &journal)
        .expect_err("closed PR must fail")
        .to_string()
        .contains("not OPEN"));
}

#[test]
fn github_receipt_requires_exact_marker_head_repository_and_author_provenance() {
    let journal = completed_github_journal(1);
    let exact = exact_github_receipt(&journal);
    validate_github_receipt_contract(&exact, &journal).expect("exact receipt");

    let mut cases = Vec::new();
    let mut changed = exact.clone();
    changed.title.push('!');
    cases.push(("title", changed));
    let mut changed = exact.clone();
    changed.body.push_str("different");
    cases.push(("body", changed));
    let mut changed = exact.clone();
    changed.head_ref_name = "maco/review/agent-a/front-run".to_string();
    cases.push(("head ref", changed));
    let mut changed = exact.clone();
    changed.head_repository_owner = "attacker".to_string();
    cases.push(("head owner", changed));
    let mut changed = exact.clone();
    changed.head_repository_name = "fork".to_string();
    cases.push(("head repository", changed));
    let mut changed = exact.clone();
    changed.is_cross_repository = true;
    cases.push(("cross repository", changed));
    let mut changed = exact;
    changed.author = "unexpected-bot[bot]".to_string();
    cases.push(("author", changed));

    for (label, changed) in cases {
        assert!(
            validate_github_receipt_contract(&changed, &journal).is_err(),
            "changed {label} provenance must fail"
        );
    }
}

#[test]
fn publication_journal_remote_binding_is_keyed_and_does_not_serialize_credentials() {
    let raw =
        "https://user-one:super-secret@example.invalid/repo.git?token=query-secret#fragment-secret";
    let equivalent =
        "https://user-two:different-secret@example.invalid/repo.git?token=other#different";
    let display = redact_remote_url(raw);
    let equivalent_display = redact_remote_url(equivalent);
    assert_eq!(
        display,
        "https://<redacted>@example.invalid/repo.git?<redacted>#<redacted>"
    );
    assert_eq!(display, equivalent_display);
    let secret = [7_u8; REMOTE_BINDING_SECRET_BYTES];
    let other_secret = [8_u8; REMOTE_BINDING_SECRET_BYTES];
    let digest =
        publication_remote_binding_digest(&secret, "origin", raw).expect("digest remote binding");
    let equivalent_digest = publication_remote_binding_digest(&secret, "origin", equivalent)
        .expect("digest equivalent remote binding");
    let other_key_digest = publication_remote_binding_digest(&other_secret, "origin", raw)
        .expect("digest remote binding with another key");
    assert_ne!(digest, equivalent_digest);
    assert_ne!(digest, other_key_digest);
    let serialized = serde_json::json!({
        "remote_binding_digest": digest,
        "remote_display": display,
    })
    .to_string();
    assert!(!serialized.contains("user-one"));
    assert!(!serialized.contains("super-secret"));
    assert!(!serialized.contains("query-secret"));
    assert!(!serialized.contains("fragment-secret"));
    assert!(serialized.contains("<redacted>"));

    assert!(publication_remote_transport(raw).is_err());
    assert!(publication_remote_transport(equivalent).is_err());
}

#[test]
fn github_repository_binding_accepts_only_https_without_url_credentials() {
    let https = github_repository_identity("https://github.example/Owner/repo.git")
        .expect("parse HTTPS origin");
    assert_eq!(https.selector(), "github.example/owner/repo");
    assert!(github_repository_identity("/tmp/local-origin.git").is_err());
    assert!(github_repository_identity("ssh://git@github.example/Owner/repo.git").is_err());
    assert!(github_repository_identity("git@github.example:Owner/repo.git").is_err());
    assert!(
        github_repository_identity("https://user:secret@github.example/Owner/repo.git").is_err()
    );
    assert!(github_repository_identity("https://github.example/group/owner/repo.git").is_err());
}

#[test]
fn github_receipt_url_is_bound_to_repository_and_number() {
    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "owner".to_string(),
        name: "repo".to_string(),
    };
    validate_github_receipt_url("https://github.example/owner/repo/pull/7", &repository, 7)
        .expect("matching receipt URL");
    assert!(validate_github_receipt_url(
        "https://github.example/other/repo/pull/7",
        &repository,
        7,
    )
    .expect_err("wrong repository must fail")
    .to_string()
    .contains("bound forge repository"));
    assert!(validate_github_receipt_url(
        "https://github.example/owner/repo/pull/8",
        &repository,
        7,
    )
    .is_err());
    assert!(validate_github_receipt_url(
        "https://github.example/owner/repo/pull/7?token=x",
        &repository,
        7,
    )
    .is_err());
    assert!(validate_github_receipt_url(
        "https://github.example/owner/repo/pull/7#fragment",
        &repository,
        7,
    )
    .is_err());
    assert!(validate_github_receipt_url(
        "https://github.example/owner/repo/pull/0",
        &repository,
        0,
    )
    .is_err());
    assert!(validate_github_receipt_url(
        "https://github.example/owner/repo/pull/007",
        &repository,
        7,
    )
    .is_err());
}

#[test]
fn github_issue_receipt_requires_exact_nonzero_bound_url() {
    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "owner".to_string(),
        name: "repo".to_string(),
    };
    assert_eq!(
        validate_github_issue_receipt_url(
            "https://github.example/owner/repo/issues/9",
            &repository,
            9,
        )
        .expect("valid issue receipt"),
        "https://github.example/owner/repo/issues/9"
    );
    for invalid in [
        "",
        "https://github.example/owner/repo/issues",
        "https://github.example/owner/repo/issues/0",
        "https://github.example/owner/repo/issues/009",
        "https://github.example/owner/repo/issues/8",
        "https://github.example/other/repo/issues/9",
        "https://github.example/owner/repo/issues/9?token=x",
        "https://github.example/owner/repo/issues/9#fragment",
        "http://github.example/owner/repo/issues/9",
    ] {
        assert!(
            validate_github_issue_receipt_url(invalid, &repository, 9).is_err(),
            "invalid issue receipt passed: {invalid}"
        );
    }
}

#[test]
fn github_pr_receipt_parser_bounds_strings_and_requires_canonical_values() {
    let valid = serde_json::json!({
        "url": "https://github.example/owner/repo/pull/7",
        "headRefOid": "1111111111111111111111111111111111111111",
        "baseRefOid": "2222222222222222222222222222222222222222",
        "number": 7,
        "baseRefName": "main",
        "state": "OPEN",
        "isDraft": true,
        "title": "Agent agent-a changes",
        "body": test_publication_pr_body(),
        "headRefName": "maco/review/agent-a/test",
        "headRepository": {
            "name": "repo",
            "nameWithOwner": "owner/repo"
        },
        "headRepositoryOwner": { "login": "owner" },
        "isCrossRepository": false,
        "author": { "login": "publisher" },
    });
    github_pr_receipt_from_json(&valid).expect("valid PR receipt");

    let mut invalid = valid.clone();
    invalid["url"] = serde_json::json!("https://github.example/owner/repo/pull/7?x=1");
    assert!(github_pr_receipt_from_json(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid["number"] = serde_json::json!(0);
    assert!(github_pr_receipt_from_json(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid["headRefOid"] = serde_json::json!("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    assert!(github_pr_receipt_from_json(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid["baseRefName"] = serde_json::json!("a".repeat(MAX_GITHUB_RECEIPT_STRING_BYTES + 1));
    assert!(github_pr_receipt_from_json(&invalid).is_err());
    let mut invalid = valid.clone();
    invalid["body"] = serde_json::json!("a".repeat(MAX_GITHUB_RECEIPT_BODY_BYTES + 1));
    assert!(github_pr_receipt_from_json(&invalid).is_err());
    let excessive = serde_json::Value::Array(
        std::iter::repeat_n(valid, MAX_GITHUB_PR_LIST_RECEIPTS + 1).collect(),
    );
    assert!(github_pr_list_from_json(&excessive).is_err());
}

#[test]
fn invalid_github_receipt_is_not_persisted_before_contract_checks() {
    let temp = tempfile::tempdir().expect("tempdir");
    let mut transaction = PublicationTransaction {
        directory: temp.path().to_path_buf(),
        journal: PublicationTransactionJournal {
            version: PUBLICATION_JOURNAL_VERSION,
            transaction_id: "invalid-receipt".to_string(),
            sequence: 0,
            agent_id: "agent-a".to_string(),
            forge: ForgeKind::Github,
            expected_oid: "1111111111111111111111111111111111111111".to_string(),
            expected_base_oid: Some("2222222222222222222222222222222222222222".to_string()),
            remote_name: "origin".to_string(),
            remote_binding_digest: "3333333333333333333333333333333333333333".to_string(),
            remote_display: "https://github.example/owner/repo.git".to_string(),
            remote_ref: "refs/heads/maco/review/agent-a/test".to_string(),
            remote_branch: "maco/review/agent-a/test".to_string(),
            github_repository: Some(GithubRepositoryIdentity {
                host: "github.example".to_string(),
                owner: "owner".to_string(),
                name: "repo".to_string(),
            }),
            pr_marker_nonce: Some(test_publication_pr_marker()),
            expected_pr_title: Some("Agent agent-a changes".to_string()),
            expected_pr_body: Some(test_publication_pr_body()),
            expected_pr_author: Some("publisher".to_string()),
            base: "main".to_string(),
            draft: true,
            phase: PublicationTransactionPhase::PushObserved,
            push_observed_oid: Some("1111111111111111111111111111111111111111".to_string()),
            pr_url: None,
            pr_head_oid: None,
            pr_base: None,
            pr_state: None,
            pr_is_draft: None,
            pr_number: None,
            pr_title: None,
            pr_body: None,
            pr_head_ref_name: None,
            pr_head_repository_owner: None,
            pr_head_repository_name: None,
            pr_is_cross_repository: None,
            pr_author: None,
            create_attempted: true,
            created_by_transaction: false,
            observed_existing_pr: false,
            last_error: None,
            updated_unix_seconds: 0,
        },
        remote_url: "https://github.example/owner/repo.git".to_string(),
        push_effect_request: None,
        pr_effect_request: None,
    };
    let receipt = GithubPrResult {
        url: "https://github.example/owner/repo/pull/7".to_string(),
        head_oid: transaction.journal.expected_oid.clone(),
        base_oid: "4444444444444444444444444444444444444444".to_string(),
        number: 7,
        base_ref_name: "main".to_string(),
        state: "OPEN".to_string(),
        is_draft: true,
        title: "Agent agent-a changes".to_string(),
        body: test_publication_pr_body(),
        head_ref_name: "maco/review/agent-a/test".to_string(),
        head_repository_owner: "owner".to_string(),
        head_repository_name: "repo".to_string(),
        is_cross_repository: false,
        author: "publisher".to_string(),
        created: false,
    };

    let error = verify_github_receipt_with_remote_check(
        temp.path(),
        &mut transaction,
        receipt,
        true,
        false,
        |_, _, _| Ok(()),
    )
    .expect_err("wrong base receipt must fail before persistence");

    assert!(error.to_string().contains("baseRefOid"));
    assert_eq!(transaction.journal.sequence, 0);
    assert_eq!(
        transaction.journal.phase,
        PublicationTransactionPhase::PushObserved
    );
    assert!(transaction.journal.pr_url.is_none());
    assert_eq!(
        fs::read_dir(temp.path()).expect("read journal dir").count(),
        0
    );
}

#[test]
fn github_command_environment_is_an_explicit_data_auth_allowlist() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "owner".to_string(),
        name: "repo".to_string(),
    };
    let context = GhCommandContext::create_with_token_source(&repo_path, &repository, |key| {
        enterprise_test_value("github.example", key)
    })
    .expect("create gh context");
    for key in [
        "GH_REPO",
        "GH_HOST",
        "GH_DEBUG",
        "GH_FORCE_TTY",
        "GH_PAGER",
        "HOME",
        "HTTPS_PROXY",
        "ALL_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "GIT_SSL_CAINFO",
        "GIT_SSL_CAPATH",
        "GH_TOKEN",
        "GITHUB_TOKEN",
        "GH_ENTERPRISE_TOKEN",
        "GITHUB_ENTERPRISE_TOKEN",
        "GIT_CONFIG_NOSYSTEM",
        "GIT_CONFIG_GLOBAL",
    ] {
        assert!(
            !context.environment.contains_key(key),
            "unexpected inherited routing variable {key}"
        );
    }
    assert_eq!(
        context
            .environment
            .get("GH_PROMPT_DISABLED")
            .map(String::as_str),
        Some("1")
    );
    assert_eq!(
        context.environment.get("GH_CONFIG_DIR").map(String::as_str),
        context.runtime_directory.path().to_str()
    );
}

#[test]
fn publication_git_uses_only_private_path_scoped_basic_auth_config() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let raw = "https://example.invalid/owner/repo";
    let context = PublicationGitContext::create_with_token_source(
        &repo_path,
        raw,
        test_observe_operation(),
        |key| enterprise_test_value("example.invalid", key),
    )
    .expect("create publication Git context");
    let args = context.command_args(vec![
        OsString::from("ls-remote"),
        OsString::from("--refs"),
        OsString::from("maco-publication"),
        OsString::from("refs/heads/test"),
    ]);
    let argv = args
        .iter()
        .map(|argument| argument.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    assert!(!argv.contains(raw));
    assert!(!argv.contains("test-token"));
    assert!(!context
        .environment
        .values()
        .any(|value| value.contains("test-token")));
    let config = git2::Config::open(&context.directory.join("config"))
        .expect("open private publication config");
    let header = config
        .get_string("http.https://example.invalid/owner/repo.git.extraheader")
        .expect("scoped auth header");
    assert_eq!(
        header,
        "Authorization: Basic eC1hY2Nlc3MtdG9rZW46dGVzdC10b2tlbg=="
    );
    assert_eq!(
        config
            .get_string("remote.maco-publication.url")
            .expect("bound remote"),
        "https://example.invalid/owner/repo.git"
    );
    assert_eq!(
        config
            .get_string("http.followredirects")
            .expect("redirect setting"),
        "false"
    );
    assert!(config.get_bool("http.sslverify").expect("TLS setting"));
    assert_eq!(config.get_string("http.proxy").expect("proxy setting"), "");
    assert_eq!(
        config
            .get_string("credential.helper")
            .expect("credential helper setting"),
        ""
    );
}

#[test]
fn publication_profiles_expose_only_required_config_and_git_objects() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let repo = Repository::init(&repo_path).expect("init repo");
    let context = PublicationGitContext::create_with_token_source(
        &repo_path,
        "https://github.example/owner/repo.git",
        test_observe_operation(),
        |key| enterprise_test_value("github.example", key),
    )
    .expect("create publication context");
    let PublicationGitBoundary::Https(profile) = &context.boundary;
    assert_eq!(
        profile.visible_read_only_roots(),
        &[context.directory.join("objects")]
    );
    assert_eq!(profile.visible_read_only_files().len(), 2);
    let state = fs::canonicalize(repo.commondir().join("maco/state")).expect("state");
    assert!(profile.hidden_roots().contains(&state));
    assert!(profile
        .hidden_roots()
        .contains(&fs::canonicalize(&repo_path).expect("repo root")));

    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "owner".to_string(),
        name: "repo".to_string(),
    };
    let gh = GhCommandContext::create_with_token_source(&repo_path, &repository, |key| {
        enterprise_test_value("github.example", key)
    })
    .expect("create gh context");
    assert!(gh.profile.visible_read_only_roots().is_empty());
    assert_eq!(gh.profile.visible_read_only_files().len(), 1);
    assert!(gh.profile.hidden_roots().contains(&state));
}

#[test]
fn missing_https_token_cleans_private_runtime_without_residue() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let repo = Repository::init(&repo_path).expect("init repo");
    merge::ensure_repo_common_state_directory(&repo).expect("state");
    let mut allocated_runtime = None;
    assert!(
        PublicationGitContext::create_with_token_source_and_runtime_observer(
            &repo_path,
            "https://github.example/owner/repo.git",
            test_observe_operation(),
            |key| (key == "GH_HOST").then(|| "github.example".to_string()),
            |path| allocated_runtime = Some(path.to_path_buf()),
        )
        .is_err()
    );
    let allocated_runtime = allocated_runtime.expect("observe allocated publication runtime");
    assert!(
        !allocated_runtime.exists(),
        "failed setup left its exact private runtime entry: {}",
        allocated_runtime.display()
    );
}

#[test]
fn private_config_in_place_mutation_and_hardlink_are_detected_before_spawn() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let context = PublicationGitContext::create_with_token_source(
        &repo_path,
        "https://github.example/owner/repo.git",
        test_observe_operation(),
        |key| enterprise_test_value("github.example", key),
    )
    .expect("create publication context");
    let config_path = context.directory.join("config");
    let mut original = fs::read(&config_path).expect("read config");
    fs::write(&config_path, b"[core]\n\tbare = true\n").expect("mutate config in place");
    assert!(verify_private_config_files(&context.config_files).is_err());
    merge::write_private_file(&context.directory.join("replacement"), &original)
        .expect("write replacement");
    fs::remove_file(&config_path).expect("remove mutated config");
    fs::rename(context.directory.join("replacement"), &config_path)
        .expect("restore config path with changed inode");
    assert!(verify_private_config_files(&context.config_files).is_err());

    let hardlink = context.directory.join("config-hardlink");
    fs::hard_link(&config_path, &hardlink).expect("hardlink config");
    assert!(capture_private_config_file(&config_path).is_err());
    fs::remove_file(hardlink).expect("remove hardlink before secret cleanup");
    zeroize_bytes(&mut original);
}

#[cfg(unix)]
#[test]
fn private_network_configs_are_verifiably_erased_before_explicit_runtime_close() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let mut git = PublicationGitContext::create_with_token_source(
        &repo_path,
        "https://github.example/owner/repo.git",
        test_observe_operation(),
        |key| enterprise_test_value("github.example", key),
    )
    .expect("create publication context");
    let git_runtime = git.directory.clone();
    let git_config_paths = git
        .config_files
        .iter()
        .map(|identity| (identity.path.clone(), identity.bytes.len()))
        .collect::<Vec<_>>();
    assert!(git_config_paths.iter().any(|(path, _)| {
        fs::read(path).is_ok_and(|bytes| {
            bytes
                .windows(b"Authorization".len())
                .any(|part| part == b"Authorization")
        })
    }));
    erase_private_config_files(&mut git.config_files).expect("verified Git config erasure");
    for (path, length) in &git_config_paths {
        let bytes = fs::read(path).expect("read erased Git config");
        assert_eq!(bytes.len(), *length);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
    git.close().expect("close erased Git runtime");
    assert!(!git_runtime.exists());

    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "owner".to_string(),
        name: "repo".to_string(),
    };
    let mut gh = GhCommandContext::create_with_token_source(&repo_path, &repository, |key| {
        enterprise_test_value("github.example", key)
    })
    .expect("create gh context");
    let gh_runtime = gh.runtime_directory.path().to_path_buf();
    let gh_config_paths = gh
        .config_files
        .iter()
        .map(|identity| (identity.path.clone(), identity.bytes.len()))
        .collect::<Vec<_>>();
    erase_private_config_files(&mut gh.config_files).expect("verified gh config erasure");
    for (path, length) in &gh_config_paths {
        let bytes = fs::read(path).expect("read erased gh config");
        assert_eq!(bytes.len(), *length);
        assert!(bytes.iter().all(|byte| *byte == 0));
    }
    gh.close().expect("close erased gh runtime");
    assert!(!gh_runtime.exists());
}

#[test]
fn publication_remote_rejects_ambiguous_encoded_query_and_fragment_credentials() {
    assert!(validate_publication_remote_url(
        "https://user:secret@example.invalid/repo.git?token=secret"
    )
    .is_err());
    assert!(
        validate_publication_remote_url("https://user:secret@example.invalid/repo.git#secret")
            .is_err()
    );
    assert!(
        validate_publication_remote_url("https://user:abc%64ef@example.invalid/repo.git").is_err()
    );
}

#[test]
fn publication_remote_accepts_only_bounded_canonical_https() {
    assert!(matches!(
        publication_remote_transport("https://github.example/owner/repo")
            .expect("classify HTTPS remote"),
        PublicationRemoteTransport::Https { command_url, .. }
            if command_url == "https://github.example/owner/repo.git"
    ));
    assert!(matches!(
        publication_remote_transport("https://github.com:443/owner/repo")
            .expect("normalize canonical public HTTPS port"),
        PublicationRemoteTransport::Https { host, command_url, .. }
            if host == "github.com" && command_url == "https://github.com/owner/repo.git"
    ));
    for remote in [
        "https://github.com:0443/owner/repo.git",
        "https://github.com:444/owner/repo.git",
    ] {
        assert!(
            publication_remote_transport(remote).is_err(),
            "noncanonical public GitHub authority must fail: {remote}"
        );
    }

    for remote in [
        "ssh://github.example/owner/repo.git",
        "ssh://git@github.example:2222/owner/repo.git",
        "git+ssh://github.example/owner/repo.git",
        "ssh+git://git@github.example/owner/repo.git",
        "github.example:owner/repo.git",
        "git@github.example:owner/repo.git",
        "[2001:db8::1]:owner/repo.git",
        "git@[2001:db8::1]:owner/repo.git",
        "/tmp/repo.git",
        "file:///tmp/repo.git",
        "../repo.git",
        r"C:\\repo.git",
        "http://github.example/owner/repo.git",
        "git://github.example/owner/repo.git",
        "ext://host/repo",
        "SSH://host/repo",
        "host::remote-helper",
        "ssh://user@@host/repo",
        "ssh://[2001:db8::1/repo",
        "host:",
        "https://user@github.example/owner/repo.git",
        "https://github.example/owner/repo.git?token=x",
        "https://github.example/owner/repo.git#fragment",
        "https://github.example/owner/%72epo.git",
    ] {
        assert!(
            publication_remote_transport(remote).is_err(),
            "ambiguous remote must fail: {remote}"
        );
    }
}

#[test]
fn publication_object_store_rejects_alternates_promisor_and_partial_clone_inputs() {
    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let repo = Repository::init(&repo_path).expect("init repo");
    let objects = fs::canonicalize(repo.commondir().join("objects")).expect("objects");
    validate_publication_object_store_is_self_contained(&repo, &objects)
        .expect("ordinary object store");

    let alternates = objects.join("info/alternates");
    fs::write(&alternates, b"/tmp/escape\n").expect("write alternates");
    assert!(validate_publication_object_store_is_self_contained(&repo, &objects).is_err());
    fs::remove_file(&alternates).expect("remove alternates");

    let promisor = objects.join("pack/pack-test.promisor");
    fs::write(&promisor, b"").expect("write promisor marker");
    assert!(validate_publication_object_store_is_self_contained(&repo, &objects).is_err());
    fs::remove_file(&promisor).expect("remove promisor marker");

    repo.config()
        .expect("repo config")
        .set_str("extensions.partialClone", "origin")
        .expect("set partial clone extension");
    assert!(validate_publication_object_store_is_self_contained(&repo, &objects).is_err());
}

#[test]
fn private_publication_object_database_contains_only_exact_reachable_closure() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = Repository::init_bare(temp.path().join("source.git")).expect("source repo");
    let destination =
        Repository::init_bare(temp.path().join("destination.git")).expect("destination repo");
    let blob = source
        .blob(b"reachable publication content\n")
        .expect("blob");
    let gitlink = Oid::from_str("7777777777777777777777777777777777777777").expect("gitlink oid");
    let mut tree = source.treebuilder(None).expect("tree builder");
    tree.insert("README.md", blob, 0o100644)
        .expect("insert reachable blob");
    tree.insert("vendor", gitlink, 0o160000)
        .expect("insert non-traversed gitlink");
    let tree_oid = tree.write().expect("write tree");
    let tree = source.find_tree(tree_oid).expect("find tree");
    let signature =
        git2::Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    let commit = source
        .commit(None, &signature, &signature, "candidate", &tree, &[])
        .expect("commit candidate");
    let unreachable = source
        .blob(b"unreachable local secret\n")
        .expect("extra blob");

    let seal = materialize_publication_object_closure(&source, &destination, &commit.to_string())
        .expect("materialize exact publication closure");

    assert_eq!(seal.expected_oid, commit);
    assert_eq!(seal.object_ids, BTreeSet::from([commit, tree_oid, blob]));
    assert!(destination.find_object(commit, None).is_ok());
    assert!(destination.find_object(tree_oid, None).is_ok());
    assert!(destination.find_object(blob, None).is_ok());
    assert!(destination.find_object(gitlink, None).is_err());
    assert!(destination.find_object(unreachable, None).is_err());
    verify_private_publication_object_closure(&destination, &seal)
        .expect("private closure remains exact");

    destination
        .blob(b"object outside sealed closure")
        .expect("inject extra private object");
    assert!(
        verify_private_publication_object_closure(&destination, &seal)
            .expect_err("extra private object must break the seal")
            .to_string()
            .contains("outside the exact closure")
    );
}

#[test]
fn publication_closure_rejects_duplicate_parents_cycles_and_excessive_tree_depth() {
    let temp = tempfile::tempdir().expect("tempdir");
    let source = Repository::init_bare(temp.path().join("source.git")).expect("source repo");
    let destination =
        Repository::init_bare(temp.path().join("destination.git")).expect("destination repo");
    let signature =
        git2::Signature::now("maco test", "maco-test@example.invalid").expect("signature");
    let empty_tree_oid = source
        .treebuilder(None)
        .expect("empty tree")
        .write()
        .expect("write empty tree");
    let empty_tree = source.find_tree(empty_tree_oid).expect("find empty tree");
    let root_oid = source
        .commit(None, &signature, &signature, "root", &empty_tree, &[])
        .expect("root commit");
    let root = source.find_commit(root_oid).expect("find root commit");
    let duplicate_parent = source
        .commit(
            None,
            &signature,
            &signature,
            "duplicate parent",
            &empty_tree,
            &[&root, &root],
        )
        .expect("write duplicate-parent commit");
    let duplicate_error = match materialize_publication_object_closure(
        &source,
        &destination,
        &duplicate_parent.to_string(),
    ) {
        Ok(_) => panic!("duplicate commit parent must fail"),
        Err(error) => error,
    };
    assert!(duplicate_error
        .to_string()
        .contains("self or duplicate parent"));

    let first = Oid::from_str("1111111111111111111111111111111111111111").expect("first oid");
    let second = Oid::from_str("2222222222222222222222222222222222222222").expect("second oid");
    let cycle = BTreeMap::from([(first, vec![second]), (second, vec![first])]);
    assert!(validate_publication_commit_graph(&cycle, first)
        .expect_err("cycle must fail")
        .to_string()
        .contains("cycle"));

    let leaf = source.blob(b"leaf").expect("leaf blob");
    let mut nested_oid = leaf;
    for depth in 0..=MAX_PUBLICATION_TREE_DEPTH + 1 {
        let mut nested = source.treebuilder(None).expect("nested tree");
        let mode = if depth == 0 { 0o100644 } else { 0o040000 };
        nested
            .insert("entry", nested_oid, mode)
            .expect("insert nested object");
        nested_oid = nested.write().expect("write nested tree");
    }
    let deep_tree = source.find_tree(nested_oid).expect("find deep tree");
    let deep_commit = source
        .commit(None, &signature, &signature, "deep", &deep_tree, &[])
        .expect("deep commit");
    let deep_destination =
        Repository::init_bare(temp.path().join("deep-destination.git")).expect("deep destination");
    let depth_error = match materialize_publication_object_closure(
        &source,
        &deep_destination,
        &deep_commit.to_string(),
    ) {
        Ok(_) => panic!("excessive tree depth must fail"),
        Err(error) => error,
    };
    assert!(
        depth_error.to_string().contains("depth safety bound"),
        "unexpected deep-tree error: {depth_error:#}"
    );
}

#[test]
fn token_selection_is_host_specific_unambiguous_and_basic_encoded() {
    let public = select_network_token_with("github.com", |key| {
        (key == "GH_TOKEN").then(|| "test-token".to_string())
    })
    .expect("public token");
    assert_eq!(
        public.basic_str().expect("basic token"),
        "eC1hY2Nlc3MtdG9rZW46dGVzdC10b2tlbg=="
    );
    assert!(select_network_token_with("github.com", |_| None).is_err());
    assert!(
        select_network_token_with("github.example", |key| match key {
            "GH_HOST" => Some("github.example".to_string()),
            "GH_ENTERPRISE_TOKEN" => Some("first-token".to_string()),
            "GITHUB_ENTERPRISE_TOKEN" => Some("second-token".to_string()),
            _ => None,
        })
        .is_err()
    );
    assert!(select_network_token_with("github.com", |key| {
        (key == "GH_TOKEN").then(|| "unsafe'token".to_string())
    })
    .is_err());
}

#[test]
fn enterprise_host_authorization_precedes_and_exactly_scopes_token_selection() {
    use std::cell::Cell;

    let token_was_requested = Cell::new(false);
    let missing_host = select_network_token_with("github.example", |key| {
        if key.contains("TOKEN") {
            token_was_requested.set(true);
            Some("test-token".to_string())
        } else {
            None
        }
    });
    assert!(missing_host.is_err());
    assert!(!token_was_requested.get());

    let mismatch = select_network_token_with("github.example:8443", |key| match key {
        "GH_HOST" => Some("github.example".to_string()),
        "GH_ENTERPRISE_TOKEN" => Some("test-token".to_string()),
        _ => None,
    });
    assert!(mismatch.is_err());

    select_network_token_with("github.example:8443", |key| match key {
        "GH_HOST" => Some("github.example:8443".to_string()),
        "GH_ENTERPRISE_TOKEN" => Some("test-token".to_string()),
        _ => None,
    })
    .expect("exact enterprise authority is explicitly approved");

    let private_token_was_requested = Cell::new(false);
    let private_unapproved = select_network_token_with("127.0.0.1", |key| {
        if key.contains("TOKEN") {
            private_token_was_requested.set(true);
            Some("test-token".to_string())
        } else {
            None
        }
    });
    assert!(private_unapproved.is_err());
    assert!(!private_token_was_requested.get());
    select_network_token_with("127.0.0.1", |key| match key {
        "GH_HOST" => Some("127.0.0.1".to_string()),
        "GH_ENTERPRISE_TOKEN" => Some("test-token".to_string()),
        _ => None,
    })
    .expect("owner may explicitly approve an exact private enterprise endpoint");
}

#[test]
fn github_expected_author_is_explicit_exact_and_bot_compatible() {
    assert!(select_github_expected_author_with(|_| None).is_err());
    assert!(select_github_expected_author_with(|key| match key {
        "GH_EXPECTED_AUTHOR" => Some("publisher".to_string()),
        "GITHUB_EXPECTED_AUTHOR" => Some("other".to_string()),
        _ => None,
    })
    .is_err());
    assert_eq!(
        select_github_expected_author_with(|key| {
            (key == "GH_EXPECTED_AUTHOR").then(|| "Release-Bot[bot]".to_string())
        })
        .expect("explicit bot provenance"),
        "release-bot[bot]"
    );
}

#[test]
fn approved_github_actor_guard_blocks_missing_or_wrong_actor_before_mutation() {
    use std::cell::Cell;

    let pinned = tempfile::tempdir().expect("pinned actor repo");
    let repository = Repository::init(pinned.path()).expect("init pinned actor repo");
    repository
        .config()
        .expect("open pinned actor config")
        .set_str(APPROVED_GITHUB_LOGIN_CONFIG_KEY, "Meta-Develop")
        .expect("set approved actor pin");
    let config_path = repository.path().join("config");

    let actor_calls = Cell::new(0_u32);
    let mutation_calls = Cell::new(0_u32);
    let result = execute_with_approved_github_actor(
        capture_approved_github_actor_binding(&config_path),
        || {
            actor_calls.set(actor_calls.get() + 1);
            Ok("diverxgeneral".to_string())
        },
        || {
            mutation_calls.set(mutation_calls.get() + 1);
            Ok(())
        },
    );
    assert!(result
        .expect_err("wrong actor must fail")
        .to_string()
        .contains("does not exactly match"));
    assert_eq!(actor_calls.get(), 1);
    assert_eq!(mutation_calls.get(), 0);

    let missing = tempfile::tempdir().expect("missing actor repo");
    let missing_repository = Repository::init(missing.path()).expect("init missing actor repo");
    let missing_actor_calls = Cell::new(0_u32);
    let missing_mutation_calls = Cell::new(0_u32);
    let result = execute_with_approved_github_actor(
        capture_approved_github_actor_binding(&missing_repository.path().join("config")),
        || {
            missing_actor_calls.set(missing_actor_calls.get() + 1);
            Ok("Meta-Develop".to_string())
        },
        || {
            missing_mutation_calls.set(missing_mutation_calls.get() + 1);
            Ok(())
        },
    );
    assert!(result
        .expect_err("missing pin must fail")
        .to_string()
        .contains("must contain exactly one non-empty value"));
    assert_eq!(missing_actor_calls.get(), 0);
    assert_eq!(missing_mutation_calls.get(), 0);
}

#[test]
fn approved_github_actor_guard_runs_only_after_an_exact_actor_check() {
    use std::cell::RefCell;

    let temp = tempfile::tempdir().expect("approved actor repo");
    let repository = Repository::init(temp.path()).expect("init approved actor repo");
    repository
        .config()
        .expect("open approved actor config")
        .set_str(APPROVED_GITHUB_LOGIN_CONFIG_KEY, "Meta-Develop")
        .expect("set approved actor pin");
    let events = RefCell::new(Vec::new());
    execute_with_approved_github_actor(
        capture_approved_github_actor_binding(&repository.path().join("config")),
        || {
            events.borrow_mut().push("actor");
            Ok("Meta-Develop".to_string())
        },
        || {
            events.borrow_mut().push("mutation");
            Ok(())
        },
    )
    .expect("exact actor runs mutation");
    assert_eq!(*events.borrow(), ["actor", "mutation"]);
}

#[test]
fn every_allowlisted_human_gh_mutation_uses_the_actor_guard() {
    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "owner".to_string(),
        name: "repo".to_string(),
    };
    let selector = repository.selector();
    for args in [
        vec![
            "pr",
            "create",
            "--repo",
            &selector,
            "--base",
            "main",
            "--head",
            "topic",
            "--title",
            "title",
            "--body-file",
            "-",
        ],
        vec![
            "issue",
            "create",
            "--repo",
            &selector,
            "--title",
            "title",
            "--body-file",
            "-",
        ],
        vec![
            "pr",
            "comment",
            "7",
            "--repo",
            &selector,
            "--body-file",
            "-",
        ],
        vec![
            "issue",
            "comment",
            "8",
            "--repo",
            &selector,
            "--body-file",
            "-",
        ],
    ] {
        let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
        assert_eq!(
            classify_gh_operation(&args, &StdinMode::Bytes(Vec::new()), &repository)
                .expect("allowlisted human mutation"),
            GhOperationClass::HumanMutation
        );
    }

    let source =
        fs::read_to_string(Path::new(env!("CARGO_MANIFEST_DIR")).join("src/publication/part3.rs"))
            .expect("read publication transport source");
    assert_eq!(source.matches(".run_human_mutation(").count(), 3);
    for label in ["gh pr create", "gh issue create", "gh source comment"] {
        let label_offset = source.find(label).expect("human mutation label");
        let prefix = &source[label_offset.saturating_sub(160)..label_offset];
        assert!(
            prefix.contains("run_human_mutation"),
            "{label} bypassed the actor guard"
        );
    }
}

#[test]
fn github_actor_lookup_is_exact_and_case_sensitive() {
    let parsed = github_actor_login_from_output(merge::RequiredCommandOutput {
        success: true,
        stdout: b"Meta-Develop\n".to_vec(),
        stderr: Vec::new(),
    })
    .expect("canonical actor lookup output");
    assert_eq!(parsed, "Meta-Develop");
    assert!(
        github_actor_login_from_output(merge::RequiredCommandOutput {
            success: true,
            stdout: b"Meta-Develop\nextra\n".to_vec(),
            stderr: Vec::new(),
        })
        .is_err()
    );
}

#[test]
fn publication_pr_markers_are_canonical_unpredictable_and_exactly_embedded() {
    let first = generate_publication_pr_marker_nonce().expect("first marker");
    let second = generate_publication_pr_marker_nonce().expect("second marker");
    validate_publication_pr_marker_nonce(&first).expect("canonical first marker");
    validate_publication_pr_marker_nonce(&second).expect("canonical second marker");
    assert_ne!(first, second);
    let body = pr_body_with_publication_marker("body", &first).expect("marker body");
    assert_eq!(
        body.matches(&format!("<!-- maco-publication-marker:{first} -->"))
            .count(),
        1
    );
    assert!(!body.contains(&second));
}

#[test]
fn token_redaction_covers_raw_and_basic_forms() {
    let token = select_network_token_with("github.com", |key| {
        (key == "GH_TOKEN").then(|| "test-token".to_string())
    })
    .expect("token");
    let mut output = format!(
        "raw={} basic={}",
        token.as_str().expect("raw"),
        token.basic_str().expect("basic")
    )
    .into_bytes();
    redact_private_bytes(&mut output, &token.bytes);
    redact_private_bytes(&mut output, &token.basic);
    let output = String::from_utf8(output).expect("UTF-8 redaction");
    assert!(!output.contains("test-token"));
    assert!(!output.contains("eC1hY2Nlc3MtdG9rZW46dGVzdC10b2tlbg=="));
    assert_eq!(output.matches("<redacted:network-token>").count(), 2);
}

#[test]
fn publication_network_capability_callsites_are_exactly_audited() {
    let source_directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut constructors = Vec::new();
    let mut runners = Vec::new();
    let constructor_needle = ["TrustedFixedNetworkProfile", "::read_write("].concat();
    let runner_needle = ["merge::run_required_", "network_direct("].concat();
    for path in rust_sources_under(&source_directory) {
        if is_rust_test_source(&path) {
            continue;
        }
        let source = fs::read_to_string(&path).expect("read Rust source");
        let name = source_audit_module_name(&path, &source_directory);
        let production_source = source
            .split_once("#[cfg(test)]\nmod tests")
            .map_or(source.as_str(), |(production, _)| production);
        for _ in production_source.match_indices(&constructor_needle) {
            constructors.push(name.clone());
        }
        for _ in production_source.match_indices(&runner_needle) {
            runners.push(name.clone());
        }
    }
    constructors.sort();
    runners.sort();
    assert_eq!(
        constructors,
        [
            "process_runner.rs",
            "publication.rs",
            "publication.rs",
            "supervise.rs",
        ]
    );
    assert_eq!(
        runners,
        ["publication.rs", "publication.rs", "publication.rs"]
    );
}

fn rust_sources_under(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(&directory).expect("read source directory") {
            let entry = entry.expect("read source entry");
            let path = entry.path();
            if path.is_dir() {
                pending.push(path);
                continue;
            }
            if path.extension().and_then(|extension| extension.to_str()) == Some("rs") {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn is_rust_test_source(path: &Path) -> bool {
    path.components().any(|component| {
        let name = component.as_os_str().to_string_lossy();
        name == "tests" || name == "tests.rs" || name.starts_with("tests_part")
    })
}

fn source_audit_module_name(path: &Path, source_directory: &Path) -> String {
    let relative = path
        .strip_prefix(source_directory)
        .expect("source path stays under src");
    let first = relative
        .components()
        .next()
        .expect("source path has a module component");
    let name = first.as_os_str().to_string_lossy();
    if name.ends_with(".rs") {
        name.into_owned()
    } else {
        format!("{name}.rs")
    }
}

#[test]
fn publication_url_slug_ref_and_oid_bounds_fail_closed() {
    assert!(publication_remote_transport(&format!(
        "https://example.invalid/owner/{}",
        "a".repeat(MAX_PUBLICATION_PATH_BYTES)
    ))
    .is_err());
    assert!(publication_remote_transport(&format!(
        "https://{}.example/owner/repo",
        "a".repeat(64)
    ))
    .is_err());
    assert!(github_repository_identity(&format!(
        "https://example.invalid/{}/repo",
        "a".repeat(MAX_GITHUB_SLUG_BYTES + 1)
    ))
    .is_err());
    assert!(validate_publication_ref(&format!(
        "refs/heads/{}",
        "a".repeat(MAX_PUBLICATION_REF_BYTES)
    ))
    .is_err());
    assert!(validate_publication_git_operation(&[
        OsString::from("push"),
        OsString::from("--no-verify"),
        OsString::from("--force-with-lease=refs/heads/review:"),
        OsString::from("maco-publication"),
        OsString::from(format!("{}:refs/heads/review", "A".repeat(40))),
    ])
    .is_err());

    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "owner".to_string(),
        name: "repo".to_string(),
    };
    for malicious in ["--web", "--help"] {
        let view = [
            "pr",
            "view",
            malicious,
            "--repo",
            "github.example/owner/repo",
            "--json",
            "url,headRefOid,baseRefOid,number,baseRefName,state,isDraft",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        assert!(validate_gh_operation(&view, &StdinMode::Null, &repository).is_err());

        let create = [
            "pr",
            "create",
            "--repo",
            "github.example/owner/repo",
            "--base",
            malicious,
            "--head",
            "branch",
            "--title",
            "title",
            "--body-file",
            "-",
        ]
        .into_iter()
        .map(OsString::from)
        .collect::<Vec<_>>();
        assert!(
            validate_gh_operation(&create, &StdinMode::Bytes(Vec::new()), &repository).is_err()
        );

        for args in [
            vec![
                "pr",
                "list",
                "--repo",
                "github.example/owner/repo",
                "--head",
                malicious,
                "--state",
                "all",
                "--json",
                "url,headRefOid,baseRefOid,number,baseRefName,state,isDraft",
            ],
            vec![
                "pr",
                "create",
                "--repo",
                "github.example/owner/repo",
                "--base",
                "main",
                "--head",
                malicious,
                "--title",
                "title",
                "--body-file",
                "-",
            ],
            vec![
                "pr",
                "create",
                "--repo",
                "github.example/owner/repo",
                "--base",
                "main",
                "--head",
                "branch",
                "--title",
                malicious,
                "--body-file",
                "-",
            ],
            vec![
                "issue",
                "create",
                "--repo",
                "github.example/owner/repo",
                "--title",
                "title",
                "--body-file",
                "-",
                "--label",
                malicious,
            ],
        ] {
            let stdin = if args.get(1) == Some(&"list") {
                StdinMode::Null
            } else {
                StdinMode::Bytes(Vec::new())
            };
            let args = args.into_iter().map(OsString::from).collect::<Vec<_>>();
            assert!(validate_gh_operation(&args, &stdin, &repository).is_err());
        }
    }
}

#[test]
fn github_source_list_argv_is_host_bound_exact_and_bounded() {
    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "owner".to_string(),
        name: "repo".to_string(),
    };
    let args = github_source_list_args(
        &repository,
        ExternalSourceObjectKind::PullRequest,
        17,
        &["security".to_string(), "ready".to_string()],
    )
    .expect("trusted source list argv");
    let text = args
        .iter()
        .map(|argument| argument.to_str().expect("UTF-8 argv"))
        .collect::<Vec<_>>();
    assert_eq!(
        text,
        [
            "pr",
            "list",
            "--repo",
            "github.example/owner/repo",
            "--state",
            "open",
            "--json",
            GITHUB_PR_SOURCE_FIELDS,
            "--limit",
            "17",
            "--label",
            "security",
            "--label",
            "ready",
        ]
    );
    validate_gh_operation(&args, &StdinMode::Null, &repository)
        .expect("exact allowlisted source list");
    let issue_args = github_source_list_args(
        &repository,
        ExternalSourceObjectKind::Issue,
        MAX_GITHUB_SOURCE_LIST_ITEMS,
        &[],
    )
    .expect("trusted issue source list argv");
    validate_gh_operation(&issue_args, &StdinMode::Null, &repository)
        .expect("exact allowlisted issue source list");
    assert_eq!(issue_args[0], "issue");
    assert_eq!(issue_args[3], "github.example/owner/repo");

    let other_host = GithubRepositoryIdentity {
        host: "other.example".to_string(),
        owner: "owner".to_string(),
        name: "repo".to_string(),
    };
    assert!(validate_gh_operation(&args, &StdinMode::Null, &other_host).is_err());
    assert!(github_source_list_args(&repository, ExternalSourceObjectKind::Issue, 0, &[]).is_err());
    assert!(github_source_list_args(
        &repository,
        ExternalSourceObjectKind::Issue,
        MAX_GITHUB_SOURCE_LIST_ITEMS + 1,
        &[]
    )
    .is_err());
    assert!(github_source_list_args(
        &repository,
        ExternalSourceObjectKind::Issue,
        1,
        &vec!["label".to_string(); MAX_GITHUB_SOURCE_LIST_LABELS + 1]
    )
    .is_err());
    assert!(github_source_list_args(
        &repository,
        ExternalSourceObjectKind::Issue,
        1,
        &["--web".to_string()]
    )
    .is_err());
}

#[test]
fn zeroizing_string_debug_is_redacted_and_explicit_clear_empties_it() {
    let mut secret = ZeroizingString("test-token".to_string());
    assert_eq!(format!("{secret:?}"), "<redacted:zeroizing-string>");
    secret.zeroize();
    assert!(secret.as_str().is_empty());
}

#[cfg(unix)]
#[test]
fn gh_command_refuses_changed_private_runtime_before_spawn() {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir().expect("tempdir");
    let repo_path = temp.path().join("repo");
    Repository::init(&repo_path).expect("init repo");
    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "owner".to_string(),
        name: "repo".to_string(),
    };
    let mut context = GhCommandContext::create_with_token_source(&repo_path, &repository, |key| {
        enterprise_test_value("github.example", key)
    })
    .expect("create gh context");
    assert_ne!(context.runtime_directory.path(), repo_path);
    fs::set_permissions(
        context.runtime_directory.path(),
        fs::Permissions::from_mode(0o755),
    )
    .expect("weaken gh runtime mode");
    let result = context.run_inner(
        "gh identity test",
        vec![OsString::from("--version")],
        StdinMode::Null,
    );
    fs::set_permissions(
        context.runtime_directory.path(),
        fs::Permissions::from_mode(0o700),
    )
    .expect("restore gh runtime mode for cleanup");
    let error = match result {
        Ok(_) => panic!("changed gh runtime must fail before command execution"),
        Err(error) => error,
    };
    assert!(error.to_string().contains("private gh runtime changed"));
    context.close().expect("explicit gh context cleanup");
}

#[cfg(unix)]
#[test]
fn publication_remote_binding_key_is_private_stable_and_fixed_length() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let state = tempfile::tempdir().expect("state dir");
    let first = load_or_create_remote_binding_secret(state.path()).expect("create key");
    let second = load_or_create_remote_binding_secret(state.path()).expect("reload key");
    assert_eq!(first, second);
    assert_eq!(first.len(), REMOTE_BINDING_SECRET_BYTES);
    let metadata =
        fs::metadata(state.path().join(REMOTE_BINDING_SECRET_FILE)).expect("key metadata");
    assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    assert_eq!(metadata.nlink(), 1);
}

#[test]
fn publication_remote_binding_key_missing_with_prior_transaction_fails_closed() {
    let state = tempfile::tempdir().expect("state dir");
    fs::create_dir_all(state.path().join("publication-transactions/prior"))
        .expect("prior transaction");

    let error = load_or_create_remote_binding_secret(state.path())
        .expect_err("missing key with prior transaction must fail");

    assert!(error
        .to_string()
        .contains("prior transaction entries exist"));
    assert!(!state.path().join(REMOTE_BINDING_SECRET_FILE).exists());
}

#[cfg(unix)]
#[test]
fn publication_remote_binding_key_rejects_corruption_permissions_and_symlink() {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let corrupt = tempfile::tempdir().expect("corrupt state");
    let corrupt_path = corrupt.path().join(REMOTE_BINDING_SECRET_FILE);
    fs::write(&corrupt_path, b"short").expect("write corrupt key");
    fs::set_permissions(&corrupt_path, fs::Permissions::from_mode(0o600))
        .expect("chmod corrupt key");
    assert!(read_remote_binding_secret(&corrupt_path)
        .expect_err("corrupt key must fail")
        .to_string()
        .contains("invalid length"));

    let exposed = tempfile::tempdir().expect("exposed state");
    let exposed_path = exposed.path().join(REMOTE_BINDING_SECRET_FILE);
    fs::write(&exposed_path, [1_u8; REMOTE_BINDING_SECRET_BYTES]).expect("write exposed key");
    fs::set_permissions(&exposed_path, fs::Permissions::from_mode(0o644))
        .expect("chmod exposed key");
    assert!(read_remote_binding_secret(&exposed_path)
        .expect_err("exposed key must fail")
        .to_string()
        .contains("mode 0600"));

    let replaced = tempfile::tempdir().expect("replaced state");
    let target = replaced.path().join("target");
    fs::write(&target, [2_u8; REMOTE_BINDING_SECRET_BYTES]).expect("write key target");
    fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).expect("chmod key target");
    let replaced_path = replaced.path().join(REMOTE_BINDING_SECRET_FILE);
    symlink(&target, &replaced_path).expect("replace key with symlink");
    assert!(read_remote_binding_secret(&replaced_path)
        .expect_err("symlink key must fail")
        .to_string()
        .contains("non-reparse"));
}

#[cfg(unix)]
#[test]
fn publication_remote_binding_key_recovers_only_known_crash_temp_link() {
    use std::os::unix::fs::MetadataExt;

    let state = tempfile::tempdir().expect("state dir");
    let secret = load_or_create_remote_binding_secret(state.path()).expect("create key");
    let key = state.path().join(REMOTE_BINDING_SECRET_FILE);
    let crash_temp = state
        .path()
        .join(format!(".{REMOTE_BINDING_SECRET_FILE}-123-456.tmp"));
    fs::hard_link(&key, &crash_temp).expect("simulate crash temp hard link");
    assert_eq!(fs::metadata(&key).expect("linked key metadata").nlink(), 2);

    let recovered = read_remote_binding_secret(&key).expect("recover known temp link");

    assert_eq!(recovered, secret);
    assert!(!crash_temp.exists());
    assert_eq!(
        fs::metadata(&key).expect("recovered key metadata").nlink(),
        1
    );

    let unknown = state.path().join("unknown-key-link");
    fs::hard_link(&key, &unknown).expect("create unknown key hard link");
    assert!(read_remote_binding_secret(&key)
        .expect_err("unknown hard link must fail")
        .to_string()
        .contains("multiple hard links"));
}

use crate::optimizer::{
    ids::TimestampMillis,
    merge_authority::{
        AgentIdentity, CompletionMode, LensDecision, LensVerdict, MergeActor, MergeBlocker,
        ProducerFingerprint, SessionId,
    },
};
use crate::publication::forge_transport::{
    decide_pull_request_merge, AuthenticatedPullRequestMergeEvidence, FakeForgeTransport,
    ForgeActor, ForgeCheck, ForgeCheckConclusion, ForgeCheckStatus, ForgeItem, ForgeItemKind,
    ForgeRepository, ForgeReview, ForgeReviewState, ForgeTimestamp, ProviderObjectId,
    ProviderObjectKind, PullRequestAuditorEvidence, PullRequestChangedPathsEvidence,
    PullRequestFreshnessEvidence, PullRequestFreshnessStatus, PullRequestMergeAuthorityBlocker,
    PullRequestMergeAuthorityDecision, PullRequestMergeAuthorityInput,
    PullRequestMergeSimulationEvidence, PullRequestProducerEvidence, PullRequestReviewSnapshot,
    ReportedActorKind,
};

const MERGE_AUTHORITY_OBSERVED_AT: &str = "2026-08-30T09:00:00Z";

fn merge_authority_object(kind: ProviderObjectKind, stable_id: &str) -> ProviderObjectId {
    ProviderObjectId::new("github", kind, stable_id).expect("valid provider object")
}

fn merge_authority_repository() -> ForgeRepository {
    ForgeRepository::new(
        "github",
        "github.example/acme/repo",
        merge_authority_object(ProviderObjectKind::Repository, "R_authority"),
    )
    .expect("valid repository")
}

fn merge_authority_item(head_oid: &str) -> ForgeItem {
    ForgeItem::new(
        merge_authority_repository(),
        ForgeItemKind::PullRequest,
        327,
        merge_authority_object(ProviderObjectKind::Item, "PR_327"),
        "revision:327",
        Some(head_oid.to_string()),
        Some("2".repeat(40)),
    )
    .expect("valid pull request")
}

fn merge_authority_check(
    stable_id: &str,
    name: &str,
    status: ForgeCheckStatus,
    conclusion: Option<ForgeCheckConclusion>,
    head_oid: &str,
) -> ForgeCheck {
    ForgeCheck::new(
        merge_authority_object(ProviderObjectKind::Check, stable_id),
        ForgeActor::new(
            "github",
            merge_authority_object(ProviderObjectKind::Actor, "BOT_ci"),
            "ci-bot",
            ReportedActorKind::Bot,
        )
        .expect("valid check actor"),
        name,
        status,
        conclusion,
        head_oid,
        ForgeTimestamp::new(MERGE_AUTHORITY_OBSERVED_AT).expect("valid check timestamp"),
    )
    .expect("valid check")
}

fn merge_authority_auditor_review(
    head_oid: &str,
    actor_id: &str,
    state: ForgeReviewState,
) -> ForgeReview {
    ForgeReview::new(
        merge_authority_object(ProviderObjectKind::Review, "R_auditor"),
        ForgeActor::new(
            "github",
            merge_authority_object(ProviderObjectKind::Actor, actor_id),
            actor_id,
            ReportedActorKind::Human,
        )
        .expect("valid auditor actor"),
        state,
        "authenticated auditor approval",
        ForgeTimestamp::new(MERGE_AUTHORITY_OBSERVED_AT).expect("valid review timestamp"),
        head_oid,
    )
    .expect("valid auditor review")
}

fn merge_execution_snapshot(
    head_oid: &str,
    lint_status: ForgeCheckStatus,
    lint_conclusion: Option<ForgeCheckConclusion>,
    auditor_actor_id: &str,
    review_state: ForgeReviewState,
) -> PullRequestReviewSnapshot {
    PullRequestReviewSnapshot::new(
        merge_authority_item(head_oid),
        ForgeTimestamp::new(MERGE_AUTHORITY_OBSERVED_AT).expect("valid observation timestamp"),
        vec![merge_authority_auditor_review(
            head_oid,
            auditor_actor_id,
            review_state,
        )],
        Vec::new(),
        vec![
            merge_authority_check(
                "C_unit",
                "ci/unit",
                ForgeCheckStatus::Completed,
                Some(ForgeCheckConclusion::Success),
                head_oid,
            ),
            merge_authority_check("C_lint", "ci/lint", lint_status, lint_conclusion, head_oid),
        ],
    )
    .expect("valid review snapshot")
}

fn merge_authority_fixture(
    lint_status: ForgeCheckStatus,
    lint_conclusion: Option<ForgeCheckConclusion>,
) -> (PullRequestReviewSnapshot, PullRequestMergeAuthorityInput) {
    let snapshot = merge_execution_snapshot(
        &"1".repeat(40),
        lint_status,
        lint_conclusion,
        "auditor",
        ForgeReviewState::Approved,
    );
    let producer_actor = MergeActor {
        agent: AgentIdentity {
            stable_id: "producer".to_string(),
        },
        session: SessionId {
            id: "producer-session".to_string(),
        },
        model_label: "worker-model".to_string(),
    };
    let input = PullRequestMergeAuthorityInput {
        freshness: Some(PullRequestFreshnessEvidence {
            current_item: snapshot.item().clone(),
            snapshot_observed_at: snapshot.observed_at().clone(),
            status: PullRequestFreshnessStatus::Fresh,
            decided_at: TimestampMillis::from_millis(1_777_777_777_000),
        }),
        required_checks: Some(vec!["ci/unit".to_string(), "ci/lint".to_string()]),
        producer: Some(PullRequestProducerEvidence {
            head_oid: "1".repeat(40),
            producer: ProducerFingerprint {
                actor: producer_actor,
                commit_authors: vec!["producer".to_string()],
                commit_committers: vec!["producer".to_string()],
            },
        }),
        auditor: Some(PullRequestAuditorEvidence {
            head_oid: "1".repeat(40),
            snapshot_observed_at: snapshot.observed_at().clone(),
            auditor: MergeActor {
                agent: AgentIdentity {
                    stable_id: "auditor".to_string(),
                },
                session: SessionId {
                    id: "auditor-session".to_string(),
                },
                model_label: "auditor-model".to_string(),
            },
            lenses: vec![
                LensVerdict {
                    lens_id: "diff-lens".to_string(),
                    model_label: "review-model-a".to_string(),
                    framing: "adversarial-diff".to_string(),
                    information_scope: "diff-only".to_string(),
                    decision: LensDecision::Accept,
                },
                LensVerdict {
                    lens_id: "test-lens".to_string(),
                    model_label: "review-model-b".to_string(),
                    framing: "tests-as-contract".to_string(),
                    information_scope: "tests-only".to_string(),
                    decision: LensDecision::Accept,
                },
            ],
        }),
        merge_simulation: Some(PullRequestMergeSimulationEvidence {
            head_oid: "1".repeat(40),
            base_oid: "2".repeat(40),
            snapshot_observed_at: snapshot.observed_at().clone(),
            merges_cleanly: true,
        }),
        completion_mode: Some(CompletionMode::MergeCommit),
        changed_paths: Some(PullRequestChangedPathsEvidence {
            head_oid: "1".repeat(40),
            paths: vec![PathBuf::from("src/publication/forge_coordination.rs")],
        }),
    };
    (snapshot, input)
}

fn assert_merge_authority_blocker(
    decision: &PullRequestMergeAuthorityDecision,
    expected: impl Fn(&PullRequestMergeAuthorityBlocker) -> bool,
) {
    assert!(
        !decision.is_allowed(),
        "unexpected allowed decision: {decision:?}"
    );
    assert!(
        decision.blockers().iter().any(expected),
        "expected blocker was absent: {decision:?}"
    );
}

#[test]
fn pull_request_merge_evidence_adapter_allows_fully_bound_green_evidence() {
    let (snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );

    let decision = decide_pull_request_merge(&snapshot, &input);

    assert!(
        decision.is_allowed(),
        "green evidence was blocked: {decision:?}"
    );
    let optimizer = decision.merge_decision().expect("optimizer decision");
    assert!(optimizer.auto_merge_performed);
    assert!(optimizer.blockers.is_empty());
    assert!(optimizer.failed_checks.is_empty());
    assert!(optimizer.explanation.contains("ci/unit, ci/lint"));
}

#[test]
fn pull_request_merge_evidence_adapter_types_every_missing_input() {
    let (snapshot, baseline) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );

    let mut input = baseline.clone();
    input.freshness = None;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::MissingFreshnessEvidence
        )
    });

    let mut input = baseline.clone();
    input.required_checks = None;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::MissingRequiredChecks
        )
    });

    let mut input = baseline.clone();
    input.producer = None;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::MissingProducerEvidence
        )
    });

    let mut input = baseline.clone();
    input.auditor = None;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::MissingAuditorEvidence
        )
    });

    let mut input = baseline.clone();
    input.merge_simulation = None;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::MissingMergeSimulationEvidence
        )
    });

    let mut input = baseline.clone();
    input.completion_mode = None;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::MissingCompletionMode
        )
    });

    let mut input = baseline;
    input.changed_paths = None;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::MissingChangedPathsEvidence
        )
    });
}

#[test]
fn pull_request_merge_evidence_adapter_rejects_every_stale_binding() {
    let (snapshot, baseline) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );

    let mut input = baseline.clone();
    input.freshness.as_mut().expect("freshness").status = PullRequestFreshnessStatus::Stale;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::StaleSnapshotObservation
        )
    });

    let mut input = baseline.clone();
    input.freshness.as_mut().expect("freshness").status = PullRequestFreshnessStatus::Uncertain;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::UncertainSnapshotFreshness
        )
    });

    let mut input = baseline.clone();
    input.freshness.as_mut().expect("freshness").current_item =
        merge_authority_item(&"3".repeat(40));
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::StaleSnapshotHead { .. }
        )
    });

    let mut input = baseline.clone();
    input.producer.as_mut().expect("producer").head_oid = "3".repeat(40);
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::StaleProducerEvidence
        )
    });

    let mut input = baseline.clone();
    input.auditor.as_mut().expect("auditor").head_oid = "3".repeat(40);
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::StaleAuditorEvidence
        )
    });

    let mut input = baseline.clone();
    input
        .merge_simulation
        .as_mut()
        .expect("merge simulation")
        .base_oid = "3".repeat(40);
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::StaleMergeSimulationEvidence
        )
    });

    let mut input = baseline;
    input
        .changed_paths
        .as_mut()
        .expect("changed paths")
        .head_oid = "3".repeat(40);
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::StaleChangedPathsEvidence
        )
    });
}

#[test]
fn pull_request_merge_evidence_adapter_maps_all_non_success_check_states() {
    let (snapshot, mut input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    input.required_checks = Some(vec!["ci/missing".to_string()]);
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::MissingRequiredCheck { .. }
        )
    });

    let (snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Stale),
    );
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::StaleRequiredCheck { .. }
        )
    });

    let (snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Skipped),
    );
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::SkippedRequiredCheck { .. }
        )
    });

    let (snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Failure),
    );
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::FailedRequiredCheck { .. }
        )
    });

    let (snapshot, input) = merge_authority_fixture(ForgeCheckStatus::InProgress, None);
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::UncertainRequiredCheck { .. }
        )
    });
}

#[test]
fn pull_request_merge_evidence_adapter_requires_two_decorrelated_accepted_lenses() {
    let (snapshot, mut input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    let lenses = &mut input.auditor.as_mut().expect("auditor").lenses;
    lenses[1].model_label = lenses[0].model_label.clone();
    lenses[1].framing = lenses[0].framing.clone();
    lenses[1].information_scope = lenses[0].information_scope.clone();
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::OptimizerBlocked(
                MergeBlocker::InsufficientDecorrelatedLenses { .. }
            )
        )
    });

    let (snapshot, mut input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    input.auditor.as_mut().expect("auditor").lenses[0].decision = LensDecision::Uncertain;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::OptimizerBlocked(
                MergeBlocker::BlockingReviewLenses { .. }
            )
        )
    });
}

#[test]
fn pull_request_merge_evidence_adapter_preserves_independence_and_never_auto_merge() {
    let (snapshot, mut input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    let producer_actor = input
        .producer
        .as_ref()
        .expect("producer")
        .producer
        .actor
        .clone();
    input.auditor.as_mut().expect("auditor").auditor = producer_actor;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::OptimizerBlocked(
                MergeBlocker::ReviewerNotIndependent
            )
        )
    });

    let (snapshot, mut input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    input.changed_paths.as_mut().expect("changed paths").paths =
        vec![PathBuf::from("src/optimizer/merge_authority.rs")];
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::OptimizerBlocked(MergeBlocker::NeverAutoMerge { .. })
        )
    });
}

#[test]
fn pull_request_merge_evidence_adapter_requires_clean_non_flattening_simulation() {
    let (snapshot, mut input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    input
        .merge_simulation
        .as_mut()
        .expect("merge simulation")
        .merges_cleanly = false;
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::OptimizerBlocked(MergeBlocker::MergeSimulationFailed)
        )
    });

    let (snapshot, mut input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    input.completion_mode = Some(CompletionMode::Squash);
    assert_merge_authority_blocker(&decide_pull_request_merge(&snapshot, &input), |blocker| {
        matches!(
            blocker,
            PullRequestMergeAuthorityBlocker::OptimizerBlocked(
                MergeBlocker::HistoryFlatteningCompletionMode { .. }
            )
        )
    });
}

fn authenticated_merge_evidence(
    snapshot: &PullRequestReviewSnapshot,
    input: &PullRequestMergeAuthorityInput,
) -> AuthenticatedPullRequestMergeEvidence {
    AuthenticatedPullRequestMergeEvidence::from_authenticated_acceptance(
        snapshot.item().clone(),
        merge_authority_object(ProviderObjectKind::Review, "R_auditor"),
        ForgeActor::new(
            "github",
            merge_authority_object(
                ProviderObjectKind::Actor,
                &input
                    .auditor
                    .as_ref()
                    .expect("fixture auditor")
                    .auditor
                    .agent
                    .stable_id,
            ),
            input
                .auditor
                .as_ref()
                .expect("fixture auditor")
                .auditor
                .agent
                .stable_id
                .clone(),
            ReportedActorKind::Human,
        )
        .expect("fixture approved reviewer"),
        input
            .required_checks
            .clone()
            .expect("fixture required checks"),
        input.producer.clone().expect("fixture producer"),
        input.auditor.clone().expect("fixture auditor"),
        input
            .merge_simulation
            .clone()
            .expect("fixture merge simulation"),
        input.completion_mode.expect("fixture completion mode"),
        input.changed_paths.clone().expect("fixture changed paths"),
    )
    .expect("authenticated merge evidence")
}

fn authenticated_merge_repository() -> tempfile::TempDir {
    let repository = tempfile::tempdir().expect("merge repository tempdir");
    Repository::init(repository.path()).expect("initialize merge repository");
    repository
}

#[derive(Default)]
struct ScriptedAuthenticatedMergeState {
    lookup_override: Option<Vec<PullRequestMergeReceipt>>,
    lose_execute_response: bool,
    lookup_calls: usize,
    execute_calls: usize,
    verify_calls: usize,
}

struct ScriptedAuthenticatedMergeTransport {
    inner: FakeForgeTransport,
    state: Mutex<ScriptedAuthenticatedMergeState>,
}

impl ScriptedAuthenticatedMergeTransport {
    fn new(snapshot: &PullRequestReviewSnapshot) -> Self {
        let mut inner = FakeForgeTransport::new();
        inner
            .register_pull_request_merge_observation(snapshot.item(), snapshot.clone())
            .expect("register scripted merge ground truth");
        Self {
            inner,
            state: Mutex::new(ScriptedAuthenticatedMergeState::default()),
        }
    }

    fn override_lookup(&self, receipts: Option<Vec<PullRequestMergeReceipt>>) {
        self.state
            .lock()
            .expect("scripted merge state")
            .lookup_override = receipts;
    }

    fn lose_execute_response(&self) {
        self.state
            .lock()
            .expect("scripted merge state")
            .lose_execute_response = true;
    }

    fn call_counts(&self) -> (usize, usize, usize) {
        let state = self.state.lock().expect("scripted merge state");
        (state.lookup_calls, state.execute_calls, state.verify_calls)
    }
}

impl PullRequestMergeTransport for ScriptedAuthenticatedMergeTransport {
    fn observe_pull_request_for_merge(
        &self,
        candidate: &ForgeItem,
    ) -> Result<PullRequestReviewSnapshot> {
        self.inner.observe_pull_request_for_merge(candidate)
    }

    fn lookup_pull_request_merge(
        &self,
        effect: &PullRequestMergeEffect,
    ) -> Result<Vec<PullRequestMergeReceipt>> {
        let lookup_override = {
            let mut state = self.state.lock().expect("scripted merge state");
            state.lookup_calls += 1;
            state.lookup_override.clone()
        };
        match lookup_override {
            Some(receipts) => Ok(receipts),
            None => self.inner.lookup_pull_request_merge(effect),
        }
    }

    fn execute_pull_request_merge(
        &self,
        effect: &PullRequestMergeEffect,
    ) -> Result<PullRequestMergeReceipt> {
        let lose_response = {
            let mut state = self.state.lock().expect("scripted merge state");
            state.execute_calls += 1;
            state.lose_execute_response
        };
        let receipt = self.inner.execute_pull_request_merge(effect)?;
        if lose_response {
            bail!("injected authenticated merge response loss");
        }
        Ok(receipt)
    }

    fn verify_pull_request_merge(
        &self,
        effect: &PullRequestMergeEffect,
        receipt: &PullRequestMergeReceipt,
    ) -> Result<PullRequestMergeReceipt> {
        self.state
            .lock()
            .expect("scripted merge state")
            .verify_calls += 1;
        receipt.validate_for_effect(effect)?;
        if self.lookup_pull_request_merge(effect)?.as_slice() != [receipt.clone()] {
            bail!("scripted merge receipt was missing, duplicated, or changed");
        }
        Ok(receipt.clone())
    }
}

fn seed_authenticated_merge_phase(
    repo: &Path,
    candidate: &ForgeItem,
    evidence: &AuthenticatedPullRequestMergeEvidence,
    transport: &ScriptedAuthenticatedMergeTransport,
    phase: EffectPhase,
    seed_provider_effect: bool,
) -> Option<PullRequestMergeReceipt> {
    let plan_digest = stable_json_digest(&(
        "maco_authenticated_pull_request_merge_plan_v1",
        candidate,
        evidence,
    ))
    .expect("authenticated merge plan digest");
    let effect_id = format!("merge:{plan_digest}");
    let logical_id = format!("pr-merge-{plan_digest}");
    let planned = AuthenticatedPullRequestMergeRecord {
        version: AUTHENTICATED_PR_MERGE_VERSION,
        plan_digest: plan_digest.clone(),
        candidate: candidate.clone(),
        effect: None,
        authority: None,
        receipt: None,
    };
    let auth = repository_auth_writer(repo)
        .expect("seed authenticated merge auth writer")
        .into_authenticator()
        .expect("seed authenticated merge authenticator");
    let mut wal: EffectWal = EffectWal::create_planned(auth, &logical_id, &effect_id, &planned)
        .expect("seed planned authenticated merge");
    if phase == EffectPhase::Planned {
        return None;
    }

    let authorized = match authorize_current_pull_request_merge(candidate, evidence, transport)
        .expect("authorize seeded authenticated merge")
    {
        PullRequestMergePreflight::Allowed(authorized) => authorized,
        PullRequestMergePreflight::Blocked(outcome) => {
            panic!("seeded authenticated merge was blocked: {outcome:?}")
        }
    };
    let effect = pull_request_merge_effect(&effect_id, &plan_digest, evidence, &authorized)
        .expect("seed authenticated merge effect");
    let started = AuthenticatedPullRequestMergeRecord {
        version: AUTHENTICATED_PR_MERGE_VERSION,
        plan_digest: plan_digest.clone(),
        candidate: candidate.clone(),
        effect: Some(effect.clone()),
        authority: Some(authorized.authority.clone()),
        receipt: None,
    };
    wal.started(&effect_id, &started)
        .expect("seed started authenticated merge");

    let receipt = seed_provider_effect.then(|| {
        transport
            .execute_pull_request_merge(&effect)
            .expect("seed provider merge receipt")
    });
    if matches!(phase, EffectPhase::Observed | EffectPhase::Completed) {
        let observed = AuthenticatedPullRequestMergeRecord {
            receipt: Some(
                receipt
                    .clone()
                    .expect("observed seeded merge requires a provider receipt"),
            ),
            ..started
        };
        wal.observed(&effect_id, &observed)
            .expect("seed observed authenticated merge");
        if phase == EffectPhase::Completed {
            wal.completed(&effect_id, &observed)
                .expect("seed completed authenticated merge");
        }
    }
    receipt
}

fn mismatched_effect_merge_receipt(receipt: &PullRequestMergeReceipt) -> PullRequestMergeReceipt {
    PullRequestMergeReceipt::new(
        "merge:mismatched-effect",
        receipt.item().clone(),
        receipt.approved_actor().clone(),
        receipt.evidence_digest(),
        receipt.ground_truth_digest(),
        receipt.completion_mode(),
        receipt.provider_merge_id().clone(),
        receipt.merged_oid(),
        receipt.url(),
        receipt.merged_at().clone(),
    )
    .expect("valid receipt for a different merge effect")
}

fn changed_provider_merge_receipt(receipt: &PullRequestMergeReceipt) -> PullRequestMergeReceipt {
    let changed_oid = if receipt.merged_oid().bytes().all(|byte| byte == b'f') {
        "e".repeat(40)
    } else {
        "f".repeat(40)
    };
    let plan_digest = receipt
        .evidence_digest()
        .strip_prefix("sha256:")
        .expect("merge evidence digest prefix");
    PullRequestMergeReceipt::new(
        format!("merge:{plan_digest}"),
        receipt.item().clone(),
        receipt.approved_actor().clone(),
        receipt.evidence_digest(),
        receipt.ground_truth_digest(),
        receipt.completion_mode(),
        receipt.provider_merge_id().clone(),
        changed_oid,
        receipt.url(),
        receipt.merged_at().clone(),
    )
    .expect("valid changed provider merge receipt")
}

#[test]
fn authenticated_pull_request_merge_recovers_every_wal_phase_without_a_second_merge() {
    for phase in [
        EffectPhase::Planned,
        EffectPhase::Started,
        EffectPhase::Observed,
        EffectPhase::Completed,
    ] {
        let (snapshot, input) = merge_authority_fixture(
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
        );
        let evidence = authenticated_merge_evidence(&snapshot, &input);
        let repository = authenticated_merge_repository();
        let transport = ScriptedAuthenticatedMergeTransport::new(&snapshot);
        let seeded_receipt = seed_authenticated_merge_phase(
            repository.path(),
            snapshot.item(),
            &evidence,
            &transport,
            phase,
            phase != EffectPhase::Planned,
        );

        let recovered = execute_authenticated_pull_request_merge(
            repository.path(),
            snapshot.item(),
            Some(&evidence),
            &transport,
        )
        .unwrap_or_else(|error| panic!("recover {phase:?} authenticated merge: {error:#}"));
        let retry = execute_authenticated_pull_request_merge(
            repository.path(),
            snapshot.item(),
            Some(&evidence),
            &transport,
        )
        .unwrap_or_else(|error| panic!("retry recovered {phase:?} authenticated merge: {error:#}"));

        assert!(recovered.is_merged(), "{phase:?} recovery was blocked");
        assert_eq!(recovered.receipt(), retry.receipt());
        if let Some(seeded_receipt) = seeded_receipt.as_ref() {
            assert_eq!(recovered.receipt(), Some(seeded_receipt));
        }
        assert_eq!(
            transport.call_counts().1,
            1,
            "{phase:?} recovery issued a second provider merge"
        );
    }
}

#[test]
fn authenticated_pull_request_merge_reconciles_a_lost_response_without_resending() {
    let (snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    let evidence = authenticated_merge_evidence(&snapshot, &input);
    let repository = authenticated_merge_repository();
    let transport = ScriptedAuthenticatedMergeTransport::new(&snapshot);
    transport.lose_execute_response();

    let recovered = execute_authenticated_pull_request_merge(
        repository.path(),
        snapshot.item(),
        Some(&evidence),
        &transport,
    )
    .expect("lost merge response reconciles by exact lookup");
    let retry = execute_authenticated_pull_request_merge(
        repository.path(),
        snapshot.item(),
        Some(&evidence),
        &transport,
    )
    .expect("completed lost-response recovery is reusable");

    assert_eq!(recovered.receipt(), retry.receipt());
    let (lookup_calls, execute_calls, verify_calls) = transport.call_counts();
    assert!(
        lookup_calls > 0,
        "lost response was not reconciled by lookup"
    );
    assert!(verify_calls > 0, "reconciled receipt was not verified");
    assert_eq!(execute_calls, 1, "lost response caused a blind resend");
}

#[test]
fn authenticated_pull_request_merge_started_lookup_ambiguity_fails_closed() {
    for case in ["zero", "multiple", "mismatched"] {
        let (snapshot, input) = merge_authority_fixture(
            ForgeCheckStatus::Completed,
            Some(ForgeCheckConclusion::Success),
        );
        let evidence = authenticated_merge_evidence(&snapshot, &input);
        let repository = authenticated_merge_repository();
        let transport = ScriptedAuthenticatedMergeTransport::new(&snapshot);
        let seeded_receipt = seed_authenticated_merge_phase(
            repository.path(),
            snapshot.item(),
            &evidence,
            &transport,
            EffectPhase::Started,
            case != "zero",
        );
        match case {
            "zero" => transport.override_lookup(Some(Vec::new())),
            "multiple" => {
                let receipt = seeded_receipt.expect("multiple case provider receipt");
                transport.override_lookup(Some(vec![receipt.clone(), receipt]));
            }
            "mismatched" => {
                let receipt = seeded_receipt.expect("mismatched case provider receipt");
                transport.override_lookup(Some(vec![mismatched_effect_merge_receipt(&receipt)]));
            }
            _ => unreachable!(),
        }
        let execute_calls_before = transport.call_counts().1;

        let error = execute_authenticated_pull_request_merge(
            repository.path(),
            snapshot.item(),
            Some(&evidence),
            &transport,
        )
        .unwrap_err();

        let error_text = format!("{error:#}");
        assert!(
            if case == "mismatched" {
                error_text.contains("does not bind the exact authorized effect")
            } else {
                error_text.contains("started pull-request merge")
            },
            "unexpected {case} lookup error: {error_text}"
        );
        assert_eq!(
            transport.call_counts().1,
            execute_calls_before,
            "{case} lookup ambiguity caused a blind provider merge"
        );
    }
}

#[test]
fn authenticated_pull_request_merge_completed_receipt_is_revalidated_and_stale_state_fails() {
    let (snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    let evidence = authenticated_merge_evidence(&snapshot, &input);
    let repository = authenticated_merge_repository();
    let transport = ScriptedAuthenticatedMergeTransport::new(&snapshot);
    let receipt = seed_authenticated_merge_phase(
        repository.path(),
        snapshot.item(),
        &evidence,
        &transport,
        EffectPhase::Completed,
        true,
    )
    .expect("completed provider receipt");

    let exact = execute_authenticated_pull_request_merge(
        repository.path(),
        snapshot.item(),
        Some(&evidence),
        &transport,
    )
    .expect("completed receipt revalidates against exact provider state");
    assert_eq!(exact.receipt(), Some(&receipt));

    for stale in [Vec::new(), vec![changed_provider_merge_receipt(&receipt)]] {
        transport.override_lookup(Some(stale));
        let error = execute_authenticated_pull_request_merge(
            repository.path(),
            snapshot.item(),
            Some(&evidence),
            &transport,
        )
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("completed pull-request merge receipt changed or disappeared"),
            "unexpected completed-receipt revalidation error: {error:#}"
        );
        assert_eq!(
            transport.call_counts().1,
            1,
            "stale completed receipt caused a second provider merge"
        );
    }
    assert!(
        transport.call_counts().2 >= 3,
        "completed receipt was not reverified on every retry"
    );
}

#[test]
fn authenticated_github_merge_operation_is_finite_and_head_bound() {
    let repository = GithubRepositoryIdentity {
        host: "github.example".to_string(),
        owner: "acme".to_string(),
        name: "repo".to_string(),
    };
    let digest = "a".repeat(64);
    let operation = AuthenticatedGithubOperation::Merge {
        number: 327,
        expected_head_oid: "1".repeat(40),
        effect_id: format!("merge:{digest}"),
        evidence_digest: format!("sha256:{digest}"),
        ground_truth_digest: format!("sha256:{}", "b".repeat(64)),
    };
    let (args, stdin) = operation
        .command(&repository)
        .expect("finite merge operation");
    let args = args
        .iter()
        .map(|argument| argument.to_str().expect("UTF-8 argument"))
        .collect::<Vec<_>>();
    assert_eq!(
        args,
        [
            "api",
            "--method",
            "PUT",
            "repos/acme/repo/pulls/327/merge",
            "--input",
            "-"
        ]
    );
    let StdinMode::Bytes(body) = stdin else {
        panic!("merge operation must send one bounded JSON body");
    };
    let body: serde_json::Value = serde_json::from_slice(&body).expect("merge JSON");
    assert_eq!(body["sha"], "1".repeat(40));
    assert_eq!(body["merge_method"], "merge");
    assert!(body["commit_message"]
        .as_str()
        .expect("effect marker")
        .contains(&format!("merge:{digest}")));

    let invalid = AuthenticatedGithubOperation::Merge {
        number: 327,
        expected_head_oid: "not-a-head".to_string(),
        effect_id: format!("merge:{digest}"),
        evidence_digest: format!("sha256:{digest}"),
        ground_truth_digest: format!("sha256:{}", "b".repeat(64)),
    };
    assert!(invalid.command(&repository).is_err());

    let node = github_node_object_id(ProviderObjectKind::Actor, "MDQ6VXNlcjE=")
        .expect("real GitHub base64 node id");
    assert_eq!(node.provider_id(), "github");
    assert_eq!(node.kind(), ProviderObjectKind::Actor);
    assert!(node.stable_id().starts_with("node:sha256:"));
}

fn assert_authenticated_no_merge(
    outcome: &AuthenticatedPullRequestMergeOutcome,
    expected: impl Fn(&AuthenticatedPullRequestMergeBlocker) -> bool,
) {
    assert!(
        !outcome.is_merged(),
        "unexpected merge outcome: {outcome:?}"
    );
    assert!(
        outcome.blockers().iter().any(expected),
        "expected no-merge blocker was absent: {outcome:?}"
    );
}

#[test]
fn authenticated_pull_request_merge_types_missing_evidence_without_effect() {
    let (snapshot, _) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    let repository = authenticated_merge_repository();
    let fake = FakeForgeTransport::new();

    let outcome =
        execute_authenticated_pull_request_merge(repository.path(), snapshot.item(), None, &fake)
            .expect("typed missing evidence");

    assert_authenticated_no_merge(&outcome, |blocker| {
        matches!(
            blocker,
            AuthenticatedPullRequestMergeBlocker::MissingAuthenticatedAuditorEvidence
        )
    });
    assert_eq!(fake.pull_request_merge_count().expect("merge count"), 0);
}

#[test]
fn authenticated_pull_request_merge_refuses_stale_head_without_effect() {
    let (candidate_snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    let evidence = authenticated_merge_evidence(&candidate_snapshot, &input);
    let current_snapshot = merge_execution_snapshot(
        &"3".repeat(40),
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
        "auditor",
        ForgeReviewState::Approved,
    );
    let mut fake = FakeForgeTransport::new();
    fake.register_pull_request_merge_observation(candidate_snapshot.item(), current_snapshot)
        .expect("register stale current head");
    let repository = authenticated_merge_repository();

    let outcome = execute_authenticated_pull_request_merge(
        repository.path(),
        candidate_snapshot.item(),
        Some(&evidence),
        &fake,
    )
    .expect("typed stale head");

    assert_authenticated_no_merge(&outcome, |blocker| {
        matches!(
            blocker,
            AuthenticatedPullRequestMergeBlocker::StaleCandidateHead { .. }
        )
    });
    assert_eq!(fake.pull_request_merge_count().expect("merge count"), 0);
}

#[test]
fn authenticated_pull_request_merge_refuses_red_ci_without_effect() {
    let (snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Failure),
    );
    let evidence = authenticated_merge_evidence(&snapshot, &input);
    let mut fake = FakeForgeTransport::new();
    fake.register_pull_request_merge_observation(snapshot.item(), snapshot.clone())
        .expect("register red CI ground truth");
    let repository = authenticated_merge_repository();

    let outcome = execute_authenticated_pull_request_merge(
        repository.path(),
        snapshot.item(),
        Some(&evidence),
        &fake,
    )
    .expect("typed red CI");

    assert_authenticated_no_merge(&outcome, |blocker| {
        matches!(
            blocker,
            AuthenticatedPullRequestMergeBlocker::Authority(
                PullRequestMergeAuthorityBlocker::FailedRequiredCheck { .. }
            )
        )
    });
    assert_eq!(fake.pull_request_merge_count().expect("merge count"), 0);
}

#[test]
fn authenticated_pull_request_merge_refuses_a_changed_check_union_without_effect() {
    let (candidate_snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    let evidence = authenticated_merge_evidence(&candidate_snapshot, &input);
    let current_snapshot = PullRequestReviewSnapshot::new(
        candidate_snapshot.item().clone(),
        candidate_snapshot.observed_at().clone(),
        candidate_snapshot.reviews().to_vec(),
        Vec::new(),
        [
            candidate_snapshot.checks().to_vec(),
            vec![merge_authority_check(
                "C_late",
                "ci/late",
                ForgeCheckStatus::Completed,
                Some(ForgeCheckConclusion::Success),
                candidate_snapshot.item().head_oid().expect("head OID"),
            )],
        ]
        .concat(),
    )
    .expect("changed provider check union");
    let mut fake = FakeForgeTransport::new();
    fake.register_pull_request_merge_observation(candidate_snapshot.item(), current_snapshot)
        .expect("register changed check union");
    let repository = authenticated_merge_repository();

    let outcome = execute_authenticated_pull_request_merge(
        repository.path(),
        candidate_snapshot.item(),
        Some(&evidence),
        &fake,
    )
    .expect("typed changed-check refusal");

    assert_authenticated_no_merge(&outcome, |blocker| {
        matches!(
            blocker,
            AuthenticatedPullRequestMergeBlocker::CurrentCheckSetMismatch
        )
    });
    assert_eq!(fake.pull_request_merge_count().expect("merge count"), 0);
}

#[test]
fn authenticated_pull_request_merge_refuses_self_audit_without_effect() {
    let (candidate_snapshot, mut input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    input.auditor.as_mut().expect("fixture auditor").auditor = input
        .producer
        .as_ref()
        .expect("fixture producer")
        .producer
        .actor
        .clone();
    let evidence = authenticated_merge_evidence(&candidate_snapshot, &input);
    let current_snapshot = merge_execution_snapshot(
        &"1".repeat(40),
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
        "producer",
        ForgeReviewState::Approved,
    );
    let mut fake = FakeForgeTransport::new();
    fake.register_pull_request_merge_observation(candidate_snapshot.item(), current_snapshot)
        .expect("register self-audit ground truth");
    let repository = authenticated_merge_repository();

    let outcome = execute_authenticated_pull_request_merge(
        repository.path(),
        candidate_snapshot.item(),
        Some(&evidence),
        &fake,
    )
    .expect("typed self-audit");

    assert_authenticated_no_merge(&outcome, |blocker| {
        matches!(
            blocker,
            AuthenticatedPullRequestMergeBlocker::Authority(
                PullRequestMergeAuthorityBlocker::OptimizerBlocked(
                    MergeBlocker::ReviewerNotIndependent
                )
            )
        )
    });
    assert_eq!(fake.pull_request_merge_count().expect("merge count"), 0);
}

#[test]
fn authenticated_pull_request_merge_records_exact_success_receipt() {
    let (snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    let evidence = authenticated_merge_evidence(&snapshot, &input);
    let mut fake = FakeForgeTransport::new();
    fake.register_pull_request_merge_observation(snapshot.item(), snapshot.clone())
        .expect("register green merge ground truth");
    let repository = authenticated_merge_repository();

    let outcome = execute_authenticated_pull_request_merge(
        repository.path(),
        snapshot.item(),
        Some(&evidence),
        &fake,
    )
    .expect("successful authenticated merge");

    assert!(outcome.is_merged(), "green merge was blocked: {outcome:?}");
    let receipt = outcome.receipt().expect("authenticated merge receipt");
    assert_eq!(receipt.item(), snapshot.item());
    assert_eq!(
        receipt.approved_actor().provider_actor_id().stable_id(),
        "auditor"
    );
    assert_eq!(receipt.completion_mode(), CompletionMode::MergeCommit);
    assert!(receipt.evidence_digest().starts_with("sha256:"));
    assert!(receipt.ground_truth_digest().starts_with("sha256:"));
    assert_eq!(receipt.merged_oid().len(), 40);
    assert_eq!(
        receipt.provider_merge_id().kind(),
        ProviderObjectKind::Merge
    );
    assert!(receipt.url().contains("/pull/327/merge/"));
    assert_eq!(receipt.merged_at().as_str(), "2000-01-01T00:00:00Z");
    assert_eq!(fake.pull_request_merge_count().expect("merge count"), 1);
}

#[test]
fn authenticated_pull_request_merge_duplicate_retry_reconciles_one_effect() {
    let (snapshot, input) = merge_authority_fixture(
        ForgeCheckStatus::Completed,
        Some(ForgeCheckConclusion::Success),
    );
    let evidence = authenticated_merge_evidence(&snapshot, &input);
    let mut fake = FakeForgeTransport::new();
    fake.register_pull_request_merge_observation(snapshot.item(), snapshot.clone())
        .expect("register retry merge ground truth");
    let repository = authenticated_merge_repository();

    let first = execute_authenticated_pull_request_merge(
        repository.path(),
        snapshot.item(),
        Some(&evidence),
        &fake,
    )
    .expect("first authenticated merge");
    let retry = execute_authenticated_pull_request_merge(
        repository.path(),
        snapshot.item(),
        Some(&evidence),
        &fake,
    )
    .expect("reconciled authenticated merge retry");

    assert_eq!(first.receipt(), retry.receipt());
    assert_eq!(fake.pull_request_merge_count().expect("merge count"), 1);
}

fn sequenced_provider_review(
    sequence: u64,
    submitted_at: &str,
    state: ForgeReviewState,
) -> SequencedGithubReview {
    SequencedGithubReview {
        sequence,
        review: ForgeReview::new(
            merge_authority_object(ProviderObjectKind::Review, &format!("R_review_{sequence}")),
            ForgeActor::new(
                "github",
                merge_authority_object(ProviderObjectKind::Actor, "A_reviewer"),
                "reviewer",
                ReportedActorKind::Human,
            )
            .expect("review actor"),
            state,
            "review",
            ForgeTimestamp::new(submitted_at).expect("review timestamp"),
            "1".repeat(40),
        )
        .expect("provider review"),
    }
}

#[test]
fn github_merge_ground_truth_uses_latest_decisive_review_state() {
    let reviews = latest_effective_github_reviews(vec![
        sequenced_provider_review(1, "2026-08-30T00:00:01Z", ForgeReviewState::Approved),
        sequenced_provider_review(2, "2026-08-30T00:00:02Z", ForgeReviewState::Commented),
        sequenced_provider_review(
            3,
            "2026-08-30T00:00:03Z",
            ForgeReviewState::ChangesRequested,
        ),
    ]);
    assert_eq!(reviews.len(), 1);
    assert_eq!(reviews[0].state(), ForgeReviewState::ChangesRequested);

    let dismissed = latest_effective_github_reviews(vec![
        sequenced_provider_review(4, "2026-08-30T00:00:04Z", ForgeReviewState::Approved),
        sequenced_provider_review(5, "2026-08-30T00:00:05Z", ForgeReviewState::Dismissed),
    ]);
    assert_eq!(dismissed.len(), 1);
    assert_eq!(dismissed[0].state(), ForgeReviewState::Dismissed);
}

#[test]
fn authenticated_github_pagination_rejects_incomplete_shapes() {
    validate_authenticated_github_page_shape([0], "empty collection")
        .expect("one empty page is a complete empty collection");
    validate_authenticated_github_page_shape([100, 1], "complete collection")
        .expect("full non-final page and nonempty final page");
    assert!(validate_authenticated_github_page_shape([99, 1], "short page").is_err());
    assert!(validate_authenticated_github_page_shape([100, 0], "empty tail").is_err());
    assert!(validate_authenticated_github_page_shape(
        std::iter::repeat_n(100, AUTHENTICATED_GITHUB_MAX_PAGES + 1),
        "excessive pages",
    )
    .is_err());
}

#[test]
fn github_same_repository_head_requires_the_provider_node_identity() {
    let base = GithubApiRepository {
        node_id: "R_base".to_string(),
        full_name: "acme/repo".to_string(),
    };
    let exact = GithubApiRepository {
        node_id: "R_base".to_string(),
        full_name: "ACME/REPO".to_string(),
    };
    let lookalike = GithubApiRepository {
        node_id: "R_other".to_string(),
        full_name: "acme/repo".to_string(),
    };
    assert!(github_same_repository_head(
        Some(&exact),
        &base,
        "acme/repo"
    ));
    assert!(!github_same_repository_head(
        Some(&lookalike),
        &base,
        "acme/repo"
    ));
    assert!(!github_same_repository_head(None, &base, "acme/repo"));
}

fn github_status(id: &str, state: &str, updated_at: &str) -> GithubApiStatus {
    GithubApiStatus {
        node_id: id.to_string(),
        context: "ci/status".to_string(),
        state: state.to_string(),
        updated_at: updated_at.to_string(),
        creator: Some(GithubApiActor {
            node_id: "A_status".to_string(),
            login: "status-bot".to_string(),
            kind: "Bot".to_string(),
        }),
    }
}

#[test]
fn github_commit_status_union_rejects_equal_timestamp_ambiguity() {
    let latest = latest_github_statuses(vec![
        github_status("S_old", "pending", "2026-08-30T00:00:01Z"),
        github_status("S_new", "success", "2026-08-30T00:00:02Z"),
    ])
    .expect("strict latest status");
    assert_eq!(latest.len(), 1);
    assert_eq!(latest[0].state, "success");

    assert!(latest_github_statuses(vec![
        github_status("S_red", "failure", "2026-08-30T00:00:03Z"),
        github_status("S_green", "success", "2026-08-30T00:00:03Z"),
    ])
    .is_err());
}

#[test]
fn github_pr_source_fields_include_fail_closed_source_provenance() {
    let fields = GITHUB_PR_SOURCE_FIELDS.split(',').collect::<BTreeSet<_>>();
    assert!(fields.contains("headRepository"));
    assert!(fields.contains("isCrossRepository"));
}
