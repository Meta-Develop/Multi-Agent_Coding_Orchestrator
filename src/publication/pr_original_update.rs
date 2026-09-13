//! Explicit, authenticated update of an existing same-repository GitHub PR head.
//!
//! This is independent of create-only PR publication and of Inbox repair.

use super::*;
use crate::effect_wal::EffectEvent;
use crate::safe_state::BoundedRegularReader;

const UPDATE_GRANT_VERSION: u32 = 1;
const UPDATE_RECORD_VERSION: u32 = 1;

#[derive(Debug, Clone)]
pub struct PrOriginalUpdateOptions {
    pub repo: PathBuf,
    pub from_branch: String,
    pub grant_file: PathBuf,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OriginalPrUpdateGrant {
    version: u32,
    repository: ForgeRepository,
    pull_request_number: u64,
    pull_request_id: ProviderObjectId,
    head_ref: String,
    expected_head_oid: String,
    base_ref: String,
    expected_base_oid: String,
    candidate_oid: String,
    approved_actor_id: ProviderObjectId,
    approved_actor_login: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OriginalPrUpdatePlan {
    version: u32,
    grant: OriginalPrUpdateGrant,
    grant_raw_sha256: String,
    candidate_binding: merge::CandidateValidationBinding,
    validation_sha256: String,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct OriginalPrUpdateRecord {
    version: u32,
    plan: OriginalPrUpdatePlan,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    receipt: Option<OriginalPrUpdateReceipt>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OriginalPrUpdateReceipt {
    pub version: u32,
    pub repository: ForgeRepository,
    pub pull_request_number: u64,
    pub pull_request_id: ProviderObjectId,
    pub remote_ref: String,
    pub previous_oid: String,
    pub updated_oid: String,
    pub grant_raw_sha256: String,
    pub candidate_binding: merge::CandidateValidationBinding,
    pub validation_sha256: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct OriginalPrUpdatePreview {
    pub repository: ForgeRepository,
    pub pull_request_number: u64,
    pub pull_request_id: ProviderObjectId,
    pub head_ref: String,
    pub previous_oid: String,
    pub candidate_oid: String,
    pub from_branch: String,
    pub changed_paths: Vec<PathBuf>,
    pub grant_raw_sha256: String,
    pub candidate_validation_binding: merge::CandidateValidationBinding,
    pub next_action: String,
}

struct BoundGrant {
    value: OriginalPrUpdateGrant,
    raw_sha256: String,
    path: PathBuf,
}

struct LocalCandidate {
    binding: merge::CandidateValidationBinding,
    changed_paths: Vec<PathBuf>,
}

impl OriginalPrUpdateGrant {
    fn validate(&self) -> Result<()> {
        if self.version != UPDATE_GRANT_VERSION
            || self.repository.provider_id() != "github"
            || self.pull_request_number == 0
        {
            bail!("original PR update grant version, provider, or number is invalid");
        }
        for (id, kind, label) in [
            (
                self.repository.provider_repository_id(),
                ProviderObjectKind::Repository,
                "repository",
            ),
            (
                &self.pull_request_id,
                ProviderObjectKind::Item,
                "pull request",
            ),
            (
                &self.approved_actor_id,
                ProviderObjectKind::Actor,
                "approved actor",
            ),
        ] {
            if id.provider_id() != "github"
                || id.kind() != kind
                || !is_canonical_github_node_digest(id.stable_id())
            {
                bail!("original PR update {label} must have a canonical GitHub node identity");
            }
        }
        validate_publication_ref(&self.head_ref)?;
        validate_publication_ref(&self.base_ref)?;
        if self.head_ref == self.base_ref {
            bail!("original PR head and base refs must differ");
        }
        for (oid, label) in [
            (&self.expected_head_oid, "expected PR head"),
            (&self.expected_base_oid, "expected PR base"),
            (&self.candidate_oid, "candidate"),
        ] {
            validate_exact_git_oid(oid, label)?;
        }
        if self.expected_head_oid == self.candidate_oid {
            bail!("original PR update candidate is already the observed head");
        }
        validate_github_slug(&self.approved_actor_login, "approved PR update actor")?;
        if self.approved_actor_login != self.approved_actor_login.to_ascii_lowercase() {
            bail!("approved PR update actor login must be canonical lowercase");
        }
        let repository =
            github_repository_identity_from_selector(self.repository.canonical_locator())?;
        if repository.selector() != self.repository.canonical_locator() {
            bail!("original PR update repository selector is not canonical");
        }
        Ok(())
    }
}

fn is_canonical_github_node_digest(value: &str) -> bool {
    value.strip_prefix("node:sha256:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn validate_exact_git_oid(value: &str, label: &str) -> Result<Oid> {
    if value.len() != 40
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("{label} must be a canonical lowercase 40-character Git OID");
    }
    Oid::from_str(value).with_context(|| format!("{label} is not a Git OID"))
}

impl BoundGrant {
    fn load(repo_root: &Path, path: &Path) -> Result<Self> {
        #[cfg(not(unix))]
        {
            let _ = (repo_root, path);
            bail!("original PR update grant requires Unix no-follow ownership checks");
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            if !path.is_absolute()
                || path.components().any(|part| {
                    matches!(
                        part,
                        std::path::Component::CurDir | std::path::Component::ParentDir
                    )
                })
            {
                bail!("original PR update grant path must be absolute and normalized");
            }
            let parent = path
                .parent()
                .context("original PR update grant has no parent")?;
            path.file_name()
                .context("original PR update grant has no file name")?;
            let canonical_parent =
                fs::canonicalize(parent).context("failed to resolve grant parent")?;
            if canonical_parent != parent {
                bail!("original PR update grant path traverses a linked directory");
            }
            let canonical_repo =
                fs::canonicalize(repo_root).context("failed to resolve source repository")?;
            if canonical_parent.starts_with(canonical_repo) {
                bail!("original PR update grant must be outside the source repository");
            }
            let root = SafeRoot::open_existing(parent)?;
            let raw = BoundedRegularReader::read_tree_no_follow_validated(
                path,
                MAX_PUBLICATION_SOURCE_CONFIG_BYTES,
                |metadata| {
                    if !metadata.file_type().is_file()
                        || metadata.uid() != unsafe { libc::geteuid() }
                        || metadata.nlink() != 1
                        || metadata.permissions().mode() & 0o022 != 0
                    {
                        bail!("original PR update grant must be an owned single-link regular file without group/world write access");
                    }
                    Ok(())
                },
            )?;
            root.verify()?;
            let value: OriginalPrUpdateGrant = serde_json::from_slice(&raw)
                .context("original PR update grant is not strict versioned JSON")?;
            value.validate()?;
            Ok(Self {
                value,
                raw_sha256: sha256_hex(&raw),
                path: path.to_path_buf(),
            })
        }
    }

    fn verify_unchanged(&self, repo_root: &Path) -> Result<()> {
        let current = Self::load(repo_root, &self.path)?;
        if current.raw_sha256 != self.raw_sha256 || current.value != self.value {
            bail!("original PR update operator grant changed after binding");
        }
        Ok(())
    }
}

fn local_candidate(
    repo_root: &Path,
    branch: &str,
    grant: &OriginalPrUpdateGrant,
) -> Result<LocalCandidate> {
    let repo = crate::git_repository::open(repo_root)?;
    validate_publication_branch_name(branch, "original PR update branch")?;
    let candidate_oid = branch_head_oid(&repo, branch, "original PR update branch")?;
    if candidate_oid.to_string() != grant.candidate_oid {
        bail!("task branch no longer points at the granted candidate commit");
    }
    let old_oid = validate_exact_git_oid(&grant.expected_head_oid, "expected PR head")?;
    let old = repo
        .find_commit(old_oid)
        .context("original PR head commit is not available locally")?;
    let new = repo
        .find_commit(candidate_oid)
        .context("candidate commit is not available locally")?;
    if !repo.graph_descendant_of(candidate_oid, old_oid)? {
        bail!("candidate is not a descendant of the exact original PR head");
    }
    validate_new_commit_history(&repo, old_oid, candidate_oid)?;
    let (changes, raw_diff) = diff_trees(&repo, &old.tree()?, &new.tree()?)?;
    if changes.is_empty() || raw_diff.is_empty() {
        bail!("original PR update candidate has no changed content from the granted head");
    }
    let changed_paths = changes
        .into_iter()
        .map(|change| change.path)
        .collect::<Vec<_>>();
    for path in &changed_paths {
        validate_update_path(path)?;
    }
    let metadata = WorktreeMergeMetadata {
        agent_id: branch_publication_agent_id(branch)?,
        worktree_path: repo_root.to_path_buf(),
        branch: branch.to_string(),
        primary_repo_root: repo_root.to_path_buf(),
        primary_head: Some(old_oid.to_string()),
        agent_head: Some(candidate_oid.to_string()),
        merge_base: Some(old_oid.to_string()),
        base_matches_primary: None,
    };
    Ok(LocalCandidate {
        binding: merge::candidate_validation_binding(&metadata, &raw_diff)?,
        changed_paths,
    })
}

fn validate_update_path(path: &Path) -> Result<()> {
    normalize_repo_relative_path(path)
        .context("candidate changed path is not repository-relative")?;
    if path.starts_with(".agents")
        || path.starts_with(".agent")
        || crate::repo_map::is_ignored_worktree_store_path(path)
        || crate::repo_map::is_runtime_control_path(path)
    {
        bail!("original PR update candidate changes private agent or runtime context");
    }
    Ok(())
}

fn validate_new_commit_history(repo: &Repository, old_oid: Oid, candidate_oid: Oid) -> Result<()> {
    let mut walk = repo
        .revwalk()
        .context("failed to inspect original PR update ancestry")?;
    walk.push(candidate_oid)?;
    walk.hide(old_oid)?;
    let mut count = 0_usize;
    for entry in walk {
        count = count
            .checked_add(1)
            .context("PR update commit count overflowed")?;
        if count > MAX_PUBLICATION_COMMIT_DEPTH {
            bail!("original PR update history exceeds the publication commit-depth bound");
        }
        let commit = repo.find_commit(entry?)?;
        let tree = commit.tree()?;
        for parent in commit.parents() {
            let parent_tree = parent.tree()?;
            validate_commit_path_delta(repo, Some(&parent_tree), &tree)?;
        }
        if commit.parent_count() == 0 {
            validate_commit_path_delta(repo, None, &tree)?;
        }
    }
    Ok(())
}

fn validate_commit_path_delta(
    repo: &Repository,
    old: Option<&Tree<'_>>,
    new: &Tree<'_>,
) -> Result<()> {
    let diff = repo.diff_tree_to_tree(old, Some(new), None)?;
    for delta in diff.deltas() {
        if let Some(path) = delta.old_file().path() {
            validate_update_path(path)?;
        }
        if let Some(path) = delta.new_file().path() {
            validate_update_path(path)?;
        }
    }
    Ok(())
}

fn bind(
    repo_root: &Path,
    options: &PrOriginalUpdateOptions,
) -> Result<(BoundGrant, LocalCandidate, String)> {
    let grant = BoundGrant::load(repo_root, &options.grant_file)?;
    let repo = crate::git_repository::open(repo_root)?;
    let remote = remote_url(&repo, "origin")?;
    let source = github_repository_identity(&remote)?;
    if source.selector() != grant.value.repository.canonical_locator() {
        bail!("original PR update grant repository differs from canonical origin");
    }
    let candidate = local_candidate(repo_root, &options.from_branch, &grant.value)?;
    Ok((grant, candidate, remote))
}

pub fn preview_update(options: PrOriginalUpdateOptions) -> Result<OriginalPrUpdatePreview> {
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let (grant, candidate, _) = bind(&repo_root, &options)?;
    Ok(OriginalPrUpdatePreview {
        repository: grant.value.repository.clone(),
        pull_request_number: grant.value.pull_request_number,
        pull_request_id: grant.value.pull_request_id.clone(),
        head_ref: grant.value.head_ref.clone(),
        previous_oid: grant.value.expected_head_oid.clone(),
        candidate_oid: grant.value.candidate_oid.clone(),
        from_branch: options.from_branch,
        changed_paths: candidate.changed_paths,
        grant_raw_sha256: grant.raw_sha256,
        candidate_validation_binding: candidate.binding,
        next_action: "validate this exact B-to-C candidate and supply a passed bound validation envelope to pr update-existing; preview made no provider request or remote change".to_string(),
    })
}

impl OriginalPrUpdatePlan {
    fn validate(&self) -> Result<()> {
        if self.version != UPDATE_RECORD_VERSION {
            bail!("original PR update plan version is unsupported");
        }
        self.grant.validate()?;
        validate_external_digest(&self.grant_raw_sha256, "original PR update raw grant")?;
        validate_external_digest(&self.validation_sha256, "original PR update validation")?;
        if self.candidate_binding.clone().canonicalized()? != self.candidate_binding
            || self.candidate_binding.primary_head.as_deref()
                != Some(self.grant.expected_head_oid.as_str())
            || self.candidate_binding.agent_head.as_deref()
                != Some(self.grant.candidate_oid.as_str())
            || self.candidate_binding.merge_base.as_deref()
                != Some(self.grant.expected_head_oid.as_str())
        {
            bail!("original PR update validation binding is not exact B-to-C evidence");
        }
        Ok(())
    }

    fn logical_id(&self) -> Result<String> {
        Ok(format!(
            "pr-update-{}",
            stable_json_digest(&(
                "maco_original_pr_update_logical_v1",
                &self.grant.repository,
                self.grant.pull_request_number,
                &self.grant.pull_request_id,
                &self.grant.expected_head_oid,
            ))?
        ))
    }

    fn effect_id(&self) -> Result<String> {
        stable_json_digest(&("maco_original_pr_update_effect_v1", self))
    }
}

impl OriginalPrUpdateReceipt {
    fn for_plan(plan: &OriginalPrUpdatePlan) -> Self {
        Self {
            version: UPDATE_RECORD_VERSION,
            repository: plan.grant.repository.clone(),
            pull_request_number: plan.grant.pull_request_number,
            pull_request_id: plan.grant.pull_request_id.clone(),
            remote_ref: plan.grant.head_ref.clone(),
            previous_oid: plan.grant.expected_head_oid.clone(),
            updated_oid: plan.grant.candidate_oid.clone(),
            grant_raw_sha256: plan.grant_raw_sha256.clone(),
            candidate_binding: plan.candidate_binding.clone(),
            validation_sha256: plan.validation_sha256.clone(),
        }
    }
}

pub fn update_existing(
    options: PrOriginalUpdateOptions,
    evidence: ValidationEvidenceBundle,
) -> Result<OriginalPrUpdateReceipt> {
    let repo_root = discover_primary_repo_root(&options.repo)?;
    let _lock = RepoCommonLock::acquire(&repo_root, "pr-publish")?;
    let (grant, candidate, remote_url) = bind(&repo_root, &options)?;
    let bound = evidence.try_into_exact_bound()?;
    if bound.binding() != &candidate.binding {
        bail!("passed validation envelope does not bind the exact original PR B-to-C candidate");
    }
    let validation_sha256 = sha256_hex(&serde_json::to_vec(&(
        bound.binding(),
        bound.evidence().reports(),
    ))?);
    let plan = OriginalPrUpdatePlan {
        version: UPDATE_RECORD_VERSION,
        grant: grant.value.clone(),
        grant_raw_sha256: grant.raw_sha256.clone(),
        candidate_binding: candidate.binding.clone(),
        validation_sha256,
    };
    plan.validate()?;
    let mut transport = LiveOriginalPrUpdateTransport {
        repo_root: &repo_root,
        remote_url: &remote_url,
        selector: grant.value.repository.canonical_locator(),
    };
    execute_update_with_transport(&repo_root, plan, &mut transport, || {
        grant.verify_unchanged(&repo_root)?;
        if local_candidate(&repo_root, &options.from_branch, &grant.value)?.binding
            != candidate.binding
        {
            bail!("original PR update candidate changed before provider action");
        }
        Ok(())
    })
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PrObservation {
    repository_id: ProviderObjectId,
    pull_request_id: ProviderObjectId,
    number: u64,
    head_ref: String,
    head_oid: String,
    base_ref: String,
    base_oid: String,
    open: bool,
    same_repository_head: bool,
    repository_locator: String,
    url: String,
}

trait OriginalPrUpdateTransport {
    fn observe_pr(&mut self, number: u64) -> Result<PrObservation>;
    fn observe_remote(&mut self, remote_ref: &str) -> Result<Option<String>>;
    fn approved_actor(&mut self) -> Result<ForgeActor>;
    fn push_exact(&mut self, old_oid: &str, new_oid: &str, remote_ref: &str) -> Result<()>;
}

struct LiveOriginalPrUpdateTransport<'a> {
    repo_root: &'a Path,
    remote_url: &'a str,
    selector: &'a str,
}

#[derive(Deserialize)]
struct GithubUpdatePullRef {
    sha: String,
    #[serde(rename = "ref")]
    ref_name: String,
    repo: Option<GithubApiRepository>,
}

#[derive(Deserialize)]
struct GithubUpdatePullRequest {
    node_id: String,
    number: u64,
    state: String,
    merged: bool,
    html_url: String,
    head: GithubUpdatePullRef,
    base: GithubUpdatePullRef,
}

impl OriginalPrUpdateTransport for LiveOriginalPrUpdateTransport<'_> {
    fn observe_pr(&mut self, number: u64) -> Result<PrObservation> {
        let transport = GithubPullRequestMergeTransport::new(self.repo_root, self.selector)?;
        let pull: GithubUpdatePullRequest = parse_authenticated_github_json(
            &transport.json(
                "gh original PR update observation",
                AuthenticatedGithubOperation::PullRequest { number },
            )?,
            "GitHub original PR update observation",
        )?;
        let base_repo = pull
            .base
            .repo
            .context("original PR base repository is missing")?;
        let head_repo = pull
            .head
            .repo
            .context("original PR head repository is missing")?;
        validate_exact_git_oid(&pull.head.sha, "observed original PR head")?;
        validate_exact_git_oid(&pull.base.sha, "observed original PR base")?;
        let source = github_repository_identity_from_selector(self.selector)?;
        let expected_owner_name = format!("{}/{}", source.owner, source.name);
        let same_repository_head = head_repo.node_id == base_repo.node_id
            && head_repo.full_name.to_ascii_lowercase() == expected_owner_name
            && base_repo.full_name.to_ascii_lowercase() == expected_owner_name;
        Ok(PrObservation {
            repository_id: github_node_object_id(
                ProviderObjectKind::Repository,
                &base_repo.node_id,
            )?,
            pull_request_id: github_node_object_id(ProviderObjectKind::Item, &pull.node_id)?,
            number: pull.number,
            head_ref: format!("refs/heads/{}", pull.head.ref_name),
            head_oid: pull.head.sha,
            base_ref: format!("refs/heads/{}", pull.base.ref_name),
            base_oid: pull.base.sha,
            open: pull.state.eq_ignore_ascii_case("open") && !pull.merged,
            same_repository_head,
            repository_locator: format!("{}/{}", source.owner, source.name),
            url: pull.html_url,
        })
    }

    fn observe_remote(&mut self, remote_ref: &str) -> Result<Option<String>> {
        observe_remote_ref(self.repo_root, self.remote_url, remote_ref)
    }

    fn approved_actor(&mut self) -> Result<ForgeActor> {
        GithubPullRequestMergeTransport::new(self.repo_root, self.selector)?.approved_merge_actor()
    }

    fn push_exact(&mut self, old_oid: &str, new_oid: &str, remote_ref: &str) -> Result<()> {
        let operation = PublicationGitOperation::push_update_exact(old_oid, new_oid, remote_ref)?;
        let output =
            PublicationGitContext::create(self.repo_root, self.remote_url, operation)?.run()?;
        if !output.success {
            bail!(
                "exact original PR CAS push failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }
}

fn verify_pr_observation(
    plan: &OriginalPrUpdatePlan,
    observed: &PrObservation,
    head_oid: &str,
) -> Result<()> {
    let grant = &plan.grant;
    let source = github_repository_identity_from_selector(grant.repository.canonical_locator())?;
    let expected_url = format!(
        "https://{}/{}/{}/pull/{}",
        source.host, source.owner, source.name, grant.pull_request_number,
    );
    if observed.repository_id != *grant.repository.provider_repository_id()
        || observed.pull_request_id != grant.pull_request_id
        || observed.number != grant.pull_request_number
        || observed.head_ref != grant.head_ref
        || observed.head_oid != head_oid
        || observed.base_ref != grant.base_ref
        || observed.base_oid != grant.expected_base_oid
        || !observed.open
        || !observed.same_repository_head
        || observed.repository_locator != format!("{}/{}", source.owner, source.name)
        || observed.url.to_ascii_lowercase() != expected_url
    {
        bail!("GitHub original PR identity, repository, ref, base, or expected head changed");
    }
    Ok(())
}

fn verify_actor(
    plan: &OriginalPrUpdatePlan,
    transport: &mut impl OriginalPrUpdateTransport,
) -> Result<()> {
    let actor = transport.approved_actor()?;
    if actor.provider_id() != "github"
        || actor.provider_actor_id() != &plan.grant.approved_actor_id
        || actor.canonical_handle() != plan.grant.approved_actor_login
    {
        bail!("authenticated approved GitHub actor differs from the operator update grant");
    }
    Ok(())
}

fn verify_remote_and_pr(
    plan: &OriginalPrUpdatePlan,
    transport: &mut impl OriginalPrUpdateTransport,
    expected_head: &str,
) -> Result<()> {
    let observed = transport.observe_pr(plan.grant.pull_request_number)?;
    verify_pr_observation(plan, &observed, expected_head)?;
    if transport.observe_remote(&plan.grant.head_ref)?.as_deref() != Some(expected_head) {
        bail!("original PR remote ref differs from its exact expected head");
    }
    verify_actor(plan, transport)
}

fn latest_update_record(
    wal: &EffectWal,
    effect_id: &str,
    plan: &OriginalPrUpdatePlan,
) -> Result<(EffectPhase, OriginalPrUpdateRecord)> {
    if wal.logical_id() != plan.logical_id()? || effect_id != plan.effect_id()? {
        bail!("original PR update WAL does not bind the requested plan");
    }
    let phase = wal
        .phase(effect_id)
        .context("original PR update WAL omitted its effect")?;
    let mut latest = None;
    for event in wal.events() {
        let prior = validated_update_event(event, wal.logical_id())?;
        if event.effect_id == effect_id {
            if prior.plan != *plan {
                bail!("original PR update WAL contains an inconsistent current plan");
            }
            latest = Some((event.phase, prior));
        } else if event.phase != EffectPhase::Planned {
            bail!("another original PR update effect reached an uncertain or completed phase");
        }
    }
    let (latest_phase, record) = latest.context("original PR update WAL omitted current event")?;
    if latest_phase != phase {
        bail!("original PR update WAL current phase disagrees with its event sequence");
    }
    Ok((phase, record))
}

fn validated_update_event(event: &EffectEvent, logical_id: &str) -> Result<OriginalPrUpdateRecord> {
    let record: OriginalPrUpdateRecord = serde_json::from_value(event.data.clone())?;
    record.plan.validate()?;
    if record.version != UPDATE_RECORD_VERSION
        || record.plan.logical_id()? != logical_id
        || record.plan.effect_id()? != event.effect_id
    {
        bail!("original PR update WAL contains an inconsistent prior plan");
    }
    match event.phase {
        EffectPhase::Planned | EffectPhase::Started if record.receipt.is_none() => {}
        EffectPhase::Observed | EffectPhase::Completed
            if record.receipt.as_ref()
                == Some(&OriginalPrUpdateReceipt::for_plan(&record.plan)) => {}
        _ => bail!("original PR update WAL contains an inconsistent prior receipt"),
    }
    Ok(record)
}

fn execute_update_with_transport(
    repo_root: &Path,
    plan: OriginalPrUpdatePlan,
    transport: &mut impl OriginalPrUpdateTransport,
    mut recheck_local: impl FnMut() -> Result<()>,
) -> Result<OriginalPrUpdateReceipt> {
    plan.validate()?;
    let logical_id = plan.logical_id()?;
    let effect_id = plan.effect_id()?;
    let planned = OriginalPrUpdateRecord {
        version: UPDATE_RECORD_VERSION,
        plan: plan.clone(),
        receipt: None,
    };
    let mut wal = match EffectWal::create_planned(
        repository_auth_writer(repo_root)?.into_authenticator()?,
        &logical_id,
        &effect_id,
        &planned,
    ) {
        Ok(wal) => wal,
        Err(create_error) => EffectWal::open_instance(
            repository_auth_writer(repo_root)?.into_authenticator()?,
            &logical_id,
        ).with_context(|| format!("could not open existing authenticated original PR update WAL after create refusal: {create_error:#}"))?,
    };
    if wal.phase(&effect_id).is_none() {
        for event in wal.events() {
            let _ = validated_update_event(event, &logical_id)?;
            if event.phase != EffectPhase::Planned {
                bail!("prior original PR update reached an uncertain or completed phase; new plan refused");
            }
        }
        wal.planned(&effect_id, &planned)?;
    }
    let (phase, _) = latest_update_record(&wal, &effect_id, &plan)?;
    let receipt = OriginalPrUpdateReceipt::for_plan(&plan);
    match phase {
        EffectPhase::Planned => {
            recheck_local()?;
            verify_remote_and_pr(&plan, transport, &plan.grant.expected_head_oid)?;
            recheck_local()?;
            verify_remote_and_pr(&plan, transport, &plan.grant.expected_head_oid)?;
            wal.started(&effect_id, &planned)?;
            let pushed = transport.push_exact(
                &plan.grant.expected_head_oid,
                &plan.grant.candidate_oid,
                &plan.grant.head_ref,
            );
            verify_remote_and_pr(&plan, transport, &plan.grant.candidate_oid)
                .with_context(|| match pushed {
                    Ok(()) => "CAS push did not produce independently verified original PR and remote heads; no blind retry".to_string(),
                    Err(error) => format!("CAS push failed or response was lost ({error:#}); no blind retry"),
                })?;
            let observed = OriginalPrUpdateRecord {
                receipt: Some(receipt.clone()),
                ..planned.clone()
            };
            wal.observed(&effect_id, &observed)?;
            verify_remote_and_pr(&plan, transport, &plan.grant.candidate_oid)?;
            wal.completed(&effect_id, &observed)?;
        }
        EffectPhase::Started => {
            verify_remote_and_pr(&plan, transport, &plan.grant.candidate_oid)
                .context("started original PR update is ambiguous; blind CAS retry is forbidden")?;
            let observed = OriginalPrUpdateRecord {
                receipt: Some(receipt.clone()),
                ..planned
            };
            wal.observed(&effect_id, &observed)?;
            verify_remote_and_pr(&plan, transport, &plan.grant.candidate_oid)?;
            wal.completed(&effect_id, &observed)?;
        }
        EffectPhase::Observed => {
            verify_remote_and_pr(&plan, transport, &plan.grant.candidate_oid)?;
            wal.completed(
                &effect_id,
                &OriginalPrUpdateRecord {
                    receipt: Some(receipt.clone()),
                    ..planned
                },
            )?;
        }
        EffectPhase::Completed => {
            verify_remote_and_pr(&plan, transport, &plan.grant.candidate_oid)?;
        }
    }
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    struct Fixture {
        root: TempDir,
        repo_root: PathBuf,
        grant: OriginalPrUpdateGrant,
        plan: OriginalPrUpdatePlan,
        primary_oid: Oid,
    }

    fn node(kind: ProviderObjectKind, raw: &str) -> ProviderObjectId {
        github_node_object_id(kind, raw).unwrap()
    }

    fn commit(repo: &Repository, reference: &str, parent: Option<Oid>, contents: &str) -> Oid {
        let blob = repo.blob(contents.as_bytes()).unwrap();
        let mut builder = repo.treebuilder(None).unwrap();
        builder.insert("candidate.txt", blob, 0o100644).unwrap();
        let tree = repo.find_tree(builder.write().unwrap()).unwrap();
        let signature = Signature::now("test", "test@example.com").unwrap();
        let parents = parent
            .map(|oid| repo.find_commit(oid).unwrap())
            .into_iter()
            .collect::<Vec<_>>();
        let refs = parents.iter().collect::<Vec<_>>();
        repo.commit(
            Some(reference),
            &signature,
            &signature,
            contents,
            &tree,
            &refs,
        )
        .unwrap()
    }

    fn fixture() -> Fixture {
        let root = TempDir::new().unwrap();
        let repo_root = root.path().join("repository");
        let repo = Repository::init(&repo_root).unwrap();
        repo.remote("origin", "https://github.com/example/project.git")
            .unwrap();
        let primary_oid = commit(&repo, "refs/heads/main", None, "A");
        repo.set_head("refs/heads/main").unwrap();
        let old_oid = commit(&repo, "refs/heads/pr", Some(primary_oid), "B");
        let new_oid = commit(&repo, "refs/heads/task", Some(old_oid), "C");
        let grant = OriginalPrUpdateGrant {
            version: UPDATE_GRANT_VERSION,
            repository: ForgeRepository::new(
                "github",
                "github.com/example/project",
                node(ProviderObjectKind::Repository, "R_project"),
            )
            .unwrap(),
            pull_request_number: 17,
            pull_request_id: node(ProviderObjectKind::Item, "PR_17"),
            head_ref: "refs/heads/pr".to_string(),
            expected_head_oid: old_oid.to_string(),
            base_ref: "refs/heads/main".to_string(),
            expected_base_oid: primary_oid.to_string(),
            candidate_oid: new_oid.to_string(),
            approved_actor_id: node(ProviderObjectKind::Actor, "U_operator"),
            approved_actor_login: "operator".to_string(),
        };
        let candidate = local_candidate(&repo_root, "task", &grant).unwrap();
        let plan = OriginalPrUpdatePlan {
            version: UPDATE_RECORD_VERSION,
            grant: grant.clone(),
            grant_raw_sha256: sha256_hex(&serde_json::to_vec(&grant).unwrap()),
            candidate_binding: candidate.binding,
            validation_sha256: sha256_hex(b"passed validation fixture"),
        };
        Fixture {
            root,
            repo_root,
            grant,
            plan,
            primary_oid,
        }
    }

    struct FakeTransport {
        pr: PrObservation,
        remote: Option<String>,
        actor: ForgeActor,
        pushes: usize,
        fail_before_push: bool,
        fail_after_push: bool,
    }

    impl FakeTransport {
        fn new(plan: &OriginalPrUpdatePlan) -> Self {
            let grant = &plan.grant;
            Self {
                pr: PrObservation {
                    repository_id: grant.repository.provider_repository_id().clone(),
                    pull_request_id: grant.pull_request_id.clone(),
                    number: grant.pull_request_number,
                    head_ref: grant.head_ref.clone(),
                    head_oid: grant.expected_head_oid.clone(),
                    base_ref: grant.base_ref.clone(),
                    base_oid: grant.expected_base_oid.clone(),
                    open: true,
                    same_repository_head: true,
                    repository_locator: "example/project".to_string(),
                    url: "https://github.com/example/project/pull/17".to_string(),
                },
                remote: Some(grant.expected_head_oid.clone()),
                actor: ForgeActor::new(
                    "github",
                    grant.approved_actor_id.clone(),
                    grant.approved_actor_login.clone(),
                    ReportedActorKind::Human,
                )
                .unwrap(),
                pushes: 0,
                fail_before_push: false,
                fail_after_push: false,
            }
        }
    }

    impl OriginalPrUpdateTransport for FakeTransport {
        fn observe_pr(&mut self, number: u64) -> Result<PrObservation> {
            assert_eq!(number, self.pr.number);
            Ok(self.pr.clone())
        }

        fn observe_remote(&mut self, remote_ref: &str) -> Result<Option<String>> {
            assert_eq!(remote_ref, self.pr.head_ref);
            Ok(self.remote.clone())
        }

        fn approved_actor(&mut self) -> Result<ForgeActor> {
            Ok(self.actor.clone())
        }

        fn push_exact(&mut self, old_oid: &str, new_oid: &str, remote_ref: &str) -> Result<()> {
            assert_eq!(old_oid, self.remote.as_deref().unwrap());
            assert_eq!(remote_ref, self.pr.head_ref);
            self.pushes += 1;
            if self.fail_before_push {
                bail!("scripted lost-before-write response");
            }
            self.remote = Some(new_oid.to_string());
            self.pr.head_oid = new_oid.to_string();
            if self.fail_after_push {
                bail!("scripted lost-after-write response");
            }
            Ok(())
        }
    }

    #[test]
    fn primary_a_different_from_pr_b_still_binds_exact_b_to_c_candidate() {
        let fixture = fixture();
        let repo = crate::git_repository::open(&fixture.repo_root).unwrap();
        assert_eq!(repo.head().unwrap().target(), Some(fixture.primary_oid));
        assert_ne!(
            fixture.primary_oid.to_string(),
            fixture.grant.expected_head_oid
        );
        let candidate = local_candidate(&fixture.repo_root, "task", &fixture.grant).unwrap();
        assert_eq!(
            candidate.binding.primary_head.as_deref(),
            Some(fixture.grant.expected_head_oid.as_str())
        );
        assert_eq!(
            candidate.binding.agent_head.as_deref(),
            Some(fixture.grant.candidate_oid.as_str())
        );
        assert_eq!(
            candidate.binding.merge_base.as_deref(),
            Some(fixture.grant.expected_head_oid.as_str())
        );
        assert_eq!(
            candidate.changed_paths,
            vec![PathBuf::from("candidate.txt")]
        );
        let _ = fixture.root.path();
    }

    #[cfg(unix)]
    #[test]
    fn operator_grant_is_outside_repo_strict_and_preview_has_no_transport() {
        use std::os::unix::fs::PermissionsExt;
        let fixture = fixture();
        let grant_path = fixture.root.path().join("operator-grant.json");
        fs::write(&grant_path, serde_json::to_vec(&fixture.grant).unwrap()).unwrap();
        fs::set_permissions(&grant_path, fs::Permissions::from_mode(0o600)).unwrap();
        let options = PrOriginalUpdateOptions {
            repo: fixture.repo_root.clone(),
            from_branch: "task".to_string(),
            grant_file: grant_path.clone(),
        };
        let preview = preview_update(options.clone()).unwrap();
        assert_eq!(preview.previous_oid, fixture.grant.expected_head_oid);
        assert_eq!(preview.candidate_oid, fixture.grant.candidate_oid);
        assert_eq!(
            preview.candidate_validation_binding,
            fixture.plan.candidate_binding
        );
        assert_eq!(
            preview.grant_raw_sha256,
            sha256_hex(&fs::read(&grant_path).unwrap())
        );
        let original = BoundGrant::load(&fixture.repo_root, &grant_path).unwrap();
        fs::set_permissions(&grant_path, fs::Permissions::from_mode(0o666)).unwrap();
        assert!(preview_update(options.clone()).is_err());
        fs::set_permissions(&grant_path, fs::Permissions::from_mode(0o600)).unwrap();
        let mut foreign = fixture.grant.clone();
        foreign.repository = ForgeRepository::new(
            "github",
            "github.com/other/project",
            node(ProviderObjectKind::Repository, "R_other"),
        )
        .unwrap();
        fs::write(&grant_path, serde_json::to_vec(&foreign).unwrap()).unwrap();
        assert!(preview_update(options.clone()).is_err());
        assert!(original.verify_unchanged(&fixture.repo_root).is_err());
        fs::write(&grant_path, b"{\"version\":1,\"unknown\":true}").unwrap();
        assert!(preview_update(options.clone()).is_err());
        let inside = fixture.repo_root.join("grant.json");
        fs::write(&inside, serde_json::to_vec(&fixture.grant).unwrap()).unwrap();
        fs::set_permissions(&inside, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(preview_update(PrOriginalUpdateOptions {
            grant_file: inside,
            ..options.clone()
        })
        .is_err());
        fs::write(&grant_path, serde_json::to_vec(&fixture.grant).unwrap()).unwrap();
        let symlink = fixture.root.path().join("linked-grant.json");
        std::os::unix::fs::symlink(&grant_path, &symlink).unwrap();
        assert!(preview_update(PrOriginalUpdateOptions {
            grant_file: symlink,
            ..options
        })
        .is_err());
    }

    #[test]
    fn non_descendant_candidate_is_refused_even_when_primary_is_clean() {
        let mut fixture = fixture();
        let repo = crate::git_repository::open(&fixture.repo_root).unwrap();
        let divergent = commit(
            &repo,
            "refs/heads/divergent",
            Some(fixture.primary_oid),
            "D",
        );
        fixture.grant.candidate_oid = divergent.to_string();
        assert!(local_candidate(&fixture.repo_root, "divergent", &fixture.grant).is_err());
    }

    #[test]
    fn candidate_paths_preserve_private_agent_and_runtime_boundaries() {
        assert!(validate_update_path(Path::new("src/lib.rs")).is_ok());
        assert!(validate_update_path(Path::new(".agents/AGENTS.md")).is_err());
        assert!(validate_update_path(Path::new(".agent")).is_err());
        assert!(validate_update_path(Path::new(".agent/custom.json")).is_err());
        assert!(validate_update_path(Path::new(".maco/state.json")).is_err());
        assert!(validate_update_path(Path::new(".worktrees/lane/file.rs")).is_err());
        assert!(validate_update_path(Path::new(".worktrees-quarantine-1/lane/file.rs")).is_err());
        assert!(validate_update_path(Path::new("../outside")).is_err());
    }

    #[test]
    fn intermediate_private_context_commit_is_refused_even_when_final_diff_is_clean() {
        for private_root in [".agents", ".agent", ".worktrees", ".worktrees-quarantine-1"] {
            assert_intermediate_private_context_commit_refused(private_root);
        }
    }

    fn assert_intermediate_private_context_commit_refused(private_root: &str) {
        let mut fixture = fixture();
        let repo = crate::git_repository::open(&fixture.repo_root).unwrap();
        let old_oid = Oid::from_str(&fixture.grant.expected_head_oid).unwrap();
        let old = repo.find_commit(old_oid).unwrap();
        let mut private = repo.treebuilder(None).unwrap();
        private
            .insert("secret.txt", repo.blob(b"private").unwrap(), 0o100644)
            .unwrap();
        let private_tree = private.write().unwrap();
        let mut root = repo.treebuilder(None).unwrap();
        root.insert(
            "candidate.txt",
            old.tree().unwrap().get_name("candidate.txt").unwrap().id(),
            0o100644,
        )
        .unwrap();
        root.insert(private_root, private_tree, 0o040000).unwrap();
        let tree = repo.find_tree(root.write().unwrap()).unwrap();
        let signature = Signature::now("test", "test@example.com").unwrap();
        let intermediate = repo
            .commit(
                Some("refs/heads/private-hop"),
                &signature,
                &signature,
                "private hop",
                &tree,
                &[&old],
            )
            .unwrap();
        let final_oid = commit(&repo, "refs/heads/private-task", Some(intermediate), "C");
        fixture.grant.candidate_oid = final_oid.to_string();
        let final_tree = repo.find_commit(final_oid).unwrap().tree().unwrap();
        let (net_changes, _) = diff_trees(&repo, &old.tree().unwrap(), &final_tree).unwrap();
        assert_eq!(net_changes.len(), 1);
        assert_eq!(net_changes[0].path, PathBuf::from("candidate.txt"));
        assert!(local_candidate(&fixture.repo_root, "private-task", &fixture.grant).is_err());
    }

    #[test]
    fn exact_cas_operation_is_distinct_from_create_only_and_rejects_empty_old_oid() {
        let fixture = fixture();
        let args = PublicationGitOperation::push_update_exact(
            &fixture.grant.expected_head_oid,
            &fixture.grant.candidate_oid,
            &fixture.grant.head_ref,
        )
        .unwrap()
        .arguments();
        validate_publication_git_operation(&args).unwrap();
        assert!(args.iter().any(|arg| arg.to_string_lossy()
            == format!(
                "--force-with-lease={}:{}",
                fixture.grant.head_ref, fixture.grant.expected_head_oid,
            )));
        assert!(PublicationGitOperation::push_update_exact(
            "",
            &fixture.grant.candidate_oid,
            &fixture.grant.head_ref
        )
        .is_err());
        let create = PublicationGitOperation::push_create_only(
            &fixture.grant.candidate_oid,
            &fixture.grant.head_ref,
        )
        .unwrap()
        .arguments();
        validate_publication_git_operation(&create).unwrap();
        assert_ne!(args, create);
    }

    #[test]
    fn wrong_pr_identity_head_remote_or_actor_refuses_before_cas() {
        let fixture = fixture();
        let mut fake = FakeTransport::new(&fixture.plan);
        fake.pr.pull_request_id = node(ProviderObjectKind::Item, "other-pr");
        assert!(
            verify_remote_and_pr(&fixture.plan, &mut fake, &fixture.grant.expected_head_oid)
                .is_err()
        );
        fake = FakeTransport::new(&fixture.plan);
        fake.pr.head_ref = "refs/heads/other".to_string();
        assert!(
            verify_pr_observation(&fixture.plan, &fake.pr, &fixture.grant.expected_head_oid)
                .is_err()
        );
        fake = FakeTransport::new(&fixture.plan);
        fake.remote = Some(fixture.grant.candidate_oid.clone());
        assert!(
            verify_remote_and_pr(&fixture.plan, &mut fake, &fixture.grant.expected_head_oid)
                .is_err()
        );
        fake = FakeTransport::new(&fixture.plan);
        fake.actor = ForgeActor::new(
            "github",
            node(ProviderObjectKind::Actor, "other"),
            "other",
            ReportedActorKind::Human,
        )
        .unwrap();
        assert!(
            verify_remote_and_pr(&fixture.plan, &mut fake, &fixture.grant.expected_head_oid)
                .is_err()
        );
        assert_eq!(fake.pushes, 0);
    }

    #[test]
    fn rest_pull_request_ref_and_repository_shape_is_bound_before_cas() {
        let fixture = fixture();
        let pull: GithubUpdatePullRequest = serde_json::from_value(serde_json::json!({
            "node_id": "PR_17",
            "number": 17,
            "state": "open",
            "merged": false,
            "html_url": "https://github.com/Example/Project/pull/17",
            "head": {
                "sha": fixture.grant.expected_head_oid,
                "ref": "pr",
                "repo": { "node_id": "R_project", "full_name": "Example/Project" }
            },
            "base": {
                "sha": fixture.grant.expected_base_oid,
                "ref": "main",
                "repo": { "node_id": "R_project", "full_name": "Example/Project" }
            }
        }))
        .unwrap();
        assert_eq!(pull.head.ref_name, "pr");
        assert_eq!(pull.base.ref_name, "main");
        assert_eq!(
            pull.head.repo.unwrap().node_id,
            pull.base.repo.unwrap().node_id
        );
        assert_eq!(
            pull.html_url.to_ascii_lowercase(),
            "https://github.com/example/project/pull/17"
        );
    }

    #[test]
    fn authenticated_cas_reconciles_lost_success_without_another_push() {
        let fixture = fixture();
        let mut fake = FakeTransport::new(&fixture.plan);
        fake.fail_after_push = true;
        let first = execute_update_with_transport(
            &fixture.repo_root,
            fixture.plan.clone(),
            &mut fake,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(first.updated_oid, fixture.grant.candidate_oid);
        assert_eq!(fake.pushes, 1);
        let second = execute_update_with_transport(
            &fixture.repo_root,
            fixture.plan.clone(),
            &mut fake,
            || Ok(()),
        )
        .unwrap();
        assert_eq!(second, first);
        assert_eq!(fake.pushes, 1);
    }

    #[test]
    fn preflight_refusal_allows_a_corrected_explicit_plan_without_erasing_planned_history() {
        let fixture = fixture();
        let mut fake = FakeTransport::new(&fixture.plan);
        fake.actor = ForgeActor::new(
            "github",
            node(ProviderObjectKind::Actor, "U_corrected"),
            "corrected",
            ReportedActorKind::Human,
        )
        .unwrap();
        assert!(execute_update_with_transport(
            &fixture.repo_root,
            fixture.plan.clone(),
            &mut fake,
            || Ok(()),
        )
        .is_err());
        assert_eq!(fake.pushes, 0);

        let mut corrected = fixture.plan.clone();
        corrected.grant.approved_actor_id = fake.actor.provider_actor_id().clone();
        corrected.grant.approved_actor_login = fake.actor.canonical_handle().to_string();
        corrected.grant_raw_sha256 = sha256_hex(&serde_json::to_vec(&corrected.grant).unwrap());
        let receipt =
            execute_update_with_transport(&fixture.repo_root, corrected.clone(), &mut fake, || {
                Ok(())
            })
            .unwrap();
        assert_eq!(receipt.updated_oid, fixture.grant.candidate_oid);
        assert_eq!(fake.pushes, 1);
        let wal: EffectWal = EffectWal::open_instance(
            repository_auth_writer(&fixture.repo_root)
                .unwrap()
                .into_authenticator()
                .unwrap(),
            &corrected.logical_id().unwrap(),
        )
        .unwrap();
        assert_eq!(wal.events().len(), 5);
        assert_eq!(wal.events()[0].phase, EffectPhase::Planned);
        assert_eq!(wal.events()[0].effect_id, fixture.plan.effect_id().unwrap());
        assert_eq!(
            wal.phase(&corrected.effect_id().unwrap()),
            Some(EffectPhase::Completed)
        );
    }

    #[test]
    fn ambiguous_started_update_never_retries_push_and_only_reconciles_exact_heads() {
        let fixture = fixture();
        let mut fake = FakeTransport::new(&fixture.plan);
        fake.fail_before_push = true;
        assert!(execute_update_with_transport(
            &fixture.repo_root,
            fixture.plan.clone(),
            &mut fake,
            || Ok(())
        )
        .is_err());
        assert_eq!(fake.pushes, 1);
        fake.fail_before_push = false;
        let mut changed = fixture.plan.clone();
        changed.validation_sha256 = sha256_hex(b"different independently passed validation");
        assert_ne!(
            changed.effect_id().unwrap(),
            fixture.plan.effect_id().unwrap()
        );
        assert!(
            execute_update_with_transport(&fixture.repo_root, changed, &mut fake, || Ok(()),)
                .is_err()
        );
        assert_eq!(fake.pushes, 1);
        assert!(execute_update_with_transport(
            &fixture.repo_root,
            fixture.plan.clone(),
            &mut fake,
            || Ok(())
        )
        .is_err());
        assert_eq!(fake.pushes, 1);
        fake.remote = Some(fixture.grant.candidate_oid.clone());
        fake.pr.head_oid = fixture.grant.candidate_oid.clone();
        assert!(execute_update_with_transport(
            &fixture.repo_root,
            fixture.plan.clone(),
            &mut fake,
            || Ok(())
        )
        .is_ok());
        assert_eq!(fake.pushes, 1);
    }
}
