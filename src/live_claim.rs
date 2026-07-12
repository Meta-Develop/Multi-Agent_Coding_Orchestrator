use crate::safe_state::{
    stable_checksum, AtomicStateWriter, BoundedRegularReader, FileIdentity, KernelStateLock,
    SafeRoot,
};
use anyhow::{bail, Context, Result};
use serde::Serialize;
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const CLAIMS_DIR: &str = ".agents/live/claims";
const TEMPLATE_FILE: &str = "CLAIM_TEMPLATE.md";
const BOARD_LOCK_FILE: &str = ".maco-live-claims.lock";
const DEFAULT_STALE_AFTER_MINUTES: u64 = 720;
const MAX_STALE_AFTER_MINUTES: u64 = 525_600;
const MAX_CLAIM_ENTRIES: usize = 256;
const MAX_CLAIM_RESIDUE_ENTRIES: usize = 32;
const MAX_CLAIM_BYTES: u64 = 64 * 1024;
const MAX_CLAIM_LINES: usize = 1_024;
const MAX_CLAIM_LINE_BYTES: usize = 4 * 1024;
const MAX_CLAIM_FIELDS: usize = 64;
const MAX_CLAIM_ISSUES: usize = 128;
const MAX_CLAIM_ID_BYTES: usize = 128;
const MAX_OWNER_BYTES: usize = 128;
const MAX_TIMESTAMP_BYTES: usize = 64;
const MAX_OWNED_FILES: usize = 128;
const MAX_OWNED_PATH_BYTES: usize = 4 * 1024;
const MAX_AUDIT_ACTOR_BYTES: usize = 128;
const MAX_AUDIT_REASON_BYTES: usize = 2 * 1024;
const MAX_AUDIT_ENTRY_BYTES: usize = 4 * 1024;
const CLAIM_RELEASE_HEADROOM_BYTES: usize = 8 * 1024;
const MAX_FUTURE_CLOCK_SKEW_SECONDS: i64 = 5 * 60;
const VALID_STATUSES: &[&str] = &["active", "blocked", "ready-for-review", "handoff", "done"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimsStatusReport {
    pub repo: PathBuf,
    pub claims_dir: PathBuf,
    pub now: String,
    pub claim_count: usize,
    pub lock_count: usize,
    pub claims: Vec<LiveClaimSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimSummary {
    pub claim_id: String,
    pub file: PathBuf,
    pub owner: Option<String>,
    pub status: Option<String>,
    pub is_lock: bool,
    pub created: Option<String>,
    pub updated: Option<String>,
    pub heartbeat: Option<String>,
    pub stale_after_minutes: Option<u64>,
    pub owned_files: Vec<PathBuf>,
    pub liveness: LiveClaimLiveness,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimLiveness {
    pub state: String,
    pub reference_field: Option<String>,
    pub reference_timestamp: Option<String>,
    pub age_minutes: Option<i64>,
    pub stale_after_minutes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimsValidationReport {
    pub repo: PathBuf,
    pub claims_dir: PathBuf,
    pub valid: bool,
    pub claim_count: usize,
    pub issue_count: usize,
    pub claims: Vec<LiveClaimValidation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimValidation {
    pub claim_id: String,
    pub file: PathBuf,
    pub issues: Vec<LiveClaimIssue>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimIssue {
    pub severity: String,
    pub field: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimMutationReport {
    pub claim_id: String,
    pub file: PathBuf,
    pub actor: String,
    pub previous_status: Option<String>,
    pub status: Option<String>,
    pub updated: String,
    pub audit_entry: String,
    pub claim: LiveClaimSummary,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LiveClaimApplyReport {
    pub claim_id: String,
    pub file: PathBuf,
    pub actor: String,
    pub created: bool,
    pub updated: String,
    pub claim: LiveClaimSummary,
}

#[derive(Debug, Clone)]
pub struct LiveClock {
    raw: String,
    epoch_seconds: i64,
}

impl LiveClock {
    pub fn parse(value: &str) -> Result<Self> {
        let raw = clean_scalar(value);
        if raw.len() > MAX_TIMESTAMP_BYTES || raw.chars().any(char::is_control) {
            bail!("live timestamp is malformed or exceeds its bounded length");
        }
        let epoch_seconds =
            parse_timestamp_seconds(&raw).context("failed to parse live timestamp")?;
        Ok(Self { raw, epoch_seconds })
    }

    pub fn now() -> Self {
        let epoch_seconds = match SystemTime::now().duration_since(UNIX_EPOCH) {
            Ok(duration) => i64::try_from(duration.as_secs()).unwrap_or(i64::MAX),
            Err(_) => 0,
        };
        Self {
            raw: format_epoch_seconds(epoch_seconds),
            epoch_seconds,
        }
    }

    pub fn raw(&self) -> &str {
        &self.raw
    }
}

pub fn status(repo: impl AsRef<Path>, now: &LiveClock) -> Result<LiveClaimsStatusReport> {
    let repo = repo.as_ref().to_path_buf();
    let claims_dir = claims_dir(&repo);
    let claims = load_claims(&claims_dir, now)?;
    let lock_count = claims.iter().filter(|claim| claim.is_lock).count();
    Ok(LiveClaimsStatusReport {
        repo,
        claims_dir,
        now: now.raw.clone(),
        claim_count: claims.len(),
        lock_count,
        claims,
    })
}

pub fn validate(repo: impl AsRef<Path>, now: &LiveClock) -> Result<LiveClaimsValidationReport> {
    let repo = repo.as_ref().to_path_buf();
    let claims_dir = claims_dir(&repo);
    let claims = load_parsed_claims(&claims_dir)?;
    let mut validations = Vec::with_capacity(claims.len());
    let mut issue_count = 0usize;
    let mut id_counts = BTreeMap::<String, usize>::new();
    for claim in &claims {
        id_counts
            .entry(claim.display_id())
            .and_modify(|count| *count = count.saturating_add(1))
            .or_insert(1);
    }
    let overlap_files = overlapping_active_claim_files(&claims);

    for claim in claims {
        let mut issues = claim.issues.clone();
        if id_counts
            .get(&claim.display_id())
            .copied()
            .unwrap_or_default()
            > 1
        {
            issues.push(LiveClaimIssue {
                severity: "error".to_string(),
                field: "claim_id".to_string(),
                message: "claim id is duplicated across claim files".to_string(),
            });
        }
        if overlap_files.contains(&claim.file) {
            issues.push(LiveClaimIssue {
                severity: "error".to_string(),
                field: "owned_files".to_string(),
                message: "active claim ownership overlaps another active claim at a path boundary"
                    .to_string(),
            });
        }
        if claim.stale_after_minutes.is_none() {
            issues.push(LiveClaimIssue {
                severity: "warning".to_string(),
                field: "stale_after_minutes".to_string(),
                message: "claim has no stale-after value; liveness uses the default".to_string(),
            });
        }
        for warning in summary_from_parsed(&claim, now).warnings {
            issues.push(LiveClaimIssue {
                severity: "warning".to_string(),
                field: "liveness".to_string(),
                message: warning,
            });
        }
        issue_count = issue_count.saturating_add(issues.len());
        validations.push(LiveClaimValidation {
            claim_id: claim.display_id(),
            file: claim.file.clone(),
            issues,
        });
    }

    let valid = validations
        .iter()
        .all(|claim| claim.issues.iter().all(|issue| issue.severity != "error"));

    Ok(LiveClaimsValidationReport {
        repo,
        claims_dir,
        valid,
        claim_count: validations.len(),
        issue_count,
        claims: validations,
    })
}

pub fn heartbeat(
    repo: impl AsRef<Path>,
    claim_id: &str,
    actor: &str,
) -> Result<LiveClaimMutationReport> {
    heartbeat_with_clock(repo.as_ref(), claim_id, actor, &LiveClock::now())
}

fn heartbeat_with_clock(
    repo: &Path,
    claim_id: &str,
    actor: &str,
    now: &LiveClock,
) -> Result<LiveClaimMutationReport> {
    validate_actor(actor, "heartbeat")?;
    mutate_claim(repo, claim_id, actor, now, ClaimMutation::Heartbeat, |_| {
        Ok(())
    })
}

pub fn override_release(
    repo: impl AsRef<Path>,
    claim_id: &str,
    actor: &str,
    reason: &str,
) -> Result<LiveClaimMutationReport> {
    override_release_with_clock(repo.as_ref(), claim_id, actor, reason, &LiveClock::now())
}

fn override_release_with_clock(
    repo: &Path,
    claim_id: &str,
    actor: &str,
    reason: &str,
    now: &LiveClock,
) -> Result<LiveClaimMutationReport> {
    validate_actor(actor, "override-release")?;
    validate_audit_reason(reason)?;
    mutate_claim(
        repo,
        claim_id,
        actor,
        now,
        ClaimMutation::OverrideRelease {
            reason: reason.trim(),
        },
        |_| Ok(()),
    )
}

pub fn release(
    repo: impl AsRef<Path>,
    claim_id: &str,
    actor: &str,
    status: &str,
    reason: &str,
) -> Result<LiveClaimMutationReport> {
    validate_actor(actor, "release")?;
    validate_audit_reason(reason)?;
    if !matches!(status, "done" | "handoff") {
        bail!("release status must be done or handoff");
    }
    mutate_claim(
        repo.as_ref(),
        claim_id,
        actor,
        &LiveClock::now(),
        ClaimMutation::OwnerRelease { status, reason },
        |_| Ok(()),
    )
}

pub fn apply(
    repo: impl AsRef<Path>,
    draft: impl AsRef<Path>,
    actor: &str,
) -> Result<LiveClaimApplyReport> {
    validate_actor(actor, "apply")?;
    let now = LiveClock::now();
    apply_with_clock(repo.as_ref(), draft.as_ref(), actor, &now)
}

fn apply_with_clock(
    repo: &Path,
    draft: &Path,
    actor: &str,
    now: &LiveClock,
) -> Result<LiveClaimApplyReport> {
    let claims_path = claims_dir(repo);
    let root = open_claims_root(&claims_path)?.context("claim board does not exist")?;
    let lock = acquire_claim_board_lock(&root)?;
    prepare_claim_board(&root, &lock)?;
    let canonical_draft = draft
        .canonicalize()
        .context("claim draft is missing or inaccessible")?;
    if canonical_draft.starts_with(root.path()) {
        bail!("claim drafts must remain outside the live claim board");
    }
    let bytes = BoundedRegularReader::read(draft, MAX_CLAIM_BYTES)
        .map_err(|_| anyhow::anyhow!("claim draft is not a bounded no-follow regular file"))?;
    let content = std::str::from_utf8(&bytes).context("claim draft is not valid UTF-8")?;
    let preliminary = parse_claim_file(PathBuf::from(CLAIMS_DIR).join("draft.md"), content);
    let claim_id = preliminary
        .claim_id
        .as_deref()
        .context("claim draft is missing its claim id")?;
    validate_claim_id(claim_id, "claim draft id")?;
    let file_name = OsString::from(format!("{claim_id}.md"));
    let file = PathBuf::from(CLAIMS_DIR).join(&file_name);
    let draft_claim = parse_claim_file(file.clone(), content);
    ensure_claim_valid(&draft_claim)?;
    if draft_claim.owner.as_deref() != Some(actor) {
        bail!("claim apply actor must exactly match the draft owner");
    }
    let status = draft_claim
        .status
        .as_deref()
        .context("claim draft status is missing")?;
    if !matches!(status, "active" | "blocked" | "ready-for-review") {
        bail!("claim apply accepts only active, blocked, or ready-for-review drafts");
    }
    if draft_claim
        .latest_timestamp_seconds()?
        .is_some_and(|latest| latest > now.epoch_seconds)
    {
        bail!("claim draft contains a future timestamp generation");
    }

    let (claims, initial_board) = load_stable_claim_board(&root, &lock)?;
    ensure_claim_board_valid(&claims)?;
    let existing = claims.iter().find(|claim| claim.display_id() == claim_id);
    if existing
        .and_then(|claim| claim.owner.as_deref())
        .is_some_and(|owner| owner != actor)
    {
        bail!("claim apply cannot update a claim owned by another actor");
    }
    let created = existing.is_none();
    let audit_entry = format!("`{}` - `{actor}` applied claim draft", now.raw());
    let updated_limit = usize::try_from(MAX_CLAIM_BYTES)
        .unwrap_or(usize::MAX)
        .saturating_sub(CLAIM_RELEASE_HEADROOM_BYTES);
    let updated = update_claim_content(
        content,
        &draft_claim,
        now,
        Some(status),
        &audit_entry,
        updated_limit,
    )?;
    let updated_claim = parse_claim_file(file.clone(), &updated);
    ensure_claim_valid(&updated_claim)?;
    let mut proposed = claims
        .into_iter()
        .filter(|claim| claim.display_id() != claim_id)
        .collect::<Vec<_>>();
    proposed.push(updated_claim);
    ensure_claim_board_valid(&proposed)?;
    let mut no_hook = no_claim_publish_hook;
    let final_claims = atomic_publish_claim(
        &root,
        &lock,
        &initial_board,
        &file_name,
        updated.as_bytes(),
        &mut no_hook,
    )?;
    ensure_claim_board_valid(&final_claims)?;
    let final_claim = final_claims
        .into_iter()
        .find(|claim| claim.display_id() == claim_id)
        .context("applied claim disappeared from the stable board")?;
    let summary = summary_from_parsed(&final_claim, now);
    Ok(LiveClaimApplyReport {
        claim_id: claim_id.to_string(),
        file,
        actor: actor.to_string(),
        created,
        updated: now.raw().to_string(),
        claim: summary,
    })
}

fn no_claim_publish_hook(_path: &Path) -> Result<()> {
    Ok(())
}

#[derive(Clone, Copy)]
enum ClaimMutation<'a> {
    Heartbeat,
    OverrideRelease { reason: &'a str },
    OwnerRelease { status: &'a str, reason: &'a str },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimFileGeneration {
    identity: FileIdentity,
    bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimBoardSnapshot {
    entries: BTreeMap<OsString, ClaimFileGeneration>,
}

fn verify_claim_board_replacement(
    before: &ClaimBoardSnapshot,
    after: &ClaimBoardSnapshot,
    target: &OsStr,
    expected_bytes: &[u8],
) -> Result<()> {
    let mut expected_names = before.entries.keys().cloned().collect::<BTreeSet<_>>();
    expected_names.insert(target.to_os_string());
    if expected_names.len() != after.entries.len() || expected_names.iter().ne(after.entries.keys())
    {
        bail!("claim board names changed during atomic replacement");
    }
    for (name, before_generation) in &before.entries {
        let after_generation = after
            .entries
            .get(name)
            .context("claim board entry disappeared during replacement")?;
        if name == target {
            if after_generation.bytes != expected_bytes {
                bail!("claim replacement content changed after atomic replacement");
            }
        } else if after_generation != before_generation {
            bail!("another claim board entry changed during atomic replacement");
        }
    }
    if !before.entries.contains_key(target) {
        let created = after
            .entries
            .get(target)
            .context("new claim did not appear after atomic replacement")?;
        if created.bytes != expected_bytes {
            bail!("new claim content changed after atomic replacement");
        }
    }
    Ok(())
}

fn mutate_claim<F>(
    repo: &Path,
    claim_id: &str,
    actor: &str,
    now: &LiveClock,
    mutation: ClaimMutation<'_>,
    mut before_first_fence: F,
) -> Result<LiveClaimMutationReport>
where
    F: FnMut(&Path) -> Result<()>,
{
    validate_claim_id(claim_id, "requested claim id")?;
    let claims_path = claims_dir(repo);
    let root = open_claims_root(&claims_path)?.context("claim board does not exist")?;
    let lock = acquire_claim_board_lock(&root)?;
    prepare_claim_board(&root, &lock)?;
    let (claims, initial_board) = load_stable_claim_board(&root, &lock)?;
    ensure_claim_board_valid(&claims)?;
    let claim = claims
        .into_iter()
        .find(|claim| claim.display_id() == claim_id)
        .context("requested claim was not found")?;
    let previous_status = claim.status.clone();
    let owner = claim.owner.as_deref().context("claim owner is missing")?;
    let status = claim.status.as_deref().context("claim status is missing")?;
    let (next_status, audit_entry) = match mutation {
        ClaimMutation::Heartbeat => {
            if actor != owner {
                bail!("heartbeat actor must exactly match the claim owner");
            }
            if !matches!(status, "active" | "blocked") {
                bail!("heartbeat is allowed only for active or blocked claims");
            }
            if claim
                .latest_timestamp_seconds()?
                .is_some_and(|latest| now.epoch_seconds < latest)
            {
                bail!("heartbeat refuses a future or rollback timestamp");
            }
            (None, format!("`{}` - `{}` heartbeat", now.raw(), actor))
        }
        ClaimMutation::OverrideRelease { reason } => {
            if !matches!(status, "active" | "blocked") {
                bail!("override-release is allowed only for active or blocked claims");
            }
            let liveness = summary_from_parsed(&claim, now).liveness;
            if liveness.state != "stale" {
                bail!("override-release requires a claim that is provably stale");
            }
            (
                Some("handoff"),
                format!(
                    "`{}` - `{}` override-release; previous status `{}`; reason: {}",
                    now.raw(),
                    actor,
                    status,
                    reason
                ),
            )
        }
        ClaimMutation::OwnerRelease {
            status: next_status,
            reason,
        } => {
            if actor != owner {
                bail!("release actor must exactly match the claim owner");
            }
            if !matches!(status, "active" | "blocked" | "ready-for-review") {
                bail!("release is allowed only for active, blocked, or ready-for-review claims");
            }
            if claim
                .latest_timestamp_seconds()?
                .is_some_and(|latest| now.epoch_seconds < latest)
            {
                bail!("release refuses a future or rollback timestamp");
            }
            (
                Some(next_status),
                format!(
                    "`{}` - `{}` released claim as `{}`; previous status `{}`; reason: {}",
                    now.raw(),
                    actor,
                    next_status,
                    status,
                    reason
                ),
            )
        }
    };
    if audit_entry.len() > MAX_AUDIT_ENTRY_BYTES {
        bail!("claim audit entry exceeds its bounded length");
    }

    let file_name = claim
        .file
        .file_name()
        .context("claim file name is missing")?
        .to_os_string();
    let initial = initial_board
        .entries
        .get(&file_name)
        .cloned()
        .context("claim file disappeared from the stable board snapshot")?;
    let content = std::str::from_utf8(&initial.bytes).context("claim file is not valid UTF-8")?;
    let current = parse_claim_file(claim.file.clone(), content);
    ensure_claim_valid(&current)?;
    if current.display_id() != claim.display_id()
        || current.owner != claim.owner
        || current.status != claim.status
    {
        bail!("claim identity changed before mutation");
    }
    let updated_limit = match mutation {
        ClaimMutation::Heartbeat => usize::try_from(MAX_CLAIM_BYTES)
            .unwrap_or(usize::MAX)
            .saturating_sub(CLAIM_RELEASE_HEADROOM_BYTES),
        ClaimMutation::OverrideRelease { .. } | ClaimMutation::OwnerRelease { .. } => {
            usize::try_from(MAX_CLAIM_BYTES).unwrap_or(usize::MAX)
        }
    };
    let updated = update_claim_content(
        content,
        &current,
        now,
        next_status,
        &audit_entry,
        updated_limit,
    )?;
    if updated.len() > usize::try_from(MAX_CLAIM_BYTES).unwrap_or(usize::MAX) {
        bail!("updated claim exceeds its bounded file size");
    }
    let updated_claim = parse_claim_file(claim.file.clone(), &updated);
    ensure_claim_valid(&updated_claim)?;
    if updated_claim.display_id() != claim_id || updated_claim.owner.as_deref() != Some(owner) {
        bail!("updated claim identity or owner changed unexpectedly");
    }

    let final_claims = atomic_publish_claim(
        &root,
        &lock,
        &initial_board,
        &file_name,
        updated.as_bytes(),
        &mut before_first_fence,
    )?;
    ensure_claim_board_valid(&final_claims)?;
    let final_claim = final_claims
        .into_iter()
        .find(|candidate| candidate.display_id() == claim_id)
        .context("updated claim disappeared from the stable board")?;
    let summary = summary_from_parsed(&final_claim, now);
    Ok(LiveClaimMutationReport {
        claim_id: summary.claim_id.clone(),
        file: summary.file.clone(),
        actor: actor.to_string(),
        previous_status,
        status: summary.status.clone(),
        updated: now.raw().to_string(),
        audit_entry,
        claim: summary,
    })
}

fn atomic_publish_claim<F>(
    root: &SafeRoot,
    lock: &KernelStateLock,
    initial_board: &ClaimBoardSnapshot,
    file_name: &OsStr,
    updated: &[u8],
    before_first_fence: &mut F,
) -> Result<Vec<ParsedClaim>>
where
    F: FnMut(&Path) -> Result<()>,
{
    if !initial_board.entries.contains_key(file_name)
        && initial_board.entries.len() >= MAX_CLAIM_ENTRIES
    {
        bail!("claim board has no bounded entry capacity for a new claim");
    }
    let claim_path = root.direct_child(file_name)?;
    let mut fence_phase = 0u8;
    AtomicStateWriter::write_direct_fenced(root, file_name, updated, || {
        lock.verify_direct_binding(root)
            .map_err(|_| anyhow::anyhow!("claim board mutation lock binding changed"))?;
        root.verify()
            .map_err(|_| anyhow::anyhow!("claim board root binding changed"))?;
        match fence_phase {
            0 => {
                before_first_fence(&claim_path)?;
                let observed = capture_claim_board_snapshot(root, Some((file_name, updated)))?;
                if &observed != initial_board {
                    bail!("claim board generation changed before atomic replacement");
                }
            }
            1 => {
                let observed = capture_claim_board_snapshot(root, None)?;
                verify_claim_board_replacement(initial_board, &observed, file_name, updated)?;
            }
            _ => bail!("claim mutation fence was invoked unexpectedly"),
        }
        fence_phase = fence_phase.saturating_add(1);
        Ok(())
    })
    .map_err(|_| anyhow::anyhow!("claim atomic mutation was refused"))?;
    if fence_phase != 2 {
        bail!("claim atomic mutation did not complete both generation fences");
    }

    let (final_claims, _) = load_stable_claim_board(root, lock)?;
    Ok(final_claims)
}

fn claims_dir(repo: &Path) -> PathBuf {
    repo.join(CLAIMS_DIR)
}

fn load_claims(claims_dir: &Path, now: &LiveClock) -> Result<Vec<LiveClaimSummary>> {
    let claims = load_parsed_claims(claims_dir)?;
    ensure_claim_board_valid(&claims)?;
    Ok(claims
        .iter()
        .map(|claim| summary_from_parsed(claim, now))
        .collect())
}

fn load_parsed_claims(claims_dir: &Path) -> Result<Vec<ParsedClaim>> {
    let Some(root) = open_claims_root(claims_dir)? else {
        return Ok(Vec::new());
    };
    let lock = acquire_claim_board_lock(&root)?;
    prepare_claim_board(&root, &lock)?;
    let (claims, _) = load_stable_claim_board(&root, &lock)?;
    Ok(claims)
}

fn open_claims_root(claims_dir: &Path) -> Result<Option<SafeRoot>> {
    match SafeRoot::open_existing(claims_dir) {
        Ok(root) => Ok(Some(root)),
        Err(error) if error_chain_has_kind(&error, std::io::ErrorKind::NotFound) => Ok(None),
        Err(_) => bail!("claim board directory is unsafe or inaccessible"),
    }
}

fn acquire_claim_board_lock(root: &SafeRoot) -> Result<KernelStateLock> {
    let lock = KernelStateLock::acquire_direct(root, BOARD_LOCK_FILE)
        .map_err(|_| anyhow::anyhow!("claim board lock is unsafe or unavailable"))?;
    lock.verify_direct_binding(root)
        .map_err(|_| anyhow::anyhow!("claim board lock binding changed"))?;
    Ok(lock)
}

fn prepare_claim_board(root: &SafeRoot, lock: &KernelStateLock) -> Result<()> {
    lock.verify_direct_binding(root)
        .map_err(|_| anyhow::anyhow!("claim board lock binding changed"))?;
    scavenge_claim_board_residue(root)?;
    lock.verify_direct_binding(root)
        .map_err(|_| anyhow::anyhow!("claim board lock binding changed"))?;
    Ok(())
}

fn load_stable_claim_board(
    root: &SafeRoot,
    lock: &KernelStateLock,
) -> Result<(Vec<ParsedClaim>, ClaimBoardSnapshot)> {
    load_stable_claim_board_with_hook(root, lock, || Ok(()))
}

fn load_stable_claim_board_with_hook<F>(
    root: &SafeRoot,
    lock: &KernelStateLock,
    after_first_snapshot: F,
) -> Result<(Vec<ParsedClaim>, ClaimBoardSnapshot)>
where
    F: FnOnce() -> Result<()>,
{
    lock.verify_direct_binding(root)
        .map_err(|_| anyhow::anyhow!("claim board lock binding changed"))?;
    let before = capture_claim_board_snapshot(root, None)?;
    let claims = parsed_claims_from_snapshot(&before)?;
    after_first_snapshot()?;
    let after = capture_claim_board_snapshot(root, None)?;
    if before != after {
        bail!("claim board generation changed during bounded read");
    }
    lock.verify_direct_binding(root)
        .map_err(|_| anyhow::anyhow!("claim board lock binding changed"))?;
    Ok((claims, before))
}

fn parsed_claims_from_snapshot(snapshot: &ClaimBoardSnapshot) -> Result<Vec<ParsedClaim>> {
    let mut claims = Vec::new();
    for (file_name, generation) in &snapshot.entries {
        if file_name == OsStr::new(TEMPLATE_FILE) {
            std::str::from_utf8(&generation.bytes)
                .map_err(|_| anyhow::anyhow!("claim template is not valid UTF-8"))?;
            continue;
        }
        if file_name == OsStr::new(BOARD_LOCK_FILE) {
            if !generation.bytes.is_empty() {
                bail!("claim board lock file must remain empty");
            }
            continue;
        }
        let content = std::str::from_utf8(&generation.bytes)
            .map_err(|_| anyhow::anyhow!("claim board entry is not valid UTF-8"))?;
        claims.push(parse_claim_file(
            PathBuf::from(CLAIMS_DIR).join(file_name.clone()),
            content,
        ));
    }
    claims.sort_by_key(|claim| claim.display_id());
    Ok(claims)
}

fn capture_claim_board_snapshot(
    root: &SafeRoot,
    permitted_writer_target: Option<(&OsStr, &[u8])>,
) -> Result<ClaimBoardSnapshot> {
    let mut entries = BTreeMap::new();
    let mut permitted_temp_count = 0usize;
    for file_name in
        bounded_claim_entry_names_with_writer(root, permitted_writer_target.map(|v| v.0))?
    {
        if let Some((target, expected_bytes)) = permitted_writer_target {
            if is_canonical_claim_temp_for(&file_name, target) {
                permitted_temp_count = permitted_temp_count.saturating_add(1);
                let generation = read_entry_generation(root, &file_name, MAX_CLAIM_BYTES)
                    .map_err(|_| anyhow::anyhow!("claim writer temporary file is unsafe"))?;
                if generation.bytes != expected_bytes {
                    bail!("claim writer temporary content changed before replacement");
                }
                continue;
            }
        }
        let max_bytes = if file_name == OsStr::new(BOARD_LOCK_FILE) {
            0
        } else {
            MAX_CLAIM_BYTES
        };
        let generation = read_entry_generation(root, &file_name, max_bytes).map_err(|_| {
            if file_name == OsStr::new(TEMPLATE_FILE) {
                anyhow::anyhow!("claim template is not a bounded regular file")
            } else if file_name == OsStr::new(BOARD_LOCK_FILE) {
                anyhow::anyhow!("claim board lock file is unsafe")
            } else {
                anyhow::anyhow!("claim board entry is not a bounded regular file")
            }
        })?;
        entries.insert(file_name, generation);
    }
    if permitted_writer_target.is_some() && permitted_temp_count != 1 {
        bail!("claim writer temporary generation is missing or ambiguous");
    }
    Ok(ClaimBoardSnapshot { entries })
}

fn bounded_claim_entry_names_with_writer(
    root: &SafeRoot,
    permitted_writer_target: Option<&OsStr>,
) -> Result<Vec<OsString>> {
    let extra = usize::from(permitted_writer_target.is_some());
    let names = raw_claim_entry_names(root, MAX_CLAIM_ENTRIES.saturating_add(extra))?;
    let mut claim_entry_count = 0usize;
    let mut validated = Vec::with_capacity(names.len());
    for name in names {
        if permitted_writer_target.is_some_and(|target| is_canonical_claim_temp_for(&name, target))
        {
            validated.push(name);
            continue;
        }
        claim_entry_count = claim_entry_count.saturating_add(1);
        if claim_entry_count > MAX_CLAIM_ENTRIES {
            bail!("claim board exceeds its {} entry limit", MAX_CLAIM_ENTRIES);
        }
        if name != OsStr::new(TEMPLATE_FILE) && name != OsStr::new(BOARD_LOCK_FILE) {
            let text = name
                .to_str()
                .context("claim board contains a non-UTF-8 entry name")?;
            validate_claim_file_name(text)?;
        }
        validated.push(name);
    }
    validated.sort();
    Ok(validated)
}

fn raw_claim_entry_names(root: &SafeRoot, max_entries: usize) -> Result<Vec<OsString>> {
    root.verify()
        .map_err(|_| anyhow::anyhow!("claim board directory binding changed"))?;
    let entries =
        fs::read_dir(root.path()).map_err(|_| anyhow::anyhow!("claim board cannot be listed"))?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| anyhow::anyhow!("claim board entry cannot be listed"))?;
        names.push(entry.file_name());
        if names.len() > max_entries {
            bail!("claim board exceeds its bounded entry limit");
        }
    }
    root.verify()
        .map_err(|_| anyhow::anyhow!("claim board directory binding changed"))?;
    names.sort();
    Ok(names)
}

fn scavenge_claim_board_residue(root: &SafeRoot) -> Result<()> {
    let names = raw_claim_entry_names(
        root,
        MAX_CLAIM_ENTRIES.saturating_add(MAX_CLAIM_RESIDUE_ENTRIES),
    )?;
    let mut claim_files = BTreeSet::new();
    for name in &names {
        if name == OsStr::new(TEMPLATE_FILE) || name == OsStr::new(BOARD_LOCK_FILE) {
            continue;
        }
        if name
            .to_str()
            .is_some_and(|text| validate_claim_file_name(text).is_ok())
        {
            claim_files.insert(name.clone());
        }
    }
    let mut candidate_targets = claim_files.clone();
    for name in &names {
        if let Some(target) = canonical_claim_temp_target(name) {
            candidate_targets.insert(target);
        }
    }
    let mut targets = BTreeSet::new();
    for name in &names {
        if name == OsStr::new(TEMPLATE_FILE)
            || name == OsStr::new(BOARD_LOCK_FILE)
            || claim_files.contains(name)
        {
            continue;
        }
        let mut matched_target = None;
        for target in &candidate_targets {
            if is_canonical_claim_temp_for(name, target)
                || is_canonical_claim_quarantine_for(name, target)
            {
                matched_target = Some(target.clone());
                break;
            }
        }
        let target = matched_target.context(
            "claim board contains unknown writer residue; manual inspection is required",
        )?;
        targets.insert(target);
    }
    for target in targets {
        AtomicStateWriter::scavenge_direct_temps(root, &target)
            .map_err(|_| anyhow::anyhow!("claim writer residue could not be safely recovered"))?;
    }
    Ok(())
}

fn is_canonical_claim_temp_for(name: &OsStr, target: &OsStr) -> bool {
    canonical_claim_temp_target(name).as_deref() == Some(target)
}

fn canonical_claim_temp_target(name: &OsStr) -> Option<OsString> {
    let body = name.to_str()?.strip_prefix('.')?.strip_suffix(".tmp")?;
    let (target_and_first, second) = body.rsplit_once('-')?;
    let (target, first) = target_and_first.rsplit_once('.')?;
    if !canonical_decimal_u64(first)
        || !canonical_decimal_u64(second)
        || validate_claim_file_name(target).is_err()
    {
        return None;
    }
    Some(OsString::from(target))
}

fn is_canonical_claim_quarantine_for(name: &OsStr, target: &OsStr) -> bool {
    let (Some(name), Some(target)) = (name.to_str(), target.to_str()) else {
        return false;
    };
    let prefix = format!(
        ".maco-temp-quarantine-{}-",
        stable_checksum(target.as_bytes())
    );
    let Some(body) = name.strip_prefix(&prefix) else {
        return false;
    };
    let Some((body, inode)) = body.rsplit_once('-') else {
        return false;
    };
    let Some((source_checksum, device)) = body.rsplit_once('-') else {
        return false;
    };
    is_canonical_stable_checksum(source_checksum)
        && is_fixed_lower_hex(device)
        && is_fixed_lower_hex(inode)
}

fn canonical_decimal_u64(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| byte.is_ascii_digit())
        && (value.len() == 1 || !value.starts_with('0'))
        && value.parse::<u64>().is_ok()
}

fn is_canonical_stable_checksum(value: &str) -> bool {
    let Some(body) = value.strip_prefix("maco-v1-") else {
        return false;
    };
    let Some((hex, length)) = body.rsplit_once('-') else {
        return false;
    };
    hex.len() == 32
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
        && canonical_decimal_u64(length)
}

fn is_fixed_lower_hex(value: &str) -> bool {
    value.len() == 16
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn validate_claim_file_name(file_name: &str) -> Result<()> {
    let stem = file_name
        .strip_suffix(".md")
        .context("claim board contains an unsupported non-claim entry")?;
    validate_claim_id(stem, "claim file name")
}

fn read_entry_generation(
    root: &SafeRoot,
    file_name: &OsStr,
    max_bytes: u64,
) -> Result<ClaimFileGeneration> {
    root.verify()
        .map_err(|_| anyhow::anyhow!("claim board directory binding changed"))?;
    let path = root.direct_child(file_name)?;
    let before = BoundedRegularReader::identity(&path)
        .map_err(|_| anyhow::anyhow!("claim file identity is unsafe"))?;
    let bytes = BoundedRegularReader::read_direct(root, file_name, max_bytes)
        .map_err(|_| anyhow::anyhow!("claim file is not a bounded regular file"))?;
    let after = BoundedRegularReader::identity(&path)
        .map_err(|_| anyhow::anyhow!("claim file identity is unsafe"))?;
    if before != after {
        bail!("claim file identity changed during bounded read");
    }
    root.verify()
        .map_err(|_| anyhow::anyhow!("claim board directory binding changed"))?;
    Ok(ClaimFileGeneration {
        identity: before,
        bytes,
    })
}

fn ensure_claim_board_valid(claims: &[ParsedClaim]) -> Result<()> {
    if claims
        .iter()
        .any(|claim| claim.issues.iter().any(|issue| issue.severity == "error"))
    {
        bail!("claim board contains an invalid entry; run live validate for bounded diagnostics");
    }
    let mut ids = BTreeSet::new();
    for claim in claims {
        if !ids.insert(claim.display_id()) {
            bail!("claim board contains duplicate claim ids");
        }
    }
    if !overlapping_active_claim_files(claims).is_empty() {
        bail!("claim board contains overlapping active ownership paths");
    }
    Ok(())
}

fn overlapping_active_claim_files(claims: &[ParsedClaim]) -> BTreeSet<PathBuf> {
    let mut overlapping = BTreeSet::new();
    for (index, left) in claims.iter().enumerate() {
        if !matches!(left.status.as_deref(), Some("active" | "blocked")) {
            continue;
        }
        for right in claims.iter().skip(index.saturating_add(1)) {
            if !matches!(right.status.as_deref(), Some("active" | "blocked")) {
                continue;
            }
            if left.owned_files.iter().any(|left_path| {
                right
                    .owned_files
                    .iter()
                    .any(|right_path| owned_paths_overlap(left_path, right_path))
            }) {
                overlapping.insert(left.file.clone());
                overlapping.insert(right.file.clone());
            }
        }
    }
    overlapping
}

fn owned_paths_overlap(left: &Path, right: &Path) -> bool {
    left.starts_with(right) || right.starts_with(left)
}

fn ensure_claim_valid(claim: &ParsedClaim) -> Result<()> {
    ensure_claim_board_valid(std::slice::from_ref(claim))
}

fn error_chain_has_kind(error: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io| io.kind() == kind)
    })
}

#[derive(Debug, Clone)]
struct ParsedClaim {
    file: PathBuf,
    claim_id: Option<String>,
    owner: Option<String>,
    status: Option<String>,
    created: Option<String>,
    updated: Option<String>,
    heartbeat: Option<String>,
    date: Option<String>,
    stale_after_minutes: Option<u64>,
    owned_files: Vec<PathBuf>,
    issues: Vec<LiveClaimIssue>,
}

impl ParsedClaim {
    fn display_id(&self) -> String {
        self.claim_id.clone().unwrap_or_else(|| {
            self.file
                .file_stem()
                .and_then(|stem| stem.to_str())
                .unwrap_or("unknown")
                .to_string()
        })
    }

    fn reference_timestamp(&self) -> Option<(&'static str, &str)> {
        self.heartbeat
            .as_deref()
            .map(|timestamp| ("heartbeat", timestamp))
            .or_else(|| {
                self.updated
                    .as_deref()
                    .map(|timestamp| ("updated", timestamp))
            })
            .or_else(|| {
                self.created
                    .as_deref()
                    .map(|timestamp| ("created", timestamp))
            })
            .or_else(|| self.date.as_deref().map(|timestamp| ("date", timestamp)))
    }

    fn latest_timestamp_seconds(&self) -> Result<Option<i64>> {
        let mut latest = None;
        for timestamp in [
            self.created.as_deref(),
            self.updated.as_deref(),
            self.heartbeat.as_deref(),
            self.date.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            let parsed = parse_timestamp_seconds(timestamp)
                .context("claim contains an invalid timestamp generation")?;
            latest = Some(latest.map_or(parsed, |current: i64| current.max(parsed)));
        }
        Ok(latest)
    }
}

fn parse_claim_file(file: PathBuf, content: &str) -> ParsedClaim {
    let mut claim = ParsedClaim {
        file,
        claim_id: None,
        owner: None,
        status: None,
        created: None,
        updated: None,
        heartbeat: None,
        date: None,
        stale_after_minutes: None,
        owned_files: Vec::new(),
        issues: Vec::new(),
    };
    if content.len() > usize::try_from(MAX_CLAIM_BYTES).unwrap_or(usize::MAX) {
        push_parse_issue(&mut claim, "file", "claim file exceeds its bounded size");
        return claim;
    }

    let mut header_values = Vec::new();
    let mut fields = BTreeMap::<String, Vec<String>>::new();
    let mut field_count = 0usize;
    let mut owned_heading_count = 0usize;
    let mut in_owned_files = false;
    let mut owned_files = Vec::new();

    for (line_index, line) in content.lines().enumerate() {
        if line_index >= MAX_CLAIM_LINES {
            push_parse_issue(&mut claim, "lines", "claim exceeds its bounded line count");
            break;
        }
        if line.len() > MAX_CLAIM_LINE_BYTES {
            push_parse_issue(
                &mut claim,
                "line",
                "claim contains a line that exceeds its bounded length",
            );
            continue;
        }
        if line
            .chars()
            .any(|character| character.is_control() && character != '\t')
        {
            push_parse_issue(
                &mut claim,
                "line",
                "claim contains an unsupported control character",
            );
            continue;
        }
        let trimmed = line.trim();
        if let Some(rest) = line.strip_prefix("# Claim:") {
            header_values.push(clean_scalar(rest));
            continue;
        }

        let is_outer_bullet = line.starts_with("- ");
        if in_owned_files {
            if is_outer_bullet {
                in_owned_files = false;
            } else if let Some(path) = owned_file_from_line(trimmed) {
                owned_files.push(path);
                continue;
            }
        }

        if is_outer_bullet {
            let lower = trimmed.to_ascii_lowercase();
            if lower.starts_with("- owned files")
                && lower.contains("regions")
                && lower.ends_with(':')
            {
                owned_heading_count = owned_heading_count.saturating_add(1);
                in_owned_files = true;
                continue;
            }
            if let Some((key, value)) = field_from_line(trimmed) {
                if matches!(
                    key.as_str(),
                    "claim id"
                        | "owner"
                        | "status"
                        | "created"
                        | "updated"
                        | "heartbeat"
                        | "date"
                        | "stale after minutes"
                ) {
                    field_count = field_count.saturating_add(1);
                    fields.entry(key).or_default().push(value);
                }
            }
        }
    }

    if field_count > MAX_CLAIM_FIELDS {
        push_parse_issue(
            &mut claim,
            "fields",
            "claim exceeds its bounded recognized-field count",
        );
    }
    if header_values.len() > 1 {
        push_parse_issue(
            &mut claim,
            "claim_id",
            "claim contains duplicate Claim headers",
        );
    }
    let header_id = header_values.into_iter().next();
    let field_id = take_single_field(&mut claim, &mut fields, "claim id");
    if header_id.is_some() && field_id.is_some() && header_id != field_id {
        push_parse_issue(
            &mut claim,
            "claim_id",
            "Claim header and Claim ID field do not match",
        );
    }
    claim.claim_id = field_id.or(header_id);
    claim.owner = take_single_field(&mut claim, &mut fields, "owner");
    claim.status = take_single_field(&mut claim, &mut fields, "status");
    claim.created = take_single_field(&mut claim, &mut fields, "created");
    claim.updated = take_single_field(&mut claim, &mut fields, "updated");
    claim.heartbeat = take_single_field(&mut claim, &mut fields, "heartbeat");
    claim.date = take_single_field(&mut claim, &mut fields, "date");
    let stale = take_single_field(&mut claim, &mut fields, "stale after minutes");
    if let Some(stale) = stale {
        match stale.parse::<u64>() {
            Ok(value) if (1..=MAX_STALE_AFTER_MINUTES).contains(&value) => {
                claim.stale_after_minutes = Some(value)
            }
            _ => push_parse_issue(
                &mut claim,
                "stale_after_minutes",
                "stale-after value is malformed or out of bounds",
            ),
        }
    }

    if owned_heading_count != 1 {
        push_parse_issue(
            &mut claim,
            "owned_files",
            "claim must contain exactly one owned-files section",
        );
    }
    if owned_files.len() > MAX_OWNED_FILES {
        push_parse_issue(
            &mut claim,
            "owned_files",
            "claim exceeds its bounded owned-file count",
        );
        owned_files.truncate(MAX_OWNED_FILES);
    }
    let mut unique_owned = BTreeSet::new();
    for path in owned_files {
        if validate_owned_path(&path).is_err() {
            push_parse_issue(
                &mut claim,
                "owned_files",
                "claim contains an invalid or out-of-bounds owned path",
            );
            continue;
        }
        if !unique_owned.insert(path.clone()) {
            push_parse_issue(
                &mut claim,
                "owned_files",
                "claim contains a duplicate owned path",
            );
            continue;
        }
        claim.owned_files.push(path);
    }
    claim.owned_files.sort();

    if let Some(claim_id) = claim.claim_id.as_deref() {
        if validate_claim_id(claim_id, "claim id").is_err() {
            push_parse_issue(
                &mut claim,
                "claim_id",
                "claim id is not canonical or is out of bounds",
            );
        }
    } else {
        push_parse_issue(&mut claim, "claim_id", "missing required field 'claim_id'");
    }
    if let Some(owner) = claim.owner.as_deref() {
        if validate_owner(owner).is_err() {
            push_parse_issue(
                &mut claim,
                "owner",
                "claim owner is not canonical or is out of bounds",
            );
        }
    } else {
        push_parse_issue(&mut claim, "owner", "missing required field 'owner'");
    }
    if let Some(status) = claim.status.as_deref() {
        if !VALID_STATUSES.contains(&status) {
            push_parse_issue(&mut claim, "status", "claim status is unsupported");
        }
    } else {
        push_parse_issue(&mut claim, "status", "missing required field 'status'");
    }
    if claim.owned_files.is_empty() {
        push_parse_issue(
            &mut claim,
            "owned_files",
            "claim must list at least one owned file or surface",
        );
    }
    for (field, timestamp) in [
        ("created", claim.created.clone()),
        ("updated", claim.updated.clone()),
        ("heartbeat", claim.heartbeat.clone()),
        ("date", claim.date.clone()),
    ] {
        if let Some(timestamp) = timestamp {
            if timestamp.len() > MAX_TIMESTAMP_BYTES
                || timestamp.chars().any(char::is_control)
                || parse_timestamp_seconds(&timestamp).is_err()
            {
                push_parse_issue(
                    &mut claim,
                    field,
                    "claim timestamp is malformed or out of bounds",
                );
            }
        }
    }
    if claim.reference_timestamp().is_none() {
        push_parse_issue(
            &mut claim,
            "heartbeat",
            "claim has no heartbeat, updated, created, or date timestamp",
        );
    }
    if let (Some(file_stem), Some(claim_id)) = (
        claim.file.file_stem().and_then(|stem| stem.to_str()),
        claim.claim_id.as_deref(),
    ) {
        if file_stem != claim_id {
            push_parse_issue(
                &mut claim,
                "claim_id",
                "claim id does not match its canonical file name",
            );
        }
    }
    claim
}

fn take_single_field(
    claim: &mut ParsedClaim,
    fields: &mut BTreeMap<String, Vec<String>>,
    key: &str,
) -> Option<String> {
    let values = fields.remove(key).unwrap_or_default();
    if values.len() > 1 {
        push_parse_issue(
            claim,
            &key.replace(' ', "_"),
            "claim contains a duplicate recognized field",
        );
    }
    values.into_iter().next()
}

fn push_parse_issue(claim: &mut ParsedClaim, field: &str, message: &str) {
    if claim.issues.len() >= MAX_CLAIM_ISSUES {
        return;
    }
    claim.issues.push(LiveClaimIssue {
        severity: "error".to_string(),
        field: field.to_string(),
        message: message.to_string(),
    });
}

fn field_from_line(line: &str) -> Option<(String, String)> {
    let body = line.strip_prefix("- ")?;
    let (key, value) = body.split_once(':')?;
    Some((key.trim().to_ascii_lowercase(), clean_scalar(value)))
}

fn owned_file_from_line(line: &str) -> Option<PathBuf> {
    let body = line.strip_prefix("- ")?;
    if let Some(after_first) = body.strip_prefix('`') {
        let (path, _) = after_first.split_once('`')?;
        return Some(PathBuf::from(path));
    }
    let candidate = body.split(':').next().unwrap_or(body).trim();
    if candidate.is_empty() {
        None
    } else {
        Some(PathBuf::from(clean_scalar(candidate)))
    }
}

fn validate_claim_id(value: &str, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > MAX_CLAIM_ID_BYTES {
        bail!("{label} is empty or exceeds its bounded length");
    }
    let bytes = value.as_bytes();
    if !bytes
        .first()
        .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || !bytes
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        || bytes.iter().any(|byte| {
            !(byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || matches!(*byte, b'-' | b'_' | b'.'))
        })
        || value.contains("..")
    {
        bail!("{label} is not canonical");
    }
    Ok(())
}

fn validate_owner(value: &str) -> Result<()> {
    if value.len() > MAX_OWNER_BYTES {
        bail!("claim owner exceeds its bounded length");
    }
    validate_claim_id(value, "claim owner")
}

fn validate_actor(actor: &str, operation: &str) -> Result<()> {
    let actor = actor.trim();
    if actor.is_empty() {
        bail!("{operation} requires --by");
    }
    if actor.len() > MAX_AUDIT_ACTOR_BYTES || actor != clean_scalar(actor) {
        bail!("{operation} actor is not canonical or exceeds its bounded length");
    }
    validate_owner(actor).map_err(|_| {
        anyhow::anyhow!("{operation} actor is not canonical or exceeds its bounded length")
    })
}

fn validate_audit_reason(reason: &str) -> Result<()> {
    let reason = reason.trim();
    if reason.is_empty() {
        bail!("override-release requires --reason");
    }
    if reason.len() > MAX_AUDIT_REASON_BYTES
        || reason.chars().any(char::is_control)
        || reason.chars().any(|character| {
            character == char::from(96)
                || matches!(character, '#' | '[' | ']' | '<' | '>' | '*' | '|' | '\\')
        })
    {
        bail!("override-release reason is unsafe for a bounded Markdown audit entry");
    }
    Ok(())
}

fn validate_owned_path(path: &Path) -> Result<()> {
    let value = path
        .to_str()
        .context("claim owned path must be valid UTF-8")?;
    if value.is_empty()
        || value.len() > MAX_OWNED_PATH_BYTES
        || path.is_absolute()
        || value.chars().any(char::is_control)
    {
        bail!("claim owned path is invalid or out of bounds");
    }
    for component in path.components() {
        if !matches!(component, std::path::Component::Normal(_)) {
            bail!("claim owned path is not canonical relative form");
        }
    }
    Ok(())
}

fn summary_from_parsed(claim: &ParsedClaim, now: &LiveClock) -> LiveClaimSummary {
    let mut warnings = Vec::new();
    let stale_after_minutes = claim
        .stale_after_minutes
        .unwrap_or(DEFAULT_STALE_AFTER_MINUTES);
    let liveness = if let Some((field, timestamp)) = claim.reference_timestamp() {
        match parse_timestamp_seconds(timestamp) {
            Ok(reference_seconds) => {
                if reference_seconds
                    > now
                        .epoch_seconds
                        .saturating_add(MAX_FUTURE_CLOCK_SKEW_SECONDS)
                {
                    warnings.push(format!(
                        "{field} timestamp is unreasonably far in the future"
                    ));
                    LiveClaimLiveness {
                        state: "unknown".to_string(),
                        reference_field: Some(field.to_string()),
                        reference_timestamp: Some(timestamp.to_string()),
                        age_minutes: None,
                        stale_after_minutes: claim.stale_after_minutes,
                    }
                } else {
                    let age_minutes = (now.epoch_seconds - reference_seconds) / 60;
                    let stale_after_i64 = i64::try_from(stale_after_minutes).unwrap_or(i64::MAX);
                    let state = match age_minutes.cmp(&stale_after_i64) {
                        Ordering::Greater => "stale",
                        Ordering::Equal | Ordering::Less => "fresh",
                    };
                    LiveClaimLiveness {
                        state: state.to_string(),
                        reference_field: Some(field.to_string()),
                        reference_timestamp: Some(timestamp.to_string()),
                        age_minutes: Some(age_minutes),
                        stale_after_minutes: Some(stale_after_minutes),
                    }
                }
            }
            Err(_) => {
                warnings.push(format!("{field} timestamp is malformed"));
                LiveClaimLiveness {
                    state: "unknown".to_string(),
                    reference_field: Some(field.to_string()),
                    reference_timestamp: Some(timestamp.to_string()),
                    age_minutes: None,
                    stale_after_minutes: claim.stale_after_minutes,
                }
            }
        }
    } else {
        warnings.push("no heartbeat, updated, created, or date timestamp available".to_string());
        LiveClaimLiveness {
            state: "stale_risk".to_string(),
            reference_field: None,
            reference_timestamp: None,
            age_minutes: None,
            stale_after_minutes: claim.stale_after_minutes,
        }
    };

    if claim.stale_after_minutes.is_none() {
        warnings.push(format!(
            "missing stale-after value; using default {DEFAULT_STALE_AFTER_MINUTES} minutes"
        ));
    }

    let is_lock = matches!(claim.status.as_deref(), Some("active" | "blocked"));
    LiveClaimSummary {
        claim_id: claim.display_id(),
        file: claim.file.clone(),
        owner: claim.owner.clone(),
        status: claim.status.clone(),
        is_lock,
        created: claim.created.clone().or_else(|| claim.date.clone()),
        updated: claim.updated.clone(),
        heartbeat: claim.heartbeat.clone(),
        stale_after_minutes: claim.stale_after_minutes,
        owned_files: claim.owned_files.clone(),
        liveness,
        warnings,
    }
}

fn update_claim_content(
    content: &str,
    claim: &ParsedClaim,
    now: &LiveClock,
    status: Option<&str>,
    audit_entry: &str,
    max_bytes: usize,
) -> Result<String> {
    let mut lines = content.lines().map(ToString::to_string).collect::<Vec<_>>();
    ensure_field(&mut lines, "Claim ID", &claim.display_id());
    ensure_field(
        &mut lines,
        "Owner",
        claim.owner.as_deref().unwrap_or(&claim.display_id()),
    );
    ensure_field(
        &mut lines,
        "Created",
        claim
            .created
            .as_deref()
            .or(claim.date.as_deref())
            .unwrap_or(now.raw()),
    );
    ensure_field(&mut lines, "Updated", now.raw());
    ensure_field(&mut lines, "Heartbeat", now.raw());
    ensure_field(
        &mut lines,
        "Stale after minutes",
        &claim
            .stale_after_minutes
            .unwrap_or(DEFAULT_STALE_AFTER_MINUTES)
            .to_string(),
    );
    if let Some(status) = status {
        ensure_field(&mut lines, "Status", status);
    } else if let Some(existing) = &claim.status {
        ensure_field(&mut lines, "Status", existing);
    }
    ensure_owned_files_heading(&mut lines);
    let base = lines.join("\n");
    let with_audit = format!("{}\n", append_audit_entry(&base, audit_entry));
    if with_audit.len() <= max_bytes {
        return Ok(with_audit);
    }
    let compacted = compact_audit_history(&base)?;
    let with_compacted_audit = format!("{}\n", append_audit_entry(&compacted, audit_entry));
    if with_compacted_audit.len() > max_bytes {
        bail!("claim cannot preserve bounded release headroom after audit compaction");
    }
    Ok(with_compacted_audit)
}

fn ensure_field(lines: &mut Vec<String>, key: &str, value: &str) {
    let key_lower = key.to_ascii_lowercase();
    let new_line = format!("- {key}: `{}`", value.trim());
    for line in lines.iter_mut() {
        if let Some((candidate, _)) = field_from_line(line.trim()) {
            if candidate == key_lower {
                *line = new_line;
                return;
            }
        }
    }

    let insert_at = lines
        .iter()
        .position(|line| line.starts_with("- Owner:"))
        .map(|index| index.saturating_add(1))
        .or_else(|| lines.iter().position(|line| line.starts_with("- Date:")))
        .map(|index| index.saturating_add(1))
        .unwrap_or_else(|| {
            lines
                .iter()
                .position(|line| line.starts_with("# Claim:"))
                .map(|index| index.saturating_add(1))
                .unwrap_or(0)
        });
    lines.insert(insert_at, new_line);
}

fn ensure_owned_files_heading(lines: &mut Vec<String>) {
    let has_owned_files = lines
        .iter()
        .any(|line| line.to_ascii_lowercase().contains("owned files"));
    if has_owned_files {
        return;
    }
    let insert_at = lines
        .iter()
        .position(|line| line.starts_with("- Non-overlap"))
        .unwrap_or(lines.len());
    lines.insert(
        insert_at,
        "- Owned files, regions, devices, or services:".to_string(),
    );
    lines.insert(
        insert_at.saturating_add(1),
        "  - `<path-or-surface>`".to_string(),
    );
}

fn append_audit_entry(content: &str, audit_entry: &str) -> String {
    let entry = format!("- {audit_entry}");
    if content.contains("\n## Audit log") || content.starts_with("## Audit log") {
        let mut lines = content.lines().map(ToString::to_string).collect::<Vec<_>>();
        let audit_index = lines.iter().position(|line| line.trim() == "## Audit log");
        if let Some(index) = audit_index {
            let insert_at = lines
                .iter()
                .enumerate()
                .skip(index.saturating_add(1))
                .find_map(|(line_index, line)| {
                    if line.starts_with("## ") {
                        Some(line_index)
                    } else {
                        None
                    }
                })
                .unwrap_or(lines.len());
            if insert_at < lines.len() {
                if insert_at > 0 && !lines[insert_at.saturating_sub(1)].trim().is_empty() {
                    lines.insert(insert_at, String::new());
                }
                lines.insert(insert_at, entry);
                lines.insert(insert_at.saturating_add(1), String::new());
            } else if insert_at > 0 && !lines[insert_at.saturating_sub(1)].trim().is_empty() {
                lines.insert(insert_at, String::new());
                lines.insert(insert_at.saturating_add(1), entry);
            } else {
                lines.insert(insert_at, entry);
            }
            return lines.join("\n");
        }
    }

    if let Some(index) = content.find("\n## Public Boundary Reminder") {
        let (before, after) = content.split_at(index);
        format!("{before}\n## Audit log\n\n{entry}\n{after}")
    } else {
        format!("{content}\n\n## Audit log\n\n{entry}")
    }
}

fn compact_audit_history(content: &str) -> Result<String> {
    let mut lines = content.lines().map(ToString::to_string).collect::<Vec<_>>();
    let Some(audit_index) = lines.iter().position(|line| line.trim() == "## Audit log") else {
        return Ok(content.to_string());
    };
    let end = lines
        .iter()
        .enumerate()
        .skip(audit_index.saturating_add(1))
        .find_map(|(index, line)| line.starts_with("## ").then_some(index))
        .unwrap_or(lines.len());
    let history = lines[audit_index.saturating_add(1)..end].join("\n");
    let entry_count = history
        .lines()
        .filter(|line| line.trim_start().starts_with("- "))
        .count();
    let digest = stable_checksum(history.as_bytes());
    let compacted =
        format!("- prior audit history compacted: {entry_count} entries; digest `{digest}`");
    lines.splice(
        audit_index.saturating_add(1)..end,
        [String::new(), compacted, String::new()],
    );
    Ok(lines.join("\n"))
}

fn clean_scalar(value: &str) -> String {
    value
        .trim()
        .trim_matches('`')
        .trim_matches('"')
        .trim()
        .to_string()
}

fn parse_timestamp_seconds(value: &str) -> Result<i64> {
    let value = clean_scalar(value);
    if value.len() == 10 && value.as_bytes().get(4) == Some(&b'-') {
        let (year, month, day) = parse_date(&value)?;
        return days_from_civil(year, month, day)
            .checked_mul(86_400)
            .context("timestamp overflow");
    }

    let (date_part, time_part) = value
        .split_once('T')
        .or_else(|| value.split_once(' '))
        .context("timestamp must be YYYY-MM-DD or RFC3339-like date time")?;
    let (year, month, day) = parse_date(date_part)?;
    let (time_part, offset_seconds) = split_time_offset(time_part)?;
    let (hour, minute, second) = parse_time(time_part)?;
    let day_seconds = i64::from(hour)
        .checked_mul(3_600)
        .and_then(|value| value.checked_add(i64::from(minute) * 60))
        .and_then(|value| value.checked_add(i64::from(second)))
        .context("timestamp overflow")?;
    days_from_civil(year, month, day)
        .checked_mul(86_400)
        .and_then(|value| value.checked_add(day_seconds))
        .and_then(|value| value.checked_sub(i64::from(offset_seconds)))
        .context("timestamp overflow")
}

fn parse_date(value: &str) -> Result<(i32, u32, u32)> {
    let parts = value.split('-').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("date must be YYYY-MM-DD");
    }
    let year = parts[0].parse::<i32>().context("invalid year")?;
    let month = parts[1].parse::<u32>().context("invalid month")?;
    let day = parts[2].parse::<u32>().context("invalid day")?;
    if !(1..=12).contains(&month) {
        bail!("month out of range");
    }
    if !(1..=days_in_month(year, month)).contains(&day) {
        bail!("day out of range");
    }
    Ok((year, month, day))
}

fn split_time_offset(value: &str) -> Result<(&str, i32)> {
    if let Some(time) = value.strip_suffix('Z') {
        return Ok((time, 0));
    }
    let mut offset_index = None;
    for (index, character) in value.char_indices().skip(1) {
        if matches!(character, '+' | '-') {
            offset_index = Some(index);
        }
    }
    if let Some(index) = offset_index {
        let (time, offset) = value.split_at(index);
        let sign = if offset.starts_with('-') { -1 } else { 1 };
        let offset_body = &offset[1..];
        let (hours, minutes) = offset_body
            .split_once(':')
            .context("UTC offset must be HH:MM")?;
        let hours = hours.parse::<i32>().context("invalid UTC offset hour")?;
        let minutes = minutes
            .parse::<i32>()
            .context("invalid UTC offset minute")?;
        if !(0..=23).contains(&hours) || !(0..=59).contains(&minutes) {
            bail!("UTC offset out of range");
        }
        return Ok((time, sign * (hours * 3_600 + minutes * 60)));
    }
    Ok((value, 0))
}

fn parse_time(value: &str) -> Result<(u32, u32, u32)> {
    let parts = value.split(':').collect::<Vec<_>>();
    if parts.len() != 3 {
        bail!("time must be HH:MM:SS");
    }
    let hour = parts[0].parse::<u32>().context("invalid hour")?;
    let minute = parts[1].parse::<u32>().context("invalid minute")?;
    let second_part = parts[2].split('.').next().unwrap_or(parts[2]);
    let second = second_part.parse::<u32>().context("invalid second")?;
    if hour > 23 || minute > 59 || second > 60 {
        bail!("time out of range");
    }
    Ok((hour, minute, second))
}

fn days_in_month(year: i32, month: u32) -> u32 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if is_leap_year(year) => 29,
        2 => 28,
        _ => 0,
    }
}

fn is_leap_year(year: i32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || year % 400 == 0
}

fn days_from_civil(year: i32, month: u32, day: u32) -> i64 {
    let mut y = i64::from(year);
    let m = i64::from(month);
    let d = i64::from(day);
    y -= if m <= 2 { 1 } else { 0 };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let month_prime = m + if m > 2 { -3 } else { 9 };
    let doy = (153 * month_prime + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

fn civil_from_days(days: i64) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let mut y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = mp + if mp < 10 { 3 } else { -9 };
    y += if m <= 2 { 1 } else { 0 };
    (
        i32::try_from(y).unwrap_or(i32::MAX),
        u32::try_from(m).unwrap_or(1),
        u32::try_from(d).unwrap_or(1),
    )
}

fn format_epoch_seconds(epoch_seconds: i64) -> String {
    let days = epoch_seconds.div_euclid(86_400);
    let seconds = epoch_seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = seconds / 3_600;
    let minute = (seconds % 3_600) / 60;
    let second = seconds % 60;
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn claim_text(
        claim_id: &str,
        owner: &str,
        status: &str,
        timestamp: &str,
        owned_surface: &str,
    ) -> String {
        format!(
            "# Claim: {claim_id}\n\n- Claim ID: {claim_id}\n- Owner: {owner}\n- Status: {status}\n- Created: {timestamp}\n- Updated: {timestamp}\n- Heartbeat: {timestamp}\n- Stale after minutes: 60\n- Owned files, regions, devices, or services:\n  - {owned_surface}: bounded test surface\n\n## Audit log\n\n- {timestamp} - {owner} created\n"
        )
    }

    fn write_claim(
        repo: &Path,
        claim_id: &str,
        owner: &str,
        status: &str,
        timestamp: &str,
    ) -> Result<PathBuf> {
        let directory = repo.join(CLAIMS_DIR);
        std::fs::create_dir_all(&directory)?;
        let path = directory.join(format!("{claim_id}.md"));
        std::fs::write(
            &path,
            claim_text(
                claim_id,
                owner,
                status,
                timestamp,
                "Host-global transient service and runtime coordination",
            ),
        )?;
        Ok(path)
    }

    #[test]
    fn parser_accepts_legacy_and_nonfilesystem_surfaces_but_rejects_strict_grammar_errors() {
        let legacy = parse_claim_file(
            PathBuf::from(CLAIMS_DIR).join("legacy.md"),
            "# Claim: legacy\n\n- Owner: worker-a\n- Date: 2026-05-19\n- Status: active\n- Owned files, regions, devices, or services:\n  - Host-global transient service coordination: test\n",
        );
        assert!(legacy.issues.is_empty(), "{:?}", legacy.issues);
        assert_eq!(
            legacy.owned_files,
            vec![PathBuf::from("Host-global transient service coordination")]
        );

        let completed = parse_claim_file(
            PathBuf::from(CLAIMS_DIR).join("completed.md"),
            &claim_text(
                "completed",
                "worker-a",
                "completed",
                "2026-05-19T00:00:00Z",
                "src/live_claim.rs",
            ),
        );
        assert!(completed.issues.iter().any(|issue| issue.field == "status"));

        let duplicate_owner = claim_text(
            "duplicate",
            "worker-a",
            "active",
            "2026-05-19T00:00:00Z",
            "src/live_claim.rs",
        )
        .replace("- Status:", "- Owner: worker-b\n- Status:");
        let duplicate = parse_claim_file(
            PathBuf::from(CLAIMS_DIR).join("duplicate.md"),
            &duplicate_owner,
        );
        assert!(duplicate
            .issues
            .iter()
            .any(|issue| issue.message.contains("duplicate recognized field")));

        let mismatch = parse_claim_file(
            PathBuf::from(CLAIMS_DIR).join("mismatch.md"),
            &claim_text(
                "different",
                "worker-a",
                "active",
                "2026-05-19T00:00:00Z",
                "src/live_claim.rs",
            ),
        );
        assert!(mismatch
            .issues
            .iter()
            .any(|issue| issue.message.contains("file name")));
    }

    #[test]
    fn future_timestamps_are_unknown_and_cannot_be_override_released() -> Result<()> {
        let temp = tempfile::tempdir()?;
        write_claim(
            temp.path(),
            "future-claim",
            "future-claim",
            "active",
            "2026-05-21T00:00:00Z",
        )?;
        let now = LiveClock::parse("2026-05-20T00:00:00Z")?;
        let report = status(temp.path(), &now)?;
        assert_eq!(report.claims[0].liveness.state, "unknown");
        assert!(report.claims[0]
            .warnings
            .iter()
            .any(|warning| warning.contains("future")));
        let error = override_release_with_clock(
            temp.path(),
            "future-claim",
            "project-owner",
            "owner unavailable and bounded files are blocked",
            &now,
        )
        .expect_err("future claim must not be adopted as stale");
        assert!(error.to_string().contains("provably stale"));
        let heartbeat_error =
            heartbeat_with_clock(temp.path(), "future-claim", "future-claim", &now)
                .expect_err("future heartbeat generations must not be rolled back");
        assert!(heartbeat_error.to_string().contains("future or rollback"));
        Ok(())
    }

    #[test]
    fn heartbeat_requires_exact_owner_and_override_requires_stale_safe_input() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = write_claim(
            temp.path(),
            "owner-claim",
            "owner-claim",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let original = std::fs::read(&path)?;
        let fresh = LiveClock::parse("2026-05-20T00:30:00Z")?;
        assert!(heartbeat_with_clock(temp.path(), "owner-claim", "other-owner", &fresh).is_err());
        assert_eq!(std::fs::read(&path)?, original);
        assert!(override_release_with_clock(
            temp.path(),
            "owner-claim",
            "project-owner",
            "fresh claim must remain owned",
            &fresh,
        )
        .is_err());
        assert_eq!(std::fs::read(&path)?, original);

        let stale = LiveClock::parse("2026-05-20T02:00:00Z")?;
        assert!(override_release_with_clock(
            temp.path(),
            "owner-claim",
            "project-owner",
            "line one\nline two",
            &stale,
        )
        .is_err());
        assert!(override_release_with_clock(
            temp.path(),
            "owner-claim",
            "project-owner",
            &format!("unsafe {} inline", char::from(96)),
            &stale,
        )
        .is_err());
        let report = heartbeat_with_clock(temp.path(), "owner-claim", "owner-claim", &fresh)?;
        assert_eq!(report.actor, "owner-claim");
        assert_eq!(
            report.file,
            PathBuf::from(CLAIMS_DIR).join("owner-claim.md")
        );
        let rollback = LiveClock::parse("2026-05-20T00:29:59Z")?;
        assert!(
            heartbeat_with_clock(temp.path(), "owner-claim", "owner-claim", &rollback)
                .expect_err("heartbeat rollback must fail")
                .to_string()
                .contains("future or rollback")
        );
        Ok(())
    }

    #[test]
    fn atomic_mutation_fence_rejects_same_inode_content_and_rebound_inode_races() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = write_claim(
            temp.path(),
            "content-race",
            "content-race",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        let changed = claim_text(
            "content-race",
            "content-race",
            "active",
            "2026-05-20T00:01:00Z",
            "src/live_claim.rs",
        );
        let error = mutate_claim(
            temp.path(),
            "content-race",
            "content-race",
            &now,
            ClaimMutation::Heartbeat,
            |claim_path| {
                std::fs::write(claim_path, &changed)?;
                Ok(())
            },
        )
        .expect_err("same-inode content race must fail");
        assert!(error.to_string().contains("atomic mutation was refused"));
        assert_eq!(std::fs::read_to_string(&path)?, changed);

        let second = tempfile::tempdir()?;
        let path = write_claim(
            second.path(),
            "inode-race",
            "inode-race",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let replacement = claim_text(
            "inode-race",
            "inode-race",
            "active",
            "2026-05-20T00:02:00Z",
            "src/live_claim.rs",
        );
        let error = mutate_claim(
            second.path(),
            "inode-race",
            "inode-race",
            &now,
            ClaimMutation::Heartbeat,
            |claim_path| {
                std::fs::remove_file(claim_path)?;
                std::fs::write(claim_path, &replacement)?;
                Ok(())
            },
        )
        .expect_err("inode rebound race must fail");
        assert!(error.to_string().contains("atomic mutation was refused"));
        assert_eq!(std::fs::read_to_string(&path)?, replacement);
        Ok(())
    }

    #[test]
    fn concurrent_heartbeats_preserve_both_audit_entries_under_board_lock() -> Result<()> {
        let temp = Arc::new(tempfile::tempdir()?);
        let path = write_claim(
            temp.path(),
            "locked-claim",
            "locked-claim",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let mut threads = Vec::new();
        for timestamp in ["2026-05-20T00:11:00Z", "2026-05-20T00:11:00Z"] {
            let temp = Arc::clone(&temp);
            threads.push(std::thread::spawn(move || -> Result<()> {
                heartbeat_with_clock(
                    temp.path(),
                    "locked-claim",
                    "locked-claim",
                    &LiveClock::parse(timestamp)?,
                )?;
                Ok(())
            }));
        }
        for thread in threads {
            thread
                .join()
                .map_err(|_| anyhow::anyhow!("heartbeat thread panicked"))??;
        }
        let content = std::fs::read_to_string(path)?;
        assert_eq!(content.matches(" heartbeat").count(), 2);
        Ok(())
    }

    #[test]
    fn stable_board_read_and_mutation_fence_cover_names_and_other_claim_generations() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        write_claim(
            temp.path(),
            "first-claim",
            "first-claim",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let second_path = write_claim(
            temp.path(),
            "second-claim",
            "second-claim",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let second_content = claim_text(
            "second-claim",
            "second-claim",
            "active",
            "2026-05-20T00:01:00Z",
            "tests/live_cli.rs",
        );
        let root = open_claims_root(&claims_dir(temp.path()))?.context("claim root")?;
        let lock = acquire_claim_board_lock(&root)?;
        prepare_claim_board(&root, &lock)?;
        let read_error = load_stable_claim_board_with_hook(&root, &lock, || {
            std::fs::write(&second_path, &second_content)?;
            Ok(())
        })
        .expect_err("stable board reads must reject generation changes");
        assert!(read_error.to_string().contains("generation changed"));
        drop(lock);

        std::fs::write(
            &second_path,
            claim_text(
                "second-claim",
                "second-claim",
                "active",
                "2026-05-20T00:00:00Z",
                "tests/live_cli.rs",
            ),
        )?;
        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        let mutation_error = mutate_claim(
            temp.path(),
            "first-claim",
            "first-claim",
            &now,
            ClaimMutation::Heartbeat,
            |_| {
                std::fs::write(&second_path, &second_content)?;
                Ok(())
            },
        )
        .expect_err("mutation fence must cover every board entry");
        assert!(mutation_error
            .to_string()
            .contains("atomic mutation was refused"));
        Ok(())
    }

    #[test]
    fn active_owned_paths_are_component_aware_and_fail_board_validation() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let directory = claims_dir(temp.path());
        std::fs::create_dir_all(&directory)?;
        std::fs::write(
            directory.join("parent-claim.md"),
            claim_text(
                "parent-claim",
                "parent-claim",
                "active",
                "2026-05-20T00:00:00Z",
                "src/live_claim.rs",
            ),
        )?;
        let child = claim_text(
            "child-claim",
            "child-claim",
            "blocked",
            "2026-05-20T00:00:00Z",
            "src/live_claim.rs/tests",
        );
        std::fs::write(directory.join("child-claim.md"), child)?;
        let report = validate(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)?;
        assert!(!report.valid);
        assert_eq!(
            report
                .claims
                .iter()
                .filter(|claim| claim
                    .issues
                    .iter()
                    .any(|issue| issue.message.contains("overlaps")))
                .count(),
            2
        );
        assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());

        std::fs::write(
            directory.join("child-claim.md"),
            claim_text(
                "child-claim",
                "child-claim",
                "handoff",
                "2026-05-20T00:00:00Z",
                "src/live_claim.rs/tests",
            ),
        )?;
        assert_eq!(
            status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)?.claim_count,
            2
        );
        Ok(())
    }

    #[test]
    fn apply_atomically_creates_owner_updates_and_release_uses_the_same_board_path() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let directory = claims_dir(temp.path());
        std::fs::create_dir_all(&directory)?;
        let draft = temp.path().join("claim-draft.md");
        std::fs::write(
            &draft,
            claim_text(
                "applied-claim",
                "applied-owner",
                "active",
                "2026-05-20T00:00:00Z",
                "src/review.rs",
            ),
        )?;
        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        let created = apply_with_clock(temp.path(), &draft, "applied-owner", &now)?;
        assert!(created.created);
        assert!(std::fs::read_to_string(directory.join("applied-claim.md"))?
            .contains("applied claim draft"));
        assert!(apply_with_clock(
            temp.path(),
            &directory.join("applied-claim.md"),
            "applied-owner",
            &now,
        )
        .expect_err("drafts inside the board must be refused")
        .to_string()
        .contains("outside"));

        let other_actor = apply_with_clock(temp.path(), &draft, "other-owner", &now)
            .expect_err("only the exact owner may update a claim");
        assert!(other_actor.to_string().contains("draft owner"));

        std::fs::write(
            directory.join("other-claim.md"),
            claim_text(
                "other-claim",
                "other-owner",
                "active",
                "2026-05-20T00:00:00Z",
                "src",
            ),
        )?;
        std::fs::write(
            &draft,
            claim_text(
                "applied-claim",
                "applied-owner",
                "blocked",
                "2026-05-20T00:00:00Z",
                "src/review.rs",
            ),
        )?;
        assert!(apply_with_clock(temp.path(), &draft, "applied-owner", &now).is_err());
        std::fs::remove_file(directory.join("other-claim.md"))?;
        let updated = apply_with_clock(temp.path(), &draft, "applied-owner", &now)?;
        assert!(!updated.created);
        assert_eq!(updated.claim.status.as_deref(), Some("blocked"));

        let released = release(
            temp.path(),
            "applied-claim",
            "applied-owner",
            "done",
            "owner completed the bounded work",
        )?;
        assert_eq!(released.status.as_deref(), Some("done"));
        assert!(released.audit_entry.contains("released claim as `done`"));
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn claim_writer_residue_is_canonically_scavenged_and_unknown_residue_is_refused() -> Result<()>
    {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir()?;
        write_claim(
            temp.path(),
            "residue-claim",
            "residue-claim",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let directory = claims_dir(temp.path());
        let known = directory.join(".residue-claim.md.1-2.tmp");
        std::fs::write(&known, b"bounded residue")?;
        std::fs::set_permissions(&known, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)?.claim_count,
            1
        );
        assert!(!known.exists());

        let interrupted_create = directory.join(".new-residue-claim.md.3-4.tmp");
        std::fs::write(&interrupted_create, b"bounded interrupted create residue")?;
        std::fs::set_permissions(&interrupted_create, std::fs::Permissions::from_mode(0o600))?;
        assert_eq!(
            status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)?.claim_count,
            1
        );
        assert!(!interrupted_create.exists());

        let unknown = directory.join(".residue-claim.md.bad.tmp");
        std::fs::write(&unknown, b"unknown residue")?;
        std::fs::set_permissions(&unknown, std::fs::Permissions::from_mode(0o600))?;
        let error = status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)
            .expect_err("unknown writer residue must fail closed");
        assert!(error.to_string().contains("unknown writer residue"));
        assert!(unknown.exists());
        Ok(())
    }

    #[test]
    fn stale_release_compacts_audit_growth_instead_of_becoming_unreleasable() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = write_claim(
            temp.path(),
            "audit-growth",
            "audit-growth",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let mut content = std::fs::read_to_string(&path)?;
        while content.len() < MAX_CLAIM_BYTES as usize - 16 {
            content
                .push_str("- old bounded audit entry 0123456789012345678901234567890123456789\n");
        }
        content.truncate(MAX_CLAIM_BYTES as usize - 16);
        while !content.ends_with('\n') {
            content.pop();
        }
        std::fs::write(&path, content)?;

        let report = override_release_with_clock(
            temp.path(),
            "audit-growth",
            "project-owner",
            "stale owner unavailable",
            &LiveClock::parse("2026-05-20T02:00:00Z")?,
        )?;
        assert_eq!(report.status.as_deref(), Some("handoff"));
        let released = std::fs::read_to_string(path)?;
        assert!(released.contains("prior audit history compacted"));
        assert!(released.contains("override-release"));
        assert!(released.len() <= MAX_CLAIM_BYTES as usize);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn board_loader_rejects_links_special_files_unsafe_extras_and_bounds_without_path_leaks(
    ) -> Result<()> {
        use std::os::unix::{
            ffi::{OsStrExt, OsStringExt},
            fs::symlink,
        };

        let temp = tempfile::tempdir()?;
        let directory = temp.path().join(CLAIMS_DIR);
        std::fs::create_dir_all(&directory)?;
        let external = temp.path().join("external-secret");
        std::fs::write(
            &external,
            claim_text(
                "linked",
                "linked",
                "active",
                "2026-05-20T00:00:00Z",
                "src/live_claim.rs",
            ),
        )?;
        symlink(&external, directory.join("linked.md"))?;
        let error = status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)
            .expect_err("claim symlink must fail closed");
        assert!(!error.to_string().contains(&external.display().to_string()));
        std::fs::remove_file(directory.join("linked.md"))?;

        std::fs::hard_link(&external, directory.join("hardlinked.md"))?;
        assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
        std::fs::remove_file(directory.join("hardlinked.md"))?;

        let fifo_path = directory.join("fifo.md");
        let fifo = std::ffi::CString::new(fifo_path.as_os_str().as_bytes())?;
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
        std::fs::remove_file(&fifo_path)?;

        std::fs::create_dir(directory.join("directory.md"))?;
        assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
        std::fs::remove_dir(directory.join("directory.md"))?;

        std::fs::write(
            directory.join("oversized.md"),
            vec![b'x'; MAX_CLAIM_BYTES as usize + 1],
        )?;
        assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
        std::fs::remove_file(directory.join("oversized.md"))?;

        std::fs::write(directory.join("nonutf.md"), [0xff, 0xfe])?;
        assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
        std::fs::remove_file(directory.join("nonutf.md"))?;

        let non_utf_name = OsString::from_vec(b"nonutf-\xff.md".to_vec());
        std::fs::write(directory.join(&non_utf_name), b"bounded")?;
        assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
        std::fs::remove_file(directory.join(&non_utf_name))?;

        std::fs::write(directory.join("unexpected.bin"), b"unexpected")?;
        assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
        std::fs::remove_file(directory.join("unexpected.bin"))?;

        symlink(&external, directory.join(TEMPLATE_FILE))?;
        assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());
        std::fs::remove_file(directory.join(TEMPLATE_FILE))?;

        std::fs::remove_file(directory.join(BOARD_LOCK_FILE))?;
        symlink(&external, directory.join(BOARD_LOCK_FILE))?;
        assert!(status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?).is_err());

        let linked_root = tempfile::tempdir()?;
        std::fs::create_dir_all(linked_root.path().join(".agents/live"))?;
        symlink(&directory, linked_root.path().join(CLAIMS_DIR))?;
        assert!(status(
            linked_root.path(),
            &LiveClock::parse("2026-05-20T00:30:00Z")?
        )
        .is_err());
        Ok(())
    }

    #[test]
    fn board_entry_count_is_bounded_before_claim_contents_are_parsed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let directory = temp.path().join(CLAIMS_DIR);
        std::fs::create_dir_all(&directory)?;
        for index in 0..=MAX_CLAIM_ENTRIES {
            std::fs::write(directory.join(format!("claim-{index}.md")), b"")?;
        }
        let error = status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)
            .expect_err("entry count must be bounded");
        assert!(error.to_string().contains("entry limit"));
        Ok(())
    }

    #[test]
    fn real_board_style_surfaces_load_until_legacy_completed_status_fails_closed() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let directory = temp.path().join(CLAIMS_DIR);
        std::fs::create_dir_all(&directory)?;
        std::fs::write(
            directory.join("global-validation.md"),
            claim_text(
                "global-validation",
                "global-validation",
                "active",
                "2026-05-20T00:00:00Z",
                "Host-global transient service units, cgroups, and runtime directories",
            ),
        )?;
        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        assert_eq!(status(temp.path(), &now)?.claim_count, 1);
        std::fs::write(
            directory.join("legacy-completed.md"),
            claim_text(
                "legacy-completed",
                "legacy-completed",
                "completed",
                "2026-05-20T00:00:00Z",
                "src/live_claim.rs",
            ),
        )?;
        assert!(status(temp.path(), &now).is_err());
        assert!(!validate(temp.path(), &now)?.valid);
        Ok(())
    }

    #[test]
    fn validation_includes_parser_errors_and_duplicate_claim_ids_without_raw_values() -> Result<()>
    {
        let temp = tempfile::tempdir()?;
        let directory = temp.path().join(CLAIMS_DIR);
        std::fs::create_dir_all(&directory)?;
        let first = claim_text(
            "first",
            "first",
            "waiting-secret-value",
            "malformed-secret-timestamp",
            "src/live_claim.rs",
        )
        .replace("- Owner: first", "- Owner: first\n- Owner: duplicate-owner");
        std::fs::write(directory.join("first.md"), first)?;
        let second = claim_text(
            "first",
            "second",
            "active",
            "2026-05-20T00:00:00Z",
            "src/live_claim.rs",
        );
        std::fs::write(directory.join("second.md"), second)?;

        let report = validate(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)?;
        assert!(!report.valid);
        let serialized = serde_json::to_string(&report)?;
        assert!(serialized.contains("duplicate recognized field"));
        assert!(serialized.contains("duplicated across claim files"));
        assert!(!serialized.contains("waiting-secret-value"));
        assert!(!serialized.contains("malformed-secret-timestamp"));
        Ok(())
    }
}
