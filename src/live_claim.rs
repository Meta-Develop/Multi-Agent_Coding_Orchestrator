use crate::{
    agent_lifecycle::process_start_time,
    artifacts::state_auth::sha256_hex,
    safe_state::{
        stable_checksum, AtomicStateWriter, BoundedRegularReader, FileIdentity, KernelStateLock,
        SafeRoot,
    },
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    cmp::Ordering,
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs::{self, File, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering as AtomicOrdering},
    time::{SystemTime, UNIX_EPOCH},
};

#[cfg(unix)]
use std::os::unix::{
    ffi::OsStrExt,
    fs::{MetadataExt, OpenOptionsExt},
    io::{AsRawFd, FromRawFd},
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
const MAX_APPLY_DRAFT_AGE_SECONDS: i64 = 5 * 60;
const MAX_DRAFT_PARENT_BYTES: usize = 4 * 1024;
const MAX_DRAFT_LEAF_BYTES: usize = 255;
const MAX_FUTURE_CLOCK_SKEW_SECONDS: i64 = 5 * 60;
const VALID_STATUSES: &[&str] = &["active", "blocked", "ready-for-review", "handoff", "done"];
#[cfg(target_os = "linux")]
const CLAIM_FALLBACK_RESIDUE_PREFIX: &str = ".maco-live-old-v1.";
#[cfg(target_os = "linux")]
const CLAIM_FALLBACK_RESIDUE_SUFFIX: &str = ".txn";

static CLAIM_TEMP_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Boot-scoped identity for the MACO process that acquired a durable path claim.
///
/// A PID alone is not enough to decide whether a retained claim still belongs to
/// a live process because the operating system may reuse it.  The start-time
/// token comes from the existing agent-lifecycle identity implementation and is
/// boot-scoped on Linux.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ClaimProcessIdentity {
    pub(crate) pid: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) process_start_time: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ClaimProcessLiveness {
    Live,
    Interrupted,
    Unknown,
}

pub(crate) fn current_claim_process_identity() -> ClaimProcessIdentity {
    let pid = std::process::id();
    ClaimProcessIdentity {
        pid,
        process_start_time: process_start_time(pid).ok(),
    }
}

pub(crate) fn claim_process_liveness(identity: &ClaimProcessIdentity) -> ClaimProcessLiveness {
    let Some(expected_start_time) = identity.process_start_time.as_deref() else {
        return ClaimProcessLiveness::Unknown;
    };
    match process_start_time(identity.pid) {
        Ok(observed_start_time) if observed_start_time == expected_start_time => {
            ClaimProcessLiveness::Live
        }
        Ok(_) => ClaimProcessLiveness::Interrupted,
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            ClaimProcessLiveness::Interrupted
        }
        Err(_) => ClaimProcessLiveness::Unknown,
    }
}

#[cfg(all(test, target_os = "linux"))]
std::thread_local! {
    static CLAIM_TEST_EXCHANGE_ERRNO: std::cell::Cell<Option<i32>> =
        const { std::cell::Cell::new(None) };
    static CLAIM_TEST_FALLBACK_CRASH: std::cell::Cell<Option<ClaimFallbackCrashPoint>> =
        const { std::cell::Cell::new(None) };
}

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
    apply_with_clock_and_hooks(repo, draft, actor, now, |_| Ok(()), |_| Ok(()))
}

fn apply_with_clock_and_hooks<D, P>(
    repo: &Path,
    draft: &Path,
    actor: &str,
    now: &LiveClock,
    mut after_draft_bind: D,
    mut before_publish: P,
) -> Result<LiveClaimApplyReport>
where
    D: FnMut(&Path) -> Result<()>,
    P: FnMut(&Path) -> Result<()>,
{
    let claims_path = claims_dir(repo);
    let root = open_claims_root(&claims_path)?.context("claim board does not exist")?;
    let lock = acquire_claim_board_lock(&root)?;
    prepare_claim_board(&root, &lock)?;
    let bound_draft = BoundClaimDraft::bind(draft, &root)?;
    after_draft_bind(bound_draft.path())?;
    let (mut claims, initial_board) = load_stable_claim_board(&root, &lock)?;
    ensure_claim_board_allows_apply(&claims)?;
    bound_draft.verify(&root, &initial_board)?;

    let content = std::str::from_utf8(&bound_draft.generation.bytes)
        .context("claim draft is not valid UTF-8")?;
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
    validate_initial_claim_draft(content, &draft_claim, actor, now)?;
    if initial_board.entries.contains_key(&file_name) {
        bail!(
            "claim apply is create-only; release or hand off the existing claim and use a new claim id"
        );
    }
    let audit_entry = format!(
        "`{}` - `{actor}` created claim from bounded draft",
        now.raw()
    );
    let updated_limit = usize::try_from(MAX_CLAIM_BYTES)
        .unwrap_or(usize::MAX)
        .saturating_sub(CLAIM_RELEASE_HEADROOM_BYTES);
    let updated = update_claim_content(
        content,
        &draft_claim,
        now,
        Some("active"),
        &audit_entry,
        updated_limit,
    )?;
    let updated_claim = parse_claim_file(file.clone(), &updated);
    ensure_claim_valid(&updated_claim)?;
    claims.push(updated_claim);
    ensure_claim_board_allows_apply(&claims)?;
    let final_claims = atomic_publish_claim(
        &root,
        &lock,
        &initial_board,
        &file_name,
        updated.as_bytes(),
        &mut before_publish,
    )?;
    ensure_claim_board_allows_apply(&final_claims)?;
    let final_claim = final_claims
        .into_iter()
        .find(|claim| claim.display_id() == claim_id)
        .context("applied claim disappeared from the stable board")?;
    let summary = summary_from_parsed(&final_claim, now);
    Ok(LiveClaimApplyReport {
        claim_id: claim_id.to_string(),
        file,
        actor: actor.to_string(),
        created: true,
        updated: now.raw().to_string(),
        claim: summary,
    })
}

fn validate_initial_claim_draft(
    content: &str,
    claim: &ParsedClaim,
    actor: &str,
    now: &LiveClock,
) -> Result<()> {
    if claim.owner.as_deref() != Some(actor) {
        bail!("claim apply actor must exactly match the draft owner");
    }
    if claim.status.as_deref() != Some("active") {
        bail!("claim apply accepts only a new claim with initial status active");
    }
    if claim.date.is_some() {
        bail!("claim apply drafts must use explicit Created, Updated, and Heartbeat fields");
    }
    let created = claim
        .created
        .as_deref()
        .context("claim apply draft is missing Created")?;
    let updated = claim
        .updated
        .as_deref()
        .context("claim apply draft is missing Updated")?;
    let heartbeat = claim
        .heartbeat
        .as_deref()
        .context("claim apply draft is missing Heartbeat")?;
    if created != updated || created != heartbeat {
        bail!("claim apply draft timestamps must be one initial generation");
    }
    let created_seconds = parse_timestamp_seconds(created)
        .context("claim apply draft Created timestamp is malformed")?;
    if created != format_epoch_seconds(created_seconds) {
        bail!("claim apply draft Created timestamp must be canonical UTC seconds");
    }
    if created_seconds > now.epoch_seconds {
        bail!("claim apply draft contains a future timestamp generation");
    }
    if now.epoch_seconds.saturating_sub(created_seconds) > MAX_APPLY_DRAFT_AGE_SECONDS {
        bail!("claim apply draft is too old for create-only publication");
    }
    let mut claim_id_fields = 0usize;
    for line in content.lines() {
        if field_from_line(line.trim()).is_some_and(|(key, _)| key == "claim id") {
            claim_id_fields = claim_id_fields.saturating_add(1);
        }
    }
    let claim_headers = content
        .lines()
        .filter(|line| line.starts_with("# Claim:"))
        .count();
    if claim_id_fields != 1 || claim_headers != 1 {
        bail!("claim apply draft must contain one matching Claim header and Claim ID field");
    }
    if content.lines().any(|line| {
        line.trim()
            .strip_prefix("##")
            .is_some_and(|heading| heading.trim().eq_ignore_ascii_case("audit log"))
    }) {
        bail!("claim apply draft must not replay or replace audit history");
    }
    Ok(())
}

#[derive(Debug)]
struct BoundClaimDraft {
    parent: SafeRoot,
    leaf: OsString,
    path: PathBuf,
    generation: ClaimFileGeneration,
}

impl BoundClaimDraft {
    fn bind(draft: &Path, board_root: &SafeRoot) -> Result<Self> {
        let leaf = draft
            .file_name()
            .context("claim draft path must end in one file name")?
            .to_os_string();
        let leaf_text = leaf
            .to_str()
            .context("claim draft file name must be valid UTF-8")?;
        if leaf_text.is_empty()
            || leaf_text.len() > MAX_DRAFT_LEAF_BYTES
            || leaf_text.chars().any(char::is_control)
        {
            bail!("claim draft file name is invalid or out of bounds");
        }
        let parent_path = draft
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let parent = SafeRoot::open_existing(parent_path)
            .map_err(|_| anyhow::anyhow!("claim draft parent is unsafe or inaccessible"))?;
        let parent_text = parent
            .path()
            .to_str()
            .context("claim draft parent must be valid UTF-8")?;
        if parent_text.len() > MAX_DRAFT_PARENT_BYTES || parent_text.chars().any(char::is_control) {
            bail!("claim draft parent is invalid or out of bounds");
        }
        verify_draft_parent_outside_board(&parent, board_root)?;
        let generation = read_entry_generation(&parent, &leaf, MAX_CLAIM_BYTES)
            .map_err(|_| anyhow::anyhow!("claim draft is not a bounded no-follow regular file"))?;
        parent
            .verify()
            .map_err(|_| anyhow::anyhow!("claim draft parent binding changed"))?;
        board_root
            .verify()
            .map_err(|_| anyhow::anyhow!("claim board root binding changed"))?;
        let path = parent.direct_child(&leaf)?;
        Ok(Self {
            parent,
            leaf,
            path,
            generation,
        })
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn verify(&self, board_root: &SafeRoot, board: &ClaimBoardSnapshot) -> Result<()> {
        verify_draft_parent_outside_board(&self.parent, board_root)?;
        let observed = read_entry_generation(&self.parent, &self.leaf, MAX_CLAIM_BYTES)
            .map_err(|_| anyhow::anyhow!("claim draft binding changed"))?;
        if observed != self.generation {
            bail!("claim draft identity or content changed after binding");
        }
        if board
            .entries
            .values()
            .any(|generation| generation.identity == self.generation.identity)
        {
            bail!("claim draft must not alias or hard-link a live claim board entry");
        }
        self.parent
            .verify()
            .map_err(|_| anyhow::anyhow!("claim draft parent binding changed"))?;
        board_root
            .verify()
            .map_err(|_| anyhow::anyhow!("claim board root binding changed"))?;
        Ok(())
    }
}

fn verify_draft_parent_outside_board(parent: &SafeRoot, board_root: &SafeRoot) -> Result<()> {
    parent
        .verify()
        .map_err(|_| anyhow::anyhow!("claim draft parent binding changed"))?;
    board_root
        .verify()
        .map_err(|_| anyhow::anyhow!("claim board root binding changed"))?;
    if parent.identity() == board_root.identity() || parent.path().starts_with(board_root.path()) {
        bail!("claim drafts must remain outside the live claim board and its aliases");
    }
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
    #[cfg(target_os = "linux")]
    atomic_publish_claim_linux(
        root,
        lock,
        initial_board,
        file_name,
        updated,
        before_first_fence,
    )
    .context("claim atomic mutation was refused")?;
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (lock, initial_board, file_name, updated, before_first_fence);
        bail!("claim atomic mutation requires Linux renameat2 CAS support");
    }

    let (final_claims, _) = load_stable_claim_board(root, lock)?;
    Ok(final_claims)
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct StagedClaimFile {
    name: OsString,
    generation: ClaimFileGeneration,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, PartialEq, Eq)]
struct ClaimFallbackTransaction {
    name: OsString,
    target_checksum: String,
    old_checksum: String,
    new_checksum: String,
    other_board_checksum: String,
    old_identity: FileIdentity,
    new_identity: FileIdentity,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClaimFallbackCrashPoint {
    AfterOldDisplacement,
    AfterNewPublication,
}

#[cfg(all(test, target_os = "linux"))]
#[derive(Debug)]
struct InjectedClaimFallbackCrash(ClaimFallbackCrashPoint);

#[cfg(all(test, target_os = "linux"))]
impl std::fmt::Display for InjectedClaimFallbackCrash {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "injected claim fallback crash at {:?}", self.0)
    }
}

#[cfg(all(test, target_os = "linux"))]
impl std::error::Error for InjectedClaimFallbackCrash {}

#[cfg(target_os = "linux")]
fn atomic_publish_claim_linux<F>(
    root: &SafeRoot,
    lock: &KernelStateLock,
    initial_board: &ClaimBoardSnapshot,
    file_name: &OsStr,
    updated: &[u8],
    before_publish: &mut F,
) -> Result<()>
where
    F: FnMut(&Path) -> Result<()>,
{
    let directory = open_claim_board_directory(root)?;
    let staged = stage_claim_file(&directory, file_name, updated)?;
    let claim_path = root.direct_child(file_name)?;
    let publish_result = (|| -> Result<()> {
        lock.verify_direct_binding(root)
            .map_err(|_| anyhow::anyhow!("claim board mutation lock binding changed"))?;
        root.verify()
            .map_err(|_| anyhow::anyhow!("claim board root binding changed"))?;
        let observed = capture_claim_board_snapshot(root, Some((file_name, updated)))?;
        if &observed != initial_board {
            bail!("claim board generation changed before atomic replacement");
        }
        before_publish(&claim_path)?;
        lock.verify_direct_binding(root)
            .map_err(|_| anyhow::anyhow!("claim board mutation lock binding changed"))?;
        root.verify()
            .map_err(|_| anyhow::anyhow!("claim board root binding changed"))?;

        if let Some(initial_target) = initial_board.entries.get(file_name) {
            publish_existing_claim_exchange(
                root,
                &directory,
                initial_board,
                file_name,
                updated,
                initial_target,
                &staged,
            )
        } else {
            publish_new_claim_noreplace(
                root,
                &directory,
                initial_board,
                file_name,
                updated,
                &staged,
            )
        }
    })();
    if let Err(error) = publish_result {
        if is_injected_claim_fallback_crash(&error) {
            return Err(error);
        }
        if let Err(cleanup_error) =
            cleanup_claim_temp_if_exact(root, &directory, &staged.name, &staged.generation)
        {
            return Err(error.context(format!(
                "claim publication cleanup also failed: {cleanup_error:#}"
            )));
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_new_claim_noreplace(
    root: &SafeRoot,
    directory: &File,
    initial_board: &ClaimBoardSnapshot,
    file_name: &OsStr,
    updated: &[u8],
    staged: &StagedClaimFile,
) -> Result<()> {
    rename_claim_entry(directory, &staged.name, file_name, libc::RENAME_NOREPLACE)
        .context("create-only claim target appeared before publication")?;
    let validation = (|| -> Result<()> {
        directory
            .sync_all()
            .context("failed to flush create-only claim publication")?;
        let observed = capture_claim_board_snapshot(root, None)?;
        verify_claim_board_replacement(initial_board, &observed, file_name, updated)
    })();
    if let Err(error) = validation {
        rollback_created_claim(root, directory, file_name, staged)?;
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn publish_existing_claim_exchange(
    root: &SafeRoot,
    directory: &File,
    initial_board: &ClaimBoardSnapshot,
    file_name: &OsStr,
    updated: &[u8],
    initial_target: &ClaimFileGeneration,
    staged: &StagedClaimFile,
) -> Result<()> {
    match rename_claim_entry(directory, &staged.name, file_name, libc::RENAME_EXCHANGE) {
        Ok(()) => {}
        Err(error) if rename_exchange_is_unsupported(&error) => {
            return publish_existing_claim_noreplace_fallback(
                root,
                directory,
                initial_board,
                file_name,
                updated,
                initial_target,
                staged,
            )
            .context("claim no-replace fallback failed after exchange was unsupported");
        }
        Err(error) => return Err(error).context("claim compare-and-swap exchange failed"),
    }
    let validation = (|| -> Result<()> {
        directory
            .sync_all()
            .context("failed to flush claim compare-and-swap exchange")?;
        let exchanged_old = read_entry_generation(root, &staged.name, MAX_CLAIM_BYTES)
            .context("exchanged claim generation is unsafe")?;
        if exchanged_old != *initial_target {
            bail!("claim pathname or in-place generation changed before CAS exchange");
        }
        let observed =
            capture_claim_board_snapshot(root, Some((file_name, initial_target.bytes.as_slice())))?;
        verify_claim_board_replacement(initial_board, &observed, file_name, updated)
    })();
    if let Err(error) = validation {
        rename_claim_entry(directory, &staged.name, file_name, libc::RENAME_EXCHANGE)
            .context("failed to roll back refused claim compare-and-swap exchange")?;
        directory
            .sync_all()
            .context("failed to flush refused claim CAS rollback")?;
        return Err(error);
    }
    cleanup_claim_temp_if_exact(root, directory, &staged.name, initial_target)?;
    let observed = capture_claim_board_snapshot(root, None)?;
    verify_claim_board_replacement(initial_board, &observed, file_name, updated)
}

#[cfg(target_os = "linux")]
fn publish_existing_claim_noreplace_fallback(
    root: &SafeRoot,
    directory: &File,
    initial_board: &ClaimBoardSnapshot,
    file_name: &OsStr,
    updated: &[u8],
    initial_target: &ClaimFileGeneration,
    staged: &StagedClaimFile,
) -> Result<()> {
    let transaction =
        ClaimFallbackTransaction::new(file_name, initial_board, initial_target, staged)?;
    rename_claim_entry(
        directory,
        file_name,
        &transaction.name,
        libc::RENAME_NOREPLACE,
    )
    .context("failed to displace old claim generation for no-replace publication")?;
    directory
        .sync_all()
        .context("failed to flush old claim displacement")?;
    maybe_inject_claim_fallback_crash(ClaimFallbackCrashPoint::AfterOldDisplacement)?;

    let transaction_result = (|| -> Result<()> {
        let displaced = read_entry_generation(root, &transaction.name, MAX_CLAIM_BYTES)
            .context("displaced old claim generation is unsafe")?;
        transaction.verify_old_generation(&displaced)?;
        let displaced_board = capture_claim_board_snapshot_excluding(
            root,
            &[
                (&transaction.name, &displaced),
                (&staged.name, &staged.generation),
            ],
        )?;
        verify_other_claim_board_entries(initial_board, &displaced_board, file_name)?;
        transaction.verify_other_board(&displaced_board, file_name)?;
        if displaced_board.entries.contains_key(file_name) {
            bail!("claim target reappeared after old-generation displacement");
        }

        rename_claim_entry(directory, &staged.name, file_name, libc::RENAME_NOREPLACE)
            .context("failed to publish staged claim through vacant target")?;
        directory
            .sync_all()
            .context("failed to flush no-replace claim publication")?;
        maybe_inject_claim_fallback_crash(ClaimFallbackCrashPoint::AfterNewPublication)?;

        let published_board =
            capture_claim_board_snapshot_excluding(root, &[(&transaction.name, initial_target)])?;
        verify_claim_board_replacement(initial_board, &published_board, file_name, updated)?;
        transaction.verify_other_board(&published_board, file_name)?;
        let published = published_board
            .entries
            .get(file_name)
            .context("fallback-published claim generation disappeared")?;
        transaction.verify_new_generation(published)?;
        cleanup_claim_temp_if_exact(root, directory, &transaction.name, initial_target)?;
        let finalized = capture_claim_board_snapshot(root, None)?;
        verify_claim_board_replacement(initial_board, &finalized, file_name, updated)
    })();

    if let Err(error) = transaction_result {
        if is_injected_claim_fallback_crash(&error) {
            return Err(error);
        }
        if let Err(rollback_error) = rollback_claim_fallback_transaction(
            root,
            directory,
            file_name,
            initial_target,
            staged,
            &transaction,
        ) {
            return Err(error.context(format!(
                "claim no-replace fallback rollback also failed; transaction residue was preserved: {rollback_error:#}"
            )));
        }
        return Err(error);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn rollback_claim_fallback_transaction(
    root: &SafeRoot,
    directory: &File,
    file_name: &OsStr,
    initial_target: &ClaimFileGeneration,
    staged: &StagedClaimFile,
    transaction: &ClaimFallbackTransaction,
) -> Result<()> {
    let residue = read_optional_entry_generation(root, &transaction.name, MAX_CLAIM_BYTES)?;
    let target = read_optional_entry_generation(root, file_name, MAX_CLAIM_BYTES)?;
    let staged_generation = read_optional_entry_generation(root, &staged.name, MAX_CLAIM_BYTES)?;

    let residue = residue.context(
        "fallback rollback cannot prove the displaced old generation; preserving current state",
    )?;
    transaction.verify_old_generation(&residue)?;
    if residue != *initial_target {
        bail!("fallback rollback old generation changed; preserving current state");
    }

    match (target, staged_generation) {
        (None, Some(observed_staged)) if observed_staged == staged.generation => {
            rename_claim_entry(
                directory,
                &transaction.name,
                file_name,
                libc::RENAME_NOREPLACE,
            )
            .context("failed to restore old claim generation")?;
            directory
                .sync_all()
                .context("failed to flush old claim restoration")?;
            cleanup_claim_temp_if_exact(
                root,
                directory,
                &staged.name,
                &staged.generation,
            )
        }
        (None, None) => {
            rename_claim_entry(
                directory,
                &transaction.name,
                file_name,
                libc::RENAME_NOREPLACE,
            )
            .context("failed to restore old claim generation")?;
            directory
                .sync_all()
                .context("failed to flush old claim restoration")
        }
        (Some(observed_target), None) if observed_target == staged.generation => {
            rename_claim_entry(
                directory,
                file_name,
                &staged.name,
                libc::RENAME_NOREPLACE,
            )
            .context("failed to retract fallback-published claim generation")?;
            directory
                .sync_all()
                .context("failed to flush fallback publication retraction")?;
            rename_claim_entry(
                directory,
                &transaction.name,
                file_name,
                libc::RENAME_NOREPLACE,
            )
            .context("failed to restore old claim generation after retraction")?;
            directory
                .sync_all()
                .context("failed to flush old claim restoration after retraction")?;
            cleanup_claim_temp_if_exact(
                root,
                directory,
                &staged.name,
                &staged.generation,
            )
        }
        _ => bail!(
            "fallback rollback found an unexpected or ambiguous transaction state; preserving it for inspection"
        ),
    }
}

#[cfg(target_os = "linux")]
impl ClaimFallbackTransaction {
    fn new(
        file_name: &OsStr,
        initial_board: &ClaimBoardSnapshot,
        initial_target: &ClaimFileGeneration,
        staged: &StagedClaimFile,
    ) -> Result<Self> {
        let target_checksum = compact_claim_checksum(file_name.as_bytes());
        let old_checksum = compact_claim_checksum(&initial_target.bytes);
        let new_checksum = compact_claim_checksum(&staged.generation.bytes);
        let other_board_checksum = claim_board_other_checksum(initial_board, file_name);
        let name = OsString::from(format!(
            "{CLAIM_FALLBACK_RESIDUE_PREFIX}{target_checksum}.{old_checksum}.{new_checksum}.{other_board_checksum}.{:016x}.{:016x}.{:016x}.{:016x}{CLAIM_FALLBACK_RESIDUE_SUFFIX}",
            initial_target.identity.device,
            initial_target.identity.file,
            staged.generation.identity.device,
            staged.generation.identity.file,
        ));
        if name.as_bytes().len() > MAX_DRAFT_LEAF_BYTES {
            bail!("claim fallback transaction name exceeds the bounded leaf length");
        }
        Ok(Self {
            name,
            target_checksum,
            old_checksum,
            new_checksum,
            other_board_checksum,
            old_identity: initial_target.identity.clone(),
            new_identity: staged.generation.identity.clone(),
        })
    }

    fn parse(name: &OsStr) -> Result<Option<Self>> {
        let Some(text) = name.to_str() else {
            return Ok(None);
        };
        let Some(body) = text
            .strip_prefix(CLAIM_FALLBACK_RESIDUE_PREFIX)
            .and_then(|value| value.strip_suffix(CLAIM_FALLBACK_RESIDUE_SUFFIX))
        else {
            return Ok(None);
        };
        let fields = body.split('.').collect::<Vec<_>>();
        let [target_checksum, old_checksum, new_checksum, other_board_checksum, old_device, old_file, new_device, new_file] =
            fields.as_slice()
        else {
            bail!("claim fallback transaction residue name is malformed");
        };
        for checksum in [
            target_checksum,
            old_checksum,
            new_checksum,
            other_board_checksum,
        ] {
            if !is_compact_claim_checksum(checksum) {
                bail!("claim fallback transaction checksum is malformed");
            }
        }
        Ok(Some(Self {
            name: name.to_os_string(),
            target_checksum: (*target_checksum).to_string(),
            old_checksum: (*old_checksum).to_string(),
            new_checksum: (*new_checksum).to_string(),
            other_board_checksum: (*other_board_checksum).to_string(),
            old_identity: FileIdentity {
                device: parse_fixed_lower_hex_u64(old_device)?,
                file: parse_fixed_lower_hex_u64(old_file)?,
            },
            new_identity: FileIdentity {
                device: parse_fixed_lower_hex_u64(new_device)?,
                file: parse_fixed_lower_hex_u64(new_file)?,
            },
        }))
    }

    fn verify_old_generation(&self, generation: &ClaimFileGeneration) -> Result<()> {
        if generation.identity != self.old_identity
            || compact_claim_checksum(&generation.bytes) != self.old_checksum
        {
            bail!("claim fallback old-generation residue was changed or rebound");
        }
        Ok(())
    }

    fn verify_new_generation(&self, generation: &ClaimFileGeneration) -> Result<()> {
        if generation.identity != self.new_identity
            || compact_claim_checksum(&generation.bytes) != self.new_checksum
        {
            bail!("claim fallback new generation was changed or rebound");
        }
        Ok(())
    }

    fn verify_other_board(&self, board: &ClaimBoardSnapshot, target: &OsStr) -> Result<()> {
        if claim_board_other_checksum(board, target) != self.other_board_checksum {
            bail!("another claim board entry changed during no-replace transaction");
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
fn compact_claim_checksum(bytes: &[u8]) -> String {
    sha256_hex(bytes).chars().take(32).collect()
}

#[cfg(target_os = "linux")]
fn is_compact_claim_checksum(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(target_os = "linux")]
fn parse_fixed_lower_hex_u64(value: &str) -> Result<u64> {
    if !is_fixed_lower_hex(value) {
        bail!("claim fallback transaction identity is malformed");
    }
    u64::from_str_radix(value, 16).context("claim fallback transaction identity is invalid")
}

#[cfg(target_os = "linux")]
fn claim_board_other_checksum(snapshot: &ClaimBoardSnapshot, target: &OsStr) -> String {
    let mut encoded = Vec::new();
    for (name, generation) in &snapshot.entries {
        if name == target {
            continue;
        }
        encoded.extend_from_slice(name.as_bytes());
        encoded.push(0);
        encoded.extend_from_slice(format!("{:016x}", generation.identity.device).as_bytes());
        encoded.push(0);
        encoded.extend_from_slice(format!("{:016x}", generation.identity.file).as_bytes());
        encoded.push(0);
        encoded.extend_from_slice(compact_claim_checksum(&generation.bytes).as_bytes());
        encoded.push(0xff);
    }
    compact_claim_checksum(&encoded)
}

#[cfg(target_os = "linux")]
fn verify_other_claim_board_entries(
    before: &ClaimBoardSnapshot,
    after: &ClaimBoardSnapshot,
    target: &OsStr,
) -> Result<()> {
    let before_other = before
        .entries
        .iter()
        .filter(|(name, _)| name.as_os_str() != target)
        .collect::<Vec<_>>();
    let after_other = after
        .entries
        .iter()
        .filter(|(name, _)| name.as_os_str() != target)
        .collect::<Vec<_>>();
    if before_other != after_other {
        bail!("another claim board entry changed during no-replace transaction");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn read_optional_entry_generation(
    root: &SafeRoot,
    file_name: &OsStr,
    max_bytes: u64,
) -> Result<Option<ClaimFileGeneration>> {
    if !root.direct_child_exists(file_name)? {
        return Ok(None);
    }
    read_entry_generation(root, file_name, max_bytes).map(Some)
}

#[cfg(target_os = "linux")]
fn rename_exchange_is_unsupported(error: &anyhow::Error) -> bool {
    error.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .and_then(std::io::Error::raw_os_error)
            .is_some_and(|code| {
                code == libc::EINVAL || code == libc::EOPNOTSUPP || code == libc::ENOTSUP
            })
    })
}

#[cfg(all(test, target_os = "linux"))]
fn maybe_inject_claim_fallback_crash(point: ClaimFallbackCrashPoint) -> Result<()> {
    let injected = CLAIM_TEST_FALLBACK_CRASH.with(|value| {
        if value.get() == Some(point) {
            value.set(None);
            true
        } else {
            false
        }
    });
    if injected {
        return Err(anyhow::Error::new(InjectedClaimFallbackCrash(point)));
    }
    Ok(())
}

#[cfg(all(not(test), target_os = "linux"))]
fn maybe_inject_claim_fallback_crash(_point: ClaimFallbackCrashPoint) -> Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
fn is_injected_claim_fallback_crash(error: &anyhow::Error) -> bool {
    error
        .chain()
        .any(|cause| cause.downcast_ref::<InjectedClaimFallbackCrash>().is_some())
}

#[cfg(all(not(test), target_os = "linux"))]
fn is_injected_claim_fallback_crash(_error: &anyhow::Error) -> bool {
    false
}

#[cfg(target_os = "linux")]
fn rollback_created_claim(
    root: &SafeRoot,
    directory: &File,
    file_name: &OsStr,
    staged: &StagedClaimFile,
) -> Result<()> {
    let observed = read_entry_generation(root, file_name, MAX_CLAIM_BYTES)
        .context("created claim changed before rollback")?;
    if observed != staged.generation {
        bail!("created claim changed before rollback; preserving it for inspection");
    }
    rename_claim_entry(directory, file_name, &staged.name, libc::RENAME_NOREPLACE)
        .context("failed to roll back create-only claim publication")?;
    directory
        .sync_all()
        .context("failed to flush create-only claim rollback")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn open_claim_board_directory(root: &SafeRoot) -> Result<File> {
    root.verify()
        .map_err(|_| anyhow::anyhow!("claim board root binding changed"))?;
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let directory = options
        .open(root.path())
        .context("failed to open claim board directory for CAS")?;
    let metadata = directory
        .metadata()
        .context("failed to inspect claim board CAS directory")?;
    let identity = FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    };
    if !metadata.is_dir() || &identity != root.identity() {
        bail!("claim board CAS directory identity changed");
    }
    root.verify()
        .map_err(|_| anyhow::anyhow!("claim board root binding changed"))?;
    Ok(directory)
}

#[cfg(target_os = "linux")]
fn stage_claim_file(
    directory: &File,
    file_name: &OsStr,
    contents: &[u8],
) -> Result<StagedClaimFile> {
    let target = file_name
        .to_str()
        .context("claim target name is not valid UTF-8")?;
    for _ in 0..128 {
        let counter = CLAIM_TEMP_COUNTER.fetch_add(1, AtomicOrdering::Relaxed);
        let epoch_nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_nanos())
            .unwrap_or_default();
        let nonce = u64::try_from(epoch_nanos & u128::from(u64::MAX))
            .unwrap_or_default()
            .wrapping_add(counter);
        let name = OsString::from(format!(".{target}.{}-{nonce}.tmp", std::process::id()));
        let name_c = claim_c_string(&name)?;
        let fd = unsafe {
            libc::openat(
                directory.as_raw_fd(),
                name_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                0o600,
            )
        };
        if fd < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                continue;
            }
            return Err(error).context("failed to stage claim CAS content");
        }
        let mut file = unsafe { File::from_raw_fd(fd) };
        if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to secure staged claim CAS content");
        }
        file.write_all(contents)
            .context("failed to write staged claim CAS content")?;
        file.sync_all()
            .context("failed to flush staged claim CAS content")?;
        let metadata = file
            .metadata()
            .context("failed to inspect staged claim CAS content")?;
        if !metadata.is_file()
            || metadata.nlink() != 1
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o777 != 0o600
        {
            bail!("staged claim CAS metadata is unsafe");
        }
        let generation = ClaimFileGeneration {
            identity: FileIdentity {
                device: metadata.dev(),
                file: metadata.ino(),
            },
            bytes: contents.to_vec(),
        };
        drop(file);
        directory
            .sync_all()
            .context("failed to flush staged claim CAS directory entry")?;
        return Ok(StagedClaimFile { name, generation });
    }
    bail!("failed to reserve a bounded claim CAS temporary file")
}

#[cfg(target_os = "linux")]
fn cleanup_claim_temp_if_exact(
    root: &SafeRoot,
    directory: &File,
    name: &OsStr,
    expected: &ClaimFileGeneration,
) -> Result<()> {
    if !root.direct_child_exists(name)? {
        return Ok(());
    }
    let observed = read_entry_generation(root, name, MAX_CLAIM_BYTES)
        .context("claim CAS temporary generation is unsafe")?;
    if &observed != expected {
        bail!("claim CAS temporary generation changed; preserving it for inspection");
    }
    let name_c = claim_c_string(name)?;
    if unsafe { libc::unlinkat(directory.as_raw_fd(), name_c.as_ptr(), 0) } != 0 {
        return Err(std::io::Error::last_os_error())
            .context("failed to remove verified claim CAS temporary generation");
    }
    directory
        .sync_all()
        .context("failed to flush claim CAS temporary cleanup")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn rename_claim_entry(directory: &File, source: &OsStr, target: &OsStr, flags: u32) -> Result<()> {
    #[cfg(test)]
    if flags == libc::RENAME_EXCHANGE {
        if let Some(errno) = CLAIM_TEST_EXCHANGE_ERRNO.with(std::cell::Cell::get) {
            return Err(std::io::Error::from_raw_os_error(errno))
                .context("claim renameat2 CAS was refused");
        }
    }
    let source = claim_c_string(source)?;
    let target = claim_c_string(target)?;
    if unsafe {
        libc::renameat2(
            directory.as_raw_fd(),
            source.as_ptr(),
            directory.as_raw_fd(),
            target.as_ptr(),
            flags,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("claim renameat2 CAS was refused");
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn claim_c_string(value: &OsStr) -> Result<std::ffi::CString> {
    std::ffi::CString::new(value.as_bytes()).context("claim entry contains a NUL byte")
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
    #[cfg(target_os = "linux")]
    recover_claim_fallback_transactions(root, lock)?;
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

#[cfg(target_os = "linux")]
fn capture_claim_board_snapshot_excluding(
    root: &SafeRoot,
    permitted_artifacts: &[(&OsStr, &ClaimFileGeneration)],
) -> Result<ClaimBoardSnapshot> {
    let names = raw_claim_entry_names(
        root,
        MAX_CLAIM_ENTRIES.saturating_add(permitted_artifacts.len()),
    )?;
    let mut observed_artifacts = BTreeSet::new();
    let mut entries = BTreeMap::new();
    for file_name in names {
        if let Some((_, expected)) = permitted_artifacts
            .iter()
            .find(|(name, _)| *name == file_name.as_os_str())
        {
            if !observed_artifacts.insert(file_name.clone()) {
                bail!("claim transaction artifact name is duplicated");
            }
            let observed = read_entry_generation(root, &file_name, MAX_CLAIM_BYTES)
                .context("claim transaction artifact is unsafe")?;
            if &observed != *expected {
                bail!("claim transaction artifact changed during bounded inspection");
            }
            continue;
        }
        let max_bytes = if file_name == OsStr::new(BOARD_LOCK_FILE) {
            0
        } else {
            MAX_CLAIM_BYTES
        };
        if file_name != OsStr::new(TEMPLATE_FILE) && file_name != OsStr::new(BOARD_LOCK_FILE) {
            let text = file_name
                .to_str()
                .context("claim board contains a non-UTF-8 entry name")?;
            validate_claim_file_name(text)?;
        }
        let generation = read_entry_generation(root, &file_name, max_bytes)
            .context("claim board entry is not a bounded regular file")?;
        entries.insert(file_name, generation);
    }
    if observed_artifacts.len() != permitted_artifacts.len() {
        bail!("claim transaction artifact is missing or ambiguous");
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

#[cfg(target_os = "linux")]
fn recover_claim_fallback_transactions(root: &SafeRoot, lock: &KernelStateLock) -> Result<()> {
    let names = raw_claim_entry_names(
        root,
        MAX_CLAIM_ENTRIES.saturating_add(MAX_CLAIM_RESIDUE_ENTRIES),
    )?;
    let mut transactions = Vec::new();
    for name in &names {
        let Some(text) = name.to_str() else {
            continue;
        };
        if !text.starts_with(CLAIM_FALLBACK_RESIDUE_PREFIX) {
            continue;
        }
        let transaction = ClaimFallbackTransaction::parse(name)?
            .context("claim fallback transaction residue is malformed")?;
        transactions.push(transaction);
    }
    if transactions.is_empty() {
        return Ok(());
    }
    if transactions.len() != 1 {
        bail!(
            "claim board contains duplicate or ambiguous fallback transaction residue; manual inspection is required"
        );
    }
    let transaction = transactions
        .pop()
        .context("claim fallback transaction residue disappeared from recovery inventory")?;
    lock.verify_direct_binding(root)
        .map_err(|_| anyhow::anyhow!("claim board lock binding changed during recovery"))?;
    root.verify()
        .map_err(|_| anyhow::anyhow!("claim board root binding changed during recovery"))?;
    let directory = open_claim_board_directory(root)?;
    let old_generation = read_entry_generation(root, &transaction.name, MAX_CLAIM_BYTES)
        .context("claim fallback transaction residue is unsafe")?;
    transaction.verify_old_generation(&old_generation)?;
    let old_content = std::str::from_utf8(&old_generation.bytes)
        .context("claim fallback old generation is not valid UTF-8")?;
    let preliminary = parse_claim_file(
        PathBuf::from(CLAIMS_DIR).join("fallback-recovery.md"),
        old_content,
    );
    let claim_id = preliminary
        .claim_id
        .as_deref()
        .context("claim fallback old generation has no claim id")?;
    validate_claim_id(claim_id, "claim fallback old-generation id")?;
    let target = OsString::from(format!("{claim_id}.md"));
    if compact_claim_checksum(target.as_bytes()) != transaction.target_checksum {
        bail!("claim fallback transaction target binding does not match its old generation");
    }
    let old_claim = parse_claim_file(PathBuf::from(CLAIMS_DIR).join(&target), old_content);
    ensure_claim_valid(&old_claim).context("claim fallback old generation is not a valid claim")?;

    let mut staged = None;
    for name in &names {
        if is_canonical_claim_temp_for(name, &target) {
            if staged.is_some() {
                bail!(
                    "claim fallback transaction has duplicate staged generations; preserving it for inspection"
                );
            }
            let generation = read_entry_generation(root, name, MAX_CLAIM_BYTES)
                .context("claim fallback staged generation is unsafe")?;
            transaction.verify_new_generation(&generation)?;
            staged = Some((name.clone(), generation));
        }
    }
    let mut permitted = vec![(transaction.name.as_os_str(), &old_generation)];
    if let Some((name, generation)) = &staged {
        permitted.push((name.as_os_str(), generation));
    }
    let board = capture_claim_board_snapshot_excluding(root, &permitted)?;
    transaction.verify_other_board(&board, &target)?;
    let target_generation = board.entries.get(&target).cloned();
    lock.verify_direct_binding(root)
        .map_err(|_| anyhow::anyhow!("claim board lock binding changed during recovery"))?;
    root.verify()
        .map_err(|_| anyhow::anyhow!("claim board root binding changed during recovery"))?;

    match (target_generation, staged) {
        (None, staged) => {
            rename_claim_entry(
                &directory,
                &transaction.name,
                &target,
                libc::RENAME_NOREPLACE,
            )
            .context("failed to recover displaced old claim generation")?;
            directory
                .sync_all()
                .context("failed to flush recovered old claim generation")?;
            let restored = read_entry_generation(root, &target, MAX_CLAIM_BYTES)
                .context("recovered old claim generation is unsafe")?;
            if restored != old_generation {
                bail!("recovered old claim generation changed unexpectedly");
            }
            if let Some((staged_name, staged_generation)) = staged {
                cleanup_claim_temp_if_exact(
                    root,
                    &directory,
                    &staged_name,
                    &staged_generation,
                )?;
            }
        }
        (Some(published), None) => {
            transaction.verify_new_generation(&published)?;
            let rebound = read_entry_generation(root, &target, MAX_CLAIM_BYTES)
                .context("fallback-published claim changed before recovery finalization")?;
            if rebound != published {
                bail!(
                    "fallback-published claim changed before recovery finalization; preserving residue"
                );
            }
            cleanup_claim_temp_if_exact(
                root,
                &directory,
                &transaction.name,
                &old_generation,
            )?;
            let finalized = read_entry_generation(root, &target, MAX_CLAIM_BYTES)
                .context("fallback-published claim changed after recovery finalization")?;
            transaction.verify_new_generation(&finalized)?;
        }
        _ => bail!(
            "claim fallback transaction state is unexpected or ambiguous; preserving it for manual inspection"
        ),
    }
    lock.verify_direct_binding(root)
        .map_err(|_| anyhow::anyhow!("claim board lock binding changed after recovery"))?;
    root.verify()
        .map_err(|_| anyhow::anyhow!("claim board root binding changed after recovery"))?;
    Ok(())
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
    for claim in claims {
        ensure_claim_has_no_errors(claim, "claim board entry")?;
    }
    if let Some((left, right)) = first_duplicate_claim_pair(claims, |_, _| true) {
        bail!(
            "claim board entries `{}` and `{}` have duplicate `claim_id` fields",
            left.file.display(),
            right.file.display()
        );
    }
    if let Some((left, right)) = first_overlapping_active_claim_pair(claims) {
        bail!(
            "claim board entries `{}` and `{}` have overlapping `owned_files` fields",
            left.file.display(),
            right.file.display()
        );
    }
    Ok(())
}

fn ensure_claim_board_allows_apply(claims: &[ParsedClaim]) -> Result<()> {
    for claim in claims {
        if let Some(issue) = claim
            .issues
            .iter()
            .find(|issue| issue.severity == "error" && issue.field == "status")
        {
            bail!(
                "claim apply board entry `{}` has an invalid `{}` field",
                claim.file.display(),
                issue.field
            );
        }
        if !claim_is_provably_non_conflicting(claim) {
            ensure_claim_has_no_errors(claim, "claim apply board entry")?;
        }
    }
    if let Some((left, right)) = first_duplicate_claim_pair(claims, |left, right| {
        !claim_is_provably_non_conflicting(left) || !claim_is_provably_non_conflicting(right)
    }) {
        bail!(
            "claim apply board entries `{}` and `{}` have duplicate `claim_id` fields",
            left.file.display(),
            right.file.display()
        );
    }
    if let Some((left, right)) = first_overlapping_active_claim_pair(claims) {
        bail!(
            "claim apply board entries `{}` and `{}` have overlapping `owned_files` fields",
            left.file.display(),
            right.file.display()
        );
    }
    Ok(())
}

fn claim_can_conflict(claim: &ParsedClaim) -> bool {
    matches!(claim.status.as_deref(), Some("active" | "blocked"))
}

fn claim_is_provably_non_conflicting(claim: &ParsedClaim) -> bool {
    matches!(
        claim.status.as_deref(),
        Some("ready-for-review" | "handoff" | "done")
    )
}

fn ensure_claim_has_no_errors(claim: &ParsedClaim, context: &str) -> Result<()> {
    if let Some(issue) = claim.issues.iter().find(|issue| issue.severity == "error") {
        bail!(
            "{context} `{}` has an invalid `{}` field",
            claim.file.display(),
            issue.field
        );
    }
    Ok(())
}

fn first_duplicate_claim_pair<'a, F>(
    claims: &'a [ParsedClaim],
    mut blocks: F,
) -> Option<(&'a ParsedClaim, &'a ParsedClaim)>
where
    F: FnMut(&ParsedClaim, &ParsedClaim) -> bool,
{
    for (index, left) in claims.iter().enumerate() {
        for right in claims.iter().skip(index.saturating_add(1)) {
            if left.display_id() == right.display_id() && blocks(left, right) {
                return Some((left, right));
            }
        }
    }
    None
}

fn first_overlapping_active_claim_pair(
    claims: &[ParsedClaim],
) -> Option<(&ParsedClaim, &ParsedClaim)> {
    for (index, left) in claims.iter().enumerate() {
        if !claim_can_conflict(left) {
            continue;
        }
        for right in claims.iter().skip(index.saturating_add(1)) {
            if !claim_can_conflict(right) {
                continue;
            }
            if left.owned_files.iter().any(|left_path| {
                right
                    .owned_files
                    .iter()
                    .any(|right_path| owned_paths_overlap(left_path, right_path))
            }) {
                return Some((left, right));
            }
        }
    }
    None
}

fn overlapping_active_claim_files(claims: &[ParsedClaim]) -> BTreeSet<PathBuf> {
    let mut overlapping = BTreeSet::new();
    for (index, left) in claims.iter().enumerate() {
        if !claim_can_conflict(left) {
            continue;
        }
        for right in claims.iter().skip(index.saturating_add(1)) {
            if !claim_can_conflict(right) {
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
    ensure_claim_has_no_errors(claim, "claim entry")
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

    let is_lock = claim_can_conflict(claim);
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

    #[cfg(target_os = "linux")]
    struct ClaimAtomicTestFaultGuard {
        previous_errno: Option<i32>,
        previous_crash: Option<ClaimFallbackCrashPoint>,
    }

    #[cfg(target_os = "linux")]
    impl ClaimAtomicTestFaultGuard {
        fn install(
            errno: Option<i32>,
            crash: Option<ClaimFallbackCrashPoint>,
        ) -> ClaimAtomicTestFaultGuard {
            let previous_errno = CLAIM_TEST_EXCHANGE_ERRNO.with(|value| value.replace(errno));
            let previous_crash = CLAIM_TEST_FALLBACK_CRASH.with(|value| value.replace(crash));
            ClaimAtomicTestFaultGuard {
                previous_errno,
                previous_crash,
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Drop for ClaimAtomicTestFaultGuard {
        fn drop(&mut self) {
            CLAIM_TEST_EXCHANGE_ERRNO.with(|value| value.set(self.previous_errno));
            CLAIM_TEST_FALLBACK_CRASH.with(|value| value.set(self.previous_crash));
        }
    }

    #[cfg(target_os = "linux")]
    fn fallback_residue_paths(directory: &Path) -> Result<Vec<PathBuf>> {
        let mut paths = std::fs::read_dir(directory)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| {
                path.file_name()
                    .and_then(OsStr::to_str)
                    .is_some_and(|name| name.starts_with(CLAIM_FALLBACK_RESIDUE_PREFIX))
            })
            .collect::<Vec<_>>();
        paths.sort();
        Ok(paths)
    }

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

    fn initial_draft_text(
        claim_id: &str,
        owner: &str,
        status: &str,
        timestamp: &str,
        owned_surface: &str,
    ) -> String {
        format!(
            "# Claim: {claim_id}\n\n- Claim ID: {claim_id}\n- Owner: {owner}\n- Status: {status}\n- Created: {timestamp}\n- Updated: {timestamp}\n- Heartbeat: {timestamp}\n- Stale after minutes: 60\n- Owned files, regions, devices, or services:\n  - {owned_surface}: bounded test surface\n"
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
    fn atomic_mutation_cas_rejects_same_inode_and_replacement_races_for_every_mutator() -> Result<()>
    {
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

        for (claim_id, actor, mutation, mutation_now) in [
            (
                "heartbeat-race",
                "heartbeat-race",
                ClaimMutation::Heartbeat,
                "2026-05-20T00:30:00Z",
            ),
            (
                "release-race",
                "release-race",
                ClaimMutation::OwnerRelease {
                    status: "done",
                    reason: "bounded release race",
                },
                "2026-05-20T00:30:00Z",
            ),
            (
                "override-race",
                "project-owner",
                ClaimMutation::OverrideRelease {
                    reason: "bounded override race",
                },
                "2026-05-20T02:00:00Z",
            ),
        ] {
            let second = tempfile::tempdir()?;
            let path = write_claim(
                second.path(),
                claim_id,
                claim_id,
                "active",
                "2026-05-20T00:00:00Z",
            )?;
            let replacement = claim_text(
                claim_id,
                claim_id,
                "active",
                "2026-05-20T00:02:00Z",
                "src/live_claim.rs",
            );
            let error = mutate_claim(
                second.path(),
                claim_id,
                actor,
                &LiveClock::parse(mutation_now)?,
                mutation,
                |claim_path| {
                    std::fs::remove_file(claim_path)?;
                    std::fs::write(claim_path, &replacement)?;
                    Ok(())
                },
            )
            .expect_err("pathname replacement race must fail");
            assert!(error.to_string().contains("atomic mutation was refused"));
            assert_eq!(std::fs::read_to_string(&path)?, replacement);
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unsupported_exchange_uses_noreplace_fallback_for_every_existing_claim_mutator() -> Result<()>
    {
        for (claim_id, actor, mutation, now, expected_status, expected_audit) in [
            (
                "fallback-heartbeat",
                "fallback-heartbeat",
                ClaimMutation::Heartbeat,
                "2026-05-20T00:30:00Z",
                "active",
                " heartbeat",
            ),
            (
                "fallback-release",
                "fallback-release",
                ClaimMutation::OwnerRelease {
                    status: "done",
                    reason: "bounded fallback release",
                },
                "2026-05-20T00:30:00Z",
                "done",
                "released claim as `done`",
            ),
            (
                "fallback-override",
                "project-owner",
                ClaimMutation::OverrideRelease {
                    reason: "bounded stale fallback override",
                },
                "2026-05-20T02:00:00Z",
                "handoff",
                "override-release",
            ),
        ] {
            let temp = tempfile::tempdir()?;
            let path = write_claim(
                temp.path(),
                claim_id,
                claim_id,
                "active",
                "2026-05-20T00:00:00Z",
            )?;
            let report = {
                let _fault = ClaimAtomicTestFaultGuard::install(Some(libc::EINVAL), None);
                mutate_claim(
                    temp.path(),
                    claim_id,
                    actor,
                    &LiveClock::parse(now)?,
                    mutation,
                    |_| Ok(()),
                )?
            };
            assert_eq!(report.status.as_deref(), Some(expected_status));
            assert!(report.audit_entry.contains(expected_audit));
            assert!(std::fs::read_to_string(path)?.contains(expected_audit));
            assert!(fallback_residue_paths(&claims_dir(temp.path()))?.is_empty());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn non_capability_exchange_error_preserves_cause_and_never_falls_back() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let path = write_claim(
            temp.path(),
            "exchange-eio",
            "exchange-eio",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let original = std::fs::read(&path)?;
        let error = {
            let _fault = ClaimAtomicTestFaultGuard::install(Some(libc::EIO), None);
            heartbeat_with_clock(
                temp.path(),
                "exchange-eio",
                "exchange-eio",
                &LiveClock::parse("2026-05-20T00:30:00Z")?,
            )
            .expect_err("non-capability exchange errors must not enter the fallback")
        };
        let chain = format!("{error:#}");
        assert!(chain.contains("claim compare-and-swap exchange failed"));
        assert!(chain.contains("Input/output error"), "{chain}");
        assert_eq!(std::fs::read(&path)?, original);
        assert!(fallback_residue_paths(&claims_dir(temp.path()))?.is_empty());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn noreplace_fallback_rejects_target_and_other_board_generation_races() -> Result<()> {
        let target_race = tempfile::tempdir()?;
        let target_path = write_claim(
            target_race.path(),
            "fallback-target-race",
            "fallback-target-race",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let root =
            open_claims_root(&claims_dir(target_race.path()))?.context("target race root")?;
        let lock = acquire_claim_board_lock(&root)?;
        prepare_claim_board(&root, &lock)?;
        let (_, initial_board) = load_stable_claim_board(&root, &lock)?;
        let target_name = OsStr::new("fallback-target-race.md");
        let initial_target = initial_board
            .entries
            .get(target_name)
            .context("target race initial generation")?
            .clone();
        let directory = open_claim_board_directory(&root)?;
        let staged = stage_claim_file(&directory, target_name, b"bounded replacement")?;
        std::fs::remove_file(&target_path)?;
        std::fs::write(&target_path, b"racing direct replacement")?;
        let target_error = publish_existing_claim_noreplace_fallback(
            &root,
            &directory,
            &initial_board,
            target_name,
            &staged.generation.bytes,
            &initial_target,
            &staged,
        )
        .expect_err("fallback target CAS race must fail closed");
        assert!(format!("{target_error:#}").contains("old-generation residue was changed"));
        assert!(!target_path.exists());
        assert_eq!(
            fallback_residue_paths(&claims_dir(target_race.path()))?.len(),
            1
        );

        let board_race = tempfile::tempdir()?;
        let first_path = write_claim(
            board_race.path(),
            "fallback-board-first",
            "fallback-board-first",
            "active",
            "2026-05-20T00:00:00Z",
        )?;
        let second_path = write_claim(
            board_race.path(),
            "fallback-board-second",
            "fallback-board-second",
            "done",
            "2026-05-20T00:00:00Z",
        )?;
        let original_first = std::fs::read(&first_path)?;
        let root = open_claims_root(&claims_dir(board_race.path()))?.context("board race root")?;
        let lock = acquire_claim_board_lock(&root)?;
        prepare_claim_board(&root, &lock)?;
        let (_, initial_board) = load_stable_claim_board(&root, &lock)?;
        let target_name = OsStr::new("fallback-board-first.md");
        let initial_target = initial_board
            .entries
            .get(target_name)
            .context("board race initial generation")?
            .clone();
        let directory = open_claim_board_directory(&root)?;
        let staged = stage_claim_file(&directory, target_name, b"bounded replacement")?;
        std::fs::write(
            &second_path,
            claim_text(
                "fallback-board-second",
                "fallback-board-second",
                "done",
                "2026-05-20T00:01:00Z",
                "src/changed.rs",
            ),
        )?;
        let board_error = publish_existing_claim_noreplace_fallback(
            &root,
            &directory,
            &initial_board,
            target_name,
            &staged.generation.bytes,
            &initial_target,
            &staged,
        )
        .expect_err("fallback whole-board CAS race must fail closed");
        assert!(format!("{board_error:#}").contains("another claim board entry changed"));
        assert_eq!(std::fs::read(&first_path)?, original_first);
        assert!(fallback_residue_paths(&claims_dir(board_race.path()))?.is_empty());
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn noreplace_fallback_recovers_crashes_before_and_after_new_publication() -> Result<()> {
        for (claim_id, crash, expected_heartbeats) in [
            (
                "fallback-crash-old",
                ClaimFallbackCrashPoint::AfterOldDisplacement,
                0,
            ),
            (
                "fallback-crash-new",
                ClaimFallbackCrashPoint::AfterNewPublication,
                1,
            ),
        ] {
            let temp = tempfile::tempdir()?;
            let path = write_claim(
                temp.path(),
                claim_id,
                claim_id,
                "active",
                "2026-05-20T00:00:00Z",
            )?;
            let error = {
                let _fault = ClaimAtomicTestFaultGuard::install(Some(libc::EINVAL), Some(crash));
                heartbeat_with_clock(
                    temp.path(),
                    claim_id,
                    claim_id,
                    &LiveClock::parse("2026-05-20T00:30:00Z")?,
                )
                .expect_err("injected fallback crash must interrupt publication")
            };
            assert!(format!("{error:#}").contains("injected claim fallback crash"));
            assert_eq!(fallback_residue_paths(&claims_dir(temp.path()))?.len(), 1);
            assert_eq!(
                status(temp.path(), &LiveClock::parse("2026-05-20T00:31:00Z")?)?.claim_count,
                1
            );
            let recovered = std::fs::read_to_string(&path)?;
            assert_eq!(recovered.matches(" heartbeat").count(), expected_heartbeats);
            assert!(fallback_residue_paths(&claims_dir(temp.path()))?.is_empty());
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn fallback_recovery_preserves_tampered_duplicate_and_unsafe_residue() -> Result<()> {
        fn leave_old_displacement(repo: &Path, claim_id: &str) -> Result<PathBuf> {
            write_claim(repo, claim_id, claim_id, "active", "2026-05-20T00:00:00Z")?;
            {
                let _fault = ClaimAtomicTestFaultGuard::install(
                    Some(libc::EINVAL),
                    Some(ClaimFallbackCrashPoint::AfterOldDisplacement),
                );
                heartbeat_with_clock(
                    repo,
                    claim_id,
                    claim_id,
                    &LiveClock::parse("2026-05-20T00:30:00Z")?,
                )
                .expect_err("old displacement crash must leave transaction residue");
            }
            fallback_residue_paths(&claims_dir(repo))?
                .pop()
                .context("missing fallback residue")
        }

        let tampered = tempfile::tempdir()?;
        let tampered_residue = leave_old_displacement(tampered.path(), "tampered-residue")?;
        std::fs::write(&tampered_residue, b"tampered old generation")?;
        let tampered_error = status(tampered.path(), &LiveClock::parse("2026-05-20T00:31:00Z")?)
            .expect_err("tampered fallback residue must fail closed");
        assert!(format!("{tampered_error:#}").contains("old-generation residue was changed"));
        assert!(tampered_residue.exists());

        let duplicate = tempfile::tempdir()?;
        let first_residue = leave_old_displacement(duplicate.path(), "duplicate-residue")?;
        let directory = claims_dir(duplicate.path());
        let first_name = first_residue.file_name().context("fallback residue name")?;
        let transaction =
            ClaimFallbackTransaction::parse(first_name)?.context("parse fallback transaction")?;
        let duplicate_path = directory.join("duplicate-old-copy");
        std::fs::copy(&first_residue, &duplicate_path)?;
        let copied = read_entry_generation(
            &open_claims_root(&directory)?.context("duplicate residue root")?,
            OsStr::new("duplicate-old-copy"),
            MAX_CLAIM_BYTES,
        )?;
        let duplicate_name = OsString::from(format!(
            "{CLAIM_FALLBACK_RESIDUE_PREFIX}{}.{}.{}.{}.{:016x}.{:016x}.{:016x}.{:016x}{CLAIM_FALLBACK_RESIDUE_SUFFIX}",
            transaction.target_checksum,
            transaction.old_checksum,
            transaction.new_checksum,
            transaction.other_board_checksum,
            copied.identity.device,
            copied.identity.file,
            transaction.new_identity.device,
            transaction.new_identity.file,
        ));
        std::fs::rename(&duplicate_path, directory.join(&duplicate_name))?;
        let duplicate_error = status(duplicate.path(), &LiveClock::parse("2026-05-20T00:31:00Z")?)
            .expect_err("duplicate fallback residue must fail closed");
        assert!(format!("{duplicate_error:#}").contains("duplicate or ambiguous"));
        assert!(first_residue.exists());
        assert!(directory.join(duplicate_name).exists());

        let unsafe_residue = tempfile::tempdir()?;
        let residue = leave_old_displacement(unsafe_residue.path(), "unsafe-residue")?;
        let external = unsafe_residue.path().join("external-old-generation");
        std::fs::write(&external, b"unsafe replacement")?;
        std::fs::remove_file(&residue)?;
        std::os::unix::fs::symlink(&external, &residue)?;
        let unsafe_error = status(
            unsafe_residue.path(),
            &LiveClock::parse("2026-05-20T00:31:00Z")?,
        )
        .expect_err("unsafe fallback residue must fail closed");
        assert!(format!("{unsafe_error:#}").contains("transaction residue is unsafe"));
        assert!(std::fs::symlink_metadata(&residue)?
            .file_type()
            .is_symlink());
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
        let status_error = status(temp.path(), &LiveClock::parse("2026-05-20T00:30:00Z")?)
            .expect_err("overlapping live claims must fail board validation");
        let status_message = status_error.to_string();
        assert!(status_message.contains("parent-claim.md"));
        assert!(status_message.contains("child-claim.md"));
        assert!(status_message.contains("overlapping"));
        assert!(status_message.contains("`owned_files`"));
        assert!(!status_message.contains("src/live_claim.rs"));
        assert!(!status_message.contains("src/live_claim.rs/tests"));

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
    fn apply_admission_ignores_duplicate_ids_only_when_every_claim_is_non_conflicting() -> Result<()>
    {
        let timestamp = "2026-05-20T00:00:00Z";
        let duplicate_id = "raw-duplicate-id-value";
        let mut done = parse_claim_file(
            PathBuf::from(CLAIMS_DIR).join("done.md"),
            &claim_text("done", "done", "done", timestamp, "src/done.rs"),
        );
        done.claim_id = Some(duplicate_id.to_string());
        let mut handoff = parse_claim_file(
            PathBuf::from(CLAIMS_DIR).join("handoff.md"),
            &claim_text("handoff", "handoff", "handoff", timestamp, "src/handoff.rs"),
        );
        handoff.claim_id = Some(duplicate_id.to_string());

        ensure_claim_board_allows_apply(&[done.clone(), handoff.clone()])?;

        let strict_error = ensure_claim_board_valid(&[done.clone(), handoff.clone()])
            .expect_err("strict board validation must keep reporting terminal duplicates");
        let strict_message = strict_error.to_string();
        assert!(strict_message.contains("done.md"));
        assert!(strict_message.contains("handoff.md"));
        assert!(strict_message.contains("duplicate"));
        assert!(strict_message.contains("`claim_id`"));
        assert!(!strict_message.contains(duplicate_id));

        for status in ["active", "blocked", "completed"] {
            let mut conflicting = handoff.clone();
            conflicting.status = Some(status.to_string());
            let error = ensure_claim_board_allows_apply(&[done.clone(), conflicting]).expect_err(
                "a duplicate id involving a classified or unclassified claim must block",
            );
            let message = error.to_string();
            assert!(message.contains("done.md"));
            assert!(message.contains("handoff.md"));
            assert!(message.contains("duplicate"));
            assert!(message.contains("`claim_id`"));
            assert!(!message.contains(duplicate_id));
        }
        Ok(())
    }

    #[test]
    fn apply_is_create_only_and_scope_changes_require_a_new_claim_id() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let directory = claims_dir(temp.path());
        std::fs::create_dir_all(&directory)?;
        let draft = temp.path().join("claim-draft.md");
        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        std::fs::write(
            &draft,
            initial_draft_text(
                "applied-claim",
                "applied-owner",
                "active",
                now.raw(),
                "src/live_claim.rs",
            ),
        )?;
        let created = apply_with_clock(temp.path(), &draft, "applied-owner", &now)?;
        assert!(created.created);
        let claim_path = directory.join("applied-claim.md");
        let created_content = std::fs::read_to_string(&claim_path)?;
        assert!(created_content.contains("created claim from bounded draft"));

        std::fs::write(
            &draft,
            initial_draft_text(
                "applied-claim",
                "applied-owner",
                "active",
                now.raw(),
                "src/changed-scope.rs",
            ),
        )?;
        let existing = apply_with_clock(temp.path(), &draft, "applied-owner", &now)
            .expect_err("existing claim updates must be refused even for the exact owner");
        assert!(existing.to_string().contains("create-only"));
        assert_eq!(std::fs::read_to_string(&claim_path)?, created_content);

        mutate_claim(
            temp.path(),
            "applied-claim",
            "applied-owner",
            &LiveClock::parse("2026-05-20T00:31:00Z")?,
            ClaimMutation::OwnerRelease {
                status: "handoff",
                reason: "scope change requires a new claim id",
            },
            |_| Ok(()),
        )?;
        let terminal_replay = apply_with_clock(temp.path(), &draft, "applied-owner", &now)
            .expect_err("released ids must not be replayed");
        assert!(terminal_replay.to_string().contains("create-only"));

        std::fs::write(
            &draft,
            initial_draft_text(
                "applied-claim-v2",
                "applied-owner",
                "active",
                now.raw(),
                "src/changed-scope.rs",
            ),
        )?;
        let replacement = apply_with_clock(temp.path(), &draft, "applied-owner", &now)?;
        assert_eq!(replacement.claim_id, "applied-claim-v2");
        assert!(replacement.created);
        Ok(())
    }

    #[test]
    fn apply_ignores_malformed_terminal_claims_while_validation_reports_them() -> Result<()> {
        for status in ["done", "handoff"] {
            let temp = tempfile::tempdir()?;
            let directory = claims_dir(temp.path());
            std::fs::create_dir_all(&directory)?;
            let terminal_id = format!("malformed-{status}");
            let terminal_path = write_claim(
                temp.path(),
                &terminal_id,
                "terminal-owner",
                status,
                "2026-05-20T00:00:00Z",
            )?;
            let raw_owner = format!("TerminalOwnerSecret{status}");
            let malformed = std::fs::read_to_string(&terminal_path)?
                .replace("- Owner: terminal-owner", &format!("- Owner: {raw_owner}"));
            std::fs::write(&terminal_path, malformed)?;

            let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
            let draft = temp.path().join("claim-draft.md");
            let created_id = format!("created-after-{status}");
            std::fs::write(
                &draft,
                initial_draft_text(
                    &created_id,
                    "new-owner",
                    "active",
                    now.raw(),
                    "src/new_scope.rs",
                ),
            )?;

            let created = apply_with_clock(temp.path(), &draft, "new-owner", &now)?;
            assert_eq!(created.claim_id, created_id);
            let validation = validate(temp.path(), &now)?;
            assert!(!validation.valid);
            let terminal = validation
                .claims
                .iter()
                .find(|claim| {
                    claim.file
                        == PathBuf::from(CLAIMS_DIR)
                            .join(&terminal_id)
                            .with_extension("md")
                })
                .context("terminal claim validation")?;
            assert!(terminal
                .issues
                .iter()
                .any(|issue| issue.severity == "error" && issue.field == "owner"));
            assert!(!serde_json::to_string(&validation)?.contains(&raw_owner));
        }
        Ok(())
    }

    #[test]
    fn apply_rejects_malformed_live_claims_with_file_and_field_only() -> Result<()> {
        for status in ["active", "blocked"] {
            let temp = tempfile::tempdir()?;
            let malformed_id = format!("malformed-{status}");
            let raw_owner = format!("LiveOwnerSecret{status}");
            write_claim(
                temp.path(),
                &malformed_id,
                &raw_owner,
                status,
                "2026-05-20T00:00:00Z",
            )?;
            let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
            let draft = temp.path().join("claim-draft.md");
            let created_id = format!("blocked-by-{status}");
            std::fs::write(
                &draft,
                initial_draft_text(
                    &created_id,
                    "new-owner",
                    "active",
                    now.raw(),
                    "src/new_scope.rs",
                ),
            )?;

            let error = apply_with_clock(temp.path(), &draft, "new-owner", &now)
                .expect_err("a malformed live claim must block creation");
            let message = error.to_string();
            assert!(message.contains(&format!("{malformed_id}.md")));
            assert!(message.contains("`owner`"));
            assert!(!message.contains(&raw_owner));
            assert!(!claims_dir(temp.path())
                .join(format!("{created_id}.md"))
                .exists());
        }
        Ok(())
    }

    #[test]
    fn apply_rejects_a_malformed_draft_with_file_and_field_only() -> Result<()> {
        let temp = tempfile::tempdir()?;
        std::fs::create_dir_all(claims_dir(temp.path()))?;
        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        let draft = temp.path().join("claim-draft.md");
        let raw_owner = "MalformedDraftOwnerSecret";
        std::fs::write(
            &draft,
            initial_draft_text(
                "malformed-draft",
                raw_owner,
                "active",
                now.raw(),
                "src/live_claim.rs",
            ),
        )?;

        let error = apply_with_clock(temp.path(), &draft, "draft-owner", &now)
            .expect_err("the supported write path must reject a malformed draft");
        let message = error.to_string();
        assert!(message.contains("malformed-draft.md"));
        assert!(message.contains("`owner`"));
        assert!(!message.contains(raw_owner));
        assert!(!claims_dir(temp.path()).join("malformed-draft.md").exists());
        Ok(())
    }

    #[test]
    fn apply_rejects_old_future_terminal_and_audit_replay_drafts() -> Result<()> {
        let temp = tempfile::tempdir()?;
        std::fs::create_dir_all(claims_dir(temp.path()))?;
        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        let cases = [
            (
                "old-draft",
                "active",
                "2026-05-20T00:20:00Z",
                false,
                "too old",
            ),
            (
                "future-draft",
                "active",
                "2026-05-20T00:31:00Z",
                false,
                "future",
            ),
            (
                "terminal-draft",
                "done",
                "2026-05-20T00:30:00Z",
                false,
                "initial status active",
            ),
            (
                "audit-draft",
                "active",
                "2026-05-20T00:30:00Z",
                true,
                "audit history",
            ),
        ];
        for (claim_id, status, timestamp, with_audit, expected) in cases {
            let draft = temp.path().join(format!("{claim_id}.draft"));
            let mut content =
                initial_draft_text(claim_id, claim_id, status, timestamp, "src/live_claim.rs");
            if with_audit {
                content.push_str("\n## Audit log\n\n- forged prior history\n");
            }
            std::fs::write(&draft, content)?;
            let error = apply_with_clock(temp.path(), &draft, claim_id, &now)
                .expect_err("unsafe initial draft generation must be refused");
            assert!(error.to_string().contains(expected), "{error:#}");
            assert!(!claims_dir(temp.path())
                .join(format!("{claim_id}.md"))
                .exists());
        }
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn apply_binds_draft_parent_leaf_and_board_aliases_without_following_links() -> Result<()> {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir()?;
        let directory = claims_dir(temp.path());
        std::fs::create_dir_all(&directory)?;
        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        let board_claim = write_claim(
            temp.path(),
            "board-source",
            "board-source",
            "done",
            now.raw(),
        )?;

        let inside = apply_with_clock(temp.path(), &board_claim, "board-source", &now)
            .expect_err("board-internal drafts must be refused");
        assert!(inside.to_string().contains("outside"));

        let hardlink = temp.path().join("hardlinked-draft.md");
        std::fs::hard_link(&board_claim, &hardlink)?;
        let hardlink_error = apply_with_clock(temp.path(), &hardlink, "board-source", &now)
            .expect_err("board hard links must be refused");
        assert!(hardlink_error.to_string().contains("bounded no-follow"));
        std::fs::remove_file(&hardlink)?;

        let alias = temp.path().join("claim-board-alias");
        symlink(&directory, &alias)?;
        let alias_error = apply_with_clock(
            temp.path(),
            &alias.join("board-source.md"),
            "board-source",
            &now,
        )
        .expect_err("board symlink aliases must be refused");
        assert!(alias_error.to_string().contains("parent"));

        let draft_parent = temp.path().join("draft-parent");
        let replacement_parent = temp.path().join("replacement-parent");
        std::fs::create_dir(&draft_parent)?;
        std::fs::create_dir(&replacement_parent)?;
        let draft = draft_parent.join("ancestor-race.md");
        std::fs::write(
            &draft,
            initial_draft_text(
                "ancestor-race",
                "ancestor-race",
                "active",
                now.raw(),
                "src/live_claim.rs",
            ),
        )?;
        let moved_parent = temp.path().join("draft-parent-original");
        let race = apply_with_clock_and_hooks(
            temp.path(),
            &draft,
            "ancestor-race",
            &now,
            |_| {
                std::fs::rename(&draft_parent, &moved_parent)?;
                symlink(&replacement_parent, &draft_parent)?;
                Ok(())
            },
            |_| Ok(()),
        )
        .expect_err("ancestor symlink replacement must invalidate the bound draft");
        assert!(race.to_string().contains("parent binding changed"));
        Ok(())
    }

    #[test]
    fn apply_create_race_never_replaces_a_concurrently_created_target() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let directory = claims_dir(temp.path());
        std::fs::create_dir_all(&directory)?;
        let now = LiveClock::parse("2026-05-20T00:30:00Z")?;
        let draft = temp.path().join("create-race.draft");
        std::fs::write(
            &draft,
            initial_draft_text(
                "create-race",
                "create-race",
                "active",
                now.raw(),
                "src/live_claim.rs",
            ),
        )?;
        let raced_content = claim_text(
            "create-race",
            "racing-owner",
            "done",
            now.raw(),
            "src/raced.rs",
        );
        let target = directory.join("create-race.md");
        let error = apply_with_clock_and_hooks(
            temp.path(),
            &draft,
            "create-race",
            &now,
            |_| Ok(()),
            |_| {
                std::fs::write(&target, &raced_content)?;
                Ok(())
            },
        )
        .expect_err("create-only rename must refuse a concurrently appearing target");
        assert!(error.to_string().contains("atomic mutation was refused"));
        assert_eq!(std::fs::read_to_string(&target)?, raced_content);
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
            directory.join("legacy-status.md"),
            claim_text(
                "legacy-status",
                "legacy-status",
                "completed",
                "2026-05-20T00:00:00Z",
                "src/live_claim.rs",
            ),
        )?;
        let error = status(temp.path(), &now)
            .expect_err("an unsupported status must remain fail-closed outside apply admission");
        let message = error.to_string();
        assert!(message.contains("legacy-status.md"));
        assert!(message.contains("`status`"));
        assert!(!message.contains("completed"));
        let validation = validate(temp.path(), &now)?;
        assert!(!validation.valid);
        let legacy = validation
            .claims
            .iter()
            .find(|claim| claim.file.ends_with("legacy-status.md"))
            .context("legacy completed validation")?;
        assert!(legacy
            .issues
            .iter()
            .any(|issue| issue.severity == "error" && issue.field == "status"));
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
