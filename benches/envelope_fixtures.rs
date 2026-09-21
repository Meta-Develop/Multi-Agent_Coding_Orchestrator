//! Isolated S/M Git fixtures and production-API helpers for the worktree/merge envelope.

use git2::{ResetType, Signature};
use multi_agent_coding_orchestrator::{
    merge::{
        preview_merge_apply_with_evidence, ApplyReadinessStatus, MergeApplyReviewIntent,
        MergeCollectOptions, MergeForceOptions, MergePreviewOptions, ValidationEvidenceBundle,
        DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
    },
    sync_store::SyncStore,
    worktree::{WorktreeCreateOptions, WorktreeManager, WorktreeRecord},
};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Once,
};

const MERGE_AGENT: &str = "envelope-merge";
pub const SMALL_CLAIM_PATH: &str = "src/lib.rs";
pub const MEDIUM_CLAIM_PATH: &str = "data/000.txt";

pub struct EnvelopeRepo {
    fixture: crate::RepositoryFixture,
    pub worktree_root: PathBuf,
}

pub struct MergeLane {
    pub repo: EnvelopeRepo,
    pub agent_id: String,
    pub claim_path: &'static str,
    pub worktree: WorktreeRecord,
}

pub struct OutcomeCounters {
    pub success: std::sync::atomic::AtomicU64,
    pub failure: std::sync::atomic::AtomicU64,
}

impl OutcomeCounters {
    pub fn new() -> Self {
        Self {
            success: std::sync::atomic::AtomicU64::new(0),
            failure: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn record_ok(&self) {
        self.success
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn record_err(&self) {
        self.failure
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> (u64, u64) {
        (
            self.success.load(std::sync::atomic::Ordering::Relaxed),
            self.failure.load(std::sync::atomic::Ordering::Relaxed),
        )
    }
}

impl EnvelopeRepo {
    pub fn small() -> Self {
        from_fixture(crate::RepositoryFixture::claims())
    }

    pub fn medium() -> Self {
        from_fixture(crate::RepositoryFixture::medium())
    }

    pub fn repo_path(&self) -> &Path {
        &self.fixture.repo_path
    }

    pub fn scratch_path(&self) -> &Path {
        self.fixture
            .repo_path
            .parent()
            .expect("benchmark fixture repo has a parent tempdir")
    }

    pub fn manager(&self) -> WorktreeManager {
        WorktreeManager::new(self.repo_path())
    }
}

fn from_fixture(fixture: crate::RepositoryFixture) -> EnvelopeRepo {
    ensure_libgit2_extensions();
    let worktree_root = fixture
        .repo_path
        .parent()
        .expect("benchmark fixture repo has a parent tempdir")
        .join("worktrees");
    fs::create_dir_all(&worktree_root).expect("create envelope worktree root");
    EnvelopeRepo {
        fixture,
        worktree_root,
    }
}

pub fn ensure_libgit2_extensions() {
    multi_agent_coding_orchestrator::configure_libgit2_repository_extensions()
        .expect("register supported Git repository extensions");
}

pub fn create_managed(repo: &EnvelopeRepo, agent_id: &str) -> WorktreeRecord {
    repo.manager()
        .create(WorktreeCreateOptions {
            agent_id: agent_id.to_string(),
            branch: None,
            base: None,
            worktree_root: Some(repo.worktree_root.clone()),
        })
        .unwrap_or_else(|error| {
            panic!("WorktreeManager::create({agent_id}) must succeed on a clean fixture: {error:#}")
        })
}

pub fn force_remove(repo: &EnvelopeRepo, agent_id: &str) {
    repo.manager()
        .remove(agent_id, true, true)
        .unwrap_or_else(|error| {
            panic!("WorktreeManager::remove(force=true) for {agent_id} must succeed: {error:#}")
        });
}

pub fn try_force_remove(repo: &EnvelopeRepo, agent_id: &str) -> bool {
    repo.manager().remove(agent_id, true, true).is_ok()
}

pub fn prepare_merge_lane(repo: EnvelopeRepo, claim_path: &'static str) -> MergeLane {
    let worktree = create_managed(&repo, MERGE_AGENT);
    let store = SyncStore::open(repo.repo_path()).expect("open envelope SyncStore");
    let claim = store
        .claim_paths(MERGE_AGENT, [claim_path])
        .expect("claim the single merge path");
    assert_eq!(claim.agent_id, MERGE_AGENT);
    commit_relative(
        &worktree.path,
        claim_path,
        "envelope merge candidate\n",
        "envelope single-path merge candidate",
    );
    MergeLane {
        repo,
        agent_id: MERGE_AGENT.to_string(),
        claim_path,
        worktree,
    }
}

pub fn merge_preview_options(lane: &MergeLane) -> MergePreviewOptions {
    MergePreviewOptions {
        collect: MergeCollectOptions {
            repo: lane.repo.repo_path().to_path_buf(),
            agent_id: lane.agent_id.clone(),
            claimed_paths: vec![PathBuf::from(lane.claim_path)],
            include_full_diff: false,
            diff_summary_char_limit: DEFAULT_DIFF_SUMMARY_CHAR_LIMIT,
            validations: Vec::new(),
        },
        forces: MergeForceOptions::default(),
        require_validation: false,
        review_intent: MergeApplyReviewIntent::default(),
    }
}

pub fn preview_merge(
    lane: &MergeLane,
) -> multi_agent_coding_orchestrator::merge::MergeApplyPreview {
    let preview = preview_merge_apply_with_evidence(
        merge_preview_options(lane),
        ValidationEvidenceBundle::default(),
    )
    .expect("preview_merge_apply_with_evidence must succeed");
    assert_ne!(
        preview.safety.readiness.status,
        ApplyReadinessStatus::Blocked,
        "envelope preview must keep apply gates satisfied: {:?}",
        preview.safety.readiness
    );
    assert!(
        preview
            .candidate
            .changed_paths
            .iter()
            .any(|path| path == Path::new(lane.claim_path)),
        "preview must include the claimed single-path diff"
    );
    preview
}

pub fn reset_primary_hard(repo_path: &Path) {
    ensure_libgit2_extensions();
    let repo = git2::Repository::open(repo_path).expect("open primary for reset");
    let head = repo
        .head()
        .expect("primary HEAD")
        .peel_to_commit()
        .expect("primary HEAD commit");
    repo.reset(head.as_object(), ResetType::Hard, None)
        .expect("reset primary working tree after merge apply");
}

pub fn commit_relative(worktree: &Path, relative: &str, contents: &str, message: &str) {
    ensure_libgit2_extensions();
    let path = worktree.join(relative);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).expect("create envelope worktree parent");
    }
    fs::write(&path, contents).expect("write envelope worktree file");
    let repo = git2::Repository::open(worktree).expect("open agent worktree");
    let mut index = repo.index().expect("open agent index");
    index
        .add_path(Path::new(relative))
        .expect("stage envelope worktree path");
    index.write().expect("write agent index");
    let tree_id = index.write_tree().expect("write agent tree");
    let tree = repo.find_tree(tree_id).expect("find agent tree");
    let signature = Signature::now("maco benchmark", "maco-benchmark@example.invalid")
        .expect("envelope signature");
    let parent = repo
        .head()
        .expect("agent HEAD")
        .peel_to_commit()
        .expect("agent parent commit");
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &[&parent],
    )
    .expect("commit envelope worktree change");
}

pub fn maco_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_maco"))
}

pub fn write_cli_preview_watermark(lane: &MergeLane, watermark_path: &Path) {
    let output = Command::new(maco_bin())
        .arg("merge")
        .arg("preview")
        .arg(&lane.agent_id)
        .arg("--repo")
        .arg(lane.repo.repo_path())
        .arg("--claim")
        .arg(lane.claim_path)
        .arg("--json")
        .env("RUST_LOG", "off")
        .output()
        .expect("spawn maco merge preview");
    if !output.status.success() {
        panic!(
            "maco merge preview failed (status {:?}): stderr={} stdout={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }
    fs::write(watermark_path, output.stdout).expect("write reviewed preview JSON");
}

pub fn cli_merge_apply(lane: &MergeLane, watermark_path: &Path) -> serde_json::Value {
    let output = Command::new(maco_bin())
        .arg("merge")
        .arg("apply")
        .arg(&lane.agent_id)
        .arg("--repo")
        .arg(lane.repo.repo_path())
        .arg("--claim")
        .arg(lane.claim_path)
        .arg("--reviewed-watermark")
        .arg(watermark_path)
        .arg("--json")
        .env("RUST_LOG", "off")
        .output()
        .expect("spawn maco merge apply");
    if !output.status.success() {
        panic!(
            "maco merge apply failed (status {:?}): stderr={} stdout={}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        );
    }
    let report: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse merge apply JSON");
    assert_eq!(
        report.get("applied").and_then(serde_json::Value::as_bool),
        Some(true),
        "merge apply must mutate the primary: {report}"
    );
    assert_eq!(
        report.get("status").and_then(serde_json::Value::as_str),
        Some("applied"),
        "merge apply status must be applied: {report}"
    );
    report
}

pub fn git_maco_state_bytes(repo_path: &Path) -> Option<u64> {
    let git_dir = repo_path.join(".git");
    if !git_dir.is_dir() {
        return None;
    }
    let maco = git_dir.join("maco");
    if !maco.exists() {
        return Some(0);
    }
    Some(directory_bytes(&maco))
}

fn directory_bytes(path: &Path) -> u64 {
    let mut total = 0;
    let Ok(entries) = fs::read_dir(path) else {
        return 0;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            total += directory_bytes(&path);
        } else {
            total += meta.len();
        }
    }
    total
}

pub fn eprint_identity_once(sample_path: &Path) {
    static ONCE: Once = Once::new();
    ONCE.call_once(|| {
        eprintln!(
            "coordination_envelope_identity os={} arch={} rustc={} filesystem={} \
             criterion=samples:10,warmup_ms:300,measure_ms:700 \
             p50=criterion_estimated_median \
             p95_p99=criterion_bootstrap_percentiles_same_window_not_ci_gates \
             lock_wait_hold=UNAVAILABLE \
             ntfs3_sweep=UNAVAILABLE \
             classify_semantic_conflicts=UNAVAILABLE \
             continuity_commits_per_sec=UNAVAILABLE",
            std::env::consts::OS,
            std::env::consts::ARCH,
            rustc_version(),
            filesystem_identity(sample_path)
        );
    });
}

fn rustc_version() -> String {
    Command::new("rustc")
        .arg("--version")
        .output()
        .ok()
        .and_then(|output| {
            output
                .status
                .success()
                .then(|| String::from_utf8_lossy(&output.stdout).trim().to_string())
        })
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "UNAVAILABLE".to_string())
}

fn filesystem_identity(path: &Path) -> String {
    #[cfg(windows)]
    {
        return windows_filesystem_identity(path).unwrap_or_else(|| "UNAVAILABLE".to_string());
    }
    #[cfg(unix)]
    {
        return unix_filesystem_identity(path).unwrap_or_else(|| "UNAVAILABLE".to_string());
    }
    #[cfg(not(any(windows, unix)))]
    {
        let _ = path;
        "UNAVAILABLE".to_string()
    }
}

#[cfg(windows)]
fn windows_filesystem_identity(path: &Path) -> Option<String> {
    let canonical = fs::canonicalize(path).ok()?;
    let volume = match canonical.components().next()? {
        std::path::Component::Prefix(prefix) => match prefix.kind() {
            std::path::Prefix::Disk(letter) | std::path::Prefix::VerbatimDisk(letter) => {
                format!("{}:\\", letter as char)
            }
            _ => return None,
        },
        _ => return None,
    };
    let output = Command::new("fsutil")
        .args(["fsinfo", "volumeinfo", &volume])
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    parse_known_filesystem(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(unix)]
fn unix_filesystem_identity(path: &Path) -> Option<String> {
    let canonical = fs::canonicalize(path).ok()?;
    let mounts = fs::read_to_string("/proc/self/mounts").ok()?;
    let mut best: Option<(usize, String)> = None;
    for line in mounts.lines() {
        let mut parts = line.split_whitespace();
        let _device = parts.next()?;
        let mount = Path::new(parts.next()?);
        let fstype = parts.next()?;
        if canonical.starts_with(mount) {
            let len = mount.as_os_str().len();
            if best.as_ref().is_none_or(|(best_len, _)| len > *best_len) {
                best = Some((len, fstype.to_string()));
            }
        }
    }
    best.map(|(_, fstype)| fstype)
}

#[cfg(windows)]
fn parse_known_filesystem(text: &str) -> Option<String> {
    for line in text.lines() {
        if let Some((_, rhs)) = line.split_once(':') {
            let candidate = rhs.trim();
            if matches!(
                candidate.to_ascii_uppercase().as_str(),
                "NTFS" | "REFS" | "EXFAT" | "FAT32" | "FAT16"
            ) {
                return Some(candidate.to_ascii_uppercase());
            }
        }
    }
    let upper = text.to_ascii_uppercase();
    for known in ["NTFS", "REFS", "EXFAT", "FAT32"] {
        if upper.contains(known) {
            return Some(known.to_string());
        }
    }
    None
}
