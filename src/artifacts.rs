use crate::orchestrator::RunId;
use anyhow::{bail, Context, Result};
use git2::Repository;
use serde::Serialize;
use serde_json::Value;
use std::{
    fs,
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunArtifactFamily {
    Autopilot,
    Consult,
    Inbox,
    Supervise,
}

impl RunArtifactFamily {
    pub fn label(self) -> &'static str {
        match self {
            Self::Autopilot => "autopilot",
            Self::Consult => "consult",
            Self::Inbox => "inbox",
            Self::Supervise => "supervise",
        }
    }

    pub fn generated_prefix(self) -> &'static str {
        match self {
            Self::Autopilot => "autopilot",
            Self::Consult => "consult",
            Self::Inbox => "inbox",
            Self::Supervise => "o2",
        }
    }

    pub fn run_root(self) -> PathBuf {
        match self {
            Self::Autopilot => PathBuf::from(".maco").join("autopilot").join("runs"),
            Self::Consult => PathBuf::from(".maco").join("consult").join("runs"),
            Self::Inbox => PathBuf::from(".maco").join("inbox").join("runs"),
            Self::Supervise => PathBuf::from(".maco").join("o2").join("runs"),
        }
    }

    pub fn final_report_relative_path(self) -> PathBuf {
        match self {
            Self::Autopilot | Self::Inbox => PathBuf::from("final-report.json"),
            Self::Consult => PathBuf::from("consultant-report.json"),
            Self::Supervise => PathBuf::from("reports").join("supervisor-final.json"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ResolvedRunId {
    pub repo: PathBuf,
    pub run_id: RunId,
    pub run_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactListReport {
    pub family: RunArtifactFamily,
    pub run_root: PathBuf,
    pub ordering: &'static str,
    pub runs: Vec<RunArtifactSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactLatestReport {
    pub family: RunArtifactFamily,
    pub run_root: PathBuf,
    pub ordering: &'static str,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run: Option<RunArtifactSummary>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactSummary {
    pub run_id: String,
    pub run_dir: PathBuf,
    pub final_report_path: PathBuf,
    pub final_report_exists: bool,
    pub final_report_status: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_report_success: Option<bool>,
    pub final_report_readable: bool,
    pub final_report_corrupt: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub final_report_error: Option<String>,
    #[serde(skip)]
    modified: SystemTime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactPruneReport {
    pub family: RunArtifactFamily,
    pub run_root: PathBuf,
    pub ordering: &'static str,
    pub keep: usize,
    pub dry_run: bool,
    pub kept_count: usize,
    pub deleted_count: usize,
    pub delete_candidate_count: usize,
    pub entries: Vec<RunArtifactPruneEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RunArtifactPruneEntry {
    pub run_id: String,
    pub run_dir: PathBuf,
    pub action: RunArtifactPruneAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RunArtifactPruneAction {
    Keep,
    Delete,
    WouldDelete,
}

pub fn discover_repo_root(repo_path: impl AsRef<Path>) -> Result<PathBuf> {
    let repo_path = repo_path.as_ref();
    let repo = Repository::discover(repo_path)
        .with_context(|| format!("failed to discover repository from {}", repo_path.display()))?;
    repo.workdir()
        .map(Path::to_path_buf)
        .context("repository command requires a non-bare repository")
}

pub fn run_root(repo: &Path, family: RunArtifactFamily) -> PathBuf {
    repo.join(family.run_root())
}

pub fn run_dir(repo: &Path, family: RunArtifactFamily, run_id: &RunId) -> PathBuf {
    run_root(repo, family).join(run_id.as_str())
}

pub fn final_report_path(repo: &Path, family: RunArtifactFamily, run_id: &RunId) -> PathBuf {
    run_dir(repo, family, run_id).join(family.final_report_relative_path())
}

pub fn ensure_run_dir_available(
    repo: &Path,
    family: RunArtifactFamily,
    run_id: &RunId,
) -> Result<()> {
    let dir = run_dir(repo, family, run_id);
    if dir.exists() {
        bail!(
            "{} run id '{}' already exists at {}; choose a new --run-id or prune old artifacts first",
            family.label(),
            run_id.as_str(),
            dir.display()
        );
    }
    Ok(())
}

pub fn resolve_run_id(
    repo: impl AsRef<Path>,
    family: RunArtifactFamily,
    explicit: Option<&str>,
) -> Result<ResolvedRunId> {
    let repo = discover_repo_root(repo)?;
    let run_id = match explicit {
        Some(value) => RunId::new(value)?,
        None => generate_run_id(&repo, family)?,
    };
    ensure_run_dir_available(&repo, family, &run_id)?;
    let run_dir = run_dir(&repo, family, &run_id);
    Ok(ResolvedRunId {
        repo,
        run_id,
        run_dir,
    })
}

pub fn generate_run_id(repo: &Path, family: RunArtifactFamily) -> Result<RunId> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .context("system clock is before UNIX epoch")?
        .as_millis();
    for suffix in 0..1000u16 {
        let candidate = RunId::new(format!(
            "{}-{}-{}-{}",
            family.generated_prefix(),
            millis,
            process::id(),
            suffix
        ))?;
        if !run_dir(repo, family, &candidate).exists() {
            return Ok(candidate);
        }
    }
    bail!(
        "failed to generate a collision-free {} run id under {}",
        family.label(),
        run_root(repo, family).display()
    )
}

pub fn list_runs(
    repo: impl AsRef<Path>,
    family: RunArtifactFamily,
) -> Result<RunArtifactListReport> {
    let repo = discover_repo_root(repo)?;
    let run_root = run_root(&repo, family);
    let runs = sorted_run_summaries(&run_root, family)?;
    Ok(RunArtifactListReport {
        family,
        run_root: family.run_root(),
        ordering: artifact_ordering(),
        runs,
    })
}

pub fn latest_run(
    repo: impl AsRef<Path>,
    family: RunArtifactFamily,
) -> Result<RunArtifactLatestReport> {
    let list = list_runs(repo, family)?;
    Ok(RunArtifactLatestReport {
        family: list.family,
        run_root: list.run_root,
        ordering: list.ordering,
        run: list.runs.into_iter().next(),
    })
}

pub fn prune_runs(
    repo: impl AsRef<Path>,
    family: RunArtifactFamily,
    keep: usize,
    dry_run: bool,
) -> Result<RunArtifactPruneReport> {
    let repo = discover_repo_root(repo)?;
    let absolute_root = run_root(&repo, family);
    let runs = sorted_run_summaries(&absolute_root, family)?;
    let mut entries = Vec::new();
    let mut kept_count = 0usize;
    let mut deleted_count = 0usize;
    let mut delete_candidate_count = 0usize;

    for (index, run) in runs.into_iter().enumerate() {
        if index < keep {
            kept_count = kept_count.saturating_add(1);
            entries.push(RunArtifactPruneEntry {
                run_id: run.run_id,
                run_dir: run.run_dir,
                action: RunArtifactPruneAction::Keep,
            });
            continue;
        }

        delete_candidate_count = delete_candidate_count.saturating_add(1);
        let absolute_run_dir = absolute_root.join(&run.run_id);
        ensure_child_run_dir(&absolute_root, &absolute_run_dir)?;
        if dry_run {
            entries.push(RunArtifactPruneEntry {
                run_id: run.run_id,
                run_dir: run.run_dir,
                action: RunArtifactPruneAction::WouldDelete,
            });
        } else {
            fs::remove_dir_all(&absolute_run_dir)
                .with_context(|| format!("failed to delete {}", absolute_run_dir.display()))?;
            deleted_count = deleted_count.saturating_add(1);
            entries.push(RunArtifactPruneEntry {
                run_id: run.run_id,
                run_dir: run.run_dir,
                action: RunArtifactPruneAction::Delete,
            });
        }
    }

    Ok(RunArtifactPruneReport {
        family,
        run_root: family.run_root(),
        ordering: artifact_ordering(),
        keep,
        dry_run,
        kept_count,
        deleted_count,
        delete_candidate_count,
        entries,
    })
}

pub fn artifact_ordering() -> &'static str {
    "newest first by final-report modification time, then run directory modification time, ties by descending run id"
}

fn sorted_run_summaries(
    absolute_root: &Path,
    family: RunArtifactFamily,
) -> Result<Vec<RunArtifactSummary>> {
    if !absolute_root.exists() {
        return Ok(Vec::new());
    }
    let mut runs = Vec::new();
    for entry in fs::read_dir(absolute_root)
        .with_context(|| format!("failed to read run root {}", absolute_root.display()))?
    {
        let entry = entry
            .with_context(|| format!("failed to inspect run root {}", absolute_root.display()))?;
        let file_type = entry.file_type().with_context(|| {
            format!(
                "failed to inspect artifact entry {}",
                entry.path().display()
            )
        })?;
        if !file_type.is_dir() {
            continue;
        }
        let run_id = entry.file_name().to_string_lossy().into_owned();
        let run_dir = entry.path();
        runs.push(summarize_run(absolute_root, family, run_id, run_dir)?);
    }
    runs.sort_by(|left, right| {
        right
            .modified
            .cmp(&left.modified)
            .then_with(|| right.run_id.cmp(&left.run_id))
    });
    Ok(runs)
}

fn summarize_run(
    absolute_root: &Path,
    family: RunArtifactFamily,
    run_id: String,
    absolute_run_dir: PathBuf,
) -> Result<RunArtifactSummary> {
    ensure_child_run_dir(absolute_root, &absolute_run_dir)?;
    let final_report_path = absolute_run_dir.join(family.final_report_relative_path());
    let modified = final_report_path
        .metadata()
        .and_then(|metadata| metadata.modified())
        .or_else(|_| {
            absolute_run_dir
                .metadata()
                .and_then(|metadata| metadata.modified())
        })
        .unwrap_or(UNIX_EPOCH);
    let public_run_dir = family.run_root().join(&run_id);
    let public_final_report_path = public_run_dir.join(family.final_report_relative_path());

    if !final_report_path.exists() {
        return Ok(RunArtifactSummary {
            run_id,
            run_dir: public_run_dir,
            final_report_path: public_final_report_path,
            final_report_exists: false,
            final_report_status: "missing".to_string(),
            final_report_success: None,
            final_report_readable: false,
            final_report_corrupt: false,
            final_report_error: None,
            modified,
        });
    }

    let contents = match fs::read_to_string(&final_report_path) {
        Ok(contents) => contents,
        Err(error) => {
            return Ok(RunArtifactSummary {
                run_id,
                run_dir: public_run_dir,
                final_report_path: public_final_report_path,
                final_report_exists: true,
                final_report_status: "read_error".to_string(),
                final_report_success: None,
                final_report_readable: false,
                final_report_corrupt: false,
                final_report_error: Some(error.to_string()),
                modified,
            });
        }
    };
    let value = match serde_json::from_str::<Value>(&contents) {
        Ok(value) => value,
        Err(error) => {
            return Ok(RunArtifactSummary {
                run_id,
                run_dir: public_run_dir,
                final_report_path: public_final_report_path,
                final_report_exists: true,
                final_report_status: "malformed".to_string(),
                final_report_success: None,
                final_report_readable: false,
                final_report_corrupt: true,
                final_report_error: Some(error.to_string()),
                modified,
            });
        }
    };
    let status = value
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or("readable")
        .to_string();
    let success = value.get("success").and_then(Value::as_bool);
    Ok(RunArtifactSummary {
        run_id,
        run_dir: public_run_dir,
        final_report_path: public_final_report_path,
        final_report_exists: true,
        final_report_status: status,
        final_report_success: success,
        final_report_readable: true,
        final_report_corrupt: false,
        final_report_error: None,
        modified,
    })
}

fn ensure_child_run_dir(root: &Path, run_dir: &Path) -> Result<()> {
    if run_dir.parent() != Some(root) {
        bail!(
            "refusing to operate outside run root {}; candidate was {}",
            root.display(),
            run_dir.display()
        );
    }
    Ok(())
}
