use crate::merge::MergeCandidate;
use git2::Oid;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

pub const MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergePreviewFreshnessWatermark {
    pub version: u32,
    pub primary_head: Option<String>,
    pub source_head: Option<String>,
    pub source_agent_id: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergePreviewDriftAxis {
    PrimaryHead,
    SourceHead,
    SourceIdentity,
}

impl MergePreviewDriftAxis {
    fn label(self) -> &'static str {
        match self {
            Self::PrimaryHead => "primary HEAD",
            Self::SourceHead => "source HEAD",
            Self::SourceIdentity => "source identity",
        }
    }
}

#[derive(Debug, Error)]
pub enum MergePreviewFreshnessError {
    #[error("merge apply refused: reviewed preview watermark is malformed: {message}")]
    MalformedWatermark { message: String },
    #[error(
        "merge apply refused: reviewed preview watermark version {version} is unsupported; expected version {expected}"
    )]
    UnsupportedWatermarkVersion { version: u32, expected: u32 },
    #[error(
        "merge apply refused: preview freshness state no longer matches current repository state ({moved}); retry after concurrent repository activity stops or run merge preview again"
    )]
    Drift {
        axes: Vec<MergePreviewDriftAxis>,
        moved: String,
    },
}

impl MergePreviewFreshnessError {
    pub fn drift_axes(&self) -> &[MergePreviewDriftAxis] {
        match self {
            Self::MalformedWatermark { .. } | Self::UnsupportedWatermarkVersion { .. } => &[],
            Self::Drift { axes, .. } => axes,
        }
    }

    fn malformed(message: impl Into<String>) -> Self {
        Self::MalformedWatermark {
            message: message.into(),
        }
    }

    fn drift(axes: Vec<MergePreviewDriftAxis>) -> Self {
        let moved = axes
            .iter()
            .map(|axis| axis.label())
            .collect::<Vec<_>>()
            .join(", ");
        Self::Drift { axes, moved }
    }
}

impl MergePreviewFreshnessWatermark {
    pub fn capture_from_candidate(
        candidate: &MergeCandidate,
    ) -> Result<Self, MergePreviewFreshnessError> {
        let current = capture_current_heads(
            &candidate.metadata.primary_repo_root,
            &candidate.metadata.worktree_path,
            &candidate.metadata.agent_id,
        )?;
        let stamped = Self {
            version: MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION,
            primary_head: canonical_optional_oid(
                candidate.metadata.primary_head.clone(),
                "primary_head",
            )?,
            source_head: canonical_optional_oid(
                candidate.metadata.agent_head.clone(),
                "source_head",
            )?,
            source_agent_id: candidate.metadata.agent_id.clone(),
        }
        .canonicalized()?;
        refuse_if_drifted(&stamped, &current)?;
        Ok(stamped)
    }

    pub fn canonicalized(self) -> Result<Self, MergePreviewFreshnessError> {
        if self.version != MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION {
            return Err(MergePreviewFreshnessError::UnsupportedWatermarkVersion {
                version: self.version,
                expected: MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION,
            });
        }
        if self.source_agent_id.trim().is_empty() {
            return Err(MergePreviewFreshnessError::malformed(
                "source_agent_id must be non-empty",
            ));
        }
        Ok(Self {
            version: self.version,
            primary_head: canonical_optional_oid(self.primary_head, "primary_head")?,
            source_head: canonical_optional_oid(self.source_head, "source_head")?,
            source_agent_id: self.source_agent_id,
        })
    }

    pub fn drift_axes(&self, current: &Self) -> Vec<MergePreviewDriftAxis> {
        let mut axes = Vec::new();
        if self.primary_head != current.primary_head {
            axes.push(MergePreviewDriftAxis::PrimaryHead);
        }
        if self.source_head != current.source_head {
            axes.push(MergePreviewDriftAxis::SourceHead);
        }
        if self.source_agent_id != current.source_agent_id {
            axes.push(MergePreviewDriftAxis::SourceIdentity);
        }
        axes
    }
}

pub fn capture_current_heads(
    primary_repo: &Path,
    source_worktree: &Path,
    agent_id: &str,
) -> Result<MergePreviewFreshnessWatermark, MergePreviewFreshnessError> {
    Ok(MergePreviewFreshnessWatermark {
        version: MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION,
        primary_head: head_oid_string(primary_repo, "primary HEAD")?,
        source_head: head_oid_string(source_worktree, "source HEAD")?,
        source_agent_id: agent_id.to_string(),
    }
    .canonicalized()?)
}

pub fn refuse_if_drifted(
    reviewed: &MergePreviewFreshnessWatermark,
    current: &MergePreviewFreshnessWatermark,
) -> Result<(), MergePreviewFreshnessError> {
    let reviewed = reviewed.clone().canonicalized()?;
    let current = current.clone().canonicalized()?;
    let axes = reviewed.drift_axes(&current);
    if axes.is_empty() {
        Ok(())
    } else {
        Err(MergePreviewFreshnessError::drift(axes))
    }
}

pub fn reviewed_merge_preview_watermark_from_json(
    value: &serde_json::Value,
) -> Result<MergePreviewFreshnessWatermark, MergePreviewFreshnessError> {
    let object = value.as_object().ok_or_else(|| {
        MergePreviewFreshnessError::malformed(
            "expected a watermark object or full merge preview JSON object",
        )
    })?;
    let watermark_value = if object.contains_key("freshness_watermark") {
        object.get("freshness_watermark").ok_or_else(|| {
            MergePreviewFreshnessError::malformed("full merge preview omitted freshness_watermark")
        })?
    } else {
        value
    };
    let watermark: MergePreviewFreshnessWatermark = serde_json::from_value(watermark_value.clone())
        .map_err(|error| {
            MergePreviewFreshnessError::malformed(format!("watermark JSON is invalid: {error}"))
        })?;
    watermark.canonicalized()
}

fn head_oid_string(
    repo_path: &Path,
    label: &str,
) -> Result<Option<String>, MergePreviewFreshnessError> {
    let repo = crate::git_repository::open(repo_path).map_err(|source| {
        MergePreviewFreshnessError::malformed(format!("failed to open {label}: {source}"))
    })?;
    let oid = match repo.head() {
        Ok(head) => Some(
            head.peel_to_commit()
                .map_err(|source| {
                    MergePreviewFreshnessError::malformed(format!(
                        "failed to read {label} commit: {source}"
                    ))
                })?
                .id()
                .to_string(),
        ),
        Err(_) => None,
    };
    Ok(oid)
}

fn canonical_optional_oid(
    value: Option<String>,
    field: &str,
) -> Result<Option<String>, MergePreviewFreshnessError> {
    match value {
        None => Ok(None),
        Some(value) => {
            let oid = Oid::from_str(&value).map_err(|_| {
                MergePreviewFreshnessError::malformed(format!("{field} must be a Git object id"))
            })?;
            let canonical = oid.to_string();
            if canonical != value {
                return Err(MergePreviewFreshnessError::malformed(format!(
                    "{field} must use its canonical 40-character lowercase form"
                )));
            }
            Ok(Some(canonical))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::worktree::WorktreeManager;
    use anyhow::{Context, Result};
    use git2::Signature;
    use std::fs;
    use tempfile::TempDir;

    #[test]
    fn reviewed_watermark_refuses_primary_and_source_head_drift() -> Result<()> {
        let temp = TempDir::new()?;
        let primary = temp.path().join("primary");
        WorktreeManager::init_repository(&primary, "main")?;
        let repo = crate::git_repository::open(&primary)?;
        commit_file(&repo, "README.md", "base\n")?;
        let source = temp.path().join("source");
        fs::create_dir(&source)?;
        // Linked worktree-style copy of the same git dir via clone for an independent HEAD.
        let source_repo = git2::Repository::clone(primary.to_str().context("utf8")?, &source)?;
        let first = head_oid_string(&primary, "primary")?.context("primary head")?;
        let reviewed = MergePreviewFreshnessWatermark {
            version: 1,
            primary_head: Some(first.clone()),
            source_head: Some(first.clone()),
            source_agent_id: "agent-a".to_string(),
        };
        let current = capture_current_heads(&primary, &source, "agent-a")?;
        refuse_if_drifted(&reviewed, &current)?;

        commit_file(&repo, "README.md", "moved\n")?;
        let drifted_primary = capture_current_heads(&primary, &source, "agent-a")?;
        let error = refuse_if_drifted(&reviewed, &drifted_primary)
            .expect_err("primary HEAD drift must refuse apply");
        assert!(error.to_string().contains("primary HEAD"));

        commit_file(&source_repo, "NOTE.md", "source moved\n")?;
        let drifted_source = capture_current_heads(&primary, &source, "agent-a")?;
        let still_reviewed = MergePreviewFreshnessWatermark {
            version: 1,
            primary_head: drifted_source.primary_head.clone(),
            source_head: Some(first),
            source_agent_id: "agent-a".to_string(),
        };
        let error = refuse_if_drifted(&still_reviewed, &drifted_source)
            .expect_err("source HEAD drift must refuse apply");
        assert!(error.to_string().contains("source HEAD"));
        Ok(())
    }

    #[test]
    fn watermark_parser_rejects_malformed_and_unsupported_versions() {
        let bad = serde_json::json!({"version": 1, "source_agent_id": ""});
        assert!(reviewed_merge_preview_watermark_from_json(&bad).is_err());
        let unsupported = serde_json::json!({
            "version": 99,
            "primary_head": null,
            "source_head": null,
            "source_agent_id": "agent-a"
        });
        let error = reviewed_merge_preview_watermark_from_json(&unsupported)
            .expect_err("unsupported version");
        assert!(matches!(
            error,
            MergePreviewFreshnessError::UnsupportedWatermarkVersion { version: 99, .. }
        ));
        let nested = serde_json::json!({
            "freshness_watermark": {
                "version": 1,
                "primary_head": null,
                "source_head": null,
                "source_agent_id": "agent-a"
            }
        });
        let parsed = reviewed_merge_preview_watermark_from_json(&nested).expect("nested watermark");
        assert_eq!(parsed.source_agent_id, "agent-a");
    }

    fn commit_file(repo: &git2::Repository, path: &str, contents: &str) -> Result<Oid> {
        fs::write(repo.workdir().context("workdir")?.join(path), contents)?;
        let mut index = repo.index()?;
        index.add_path(Path::new(path))?;
        index.write()?;
        let tree_id = index.write_tree()?;
        let tree = repo.find_tree(tree_id)?;
        let signature = Signature::now("maco", "maco@example.com")?;
        let parents = match repo.head() {
            Ok(head) => vec![head.peel_to_commit()?],
            Err(_) => Vec::new(),
        };
        let parent_refs = parents.iter().collect::<Vec<_>>();
        Ok(repo.commit(
            Some("HEAD"),
            &signature,
            &signature,
            "test",
            &tree,
            &parent_refs,
        )?)
    }
}
