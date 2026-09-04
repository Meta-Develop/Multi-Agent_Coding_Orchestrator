use crate::{
    artifacts::state_auth::sha256_hex,
    merge::{MergeApplyPreview, PrimaryRepositoryState},
    worktree::normalize_agent_id,
};
use git2::Oid;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::Path;
use thiserror::Error;

pub const MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION: u32 = 2;
pub const MERGE_APPLY_REVIEW_REFUSAL_VERSION: u32 = 2;
const REVIEWED_PREVIEW_DIGEST_DOMAIN: &[u8] = b"maco-reviewed-merge-preview-v2\0";

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergePreviewFreshnessWatermark {
    pub version: u32,
    pub primary: MergePreviewPrimaryBinding,
    pub source: MergePreviewSourceBinding,
    pub candidate: MergePreviewCandidateBinding,
    pub base_preview: MergePreviewIdentityBinding,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergePreviewPrimaryBinding {
    pub head: Option<String>,
    pub index_digest: Option<String>,
    pub worktree_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergePreviewSourceBinding {
    pub agent_id: String,
    pub head: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergePreviewCandidateBinding {
    pub snapshot_tree: String,
    pub diff_oid: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MergePreviewIdentityBinding {
    pub sha256: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergePreviewDriftAxis {
    PrimaryHead,
    PrimaryIndex,
    PrimaryWorktree,
    SourceHead,
    SourceIdentity,
    CandidateSnapshot,
    CandidateDiff,
    BasePreview,
}

impl MergePreviewDriftAxis {
    fn label(self) -> &'static str {
        match self {
            Self::PrimaryHead => "primary HEAD",
            Self::PrimaryIndex => "primary index",
            Self::PrimaryWorktree => "primary worktree",
            Self::SourceHead => "source HEAD",
            Self::SourceIdentity => "source identity",
            Self::CandidateSnapshot => "candidate snapshot",
            Self::CandidateDiff => "candidate diff",
            Self::BasePreview => "base preview",
        }
    }

    fn is_repository_state(self) -> bool {
        matches!(
            self,
            Self::PrimaryHead | Self::PrimaryIndex | Self::PrimaryWorktree | Self::SourceHead
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeReviewBindingStatus {
    Matched,
    Missing,
    Malformed,
    UnsupportedVersion,
    Stale,
    Substituted,
}

#[derive(Debug, Error)]
pub enum MergePreviewFreshnessError {
    #[error(
        "merge apply refused: reviewed preview evidence is required; run merge preview --json and pass its output with --reviewed-watermark"
    )]
    MissingReviewedEvidence,
    #[error("merge apply refused: reviewed preview evidence is malformed: {message}")]
    MalformedWatermark { message: String },
    #[error(
        "merge apply refused: reviewed preview evidence version {version} is unsupported; expected version {expected}"
    )]
    UnsupportedWatermarkVersion { version: u32, expected: u32 },
    #[error(
        "merge apply refused: reviewed preview evidence no longer matches the exact current apply preview ({moved}); run merge preview again with the same options"
    )]
    Mismatch {
        axes: Vec<MergePreviewDriftAxis>,
        moved: String,
    },
}

impl MergePreviewFreshnessError {
    pub fn drift_axes(&self) -> &[MergePreviewDriftAxis] {
        match self {
            Self::Mismatch { axes, .. } => axes,
            Self::MissingReviewedEvidence
            | Self::MalformedWatermark { .. }
            | Self::UnsupportedWatermarkVersion { .. } => &[],
        }
    }

    pub fn binding_status(&self) -> MergeReviewBindingStatus {
        match self {
            Self::MissingReviewedEvidence => MergeReviewBindingStatus::Missing,
            Self::MalformedWatermark { .. } => MergeReviewBindingStatus::Malformed,
            Self::UnsupportedWatermarkVersion { .. } => {
                MergeReviewBindingStatus::UnsupportedVersion
            }
            Self::Mismatch { axes, .. } if axes.iter().any(|axis| axis.is_repository_state()) => {
                MergeReviewBindingStatus::Stale
            }
            Self::Mismatch { .. } => MergeReviewBindingStatus::Substituted,
        }
    }

    pub(crate) fn malformed(message: impl Into<String>) -> Self {
        Self::MalformedWatermark {
            message: message.into(),
        }
    }

    fn mismatch(axes: Vec<MergePreviewDriftAxis>) -> Self {
        let moved = axes
            .iter()
            .map(|axis| axis.label())
            .collect::<Vec<_>>()
            .join(", ");
        Self::Mismatch { axes, moved }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeApplyReviewRefusalStatus {
    Refused,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MergeApplyReviewRefusalKind {
    ReviewedPreviewEvidence,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeApplyReviewRefusalDetail {
    pub kind: MergeApplyReviewRefusalKind,
    pub message: String,
    pub axes: Vec<MergePreviewDriftAxis>,
    pub next_safe_operation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MergeApplyReviewRefusalEnvelope {
    pub version: u32,
    pub status: MergeApplyReviewRefusalStatus,
    pub applied: bool,
    pub review_bound: bool,
    pub review_binding_status: MergeReviewBindingStatus,
    pub refusal: MergeApplyReviewRefusalDetail,
}

impl MergeApplyReviewRefusalEnvelope {
    pub fn from_error(error: &MergePreviewFreshnessError) -> Self {
        Self {
            version: MERGE_APPLY_REVIEW_REFUSAL_VERSION,
            status: MergeApplyReviewRefusalStatus::Refused,
            applied: false,
            review_bound: false,
            review_binding_status: error.binding_status(),
            refusal: MergeApplyReviewRefusalDetail {
                kind: MergeApplyReviewRefusalKind::ReviewedPreviewEvidence,
                message: error.to_string(),
                axes: error.drift_axes().to_vec(),
                next_safe_operation: "run_merge_preview_again_with_the_same_options".to_string(),
            },
        }
    }
}

impl MergePreviewFreshnessWatermark {
    pub(crate) fn capture_from_preview(
        preview: &MergeApplyPreview,
    ) -> Result<Self, MergePreviewFreshnessError> {
        let candidate = &preview.candidate;
        let primary = PrimaryRepositoryState::capture(&candidate.metadata.primary_repo_root)
            .map_err(|source| {
                MergePreviewFreshnessError::malformed(format!(
                    "failed to capture primary repository state: {source:#}"
                ))
            })?;
        let source_head = head_oid_string(&candidate.metadata.worktree_path, "source HEAD")?;
        let expected_primary_head = canonical_optional_oid(
            candidate.metadata.primary_head.clone(),
            "candidate.metadata.primary_head",
        )?;
        let expected_source_head = canonical_optional_oid(
            candidate.metadata.agent_head.clone(),
            "candidate.metadata.agent_head",
        )?;
        let mut moved = Vec::new();
        if expected_primary_head != primary.head_string() {
            moved.push(MergePreviewDriftAxis::PrimaryHead);
        }
        if expected_source_head != source_head {
            moved.push(MergePreviewDriftAxis::SourceHead);
        }
        if !moved.is_empty() {
            return Err(MergePreviewFreshnessError::mismatch(moved));
        }

        Self {
            version: MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION,
            primary: MergePreviewPrimaryBinding {
                head: primary.head_string(),
                index_digest: primary.index_digest_string(),
                worktree_digest: primary.worktree_digest_string(),
            },
            source: MergePreviewSourceBinding {
                agent_id: candidate.metadata.agent_id.clone(),
                head: source_head,
            },
            candidate: MergePreviewCandidateBinding {
                snapshot_tree: candidate.snapshot_tree.to_string(),
                diff_oid: candidate.validation_binding.diff_oid.clone(),
            },
            base_preview: MergePreviewIdentityBinding {
                sha256: preview_identity_sha256(preview)?,
            },
        }
        .canonicalized()
    }

    pub fn canonicalized(mut self) -> Result<Self, MergePreviewFreshnessError> {
        if self.version != MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION {
            return Err(MergePreviewFreshnessError::UnsupportedWatermarkVersion {
                version: self.version,
                expected: MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION,
            });
        }
        let normalized_agent = normalize_agent_id(&self.source.agent_id).map_err(|source| {
            MergePreviewFreshnessError::malformed(format!("source.agent_id is invalid: {source:#}"))
        })?;
        if normalized_agent != self.source.agent_id {
            return Err(MergePreviewFreshnessError::malformed(
                "source.agent_id must be canonical",
            ));
        }
        self.primary.head = canonical_optional_oid(self.primary.head, "primary.head")?;
        self.primary.index_digest =
            canonical_optional_oid(self.primary.index_digest, "primary.index_digest")?;
        self.primary.worktree_digest =
            canonical_oid(self.primary.worktree_digest, "primary.worktree_digest")?;
        self.source.head = canonical_optional_oid(self.source.head, "source.head")?;
        self.candidate.snapshot_tree =
            canonical_oid(self.candidate.snapshot_tree, "candidate.snapshot_tree")?;
        self.candidate.diff_oid = canonical_oid(self.candidate.diff_oid, "candidate.diff_oid")?;
        self.base_preview.sha256 =
            canonical_sha256(self.base_preview.sha256, "base_preview.sha256")?;
        Ok(self)
    }

    pub fn drift_axes(&self, current: &Self) -> Vec<MergePreviewDriftAxis> {
        let mut axes = Vec::new();
        if self.primary.head != current.primary.head {
            axes.push(MergePreviewDriftAxis::PrimaryHead);
        }
        if self.primary.index_digest != current.primary.index_digest {
            axes.push(MergePreviewDriftAxis::PrimaryIndex);
        }
        if self.primary.worktree_digest != current.primary.worktree_digest {
            axes.push(MergePreviewDriftAxis::PrimaryWorktree);
        }
        if self.source.head != current.source.head {
            axes.push(MergePreviewDriftAxis::SourceHead);
        }
        if self.source.agent_id != current.source.agent_id {
            axes.push(MergePreviewDriftAxis::SourceIdentity);
        }
        if self.candidate.snapshot_tree != current.candidate.snapshot_tree {
            axes.push(MergePreviewDriftAxis::CandidateSnapshot);
        }
        if self.candidate.diff_oid != current.candidate.diff_oid {
            axes.push(MergePreviewDriftAxis::CandidateDiff);
        }
        if self.base_preview.sha256 != current.base_preview.sha256 {
            axes.push(MergePreviewDriftAxis::BasePreview);
        }
        axes
    }
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
        Err(MergePreviewFreshnessError::mismatch(axes))
    }
}

pub(crate) fn refuse_if_state_or_candidate_drifted(
    reviewed: &MergePreviewFreshnessWatermark,
    current: &MergePreviewFreshnessWatermark,
) -> Result<(), MergePreviewFreshnessError> {
    let reviewed = reviewed.clone().canonicalized()?;
    let current = current.clone().canonicalized()?;
    let axes = reviewed
        .drift_axes(&current)
        .into_iter()
        .filter(|axis| *axis != MergePreviewDriftAxis::BasePreview)
        .collect::<Vec<_>>();
    if axes.is_empty() {
        Ok(())
    } else {
        Err(MergePreviewFreshnessError::mismatch(axes))
    }
}

pub fn reviewed_merge_preview_watermark_from_json(
    value: &Value,
) -> Result<MergePreviewFreshnessWatermark, MergePreviewFreshnessError> {
    let object = value.as_object().ok_or_else(|| {
        MergePreviewFreshnessError::malformed(
            "expected either a full merge preview or a one-field freshness_watermark object",
        )
    })?;

    if let Some(watermark_value) = object.get("freshness_watermark") {
        let watermark = parse_watermark(watermark_value)?;
        if object.len() == 1 {
            return Ok(watermark);
        }
        let expected_keys = [
            "candidate",
            "freshness_watermark",
            "review_intent",
            "safety",
        ];
        if object.len() != expected_keys.len()
            || expected_keys.iter().any(|key| !object.contains_key(*key))
        {
            return Err(MergePreviewFreshnessError::malformed(
                "full merge preview must contain exactly candidate, safety, review_intent, and freshness_watermark",
            ));
        }
        let mut base_preview = value.clone();
        base_preview
            .as_object_mut()
            .ok_or_else(|| MergePreviewFreshnessError::malformed("preview must be an object"))?
            .remove("freshness_watermark");
        let supplied_preview_digest = json_identity_sha256(&base_preview)?;
        if supplied_preview_digest != watermark.base_preview.sha256 {
            return Err(MergePreviewFreshnessError::mismatch(vec![
                MergePreviewDriftAxis::BasePreview,
            ]));
        }
        return Ok(watermark);
    }

    Err(MergePreviewFreshnessError::malformed(
        "expected either a full merge preview or a one-field freshness_watermark object",
    ))
}

fn parse_watermark(
    value: &Value,
) -> Result<MergePreviewFreshnessWatermark, MergePreviewFreshnessError> {
    let object = value
        .as_object()
        .ok_or_else(|| MergePreviewFreshnessError::malformed("watermark must be a JSON object"))?;
    let version = object
        .get("version")
        .and_then(Value::as_u64)
        .and_then(|version| u32::try_from(version).ok())
        .ok_or_else(|| {
            MergePreviewFreshnessError::malformed(
                "watermark.version must be an unsigned 32-bit integer",
            )
        })?;
    if version != MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION {
        return Err(MergePreviewFreshnessError::UnsupportedWatermarkVersion {
            version,
            expected: MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION,
        });
    }
    let watermark: MergePreviewFreshnessWatermark =
        serde_json::from_value(value.clone()).map_err(|error| {
            MergePreviewFreshnessError::malformed(format!("watermark JSON is invalid: {error}"))
        })?;
    watermark.canonicalized()
}

fn preview_identity_sha256(
    preview: &MergeApplyPreview,
) -> Result<String, MergePreviewFreshnessError> {
    let value = serde_json::to_value(preview).map_err(|source| {
        MergePreviewFreshnessError::malformed(format!(
            "failed to serialize base preview identity: {source}"
        ))
    })?;
    json_identity_sha256(&value)
}

fn json_identity_sha256(value: &Value) -> Result<String, MergePreviewFreshnessError> {
    let mut bytes = REVIEWED_PREVIEW_DIGEST_DOMAIN.to_vec();
    append_canonical_json(value, &mut bytes)?;
    Ok(sha256_hex(&bytes))
}

fn append_canonical_json(
    value: &Value,
    output: &mut Vec<u8>,
) -> Result<(), MergePreviewFreshnessError> {
    match value {
        Value::Object(object) => {
            output.push(b'{');
            let mut keys = object.keys().collect::<Vec<_>>();
            keys.sort_unstable();
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                output.extend(serde_json::to_vec(key).map_err(|source| {
                    MergePreviewFreshnessError::malformed(format!(
                        "failed to encode preview object key: {source}"
                    ))
                })?);
                output.push(b':');
                append_canonical_json(&object[key], output)?;
            }
            output.push(b'}');
        }
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index > 0 {
                    output.push(b',');
                }
                append_canonical_json(value, output)?;
            }
            output.push(b']');
        }
        scalar => output.extend(serde_json::to_vec(scalar).map_err(|source| {
            MergePreviewFreshnessError::malformed(format!(
                "failed to encode preview scalar: {source}"
            ))
        })?),
    }
    Ok(())
}

fn head_oid_string(
    repo_path: &Path,
    label: &str,
) -> Result<Option<String>, MergePreviewFreshnessError> {
    let repo = crate::git_repository::open(repo_path).map_err(|source| {
        MergePreviewFreshnessError::malformed(format!("failed to open {label}: {source}"))
    })?;
    let result = match repo.head() {
        Ok(head) => Ok(Some(
            head.peel_to_commit()
                .map_err(|source| {
                    MergePreviewFreshnessError::malformed(format!(
                        "failed to read {label} commit: {source}"
                    ))
                })?
                .id()
                .to_string(),
        )),
        Err(error) if error.code() == git2::ErrorCode::UnbornBranch => Ok(None),
        Err(error) => Err(MergePreviewFreshnessError::malformed(format!(
            "failed to read {label}: {error}"
        ))),
    };
    result
}

fn canonical_optional_oid(
    value: Option<String>,
    field: &str,
) -> Result<Option<String>, MergePreviewFreshnessError> {
    value.map(|value| canonical_oid(value, field)).transpose()
}

fn canonical_oid(value: String, field: &str) -> Result<String, MergePreviewFreshnessError> {
    let oid = Oid::from_str(&value).map_err(|_| {
        MergePreviewFreshnessError::malformed(format!("{field} must be a Git object id"))
    })?;
    let canonical = oid.to_string();
    if canonical != value {
        return Err(MergePreviewFreshnessError::malformed(format!(
            "{field} must use its canonical 40-character lowercase form"
        )));
    }
    Ok(canonical)
}

fn canonical_sha256(value: String, field: &str) -> Result<String, MergePreviewFreshnessError> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(MergePreviewFreshnessError::malformed(format!(
            "{field} must be 64 lowercase hexadecimal characters"
        )));
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn watermark() -> MergePreviewFreshnessWatermark {
        let oid = "1111111111111111111111111111111111111111".to_string();
        MergePreviewFreshnessWatermark {
            version: MERGE_PREVIEW_FRESHNESS_WATERMARK_VERSION,
            primary: MergePreviewPrimaryBinding {
                head: Some(oid.clone()),
                index_digest: Some("2222222222222222222222222222222222222222".to_string()),
                worktree_digest: "3333333333333333333333333333333333333333".to_string(),
            },
            source: MergePreviewSourceBinding {
                agent_id: "agent-a".to_string(),
                head: Some(oid),
            },
            candidate: MergePreviewCandidateBinding {
                snapshot_tree: "4444444444444444444444444444444444444444".to_string(),
                diff_oid: "5555555555555555555555555555555555555555".to_string(),
            },
            base_preview: MergePreviewIdentityBinding {
                sha256: "66".repeat(32),
            },
        }
    }

    #[test]
    fn reviewed_watermark_reports_every_independent_drift_axis() {
        macro_rules! assert_only_axis {
            ($axis:expr, $mutate:expr) => {{
                let reviewed = watermark();
                let mut current = reviewed.clone();
                $mutate(&mut current);
                let error =
                    refuse_if_drifted(&reviewed, &current).expect_err("one-axis drift must refuse");
                assert_eq!(error.drift_axes(), &[$axis]);
            }};
        }

        assert_only_axis!(
            MergePreviewDriftAxis::PrimaryHead,
            |current: &mut MergePreviewFreshnessWatermark| {
                current.primary.head = None;
            }
        );
        assert_only_axis!(
            MergePreviewDriftAxis::PrimaryIndex,
            |current: &mut MergePreviewFreshnessWatermark| {
                current.primary.index_digest = None;
            }
        );
        assert_only_axis!(
            MergePreviewDriftAxis::PrimaryWorktree,
            |current: &mut MergePreviewFreshnessWatermark| {
                current.primary.worktree_digest = "7777777777777777777777777777777777777777".into();
            }
        );
        assert_only_axis!(
            MergePreviewDriftAxis::SourceHead,
            |current: &mut MergePreviewFreshnessWatermark| {
                current.source.head = None;
            }
        );
        assert_only_axis!(
            MergePreviewDriftAxis::SourceIdentity,
            |current: &mut MergePreviewFreshnessWatermark| {
                current.source.agent_id = "agent-b".into();
            }
        );
        assert_only_axis!(
            MergePreviewDriftAxis::CandidateSnapshot,
            |current: &mut MergePreviewFreshnessWatermark| {
                current.candidate.snapshot_tree = "8888888888888888888888888888888888888888".into();
            }
        );
        assert_only_axis!(
            MergePreviewDriftAxis::CandidateDiff,
            |current: &mut MergePreviewFreshnessWatermark| {
                current.candidate.diff_oid = "9999999999999999999999999999999999999999".into();
            }
        );
        assert_only_axis!(
            MergePreviewDriftAxis::BasePreview,
            |current: &mut MergePreviewFreshnessWatermark| {
                current.base_preview.sha256 = "aa".repeat(32);
            }
        );
    }

    #[test]
    fn watermark_parser_rejects_unknown_missing_and_unsupported_versions() {
        let mut unknown = serde_json::to_value(watermark()).expect("watermark value");
        unknown["primary"]["unknown"] = Value::Bool(true);
        assert!(reviewed_merge_preview_watermark_from_json(&unknown).is_err());

        let missing = serde_json::json!({"candidate": {}, "safety": {}});
        assert!(reviewed_merge_preview_watermark_from_json(&missing).is_err());

        let mut unsupported = watermark();
        unsupported.version = 99;
        let unsupported = serde_json::json!({"freshness_watermark": unsupported});
        let error = reviewed_merge_preview_watermark_from_json(&unsupported)
            .expect_err("unsupported version");
        assert!(matches!(
            error,
            MergePreviewFreshnessError::UnsupportedWatermarkVersion { version: 99, .. }
        ));

        let raw = serde_json::to_value(watermark()).expect("raw watermark value");
        let error = reviewed_merge_preview_watermark_from_json(&raw)
            .expect_err("raw watermark must be malformed");
        assert!(matches!(
            error,
            MergePreviewFreshnessError::MalformedWatermark { .. }
        ));
    }

    #[test]
    fn nested_watermark_is_accepted_and_tampered_full_preview_is_substituted() {
        let watermark = watermark();
        let nested = serde_json::json!({"freshness_watermark": watermark});
        let parsed = reviewed_merge_preview_watermark_from_json(&nested)
            .expect("nested freshness watermark");
        assert_eq!(parsed.source.agent_id, "agent-a");

        let full = serde_json::json!({
            "candidate": {"changed_paths": ["README.md"]},
            "safety": {"readiness": "safe"},
            "review_intent": {},
            "freshness_watermark": parsed,
        });
        let error = reviewed_merge_preview_watermark_from_json(&full)
            .expect_err("full preview not matching its digest must be refused");
        assert_eq!(error.drift_axes(), &[MergePreviewDriftAxis::BasePreview]);
        assert_eq!(
            error.binding_status(),
            MergeReviewBindingStatus::Substituted
        );
    }

    #[test]
    fn merge_preview_v2_valid_fixture_digest_matches_semantic_base_preview() {
        let mut report: Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/fixtures/schemas/merge-preview-report-v2.valid.json"
        )))
        .expect("merge preview v2 valid fixture");
        let watermark: MergePreviewFreshnessWatermark =
            reviewed_merge_preview_watermark_from_json(&report)
                .expect("fixture must contain a semantically current base preview digest");
        report
            .as_object_mut()
            .expect("merge preview fixture must be an object")
            .remove("freshness_watermark")
            .expect("merge preview fixture must contain a freshness watermark");

        let recomputed_digest =
            json_identity_sha256(&report).expect("recompute fixture base preview digest");

        assert_eq!(watermark.base_preview.sha256, recomputed_digest);
    }

    #[test]
    fn refusal_envelope_preserves_status_and_precise_axes() {
        let error = MergePreviewFreshnessError::mismatch(vec![
            MergePreviewDriftAxis::PrimaryIndex,
            MergePreviewDriftAxis::PrimaryWorktree,
        ]);
        let envelope = MergeApplyReviewRefusalEnvelope::from_error(&error);
        let value = serde_json::to_value(envelope).expect("serialize refusal");
        assert_eq!(value["version"], MERGE_APPLY_REVIEW_REFUSAL_VERSION);
        assert_eq!(value["status"], "refused");
        assert_eq!(value["review_bound"], false);
        assert_eq!(value["review_binding_status"], "stale");
        assert_eq!(value["refusal"]["axes"][0], "primary_index");
        assert_eq!(value["refusal"]["axes"][1], "primary_worktree");
    }
}
