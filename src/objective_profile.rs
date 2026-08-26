//! Versioned operator-tunable objective profiles for evaluation and selection.
//!
//! Pareto dominance stays preference-free. A profile names the weights that turn
//! a frontier into an auditable choice.

use crate::safe_state::BoundedRegularReader;
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, path::Path};

pub const OBJECTIVE_PROFILE_OVERRIDE_FILE: &str = "maco-objective-profiles.json";
pub const DEFAULT_OBJECTIVE_PROFILE_ID: &str = "maco-default-objective-v2";
pub const DEFAULT_OBJECTIVE_PROFILE_VERSION: u32 = 2;
pub const HELD_OUT_WEIGHT_PERCENT: u32 = 50;
pub const BREADTH_WEIGHT_PERCENT: u32 = 25;
pub const ANTI_SHORTCUT_WEIGHT_PERCENT: u32 = 25;
pub const DEFAULT_MODEL_CHANGE_SWITCH_COST_MICROUNITS: u64 = 10_000;
pub const DEFAULT_RUNTIME_CHANGE_SWITCH_COST_MICROUNITS: u64 = 25_000;

const OBJECTIVE_PROFILE_DOCUMENT_SCHEMA_VERSION: u32 = 1;
const MAX_OBJECTIVE_PROFILE_FILE_BYTES: u64 = 256 * 1024;
const MAX_OBJECTIVE_PROFILES: usize = 64;
const MAX_OBJECTIVE_PROFILE_ID_BYTES: usize = 128;

/// Strict repository-local objective-profile override document.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveProfileDocument {
    pub schema_version: u32,
    pub profiles: Vec<ObjectiveProfile>,
}

/// Provenance of the immutable effective profile recorded in run evidence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ObjectiveProfileSource {
    BuiltIn,
    RepositoryOverride,
}

/// Fully resolved objective-profile evidence. The binding contains all
/// effective weights, so later edits to the override file cannot change it.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResolvedObjectiveProfile {
    pub profile: ObjectiveProfileBinding,
    pub source: ObjectiveProfileSource,
}

/// Named, versioned weights over quality components and non-quality axes.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveProfile {
    pub id: String,
    pub version: u32,
    pub quality: QualityWeights,
    #[serde(default)]
    pub tradeoffs: TradeoffWeights,
    #[serde(default = "historical_zero_switch_costs")]
    pub switch_costs: ContextSwitchCosts,
}

/// Conservative, operator-tunable re-priming costs for automatic routing.
///
/// An omitted historical field decodes to zero through the explicit serde
/// default on its containing profile. New default profiles use [`Self::default`]
/// and therefore opt into the conservative nonzero values.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ContextSwitchCosts {
    pub model_change_same_runtime_microunits: u64,
    pub runtime_change_microunits: u64,
}

impl ContextSwitchCosts {
    pub const fn zero() -> Self {
        Self {
            model_change_same_runtime_microunits: 0,
            runtime_change_microunits: 0,
        }
    }
}

impl Default for ContextSwitchCosts {
    fn default() -> Self {
        Self {
            model_change_same_runtime_microunits: DEFAULT_MODEL_CHANGE_SWITCH_COST_MICROUNITS,
            runtime_change_microunits: DEFAULT_RUNTIME_CHANGE_SWITCH_COST_MICROUNITS,
        }
    }
}

pub(crate) const fn historical_zero_switch_costs() -> ContextSwitchCosts {
    ContextSwitchCosts::zero()
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct QualityWeights {
    pub held_out_percent: u32,
    pub breadth_percent: u32,
    pub anti_shortcut_percent: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TradeoffWeights {
    #[serde(default = "default_cost_weight")]
    pub monetary_cost_percent: u32,
    #[serde(default)]
    pub quota_consumption_percent: u32,
    #[serde(default)]
    pub latency_percent: u32,
    #[serde(default)]
    pub retry_rework_percent: u32,
    #[serde(default)]
    pub human_review_percent: u32,
}

const fn default_cost_weight() -> u32 {
    100
}

impl Default for TradeoffWeights {
    fn default() -> Self {
        Self {
            monetary_cost_percent: 100,
            quota_consumption_percent: 0,
            latency_percent: 0,
            retry_rework_percent: 0,
            human_review_percent: 0,
        }
    }
}

/// Binding recorded beside an experiment so re-weighting cannot silently
/// invalidate past conclusions.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveProfileBinding {
    pub id: String,
    pub version: u32,
    pub content_hash: String,
    pub quality: QualityWeights,
    pub tradeoffs: TradeoffWeights,
    #[serde(default = "historical_zero_switch_costs")]
    pub switch_costs: ContextSwitchCosts,
}

impl Default for ObjectiveProfile {
    fn default() -> Self {
        default_objective_profile()
    }
}

pub fn default_objective_profile() -> ObjectiveProfile {
    ObjectiveProfile {
        id: DEFAULT_OBJECTIVE_PROFILE_ID.to_string(),
        version: DEFAULT_OBJECTIVE_PROFILE_VERSION,
        quality: QualityWeights {
            held_out_percent: HELD_OUT_WEIGHT_PERCENT,
            breadth_percent: BREADTH_WEIGHT_PERCENT,
            anti_shortcut_percent: ANTI_SHORTCUT_WEIGHT_PERCENT,
        },
        tradeoffs: TradeoffWeights::default(),
        switch_costs: ContextSwitchCosts::default(),
    }
}

/// Return the built-in objective as the same immutable resolved object used by
/// repository overrides and downstream evaluation/selection consumers.
pub fn default_resolved_objective_profile() -> Result<ResolvedObjectiveProfile> {
    Ok(ResolvedObjectiveProfile {
        profile: default_objective_profile().binding()?,
        source: ObjectiveProfileSource::BuiltIn,
    })
}

impl ObjectiveProfile {
    pub fn validate(&self) -> Result<()> {
        validate_objective_profile_id(&self.id)?;
        if self.version == 0 {
            bail!("objective profile version must be greater than zero");
        }
        validate_weight("quality.held_out_percent", self.quality.held_out_percent)?;
        validate_weight("quality.breadth_percent", self.quality.breadth_percent)?;
        validate_weight(
            "quality.anti_shortcut_percent",
            self.quality.anti_shortcut_percent,
        )?;
        let quality_total = self
            .quality
            .held_out_percent
            .checked_add(self.quality.breadth_percent)
            .and_then(|total| total.checked_add(self.quality.anti_shortcut_percent))
            .context("objective quality weights overflowed")?;
        if quality_total != 100 {
            bail!("objective quality weights must sum to 100, got {quality_total}");
        }
        validate_weight(
            "tradeoffs.monetary_cost_percent",
            self.tradeoffs.monetary_cost_percent,
        )?;
        validate_weight(
            "tradeoffs.quota_consumption_percent",
            self.tradeoffs.quota_consumption_percent,
        )?;
        validate_weight("tradeoffs.latency_percent", self.tradeoffs.latency_percent)?;
        validate_weight(
            "tradeoffs.retry_rework_percent",
            self.tradeoffs.retry_rework_percent,
        )?;
        validate_weight(
            "tradeoffs.human_review_percent",
            self.tradeoffs.human_review_percent,
        )?;
        let tradeoff_total = self
            .tradeoffs
            .monetary_cost_percent
            .checked_add(self.tradeoffs.quota_consumption_percent)
            .and_then(|total| total.checked_add(self.tradeoffs.latency_percent))
            .and_then(|total| total.checked_add(self.tradeoffs.retry_rework_percent))
            .and_then(|total| total.checked_add(self.tradeoffs.human_review_percent))
            .context("objective tradeoff weights overflowed")?;
        if tradeoff_total != 100 {
            bail!("objective tradeoff weights must sum to 100, got {tradeoff_total}");
        }
        Ok(())
    }

    pub fn content_hash(&self) -> Result<String> {
        let payload = serde_json::to_vec(self).context("failed to serialize objective profile")?;
        Ok(crate::artifacts::state_auth::sha256_hex(&payload))
    }

    pub fn binding(&self) -> Result<ObjectiveProfileBinding> {
        self.validate()?;
        Ok(ObjectiveProfileBinding {
            id: self.id.clone(),
            version: self.version,
            content_hash: self.content_hash()?,
            quality: self.quality.clone(),
            tradeoffs: self.tradeoffs.clone(),
            switch_costs: self.switch_costs.clone(),
        })
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let profile: Self =
            serde_json::from_slice(bytes).context("objective profile is not valid JSON")?;
        profile.validate()?;
        Ok(profile)
    }

    pub fn overall_quality_basis_points(
        &self,
        held_out_basis_points: u32,
        breadth_basis_points: u32,
        anti_shortcut_basis_points: u32,
    ) -> u32 {
        let weighted = u64::from(held_out_basis_points) * u64::from(self.quality.held_out_percent)
            + u64::from(breadth_basis_points) * u64::from(self.quality.breadth_percent)
            + u64::from(anti_shortcut_basis_points) * u64::from(self.quality.anti_shortcut_percent);
        (weighted / 100) as u32
    }
}

impl ObjectiveProfileBinding {
    /// Verifies both the effective values and their immutable content binding.
    pub fn validate(&self) -> Result<()> {
        let profile = ObjectiveProfile {
            id: self.id.clone(),
            version: self.version,
            quality: self.quality.clone(),
            tradeoffs: self.tradeoffs.clone(),
            switch_costs: self.switch_costs.clone(),
        };
        profile.validate()?;
        if self.content_hash.len() != 64
            || !self
                .content_hash
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            bail!("objective profile content hash must be a lowercase SHA-256 digest");
        }
        let actual = profile.content_hash()?;
        if self.content_hash != actual {
            bail!("objective profile content hash does not match its effective values");
        }
        Ok(())
    }
}

impl ObjectiveProfileDocument {
    pub fn validate(&self) -> Result<()> {
        if self.schema_version != OBJECTIVE_PROFILE_DOCUMENT_SCHEMA_VERSION {
            bail!(
                "unsupported objective profile document schema version {} (expected {})",
                self.schema_version,
                OBJECTIVE_PROFILE_DOCUMENT_SCHEMA_VERSION
            );
        }
        if self.profiles.len() > MAX_OBJECTIVE_PROFILES {
            bail!("objective profile document exceeds the {MAX_OBJECTIVE_PROFILES}-profile limit");
        }
        let mut ids = std::collections::BTreeSet::new();
        for profile in &self.profiles {
            profile
                .validate()
                .with_context(|| format!("objective profile '{}' is invalid", profile.id))?;
            if !ids.insert(profile.id.as_str()) {
                bail!("objective profile document repeats id '{}'", profile.id);
            }
        }
        Ok(())
    }

    pub fn from_json(bytes: &[u8]) -> Result<Self> {
        let document: Self = serde_json::from_slice(bytes)
            .context("objective profile override document is not valid strict JSON")?;
        document.validate()?;
        Ok(document)
    }
}

/// Resolves a requested profile against the strict repository override and
/// built-ins. A matching repository entry wins; otherwise the built-in is
/// used; an unknown id fails closed.
pub fn resolve_objective_profile(
    repo: &Path,
    requested_id: Option<&str>,
) -> Result<ResolvedObjectiveProfile> {
    let requested_id = requested_id.unwrap_or(DEFAULT_OBJECTIVE_PROFILE_ID);
    validate_objective_profile_id(requested_id)
        .context("requested objective profile id is invalid")?;

    let override_document = read_objective_profile_override(repo)?
        .map(|bytes| ObjectiveProfileDocument::from_json(&bytes))
        .transpose()?;

    if let Some(profile) = override_document.as_ref().and_then(|document| {
        document
            .profiles
            .iter()
            .find(|profile| profile.id == requested_id)
    }) {
        return Ok(ResolvedObjectiveProfile {
            profile: profile.binding()?,
            source: ObjectiveProfileSource::RepositoryOverride,
        });
    }

    let built_in = default_objective_profile();
    if built_in.id == requested_id {
        return Ok(ResolvedObjectiveProfile {
            profile: built_in.binding()?,
            source: ObjectiveProfileSource::BuiltIn,
        });
    }

    bail!("unknown objective profile id '{requested_id}'")
}

fn read_objective_profile_override(repo: &Path) -> Result<Option<Vec<u8>>> {
    match BoundedRegularReader::read_relative(
        repo,
        OBJECTIVE_PROFILE_OVERRIDE_FILE,
        MAX_OBJECTIVE_PROFILE_FILE_BYTES,
    ) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error)
            if error
                .root_cause()
                .downcast_ref::<std::io::Error>()
                .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to read bounded repository objective profile override {OBJECTIVE_PROFILE_OVERRIDE_FILE}"
            )
        }),
    }
}

fn validate_objective_profile_id(id: &str) -> Result<()> {
    if id.is_empty() || id.len() > MAX_OBJECTIVE_PROFILE_ID_BYTES || id.trim() != id {
        bail!(
            "objective profile id must be trimmed and contain 1 to {MAX_OBJECTIVE_PROFILE_ID_BYTES} bytes"
        );
    }
    let bytes = id.as_bytes();
    if !bytes[0].is_ascii_alphanumeric()
        || !bytes[bytes.len() - 1].is_ascii_alphanumeric()
        || !bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(*byte, b'-' | b'_' | b'.'))
    {
        bail!(
            "objective profile id must be ASCII alphanumeric with only internal '.', '-', or '_' separators"
        );
    }
    Ok(())
}

fn validate_weight(name: &str, value: u32) -> Result<()> {
    if value > 100 {
        bail!("objective profile {name} must be between 0 and 100, got {value}");
    }
    Ok(())
}

/// Preference-bearing score used only after Pareto evidence is computed.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ObjectiveSelection {
    pub profile_id: String,
    pub profile_hash: String,
    pub selected_profile_id: String,
    pub selected_score: f64,
    pub runner_up_profile_id: Option<String>,
    pub runner_up_score: Option<f64>,
    pub scores: BTreeMap<String, f64>,
}

/// Choose one frontier point using the profile. Empty frontiers yield `None`.
pub fn select_from_frontier(
    profile: &ResolvedObjectiveProfile,
    points: &[(String, FrontierAxes)],
) -> Result<Option<ObjectiveSelection>> {
    profile.profile.validate()?;
    if points.is_empty() {
        return Ok(None);
    }
    let mut scores = BTreeMap::new();
    let mut ranked = Vec::new();
    for (id, axes) in points {
        if let Err(error) = axes.validate() {
            bail!("frontier point '{id}' has invalid objective evidence: {error:#}");
        }
        let score = profile.profile.score_axes(axes);
        scores.insert(id.clone(), score);
        ranked.push((id.clone(), score));
    }
    ranked.sort_by(|left, right| {
        left.1
            .total_cmp(&right.1)
            .then_with(|| left.0.cmp(&right.0))
    });
    let selected = ranked
        .first()
        .cloned()
        .context("objective frontier unexpectedly became empty while ranking")?;
    let runner_up = ranked.get(1).cloned();
    Ok(Some(ObjectiveSelection {
        profile_id: profile.profile.id.clone(),
        profile_hash: profile.profile.content_hash.clone(),
        selected_profile_id: selected.0,
        selected_score: selected.1,
        runner_up_profile_id: runner_up.as_ref().map(|(id, _)| id.clone()),
        runner_up_score: runner_up.map(|(_, score)| score),
        scores,
    }))
}

/// Normalized axes used by the selection policy. Lower is better.
#[derive(Debug, Clone, Copy, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FrontierAxes {
    /// Raw preference-free evaluation quality evidence. Higher is better.
    pub held_out_quality_basis_points: u32,
    pub breadth_quality_basis_points: u32,
    pub anti_shortcut_quality_basis_points: u32,
    /// Normalized operational/economic evidence in `[0, 1]`. Lower is better.
    pub monetary_cost: f64,
    pub quota_consumption: f64,
    pub latency: f64,
    pub retry_rework: f64,
    pub human_review: f64,
}

impl FrontierAxes {
    fn validate(&self) -> Result<()> {
        for (name, value) in [
            (
                "held_out_quality_basis_points",
                self.held_out_quality_basis_points,
            ),
            (
                "breadth_quality_basis_points",
                self.breadth_quality_basis_points,
            ),
            (
                "anti_shortcut_quality_basis_points",
                self.anti_shortcut_quality_basis_points,
            ),
        ] {
            if value > 10_000 {
                bail!("{name} must be at most 10000, got {value}");
            }
        }
        for (name, value) in [
            ("monetary_cost", self.monetary_cost),
            ("quota_consumption", self.quota_consumption),
            ("latency", self.latency),
            ("retry_rework", self.retry_rework),
            ("human_review", self.human_review),
        ] {
            if !value.is_finite() || !(0.0..=1.0).contains(&value) {
                bail!("{name} must be a finite normalized value between 0 and 1");
            }
        }
        Ok(())
    }
}

impl ObjectiveProfileBinding {
    fn score_axes(&self, axes: &FrontierAxes) -> f64 {
        let held_out_loss = f64::from(10_000 - axes.held_out_quality_basis_points) / 10_000.0;
        let breadth_loss = f64::from(10_000 - axes.breadth_quality_basis_points) / 10_000.0;
        let anti_shortcut_loss =
            f64::from(10_000 - axes.anti_shortcut_quality_basis_points) / 10_000.0;
        let quality_loss = (held_out_loss * f64::from(self.quality.held_out_percent)
            + breadth_loss * f64::from(self.quality.breadth_percent)
            + anti_shortcut_loss * f64::from(self.quality.anti_shortcut_percent))
            / 100.0;
        let tradeoff_loss = (axes.monetary_cost * f64::from(self.tradeoffs.monetary_cost_percent)
            + axes.quota_consumption * f64::from(self.tradeoffs.quota_consumption_percent)
            + axes.latency * f64::from(self.tradeoffs.latency_percent)
            + axes.retry_rework * f64::from(self.tradeoffs.retry_rework_percent)
            + axes.human_review * f64::from(self.tradeoffs.human_review_percent))
            / 100.0;
        (quality_loss + tradeoff_loss) / 2.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn repository_override_profile(id: &str) -> ObjectiveProfile {
        ObjectiveProfile {
            id: id.to_string(),
            version: 7,
            quality: QualityWeights {
                held_out_percent: 40,
                breadth_percent: 35,
                anti_shortcut_percent: 25,
            },
            tradeoffs: TradeoffWeights {
                monetary_cost_percent: 50,
                quota_consumption_percent: 20,
                latency_percent: 15,
                retry_rework_percent: 10,
                human_review_percent: 5,
            },
            switch_costs: ContextSwitchCosts::default(),
        }
    }

    fn write_override(repo: &Path, profiles: Vec<ObjectiveProfile>) {
        let document = ObjectiveProfileDocument {
            schema_version: OBJECTIVE_PROFILE_DOCUMENT_SCHEMA_VERSION,
            profiles,
        };
        fs::write(
            repo.join(OBJECTIVE_PROFILE_OVERRIDE_FILE),
            serde_json::to_vec_pretty(&document).expect("serialize override"),
        )
        .expect("write override");
    }

    #[test]
    fn default_profile_reproduces_50_25_25_and_hashes_stably() {
        let profile = default_objective_profile();
        profile.validate().expect("default");
        assert_eq!(profile.quality.held_out_percent, 50);
        assert_eq!(profile.quality.breadth_percent, 25);
        assert_eq!(profile.quality.anti_shortcut_percent, 25);
        assert_eq!(profile.tradeoffs, TradeoffWeights::default());
        assert_eq!(profile.overall_quality_basis_points(10_000, 0, 0), 5_000);
        assert_eq!(profile.overall_quality_basis_points(0, 10_000, 0), 2_500);
        assert_eq!(profile.overall_quality_basis_points(0, 0, 10_000), 2_500);
        let first = profile.content_hash().expect("hash");
        let second = profile.content_hash().expect("hash");
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert_eq!(profile.id, "maco-default-objective-v2");
        assert_eq!(profile.version, 2);
        assert_eq!(
            profile.switch_costs,
            ContextSwitchCosts {
                model_change_same_runtime_microunits: 10_000,
                runtime_change_microunits: 25_000,
            }
        );
        assert_eq!(
            profile.binding().expect("binding").switch_costs,
            profile.switch_costs
        );

        let binding = profile.binding().expect("binding");
        binding.validate().expect("valid binding");
        let encoded = serde_json::to_vec(&binding).expect("serialize binding");
        let decoded: ObjectiveProfileBinding =
            serde_json::from_slice(&encoded).expect("deserialize binding");
        assert_eq!(decoded, binding);
        decoded.validate().expect("round-tripped binding");
    }

    #[test]
    fn absent_override_and_omitted_selector_resolve_built_in_default() {
        let repo = tempfile::tempdir().expect("repo");
        let resolved = resolve_objective_profile(repo.path(), None).expect("resolve default");
        assert_eq!(resolved.source, ObjectiveProfileSource::BuiltIn);
        assert_eq!(resolved.profile.id, DEFAULT_OBJECTIVE_PROFILE_ID);
        assert_eq!(resolved.profile.version, DEFAULT_OBJECTIVE_PROFILE_VERSION);
        assert_eq!(resolved.profile.quality.held_out_percent, 50);
        resolved.profile.validate().expect("valid evidence");
        assert_eq!(
            serde_json::to_value(resolved.source).expect("source JSON"),
            serde_json::json!("built_in")
        );
    }

    #[test]
    fn repository_override_has_precedence_and_records_source() {
        let repo = tempfile::tempdir().expect("repo");
        let profile = repository_override_profile(DEFAULT_OBJECTIVE_PROFILE_ID);
        write_override(repo.path(), vec![profile.clone()]);

        let resolved = resolve_objective_profile(repo.path(), None).expect("resolve override");
        assert_eq!(resolved.source, ObjectiveProfileSource::RepositoryOverride);
        assert_eq!(
            resolved.profile,
            profile.binding().expect("expected binding")
        );
        assert_eq!(
            serde_json::to_value(resolved.source).expect("source JSON"),
            serde_json::json!("repository_override")
        );
    }

    #[test]
    fn unknown_selected_profile_fails_closed() {
        let repo = tempfile::tempdir().expect("repo");
        write_override(repo.path(), vec![repository_override_profile("known-v1")]);
        let error = resolve_objective_profile(repo.path(), Some("missing-v1"))
            .expect_err("unknown profile must fail");
        assert!(error.to_string().contains("unknown objective profile"));
    }

    #[test]
    fn strict_document_rejects_schema_fields_duplicates_and_invalid_values() {
        let invalid_documents = [
            r#"{"schema_version":2,"profiles":[]}"#,
            r#"{"schema_version":1,"profiles":[],"extra":true}"#,
            r#"{"schema_version":1,"profiles":[{"id":"valid-v1","version":1,"quality":{"held_out_percent":50,"breadth_percent":25,"anti_shortcut_percent":25,"extra":0}}]}"#,
            r#"{"schema_version":1,"profiles":[{"id":"duplicate-v1","version":1,"quality":{"held_out_percent":50,"breadth_percent":25,"anti_shortcut_percent":25}},{"id":"duplicate-v1","version":2,"quality":{"held_out_percent":50,"breadth_percent":25,"anti_shortcut_percent":25}}]}"#,
            r#"{"schema_version":1,"profiles":[{"id":" invalid","version":1,"quality":{"held_out_percent":50,"breadth_percent":25,"anti_shortcut_percent":25}}]}"#,
            r#"{"schema_version":1,"profiles":[{"id":"zero-version","version":0,"quality":{"held_out_percent":50,"breadth_percent":25,"anti_shortcut_percent":25}}]}"#,
            r#"{"schema_version":1,"profiles":[{"id":"bad-sum","version":1,"quality":{"held_out_percent":49,"breadth_percent":25,"anti_shortcut_percent":25}}]}"#,
            r#"{"schema_version":1,"profiles":[{"id":"bad-bound","version":1,"quality":{"held_out_percent":101,"breadth_percent":0,"anti_shortcut_percent":0}}]}"#,
            r#"{"schema_version":1,"profiles":[{"id":"overflow","version":4294967296,"quality":{"held_out_percent":50,"breadth_percent":25,"anti_shortcut_percent":25}}]}"#,
        ];
        for document in invalid_documents {
            ObjectiveProfileDocument::from_json(document.as_bytes())
                .expect_err("invalid strict document must fail");
        }
    }

    #[cfg(unix)]
    #[test]
    fn override_loading_rejects_links_directories_and_oversize_files() {
        use std::os::unix::fs::symlink;

        let repo = tempfile::tempdir().expect("repo");
        let override_path = repo.path().join(OBJECTIVE_PROFILE_OVERRIDE_FILE);
        let external = tempfile::NamedTempFile::new().expect("external override");
        fs::write(external.path(), br#"{"schema_version":1,"profiles":[]}"#)
            .expect("write external");

        symlink(external.path(), &override_path).expect("symlink override");
        assert!(resolve_objective_profile(repo.path(), None).is_err());
        fs::remove_file(&override_path).expect("remove symlink");

        fs::hard_link(external.path(), &override_path).expect("hardlink override");
        assert!(resolve_objective_profile(repo.path(), None).is_err());
        fs::remove_file(&override_path).expect("remove hardlink");

        fs::create_dir(&override_path).expect("directory override");
        assert!(resolve_objective_profile(repo.path(), None).is_err());
        fs::remove_dir(&override_path).expect("remove directory");

        fs::write(
            &override_path,
            vec![b' '; usize::try_from(MAX_OBJECTIVE_PROFILE_FILE_BYTES + 1).expect("test size")],
        )
        .expect("write oversized override");
        assert!(resolve_objective_profile(repo.path(), None).is_err());
    }

    #[test]
    fn selection_records_profile_hash_and_runner_up() {
        let profile = default_resolved_objective_profile().expect("resolved default profile");
        let selection = select_from_frontier(
            &profile,
            &[
                (
                    "cheap".to_string(),
                    FrontierAxes {
                        held_out_quality_basis_points: 9_000,
                        breadth_quality_basis_points: 9_000,
                        anti_shortcut_quality_basis_points: 9_000,
                        monetary_cost: 0.1,
                        quota_consumption: 0.0,
                        latency: 0.0,
                        retry_rework: 0.0,
                        human_review: 0.0,
                    },
                ),
                (
                    "expensive".to_string(),
                    FrontierAxes {
                        held_out_quality_basis_points: 9_000,
                        breadth_quality_basis_points: 9_000,
                        anti_shortcut_quality_basis_points: 9_000,
                        monetary_cost: 0.9,
                        quota_consumption: 0.0,
                        latency: 0.0,
                        retry_rework: 0.0,
                        human_review: 0.0,
                    },
                ),
            ],
        )
        .expect("select")
        .expect("non-empty");
        assert_eq!(selection.selected_profile_id, "cheap");
        assert_eq!(selection.runner_up_profile_id.as_deref(), Some("expensive"));
        assert_eq!(selection.profile_id, DEFAULT_OBJECTIVE_PROFILE_ID);
        assert_eq!(selection.profile_hash, profile.profile.content_hash);

        let round_trip: ObjectiveSelection = serde_json::from_value(
            serde_json::to_value(&selection).expect("serialize objective selection"),
        )
        .expect("deserialize objective selection");
        assert_eq!(round_trip, selection);
    }

    #[test]
    fn explicit_frontier_policy_uses_raw_quality_axes_after_frontier_construction() {
        let profile = default_resolved_objective_profile().expect("resolved default profile");
        let selection = select_from_frontier(
            &profile,
            &[
                (
                    "quality".to_string(),
                    FrontierAxes {
                        held_out_quality_basis_points: 10_000,
                        breadth_quality_basis_points: 10_000,
                        anti_shortcut_quality_basis_points: 10_000,
                        monetary_cost: 0.1,
                        quota_consumption: 0.0,
                        latency: 0.0,
                        retry_rework: 0.0,
                        human_review: 0.0,
                    },
                ),
                (
                    "cheap-low-quality".to_string(),
                    FrontierAxes {
                        held_out_quality_basis_points: 0,
                        breadth_quality_basis_points: 0,
                        anti_shortcut_quality_basis_points: 0,
                        monetary_cost: 0.0,
                        quota_consumption: 0.0,
                        latency: 0.0,
                        retry_rework: 0.0,
                        human_review: 0.0,
                    },
                ),
            ],
        )
        .expect("select")
        .expect("non-empty");

        assert_eq!(selection.selected_profile_id, "quality");
    }

    #[test]
    fn quality_component_weights_change_policy_choice_from_raw_evidence() {
        let default = default_resolved_objective_profile().expect("resolved default profile");
        let points = [
            (
                "held-out".to_string(),
                FrontierAxes {
                    held_out_quality_basis_points: 10_000,
                    breadth_quality_basis_points: 0,
                    anti_shortcut_quality_basis_points: 5_000,
                    monetary_cost: 0.0,
                    quota_consumption: 0.0,
                    latency: 0.0,
                    retry_rework: 0.0,
                    human_review: 0.0,
                },
            ),
            (
                "breadth".to_string(),
                FrontierAxes {
                    held_out_quality_basis_points: 0,
                    breadth_quality_basis_points: 10_000,
                    anti_shortcut_quality_basis_points: 5_000,
                    monetary_cost: 0.0,
                    quota_consumption: 0.0,
                    latency: 0.0,
                    retry_rework: 0.0,
                    human_review: 0.0,
                },
            ),
        ];
        let default_selection = select_from_frontier(&default, &points)
            .expect("default selection")
            .expect("non-empty");
        assert_eq!(default_selection.selected_profile_id, "held-out");

        let mut breadth_profile = default_objective_profile();
        breadth_profile.id = "breadth-first-v1".to_string();
        breadth_profile.quality = QualityWeights {
            held_out_percent: 10,
            breadth_percent: 80,
            anti_shortcut_percent: 10,
        };
        let breadth = ResolvedObjectiveProfile {
            profile: breadth_profile.binding().expect("breadth profile binding"),
            source: ObjectiveProfileSource::RepositoryOverride,
        };
        let breadth_selection = select_from_frontier(&breadth, &points)
            .expect("breadth selection")
            .expect("non-empty");
        assert_eq!(breadth_selection.selected_profile_id, "breadth");
        assert_ne!(
            default_selection.profile_hash,
            breadth_selection.profile_hash
        );
    }

    #[test]
    fn frontier_policy_rejects_out_of_range_typed_evidence() {
        let profile = default_resolved_objective_profile().expect("resolved default profile");
        let error = select_from_frontier(
            &profile,
            &[(
                "invalid".to_string(),
                FrontierAxes {
                    held_out_quality_basis_points: 10_001,
                    breadth_quality_basis_points: 10_000,
                    anti_shortcut_quality_basis_points: 10_000,
                    monetary_cost: 0.0,
                    quota_consumption: 0.0,
                    latency: 0.0,
                    retry_rework: 0.0,
                    human_review: 0.0,
                },
            )],
        )
        .expect_err("out-of-range evidence must fail closed");
        assert!(error
            .to_string()
            .contains("held_out_quality_basis_points must be at most 10000"));
    }

    #[test]
    fn invalid_weights_fail_closed() {
        let mut profile = default_objective_profile();
        profile.quality.held_out_percent = 40;
        assert!(profile.validate().unwrap_err().to_string().contains("100"));
    }

    #[test]
    fn historical_profile_and_binding_omissions_decode_to_zero_switch_costs() {
        let profile = ObjectiveProfile::from_json(
            br#"{"id":"legacy","version":1,"quality":{"held_out_percent":50,"breadth_percent":25,"anti_shortcut_percent":25}}"#,
        )
        .expect("historical profile");
        assert_eq!(profile.id, "legacy");
        assert_eq!(profile.version, 1);
        assert_eq!(profile.switch_costs, ContextSwitchCosts::zero());

        let binding: ObjectiveProfileBinding = serde_json::from_value(serde_json::json!({
            "id": "legacy",
            "version": 1,
            "content_hash": "0".repeat(64),
            "quality": {
                "held_out_percent": 50,
                "breadth_percent": 25,
                "anti_shortcut_percent": 25
            },
            "tradeoffs": TradeoffWeights::default()
        }))
        .expect("historical binding");
        assert_eq!(binding.switch_costs, ContextSwitchCosts::zero());
    }

    #[test]
    fn malformed_switch_cost_json_fails_closed() {
        for value in ["-1", "18446744073709551616"] {
            let json = format!(
                "{{\"id\":\"invalid\",\"version\":1,\"quality\":{{\"held_out_percent\":50,\"breadth_percent\":25,\"anti_shortcut_percent\":25}},\"switch_costs\":{{\"model_change_same_runtime_microunits\":{value},\"runtime_change_microunits\":25000}}}}"
            );
            assert!(ObjectiveProfile::from_json(json.as_bytes()).is_err());
        }
    }
}
