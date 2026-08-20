//! Multi-axis routing taxonomy and per-cell evidence coverage (issue #202).
//!
//! The taxonomy is versioned *data*, not an enum in the decision path.
//! Unclassifiable work lands in an explicit `unknown` cell so it cannot
//! silently pollute a real cell's statistics. Promotion into a cell requires
//! both #169's absolute LCB floor *and* a paired comparison against that
//! cell's incumbent.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::error::OptimizerError;
use super::explanation::DecisionDiagnostics;
use super::features::{keys, FeatureBag};
use super::ids::{PolicyId, TimestampMillis};
use super::predictor::wilson_lcb_bp;

pub const TAXONOMY_SCHEMA_VERSION: u32 = 1;
pub const UNKNOWN_AXIS: &str = "unknown";

/// Default paired-promotion confidence (75%).
pub const DEFAULT_PAIRED_CONFIDENCE_BP: u16 = 7_500;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AxisValue {
    pub id: String,
    #[serde(default)]
    pub aliases: Vec<String>,
}

impl AxisValue {
    pub fn new(id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            aliases: Vec::new(),
        }
    }

    pub fn matches(&self, raw: &str) -> bool {
        let needle = normalize_token(raw);
        if self.id == needle {
            return true;
        }
        self.aliases
            .iter()
            .any(|alias| normalize_token(alias) == needle)
    }
}

/// Versioned taxonomy document. Operators can extend axes without a code edit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaxonomySpec {
    pub version: u32,
    pub domains: Vec<AxisValue>,
    pub task_kinds: Vec<AxisValue>,
    pub modifiers: Vec<AxisValue>,
}

impl TaxonomySpec {
    pub fn v1() -> Self {
        Self {
            version: TAXONOMY_SCHEMA_VERSION,
            domains: vec![
                AxisValue::new("backend"),
                AxisValue::new("frontend"),
                AxisValue::new("database"),
                AxisValue::new("systems"),
                AxisValue::new(UNKNOWN_AXIS),
            ],
            task_kinds: vec![
                AxisValue::new("bug_fix"),
                AxisValue::new("feature"),
                AxisValue::new("test"),
                AxisValue::new("command"),
                AxisValue::new("review"),
                AxisValue::new(UNKNOWN_AXIS),
            ],
            modifiers: vec![
                AxisValue::new("bounded_edit"),
                AxisValue::new("visual"),
                AxisValue::new("concurrency"),
                AxisValue::new("security"),
                AxisValue::new("performance"),
            ],
        }
    }

    pub fn contains_domain(&self, id: &str) -> bool {
        self.domains.iter().any(|axis| axis.id == id)
    }

    pub fn contains_kind(&self, id: &str) -> bool {
        self.task_kinds.iter().any(|axis| axis.id == id)
    }

    pub fn contains_modifier(&self, id: &str) -> bool {
        self.modifiers.iter().any(|axis| axis.id == id)
    }

    pub fn map_from(&self, other: &TaxonomyCell) -> VersionRelation {
        if other.version == self.version {
            return VersionRelation::Same;
        }
        let domain_ok = self.contains_domain(&other.domain);
        let kind_ok = self.contains_kind(&other.task_kind);
        let modifiers_ok = other
            .modifiers
            .iter()
            .all(|modifier| self.contains_modifier(modifier));
        if domain_ok && kind_ok && modifiers_ok {
            VersionRelation::Mapped(TaxonomyCell {
                version: self.version,
                domain: other.domain.clone(),
                task_kind: other.task_kind.clone(),
                modifiers: other.modifiers.clone(),
            })
        } else {
            VersionRelation::Incomparable
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionRelation {
    Same,
    Mapped(TaxonomyCell),
    Incomparable,
}

/// One cell in the (domain, task kind, modifiers) grid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct TaxonomyCell {
    pub version: u32,
    pub domain: String,
    pub task_kind: String,
    pub modifiers: Vec<String>,
}

impl TaxonomyCell {
    pub fn unknown(version: u32) -> Self {
        Self {
            version,
            domain: UNKNOWN_AXIS.to_string(),
            task_kind: UNKNOWN_AXIS.to_string(),
            modifiers: Vec::new(),
        }
    }

    pub fn key(&self) -> String {
        let mut modifiers = self.modifiers.clone();
        modifiers.sort();
        format!(
            "v{}:{}:{}:{}",
            self.version,
            self.domain,
            self.task_kind,
            modifiers.join("+")
        )
    }

    pub fn is_unknown(&self) -> bool {
        self.domain == UNKNOWN_AXIS && self.task_kind == UNKNOWN_AXIS
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellClassification {
    pub cell: TaxonomyCell,
    pub confidence_bp: u16,
    pub taxonomy_version: u32,
}

impl CellClassification {
    pub fn attach(&self, bag: &mut FeatureBag) {
        insert_int(
            bag,
            keys::TASK_TAXONOMY_VERSION,
            i64::from(self.taxonomy_version),
        );
        insert_text(bag, keys::TASK_TAXONOMY_DOMAIN, &self.cell.domain);
        insert_text(bag, keys::TASK_TAXONOMY_KIND, &self.cell.task_kind);
        insert_text(
            bag,
            keys::TASK_TAXONOMY_MODIFIERS,
            self.cell.modifiers.join(","),
        );
        insert_int(
            bag,
            keys::TASK_TAXONOMY_CONFIDENCE_BP,
            i64::from(self.confidence_bp),
        );
    }

    pub fn record_on(
        &self,
        diagnostics: &mut DecisionDiagnostics,
        coverage: Option<&CellCoverage>,
    ) {
        diagnostics.taxonomy_version = Some(self.taxonomy_version);
        diagnostics.taxonomy_cell = Some(self.cell.key());
        diagnostics.taxonomy_confidence_bp = Some(self.confidence_bp);
        if let Some(coverage) = coverage {
            diagnostics.recommendation_source =
                Some(coverage.recommendation_source.as_str().to_string());
            diagnostics.evidence_observations = Some(coverage.observations);
        }
    }
}

fn insert_int(bag: &mut FeatureBag, key: &str, value: i64) {
    if let Ok(id) = super::ids::FeatureId::new(key) {
        bag.insert(id, super::features::FeatureValue::Integer(value));
    }
}

fn insert_text(bag: &mut FeatureBag, key: &str, value: impl Into<String>) {
    if let Ok(id) = super::ids::FeatureId::new(key) {
        bag.insert(id, super::features::FeatureValue::Text(value.into()));
    }
}

/// Cheap, reproducible classifier over #163 static features.
pub fn classify(task: &FeatureBag, repo: &FeatureBag, spec: &TaxonomySpec) -> CellClassification {
    let mut domain_votes: BTreeMap<&str, u32> = BTreeMap::new();
    let mut kind_votes: BTreeMap<&str, u32> = BTreeMap::new();
    let mut modifiers = Vec::new();
    let mut signals = 0u32;

    let language = task
        .text(keys::TASK_LANGUAGE)
        .or_else(|| task.text("optimizer.task.language"))
        .unwrap_or("");
    let framework = task.text(keys::TASK_FRAMEWORK).unwrap_or("");

    if task.boolean(keys::TASK_SCHEMA_OR_MIGRATION_IMPACT) == Some(true) {
        *domain_votes.entry("database").or_insert(0) += 2;
        signals += 1;
    }
    if looks_frontend(language, framework) {
        *domain_votes.entry("frontend").or_insert(0) += 2;
        signals += 1;
    }
    if task.boolean(keys::TASK_HARDWARE_OR_ENVIRONMENT_COUPLING) == Some(true) {
        *domain_votes.entry("systems").or_insert(0) += 2;
        signals += 1;
    }
    if task.boolean(keys::TASK_PUBLIC_API_IMPACT) == Some(true)
        || language.eq_ignore_ascii_case("rust")
        || language.eq_ignore_ascii_case("go")
    {
        *domain_votes.entry("backend").or_insert(0) += 1;
        signals += 1;
    }

    let files = task.integer(keys::TASK_ESTIMATED_FILES_AFFECTED);
    let oracle = task.integer(keys::TASK_TEST_ORACLE_STRENGTH_MICRO);
    let tools = task.integer(keys::TASK_ESTIMATED_TOOL_STEP_COUNT);
    let historical = task.integer(keys::TASK_HISTORICAL_CLASS_COUNT);

    if oracle.unwrap_or(0) >= 700_000 || looks_test_task(task, repo) {
        *kind_votes.entry("test").or_insert(0) += 2;
        signals += 1;
    }
    if tools.unwrap_or(0) >= 8 && files.unwrap_or(i64::MAX) <= 2 {
        *kind_votes.entry("command").or_insert(0) += 2;
        signals += 1;
    }
    if let Some(files) = files {
        if files > 0 && files <= 3 && oracle.unwrap_or(0) < 700_000 {
            *kind_votes.entry("bug_fix").or_insert(0) += 1;
            signals += 1;
        }
        if files >= 6 {
            *kind_votes.entry("feature").or_insert(0) += 1;
            signals += 1;
        }
        if files > 0 && files <= 2 {
            modifiers.push("bounded_edit".to_string());
        }
    }
    if historical.unwrap_or(0) >= 4 {
        *kind_votes.entry("feature").or_insert(0) += 1;
        signals += 1;
    }
    if task.boolean(keys::TASK_FORMAL_VERIFICATION_AVAILABLE) == Some(true) {
        *kind_votes.entry("review").or_insert(0) += 1;
        signals += 1;
    }
    if looks_frontend(language, framework) {
        modifiers.push("visual".to_string());
    }
    if task.boolean(keys::TASK_CONCURRENCY_INVOLVEMENT) == Some(true) {
        modifiers.push("concurrency".to_string());
    }
    if task.boolean(keys::TASK_SECURITY_SENSITIVITY) == Some(true) {
        modifiers.push("security".to_string());
    }
    if task.boolean(keys::TASK_PERFORMANCE_SENSITIVITY) == Some(true) {
        modifiers.push("performance".to_string());
    }
    modifiers.retain(|modifier| spec.contains_modifier(modifier));
    modifiers.sort();
    modifiers.dedup();

    let domain = pick_axis(&domain_votes, spec, AxisKind::Domain);
    let task_kind = pick_axis(&kind_votes, spec, AxisKind::Kind);
    let classified = domain != UNKNOWN_AXIS || task_kind != UNKNOWN_AXIS;
    let confidence_bp = if !classified {
        0
    } else {
        let strength = signals.min(8);
        (2_000u16.saturating_mul(u16::try_from(strength).unwrap_or(8))).min(9_500)
    };

    let cell = if classified {
        TaxonomyCell {
            version: spec.version,
            domain: domain.to_string(),
            task_kind: task_kind.to_string(),
            modifiers,
        }
    } else {
        TaxonomyCell::unknown(spec.version)
    };

    CellClassification {
        taxonomy_version: spec.version,
        confidence_bp,
        cell,
    }
}

enum AxisKind {
    Domain,
    Kind,
}

fn pick_axis<'a>(votes: &BTreeMap<&'a str, u32>, spec: &TaxonomySpec, kind: AxisKind) -> &'a str {
    let winner = votes
        .iter()
        .max_by_key(|(name, count)| (*count, *name))
        .map(|(name, count)| (*name, *count));
    match winner {
        Some((name, count)) if count > 0 => {
            let allowed = match kind {
                AxisKind::Domain => spec.contains_domain(name),
                AxisKind::Kind => spec.contains_kind(name),
            };
            if allowed {
                name
            } else {
                UNKNOWN_AXIS
            }
        }
        _ => UNKNOWN_AXIS,
    }
}

fn looks_frontend(language: &str, framework: &str) -> bool {
    let blob = format!("{language} {framework}").to_ascii_lowercase();
    [
        "typescript",
        "javascript",
        "css",
        "html",
        "react",
        "vue",
        "svelte",
    ]
    .iter()
    .any(|token| blob.contains(token))
}

fn looks_test_task(task: &FeatureBag, repo: &FeatureBag) -> bool {
    let test_density = repo.integer(keys::REPO_TEST_DENSITY_MICRO).unwrap_or(0);
    let files = task
        .integer(keys::TASK_ESTIMATED_FILES_AFFECTED)
        .unwrap_or(0);
    test_density >= 400_000 && files <= 4
}

fn normalize_token(raw: &str) -> String {
    raw.trim().to_ascii_lowercase().replace([' ', '-'], "_")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RecommendationSource {
    Measured,
    PartiallyPooled,
    PriorDriven,
}

impl RecommendationSource {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Measured => "measured",
            Self::PartiallyPooled => "partially_pooled",
            Self::PriorDriven => "prior_driven",
        }
    }
}

/// Exponential time decay used for effective sample size (#170-compatible).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeDecay {
    pub half_life_millis: u64,
}

impl Default for TimeDecay {
    fn default() -> Self {
        Self {
            half_life_millis: 30 * 24 * 60 * 60 * 1_000,
        }
    }
}

impl TimeDecay {
    /// Weight in milli-counts: 1000 * 1/2^(age / half_life).
    pub fn weight_milli(self, age_millis: u64) -> u32 {
        if self.half_life_millis == 0 {
            return 1_000;
        }
        let mut weight = 1_000u32;
        let mut remaining = age_millis;
        while remaining >= self.half_life_millis {
            weight /= 2;
            remaining -= self.half_life_millis;
            if weight == 0 {
                return 0;
            }
        }
        if remaining == 0 {
            return weight;
        }
        // Linear interpolation over the leftover fraction of a half-life.
        let frac = (remaining.saturating_mul(1_000) / self.half_life_millis) as u32;
        weight.saturating_sub(weight.saturating_mul(frac) / 2_000)
    }
}

/// One ledger row consumed by the coverage map.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageObservation {
    pub cell: TaxonomyCell,
    pub model: String,
    pub effort: String,
    pub observed_at: TimestampMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CellCoverage {
    pub cell: TaxonomyCell,
    pub observations: u32,
    pub effective_sample_size_milli: u32,
    pub coverage_by_model_effort: BTreeMap<String, u32>,
    pub recommendation_source: RecommendationSource,
}

impl CellCoverage {
    pub fn empty(cell: TaxonomyCell) -> Self {
        Self {
            cell,
            observations: 0,
            effective_sample_size_milli: 0,
            coverage_by_model_effort: BTreeMap::new(),
            recommendation_source: RecommendationSource::PriorDriven,
        }
    }
}

/// Pure function of a ledger snapshot. Replayable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoverageMap {
    pub taxonomy_version: u32,
    pub as_of: TimestampMillis,
    pub cells: BTreeMap<String, CellCoverage>,
}

impl CoverageMap {
    pub fn from_ledger(
        records: &[CoverageObservation],
        spec: &TaxonomySpec,
        decay: TimeDecay,
        as_of: TimestampMillis,
    ) -> Self {
        let mut grouped: BTreeMap<String, Vec<&CoverageObservation>> = BTreeMap::new();
        for record in records {
            match spec.map_from(&record.cell) {
                VersionRelation::Same | VersionRelation::Mapped(_) => {
                    grouped.entry(record.cell.key()).or_default().push(record);
                }
                VersionRelation::Incomparable => {}
            }
        }
        let mut cells = BTreeMap::new();
        for (key, rows) in grouped {
            let cell = rows[0].cell.clone();
            let mut coverage = CellCoverage::empty(cell);
            coverage.observations = u32::try_from(rows.len()).unwrap_or(u32::MAX);
            let mut effective = 0u32;
            for row in rows {
                let age = as_of
                    .as_millis()
                    .saturating_sub(row.observed_at.as_millis());
                effective = effective.saturating_add(decay.weight_milli(age));
                let slot = format!("{}@{}", row.model, row.effort);
                *coverage.coverage_by_model_effort.entry(slot).or_insert(0) += 1;
            }
            coverage.effective_sample_size_milli = effective;
            coverage.recommendation_source = if coverage.observations == 0 {
                RecommendationSource::PriorDriven
            } else if coverage.observations < 8 {
                RecommendationSource::PartiallyPooled
            } else {
                RecommendationSource::Measured
            };
            cells.insert(key, coverage);
        }
        Self {
            taxonomy_version: spec.version,
            as_of,
            cells,
        }
    }

    pub fn coverage_for(&self, cell: &TaxonomyCell) -> CellCoverage {
        self.cells
            .get(&cell.key())
            .cloned()
            .unwrap_or_else(|| CellCoverage::empty(cell.clone()))
    }

    /// Low-coverage cells first so #169's exploration budget can target them.
    pub fn exploration_order(&self) -> Vec<&CellCoverage> {
        let mut cells: Vec<&CellCoverage> = self.cells.values().collect();
        cells.sort_by_key(|cell| (cell.effective_sample_size_milli, cell.cell.key()));
        cells
    }

    pub fn render_text(&self) -> String {
        let mut lines = vec![format!(
            "taxonomy v{} coverage ({} cells)",
            self.taxonomy_version,
            self.cells.len()
        )];
        for cell in self.exploration_order() {
            lines.push(format!(
                "{} n={} ess_milli={} source={}",
                cell.cell.key(),
                cell.observations,
                cell.effective_sample_size_milli,
                cell.recommendation_source.as_str()
            ));
        }
        lines.join("\n")
    }
}

/// Matched comparison against the cell incumbent, plus the absolute LCB floor.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedPromotionRequest {
    pub cell: TaxonomyCell,
    pub incumbent_policy: PolicyId,
    pub incumbent_lcb_bp: u16,
    pub incumbent_observations: u32,
    pub candidate_policy: PolicyId,
    pub candidate_lcb_bp: u16,
    pub candidate_observations: u32,
    pub paired_wins: u32,
    pub paired_trials: u32,
    pub absolute_floor_bp: u16,
    pub paired_confidence_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairedPromotionDecision {
    pub absolute_lcb_cleared: bool,
    pub paired_improves_on_incumbent: bool,
    pub paired_lcb_bp: u16,
    pub promoted: bool,
    pub reason: String,
}

pub fn decide_paired_promotion(request: &PairedPromotionRequest) -> PairedPromotionDecision {
    if request.candidate_policy == request.incumbent_policy {
        return PairedPromotionDecision {
            absolute_lcb_cleared: request.candidate_lcb_bp >= request.absolute_floor_bp,
            paired_improves_on_incumbent: false,
            paired_lcb_bp: 0,
            promoted: false,
            reason: format!(
                "candidate_is_incumbent:lcb={}:n={}",
                request.incumbent_lcb_bp, request.incumbent_observations
            ),
        };
    }
    let absolute = request.candidate_lcb_bp >= request.absolute_floor_bp;
    let paired_lcb = wilson_lcb_bp(
        u64::from(request.paired_wins),
        u64::from(request.paired_trials),
        196,
    );
    let paired = request.paired_trials > 0 && paired_lcb >= request.paired_confidence_bp;
    let promoted = absolute && paired;
    let reason = if !absolute {
        format!(
            "absolute_lcb_below_floor:candidate_n={}",
            request.candidate_observations
        )
    } else if !paired {
        "paired_comparison_lost_to_incumbent".to_string()
    } else {
        format!(
            "promoted_against_incumbent:incumbent_n={}",
            request.incumbent_observations
        )
    };
    PairedPromotionDecision {
        absolute_lcb_cleared: absolute,
        paired_improves_on_incumbent: paired,
        paired_lcb_bp: paired_lcb,
        promoted,
        reason,
    }
}

pub fn classify_or_unknown(
    task: &FeatureBag,
    repo: &FeatureBag,
    spec: Option<&TaxonomySpec>,
) -> CellClassification {
    match spec {
        Some(spec) => classify(task, repo, spec),
        None => CellClassification {
            cell: TaxonomyCell::unknown(TAXONOMY_SCHEMA_VERSION),
            confidence_bp: 0,
            taxonomy_version: TAXONOMY_SCHEMA_VERSION,
        },
    }
}

pub fn parse_taxonomy_spec(bytes: &[u8]) -> Result<TaxonomySpec, OptimizerError> {
    serde_json::from_slice(bytes)
        .map_err(|error| OptimizerError::invalid(format!("taxonomy spec JSON: {error}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::features::FeatureValue;
    use crate::optimizer::ids::FeatureId;

    fn put_bool(bag: &mut FeatureBag, key: &str, value: bool) {
        bag.insert(
            FeatureId::new(key).expect("id"),
            FeatureValue::Boolean(value),
        );
    }

    fn put_int(bag: &mut FeatureBag, key: &str, value: i64) {
        bag.insert(
            FeatureId::new(key).expect("id"),
            FeatureValue::Integer(value),
        );
    }

    fn put_text(bag: &mut FeatureBag, key: &str, value: &str) {
        bag.insert(
            FeatureId::new(key).expect("id"),
            FeatureValue::Text(value.to_string()),
        );
    }

    #[test]
    fn unclassifiable_work_lands_in_unknown_not_a_real_cell() {
        let spec = TaxonomySpec::v1();
        let classification = classify(&FeatureBag::new(), &FeatureBag::new(), &spec);
        assert!(classification.cell.is_unknown());
        assert_eq!(classification.confidence_bp, 0);
        assert_eq!(classification.cell.domain, UNKNOWN_AXIS);
        assert_eq!(classification.cell.task_kind, UNKNOWN_AXIS);
    }

    #[test]
    fn backend_test_bounded_edit_is_a_distinct_cell() {
        let spec = TaxonomySpec::v1();
        let mut task = FeatureBag::new();
        put_text(&mut task, keys::TASK_LANGUAGE, "rust");
        put_bool(&mut task, keys::TASK_PUBLIC_API_IMPACT, true);
        put_int(&mut task, keys::TASK_ESTIMATED_FILES_AFFECTED, 1);
        put_int(&mut task, keys::TASK_TEST_ORACLE_STRENGTH_MICRO, 800_000);
        let classification = classify(&task, &FeatureBag::new(), &spec);
        assert_eq!(classification.cell.domain, "backend");
        assert_eq!(classification.cell.task_kind, "test");
        assert!(classification
            .cell
            .modifiers
            .contains(&"bounded_edit".to_string()));
        assert!(classification.confidence_bp > 0);
    }

    #[test]
    fn zero_observation_cell_is_prior_driven() {
        let spec = TaxonomySpec::v1();
        let map = CoverageMap::from_ledger(
            &[],
            &spec,
            TimeDecay::default(),
            TimestampMillis::from_millis(10),
        );
        let coverage = map.coverage_for(&TaxonomyCell {
            version: 1,
            domain: "backend".into(),
            task_kind: "test".into(),
            modifiers: vec!["bounded_edit".into()],
        });
        assert_eq!(coverage.observations, 0);
        assert_eq!(
            coverage.recommendation_source,
            RecommendationSource::PriorDriven
        );
        assert_eq!(coverage.effective_sample_size_milli, 0);
    }

    #[test]
    fn coverage_map_is_pure_and_replayable() {
        let spec = TaxonomySpec::v1();
        let cell = TaxonomyCell {
            version: 1,
            domain: "backend".into(),
            task_kind: "bug_fix".into(),
            modifiers: vec!["bounded_edit".into()],
        };
        let records = vec![
            CoverageObservation {
                cell: cell.clone(),
                model: "runtime-a".into(),
                effort: "low".into(),
                observed_at: TimestampMillis::from_millis(1_000),
            },
            CoverageObservation {
                cell: cell.clone(),
                model: "runtime-a".into(),
                effort: "medium".into(),
                observed_at: TimestampMillis::from_millis(2_000),
            },
        ];
        let as_of = TimestampMillis::from_millis(3_000);
        let left = CoverageMap::from_ledger(&records, &spec, TimeDecay::default(), as_of);
        let right = CoverageMap::from_ledger(&records, &spec, TimeDecay::default(), as_of);
        assert_eq!(left, right);
        let coverage = left.coverage_for(&cell);
        assert_eq!(coverage.observations, 2);
        assert_eq!(
            coverage.recommendation_source,
            RecommendationSource::PartiallyPooled
        );
        assert!(coverage
            .coverage_by_model_effort
            .contains_key("runtime-a@low"));
    }

    #[test]
    fn candidate_clearing_absolute_lcb_but_losing_paired_is_not_promoted() {
        let request = PairedPromotionRequest {
            cell: TaxonomyCell::unknown(1),
            incumbent_policy: PolicyId::new("incumbent").expect("id"),
            incumbent_lcb_bp: 8_800,
            incumbent_observations: 40,
            candidate_policy: PolicyId::new("challenger").expect("id"),
            candidate_lcb_bp: 9_200,
            candidate_observations: 12,
            paired_wins: 4,
            paired_trials: 10,
            absolute_floor_bp: 8_000,
            paired_confidence_bp: DEFAULT_PAIRED_CONFIDENCE_BP,
        };
        let decision = decide_paired_promotion(&request);
        assert!(decision.absolute_lcb_cleared);
        assert!(!decision.paired_improves_on_incumbent);
        assert!(!decision.promoted);
        assert_eq!(decision.reason, "paired_comparison_lost_to_incumbent");
    }

    #[test]
    fn both_gates_required_for_promotion() {
        let request = PairedPromotionRequest {
            cell: TaxonomyCell::unknown(1),
            incumbent_policy: PolicyId::new("incumbent").expect("id"),
            incumbent_lcb_bp: 8_000,
            incumbent_observations: 20,
            candidate_policy: PolicyId::new("challenger").expect("id"),
            candidate_lcb_bp: 9_400,
            candidate_observations: 40,
            paired_wins: 36,
            paired_trials: 40,
            absolute_floor_bp: 8_000,
            paired_confidence_bp: DEFAULT_PAIRED_CONFIDENCE_BP,
        };
        let decision = decide_paired_promotion(&request);
        assert!(decision.promoted);
        assert!(decision.absolute_lcb_cleared);
        assert!(decision.paired_improves_on_incumbent);
    }

    #[test]
    fn taxonomy_version_change_maps_or_marks_incomparable() {
        let v1 = TaxonomySpec::v1();
        let mut v2 = v1.clone();
        v2.version = 2;
        let same_axes = TaxonomyCell {
            version: 1,
            domain: "backend".into(),
            task_kind: "test".into(),
            modifiers: vec!["bounded_edit".into()],
        };
        assert!(matches!(
            v2.map_from(&same_axes),
            VersionRelation::Mapped(_)
        ));

        let mut v2_dropped = v2.clone();
        v2_dropped.domains.retain(|axis| axis.id != "backend");
        assert_eq!(
            v2_dropped.map_from(&same_axes),
            VersionRelation::Incomparable
        );

        let json = serde_json::to_vec(&v1).expect("json");
        let parsed = parse_taxonomy_spec(&json).expect("parse");
        assert_eq!(parsed.version, 1);
    }

    #[test]
    fn classification_is_reproducible_from_the_same_features() {
        let spec = TaxonomySpec::v1();
        let mut task = FeatureBag::new();
        put_text(&mut task, keys::TASK_LANGUAGE, "typescript");
        put_text(&mut task, keys::TASK_FRAMEWORK, "react");
        put_int(&mut task, keys::TASK_ESTIMATED_FILES_AFFECTED, 2);
        let left = classify(&task, &FeatureBag::new(), &spec);
        let right = classify(&task, &FeatureBag::new(), &spec);
        assert_eq!(left, right);
        assert_eq!(left.cell.domain, "frontend");
        assert!(left.cell.modifiers.contains(&"visual".to_string()));
    }

    #[test]
    fn old_records_without_taxonomy_fields_remain_readable() {
        let json = r#"{"decided_at":1,"selected_policy":null,"selected_action":null,"quality_lcb_bp":null,"predicted_p95_time_to_certification_micros":null,"predicted_consumption":{},"reserves_after_selection":{},"objective_value_micros":null,"rejected_candidates":[],"candidate_ids":[],"candidate_predictions":[],"continuation":null,"escalation_comparison":null}"#;
        let restored: DecisionDiagnostics = serde_json::from_str(json).expect("old envelope");
        assert!(restored.taxonomy_cell.is_none());
        assert!(restored.recommendation_source.is_none());
    }

    #[test]
    fn exploration_order_puts_blind_spots_first() {
        let spec = TaxonomySpec::v1();
        let thin = TaxonomyCell {
            version: 1,
            domain: "frontend".into(),
            task_kind: "bug_fix".into(),
            modifiers: vec![],
        };
        let thick = TaxonomyCell {
            version: 1,
            domain: "backend".into(),
            task_kind: "test".into(),
            modifiers: vec![],
        };
        let mut records = vec![CoverageObservation {
            cell: thin.clone(),
            model: "runtime-a".into(),
            effort: "low".into(),
            observed_at: TimestampMillis::from_millis(1),
        }];
        for i in 0..12 {
            records.push(CoverageObservation {
                cell: thick.clone(),
                model: "runtime-b".into(),
                effort: "medium".into(),
                observed_at: TimestampMillis::from_millis(i),
            });
        }
        let map = CoverageMap::from_ledger(
            &records,
            &spec,
            TimeDecay::default(),
            TimestampMillis::from_millis(20),
        );
        let order = map.exploration_order();
        assert_eq!(order[0].cell.domain, "frontend");
        assert_eq!(
            order[1].recommendation_source,
            RecommendationSource::Measured
        );
        assert!(map.render_text().contains("prior_driven") || map.render_text().contains("n="));
    }
}
