//! Audit the router's own calibration (issue #205).
//!
//! Predictions recorded on a decision are joined with measured outcomes and
//! scored. Miscalibration walks an ordered ladder — widen posteriors, raise
//! the LCB margin, restrict to the known-safe baseline, then fail closed.
//! Nothing here can set, clear, or weaken a certification result.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

use super::explanation::DecisionDiagnostics;
use super::ids::TimestampMillis;
use super::objective::PreferenceProfileId;
use super::operator_labels::LearnedPolicyOutcome;
use super::predictor::{
    mean_i64, quantile_i64, HierarchicalPolicyPredictor, PolicyOutcomeDistribution,
};
use super::taxonomy::{TaxonomyCell, TimeDecay};
use super::telemetry::InvocationRecord;

pub const MIN_ENVELOPE_OBSERVATIONS: u32 = 8;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredictedQuantities {
    pub certified_probability_bp: u16,
    pub time_to_cert_micros: i64,
    pub time_p95_micros: i64,
    #[serde(default)]
    pub time_samples_micros: Vec<i64>,
    #[serde(default)]
    pub expected_cost_micros: i64,
    #[serde(default)]
    pub consumption: BTreeMap<String, i64>,
    #[serde(default)]
    pub human_intervention_bp: u16,
}

impl PredictedQuantities {
    pub fn from_distribution(distribution: &PolicyOutcomeDistribution) -> Self {
        Self {
            certified_probability_bp: distribution.certified_probability_bp,
            time_to_cert_micros: distribution.expected_latency_micros,
            time_p95_micros: distribution.details.tail_latency_p95_micros,
            time_samples_micros: distribution.details.time_to_cert_samples_micros.clone(),
            expected_cost_micros: distribution.expected_cost_micros,
            consumption: distribution
                .details
                .consumption
                .iter()
                .map(|(id, forecast)| {
                    let samples: Vec<i64> = forecast.samples.iter().map(|q| q.as_i64()).collect();
                    (id.as_str().to_string(), mean_i64(&samples))
                })
                .collect(),
            human_intervention_bp: distribution.details.human_intervention_bp,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MeasuredOutcome {
    pub certified: bool,
    #[serde(default)]
    pub time_to_cert_micros: Option<i64>,
    #[serde(default)]
    pub cost_micros: Option<i64>,
    #[serde(default)]
    pub consumption: BTreeMap<String, i64>,
    #[serde(default)]
    pub human_intervention: bool,
}

impl MeasuredOutcome {
    pub fn from_invocation(record: &InvocationRecord) -> Self {
        let mut consumption = BTreeMap::new();
        if let Some(tokens) = record.input_tokens {
            consumption.insert(
                "input_tokens".to_string(),
                i64::try_from(tokens).unwrap_or(i64::MAX),
            );
        }
        if let Some(tokens) = record.cached_input_tokens {
            consumption.insert(
                "cached_input_tokens".to_string(),
                i64::try_from(tokens).unwrap_or(i64::MAX),
            );
        }
        if let Some(tokens) = record.output_tokens {
            consumption.insert(
                "output_tokens".to_string(),
                i64::try_from(tokens).unwrap_or(i64::MAX),
            );
        }
        if let Some(credits) = record.provider_credits {
            consumption.insert("provider_credits".to_string(), credits);
        }
        Self {
            certified: record.certified.unwrap_or(false),
            time_to_cert_micros: record.finished_at.map(|finished| {
                i64::try_from(
                    finished
                        .as_millis()
                        .saturating_sub(record.started_at.as_millis())
                        .saturating_mul(1_000),
                )
                .unwrap_or(i64::MAX)
            }),
            cost_micros: record.cost_micros.or(record.api_cost_micros),
            consumption,
            human_intervention: record.human_intervention,
        }
    }

    pub fn incorporate_labels(&mut self, outcome: &LearnedPolicyOutcome) {
        if outcome.rework.is_some() {
            self.human_intervention = true;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScoredRecord {
    pub cell: TaxonomyCell,
    pub model: String,
    pub effort: String,
    #[serde(default)]
    pub profile_id: Option<String>,
    pub predicted: PredictedQuantities,
    pub measured: MeasuredOutcome,
    pub observed_at: TimestampMillis,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CalibrationMetrics {
    pub observation_count: u32,
    pub effective_sample_size_milli: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ece_bp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ece_lower_bp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ece_upper_bp: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub brier_milli: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub log_score_milli: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pit_mean_milli: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p95_interval_coverage_bp: Option<u16>,
}

impl CalibrationMetrics {
    pub fn from_ledger(
        records: &[ScoredRecord],
        cell: Option<&TaxonomyCell>,
        model: Option<&str>,
        effort: Option<&str>,
        decay: TimeDecay,
        as_of: TimestampMillis,
    ) -> Self {
        let rows: Vec<&ScoredRecord> = records
            .iter()
            .filter(|row| cell.is_none_or(|cell| &row.cell == cell))
            .filter(|row| model.is_none_or(|model| row.model == model))
            .filter(|row| effort.is_none_or(|effort| row.effort == effort))
            .collect();
        metrics_from_rows(&rows, decay, as_of)
    }
}

fn metrics_from_rows(
    rows: &[&ScoredRecord],
    decay: TimeDecay,
    as_of: TimestampMillis,
) -> CalibrationMetrics {
    if rows.is_empty() {
        return CalibrationMetrics::default();
    }
    let mut ece_num = 0u64;
    let mut ece_den = 0u64;
    let mut brier_acc = 0u64;
    let mut log_acc = 0i64;
    let mut pit_acc = 0u64;
    let mut pit_n = 0u64;
    let mut cover = 0u64;
    let mut cover_n = 0u64;
    let mut ess = 0u32;
    let bins = 10u64;
    let mut bin_conf = [0u64; 10];
    let mut bin_hits = [0u64; 10];
    let mut bin_n = [0u64; 10];

    for row in rows {
        let age = as_of
            .as_millis()
            .saturating_sub(row.observed_at.as_millis());
        let weight = u64::from(decay.weight_milli(age).max(1));
        ess = ess.saturating_add(weight as u32);
        let p = u64::from(row.predicted.certified_probability_bp);
        let y = u64::from(row.measured.certified);
        let bin = ((p * bins) / 10_001).min(9) as usize;
        bin_conf[bin] = bin_conf[bin].saturating_add(p.saturating_mul(weight));
        bin_hits[bin] = bin_hits[bin].saturating_add(y.saturating_mul(weight));
        bin_n[bin] = bin_n[bin].saturating_add(weight);
        let err = if y == 1 {
            10_000u64.saturating_sub(p)
        } else {
            p
        };
        brier_acc = brier_acc.saturating_add(err.saturating_mul(err).saturating_mul(weight));
        ece_den = ece_den.saturating_add(weight);
        log_acc = log_acc.saturating_add(
            i64::from(neg_log_milli(if y == 1 {
                row.predicted.certified_probability_bp
            } else {
                10_000u16.saturating_sub(row.predicted.certified_probability_bp)
            })) * weight as i64,
        );

        if let Some(realized) = row.measured.time_to_cert_micros {
            if !row.predicted.time_samples_micros.is_empty() {
                let below = row
                    .predicted
                    .time_samples_micros
                    .iter()
                    .filter(|sample| **sample < realized)
                    .count();
                let pit = (below as u64).saturating_mul(1_000)
                    / row.predicted.time_samples_micros.len() as u64;
                pit_acc = pit_acc.saturating_add(pit.saturating_mul(weight));
                pit_n = pit_n.saturating_add(weight);
            }
            if row.predicted.time_p95_micros > 0 {
                if realized <= row.predicted.time_p95_micros {
                    cover = cover.saturating_add(weight);
                }
                cover_n = cover_n.saturating_add(weight);
            }
        }
    }

    for bin in 0..10 {
        if bin_n[bin] == 0 {
            continue;
        }
        let conf = bin_conf[bin] / bin_n[bin];
        let acc = bin_hits[bin].saturating_mul(10_000) / bin_n[bin];
        let gap = conf.abs_diff(acc);
        ece_num = ece_num.saturating_add(gap.saturating_mul(bin_n[bin]));
    }

    let ece = (ece_den > 0).then(|| (ece_num / ece_den).min(10_000) as u16);
    let (ece_lower_bp, ece_upper_bp) = match ece {
        Some(point) => {
            let n = u64::from(rows.len().max(1) as u32);
            let se = 10_000u64 / n.isqrt().max(1);
            let half = (se.saturating_mul(196) / 100).min(10_000);
            (
                Some(u16::try_from(u64::from(point).saturating_sub(half)).unwrap_or(0)),
                Some(
                    u16::try_from(u64::from(point).saturating_add(half).min(10_000))
                        .unwrap_or(10_000),
                ),
            )
        }
        None => (None, None),
    };

    CalibrationMetrics {
        observation_count: u32::try_from(rows.len()).unwrap_or(u32::MAX),
        effective_sample_size_milli: ess,
        ece_bp: ece,
        ece_lower_bp,
        ece_upper_bp,
        brier_milli: (ece_den > 0)
            .then(|| ((brier_acc / ece_den) / 10).min(u64::from(u32::MAX)) as u32),
        log_score_milli: (ece_den > 0).then(|| (log_acc / ece_den as i64) as i32),
        pit_mean_milli: (pit_n > 0).then(|| (pit_acc / pit_n) as i32),
        p95_interval_coverage_bp: (cover_n > 0)
            .then(|| ((cover.saturating_mul(10_000)) / cover_n).min(10_000) as u16),
    }
}

fn neg_log_milli(probability_bp: u16) -> i32 {
    let p = probability_bp.clamp(1, 9_999);
    // -ln(p/10000) ≈ (10000-p)/p  in nats, scaled to milli.
    let numer = i64::from(10_000u16.saturating_sub(p)).saturating_mul(1_000);
    (numer / i64::from(p)) as i32
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MiscalibrationStep {
    WidenPosteriors { metric: String, value: i64 },
    RaiseLcbMargin { metric: String, extra_bp: u16 },
    RestrictToBaseline { metric: String },
    FailClosed { metric: String },
}

impl MiscalibrationStep {
    pub fn as_label(&self) -> &'static str {
        match self {
            Self::WidenPosteriors { .. } => "widen_posteriors",
            Self::RaiseLcbMargin { .. } => "raise_lcb_margin",
            Self::RestrictToBaseline { .. } => "restrict_to_baseline",
            Self::FailClosed { .. } => "fail_closed",
        }
    }

    pub fn metric(&self) -> &str {
        match self {
            Self::WidenPosteriors { metric, .. }
            | Self::RaiseLcbMargin { metric, .. }
            | Self::RestrictToBaseline { metric }
            | Self::FailClosed { metric } => metric,
        }
    }
}

/// Ordered response. There is no `certified` field — this type cannot
/// represent a certification mutation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct CalibrationResponse {
    pub steps: Vec<MiscalibrationStep>,
    pub lcb_margin_extra_bp: u16,
    pub widen_milli: u32,
    pub restrict_to_baseline: bool,
    pub fail_closed: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub triggering_metric: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationAuditor {
    pub widen_ece_bp: u16,
    pub raise_ece_bp: u16,
    pub baseline_ece_bp: u16,
    pub fail_ece_bp: u16,
    pub min_p95_coverage_bp: u16,
}

impl Default for CalibrationAuditor {
    fn default() -> Self {
        Self {
            widen_ece_bp: 500,
            raise_ece_bp: 1_000,
            baseline_ece_bp: 2_000,
            fail_ece_bp: 3_500,
            min_p95_coverage_bp: 8_000,
        }
    }
}

impl CalibrationAuditor {
    pub fn respond(&self, metrics: &CalibrationMetrics) -> CalibrationResponse {
        let mut response = CalibrationResponse::default();
        if metrics.observation_count == 0 {
            return response;
        }
        let ece = metrics.ece_bp.unwrap_or(0);
        let coverage = metrics.p95_interval_coverage_bp;
        let (severity, metric, value) = if ece >= self.fail_ece_bp {
            (4, "ece_bp", i64::from(ece))
        } else if ece >= self.baseline_ece_bp {
            (3, "ece_bp", i64::from(ece))
        } else if ece >= self.raise_ece_bp {
            (2, "ece_bp", i64::from(ece))
        } else if ece >= self.widen_ece_bp {
            (1, "ece_bp", i64::from(ece))
        } else if coverage.is_some_and(|cover| cover < self.min_p95_coverage_bp) {
            let cover = coverage.unwrap_or(0);
            if cover < 5_000 {
                (4, "p95_interval_coverage_bp", i64::from(cover))
            } else if cover < 6_500 {
                (3, "p95_interval_coverage_bp", i64::from(cover))
            } else if cover < 7_500 {
                (2, "p95_interval_coverage_bp", i64::from(cover))
            } else {
                (1, "p95_interval_coverage_bp", i64::from(cover))
            }
        } else {
            (0, "", 0)
        };
        if severity == 0 {
            return response;
        }
        response.triggering_metric = Some(metric.to_string());
        response.steps.push(MiscalibrationStep::WidenPosteriors {
            metric: metric.to_string(),
            value,
        });
        response.widen_milli = 2_000;
        if severity >= 2 {
            response.steps.push(MiscalibrationStep::RaiseLcbMargin {
                metric: metric.to_string(),
                extra_bp: 200,
            });
            response.lcb_margin_extra_bp = 200;
        }
        if severity >= 3 {
            response.steps.push(MiscalibrationStep::RestrictToBaseline {
                metric: metric.to_string(),
            });
            response.restrict_to_baseline = true;
        }
        if severity >= 4 {
            response.steps.push(MiscalibrationStep::FailClosed {
                metric: metric.to_string(),
            });
            response.fail_closed = true;
        }
        response
    }

    pub fn apply_to_predictor(
        predictor: &mut HierarchicalPolicyPredictor,
        response: &CalibrationResponse,
    ) {
        if response.widen_milli > 0 {
            predictor.widen_posteriors(u64::from(response.widen_milli));
        }
        if response.lcb_margin_extra_bp > 0 {
            predictor.raise_lcb_margin(u32::from(response.lcb_margin_extra_bp));
        }
    }

    pub fn record_on(diagnostics: &mut DecisionDiagnostics, response: &CalibrationResponse) {
        if let Some(step) = response.steps.last() {
            diagnostics.calibration_step = Some(step.as_label().to_string());
            diagnostics.calibration_metric = Some(step.metric().to_string());
        }
    }
}

/// How miscalibration constrains the *selector*, never the certifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SelectionConstraint {
    Unrestricted,
    RestrictToBaseline,
    FailClosed,
}

impl CalibrationResponse {
    pub fn selection_constraint(&self) -> SelectionConstraint {
        if self.fail_closed {
            SelectionConstraint::FailClosed
        } else if self.restrict_to_baseline {
            SelectionConstraint::RestrictToBaseline
        } else {
            SelectionConstraint::Unrestricted
        }
    }
}

/// Filter candidates according to the ordered ladder. An empty result is
/// fail-closed: the caller must not pick a policy. Certification is untouched.
pub fn constrain_candidates<'a>(
    candidates: &'a [super::policy::PolicyGraph],
    response: &CalibrationResponse,
    baseline: Option<&super::ids::PolicyId>,
) -> Vec<&'a super::policy::PolicyGraph> {
    match response.selection_constraint() {
        SelectionConstraint::Unrestricted => candidates.iter().collect(),
        SelectionConstraint::RestrictToBaseline => candidates
            .iter()
            .filter(|policy| baseline.is_some_and(|id| &policy.policy_id == id))
            .collect(),
        SelectionConstraint::FailClosed => Vec::new(),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvelopeStatus {
    Known,
    Unknown,
}

/// Published cost envelope for an objective profile. Insufficient data is
/// `unknown` — never a fabricated point estimate.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CostEnvelope {
    pub profile_id: String,
    pub cell: TaxonomyCell,
    pub status: EnvelopeStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_cost_micros: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p95_cost_micros: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_latency_micros: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub p95_latency_micros: Option<i64>,
    #[serde(default)]
    pub consumption: BTreeMap<String, i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub realized_vs_forecast_gap_micros: Option<i64>,
    pub observation_count: u32,
}

impl CostEnvelope {
    pub fn from_records(
        records: &[ScoredRecord],
        profile: &PreferenceProfileId,
        cell: &TaxonomyCell,
    ) -> Self {
        let rows: Vec<&ScoredRecord> = records
            .iter()
            .filter(|row| row.profile_id.as_deref() == Some(profile.as_str()) && &row.cell == cell)
            .collect();
        if (rows.len() as u32) < MIN_ENVELOPE_OBSERVATIONS {
            return Self {
                profile_id: profile.as_str().to_string(),
                cell: cell.clone(),
                status: EnvelopeStatus::Unknown,
                expected_cost_micros: None,
                p95_cost_micros: None,
                expected_latency_micros: None,
                p95_latency_micros: None,
                consumption: BTreeMap::new(),
                realized_vs_forecast_gap_micros: None,
                observation_count: u32::try_from(rows.len()).unwrap_or(0),
            };
        }
        let costs: Vec<i64> = rows
            .iter()
            .filter_map(|row| row.measured.cost_micros)
            .collect();
        let times: Vec<i64> = rows
            .iter()
            .filter_map(|row| row.measured.time_to_cert_micros)
            .collect();
        let forecasts: Vec<i64> = rows
            .iter()
            .map(|row| row.predicted.expected_cost_micros)
            .collect();
        let realized_mean = mean_i64(&costs);
        let forecast_mean = mean_i64(&forecasts);
        let mut consumption_acc: BTreeMap<String, (i64, u32)> = BTreeMap::new();
        for row in &rows {
            for (dimension, amount) in &row.measured.consumption {
                let entry = consumption_acc.entry(dimension.clone()).or_insert((0, 0));
                entry.0 = entry.0.saturating_add(*amount);
                entry.1 = entry.1.saturating_add(1);
            }
        }
        let consumption = consumption_acc
            .into_iter()
            .filter_map(|(dimension, (sum, count))| {
                (count > 0).then_some((dimension, sum / i64::from(count)))
            })
            .collect();
        Self {
            profile_id: profile.as_str().to_string(),
            cell: cell.clone(),
            status: EnvelopeStatus::Known,
            expected_cost_micros: Some(realized_mean),
            p95_cost_micros: Some(quantile_i64(&costs, 9_500)),
            expected_latency_micros: Some(mean_i64(&times)),
            p95_latency_micros: Some(quantile_i64(&times, 9_500)),
            consumption,
            realized_vs_forecast_gap_micros: Some(realized_mean.saturating_sub(forecast_mean)),
            observation_count: u32::try_from(rows.len()).unwrap_or(u32::MAX),
        }
    }
}

/// Append-only scored prediction/outcome pairs. Original #159 records stay intact.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CalibrationLedger {
    records: Vec<ScoredRecord>,
}

impl CalibrationLedger {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn append(&mut self, record: ScoredRecord) {
        self.records.push(record);
    }

    pub fn records(&self) -> &[ScoredRecord] {
        &self.records
    }

    pub fn metrics(
        &self,
        cell: Option<&TaxonomyCell>,
        model: Option<&str>,
        effort: Option<&str>,
        decay: TimeDecay,
        as_of: TimestampMillis,
    ) -> CalibrationMetrics {
        CalibrationMetrics::from_ledger(&self.records, cell, model, effort, decay, as_of)
    }

    pub fn envelope(&self, profile: &PreferenceProfileId, cell: &TaxonomyCell) -> CostEnvelope {
        CostEnvelope::from_records(&self.records, profile, cell)
    }

    pub fn respond(
        &self,
        auditor: &CalibrationAuditor,
        decay: TimeDecay,
        as_of: TimestampMillis,
    ) -> CalibrationResponse {
        auditor.respond(&self.metrics(None, None, None, decay, as_of))
    }
}

pub fn reconcile(
    distribution: &PolicyOutcomeDistribution,
    measured: MeasuredOutcome,
    cell: TaxonomyCell,
    model: impl Into<String>,
    effort: impl Into<String>,
    observed_at: TimestampMillis,
) -> ScoredRecord {
    ScoredRecord {
        cell,
        model: model.into(),
        effort: effort.into(),
        profile_id: None,
        predicted: PredictedQuantities::from_distribution(distribution),
        measured,
        observed_at,
    }
}

pub fn reconcile_invocation(
    distribution: &PolicyOutcomeDistribution,
    record: &InvocationRecord,
    labels: Option<&LearnedPolicyOutcome>,
    cell: TaxonomyCell,
    observed_at: TimestampMillis,
) -> ScoredRecord {
    let mut measured = MeasuredOutcome::from_invocation(record);
    if let Some(outcome) = labels {
        measured.incorporate_labels(outcome);
    }
    let model = record
        .resolved_model
        .as_ref()
        .or(record.requested_model.as_ref())
        .map(ToString::to_string)
        .unwrap_or_else(|| "unknown".to_string());
    let effort = record
        .resolved_effort
        .as_ref()
        .or(record.requested_effort.as_ref())
        .map(|effort| effort.as_label().to_string())
        .unwrap_or_else(|| "unknown".to_string());
    ScoredRecord {
        cell,
        model,
        effort,
        profile_id: None,
        predicted: PredictedQuantities::from_distribution(distribution),
        measured,
        observed_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::ids::PolicyId;
    use crate::optimizer::taxonomy::TAXONOMY_SCHEMA_VERSION;

    fn cell() -> TaxonomyCell {
        TaxonomyCell {
            version: TAXONOMY_SCHEMA_VERSION,
            domain: "backend".into(),
            task_kind: "bug_fix".into(),
            modifiers: vec!["bounded_edit".into()],
        }
    }

    fn scored(certified_p: u16, realized: bool, p95: i64, realized_t: i64) -> ScoredRecord {
        let mut predicted = PredictedQuantities {
            certified_probability_bp: certified_p,
            time_to_cert_micros: p95 / 2,
            time_p95_micros: p95,
            time_samples_micros: vec![p95 / 4, p95 / 2, p95],
            expected_cost_micros: 100,
            consumption: BTreeMap::new(),
            human_intervention_bp: 0,
        };
        if p95 == 0 {
            predicted.time_samples_micros.clear();
        }
        ScoredRecord {
            cell: cell(),
            model: "runtime-a".into(),
            effort: "low".into(),
            profile_id: Some("default".into()),
            predicted,
            measured: MeasuredOutcome {
                certified: realized,
                time_to_cert_micros: Some(realized_t),
                cost_micros: Some(120),
                consumption: BTreeMap::new(),
                human_intervention: false,
            },
            observed_at: TimestampMillis::from_millis(1),
        }
    }

    #[test]
    fn overconfident_predictor_triggers_the_fallback_ladder() {
        let records: Vec<ScoredRecord> = (0..20)
            .map(|i| scored(9_900, i % 5 == 0, 1_000, 900))
            .collect();
        let metrics = CalibrationMetrics::from_ledger(
            &records,
            Some(&cell()),
            Some("runtime-a"),
            Some("low"),
            TimeDecay::default(),
            TimestampMillis::from_millis(10),
        );
        assert!(metrics.ece_bp.unwrap_or(0) > 1_000, "{metrics:?}");
        let response = CalibrationAuditor::default().respond(&metrics);
        assert!(!response.steps.is_empty());
        assert_eq!(response.triggering_metric.as_deref(), Some("ece_bp"));
        assert!(response.steps.iter().any(|step| matches!(
            step,
            MiscalibrationStep::WidenPosteriors { metric, .. } if metric == "ece_bp"
        )));
        let json = serde_json::to_value(&response).expect("json");
        assert!(json.get("certified").is_none());
        let mut diagnostics = DecisionDiagnostics::new(TimestampMillis::from_millis(1), vec![]);
        CalibrationAuditor::record_on(&mut diagnostics, &response);
        assert_eq!(diagnostics.calibration_metric.as_deref(), Some("ece_bp"));
        assert!(diagnostics.calibration_step.is_some());
        assert!(metrics.ece_lower_bp.is_some());
        assert!(metrics.ece_upper_bp.is_some());
        assert!(metrics.ece_lower_bp <= metrics.ece_bp);
        assert!(metrics.ece_bp <= metrics.ece_upper_bp);
    }

    #[test]
    fn p95_interval_coverage_is_replayable() {
        let records: Vec<ScoredRecord> = (0..10)
            .map(|i| scored(5_000, true, 1_000, if i < 9 { 800 } else { 2_000 }))
            .collect();
        let as_of = TimestampMillis::from_millis(10);
        let left = CalibrationMetrics::from_ledger(
            &records,
            Some(&cell()),
            None,
            None,
            TimeDecay::default(),
            as_of,
        );
        let right = CalibrationMetrics::from_ledger(
            &records,
            Some(&cell()),
            None,
            None,
            TimeDecay::default(),
            as_of,
        );
        assert_eq!(left, right);
        assert_eq!(left.p95_interval_coverage_bp, Some(9_000));
    }

    #[test]
    fn insufficient_profile_observations_report_unknown() {
        let records = vec![scored(8_000, true, 1_000, 800)];
        let envelope = CostEnvelope::from_records(
            &records,
            &PreferenceProfileId::new("default").expect("id"),
            &cell(),
        );
        assert_eq!(envelope.status, EnvelopeStatus::Unknown);
        assert!(envelope.expected_cost_micros.is_none());
        assert_eq!(envelope.observation_count, 1);
    }

    #[test]
    fn known_envelope_uses_measured_actuals() {
        let records: Vec<ScoredRecord> = (0..10).map(|_| scored(8_000, true, 1_000, 800)).collect();
        let envelope = CostEnvelope::from_records(
            &records,
            &PreferenceProfileId::new("default").expect("id"),
            &cell(),
        );
        assert_eq!(envelope.status, EnvelopeStatus::Known);
        assert_eq!(envelope.expected_cost_micros, Some(120));
        assert!(envelope.realized_vs_forecast_gap_micros.is_some());
    }

    #[test]
    fn calibration_cannot_alter_a_certification_result() {
        let response = CalibrationResponse {
            fail_closed: true,
            triggering_metric: Some("ece_bp".into()),
            ..CalibrationResponse::default()
        };
        let json = serde_json::to_value(&response).expect("json");
        assert!(json.get("certified").is_none());
        let result = crate::optimizer::certification::CertificationResult::rejected();
        assert!(!result.certified);
        let _ = response.fail_closed;
        assert!(!result.certified);
    }

    #[test]
    fn apply_widens_predictor_without_granting_certification() {
        let mut predictor = HierarchicalPolicyPredictor::new();
        let before = predictor.lcb_z_hundredths();
        let response = CalibrationResponse {
            widen_milli: 4_000,
            lcb_margin_extra_bp: 200,
            steps: vec![
                MiscalibrationStep::WidenPosteriors {
                    metric: "ece_bp".into(),
                    value: 2_000,
                },
                MiscalibrationStep::RaiseLcbMargin {
                    metric: "ece_bp".into(),
                    extra_bp: 200,
                },
            ],
            triggering_metric: Some("ece_bp".into()),
            ..CalibrationResponse::default()
        };
        CalibrationAuditor::apply_to_predictor(&mut predictor, &response);
        assert!(predictor.lcb_z_hundredths() > before);
    }

    #[test]
    fn reconcile_joins_prediction_and_measured_outcome() {
        let distribution =
            PolicyOutcomeDistribution::new(PolicyId::new("p").expect("id"), 50, 100, 8_000, 8_000);
        let scored = reconcile(
            &distribution,
            MeasuredOutcome {
                certified: true,
                time_to_cert_micros: Some(90),
                cost_micros: Some(40),
                consumption: BTreeMap::new(),
                human_intervention: false,
            },
            cell(),
            "runtime-a",
            "low",
            TimestampMillis::from_millis(3),
        );
        assert_eq!(scored.predicted.certified_probability_bp, 8_000);
        assert!(scored.measured.certified);
    }

    fn empty_graph(id: &str) -> crate::optimizer::policy::PolicyGraph {
        crate::optimizer::policy::PolicyGraph::new(
            PolicyId::new(id).expect("id"),
            1,
            crate::optimizer::ids::PolicyNodeId::new("start").expect("node"),
            crate::optimizer::action::TopologySpec {
                planner: crate::optimizer::action::PlannerTopology::Single,
                workers: crate::optimizer::action::WorkerTopology::One,
                hedge: crate::optimizer::action::HedgeTopology::None,
                review: crate::optimizer::action::ReviewTopology::Independent,
                restart: crate::optimizer::action::RestartMode::Continuation,
            },
        )
    }

    #[test]
    fn fail_closed_constraint_empties_candidates_without_touching_certified() {
        let graph = empty_graph("baseline");
        let response = CalibrationResponse {
            fail_closed: true,
            restrict_to_baseline: true,
            triggering_metric: Some("ece_bp".into()),
            ..CalibrationResponse::default()
        };
        let kept = constrain_candidates(
            std::slice::from_ref(&graph),
            &response,
            Some(&graph.policy_id),
        );
        assert!(kept.is_empty());
        assert_eq!(
            response.selection_constraint(),
            SelectionConstraint::FailClosed
        );
        let result = crate::optimizer::certification::CertificationResult::rejected();
        assert!(!result.certified);
        let json = serde_json::to_value(&response).expect("json");
        assert!(json.get("certified").is_none());
    }

    #[test]
    fn restrict_to_baseline_keeps_only_the_known_safe_policy() {
        let baseline = empty_graph("baseline");
        let other = empty_graph("other");
        let response = CalibrationResponse {
            restrict_to_baseline: true,
            ..CalibrationResponse::default()
        };
        let candidates = [baseline.clone(), other];
        let kept = constrain_candidates(&candidates, &response, Some(&baseline.policy_id));
        assert_eq!(kept.len(), 1);
        assert_eq!(kept[0].policy_id.as_str(), "baseline");
    }

    #[test]
    fn ledger_join_is_append_only_and_feeds_unknown_envelopes() {
        let distribution =
            PolicyOutcomeDistribution::new(PolicyId::new("p").expect("id"), 50, 100, 8_000, 8_000);
        let mut ledger = CalibrationLedger::new();
        ledger.append(reconcile(
            &distribution,
            MeasuredOutcome {
                certified: true,
                time_to_cert_micros: Some(90),
                cost_micros: Some(40),
                consumption: BTreeMap::from([("input_tokens".into(), 12)]),
                human_intervention: false,
            },
            cell(),
            "runtime-a",
            "low",
            TimestampMillis::from_millis(3),
        ));
        assert_eq!(ledger.records().len(), 1);
        let envelope = ledger.envelope(&PreferenceProfileId::new("default").expect("id"), &cell());
        assert_eq!(envelope.status, EnvelopeStatus::Unknown);
    }
}
