//! Dated, relative public coding evidence. No class-fit samples or authority are inferred.
use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::{
    AuthorityRole, CandidateKey, ModelPrior, PriorDataset, ReasoningEffort, SelectionError,
    TaskProfile, TaskShapeCeiling,
};

/// An exact higher-is-better fraction in [0, 1], not selector quality.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicBenchmarkScore {
    pub numerator: u32,
    pub denominator: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicBenchmarkRow {
    pub benchmark_id: String,
    pub benchmark_version: String,
    pub metric: String,
    pub score: PublicBenchmarkScore,
    pub runtime: String,
    pub model: String,
    /// Absence is unknown; never substitute another effort or a served default.
    #[serde(default)]
    pub requested_effort: Option<ReasoningEffort>,
    pub source_url: String,
    pub published_on: String,
    pub read_on: String,
    #[serde(default)]
    pub cost_per_task_microunits: Option<u64>,
}

fn default_max_age_days() -> u16 {
    90
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicBenchmarkSnapshot {
    /// Explicit terminal-task applicability; never an authority-role mapping.
    pub task_classes: BTreeSet<String>,
    #[serde(default)]
    pub reference_lane: Option<CandidateKey>,
    /// Both publication and read dates must be within this inclusive window
    /// before the frozen evaluation date. Maximum/default: 90.
    #[serde(default = "default_max_age_days")]
    pub max_age_days: u16,
    pub rows: Vec<PublicBenchmarkRow>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RelativePublicBenchmarkPrior {
    pub quality_basis_points: u16,
    pub cost_per_task_microunits: Option<u64>,
}

fn invalid(message: &str) -> SelectionError {
    SelectionError::InvalidInput(message.into())
}

// Dates are validated first; Gregorian day number, independent of host time.
fn day_number(date: &str) -> Result<u32, SelectionError> {
    super::validate_prior_date("public_benchmark.date", date)?;
    let year: u32 = date[..4].parse().map_err(|_| invalid("invalid year"))?;
    let month: usize = date[5..7].parse().map_err(|_| invalid("invalid month"))?;
    let day: u32 = date[8..].parse().map_err(|_| invalid("invalid day"))?;
    let previous = year - 1;
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let months = [
        31,
        if leap { 29 } else { 28 },
        31,
        30,
        31,
        30,
        31,
        31,
        30,
        31,
        30,
        31,
    ];
    Ok(previous * 365 + previous / 4 - previous / 100
        + previous / 400
        + months[..month - 1].iter().sum::<u32>()
        + day)
}

impl PublicBenchmarkRow {
    fn matches(&self, key: &CandidateKey) -> bool {
        self.runtime == key.runtime
            && self.model == key.model
            && self.requested_effort == Some(key.effort)
    }
}

impl PublicBenchmarkSnapshot {
    pub fn relative_prior(
        &self,
        candidate: &CandidateKey,
        as_of: &str,
    ) -> Option<RelativePublicBenchmarkPrior> {
        let reference_key = self.reference_lane.as_ref()?;
        let reference = self.rows.iter().find(|row| row.matches(reference_key))?;
        let lane = self.rows.iter().find(|row| row.matches(candidate))?;
        if lane.benchmark_id != reference.benchmark_id
            || lane.benchmark_version != reference.benchmark_version
            || lane.metric != reference.metric
            || reference.score.numerator == 0
            || self.max_age_days == 0
            || self.max_age_days > 90
        {
            return None;
        }
        let as_of = day_number(as_of).ok()?;
        for row in [lane, reference] {
            if row.score.denominator == 0 || row.score.numerator > row.score.denominator {
                return None;
            }
            let published = day_number(&row.published_on).ok()?;
            let read = day_number(&row.read_on).ok()?;
            if published > read
                || read > as_of
                || as_of.checked_sub(published)? > u32::from(self.max_age_days)
                || as_of.checked_sub(read)? > u32::from(self.max_age_days)
            {
                return None;
            }
        }
        // u32 fractions leave ample room for exact cross multiplication in u128.
        let numerator = u128::from(lane.score.numerator) * u128::from(reference.score.denominator);
        let denominator =
            u128::from(lane.score.denominator) * u128::from(reference.score.numerator);
        let quality = ((numerator * 10_000 / denominator).min(10_000)) as u16;
        Some(RelativePublicBenchmarkPrior {
            quality_basis_points: quality,
            cost_per_task_microunits: lane.cost_per_task_microunits,
        })
    }
}

impl PriorDataset {
    pub(crate) fn validate_public_benchmarks(&self) -> Result<(), SelectionError> {
        if let Some(as_of) = &self.public_benchmarks_evaluated_on {
            day_number(as_of)?;
            if as_of < &self.published_on {
                return Err(invalid(
                    "public benchmark evaluation predates snapshot publication",
                ));
            }
        }
        let mut seen = BTreeSet::new();
        for snapshot in &self.public_benchmarks {
            if snapshot.max_age_days == 0
                || snapshot.max_age_days > 90
                || snapshot.task_classes.is_empty()
                || snapshot
                    .task_classes
                    .iter()
                    .any(|class| class.trim().is_empty())
            {
                return Err(invalid(
                    "public benchmark requires task classes and a 1..=90 day window",
                ));
            }
            let mut rows = BTreeSet::new();
            for row in &snapshot.rows {
                if [
                    &row.benchmark_id,
                    &row.benchmark_version,
                    &row.metric,
                    &row.runtime,
                    &row.model,
                ]
                .iter()
                .any(|value| value.trim().is_empty())
                    || !row.source_url.starts_with("https://")
                    || row.source_url.len() <= 8
                    || row.score.denominator == 0
                    || row.score.numerator > row.score.denominator
                {
                    return Err(invalid(
                        "malformed public benchmark row or missing HTTPS provenance",
                    ));
                }
                day_number(&row.published_on)?;
                day_number(&row.read_on)?;
                let key = (&row.runtime, &row.model, row.requested_effort);
                if !rows.insert(key) {
                    return Err(invalid("ambiguous public benchmark lane within snapshot"));
                }
                for class in &snapshot.task_classes {
                    if !seen.insert((class, key)) {
                        return Err(invalid(
                            "public benchmark lanes cannot be compared across snapshots",
                        ));
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn public_benchmark_applies(&self, candidate: &CandidateKey) -> bool {
        self.public_benchmarks.iter().any(|snapshot| {
            snapshot
                .rows
                .iter()
                .any(|row| row.runtime == candidate.runtime && row.model == candidate.model)
        })
    }

    pub fn relative_public_prior(
        &self,
        candidate: &CandidateKey,
        task: &TaskProfile,
    ) -> Option<RelativePublicBenchmarkPrior> {
        let ceiling = TaskShapeCeiling::bounded_terminal();
        if task.authority_role != AuthorityRole::TerminalLeaf
            || !ceiling.boundedness.contains(&task.boundedness)
            || task.risk > ceiling.maximum_risk
            || task.context > ceiling.maximum_context
            || task.horizon > ceiling.maximum_horizon
        {
            return None;
        }
        self.public_benchmarks
            .iter()
            .find(|snapshot| {
                snapshot.task_classes.contains(&task.task_class)
                    && snapshot.rows.iter().any(|row| row.matches(candidate))
            })?
            .relative_prior(
                candidate,
                self.public_benchmarks_evaluated_on
                    .as_deref()
                    .unwrap_or(&self.published_on),
            )
    }

    pub(crate) fn public_benchmark_efforts(
        &self,
        runtime: &str,
        model: &str,
        task: &TaskProfile,
    ) -> BTreeSet<ReasoningEffort> {
        self.public_benchmarks
            .iter()
            .flat_map(|snapshot| &snapshot.rows)
            .filter(|row| row.runtime == runtime && row.model == model)
            .filter_map(|row| row.requested_effort)
            .filter(|effort| {
                self.relative_public_prior(
                    &CandidateKey {
                        runtime: runtime.into(),
                        model: model.into(),
                        effort: *effort,
                    },
                    task,
                )
                .is_some()
            })
            .collect()
    }

    /// Create bounded, execution-only identities for new lanes. Existing operator
    /// rows (including prohibitions, authority and reviewer strength) are untouched.
    pub(crate) fn add_public_benchmark_models(&mut self) {
        for snapshot in &self.public_benchmarks {
            for row in &snapshot.rows {
                if self
                    .models
                    .iter()
                    .any(|prior| prior.runtime == row.runtime && prior.model == row.model)
                {
                    continue;
                }
                self.models.push(ModelPrior {
                    runtime: row.runtime.clone(), model: row.model.clone(),
                    observed_on: self.published_on.clone(), source_id: "dated-public-benchmark".into(),
                    prior_scope: "relative public coding benchmark; bounded terminal execution only".into(),
                    limitations: vec!["No class-fit samples, judgment authority, reviewer strength or complete accepted-cycle costs inferred".into()],
                    prohibited: false, prohibition_reason: None,
                    prohibited_authority_roles: [AuthorityRole::Delegating, AuthorityRole::AcceptanceGate,
                        AuthorityRole::ReviewAuditor, AuthorityRole::Audit, AuthorityRole::ConflictResolution,
                        AuthorityRole::FailureClassification, AuthorityRole::GitPublication, AuthorityRole::UnknownJudgment].into_iter().collect(),
                    long_context_eligible: false, task_shape_ceiling: Some(TaskShapeCeiling::bounded_terminal()),
                    strong_gate_fallback_efforts: BTreeSet::new(), strength_rank: 0,
                    class_fit: Vec::new(), authority_evidence: Vec::new(), one_shot_environment_fallbacks: Vec::new(),
                });
            }
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::selection::{self, tests::loaded_policy_test_receipt, IneligibilityCode};

    pub(crate) fn synthetic_snapshot() -> PublicBenchmarkSnapshot {
        // Entirely synthetic scores; no claim about any real model or benchmark.
        let row = |model: &str, numerator| PublicBenchmarkRow {
            benchmark_id: "synthetic-coding".into(),
            benchmark_version: "v1".into(),
            metric: "pass@1".into(),
            score: PublicBenchmarkScore {
                numerator,
                denominator: 100,
            },
            runtime: "codex".into(),
            model: model.into(),
            requested_effort: Some(ReasoningEffort::Low),
            source_url: "https://example.invalid/synthetic-benchmark".into(),
            published_on: "2026-10-15".into(),
            read_on: "2026-11-03".into(),
            cost_per_task_microunits: None,
        };
        PublicBenchmarkSnapshot {
            task_classes: ["localized_code_change".into(), "review_gate".into()]
                .into_iter()
                .collect(),
            reference_lane: Some(CandidateKey {
                runtime: "codex".into(),
                model: "synthetic-reference".into(),
                effort: ReasoningEffort::Low,
            }),
            max_age_days: 90,
            rows: vec![row("synthetic-reference", 50), row("synthetic-worker", 45)],
        }
    }

    fn input() -> selection::SelectionInput {
        let mut input = selection::selection_test_base_input();
        input.priors.published_on = "2026-11-03".into();
        input.priors.public_benchmarks = vec![synthetic_snapshot()];
        input.priors.add_public_benchmark_models();
        input.catalogs.truncate(1);
        input.catalogs[0].models.truncate(1);
        input.catalogs[0].models[0].model = "synthetic-worker".into();
        input.catalogs[0].models[0].supported_efforts = vec![ReasoningEffort::Low];
        input
    }

    fn key() -> CandidateKey {
        CandidateKey {
            runtime: "codex".into(),
            model: "synthetic-worker".into(),
            effort: ReasoningEffort::Low,
        }
    }

    #[test]
    fn public_benchmark_relative_quality_supports_terminal_roles_without_costs_or_samples(
    ) -> anyhow::Result<()> {
        for role in ["worker", "researcher"] {
            let mut input = input();
            let mut receipt = loaded_policy_test_receipt()?;
            receipt.role = role.into();
            if role == "researcher" {
                input.task.task_class = "review_gate".into();
            }
            let prior = input
                .priors
                .relative_public_prior(&key(), &input.task)
                .expect("same benchmark reference");
            assert_eq!(prior.quality_basis_points, 9000);
            let decision =
                selection::select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
            assert_eq!(
                decision
                    .choice
                    .as_ref()
                    .expect("eligible terminal lane")
                    .candidate,
                key()
            );
            let evidence = decision.candidate_set[0]
                .loaded_policy_evidence
                .as_ref()
                .expect("explicit evidence");
            assert_eq!(evidence.quality_basis_points, Some(9000));
            assert_eq!(evidence.expected_accepted_cycle_cost_microunits, None);
            assert!(evidence.uncertainty_penalty > 0);
            assert_eq!(evidence.samples, 0);
        }
        Ok(())
    }

    #[test]
    fn public_benchmark_unknown_comparisons_never_become_eligible() -> anyhow::Result<()> {
        for case in [
            "no-reference",
            "absent-reference-row",
            "zero-reference",
            "reference-effort",
            "stale-lane",
            "stale-reference",
            "version",
            "benchmark",
            "metric",
            "effort",
            "future-read",
            "date-order",
            "unmapped-task",
            "bounds",
        ] {
            let mut input = input();
            let snapshot = &mut input.priors.public_benchmarks[0];
            match case {
                "no-reference" => snapshot.reference_lane = None,
                "absent-reference-row" => {
                    snapshot.rows.remove(0);
                }
                "zero-reference" => snapshot.rows[0].score.numerator = 0,
                "reference-effort" => snapshot.rows[0].requested_effort = None,
                "stale-lane" => {
                    snapshot.rows[1].published_on = "2026-08-04".into();
                }
                "stale-reference" => {
                    snapshot.rows[0].published_on = "2026-08-04".into();
                }
                "version" => {
                    snapshot.rows[1].benchmark_version = "v2".into();
                }
                "benchmark" => {
                    snapshot.rows[1].benchmark_id = "other-synthetic".into();
                }
                "metric" => {
                    snapshot.rows[1].metric = "different".into();
                }
                "effort" => {
                    snapshot.rows[1].requested_effort = None;
                }
                "future-read" => {
                    snapshot.rows[1].read_on = "2026-11-04".into();
                }
                "date-order" => {
                    snapshot.rows[1].read_on = "2026-10-01".into();
                }
                "unmapped-task" => {
                    input.task.task_class = "unmapped".into();
                }
                "bounds" => {
                    input.task.risk = selection::RiskLevel::High;
                }
                _ => unreachable!(),
            };
            assert!(
                input
                    .priors
                    .relative_public_prior(&key(), &input.task)
                    .is_none(),
                "{case}"
            );
            let decision = selection::select_with_loaded_routing_policy(
                &input,
                &[],
                Some(&loaded_policy_test_receipt()?),
            )?;
            assert!(decision.choice.is_none(), "{case}: {decision:?}");
        }
        Ok(())
    }

    #[test]
    fn public_benchmark_floor_cap_window_and_effort_are_exact() -> anyhow::Result<()> {
        let mut input = input();
        let snapshot = &mut input.priors.public_benchmarks[0];
        snapshot.rows[1].score.numerator = 100;
        assert_eq!(
            snapshot
                .relative_prior(&key(), "2026-11-03")
                .unwrap()
                .quality_basis_points,
            10_000
        );
        snapshot.rows[1].published_on = "2026-08-05".into(); // exactly 90 days
        assert!(snapshot.relative_prior(&key(), "2026-11-03").is_some());
        snapshot.rows[1].published_on = "2026-08-04".into();
        assert!(snapshot.relative_prior(&key(), "2026-11-03").is_none());
        snapshot.rows[1].published_on = "2026-10-15".into();
        snapshot.rows[1].score.numerator = 39; // 7800 bp against 50/100, below unchanged 8000 floor
        let decision = selection::select_with_loaded_routing_policy(
            &input,
            &[],
            Some(&loaded_policy_test_receipt()?),
        )?;
        assert!(decision.choice.is_none());
        assert!(decision.candidate_set[0]
            .ineligibility_reasons
            .iter()
            .any(|reason| reason.code == IneligibilityCode::QualityBarNotMet));
        let mut other = key();
        other.effort = ReasoningEffort::Xhigh;
        assert!(input
            .priors
            .relative_public_prior(&other, &input.task)
            .is_none());
        Ok(())
    }

    #[test]
    fn public_benchmark_never_supplies_authority_samples_or_reviewer_strength() -> anyhow::Result<()>
    {
        for authority in [
            AuthorityRole::Delegating,
            AuthorityRole::AcceptanceGate,
            AuthorityRole::ReviewAuditor,
            AuthorityRole::Audit,
            AuthorityRole::ConflictResolution,
            AuthorityRole::FailureClassification,
            AuthorityRole::GitPublication,
            AuthorityRole::UnknownJudgment,
        ] {
            let mut input = input();
            input.task.authority_role = authority;
            for loaded in [true, false] {
                let receipt = loaded_policy_test_receipt()?;
                let decision = selection::select_with_loaded_routing_policy(
                    &input,
                    &[],
                    loaded.then_some(&receipt),
                )?;
                assert!(decision.choice.is_none(), "{authority:?}");
            }
        }
        let mut input = input();
        let before = input
            .priors
            .models
            .iter()
            .find(|prior| prior.model == "gpt-5.6-sol")
            .unwrap()
            .clone();
        input.priors.public_benchmarks[0].rows[1].model = "gpt-5.6-sol".into();
        input.priors.add_public_benchmark_models();
        assert_eq!(
            &before,
            input
                .priors
                .models
                .iter()
                .find(|prior| prior.model == "gpt-5.6-sol")
                .unwrap()
        );
        input.priors.public_benchmarks[0].rows[1].model = "synthetic-worker".into();
        let mut receipt = loaded_policy_test_receipt()?;
        receipt.frozen.policy.default_role.require_measured_quality = true;
        receipt.frozen.sha256 =
            crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(&receipt.frozen.policy)?);
        assert!(
            selection::select_with_loaded_routing_policy(&input, &[], Some(&receipt))?
                .choice
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn public_benchmark_preserves_other_gates_and_cost_uncertainty() -> anyhow::Result<()> {
        for gate in ["catalog", "admission", "constraint", "role-floor"] {
            let mut input = input();
            let mut receipt = loaded_policy_test_receipt()?;
            match gate {
                "catalog" => input.catalogs[0].models[0].available = false,
                "admission" => input.pools[0].admission_open = false,
                "constraint" => {
                    input.constraints.forbidden_models.insert(key().model);
                }
                "role-floor" => {
                    receipt
                        .frozen
                        .policy
                        .default_role
                        .minimum_quality_basis_points = 9500
                }
                _ => unreachable!(),
            }
            receipt.frozen.sha256 = crate::artifacts::state_auth::sha256_hex(&serde_json::to_vec(
                &receipt.frozen.policy,
            )?);
            assert!(
                selection::select_with_loaded_routing_policy(&input, &[], Some(&receipt))?
                    .choice
                    .is_none(),
                "{gate}"
            );
        }
        let mut input = input();
        input.priors.public_benchmarks[0].rows[1].cost_per_task_microunits = Some(1234);
        let decision = selection::select_with_loaded_routing_policy(
            &input,
            &[],
            Some(&loaded_policy_test_receipt()?),
        )?;
        let evidence = decision.candidate_set[0]
            .loaded_policy_evidence
            .as_ref()
            .unwrap();
        assert_eq!(evidence.expected_accepted_cycle_cost_microunits, Some(1234));
        assert!(evidence.uncertainty_penalty > 0);
        Ok(())
    }

    #[test]
    fn public_benchmark_defaults_strict_schema_and_replay_are_preserved() -> anyhow::Result<()> {
        let mut raw = serde_json::to_value(synthetic_snapshot())?;
        raw.as_object_mut().unwrap().remove("max_age_days");
        raw["rows"][1]
            .as_object_mut()
            .unwrap()
            .remove("requested_effort");
        let decoded: PublicBenchmarkSnapshot = serde_json::from_value(raw.clone())?;
        assert_eq!(decoded.max_age_days, 90);
        assert!(decoded.relative_prior(&key(), "2026-11-03").is_none());
        raw["unrecognized_grant"] = serde_json::json!(true);
        assert!(serde_json::from_value::<PublicBenchmarkSnapshot>(raw).is_err());
        let input = input();
        let receipt = loaded_policy_test_receipt()?;
        let decision = selection::select_with_loaded_routing_policy(&input, &[], Some(&receipt))?;
        let id = "https://example.invalid/selection-public-benchmark";
        let mut compiler = boon::Compiler::new();
        compiler
            .add_resource(
                id,
                super::super::schema::selection_provenance_schema_value(),
            )
            .map_err(|error| anyhow::anyhow!("register public benchmark schema: {error:#}"))?;
        let mut schemas = boon::Schemas::new();
        let index = compiler
            .compile(id, &mut schemas)
            .map_err(|error| anyhow::anyhow!("compile public benchmark schema: {error:#}"))?;
        schemas
            .validate(&serde_json::to_value(&decision)?, index)
            .map_err(|error| anyhow::anyhow!("{error}"))?;
        let mut reordered = input;
        reordered.priors.public_benchmarks[0].rows.reverse();
        assert_eq!(
            decision,
            selection::select_with_loaded_routing_policy(&reordered, &[], Some(&receipt))?
        );
        Ok(())
    }

    #[test]
    fn public_benchmark_ambiguous_or_malformed_snapshots_are_refused() {
        let mut input = input();
        input.priors.public_benchmarks.push(synthetic_snapshot());
        assert!(selection::validate_prior_dataset(&input.priors).is_err());
        input.priors.public_benchmarks.pop();
        input.priors.public_benchmarks[0].rows[0].score.denominator = 0;
        assert!(selection::validate_prior_dataset(&input.priors).is_err());
    }
}
