//! Campaign-measured model observations re-homed as optimizer seed evidence (#180).
//!
//! These records are data, not policy. They never select a `(runtime, model,
//! effort)` triple and they cannot relax [`crate::optimizer::EvaluationFunction`]'s
//! quality floor. Ranking authority is the evaluation function: certified
//! quality is a hard constraint and cost-to-certification is the sole
//! objective. A static role→model table in this document is a schema
//! violation and fails closed.

use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};

use super::error::OptimizerError;
use super::features::{FeatureBag, FeatureValue};
use super::ids::FeatureId;

pub const SEED_EVIDENCE_SCHEMA: &str = "maco.optimizer.seed-evidence.v0";
pub const SHIPPED_SEED_EVIDENCE_JSON: &str = include_str!("data/seed-evidence-v0.json");

/// Tracked seed-evidence document. Unknown top-level keys fail closed so a
/// role→model table cannot be smuggled in as "observations".
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedEvidenceDocument {
    pub schema: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub note: String,
    pub observations: Vec<SeedObservation>,
}

/// One measured observation. Extra policy fields (`role`, `rules`, `tier`)
/// fail closed via `deny_unknown_fields`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SeedObservation {
    pub model: String,
    pub axis: String,
    pub source: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value_relative_to: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub range: Option<Vec<Value>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unit: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub input: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub output: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta_vs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub delta: Option<Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

pub fn load_shipped_seed_evidence() -> Result<SeedEvidenceDocument, OptimizerError> {
    parse_seed_evidence(SHIPPED_SEED_EVIDENCE_JSON)
}

pub fn parse_seed_evidence(json: &str) -> Result<SeedEvidenceDocument, OptimizerError> {
    let document: SeedEvidenceDocument = serde_json::from_str(json).map_err(|error| {
        OptimizerError::invalid(format!(
            "seed evidence is not a valid observation document: {error}"
        ))
    })?;
    document.validate()?;
    Ok(document)
}

impl SeedEvidenceDocument {
    pub fn validate(&self) -> Result<(), OptimizerError> {
        if self.schema != SEED_EVIDENCE_SCHEMA {
            return Err(OptimizerError::invalid(format!(
                "unsupported seed evidence schema '{}'",
                self.schema
            )));
        }
        if self.observations.is_empty() {
            return Err(OptimizerError::invalid(
                "seed evidence must contain at least one observation",
            ));
        }
        for observation in &self.observations {
            observation.validate()?;
        }
        Ok(())
    }

    /// Feature bags keyed by measured model slug. This is evidence for later
    /// telemetry/feature ingest, not a selected execution policy.
    pub fn feature_bags(&self) -> Result<Vec<(String, FeatureBag)>, OptimizerError> {
        let mut bags: Vec<(String, FeatureBag)> = Vec::new();
        for observation in &self.observations {
            let entries = observation.feature_entries()?;
            if entries.is_empty() {
                continue;
            }
            if let Some((_, bag)) = bags
                .iter_mut()
                .find(|(model, _)| model == &observation.model)
            {
                for (id, value) in entries {
                    bag.insert(id, value);
                }
            } else {
                let mut bag = FeatureBag::new();
                for (id, value) in entries {
                    bag.insert(id, value);
                }
                bags.push((observation.model.clone(), bag));
            }
        }
        Ok(bags)
    }
}

impl SeedObservation {
    fn validate(&self) -> Result<(), OptimizerError> {
        for (name, value) in [
            ("model", self.model.as_str()),
            ("axis", self.axis.as_str()),
            ("source", self.source.as_str()),
        ] {
            if value.is_empty() || value != value.trim() {
                return Err(OptimizerError::invalid(format!(
                    "seed observation {name} must be a non-empty trimmed string"
                )));
            }
        }
        Ok(())
    }

    fn feature_entries(&self) -> Result<Vec<(FeatureId, FeatureValue)>, OptimizerError> {
        let mut entries = Vec::new();
        if let Some(value) = &self.value {
            entries.push((self.feature_id("")?, json_feature_value(value, "value")?));
        }
        if let Some(input) = &self.input {
            entries.push((
                self.feature_id("input")?,
                json_feature_value(input, "input")?,
            ));
        }
        if let Some(output) = &self.output {
            entries.push((
                self.feature_id("output")?,
                json_feature_value(output, "output")?,
            ));
        }
        if let Some(delta) = &self.delta {
            entries.push((
                self.feature_id("delta")?,
                json_feature_value(delta, "delta")?,
            ));
        }
        Ok(entries)
    }

    fn feature_id(&self, suffix: &str) -> Result<FeatureId, OptimizerError> {
        let key = if suffix.is_empty() {
            format!("seed.{}.{}", self.model, self.axis)
        } else {
            format!("seed.{}.{}.{}", self.model, self.axis, suffix)
        };
        FeatureId::new(key)
    }
}

fn json_feature_value(value: &Value, field: &str) -> Result<FeatureValue, OptimizerError> {
    match value {
        Value::Number(number) => Ok(FeatureValue::Micro(number_to_micro(number, field)?)),
        Value::String(text) => {
            if text.trim().is_empty() || text != text.trim() {
                return Err(OptimizerError::invalid(format!(
                    "seed observation {field} string must be non-empty and trimmed"
                )));
            }
            Ok(FeatureValue::Text(text.clone()))
        }
        _ => Err(OptimizerError::invalid(format!(
            "seed observation {field} must be a number or string"
        ))),
    }
}

fn number_to_micro(number: &Number, field: &str) -> Result<i64, OptimizerError> {
    if let Some(integer) = number.as_i64() {
        return integer.checked_mul(1_000_000).ok_or_else(|| {
            OptimizerError::invalid(format!("seed observation {field} overflows micro units"))
        });
    }
    let value = number.as_f64().ok_or_else(|| {
        OptimizerError::invalid(format!("seed observation {field} is not a finite number"))
    })?;
    if !value.is_finite() {
        return Err(OptimizerError::invalid(format!(
            "seed observation {field} is not a finite number"
        )));
    }
    let micro = (value * 1_000_000.0).round();
    if micro < i64::MIN as f64 || micro > i64::MAX as f64 {
        return Err(OptimizerError::invalid(format!(
            "seed observation {field} overflows micro units"
        )));
    }
    #[allow(clippy::cast_possible_truncation)]
    Ok(micro as i64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::optimizer::action::CanonicalEffort;
    use crate::optimizer::evaluation_fn::{EvaluatedPolicy, EvaluationFunction, EvaluationOutcome};
    use crate::optimizer::ids::PolicyId;

    #[test]
    fn shipped_seed_evidence_is_observations_not_a_role_model_table() {
        let document = load_shipped_seed_evidence().expect("shipped seed evidence");
        assert_eq!(document.schema, SEED_EVIDENCE_SCHEMA);
        assert!(document.note.contains("Data, not policy"));
        assert!(!document.observations.is_empty());
        let encoded = serde_json::to_value(&document).expect("encode");
        let object = encoded.as_object().expect("object");
        assert!(!object.contains_key("role_models"));
        assert!(!object.contains_key("rules"));
        assert!(!object.contains_key("defaults"));
        assert!(!object.contains_key("selected_model"));
        assert!(!object.contains_key("policy"));
        let bags = document.feature_bags().expect("feature bags");
        assert!(!bags.is_empty());
        assert!(bags.iter().all(|(_, bag)| !bag.is_empty()));
    }

    #[test]
    fn role_model_table_fails_closed_as_seed_evidence() {
        let error = parse_seed_evidence(
            r#"{
                "schema": "maco.optimizer.seed-evidence.v0",
                "observations": [
                    {"model": "any", "axis": "cost", "value": 1, "source": "test"}
                ],
                "role_models": {"worker": "any"}
            }"#,
        )
        .expect_err("role_models must fail closed");
        assert!(
            error
                .to_string()
                .contains("seed evidence is not a valid observation document"),
            "{error}"
        );
    }

    #[test]
    fn empty_or_rule_shaped_documents_fail_closed() {
        let empty = parse_seed_evidence(
            r#"{
                "schema": "maco.optimizer.seed-evidence.v0",
                "observations": []
            }"#,
        )
        .expect_err("empty observations");
        assert!(empty.to_string().contains("at least one observation"));

        let wrong_schema = parse_seed_evidence(
            r#"{
                "schema": "maco.optimizer.model-policy.v1",
                "observations": [
                    {"model": "any", "axis": "cost", "value": 1, "source": "test"}
                ]
            }"#,
        )
        .expect_err("wrong schema");
        assert!(wrong_schema
            .to_string()
            .contains("unsupported seed evidence schema"));
    }

    #[test]
    fn seed_evidence_cannot_buy_down_the_evaluation_quality_floor() {
        let _document = load_shipped_seed_evidence().expect("shipped seed evidence");
        let eval = EvaluationFunction::shipped_default();
        let outcome = eval.evaluate(&[EvaluatedPolicy {
            policy_id: PolicyId::new("weak-lcb").expect("policy id"),
            certified_quality: true,
            quality_lower_confidence_bp: 7_999,
            cost_to_certification_micros: 1,
            resource_constraints_satisfied: true,
            effort: CanonicalEffort::Low,
        }]);
        assert!(matches!(outcome, EvaluationOutcome::Infeasible { .. }));
        assert!(!outcome.may_merge());
        assert!(!outcome.may_publish());
    }

    #[test]
    fn ranking_and_seed_modules_do_not_load_campaign_model_policy() {
        let seed_production = include_str!("seed_evidence.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("seed evidence production source");
        let sources = [include_str!("evaluation_fn.rs"), seed_production].join("\n");
        for needle in [
            ["MODEL_", "POLICY.md"].concat(),
            ["campaign-", "20260816"].concat(),
            ["campaign-", "g18"].concat(),
        ] {
            assert!(
                !sources.contains(&needle),
                "optimizer ranking/evidence path still names campaign policy {needle}"
            );
        }
        assert!(
            !include_str!("evaluation_fn.rs").contains("role_models"),
            "evaluation function must not encode a role_models table"
        );
    }

    #[test]
    fn tracked_tree_contains_no_campaign_model_policy_markdown() {
        let output = std::process::Command::new("git")
            .args(["ls-files", "-z", "--", "*.md"])
            .current_dir(env!("CARGO_MANIFEST_DIR"))
            .output()
            .expect("git ls-files");
        assert!(output.status.success(), "git ls-files failed");
        let tracked = String::from_utf8_lossy(&output.stdout);
        assert!(
            !tracked.contains("MODEL_POLICY.md"),
            "tracked MODEL_POLICY.md must not exist"
        );
    }
}
