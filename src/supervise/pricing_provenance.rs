use crate::llm::pricing_contract::OperatorPricingContract;
use serde::{Deserialize, Serialize};

/// Frozen operator metadata for an estimate, never an invoice or quota conversion.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PricingContractProvenance {
    pub contract: OperatorPricingContract,
    pub normalized_sha256: String,
    pub plan_id: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ChargePricingBasis {
    /// Historical or direct ledger callers did not attest a pricing basis.
    #[default]
    Unattributed,
    OperatorContractEstimate,
    Synthetic,
    Unpriced,
    ConservativeReservation,
    /// Parent-observed native cost-equivalent units, without a USD conversion.
    ProviderNativeCostEquivalent,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ChargePricing {
    pub basis: ChargePricingBasis,
    /// A retained contract does not establish that this charge was priceable.
    pub contract: Option<PricingContractProvenance>,
    pub runtime: Option<String>,
    /// The settlement allocation; absent when a single model cannot be established.
    pub model: Option<String>,
}

/// Pricing basis for one attributable dispatch and its outcome cost phase.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OutcomeChargePricing {
    pub reservation_id: u64,
    pub phase: OutcomeCostPhase,
    pub pricing: ChargePricing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OutcomeCostPhase {
    Execution,
    Rework,
    Review,
    Rereview,
    UnknownReview,
}

pub(crate) fn outcome_charge_schema_value() -> serde_json::Value {
    serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["reservation_id", "phase", "pricing"],
        "properties": {
            "reservation_id": {"type": "integer", "minimum": 1},
            "phase": {"enum": ["execution", "rework", "review", "rereview", "unknown_review"]},
            "pricing": charge_schema_value(serde_json::json!({}))["properties"]["pricing"].clone()
        }
    })
}

pub(super) fn contract_schema_value() -> serde_json::Value {
    serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["contract", "normalized_sha256", "plan_id"],
        "properties": {
            "contract": super::schema_artifacts::operator_pricing_plan_schema_value()["$defs"]["contract"].clone(),
            "normalized_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "plan_id": {"type": "string", "minLength": 1}
        }
    })
}

pub(super) fn charge_schema_value(role_schema: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["reservation_id", "role", "tokens", "cost_usd", "usage_complete", "pricing"],
        "properties": {
            "reservation_id": {"type": "integer", "minimum": 1},
            "role": role_schema,
            "tokens": {"type": "integer", "minimum": 0},
            "cost_usd": {"type": ["number", "null"], "minimum": 0},
            "usage_complete": {"type": "boolean"},
            "pricing": {
                "type": "object", "additionalProperties": false,
                "required": ["basis", "contract", "runtime", "model"],
                "properties": {
                    "basis": {"enum": ["unattributed", "operator_contract_estimate", "synthetic", "unpriced", "conservative_reservation", "provider_native_cost_equivalent"]},
                    "contract": {"oneOf": [{"type": "null"}, contract_schema_value()]},
                    "runtime": {"type": ["string", "null"]},
                    "model": {"type": ["string", "null"]}
                }
            }
        }
    })
}
