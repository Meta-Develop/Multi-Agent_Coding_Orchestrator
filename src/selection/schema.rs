//! Authoritative strict JSON Schema fragments for published selector events.

use serde_json::{json, Value};

macro_rules! strict_object {
    ($($name:literal => $schema:expr),+ $(,)?) => {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": [$($name),+],
            "properties": {$($name: $schema),+}
        })
    };
}

fn string() -> Value {
    json!({"type": "string"})
}

fn nonempty_string() -> Value {
    json!({"type": "string", "minLength": 1})
}

fn nonnegative_integer() -> Value {
    json!({"type": "integer", "minimum": 0})
}

fn positive_integer() -> Value {
    json!({"type": "integer", "minimum": 1})
}

fn basis_points() -> Value {
    json!({"type": "integer", "minimum": 0, "maximum": 10_000})
}

fn nullable(schema: Value) -> Value {
    json!({"oneOf": [schema, {"type": "null"}]})
}

fn array(items: Value) -> Value {
    json!({"type": "array", "items": items})
}

fn set(items: Value) -> Value {
    json!({"type": "array", "items": items, "uniqueItems": true})
}

fn enum_schema(values: &[&str]) -> Value {
    json!({"type": "string", "enum": values})
}

fn date() -> Value {
    json!({"type": "string", "pattern": "^[0-9]{4}-[0-9]{2}-[0-9]{2}$"})
}

fn reasoning_effort() -> Value {
    enum_schema(&["low", "medium", "high", "xhigh", "max", "ultra"])
}

fn risk(include_unknown: bool) -> Value {
    if include_unknown {
        enum_schema(&["low", "medium", "high", "critical", "unknown"])
    } else {
        enum_schema(&["low", "medium", "high", "critical"])
    }
}

fn boundedness(include_unknown: bool) -> Value {
    if include_unknown {
        enum_schema(&["tightly_bounded", "bounded", "cross_cutting", "unknown"])
    } else {
        enum_schema(&["tightly_bounded", "bounded", "cross_cutting"])
    }
}

fn context_size(include_unknown: bool) -> Value {
    if include_unknown {
        enum_schema(&["small", "medium", "large", "long", "unknown"])
    } else {
        enum_schema(&["small", "medium", "large", "long"])
    }
}

fn task_horizon(include_unknown: bool) -> Value {
    if include_unknown {
        enum_schema(&["short", "medium", "long", "unknown"])
    } else {
        enum_schema(&["short", "medium", "long"])
    }
}

fn authority_role() -> Value {
    enum_schema(&[
        "terminal_leaf",
        "delegating",
        "acceptance_gate",
        "review_auditor",
        "audit",
        "conflict_resolution",
        "failure_classification",
        "git_publication",
        "unknown_judgment",
    ])
}

fn task_profile(include_unknown_shape: bool) -> Value {
    strict_object!(
        "task_class" => nonempty_string(),
        "risk" => risk(include_unknown_shape),
        "boundedness" => boundedness(include_unknown_shape),
        "context" => context_size(include_unknown_shape),
        "horizon" => task_horizon(include_unknown_shape),
        "authority_role" => authority_role(),
    )
}

fn candidate_key() -> Value {
    strict_object!(
        "runtime" => nonempty_string(),
        "model" => nonempty_string(),
        "effort" => reasoning_effort(),
    )
}

fn candidate_capabilities() -> Value {
    strict_object!(
        "task_classes" => set(nonempty_string()),
        "authority_roles" => set(authority_role()),
        "boundedness" => set(boundedness(true)),
        "maximum_risk" => risk(true),
        "maximum_context" => context_size(true),
        "maximum_horizon" => task_horizon(true),
        "long_context" => json!({"type": "boolean"}),
    )
}

fn catalog_model() -> Value {
    strict_object!(
        "model" => nonempty_string(),
        "available" => json!({"type": "boolean"}),
        "supported_efforts" => set(reasoning_effort()),
        "capabilities" => candidate_capabilities(),
    )
}

fn runtime_catalog() -> Value {
    strict_object!(
        "runtime" => nonempty_string(),
        "revision" => nonempty_string(),
        "advertised_at" => nonempty_string(),
        "models" => array(catalog_model()),
    )
}

fn quota_pool_kind() -> Value {
    enum_schema(&["subscription_included", "metered", "prepaid_credits"])
}

fn quota_reset_window() -> Value {
    json!({
        "oneOf": [
            {"type": "string", "enum": ["none", "calendar_month"]},
            strict_object!(
                "rolling_hours" => strict_object!(
                    "hours" => positive_integer(),
                ),
            )
        ]
    })
}

fn pool_reference() -> Value {
    strict_object!(
        "runtime" => nonempty_string(),
        "account" => nonempty_string(),
        "window" => quota_reset_window(),
    )
}

fn exhaustion_behavior() -> Value {
    enum_schema(&["fail_closed", "degrade"])
}

fn consumption_source() -> Value {
    enum_schema(&["local_observed", "provider_reported"])
}

fn runtime_pool_state() -> Value {
    strict_object!(
        "runtime" => nonempty_string(),
        "admission_open" => json!({"type": "boolean"}),
        "pool_reference" => nullable(pool_reference()),
        "pool_kind" => nullable(quota_pool_kind()),
        "entitlement_bounded" => json!({"type": "boolean"}),
        "entitlement_capacity_units" => nonnegative_integer(),
        "entitlement_remaining_units" => nonnegative_integer(),
        "pool_pressure_basis_points" => basis_points(),
        "observed_consumption_units" => nonnegative_integer(),
        "marginal_cost_microunits" => nonnegative_integer(),
        "exhausted" => json!({"type": "boolean"}),
        "exhaustion_behavior" => nullable(exhaustion_behavior()),
        "authorized_alternatives" => array(pool_reference()),
        "observation_revision" => nonempty_string(),
        "observation_source" => nullable(consumption_source()),
        "admission_provenance" => nonempty_string(),
        "failover_provenance" => nullable(nonempty_string()),
    )
}

fn operator_constraints() -> Value {
    strict_object!(
        "allowed_runtimes" => set(string()),
        "allowed_models" => set(string()),
        "forbidden_runtimes" => set(string()),
        "forbidden_models" => set(string()),
        "forbidden_candidates" => set(candidate_key()),
        "allow_debug_override" => json!({"type": "boolean"}),
    )
}

fn selector_calibration_ref() -> Value {
    strict_object!(
        "name" => nonempty_string(),
        "version" => positive_integer(),
        "expected_digest" => nullable(json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})),
    )
}

fn context_switch_costs() -> Value {
    strict_object!(
        "model_change_same_runtime_microunits" => nonnegative_integer(),
        "runtime_change_microunits" => nonnegative_integer(),
    )
}

fn routing_quality_weights() -> Value {
    strict_object!(
        "held_out_percent" => json!({"type": "integer", "minimum": 0, "maximum": 100}),
        "breadth_percent" => json!({"type": "integer", "minimum": 0, "maximum": 100}),
        "anti_shortcut_percent" => json!({"type": "integer", "minimum": 0, "maximum": 100}),
    )
}

fn routing_tradeoff_weights() -> Value {
    strict_object!(
        "monetary_cost_percent" => json!({"type": "integer", "minimum": 0, "maximum": 100}),
        "quota_consumption_percent" => json!({"type": "integer", "minimum": 0, "maximum": 100}),
        "latency_percent" => json!({"type": "integer", "minimum": 0, "maximum": 100}),
        "retry_rework_percent" => json!({"type": "integer", "minimum": 0, "maximum": 100}),
        "human_review_percent" => json!({"type": "integer", "minimum": 0, "maximum": 100}),
    )
}

fn routing_objective_profile_binding() -> Value {
    strict_object!(
        "id" => nonempty_string(),
        "version" => positive_integer(),
        "content_hash" => json!({"type": "string", "pattern": "^[0-9a-f]{64}$"}),
        "quality" => routing_quality_weights(),
        "tradeoffs" => routing_tradeoff_weights(),
        "switch_costs" => context_switch_costs(),
    )
}

fn resolved_routing_objective_profile() -> Value {
    strict_object!(
        "profile" => routing_objective_profile_binding(),
        "source" => enum_schema(&["built_in", "repository_override"]),
    )
}

fn selector_calibration() -> Value {
    strict_object!(
        "name" => nonempty_string(),
        "version" => positive_integer(),
        "effective_date" => date(),
        "minimum_quality_basis_points" => basis_points(),
        "minimum_class_fit_samples" => positive_integer(),
        "minimum_authority_samples" => positive_integer(),
        "pool_pressure_full_cost_microunits" => nonnegative_integer(),
        "observed_consumption_unit_cost_microunits" => nonnegative_integer(),
        "entitlement_scarcity_full_cost_microunits" => nonnegative_integer(),
        "retry_penalty_microunits" => nonnegative_integer(),
        "degrade_effort_rank_penalty_microunits" => nonnegative_integer(),
    )
}

fn class_fit_prior() -> Value {
    strict_object!(
        "task_class" => nonempty_string(),
        "effort" => reasoning_effort(),
        "quality_basis_points" => basis_points(),
        "sample_size" => nonnegative_integer(),
        "execution_cost_microunits" => nonnegative_integer(),
        "review_cost_microunits" => nonnegative_integer(),
        "rework_cost_microunits" => nonnegative_integer(),
        "rereview_cost_microunits" => nonnegative_integer(),
    )
}

fn authority_evidence_prior() -> Value {
    strict_object!(
        "task_class" => nonempty_string(),
        "role" => authority_role(),
        "effort" => reasoning_effort(),
        "quality_basis_points" => basis_points(),
        "sample_size" => nonnegative_integer(),
    )
}

fn one_shot_environment_fallback() -> Value {
    strict_object!(
        "rejection_code" => nonempty_string(),
        "target_runtime" => nonempty_string(),
        "target_model" => nonempty_string(),
        "target_effort" => reasoning_effort(),
    )
}

fn model_prior() -> Value {
    strict_object!(
        "runtime" => nonempty_string(),
        "model" => nonempty_string(),
        "observed_on" => date(),
        "source_id" => nonempty_string(),
        "prior_scope" => nonempty_string(),
        "limitations" => array(string()),
        "prohibited" => json!({"type": "boolean"}),
        "prohibition_reason" => nullable(nonempty_string()),
        "prohibited_authority_roles" => set(authority_role()),
        "long_context_eligible" => json!({"type": "boolean"}),
        "strong_gate_fallback_efforts" => set(reasoning_effort()),
        "strength_rank" => nonnegative_integer(),
        "class_fit" => array(class_fit_prior()),
        "authority_evidence" => array(authority_evidence_prior()),
        "one_shot_environment_fallbacks" => array(one_shot_environment_fallback()),
    )
}

fn prior_dataset() -> Value {
    strict_object!(
        "schema_version" => json!({"type": "integer", "const": 2}),
        "dataset_id" => nonempty_string(),
        "revision" => nonempty_string(),
        "published_on" => date(),
        "objective_profiles" => array(selector_calibration()),
        "models" => array(model_prior()),
    )
}

fn environment_failure() -> Value {
    strict_object!(
        "code" => nonempty_string(),
        "evidence_id" => nonempty_string(),
        "detail" => string(),
    )
}

fn fixed_cause_relaunch() -> Value {
    strict_object!(
        "proven_failure_cause" => nonempty_string(),
        "exact_corrective_change" => nonempty_string(),
        "same_cause_fix_verification" => nonempty_string(),
    )
}

fn outcome_record() -> Value {
    strict_object!(
        "attempt_id" => nonempty_string(),
        "task" => task_profile(true),
        "candidate" => candidate_key(),
        "result" => enum_schema(&["accepted", "rejected", "blocked"]),
        "failure_class" => nullable(enum_schema(&["model_quality", "environment", "operator", "unknown"])),
        "execution_cost_microunits" => nonnegative_integer(),
        "review_cost_microunits" => nonnegative_integer(),
        "rework_cost_microunits" => nonnegative_integer(),
        "rereview_cost_microunits" => nonnegative_integer(),
        "environment_cost_microunits" => nonnegative_integer(),
        "environment_failures" => array(environment_failure()),
        "fixed_cause_relaunch" => nullable(fixed_cause_relaunch()),
    )
}

fn debug_override() -> Value {
    strict_object!(
        "candidate" => candidate_key(),
        "requested_by" => nonempty_string(),
        "reason" => nonempty_string(),
    )
}

fn environment_rejection_state() -> Value {
    strict_object!(
        "candidate" => candidate_key(),
        "rejection_code" => nonempty_string(),
        "evidence_id" => nonempty_string(),
        "fallback_transition_used" => json!({"type": "boolean"}),
    )
}

fn dynamic_signals() -> Value {
    strict_object!(
        "retry_count" => nonnegative_integer(),
        "budget_signal" => enum_schema(&["continue", "degrade", "owner_escalation"]),
        "previous_choice" => nullable(candidate_key()),
        "previous_catalog_digest" => nullable(json!({"type": "string", "pattern": "^[0-9a-f]{64}$"})),
        "environment_rejections" => array(environment_rejection_state()),
    )
}

fn selection_input() -> Value {
    strict_object!(
        "task" => task_profile(false),
        "catalogs" => array(runtime_catalog()),
        "pools" => array(runtime_pool_state()),
        "quota_source" => nullable(pool_reference()),
        "constraints" => operator_constraints(),
        "priors" => prior_dataset(),
        "objective_profile" => selector_calibration_ref(),
        "resolved_objective_profile" => resolved_routing_objective_profile(),
        "outcomes" => array(outcome_record()),
        "signals" => dynamic_signals(),
        "debug_override" => nullable(debug_override()),
    )
}

fn digest_record() -> Value {
    strict_object!(
        "algorithm" => json!({"const": "sha256"}),
        "value" => json!({"type": "string", "pattern": "^[0-9a-f]{64}$"}),
    )
}

fn input_digests() -> Value {
    strict_object!(
        "normalized_input" => digest_record(),
        "task" => digest_record(),
        "catalogs" => digest_record(),
        "pools" => digest_record(),
        "constraints" => digest_record(),
        "priors" => digest_record(),
        "resolved_objective_profile" => digest_record(),
        "outcomes" => digest_record(),
        "signals" => digest_record(),
    )
}

fn selector_calibration_provenance() -> Value {
    strict_object!(
        "dataset_id" => nonempty_string(),
        "dataset_revision" => nonempty_string(),
        "dataset_published_on" => date(),
        "profile_name" => nonempty_string(),
        "profile_version" => positive_integer(),
        "profile_effective_date" => date(),
        "profile_digest" => digest_record(),
    )
}

fn ledger_summary() -> Value {
    strict_object!(
        "matching_attempts" => nonnegative_integer(),
        "accepted" => nonnegative_integer(),
        "rejected" => nonnegative_integer(),
        "blocked" => nonnegative_integer(),
        "quality_attempts" => nonnegative_integer(),
        "environment_failure_count" => nonnegative_integer(),
        "execution_cost_microunits" => nonnegative_integer(),
        "review_cost_microunits" => nonnegative_integer(),
        "rework_cost_microunits" => nonnegative_integer(),
        "rereview_cost_microunits" => nonnegative_integer(),
        "environment_cost_microunits" => nonnegative_integer(),
        "total_cycle_cost_microunits" => nonnegative_integer(),
    )
}

fn ineligibility_reason() -> Value {
    strict_object!(
        "code" => enum_schema(&[
            "catalog_unavailable", "operator_constraint", "runtime_admission_closed",
            "entitlement_exhausted", "quota_fail_closed", "quota_alternative_not_authorized",
            "task_class_not_advertised", "task_shape_not_advertised",
            "authority_not_advertised", "policy_prohibited", "long_context_prohibited",
            "missing_dated_prior", "missing_class_fit_evidence", "class_fit_evidence_insufficient",
            "quality_bar_not_met", "missing_authority_evidence", "authority_evidence_insufficient",
            "authority_quality_bar_not_met", "unknown_judgment_authority", "environment_rejected"
        ]),
        "detail" => nonempty_string(),
    )
}

fn context_switch_transition() -> Value {
    enum_schema(&[
        "initial",
        "stay",
        "effort_change_same_runtime_model",
        "model_change_same_runtime",
        "runtime_change",
    ])
}

fn score_breakdown() -> Value {
    strict_object!(
        "posterior_quality_basis_points" => basis_points(),
        "authority_quality_basis_points" => nullable(basis_points()),
        "expected_total_cost_per_accepted_task_microunits" => nonnegative_integer(),
        "pool_pressure_cost_microunits" => nonnegative_integer(),
        "entitlement_scarcity_cost_microunits" => nonnegative_integer(),
        "observed_consumption_cost_microunits" => nonnegative_integer(),
        "marginal_cost_microunits" => nonnegative_integer(),
        "retry_cost_microunits" => nonnegative_integer(),
        "degrade_cost_microunits" => nonnegative_integer(),
        "switch_transition" => context_switch_transition(),
        "configured_switch_cost_microunits" => nonnegative_integer(),
        "switch_cost_microunits" => nonnegative_integer(),
        "routing_score_semantics" => enum_schema(&["legacy_baseline_plus_cost_proxy_adjustments_v1"]),
        "routing_tradeoff_weights" => routing_tradeoff_weights(),
        "legacy_baseline_score_microunits" => nonnegative_integer(),
        "retry_rework_cost_proxy_microunits" => nonnegative_integer(),
        "human_review_cost_proxy_microunits" => nonnegative_integer(),
        "retry_rework_adjustment_microunits" => nonnegative_integer(),
        "human_review_adjustment_microunits" => nonnegative_integer(),
        "total_adjustment_microunits" => nonnegative_integer(),
        "total_score_microunits" => nonnegative_integer(),
    )
}

fn candidate_evaluation() -> Value {
    strict_object!(
        "candidate" => candidate_key(),
        "prior_source_id" => nullable(nonempty_string()),
        "prior_observed_on" => nullable(date()),
        "prior_scope" => nullable(nonempty_string()),
        "prior_limitations" => array(string()),
        "strong_gate_fallback" => json!({"type": "boolean"}),
        "eligible" => json!({"type": "boolean"}),
        "ineligibility_reasons" => array(ineligibility_reason()),
        "quota" => quota_candidate_provenance(),
        "ledger" => ledger_summary(),
        "score" => nullable(score_breakdown()),
    )
}

fn selected_choice() -> Value {
    strict_object!(
        "candidate" => candidate_key(),
        "switch_transition" => context_switch_transition(),
        "configured_switch_cost_microunits" => nonnegative_integer(),
        "switch_cost_microunits" => nonnegative_integer(),
        "total_score_microunits" => nonnegative_integer(),
        "reason" => enum_schema(&[
            "lowest_expected_total_cost_per_accepted_task",
            "lowest_legacy_baseline_plus_cost_proxy_adjustments",
            "strongest_no_evidence_judgment_fallback",
            "debug_override",
            "one_shot_environment_fallback",
            "authorized_quota_degrade"
        ]),
    )
}

fn quota_candidate_provenance() -> Value {
    strict_object!(
        "source_pool" => nullable(pool_reference()),
        "target_pool" => nullable(pool_reference()),
        "source_exhausted" => json!({"type": "boolean"}),
        "configured_behavior" => nullable(exhaustion_behavior()),
        "authorized_alternative" => json!({"type": "boolean"}),
        "disposition" => enum_schema(&[
            "legacy_unconfigured", "source_available", "source_exhausted",
            "authorized_alternative", "rejected_unauthorized_alternative", "fail_closed"
        ]),
        "source_observation_revision" => nullable(nonempty_string()),
        "source_observation" => nullable(consumption_source()),
        "target_marginal_cost_microunits" => nullable(nonnegative_integer()),
        "reason" => nonempty_string(),
    )
}

fn rejected_quota_alternative() -> Value {
    strict_object!(
        "candidate" => candidate_key(),
        "reasons" => array(ineligibility_reason()),
    )
}

fn quota_decision_provenance() -> Value {
    strict_object!(
        "source_pool" => pool_reference(),
        "configured_behavior" => exhaustion_behavior(),
        "source_exhausted" => json!({"type": "boolean"}),
        "local_observation_revision" => nonempty_string(),
        "observation_source" => consumption_source(),
        "marginal_cost_assumption_microunits" => nonnegative_integer(),
        "authorized_alternatives" => array(pool_reference()),
        "eligible_alternatives" => array(candidate_key()),
        "rejected_alternatives" => array(rejected_quota_alternative()),
        "selected_alternative" => nullable(candidate_key()),
        "disposition" => enum_schema(&[
            "source_available", "fail_closed", "degraded", "refused_by_explicit_override",
            "refused_no_eligible_alternative"
        ]),
        "reason" => nonempty_string(),
    )
}

fn debug_override_provenance() -> Value {
    strict_object!(
        "request" => debug_override(),
        "disposition" => enum_schema(&["applied", "rejected"]),
        "reason" => nonempty_string(),
    )
}

fn environment_fallback_transition() -> Value {
    strict_object!(
        "source" => candidate_key(),
        "target" => candidate_key(),
        "rejection_code" => nonempty_string(),
        "evidence_id" => nonempty_string(),
        "transition_ordinal" => json!({"type": "integer", "minimum": 1, "maximum": 255}),
        "maximum_transitions" => json!({"type": "integer", "minimum": 1, "maximum": 255}),
    )
}

fn catalog_revision_provenance() -> Value {
    strict_object!(
        "runtime" => nonempty_string(),
        "revision" => nonempty_string(),
        "advertised_at" => nonempty_string(),
    )
}

fn ranked_score() -> Value {
    strict_object!(
        "rank" => json!({"type": "integer", "minimum": 2}),
        "candidate" => candidate_key(),
        "switch_transition" => context_switch_transition(),
        "configured_switch_cost_microunits" => nonnegative_integer(),
        "switch_cost_microunits" => nonnegative_integer(),
        "total_score_microunits" => nonnegative_integer(),
    )
}

pub(crate) fn selection_provenance_schema_value() -> Value {
    strict_object!(
        "schema_version" => json!({"type": "integer", "const": 3}),
        "status" => enum_schema(&["selected", "fail_closed"]),
        "normalized_input" => selection_input(),
        "normalized_task" => task_profile(false),
        "input_digests" => input_digests(),
        "objective_profile" => selector_calibration_provenance(),
        "resolved_objective_profile" => resolved_routing_objective_profile(),
        "catalog_revisions" => array(catalog_revision_provenance()),
        "runtime_operations" => array(runtime_pool_state()),
        "triggers" => set(enum_schema(&[
            "initial", "retry", "budget_degrade", "catalog_change", "environment_fallback",
            "debug_override", "quota_exhaustion"
        ])),
        "candidate_set" => array(candidate_evaluation()),
        "choice" => nullable(selected_choice()),
        "runner_up_scores" => array(ranked_score()),
        "decision_reason" => nonempty_string(),
        "debug_override" => nullable(debug_override_provenance()),
        "environment_fallback" => nullable(environment_fallback_transition()),
        "quota" => nullable(quota_decision_provenance()),
    )
}

pub(crate) fn selection_event_schema_value() -> Value {
    strict_object!(
        "assignment_id" => nullable(nonempty_string()),
        "attempt" => nonnegative_integer(),
        "role" => enum_schema(&[
            "supervisor", "child_orchestrator", "worker", "gate_classifier", "auditor"
        ]),
        "primary_cause" => enum_schema(&["initial", "debug_override", "budget_degrade", "retry"]),
        "provenance" => selection_provenance_schema_value(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_every_object_is_closed(schema: &Value) {
        match schema {
            Value::Object(object) => {
                if object.get("type") == Some(&Value::String("object".to_string())) {
                    assert_eq!(
                        object.get("additionalProperties"),
                        Some(&Value::Bool(false))
                    );
                    let properties = object["properties"].as_object().expect("object properties");
                    let required = object["required"].as_array().expect("object required");
                    assert_eq!(required.len(), properties.len());
                    for field in properties.keys() {
                        assert!(required.iter().any(|required| required == field));
                    }
                }
                for value in object.values() {
                    assert_every_object_is_closed(value);
                }
            }
            Value::Array(values) => {
                for value in values {
                    assert_every_object_is_closed(value);
                }
            }
            _ => {}
        }
    }

    #[test]
    fn event_and_every_nested_selector_object_are_closed_and_exhaustively_required() {
        let event = selection_event_schema_value();
        assert_every_object_is_closed(&event);

        let provenance = &event["properties"]["provenance"];
        assert_eq!(provenance["properties"]["schema_version"]["const"], 3);
        assert_eq!(
            provenance["properties"]["normalized_input"]["properties"]["priors"]["properties"]
                ["schema_version"]["const"],
            2
        );
        let calibration = &provenance["properties"]["normalized_input"]["properties"]["priors"]
            ["properties"]["objective_profiles"]["items"];
        assert!(!calibration["properties"]
            .as_object()
            .expect("calibration properties")
            .contains_key("switch_costs"));
        let resolved_profile = &provenance["properties"]["normalized_input"]["properties"]
            ["resolved_objective_profile"]["properties"]["profile"];
        assert!(resolved_profile["required"]
            .as_array()
            .is_some_and(|required| required.iter().any(|field| field == "switch_costs")));
        let score =
            &provenance["properties"]["candidate_set"]["items"]["properties"]["score"]["oneOf"][0];
        for field in [
            "switch_transition",
            "configured_switch_cost_microunits",
            "switch_cost_microunits",
            "total_score_microunits",
        ] {
            assert!(score["required"]
                .as_array()
                .is_some_and(|required| required.iter().any(|value| value == field)));
        }
    }
}
