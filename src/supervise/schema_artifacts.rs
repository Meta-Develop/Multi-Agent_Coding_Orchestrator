use super::*;

pub(super) fn write_plan_snapshot(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    plan: &SupervisorPlan,
    consultant: &SupervisorConsultantPlan,
    assignment_metadata: &AssignmentMetadata,
    plan_metadata: &SupervisorPlanMetadata,
) -> Result<()> {
    let value = supervisor_plan_value(plan, consultant, assignment_metadata, plan_metadata)?;
    write_artifact_json(
        writer,
        relative,
        &value,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )
    .with_context(|| format!("failed to write plan snapshot {}", relative.display()))
}

pub(super) fn write_orchestrator_schema(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
) -> Result<()> {
    write_schema(writer, relative, orchestrator_report_schema_value())
}

pub(super) fn write_supervisor_final_schema(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
) -> Result<()> {
    write_schema(writer, relative, supervisor_final_report_schema_value())
}

pub(super) fn supervisor_final_report_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "SupervisorFinalReport",
        "type": "object",
        "required": ["version", "role_economics_profile", "role_usage", "usage_complete"],
        "properties": {
            "version": {"type": "integer", "const": SUPERVISOR_SCHEMA_VERSION},
            "role_economics_profile": role_economics_profile_schema_value(),
            "role_usage": complete_role_usage_schema_value(),
            "usage_complete": {"type": "boolean"},
            "run_lifecycle": {
                "type": "string",
                "enum": ["active", "interrupted", "uncertain", "resumable", "finalized"]
            },
            "gate_denials": {
                "type": "array",
                "items": gate_denial_schema_value()
            },
            "gate_correction_outcomes": {
                "type": "array",
                "items": gate_correction_outcome_schema_value()
            },
            "autonomy_kpis": autonomy_kpi_report_schema_value(),
            "run_budget": run_budget_report_schema_value(),
            "review_lens_usage": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["lens_id", "backend_id", "model", "observation"],
                    "properties": {
                        "lens_id": {"type": "string"},
                        "backend_id": {"type": "string"},
                        "model": {"type": "string"},
                        "usage": usage_schema_value(),
                        "cost_usd": {"type": "number", "minimum": 0},
                        "observation": {
                            "type": "string",
                            "enum": [
                                "process_observed",
                                "supervisor_aggregate",
                                "not_process_observable",
                                "synthetic_fake"
                            ]
                        },
                        "unavailable_reason": {"type": "string"}
                    }
                }
            },
            "review_lens_total_usage": usage_schema_value(),
            "review_lens_total_cost_usd": {"type": "number", "minimum": 0},
            "environment_failures": {
                "type": "array",
                "items": environment_failure_schema_value()
            },
            "generated_follow_up_tasks": generated_follow_up_tasks_schema_value()
        }
    })
}

fn role_economics_profile_schema_value() -> serde_json::Value {
    let role_binding = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "resolved_model", "resolved_reasoning_effort", "observation"
        ],
        "properties": {
            "configured_model": {"type": "string"},
            "configured_reasoning_effort": {"type": "string"},
            "resolved_model": {"type": ["string", "null"]},
            "resolved_reasoning_effort": {"type": ["string", "null"]},
            "observation": {
                "type": "string",
                "enum": [
                    "runtime_catalog_resolved", "runtime_default_resolved", "synthetic_fake",
                    "catalog_unavailable", "resolution_failed"
                ]
            },
            "resolution_observation": {
                "type": "string",
                "enum": [
                    "preferred_model", "catalog_fallback", "runtime_default",
                    "local_deterministic_fake", "not_resolved"
                ]
            },
            "configured_model_chain": {
                "type": "array",
                "items": {"type": "string"},
                "uniqueItems": true
            },
            "resolved_candidate_index": {"type": "integer", "minimum": 0},
            "unavailable_reason": {"type": "string"}
        }
    });
    let role_selection = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "model": {"type": "string"},
            "reasoning_effort": {"type": "string"},
            "unavailable_model_fallback": {
                "oneOf": [
                    {
                        "type": "string",
                        "enum": ["fail_closed", "runtime_default", "local_deterministic_fake"]
                    },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["ordered_catalog_chain"],
                        "properties": {
                            "ordered_catalog_chain": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["models", "on_exhausted"],
                                "properties": {
                                    "models": {
                                        "type": "array",
                                        "minItems": 1,
                                        "items": {"type": "string"},
                                        "uniqueItems": true
                                    },
                                    "on_exhausted": {
                                        "type": "string",
                                        "enum": [
                                            "fail_closed", "runtime_default",
                                            "local_deterministic_fake"
                                        ]
                                    }
                                }
                            }
                        }
                    }
                ]
            }
        }
    });
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "schema_version", "name", "evidence", "evidence_notice", "production_eligible",
            "model_availability", "overridden_roles", "role_models",
            "model_catalog_observation", "execution"
        ],
        "properties": {
            "schema_version": {
                "type": "integer",
                "const": SUPERVISOR_EXECUTION_TELEMETRY_SCHEMA_VERSION
            },
            "name": {"type": "string"},
            "evidence": {"type": "string"},
            "evidence_notice": {"type": "string"},
            "production_eligible": {"type": "boolean"},
            "model_availability": {
                "type": "string",
                "enum": ["unknown", "available", "unavailable"]
            },
            "overridden_roles": {
                "type": "array",
                "items": agent_role_schema_value(),
                "uniqueItems": true
            },
            "role_models": role_map_schema_value(role_selection),
            "model_catalog_observation": {
                "type": "string",
                "enum": ["consulted", "consultation_failed", "not_consulted"]
            },
            "execution": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "assignment_count", "started_assignment_count", "completed_assignment_count",
                    "concurrency", "role_bindings", "usage"
                ],
                "properties": {
                    "assignment_count": {"type": "integer", "minimum": 0},
                    "started_assignment_count": {"type": "integer", "minimum": 0},
                    "completed_assignment_count": {"type": "integer", "minimum": 0},
                    "concurrency": concurrency_report_schema_value(),
                    "role_bindings": role_map_schema_value(role_binding),
                    "usage": execution_usage_schema_value()
                }
            }
        }
    })
}

fn agent_role_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "enum": ["supervisor", "child_orchestrator", "worker", "gate_classifier", "auditor"]
    })
}

fn role_map_schema_value(value_schema: serde_json::Value) -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["supervisor", "child_orchestrator", "worker", "gate_classifier", "auditor"],
        "properties": {
            "supervisor": value_schema.clone(),
            "child_orchestrator": value_schema.clone(),
            "worker": value_schema.clone(),
            "gate_classifier": value_schema.clone(),
            "auditor": value_schema
        }
    })
}

fn concurrency_report_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "configured_max_concurrent_children", "policy_input_observation", "policy_input",
            "policy_input_unavailable_reason", "achieved_max_concurrent_children",
            "achieved_mean_concurrent_children", "achieved_mean_observation",
            "achieved_mean_unavailable_reason"
        ],
        "properties": {
            "configured_max_concurrent_children": {"type": "integer", "minimum": 1},
            "policy_input_observation": process_observation_schema_value(),
            "policy_input": {"type": ["string", "null"]},
            "policy_input_unavailable_reason": {"type": ["string", "null"]},
            "achieved_max_concurrent_children": {"type": "integer", "minimum": 0},
            "achieved_mean_concurrent_children": {"type": ["number", "null"], "minimum": 0},
            "achieved_mean_observation": process_observation_schema_value(),
            "achieved_mean_unavailable_reason": {"type": ["string", "null"]}
        }
    })
}

fn process_observation_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "enum": ["scheduler_observed", "not_retained", "not_process_observable"]
    })
}

fn execution_usage_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "total_usage", "total_cost_usd", "usage_complete", "observation"
        ],
        "properties": {
            "total_usage": {
                "anyOf": [usage_schema_value(), {"type": "null"}]
            },
            "total_cost_usd": {"type": ["number", "null"], "minimum": 0},
            "usage_complete": {"type": "boolean"},
            "observation": role_usage_observation_schema_value(),
            "unavailable_reason": {"type": "string"}
        }
    })
}

fn complete_role_usage_schema_value() -> serde_json::Value {
    role_map_schema_value(json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["observation"],
        "properties": {
            "models": {"type": "array", "items": {"type": "string"}, "uniqueItems": true},
            "usage": usage_schema_value(),
            "cost_usd": {"type": "number", "minimum": 0},
            "observation": role_usage_observation_schema_value(),
            "unavailable_reason": {"type": "string"}
        }
    }))
}

fn role_usage_observation_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "enum": [
            "process_observed", "supervisor_aggregate", "not_process_observable", "synthetic_fake"
        ]
    })
}

fn autonomy_kpi_report_schema_value() -> serde_json::Value {
    let optional_count = || json!({"type": ["integer", "null"], "minimum": 0});
    let coverage_marker = || {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["observation"],
            "properties": {
                "observation": {
                    "type": "string",
                    "enum": ["supervisor_aggregate", "not_process_observable"]
                },
                "unavailable_reason": {"type": "string"}
            }
        })
    };
    let ratio = || {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["numerator", "denominator"],
            "properties": {
                "numerator": {"type": "integer", "minimum": 0},
                "denominator": {"type": "integer", "minimum": 1}
            }
        })
    };
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "observation",
            "population",
            "coverage",
            "actions_reviewed",
            "denials",
            "self_corrections",
            "human_escalations",
            "interrupted"
        ],
        "properties": {
            "observation": {
                "type": "string",
                "enum": ["supervisor_aggregate", "not_process_observable"]
            },
            "population": {
                "type": "string",
                "const": "reviewed_gate_actions"
            },
            "coverage": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "review_decisions",
                    "reviewed_denial_terminal_lifecycles",
                    "human_follow_up_responses",
                    "scheduler_budget_denial_lifecycles",
                    "rate_denominators"
                ],
                "properties": {
                    "review_decisions": coverage_marker(),
                    "reviewed_denial_terminal_lifecycles": coverage_marker(),
                    "human_follow_up_responses": coverage_marker(),
                    "scheduler_budget_denial_lifecycles": coverage_marker(),
                    "rate_denominators": coverage_marker()
                }
            },
            "actions_reviewed": optional_count(),
            "denials": optional_count(),
            "self_corrections": optional_count(),
            "human_escalations": optional_count(),
            "interrupted": {"type": ["boolean", "null"]},
            "licensed_dependent_failures": optional_count(),
            "generated_follow_up_tasks": optional_count(),
            "denial_rate": ratio(),
            "self_correction_rate": ratio(),
            "interruption_rate": ratio(),
            "reviewed_actions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["action_gate_id", "allowed"],
                    "properties": {
                        "action_gate_id": {"type": "string", "minLength": 1, "maxLength": 128},
                        "correction_correlation_id": {"type": "string", "minLength": 1, "maxLength": 128},
                        "denial_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "allowed": {"type": "boolean"},
                        "human_intervention": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["target", "outcome"],
                            "properties": {
                                "target": {"type": "string", "const": "human"},
                                "outcome": {"type": "string", "const": "intervention_required"}
                            }
                        }
                    }
                }
            },
            "gate_lifecycles": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "denial_id",
                        "correction_correlation_id",
                        "route",
                        "correction_attempts"
                    ],
                    "properties": {
                        "denial_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                        "correction_correlation_id": {"type": "string", "minLength": 1, "maxLength": 128},
                        "route": {
                            "type": "string",
                            "enum": ["planner_parent", "child_controller", "integration_controller"]
                        },
                        "correction_attempts": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": MAX_GATE_CORRECTIONS_LIMIT
                        },
                        "terminal_outcome": {
                            "type": "string",
                            "enum": ["self_corrected", "exhausted", "escalated"]
                        }
                    }
                }
            },
            "unavailable_reason": {"type": "string"}
        }
    })
}

fn usage_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["input_tokens", "output_tokens", "total_tokens"],
        "properties": {
            "input_tokens": {"type": "integer", "minimum": 0},
            "output_tokens": {"type": "integer", "minimum": 0},
            "total_tokens": {"type": "integer", "minimum": 0}
        }
    })
}

fn run_budget_report_schema_value() -> serde_json::Value {
    let amount = || {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["tokens"],
            "properties": {
                "tokens": {"type": "integer", "minimum": 0},
                "cost_usd": {"type": "number", "minimum": 0}
            }
        })
    };
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "limits",
            "consumed",
            "reserved",
            "committed",
            "remaining",
            "active_reservations",
            "usage_complete",
            "action",
            "new_dispatch_allowed"
        ],
        "properties": {
            "limits": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "soft_tokens": {"type": "integer", "minimum": 1},
                    "hard_tokens": {"type": "integer", "minimum": 1},
                    "soft_cost_usd": {"type": "number", "exclusiveMinimum": 0},
                    "hard_cost_usd": {"type": "number", "exclusiveMinimum": 0}
                }
            },
            "consumed": amount(),
            "reserved": amount(),
            "committed": amount(),
            "remaining": {
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "soft_tokens": {"type": "integer", "minimum": 0},
                    "hard_tokens": {"type": "integer", "minimum": 0},
                    "soft_cost_usd": {"type": "number", "minimum": 0},
                    "hard_cost_usd": {"type": "number", "minimum": 0}
                }
            },
            "roles": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "role",
                        "consumed",
                        "reserved",
                        "active_reservations",
                        "usage_complete"
                    ],
                    "properties": {
                        "role": {
                            "type": "string",
                            "enum": [
                                "supervisor",
                                "child_orchestrator",
                                "worker",
                                "gate_classifier",
                                "auditor"
                            ]
                        },
                        "consumed": amount(),
                        "reserved": amount(),
                        "active_reservations": {"type": "integer", "minimum": 0},
                        "usage_complete": {"type": "boolean"}
                    }
                }
            },
            "active_reservations": {"type": "integer", "minimum": 0},
            "usage_complete": {"type": "boolean"},
            "action": {
                "type": "string",
                "enum": ["continue", "degrade", "owner_escalation"]
            },
            "new_dispatch_allowed": {"type": "boolean"},
            "reasons": {
                "type": "array",
                "uniqueItems": true,
                "items": {
                    "type": "string",
                    "enum": [
                        "soft_token_ceiling_reached",
                        "hard_token_ceiling_reached",
                        "soft_cost_ceiling_reached",
                        "hard_cost_ceiling_reached",
                        "missing_pricing",
                        "estimated_provider_usage",
                        "missing_provider_usage",
                        "missing_actual_cost"
                    ]
                }
            }
        }
    })
}

pub(super) fn orchestrator_report_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "OrchestratorReviewReport",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "id",
            "role",
            "assigned_paths",
            "semantic_symbols",
            "semantic_modules",
            "claim_token",
            "semantic_intent_token",
            "commands_run",
            "environment_failures",
            "files_changed",
            "validation_results",
            "findings",
            "field_guide_entries",
            "worker_reports",
            "audit_reports",
            "decomposition_completions",
            "accepted",
            "rejected",
            "status",
            "remaining_risk",
            "next_safe_action"
        ],
        "properties": {
            "id": {"type": "string"},
            "role": {"type": "string", "const": "child_orchestrator"},
            "assigned_paths": {"type": "array", "items": {"type": "string"}},
            "semantic_symbols": {"type": "array", "items": {"type": "string"}},
            "semantic_modules": {"type": "array", "items": {"type": "string"}},
            "claim_token": {"type": ["integer", "null"]},
            "semantic_intent_token": {"type": ["integer", "null"]},
            "commands_run": {"type": "array", "items": command_run_record_schema_value()},
            "environment_failures": {"type": "array", "items": environment_failure_schema_value()},
            "files_changed": {"type": "array", "items": {"type": "string"}},
            "validation_results": {"type": "array", "items": validation_result_schema_value()},
            "findings": {"type": "array", "items": finding_schema_value()},
            "field_guide_entries": field_guide_entries_schema_value(),
            "worker_reports": {"type": "array", "items": worker_report_schema_value()},
            "audit_reports": {"type": "array", "items": auditor_report_schema_value()},
            "decomposition_completions": {
                "type": "array",
                "uniqueItems": true,
                "items": decomposition_completion_object_schema_value()
            },
            "licensed_breakage_review": licensed_breakage_review_schema_value(),
            "generated_follow_up_tasks": generated_follow_up_tasks_schema_value(),
            "gate_denials": {"type": "array", "items": gate_denial_schema_value()},
            "gate_correction_outcomes": {
                "type": "array",
                "items": gate_correction_outcome_schema_value()
            },
            "accepted": {"type": "boolean"},
            "rejected": {"type": "boolean"},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "remaining_risk": {"type": "string"},
            "next_safe_action": {"type": "string"}
        },
        "allOf": [orchestrator_environment_failure_outcome_schema_value()]
    })
}

fn licensed_breakage_review_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["declaration_sha256", "migration_rationale", "failures"],
        "properties": {
            "declaration_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "migration_rationale": {
                "type": "string",
                "minLength": 1,
                "maxLength": MAX_LICENSED_BREAKAGE_RATIONALE_BYTES
            },
            "failures": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "dependent_id",
                        "validation_name",
                        "failure_signature",
                        "paths",
                        "interfaces"
                    ],
                    "properties": {
                        "dependent_id": {"type": "string", "minLength": 1},
                        "validation_name": {"type": "string", "minLength": 1},
                        "failure_signature": {
                            "type": "string",
                            "minLength": 1,
                            "maxLength": MAX_LICENSED_BREAKAGE_FAILURE_SIGNATURE_BYTES
                        },
                        "paths": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string", "minLength": 1}
                        },
                        "interfaces": {
                            "type": "array",
                            "minItems": 1,
                            "items": {"type": "string", "minLength": 1}
                        }
                    }
                }
            }
        }
    })
}

fn generated_follow_up_tasks_schema_value() -> serde_json::Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "supervisor_plan",
                "breaking_assignment_id",
                "breaking_change",
                "declaration_sha256",
                "failure_signature",
                "migration_rationale",
                "cascade_depth",
                "dispatch_status",
                "handoff"
            ],
            "properties": {
                "supervisor_plan": generated_follow_up_supervisor_plan_schema_value(),
                "breaking_assignment_id": {"type": "string", "minLength": 1},
                "breaking_change": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "version", "agent_id", "primary_head", "agent_head", "merge_base", "diff_oid"
                    ],
                    "properties": {
                        "version": {"type": "integer"},
                        "agent_id": {"type": "string", "minLength": 1},
                        "primary_head": {"type": ["string", "null"]},
                        "agent_head": {"type": ["string", "null"]},
                        "merge_base": {"type": ["string", "null"]},
                        "diff_oid": {"type": "string", "minLength": 1}
                    }
                },
                "declaration_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "failure_signature": {"type": "string", "minLength": 1},
                "migration_rationale": {"type": "string", "minLength": 1},
                "cascade_depth": {"type": "integer", "const": LICENSED_BREAKAGE_CASCADE_DEPTH},
                "dispatch_status": {"type": "string", "const": "deferred_for_planned_run"},
                "handoff": {"type": "string", "minLength": 1}
            }
        }
    })
}

fn generated_follow_up_supervisor_plan_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "version", "task", "task_file", "max_depth", "max_child_assignments",
            "max_child_retries", "max_gate_corrections", "child_timeout_seconds",
            "semantic_coordination", "role_models", "model_pricing", "review_lenses",
            "review_aggregation_policy", "assignments", "spec_fragment_ids",
            "assignment_schedule", "run_budget", "consultant", "generated_follow_up"
        ],
        "properties": {
            "version": {"type": "integer", "const": SUPERVISOR_SCHEMA_VERSION},
            "task": {"type": "string", "minLength": 1},
            "task_file": {"type": ["string", "null"]},
            "max_depth": {"type": "integer"},
            "max_child_assignments": {"type": "integer", "const": 1},
            "max_child_retries": {"type": "integer"},
            "max_gate_corrections": {"type": "integer"},
            "child_timeout_seconds": {"type": "integer", "minimum": 1},
            "semantic_coordination": {"type": "string", "enum": ["off", "warn", "block"]},
            "role_models": {"type": "object"},
            "model_pricing": {"type": "object"},
            "review_lenses": {"type": "array", "minItems": 1},
            "review_aggregation_policy": {"type": "object"},
            "assignments": {"type": "array", "minItems": 1, "maxItems": 1},
            "spec_fragment_ids": {"type": "array", "maxItems": 0},
            "assignment_schedule": {"type": "array", "minItems": 1, "maxItems": 1},
            "run_budget": {
                "type": "object",
                "required": ["soft_tokens", "hard_tokens", "role_token_reservations"]
            },
            "consultant": {"type": "object"},
            "generated_follow_up": generated_follow_up_plan_context_schema_value()
        }
    })
}

fn generated_follow_up_plan_context_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "breaking_assignment_id", "breaking_change", "declaration_sha256",
            "failure_signature", "migration_rationale", "cascade_depth",
            "dispatch_status", "handoff", "operator_defaults"
        ],
        "properties": {
            "breaking_assignment_id": {"type": "string", "minLength": 1},
            "breaking_change": {"type": "object"},
            "declaration_sha256": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "failure_signature": {"type": "string", "minLength": 1},
            "migration_rationale": {"type": "string", "minLength": 1},
            "cascade_depth": {"type": "integer", "const": LICENSED_BREAKAGE_CASCADE_DEPTH},
            "dispatch_status": {"type": "string", "const": "deferred_for_planned_run"},
            "handoff": {"type": "string", "minLength": 1},
            "operator_defaults": {
                "type": "array",
                "minItems": 2,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["field", "value", "rationale"],
                    "properties": {
                        "field": {"type": "string", "minLength": 1},
                        "value": {"type": "string"},
                        "rationale": {"type": "string", "minLength": 1}
                    }
                }
            }
        }
    })
}

fn gate_denial_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "version",
            "denial_id",
            "correction_correlation_id",
            "reason",
            "retryability",
            "context",
            "route",
            "next_safe_operation"
        ],
        "properties": {
            "version": {"type": "integer", "const": 1},
            "denial_id": {
                "type": "string",
                "pattern": "^[0-9a-f]{64}$"
            },
            "correction_correlation_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "reason": {"type": "object"},
            "retryability": {
                "type": "string",
                "enum": ["retry_after_correction", "not_retryable"]
            },
            "context": {
                "type": "object",
                "additionalProperties": false,
                "required": ["owner", "source", "paths"],
                "properties": {
                    "owner": {"type": "string"},
                    "source": {"type": "string"},
                    "paths": {"type": "array", "items": {"type": "string"}}
                }
            },
            "route": {
                "type": "string",
                "enum": ["planner_parent", "child_controller", "integration_controller"]
            },
            "next_safe_operation": {"type": "string"}
        }
    })
}

fn gate_correction_outcome_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "denial_id",
            "correction_correlation_id",
            "route",
            "terminal_class",
            "correction_attempts"
        ],
        "properties": {
            "denial_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
            "correction_correlation_id": {"type": "string", "minLength": 1, "maxLength": 128},
            "route": {
                "type": "string",
                "enum": ["planner_parent", "child_controller", "integration_controller"]
            },
            "terminal_class": {
                "type": "string",
                "enum": ["self_corrected", "exhausted", "escalated"]
            },
            "correction_attempts": {
                "type": "integer",
                "minimum": 0,
                "maximum": MAX_GATE_CORRECTIONS_LIMIT
            }
        }
    })
}

pub(super) fn write_worker_schema(writer: &mut ArtifactRunWriter, relative: &Path) -> Result<()> {
    write_schema(writer, relative, worker_report_schema_value())
}

pub(super) fn write_auditor_schema(writer: &mut ArtifactRunWriter, relative: &Path) -> Result<()> {
    write_schema(writer, relative, auditor_report_schema_value())
}

pub(super) fn auditor_report_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "AuditorReport",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "id",
            "role",
            "reviewed_worker_ids",
            "reviewed_paths",
            "commands_run",
            "environment_failures",
            "validation_results",
            "findings",
            "rejection_kind",
            "no_further_delegation",
            "read_only",
            "accepted",
            "rejected",
            "status",
            "remaining_risk",
            "next_safe_action"
        ],
        "properties": {
            "id": {"type": "string"},
            "role": {"type": "string", "const": "auditor"},
            "reviewed_worker_ids": {"type": "array", "items": {"type": "string"}},
            "reviewed_paths": {"type": "array", "items": {"type": "string"}},
            "commands_run": {"type": "array", "items": command_run_record_schema_value()},
            "environment_failures": {"type": "array", "items": environment_failure_schema_value()},
            "validation_results": {"type": "array", "items": validation_result_schema_value()},
            "findings": {"type": "array", "items": finding_schema_value()},
            "rejection_kind": {
                "type": ["string", "null"],
                "enum": ["implementation_defect", "evidence_quality", null]
            },
            "no_further_delegation": {"type": "boolean", "const": true},
            "read_only": {"type": "boolean", "const": true},
            "accepted": {"type": "boolean"},
            "rejected": {"type": "boolean"},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "remaining_risk": {"type": "string"},
            "next_safe_action": {"type": "string"}
        },
        "allOf": [environment_failure_outcome_schema_value()]
    })
}

pub(super) fn worker_report_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "WorkerReport",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "id",
            "role",
            "assignment_kind",
            "target_path",
            "assigned_paths",
            "semantic_symbols",
            "semantic_modules",
            "claim_token",
            "semantic_intent_token",
            "commands_run",
            "environment_failures",
            "files_changed",
            "validation_results",
            "findings",
            "field_guide_entries",
            "bloated_file_flags",
            "decomposition_completion",
            "no_further_delegation",
            "accepted",
            "rejected",
            "status",
            "remaining_risk",
            "next_safe_action"
        ],
        "properties": {
            "id": {"type": "string"},
            "role": {"type": "string", "const": "worker"},
            "assignment_kind": assignment_kind_schema_value(),
            "target_path": {"type": ["string", "null"]},
            "assigned_paths": {"type": "array", "items": {"type": "string"}},
            "semantic_symbols": {"type": "array", "items": {"type": "string"}},
            "semantic_modules": {"type": "array", "items": {"type": "string"}},
            "claim_token": {"type": ["integer", "null"]},
            "semantic_intent_token": {"type": ["integer", "null"]},
            "commands_run": {"type": "array", "items": command_run_record_schema_value()},
            "environment_failures": {"type": "array", "items": environment_failure_schema_value()},
            "files_changed": {"type": "array", "items": {"type": "string"}},
            "validation_results": {"type": "array", "items": validation_result_schema_value()},
            "findings": {"type": "array", "items": finding_schema_value()},
            "field_guide_entries": field_guide_entries_schema_value(),
            "bloated_file_flags": {
                "type": "array",
                "maxItems": MAX_BLOATED_FILE_FLAGS_PER_WORKER,
                "uniqueItems": true,
                "items": bloated_file_flag_schema_value()
            },
            "decomposition_completion": decomposition_completion_schema_value(),
            "no_further_delegation": {"type": "boolean", "const": true},
            "accepted": {"type": "boolean"},
            "rejected": {"type": "boolean"},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "remaining_risk": {"type": "string"},
            "next_safe_action": {"type": "string"}
        },
        "allOf": [environment_failure_outcome_schema_value()]
    })
}

fn field_guide_entries_schema_value() -> serde_json::Value {
    json!({
        "type": "array",
        "maxItems": MAX_FIELD_GUIDE_ENTRIES_PER_REPORT,
        "items": {
            "type": "object",
            "additionalProperties": false,
            "required": ["finding", "context"],
            "properties": {
                "finding": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_FIELD_GUIDE_FINDING_BYTES
                },
                "context": {
                    "type": "string",
                    "minLength": 1,
                    "maxLength": MAX_FIELD_GUIDE_CONTEXT_BYTES
                }
            }
        }
    })
}

fn assignment_kind_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "enum": ["ordinary", "megafile_decomposition"]
    })
}

fn bloated_file_flag_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["path"],
        "properties": {
            "path": {"type": "string", "minLength": 1}
        }
    })
}

pub(super) fn decomposition_completion_schema_value() -> serde_json::Value {
    json!({
        "type": ["object", "null"],
        "additionalProperties": false,
        "required": ["target_path", "replacement_paths"],
        "properties": {
            "target_path": {"type": "string", "minLength": 1},
            "replacement_paths": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_DECOMPOSITION_REPLACEMENT_PATHS,
                "uniqueItems": true,
                "items": {"type": "string", "minLength": 1}
            }
        }
    })
}

fn decomposition_completion_object_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["target_path", "replacement_paths"],
        "properties": {
            "target_path": {"type": "string", "minLength": 1},
            "replacement_paths": {
                "type": "array",
                "minItems": 1,
                "maxItems": MAX_DECOMPOSITION_REPLACEMENT_PATHS,
                "uniqueItems": true,
                "items": {"type": "string", "minLength": 1}
            }
        }
    })
}

pub(super) fn command_run_record_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "command",
            "cwd",
            "exit_code",
            "status",
            "timeout_seconds",
            "duration_ms",
            "timed_out",
            "stdout",
            "stderr",
            "error"
        ],
        "properties": {
            "command": {"type": "array", "items": {"type": "string"}},
            "cwd": {"type": "string"},
            "exit_code": {"type": ["integer", "null"]},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "timeout_seconds": {"type": "integer"},
            "duration_ms": {"type": "integer"},
            "timed_out": {"type": "boolean"},
            "stdout": {"type": "string"},
            "stderr": {"type": "string"},
            "sandbox_denials": {
                "type": "array",
                "uniqueItems": true,
                "items": sandbox_denial_evidence_schema_value()
            },
            "environment_preflight_results": {
                "type": "array",
                "items": environment_preflight_result_schema_value()
            },
            "environment_failures": {
                "type": "array",
                "items": environment_failure_schema_value()
            },
            "error": {"type": ["string", "null"]}
        },
        "allOf": [command_environment_failure_outcome_schema_value()]
    })
}

fn command_environment_failure_outcome_schema_value() -> serde_json::Value {
    json!({
        "if": {
            "properties": {
                "environment_failures": {"minItems": 1}
            },
            "required": ["environment_failures"]
        },
        "then": {
            "properties": {
                "status": {"const": "failed"}
            }
        }
    })
}

fn environment_failure_outcome_schema_value() -> serde_json::Value {
    json!({
        "if": environment_failure_source_schema_value(),
        "then": failed_environment_outcome_schema_value()
    })
}

fn orchestrator_environment_failure_outcome_schema_value() -> serde_json::Value {
    json!({
        "if": {
            "anyOf": [
                environment_failure_source_schema_value(),
                {
                    "properties": {
                        "worker_reports": {
                            "contains": environment_failure_source_schema_value(),
                            "minContains": 1
                        }
                    },
                    "required": ["worker_reports"]
                },
                {
                    "properties": {
                        "audit_reports": {
                            "contains": environment_failure_source_schema_value(),
                            "minContains": 1
                        }
                    },
                    "required": ["audit_reports"]
                }
            ]
        },
        "then": failed_environment_outcome_schema_value()
    })
}

fn environment_failure_source_schema_value() -> serde_json::Value {
    json!({
        "anyOf": [
            {
                "properties": {
                    "environment_failures": {"minItems": 1}
                },
                "required": ["environment_failures"]
            },
            {
                "properties": {
                    "commands_run": {
                        "contains": {
                            "properties": {
                                "environment_failures": {"minItems": 1}
                            },
                            "required": ["environment_failures"]
                        },
                        "minContains": 1
                    }
                },
                "required": ["commands_run"]
            }
        ]
    })
}

fn failed_environment_outcome_schema_value() -> serde_json::Value {
    json!({
        "properties": {
            "accepted": {"const": false},
            "rejected": {"const": true},
            "status": {"const": "failed"}
        }
    })
}

fn environment_failure_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["category", "summary", "remediation"],
        "properties": {
            "category": {
                "type": "string",
                "enum": [
                    "missing_executable",
                    "version_mismatch",
                    "missing_credential",
                    "network_forbidden",
                    "sandbox_unavailable",
                    "probe_failed",
                    "runtime_model_catalog_unavailable"
                ]
            },
            "requirement": environment_requirement_schema_value(),
            "summary": {"type": "string"},
            "remediation": {
                "type": "array",
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["scope", "guidance"],
                    "properties": {
                        "scope": {
                            "type": "string",
                            "enum": [
                                "project_local",
                                "persistent_nixos_host_software",
                                "credential_configuration",
                                "capability_policy"
                            ]
                        },
                        "guidance": {"type": "string"}
                    }
                }
            }
        }
    })
}

fn environment_preflight_result_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["requirement", "status"],
        "properties": {
            "requirement": environment_requirement_schema_value(),
            "status": {"type": "string", "enum": ["satisfied", "blocked"]},
            "observation": {
                "type": "object"
            }
        }
    })
}

fn environment_requirement_schema_value() -> serde_json::Value {
    let executable = [
        "bash", "cargo", "cmake", "codex", "git", "nix", "node", "npm", "python3", "rustc",
    ];
    json!({
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "executable"],
                "properties": {
                    "kind": {"const": "executable"},
                    "executable": {"type": "string", "enum": executable},
                    "version": {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "minimum_inclusive": environment_version_schema_value(),
                            "maximum_exclusive": environment_version_schema_value()
                        },
                        "anyOf": [
                            {"required": ["minimum_inclusive"]},
                            {"required": ["maximum_exclusive"]}
                        ]
                    }
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "credential"],
                "properties": {
                    "kind": {"const": "credential"},
                    "credential": {
                        "type": "string",
                        "enum": ["codex_access_token", "codex_api_key", "open_ai_api_key"]
                    }
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "configuration"],
                "properties": {
                    "kind": {"const": "configuration"},
                    "configuration": {"const": "codex_auth_file"}
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "access"],
                "properties": {
                    "kind": {"const": "network"},
                    "access": {"type": "string", "enum": ["disabled", "enabled"]}
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "capability"],
                "properties": {
                    "kind": {"const": "sandbox"},
                    "capability": {"const": "verified_external_codex"}
                }
            }
        ]
    })
}

fn environment_version_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["major", "minor", "patch"],
        "properties": {
            "major": {"type": "integer", "minimum": 0},
            "minor": {"type": "integer", "minimum": 0},
            "patch": {"type": "integer", "minimum": 0}
        }
    })
}

fn sandbox_denial_evidence_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["boundary", "policy_id", "operation", "retryability"],
        "properties": {
            "boundary": {"type": "string", "enum": ["outer_systemd", "inner_codex"]},
            "policy_id": {"type": "string", "minLength": 1},
            "operation": {"type": "string", "enum": ["establish_boundary", "write"]},
            "path": {"type": "string", "minLength": 1},
            "retryability": {
                "type": "string",
                "enum": ["requires_declared_exception", "not_retryable"]
            }
        }
    })
}

fn validation_result_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["name", "status", "command", "message"],
        "properties": {
            "name": {"type": "string"},
            "status": {"type": "string", "enum": ["pending", "succeeded", "failed", "rejected", "missing"]},
            "command": {"type": "array", "items": {"type": "string"}},
            "message": {"type": ["string", "null"]}
        }
    })
}

fn finding_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["severity", "message", "paths"],
        "properties": {
            "severity": {"type": "string", "enum": ["info", "warning", "error"]},
            "message": {"type": "string"},
            "paths": {"type": "array", "items": {"type": "string"}}
        }
    })
}

fn write_schema(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    schema: serde_json::Value,
) -> Result<()> {
    write_artifact_json(
        writer,
        relative,
        &schema,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )
    .with_context(|| format!("failed to write schema {}", relative.display()))
}

pub(super) fn encode_final_report(report: &SupervisorFinalReport) -> Result<Vec<u8>> {
    let mut normalized_report = report.clone();
    enforce_supervisor_final_environment_failure_outcome(&mut normalized_report);
    let mut contents = serde_json::to_vec_pretty(&normalized_report)
        .context("failed to serialize normalized supervisor final report")?;
    contents.push(b'\n');
    if contents.len() > MAX_SUPERVISOR_REPORT_BYTES {
        bail!("normalized supervisor final report exceeds its bounded size");
    }
    Ok(contents)
}

#[cfg(test)]
pub(super) fn write_final_report(
    writer: &mut ArtifactRunWriter,
    report: &SupervisorFinalReport,
) -> Result<()> {
    let contents = encode_final_report(report)?;
    writer
        .write_bytes(
            RunArtifactFamily::Supervise.final_report_relative_path(),
            &contents,
            ArtifactFileDisposition::PrivateEvidence,
        )
        .context("failed to write normalized supervisor final report")?;
    Ok(())
}

pub(super) fn read_supervisor_final_report(
    reader: &ArtifactRunReader,
) -> Result<SupervisorFinalReport> {
    let relative = RunArtifactFamily::Supervise.final_report_relative_path();
    let contents = reader.read(&relative).with_context(|| {
        format!(
            "failed to read supervisor final report {}",
            relative.display()
        )
    })?;
    if contents.len() > MAX_SUPERVISOR_REPORT_BYTES {
        bail!("supervisor final report exceeds its bounded size");
    }
    serde_json::from_slice(&contents).with_context(|| {
        format!(
            "failed to parse supervisor final report {}",
            relative.display()
        )
    })
}

pub(super) fn read_finalized_supervisor_report(
    repo: &Path,
    run_id: &RunId,
    run_dir: &Path,
) -> Result<Option<SupervisorFinalReport>> {
    let run_metadata = match fs::symlink_metadata(run_dir) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to inspect supervisor run directory {}",
                    run_dir.display()
                )
            })
        }
    };
    validate_active_artifact_run_dir(run_dir, &run_metadata)?;
    let marker = run_dir.join(ARTIFACT_FINALIZATION_MARKER);
    match fs::symlink_metadata(&marker) {
        Ok(_) => {
            let reader = ArtifactRunReader::open(repo, RunArtifactFamily::Supervise, run_id)
                .with_context(|| {
                    format!(
                        "supervisor run '{}' is not a verified finalized artifact",
                        run_id.as_str()
                    )
                })?;
            Ok(Some(read_supervisor_final_report(&reader)?))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error).with_context(|| {
            format!(
                "failed to inspect supervisor finalization marker {}",
                marker.display()
            )
        }),
    }
}

fn validate_active_artifact_run_dir(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!(
            "supervisor run path is not a nofollow directory: {}",
            path.display()
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        if metadata.uid() != unsafe { libc::geteuid() } {
            bail!(
                "supervisor run directory is not owned by the effective user: {}",
                path.display()
            );
        }
        if metadata.permissions().mode() & 0o777 != 0o700 {
            bail!(
                "supervisor run directory is not owner-private: {}",
                path.display()
            );
        }
    }
    Ok(())
}

pub(super) fn write_artifact_json<T: Serialize>(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    value: &T,
    max_bytes: usize,
    disposition: ArtifactFileDisposition,
) -> Result<()> {
    let mut bytes =
        serde_json::to_vec_pretty(value).context("failed to serialize supervise artifact JSON")?;
    bytes.push(b'\n');
    if bytes.len() > max_bytes {
        bail!(
            "supervise artifact {} exceeds its configured {} byte limit",
            relative.display(),
            max_bytes
        );
    }
    writer.write_bytes(relative, &bytes, disposition)?;
    Ok(())
}

pub(super) fn write_private_prompt(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
    prompt: &str,
) -> Result<()> {
    if prompt.len() > MAX_SUPERVISOR_PROMPT_BYTES {
        bail!(
            "supervise prompt {} exceeds its configured {} byte limit",
            relative.display(),
            MAX_SUPERVISOR_PROMPT_BYTES
        );
    }
    writer.write_bytes(
        relative,
        prompt.as_bytes(),
        ArtifactFileDisposition::PrivateEvidence,
    )?;
    Ok(())
}
