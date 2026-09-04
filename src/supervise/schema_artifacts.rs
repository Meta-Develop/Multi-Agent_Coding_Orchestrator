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

pub(super) fn write_codex_orchestrator_schema(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
) -> Result<()> {
    write_schema(
        writer,
        relative,
        codex_response_format_schema(orchestrator_report_schema_value())?,
    )
}

pub(super) fn write_supervisor_final_schema(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
) -> Result<()> {
    write_schema(writer, relative, supervisor_final_report_schema_value())
}

pub(super) fn write_worktree_writable_admission_schema(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
) -> Result<()> {
    write_schema(writer, relative, worktree_writable_admission_schema_value())
}

const REACHABLE_SUPERVISOR_RUNTIMES: [SupervisorRuntime; 6] = [
    SupervisorRuntime::Codex,
    SupervisorRuntime::Fake,
    SupervisorRuntime::Grok,
    SupervisorRuntime::Cursor,
    SupervisorRuntime::ClaudeCode,
    SupervisorRuntime::GeminiCli,
];

fn supervisor_runtime_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "enum": REACHABLE_SUPERVISOR_RUNTIMES.map(SupervisorRuntime::as_str)
    })
}

pub(super) fn worktree_writable_admission_schema_value() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "title": "WorktreeWritableAdmission",
        "type": "object",
        "additionalProperties": false,
        "required": [
            "version", "assignment_id", "attempt", "target", "worktree", "claims",
            "native_sandbox"
        ],
        "properties": {
            "version": {
                "type": "integer",
                "const": crate::external_agent::WORKTREE_WRITABLE_ADMISSION_SCHEMA_VERSION
            },
            "assignment_id": {"type": "string", "minLength": 1},
            "attempt": {"type": "integer", "minimum": 1},
            "target": {"const": "managed_child_worktree"},
            "worktree": {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "worktree_id"],
                "properties": {
                    "kind": {"const": "managed_disposable"},
                    "worktree_id": {"type": "string", "minLength": 1}
                }
            },
            "claims": {
                "type": "object",
                "additionalProperties": false,
                "required": ["state", "token", "paths"],
                "properties": {
                    "state": {"const": "held"},
                    "token": {"type": "integer", "minimum": 1},
                    "paths": {
                        "type": "array",
                        "minItems": 1,
                        "uniqueItems": true,
                        "items": {"type": "string", "minLength": 1}
                    }
                }
            },
            "native_sandbox": {
                "type": "object",
                "additionalProperties": false,
                "required": ["runtime", "workspace_access", "side_effect_confinement"],
                "properties": {
                    "runtime": supervisor_runtime_schema_value(),
                    "workspace_access": {"const": "read_write"},
                    "side_effect_confinement": {"const": "verified"}
                }
            }
        }
    })
}

pub(super) fn supervisor_final_report_schema_value() -> serde_json::Value {
    const SCHEMA_ID: &str = "https://raw.githubusercontent.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/main/schemas/supervisor-final-report-v1.schema.json";
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SCHEMA_ID,
        "title": "MACO Newly Finalized Supervisor Report v1",
        "description": "Contract for newly finalized `supervisor-final.json` reports. Historical top-level version-1 reports that predate finalized economics telemetry are outside this publication contract.",
        "type": "object",
        "additionalProperties": false,
        "required": supervisor_report_required_fields(),
        "properties": supervisor_report_properties_value("finalized"),
        "allOf": supervisor_report_outcome_constraints()
    })
}

#[cfg(test)]
pub(super) fn supervisor_collect_report_schema_value() -> serde_json::Value {
    let mut properties = supervisor_report_properties_value("finalized");
    let Some(properties) = properties.as_object_mut() else {
        return serde_json::Value::Bool(false);
    };
    properties.insert(
        "artifact_kind".to_string(),
        json!({"const": SUPERVISOR_COLLECT_ARTIFACT_KIND}),
    );
    properties.insert(
        "schema".to_string(),
        json!({"const": SUPERVISOR_COLLECT_SCHEMA_ID}),
    );
    properties.insert(
        "schema_version".to_string(),
        json!({"type": "integer", "const": SUPERVISOR_COLLECT_SCHEMA_VERSION}),
    );
    properties.insert(
        "collection_state".to_string(),
        json!({
            "type": "string",
            "enum": [
                "active", "resumable", "uncertain", "interrupted", "finalized",
                "inconsistent_finalized"
            ]
        }),
    );
    properties.insert(
        "final_report_available".to_string(),
        json!({"type": "boolean"}),
    );
    properties.insert(
        "run_lifecycle".to_string(),
        supervisor_run_lifecycle_schema_value(),
    );

    let mut required = supervisor_report_required_fields();
    required.retain(|field| !matches!(*field, "role_economics_profile" | "role_usage"));
    required.extend([
        "artifact_kind",
        "schema",
        "schema_version",
        "collection_state",
        "final_report_available",
    ]);
    let mut constraints = supervisor_report_outcome_constraints();
    constraints.push(json!({
        "oneOf": [
            collect_nonfinal_state_schema_value("active", "active"),
            collect_nonfinal_state_schema_value("resumable", "resumable"),
            collect_nonfinal_state_schema_value("uncertain", "uncertain"),
            collect_nonfinal_state_schema_value("interrupted", "interrupted"),
            collect_finalized_state_schema_value(),
            collect_nonfinal_state_schema_value("inconsistent_finalized", "finalized")
        ]
    }));

    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": SUPERVISOR_COLLECT_SCHEMA_ID,
        "title": "MACO Supervisor Collect Report v1",
        "description": "Lifecycle-aware public output from `maco supervise collect`. Finalized reports preserve the historical supervisor-final v1 fields; nonfinal states are explicit incomplete snapshots.",
        "type": "object",
        "additionalProperties": false,
        "required": required,
        "properties": properties,
        "allOf": constraints
    })
}

fn supervisor_report_required_fields() -> Vec<&'static str> {
    vec![
        "version",
        "run_id",
        "role",
        "repo",
        "plan_file",
        "run_dir",
        "runtime",
        "publishable",
        "success",
        "accepted",
        "rejected",
        "status",
        "run_lifecycle",
        "assigned_paths",
        "semantic_symbols",
        "semantic_modules",
        "claim_tokens",
        "semantic_intent_tokens",
        "role_economics_profile",
        "role_usage",
        "usage_complete",
        "commands_run",
        "environment_failures",
        "autonomy_kpis",
        "files_changed",
        "validation_results",
        "findings",
        "bloated_file_flags",
        "decomposition_candidates",
        "breaker_trip",
        "orchestrator_reports",
        "released_claims",
        "release_errors",
        "released_semantic_intents",
        "semantic_release_errors",
        "remaining_risk",
        "next_safe_action",
    ]
}

fn supervisor_report_properties_value(run_lifecycle: &str) -> serde_json::Value {
    merge_schema_property_groups([
        json!({
          "version": {"type": "integer", "const": SUPERVISOR_SCHEMA_VERSION},
          "run_id": identifier_schema_value(),
          "role": {"const": "supervisor"},
          "repo": {"const": "."},
          "plan_file": safe_published_path_schema_value(),
          "run_dir": safe_published_path_schema_value(),
          "runtime": supervisor_runtime_schema_value(),
          "publishable": {"type": "boolean"},
          "success": {"type": "boolean"},
          "accepted": {"type": "boolean"},
          "rejected": {"type": "boolean"},
          "status": review_status_schema_value(),
          "run_lifecycle": {"const": run_lifecycle},
          "evidence_only_reaudit": evidence_only_reaudit_schema_value(),
          "assigned_paths": path_array_schema_value(),
          "semantic_symbols": string_array_schema_value(),
          "semantic_modules": string_array_schema_value(),
          "claim_tokens": nonnegative_integer_array_schema_value(),
          "semantic_intent_tokens": nonnegative_integer_array_schema_value()
        }),
        json!({
          "role_economics_profile": role_economics_profile_schema_value(),
          "run_budget": run_budget_report_schema_value(),
          "role_usage": complete_role_usage_schema_value(),
          "review_lens_usage": {
              "type": "array",
              "items": review_lens_usage_report_schema_value()
          },
          "review_lens_total_usage": usage_schema_value(),
          "review_lens_total_cost_usd": {"type": "number", "minimum": 0},
          "total_usage": usage_schema_value(),
          "total_cost_usd": {"type": "number", "minimum": 0},
          "usage_complete": {"type": "boolean"},
          "commands_run": {"type": "array", "items": command_run_record_schema_value()},
          "environment_failures": {"type": "array", "items": environment_failure_schema_value()},
          "sandbox_denials": {"type": "array", "uniqueItems": true, "items": sandbox_denial_evidence_schema_value()},
          "gate_denials": {"type": "array", "items": gate_denial_schema_value()},
          "pre_action_review_metrics": {"type": "array", "items": review_metric_snapshot_schema_value()},
          "gate_correction_outcomes": {"type": "array", "items": gate_correction_outcome_schema_value()}
        }),
        json!({
          "autonomy_kpis": autonomy_kpi_report_schema_value(),
          "files_changed": path_array_schema_value(),
          "validation_results": {"type": "array", "items": validation_result_schema_value()},
          "findings": {"type": "array", "items": finding_schema_value()},
          "bloated_file_flags": {
              "type": "array",
              "uniqueItems": true,
              "items": bloated_file_flag_schema_value()
          },
          "decomposition_candidates": {
              "type": "array",
              "items": supervisor_final_decomposition_completion_object_schema_value()
          },
          "generated_follow_up_tasks": generated_follow_up_tasks_schema_value(),
          "assignment_traceability": {
              "type": "array",
              "items": assignment_traceability_schema_value()
          },
          "coverage_gaps": {"type": "array", "items": coverage_gap_schema_value()},
          "breaker_trip": {
              "anyOf": [supervisor_breaker_trip_schema_value(), {"type": "null"}]
          },
          "orchestrator_reports": {"type": "array", "items": supervisor_final_orchestrator_report_schema_value()}
        }),
        json!({
          "released_claims": {"type": "array", "items": path_claim_schema_value()},
          "release_errors": string_array_schema_value(),
          "released_semantic_intents": {"type": "array", "items": semantic_intent_schema_value()},
          "semantic_release_errors": string_array_schema_value(),
          "remaining_risk": {"type": "string"},
          "next_safe_action": {"type": "string"}
        }),
    ])
}

fn merge_schema_property_groups<const N: usize>(
    groups: [serde_json::Value; N],
) -> serde_json::Value {
    let mut properties = serde_json::Map::new();
    for group in groups {
        if let serde_json::Value::Object(group) = group {
            properties.extend(group);
        }
    }
    serde_json::Value::Object(properties)
}

fn supervisor_report_outcome_constraints() -> Vec<serde_json::Value> {
    vec![
        json!({
            "if": {"properties": {"publishable": {"const": true}}, "required": ["publishable"]},
            "then": {"properties": {"accepted": {"const": true}}},
            "else": {"properties": {"accepted": {"const": false}}}
        }),
        environment_failure_outcome_schema_value(),
    ]
}

#[cfg(test)]
fn collect_nonfinal_state_schema_value(
    collection_state: &str,
    run_lifecycle: &str,
) -> serde_json::Value {
    json!({
        "properties": {
            "collection_state": {"const": collection_state},
            "final_report_available": {"const": false},
            "run_lifecycle": {"const": run_lifecycle},
            "plan_file": {"const": SUPERVISOR_COLLECT_UNFINALIZED_PLAN_FILE},
            "publishable": {"const": false},
            "success": {"const": false},
            "accepted": {"const": false},
            "rejected": {"const": true},
            "status": {"const": "missing"},
            "usage_complete": {"const": false}
        },
        "required": [
            "collection_state", "final_report_available", "run_lifecycle", "plan_file",
            "publishable", "success", "accepted", "rejected", "status", "usage_complete"
        ],
        "not": {
            "anyOf": [
                {"required": ["role_economics_profile"]},
                {"required": ["role_usage"]}
            ]
        }
    })
}

#[cfg(test)]
fn collect_finalized_state_schema_value() -> serde_json::Value {
    json!({
        "properties": {
            "collection_state": {"const": "finalized"},
            "final_report_available": {"const": true},
            "run_lifecycle": {"const": "finalized"}
        },
        "required": [
            "collection_state", "final_report_available", "run_lifecycle",
            "role_economics_profile", "role_usage"
        ],
        "not": {
            "properties": {
                "plan_file": {"const": SUPERVISOR_COLLECT_UNFINALIZED_PLAN_FILE}
            },
            "required": ["plan_file"]
        }
    })
}

fn identifier_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "^[A-Za-z0-9._-]+$"
    })
}

fn safe_published_path_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "minLength": 1,
        "pattern": "^([A-Za-z]($|[^:\\u0000-\\u001F])|[^A-Za-z\\\\/\\u0000-\\u001F])[^\\u0000-\\u001F]*$",
        "not": {"pattern": "(^|[\\\\/])\\.\\.([\\\\/]|$)"}
    })
}

fn repository_relative_path_schema_value() -> serde_json::Value {
    let mut schema = safe_published_path_schema_value();
    schema["maxLength"] = json!(4096);
    schema
}

fn path_array_schema_value() -> serde_json::Value {
    json!({
        "type": "array",
        "uniqueItems": true,
        "items": repository_relative_path_schema_value()
    })
}

fn string_array_schema_value() -> serde_json::Value {
    json!({"type": "array", "items": {"type": "string"}})
}

fn nonnegative_integer_array_schema_value() -> serde_json::Value {
    json!({
        "type": "array",
        "uniqueItems": true,
        "items": {"type": "integer", "minimum": 0}
    })
}

fn review_status_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "enum": ["pending", "succeeded", "failed", "rejected", "missing"]
    })
}

#[cfg(test)]
fn supervisor_run_lifecycle_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "enum": ["active", "interrupted", "uncertain", "resumable", "finalized"]
    })
}

fn review_lens_usage_report_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["lens_id", "backend_id", "model", "observation"],
        "properties": {
            "lens_id": {"type": "string"},
            "backend_id": {"type": "string"},
            "model": {"type": "string"},
            "usage": usage_schema_value(),
            "cost_usd": {"type": "number", "minimum": 0},
            "observation": role_usage_observation_schema_value(),
            "unavailable_reason": {"type": "string"}
        }
    })
}

fn candidate_validation_binding_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["version", "agent_id", "primary_head", "agent_head", "merge_base", "diff_oid"],
        "properties": {
            "version": {"type": "integer", "minimum": 1},
            "agent_id": identifier_schema_value(),
            "primary_head": {"type": ["string", "null"]},
            "agent_head": {"type": ["string", "null"]},
            "merge_base": {"type": ["string", "null"]},
            "diff_oid": {"type": "string", "minLength": 1}
        }
    })
}

fn evidence_only_reaudit_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "source_run_id", "assignment_id", "attempt", "preserved_candidate_binding",
            "accepted"
        ],
        "properties": {
            "source_run_id": identifier_schema_value(),
            "assignment_id": identifier_schema_value(),
            "attempt": {"type": "integer", "minimum": 0, "maximum": 255},
            "preserved_candidate_binding": candidate_validation_binding_schema_value(),
            "accepted": {"type": "boolean"}
        }
    })
}

fn review_metric_snapshot_schema_value() -> serde_json::Value {
    let ratio = || {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["numerator", "denominator"],
            "properties": {
                "numerator": {"type": "integer", "minimum": 0},
                "denominator": {"type": "integer", "minimum": 0}
            }
        })
    };
    let latency_budget = || {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": ["p50_ms", "p95_ms", "timeout_ms"],
            "properties": {
                "p50_ms": {"type": "integer", "minimum": 0},
                "p95_ms": {"type": "integer", "minimum": 0},
                "timeout_ms": {"type": "integer", "minimum": 0}
            }
        })
    };
    let latency = || {
        json!({
            "type": "object",
            "additionalProperties": false,
            "required": [
                "sample_count", "measured_p50_ms", "measured_p95_ms", "budget",
                "p50_within_budget", "p95_within_budget"
            ],
            "properties": {
                "sample_count": {"type": "integer", "minimum": 0},
                "measured_p50_ms": {"type": ["integer", "null"], "minimum": 0},
                "measured_p95_ms": {"type": ["integer", "null"], "minimum": 0},
                "budget": latency_budget(),
                "p50_within_budget": {"type": ["boolean", "null"]},
                "p95_within_budget": {"type": ["boolean", "null"]}
            }
        })
    };
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "reviewed_action_denials", "eligible_run_human_interruptions",
            "classifier_invocations", "review_latency", "classifier_latency",
            "latency_budget_latched"
        ],
        "properties": {
            "reviewed_action_denials": ratio(),
            "eligible_run_human_interruptions": ratio(),
            "classifier_invocations": {"type": "integer", "minimum": 0},
            "review_latency": latency(),
            "classifier_latency": latency(),
            "latency_budget_latched": {"type": "boolean"}
        }
    })
}

fn assignment_traceability_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "assignment_id", "depth", "flattened_index", "spec_fragment_ids",
            "assigned_paths", "produced_changed_paths"
        ],
        "properties": {
            "assignment_id": identifier_schema_value(),
            "parent_assignment_id": identifier_schema_value(),
            "depth": {"type": "integer", "minimum": 0, "maximum": 255},
            "flattened_index": {"type": "integer", "minimum": 0},
            "spec_fragment_ids": string_array_schema_value(),
            "assigned_paths": path_array_schema_value(),
            "produced_changed_paths": path_array_schema_value(),
            "produced_diff_binding": candidate_validation_binding_schema_value(),
            "report_status": review_status_schema_value()
        }
    })
}

fn coverage_gap_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["kind", "message"],
        "properties": {
            "kind": {"enum": [
                "unassigned_spec_fragment", "missing_assignment_report",
                "no_produced_changes", "missing_diff_binding"
            ]},
            "spec_fragment_id": identifier_schema_value(),
            "assignment_id": identifier_schema_value(),
            "message": {"type": "string", "minLength": 1}
        }
    })
}

fn supervisor_breaker_trip_schema_value() -> serde_json::Value {
    let count = json!({"type": "integer", "minimum": 0});
    let reason = json!({
        "oneOf": [
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "failures", "retries", "threshold"],
                "properties": {
                    "kind": {"const": "sustained_assignment_failures"},
                    "failures": count.clone(), "retries": count.clone(), "threshold": count.clone()
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "denials", "failures", "threshold"],
                "properties": {
                    "kind": {"const": "repeated_claim_denial"},
                    "denials": count.clone(), "failures": count.clone(), "threshold": count.clone()
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "rejections", "retries", "threshold"],
                "properties": {
                    "kind": {"const": "repeated_rejection_loop"},
                    "rejections": count.clone(), "retries": count.clone(), "threshold": count.clone()
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "blocked", "warned", "conflicts", "threshold"],
                "properties": {
                    "kind": {"const": "sustained_semantic_conflicts"},
                    "blocked": count.clone(), "warned": count.clone(),
                    "conflicts": count.clone(), "threshold": count.clone()
                }
            }
        ]
    });
    let window = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "window_len", "accepted_assignments", "repeated_rejections",
            "failed_assignments", "retries", "claim_denials", "claim_failures",
            "semantic_conflict_blocks", "semantic_conflict_warnings", "semantic_conflicts"
        ],
        "properties": {
            "window_len": count.clone(), "accepted_assignments": count.clone(),
            "repeated_rejections": count.clone(), "failed_assignments": count.clone(),
            "retries": count.clone(), "claim_denials": count.clone(),
            "claim_failures": count.clone(), "semantic_conflict_blocks": count.clone(),
            "semantic_conflict_warnings": count.clone(), "semantic_conflicts": count
        }
    });
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["reason", "window", "autonomy_kpis", "recovery_guidance"],
        "properties": {
            "reason": reason,
            "window": window,
            "autonomy_kpis": autonomy_kpi_report_schema_value(),
            "recovery_guidance": {"type": "string", "minLength": 1}
        }
    })
}

fn path_claim_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["token", "agent_id", "paths"],
        "properties": {
            "token": {"type": "integer", "minimum": 1},
            "agent_id": identifier_schema_value(),
            "paths": path_array_schema_value()
        }
    })
}

fn semantic_intent_schema_value() -> serde_json::Value {
    let symbol = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "qualified_path", "name", "kind", "file"],
        "properties": {
            "id": {"type": "string", "minLength": 1},
            "qualified_path": {"type": "string", "minLength": 1},
            "name": {"type": "string", "minLength": 1},
            "kind": {"type": "string", "minLength": 1},
            "file": repository_relative_path_schema_value()
        }
    });
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "token", "agent_id", "paths", "symbols", "modules", "impacted_files",
            "task_digest", "task_excerpt", "notes", "warnings"
        ],
        "properties": {
            "token": {"type": "integer", "minimum": 1},
            "agent_id": identifier_schema_value(),
            "paths": path_array_schema_value(),
            "symbols": {"type": "array", "items": symbol},
            "modules": string_array_schema_value(),
            "impacted_files": path_array_schema_value(),
            "task_digest": {"type": ["string", "null"]},
            "task_excerpt": {"type": ["string", "null"]},
            "notes": string_array_schema_value(),
            "warnings": string_array_schema_value()
        }
    })
}

fn role_economics_profile_schema_value() -> serde_json::Value {
    let role_binding = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "resolved_model", "resolved_reasoning_effort", "observation",
            "resolution_observation"
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
                    "catalog_unavailable", "resolution_failed", "assignment_specific"
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
                                        "items": {"type": "string"},
                                        "uniqueItems": true
                                    },
                                    "budget_degrade_models": {
                                        "type": "array",
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
            "model_catalog_observation", "execution", "resolved_objective_profile"
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
            "resolved_objective_profile": resolved_objective_profile_schema_value(),
            "execution": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "assignment_count", "started_assignment_count", "completed_assignment_count",
                    "concurrency", "role_bindings", "assignment_effort_bindings",
                    "budget_degradations", "assignment_selection_ledger", "usage"
                ],
                "properties": {
                    "assignment_count": {"type": "integer", "minimum": 0},
                    "started_assignment_count": {"type": "integer", "minimum": 0},
                    "completed_assignment_count": {"type": "integer", "minimum": 0},
                    "concurrency": concurrency_report_schema_value(),
                    "role_bindings": role_map_schema_value(role_binding),
                    "assignment_effort_bindings": assignment_effort_bindings_schema_value(),
                    "budget_degradations": budget_degradation_records_schema_value(),
                    "assignment_selection_ledger": assignment_selection_ledger_schema_value(),
                    "selection_decisions": selection_decisions_schema_value(),
                    "usage": execution_usage_schema_value()
                }
            }
        }
    })
}

fn resolved_objective_profile_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["profile", "source"],
        "properties": {
            "source": {
                "type": "string",
                "enum": ["built_in", "repository_override"]
            },
            "profile": {
                "type": "object",
                "additionalProperties": false,
                "required": ["id", "version", "content_hash", "quality", "tradeoffs"],
                "properties": {
                    "id": {"type": "string", "minLength": 1},
                    "version": {"type": "integer", "minimum": 1},
                    "content_hash": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                    "quality": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["held_out_percent", "breadth_percent", "anti_shortcut_percent"],
                        "properties": {
                            "held_out_percent": {"type": "integer", "minimum": 0, "maximum": 100},
                            "breadth_percent": {"type": "integer", "minimum": 0, "maximum": 100},
                            "anti_shortcut_percent": {"type": "integer", "minimum": 0, "maximum": 100}
                        }
                    },
                    "tradeoffs": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": [
                            "monetary_cost_percent", "quota_consumption_percent", "latency_percent",
                            "retry_rework_percent", "human_review_percent"
                        ],
                        "properties": {
                            "monetary_cost_percent": {"type": "integer", "minimum": 0, "maximum": 100},
                            "quota_consumption_percent": {"type": "integer", "minimum": 0, "maximum": 100},
                            "latency_percent": {"type": "integer", "minimum": 0, "maximum": 100},
                            "retry_rework_percent": {"type": "integer", "minimum": 0, "maximum": 100},
                            "human_review_percent": {"type": "integer", "minimum": 0, "maximum": 100}
                        }
                    },
                    "switch_costs": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": [
                            "model_change_same_runtime_microunits",
                            "runtime_change_microunits"
                        ],
                        "properties": {
                            "model_change_same_runtime_microunits": {
                                "type": "integer",
                                "minimum": 0
                            },
                            "runtime_change_microunits": {
                                "type": "integer",
                                "minimum": 0
                            }
                        }
                    },
                    "quality_operations_balance": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["quality_percent", "operations_percent"],
                        "properties": {
                            "quality_percent": {"type": "integer", "minimum": 0, "maximum": 100},
                            "operations_percent": {"type": "integer", "minimum": 0, "maximum": 100}
                        }
                    }
                }
            }
        }
    })
}

fn selection_decisions_schema_value() -> serde_json::Value {
    json!({
        "type": "array",
        "items": crate::selection::selection_event_schema_value(),
    })
}

fn role_assignment_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "agent_id", "category", "legacy_role", "source",
            "requester_agent_id", "judge_agent_id", "evidence", "decision", "reason"
        ],
        "properties": {
            "agent_id": {"type": "string", "minLength": 1},
            "category": {
                "type": "string",
                "enum": [
                    "delegating_coordinator",
                    "non_delegating_terminal_worker",
                    "read_only_researcher",
                    "read_only_review_auditor"
                ]
            },
            "legacy_role": {"type": "string", "minLength": 1},
            "source": {
                "type": "string",
                "enum": ["derived_from_plan_role", "operator_override"]
            },
            "requester_agent_id": {"type": "string", "minLength": 1},
            "judge_agent_id": {"type": "string", "minLength": 1},
            "evidence": {
                "type": "object",
                "additionalProperties": false,
                "required": ["acceptance_grade", "recorded", "uncertain"],
                "properties": {
                    "acceptance_grade": {"type": "boolean"},
                    "recorded": {"type": "boolean"},
                    "uncertain": {"type": "boolean"}
                }
            },
            "decision": {
                "type": "string",
                "enum": ["granted", "refused"]
            },
            "reason": {"type": "string", "minLength": 1}
        }
    })
}

fn assignment_selection_ledger_schema_value() -> serde_json::Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "assignment_id", "attempt", "role", "selection_source", "selected_runtime",
                "selected_model", "selected_reasoning_effort", "catalog_source",
                "catalog_snapshot_digest", "catalog_revisions", "rejected_candidates",
                "evidence_gap"
            ],
            "properties": {
                "assignment_id": {"type": "string", "minLength": 1},
                "attempt": {"type": "integer", "minimum": 0},
                "role": agent_role_schema_value(),
                "role_assignment": role_assignment_schema_value(),
                "selection_source": {
                    "type": "string",
                    "enum": [
                        "automatic", "plan_role_models", "operator_override", "budget_degrade",
                        "low_difficulty_mechanical", "retry", "legacy_fake",
                        "legacy_nonpublishable_simulation"
                    ]
                },
                "selected_runtime": {"type": ["string", "null"], "minLength": 1},
                "selected_model": {"type": ["string", "null"], "minLength": 1},
                "selected_reasoning_effort": {"type": ["string", "null"], "minLength": 1},
                "catalog_source": {
                    "type": "string",
                    "enum": ["runtime_advertised", "operator_declared", "none"]
                },
                "catalog_snapshot_digest": {"type": ["string", "null"], "minLength": 1},
                "catalog_revisions": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["runtime", "revision", "advertised_at"],
                        "properties": {
                            "runtime": {"type": "string", "minLength": 1},
                            "revision": {"type": "string", "minLength": 1},
                            "advertised_at": {"type": "string", "minLength": 1}
                        }
                    }
                },
                "rejected_candidates": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["runtime", "model", "effort", "reasons"],
                        "properties": {
                            "runtime": {"type": "string", "minLength": 1},
                            "model": {"type": "string", "minLength": 1},
                            "effort": {"type": "string", "minLength": 1},
                            "reasons": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["code", "detail"],
                                    "properties": {
                                        "code": {"type": "string", "minLength": 1},
                                        "detail": {"type": "string", "minLength": 1}
                                    }
                                }
                            }
                        }
                    }
                },
                "quota_evidence": runtime_pool_state_schema_value(),
                "evidence_gap": {"type": ["string", "null"], "minLength": 1}
            }
        }
    })
}

fn runtime_pool_state_schema_value() -> serde_json::Value {
    let pool_reference = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["runtime", "account", "window"],
        "properties": {
            "runtime": {"type": "string", "minLength": 1},
            "account": {"type": "string", "minLength": 1},
            "window": {
                "oneOf": [
                    {"enum": ["none", "calendar_month"]},
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["rolling_hours"],
                        "properties": {
                            "rolling_hours": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["hours"],
                                "properties": {"hours": {"type": "integer", "minimum": 1}}
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
            "runtime", "admission_open", "pool_reference", "pool_kind",
            "entitlement_bounded", "entitlement_capacity_units",
            "entitlement_remaining_units", "pool_pressure_basis_points",
            "observed_consumption_units", "marginal_cost_microunits", "exhausted",
            "exhaustion_behavior", "authorized_alternatives", "observation_revision",
            "observation_source", "admission_provenance", "failover_provenance"
        ],
        "properties": {
            "runtime": {"type": "string", "minLength": 1},
            "admission_open": {"type": "boolean"},
            "pool_reference": pool_reference.clone(),
            "pool_kind": {"enum": ["subscription_included", "metered", "prepaid_credits"]},
            "entitlement_bounded": {"type": "boolean"},
            "entitlement_capacity_units": {"type": "integer", "minimum": 0},
            "entitlement_remaining_units": {"type": "integer", "minimum": 0},
            "pool_pressure_basis_points": {"type": "integer", "minimum": 0, "maximum": 10000},
            "observed_consumption_units": {"type": "integer", "minimum": 0},
            "marginal_cost_microunits": {"type": "integer", "minimum": 0},
            "exhausted": {"type": "boolean"},
            "exhaustion_behavior": {"enum": ["fail_closed", "degrade"]},
            "authorized_alternatives": {
                "type": "array",
                "items": pool_reference,
                "uniqueItems": true
            },
            "observation_revision": {"type": "string", "minLength": 1},
            "observation_source": {"const": "local_observed"},
            "admission_provenance": {"type": "string", "minLength": 1},
            "failover_provenance": {"type": ["string", "null"], "minLength": 1}
        }
    })
}

fn assignment_effort_bindings_schema_value() -> serde_json::Value {
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "assignment_id", "duty_id", "role", "fallback_reasoning_effort",
                "resolved_reasoning_effort", "resolution_observation", "process_observation"
            ],
            "properties": {
                "assignment_id": {"type": "string", "minLength": 1},
                "duty_id": {"type": "string", "minLength": 1},
                "role": agent_role_schema_value(),
                "requested_reasoning_effort": reasoning_effort_schema_value(),
                "fallback_reasoning_effort": {"type": "string", "minLength": 1},
                "resolved_reasoning_effort": {"type": "string", "minLength": 1},
                "resolution_observation": {
                    "type": "string",
                    "enum": [
                        "role_fallback", "assignment_override", "hard_floor_clamped",
                        "budget_degraded"
                    ]
                },
                "process_observation": process_observation_schema_value(),
                "unavailable_reason": {"type": "string", "minLength": 1}
            }
        }
    })
}

fn reasoning_effort_schema_value() -> serde_json::Value {
    json!({
        "type": "string",
        "enum": ["minimal", "low", "medium", "high", "xhigh", "max", "ultra"]
    })
}

fn budget_degradation_records_schema_value() -> serde_json::Value {
    let role_binding = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["model", "reasoning_effort"],
        "properties": {
            "model": {"type": ["string", "null"]},
            "reasoning_effort": {"type": ["string", "null"]}
        }
    });
    let change = json!({
        "oneOf": [
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "role", "before", "after"],
                "properties": {
                    "kind": {"const": "reasoning_effort"},
                    "role": agent_role_schema_value(),
                    "before": {"type": "string"},
                    "after": {"type": "string"}
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "role", "before", "after", "resolved_candidate_index"],
                "properties": {
                    "kind": {"const": "model_tier"},
                    "role": agent_role_schema_value(),
                    "before": {"type": "string"},
                    "after": {"type": "string"},
                    "resolved_candidate_index": {"type": "integer", "minimum": 0}
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "before", "after"],
                "properties": {
                    "kind": {"const": "fan_out"},
                    "before": {"type": "integer", "minimum": 1},
                    "after": {"type": "integer", "minimum": 1}
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "before_new_dispatch_allowed", "after_new_dispatch_allowed"],
                "properties": {
                    "kind": {"const": "halt"},
                    "before_new_dispatch_allowed": {"type": "boolean"},
                    "after_new_dispatch_allowed": {"type": "boolean"}
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "role"],
                "properties": {
                    "kind": {"const": "role_binding_applied"},
                    "role": {"const": "worker"}
                }
            }
        ]
    });
    json!({
        "type": "array",
        "items": {
            "type": "object",
            "additionalProperties": false,
            "required": [
                "sequence", "assignment_id", "trigger", "budget_action", "budget_reasons", "change",
                "effective_child_model", "effective_child_reasoning_effort", "effective_fan_out",
                "observation"
            ],
            "properties": {
                "sequence": {"type": "integer", "minimum": 1},
                "assignment_id": {"type": "string", "minLength": 1},
                "trigger": {
                    "type": "string",
                    "enum": ["budget_pressure", "low_difficulty_mechanical"]
                },
                "budget_action": {"type": "string", "enum": ["continue", "degrade", "owner_escalation"]},
                "budget_reasons": {
                    "type": "array",
                    "items": {"type": "string", "enum": [
                        "soft_token_ceiling_reached", "hard_token_ceiling_reached",
                        "soft_cost_ceiling_reached", "hard_cost_ceiling_reached",
                        "max_duration_reached",
                        "missing_pricing", "estimated_provider_usage", "missing_provider_usage",
                        "missing_actual_cost"
                    ]},
                    "uniqueItems": true
                },
                "change": change,
                "role_binding_transition": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["role", "before", "after"],
                    "properties": {
                        "role": {"const": "worker"},
                        "before": role_binding.clone(),
                        "after": role_binding
                    }
                },
                "effective_child_model": {"type": ["string", "null"]},
                "effective_child_reasoning_effort": {"type": ["string", "null"]},
                "effective_fan_out": {"type": "integer", "minimum": 1},
                "observation": {"const": "admission_policy_resolved"}
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
            "policy_input_details",
            "policy_input_unavailable_reason", "achieved_max_concurrent_children",
            "achieved_mean_concurrent_children", "achieved_mean_observation",
            "achieved_mean_unavailable_reason"
        ],
        "properties": {
            "configured_max_concurrent_children": {"type": "integer", "minimum": 1},
            "policy_input_observation": process_observation_schema_value(),
            "policy_input": {"type": ["string", "null"]},
            "policy_input_details": {
                "anyOf": [admission_policy_input_schema_value(), {"type": "null"}]
            },
            "policy_input_unavailable_reason": {"type": ["string", "null"]},
            "achieved_max_concurrent_children": {"type": "integer", "minimum": 0},
            "achieved_mean_concurrent_children": {"type": ["number", "null"], "minimum": 0},
            "achieved_mean_observation": process_observation_schema_value(),
            "achieved_mean_unavailable_reason": {"type": ["string", "null"]}
        }
    })
}

fn admission_policy_input_schema_value() -> serde_json::Value {
    let optional_positive = json!({"type": ["integer", "null"], "minimum": 1});
    let admission_config = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "max_concurrent_children": optional_positive.clone(),
            "provider_inflight_limit": optional_positive.clone(),
            "host_memory_available_mib": optional_positive.clone(),
            "host_memory_per_child_mib": optional_positive.clone(),
            "host_fd_available": optional_positive.clone(),
            "host_fds_per_child": optional_positive.clone(),
            "host_disk_available_mib": optional_positive.clone(),
            "host_disk_per_child_mib": optional_positive.clone(),
            "host_fallback_children": optional_positive.clone()
        }
    });
    let source = json!({
        "type": "string",
        "enum": ["configured", "operator_quota_config", "conservative_default", "measured"]
    });
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "entrypoint_bound", "plan", "cli", "effective",
            "provider_inflight_bound", "provider_inflight_source", "host", "resolved_bound"
        ],
        "properties": {
            "entrypoint_bound": {"type": "integer", "minimum": 1},
            "plan": admission_config.clone(),
            "cli": admission_config.clone(),
            "effective": admission_config,
            "provider_inflight_bound": {"type": "integer", "minimum": 1},
            "provider_inflight_source": source.clone(),
            "quota_inflight_bound": optional_positive.clone(),
            "quota_inflight_source": source.clone(),
            "quota_config_path": {"type": ["string", "null"], "minLength": 1},
            "host": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "memory_available_mib", "memory_available_source", "memory_per_child_mib",
                    "memory_bound", "fd_available", "fd_available_source", "fds_per_child",
                    "fd_bound", "disk_available_mib", "disk_available_source",
                    "disk_per_child_mib", "disk_bound", "fallback_children", "resolved_bound"
                ],
                "properties": {
                    "memory_available_mib": optional_positive.clone(),
                    "memory_available_source": source.clone(),
                    "memory_per_child_mib": {"type": "integer", "minimum": 1},
                    "memory_bound": optional_positive.clone(),
                    "fd_available": optional_positive.clone(),
                    "fd_available_source": source.clone(),
                    "fds_per_child": {"type": "integer", "minimum": 1},
                    "fd_bound": optional_positive.clone(),
                    "disk_available_mib": optional_positive.clone(),
                    "disk_available_source": source,
                    "disk_per_child_mib": {"type": "integer", "minimum": 1},
                    "disk_bound": optional_positive,
                    "fallback_children": {"type": "integer", "minimum": 1},
                    "resolved_bound": {"type": "integer", "minimum": 1}
                }
            },
            "resolved_bound": {"type": "integer", "minimum": 1}
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
            "elapsed_seconds",
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
            "max_duration_seconds": {"type": "integer", "minimum": 1},
            "sources": {
                "type": "object",
                "additionalProperties": false,
                "required": ["plan", "cli"],
                "properties": {
                    "plan": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["limits"],
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
                            "max_duration_seconds": {"type": "integer", "minimum": 1}
                        }
                    },
                    "cli": {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["limits"],
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
                            "max_duration_seconds": {"type": "integer", "minimum": 1}
                        }
                    }
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
                    "hard_cost_usd": {"type": "number", "minimum": 0},
                    "max_duration_seconds": {"type": "integer", "minimum": 0}
                }
            },
            "elapsed_seconds": {"type": "integer", "minimum": 0},
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
                        "max_duration_reached",
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
    orchestrator_report_schema_value_with_decomposition(
        worker_report_schema_value(),
        decomposition_completion_object_schema_value(),
    )
}

fn supervisor_final_orchestrator_report_schema_value() -> serde_json::Value {
    orchestrator_report_schema_value_with_decomposition(
        supervisor_final_worker_report_schema_value(),
        supervisor_final_decomposition_completion_object_schema_value(),
    )
}

fn orchestrator_report_schema_value_with_decomposition(
    worker_report_schema: serde_json::Value,
    decomposition_completion_schema: serde_json::Value,
) -> serde_json::Value {
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
            "worker_reports": {"type": "array", "items": worker_report_schema},
            "audit_reports": {"type": "array", "items": auditor_report_schema_value()},
            "review_lens_aggregate": review_lens_aggregate_schema_value(),
            "decomposition_completions": {
                "type": "array",
                "uniqueItems": true,
                "items": decomposition_completion_schema
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

fn review_lens_descriptor_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "id", "backend_id", "model", "information_scope", "expected_evidence_kind"
        ],
        "properties": {
            "id": identifier_schema_value(),
            "backend_id": {"type": "string", "minLength": 1},
            "model": {"type": "string", "minLength": 1},
            "reasoning_effort": {"type": "string", "minLength": 1},
            "information_scope": review_information_scope_schema_value(),
            "expected_evidence_kind": review_lens_evidence_kind_schema_value()
        }
    })
}

fn review_lens_coverage_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "worker_ids": string_array_schema_value(),
            "paths": path_array_schema_value()
        }
    })
}

fn review_lens_evidence_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "kind", "binding", "lens", "backend_configuration_id", "request_binding",
            "coverage"
        ],
        "properties": {
            "kind": review_lens_evidence_kind_schema_value(),
            "binding": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "lens": review_lens_descriptor_schema_value(),
            "backend_configuration_id": {"type": "string", "minLength": 1},
            "request_binding": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "coverage": review_lens_coverage_schema_value()
        }
    })
}

fn review_lens_aggregate_schema_value() -> serde_json::Value {
    let verdict_status = json!({"enum": ["accept", "reject", "procedural_failure"]});
    let verdict = json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "lens", "reported", "reported_verdict", "effective_verdict", "coverage",
            "evidence"
        ],
        "properties": {
            "lens": review_lens_descriptor_schema_value(),
            "reported": {"type": "boolean"},
            "request_binding": {"type": "string", "pattern": "^sha256:[0-9a-f]{64}$"},
            "reported_verdict": verdict_status.clone(),
            "effective_verdict": verdict_status,
            "coverage": review_lens_coverage_schema_value(),
            "evidence": {"type": "array", "items": review_lens_evidence_schema_value()},
            "validation_errors": string_array_schema_value()
        }
    });
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "version", "policy", "decision", "required_accepts", "validated_accepts",
            "rejected_lenses", "procedural_failures", "required_coverage", "lens_verdicts"
        ],
        "properties": {
            "version": {"type": "integer", "minimum": 1},
            "policy": review_aggregation_policy_schema_value(),
            "decision": {"enum": ["accept", "reject", "procedural_failure"]},
            "required_accepts": {"type": "integer", "minimum": 0},
            "validated_accepts": {"type": "integer", "minimum": 0},
            "rejected_lenses": {"type": "integer", "minimum": 0},
            "procedural_failures": {"type": "integer", "minimum": 0},
            "required_coverage": review_lens_coverage_schema_value(),
            "lens_verdicts": {"type": "array", "items": verdict}
        }
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
            "role_models": partial_role_map_schema_value(role_model_selection_schema_value()),
            "model_pricing": {
                "type": "object",
                "additionalProperties": model_pricing_schema_value()
            },
            "review_lenses": {
                "type": "array", "minItems": 1,
                "items": review_lens_config_schema_value()
            },
            "review_aggregation_policy": review_aggregation_policy_schema_value(),
            "assignments": {
                "type": "array", "minItems": 1, "maxItems": 1,
                "items": orchestrator_assignment_schema_value()
            },
            "spec_fragment_ids": {"type": "array", "maxItems": 0, "items": {"type": "string"}},
            "assignment_schedule": {
                "type": "array", "minItems": 1, "maxItems": 1,
                "items": assignment_schedule_entry_schema_value()
            },
            "run_budget": supervisor_budget_config_schema_value(),
            "consultant": supervisor_consultant_plan_schema_value(),
            "generated_follow_up": generated_follow_up_plan_context_schema_value()
        }
    })
}

fn partial_role_map_schema_value(value_schema: serde_json::Value) -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "supervisor": value_schema.clone(),
            "child_orchestrator": value_schema.clone(),
            "worker": value_schema.clone(),
            "gate_classifier": value_schema.clone(),
            "auditor": value_schema
        }
    })
}

fn role_model_selection_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "model": {"type": "string", "minLength": 1},
            "reasoning_effort": {"type": "string", "minLength": 1},
            "unavailable_model_fallback": {
                "oneOf": [
                    {"enum": ["fail_closed", "runtime_default", "local_deterministic_fake"]},
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
                                    "models": {"type": "array", "items": {"type": "string", "minLength": 1}},
                                    "budget_degrade_models": {"type": "array", "items": {"type": "string", "minLength": 1}},
                                    "on_exhausted": {"enum": ["fail_closed", "runtime_default", "local_deterministic_fake"]}
                                }
                            }
                        }
                    }
                ]
            }
        }
    })
}

fn model_pricing_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["input_usd_per_million_tokens", "output_usd_per_million_tokens"],
        "properties": {
            "input_usd_per_million_tokens": {"type": "number", "minimum": 0},
            "output_usd_per_million_tokens": {"type": "number", "minimum": 0}
        }
    })
}

fn review_lens_config_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["id", "backend", "information_scope"],
        "properties": {
            "id": identifier_schema_value(),
            "backend": {
                "oneOf": [
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["kind", "backend_id", "model"],
                        "properties": {
                            "kind": {"const": "model"},
                            "backend_id": {"type": "string", "minLength": 1},
                            "model": {"type": "string", "minLength": 1},
                            "reasoning_effort": {"type": "string", "minLength": 1}
                        }
                    },
                    {
                        "type": "object", "additionalProperties": false,
                        "required": ["kind", "backend_id", "model", "evidence_kind"],
                        "properties": {
                            "kind": {"const": "precomputed"},
                            "backend_id": {"type": "string", "minLength": 1},
                            "model": {"type": "string", "minLength": 1},
                            "evidence_kind": review_lens_evidence_kind_schema_value()
                        }
                    }
                ]
            },
            "information_scope": review_information_scope_schema_value()
        }
    })
}

fn review_information_scope_schema_value() -> serde_json::Value {
    json!({"enum": ["full_child_transcript", "diff_only", "output_report_only"]})
}

fn review_lens_evidence_kind_schema_value() -> serde_json::Value {
    json!({"enum": ["model_review", "process_evidence", "external_validation"]})
}

fn review_aggregation_policy_schema_value() -> serde_json::Value {
    json!({
        "oneOf": [
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind"], "properties": {"kind": {"const": "all_must_accept"}}
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "minimum_accepts"],
                "properties": {
                    "kind": {"const": "validated_quorum"},
                    "minimum_accepts": {"type": "integer", "minimum": 1}
                }
            }
        ]
    })
}

fn role_category_schema_value() -> serde_json::Value {
    json!({"enum": [
        "delegating_coordinator", "non_delegating_terminal_worker",
        "read_only_researcher", "read_only_review_auditor"
    ]})
}

fn assignment_selection_source_schema_value() -> serde_json::Value {
    json!({"enum": [
        "automatic", "plan_role_models", "operator_override", "budget_degrade",
        "low_difficulty_mechanical", "retry", "legacy_fake",
        "legacy_nonpublishable_simulation"
    ]})
}

fn worker_assignment_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "id", "role", "assigned_paths", "semantic_symbols", "semantic_modules",
            "environment_requirements"
        ],
        "properties": {
            "id": identifier_schema_value(),
            "role": {"const": "worker"},
            "role_category": role_category_schema_value(),
            "selection_source": assignment_selection_source_schema_value(),
            "assigned_paths": path_array_schema_value(),
            "semantic_symbols": string_array_schema_value(),
            "semantic_modules": string_array_schema_value(),
            "task": {"type": "string"},
            "environment_requirements": {
                "type": "array", "items": environment_requirement_schema_value()
            },
            "report_path": repository_relative_path_schema_value()
        }
    })
}

fn licensed_breakage_declaration_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["migration_rationale", "dependents"],
        "properties": {
            "migration_rationale": {"type": "string", "minLength": 1},
            "dependents": {
                "type": "array",
                "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["dependent_id", "paths", "interfaces"],
                    "properties": {
                        "dependent_id": identifier_schema_value(),
                        "paths": path_array_schema_value(),
                        "interfaces": string_array_schema_value()
                    }
                }
            }
        }
    })
}

fn orchestrator_assignment_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "id", "phase", "role", "assigned_paths", "semantic_symbols", "semantic_modules",
            "worker_assignments", "environment_requirements"
        ],
        "properties": {
            "id": identifier_schema_value(),
            "phase": {"enum": ["planning", "execution"]},
            "runtime": {"enum": ["codex", "fake", "grok", "cursor", "claude-code", "gemini-cli"]},
            "role": {"const": "child_orchestrator"},
            "role_category": role_category_schema_value(),
            "selection_source": assignment_selection_source_schema_value(),
            "assigned_paths": path_array_schema_value(),
            "semantic_symbols": string_array_schema_value(),
            "semantic_modules": string_array_schema_value(),
            "task": {"type": "string"},
            "worker_assignments": {"type": "array", "items": worker_assignment_schema_value()},
            "environment_requirements": {"type": "array", "items": environment_requirement_schema_value()},
            "licensed_breakage": licensed_breakage_declaration_schema_value(),
            "notes": {"type": "string"}
        }
    })
}

fn assignment_schedule_entry_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["assignment_id", "depth", "flattened_index"],
        "properties": {
            "assignment_id": identifier_schema_value(),
            "parent_assignment_id": identifier_schema_value(),
            "depth": {"type": "integer", "minimum": 0, "maximum": 255},
            "flattened_index": {"type": "integer", "minimum": 0}
        }
    })
}

fn supervisor_budget_config_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "soft_tokens": {"type": "integer", "minimum": 1},
            "hard_tokens": {"type": "integer", "minimum": 1},
            "soft_cost_usd": {"type": "number", "exclusiveMinimum": 0},
            "hard_cost_usd": {"type": "number", "exclusiveMinimum": 0},
            "role_token_reservations": partial_role_map_schema_value(
                json!({"type": "integer", "minimum": 1})
            )
        }
    })
}

fn supervisor_consultant_plan_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["enabled", "runtime", "max_consultations"],
        "properties": {
            "enabled": {"type": "boolean"},
            "runtime": {"type": "string", "minLength": 1},
            "max_consultations": {"type": "integer", "minimum": 0}
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
            "breaking_change": candidate_validation_binding_schema_value(),
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
            "reason": gate_denial_reason_schema_value(),
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
                    "source": {"enum": [
                        "claim_acquisition", "destructive_target_preflight", "budget_admission",
                        "auditor", "validation", "primary_drift", "git_apply_check",
                        "merge_scope", "validation_binding", "validation_state", "sandbox_policy",
                        "containment", "primary_integrity", "external_side_effect",
                        "authenticated_checkpoint", "future_approval_review"
                    ]},
                    "paths": path_array_schema_value()
                }
            },
            "route": {
                "type": "string",
                "enum": ["planner_parent", "child_controller", "integration_controller"]
            },
            "next_safe_operation": {"enum": [
                "narrow_or_replan_claim_ownership", "review_run_budget_and_start_new_run",
                "repair_auditor_findings", "evidence_only_reaudit", "repair_validation",
                "restore_clean_primary", "refresh_candidate_base", "repair_merge_conflict",
                "remediate_unclaimed_merge_edits", "remediate_excluded_reference",
                "restore_containment", "restore_primary_integrity",
                "inspect_authenticated_checkpoint", "reconcile_external_side_effect",
                "escalate_sandbox_policy", "replan_destructive_targets",
                "narrow_action_or_choose_another_tool", "restore_pre_action_review_service"
            ]}
        }
    })
}

fn gate_denial_reason_schema_value() -> serde_json::Value {
    let blocker = json!({"enum": [
        "dirty_primary", "stale_base", "primary_state_changed", "apply_check_failed",
        "excluded_reference", "unclaimed_edits", "validation_missing", "validation_not_run",
        "validation_skipped", "validation_failed"
    ]});
    let coordinate = json!({
        "type": "object", "additionalProperties": false,
        "required": ["root_id", "relative"],
        "properties": {
            "root_id": identifier_schema_value(),
            "relative": repository_relative_path_schema_value()
        }
    });
    let destructive = json!({
        "oneOf": [
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "target", "active_claim"],
                "properties": {
                    "kind": {"const": "active_claim_intersection"},
                    "target": coordinate.clone(), "active_claim": coordinate.clone()
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "target", "protected"],
                "properties": {
                    "kind": {"const": "protected_path_intersection"},
                    "target": coordinate.clone(),
                    "protected": {
                        "type": "object", "additionalProperties": false,
                        "required": ["coordinate", "retryability"],
                        "properties": {
                            "coordinate": coordinate,
                            "retryability": {"enum": ["requires_declared_exception", "not_retryable"]}
                        }
                    }
                }
            },
            {
                "type": "object", "additionalProperties": false,
                "required": ["kind", "target_fingerprint"],
                "properties": {
                    "kind": {"const": "undeclared_target"},
                    "target_fingerprint": {"type": "string", "minLength": 1}
                }
            }
        ]
    });
    json!({
        "oneOf": [
            {"type": "object", "additionalProperties": false, "required": ["family"], "properties": {"family": {"const": "claim_conflict"}}},
            {"type": "object", "additionalProperties": false, "required": ["family", "denial"], "properties": {"family": {"const": "budget_admission"}, "denial": {"enum": ["new_dispatch_stopped", "missing_cost_estimate", "hard_token_ceiling", "hard_cost_ceiling"]}}},
            {"type": "object", "additionalProperties": false, "required": ["family", "rejection"], "properties": {"family": {"const": "auditor_repair"}, "rejection": {"enum": ["implementation_defect", "evidence_quality"]}}},
            {"type": "object", "additionalProperties": false, "required": ["family", "blocker"], "properties": {"family": {"const": "validation_repair"}, "blocker": blocker.clone()}},
            {"type": "object", "additionalProperties": false, "required": ["family", "blocker"], "properties": {"family": {"const": "merge_remediation"}, "blocker": blocker}},
            {"type": "object", "additionalProperties": false, "required": ["family"], "properties": {"family": {"const": "containment_failure"}}},
            {"type": "object", "additionalProperties": false, "required": ["family"], "properties": {"family": {"const": "primary_integrity_failure"}}},
            {"type": "object", "additionalProperties": false, "required": ["family", "denial"], "properties": {"family": {"const": "resume_checkpoint"}, "denial": {"enum": ["integrity_failure", "unsupported_lifecycle"]}}},
            {"type": "object", "additionalProperties": false, "required": ["family", "state"], "properties": {"family": {"const": "external_side_effect"}, "state": {"enum": ["ambiguous", "completed"]}}},
            {"type": "object", "additionalProperties": false, "required": ["family", "evidence"], "properties": {"family": {"const": "sandbox"}, "evidence": sandbox_denial_evidence_schema_value()}},
            {"type": "object", "additionalProperties": false, "required": ["family", "denial"], "properties": {"family": {"const": "destructive_target"}, "denial": destructive}},
            {"type": "object", "additionalProperties": false, "required": ["family", "denial"], "properties": {"family": {"const": "approval_review"}, "denial": {"enum": [
                "permission_expansion", "outside_workspace", "destructive_workspace_operation",
                "claim_escape", "sensitive_read", "inconsistent_request", "classifier_denied",
                "classifier_timeout", "classifier_malformed_response", "classifier_protocol_error",
                "human_review_required", "latency_budget_exceeded", "duplex_fallback_required"
            ]}}}
        ]
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
            "correction_attempts",
            "unavailable_reason"
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
            },
            "unavailable_reason": {"type": ["string", "null"]}
        }
    })
}

pub(super) fn write_worker_schema(writer: &mut ArtifactRunWriter, relative: &Path) -> Result<()> {
    write_schema(writer, relative, worker_report_schema_value())
}

pub(super) fn write_codex_worker_schema(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
) -> Result<()> {
    write_schema(
        writer,
        relative,
        codex_response_format_schema(worker_report_schema_value())?,
    )
}

pub(super) fn write_auditor_schema(writer: &mut ArtifactRunWriter, relative: &Path) -> Result<()> {
    write_schema(writer, relative, auditor_report_schema_value())
}

pub(super) fn write_codex_auditor_schema(
    writer: &mut ArtifactRunWriter,
    relative: &Path,
) -> Result<()> {
    write_schema(
        writer,
        relative,
        codex_response_format_schema(auditor_report_schema_value())?,
    )
}

pub(super) fn codex_response_format_schema(
    mut authoritative: serde_json::Value,
) -> Result<serde_json::Value> {
    if authoritative
        .get("title")
        .and_then(serde_json::Value::as_str)
        == Some("OrchestratorReviewReport")
    {
        let properties = authoritative
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
            .context("authoritative orchestrator schema omitted properties")?;
        for supervisor_owned in [
            "licensed_breakage_review",
            "generated_follow_up_tasks",
            "gate_denials",
            "gate_correction_outcomes",
        ] {
            properties.remove(supervisor_owned);
        }
    }
    apply_codex_serde_option_projection(&mut authoritative)?;
    make_codex_response_format_compatible(&mut authoritative)?;
    validate_codex_response_format_schema(&authoritative)?;
    Ok(authoritative)
}

const CODEX_SERDE_OPTION_PROJECTION: &str = "x-maco-serde-option";

fn apply_codex_serde_option_projection(schema: &mut serde_json::Value) -> Result<()> {
    let expected = match schema
        .get("title")
        .and_then(serde_json::Value::as_str)
        .context("Codex report schema omitted its title")?
    {
        "WorkerReport" | "AuditorReport" => 13,
        "OrchestratorReviewReport" => 39,
        title => bail!("unsupported Codex report schema title '{title}'"),
    };
    let projected = project_serde_option_properties(schema)?;
    if projected != expected {
        bail!(
            "Codex serde Option projection expected {expected} typed properties but found {projected}"
        );
    }
    Ok(())
}

fn project_serde_option_properties(schema: &mut serde_json::Value) -> Result<usize> {
    let serde_json::Value::Object(object) = schema else {
        return Ok(0);
    };
    let projected_names = if schema_object_matches(
        object,
        &["boundary", "policy_id", "operation", "retryability"],
        &["boundary", "policy_id", "operation", "path", "retryability"],
    ) {
        &["path"][..]
    } else if schema_object_matches(
        object,
        &["requirement", "status"],
        &["requirement", "status", "observation"],
    ) {
        &["observation"][..]
    } else if schema_object_matches(
        object,
        &["category", "summary", "remediation"],
        &["category", "requirement", "summary", "remediation"],
    ) {
        &["requirement"][..]
    } else if schema_object_matches(
        object,
        &["kind", "executable"],
        &["kind", "executable", "version"],
    ) {
        &["version"][..]
    } else if schema_object_matches(object, &[], &["minimum_inclusive", "maximum_exclusive"]) {
        &["minimum_inclusive", "maximum_exclusive"][..]
    } else {
        &[][..]
    };

    let mut projected = projected_names.len();
    if !projected_names.is_empty() {
        let properties = object
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
            .context("typed serde Option projection omitted properties")?;
        for name in projected_names {
            let property = properties
                .get_mut(*name)
                .and_then(serde_json::Value::as_object_mut)
                .with_context(|| format!("typed serde Option projection omitted '{name}'"))?;
            if property
                .insert(
                    CODEX_SERDE_OPTION_PROJECTION.to_string(),
                    serde_json::Value::Bool(true),
                )
                .is_some()
            {
                bail!("typed serde Option projection duplicated '{name}'");
            }
        }
    }
    for value in object.values_mut() {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    projected += project_serde_option_properties(value)?;
                }
            }
            serde_json::Value::Object(_) => {
                projected += project_serde_option_properties(value)?;
            }
            _ => {}
        }
    }
    Ok(projected)
}

fn schema_object_matches(
    object: &serde_json::Map<String, serde_json::Value>,
    required: &[&str],
    properties: &[&str],
) -> bool {
    if object.get("type") != Some(&json!("object")) {
        return false;
    }
    let Some(actual_properties) = object
        .get("properties")
        .and_then(serde_json::Value::as_object)
    else {
        return false;
    };
    if actual_properties.len() != properties.len()
        || properties
            .iter()
            .any(|name| !actual_properties.contains_key(*name))
    {
        return false;
    }
    match object.get("required").and_then(serde_json::Value::as_array) {
        Some(actual_required) => {
            actual_required.len() == required.len()
                && required.iter().all(|name| {
                    actual_required
                        .iter()
                        .any(|actual| actual.as_str() == Some(name))
                })
        }
        None => required.is_empty(),
    }
}

fn codex_const_json_type(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(number) if number.is_i64() || number.is_u64() => "integer",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn make_codex_response_format_compatible(schema: &mut serde_json::Value) -> Result<()> {
    if schema
        .as_object()
        .is_some_and(|object| object.len() == 1 && object.get("type") == Some(&json!("object")))
    {
        *schema = codex_environment_preflight_observation_schema_value();
    }
    let serde_json::Value::Object(object) = schema else {
        return Ok(());
    };
    if !object.contains_key("type") {
        if let Some(schema_type) = object.get("const").map(codex_const_json_type) {
            object.insert("type".to_string(), json!(schema_type));
        }
    }
    for unsupported in [
        "$schema",
        "allOf",
        "if",
        "then",
        "else",
        "not",
        "contains",
        "minContains",
        "maxContains",
        "minLength",
        "maxLength",
        "pattern",
        "format",
        "minimum",
        "maximum",
        "exclusiveMinimum",
        "exclusiveMaximum",
        "multipleOf",
        "minItems",
        "maxItems",
        "uniqueItems",
        "minProperties",
        "maxProperties",
        "default",
        CODEX_SERDE_OPTION_PROJECTION,
        "examples",
        "readOnly",
        "writeOnly",
    ] {
        object.remove(unsupported);
    }

    if object.contains_key("properties") {
        let required = object
            .get("required")
            .map(|required| {
                required
                    .as_array()
                    .context("Codex response required entry must be an array")?
                    .iter()
                    .map(|value| {
                        value
                            .as_str()
                            .map(str::to_string)
                            .context("Codex response required entry must be a string")
                    })
                    .collect::<Result<BTreeSet<_>>>()
            })
            .transpose()?
            .unwrap_or_default();
        let properties = object
            .get_mut("properties")
            .and_then(serde_json::Value::as_object_mut)
            .context("Codex response properties must be an object")?;
        for (name, property_schema) in properties.iter_mut() {
            if !required.contains(name) && serde_option_accepts_explicit_null(property_schema)? {
                make_codex_property_nullable(property_schema)?;
            }
        }
        let retained_required = properties
            .keys()
            .cloned()
            .map(serde_json::Value::String)
            .collect::<Vec<_>>();
        object.insert(
            "required".to_string(),
            serde_json::Value::Array(retained_required),
        );
        object.insert(
            "additionalProperties".to_string(),
            serde_json::Value::Bool(false),
        );
        // These keywords express authoritative cross-field conditions. The local schema and
        // acceptance gates retain and enforce them after provider-constrained decoding.
        object.remove("oneOf");
        object.remove("anyOf");
    } else if let Some(one_of) = object.remove("oneOf") {
        if object.insert("anyOf".to_string(), one_of).is_some() {
            bail!("Codex response schema cannot combine oneOf and anyOf at one node");
        }
    }

    for value in object.values_mut() {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    make_codex_response_format_compatible(value)?;
                }
            }
            serde_json::Value::Object(_) => make_codex_response_format_compatible(value)?,
            _ => {}
        }
    }
    Ok(())
}

fn serde_option_accepts_explicit_null(schema: &serde_json::Value) -> Result<bool> {
    let object = schema
        .as_object()
        .context("Codex property schema must be an object")?;
    match object.get(CODEX_SERDE_OPTION_PROJECTION) {
        None => Ok(false),
        Some(serde_json::Value::Bool(true)) => Ok(true),
        Some(_) => bail!("Codex serde Option projection marker must be true"),
    }
}

fn make_codex_property_nullable(schema: &mut serde_json::Value) -> Result<()> {
    let object = schema
        .as_object_mut()
        .context("Codex optional property schema must be an object")?;
    if object.remove(CODEX_SERDE_OPTION_PROJECTION) != Some(serde_json::Value::Bool(true)) {
        bail!("Codex nullable property omitted its typed serde Option projection");
    }
    if schema
        .as_object()
        .is_some_and(|object| object.len() == 1 && object.get("type") == Some(&json!("object")))
    {
        *schema = codex_environment_preflight_observation_schema_value();
    }
    let object = schema
        .as_object_mut()
        .context("Codex optional property schema must be an object")?;
    if let Some(schema_type) = object.get_mut("type") {
        match schema_type {
            serde_json::Value::String(existing) if existing != "null" => {
                *schema_type = json!([existing.clone(), "null"]);
            }
            serde_json::Value::Array(types) => {
                if !types.iter().any(|value| value == "null") {
                    types.push(json!("null"));
                }
            }
            serde_json::Value::String(_) => {}
            _ => bail!("Codex optional property type must be a string or string array"),
        }
        if let Some(enum_values) = object
            .get_mut("enum")
            .and_then(serde_json::Value::as_array_mut)
        {
            if !enum_values.iter().any(serde_json::Value::is_null) {
                enum_values.push(serde_json::Value::Null);
            }
        }
        return Ok(());
    }
    for union in ["oneOf", "anyOf"] {
        if let Some(variants) = object
            .get_mut(union)
            .and_then(serde_json::Value::as_array_mut)
        {
            if !variants
                .iter()
                .any(|variant| variant == &json!({"type": "null"}))
            {
                variants.push(json!({"type": "null"}));
            }
            return Ok(());
        }
    }
    bail!("Codex optional property schema has no nullable type or union representation")
}

fn codex_environment_preflight_observation_schema_value() -> serde_json::Value {
    json!({
        "oneOf": [
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "executable", "version"],
                "properties": {
                    "kind": {"const": "executable_version"},
                    "executable": {
                        "type": "string",
                        "enum": ["bash", "cargo", "cmake", "codex", "git", "nix", "node", "npm", "python3", "rustc"]
                    },
                    "version": environment_version_schema_value()
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "credential"],
                "properties": {
                    "kind": {"const": "credential_present"},
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
                    "kind": {"const": "configuration_present"},
                    "configuration": {"const": "codex_auth_file"}
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "enabled"],
                "properties": {
                    "kind": {"const": "network"},
                    "enabled": {"type": "boolean"}
                }
            },
            {
                "type": "object",
                "additionalProperties": false,
                "required": ["kind", "profile"],
                "properties": {
                    "kind": {"const": "sandbox"},
                    "profile": {
                        "type": "string",
                        "enum": ["strict_offline_workspace", "trusted_fixed_network", "external_codex", "trusted_compatibility"]
                    }
                }
            }
        ]
    })
}

fn validate_codex_response_format_schema(schema: &serde_json::Value) -> Result<()> {
    let serde_json::Value::Object(object) = schema else {
        return Ok(());
    };
    if object.contains_key("const") && !object.contains_key("type") {
        bail!("Codex response const schema omitted its JSON type");
    }
    for unsupported in [
        "$schema",
        "allOf",
        "oneOf",
        "if",
        "then",
        "else",
        "not",
        "contains",
        "minContains",
        "maxContains",
        "default",
        CODEX_SERDE_OPTION_PROJECTION,
    ] {
        if object.contains_key(unsupported) {
            bail!("Codex response schema retained unsupported keyword '{unsupported}'");
        }
    }
    if let Some(properties) = object
        .get("properties")
        .and_then(serde_json::Value::as_object)
    {
        let required = object
            .get("required")
            .and_then(serde_json::Value::as_array)
            .context("Codex response object schema omitted required")?
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .context("Codex required entry is not a string")
            })
            .collect::<Result<BTreeSet<_>>>()?;
        if required.len() != properties.len()
            || properties
                .keys()
                .any(|name| !required.contains(name.as_str()))
            || object.get("additionalProperties") != Some(&serde_json::Value::Bool(false))
        {
            bail!(
                "Codex response object schema must require every property and deny additional properties"
            );
        }
    }
    for value in object.values() {
        match value {
            serde_json::Value::Array(values) => {
                for value in values {
                    validate_codex_response_format_schema(value)?;
                }
            }
            serde_json::Value::Object(_) => validate_codex_response_format_schema(value)?,
            _ => {}
        }
    }
    Ok(())
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
    worker_report_schema_value_with_decomposition(decomposition_completion_schema_value())
}

fn supervisor_final_worker_report_schema_value() -> serde_json::Value {
    worker_report_schema_value_with_decomposition(
        supervisor_final_decomposition_completion_schema_value(),
    )
}

fn worker_report_schema_value_with_decomposition(
    decomposition_completion_schema: serde_json::Value,
) -> serde_json::Value {
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
            "decomposition_completion": decomposition_completion_schema,
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
    decomposition_completion_schema_value_with_binding(json!(["object", "null"]), false)
}

fn decomposition_completion_object_schema_value() -> serde_json::Value {
    decomposition_completion_schema_value_with_binding(json!("object"), false)
}

fn supervisor_final_decomposition_completion_schema_value() -> serde_json::Value {
    decomposition_completion_schema_value_with_binding(json!(["object", "null"]), true)
}

fn supervisor_final_decomposition_completion_object_schema_value() -> serde_json::Value {
    decomposition_completion_schema_value_with_binding(json!("object"), true)
}

fn decomposition_completion_schema_value_with_binding(
    schema_type: serde_json::Value,
    include_supervisor_binding: bool,
) -> serde_json::Value {
    let base_properties = json!({
        "target_path": {"type": "string", "minLength": 1},
        "replacement_paths": {
            "type": "array",
            "minItems": 1,
            "maxItems": MAX_DECOMPOSITION_REPLACEMENT_PATHS,
            "uniqueItems": true,
            "items": {"type": "string", "minLength": 1}
        }
    });
    let properties = if include_supervisor_binding {
        merge_schema_property_groups([
            base_properties,
            json!({
                "supervisor_candidate_binding": candidate_validation_binding_schema_value()
            }),
        ])
    } else {
        base_properties
    };
    json!({
        "type": schema_type,
        "additionalProperties": false,
        "required": ["target_path", "replacement_paths"],
        "properties": properties
    })
}

pub(super) fn command_run_record_schema_value() -> serde_json::Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "command",
            "cwd",
            "status",
            "timeout_seconds",
            "duration_ms",
            "timed_out",
            "stdout",
            "stderr",
            "environment_preflight_results",
            "environment_failures"
        ],
        "properties": {
            "command": {"type": "array", "items": {"type": "string"}},
            "cwd": safe_published_path_schema_value(),
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
            "observation": codex_environment_preflight_observation_schema_value()
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
        "required": ["name", "status", "command"],
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

#[cfg(test)]
mod selection_schema_tests {
    use super::*;

    fn open_object_schema_paths(value: &serde_json::Value) -> Vec<String> {
        fn walk(value: &serde_json::Value, path: &str, open: &mut Vec<String>) {
            match value {
                serde_json::Value::Object(object) => {
                    let object_type = object.get("type").is_some_and(|schema_type| {
                        schema_type == "object"
                            || schema_type
                                .as_array()
                                .is_some_and(|types| types.iter().any(|value| value == "object"))
                    });
                    if object_type && !object.contains_key("additionalProperties") {
                        open.push(path.to_string());
                    }
                    for (name, child) in object {
                        walk(child, &format!("{path}/{name}"), open);
                    }
                }
                serde_json::Value::Array(values) => {
                    for (index, child) in values.iter().enumerate() {
                        walk(child, &format!("{path}/{index}"), open);
                    }
                }
                _ => {}
            }
        }

        let mut open = Vec::new();
        walk(value, "$", &mut open);
        open
    }

    #[test]
    fn generated_supervisor_contract_has_no_open_object_schema() {
        assert_eq!(
            open_object_schema_paths(&supervisor_final_report_schema_value()),
            Vec::<String>::new()
        );
    }

    #[test]
    fn generated_supervisor_contract_accepts_published_valid_fixture() -> Result<()> {
        let instance: serde_json::Value = serde_json::from_str(include_str!(
            "../../fixtures/schemas/supervisor-final-report-v1.valid.json"
        ))?;
        let schema = supervisor_final_report_schema_value();
        assert!(
            schema_accepts_instance(&schema, &instance),
            "generated complete supervisor contract rejected the published valid fixture"
        );
        Ok(())
    }

    #[test]
    #[ignore = "maintainer-only schema rendering helper"]
    fn print_complete_supervisor_final_contract() -> Result<()> {
        println!(
            "FINAL_SCHEMA_BEGIN{}FINAL_SCHEMA_END",
            serde_json::to_string(&supervisor_final_report_schema_value())?
        );
        Ok(())
    }

    #[test]
    #[ignore = "maintainer-only schema rendering helper"]
    fn print_complete_supervisor_collect_contract() -> Result<()> {
        println!(
            "COLLECT_SCHEMA_BEGIN{}COLLECT_SCHEMA_END",
            serde_json::to_string(&supervisor_collect_report_schema_value())?
        );
        Ok(())
    }

    fn required_contains(schema: &serde_json::Value, field: &str) -> bool {
        schema["required"]
            .as_array()
            .is_some_and(|required| required.iter().any(|value| value == field))
    }

    fn schema_accepts_null(schema: &serde_json::Value) -> bool {
        schema["type"] == "null"
            || schema["type"]
                .as_array()
                .is_some_and(|types| types.iter().any(|value| value == "null"))
            || schema["anyOf"]
                .as_array()
                .is_some_and(|variants| variants.iter().any(schema_accepts_null))
    }

    fn schema_accepts_instance(schema: &serde_json::Value, instance: &serde_json::Value) -> bool {
        let Some(schema) = schema.as_object() else {
            return true;
        };
        if let Some(any_of) = schema.get("anyOf").and_then(serde_json::Value::as_array) {
            if !any_of
                .iter()
                .any(|variant| schema_accepts_instance(variant, instance))
            {
                return false;
            }
        }
        if schema
            .get("const")
            .is_some_and(|expected| expected != instance)
        {
            return false;
        }
        if schema
            .get("enum")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|values| !values.contains(instance))
        {
            return false;
        }
        if let Some(schema_type) = schema.get("type") {
            let matches_type = |schema_type: &serde_json::Value| match schema_type.as_str() {
                Some("null") => instance.is_null(),
                Some("boolean") => instance.is_boolean(),
                Some("integer") => instance.as_i64().is_some() || instance.as_u64().is_some(),
                Some("number") => instance.is_number(),
                Some("string") => instance.is_string(),
                Some("array") => instance.is_array(),
                Some("object") => instance.is_object(),
                _ => false,
            };
            let accepted_type = schema_type.as_array().map_or_else(
                || matches_type(schema_type),
                |types| types.iter().any(matches_type),
            );
            if !accepted_type {
                return false;
            }
        }
        if let Some(instance) = instance.as_object() {
            let properties = schema
                .get("properties")
                .and_then(serde_json::Value::as_object);
            if let Some(required) = schema.get("required").and_then(serde_json::Value::as_array) {
                if required.iter().any(|name| {
                    name.as_str()
                        .is_none_or(|name| !instance.contains_key(name))
                }) {
                    return false;
                }
            }
            for (name, value) in instance {
                match properties.and_then(|properties| properties.get(name)) {
                    Some(property_schema) => {
                        if !schema_accepts_instance(property_schema, value) {
                            return false;
                        }
                    }
                    None if schema.get("additionalProperties") == Some(&json!(false)) => {
                        return false;
                    }
                    None => {}
                }
            }
        }
        if let Some(instance) = instance.as_array() {
            if let Some(items) = schema.get("items") {
                if instance
                    .iter()
                    .any(|value| !schema_accepts_instance(items, value))
                {
                    return false;
                }
            }
        }
        true
    }

    fn assert_serialized_keys_are_required(value: &serde_json::Value, schema: &serde_json::Value) {
        let object = value.as_object().expect("representative report object");
        let properties = schema["properties"]
            .as_object()
            .expect("compatible object properties");
        for key in object.keys() {
            assert!(
                properties.contains_key(key),
                "schema omitted serialized key {key}"
            );
            assert!(
                required_contains(schema, key),
                "schema did not require key {key}"
            );
        }
    }

    #[test]
    fn codex_report_schemas_are_strict_shape_only_derivatives() -> Result<()> {
        let authoritative = orchestrator_report_schema_value();
        assert!(authoritative.get("allOf").is_some());
        assert!(authoritative["properties"]
            .get("licensed_breakage_review")
            .is_some());

        let codex = codex_response_format_schema(authoritative.clone())?;
        assert_eq!(codex["title"], "OrchestratorReviewReport");
        assert!(codex.get("$schema").is_none());
        assert!(codex.get("allOf").is_none());
        assert!(required_contains(&codex, "worker_reports"));
        assert!(required_contains(&codex, "audit_reports"));
        assert!(codex["properties"]
            .get("licensed_breakage_review")
            .is_none());
        assert!(codex["properties"]
            .get("generated_follow_up_tasks")
            .is_none());
        assert!(codex["properties"].get("gate_denials").is_none());
        assert!(codex["properties"]
            .get("gate_correction_outcomes")
            .is_none());
        let worker = &codex["properties"]["worker_reports"]["items"];
        let command = &worker["properties"]["commands_run"]["items"];
        for field in [
            "sandbox_denials",
            "environment_preflight_results",
            "environment_failures",
        ] {
            assert!(required_contains(command, field));
            assert!(command["properties"].get(field).is_some());
            assert!(!schema_accepts_null(&command["properties"][field]));
        }
        for field in ["stdout", "stderr"] {
            assert!(required_contains(command, field));
            assert!(!schema_accepts_null(&command["properties"][field]));
        }
        let denial = &command["properties"]["sandbox_denials"]["items"];
        assert!(required_contains(denial, "path"));
        assert!(schema_accepts_null(&denial["properties"]["path"]));
        let preflight = &command["properties"]["environment_preflight_results"]["items"];
        assert!(required_contains(preflight, "observation"));
        assert!(schema_accepts_null(&preflight["properties"]["observation"]));
        let failure = &command["properties"]["environment_failures"]["items"];
        assert!(required_contains(failure, "requirement"));
        assert!(schema_accepts_null(&failure["properties"]["requirement"]));
        let requirement_kind =
            &failure["properties"]["requirement"]["anyOf"][0]["properties"]["kind"];
        assert_eq!(requirement_kind["const"], "executable");
        assert_eq!(requirement_kind["type"], "string");
        let validation = &worker["properties"]["validation_results"]["items"];
        assert!(required_contains(validation, "command"));
        assert!(!schema_accepts_null(&validation["properties"]["command"]));
        assert!(required_contains(validation, "message"));
        assert!(schema_accepts_null(&validation["properties"]["message"]));
        validate_codex_response_format_schema(&codex)?;
        assert!(validate_codex_response_format_schema(&json!({
            "const": "missing-type"
        }))
        .is_err());

        let auditor = codex_response_format_schema(auditor_report_schema_value())?;
        assert_eq!(auditor["title"], "AuditorReport");
        assert!(required_contains(&auditor, "reviewed_worker_ids"));
        assert!(required_contains(&auditor, "read_only"));
        validate_codex_response_format_schema(&auditor)?;

        let requirement = crate::external_agent::EnvironmentRequirement::executable(
            crate::external_agent::EnvironmentExecutable::Cargo,
            Some(
                crate::external_agent::EnvironmentVersionConstraint::bounded(
                    crate::external_agent::EnvironmentVersion::new(1, 90, 0),
                    crate::external_agent::EnvironmentVersion::new(2, 0, 0),
                ),
            ),
        );
        let failure = EnvironmentFailure {
            category: EnvironmentFailureCategory::VersionMismatch,
            requirement: Some(requirement.clone()),
            summary: "representative version mismatch".to_string(),
            remediation: vec![EnvironmentRemediation {
                scope: EnvironmentRemediationScope::ProjectLocal,
                guidance: "use the pinned toolchain".to_string(),
            }],
        };
        let command_record = CommandRunRecord {
            command: vec!["cargo".to_string(), "check".to_string()],
            cwd: PathBuf::from("."),
            exit_code: Some(1),
            status: ReviewStatus::Failed,
            timeout_seconds: 30,
            duration_ms: 4,
            timed_out: false,
            stdout: String::new(),
            stderr: "version mismatch".to_string(),
            sandbox_denials: vec![SandboxDenialEvidence {
                boundary: crate::external_agent::SandboxDenialBoundary::InnerCodex,
                policy_id: "maco_external_codex_inner_v1".to_string(),
                operation: crate::external_agent::SandboxDeniedOperation::Write,
                path: Some(PathBuf::from(".maco/schema-test")),
                retryability: crate::external_agent::SandboxDenialRetryability::NotRetryable,
            }],
            environment_preflight_results: vec![EnvironmentPreflightResult {
                requirement,
                status: crate::external_agent::EnvironmentPreflightStatus::Blocked,
                observation: Some(
                    crate::external_agent::EnvironmentPreflightObservation::ExecutableVersion {
                        executable: crate::external_agent::EnvironmentExecutable::Cargo,
                        version: crate::external_agent::EnvironmentVersion::new(1, 89, 0),
                    },
                ),
            }],
            environment_failures: vec![failure.clone()],
            error: Some("representative failure".to_string()),
        };
        let validation_result = ValidationResult {
            name: "cargo check".to_string(),
            status: ReviewStatus::Failed,
            command: vec!["cargo".to_string(), "check".to_string()],
            message: Some("representative failure".to_string()),
        };
        let worker_report = WorkerReport {
            id: "worker-schema".to_string(),
            role: AgentRole::Worker,
            assignment_kind: AssignmentKind::Ordinary,
            target_path: None,
            assigned_paths: vec![PathBuf::from("src/lib.rs")],
            semantic_symbols: Vec::new(),
            semantic_modules: Vec::new(),
            claim_token: Some(1),
            semantic_intent_token: Some(2),
            commands_run: vec![command_record.clone()],
            environment_failures: vec![failure.clone()],
            files_changed: Vec::new(),
            validation_results: vec![validation_result.clone()],
            findings: Vec::new(),
            field_guide_entries: Vec::new(),
            bloated_file_flags: Vec::new(),
            decomposition_completion: None,
            no_further_delegation: Some(true),
            accepted: false,
            rejected: true,
            status: ReviewStatus::Failed,
            remaining_risk: "representative risk".to_string(),
            next_safe_action: "correct the environment".to_string(),
        };
        let auditor_report = AuditorReport {
            id: "auditor-schema".to_string(),
            role: AgentRole::Auditor,
            reviewed_worker_ids: vec![worker_report.id.clone()],
            reviewed_paths: worker_report.assigned_paths.clone(),
            commands_run: vec![command_record],
            environment_failures: vec![failure],
            validation_results: vec![validation_result],
            findings: Vec::new(),
            rejection_kind: Some(AuditorRejectionKind::EvidenceQuality),
            no_further_delegation: Some(true),
            read_only: true,
            accepted: false,
            rejected: true,
            status: ReviewStatus::Failed,
            remaining_risk: "representative risk".to_string(),
            next_safe_action: "correct the evidence".to_string(),
        };
        let serialized_worker = serde_json::to_value(&worker_report)?;
        let serialized_auditor = serde_json::to_value(&auditor_report)?;
        let worker_response = codex_response_format_schema(worker_report_schema_value())?;
        assert_serialized_keys_are_required(&serialized_worker, worker);
        assert_serialized_keys_are_required(&serialized_auditor, &auditor);
        assert_serialized_keys_are_required(&serialized_worker["commands_run"][0], command);
        assert!(schema_accepts_instance(
            &worker_response,
            &serialized_worker
        ));
        assert!(schema_accepts_instance(&auditor, &serialized_auditor));
        let _: WorkerReport = serde_json::from_value(serialized_worker.clone())?;
        let _: AuditorReport = serde_json::from_value(serialized_auditor)?;

        let mut explicit_null_worker = serialized_worker.clone();
        explicit_null_worker["commands_run"][0]["sandbox_denials"][0]["boundary"] =
            json!("outer_systemd");
        explicit_null_worker["commands_run"][0]["sandbox_denials"][0]["policy_id"] =
            json!("maco_external_codex_outer_systemd_v1");
        explicit_null_worker["commands_run"][0]["sandbox_denials"][0]["operation"] =
            json!("establish_boundary");
        explicit_null_worker["commands_run"][0]["sandbox_denials"][0]["path"] = json!(null);
        explicit_null_worker["commands_run"][0]["environment_preflight_results"][0]
            ["observation"] = json!(null);
        explicit_null_worker["commands_run"][0]["environment_failures"][0]["requirement"] =
            json!(null);
        explicit_null_worker["validation_results"][0]["message"] = json!(null);
        assert!(schema_accepts_instance(
            &worker_response,
            &explicit_null_worker
        ));
        let _: WorkerReport = serde_json::from_value(explicit_null_worker)?;

        for (field, replacement) in [("sandbox_denials", json!(null)), ("stdout", json!(null))] {
            let mut invalid = serialized_worker.clone();
            invalid["commands_run"][0][field] = replacement;
            assert!(!schema_accepts_instance(&worker_response, &invalid));
            assert!(serde_json::from_value::<WorkerReport>(invalid).is_err());
        }
        let mut invalid_validation_command = serialized_worker;
        invalid_validation_command["validation_results"][0]["command"] = json!(null);
        assert!(!schema_accepts_instance(
            &worker_response,
            &invalid_validation_command
        ));
        assert!(serde_json::from_value::<WorkerReport>(invalid_validation_command).is_err());
        Ok(())
    }

    #[test]
    fn selection_event_schema_is_authoritative_for_dynamic_and_tracked_artifacts() -> Result<()> {
        let dynamic = selection_decisions_schema_value();
        let event = &dynamic["items"];
        assert_eq!(event["additionalProperties"], false);
        assert!(required_contains(event, "assignment_id"));
        assert!(required_contains(event, "primary_cause"));
        let decision = &event["properties"]["provenance"];
        assert_eq!(decision["additionalProperties"], false);
        assert!(required_contains(decision, "normalized_input"));
        let normalized_input = &decision["properties"]["normalized_input"];
        assert_eq!(normalized_input["additionalProperties"], false);
        assert!(required_contains(normalized_input, "catalogs"));
        assert_eq!(
            normalized_input["properties"]["catalogs"]["items"]["additionalProperties"],
            false
        );

        let digests = &decision["properties"]["input_digests"];
        assert_eq!(digests["additionalProperties"], false);
        assert!(required_contains(digests, "normalized_input"));
        let digest = &digests["properties"]["normalized_input"];
        assert_eq!(digest["additionalProperties"], false);
        assert!(required_contains(digest, "algorithm"));
        assert!(required_contains(digest, "value"));

        let candidate = &decision["properties"]["candidate_set"]["items"];
        assert_eq!(candidate["additionalProperties"], false);
        assert!(required_contains(candidate, "score"));
        let score = &candidate["properties"]["score"]["oneOf"][0];
        assert_eq!(score["additionalProperties"], false);
        assert!(required_contains(score, "total_score_microunits"));

        let tracked: serde_json::Value = serde_json::from_str(include_str!(
            "../../schemas/supervisor-final-report-v1.schema.json"
        ))?;
        let tracked_execution =
            &tracked["properties"]["role_economics_profile"]["properties"]["execution"];
        let tracked_event = &tracked_execution["properties"]["selection_decisions"]["items"];
        assert_eq!(tracked_event, event);
        assert!(required_contains(
            tracked_execution,
            "assignment_selection_ledger"
        ));
        assert!(required_contains(
            &supervisor_final_report_schema_value()["properties"]["role_economics_profile"]
                ["properties"]["execution"],
            "assignment_selection_ledger"
        ));
        Ok(())
    }

    #[test]
    fn generated_complete_contracts_match_tracked_schemas() -> Result<()> {
        let tracked: serde_json::Value = serde_json::from_str(include_str!(
            "../../schemas/supervisor-final-report-v1.schema.json"
        ))?;
        let tracked_collect: serde_json::Value = serde_json::from_str(include_str!(
            "../../schemas/supervisor-collect-report-v1.schema.json"
        ))?;
        assert_eq!(tracked, supervisor_final_report_schema_value());
        assert_eq!(tracked_collect, supervisor_collect_report_schema_value());
        Ok(())
    }

    #[test]
    fn reachable_runtime_schema_is_synchronized_across_generated_and_published_contracts(
    ) -> Result<()> {
        let runtime_schema = supervisor_runtime_schema_value();
        let generated = supervisor_final_report_schema_value();
        let admission = worktree_writable_admission_schema_value();
        let tracked: serde_json::Value = serde_json::from_str(include_str!(
            "../../schemas/supervisor-final-report-v1.schema.json"
        ))?;

        assert_eq!(generated["properties"]["runtime"], runtime_schema);
        assert_eq!(
            admission["properties"]["native_sandbox"]["properties"]["runtime"],
            runtime_schema
        );
        assert_eq!(tracked["properties"]["runtime"], runtime_schema);
        assert_eq!(
            tracked["properties"]["role_economics_profile"]["properties"]
                ["resolved_objective_profile"],
            generated["properties"]["role_economics_profile"]["properties"]
                ["resolved_objective_profile"]
        );
        assert_eq!(
            runtime_schema["enum"],
            json!(REACHABLE_SUPERVISOR_RUNTIMES.map(SupervisorRuntime::as_str))
        );
        Ok(())
    }

    #[test]
    fn degradation_and_ledger_source_schemas_match_tracked_artifact_exactly() -> Result<()> {
        let dynamic = supervisor_final_report_schema_value();
        let dynamic_execution =
            &dynamic["properties"]["role_economics_profile"]["properties"]["execution"];
        let tracked: serde_json::Value = serde_json::from_str(include_str!(
            "../../schemas/supervisor-final-report-v1.schema.json"
        ))?;
        let tracked_execution =
            &tracked["properties"]["role_economics_profile"]["properties"]["execution"];
        assert_eq!(tracked_execution, dynamic_execution);
        Ok(())
    }
}
