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
        "properties": {
            "gate_denials": {
                "type": "array",
                "items": gate_denial_schema_value()
            },
            "gate_correction_outcomes": {
                "type": "array",
                "items": gate_correction_outcome_schema_value()
            },
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
            }
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
                    "probe_failed"
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

pub(super) fn write_final_report(
    writer: &mut ArtifactRunWriter,
    report: &SupervisorFinalReport,
) -> Result<()> {
    let mut normalized_report = report.clone();
    enforce_supervisor_final_environment_failure_outcome(&mut normalized_report);
    write_artifact_json(
        writer,
        &RunArtifactFamily::Supervise.final_report_relative_path(),
        &normalized_report,
        MAX_SUPERVISOR_REPORT_BYTES,
        ArtifactFileDisposition::PrivateEvidence,
    )
    .context("failed to write normalized supervisor final report")
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
