use super::types::MAX_SECRETS;
use super::*;
use serde_json::json;

const PLACEHOLDER: &str = "placeholder.lifecycle.test-value.v1";
const PLACEHOLDER_ROTATED: &str = "placeholder.lifecycle.test-value.v2";
const ENV_KEY: &str = "MACO_PLACEHOLDER_TOKEN";

fn parent_scope() -> SecretScope {
    SecretScope::try_new(
        Some("assign-parent".to_string()),
        Some("worktree-parent".to_string()),
        Some("runtime-codex".to_string()),
    )
    .expect("parent scope")
}

fn child_scope() -> SecretScope {
    SecretScope::try_new(
        Some("assign-child".to_string()),
        Some("worktree-child".to_string()),
        Some("runtime-codex".to_string()),
    )
    .expect("child scope")
}

fn sibling_scope() -> SecretScope {
    SecretScope::assignment("assign-sibling").expect("sibling scope")
}

fn bound_vault() -> (SecretVault, SecretRef) {
    let mut vault = SecretVault::at_unix_ms(1_000);
    let declaration = SecretDeclaration::new("forge.placeholder.token", ENV_KEY, parent_scope())
        .expect("declaration")
        .with_expiry(5_000);
    let reference = vault.declare(declaration).expect("declare");
    vault
        .bind_material(&reference, PLACEHOLDER)
        .expect("bind placeholder");
    (vault, reference)
}

fn assert_no_placeholder(haystack: &str) {
    assert!(
        !haystack.contains(PLACEHOLDER),
        "raw placeholder leaked: {haystack}"
    );
    assert!(
        !haystack.contains(PLACEHOLDER_ROTATED),
        "rotated placeholder leaked: {haystack}"
    );
}

#[test]
fn empty_scope_fails_closed() {
    let error = SecretScope::try_new(None, None, None).expect_err("empty scope");
    assert_eq!(error, SecretLifecycleError::Unscoped);
}

#[test]
fn plans_and_reports_round_trip_without_raw_material() {
    let (mut vault, reference) = bound_vault();
    let bindings = vault.plan_bindings();
    assert_eq!(bindings.len(), 1);
    assert_eq!(bindings[0].reference, reference);
    assert_eq!(bindings[0].env_key, ENV_KEY);
    assert_eq!(bindings[0].persistence, PersistencePolicy::ReferenceOnly);

    let encoded = serde_json::to_string(&bindings).expect("encode plan");
    assert_no_placeholder(&encoded);
    let decoded: Vec<SecretPlanBinding> = serde_json::from_str(&encoded).expect("decode plan");
    assert_eq!(decoded, bindings);

    let report = vault.report().expect("report");
    let report_json = serde_json::to_string(&report).expect("encode report");
    assert_no_placeholder(&report_json);
    let restored: SecretLifecycleReport =
        serde_json::from_str(&report_json).expect("decode report");
    assert_eq!(restored.version, SECRET_LIFECYCLE_VERSION);
    assert_eq!(restored.secrets[0].state, SecretState::Bound);
    assert_eq!(restored, report);
}

#[test]
fn child_cannot_observe_undelegated_secret() {
    let (mut vault, reference) = bound_vault();
    let parent_lease = vault
        .inject(&reference, &parent_scope())
        .expect("parent inject");
    assert!(parent_lease.material_eq(PLACEHOLDER));

    let denied = vault
        .inject(&reference, &child_scope())
        .expect_err("child must not inject");
    assert_eq!(
        denied,
        SecretLifecycleError::NotDelegated {
            name: "forge.placeholder.token".to_string(),
        }
    );

    let sibling_env = vault
        .inject_environment(&sibling_scope())
        .expect("sibling env");
    assert!(sibling_env.is_empty());
    assert!(!sibling_env.contains_key(ENV_KEY));

    vault
        .delegate(&reference, child_scope())
        .expect("delegate child");
    let child_lease = vault
        .inject(&reference, &child_scope())
        .expect("delegated child inject");
    assert!(child_lease.material_eq(PLACEHOLDER));
}

#[test]
fn forbidden_delegation_fails_closed() {
    let mut vault = SecretVault::at_unix_ms(1_000);
    let declaration = SecretDeclaration::new("forge.placeholder.token", ENV_KEY, parent_scope())
        .expect("declaration")
        .with_delegation(DelegationPolicy::Forbidden);
    let reference = vault.declare(declaration).expect("declare");
    vault.bind_material(&reference, PLACEHOLDER).expect("bind");
    let error = vault
        .delegate(&reference, child_scope())
        .expect_err("forbidden");
    assert_eq!(
        error,
        SecretLifecycleError::DelegationForbidden {
            name: "forge.placeholder.token".to_string(),
        }
    );
}

#[test]
fn expiry_revocation_rotation_and_destruction_are_fail_closed() {
    let (mut vault, reference) = bound_vault();
    vault.set_unix_ms(5_000);
    let expired = vault
        .inject(&reference, &parent_scope())
        .expect_err("expired");
    assert_eq!(
        expired,
        SecretLifecycleError::Expired {
            name: "forge.placeholder.token".to_string(),
        }
    );

    let (mut vault, reference) = bound_vault();
    vault.revoke(&reference).expect("revoke");
    let revoked = vault
        .inject(&reference, &parent_scope())
        .expect_err("revoked");
    assert_eq!(
        revoked,
        SecretLifecycleError::Revoked {
            name: "forge.placeholder.token".to_string(),
        }
    );

    let (mut vault, reference) = bound_vault();
    let rotated = vault
        .rotate_material(&reference, PLACEHOLDER_ROTATED)
        .expect("rotate");
    assert_eq!(rotated.generation(), 2);
    let stale = vault
        .inject(&reference, &parent_scope())
        .expect_err("stale generation");
    assert_eq!(
        stale,
        SecretLifecycleError::StaleGeneration {
            name: "forge.placeholder.token".to_string(),
            generation: 1,
        }
    );
    let lease = vault
        .inject(&rotated, &parent_scope())
        .expect("new generation");
    assert!(lease.material_eq(PLACEHOLDER_ROTATED));
    assert!(!lease.material_eq(PLACEHOLDER));

    vault.destroy(&rotated).expect("destroy");
    let destroyed = vault
        .inject(&rotated, &parent_scope())
        .expect_err("destroyed");
    assert_eq!(
        destroyed,
        SecretLifecycleError::Destroyed {
            name: "forge.placeholder.token".to_string(),
        }
    );
}

#[test]
fn artifacts_logs_errors_and_debug_cannot_carry_raw_material() {
    let (mut vault, reference) = bound_vault();
    let leaked = json!({
        "journal": format!("binding token={PLACEHOLDER}"),
        "error_path": format!("{PLACEHOLDER} in Display"),
        "nested": { "note": PLACEHOLDER },
    });
    let redacted = vault.redact_json(&leaked).expect("redact json");
    let redacted_text = serde_json::to_string(&redacted).expect("encode redacted json");
    assert_no_placeholder(&redacted_text);
    assert!(redacted_text.contains("<redacted:forge.placeholder.token>"));

    let text = vault
        .redact_text(&format!("log line with {PLACEHOLDER}"))
        .expect("redact text");
    assert_no_placeholder(&text.text);
    assert_eq!(text.summary.total_replacements, 1);

    let denied = vault
        .inject(&reference, &child_scope())
        .expect_err("child denied");
    let display = format!("{denied}");
    let debug = format!("{denied:?}");
    let encoded = serde_json::to_string(&denied).expect("encode error");
    assert_no_placeholder(&display);
    assert_no_placeholder(&debug);
    assert_no_placeholder(&encoded);

    let vault_debug = format!("{vault:?}");
    assert_no_placeholder(&vault_debug);

    let lease = vault
        .inject(&reference, &parent_scope())
        .expect("parent lease");
    let lease_debug = format!("{lease:?}");
    let lease_json = serde_json::to_string(&lease).expect("lease json");
    assert_no_placeholder(&lease_debug);
    assert_no_placeholder(&lease_json);
    assert!(lease_json.contains("<redacted:secret-lease>"));

    let env = vault
        .inject_environment(&parent_scope())
        .expect("parent env");
    let env_debug = format!("{env:?}");
    let env_json = serde_json::to_string(&env).expect("env json");
    assert_no_placeholder(&env_debug);
    assert_no_placeholder(&env_json);
    assert!(env.material_eq(ENV_KEY, PLACEHOLDER));
    assert!(env_json.contains("<redacted:secret-env>"));

    let redactor = vault.redactor().expect("redactor");
    let redactor_debug = format!("{redactor:?}");
    assert_no_placeholder(&redactor_debug);
}

#[test]
fn rotation_then_report_then_finish_leaves_no_raw_material() {
    let (mut vault, reference) = bound_vault();
    let rotated = vault
        .rotate_material(&reference, PLACEHOLDER_ROTATED)
        .expect("rotate");
    let leak = format!("old={PLACEHOLDER} new={PLACEHOLDER_ROTATED}");
    let redacted = vault.redact_text(&leak).expect("redact both generations");
    assert_no_placeholder(&redacted.text);

    let report = vault.report().expect("report");
    let encoded = serde_json::to_string_pretty(&report).expect("pretty report");
    assert_no_placeholder(&encoded);
    let restored: SecretLifecycleReport = serde_json::from_str(&encoded).expect("round-trip");
    assert_eq!(restored.secrets[0].reference, rotated);
    assert!(restored
        .audit
        .events()
        .iter()
        .any(|event| event.action() == SecretAuditAction::Rotate));

    vault.finish().expect("finish");
    let finished = vault
        .inject(&rotated, &parent_scope())
        .expect_err("finished");
    assert_eq!(
        finished,
        SecretLifecycleError::Destroyed {
            name: "forge.placeholder.token".to_string(),
        }
    );
    let post = vault.report().expect("post-finish report");
    assert_no_placeholder(&serde_json::to_string(&post).expect("encode"));
}

#[test]
fn json_error_and_plan_fixtures_survive_serde_round_trip() {
    let fixture = json!({
        "reference": { "name": "forge.placeholder.token", "generation": 1 },
        "env_key": ENV_KEY,
        "scope": {
            "assignment_id": "assign-parent",
            "worktree_id": "worktree-parent",
            "runtime_id": "runtime-codex"
        },
        "persistence": "reference_only",
        "delegation": "explicit_scopes"
    });
    let binding: SecretPlanBinding =
        serde_json::from_value(fixture.clone()).expect("fixture binding");
    let encoded = serde_json::to_value(&binding).expect("re-encode");
    assert_eq!(encoded, fixture);

    let error = SecretLifecycleError::NotDelegated {
        name: "forge.placeholder.token".to_string(),
    };
    let error_json = serde_json::to_value(&error).expect("encode error fixture");
    let restored: SecretLifecycleError =
        serde_json::from_value(error_json.clone()).expect("decode error fixture");
    assert_eq!(restored, error);
    assert_no_placeholder(&error_json.to_string());
}

#[test]
fn audit_records_denied_child_access_without_material() {
    let (mut vault, reference) = bound_vault();
    let _ = vault.inject(&reference, &child_scope());
    let trail = vault.audit_trail();
    let denied = trail
        .events()
        .iter()
        .find(|event| {
            event.action() == SecretAuditAction::Inject
                && matches!(event.outcome(), SecretAuditOutcome::Denied { .. })
        })
        .expect("denied inject");
    let encoded = serde_json::to_string(denied).expect("encode audit event");
    assert_no_placeholder(&encoded);
    assert_eq!(denied.requester(), Some(&child_scope()));
}

#[test]
fn unscoped_and_invalid_names_fail_closed() {
    let error = SecretDeclaration::new("", ENV_KEY, parent_scope()).expect_err("empty name");
    match error {
        SecretLifecycleError::InvalidDeclaration { .. } => {}
        other => panic!("expected invalid declaration, got {other:?}"),
    }
    let error = SecretDeclaration::new("ok", "1BAD", parent_scope()).expect_err("bad env");
    match error {
        SecretLifecycleError::InvalidDeclaration { .. } => {}
        other => panic!("expected invalid env key, got {other:?}"),
    }
}

#[test]
fn inject_environment_only_contains_authorized_placeholder() {
    let (mut vault, _) = bound_vault();
    let parent_env = vault
        .inject_environment(&parent_scope())
        .expect("parent env");
    assert!(parent_env.material_eq(ENV_KEY, PLACEHOLDER));
    let child_env = vault.inject_environment(&child_scope()).expect("child env");
    assert!(child_env.is_empty());
    assert_no_placeholder(&format!("{child_env:?}"));
}

#[test]
fn already_declared_unknown_and_empty_material_fail_closed() {
    let (mut vault, reference) = bound_vault();
    let duplicate = SecretDeclaration::new("forge.placeholder.token", ENV_KEY, parent_scope())
        .expect("declaration");
    let error = vault.declare(duplicate).expect_err("duplicate");
    assert_eq!(
        error,
        SecretLifecycleError::AlreadyDeclared {
            name: "forge.placeholder.token".to_string(),
        }
    );

    let missing = SecretRef::new("missing.token", 1).expect("missing ref");
    let unknown = vault
        .inject(&missing, &parent_scope())
        .expect_err("unknown");
    assert_eq!(
        unknown,
        SecretLifecycleError::UnknownReference {
            name: "missing.token".to_string(),
            generation: 1,
        }
    );

    let empty = vault
        .bind_material(&reference, "")
        .expect_err("empty material");
    assert_eq!(
        empty,
        SecretLifecycleError::InvalidMaterial {
            reason: "empty".to_string(),
        }
    );
    assert_no_placeholder(&format!("{empty}"));
    assert_no_placeholder(&format!("{empty:?}"));
}

#[test]
fn vault_capacity_fails_closed() {
    let mut vault = SecretVault::at_unix_ms(1_000);
    for index in 0..MAX_SECRETS {
        let name = format!("cap.token.{index}");
        let declaration = SecretDeclaration::new(name, format!("MACO_CAP_{index}"), parent_scope())
            .expect("declaration");
        vault.declare(declaration).expect("declare within cap");
    }
    let overflow =
        SecretDeclaration::new("cap.token.overflow", "MACO_CAP_OVERFLOW", parent_scope())
            .expect("overflow declaration");
    assert_eq!(
        vault.declare(overflow).expect_err("capacity"),
        SecretLifecycleError::Capacity
    );
}
