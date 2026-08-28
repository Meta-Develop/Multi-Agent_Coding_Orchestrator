//! Integration fixtures for the secret-lifecycle contract (#336).
//!
//! Placeholder material only. These tests prove a child scope cannot observe
//! an undeclated secret, and that reports, artifacts, errors, and debug
//! formatting remain free of raw material across serde round-trips.

use multi_agent_coding_orchestrator::secret_lifecycle::{
    PersistencePolicy, SecretDeclaration, SecretLifecycleError, SecretLifecycleReport,
    SecretPlanBinding, SecretRef, SecretScope, SecretState, SecretVault, SECRET_LIFECYCLE_VERSION,
};
use serde_json::json;
use std::collections::BTreeMap;

const PLACEHOLDER: &str = "placeholder.lifecycle.test-value.v1";
const PLACEHOLDER_ROTATED: &str = "placeholder.lifecycle.test-value.v2";
const ENV_KEY: &str = "MACO_PLACEHOLDER_TOKEN";

fn parent_scope() -> SecretScope {
    SecretScope::try_new(
        Some("assign-parent".to_string()),
        Some("worktree-a".to_string()),
        Some("runtime-codex".to_string()),
    )
    .expect("parent scope")
}

fn child_scope() -> SecretScope {
    SecretScope::try_new(
        Some("assign-child".to_string()),
        Some("worktree-b".to_string()),
        Some("runtime-codex".to_string()),
    )
    .expect("child scope")
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

fn declared_vault() -> (SecretVault, SecretRef) {
    let mut vault = SecretVault::at_unix_ms(10_000);
    let declaration = SecretDeclaration::new("forge.placeholder.token", ENV_KEY, parent_scope())
        .expect("declaration");
    let reference = vault.declare(declaration).expect("declare");
    vault.bind_material(&reference, PLACEHOLDER).expect("bind");
    (vault, reference)
}

#[test]
fn child_process_environment_cannot_observe_undelegated_secret() {
    let (mut vault, reference) = declared_vault();

    let parent_lease = vault
        .inject(&reference, &parent_scope())
        .expect("parent lease");
    assert!(parent_lease.material_eq(PLACEHOLDER));
    let mut parent_env = BTreeMap::new();
    parent_lease
        .apply_to(&mut parent_env)
        .expect("apply parent env");
    assert_eq!(
        parent_env.get(ENV_KEY).map(String::as_str),
        Some(PLACEHOLDER)
    );
    assert_no_placeholder(&format!("{parent_lease:?}"));

    let child_denied = vault
        .inject(&reference, &child_scope())
        .expect_err("child must not receive material");
    assert!(matches!(
        child_denied,
        SecretLifecycleError::NotDelegated { .. }
    ));
    let child_env = vault
        .inject_environment(&child_scope())
        .expect("child environment");
    assert!(
        child_env.is_empty(),
        "undelegated child env must not contain keys"
    );
    assert!(!child_env.contains_key(ENV_KEY));

    // A child execution boundary receives only `child_env`. Serializing that
    // map as an artifact must not reveal the placeholder.
    let child_artifact = serde_json::to_string(&child_env).expect("child env artifact");
    assert_no_placeholder(&child_artifact);
    assert_no_placeholder(&format!("{child_env:?}"));
}

#[test]
fn delegated_child_receives_material_but_artifacts_do_not() {
    let (mut vault, reference) = declared_vault();
    vault
        .delegate(&reference, child_scope())
        .expect("delegate child");

    let child_env = vault
        .inject_environment(&child_scope())
        .expect("delegated child environment");
    assert!(child_env.material_eq(ENV_KEY, PLACEHOLDER));
    assert_no_placeholder(&format!("{child_env:?}"));
    let child_artifact = serde_json::to_string(&child_env).expect("delegated child artifact");
    assert_no_placeholder(&child_artifact);
    assert!(child_artifact.contains("<redacted:secret-env>"));

    let lease = vault
        .inject(&reference, &child_scope())
        .expect("delegated child lease");
    assert!(lease.material_eq(PLACEHOLDER));
    assert_no_placeholder(&serde_json::to_string(&lease).expect("lease artifact"));

    let report = vault.report().expect("report");
    assert_no_placeholder(&serde_json::to_string(&report).expect("report json"));
    assert_eq!(report.secrets[0].delegated_scopes, vec![child_scope()]);
}

#[test]
fn reports_events_and_error_paths_round_trip_without_raw_material() {
    let (mut vault, reference) = declared_vault();
    vault
        .rotate_material(&reference, PLACEHOLDER_ROTATED)
        .expect("rotate");

    let bindings = vault.plan_bindings();
    let plan_json = serde_json::to_string_pretty(&bindings).expect("plan json");
    assert_no_placeholder(&plan_json);
    let restored_plan: Vec<SecretPlanBinding> =
        serde_json::from_str(&plan_json).expect("plan round-trip");
    assert_eq!(restored_plan, bindings);
    assert_eq!(
        restored_plan[0].persistence,
        PersistencePolicy::ReferenceOnly
    );

    let report = vault.report().expect("report");
    let report_json = serde_json::to_string_pretty(&report).expect("report json");
    assert_no_placeholder(&report_json);
    let restored_report: SecretLifecycleReport =
        serde_json::from_str(&report_json).expect("report round-trip");
    assert_eq!(restored_report.version, SECRET_LIFECYCLE_VERSION);
    assert_eq!(restored_report.secrets[0].state, SecretState::Bound);
    assert_eq!(restored_report, report);

    let error = SecretLifecycleError::Destroyed {
        name: "forge.placeholder.token".to_string(),
    };
    let error_display = format!("{error}");
    let error_debug = format!("{error:?}");
    let error_json = serde_json::to_string(&error).expect("error json");
    assert_no_placeholder(&error_display);
    assert_no_placeholder(&error_debug);
    assert_no_placeholder(&error_json);
    let restored_error: SecretLifecycleError =
        serde_json::from_str(&error_json).expect("error round-trip");
    assert_eq!(restored_error, error);

    let journal = json!({
        "event": "assignment-complete",
        "notes": format!("token leak {PLACEHOLDER} {PLACEHOLDER_ROTATED}"),
    });
    let redacted = vault.redact_json(&journal).expect("redact journal");
    let redacted_json = serde_json::to_string(&redacted).expect("redacted journal");
    assert_no_placeholder(&redacted_json);

    vault.destroy_all().expect("destroy");
    let after = vault.report().expect("post-destroy report");
    assert_eq!(after.secrets[0].state, SecretState::Destroyed);
    assert_no_placeholder(&serde_json::to_string(&after).expect("post-destroy json"));
}

#[test]
fn fixture_plan_binding_rejects_unknown_fields_and_has_no_material_slot() {
    let fixture = r#"{
        "reference": {"name": "forge.placeholder.token", "generation": 1},
        "env_key": "MACO_PLACEHOLDER_TOKEN",
        "scope": {"assignment_id": "assign-parent"},
        "persistence": "reference_only",
        "delegation": "explicit_scopes",
        "material": "placeholder.lifecycle.test-value.v1"
    }"#;
    let error = serde_json::from_str::<SecretPlanBinding>(fixture)
        .expect_err("material field must be rejected");
    assert!(error.to_string().contains("unknown field"));

    let valid = r#"{
        "reference": {"name": "forge.placeholder.token", "generation": 1},
        "env_key": "MACO_PLACEHOLDER_TOKEN",
        "scope": {"assignment_id": "assign-parent"},
        "persistence": "reference_only",
        "delegation": "explicit_scopes"
    }"#;
    let binding: SecretPlanBinding = serde_json::from_str(valid).expect("valid fixture");
    let encoded = serde_json::to_string(&binding).expect("encode");
    assert_no_placeholder(&encoded);
    assert!(!encoded.contains("material"));
}
