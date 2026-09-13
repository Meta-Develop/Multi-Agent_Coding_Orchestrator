use super::*;
use crate::external_agent::EnvironmentFailureCategory;
use crate::mutation_taxonomy::{CatalogPreflightOrigin, SupervisorCatalogCodexPreflightGrant};

fn catalog_options(runtime: SupervisorRuntime, codex_bin: &str) -> SupervisorRunOptions {
    SupervisorRunOptions {
        repo: PathBuf::from("."),
        plan_file: PathBuf::from("plan.json"),
        run_id: RunId::new("catalog-preflight-admission").expect("valid run id"),
        parent_node: None,
        codex_bin: PathBuf::from(codex_bin),
        runtime,
        allow_dirty_primary: true,
        allow_live_run_collision: false,
        admission_overrides: SupervisorAdmissionConfig::default(),
        budget_overrides: RunBudgetLimits::default(),
        budget_max_duration_seconds: None,
        machine_global_retention: None,
    }
}

#[test]
fn for_supervisor_codex_without_grant_fails_closed_without_catalog_spawn() {
    let options = catalog_options(SupervisorRuntime::Codex, "codex");
    let failure = RuntimeModelCatalog::for_supervisor(&options, Path::new("."), None)
        .expect_err("missing grant must fail closed before catalog spawn");
    assert_eq!(
        failure.category,
        EnvironmentFailureCategory::RuntimeModelCatalogUnavailable
    );
    assert!(
        failure
            .summary
            .contains("cause=missing_catalog_preflight_grant"),
        "missing-grant failure must not fall through to unauthorized catalog spawn: {}",
        failure.summary
    );
}

#[test]
fn for_supervisor_fake_without_grant_keeps_local_deterministic_catalog() {
    let options = catalog_options(SupervisorRuntime::Fake, "codex");
    let catalog = RuntimeModelCatalog::for_supervisor(&options, Path::new("."), None)
        .expect("fake runtime must not require a catalog grant");
    assert_eq!(catalog, RuntimeModelCatalog::LocalDeterministicFake);
}

#[test]
fn for_supervisor_rejects_inbox_origin_grant_without_catalog_spawn() {
    let options = catalog_options(SupervisorRuntime::Codex, "codex");
    let grant = SupervisorCatalogCodexPreflightGrant::admit_from_inbox_catalog_intent(
        options.run_id.as_str(),
        Path::new("."),
        Path::new("codex"),
    )
    .expect("trusted Inbox origin spelling must admit");
    assert_eq!(grant.origin(), CatalogPreflightOrigin::Inbox);
    let failure = RuntimeModelCatalog::for_supervisor(&options, Path::new("."), Some(grant))
        .expect_err("Inbox origin must not bind for_supervisor");
    assert_eq!(
        failure.category,
        EnvironmentFailureCategory::RuntimeModelCatalogUnavailable
    );
    assert!(
        failure
            .summary
            .contains("cause=catalog_preflight_grant_origin_mismatch"),
        "cross-origin grant must fail closed before catalog spawn: {}",
        failure.summary
    );
}
