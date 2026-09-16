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

#[test]
fn supervisor_catalog_intent_admits_logical_codex_without_trusted_resolution() {
    let grant = SupervisorCatalogCodexPreflightGrant::admit_from_supervisor_catalog_intent(
        "logical-spelling-only",
        Path::new("."),
        Path::new("codex"),
    )
    .expect("logical codex spelling must admit at issuer");
    assert_eq!(grant.origin(), CatalogPreflightOrigin::Supervisor);
    assert!(grant.independently_verified_canonical_program().is_none());
}

#[cfg(target_os = "linux")]
mod linux_catalog_preflight {
    use super::*;
    use crate::external_agent::{
        codex_runtime_model_catalog_process_launch_attempts_for_test,
        reset_codex_runtime_model_catalog_process_launch_attempts_for_test,
        set_injected_trusted_codex_executable_for_test,
        supervisor_catalog_preflight_refuse_sealed_executable_resolution_drift,
        EnvironmentFailureCategory,
    };
    use crate::mutation_taxonomy::{
        CatalogPreflightOrigin, SupervisorCatalogCodexPreflightGrantError,
    };
    use std::os::unix::fs::PermissionsExt;

    struct InjectedCodexResolution {
        _path: PathBuf,
    }

    impl InjectedCodexResolution {
        fn install(path: PathBuf) -> Self {
            set_injected_trusted_codex_executable_for_test(Some(path.clone()));
            Self { _path: path }
        }
    }

    impl Drop for InjectedCodexResolution {
        fn drop(&mut self) {
            set_injected_trusted_codex_executable_for_test(None);
        }
    }

    fn write_injected_codex_fixture(dir: &Path, name: &str) -> PathBuf {
        let path = dir.join(name);
        std::fs::write(&path, "#!/bin/sh\nexit 0\n").expect("write fixture executable");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))
            .expect("chmod fixture executable");
        path
    }

    #[test]
    fn production_catalog_admit_seals_independently_verified_canonical_executable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let trusted = write_injected_codex_fixture(temp.path(), "trusted-codex");
        let _inject = InjectedCodexResolution::install(trusted.clone());
        let canonical = std::fs::canonicalize(&trusted).expect("canonicalize trusted fixture");
        let options = catalog_options(
            SupervisorRuntime::Codex,
            canonical.to_str().expect("utf8 canonical path"),
        );
        let grant = admit_production_supervisor_catalog_preflight_grant(&options, temp.path())
            .expect("admit must succeed for matching explicit trusted executable")
            .expect("Codex runtime must mint a catalog grant");
        assert_eq!(
            grant.independently_verified_canonical_program(),
            Some(canonical.as_path())
        );
        supervisor_catalog_preflight_refuse_sealed_executable_resolution_drift(&grant, temp.path())
            .expect("fresh trusted resolution must still match sealed canonical");
    }

    #[test]
    fn production_catalog_refuses_different_explicit_executable_before_sealed_grant() {
        let temp = tempfile::tempdir().expect("tempdir");
        let trusted = write_injected_codex_fixture(temp.path(), "trusted-codex");
        let other = write_injected_codex_fixture(temp.path(), "other-codex");
        let _inject = InjectedCodexResolution::install(trusted);
        let options = catalog_options(
            SupervisorRuntime::Codex,
            other.to_str().expect("utf8 other path"),
        );
        let failure = admit_production_supervisor_catalog_preflight_grant(&options, temp.path())
            .expect_err("different explicit executable must fail before sealed grant");
        assert_eq!(
            failure.category,
            EnvironmentFailureCategory::RuntimeModelCatalogUnavailable
        );
        assert!(
            failure
                .summary
                .contains("cause=untrusted_custom_executable"),
            "must refuse custom explicit executable: {}",
            failure.summary
        );
    }

    #[test]
    fn production_catalog_for_supervisor_refuses_resolution_drift_before_catalog_launch() {
        let temp = tempfile::tempdir().expect("tempdir");
        let first = write_injected_codex_fixture(temp.path(), "trusted-a");
        let second = write_injected_codex_fixture(temp.path(), "trusted-b");
        let _inject = InjectedCodexResolution::install(first.clone());
        let canonical_a = std::fs::canonicalize(&first).expect("canonicalize a");
        let options = catalog_options(
            SupervisorRuntime::Codex,
            canonical_a.to_str().expect("utf8 path"),
        );
        let grant = admit_production_supervisor_catalog_preflight_grant(&options, temp.path())
            .expect("admit")
            .expect("grant");
        set_injected_trusted_codex_executable_for_test(Some(second));
        reset_codex_runtime_model_catalog_process_launch_attempts_for_test();
        let launches_before = codex_runtime_model_catalog_process_launch_attempts_for_test();
        let failure = RuntimeModelCatalog::for_supervisor(&options, temp.path(), Some(grant))
            .expect_err("production catalog entry must refuse sealed-vs-fresh drift");
        assert_eq!(
            failure.category,
            EnvironmentFailureCategory::RuntimeModelCatalogUnavailable
        );
        assert!(
            failure
                .summary
                .contains("cause=catalog_preflight_grant_mismatch"),
            "drift must fail in prepare before auth/process: {}",
            failure.summary
        );
        assert_eq!(
            codex_runtime_model_catalog_process_launch_attempts_for_test(),
            launches_before,
            "catalog process must not launch on drift refusal"
        );
    }

    #[test]
    fn production_catalog_logical_codex_spelling_seals_trusted_resolution() {
        let temp = tempfile::tempdir().expect("tempdir");
        let trusted = write_injected_codex_fixture(temp.path(), "logical-codex");
        let _inject = InjectedCodexResolution::install(trusted.clone());
        let canonical = std::fs::canonicalize(&trusted).expect("canonicalize");
        let options = catalog_options(SupervisorRuntime::Codex, "codex");
        let grant = admit_production_supervisor_catalog_preflight_grant(&options, temp.path())
            .expect("logical codex spelling must admit")
            .expect("grant");
        assert_eq!(
            grant.independently_verified_canonical_program(),
            Some(canonical.as_path())
        );
    }

    #[test]
    fn production_catalog_accepts_symlink_canonical_alias_of_trusted_executable() {
        let temp = tempfile::tempdir().expect("tempdir");
        let trusted = write_injected_codex_fixture(temp.path(), "trusted-codex");
        let symlink = temp.path().join("trusted-codex-symlink");
        std::os::unix::fs::symlink(&trusted, &symlink).expect("symlink alias");
        let _inject = InjectedCodexResolution::install(trusted.clone());
        let trusted_canonical = std::fs::canonicalize(&trusted).expect("canonicalize trusted");
        let alias_canonical = std::fs::canonicalize(&symlink).expect("canonicalize symlink");
        assert_eq!(alias_canonical, trusted_canonical);
        let options = catalog_options(
            SupervisorRuntime::Codex,
            symlink.to_str().expect("utf8 symlink path"),
        );
        let grant = admit_production_supervisor_catalog_preflight_grant(&options, temp.path())
            .expect("symlink alias with matching canonical path must admit")
            .expect("grant");
        assert_eq!(
            grant.independently_verified_canonical_program(),
            Some(trusted_canonical.as_path())
        );
    }

    #[test]
    fn production_catalog_refuses_distinct_hard_link_path_under_exact_path_contract() {
        let temp = tempfile::tempdir().expect("tempdir");
        let trusted = write_injected_codex_fixture(temp.path(), "trusted-codex");
        let hard_link = temp.path().join("trusted-codex-hardlink");
        std::fs::hard_link(&trusted, &hard_link).expect("hard link");
        let _inject = InjectedCodexResolution::install(trusted.clone());
        let trusted_canonical = std::fs::canonicalize(&trusted).expect("canonicalize trusted");
        let link_canonical = std::fs::canonicalize(&hard_link).expect("canonicalize hard link");
        assert_ne!(link_canonical, trusted_canonical);
        let options = catalog_options(
            SupervisorRuntime::Codex,
            hard_link.to_str().expect("utf8 hard link path"),
        );
        let failure = admit_production_supervisor_catalog_preflight_grant(&options, temp.path())
            .expect_err("distinct hard-link path must not satisfy exact-path binding");
        assert!(
            failure
                .summary
                .contains("cause=untrusted_custom_executable"),
            "hard link path must be refused: {}",
            failure.summary
        );
    }

    #[test]
    fn production_catalog_sealed_grant_remains_single_use_with_supervisor_origin() {
        use crate::process_runner::{ProcessCommand, ProcessSpec};

        let temp = tempfile::tempdir().expect("tempdir");
        let trusted = write_injected_codex_fixture(temp.path(), "trusted-codex");
        let _inject = InjectedCodexResolution::install(trusted.clone());
        let canonical = std::fs::canonicalize(&trusted).expect("canonicalize");
        let parent = canonical.parent().expect("parent");
        let options = catalog_options(
            SupervisorRuntime::Codex,
            canonical.to_str().expect("utf8 path"),
        );
        let grant = admit_production_supervisor_catalog_preflight_grant(&options, temp.path())
            .expect("admit")
            .expect("grant");
        assert_eq!(grant.origin(), CatalogPreflightOrigin::Supervisor);
        let spec = ProcessSpec::direct(
            "catalog preflight binding",
            &canonical,
            ["debug", "models"],
            parent,
            64,
        );
        let ProcessCommand::Direct {
            program: spec_program,
            args: spec_argv,
        } = &spec.command
        else {
            panic!("direct catalog spec must remain a direct command");
        };
        grant
            .clone()
            .consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Supervisor,
            )
            .expect("consume once");
        assert_eq!(
            grant.consume_for_process_binding(
                spec_program,
                &spec.current_dir,
                spec_argv,
                CatalogPreflightOrigin::Supervisor,
            ),
            Err(SupervisorCatalogCodexPreflightGrantError::AlreadyConsumed)
        );
    }
}
