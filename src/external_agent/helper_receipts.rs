//! Host-owned catalog process observations; never restored as execution authority.

use super::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HelperProcessReceipt {
    pub program: PathBuf,
    pub process_tree: Option<ProcessTreeEvidence>,
    pub side_effects: Option<SideEffectConfinementEvidence>,
}

impl HelperProcessReceipt {
    pub(crate) fn capture(program: &Path, result: &Result<ProcessOutput, ProcessRunError>) -> Self {
        let rollback = result
            .as_ref()
            .err()
            .and_then(ProcessRunError::pre_release_rollback_evidence);
        let evidence = match (rollback, result) {
            (Some(evidence), _) => {
                // Match aggregate preflight evidence: errors or incomplete safety proof
                // must not become a quiescent helper receipt.
                let verified = evidence.process_tree.is_verified_empty()
                    && evidence.side_effects.is_verified()
                    && evidence.process_error.is_none()
                    && evidence.stdin_error.is_none();
                Some((
                    if verified {
                        evidence.process_tree
                    } else {
                        ProcessTreeEvidence::Unverified(ContainmentBackend::SystemdUserService)
                    },
                    evidence.side_effects,
                ))
            }
            (_, Ok(output)) => Some((output.process_tree, output.side_effects)),
            (_, Err(ProcessRunError::Wait { evidence, .. }))
            | (
                _,
                Err(ProcessRunError::Cancelled {
                    evidence: Some(evidence),
                    ..
                }),
            ) => Some((evidence.process_tree, evidence.side_effects)),
            _ => None,
        };
        Self {
            program: program.to_owned(),
            process_tree: evidence.map(|evidence| evidence.0),
            side_effects: evidence.map(|evidence| evidence.1),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("{error:#}")]
pub(super) struct ObservedCatalogFailure {
    #[source]
    pub error: anyhow::Error,
    pub receipt: HelperProcessReceipt,
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::process_runner::ProcessFailureEvidence;

    fn verified_rollback() -> ProcessFailureEvidence {
        ProcessFailureEvidence {
            stdout: CapturedBytes::default(),
            stderr: CapturedBytes::default(),
            process_tree: ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            ),
            side_effects: SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex,
            ),
            process_error: None,
            stdin_error: None,
        }
    }

    #[test]
    fn registration_rollback_receipt_survives_preflight_retention_but_not_serde() -> Result<()> {
        let result = Err(ProcessRunError::agent_registration_failed(
            "version preflight".into(),
            "codex --version".into(),
            "registration refused".into(),
            verified_rollback(),
        ));
        let receipt = HelperProcessReceipt::capture(Path::new("captured-codex"), &result);
        assert_eq!(receipt.program, Path::new("captured-codex"));
        assert_eq!(
            receipt.process_tree,
            Some(ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService
            ))
        );
        assert_eq!(
            receipt.side_effects,
            Some(SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex
            ))
        );

        let mut evidence = EnvironmentPreflightProcessEvidence::default();
        evidence.version_probe_receipts.push(receipt.clone());
        evidence.record_error(result.as_ref().unwrap_err());
        let command = ExternalAgentCommand::codex(
            "codex",
            ".",
            "prompt",
            "log",
            "output",
            Duration::from_secs(1),
        );
        let mut report = failed_external_environment_run(
            &command,
            Instant::now(),
            vec!["codex".into(), "--version".into()],
            false,
            EnvironmentFailureCategory::SandboxUnavailable,
            Some(EnvironmentRequirement::sandbox(
                EnvironmentSandboxCapability::VerifiedExternalCodex,
            )),
            "version preflight registration refused".into(),
        );
        retain_environment_preflight_process_evidence(&mut report, &evidence);
        // This is the accessor used by the native helper inventory writer.
        assert_eq!(report.version_probe_receipts(), &[receipt]);
        assert_eq!(report.process_tree, evidence.process_tree);
        assert_eq!(report.side_effects, evidence.side_effects);
        assert!(report.environment_preflight_quiescence_verified());
        assert!(!report.stdout.target_launch_attempted);
        assert!(!report.succeeded());

        report.process_tree = None;
        report.side_effects = None;
        assert!(report.environment_preflight_quiescence_verified());

        let restored: ExternalAgentRun = serde_json::from_slice(&serde_json::to_vec(&report)?)?;
        assert!(restored.version_probe_receipts().is_empty());
        assert!(!restored.environment_preflight_quiescence_verified());
        Ok(())
    }

    #[test]
    fn registration_rollback_receipt_requires_all_safety_evidence_without_errors() {
        for (case, evidence) in [
            (
                "process cleanup error",
                ProcessFailureEvidence {
                    process_error: Some("rollback cleanup failed".into()),
                    ..verified_rollback()
                },
            ),
            (
                "stdin error",
                ProcessFailureEvidence {
                    stdin_error: Some("stdin cleanup failed".into()),
                    ..verified_rollback()
                },
            ),
            (
                "unverified process tree",
                ProcessFailureEvidence {
                    process_tree: ProcessTreeEvidence::Unverified(
                        ContainmentBackend::SystemdUserService,
                    ),
                    ..verified_rollback()
                },
            ),
            (
                "best effort process tree",
                ProcessFailureEvidence {
                    process_tree: ProcessTreeEvidence::TrustedBestEffort(
                        ContainmentBackend::UnixProcessGroup,
                    ),
                    ..verified_rollback()
                },
            ),
            (
                "unverified side effects",
                ProcessFailureEvidence {
                    side_effects: SideEffectConfinementEvidence::Unverified(
                        SideEffectConfinementProfileKind::ExternalCodex,
                    ),
                    ..verified_rollback()
                },
            ),
            (
                "best effort side effects",
                ProcessFailureEvidence {
                    side_effects: SideEffectConfinementEvidence::TrustedBestEffort(
                        SideEffectConfinementProfileKind::TrustedCompatibility,
                    ),
                    ..verified_rollback()
                },
            ),
        ] {
            let result = Err(ProcessRunError::agent_registration_failed(
                "version preflight".into(),
                "codex --version".into(),
                "registration refused".into(),
                evidence,
            ));
            let receipt = HelperProcessReceipt::capture(Path::new("captured-codex"), &result);
            assert_eq!(
                receipt.process_tree,
                Some(ProcessTreeEvidence::Unverified(
                    ContainmentBackend::SystemdUserService
                )),
                "{case}"
            );
            assert!(receipt.side_effects.is_some(), "{case}");
            let mut aggregate = EnvironmentPreflightProcessEvidence::default();
            aggregate.record_error(result.as_ref().unwrap_err());
            assert_eq!(receipt.process_tree, aggregate.process_tree, "{case}");
            assert_eq!(receipt.side_effects, aggregate.side_effects, "{case}");
            assert!(aggregate.unconfirmed_child, "{case}");
        }
    }

    #[test]
    fn helper_receipt_does_not_infer_rollback_from_untyped_or_missing_evidence() {
        for error in [
            ProcessRunError::ProcessOwnership {
                label: "version preflight".into(),
                command: "codex --version".into(),
                source: std::io::Error::other(
                    "registration refused; cleanup verified empty; side effects verified",
                ),
            },
            ProcessRunError::IoSetup {
                label: "version preflight".into(),
                command: "codex --version".into(),
                source: std::io::Error::other("cleanup verified empty"),
            },
            ProcessRunError::Cancelled {
                label: "version preflight".into(),
                command: "codex --version".into(),
                phase: "before start",
                evidence: None,
            },
            ProcessRunError::ContainmentUnavailable {
                label: "version preflight".into(),
                command: "codex --version".into(),
                source: std::io::Error::other("unsupported containment"),
            },
        ] {
            let receipt = HelperProcessReceipt::capture(Path::new("captured-codex"), &Err(error));
            assert!(receipt.process_tree.is_none());
            assert!(receipt.side_effects.is_none());
        }
    }

    #[test]
    fn wait_and_cancelled_helper_receipts_keep_existing_evidence_semantics() {
        for cancelled in [false, true] {
            let evidence = Box::new(ProcessFailureEvidence {
                process_error: Some("wait or stdin diagnostic".into()),
                stdin_error: Some("stdin diagnostic".into()),
                ..verified_rollback()
            });
            let error = if cancelled {
                ProcessRunError::Cancelled {
                    label: "version preflight".into(),
                    command: "codex --version".into(),
                    phase: "wait",
                    evidence: Some(evidence),
                }
            } else {
                ProcessRunError::Wait {
                    label: "version preflight".into(),
                    command: "codex --version".into(),
                    evidence,
                    source: std::io::Error::other("wait failed"),
                }
            };
            let receipt = HelperProcessReceipt::capture(Path::new("captured-codex"), &Err(error));
            assert_eq!(receipt.process_tree, Some(verified_rollback().process_tree));
            assert_eq!(receipt.side_effects, Some(verified_rollback().side_effects));
        }
    }

    #[test]
    fn catalog_failure_keeps_its_cause_and_receipt_without_wire_authority() {
        let receipt = HelperProcessReceipt {
            program: PathBuf::from("captured-codex"),
            process_tree: Some(ProcessTreeEvidence::VerifiedEmpty(
                ContainmentBackend::SystemdUserService,
            )),
            side_effects: Some(SideEffectConfinementEvidence::Verified(
                SideEffectConfinementProfileKind::ExternalCodex,
            )),
        };
        let error = ObservedCatalogFailure {
            error: anyhow::anyhow!("private catalog diagnostic")
                .context(CodexRuntimeModelCatalogFailureCause::UnsafeProcessResult),
            receipt: receipt.clone(),
        }
        .into();
        let failure = codex_runtime_model_catalog_failure(&error);
        assert!(
            failure
                .summary
                .contains("cause=catalog_process_result_unverified"),
            "{}",
            failure.summary
        );
        assert_eq!(failure.catalog_probe_receipt, Some(receipt));
        assert!(!failure.summary.contains("private catalog diagnostic"));
        let restored: EnvironmentFailure =
            serde_json::from_value(serde_json::to_value(&failure).unwrap()).unwrap();
        assert!(restored.catalog_probe_receipt.is_none());
        assert_eq!(*failure, restored);
    }
}
