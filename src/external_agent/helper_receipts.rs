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
        let evidence = match result {
            Ok(output) => Some((output.process_tree, output.side_effects)),
            Err(ProcessRunError::Wait { evidence, .. })
            | Err(ProcessRunError::Cancelled {
                evidence: Some(evidence),
                ..
            }) => Some((evidence.process_tree, evidence.side_effects)),
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
            error: CodexRuntimeModelCatalogFailureCause::UnsafeProcessResult.into(),
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
        let restored: EnvironmentFailure =
            serde_json::from_value(serde_json::to_value(&failure).unwrap()).unwrap();
        assert!(restored.catalog_probe_receipt.is_none());
        assert_eq!(*failure, restored);
    }
}
