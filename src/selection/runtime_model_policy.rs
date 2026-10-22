//! Mandatory runtime model identity policy, independent of routing economics.
//! Qualification, effort selection and acceptance remain the selector's job.
use crate::selection;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::sync::OnceLock;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeModelPolicy {
    effective_date: String,
    source: String,
    required_models: BTreeMap<String, RequiredModel>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequiredModel {
    model: String,
    minimum_cli_version: String,
}

fn policy() -> &'static RuntimeModelPolicy {
    static POLICY: OnceLock<RuntimeModelPolicy> = OnceLock::new();
    POLICY.get_or_init(|| {
        let policy: RuntimeModelPolicy =
            serde_json::from_str(include_str!("data/runtime-model-policy.json"))
                .expect("bundled runtime model policy must validate");
        assert!(!policy.effective_date.is_empty() && !policy.source.is_empty());
        policy
    })
}

pub(crate) fn constrain(input: &mut selection::SelectionInput) {
    for catalog in &input.catalogs {
        let Some(required) = policy().required_models.get(&catalog.runtime) else {
            continue;
        };
        for model in &catalog.models {
            if model.model != required.model {
                for effort in &model.supported_efforts {
                    input
                        .constraints
                        .forbidden_candidates
                        .insert(selection::CandidateKey {
                            runtime: catalog.runtime.clone(),
                            model: model.model.clone(),
                            effort: *effort,
                        });
                }
            }
        }
    }
}

pub(crate) fn missing_model_guidance(input: &selection::SelectionInput) -> String {
    let mut guidance = String::new();
    for catalog in &input.catalogs {
        let Some(required) = policy().required_models.get(&catalog.runtime) else {
            continue;
        };
        if !catalog.models.iter().any(|model| {
            model.model == required.model
                && model.available
                && model.access != Some(selection::ModelAccessOutcome::Unavailable)
        }) {
            guidance.push_str(&format!(
                "; required {} model '{}' is absent or unavailable in the observed catalog; install codex-cli >= {} at the trusted path, validate the selected account, and rerun catalog preflight; no other model fallback is permitted",
                catalog.runtime, required.model, required.minimum_cli_version
            ));
        }
    }
    guidance
}
