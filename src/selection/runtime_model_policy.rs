//! Mandatory runtime model identity policy, independent of routing economics.
//! Qualification, effort selection and acceptance remain the selector's job.
use crate::selection;
use serde::Deserialize;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::OnceLock;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeModelPolicy {
    effective_date: String,
    source: String,
    required_models: BTreeMap<String, Vec<RequiredModel>>,
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
        for list in policy.required_models.values() {
            assert!(!list.is_empty(), "policy list must not be empty");
            let mut seen = BTreeSet::new();
            for entry in list {
                assert!(
                    seen.insert(entry.model.as_str()),
                    "policy list must not repeat a model"
                );
            }
        }
        policy
    })
}

fn usable_required<'a>(
    catalog: &selection::RuntimeCatalog,
    list: &'a [RequiredModel],
) -> Option<&'a RequiredModel> {
    list.iter().find(|entry| {
        catalog.models.iter().any(|model| {
            model.model == entry.model
                && model.available
                && model.access != Some(selection::ModelAccessOutcome::Unavailable)
        })
    })
}

pub(crate) fn constrain(input: &mut selection::SelectionInput) {
    let mut forbidden = Vec::new();
    for catalog in &input.catalogs {
        let Some(list) = policy().required_models.get(&catalog.runtime) else {
            continue;
        };
        let permitted = usable_required(catalog, list).map(|required| required.model.as_str());
        for model in &catalog.models {
            let allowed = match permitted {
                Some(required) => model.model == required,
                None => list.iter().any(|entry| entry.model == model.model),
            };
            if !allowed {
                for effort in &model.supported_efforts {
                    forbidden.push(selection::CandidateKey {
                        runtime: catalog.runtime.clone(),
                        model: model.model.clone(),
                        effort: *effort,
                    });
                }
            }
        }
    }
    input.constraints.forbidden_candidates.extend(forbidden);
}

pub(crate) fn missing_model_guidance(input: &selection::SelectionInput) -> String {
    let mut guidance = String::new();
    for catalog in &input.catalogs {
        let Some(list) = policy().required_models.get(&catalog.runtime) else {
            continue;
        };
        if usable_required(catalog, list).is_some() {
            continue;
        }
        let accepted = list
            .iter()
            .map(|entry| {
                format!(
                    "'{}' (codex-cli >= {})",
                    entry.model, entry.minimum_cli_version
                )
            })
            .collect::<Vec<_>>()
            .join(", ");
        let oldest = list
            .last()
            .expect("policy list must not be empty")
            .minimum_cli_version
            .clone();
        guidance.push_str(&format!(
            "; required {} model is absent or unavailable in the observed catalog; accepted models in preference order: {}; install codex-cli >= {} at the trusted path, validate the selected account, and rerun catalog preflight; no other model fallback is permitted",
            catalog.runtime, accepted, oldest
        ));
    }
    guidance
}

#[cfg(test)]
fn version_tuple(version: &str) -> [u32; 3] {
    let parts = version.split('.').collect::<Vec<_>>();
    assert!(parts.len() == 3, "policy versions have three components");
    let mut tuple = [0u32; 3];
    for (slot, part) in tuple.iter_mut().zip(parts) {
        *slot = part.parse().expect("numeric policy version component");
    }
    tuple
}

#[cfg(test)]
pub(crate) fn offered_by_codex_cli_0_162(model: &str) -> bool {
    let Some(list) = policy().required_models.get("codex") else {
        return true;
    };
    !list.iter().any(|entry| {
        entry.model == model && version_tuple(&entry.minimum_cli_version) > [0, 162, 0]
    })
}
