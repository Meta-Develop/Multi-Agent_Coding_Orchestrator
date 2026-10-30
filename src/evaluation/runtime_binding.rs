//! Requested cross-runtime interventions and common comparison inputs.
use super::{EvaluationError, ExperimentManifest};
use crate::{
    artifacts::state_auth::sha256_hex,
    supervise::{self, AgentRole, SupervisorRuntime, UnavailableModelFallback},
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{collections::BTreeMap, path::Path};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldOutComparisonInputs {
    pub manifest_sha256: String,
    pub caller_plan_sha256: String,
    pub common_plan_sha256: String,
    pub effective_plan_sha256: BTreeMap<String, String>,
    pub production_eligible: bool,
    pub notice: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedProfileBinding {
    pub comparison_sha256: String,
    pub effective_plan_sha256: String,
    pub roles: BTreeMap<AgentRole, ObservedRoleIdentity>,
}

/// Requested configuration is never treated as provider-resolved identity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedRoleIdentity {
    pub requested_runtime: SupervisorRuntime,
    pub requested_model: Option<String>,
    pub requested_effort: Option<String>,
    pub observed_model: Option<String>,
    pub observed_effort: Option<String>,
    pub unavailable_reason: Option<String>,
}

impl ObservedProfileBinding {
    pub(super) fn requested(
        profile: &super::EvaluationProfile,
        primary: SupervisorRuntime,
        comparison_sha256: &str,
        effective_plan_sha256: &str,
        effective_worker_runtime: SupervisorRuntime,
    ) -> Self {
        Self {
            comparison_sha256: comparison_sha256.into(),
            effective_plan_sha256: effective_plan_sha256.into(),
            roles: profile.role_models.iter().map(|(role, selection)| (*role, ObservedRoleIdentity {
                requested_runtime: if *role == AgentRole::Worker { effective_worker_runtime } else { primary },
                requested_model: selection.model.clone(),
                requested_effort: selection.reasoning_effort.clone(),
                observed_model: None,
                observed_effort: None,
                unavailable_reason: Some("provider-resolved per-role model/effort is not established by requested plan, catalog resolution, or role usage labels; inspect retained native evidence".into()),
            })).collect(),
        }
    }
}

pub(super) fn validate_observed_bindings(
    manifest: &ExperimentManifest,
    runs: &[super::ObservedExperimentRun],
) -> Result<()> {
    if !manifest
        .profiles
        .iter()
        .any(|profile| profile.worker_runtime.is_some())
    {
        return Ok(());
    }
    manifest.validate_for_observation()?;
    let mut comparison = None;
    for run in runs {
        let profile = manifest
            .profiles
            .iter()
            .find(|profile| profile.id == run.held_out.run.profile_id)
            .ok_or_else(|| anyhow::anyhow!("unknown runtime-bound profile"))?;
        let binding = run
            .profile_binding
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("missing cross-runtime comparison binding"))?;
        for digest in [&binding.comparison_sha256, &binding.effective_plan_sha256] {
            if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                bail!("invalid cross-runtime comparison digest");
            }
        }
        if comparison.is_some_and(|expected| expected != &binding.comparison_sha256) {
            bail!("incomparable arms: comparison hashes differ");
        }
        comparison.get_or_insert(&binding.comparison_sha256);
        if binding.roles.len() != profile.role_models.len() {
            bail!("incomparable arms: requested role identity set differs");
        }
        for (role, selection) in &profile.role_models {
            let identity = binding
                .roles
                .get(role)
                .ok_or_else(|| anyhow::anyhow!("missing requested role identity"))?;
            if identity.requested_model != selection.model
                || identity.requested_effort != selection.reasoning_effort
                || (*role == AgentRole::Worker
                    && Some(identity.requested_runtime) != profile.worker_runtime)
            {
                bail!("requested role identity differs from manifest");
            }
            if (identity.observed_model.is_none() || identity.observed_effort.is_none())
                && identity
                    .unavailable_reason
                    .as_ref()
                    .is_none_or(|reason| reason.trim().is_empty())
            {
                bail!("unknown observed identity requires an explicit reason");
            }
        }
    }
    Ok(())
}

pub(super) fn validate_profile_runtime_bindings(
    manifest: &ExperimentManifest,
) -> Result<(), EvaluationError> {
    let bound = manifest
        .profiles
        .iter()
        .any(|profile| profile.worker_runtime.is_some());
    let roles = manifest
        .profiles
        .first()
        .map(|profile| profile.role_models.keys().collect::<Vec<_>>());
    for profile in &manifest.profiles {
        let refuse = |message: &str| EvaluationError::InvalidManifest {
            field: format!("profiles.{}.worker_runtime", profile.id),
            message: message.into(),
        };
        if Some(profile.role_models.keys().collect::<Vec<_>>()) != roles {
            return Err(refuse("incomparable arms: role sets differ"));
        }
        if bound {
            if [
                AgentRole::Supervisor,
                AgentRole::ChildOrchestrator,
                AgentRole::Worker,
                AgentRole::Researcher,
                AgentRole::GateClassifier,
                AgentRole::Auditor,
            ]
            .iter()
            .any(|role| !profile.role_models.contains_key(role))
            {
                return Err(refuse(
                    "runtime-bound arms must explicitly bind model/effort for all six roles",
                ));
            }
            if !matches!(
                profile.worker_runtime,
                Some(SupervisorRuntime::Codex | SupervisorRuntime::Grok)
            ) {
                return Err(refuse(
                    "every arm must explicitly bind worker_runtime to codex or grok",
                ));
            }
            for selection in profile.role_models.values() {
                if selection
                    .reasoning_effort
                    .as_ref()
                    .is_none_or(|effort| effort.trim().is_empty())
                    || selection.unavailable_model_fallback != UnavailableModelFallback::FailClosed
                {
                    return Err(refuse("runtime-bound arms require explicit effort and fail_closed model selection for every role"));
                }
            }
        }
    }
    Ok(())
}

/// Offline declaration validation only; no executable, account, or provider is consulted.
pub fn validate_held_out_comparison_inputs(
    manifest: &ExperimentManifest,
    provider_plan: &Path,
) -> Result<HeldOutComparisonInputs> {
    manifest.validate_for_observation()?;
    let frozen = supervise::freeze_held_out_production_caller_plan_in_repo(provider_plan, None)?;
    comparison_inputs(manifest, &frozen, None)
}

pub(super) fn comparison_inputs(
    manifest: &ExperimentManifest,
    frozen: &supervise::FrozenHeldOutProductionCallerPlan,
    repo: Option<&Path>,
) -> Result<HeldOutComparisonInputs> {
    let mut common = None;
    let mut effective_plan_sha256 = BTreeMap::new();
    for profile in &manifest.profiles {
        let bytes = supervise::materialize_held_out_profile_runtime_caller_plan_in_repo(
            frozen,
            &profile.role_models,
            profile.worker_runtime,
            repo,
        )?;
        let mut invariant: Value = serde_json::from_slice(&bytes)?;
        invariant
            .as_object_mut()
            .expect("supervisor plan object")
            .remove("role_models");
        if profile.worker_runtime.is_some() {
            invariant["assignments"][0]
                .as_object_mut()
                .expect("assignment object")
                .remove("runtime");
        }
        let digest = sha256_hex(&serde_json::to_vec(&invariant)?);
        if common.as_ref().is_some_and(|expected| expected != &digest) {
            bail!(
                "incomparable arms: effective task, validation, review, limits or metadata differ"
            );
        }
        common.get_or_insert(digest);
        effective_plan_sha256.insert(profile.id.clone(), sha256_hex(&bytes));
    }
    Ok(HeldOutComparisonInputs {
        manifest_sha256: sha256_hex(&serde_json::to_vec(manifest)?),
        caller_plan_sha256: frozen.caller_plan_sha256.clone(),
        common_plan_sha256: common.ok_or_else(|| anyhow::anyhow!("comparison has no arms"))?,
        effective_plan_sha256,
        production_eligible: false,
        notice: "offline declaration binding only; source snapshot, runtime executables, account, priors, provider identity, usage and operator pricing still require live evidence".into(),
    })
}

pub(super) fn comparison_digest(
    inputs: &HeldOutComparisonInputs,
    source_commit: &str,
    source_tree: &str,
    runtime_bindings: &Value,
) -> Result<String> {
    Ok(sha256_hex(&serde_json::to_vec(&json!({
        "schema": "held_out_cross_runtime_comparison_v1",
        "inputs": inputs,
        "source_commit": source_commit,
        "source_tree": source_tree,
        "runtime_bindings": runtime_bindings,
    }))?))
}
