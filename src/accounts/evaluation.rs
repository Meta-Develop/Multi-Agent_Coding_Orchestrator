//! Manual account-bound input to the existing hard-quality evaluation function.

use super::{protocol::*, AccountClient, AccountError};
use crate::{
    optimizer::{
        action::CanonicalEffort,
        evaluation_fn::{
            EvaluatedPolicy, EvaluationFunction, EvaluationOutcome, DEFAULT_QUALITY_THRESHOLD_BP,
        },
        ids::PolicyId,
    },
    selection::{CandidateKey, ReasoningEffort},
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// Keeps identical runtime/model/effort candidates on different accounts distinct.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountBoundCandidate {
    pub account_alias: String,
    pub candidate: CandidateKey,
}

/// Caller-supplied evidence for the complete policy, never a model quality label.
/// The preview neither certifies nor authenticates this evidence.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PolicyEvidence {
    #[serde(with = "ClosedEvaluatedPolicy")]
    pub evaluation: EvaluatedPolicy,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "EvaluatedPolicy", deny_unknown_fields)]
struct ClosedEvaluatedPolicy {
    policy_id: PolicyId,
    certified_quality: bool,
    quality_lower_confidence_bp: u16,
    cost_to_certification_micros: i64,
    resource_constraints_satisfied: bool,
    effort: CanonicalEffort,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AccountPolicyInput {
    pub policy_id: PolicyId,
    pub binding: AccountBoundCandidate,
    pub evidence: Option<PolicyEvidence>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PreviewInput {
    pub schema_version: u32,
    /// Exact manual pin; mismatched policy bindings are invalid, never substituted.
    pub account_alias: String,
    pub quality_threshold_bp: u16,
    pub policies: Vec<AccountPolicyInput>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationalReason {
    AccountNotListed,
    AccountDisabled,
    InventoryChanged,
    DiscoveryRefused,
    DiscoveryUnavailable,
    DiscoveryTimedOut,
    DiscoveryProtocolInvalid,
    AuthUnknown,
    Unauthenticated,
    LocalLoginOnly,
    ReauthenticationRequired,
    ModelsUnknown,
    ModelNotObserved,
    EffortNotObserved,
    QuotaUnknown,
    QuotaExhausted,
    QuotaResetNeedsRevalidation,
    ObservationFromFuture,
    ObservationNeedsRevalidation,
    ModelEntitlementUnknown,
    AvailabilityUnknown,
    AccountUnavailable,
    DiscoveryFailed,
    CallerResourceConstraint,
}

#[derive(Debug, Clone, Serialize)]
pub struct PolicyPreview {
    pub policy_id: PolicyId,
    pub binding: AccountBoundCandidate,
    /// Sorted descriptor-list content identity, not an authorization revision.
    pub inventory_content_digest: String,
    /// Identity of the discovery attempt, not credential or policy authority.
    pub observation_id: Option<String>,
    pub evidence_supplied: bool,
    pub caller_resource_constraints_satisfied: Option<bool>,
    pub operational_reasons: Vec<OperationalReason>,
    pub resource_constraints_satisfied: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct AccountPreview {
    pub schema_version: u32,
    pub account_alias: String,
    pub inventory_content_digest: String,
    pub inventory: AccountList,
    pub observation: Option<AccountDiscovery>,
    pub policies: Vec<PolicyPreview>,
    pub evaluation: EvaluationOutcome,
    pub execution_ready: bool,
    pub revalidation_required: bool,
}

fn effort(value: ReasoningEffort) -> (CanonicalEffort, ModelEffort) {
    match value {
        ReasoningEffort::Low => (CanonicalEffort::Low, ModelEffort::Low),
        ReasoningEffort::Medium => (CanonicalEffort::Medium, ModelEffort::Medium),
        ReasoningEffort::High => (CanonicalEffort::High, ModelEffort::High),
        ReasoningEffort::Xhigh => (CanonicalEffort::XHigh, ModelEffort::Xhigh),
        ReasoningEffort::Max => (CanonicalEffort::Max, ModelEffort::Max),
        ReasoningEffort::Ultra => (
            CanonicalEffort::ProviderNative("ultra".into()),
            ModelEffort::Ultra,
        ),
    }
}

impl PreviewInput {
    pub fn validate(&self) -> Result<(), AccountError> {
        if self.schema_version != 1
            || !valid_alias(&self.account_alias)
            || !(DEFAULT_QUALITY_THRESHOLD_BP..=10_000).contains(&self.quality_threshold_bp)
        {
            return Err(AccountError::InvalidInput);
        }
        let mut seen = BTreeSet::new();
        for policy in &self.policies {
            if !valid_identifier(policy.policy_id.as_str())
                || !seen.insert(&policy.policy_id)
                || policy.binding.account_alias != self.account_alias
                || policy.binding.candidate.runtime != "codex"
                || !valid_identifier(&policy.binding.candidate.model)
                || policy.evidence.as_ref().is_some_and(|e| {
                    e.evaluation.policy_id != policy.policy_id
                        || e.evaluation.effort != effort(policy.binding.candidate.effort).0
                })
            {
                return Err(AccountError::InvalidInput);
            }
        }
        Ok(())
    }
}

/// Lists registrations, then discovers only the explicit account pin.
pub fn preview(
    client: &AccountClient,
    input: &PreviewInput,
) -> Result<AccountPreview, AccountError> {
    input.validate()?;
    let inventory = client.list()?;
    let observation = inventory
        .accounts
        .iter()
        .find(|account| account.alias == input.account_alias && account.enabled)
        .map(|_| client.discover(&input.account_alias));
    // Compare with completion time: discovery starts after list and connection latency.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| AccountError::InvalidInput)?
        .as_secs();
    evaluate_observation(input, inventory, observation, now)
}

/// Pure evaluation seam. Stored observations remain explicitly unvalidated.
pub fn evaluate_observation(
    input: &PreviewInput,
    mut inventory: AccountList,
    observation: Option<Result<AccountDiscovery, AccountError>>,
    now: u64,
) -> Result<AccountPreview, AccountError> {
    input.validate()?;
    inventory.validate()?;
    inventory.accounts.sort_by(|a, b| a.alias.cmp(&b.alias));
    let inventory_content_digest = crate::artifacts::state_auth::sha256_hex(
        &serde_json::to_vec(&inventory).map_err(|_| AccountError::InvalidInput)?,
    );
    let listed = inventory
        .accounts
        .iter()
        .find(|a| a.alias == input.account_alias);
    let mut common = Vec::new();
    match listed {
        None => common.push(OperationalReason::AccountNotListed),
        Some(account) if !account.enabled => common.push(OperationalReason::AccountDisabled),
        _ => {}
    }
    let observed = match observation {
        Some(Ok(observed)) => {
            observed.validate()?;
            if observed.account.alias != input.account_alias {
                return Err(AccountError::Protocol);
            }
            if listed != Some(&observed.account) {
                common.push(OperationalReason::InventoryChanged);
            }
            Some(observed)
        }
        Some(Err(error)) => {
            common.push(match error {
                AccountError::Timeout => OperationalReason::DiscoveryTimedOut,
                AccountError::Refused => OperationalReason::DiscoveryRefused,
                AccountError::Protocol => OperationalReason::DiscoveryProtocolInvalid,
                _ => OperationalReason::DiscoveryUnavailable,
            });
            None
        }
        None => None,
    };
    if let Some(observed) = &observed {
        account_reasons(observed, now, &mut common);
    }
    let mut evaluated = Vec::new();
    let mut policies = Vec::new();
    for policy in &input.policies {
        let mut reasons = common.clone();
        let (canonical, model_effort) = effort(policy.binding.candidate.effort);
        if let Some(observed) = &observed {
            match observed
                .models
                .items
                .iter()
                .find(|m| m.id == policy.binding.candidate.model)
            {
                None => reasons.push(OperationalReason::ModelNotObserved),
                Some(model) if !model.supported_reasoning_efforts.contains(&model_effort) => {
                    reasons.push(OperationalReason::EffortNotObserved)
                }
                _ => {}
            }
        }
        let supplied = policy.evidence.as_ref().map(|e| &e.evaluation);
        if supplied.is_some_and(|e| !e.resource_constraints_satisfied) {
            reasons.push(OperationalReason::CallerResourceConstraint);
        }
        // Unknown evidence must not become an optimistic resource allowance.
        let resource_constraints_satisfied = observed.is_some()
            && reasons.is_empty()
            && supplied.is_some_and(|e| e.resource_constraints_satisfied);
        let mut evaluation = supplied.cloned().unwrap_or_else(|| EvaluatedPolicy {
            policy_id: policy.policy_id.clone(),
            certified_quality: false,
            quality_lower_confidence_bp: 0,
            // Invalid-cost sentinel is explicit missing evidence, never a cost estimate.
            cost_to_certification_micros: -1,
            resource_constraints_satisfied: false,
            effort: canonical,
        });
        evaluation.resource_constraints_satisfied &= resource_constraints_satisfied;
        evaluated.push(evaluation);
        policies.push(PolicyPreview {
            policy_id: policy.policy_id.clone(),
            binding: policy.binding.clone(),
            inventory_content_digest: inventory_content_digest.clone(),
            observation_id: observed.as_ref().map(|o| o.observation_id.clone()),
            evidence_supplied: supplied.is_some(),
            caller_resource_constraints_satisfied: supplied
                .map(|e| e.resource_constraints_satisfied),
            operational_reasons: reasons,
            resource_constraints_satisfied,
        });
    }
    let evaluation = EvaluationFunction::new(input.quality_threshold_bp).evaluate(&evaluated);
    Ok(AccountPreview {
        schema_version: 1,
        account_alias: input.account_alias.clone(),
        inventory_content_digest,
        inventory,
        observation: observed,
        policies,
        evaluation,
        execution_ready: false,
        revalidation_required: true,
    })
}

fn account_reasons(observed: &AccountDiscovery, now: u64, reasons: &mut Vec<OperationalReason>) {
    use OperationalReason as R;
    match observed.auth.state {
        AuthState::Unknown => reasons.push(R::AuthUnknown),
        AuthState::Unauthenticated => reasons.push(R::Unauthenticated),
        AuthState::LocalLogin => reasons.push(R::LocalLoginOnly),
        AuthState::ReauthRequired => reasons.push(R::ReauthenticationRequired),
        AuthState::RemoteValidated => {}
    }
    if observed.observed_at > now {
        reasons.push(R::ObservationFromFuture);
    }
    // Protocol v1 promises no validity interval; age never grants freshness.
    reasons.push(R::ObservationNeedsRevalidation);
    if observed.models.state == ObservationState::Unknown {
        reasons.push(R::ModelsUnknown);
    }
    reasons.push(R::ModelEntitlementUnknown);
    match observed.availability {
        Availability::Unknown => reasons.push(R::AvailabilityUnknown),
        Availability::Unavailable => reasons.push(R::AccountUnavailable),
    }
    if observed.quota.state == ObservationState::Unknown || observed.quota.windows.is_empty() {
        reasons.push(R::QuotaUnknown);
    }
    for window in &observed.quota.windows {
        if window.used_percent >= 100.0 {
            reasons.push(R::QuotaExhausted);
        }
        if window.resets_at.is_some_and(|reset| reset <= now) {
            reasons.push(R::QuotaResetNeedsRevalidation);
        }
    }
    if observed.failure.is_some() {
        reasons.push(R::DiscoveryFailed);
    }
}
