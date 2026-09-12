//! One explicitly selected account, one durable proposal attempt, existing guardian execution.

use super::{
    invocation_protocol::*,
    invocation_state::{AccountIntentJournal, InvocationIntent},
    protocol::{valid_alias, valid_identifier, ModelEffort},
    state::SelectionStore,
    AccountClient, AccountClientConfig, AccountError,
};
use crate::{
    budget_ledger::{
        self, DurableBudgetReconciliation, DurableBudgetReservation, RollingBudgetQuota,
        WorkspaceBudgetLedger,
    },
    llm::{
        LlmProvider, LlmRequest, LlmResponse, ProviderCapabilities, ProviderError, Usage,
        WorkProposal,
    },
    optimizer::{
        ids::RuntimeSlug,
        quota_pools::{AccountId, PoolKey, ResetWindow},
    },
};
use serde::{Deserialize, Serialize};
use std::{
    path::PathBuf,
    time::{Duration, Instant},
};

/// Explicit local admission. It cannot enforce a remote token or spend ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerAdmissionPolicy {
    pub max_tokens: usize,
    pub window_seconds: u64,
    pub require_hard_spend_cap: bool,
}

#[derive(Clone)]
pub struct AccountBrokerProviderConfig {
    pub client: AccountClientConfig,
    pub repo: PathBuf,
    pub selection_state: PathBuf,
    pub alias: String,
    pub model: String,
    pub reasoning_effort: ModelEffort,
    pub admission: BrokerAdmissionPolicy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerChargeKind {
    ObservedFinal,
    ConservativeReservation,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerCostEvidence {
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerAccounting {
    pub reservation_id: Option<String>,
    pub reserved_tokens: Option<usize>,
    pub charged_tokens: Option<usize>,
    pub charge_kind: Option<BrokerChargeKind>,
    pub cost: BrokerCostEvidence,
    pub settled: bool,
}

impl Default for BrokerAccounting {
    fn default() -> Self {
        Self {
            reservation_id: None,
            reserved_tokens: None,
            charged_tokens: None,
            charge_kind: None,
            cost: BrokerCostEvidence::Unknown,
            settled: false,
        }
    }
}

/// Safe attempt evidence. Proposal content and raw provider identifiers are excluded.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BrokerAttemptMetadata {
    pub request_nonce: String,
    pub attempt_id: Option<String>,
    pub binding: Option<InvocationBinding>,
    pub start_requested: bool,
    /// This is the latest authenticated observation, not a claim that a lost start was harmless.
    pub observed_state: Option<InvocationState>,
    pub observed_effect: Option<InvocationEffect>,
    pub remote_failure: Option<InvocationFailure>,
    pub refusal: Option<InvocationRefusal>,
    pub usage: InvocationUsage,
    /// Greatest authenticated cumulative total, even if a later observation loses usage.
    pub observed_token_lower_bound: Option<u64>,
    pub accounting: BrokerAccounting,
}

impl BrokerAttemptMetadata {
    fn new(nonce: String) -> Self {
        Self {
            request_nonce: nonce,
            attempt_id: None,
            binding: None,
            start_requested: false,
            observed_state: None,
            observed_effect: None,
            remote_failure: None,
            refusal: None,
            usage: InvocationUsage::unknown(),
            observed_token_lower_bound: None,
            accounting: BrokerAccounting::default(),
        }
    }

    fn observe(&mut self, attempt: &InvocationAttempt) {
        self.attempt_id = Some(attempt.attempt_id.clone());
        self.binding = Some(attempt.binding.clone());
        self.observed_state = Some(attempt.state);
        self.observed_effect = Some(attempt.effect);
        self.remote_failure = attempt.failure;
        self.usage = attempt.usage.clone();
        if let Some(snapshot) = &attempt.usage.snapshot {
            self.observed_token_lower_bound = Some(
                self.observed_token_lower_bound
                    .unwrap_or(0)
                    .max(snapshot.total.total_tokens),
            );
        }
    }
}

impl std::fmt::Display for BrokerAttemptMetadata {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("account-bound attempt evidence retained")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BrokerProviderFailure {
    InvalidInput,
    Selection,
    UnsafeState,
    ReplayBlocked,
    Refused,
    Transport,
    Protocol,
    Deadline,
    MissingUsage,
    RemoteFailed,
    BudgetRefused,
    BudgetPersistence,
    LocalOutputLimit,
    LocalTokenLimit,
}

impl std::fmt::Display for BrokerProviderFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::InvalidInput => "invalid input",
            Self::Selection => "selection mismatch",
            Self::UnsafeState => "unsafe local state",
            Self::ReplayBlocked => "recorded request requires recovery",
            Self::Refused => "broker refusal",
            Self::Transport => "uncertain transport outcome",
            Self::Protocol => "invalid broker observation",
            Self::Deadline => "local operation deadline",
            Self::MissingUsage => "final usage unavailable",
            Self::RemoteFailed => "provider attempt failed",
            Self::BudgetRefused => "local admission refused",
            Self::BudgetPersistence => "accounting persistence failed",
            Self::LocalOutputLimit => "local output limit",
            Self::LocalTokenLimit => "local token limit",
        };
        f.write_str(value)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, thiserror::Error)]
#[serde(deny_unknown_fields)]
#[error("account-bound provider stopped: {reason}")]
pub struct BrokerProviderError {
    pub reason: BrokerProviderFailure,
    pub attempt: BrokerAttemptMetadata,
}

pub struct AccountBrokerProvider {
    config: AccountBrokerProviderConfig,
    client: AccountClient,
    last_attempt: Option<BrokerAttemptMetadata>,
}

impl AccountBrokerProvider {
    pub fn new(config: AccountBrokerProviderConfig) -> Result<Self, ProviderError> {
        if config.admission.require_hard_spend_cap {
            return Err(ProviderError::UnsupportedCapability(
                "Broker Codex cannot enforce a remote spend or token ceiling".into(),
            ));
        }
        if !valid_alias(&config.alias)
            || !valid_identifier(&config.model)
            || config.admission.max_tokens == 0
            || config.admission.window_seconds == 0
        {
            return Err(ProviderError::InvalidRequest(
                "invalid account-bound provider configuration".into(),
            ));
        }
        if !cfg!(target_os = "linux") {
            return Err(ProviderError::UnsupportedCapability(
                "account-bound provider requires Linux".into(),
            ));
        }
        let client = AccountClient::new(config.client.clone()).map_err(|_| {
            ProviderError::InvalidRequest("invalid account service deadline".into())
        })?;
        Ok(Self {
            config,
            client,
            last_attempt: None,
        })
    }

    pub fn last_attempt(&self) -> Option<&BrokerAttemptMetadata> {
        self.last_attempt.as_ref()
    }

    fn error(
        &self,
        reason: BrokerProviderFailure,
        metadata: &BrokerAttemptMetadata,
    ) -> ProviderError {
        ProviderError::AccountBroker(Box::new(BrokerProviderError {
            reason,
            attempt: metadata.clone(),
        }))
    }

    fn complete_once(&mut self, request: LlmRequest) -> Result<LlmResponse, ProviderError> {
        crate::llm::provider::validate_request(&request)?;
        if request.model != self.config.model
            || request.request_id.len() > super::protocol::MAX_FRAME_BYTES
        {
            return Err(ProviderError::InvalidRequest(
                "request does not match the fixed Broker model or request identity".into(),
            ));
        }
        let prompt = request.prompt.render();
        if prompt.chars().count() > request.budget.max_input_chars
            || request.budget.max_total_tokens == 0
        {
            return Err(ProviderError::InvalidRequest(
                "request exceeds local prompt admission".into(),
            ));
        }
        let policy = request.metadata.get("maco_agent_policy").ok_or_else(|| {
            ProviderError::InvalidRequest(
                "Broker agent provider requires the complete guardian run policy".into(),
            )
        })?;
        // Freeze the caller's actual constraints once, before preparing any remote binding.
        let rolling_quota = budget_ledger::current_rolling_binding()
            .map(|binding| {
                if binding.repo != self.config.repo {
                    return Err(ProviderError::InvalidRequest(
                        "rolling budget workspace mismatch".into(),
                    ));
                }
                if binding.quota.max_cost_usd.is_some() {
                    return Err(ProviderError::UnsupportedCapability(
                        "Broker cost evidence is unavailable".into(),
                    ));
                }
                Ok(binding.quota)
            })
            .transpose()?;
        let policy_bytes =
            serde_json::to_vec(&(policy, request.budget, self.config.admission, rolling_quota))
                .map_err(|_| ProviderError::InvalidRequest("invalid guardian run policy".into()))?;
        let endpoint = self
            .client
            .endpoint_binding()
            .map_err(|_| ProviderError::InvalidRequest("unsafe account endpoint".into()))?;
        let mut journal = AccountIntentJournal::open(&self.config.repo, &request.request_id)
            .map_err(|_| {
                ProviderError::InvalidRequest("account invocation journal is unavailable".into())
            })?;
        if let Some(prior) = journal.prior_metadata().map_err(|_| {
            ProviderError::InvalidRequest("account invocation journal is invalid".into())
        })? {
            self.last_attempt = Some(prior.clone());
            // Opening the existing ledger conservatively recovers any interrupted reservation.
            if prior.accounting.reservation_id.is_some() {
                let _ledger = WorkspaceBudgetLedger::open_or_create(&self.config.repo)
                    .map_err(|_| self.error(BrokerProviderFailure::BudgetPersistence, &prior))?;
            }
            return Err(self.error(BrokerProviderFailure::ReplayBlocked, &prior));
        }
        let nonce = super::invocation_state::new_nonce().map_err(|_| {
            ProviderError::InvalidRequest("OS attempt identity is unavailable".into())
        })?;
        let mut metadata = BrokerAttemptMetadata::new(nonce.clone());
        self.last_attempt = Some(metadata.clone());
        let selection =
            SelectionStore::open_existing(&self.config.selection_state, endpoint.clone())
                .map_err(|_| self.error(BrokerProviderFailure::Selection, &metadata))?;
        let invocation = selection
            .freeze(&self.config.alias, |selected| {
                let invocation = InvocationRequest {
                    alias: self.config.alias.clone(),
                    selection_revision: selected.revision,
                    model: self.config.model.clone(),
                    reasoning_effort: self.config.reasoning_effort,
                    policy_digest: digest(&policy_bytes),
                    input: InvocationInput::WorkProposal { prompt },
                };
                journal
                    .record_intent(
                        InvocationIntent {
                            endpoint_binding: endpoint.clone(),
                            expected_uid: self.config.client.expected_uid,
                            caller_uid: caller_uid(),
                            request_id: request.request_id.clone(),
                            request: invocation.clone(),
                            admission: self.config.admission,
                            rolling_quota,
                        },
                        &metadata,
                    )
                    .map_err(|_| AccountError::UnsafeState)?;
                Ok(invocation)
            })
            .map_err(|_| self.error(BrokerProviderFailure::Selection, &metadata))?;

        let outcome = self.run_prepared(
            &invocation,
            &mut journal,
            &mut metadata,
            request.budget.max_total_tokens,
            rolling_quota,
        );
        self.last_attempt = Some(metadata.clone());
        let terminal_record = journal.record("outcome", &metadata);
        if terminal_record.is_err() {
            return Err(self.error(BrokerProviderFailure::UnsafeState, &metadata));
        }
        let attempt = outcome.map_err(|reason| self.error(reason, &metadata))?;
        let snapshot = attempt
            .usage
            .snapshot
            .as_ref()
            .filter(|_| attempt.usage.state == InvocationUsageState::Final)
            .ok_or_else(|| self.error(BrokerProviderFailure::MissingUsage, &metadata))?;
        let usage = Usage {
            input_tokens: usize::try_from(snapshot.total.input_tokens)
                .map_err(|_| self.error(BrokerProviderFailure::Protocol, &metadata))?,
            output_tokens: usize::try_from(snapshot.total.output_tokens)
                .map_err(|_| self.error(BrokerProviderFailure::Protocol, &metadata))?,
            total_tokens: usize::try_from(snapshot.total.total_tokens)
                .map_err(|_| self.error(BrokerProviderFailure::Protocol, &metadata))?,
        };
        if usage.total_tokens > request.budget.max_total_tokens {
            return Err(self.error(BrokerProviderFailure::LocalTokenLimit, &metadata));
        }
        let proposal = attempt
            .proposal
            .ok_or_else(|| self.error(BrokerProviderFailure::Protocol, &metadata))?;
        // Measure every accepted field, including patch contents and command directories.
        let proposal_chars = serde_json::to_string(&proposal)
            .map_err(|_| self.error(BrokerProviderFailure::Protocol, &metadata))?
            .chars()
            .count();
        if proposal_chars > request.budget.max_output_chars {
            return Err(self.error(BrokerProviderFailure::LocalOutputLimit, &metadata));
        }
        let proposal: WorkProposal = proposal.into();
        // Provider raw transcript is unavailable; preserve only the caller's already-redacted input.
        Ok(LlmResponse {
            request_id: request.request_id,
            provider_id: self.provider_id().to_string(),
            model: self.config.model.clone(),
            proposal,
            usage,
            transcript: request.transcript,
            redactions: request.prompt.redactions,
            broker_attempt: Some(metadata),
        })
    }

    fn run_prepared(
        &self,
        request: &InvocationRequest,
        journal: &mut AccountIntentJournal,
        metadata: &mut BrokerAttemptMetadata,
        reservation_tokens: usize,
        rolling_quota: Option<RollingBudgetQuota>,
    ) -> Result<InvocationAttempt, BrokerProviderFailure> {
        let result = self
            .client
            .invocation_prepare(&metadata.request_nonce, request)
            .map_err(transport_failure)?;
        let prepared = accept_result(result, metadata)?;
        if prepared.state != InvocationState::Prepared
            || prepared.effect != InvocationEffect::NotDispatched
        {
            return Err(BrokerProviderFailure::ReplayBlocked);
        }
        journal
            .record("prepared", metadata)
            .map_err(|_| BrokerProviderFailure::UnsafeState)?;
        let pool = attribution_pool(&self.client, &prepared.binding)?;
        let reservation_id = journal.reservation_id();
        let mut ledger = WorkspaceBudgetLedger::open_or_create(&self.config.repo)
            .map_err(|_| BrokerProviderFailure::BudgetPersistence)?;
        self.check_admission(&ledger, reservation_tokens, &pool, rolling_quota)?;
        let now =
            budget_ledger::unix_now().map_err(|_| BrokerProviderFailure::BudgetPersistence)?;
        ledger
            .record_reservation(DurableBudgetReservation {
                reservation_id: reservation_id.clone(),
                tokens: reservation_tokens,
                requests: 1,
                cost_usd: None,
                pool: Some(pool.clone()),
                unix_seconds: now,
            })
            .map_err(|_| BrokerProviderFailure::BudgetPersistence)?;
        metadata.accounting.reservation_id = Some(reservation_id.clone());
        metadata.accounting.reserved_tokens = Some(reservation_tokens);
        let outcome = (|| {
            journal
                .record("reserved", metadata)
                .map_err(|_| BrokerProviderFailure::UnsafeState)?;
            metadata.start_requested = true;
            journal
                .record("start_requested", metadata)
                .map_err(|_| BrokerProviderFailure::UnsafeState)?;
            self.wait_for_attempt(request, prepared, metadata, &mut ledger)
        })();
        let final_tokens = metadata
            .usage
            .snapshot
            .as_ref()
            .filter(|_| metadata.usage.state == InvocationUsageState::Final)
            .and_then(|snapshot| usize::try_from(snapshot.total.total_tokens).ok());
        let observed_floor = metadata
            .observed_token_lower_bound
            .map(usize::try_from)
            .transpose()
            .map_err(|_| BrokerProviderFailure::BudgetPersistence)?
            .unwrap_or(0);
        let charged = final_tokens.unwrap_or(reservation_tokens.max(observed_floor));
        ledger
            .reconcile_reservation(DurableBudgetReconciliation {
                reservation_id,
                tokens: charged,
                requests: 1,
                cost_usd: None,
                pool: Some(pool.clone()),
                unix_seconds: budget_ledger::unix_now()
                    .map_err(|_| BrokerProviderFailure::BudgetPersistence)?,
            })
            .map_err(|_| BrokerProviderFailure::BudgetPersistence)?;
        metadata.accounting.charged_tokens = Some(charged);
        metadata.accounting.charge_kind = Some(if final_tokens.is_some() {
            BrokerChargeKind::ObservedFinal
        } else {
            BrokerChargeKind::ConservativeReservation
        });
        metadata.accounting.settled = true;
        if metadata.remote_failure == Some(InvocationFailure::RateLimited) {
            ledger
                .record_rate_limited(
                    pool.account.as_str(),
                    "account-bound provider rate limit",
                    self.config.admission.window_seconds,
                    budget_ledger::unix_now()
                        .map_err(|_| BrokerProviderFailure::BudgetPersistence)?,
                )
                .map_err(|_| BrokerProviderFailure::BudgetPersistence)?;
        }
        // Ledger ownership ends on return, before the generic provider-error hook runs.
        let completed = outcome?;
        if completed.state != InvocationState::Completed {
            return Err(BrokerProviderFailure::RemoteFailed);
        }
        if completed.usage.state != InvocationUsageState::Final {
            return Err(BrokerProviderFailure::MissingUsage);
        }
        Ok(completed)
    }

    fn check_admission(
        &self,
        ledger: &WorkspaceBudgetLedger,
        reservation_tokens: usize,
        pool: &PoolKey,
        rolling_quota: Option<RollingBudgetQuota>,
    ) -> Result<(), BrokerProviderFailure> {
        let now =
            budget_ledger::unix_now().map_err(|_| BrokerProviderFailure::BudgetPersistence)?;
        if ledger
            .active_rate_limit(pool.account.as_str(), now)
            .is_some()
            || ledger
                .active_rate_limit(budget_ledger::DEFAULT_RATE_LIMIT_POOL, now)
                .is_some()
        {
            return Err(BrokerProviderFailure::BudgetRefused);
        }
        let mut policies = vec![(
            self.config.admission.max_tokens,
            self.config.admission.window_seconds,
        )];
        if let Some(quota) = rolling_quota {
            if let Some(max) = quota.max_tokens {
                policies.push((max, quota.window_seconds));
            }
        }
        for (limit, window) in policies {
            let used = ledger
                .usage_in_window(window, now)
                .map_err(|_| BrokerProviderFailure::BudgetPersistence)?;
            if used
                .tokens
                .checked_add(reservation_tokens)
                .is_none_or(|projected| projected > limit)
            {
                return Err(BrokerProviderFailure::BudgetRefused);
            }
        }
        Ok(())
    }

    fn wait_for_attempt(
        &self,
        request: &InvocationRequest,
        prepared: InvocationAttempt,
        metadata: &mut BrokerAttemptMetadata,
        ledger: &mut WorkspaceBudgetLedger,
    ) -> Result<InvocationAttempt, BrokerProviderFailure> {
        let nonce = metadata.request_nonce.clone();
        let id = prepared.attempt_id.clone();
        let started = match self.client.invocation_start(&nonce, request, &id) {
            Ok(result) => result,
            Err(_) => self
                .client
                .invocation_status(&nonce, request, Some(&id))
                .map_err(transport_failure)?,
        };
        let mut current = checked_next(started, &prepared, metadata)?;
        persist_observed_floor(ledger, metadata)?;
        if current.state == InvocationState::Prepared {
            return Err(BrokerProviderFailure::Refused);
        }
        let now = budget_ledger::unix_now().map_err(|_| BrokerProviderFailure::Deadline)?;
        let remaining = current.broker_deadline.unwrap_or(now).saturating_sub(now);
        let deadline = Instant::now()
            .checked_add(Duration::from_secs(remaining))
            .ok_or(BrokerProviderFailure::Protocol)?;
        while !current.state.is_terminal() {
            let Some(remaining) = deadline
                .checked_duration_since(Instant::now())
                .filter(|duration| !duration.is_zero())
            else {
                if let Ok(result) = self.client.invocation_cancel(&nonce, request, &id) {
                    if let Ok(attempt) = checked_next(result, &current, metadata) {
                        persist_observed_floor(ledger, metadata)?;
                        current = attempt;
                    }
                }
                // Even a racing valid terminal is accounted; the local deadline still stops application.
                let _ = current;
                return Err(BrokerProviderFailure::Deadline);
            };
            // Same control cadence as the existing managed-account UI, not a provider retry.
            std::thread::sleep(remaining.min(Duration::from_secs(1)));
            let mut config = self.config.client.clone();
            config.timeout = config
                .timeout
                .min(deadline.saturating_duration_since(Instant::now()));
            if config.timeout.is_zero() {
                continue;
            }
            let client = AccountClient::new(config).map_err(transport_failure)?;
            let result = client
                .invocation_status(&nonce, request, Some(&id))
                .map_err(transport_failure)?;
            current = checked_next(result, &current, metadata)?;
            persist_observed_floor(ledger, metadata)?;
        }
        Ok(current)
    }
}

impl LlmProvider for AccountBrokerProvider {
    fn provider_id(&self) -> &str {
        "account-broker"
    }
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            max_context_tokens: None,
            max_output_tokens: None,
            supports_command_proposals: true,
            supports_patch_proposals: true,
            supports_transcripts: false,
        }
    }
    fn complete(&mut self, request: LlmRequest) -> Result<LlmResponse, ProviderError> {
        self.last_attempt = None;
        self.complete_once(request)
    }
}

fn transport_failure(error: AccountError) -> BrokerProviderFailure {
    match error {
        AccountError::Protocol | AccountError::UnsafeEndpoint => BrokerProviderFailure::Protocol,
        AccountError::InvalidInput => BrokerProviderFailure::InvalidInput,
        AccountError::Refused => BrokerProviderFailure::Refused,
        _ => BrokerProviderFailure::Transport,
    }
}

fn accept_result(
    result: InvocationResult,
    metadata: &mut BrokerAttemptMetadata,
) -> Result<InvocationAttempt, BrokerProviderFailure> {
    match result {
        InvocationResult::Attempt { attempt, .. } => {
            metadata.observe(&attempt);
            Ok(*attempt)
        }
        InvocationResult::Refused { reason, .. } => {
            metadata.refusal = Some(reason);
            Err(BrokerProviderFailure::Refused)
        }
    }
}

fn checked_next(
    result: InvocationResult,
    previous: &InvocationAttempt,
    metadata: &mut BrokerAttemptMetadata,
) -> Result<InvocationAttempt, BrokerProviderFailure> {
    if let InvocationResult::Attempt { attempt, .. } = &result {
        attempt
            .follows(previous)
            .map_err(|_| BrokerProviderFailure::Protocol)?;
        if attempt.usage.state == InvocationUsageState::Final
            && attempt.usage.snapshot.as_ref().is_some_and(|snapshot| {
                snapshot.total.total_tokens < metadata.observed_token_lower_bound.unwrap_or(0)
            })
        {
            return Err(BrokerProviderFailure::Protocol);
        }
    }
    accept_result(result, metadata)
}

fn persist_observed_floor(
    ledger: &mut WorkspaceBudgetLedger,
    metadata: &BrokerAttemptMetadata,
) -> Result<(), BrokerProviderFailure> {
    if let Some(total) = metadata.observed_token_lower_bound {
        let id = metadata
            .accounting
            .reservation_id
            .as_deref()
            .ok_or(BrokerProviderFailure::BudgetPersistence)?;
        ledger
            .record_observed_floor(
                id,
                usize::try_from(total).map_err(|_| BrokerProviderFailure::BudgetPersistence)?,
                budget_ledger::unix_now().map_err(|_| BrokerProviderFailure::BudgetPersistence)?,
            )
            .map_err(|_| BrokerProviderFailure::BudgetPersistence)?;
    }
    Ok(())
}

fn attribution_pool(
    client: &AccountClient,
    binding: &InvocationBinding,
) -> Result<PoolKey, BrokerProviderFailure> {
    let mut bytes = b"maco-account-attribution-v1\0openai\0".to_vec();
    bytes.extend_from_slice(
        client
            .endpoint_binding()
            .map_err(transport_failure)?
            .as_bytes(),
    );
    bytes.extend_from_slice(binding.account_pool_id.as_bytes());
    Ok(PoolKey {
        runtime: RuntimeSlug::new("codex").map_err(|_| BrokerProviderFailure::InvalidInput)?,
        account: AccountId::new(digest(&bytes)).map_err(|_| BrokerProviderFailure::InvalidInput)?,
        window: ResetWindow::None,
    })
}

fn caller_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        unsafe { libc::geteuid() }
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use crate::llm::{PromptContext, Redactor, RequestBudget};
    use serde_json::{json, Value};
    use std::{
        fs,
        io::{BufRead, BufReader, Write},
        os::unix::{fs::PermissionsExt, net::UnixListener},
        thread,
    };

    #[test]
    fn bound_rolling_constraints_change_real_prepare_identity_and_refuse_before_start() {
        let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let repo = temp.path().join("repo");
        git2::Repository::init(&repo).unwrap();
        let socket = temp.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        let client = AccountClientConfig {
            socket,
            expected_uid: caller_uid(),
            timeout: Duration::from_secs(5),
        };
        let config = AccountBrokerProviderConfig {
            client: client.clone(),
            repo: repo.clone(),
            selection_state: temp.path().join("selection"),
            alias: "selected".into(),
            model: "example-model".into(),
            reasoning_effort: ModelEffort::High,
            admission: BrokerAdmissionPolicy {
                max_tokens: RequestBudget::default().max_total_tokens * 2,
                window_seconds: 86400,
                require_hard_spend_cap: false,
            },
        };
        SelectionStore::open(
            &config.selection_state,
            AccountClient::new(client)
                .unwrap()
                .endpoint_binding()
                .unwrap(),
        )
        .unwrap()
        .select("selected", 0)
        .unwrap();
        let server = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..3 {
                let (mut stream, _) = listener.accept().unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(5)))
                    .unwrap();
                let mut line = String::new();
                BufReader::new(&stream).read_line(&mut line).unwrap();
                let message: Value = serde_json::from_str(&line).unwrap();
                assert_eq!(message["capability"], "accounts.invocation.prepare");
                let request: InvocationRequest =
                    serde_json::from_value(message["arguments"]["request"].clone()).unwrap();
                let now = budget_ledger::unix_now().unwrap();
                let response = json!({"id":message["id"],"ok":true,"result":{"schema_version":1,"outcome":"attempt","attempt":{
                    "attempt_id":"00000000-0000-4000-8000-000000000001", "request_nonce":message["arguments"]["request_nonce"],
                    "binding":{"alias":request.alias,"provider":"openai","runtime":"codex","account_pool_id":"00000000-0000-4000-8000-000000000002",
                    "credential_generation":"00000000-0000-4000-8000-000000000003","selection_revision":request.selection_revision,"model":request.model,
                    "reasoning_effort":request.reasoning_effort,"policy_digest":request.policy_digest,"prompt_digest":digest(request.input.prompt().as_bytes()),"request_digest":request.digest().unwrap()},
                    "state":"prepared","effect":"not_dispatched","prepared_at":now,"started_at":null,"broker_deadline":null,"finished_at":null,
                    "proposal":null,"usage":{"state":"unknown","snapshot":null},"failure":null}}});
                let mut bytes = serde_json::to_vec(&response).unwrap();
                bytes.push(b'\n');
                stream.write_all(&bytes).unwrap();
                requests.push(request);
            }
            requests
        });
        let reservation = RequestBudget::default().max_total_tokens;
        for (index, (max_tokens, window_seconds)) in [
            (reservation - 1, 60),
            (reservation - 2, 60),
            (reservation - 2, 120),
        ]
        .into_iter()
        .enumerate()
        {
            let quota = RollingBudgetQuota {
                max_tokens: Some(max_tokens),
                max_cost_usd: None,
                window_seconds,
            };
            let _binding =
                budget_ledger::bind_rolling_budget(&repo, quota, "bound-caller").unwrap();
            let mut provider = AccountBrokerProvider::new(config.clone()).unwrap();
            let mut context = PromptContext::new("Return a proposal.", "fixture-agent");
            context.provider_capabilities = provider.capabilities();
            let mut request = LlmRequest::new(
                format!("quota-{index}"),
                "example-model",
                context.assemble_prompt(&Redactor::new()),
            );
            request.metadata.insert(
                "maco_agent_policy".into(),
                "same complete guardian policy".into(),
            );
            assert!(
                matches!(provider.complete(request), Err(ProviderError::AccountBroker(error)) if error.reason == BrokerProviderFailure::BudgetRefused)
            );
        }
        let prepared = server.join().unwrap();
        assert_ne!(prepared[0].policy_digest, prepared[1].policy_digest);
        assert_ne!(prepared[1].policy_digest, prepared[2].policy_digest);
        assert_ne!(prepared[0].digest().unwrap(), prepared[1].digest().unwrap());
        assert_ne!(prepared[1].digest().unwrap(), prepared[2].digest().unwrap());
    }
}
