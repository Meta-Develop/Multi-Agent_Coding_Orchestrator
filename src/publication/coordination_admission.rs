//! Remote claim lifecycle over authenticated coordination transport (#410).
//!
//! Caller integration (SyncStore / publication CLI) is a separate unit. Production
//! must use [`CoordinationGithubTransport`] via [`CoordinationAdmissionService::from_github`].
//! Effect completion requires a parent-supplied [`EffectReconciliationVerifier`]; absence
//! refuses histories containing `EffectComplete` during reduction.

use super::coordination_effect::{
    effect_reconciliation_is_bound, verify_bound_effect_complete_live,
    LiveEffectVerificationContext, PublicationEffectDescriptorV1,
    PublicationEffectLiveVerification, PublicationEffectLiveVerifier,
};
use super::coordination_github::{
    CoordinationGithubAdapterConfig, CoordinationGithubRunner, CoordinationGithubTransport,
    CoordinationMutationOutcome,
};
use super::coordination_journal::{
    normalize_coordination_scopes, ActiveOwnerRecord, AuthoritySnapshot, CoordinationIntent,
    CoordinationJournalConfig, CoordinationOwnerIdentity, EffectReconciliationReceipt,
    EffectReconciliationVerifier, TrustedFiniteJournalHistory,
};
use super::forge_transport::ForgeActor;
use crate::{
    artifacts::{
        repository_auth_writer,
        state_auth::{sha256_hex, RepositoryAuthenticator},
    },
    effect_wal::{
        effect_phase_is_nonterminal, effect_wal_has_nonterminal_operations, DefaultEffectWalSpec,
        EffectPhase, EffectWal, OpenInitializedEffectWal,
    },
    process_runner::ProcessCancellation,
    sync_store::ClaimTiming,
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Condvar, Mutex,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

type CoordinationAdmissionEffectWal = EffectWal<DefaultEffectWalSpec>;

const PENDING_INTENT_LEDGER_LOGICAL: &str = "coordination-admission-pending-intents";
const LOCAL_ACTIVATION_LEDGER_LOGICAL: &str = "coordination-admission-local-activations";
const PENDING_INTENT_FORMAT_VERSION: u32 = 3;
const PENDING_INTENT_LEGACY_FORMAT_VERSION: u32 = 2;
const LOCAL_ACTIVATION_FORMAT_VERSION: u32 = 1;

/// Production transport seam; tests may substitute verified journal fixtures.
pub(crate) trait CoordinationAdmissionTransport: Send + Sync {
    fn journal_config(&self) -> &CoordinationJournalConfig;
    fn approved_actor(&self) -> &ForgeActor;
    fn worktree(&self) -> &Path;
    fn load_trusted_history(&self) -> Result<TrustedFiniteJournalHistory>;
    fn reduce_loaded_history(
        &self,
        history: &TrustedFiniteJournalHistory,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<AuthoritySnapshot>;
    fn apply_authorized_intent(
        &self,
        intent: CoordinationIntent,
        comment_author: ForgeActor,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<CoordinationMutationOutcome>;
}

impl<R: CoordinationGithubRunner> CoordinationAdmissionTransport
    for CoordinationGithubTransport<R>
{
    fn journal_config(&self) -> &CoordinationJournalConfig {
        self.config().journal()
    }

    fn approved_actor(&self) -> &ForgeActor {
        self.config().approved_actor()
    }

    fn worktree(&self) -> &Path {
        self.config().worktree()
    }

    fn load_trusted_history(&self) -> Result<TrustedFiniteJournalHistory> {
        CoordinationGithubTransport::load_trusted_history(self)
    }

    fn reduce_loaded_history(
        &self,
        history: &TrustedFiniteJournalHistory,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<AuthoritySnapshot> {
        CoordinationGithubTransport::reduce_loaded_history(self, history, effect_reconciliation)
    }

    fn apply_authorized_intent(
        &self,
        intent: CoordinationIntent,
        comment_author: ForgeActor,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<CoordinationMutationOutcome> {
        CoordinationGithubTransport::apply_authorized_intent(
            self,
            intent,
            comment_author,
            effect_reconciliation,
        )
    }
}

pub(crate) struct CoordinationAdmissionService<T: CoordinationAdmissionTransport> {
    transport: Arc<T>,
    effect_reconciliation: Option<Arc<dyn EffectReconciliationVerifier + Send + Sync>>,
    publication_live_verifier: Option<Arc<dyn PublicationEffectLiveVerifier + Send + Sync>>,
}

impl<T: CoordinationAdmissionTransport> CoordinationAdmissionService<T> {
    pub(crate) fn new(
        transport: T,
        effect_reconciliation: Option<Arc<dyn EffectReconciliationVerifier + Send + Sync>>,
        publication_live_verifier: Option<Arc<dyn PublicationEffectLiveVerifier + Send + Sync>>,
    ) -> Self {
        Self {
            transport: Arc::new(transport),
            effect_reconciliation,
            publication_live_verifier,
        }
    }

    fn transport_ref(&self) -> TransportRef<T> {
        TransportRef {
            inner: Arc::clone(&self.transport),
        }
    }

    fn reconciler(&self) -> Option<&dyn EffectReconciliationVerifier> {
        self.effect_reconciliation
            .as_ref()
            .map(|arc| arc.as_ref() as &dyn EffectReconciliationVerifier)
    }

    fn publication_live_verifier(&self) -> Option<&dyn PublicationEffectLiveVerifier> {
        self.publication_live_verifier
            .as_ref()
            .map(|arc| arc.as_ref() as &dyn PublicationEffectLiveVerifier)
    }

    fn timing(&self) -> ClaimTiming {
        self.transport.journal_config().timing()
    }

    fn load_authority(&self) -> Result<AuthoritySnapshot> {
        let history = self.transport.load_trusted_history()?;
        self.transport
            .reduce_loaded_history(&history, self.reconciler())
    }

    pub(crate) fn remote_authority_snapshot(&self) -> Result<AuthoritySnapshot> {
        self.load_authority()
    }

    pub(crate) fn admit_scopes<I, P>(
        &self,
        run_identity: &str,
        activation_nonce: &str,
        scope_paths: I,
    ) -> Result<CoordinationAdmissionResult<CoordinationScopePermit<T>>>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<Path>,
    {
        let owner =
            CoordinationOwnerIdentity::new(run_identity, activation_nonce).context("owner")?;
        let scopes = normalize_coordination_scopes(scope_paths)?;
        self.admit_owner_scopes(owner, scopes)
    }

    fn admit_owner_scopes(
        &self,
        owner: CoordinationOwnerIdentity,
        scopes: Vec<String>,
    ) -> Result<CoordinationAdmissionResult<CoordinationScopePermit<T>>> {
        let request = PendingOperationRequest {
            kind: PendingIntentKind::Claim,
            owner: owner.clone(),
            scopes: Some(scopes),
            predecessor: None,
            effect_id: None,
            release_reason: None,
            reconciliation: None,
            publication_effect: None,
        };
        let (ledger_id, intent) = self.prepare_pending_operation(request)?;
        let send_instant = Instant::now();
        let outcome = self.submit_intent(&ledger_id, intent)?;
        self.finish_scope_mutation(&owner, send_instant, outcome, &ledger_id, true)
    }

    pub(crate) fn heartbeat(
        &self,
        permit: &CoordinationScopePermit<T>,
    ) -> Result<CoordinationAdmissionResult<()>> {
        permit.ensure_live_with_authority(self)?;
        let request = PendingOperationRequest {
            kind: PendingIntentKind::Heartbeat,
            owner: permit.owner().clone(),
            scopes: None,
            predecessor: None,
            effect_id: None,
            release_reason: None,
            reconciliation: None,
            publication_effect: None,
        };
        let (ledger_id, intent) = self.prepare_pending_operation(request)?;
        let send_instant = Instant::now();
        let outcome = self.submit_intent(&ledger_id, intent)?;
        match outcome {
            MutationDispatch::Applied(snapshot) => {
                if !permit.refresh_after_applied(send_instant, &snapshot)? {
                    return Ok(CoordinationAdmissionResult::Refused(
                        CoordinationAdmissionRefusal::LocalWorkDeadlineExpired,
                    ));
                }
                self.clear_pending_intent(&ledger_id)?;
                Ok(CoordinationAdmissionResult::Ready(()))
            }
            MutationDispatch::NotApplied(reason) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteNotApplied { reason },
            )),
            MutationDispatch::Unknown(evidence) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteUnknown { evidence },
            )),
        }
    }

    pub(crate) fn release(
        &self,
        permit: CoordinationScopePermit<T>,
        reason: &str,
    ) -> Result<CoordinationAdmissionResult<()>> {
        permit.ensure_live_with_authority(self)?;
        if permit.has_shared_effect_reservation() {
            return Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::SharedEffectReservationActive,
            ));
        }
        let request = PendingOperationRequest {
            kind: PendingIntentKind::Release,
            owner: permit.owner().clone(),
            scopes: None,
            predecessor: None,
            effect_id: None,
            release_reason: Some(reason.to_string()),
            reconciliation: None,
            publication_effect: None,
        };
        let (ledger_id, intent) = self.prepare_pending_operation(request)?;
        let _send_instant = Instant::now();
        let outcome = self.submit_intent(&ledger_id, intent)?;
        permit.cancel();
        match outcome {
            MutationDispatch::Applied(_) => {
                self.clear_pending_intent(&ledger_id)?;
                self.clear_local_activation(permit.owner())?;
                Ok(CoordinationAdmissionResult::Ready(()))
            }
            MutationDispatch::NotApplied(reason) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteNotApplied { reason },
            )),
            MutationDispatch::Unknown(evidence) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteUnknown { evidence },
            )),
        }
    }

    pub(crate) fn takeover(
        &self,
        predecessor: CoordinationOwnerIdentity,
        run_identity: &str,
        activation_nonce: &str,
        scope_paths: &[PathBuf],
    ) -> Result<CoordinationAdmissionResult<CoordinationScopePermit<T>>> {
        let successor =
            CoordinationOwnerIdentity::new(run_identity, activation_nonce).context("successor")?;
        let scopes = normalize_coordination_scopes(scope_paths)?;
        let request = PendingOperationRequest {
            kind: PendingIntentKind::Takeover,
            owner: successor.clone(),
            scopes: Some(scopes),
            predecessor: Some(predecessor),
            effect_id: None,
            release_reason: None,
            reconciliation: None,
            publication_effect: None,
        };
        let (ledger_id, intent) = self.prepare_pending_operation(request)?;
        let send_instant = Instant::now();
        let outcome = self.submit_intent(&ledger_id, intent)?;
        self.finish_scope_mutation(&successor, send_instant, outcome, &ledger_id, true)
    }

    /// Remote authority inspection only; never mints a work permit.
    pub(crate) fn inspect_remote_authority(
        &self,
        run_identity: &str,
        activation_nonce: &str,
    ) -> Result<CoordinationAdmissionResult<RemoteAuthorityInspection>> {
        let owner =
            CoordinationOwnerIdentity::new(run_identity, activation_nonce).context("owner")?;
        let snapshot = self.load_authority()?;
        match locate_active_owner(&snapshot, &owner) {
            Ok(record) => Ok(CoordinationAdmissionResult::Ready(
                RemoteAuthorityInspection {
                    owner: record.owner().clone(),
                    scopes: record.scopes().to_vec(),
                    locally_authenticated: read_local_activation(
                        self.transport.worktree(),
                        &owner,
                    )?
                    .is_some(),
                },
            )),
            Err(_) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteNotApplied {
                    reason: "owner is not active in remote authority".to_string(),
                },
            )),
        }
    }

    /// Resume work only after this host's durable activation record and a fresh heartbeat CAS.
    pub(crate) fn resume_scope_permit(
        &self,
        run_identity: &str,
        activation_nonce: &str,
    ) -> Result<CoordinationAdmissionResult<CoordinationScopePermit<T>>> {
        let owner =
            CoordinationOwnerIdentity::new(run_identity, activation_nonce).context("owner")?;
        let Some(local) = read_local_activation(self.transport.worktree(), &owner)? else {
            return Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::NotLocallyAuthenticated,
            ));
        };
        if local.scopes.is_empty() {
            bail!("local activation record is malformed");
        }
        let snapshot = self.load_authority()?;
        let record = match locate_active_owner(&snapshot, &owner) {
            Ok(record) => record,
            Err(_) => {
                return Ok(CoordinationAdmissionResult::Refused(
                    CoordinationAdmissionRefusal::RemoteNotApplied {
                        reason: "owner is not active in remote authority".to_string(),
                    },
                ));
            }
        };
        if record.scopes() != local.scopes {
            return Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::PendingIntentSemanticMismatch,
            ));
        }
        let request = PendingOperationRequest {
            kind: PendingIntentKind::Heartbeat,
            owner: owner.clone(),
            scopes: None,
            predecessor: None,
            effect_id: None,
            release_reason: None,
            reconciliation: None,
            publication_effect: None,
        };
        let (ledger_id, intent) = self.prepare_pending_operation(request)?;
        let send_instant = Instant::now();
        let outcome = self.submit_intent(&ledger_id, intent)?;
        match outcome {
            MutationDispatch::Applied(snapshot) => {
                if local_work_deadline_expired(send_instant, self.timing()) {
                    return Ok(CoordinationAdmissionResult::Refused(
                        CoordinationAdmissionRefusal::LocalWorkDeadlineExpired,
                    ));
                }
                let record = locate_active_owner(&snapshot, &owner)?;
                self.clear_pending_intent(&ledger_id)?;
                let permit = CoordinationScopePermit::from_replay(
                    self.transport_ref(),
                    record,
                    send_instant,
                    self.timing(),
                )?;
                Ok(CoordinationAdmissionResult::Ready(permit))
            }
            MutationDispatch::NotApplied(reason) => {
                self.clear_pending_intent(&ledger_id)?;
                Ok(CoordinationAdmissionResult::Refused(
                    CoordinationAdmissionRefusal::RemoteNotApplied { reason },
                ))
            }
            MutationDispatch::Unknown(evidence) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteUnknown { evidence },
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn reserve_shared_effect(
        &self,
        permit: &CoordinationScopePermit<T>,
        effect_id: &str,
    ) -> Result<CoordinationAdmissionResult<CoordinationSharedEffectPermit>> {
        permit.ensure_live_with_authority(self)?;
        let request = PendingOperationRequest {
            kind: PendingIntentKind::EffectReserve {
                effect_id: effect_id.to_string(),
            },
            owner: permit.owner().clone(),
            scopes: None,
            predecessor: None,
            effect_id: Some(effect_id.to_string()),
            release_reason: None,
            reconciliation: None,
            publication_effect: None,
        };
        let (ledger_id, intent) = self.prepare_pending_operation(request)?;
        let send_instant = Instant::now();
        let outcome = self.submit_intent(&ledger_id, intent)?;
        match outcome {
            MutationDispatch::Applied(snapshot) => {
                if !permit.refresh_after_applied(send_instant, &snapshot)? {
                    return Ok(CoordinationAdmissionResult::Refused(
                        CoordinationAdmissionRefusal::LocalWorkDeadlineExpired,
                    ));
                }
                let reservation = snapshot
                    .pending_reservations()
                    .iter()
                    .find(|reserve| {
                        reserve.effect_id() == effect_id && reserve.owner() == permit.owner()
                    })
                    .context("effect reserve applied without a matching pending reservation")?;
                permit.mark_shared_effect_reserved();
                self.clear_pending_intent(&ledger_id)?;
                Ok(CoordinationAdmissionResult::Ready(
                    CoordinationSharedEffectPermit {
                        owner: permit.owner().clone(),
                        effect_id: effect_id.to_string(),
                        reserve_event_nonce: reservation.reserve_event_nonce().to_string(),
                        publication_effect: reservation.publication_effect().cloned(),
                    },
                ))
            }
            MutationDispatch::NotApplied(reason) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteNotApplied { reason },
            )),
            MutationDispatch::Unknown(evidence) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteUnknown { evidence },
            )),
        }
    }

    pub(crate) fn reserve_bound_shared_effect(
        &self,
        permit: &CoordinationScopePermit<T>,
        publication_effect: PublicationEffectDescriptorV1,
    ) -> Result<CoordinationAdmissionResult<CoordinationSharedEffectPermit>> {
        permit.ensure_live_with_authority(self)?;
        publication_effect.validate()?;
        let effect_id = publication_effect.effect_id().to_string();
        let request = PendingOperationRequest {
            kind: PendingIntentKind::EffectReserve {
                effect_id: effect_id.clone(),
            },
            owner: permit.owner().clone(),
            scopes: None,
            predecessor: None,
            effect_id: Some(effect_id.clone()),
            release_reason: None,
            reconciliation: None,
            publication_effect: Some(publication_effect),
        };
        let (ledger_id, intent) = self.prepare_pending_operation(request)?;
        let send_instant = Instant::now();
        let outcome = self.submit_intent(&ledger_id, intent)?;
        match outcome {
            MutationDispatch::Applied(snapshot) => {
                if !permit.refresh_after_applied(send_instant, &snapshot)? {
                    return Ok(CoordinationAdmissionResult::Refused(
                        CoordinationAdmissionRefusal::LocalWorkDeadlineExpired,
                    ));
                }
                let reservation = snapshot
                    .pending_reservations()
                    .iter()
                    .find(|reserve| {
                        reserve.effect_id() == effect_id && reserve.owner() == permit.owner()
                    })
                    .context(
                        "bound effect reserve applied without a matching pending reservation",
                    )?;
                if reservation.publication_effect().is_none() {
                    bail!("bound effect reserve applied without a publication descriptor");
                }
                permit.mark_shared_effect_reserved();
                self.clear_pending_intent(&ledger_id)?;
                Ok(CoordinationAdmissionResult::Ready(
                    CoordinationSharedEffectPermit {
                        owner: permit.owner().clone(),
                        effect_id,
                        reserve_event_nonce: reservation.reserve_event_nonce().to_string(),
                        publication_effect: reservation.publication_effect().cloned(),
                    },
                ))
            }
            MutationDispatch::NotApplied(reason) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteNotApplied { reason },
            )),
            MutationDispatch::Unknown(evidence) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteUnknown { evidence },
            )),
        }
    }

    #[cfg(test)]
    pub(crate) fn complete_shared_effect(
        &self,
        permit: &CoordinationScopePermit<T>,
        shared: CoordinationSharedEffectPermit,
        reconciliation: EffectReconciliationReceipt,
    ) -> Result<CoordinationAdmissionResult<()>> {
        if effect_reconciliation_is_bound(&reconciliation) {
            return Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::EffectReconciliationRejected,
            ));
        }
        permit.ensure_live_with_authority(self)?;
        shared.ensure_live_reservation(self, permit.owner())?;
        let verifier = self
            .reconciler()
            .context("effect completion requires a configured EffectReconciliationVerifier")?;
        if !verifier.verify_reconciliation(permit.owner(), &shared.effect_id, &reconciliation) {
            return Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::EffectReconciliationRejected,
            ));
        }
        let request = PendingOperationRequest {
            kind: PendingIntentKind::EffectComplete {
                effect_id: shared.effect_id.clone(),
            },
            owner: permit.owner().clone(),
            scopes: None,
            predecessor: None,
            effect_id: Some(shared.effect_id.clone()),
            release_reason: None,
            reconciliation: Some(reconciliation),
            publication_effect: None,
        };
        let (ledger_id, intent) = self.prepare_pending_operation(request)?;
        let send_instant = Instant::now();
        let outcome = self.submit_intent(&ledger_id, intent)?;
        match outcome {
            MutationDispatch::Applied(snapshot) => {
                if !permit.refresh_after_applied(send_instant, &snapshot)? {
                    return Ok(CoordinationAdmissionResult::Refused(
                        CoordinationAdmissionRefusal::LocalWorkDeadlineExpired,
                    ));
                }
                if snapshot
                    .pending_reservations()
                    .iter()
                    .any(|reserve| reserve.effect_id() == shared.effect_id)
                {
                    bail!("effect completion left a pending reservation");
                }
                permit.clear_shared_effect_reservation();
                self.clear_pending_intent(&ledger_id)?;
                Ok(CoordinationAdmissionResult::Ready(()))
            }
            MutationDispatch::NotApplied(reason) => {
                self.clear_pending_intent(&ledger_id)?;
                Ok(CoordinationAdmissionResult::Refused(
                    CoordinationAdmissionRefusal::RemoteNotApplied { reason },
                ))
            }
            MutationDispatch::Unknown(evidence) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteUnknown { evidence },
            )),
        }
    }

    pub(crate) fn complete_bound_shared_effect(
        &self,
        permit: &CoordinationScopePermit<T>,
        shared: CoordinationSharedEffectPermit,
        reconciliation: EffectReconciliationReceipt,
    ) -> Result<CoordinationAdmissionResult<()>> {
        if !effect_reconciliation_is_bound(&reconciliation) {
            return Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::EffectReconciliationRejected,
            ));
        }
        permit.ensure_live_with_authority(self)?;
        shared.ensure_live_reservation(self, permit.owner())?;
        let descriptor = shared
            .publication_effect
            .as_ref()
            .context("bound effect completion requires a bound shared effect permit")?;
        match verify_bound_effect_complete_live(
            LiveEffectVerificationContext::admission_live(),
            self.publication_live_verifier(),
            permit.owner(),
            &shared.reserve_event_nonce,
            descriptor,
            &reconciliation,
        ) {
            Ok(PublicationEffectLiveVerification::Verified) => {}
            Ok(PublicationEffectLiveVerification::Refused) => {
                return Ok(CoordinationAdmissionResult::Refused(
                    CoordinationAdmissionRefusal::EffectReconciliationRejected,
                ));
            }
            Ok(PublicationEffectLiveVerification::Unknown) => {
                return Ok(CoordinationAdmissionResult::Refused(
                    CoordinationAdmissionRefusal::RemoteUnknown {
                        evidence: "bound publication effect verification is unknown".to_string(),
                    },
                ));
            }
            Err(_) => {
                return Ok(CoordinationAdmissionResult::Refused(
                    CoordinationAdmissionRefusal::EffectReconciliationRejected,
                ));
            }
        }
        let request = PendingOperationRequest {
            kind: PendingIntentKind::EffectComplete {
                effect_id: shared.effect_id.clone(),
            },
            owner: permit.owner().clone(),
            scopes: None,
            predecessor: None,
            effect_id: Some(shared.effect_id.clone()),
            release_reason: None,
            reconciliation: Some(reconciliation),
            publication_effect: None,
        };
        let (ledger_id, intent) = self.prepare_pending_operation(request)?;
        let send_instant = Instant::now();
        let outcome = self.submit_intent(&ledger_id, intent)?;
        match outcome {
            MutationDispatch::Applied(snapshot) => {
                if !permit.refresh_after_applied(send_instant, &snapshot)? {
                    return Ok(CoordinationAdmissionResult::Refused(
                        CoordinationAdmissionRefusal::LocalWorkDeadlineExpired,
                    ));
                }
                if snapshot
                    .pending_reservations()
                    .iter()
                    .any(|reserve| reserve.effect_id() == shared.effect_id)
                {
                    bail!("effect completion left a pending reservation");
                }
                permit.clear_shared_effect_reservation();
                self.clear_pending_intent(&ledger_id)?;
                Ok(CoordinationAdmissionResult::Ready(()))
            }
            MutationDispatch::NotApplied(reason) => {
                self.clear_pending_intent(&ledger_id)?;
                Ok(CoordinationAdmissionResult::Refused(
                    CoordinationAdmissionRefusal::RemoteNotApplied { reason },
                ))
            }
            MutationDispatch::Unknown(evidence) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteUnknown { evidence },
            )),
        }
    }

    fn finish_scope_mutation(
        &self,
        owner: &CoordinationOwnerIdentity,
        send_instant: Instant,
        outcome: MutationDispatch,
        ledger_id: &str,
        record_local_activation: bool,
    ) -> Result<CoordinationAdmissionResult<CoordinationScopePermit<T>>> {
        match outcome {
            MutationDispatch::Applied(snapshot) => {
                if local_work_deadline_expired(send_instant, self.timing()) {
                    return Ok(CoordinationAdmissionResult::Refused(
                        CoordinationAdmissionRefusal::LocalWorkDeadlineExpired,
                    ));
                }
                let record = locate_active_owner(&snapshot, owner)?;
                self.clear_pending_intent(ledger_id)?;
                if record_local_activation {
                    write_local_activation(self.transport.worktree(), owner, record.scopes())?;
                }
                let permit = CoordinationScopePermit::from_replay(
                    self.transport_ref(),
                    record,
                    send_instant,
                    self.timing(),
                )?;
                Ok(CoordinationAdmissionResult::Ready(permit))
            }
            MutationDispatch::NotApplied(reason) => {
                self.clear_pending_intent(ledger_id)?;
                Ok(CoordinationAdmissionResult::Refused(
                    CoordinationAdmissionRefusal::RemoteNotApplied { reason },
                ))
            }
            MutationDispatch::Unknown(evidence) => Ok(CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteUnknown { evidence },
            )),
        }
    }

    fn submit_intent(
        &self,
        _pending_key: &str,
        intent: CoordinationIntent,
    ) -> Result<MutationDispatch> {
        let author = self.transport.approved_actor().clone();
        let outcome = self
            .transport
            .apply_authorized_intent(intent, author, self.reconciler())
            .context("coordination admission transport apply")?;
        match outcome {
            CoordinationMutationOutcome::Applied { snapshot, .. } => {
                Ok(MutationDispatch::Applied(snapshot))
            }
            CoordinationMutationOutcome::NotApplied { reason } => {
                Ok(MutationDispatch::NotApplied(reason))
            }
            CoordinationMutationOutcome::Unknown { evidence } => {
                Ok(MutationDispatch::Unknown(evidence))
            }
        }
    }

    fn current_head_oid(&self) -> Result<String> {
        let history = self.transport.load_trusted_history()?;
        Ok(history.head_oid().map(str::to_string).unwrap_or_else(|| {
            self.transport
                .journal_config()
                .anchor_commit_oid()
                .to_string()
        }))
    }

    fn prepare_pending_operation(
        &self,
        request: PendingOperationRequest,
    ) -> Result<(String, CoordinationIntent)> {
        mutate_pending_intent_wal(self.transport.worktree(), |session| {
            let (ledger_id, event_nonce) = match &request.kind {
                PendingIntentKind::Heartbeat => {
                    let sequence = session.next_sequence()?;
                    let nonce =
                        operation_nonce_from_sequence(&request.owner, &request.kind, sequence)?;
                    (heartbeat_ledger_id(&request.owner, &nonce), nonce)
                }
                _ => {
                    let ledger_id = singleton_operation_ledger_id(&request)?;
                    let sequence = session.next_sequence()?;
                    let nonce =
                        operation_nonce_from_sequence(&request.owner, &request.kind, sequence)?;
                    (ledger_id, nonce)
                }
            };
            if let Some(record) = session.read_replayable_pending_record(&ledger_id)? {
                verify_pending_semantics(&record, &request)?;
                let intent = intent_from_pending_record(&record)?;
                return Ok((ledger_id, intent));
            }
            let parent = self.current_head_oid()?;
            let intent = build_intent_from_request(
                self.transport.journal_config().anchor_item(),
                &request,
                &event_nonce,
                &parent,
                self.timing(),
            )?;
            let intent_body = intent.render()?;
            let record = PendingIntentRecord {
                version: PENDING_INTENT_FORMAT_VERSION,
                intent_body,
                owner: request.owner.clone(),
                kind: request.kind.clone(),
                scopes: request.scopes.clone(),
                predecessor: request.predecessor.clone(),
                effect_id: request.effect_id.clone(),
                release_reason: request.release_reason.clone(),
                publication_effect: request.publication_effect.clone(),
            };
            session.write_planned(&ledger_id, &record)?;
            Ok((ledger_id, intent))
        })
    }

    fn clear_pending_intent(&self, effect_id: &str) -> Result<()> {
        clear_pending_intent(self.transport.worktree(), effect_id)
    }

    fn clear_local_activation(&self, owner: &CoordinationOwnerIdentity) -> Result<()> {
        clear_local_activation(self.transport.worktree(), owner)
    }
}

impl<R: CoordinationGithubRunner> CoordinationAdmissionService<CoordinationGithubTransport<R>> {
    pub(crate) fn from_github(
        config: CoordinationGithubAdapterConfig,
        runner: R,
        effect_reconciliation: Option<Arc<dyn EffectReconciliationVerifier + Send + Sync>>,
        publication_live_verifier: Option<Arc<dyn PublicationEffectLiveVerifier + Send + Sync>>,
    ) -> Self {
        CoordinationAdmissionService::new(
            CoordinationGithubTransport::new(config, runner),
            effect_reconciliation,
            publication_live_verifier,
        )
    }
}

impl<T: CoordinationAdmissionTransport> CoordinationAdmissionService<T> {
    pub(crate) fn claim_timing(&self) -> ClaimTiming {
        self.timing()
    }

    pub(crate) fn worktree(&self) -> &Path {
        self.transport.worktree()
    }
}

/// Mint a durable activation nonce for a new remote scope claim (not derived from claim token or wall clock).
pub(crate) fn mint_activation_nonce(worktree: &Path, run_identity: &str) -> Result<String> {
    mutate_pending_intent_wal(worktree, |session| {
        let sequence = session.next_sequence()?;
        let digest =
            sha256_hex(format!("sync-store-activation:{run_identity}:claim:{sequence}").as_bytes());
        Ok(format!("act-{}", &digest[..24]))
    })
}

pub(crate) struct RemoteAuthorityInspection {
    owner: CoordinationOwnerIdentity,
    scopes: Vec<String>,
    locally_authenticated: bool,
}

impl RemoteAuthorityInspection {
    pub(crate) fn owner(&self) -> &CoordinationOwnerIdentity {
        &self.owner
    }

    pub(crate) fn scopes(&self) -> &[String] {
        &self.scopes
    }

    pub(crate) fn locally_authenticated(&self) -> bool {
        self.locally_authenticated
    }
}

/// Opaque disposable scope-work permit minted only from applied remote authority.
pub(crate) struct CoordinationScopePermit<T: CoordinationAdmissionTransport> {
    transport: TransportRef<T>,
    owner: CoordinationOwnerIdentity,
    scopes: Vec<String>,
    timing: ClaimTiming,
    cancellation: ProcessCancellation,
    deadline_state: Arc<PermitDeadlineState>,
    shared_effect_reserved: AtomicBool,
    stopped: AtomicBool,
    guard: PermitDeadlineGuard,
}

struct TransportRef<T: CoordinationAdmissionTransport> {
    inner: Arc<T>,
}

impl<T: CoordinationAdmissionTransport> Clone for TransportRef<T> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<T: CoordinationAdmissionTransport> CoordinationAdmissionTransport for TransportRef<T> {
    fn journal_config(&self) -> &CoordinationJournalConfig {
        self.inner.journal_config()
    }

    fn approved_actor(&self) -> &ForgeActor {
        self.inner.approved_actor()
    }

    fn worktree(&self) -> &Path {
        self.inner.worktree()
    }

    fn load_trusted_history(&self) -> Result<TrustedFiniteJournalHistory> {
        self.inner.load_trusted_history()
    }

    fn reduce_loaded_history(
        &self,
        history: &TrustedFiniteJournalHistory,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<AuthoritySnapshot> {
        self.inner
            .reduce_loaded_history(history, effect_reconciliation)
    }

    fn apply_authorized_intent(
        &self,
        intent: CoordinationIntent,
        comment_author: ForgeActor,
        effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
    ) -> Result<CoordinationMutationOutcome> {
        self.inner
            .apply_authorized_intent(intent, comment_author, effect_reconciliation)
    }
}

/// Opaque shared-effect reservation bound to one live remote reservation.
pub(crate) struct CoordinationSharedEffectPermit {
    owner: CoordinationOwnerIdentity,
    effect_id: String,
    reserve_event_nonce: String,
    publication_effect: Option<PublicationEffectDescriptorV1>,
}

impl CoordinationSharedEffectPermit {
    pub(crate) fn reserve_event_nonce(&self) -> &str {
        &self.reserve_event_nonce
    }

    pub(crate) fn publication_effect(&self) -> Option<&PublicationEffectDescriptorV1> {
        self.publication_effect.as_ref()
    }

    fn ensure_live_reservation<T: CoordinationAdmissionTransport>(
        &self,
        service: &CoordinationAdmissionService<T>,
        scope_owner: &CoordinationOwnerIdentity,
    ) -> Result<()> {
        if &self.owner != scope_owner {
            bail!("shared effect permit owner does not match the scope permit owner");
        }
        let snapshot = service.load_authority()?;
        let live = snapshot.pending_reservations().iter().any(|reserve| {
            reserve.owner() == &self.owner
                && reserve.effect_id() == self.effect_id
                && reserve.reserve_event_nonce() == self.reserve_event_nonce
        });
        if !live {
            bail!("shared effect reservation is not live in remote authority");
        }
        Ok(())
    }
}

impl<T: CoordinationAdmissionTransport> CoordinationScopePermit<T> {
    fn from_replay(
        transport: TransportRef<T>,
        record: &ActiveOwnerRecord,
        send_instant: Instant,
        timing: ClaimTiming,
    ) -> Result<Self> {
        let cancellation = ProcessCancellation::new();
        let deadline_state = Arc::new(PermitDeadlineState::new(work_deadline_instant(
            send_instant,
            timing,
        )));
        let guard = PermitDeadlineGuard::spawn(Arc::clone(&deadline_state), cancellation.clone());
        Ok(Self {
            transport,
            owner: record.owner().clone(),
            scopes: record.scopes().to_vec(),
            timing,
            cancellation,
            deadline_state,
            shared_effect_reserved: AtomicBool::new(false),
            stopped: AtomicBool::new(false),
            guard,
        })
    }

    pub(crate) fn owner(&self) -> &CoordinationOwnerIdentity {
        &self.owner
    }

    pub(crate) fn cancellation(&self) -> &ProcessCancellation {
        &self.cancellation
    }

    #[cfg(test)]
    fn local_work_deadline(&self) -> Result<Instant> {
        self.deadline_state.deadline()
    }

    fn ensure_live(&self) -> Result<()> {
        let _ = self.transport.worktree();
        if self.stopped.load(Ordering::Acquire) || self.cancellation.is_cancelled() {
            bail!("coordination scope permit is no longer live");
        }
        if Instant::now() >= self.deadline_state.deadline()? {
            self.cancel();
            bail!("coordination scope permit local work deadline expired");
        }
        Ok(())
    }

    fn ensure_live_with_authority<U: CoordinationAdmissionTransport>(
        &self,
        service: &CoordinationAdmissionService<U>,
    ) -> Result<()> {
        self.ensure_live()?;
        let snapshot = service.load_authority()?;
        if !still_authoritative(&snapshot, &self.owner, &self.scopes) {
            self.cancel();
            bail!("coordination authority was lost before mutation");
        }
        Ok(())
    }

    fn refresh_after_applied(
        &self,
        send_instant: Instant,
        snapshot: &AuthoritySnapshot,
    ) -> Result<bool> {
        if local_work_deadline_expired(send_instant, self.timing) {
            self.cancel();
            return Ok(false);
        }
        if locate_active_owner(snapshot, &self.owner).is_err() {
            self.cancel();
            bail!("coordination authority was lost after mutation");
        }
        self.deadline_state
            .set_deadline(work_deadline_instant(send_instant, self.timing));
        Ok(true)
    }

    fn mark_shared_effect_reserved(&self) {
        self.shared_effect_reserved.store(true, Ordering::Release);
    }

    fn clear_shared_effect_reservation(&self) {
        self.shared_effect_reserved.store(false, Ordering::Release);
    }

    fn has_shared_effect_reservation(&self) -> bool {
        self.shared_effect_reserved.load(Ordering::Acquire)
    }

    fn cancel(&self) {
        self.stopped.store(true, Ordering::Release);
        self.cancellation.cancel();
    }
}

impl<T: CoordinationAdmissionTransport> Drop for CoordinationScopePermit<T> {
    fn drop(&mut self) {
        self.guard.stop();
        self.cancel();
    }
}

struct PermitDeadlineState {
    stop: AtomicBool,
    gate: Mutex<()>,
    cv: Condvar,
    deadline: Mutex<Instant>,
}

impl PermitDeadlineState {
    fn new(deadline: Instant) -> Self {
        Self {
            stop: AtomicBool::new(false),
            gate: Mutex::new(()),
            cv: Condvar::new(),
            deadline: Mutex::new(deadline),
        }
    }

    fn deadline(&self) -> Result<Instant> {
        let guard = self
            .deadline
            .lock()
            .map_err(|_| anyhow::anyhow!("coordination permit deadline lock poisoned"))?;
        Ok(*guard)
    }

    fn set_deadline(&self, deadline: Instant) {
        if let Ok(mut guard) = self.deadline.lock() {
            *guard = deadline;
            self.cv.notify_all();
        }
    }

    fn stop(&self) {
        self.stop.store(true, Ordering::Release);
        self.cv.notify_all();
    }
}

struct PermitDeadlineGuard {
    state: Arc<PermitDeadlineState>,
    thread: Mutex<Option<JoinHandle<()>>>,
}

impl PermitDeadlineGuard {
    fn spawn(state: Arc<PermitDeadlineState>, cancellation: ProcessCancellation) -> Self {
        let thread_state = Arc::clone(&state);
        let thread = thread::spawn(move || {
            while !thread_state.stop.load(Ordering::Acquire) && !cancellation.is_cancelled() {
                let deadline = match thread_state.deadline() {
                    Ok(value) => value,
                    Err(_) => {
                        cancellation.cancel();
                        break;
                    }
                };
                let now = Instant::now();
                if now >= deadline {
                    cancellation.cancel();
                    break;
                }
                let wait = deadline.saturating_duration_since(now);
                let gate = match thread_state.gate.lock() {
                    Ok(guard) => guard,
                    Err(error) => {
                        cancellation.cancel();
                        drop(error.into_inner());
                        break;
                    }
                };
                let wait_result = thread_state
                    .cv
                    .wait_timeout_while(gate, wait, |_| {
                        !thread_state.stop.load(Ordering::Acquire) && !cancellation.is_cancelled()
                    })
                    .map(|(guard, _)| guard);
                if wait_result.is_err() {
                    cancellation.cancel();
                    break;
                }
            }
        });
        Self {
            state,
            thread: Mutex::new(Some(thread)),
        }
    }

    fn stop(&self) {
        self.state.stop();
        let handle = self
            .thread
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take();
        if let Some(handle) = handle {
            let _ = handle.join();
        }
    }
}

impl Drop for PermitDeadlineGuard {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug)]
pub(crate) enum CoordinationAdmissionResult<T> {
    Ready(T),
    Refused(CoordinationAdmissionRefusal),
}

#[derive(Debug)]
pub(crate) enum CoordinationAdmissionRefusal {
    RemoteNotApplied { reason: String },
    RemoteUnknown { evidence: String },
    LocalWorkDeadlineExpired,
    SharedEffectReservationActive,
    EffectReconciliationRejected,
    PendingIntentSemanticMismatch,
    NotLocallyAuthenticated,
}

pub(crate) fn format_coordination_admission_refusal(
    reason: &CoordinationAdmissionRefusal,
) -> String {
    match reason {
        CoordinationAdmissionRefusal::RemoteNotApplied { reason } => {
            format!("RemoteNotApplied: remote mutation was not applied: {reason}")
        }
        CoordinationAdmissionRefusal::RemoteUnknown { evidence } => {
            format!("RemoteUnknown: remote mutation outcome is unknown: {evidence}")
        }
        CoordinationAdmissionRefusal::LocalWorkDeadlineExpired => {
            "LocalWorkDeadlineExpired: local work deadline expired before remote authority refreshed".to_string()
        }
        CoordinationAdmissionRefusal::SharedEffectReservationActive => {
            "SharedEffectReservationActive: remote scope release refused while shared publication effect is reserved".to_string()
        }
        CoordinationAdmissionRefusal::EffectReconciliationRejected => {
            "EffectReconciliationRejected: publication effect reconciliation was rejected".to_string()
        }
        CoordinationAdmissionRefusal::PendingIntentSemanticMismatch => {
            "PendingIntentSemanticMismatch: pending intent semantic mismatch".to_string()
        }
        CoordinationAdmissionRefusal::NotLocallyAuthenticated => {
            "NotLocallyAuthenticated: remote owner is not locally authenticated on this host".to_string()
        }
    }
}

enum MutationDispatch {
    Applied(AuthoritySnapshot),
    NotApplied(String),
    Unknown(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum PendingIntentKind {
    Claim,
    Heartbeat,
    Takeover,
    Release,
    EffectReserve { effect_id: String },
    EffectComplete { effect_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PendingOperationRequest {
    kind: PendingIntentKind,
    owner: CoordinationOwnerIdentity,
    scopes: Option<Vec<String>>,
    predecessor: Option<CoordinationOwnerIdentity>,
    effect_id: Option<String>,
    release_reason: Option<String>,
    reconciliation: Option<EffectReconciliationReceipt>,
    publication_effect: Option<PublicationEffectDescriptorV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct PendingIntentRecord {
    version: u32,
    intent_body: String,
    owner: CoordinationOwnerIdentity,
    kind: PendingIntentKind,
    scopes: Option<Vec<String>>,
    predecessor: Option<CoordinationOwnerIdentity>,
    effect_id: Option<String>,
    release_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    publication_effect: Option<PublicationEffectDescriptorV1>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct LocalActivationRecord {
    version: u32,
    owner: CoordinationOwnerIdentity,
    scopes: Vec<String>,
}

fn singleton_operation_ledger_id(request: &PendingOperationRequest) -> Result<String> {
    Ok(match &request.kind {
        PendingIntentKind::Claim => singleton_ledger_id(&request.owner, "claim"),
        PendingIntentKind::Takeover => singleton_ledger_id(&request.owner, "takeover"),
        PendingIntentKind::Release => singleton_ledger_id(&request.owner, "release"),
        PendingIntentKind::EffectReserve { effect_id } => format!(
            "pending:{}:{}:reserve:{}",
            request.owner.run_identity(),
            request.owner.activation_nonce(),
            effect_id
        ),
        PendingIntentKind::EffectComplete { effect_id } => format!(
            "pending:{}:{}:complete:{}",
            request.owner.run_identity(),
            request.owner.activation_nonce(),
            effect_id
        ),
        PendingIntentKind::Heartbeat => {
            bail!("heartbeat ledger ids are unique per operation nonce")
        }
    })
}

fn singleton_ledger_id(owner: &CoordinationOwnerIdentity, label: &str) -> String {
    format!(
        "pending:{}:{}:{}",
        owner.run_identity(),
        owner.activation_nonce(),
        label
    )
}

fn heartbeat_ledger_id(owner: &CoordinationOwnerIdentity, operation_nonce: &str) -> String {
    format!(
        "pending:{}:{}:heartbeat:{}",
        owner.run_identity(),
        owner.activation_nonce(),
        operation_nonce
    )
}

pub(crate) fn worktree_has_planned_coordination_pending_intents(worktree: &Path) -> Result<bool> {
    let authenticator = pending_intent_authenticator(worktree)?;
    match EffectWal::<DefaultEffectWalSpec>::open_when_initialized(
        authenticator,
        PENDING_INTENT_LEDGER_LOGICAL,
    )? {
        OpenInitializedEffectWal::NeverInitialized => Ok(false),
        OpenInitializedEffectWal::Open(wal) => Ok(effect_wal_has_nonterminal_operations(&wal)),
    }
}

fn pending_intent_authenticator(worktree: &Path) -> Result<RepositoryAuthenticator> {
    repository_auth_writer(worktree)?
        .into_authenticator()
        .context("coordination pending intent authenticator")
}

fn local_activation_authenticator(worktree: &Path) -> Result<RepositoryAuthenticator> {
    repository_auth_writer(worktree)?
        .into_authenticator()
        .context("coordination local activation authenticator")
}

fn operation_nonce_from_sequence(
    owner: &CoordinationOwnerIdentity,
    kind: &PendingIntentKind,
    sequence: u64,
) -> Result<String> {
    let digest = sha256_hex(
        format!(
            "{}:{}:{}:{}",
            owner.run_identity(),
            owner.activation_nonce(),
            serde_json::to_string(kind)?,
            sequence
        )
        .as_bytes(),
    );
    Ok(format!("evt-{}", &digest[..32]))
}

struct PendingIntentWalSession {
    wal: Option<Box<CoordinationAdmissionEffectWal>>,
    worktree: PathBuf,
}

impl PendingIntentWalSession {
    fn open(worktree: &Path) -> Result<Self> {
        let auth = pending_intent_authenticator(worktree)?;
        let wal = match EffectWal::<DefaultEffectWalSpec>::open_when_initialized(
            auth,
            PENDING_INTENT_LEDGER_LOGICAL,
        )? {
            OpenInitializedEffectWal::NeverInitialized => None,
            OpenInitializedEffectWal::Open(wal) => Some(wal),
        };
        Ok(Self {
            wal,
            worktree: worktree.to_path_buf(),
        })
    }

    fn fresh_authenticator(&self) -> Result<RepositoryAuthenticator> {
        pending_intent_authenticator(&self.worktree)
    }

    fn next_sequence(&self) -> Result<u64> {
        match &self.wal {
            None => Ok(1),
            Some(wal) => wal.next_event_sequence(),
        }
    }

    fn read_replayable_pending_record(
        &self,
        effect_id: &str,
    ) -> Result<Option<PendingIntentRecord>> {
        let Some(wal) = &self.wal else {
            return Ok(None);
        };
        match wal.phase(effect_id) {
            None | Some(EffectPhase::Completed) => Ok(None),
            Some(EffectPhase::Planned) => {
                let record = pending_record_from_wal(wal, effect_id)?;
                Ok(Some(record))
            }
            Some(phase) => bail!(
                "pending coordination intent {effect_id} is in non-replayable phase {phase:?}"
            ),
        }
    }

    fn write_planned(&mut self, effect_id: &str, record: &PendingIntentRecord) -> Result<()> {
        if let Some(wal) = &mut self.wal {
            match wal.phase(effect_id) {
                None => wal.planned(effect_id, record)?,
                Some(EffectPhase::Planned) => {}
                Some(phase) => {
                    bail!(
                        "pending coordination intent {effect_id} already exists in phase {phase:?}"
                    );
                }
            }
            return Ok(());
        }
        let wal = EffectWal::create_planned(
            self.fresh_authenticator()?,
            PENDING_INTENT_LEDGER_LOGICAL,
            effect_id,
            record,
        )?;
        self.wal = Some(Box::new(wal));
        Ok(())
    }
}

fn mutate_pending_intent_wal<R>(
    worktree: &Path,
    f: impl FnOnce(&mut PendingIntentWalSession) -> Result<R>,
) -> Result<R> {
    let mut session = PendingIntentWalSession::open(worktree)?;
    f(&mut session)
}

fn pending_record_from_wal(
    wal: &CoordinationAdmissionEffectWal,
    effect_id: &str,
) -> Result<PendingIntentRecord> {
    let event = wal
        .events()
        .iter()
        .rev()
        .find(|event| event.effect_id == effect_id)
        .context("pending coordination intent ledger omitted its latest event")?;
    let record: PendingIntentRecord =
        serde_json::from_value(event.data.clone()).context("pending intent record is malformed")?;
    if record.intent_body.is_empty()
        || (record.version != PENDING_INTENT_FORMAT_VERSION
            && record.version != PENDING_INTENT_LEGACY_FORMAT_VERSION)
    {
        bail!("pending coordination intent record is not a replayable planned operation");
    }
    Ok(record)
}

fn build_intent_from_request(
    item: &super::forge_transport::ForgeItem,
    request: &PendingOperationRequest,
    event_nonce: &str,
    parent: &str,
    timing: ClaimTiming,
) -> Result<CoordinationIntent> {
    match &request.kind {
        PendingIntentKind::Claim => CoordinationIntent::claim(
            item,
            event_nonce,
            parent,
            request.owner.clone(),
            request.scopes.clone().context("claim requires scopes")?,
            timing,
        ),
        PendingIntentKind::Heartbeat => {
            CoordinationIntent::heartbeat(item, event_nonce, parent, request.owner.clone())
        }
        PendingIntentKind::Takeover => CoordinationIntent::takeover(
            item,
            event_nonce,
            parent,
            request.owner.clone(),
            request
                .predecessor
                .clone()
                .context("takeover requires predecessor")?,
            request.scopes.clone().context("takeover requires scopes")?,
            timing,
        ),
        PendingIntentKind::Release => CoordinationIntent::release(
            item,
            event_nonce,
            parent,
            request.owner.clone(),
            request
                .release_reason
                .as_deref()
                .context("release requires reason")?,
        ),
        PendingIntentKind::EffectReserve { effect_id } => {
            if let Some(descriptor) = &request.publication_effect {
                CoordinationIntent::effect_reserve_bound(
                    item,
                    event_nonce,
                    parent,
                    request.owner.clone(),
                    descriptor.clone(),
                )
            } else {
                CoordinationIntent::effect_reserve(
                    item,
                    event_nonce,
                    parent,
                    request.owner.clone(),
                    effect_id,
                )
            }
        }
        PendingIntentKind::EffectComplete { effect_id } => {
            let reconciliation = request
                .reconciliation
                .clone()
                .context("effect completion requires reconciliation material")?;
            CoordinationIntent::effect_complete(
                item,
                event_nonce,
                parent,
                request.owner.clone(),
                effect_id,
                reconciliation,
            )
        }
    }
}

fn intent_from_pending_record(record: &PendingIntentRecord) -> Result<CoordinationIntent> {
    CoordinationIntent::parse(&record.intent_body)?
        .context("stored pending intent body is not a coordination intent")
}

fn verify_pending_semantics(
    record: &PendingIntentRecord,
    request: &PendingOperationRequest,
) -> Result<()> {
    if record.owner != request.owner || record.kind != request.kind {
        bail!("pending coordination intent record does not match the current request");
    }
    if record.scopes != request.scopes
        || record.predecessor != request.predecessor
        || record.effect_id != request.effect_id
        || record.release_reason != request.release_reason
        || record.publication_effect != request.publication_effect
    {
        return Err(PendingIntentSemanticMismatch.into());
    }
    Ok(())
}

#[derive(Debug)]
struct PendingIntentSemanticMismatch;

impl std::fmt::Display for PendingIntentSemanticMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("pending coordination intent semantics do not match the current request")
    }
}

impl std::error::Error for PendingIntentSemanticMismatch {}

#[cfg(test)]
fn write_pending_intent(
    worktree: &Path,
    effect_id: &str,
    record: &PendingIntentRecord,
) -> Result<()> {
    mutate_pending_intent_wal(worktree, |session| session.write_planned(effect_id, record))
}

fn read_pending_intent(worktree: &Path, effect_id: &str) -> Result<Option<PendingIntentRecord>> {
    let authenticator = pending_intent_authenticator(worktree)?;
    match EffectWal::<DefaultEffectWalSpec>::open_when_initialized(
        authenticator,
        PENDING_INTENT_LEDGER_LOGICAL,
    )? {
        OpenInitializedEffectWal::NeverInitialized => Ok(None),
        OpenInitializedEffectWal::Open(wal) => match wal.phase(effect_id) {
            None | Some(EffectPhase::Completed) => Ok(None),
            Some(EffectPhase::Planned) => Ok(Some(pending_record_from_wal(&wal, effect_id)?)),
            Some(phase) => bail!(
                "pending coordination intent {effect_id} is in non-replayable phase {phase:?}"
            ),
        },
    }
}

fn local_activation_effect_id(owner: &CoordinationOwnerIdentity) -> String {
    format!(
        "activation:{}:{}",
        owner.run_identity(),
        owner.activation_nonce()
    )
}

fn write_local_activation(
    worktree: &Path,
    owner: &CoordinationOwnerIdentity,
    scopes: &[String],
) -> Result<()> {
    if read_local_activation(worktree, owner)?.is_some() {
        return Ok(());
    }
    let effect_id = local_activation_effect_id(owner);
    let record = LocalActivationRecord {
        version: LOCAL_ACTIVATION_FORMAT_VERSION,
        owner: owner.clone(),
        scopes: scopes.to_vec(),
    };
    let mut wal: CoordinationAdmissionEffectWal = EffectWal::open_or_create_planned(
        || {
            repository_auth_writer(worktree)?
                .into_authenticator()
                .context("coordination admission local activation authenticator")
        },
        LOCAL_ACTIVATION_LEDGER_LOGICAL,
        &effect_id,
        &record,
    )?;
    match wal.phase(&effect_id) {
        Some(EffectPhase::Completed) => Ok(()),
        Some(EffectPhase::Planned) => {
            wal.started(&effect_id, &record)?;
            wal.observed(&effect_id, &record)?;
            wal.completed(&effect_id, &record)?;
            Ok(())
        }
        _ => bail!("local activation ledger is in an unexpected phase"),
    }
}

fn read_local_activation(
    worktree: &Path,
    owner: &CoordinationOwnerIdentity,
) -> Result<Option<LocalActivationRecord>> {
    let effect_id = local_activation_effect_id(owner);
    let authenticator = local_activation_authenticator(worktree)?;
    match EffectWal::<DefaultEffectWalSpec>::open_when_initialized(
        authenticator,
        LOCAL_ACTIVATION_LEDGER_LOGICAL,
    )? {
        OpenInitializedEffectWal::NeverInitialized => Ok(None),
        OpenInitializedEffectWal::Open(wal) => match wal.phase(&effect_id) {
            None => Ok(None),
            Some(EffectPhase::Completed) => {
                let event = wal
                    .events()
                    .iter()
                    .rev()
                    .find(|event| event.effect_id == effect_id)
                    .context("local activation ledger omitted its latest event")?;
                let record: LocalActivationRecord = serde_json::from_value(event.data.clone())
                    .context("local activation record is malformed")?;
                if record.version == LOCAL_ACTIVATION_FORMAT_VERSION && record.owner == *owner {
                    Ok(Some(record))
                } else {
                    bail!("local activation record does not match the requested owner");
                }
            }
            Some(phase) if effect_phase_is_nonterminal(phase) => {
                bail!("local activation ledger is in nonterminal phase {phase:?}");
            }
            Some(phase) => bail!("local activation ledger is in unexpected phase {phase:?}"),
        },
    }
}

fn clear_local_activation(worktree: &Path, owner: &CoordinationOwnerIdentity) -> Result<()> {
    let _ = read_local_activation(worktree, owner)?;
    Ok(())
}

fn clear_pending_intent(worktree: &Path, effect_id: &str) -> Result<()> {
    let Some(record) = read_pending_intent(worktree, effect_id)? else {
        return Ok(());
    };
    let authenticator = pending_intent_authenticator(worktree)?;
    let mut wal = EffectWal::<DefaultEffectWalSpec>::open_instance(
        authenticator,
        PENDING_INTENT_LEDGER_LOGICAL,
    )?;
    match wal.phase(effect_id) {
        Some(EffectPhase::Completed) => Ok(()),
        Some(EffectPhase::Planned) => {
            wal.started(effect_id, &record)?;
            wal.observed(effect_id, &record)?;
            wal.completed(effect_id, &record)?;
            Ok(())
        }
        Some(phase) => {
            bail!("pending coordination intent {effect_id} is in non-terminal phase {phase:?}")
        }
        None => Ok(()),
    }
}

fn work_deadline_instant(send_instant: Instant, timing: ClaimTiming) -> Instant {
    send_instant + Duration::from_secs(timing.stale_after_seconds)
}

fn local_work_deadline_expired(send_instant: Instant, timing: ClaimTiming) -> bool {
    Instant::now() >= work_deadline_instant(send_instant, timing)
}

fn locate_active_owner<'a>(
    snapshot: &'a AuthoritySnapshot,
    owner: &CoordinationOwnerIdentity,
) -> Result<&'a ActiveOwnerRecord> {
    snapshot
        .active_owners()
        .iter()
        .find(|record| record.owner() == owner)
        .context("owner is not active in the authoritative coordination snapshot")
}

fn still_authoritative(
    snapshot: &AuthoritySnapshot,
    owner: &CoordinationOwnerIdentity,
    scopes: &[String],
) -> bool {
    snapshot
        .active_owners()
        .iter()
        .any(|record| record.owner() == owner && record.scopes() == scopes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::publication::coordination_github::CoordinationMutationOutcome;
    use crate::publication::coordination_journal::{
        AuthenticatedCommentEvidence, EffectReconciliationOutcome, JournalAuthorityResult,
        TrustedJournalReductionInput, VerifiedJournalEntry,
    };
    use crate::publication::forge_transport::{
        ForgeComment, ForgeItemKind, ForgeRepository, ForgeTimestamp, ProviderObjectKind,
        ReportedActorKind,
    };
    use git2::Repository;
    use tempfile::TempDir;

    const ANCHOR: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const T0: &str = "2026-08-16T00:00:00Z";
    const T30: &str = "2026-08-16T00:00:30Z";
    const T60: &str = "2026-08-16T00:01:00Z";
    const T90: &str = "2026-08-16T00:01:30Z";

    struct TestReconciler {
        digest: String,
    }

    impl EffectReconciliationVerifier for TestReconciler {
        fn verify_reconciliation(
            &self,
            _owner: &CoordinationOwnerIdentity,
            reserve_effect_id: &str,
            receipt: &EffectReconciliationReceipt,
        ) -> bool {
            reserve_effect_id == receipt.effect_id()
                && receipt.verified_material_sha256() == self.digest
        }
    }

    struct SimState {
        entries: Vec<VerifiedJournalEntry>,
        time_index: usize,
        times: Vec<&'static str>,
        next_commit: u8,
        effect_reconciliation: Option<Arc<dyn EffectReconciliationVerifier + Send + Sync>>,
    }

    struct SimTransport {
        state: Arc<Mutex<SimState>>,
        config: CoordinationJournalConfig,
        approved: ForgeActor,
        worktree: PathBuf,
    }

    impl SimTransport {
        fn new(
            worktree: PathBuf,
            config: CoordinationJournalConfig,
            approved: ForgeActor,
            effect_reconciliation: Option<Arc<dyn EffectReconciliationVerifier + Send + Sync>>,
        ) -> Self {
            Self {
                state: Arc::new(Mutex::new(SimState {
                    entries: Vec::new(),
                    time_index: 0,
                    times: vec![T0, T30, T60, T90, T90, T90, T90],
                    next_commit: 1,
                    effect_reconciliation,
                })),
                config,
                approved,
                worktree,
            }
        }

        fn shared_clone(&self) -> Self {
            Self {
                state: Arc::clone(&self.state),
                config: self.config.clone(),
                approved: self.approved.clone(),
                worktree: self.worktree.clone(),
            }
        }

        fn install_entries(&self, entries: Vec<VerifiedJournalEntry>) {
            self.state.lock().expect("lock").entries = entries;
        }

        fn export_entries(&self) -> Vec<VerifiedJournalEntry> {
            self.state.lock().expect("lock").entries.clone()
        }

        fn advance_provider_clock(&self) {
            self.state.lock().expect("lock").time_index = 3;
        }

        fn reduce_locked_state(
            &self,
            state: &SimState,
            history: &TrustedFiniteJournalHistory,
            effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
        ) -> Result<AuthoritySnapshot> {
            let reconciler = effect_reconciliation.or_else(|| {
                state
                    .effect_reconciliation
                    .as_ref()
                    .map(|arc| arc.as_ref() as &dyn EffectReconciliationVerifier)
            });
            let input = TrustedJournalReductionInput {
                config: self.config.clone(),
                history,
                effect_reconciliation: reconciler,
            };
            match input.reduce() {
                JournalAuthorityResult::Authoritative(snapshot) => Ok(snapshot),
                JournalAuthorityResult::Refused(reason) => {
                    bail!("simulated reduction refused: {reason:?}")
                }
            }
        }
    }

    impl CoordinationAdmissionTransport for SimTransport {
        fn journal_config(&self) -> &CoordinationJournalConfig {
            &self.config
        }

        fn approved_actor(&self) -> &ForgeActor {
            &self.approved
        }

        fn worktree(&self) -> &Path {
            &self.worktree
        }

        fn load_trusted_history(&self) -> Result<TrustedFiniteJournalHistory> {
            let state = self.state.lock().expect("lock");
            TrustedFiniteJournalHistory::from_transport_verified_entries(
                &self.config,
                state.entries.clone(),
            )
        }

        fn reduce_loaded_history(
            &self,
            history: &TrustedFiniteJournalHistory,
            effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
        ) -> Result<AuthoritySnapshot> {
            let state = self.state.lock().expect("lock");
            self.reduce_locked_state(&state, history, effect_reconciliation)
        }

        fn apply_authorized_intent(
            &self,
            intent: CoordinationIntent,
            comment_author: ForgeActor,
            effect_reconciliation: Option<&dyn EffectReconciliationVerifier>,
        ) -> Result<CoordinationMutationOutcome> {
            let mut state = self.state.lock().expect("lock");
            if comment_author != self.approved {
                bail!("unexpected comment author in simulation");
            }
            let history = TrustedFiniteJournalHistory::from_transport_verified_entries(
                &self.config,
                state.entries.clone(),
            )?;
            if let Some(entry) = history
                .verified_entries()
                .iter()
                .find(|entry| entry.pointer().event_nonce() == intent.event_nonce())
            {
                let snapshot = self.reduce_locked_state(&state, &history, effect_reconciliation)?;
                return Ok(CoordinationMutationOutcome::Applied {
                    entry: Box::new(entry.clone()),
                    snapshot,
                });
            }
            let parent = history
                .head_oid()
                .map(str::to_string)
                .unwrap_or_else(|| self.config.anchor_commit_oid().to_string());
            if intent.expected_parent_oid() != parent {
                return Ok(CoordinationMutationOutcome::Unknown {
                    evidence: "in-flight intent parent does not match current journal tip"
                        .to_string(),
                });
            }
            let timestamp = state.times.get(state.time_index).copied().unwrap_or(T90);
            state.time_index += 1;
            let commit = format!("{:02x}{:0>38}", state.next_commit, 0);
            state.next_commit += 1;
            let comment_id = format!("c{}", state.entries.len());
            let body = intent.render()?;
            let pointer = super::super::coordination_journal::JournalPointer::new(
                intent.event_nonce(),
                object(ProviderObjectKind::Comment, &comment_id),
                sha256_hex(body.as_bytes()),
                &parent,
            )?;
            let forge_comment = ForgeComment::new(
                object(ProviderObjectKind::Comment, &comment_id),
                comment_author,
                &body,
                format!("https://example.com/issues/89#issuecomment-{comment_id}"),
                ForgeTimestamp::new(timestamp)?,
            )?;
            let evidence = AuthenticatedCommentEvidence::from_verified_transport(
                &forge_comment,
                self.config.anchor_item(),
            )?;
            let entry = VerifiedJournalEntry::new(pointer, commit, parent, evidence)?;
            state.entries.push(entry.clone());
            let updated_history = TrustedFiniteJournalHistory::from_transport_verified_entries(
                &self.config,
                state.entries.clone(),
            )?;
            match self.reduce_locked_state(&state, &updated_history, effect_reconciliation) {
                Ok(snapshot) => Ok(CoordinationMutationOutcome::Applied {
                    entry: Box::new(entry),
                    snapshot,
                }),
                Err(error) => {
                    state.entries.pop();
                    Ok(CoordinationMutationOutcome::NotApplied {
                        reason: error.to_string(),
                    })
                }
            }
        }
    }

    fn object(
        kind: ProviderObjectKind,
        id: &str,
    ) -> super::super::forge_transport::ProviderObjectId {
        super::super::forge_transport::ProviderObjectId::new("github", kind, id).expect("object id")
    }

    fn actor(id: &str) -> ForgeActor {
        ForgeActor::new(
            "github",
            object(ProviderObjectKind::Actor, id),
            format!("bot-{id}"),
            ReportedActorKind::Bot,
        )
        .expect("actor")
    }

    fn item() -> super::super::forge_transport::ForgeItem {
        let repository = ForgeRepository::new(
            "github",
            "github.com/meta-develop/maco",
            object(ProviderObjectKind::Repository, "R_repo"),
        )
        .expect("repository");
        super::super::forge_transport::ForgeItem::new(
            repository,
            ForgeItemKind::Issue,
            89,
            object(ProviderObjectKind::Item, "I_issue"),
            "revision:1",
            None,
            None,
        )
        .expect("item")
    }

    fn journal_config() -> CoordinationJournalConfig {
        CoordinationJournalConfig::new(
            item(),
            "refs/heads/maco/coordination/journal",
            ANCHOR,
            vec![actor("trusted-a")],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("config")
    }

    fn init_test_repo(temp: &TempDir) {
        std::fs::create_dir_all(temp.path()).expect("repo root");
        Repository::init(temp.path()).expect("init");
    }

    fn make_sim(
        temp: &TempDir,
        reconciler: Option<Arc<dyn EffectReconciliationVerifier + Send + Sync>>,
    ) -> SimTransport {
        init_test_repo(temp);
        SimTransport::new(
            temp.path().to_path_buf(),
            journal_config(),
            actor("trusted-a"),
            reconciler,
        )
    }

    fn service(
        transport: SimTransport,
        reconciler: Option<Arc<dyn EffectReconciliationVerifier + Send + Sync>>,
    ) -> CoordinationAdmissionService<SimTransport> {
        CoordinationAdmissionService::new(transport, reconciler, None)
    }

    #[test]
    fn two_instances_cannot_obtain_overlapping_permits() {
        let temp = TempDir::new().expect("tempdir");
        let sim = make_sim(&temp, None);
        let a = service(sim.shared_clone(), None);
        let b = service(sim.shared_clone(), None);
        let first = a
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("admit a");
        assert!(matches!(first, CoordinationAdmissionResult::Ready(_)));
        let second = b
            .admit_scopes("run-b", "nonce-b", ["src/a"])
            .expect("admit b");
        assert!(matches!(
            second,
            CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteNotApplied { .. }
            )
        ));
    }

    #[test]
    fn foreign_host_inspects_without_local_activation_and_cannot_resume() {
        let temp_a = TempDir::new().expect("tempdir a");
        let temp_b = TempDir::new().expect("tempdir b");
        let sim = make_sim(&temp_a, None);
        let winner = service(sim.shared_clone(), None);
        let _permit = winner
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("win")
            .ready()
            .expect("ready");
        let foreign_transport = make_sim(&temp_b, None);
        foreign_transport.install_entries(sim.export_entries());
        let foreign = service(foreign_transport, None);
        let inspection = foreign
            .inspect_remote_authority("run-a", "nonce-a")
            .expect("inspect")
            .ready()
            .expect("inspection");
        assert!(!inspection.locally_authenticated());
        assert!(matches!(
            foreign
                .resume_scope_permit("run-a", "nonce-a")
                .expect("typed refusal"),
            CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::NotLocallyAuthenticated
            )
        ));
    }

    #[test]
    fn stale_owner_cannot_resume_with_fresh_work_permit() {
        let temp = TempDir::new().expect("tempdir");
        let sim = make_sim(&temp, None);
        let owner_svc = service(sim.shared_clone(), None);
        let permit = owner_svc
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("admit")
            .ready()
            .expect("permit");
        drop(permit);
        sim.advance_provider_clock();
        let successor = service(sim.shared_clone(), None);
        successor
            .takeover(
                CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner"),
                "run-b",
                "nonce-b",
                &[PathBuf::from("src/a")],
            )
            .expect("takeover")
            .ready()
            .expect("successor");
        let outcome = owner_svc
            .resume_scope_permit("run-a", "nonce-a")
            .expect("resume");
        assert!(matches!(
            outcome,
            CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteNotApplied { .. }
            )
        ));
    }

    #[test]
    fn resume_after_local_activation_requires_fresh_heartbeat() {
        let temp = TempDir::new().expect("tempdir");
        let sim = make_sim(&temp, None);
        let svc = service(sim, None);
        let permit = svc
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("admit")
            .ready()
            .expect("permit");
        drop(permit);
        let resumed = svc
            .resume_scope_permit("run-a", "nonce-a")
            .expect("resume")
            .ready()
            .expect("resumed permit");
        assert!(resumed.ensure_live().is_ok());
    }

    #[test]
    fn stale_takeover_succeeds_only_without_reservation() {
        let temp = TempDir::new().expect("tempdir");
        let digest = "b".repeat(64);
        let reconciler: Arc<dyn EffectReconciliationVerifier + Send + Sync> =
            Arc::new(TestReconciler {
                digest: digest.clone(),
            });
        let sim = make_sim(&temp, Some(Arc::clone(&reconciler)));
        let owner = service(sim.shared_clone(), Some(Arc::clone(&reconciler)));
        let permit = owner
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("claim")
            .ready()
            .expect("permit");
        let shared = owner
            .reserve_shared_effect(&permit, "effect-1")
            .expect("reserve")
            .ready()
            .expect("reserved");
        sim.advance_provider_clock();
        let successor = service(sim.shared_clone(), Some(Arc::clone(&reconciler)));
        let blocked = successor
            .takeover(
                permit.owner().clone(),
                "run-b",
                "nonce-b",
                &[PathBuf::from("src/a")],
            )
            .expect("takeover blocked");
        assert!(matches!(
            blocked,
            CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteNotApplied { .. }
            )
        ));
        let receipt = EffectReconciliationReceipt::new(
            "effect-1",
            EffectReconciliationOutcome::Completed,
            digest,
        )
        .expect("receipt");
        owner
            .complete_shared_effect(&permit, shared, receipt)
            .expect("complete reserve")
            .ready()
            .expect("completed");
        sim.advance_provider_clock();
        let takeover = successor
            .takeover(
                permit.owner().clone(),
                "run-b",
                "nonce-b-after-complete",
                &[PathBuf::from("src/a")],
            )
            .expect("takeover after completion")
            .ready()
            .expect("successor permit");
        assert_eq!(takeover.owner().run_identity(), "run-b");
    }

    #[test]
    fn unknown_restart_retains_exact_intent_after_head_advance() {
        let temp = TempDir::new().expect("tempdir");
        let sim = make_sim(&temp, None);
        let svc = service(sim.shared_clone(), None);
        let owner = CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner");
        let ledger_id = singleton_ledger_id(&owner, "claim");
        let intent = CoordinationIntent::claim(
            &item(),
            "evt-fixed-nonce",
            ANCHOR,
            owner.clone(),
            vec!["path:src/a".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("intent");
        let body = intent.render().expect("body");
        let record = PendingIntentRecord {
            version: PENDING_INTENT_FORMAT_VERSION,
            intent_body: body,
            owner: owner.clone(),
            kind: PendingIntentKind::Claim,
            scopes: Some(vec!["path:src/a".to_string()]),
            predecessor: None,
            effect_id: None,
            release_reason: None,
            publication_effect: None,
        };
        write_pending_intent(temp.path(), &ledger_id, &record).expect("seed pending");
        sim.advance_provider_clock();
        let _ = svc
            .admit_scopes("run-b", "nonce-b", ["src/b"])
            .expect("advance head");
        let pending = read_pending_intent(temp.path(), &ledger_id)
            .expect("pending")
            .expect("still pending");
        let stored = intent_from_pending_record(&pending).expect("stored intent");
        assert_eq!(stored.event_nonce(), "evt-fixed-nonce");
        assert_eq!(stored.expected_parent_oid(), ANCHOR);
    }

    #[test]
    fn changed_scopes_under_pending_nonce_refuses() {
        let temp = TempDir::new().expect("tempdir");
        let sim = make_sim(&temp, None);
        let svc = service(sim, None);
        let owner = CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner");
        let ledger_id = singleton_ledger_id(&owner, "claim");
        let intent = CoordinationIntent::claim(
            &item(),
            "evt-fixed-nonce",
            ANCHOR,
            owner.clone(),
            vec!["path:src/a".to_string()],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("intent");
        let record = PendingIntentRecord {
            version: PENDING_INTENT_FORMAT_VERSION,
            intent_body: intent.render().expect("body"),
            owner: owner.clone(),
            kind: PendingIntentKind::Claim,
            scopes: Some(vec!["path:src/a".to_string()]),
            predecessor: None,
            effect_id: None,
            release_reason: None,
            publication_effect: None,
        };
        write_pending_intent(temp.path(), &ledger_id, &record).expect("seed pending");
        let err = svc
            .admit_scopes("run-a", "nonce-a", ["src/b"])
            .err()
            .expect("scope mismatch");
        assert!(err.to_string().contains("semantics"));
    }

    #[test]
    fn request_duration_consuming_ttl_cannot_extend_permit() {
        let temp = TempDir::new().expect("tempdir");
        init_test_repo(&temp);
        let timing = ClaimTiming::new(1, 2).expect("tight timing");
        let config = CoordinationJournalConfig::new(
            item(),
            "refs/heads/maco/coordination/journal",
            ANCHOR,
            vec![actor("trusted-a")],
            timing,
        )
        .expect("config");
        let sim = SimTransport::new(temp.path().to_path_buf(), config, actor("trusted-a"), None);
        let svc = service(sim.shared_clone(), None);
        let _ = svc
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("admit")
            .ready()
            .expect("permit");
        let history = sim.load_trusted_history().expect("history");
        let snapshot = sim.reduce_loaded_history(&history, None).expect("snapshot");
        let owner = CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner");
        let record = locate_active_owner(&snapshot, &owner).expect("active");
        let send = Instant::now() - Duration::from_secs(2);
        assert!(local_work_deadline_expired(send, timing));
        let permit = CoordinationScopePermit::from_replay(
            TransportRef {
                inner: Arc::new(sim.shared_clone()),
            },
            record,
            send,
            timing,
        )
        .expect("permit");
        assert!(permit.ensure_live().is_err());
    }

    #[test]
    fn two_heartbeats_use_distinct_nonces_and_refresh_deadline() {
        let temp = TempDir::new().expect("tempdir");
        let sim = make_sim(&temp, None);
        let svc = service(sim.shared_clone(), None);
        let permit = svc
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("admit")
            .ready()
            .expect("permit");
        let before = sim.export_entries().len();
        svc.heartbeat(&permit)
            .expect("heartbeat")
            .ready()
            .expect("hb1");
        let after_first = permit.local_work_deadline().expect("deadline2");
        svc.heartbeat(&permit)
            .expect("heartbeat")
            .ready()
            .expect("hb2");
        let after_second = permit.local_work_deadline().expect("deadline3");
        assert!(after_second >= after_first);
        let new_entries = &sim.export_entries()[before..];
        assert_eq!(new_entries.len(), 2);
        assert_ne!(
            new_entries[0].pointer().event_nonce(),
            new_entries[1].pointer().event_nonce()
        );
    }

    #[test]
    fn dropping_permit_stops_deadline_guard_promptly() {
        let temp = TempDir::new().expect("tempdir");
        let sim = make_sim(&temp, None);
        let svc = service(sim, None);
        let permit = svc
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("admit")
            .ready()
            .expect("permit");
        let cancellation = permit.cancellation().clone();
        drop(permit);
        std::thread::sleep(Duration::from_millis(20));
        assert!(cancellation.is_cancelled());
    }

    #[test]
    fn transport_replay_does_not_duplicate_history_entries() {
        let temp = TempDir::new().expect("tempdir");
        let sim = make_sim(&temp, None);
        let svc = service(sim.shared_clone(), None);
        let _ = svc
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("admit")
            .ready()
            .expect("permit");
        let entries = sim.export_entries();
        let count = entries.len();
        let last = entries.last().expect("entry");
        let stored = CoordinationIntent::parse(last.comment().body())
            .expect("parse")
            .expect("intent");
        let replay = sim
            .apply_authorized_intent(stored, actor("trusted-a"), None)
            .expect("replay");
        assert!(matches!(
            replay,
            CoordinationMutationOutcome::Applied { .. }
        ));
        assert_eq!(sim.export_entries().len(), count);
    }

    #[test]
    fn losing_authority_cancels_work() {
        let temp = TempDir::new().expect("tempdir");
        let sim = make_sim(&temp, None);
        let a = service(sim.shared_clone(), None);
        let permit = a
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("claim")
            .ready()
            .expect("permit");
        let b = service(sim.shared_clone(), None);
        let _ = b
            .admit_scopes("run-b", "nonce-b", ["src/b"])
            .expect("other scope");
        sim.advance_provider_clock();
        let _ = b
            .takeover(
                permit.owner().clone(),
                "run-c",
                "nonce-c",
                &[PathBuf::from("src/a")],
            )
            .expect("takeover");
        assert!(permit.ensure_live_with_authority(&b).is_err());
        assert!(permit.cancellation().is_cancelled());
    }

    #[test]
    fn reserved_effect_blocks_takeover_until_verified_completion() {
        let temp = TempDir::new().expect("tempdir");
        let digest = "a".repeat(64);
        let reconciler: Arc<dyn EffectReconciliationVerifier + Send + Sync> =
            Arc::new(TestReconciler {
                digest: digest.clone(),
            });
        let sim = make_sim(&temp, Some(Arc::clone(&reconciler)));
        let owner = service(sim.shared_clone(), Some(Arc::clone(&reconciler)));
        let permit = owner
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("claim")
            .ready()
            .expect("permit");
        let shared = owner
            .reserve_shared_effect(&permit, "effect-1")
            .expect("reserve")
            .ready()
            .expect("shared");
        let successor = service(sim.shared_clone(), Some(Arc::clone(&reconciler)));
        sim.advance_provider_clock();
        let blocked = successor
            .takeover(
                permit.owner().clone(),
                "run-b",
                "nonce-b",
                &[PathBuf::from("src/a")],
            )
            .expect("blocked takeover");
        assert!(matches!(
            blocked,
            CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::RemoteNotApplied { .. }
            )
        ));
        let receipt = EffectReconciliationReceipt::new(
            "effect-1",
            EffectReconciliationOutcome::Completed,
            digest,
        )
        .expect("receipt");
        owner
            .complete_shared_effect(&permit, shared, receipt)
            .expect("complete")
            .ready()
            .expect("completed");
        owner
            .release(permit, "done")
            .expect("release")
            .ready()
            .expect("released");
    }

    fn sample_pending_record(owner: &CoordinationOwnerIdentity) -> PendingIntentRecord {
        PendingIntentRecord {
            version: PENDING_INTENT_FORMAT_VERSION,
            intent_body: "<!-- maco:forge-coordination-journal:v1 -->{}<!-- /maco:forge-coordination-journal:v1 -->".to_string(),
            owner: owner.clone(),
            kind: PendingIntentKind::Heartbeat,
            scopes: None,
            predecessor: None,
            effect_id: None,
            release_reason: None,
            publication_effect: None,
        }
    }

    #[test]
    fn never_initialized_admission_wal_is_not_pending() {
        let temp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(temp.path()).expect("repo root");
        Repository::init(temp.path()).expect("init");
        assert!(
            !worktree_has_planned_coordination_pending_intents(temp.path())
                .expect("scan absent WAL")
        );
    }

    #[test]
    fn deleted_admission_payload_under_locator_refuses_pending_scan() {
        let temp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(temp.path()).expect("repo root");
        Repository::init(temp.path()).expect("init");
        let owner = CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner");
        mutate_pending_intent_wal(temp.path(), |session| {
            let sequence = session.next_sequence()?;
            let nonce =
                operation_nonce_from_sequence(&owner, &PendingIntentKind::Heartbeat, sequence)?;
            let ledger_id = heartbeat_ledger_id(&owner, &nonce);
            session.write_planned(&ledger_id, &sample_pending_record(&owner))
        })
        .expect("seed planned operation");
        let auth = pending_intent_authenticator(temp.path()).expect("auth");
        let wal =
            EffectWal::<DefaultEffectWalSpec>::open_instance(auth, PENDING_INTENT_LEDGER_LOGICAL)
                .expect("open");
        let instance_id = wal.identity().run_id.clone();
        drop(wal);
        let instance_dir = temp
            .path()
            .join(".git")
            .join("maco")
            .join("state")
            .join(crate::effect_wal::EFFECT_WAL_ROOT_NAME)
            .join(instance_id);
        std::fs::remove_dir_all(&instance_dir).expect("delete payload");
        assert!(
            worktree_has_planned_coordination_pending_intents(temp.path()).is_err(),
            "deleted payload must not classify as absent"
        );
    }

    #[test]
    fn started_pending_operation_blocks_disable_scan_and_replay() {
        let temp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(temp.path()).expect("repo root");
        Repository::init(temp.path()).expect("init");
        let owner = CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner");
        let record = sample_pending_record(&owner);
        let ledger_id = mutate_pending_intent_wal(temp.path(), |session| {
            let sequence = session.next_sequence()?;
            let nonce =
                operation_nonce_from_sequence(&owner, &PendingIntentKind::Heartbeat, sequence)?;
            let ledger_id = heartbeat_ledger_id(&owner, &nonce);
            session.write_planned(&ledger_id, &record)?;
            Ok(ledger_id)
        })
        .expect("planned");
        let auth = pending_intent_authenticator(temp.path()).expect("auth");
        let mut wal =
            EffectWal::<DefaultEffectWalSpec>::open_instance(auth, PENDING_INTENT_LEDGER_LOGICAL)
                .expect("open");
        wal.started(&ledger_id, &record).expect("started");
        drop(wal);
        assert!(
            worktree_has_planned_coordination_pending_intents(temp.path()).expect("nonterminal")
        );
        assert!(read_pending_intent(temp.path(), &ledger_id).is_err());
    }

    #[test]
    fn durable_pending_operations_allocate_distinct_heartbeat_ledgers() {
        let temp = TempDir::new().expect("tempdir");
        std::fs::create_dir_all(temp.path()).expect("repo root");
        Repository::init(temp.path()).expect("init");
        let owner = CoordinationOwnerIdentity::new("run-a", "nonce-a").expect("owner");
        let first = mutate_pending_intent_wal(temp.path(), |session| {
            let sequence = session.next_sequence()?;
            let nonce =
                operation_nonce_from_sequence(&owner, &PendingIntentKind::Heartbeat, sequence)?;
            let ledger_id = heartbeat_ledger_id(&owner, &nonce);
            session.write_planned(&ledger_id, &sample_pending_record(&owner))?;
            Ok(ledger_id)
        })
        .expect("first operation");
        let second = mutate_pending_intent_wal(temp.path(), |session| {
            let sequence = session.next_sequence()?;
            let nonce =
                operation_nonce_from_sequence(&owner, &PendingIntentKind::Heartbeat, sequence)?;
            let ledger_id = heartbeat_ledger_id(&owner, &nonce);
            session.write_planned(&ledger_id, &sample_pending_record(&owner))?;
            Ok(ledger_id)
        })
        .expect("second operation");
        assert_ne!(first, second);
    }

    fn sample_git_descriptor() -> PublicationEffectDescriptorV1 {
        crate::publication::coordination_effect::canonical_git_push_publication_fixture()
            .expect("descriptor")
    }

    #[test]
    fn bound_complete_refuses_without_live_verifier() {
        let temp = TempDir::new().expect("tempdir");
        let sim = make_sim(&temp, None);
        let svc = CoordinationAdmissionService::new(sim.shared_clone(), None, None);
        let permit = svc
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("claim")
            .ready()
            .expect("permit");
        let descriptor = sample_git_descriptor();
        let effect_id = descriptor.effect_id().to_string();
        let shared = svc
            .reserve_bound_shared_effect(&permit, descriptor.clone())
            .expect("reserve")
            .ready()
            .expect("shared");
        use crate::publication::coordination_effect::{
            GitPushParentObservationV1, ParentObservedPublicationMaterialV1,
            ParentObservedPublicationObservationV1,
        };
        let material = ParentObservedPublicationMaterialV1::try_new(
            &shared.reserve_event_nonce,
            descriptor,
            ParentObservedPublicationObservationV1::GitPush(
                GitPushParentObservationV1::try_new("refs/heads/maco/effects/abcd", "d".repeat(40))
                    .expect("git observation"),
            ),
        )
        .expect("material");
        let receipt = EffectReconciliationReceipt::new_bound(
            effect_id,
            EffectReconciliationOutcome::Completed,
            material,
        )
        .expect("receipt");
        let refused = svc
            .complete_bound_shared_effect(&permit, shared, receipt)
            .expect("complete");
        assert!(matches!(
            refused,
            CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::EffectReconciliationRejected
            )
        ));
    }

    #[test]
    fn opaque_complete_rejects_bound_receipt() {
        let temp = TempDir::new().expect("tempdir");
        let digest = "a".repeat(64);
        let reconciler: Arc<dyn EffectReconciliationVerifier + Send + Sync> =
            Arc::new(TestReconciler {
                digest: digest.clone(),
            });
        let sim = make_sim(&temp, Some(Arc::clone(&reconciler)));
        let svc = CoordinationAdmissionService::new(
            sim.shared_clone(),
            Some(Arc::clone(&reconciler)),
            None,
        );
        let permit = svc
            .admit_scopes("run-a", "nonce-a", ["src/a"])
            .expect("claim")
            .ready()
            .expect("permit");
        let shared = svc
            .reserve_shared_effect(&permit, "effect-1")
            .expect("reserve")
            .ready()
            .expect("shared");
        use crate::publication::coordination_effect::{
            GitPushParentObservationV1, ParentObservedPublicationMaterialV1,
            ParentObservedPublicationObservationV1,
        };
        let material = ParentObservedPublicationMaterialV1::try_new(
            &shared.reserve_event_nonce,
            sample_git_descriptor(),
            ParentObservedPublicationObservationV1::GitPush(
                GitPushParentObservationV1::try_new("refs/heads/maco/effects/abcd", "d".repeat(40))
                    .expect("git observation"),
            ),
        )
        .expect("material");
        let bound_effect_id = material.descriptor().effect_id().to_string();
        let receipt = EffectReconciliationReceipt::new_bound(
            bound_effect_id,
            EffectReconciliationOutcome::Completed,
            material,
        )
        .expect("receipt");
        let refused = svc
            .complete_shared_effect(&permit, shared, receipt)
            .expect("complete");
        assert!(matches!(
            refused,
            CoordinationAdmissionResult::Refused(
                CoordinationAdmissionRefusal::EffectReconciliationRejected
            )
        ));
    }

    impl<T> CoordinationAdmissionResult<T> {
        fn ready(self) -> Result<T> {
            match self {
                Self::Ready(value) => Ok(value),
                Self::Refused(reason) => bail!("expected ready admission, got refusal {reason:?}"),
            }
        }
    }
}
