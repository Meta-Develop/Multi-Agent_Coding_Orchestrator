//! SyncStore lifecycle binding to configured remote coordination authority (#410).

use crate::{
    process_runner::ProcessCancellation,
    publication::{
        coordination_admission::{
            format_coordination_admission_refusal, mint_activation_nonce,
            CoordinationAdmissionRefusal, CoordinationAdmissionResult,
            CoordinationAdmissionService, CoordinationAdmissionTransport, CoordinationScopePermit,
            CoordinationSharedEffectPermit, RemoteAuthorityInspection,
        },
        coordination_effect::PublicationEffectDescriptorV1,
        coordination_journal::{CoordinationOwnerIdentity, EffectReconciliationReceipt},
        coordination_mode::ProductionCoordinationService,
    },
    sync::ClaimToken,
    sync_store::{AuthenticatedClaimRemoteOwner, ClaimTiming},
};
use anyhow::{bail, Context, Result};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RemoteOwnerBinding {
    pub run_identity: String,
    pub activation_nonce: String,
}

impl RemoteOwnerBinding {
    pub(crate) fn owner(&self) -> Result<CoordinationOwnerIdentity> {
        CoordinationOwnerIdentity::new(&self.run_identity, &self.activation_nonce)
            .context("remote owner binding")
    }
}

/// Live remote scope permit plus cancellation for work/revalidation handoff.
#[derive(Clone)]
pub(crate) struct RemoteWorkLease {
    cancellation: ProcessCancellation,
}

impl RemoteWorkLease {
    pub(crate) fn cancellation(&self) -> &ProcessCancellation {
        &self.cancellation
    }

    pub(crate) fn signal_protected_work_lost(&self) {
        self.cancellation.cancel();
    }
}

/// Live shared-effect reservation bound to one authenticated claim token and remote scope permit.
///
/// Callers may retain this across Git/PR work without holding `PermitCache` or claims locks.
/// Dropping does not complete or release the remote reservation.
pub(crate) struct RemoteClaimSharedEffectReservation {
    claim_token: ClaimToken,
    binding: RemoteOwnerBinding,
    effect_id: String,
    shared: CoordinationSharedEffectPermit,
    _work_lease: RemoteWorkLease,
}

impl RemoteClaimSharedEffectReservation {
    pub(crate) fn new(
        claim_token: ClaimToken,
        binding: RemoteOwnerBinding,
        effect_id: String,
        shared: CoordinationSharedEffectPermit,
        work_lease: RemoteWorkLease,
    ) -> Self {
        Self {
            claim_token,
            binding,
            effect_id,
            shared,
            _work_lease: work_lease,
        }
    }

    pub(crate) fn claim_token(&self) -> ClaimToken {
        self.claim_token
    }

    pub(crate) fn binding(&self) -> &RemoteOwnerBinding {
        &self.binding
    }

    pub(crate) fn effect_id(&self) -> &str {
        &self.effect_id
    }

    pub(crate) fn owner(&self) -> Result<CoordinationOwnerIdentity> {
        self.binding.owner()
    }

    pub(crate) fn shared_permit(&self) -> &CoordinationSharedEffectPermit {
        &self.shared
    }

    pub(crate) fn reserve_event_nonce(&self) -> &str {
        self.shared.reserve_event_nonce()
    }

    pub(crate) fn publication_descriptor(&self) -> Result<&PublicationEffectDescriptorV1> {
        self.shared
            .publication_effect()
            .context("remote publication effect reservation has no bound descriptor")
    }

    pub(crate) fn work_cancellation(&self) -> &ProcessCancellation {
        self._work_lease.cancellation()
    }

    pub(crate) fn into_completion_parts(
        self,
    ) -> (RemoteOwnerBinding, CoordinationSharedEffectPermit) {
        (self.binding, self.shared)
    }
}

impl std::fmt::Debug for RemoteClaimSharedEffectReservation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteClaimSharedEffectReservation")
            .field("claim_token", &self.claim_token)
            .field("binding", &self.binding)
            .field("effect_id", &self.effect_id)
            .finish_non_exhaustive()
    }
}

/// Explicit local-only admission when remote coordination is not selected.
#[derive(Debug)]
pub(crate) enum RemotePublicationEffectAdmission {
    LocalOnly,
    Reserved(Box<RemoteClaimSharedEffectReservation>),
}

/// Explicit remote journal mutation after a durable local claim reservation.
pub(crate) enum RemoteScopeAuthorityOperation {
    Admit {
        run_identity: String,
        activation_nonce: String,
    },
    Takeover {
        predecessor: CoordinationOwnerIdentity,
        run_identity: String,
        activation_nonce: String,
    },
}

impl RemoteScopeAuthorityOperation {
    pub(crate) fn apply(
        &self,
        backend: &dyn RemoteCoordinationBackend,
        scope_paths: &[PathBuf],
    ) -> Result<CoordinationAdmissionResult<RemoteOwnerBinding>> {
        match self {
            Self::Admit {
                run_identity,
                activation_nonce,
            } => backend.admit_scopes(run_identity, activation_nonce, scope_paths),
            Self::Takeover {
                predecessor,
                run_identity,
                activation_nonce,
            } => backend.takeover(
                predecessor.clone(),
                run_identity,
                activation_nonce,
                scope_paths,
            ),
        }
    }
}

pub(crate) trait RemoteCoordinationBackend: Send + Sync {
    fn worktree(&self) -> &Path;
    fn claim_timing(&self) -> ClaimTiming;
    fn trusted_authority_snapshot(
        &self,
    ) -> Result<crate::publication::coordination_journal::AuthoritySnapshot>;
    fn admit_scopes(
        &self,
        run_identity: &str,
        activation_nonce: &str,
        scope_paths: &[PathBuf],
    ) -> Result<CoordinationAdmissionResult<RemoteOwnerBinding>>;
    fn resume_permit(
        &self,
        binding: &RemoteOwnerBinding,
    ) -> Result<CoordinationAdmissionResult<()>>;
    fn heartbeat(&self, binding: &RemoteOwnerBinding) -> Result<CoordinationAdmissionResult<()>>;
    fn release(
        &self,
        binding: &RemoteOwnerBinding,
        reason: &str,
    ) -> Result<CoordinationAdmissionResult<()>>;
    fn takeover(
        &self,
        predecessor: CoordinationOwnerIdentity,
        run_identity: &str,
        activation_nonce: &str,
        scope_paths: &[PathBuf],
    ) -> Result<CoordinationAdmissionResult<RemoteOwnerBinding>>;
    fn inspect(
        &self,
        binding: &RemoteOwnerBinding,
    ) -> Result<CoordinationAdmissionResult<RemoteAuthorityInspection>>;
    fn lease_cancellation(&self, binding: &RemoteOwnerBinding) -> Result<ProcessCancellation>;
    fn reserve_bound_publication_effect(
        &self,
        binding: &RemoteOwnerBinding,
        publication_effect: PublicationEffectDescriptorV1,
    ) -> Result<CoordinationAdmissionResult<CoordinationSharedEffectPermit>>;
    fn complete_bound_publication_effect(
        &self,
        binding: &RemoteOwnerBinding,
        shared: CoordinationSharedEffectPermit,
        reconciliation: EffectReconciliationReceipt,
    ) -> Result<CoordinationAdmissionResult<()>>;
}

struct PermitCache<T: CoordinationAdmissionTransport + 'static> {
    permits: Mutex<BTreeMap<String, CoordinationScopePermit<T>>>,
}

impl<T: CoordinationAdmissionTransport + 'static> PermitCache<T> {
    fn new() -> Self {
        Self {
            permits: Mutex::new(BTreeMap::new()),
        }
    }

    fn owner_key(owner: &CoordinationOwnerIdentity) -> String {
        format!("{}:{}", owner.run_identity(), owner.activation_nonce())
    }

    fn store(&self, permit: CoordinationScopePermit<T>) -> Result<()> {
        let key = Self::owner_key(permit.owner());
        self.permits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, permit);
        Ok(())
    }

    fn contains(&self, binding: &RemoteOwnerBinding) -> bool {
        let Ok(owner) = binding.owner() else {
            return false;
        };
        let key = Self::owner_key(&owner);
        self.permits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&key)
    }

    fn with_permit<R>(
        &self,
        binding: &RemoteOwnerBinding,
        f: impl FnOnce(&CoordinationScopePermit<T>) -> Result<R>,
    ) -> Result<R> {
        let owner = binding.owner()?;
        let key = Self::owner_key(&owner);
        let permits = self
            .permits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let permit = permits
            .get(&key)
            .context("remote scope permit is not live on this store handle")?;
        f(permit)
    }

    fn remove(&self, binding: &RemoteOwnerBinding) -> Result<CoordinationScopePermit<T>> {
        let owner = binding.owner()?;
        let key = Self::owner_key(&owner);
        self.permits
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(&key)
            .context("remote scope permit is not live on this store handle")
    }
}

struct AdmissionBackend<T: CoordinationAdmissionTransport + 'static> {
    service: Arc<CoordinationAdmissionService<T>>,
    cache: PermitCache<T>,
}

impl<T: CoordinationAdmissionTransport + 'static> AdmissionBackend<T> {
    fn new(service: Arc<CoordinationAdmissionService<T>>) -> Self {
        Self {
            service,
            cache: PermitCache::new(),
        }
    }

    fn binding_from_owner(owner: &CoordinationOwnerIdentity) -> RemoteOwnerBinding {
        RemoteOwnerBinding {
            run_identity: owner.run_identity().to_string(),
            activation_nonce: owner.activation_nonce().to_string(),
        }
    }

    fn map_ready_permit(&self, permit: CoordinationScopePermit<T>) -> Result<RemoteOwnerBinding> {
        let binding = Self::binding_from_owner(permit.owner());
        self.cache.store(permit)?;
        Ok(binding)
    }

    fn ensure_cached_scope_permit(
        &self,
        binding: &RemoteOwnerBinding,
    ) -> Result<CoordinationAdmissionResult<()>> {
        if self.cache.contains(binding) {
            return Ok(CoordinationAdmissionResult::Ready(()));
        }
        self.resume_permit(binding)
    }
}

impl<T: CoordinationAdmissionTransport + 'static> RemoteCoordinationBackend
    for AdmissionBackend<T>
{
    fn worktree(&self) -> &Path {
        self.service.worktree()
    }

    fn claim_timing(&self) -> ClaimTiming {
        self.service.claim_timing()
    }

    fn trusted_authority_snapshot(
        &self,
    ) -> Result<crate::publication::coordination_journal::AuthoritySnapshot> {
        self.service.remote_authority_snapshot()
    }

    fn admit_scopes(
        &self,
        run_identity: &str,
        activation_nonce: &str,
        scope_paths: &[PathBuf],
    ) -> Result<CoordinationAdmissionResult<RemoteOwnerBinding>> {
        let outcome = self
            .service
            .admit_scopes(run_identity, activation_nonce, scope_paths)?;
        Ok(match outcome {
            CoordinationAdmissionResult::Ready(permit) => {
                CoordinationAdmissionResult::Ready(self.map_ready_permit(permit)?)
            }
            CoordinationAdmissionResult::Refused(reason) => {
                CoordinationAdmissionResult::Refused(reason)
            }
        })
    }

    fn resume_permit(
        &self,
        binding: &RemoteOwnerBinding,
    ) -> Result<CoordinationAdmissionResult<()>> {
        let outcome = self
            .service
            .resume_scope_permit(&binding.run_identity, &binding.activation_nonce)?;
        Ok(match outcome {
            CoordinationAdmissionResult::Ready(permit) => {
                self.cache.store(permit)?;
                CoordinationAdmissionResult::Ready(())
            }
            CoordinationAdmissionResult::Refused(reason) => {
                CoordinationAdmissionResult::Refused(reason)
            }
        })
    }

    fn heartbeat(&self, binding: &RemoteOwnerBinding) -> Result<CoordinationAdmissionResult<()>> {
        if !self.cache.contains(binding) {
            // `resume_scope_permit` performs the required fresh heartbeat CAS when restoring
            // work authority on a new store handle.
            return self.resume_permit(binding);
        }
        self.cache.with_permit(binding, |permit| {
            let outcome = self.service.heartbeat(permit)?;
            Ok(match outcome {
                CoordinationAdmissionResult::Ready(()) => CoordinationAdmissionResult::Ready(()),
                CoordinationAdmissionResult::Refused(reason) => {
                    CoordinationAdmissionResult::Refused(reason)
                }
            })
        })
    }

    fn release(
        &self,
        binding: &RemoteOwnerBinding,
        reason: &str,
    ) -> Result<CoordinationAdmissionResult<()>> {
        match self.ensure_cached_scope_permit(binding)? {
            CoordinationAdmissionResult::Ready(()) => {}
            CoordinationAdmissionResult::Refused(reason) => {
                return Ok(CoordinationAdmissionResult::Refused(reason));
            }
        }
        let permit = self.cache.remove(binding)?;
        let outcome = self.service.release(permit, reason)?;
        Ok(match outcome {
            CoordinationAdmissionResult::Ready(()) => CoordinationAdmissionResult::Ready(()),
            CoordinationAdmissionResult::Refused(reason) => {
                CoordinationAdmissionResult::Refused(reason)
            }
        })
    }

    fn takeover(
        &self,
        predecessor: CoordinationOwnerIdentity,
        run_identity: &str,
        activation_nonce: &str,
        scope_paths: &[PathBuf],
    ) -> Result<CoordinationAdmissionResult<RemoteOwnerBinding>> {
        let outcome =
            self.service
                .takeover(predecessor, run_identity, activation_nonce, scope_paths)?;
        Ok(match outcome {
            CoordinationAdmissionResult::Ready(permit) => {
                CoordinationAdmissionResult::Ready(self.map_ready_permit(permit)?)
            }
            CoordinationAdmissionResult::Refused(reason) => {
                CoordinationAdmissionResult::Refused(reason)
            }
        })
    }

    fn inspect(
        &self,
        binding: &RemoteOwnerBinding,
    ) -> Result<CoordinationAdmissionResult<RemoteAuthorityInspection>> {
        self.service
            .inspect_remote_authority(&binding.run_identity, &binding.activation_nonce)
    }

    fn lease_cancellation(&self, binding: &RemoteOwnerBinding) -> Result<ProcessCancellation> {
        match self.ensure_cached_scope_permit(binding)? {
            CoordinationAdmissionResult::Ready(()) => {}
            CoordinationAdmissionResult::Refused(reason) => {
                bail!(
                    "remote scope permit cannot be restored for work lease: {}",
                    format_coordination_admission_refusal(&reason)
                );
            }
        }
        self.cache
            .with_permit(binding, |permit| Ok(permit.cancellation().clone()))
    }

    fn reserve_bound_publication_effect(
        &self,
        binding: &RemoteOwnerBinding,
        publication_effect: PublicationEffectDescriptorV1,
    ) -> Result<CoordinationAdmissionResult<CoordinationSharedEffectPermit>> {
        match self.ensure_cached_scope_permit(binding)? {
            CoordinationAdmissionResult::Ready(()) => {}
            CoordinationAdmissionResult::Refused(reason) => {
                return Ok(CoordinationAdmissionResult::Refused(reason));
            }
        }
        self.cache.with_permit(binding, |permit| {
            self.service
                .reserve_bound_shared_effect(permit, publication_effect)
        })
    }

    fn complete_bound_publication_effect(
        &self,
        binding: &RemoteOwnerBinding,
        shared: CoordinationSharedEffectPermit,
        reconciliation: EffectReconciliationReceipt,
    ) -> Result<CoordinationAdmissionResult<()>> {
        match self.ensure_cached_scope_permit(binding)? {
            CoordinationAdmissionResult::Ready(()) => {}
            CoordinationAdmissionResult::Refused(reason) => {
                return Ok(CoordinationAdmissionResult::Refused(reason));
            }
        }
        self.cache.with_permit(binding, |permit| {
            self.service
                .complete_bound_shared_effect(permit, shared, reconciliation)
        })
    }
}

pub(crate) struct RemoteCoordination {
    backend: Arc<dyn RemoteCoordinationBackend>,
}

impl std::fmt::Debug for RemoteCoordination {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteCoordination")
            .field("backend", &"RemoteCoordinationBackend")
            .finish()
    }
}

impl RemoteCoordination {
    pub(crate) fn from_production_service(service: Arc<ProductionCoordinationService>) -> Self {
        Self {
            backend: Arc::new(AdmissionBackend::new(service)),
        }
    }

    #[cfg(test)]
    pub(crate) fn from_admission_service<T: CoordinationAdmissionTransport + 'static>(
        service: Arc<CoordinationAdmissionService<T>>,
    ) -> Self {
        Self {
            backend: Arc::new(AdmissionBackend::new(service)),
        }
    }

    /// Explicitly resume persisted bindings after local admission (for example revalidation).
    /// `SyncStore` open does not call this; permits restore on first admitted use per binding.
    pub(crate) fn bootstrap_existing_bindings(
        &self,
        bindings: &[AuthenticatedClaimRemoteOwner],
    ) -> Result<()> {
        for binding in bindings {
            let remote = RemoteOwnerBinding {
                run_identity: binding.run_identity.clone(),
                activation_nonce: binding.activation_nonce.clone(),
            };
            match self.backend.resume_permit(&remote)? {
                CoordinationAdmissionResult::Ready(()) => {}
                CoordinationAdmissionResult::Refused(
                    CoordinationAdmissionRefusal::RemoteNotApplied { reason },
                ) => {
                    bail!(
                        "remote-owned claim token {} is not live in remote authority: {reason}",
                        binding.token.get()
                    );
                }
                CoordinationAdmissionResult::Refused(reason) => {
                    bail!(
                        "remote-owned claim token {} cannot resume remote permit: {}",
                        binding.token.get(),
                        format_coordination_admission_refusal(&reason)
                    );
                }
            }
        }
        Ok(())
    }

    pub(crate) fn mint_activation_nonce(&self, run_identity: &str) -> Result<String> {
        mint_activation_nonce(self.backend.worktree(), run_identity)
    }

    pub(crate) fn remote_claim_timing(&self) -> ClaimTiming {
        self.backend.claim_timing()
    }

    pub(crate) fn trusted_authority_snapshot(
        &self,
    ) -> Result<crate::publication::coordination_journal::AuthoritySnapshot> {
        self.backend.trusted_authority_snapshot()
    }

    pub(crate) fn apply_remote_scope_authority(
        &self,
        operation: RemoteScopeAuthorityOperation,
        scope_paths: &[PathBuf],
    ) -> Result<CoordinationAdmissionResult<RemoteOwnerBinding>> {
        operation.apply(self.backend.as_ref(), scope_paths)
    }

    pub(crate) fn worktree(&self) -> &Path {
        self.backend.worktree()
    }

    pub(crate) fn heartbeat_binding(&self, binding: &RemoteOwnerBinding) -> Result<()> {
        match self.backend.heartbeat(binding)? {
            CoordinationAdmissionResult::Ready(()) => Ok(()),
            CoordinationAdmissionResult::Refused(reason) => {
                bail!(
                    "remote claim heartbeat refused: {}",
                    format_coordination_admission_refusal(&reason)
                )
            }
        }
    }

    pub(crate) fn release_binding(&self, binding: &RemoteOwnerBinding, reason: &str) -> Result<()> {
        match self.backend.release(binding, reason)? {
            CoordinationAdmissionResult::Ready(()) => Ok(()),
            CoordinationAdmissionResult::Refused(reason) => {
                bail!(
                    "remote claim release refused: {}",
                    format_coordination_admission_refusal(&reason)
                )
            }
        }
    }

    pub(crate) fn remote_takeover(
        &self,
        predecessor: CoordinationOwnerIdentity,
        successor_run: &str,
        scope_paths: &[PathBuf],
    ) -> Result<RemoteOwnerBinding> {
        let activation_nonce = self.mint_activation_nonce(successor_run)?;
        self.remote_takeover_with_activation_nonce(
            predecessor,
            successor_run,
            &activation_nonce,
            scope_paths,
        )
    }

    pub(crate) fn remote_takeover_with_activation_nonce(
        &self,
        predecessor: CoordinationOwnerIdentity,
        successor_run: &str,
        activation_nonce: &str,
        scope_paths: &[PathBuf],
    ) -> Result<RemoteOwnerBinding> {
        match self
            .backend
            .takeover(predecessor, successor_run, activation_nonce, scope_paths)?
        {
            CoordinationAdmissionResult::Ready(binding) => Ok(binding),
            CoordinationAdmissionResult::Refused(reason) => {
                bail!(
                    "remote takeover refused: {}",
                    format_coordination_admission_refusal(&reason)
                )
            }
        }
    }

    pub(crate) fn inspect_binding(
        &self,
        binding: &RemoteOwnerBinding,
    ) -> Result<RemoteAuthorityInspection> {
        match self.backend.inspect(binding)? {
            CoordinationAdmissionResult::Ready(inspection) => Ok(inspection),
            CoordinationAdmissionResult::Refused(reason) => {
                bail!(
                    "remote authority inspection refused: {}",
                    format_coordination_admission_refusal(&reason)
                )
            }
        }
    }

    pub(crate) fn work_lease(&self, binding: &RemoteOwnerBinding) -> Result<RemoteWorkLease> {
        let cancellation = self.backend.lease_cancellation(binding)?;
        Ok(RemoteWorkLease { cancellation })
    }

    pub(crate) fn reserve_bound_publication_effect(
        &self,
        binding: &RemoteOwnerBinding,
        publication_effect: PublicationEffectDescriptorV1,
    ) -> Result<CoordinationSharedEffectPermit> {
        refuse_admission_result(
            self.backend
                .reserve_bound_publication_effect(binding, publication_effect)?,
        )
    }

    pub(crate) fn complete_bound_publication_effect(
        &self,
        binding: &RemoteOwnerBinding,
        shared: CoordinationSharedEffectPermit,
        reconciliation: EffectReconciliationReceipt,
    ) -> Result<()> {
        match self
            .backend
            .complete_bound_publication_effect(binding, shared, reconciliation)?
        {
            CoordinationAdmissionResult::Ready(()) => Ok(()),
            CoordinationAdmissionResult::Refused(reason) => {
                bail!(
                    "remote bound publication effect completion refused: {}",
                    format_coordination_admission_refusal(&reason)
                )
            }
        }
    }
}

pub(crate) fn remote_binding_for_token(
    remote_owners: &[AuthenticatedClaimRemoteOwner],
    token: ClaimToken,
) -> Result<Option<RemoteOwnerBinding>> {
    let Some(record) = remote_owners.iter().find(|entry| entry.token == token) else {
        return Ok(None);
    };
    Ok(Some(RemoteOwnerBinding {
        run_identity: record.run_identity.clone(),
        activation_nonce: record.activation_nonce.clone(),
    }))
}

pub(crate) fn refuse_admission_result<T>(result: CoordinationAdmissionResult<T>) -> Result<T> {
    match result {
        CoordinationAdmissionResult::Ready(value) => Ok(value),
        CoordinationAdmissionResult::Refused(reason) => {
            bail!(
                "remote coordination refused: {}",
                format_coordination_admission_refusal(&reason)
            )
        }
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use crate::publication::coordination_admission::CoordinationAdmissionService;
    use crate::publication::coordination_github::CoordinationMutationOutcome;
    use crate::publication::coordination_journal::{
        AuthenticatedCommentEvidence, CoordinationIntent, JournalAuthorityResult,
        TrustedFiniteJournalHistory, TrustedJournalReductionInput, VerifiedJournalEntry,
    };
    use crate::publication::forge_transport::{
        ForgeActor, ForgeComment, ForgeItem, ForgeItemKind, ForgeRepository, ForgeTimestamp,
        ProviderObjectKind, ReportedActorKind,
    };
    use crate::sync_store::SyncStore;
    use std::sync::{Arc, Mutex};

    const ANCHOR: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const T0: &str = "2026-08-16T00:00:00Z";
    const T30: &str = "2026-08-16T00:00:30Z";
    const T60: &str = "2026-08-16T00:01:00Z";
    const T120: &str = "2026-08-16T00:02:00Z";

    pub(crate) struct SimTransport {
        state: Arc<Mutex<SimState>>,
        config: crate::publication::coordination_journal::CoordinationJournalConfig,
        approved: ForgeActor,
        worktree: PathBuf,
    }

    struct SimState {
        entries: Vec<VerifiedJournalEntry>,
        time_index: usize,
        times: Vec<&'static str>,
        next_commit: u8,
        heartbeat_unknown_once: bool,
    }

    impl SimTransport {
        pub(crate) fn new(worktree: PathBuf) -> Self {
            let config = journal_config();
            Self {
                state: Arc::new(Mutex::new(SimState {
                    entries: Vec::new(),
                    time_index: 0,
                    times: vec![T0, T30, T60, T60, T60, T120],
                    next_commit: 1,
                    heartbeat_unknown_once: false,
                })),
                config,
                approved: actor("trusted-a"),
                worktree,
            }
        }

        pub(crate) fn shared_clone(&self) -> Self {
            Self {
                state: Arc::clone(&self.state),
                config: self.config.clone(),
                approved: self.approved.clone(),
                worktree: self.worktree.clone(),
            }
        }

        pub(crate) fn advance_provider_clock(&self) {
            let mut state = self.state.lock().expect("lock");
            state.time_index = state.times.len() - 1;
        }

        pub(crate) fn arm_next_heartbeat_unknown(&self) {
            self.state.lock().expect("lock").heartbeat_unknown_once = true;
        }

        #[cfg(test)]
        pub(crate) fn journal_entries(&self) -> Vec<VerifiedJournalEntry> {
            self.state.lock().expect("lock").entries.clone()
        }

        /// Peer-host takeover via shared sim journal only (no pending-intent WAL).
        pub(crate) fn apply_peer_takeover_journal_only(
            &self,
            predecessor: CoordinationOwnerIdentity,
            successor_run: &str,
            activation_nonce: &str,
            scope_paths: &[PathBuf],
        ) -> Result<()> {
            use crate::publication::coordination_github::CoordinationMutationOutcome;
            use crate::publication::coordination_journal::{
                normalize_coordination_scopes, CoordinationIntent,
            };

            self.advance_provider_clock();
            let history = self.load_trusted_history()?;
            let parent = history
                .head_oid()
                .map(str::to_string)
                .unwrap_or_else(|| self.config.anchor_commit_oid().to_string());
            let successor = CoordinationOwnerIdentity::new(successor_run, activation_nonce)
                .context("successor")?;
            let scopes = normalize_coordination_scopes(scope_paths)?;
            let event_nonce = format!(
                "sim-peer-takeover-{}",
                self.state.lock().expect("lock").entries.len()
            );
            let intent = CoordinationIntent::takeover(
                self.config.anchor_item(),
                event_nonce,
                parent,
                successor,
                predecessor,
                scopes,
                self.config.timing(),
            )?;
            match self.apply_authorized_intent(intent, self.approved.clone(), None)? {
                CoordinationMutationOutcome::Applied { .. } => Ok(()),
                CoordinationMutationOutcome::NotApplied { reason } => {
                    bail!("simulated peer takeover not applied: {reason}")
                }
                CoordinationMutationOutcome::Unknown { evidence } => {
                    bail!("simulated peer takeover unknown: {evidence}")
                }
            }
        }
    }

    impl CoordinationAdmissionTransport for SimTransport {
        fn journal_config(
            &self,
        ) -> &crate::publication::coordination_journal::CoordinationJournalConfig {
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
            effect_reconciliation: Option<
                &dyn crate::publication::coordination_journal::EffectReconciliationVerifier,
            >,
        ) -> Result<crate::publication::coordination_journal::AuthoritySnapshot> {
            let input = TrustedJournalReductionInput {
                config: self.config.clone(),
                history,
                effect_reconciliation,
            };
            match input.reduce() {
                JournalAuthorityResult::Authoritative(snapshot) => Ok(snapshot),
                JournalAuthorityResult::Refused(reason) => {
                    bail!("simulated reduction refused: {reason:?}")
                }
            }
        }

        fn apply_authorized_intent(
            &self,
            intent: CoordinationIntent,
            comment_author: ForgeActor,
            effect_reconciliation: Option<
                &dyn crate::publication::coordination_journal::EffectReconciliationVerifier,
            >,
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
                let snapshot = self.reduce_loaded_history(&history, effect_reconciliation)?;
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
            if matches!(
                intent.action(),
                crate::publication::coordination_journal::CoordinationIntentAction::Heartbeat
            ) && state.heartbeat_unknown_once
            {
                state.heartbeat_unknown_once = false;
                return Ok(CoordinationMutationOutcome::Unknown {
                    evidence: "simulated remote heartbeat unknown before permit ttl".to_string(),
                });
            }
            // The simulated provider clock is monotonic: once the schedule is exhausted it
            // stays at the final time instead of rewinding to an earlier one. Otherwise a
            // guard-owned heartbeat racing `advance_provider_clock` could consume the last
            // slot and make the following takeover observe a clock earlier than the
            // predecessor heartbeat, refusing it spuriously.
            let last_index = state.times.len() - 1;
            let timestamp = state.times[state.time_index.min(last_index)];
            state.time_index = (state.time_index + 1).min(state.times.len());
            let commit = format!("{:02x}{:0>38}", state.next_commit, 0);
            state.next_commit += 1;
            let comment_id = format!("c{}", state.entries.len());
            let body = intent.render()?;
            let pointer = crate::publication::coordination_journal::JournalPointer::new(
                intent.event_nonce(),
                object(ProviderObjectKind::Comment, &comment_id),
                crate::artifacts::state_auth::sha256_hex(body.as_bytes()),
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
            match self.reduce_loaded_history(&updated_history, effect_reconciliation) {
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

    pub(crate) fn open_sync_with_sim_remote(repo: &Path, sim: SimTransport) -> Result<SyncStore> {
        open_sync_with_sim_remote_and_verifiers(repo, sim, None, None)
    }

    pub(crate) fn open_sync_with_sim_remote_and_live_verifier(
        repo: &Path,
        sim: SimTransport,
        publication_live_verifier: Option<
            Arc<
                dyn crate::publication::coordination_effect::PublicationEffectLiveVerifier
                    + Send
                    + Sync,
            >,
        >,
    ) -> Result<SyncStore> {
        open_sync_with_sim_remote_and_verifiers(repo, sim, None, publication_live_verifier)
    }

    pub(crate) fn open_sync_with_sim_remote_and_verifiers(
        repo: &Path,
        sim: SimTransport,
        effect_reconciliation: Option<
            Arc<
                dyn crate::publication::coordination_journal::EffectReconciliationVerifier
                    + Send
                    + Sync,
            >,
        >,
        publication_live_verifier: Option<
            Arc<
                dyn crate::publication::coordination_effect::PublicationEffectLiveVerifier
                    + Send
                    + Sync,
            >,
        >,
    ) -> Result<SyncStore> {
        let service = Arc::new(CoordinationAdmissionService::new(
            sim,
            effect_reconciliation,
            publication_live_verifier,
        ));
        let remote = Arc::new(RemoteCoordination::from_admission_service(service));
        SyncStore::open_with_remote_coordination(repo, remote)
    }

    /// Deterministic bound git-push descriptor for publication facade tests.
    pub(crate) fn sample_publication_git_push_descriptor() -> PublicationEffectDescriptorV1 {
        crate::publication::coordination_effect::canonical_git_push_publication_fixture()
            .expect("descriptor")
    }

    /// Simulated peer host: shared authenticated transport, no `SyncStore::open` (avoids claims.lock).
    pub(crate) fn peer_remote_coordination(sim: SimTransport) -> RemoteCoordination {
        RemoteCoordination::from_admission_service(Arc::new(CoordinationAdmissionService::new(
            sim, None, None,
        )))
    }

    pub(crate) fn sim_peer_remote_takeover(
        sim: &SimTransport,
        predecessor: crate::publication::coordination_journal::CoordinationOwnerIdentity,
        successor_run: &str,
        scope_paths: &[PathBuf],
    ) -> Result<RemoteOwnerBinding> {
        sim_peer_remote_takeover_with_activation_nonce(
            sim,
            predecessor,
            successor_run,
            scope_paths,
            None,
        )
    }

    pub(crate) fn sim_peer_remote_takeover_with_activation_nonce(
        sim: &SimTransport,
        predecessor: crate::publication::coordination_journal::CoordinationOwnerIdentity,
        successor_run: &str,
        scope_paths: &[PathBuf],
        activation_nonce: Option<&str>,
    ) -> Result<RemoteOwnerBinding> {
        let activation_nonce = match activation_nonce {
            Some(nonce) => nonce.to_string(),
            None => {
                let len = sim.state.lock().expect("lock").entries.len();
                format!("act-peer-{successor_run}-{len}")
            }
        };
        sim.apply_peer_takeover_journal_only(
            predecessor,
            successor_run,
            &activation_nonce,
            scope_paths,
        )?;
        Ok(RemoteOwnerBinding {
            run_identity: successor_run.to_string(),
            activation_nonce,
        })
    }

    fn object(
        kind: ProviderObjectKind,
        id: &str,
    ) -> crate::publication::forge_transport::ProviderObjectId {
        crate::publication::forge_transport::ProviderObjectId::new("github", kind, id)
            .expect("object id")
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

    fn item() -> ForgeItem {
        let repository = ForgeRepository::new(
            "github",
            "github.com/meta-develop/maco",
            object(ProviderObjectKind::Repository, "R_repo"),
        )
        .expect("repository");
        ForgeItem::new(
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

    fn journal_config() -> crate::publication::coordination_journal::CoordinationJournalConfig {
        crate::publication::coordination_journal::CoordinationJournalConfig::new(
            item(),
            "refs/heads/maco/coordination/journal",
            ANCHOR,
            vec![actor("trusted-a")],
            ClaimTiming::new(10, 30).expect("timing"),
        )
        .expect("config")
    }
}

#[cfg(test)]
mod tests {
    use super::{
        test_support::{
            open_sync_with_sim_remote, open_sync_with_sim_remote_and_live_verifier,
            sample_publication_git_push_descriptor, sim_peer_remote_takeover, SimTransport,
        },
        RemotePublicationEffectAdmission,
    };
    use crate::publication::coordination_effect::{
        GitPushParentObservationV1, ParentObservedPublicationMaterialV1,
        ParentObservedPublicationObservationV1, PublicationEffectDescriptorV1,
        PublicationEffectLiveVerification, PublicationEffectLiveVerifier,
    };
    use crate::publication::coordination_journal::{
        CoordinationOwnerIdentity, EffectReconciliationOutcome, EffectReconciliationReceipt,
    };
    use crate::sync_store::ClaimTiming;
    use crate::sync_store::SyncStore;
    use crate::worktree::WorktreeManager;
    use std::sync::Arc;
    use tempfile::TempDir;

    fn init_repo() -> TempDir {
        let temp = TempDir::new().expect("tempdir");
        WorktreeManager::init_repository(temp.path(), "main").expect("init");
        temp
    }

    #[test]
    fn local_only_claim_unchanged_without_remote_handle() {
        let temp = init_repo();
        let store = SyncStore::open(temp.path()).expect("open");
        let outcome = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::default())
            .expect("claim");
        assert_eq!(outcome.claim.agent_id, "agent-a");
    }

    #[test]
    fn overlapping_remote_owner_refuses_second_repo_claim() {
        let temp_a = init_repo();
        let temp_b = init_repo();
        let sim = SimTransport::new(temp_a.path().to_path_buf());
        let sim_b = sim.shared_clone();
        let store_a = open_sync_with_sim_remote(temp_a.path(), sim.shared_clone()).expect("open a");
        store_a
            .claim_paths_with_timing("agent-a", ["src/shared.rs"], ClaimTiming::default())
            .expect("claim a");
        let store_b = open_sync_with_sim_remote(temp_b.path(), sim_b).expect("open b");
        let error = store_b
            .claim_paths_with_timing("agent-b", ["src/shared.rs"], ClaimTiming::default())
            .expect_err("overlap");
        assert!(error.to_string().contains("refused"));
    }

    #[test]
    fn disjoint_remote_scopes_succeed_on_two_hosts() {
        let temp_a = init_repo();
        let temp_b = init_repo();
        let sim = SimTransport::new(temp_a.path().to_path_buf());
        let store_a = open_sync_with_sim_remote(temp_a.path(), sim.shared_clone()).expect("open a");
        store_a
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::default())
            .expect("claim a");
        let store_b = open_sync_with_sim_remote(temp_b.path(), sim.shared_clone()).expect("open b");
        store_b
            .claim_paths_with_timing("agent-b", ["src/b.rs"], ClaimTiming::default())
            .expect("claim b");
    }

    #[test]
    fn reopened_store_restores_remote_permit_on_explicit_work_lease() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::default())
            .expect("claim")
            .claim;
        drop(store);
        let journal_before_reopen = sim.journal_entries().len();
        let reopened = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("reopen");
        assert_eq!(
            sim.journal_entries().len(),
            journal_before_reopen,
            "reopen must not resume every persisted binding"
        );
        let journal_before_lease = sim.journal_entries().len();
        let lease = reopened
            .remote_work_lease(claim.token)
            .expect("lease")
            .expect("remote lease");
        assert!(!lease.cancellation().is_cancelled());
        assert!(
            sim.journal_entries().len() > journal_before_lease,
            "explicit work lease must restore the requested binding with a fresh heartbeat"
        );
    }

    #[test]
    fn reopened_store_refuses_wrong_owner_heartbeat_without_constructor_remote_mutation() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::default())
            .expect("claim")
            .claim;
        let liveness_before = store.liveness_snapshot().expect("liveness")[0]
            .heartbeat_unix_seconds
            .expect("initialized heartbeat");
        drop(store);
        let journal_before_reopen = sim.journal_entries().len();
        let reopened = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("reopen");
        assert_eq!(
            sim.journal_entries().len(),
            journal_before_reopen,
            "constructor reopen must not mutate remote journal"
        );
        let error = reopened
            .heartbeat_at(claim.token, "agent-b", None, liveness_before + 1)
            .expect_err("wrong local owner after reopen");
        assert!(
            format!("{error:#}").contains("does not exactly match owner"),
            "{error:#}"
        );
        assert_eq!(sim.journal_entries().len(), journal_before_reopen);
        assert_eq!(
            reopened
                .liveness_snapshot()
                .expect("liveness after refusal")[0]
                .heartbeat_unix_seconds,
            Some(liveness_before)
        );
        let journal_before_owner = sim.journal_entries().len();
        reopened
            .heartbeat_at(claim.token, "agent-a", None, liveness_before + 1)
            .expect("exact owner heartbeat after reopen");
        assert!(
            sim.journal_entries().len() > journal_before_owner,
            "admitted owner heartbeat must restore permit and mutate journal"
        );
        assert_eq!(
            reopened
                .liveness_snapshot_at(liveness_before + 1)
                .expect("liveness after owner heartbeat")[0]
                .heartbeat_unix_seconds,
            Some(liveness_before + 1)
        );
    }

    #[test]
    fn managed_process_cancellation_for_claim_compose_run_and_remote_authority() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let timing = ClaimTiming::new(1, 3).expect("timing");
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], timing)
            .expect("claim")
            .claim;
        let run = crate::process_runner::ProcessCancellation::new();
        let bound = store
            .managed_process_cancellation_for_claim(claim.token, &run)
            .expect("bind");
        assert!(!bound.cancellation().is_cancelled());
        let predecessor = store
            .inspect_remote_claim_owner(claim.token)
            .expect("inspect")
            .owner()
            .clone();
        sim_peer_remote_takeover(&sim, predecessor, "agent-b", &claim.paths).expect("takeover");
        store
            .heartbeat(claim.token, "agent-a", None)
            .expect_err("stale remote owner must refuse heartbeat");
        assert!(
            bound.cancellation().is_cancelled(),
            "managed binding must observe remote authority loss"
        );
        assert!(
            !run.is_cancelled(),
            "run scheduler cancellation must not be mutated by remote loss"
        );
    }

    #[test]
    fn remote_work_lease_refuses_missing_remote_owner_binding() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        match store.remote_work_lease(crate::sync::ClaimToken::from_u64(9_999_999)) {
            Err(error) => {
                assert!(
                    error
                        .to_string()
                        .contains("no authenticated remote owner binding"),
                    "unexpected error: {error}"
                );
            }
            Ok(_) => panic!("missing binding must refuse lease lookup"),
        }
    }

    #[test]
    fn remote_heartbeat_loss_refuses_local_extension() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let timing = ClaimTiming::new(1, 3).expect("timing");
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], timing)
            .expect("claim")
            .claim;
        let before = store.liveness_snapshot().expect("liveness before")[0]
            .heartbeat_unix_seconds
            .expect("initialized heartbeat");
        let predecessor = store
            .inspect_remote_claim_owner(claim.token)
            .expect("inspect remote owner")
            .owner()
            .clone();
        sim_peer_remote_takeover(&sim, predecessor, "agent-b", &claim.paths)
            .expect("remote peer takeover");
        let error = store
            .heartbeat(claim.token, "agent-a", None)
            .expect_err("heartbeat");
        let message = format!("{error:#}");
        assert!(
            message.contains("remote claim heartbeat refused")
                || message.contains("coordination authority was lost before mutation"),
            "expected remote heartbeat refusal, got: {message}"
        );
        let active = store.snapshot().expect("local claims remain");
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].token, claim.token);
        assert_eq!(active[0].agent_id, "agent-a");
        assert_eq!(
            store.liveness_snapshot().expect("liveness after")[0].heartbeat_unix_seconds,
            Some(before)
        );
    }

    fn publication_push_descriptor() -> PublicationEffectDescriptorV1 {
        sample_publication_git_push_descriptor()
    }

    fn reserve_event_nonce_from_sim(sim: &SimTransport, effect_id: &str) -> String {
        use crate::publication::coordination_journal::{
            CoordinationIntent, CoordinationIntentAction,
        };
        for entry in sim.journal_entries().iter().rev() {
            let intent = CoordinationIntent::parse(entry.comment().body())
                .expect("parse journal intent")
                .expect("journal intent");
            if let CoordinationIntentAction::EffectReserve { effect_id: id, .. } = intent.action() {
                if id == effect_id {
                    return intent.event_nonce().to_string();
                }
            }
        }
        panic!("effect reserve intent not found for {effect_id}");
    }

    fn bound_push_completion_receipt(
        reserve_event_nonce: &str,
        effect_id: &str,
    ) -> EffectReconciliationReceipt {
        let descriptor = sample_publication_git_push_descriptor();
        assert_eq!(descriptor.effect_id(), effect_id);
        let material = ParentObservedPublicationMaterialV1::try_new(
            reserve_event_nonce,
            descriptor,
            ParentObservedPublicationObservationV1::GitPush(
                GitPushParentObservationV1::try_new("refs/heads/maco/effects/abcd", "d".repeat(40))
                    .expect("git observation"),
            ),
        )
        .expect("material");
        EffectReconciliationReceipt::new_bound(
            effect_id,
            EffectReconciliationOutcome::Completed,
            material,
        )
        .expect("receipt")
    }

    struct AlwaysVerifiedLiveVerifier;

    impl PublicationEffectLiveVerifier for AlwaysVerifiedLiveVerifier {
        fn verify_live_bound_completion(
            &self,
            _owner: &CoordinationOwnerIdentity,
            _descriptor: &PublicationEffectDescriptorV1,
            _material: &ParentObservedPublicationMaterialV1,
        ) -> PublicationEffectLiveVerification {
            PublicationEffectLiveVerification::Verified
        }
    }

    #[test]
    fn reserve_remote_publication_effect_is_explicit_local_only_without_remote() {
        let temp = init_repo();
        let store = SyncStore::open(temp.path()).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::default())
            .expect("claim")
            .claim;
        let admission = store
            .reserve_remote_publication_effect(claim.token, publication_push_descriptor())
            .expect("reserve");
        assert!(matches!(
            admission,
            RemotePublicationEffectAdmission::LocalOnly
        ));
    }

    #[test]
    fn reserve_remote_publication_effect_refuses_missing_owner_binding() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::default())
            .expect("claim")
            .claim;
        store
            .with_locked_update(|_, _, _, _, remote_owners| {
                remote_owners.clear();
                Ok(())
            })
            .expect("clear binding");
        let error = store
            .reserve_remote_publication_effect(claim.token, publication_push_descriptor())
            .expect_err("missing binding");
        assert!(
            error
                .to_string()
                .contains("no authenticated remote owner binding"),
            "{error}"
        );
    }

    #[test]
    fn reserve_remote_publication_effect_records_journal_reservation() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::default())
            .expect("claim")
            .claim;
        let before = sim.journal_entries().len();
        let effect_id = publication_push_descriptor().effect_id().to_string();
        let admission = store
            .reserve_remote_publication_effect(claim.token, publication_push_descriptor())
            .expect("reserve");
        let RemotePublicationEffectAdmission::Reserved(reservation) = admission else {
            panic!("expected reserved remote admission");
        };
        assert_eq!(reservation.claim_token(), claim.token);
        assert_eq!(reservation.effect_id(), effect_id);
        assert!(!reservation.work_cancellation().is_cancelled());
        let entries = sim.journal_entries();
        assert!(entries.len() > before);
        let body = entries.last().expect("journal entry").comment().body();
        assert!(body.contains(&effect_id));
        assert!(body.contains("effect_reserve"));
    }

    #[test]
    fn reserve_remote_publication_effect_refuses_lost_remote_permit() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let timing = ClaimTiming::new(1, 3).expect("timing");
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], timing)
            .expect("claim")
            .claim;
        let predecessor = store
            .inspect_remote_claim_owner(claim.token)
            .expect("inspect")
            .owner()
            .clone();
        sim_peer_remote_takeover(&sim, predecessor, "agent-b", &claim.paths).expect("takeover");
        store
            .heartbeat(claim.token, "agent-a", None)
            .expect_err("remote heartbeat refused");
        let error = store
            .reserve_remote_publication_effect(claim.token, publication_push_descriptor())
            .expect_err("lost permit");
        assert!(
            format!("{error:#}").contains("no longer live")
                || format!("{error:#}").contains("not live")
                || format!("{error:#}").contains("refused"),
            "{error:#}"
        );
    }

    #[test]
    fn complete_remote_publication_effect_refuses_without_configured_verifier() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::default())
            .expect("claim")
            .claim;
        let effect_id = publication_push_descriptor().effect_id().to_string();
        let RemotePublicationEffectAdmission::Reserved(reservation) = store
            .reserve_remote_publication_effect(claim.token, publication_push_descriptor())
            .expect("reserve")
        else {
            panic!("expected reservation");
        };
        let nonce = reserve_event_nonce_from_sim(&sim, &effect_id);
        let receipt = bound_push_completion_receipt(&nonce, &effect_id);
        let error = store
            .complete_remote_publication_effect(*reservation, receipt)
            .expect_err("live verifier required");
        assert!(
            error.to_string().contains("live publication verifier")
                || error.to_string().contains("EffectReconciliationRejected"),
            "{error}"
        );
        let entries_after_fail = sim.journal_entries().len();
        assert!(
            entries_after_fail >= 1,
            "reservation journal entry must remain after failed completion"
        );
    }

    #[test]
    fn complete_remote_publication_effect_verifies_receipt_and_clears_reservation() {
        let temp = init_repo();
        let live_verifier: Arc<dyn PublicationEffectLiveVerifier + Send + Sync> =
            Arc::new(AlwaysVerifiedLiveVerifier);
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote_and_live_verifier(
            temp.path(),
            sim.shared_clone(),
            Some(live_verifier),
        )
        .expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::default())
            .expect("claim")
            .claim;
        let effect_id = publication_push_descriptor().effect_id().to_string();
        let reserved = store
            .reserve_remote_publication_effect(claim.token, publication_push_descriptor())
            .expect("reserve");
        let RemotePublicationEffectAdmission::Reserved(reservation) = reserved else {
            panic!("expected reservation");
        };
        let reserve_entries = sim.journal_entries().len();
        let nonce = reserve_event_nonce_from_sim(&sim, &effect_id);
        let receipt = bound_push_completion_receipt(&nonce, &effect_id);
        store
            .complete_remote_publication_effect(*reservation, receipt)
            .expect("complete");
        let entries = sim.journal_entries();
        assert!(entries.len() > reserve_entries);
        let body = entries.last().expect("completion entry").comment().body();
        assert!(body.contains("effect_complete"));
        assert!(body.contains(&effect_id));
    }

    #[test]
    fn selected_remote_heartbeat_refuses_wrong_local_owner_before_remote_mutation() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::default())
            .expect("claim")
            .claim;
        let journal_before = sim.journal_entries().len();
        let liveness_before = store.liveness_snapshot().expect("liveness before")[0]
            .heartbeat_unix_seconds
            .expect("initialized heartbeat");
        let error = store
            .heartbeat_at(claim.token, "agent-b", None, liveness_before + 1)
            .expect_err("wrong local owner");
        assert!(
            format!("{error:#}").contains("does not exactly match owner"),
            "{error:#}"
        );
        assert_eq!(sim.journal_entries().len(), journal_before);
        assert_eq!(
            store.liveness_snapshot().expect("liveness after refusal")[0].heartbeat_unix_seconds,
            Some(liveness_before)
        );
        let journal_before_owner = sim.journal_entries().len();
        store
            .heartbeat_at(claim.token, "agent-a", None, liveness_before + 1)
            .expect("exact owner heartbeat");
        assert!(
            sim.journal_entries().len() > journal_before_owner,
            "correct owner must record remote heartbeat in journal"
        );
        assert_eq!(
            store
                .liveness_snapshot_at(liveness_before + 1)
                .expect("liveness after owner heartbeat")[0]
                .heartbeat_unix_seconds,
            Some(liveness_before + 1)
        );
        let journal_after_owner = sim.journal_entries().len();
        let unknown = crate::sync::ClaimToken::from_u64(9_999_999);
        let absent_error = store
            .heartbeat_at(unknown, "agent-a", None, liveness_before + 2)
            .expect_err("absent token");
        assert!(
            format!("{absent_error:#}").contains("claim token is not active"),
            "{absent_error:#}"
        );
        assert_eq!(sim.journal_entries().len(), journal_after_owner);
    }

    #[test]
    fn selected_remote_heartbeat_missing_binding_cannot_extend_local_claim() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim).expect("open");
        let claim = store
            .claim_paths_with_timing("agent-a", ["src/a.rs"], ClaimTiming::new(10, 30).unwrap())
            .expect("claim")
            .claim;
        let before = store.liveness_snapshot().expect("liveness before")[0]
            .heartbeat_unix_seconds
            .expect("initialized heartbeat");
        store
            .with_locked_update(|_, _, _, _, remote_owners| {
                remote_owners.clear();
                Ok(())
            })
            .expect("construct authenticated inconsistent binding state");
        let error = store
            .heartbeat_at(claim.token, "agent-a", None, before + 1)
            .expect_err("remote binding is mandatory");
        assert!(format!("{error:#}").contains("authenticated owner binding before heartbeat"));
        assert_eq!(
            store.liveness_snapshot().expect("liveness after")[0].heartbeat_unix_seconds,
            Some(before)
        );
    }

    #[test]
    fn fresh_peer_sync_store_observes_and_takeover_remote_without_predecessor_local_state() {
        use crate::worktree::WorktreeManager;
        use tempfile::TempDir;

        let timing = ClaimTiming::new(1, 3).expect("timing");
        let temp_a = init_repo();
        let temp_b = TempDir::new().expect("tempdir b");
        let temp_c = TempDir::new().expect("tempdir c");
        let repo_b = temp_b.path().join("repo");
        let repo_c = temp_c.path().join("repo");
        WorktreeManager::init_repository(&repo_b, "main").expect("init b");
        WorktreeManager::init_repository(&repo_c, "main").expect("init c");

        let sim = SimTransport::new(temp_a.path().to_path_buf());
        let shared = sim.shared_clone();
        let store_a = open_sync_with_sim_remote(temp_a.path(), sim).expect("open a");
        let claim = store_a
            .claim_paths_with_timing("agent-a", ["src/a.rs"], timing)
            .expect("claim a")
            .claim;
        let predecessor = store_a
            .inspect_remote_claim_owner(claim.token)
            .expect("inspect a")
            .owner()
            .clone();

        let store_b = open_sync_with_sim_remote(&repo_b, shared.shared_clone()).expect("open b");
        let observation = store_b.remote_authority_observation().expect("observe b");
        assert!(!observation.observation_permits_work);
        assert_eq!(observation.active_owners.len(), 1);
        assert_eq!(
            observation.active_owners[0].run_identity,
            predecessor.run_identity()
        );
        assert_eq!(
            observation.active_owners[0].activation_nonce,
            predecessor.activation_nonce()
        );

        let wrong_predecessor =
            CoordinationOwnerIdentity::new("other-run", "wrong-nonce").expect("wrong");
        assert!(store_b
            .takeover_remote(
                wrong_predecessor,
                "agent-b",
                claim.paths.clone(),
                Some(timing),
            )
            .is_err());

        let live_refusal = store_b
            .takeover_remote(
                predecessor.clone(),
                "agent-b",
                claim.paths.clone(),
                Some(timing),
            )
            .expect_err("live predecessor must block remote takeover until provider lease elapses");
        let live_refusal_message = format!("{live_refusal:#}");
        assert!(
            live_refusal_message.contains("remote scope authority refused")
                && live_refusal_message.contains("RemoteNotApplied"),
            "expected trusted journal refusal, got: {live_refusal_message}"
        );
        assert!(
            store_b.snapshot().expect("snapshot after refused takeover").is_empty(),
            "confirmed remote refusal must roll back the local reservation on host B: {live_refusal_message}"
        );

        shared.advance_provider_clock();

        let successor_outcome = store_b
            .takeover_remote(
                predecessor.clone(),
                "agent-b",
                claim.paths.clone(),
                Some(timing),
            )
            .expect("takeover b");
        assert_eq!(successor_outcome.claim.agent_id, "agent-b");
        let successor_owner = store_b
            .inspect_remote_claim_owner(successor_outcome.claim.token)
            .expect("inspect successor")
            .owner()
            .clone();
        assert_eq!(successor_owner.run_identity(), "agent-b");
        assert_ne!(
            successor_owner.activation_nonce(),
            predecessor.activation_nonce()
        );

        store_a
            .heartbeat(claim.token, "agent-a", None)
            .expect_err("predecessor local token must refuse remote heartbeat after takeover");

        let store_c = open_sync_with_sim_remote(&repo_c, shared).expect("open c");
        let observed_c = store_c.remote_authority_observation().expect("observe c");
        assert_eq!(observed_c.active_owners.len(), 1);
        assert_eq!(
            observed_c.active_owners[0].run_identity,
            successor_owner.run_identity()
        );
        assert_eq!(
            observed_c.active_owners[0].activation_nonce,
            successor_owner.activation_nonce()
        );

        assert!(store_b
            .remote_work_lease(successor_outcome.claim.token)
            .expect("lease lookup")
            .is_some());
    }
}
