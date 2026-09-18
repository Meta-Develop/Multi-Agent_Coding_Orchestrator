//! Publication-time remote coordination claim admission and heartbeat (#410).

use crate::{
    process_runner::ProcessCancellation,
    publication::coordination_effect::PublicationEffectDescriptorV1,
    publication::coordination_mode::{remote_coordination_status, RemoteCoordinationStatusReport},
    sync::ClaimToken,
    sync_store::{
        remote_coordination::{
            RemoteClaimSharedEffectReservation, RemoteCoordination,
            RemotePublicationEffectAdmission,
        },
        ClaimTiming, ManagedClaimProcessCancellation, SyncStore,
    },
};
use anyhow::{bail, Context, Result};
use std::sync::Arc;
use std::{
    path::{Path, PathBuf},
    sync::mpsc,
    thread::{self, JoinHandle},
    time::Duration,
};

#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PublicationCoordinationMode {
    LocalOnly,
    SelectedRemote,
}

pub(crate) enum PublicationCoordinationAdmission {
    LocalOnly,
    SelectedRemote(Box<PublicationRemoteClaimAuthority>),
}

impl PublicationCoordinationAdmission {
    pub(crate) fn is_selected_remote(&self) -> bool {
        matches!(self, Self::SelectedRemote(_))
    }

    pub(crate) fn assert_invoke_allowed(&self) -> Result<()> {
        match self {
            Self::LocalOnly => Ok(()),
            Self::SelectedRemote(authority) => {
                if authority.managed_process_cancellation().is_cancelled() {
                    bail!(
                        "publication remote claim authority is cancelled; refusing external publication invoke"
                    );
                }
                Ok(())
            }
        }
    }

    /// Revalidates remote owner lease and cancellation immediately before external mutation.
    pub(crate) fn assert_invoke_allowed_immediately_before_external_mutation(&self) -> Result<()> {
        match self {
            Self::LocalOnly => Ok(()),
            Self::SelectedRemote(authority) => {
                authority.assert_invoke_allowed_immediately_before_external_mutation()
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn mode(&self) -> PublicationCoordinationMode {
        match self {
            Self::LocalOnly => PublicationCoordinationMode::LocalOnly,
            Self::SelectedRemote(_) => PublicationCoordinationMode::SelectedRemote,
        }
    }

    pub(crate) fn establish(
        repo_root: &Path,
        agent_id: &str,
        scope_paths: &[PathBuf],
        run_cancellation: Option<&ProcessCancellation>,
    ) -> Result<Self> {
        let status = remote_coordination_status(repo_root)?;
        if !status.selected {
            return Ok(Self::LocalOnly);
        }
        validate_selected_remote_coordination_snapshot(&status)?;
        let store = SyncStore::open(repo_root)?;
        let authority = PublicationRemoteClaimAuthority::admit_selected_remote(
            store,
            agent_id,
            scope_paths,
            run_cancellation,
        )?;
        Ok(Self::SelectedRemote(Box::new(authority)))
    }

    pub(crate) fn managed_process_cancellation(&self) -> Option<&ProcessCancellation> {
        match self {
            Self::LocalOnly => None,
            Self::SelectedRemote(authority) => Some(authority.managed_process_cancellation()),
        }
    }

    pub(crate) fn reserve_remote_publication_effect(
        &mut self,
        publication_effect: PublicationEffectDescriptorV1,
    ) -> Result<RemotePublicationEffectAdmission> {
        match self {
            Self::LocalOnly => Ok(RemotePublicationEffectAdmission::LocalOnly),
            Self::SelectedRemote(authority) => {
                authority.reserve_remote_publication_effect(publication_effect)
            }
        }
    }

    pub(crate) fn complete_remote_publication_effect(
        &mut self,
        reservation: RemoteClaimSharedEffectReservation,
        reconciliation: crate::publication::coordination_journal::EffectReconciliationReceipt,
    ) -> Result<()> {
        match self {
            Self::LocalOnly => bail!(
                "cannot complete a remote publication effect while coordination mode is local-only"
            ),
            Self::SelectedRemote(authority) => {
                authority.complete_remote_publication_effect(reservation, reconciliation)
            }
        }
    }

    pub(crate) fn finish_successful_publication(self) -> Result<()> {
        match self {
            Self::LocalOnly => Ok(()),
            Self::SelectedRemote(authority) => authority.finish_successful_publication(),
        }
    }

    pub(crate) fn abandon_incomplete_publication(self) {
        if let Self::SelectedRemote(authority) = self {
            authority.abandon_incomplete_publication();
        }
    }
}

/// Holds live coordination until publication effects finish or the scope is abandoned.
pub(crate) struct PublicationCoordinationGuard {
    admission: Option<PublicationCoordinationAdmission>,
    released: bool,
}

impl PublicationCoordinationGuard {
    pub(crate) fn new(admission: PublicationCoordinationAdmission) -> Self {
        Self {
            admission: Some(admission),
            released: false,
        }
    }

    pub(crate) fn take_admission(&mut self) -> PublicationCoordinationAdmission {
        self.admission
            .take()
            .expect("publication coordination guard already consumed")
    }

    pub(crate) fn restore_admission(&mut self, admission: PublicationCoordinationAdmission) {
        self.admission = Some(admission);
    }

    pub(crate) fn finish_success(mut self) -> Result<()> {
        if let Some(admission) = self.admission.take() {
            let outcome = admission.finish_successful_publication();
            self.released = true;
            outcome?;
        } else {
            self.released = true;
        }
        Ok(())
    }
}

impl Drop for PublicationCoordinationGuard {
    fn drop(&mut self) {
        if !self.released {
            if let Some(admission) = self.admission.take() {
                admission.abandon_incomplete_publication();
            }
        }
    }
}

/// Carries the durable publication transaction together with live coordination authority.
pub(crate) struct PublicationCoordinationBundle {
    pub(crate) transaction: PublicationTransaction,
    pub(crate) coordination: PublicationCoordinationAdmission,
}

impl PublicationCoordinationBundle {
    pub(crate) fn open(
        coordination: PublicationCoordinationAdmission,
        repo_root: &Path,
        report: &PrPublicationReport,
        remote_name: &str,
        remote_url: &str,
        expected_oid: &str,
        source_guard: Option<ExternalSourceGuard>,
    ) -> Result<Self> {
        let transaction = PublicationTransaction::open(
            repo_root,
            report,
            remote_name,
            remote_url,
            expected_oid,
            source_guard,
        )?;
        Ok(Self {
            transaction,
            coordination,
        })
    }
}

pub(crate) fn validate_selected_remote_coordination_snapshot(
    status: &RemoteCoordinationStatusReport,
) -> Result<()> {
    if !status.selected {
        bail!("internal: validate_selected_remote_coordination_snapshot requires selected remote");
    }
    let timing = status.claim_timing.context(
        "remote coordination is selected but authenticated snapshot has no claim timing",
    )?;
    timing.validate()?;
    if status
        .selection_digest
        .as_ref()
        .is_none_or(|digest| digest.is_empty())
    {
        bail!("remote coordination is selected but selection digest is missing");
    }
    if status
        .repository_selector
        .as_ref()
        .is_none_or(|value| value.is_empty())
    {
        bail!("remote coordination is selected but repository selector is missing");
    }
    if status
        .journal_ref
        .as_ref()
        .is_none_or(|value| value.is_empty())
    {
        bail!("remote coordination is selected but journal reference is missing");
    }
    if status
        .anchor_commit_oid
        .as_ref()
        .is_none_or(|value| value.is_empty())
    {
        bail!("remote coordination is selected but anchor commit OID is missing");
    }
    Ok(())
}

fn remote_backend_on_store(store: &SyncStore) -> Result<Arc<RemoteCoordination>> {
    publication_store_remote_handle(store).context(
        "remote coordination is selected but this SyncStore has no remote coordination backend attached",
    )
}

fn publication_store_remote_handle(store: &SyncStore) -> Option<Arc<RemoteCoordination>> {
    store.remote_coordination_handle()
}

pub(crate) struct PublicationRemoteClaimAuthority {
    store: SyncStore,
    claim_token: ClaimToken,
    managed: ManagedClaimProcessCancellation,
    heartbeat: PublicationClaimHeartbeat,
    pending_remote_effects: usize,
    finished: bool,
}

impl PublicationRemoteClaimAuthority {
    pub(crate) fn admit_selected_remote(
        store: SyncStore,
        agent_id: &str,
        scope_paths: &[PathBuf],
        run_cancellation: Option<&ProcessCancellation>,
    ) -> Result<Self> {
        if scope_paths.is_empty() {
            bail!("publication remote claim admission requires a non-empty changed-path scope");
        }
        let remote = remote_backend_on_store(&store)?;
        let timing = remote.remote_claim_timing();
        timing.validate()?;
        let outcome = store
            .claim_paths_with_timing(agent_id, scope_paths.iter().map(PathBuf::as_path), timing)
            .context("publication remote claim admission failed")?;
        let claim = outcome.claim;
        store
            .remote_work_lease(claim.token)?
            .context(
                "selected remote publication requires an authenticated remote work lease on the admitted claim",
            )?;
        let run = run_cancellation
            .cloned()
            .unwrap_or_else(ProcessCancellation::new);
        let managed = store
            .managed_process_cancellation_for_claim(claim.token, &run)
            .context("publication remote managed process cancellation")?;
        let heartbeat = PublicationClaimHeartbeat::start(
            store.clone(),
            claim.token,
            agent_id.to_string(),
            timing,
            managed.cancellation().clone(),
        )?;
        Ok(Self {
            store,
            claim_token: claim.token,
            managed,
            heartbeat,
            pending_remote_effects: 0,
            finished: false,
        })
    }

    #[cfg(test)]
    pub(crate) fn claim_token(&self) -> ClaimToken {
        self.claim_token
    }

    pub(crate) fn managed_process_cancellation(&self) -> &ProcessCancellation {
        self.managed.cancellation()
    }

    pub(crate) fn assert_invoke_allowed_immediately_before_external_mutation(&self) -> Result<()> {
        self.assert_active_owner()?;
        self.store.remote_work_lease(self.claim_token)?.context(
            "publication remote work lease was lost immediately before external publication invoke",
        )?;
        Ok(())
    }

    pub(crate) fn reserve_remote_publication_effect(
        &mut self,
        publication_effect: PublicationEffectDescriptorV1,
    ) -> Result<RemotePublicationEffectAdmission> {
        self.assert_active_owner()?;
        let effect_id = publication_effect.effect_id().to_string();
        let admission = self
            .store
            .reserve_remote_publication_effect(self.claim_token, publication_effect)?;
        match admission {
            RemotePublicationEffectAdmission::LocalOnly => {
                bail!(
                    "selected remote publication authority refused local-only effect admission for effect '{effect_id}'"
                );
            }
            RemotePublicationEffectAdmission::Reserved(reservation) => {
                self.pending_remote_effects += 1;
                Ok(RemotePublicationEffectAdmission::Reserved(reservation))
            }
        }
    }

    pub(crate) fn complete_remote_publication_effect(
        &mut self,
        reservation: RemoteClaimSharedEffectReservation,
        reconciliation: crate::publication::coordination_journal::EffectReconciliationReceipt,
    ) -> Result<()> {
        self.assert_active_owner()?;
        if reservation.claim_token() != self.claim_token {
            bail!(
                "remote publication effect reservation token {} does not match active publication claim {}",
                reservation.claim_token().get(),
                self.claim_token.get()
            );
        }
        self.store
            .complete_remote_publication_effect(reservation, reconciliation)?;
        self.pending_remote_effects = self.pending_remote_effects.saturating_sub(1);
        Ok(())
    }

    pub(crate) fn finish_successful_publication(mut self) -> Result<()> {
        self.heartbeat.stop();
        self.assert_active_owner()?;
        if self.pending_remote_effects > 0 {
            bail!(
                "refusing to release publication claim {} while {} remote effect reservation(s) remain pending",
                self.claim_token.get(),
                self.pending_remote_effects
            );
        }
        self.store
            .release(self.claim_token)
            .context("publication claim release after successful effects")?;
        self.finished = true;
        Ok(())
    }

    pub(crate) fn abandon_incomplete_publication(mut self) {
        self.heartbeat.stop();
    }

    fn assert_active_owner(&self) -> Result<()> {
        if self.finished {
            bail!("publication remote claim authority is already finished");
        }
        if self.managed.cancellation().is_cancelled() {
            bail!(
                "publication remote claim authority is cancelled; refusing further remote publication effects"
            );
        }
        Ok(())
    }
}

impl Drop for PublicationRemoteClaimAuthority {
    fn drop(&mut self) {
        self.heartbeat.stop();
    }
}

struct PublicationClaimHeartbeat {
    stop: mpsc::Sender<()>,
    join: Option<JoinHandle<()>>,
}

impl PublicationClaimHeartbeat {
    fn start(
        store: SyncStore,
        token: ClaimToken,
        agent_id: String,
        timing: ClaimTiming,
        command_cancellation: ProcessCancellation,
    ) -> Result<Self> {
        let (stop_tx, stop_rx) = mpsc::channel();
        let interval = timing.heartbeat_interval_seconds.max(1);
        let join = thread::Builder::new()
            .name("maco-publication-claim-heartbeat".into())
            .spawn(move || {
                run_publication_claim_heartbeat(
                    store,
                    token,
                    agent_id,
                    timing,
                    interval,
                    command_cancellation,
                    stop_rx,
                )
            })
            .context("failed to spawn publication claim heartbeat worker")?;
        Ok(Self {
            stop: stop_tx,
            join: Some(join),
        })
    }

    fn stop(&mut self) {
        let _ = self.stop.send(());
        if let Some(join) = self.join.take() {
            let _ = join.join();
        }
    }
}

fn run_publication_claim_heartbeat(
    store: SyncStore,
    token: ClaimToken,
    agent_id: String,
    timing: ClaimTiming,
    interval_seconds: u64,
    command_cancellation: ProcessCancellation,
    stop_rx: mpsc::Receiver<()>,
) {
    let interval = Duration::from_secs(interval_seconds);
    match stop_rx.recv_timeout(interval) {
        Ok(()) | Err(mpsc::RecvTimeoutError::Disconnected) => return,
        Err(mpsc::RecvTimeoutError::Timeout) => {}
    }
    loop {
        if stop_rx.try_recv().is_ok() {
            return;
        }
        match store.heartbeat(token, &agent_id, Some(timing)) {
            Ok(_) => {}
            Err(error) => {
                eprintln!(
                    "publication claim heartbeat failed for agent '{agent_id}' token {}: {error:#}",
                    token.get()
                );
                command_cancellation.cancel();
                return;
            }
        }
        if stop_rx.recv_timeout(interval).is_ok() {
            return;
        }
    }
}

use super::{
    coordination_provider::ParentPublicationProviderVerifier, ExternalSourceGuard,
    PrPublicationReport, PublicationTransaction,
};
use crate::publication::coordination_journal::{
    EffectReconciliationOutcome, EffectReconciliationReceipt,
};

pub(crate) fn complete_bound_publication_reservation(
    worktree: &Path,
    coordination: &mut PublicationCoordinationAdmission,
    reservation: RemoteClaimSharedEffectReservation,
) -> Result<()> {
    coordination.assert_invoke_allowed_immediately_before_external_mutation()?;
    let descriptor = reservation.publication_descriptor()?.clone();
    let reserve_event_nonce = reservation.reserve_event_nonce();
    let verifier = ParentPublicationProviderVerifier::new(worktree.to_path_buf());
    let material = verifier.observe_bound_completion(&descriptor, reserve_event_nonce)?;
    let receipt = EffectReconciliationReceipt::new_bound(
        descriptor.effect_id(),
        EffectReconciliationOutcome::Completed,
        material,
    )?;
    coordination.complete_remote_publication_effect(reservation, receipt)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        sync_store::{
            remote_coordination::{
                test_support::{
                    open_sync_with_sim_remote, sample_publication_git_push_descriptor,
                    sim_peer_remote_takeover, SimTransport,
                },
                RemotePublicationEffectAdmission,
            },
            ClaimTiming,
        },
        worktree::WorktreeManager,
    };
    use tempfile::TempDir;

    fn init_repo() -> TempDir {
        let temp = tempfile::tempdir().expect("tempdir");
        WorktreeManager::init_repository(temp.path(), "main").expect("init");
        temp
    }

    fn publication_push_descriptor() -> PublicationEffectDescriptorV1 {
        sample_publication_git_push_descriptor()
    }

    #[test]
    fn malformed_selected_remote_snapshot_errors_without_timing() {
        let status = RemoteCoordinationStatusReport {
            selected: true,
            selection_digest: Some("d".repeat(64)),
            repository_selector: Some("github.com/o/r".to_string()),
            anchor_issue_number: Some(1),
            journal_ref: Some("ref".to_string()),
            anchor_commit_oid: Some("abc".to_string()),
            claim_timing: None,
            operator_config_path: Some("/tmp/op".to_string()),
        };
        let error = validate_selected_remote_coordination_snapshot(&status).expect_err("timing");
        assert!(error.to_string().contains("claim timing"), "{error}");
    }

    #[test]
    fn publication_remote_claim_admits_with_simulated_backend() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim).expect("open");
        let authority = PublicationRemoteClaimAuthority::admit_selected_remote(
            store.clone(),
            "agent-a",
            &[PathBuf::from("README.md")],
            None,
        )
        .expect("admit");
        let claim = store
            .snapshot()
            .expect("snapshot")
            .into_iter()
            .find(|claim| claim.token == authority.claim_token())
            .expect("admitted claim");
        assert_eq!(claim.agent_id, "agent-a");
        let inspection = store
            .inspect_remote_claim_owner(authority.claim_token())
            .expect("remote claim owner inspection");
        assert!(inspection.locally_authenticated());
        authority.abandon_incomplete_publication();
    }

    #[test]
    fn publication_remote_claim_refuses_overlapping_second_owner() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim).expect("open");
        let first = PublicationRemoteClaimAuthority::admit_selected_remote(
            store.clone(),
            "agent-a",
            &[PathBuf::from("README.md")],
            None,
        )
        .expect("first");
        let overlap = PublicationRemoteClaimAuthority::admit_selected_remote(
            store,
            "agent-b",
            &[PathBuf::from("README.md")],
            None,
        );
        let error = overlap
            .err()
            .expect("expected overlapping claim admission to fail");
        assert!(
            format!("{error:#}").contains("claim")
                || format!("{error:#}").contains("refused")
                || format!("{error:#}").contains("overlap"),
            "{error:#}"
        );
        first.abandon_incomplete_publication();
    }

    #[test]
    fn publication_finish_refuses_release_with_pending_remote_effect() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim).expect("open");
        let mut authority = PublicationRemoteClaimAuthority::admit_selected_remote(
            store,
            "agent-a",
            &[PathBuf::from("src/a.rs")],
            None,
        )
        .expect("admit");
        let RemotePublicationEffectAdmission::Reserved(_reservation) = authority
            .reserve_remote_publication_effect(publication_push_descriptor())
            .expect("reserve")
        else {
            panic!("expected reserved admission");
        };
        let error = authority
            .finish_successful_publication()
            .expect_err("pending effect");
        assert!(error.to_string().contains("pending"), "{error}");
    }

    #[test]
    fn publication_heartbeat_loss_cancels_managed_command_cancellation() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let timing = ClaimTiming::new(1, 3).expect("timing");
        let mut authority = PublicationRemoteClaimAuthority::admit_selected_remote(
            store.clone(),
            "agent-a",
            &[PathBuf::from("src/a.rs")],
            None,
        )
        .expect("admit");
        let inspection = store
            .inspect_remote_claim_owner(authority.claim_token())
            .expect("inspect");
        let predecessor = inspection.owner().clone();
        sim_peer_remote_takeover(&sim, predecessor, "agent-b", &[PathBuf::from("src/a.rs")])
            .expect("takeover");
        store
            .heartbeat(authority.claim_token(), "agent-a", Some(timing))
            .expect_err("heartbeat refused");
        assert!(
            authority.managed_process_cancellation().is_cancelled(),
            "managed publication cancellation must observe remote authority loss via composed lease"
        );
        let journal_before = sim.journal_entries().len();
        let reserve_error = authority
            .reserve_remote_publication_effect(publication_push_descriptor())
            .expect_err("reserve after authority loss");
        assert!(
            format!("{reserve_error:#}").contains("cancelled")
                || format!("{reserve_error:#}").contains("not live")
                || format!("{reserve_error:#}").contains("refused")
                || format!("{reserve_error:#}").contains("lost"),
            "{reserve_error:#}"
        );
        assert_eq!(
            sim.journal_entries().len(),
            journal_before,
            "must not record a new remote effect reservation after authority loss"
        );
        authority.abandon_incomplete_publication();
    }

    #[test]
    fn publication_reserve_refuses_missing_authenticated_binding() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim).expect("open");
        let mut authority = PublicationRemoteClaimAuthority::admit_selected_remote(
            store.clone(),
            "agent-a",
            &[PathBuf::from("src/a.rs")],
            None,
        )
        .expect("admit");
        store
            .test_clear_authenticated_remote_owner_bindings()
            .expect("clear binding");
        let error = authority
            .reserve_remote_publication_effect(publication_push_descriptor())
            .expect_err("binding");
        assert!(
            error
                .to_string()
                .contains("authenticated remote owner binding"),
            "{error}"
        );
    }

    #[test]
    fn publication_coordination_admission_local_only_without_remote_store() {
        let temp = init_repo();
        let admission = PublicationCoordinationAdmission::establish(
            temp.path(),
            "agent-a",
            &[PathBuf::from("README.md")],
            None,
        )
        .expect("establish");
        assert_eq!(admission.mode(), PublicationCoordinationMode::LocalOnly);
    }

    #[test]
    fn selected_remote_authority_refuses_local_only_store_before_claim() {
        let temp = init_repo();
        let store = SyncStore::open(temp.path()).expect("open");
        assert!(publication_store_remote_handle(&store).is_none());
        let claims_before = store.snapshot().expect("snapshot").len();
        let local_only = PublicationRemoteClaimAuthority::admit_selected_remote(
            store,
            "agent-a",
            &[PathBuf::from("README.md")],
            None,
        );
        let error = local_only
            .err()
            .expect("local-only store must refuse remote claim admission");
        assert!(
            error
                .to_string()
                .contains("no remote coordination backend attached"),
            "{error}"
        );
        let claims_after = SyncStore::open(temp.path())
            .expect("reopen")
            .snapshot()
            .expect("snapshot")
            .len();
        assert_eq!(claims_before, claims_after);
    }

    #[test]
    fn operator_cancelled_authority_refuses_reserve_without_new_reservation() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let run = ProcessCancellation::new();
        let mut authority = PublicationRemoteClaimAuthority::admit_selected_remote(
            store,
            "agent-a",
            &[PathBuf::from("src/a.rs")],
            Some(&run),
        )
        .expect("admit");
        let journal_before = sim.journal_entries().len();
        run.cancel();
        assert!(authority.managed_process_cancellation().is_cancelled());
        let error = authority
            .reserve_remote_publication_effect(publication_push_descriptor())
            .expect_err("cancelled");
        assert!(error.to_string().contains("cancelled"), "{error}");
        assert_eq!(sim.journal_entries().len(), journal_before);
        authority.abandon_incomplete_publication();
    }

    #[test]
    fn selected_remote_admission_exposes_managed_process_cancellation_binding() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim).expect("open");
        let run = ProcessCancellation::new();
        let authority = PublicationRemoteClaimAuthority::admit_selected_remote(
            store,
            "agent-a",
            &[PathBuf::from("src/a.rs")],
            Some(&run),
        )
        .expect("admit");
        let admission = PublicationCoordinationAdmission::SelectedRemote(Box::new(authority));
        let managed = admission
            .managed_process_cancellation()
            .expect("selected remote managed cancellation");
        assert!(!managed.is_cancelled());
        admission.abandon_incomplete_publication();
    }

    #[test]
    fn cancelled_after_reserve_refuses_immediate_invoke_fence_without_new_provider_writes() {
        let temp = init_repo();
        let sim = SimTransport::new(temp.path().to_path_buf());
        let store = open_sync_with_sim_remote(temp.path(), sim.shared_clone()).expect("open");
        let run = ProcessCancellation::new();
        let mut authority = PublicationRemoteClaimAuthority::admit_selected_remote(
            store,
            "agent-a",
            &[PathBuf::from("src/a.rs")],
            Some(&run),
        )
        .expect("admit");
        let journal_after_admit = sim.journal_entries().len();
        let RemotePublicationEffectAdmission::Reserved(_reservation) = authority
            .reserve_remote_publication_effect(publication_push_descriptor())
            .expect("reserve")
        else {
            panic!("expected reserved admission");
        };
        let journal_after_reserve = sim.journal_entries().len();
        assert!(
            journal_after_reserve > journal_after_admit,
            "reservation must record provider journal state"
        );
        run.cancel();
        let error = authority
            .assert_invoke_allowed_immediately_before_external_mutation()
            .expect_err("cancelled before invoke");
        assert!(error.to_string().contains("cancelled"), "{error}");
        assert_eq!(sim.journal_entries().len(), journal_after_reserve);
        authority.abandon_incomplete_publication();
    }
}
