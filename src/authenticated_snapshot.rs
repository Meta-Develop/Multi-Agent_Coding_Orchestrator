//! Typed immutable snapshots backed by the repository-authenticated journal.
//!
//! Each generation stores the complete value, a strictly increasing consumer
//! token, and its generation number. The generic journal supplies immutable
//! record publication, the HMAC chain and head, full-lifecycle locking, and the
//! single-record crash window. An existing instance with no authenticated
//! generation is never interpreted as an empty store.

// This crate-private foundation intentionally lands before every state consumer
// is converted; focused tests exercise the rollover and recovery API meanwhile.
#![allow(dead_code)]

use crate::{
    artifacts::state_auth::{
        random_identifier, sha256_hex, AuthenticationDomain, AuthenticationTag, BoundStateLock,
        RepositoryAuthenticator,
    },
    safe_state::{
        remove_direct_child_tree, AtomicStateWriter, BoundedRegularReader, FileIdentity, SafeRoot,
        TreeLinkPolicy,
    },
    state_journal::{
        AuthenticatedStateJournal, AuthenticatedStateJournalSnapshot, JournalIdentity, JournalSpec,
    },
    state_migration::is_legacy_retirement_metadata_name,
};
use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeMap, BTreeSet},
    ffi::{OsStr, OsString},
    fs,
    fs::File,
    marker::PhantomData,
};

const SNAPSHOT_METADATA_FILES_PER_LOGICAL: usize = 3;
const SNAPSHOT_RESIDUE_FORMS_PER_FILE: usize = 2;
// Mutation-capable discovery wrappers must still recover when each metadata
// file contributes three interrupted writes beyond a completely full root.
const SNAPSHOT_MIN_RECOVERABLE_RESIDUES: usize = 9;

pub(crate) trait SnapshotSpec: JournalSpec {
    const SNAPSHOT_FORMAT_VERSION: u32;
    const SNAPSHOT_PHASE: &'static str = "snapshot";
    const LOCATOR_DOMAIN: AuthenticationDomain;
    /// Maximum number of logical stores sharing this physical namespace.
    const MAX_LOGICAL_STORES: usize = 1;
    /// Namespace-wide bound across every logical store, including locators,
    /// intents, locks, and physical journal directories.
    const MAX_ROOT_ENTRIES: usize = 160;
    /// Namespace-wide physical retention bound. No automatic garbage
    /// collection is performed because old journals are rollback evidence.
    const MAX_PHYSICAL_INSTANCES: usize = 129;
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct AuthenticatedSnapshot<T> {
    pub version: u32,
    pub generation: u64,
    pub token: u64,
    pub value: T,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotLocator {
    version: u32,
    logical_id: String,
    active_identity: JournalIdentity,
    active_start_generation: u64,
    generation: u64,
    token: u64,
    prior_token: u64,
    prior_terminal_mac: AuthenticationTag,
    terminal_mac: AuthenticationTag,
    retained_instances: Vec<RetainedSnapshotAnchor>,
    mac: AuthenticationTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RetainedSnapshotAnchor {
    identity: JournalIdentity,
    start_generation: u64,
    end_generation: u64,
    terminal_token: u64,
    terminal_mac: AuthenticationTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotInitIntent {
    version: u32,
    logical_id: String,
    attempt: u32,
    physical_id: String,
    mac: AuthenticationTag,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum SnapshotRolloverPhase {
    Prepared,
    Ready,
}

/// Durable publication intent for a physical-journal rollover. `Prepared` is
/// published before the candidate directory can exist, closing the otherwise
/// ambiguous create-before-intent crash gap. Once the candidate's single
/// snapshot record is durable, `Ready` binds its complete identity and tail.
#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct SnapshotRolloverIntent {
    version: u32,
    logical_id: String,
    phase: SnapshotRolloverPhase,
    previous_identity: JournalIdentity,
    previous_start_generation: u64,
    previous_generation: u64,
    previous_token: u64,
    previous_terminal_mac: AuthenticationTag,
    candidate_run_id: String,
    expected_snapshot: Value,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_identity: Option<JournalIdentity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    next_terminal_mac: Option<AuthenticationTag>,
    mac: AuthenticationTag,
}

pub(crate) struct AuthenticatedSnapshotStore<S, T>
where
    S: SnapshotSpec,
{
    journal: AuthenticatedStateJournal<S>,
    store_root: SafeRoot,
    store_lock: BoundStateLock,
    logical_id: String,
    locator: SnapshotLocator,
    current: AuthenticatedSnapshot<T>,
    spec: PhantomData<S>,
}

impl<S, T> AuthenticatedSnapshotStore<S, T>
where
    S: SnapshotSpec,
    T: Serialize + DeserializeOwned,
{
    pub(crate) fn initialized(
        authenticator: &RepositoryAuthenticator,
        logical_id: &str,
    ) -> Result<bool> {
        validate_logical_id::<S>(logical_id)?;
        if !authenticator
            .state_root()
            .direct_child_exists(S::ROOT_NAME)?
        {
            return Ok(false);
        }
        let root = AuthenticatedStateJournal::<S>::existing_root(authenticator)?;
        let root_lock = BoundStateLock::acquire(&root, S::ROOT_LOCK_NAME)?;
        scavenge_snapshot_metadata_temps::<S>(&root, logical_id)?;
        let initialized = root.direct_child_exists(snapshot_locator_name(logical_id))?;
        if initialized {
            let _ = read_locator::<S>(authenticator, &root, logical_id)?;
        } else if root.direct_child_exists(snapshot_init_name(logical_id))? {
            let _ = read_init_intent::<S>(authenticator, &root, logical_id)?;
        }
        verify_root_inventory::<S>(authenticator, &root, &root_lock)?;
        root_lock.verify(&root)?;
        Ok(initialized)
    }

    /// Read-only verification used by offline migration inspection. The
    /// signed locator must name the exact active journal and generation bound
    /// by a retirement tombstone; this function never performs journal or
    /// locator recovery.
    pub(crate) fn verify_locator_anchor(
        authenticator: &RepositoryAuthenticator,
        logical_id: &str,
        identity: &JournalIdentity,
        generation: u64,
    ) -> Result<()> {
        validate_logical_id::<S>(logical_id)?;
        let root = AuthenticatedStateJournal::<S>::existing_root(authenticator)?;
        let root_lock = BoundStateLock::acquire(&root, S::ROOT_LOCK_NAME)?;
        let locator = read_locator::<S>(authenticator, &root, logical_id)?;
        if &locator.active_identity != identity || locator.generation != generation {
            bail!("active authenticated snapshot locator does not match its retirement tombstone");
        }
        if root.direct_child_exists(snapshot_rollover_name(logical_id))? {
            let _ = read_rollover_intent::<S>(authenticator, &root, logical_id)?;
            bail!("authenticated snapshot rollover must be recovered before offline inspection");
        }
        verify_root_inventory_allowing_metadata_temps::<S>(authenticator, &root, &root_lock)?;
        root_lock.verify(&root)?;
        authenticator.verify_epoch()
    }

    pub(crate) fn initialization_pending(
        authenticator: &RepositoryAuthenticator,
        logical_id: &str,
    ) -> Result<bool> {
        validate_logical_id::<S>(logical_id)?;
        if !authenticator
            .state_root()
            .direct_child_exists(S::ROOT_NAME)?
        {
            return Ok(false);
        }
        let root = AuthenticatedStateJournal::<S>::existing_root(authenticator)?;
        let root_lock = BoundStateLock::acquire(&root, S::ROOT_LOCK_NAME)?;
        scavenge_snapshot_metadata_temps::<S>(&root, logical_id)?;
        let pending = if root.direct_child_exists(snapshot_locator_name(logical_id))? {
            false
        } else if root.direct_child_exists(snapshot_init_name(logical_id))? {
            read_init_intent::<S>(authenticator, &root, logical_id)?;
            true
        } else {
            false
        };
        verify_root_inventory::<S>(authenticator, &root, &root_lock)?;
        root_lock.verify(&root)?;
        Ok(pending)
    }

    pub(crate) fn create(
        authenticator: RepositoryAuthenticator,
        logical_id: &str,
        initial_token: u64,
        value: T,
    ) -> Result<Self> {
        if initial_token == 0 {
            bail!("authenticated snapshot initial token must be positive");
        }
        let (store_root, store_lock, intent) =
            begin_snapshot_initialization::<S>(&authenticator, logical_id)?;
        let mut journal =
            AuthenticatedStateJournal::<S>::create(authenticator, &intent.physical_id)?;
        if journal.root().identity() != store_root.identity() {
            bail!("authenticated snapshot initialization changed its journal root identity");
        }
        let current = AuthenticatedSnapshot {
            version: S::SNAPSHOT_FORMAT_VERSION,
            generation: 1,
            token: initial_token,
            value,
        };
        journal
            .append(S::SNAPSHOT_PHASE, None, &current)
            .context("failed to publish initial authenticated snapshot")?;
        let terminal_mac = journal
            .records()
            .last()
            .map(|record| record.mac.clone())
            .context("initial authenticated snapshot lost its terminal MAC")?;
        if take_snapshot_fault(SnapshotFaultPoint::BeforeInitial) {
            bail!(
                "injected authenticated snapshot initialization fault before locator publication"
            );
        }
        let mut locator = SnapshotLocator {
            version: S::SNAPSHOT_FORMAT_VERSION,
            logical_id: logical_id.to_string(),
            active_identity: journal.identity().clone(),
            active_start_generation: 1,
            generation: 1,
            token: initial_token,
            prior_token: 0,
            prior_terminal_mac: AuthenticationTag::zero(),
            terminal_mac,
            retained_instances: Vec::new(),
            mac: AuthenticationTag::zero(),
        };
        let root_lock = BoundStateLock::acquire(&store_root, S::ROOT_LOCK_NAME)?;
        scavenge_snapshot_metadata_temps::<S>(&store_root, logical_id)?;
        write_locator::<S>(
            journal.authenticator(),
            &store_root,
            &store_lock,
            &root_lock,
            &mut locator,
        )?;
        if take_snapshot_fault(SnapshotFaultPoint::AfterInitial) {
            bail!("injected authenticated snapshot initialization fault after locator publication");
        }
        remove_init_intent::<S>(
            journal.authenticator(),
            &store_root,
            &store_lock,
            &root_lock,
            &intent,
        )?;
        verify_root_inventory::<S>(journal.authenticator(), &store_root, &root_lock)?;
        Ok(Self {
            journal,
            store_root,
            store_lock,
            logical_id: logical_id.to_string(),
            locator,
            current,
            spec: PhantomData,
        })
    }

    pub(crate) fn open_instance(
        authenticator: RepositoryAuthenticator,
        logical_id: &str,
    ) -> Result<Self> {
        validate_logical_id::<S>(logical_id)?;
        let store_root = AuthenticatedStateJournal::<S>::existing_root(&authenticator)?;
        let store_lock = BoundStateLock::try_acquire_optional_existing_exclusive(
            &store_root,
            &snapshot_lock_name(logical_id),
        )
        .context("authenticated snapshot store is active elsewhere or incomplete")?;
        let store_lock = match store_lock {
            Some(store_lock) => store_lock,
            None => {
                // No logical lock exists to order before the namespace lock. A
                // root-only inspection can therefore distinguish an empty
                // namespace from a locator whose stable logical lock vanished.
                let root_lock = BoundStateLock::acquire(&store_root, S::ROOT_LOCK_NAME)?;
                scavenge_snapshot_metadata_temps::<S>(&store_root, logical_id)?;
                root_lock.verify(&store_root)?;
                if !store_root.direct_child_exists(snapshot_locator_name(logical_id))? {
                    bail!(
                        "initialized authenticated snapshot namespace '{logical_id}' has no signed locator"
                    );
                }
                bail!(
                    "initialized authenticated snapshot namespace '{logical_id}' is missing its stable store lock"
                );
            }
        };
        let root_lock = BoundStateLock::acquire(&store_root, S::ROOT_LOCK_NAME)?;
        scavenge_snapshot_metadata_temps::<S>(&store_root, logical_id)?;
        if !store_root.direct_child_exists(snapshot_locator_name(logical_id))? {
            bail!(
                "initialized authenticated snapshot namespace '{logical_id}' has no signed locator"
            );
        }
        root_lock.verify(&store_root)?;
        let mut locator = read_locator::<S>(&authenticator, &store_root, logical_id)?;
        let authenticator = recover_rollover::<S, T>(
            authenticator,
            &store_root,
            &store_lock,
            &root_lock,
            &mut locator,
        )?;
        recover_init_after_locator::<S>(
            &authenticator,
            &store_root,
            &store_lock,
            &root_lock,
            &locator,
        )?;
        verify_root_inventory::<S>(&authenticator, &store_root, &root_lock)?;
        drop(root_lock);
        let authenticator = verify_retained_instances::<S, T>(authenticator, &locator)?;
        let journal =
            AuthenticatedStateJournal::<S>::open(authenticator, &locator.active_identity)?;
        let store = Self::from_journal(
            journal,
            store_root,
            store_lock,
            logical_id.to_string(),
            &mut locator,
        )?;
        let root_lock = BoundStateLock::acquire(&store.store_root, S::ROOT_LOCK_NAME)?;
        scavenge_snapshot_metadata_temps::<S>(&store.store_root, logical_id)?;
        verify_root_inventory::<S>(store.journal.authenticator(), &store.store_root, &root_lock)?;
        Ok(store)
    }

    /// Reads an already-initialized logical snapshot using only existing
    /// locks and exact durable state. No crash recovery, migration,
    /// scavenging, lock creation, or publication is permitted.
    pub(crate) fn read_existing_current(
        authenticator: RepositoryAuthenticator,
        logical_id: &str,
    ) -> Result<AuthenticatedSnapshot<T>> {
        validate_logical_id::<S>(logical_id)?;
        let store_root = AuthenticatedStateJournal::<S>::existing_root(&authenticator)?;
        let store_lock = BoundStateLock::try_acquire_existing_exclusive(
            &store_root,
            &snapshot_lock_name(logical_id),
        )
        .context(
            "authenticated snapshot store is active, incomplete, or missing its stable lock",
        )?;
        let root_lock = BoundStateLock::try_acquire_existing_exclusive(
            &store_root,
            S::ROOT_LOCK_NAME,
        )
        .context(
            "authenticated snapshot namespace is active, incomplete, or missing its stable lock",
        )?;
        if store_root.direct_child_exists(snapshot_init_name(logical_id))? {
            let _ = read_init_intent::<S>(&authenticator, &store_root, logical_id)?;
            bail!("authenticated snapshot initialization is transitional; recovery is required");
        }
        if store_root.direct_child_exists(snapshot_rollover_name(logical_id))? {
            let _ = read_rollover_intent::<S>(&authenticator, &store_root, logical_id)?;
            bail!("authenticated snapshot rollover is transitional; recovery is required");
        }
        let locator = read_locator::<S>(&authenticator, &store_root, logical_id)?;
        verify_root_inventory::<S>(&authenticator, &store_root, &root_lock)?;
        store_lock.verify(&store_root)?;
        root_lock.verify(&store_root)?;
        drop(root_lock);

        let authenticator = verify_retained_instances_read_only::<S, T>(authenticator, &locator)?;
        let journal = AuthenticatedStateJournal::<S>::open_existing_read_only(
            authenticator,
            &locator.active_identity,
        )?;
        let current = exact_current_from_journal::<S, T>(&journal, &locator)?;
        store_lock.verify(&store_root)?;
        Ok(current)
    }

    fn from_journal(
        journal: AuthenticatedStateJournal<S>,
        store_root: SafeRoot,
        store_lock: BoundStateLock,
        logical_id: String,
        locator: &mut SnapshotLocator,
    ) -> Result<Self> {
        if journal.identity() != &locator.active_identity {
            bail!("authenticated snapshot locator selected the wrong journal identity");
        }
        let mut previous_token = locator.prior_token;
        let mut current = None;
        for record in journal.records() {
            if record.phase != S::SNAPSHOT_PHASE || record.subject.is_some() {
                bail!("authenticated snapshot journal contains a non-snapshot record");
            }
            let snapshot: AuthenticatedSnapshot<T> = serde_json::from_value(record.payload.clone())
                .context("authenticated snapshot payload is malformed")?;
            let expected_generation = locator
                .active_start_generation
                .checked_add(record.sequence.saturating_sub(1))
                .context("authenticated snapshot absolute generation overflowed")?;
            if snapshot.version != S::SNAPSHOT_FORMAT_VERSION
                || snapshot.generation != expected_generation
                || snapshot.token <= previous_token
            {
                bail!("authenticated snapshot generation or token is non-monotonic");
            }
            previous_token = snapshot.token;
            current = Some(snapshot);
        }
        let current = current.context(
            "initialized authenticated snapshot namespace has no durable signed generation",
        )?;
        let terminal_mac = journal
            .records()
            .last()
            .map(|record| record.mac.clone())
            .context("authenticated snapshot journal has no terminal MAC")?;
        if current.generation == locator.generation {
            if current.token != locator.token || terminal_mac != locator.terminal_mac {
                bail!("authenticated snapshot locator does not match its journal tail");
            }
        } else if current.generation == locator.generation.saturating_add(1) {
            let locator_index = locator
                .generation
                .checked_sub(locator.active_start_generation)
                .context("authenticated snapshot locator generation precedes its active journal")?;
            let locator_index = usize::try_from(locator_index)
                .context("authenticated snapshot locator index overflowed")?;
            let anchored_record = journal
                .records()
                .get(locator_index)
                .context("authenticated snapshot one-record recovery anchor is missing")?;
            if anchored_record.mac != locator.terminal_mac {
                bail!("authenticated snapshot locator rollback evidence is inconsistent");
            }
            locator.generation = current.generation;
            locator.token = current.token;
            locator.terminal_mac = terminal_mac;
            let root_lock = BoundStateLock::acquire(&store_root, S::ROOT_LOCK_NAME)?;
            scavenge_snapshot_metadata_temps::<S>(&store_root, &logical_id)?;
            write_locator::<S>(
                journal.authenticator(),
                &store_root,
                &store_lock,
                &root_lock,
                locator,
            )?;
            verify_root_inventory::<S>(journal.authenticator(), &store_root, &root_lock)?;
        } else {
            bail!("authenticated snapshot locator rollback exceeds the one-record crash window");
        }
        Ok(Self {
            journal,
            store_root,
            store_lock,
            logical_id,
            locator: locator.clone(),
            current,
            spec: PhantomData,
        })
    }

    pub(crate) fn identity(&self) -> &JournalIdentity {
        self.journal.identity()
    }

    pub(crate) fn authenticator(&self) -> &RepositoryAuthenticator {
        self.journal.authenticator()
    }

    pub(crate) fn instance_id(&self) -> &str {
        self.journal.instance_id()
    }

    pub(crate) fn logical_id(&self) -> &str {
        &self.logical_id
    }

    pub(crate) fn retained_instances(&self) -> Vec<&JournalIdentity> {
        self.locator
            .retained_instances
            .iter()
            .map(|anchor| &anchor.identity)
            .collect()
    }

    pub(crate) fn current(&self) -> &AuthenticatedSnapshot<T> {
        &self.current
    }

    pub(crate) fn commit(&mut self, token: u64, value: T) -> Result<&AuthenticatedSnapshot<T>> {
        if token <= self.current.token {
            bail!("authenticated snapshot token must increase monotonically");
        }
        let generation = self
            .current
            .generation
            .checked_add(1)
            .context("authenticated snapshot generation overflowed")?;
        let next = AuthenticatedSnapshot {
            version: S::SNAPSHOT_FORMAT_VERSION,
            generation,
            token,
            value,
        };
        self.journal
            .append(S::SNAPSHOT_PHASE, None, &next)
            .context("failed to publish authenticated snapshot generation")?;
        self.current = next;
        self.locator.generation = self.current.generation;
        self.locator.token = self.current.token;
        self.locator.terminal_mac = self
            .journal
            .records()
            .last()
            .map(|record| record.mac.clone())
            .context("authenticated snapshot commit lost its terminal MAC")?;
        let root_lock = BoundStateLock::acquire(&self.store_root, S::ROOT_LOCK_NAME)?;
        scavenge_snapshot_metadata_temps::<S>(&self.store_root, &self.logical_id)?;
        write_locator::<S>(
            self.journal.authenticator(),
            &self.store_root,
            &self.store_lock,
            &root_lock,
            &mut self.locator,
        )?;
        verify_root_inventory::<S>(self.journal.authenticator(), &self.store_root, &root_lock)?;
        Ok(&self.current)
    }

    /// Starts a compacted physical journal while preserving a signed anchor to
    /// the old terminal MAC. A signed prepared intent is durable before the
    /// candidate directory can exist; the candidate is authenticated before a
    /// ready intent and the atomic locator switch are published.
    pub(crate) fn rollover(
        self,
        authenticator: RepositoryAuthenticator,
        token: u64,
        value: T,
    ) -> Result<Self> {
        if token <= self.current.token {
            bail!("authenticated snapshot rollover token must increase monotonically");
        }
        if self.locator.retained_instances.len() >= 128 {
            bail!("authenticated snapshot retained-instance bound is exhausted");
        }
        authenticator.verify_repository_binding(&self.locator.active_identity.repository)?;
        let generation = self
            .current
            .generation
            .checked_add(1)
            .context("authenticated snapshot rollover generation overflowed")?;
        let physical_id = random_identifier()?;
        let current = AuthenticatedSnapshot {
            version: S::SNAPSHOT_FORMAT_VERSION,
            generation,
            token,
            value,
        };
        let mut intent = SnapshotRolloverIntent {
            version: S::SNAPSHOT_FORMAT_VERSION,
            logical_id: self.logical_id.clone(),
            phase: SnapshotRolloverPhase::Prepared,
            previous_identity: self.locator.active_identity.clone(),
            previous_start_generation: self.locator.active_start_generation,
            previous_generation: self.current.generation,
            previous_token: self.current.token,
            previous_terminal_mac: self.locator.terminal_mac.clone(),
            candidate_run_id: physical_id.clone(),
            expected_snapshot: serde_json::to_value(&current)
                .context("failed to encode prepared rollover snapshot")?,
            next_identity: None,
            next_terminal_mac: None,
            mac: AuthenticationTag::zero(),
        };
        let root_lock = BoundStateLock::acquire(&self.store_root, S::ROOT_LOCK_NAME)?;
        scavenge_snapshot_metadata_temps::<S>(&self.store_root, &self.logical_id)?;
        let usage =
            verify_root_inventory::<S>(self.journal.authenticator(), &self.store_root, &root_lock)?;
        ensure_rollover_capacity::<S>(usage)?;
        write_rollover_intent::<S>(
            self.journal.authenticator(),
            &self.store_root,
            &self.store_lock,
            &root_lock,
            &mut intent,
        )?;
        verify_root_inventory::<S>(self.journal.authenticator(), &self.store_root, &root_lock)?;
        drop(root_lock);
        if take_snapshot_fault(SnapshotFaultPoint::AfterRolloverIntent) {
            bail!("injected authenticated snapshot rollover fault after prepared intent");
        }
        let mut journal = AuthenticatedStateJournal::<S>::create(authenticator, &physical_id)?;
        if journal.root().identity() != self.store_root.identity() {
            bail!("authenticated snapshot rollover changed its journal root identity");
        }
        if take_snapshot_fault(SnapshotFaultPoint::AfterRolloverDirectory) {
            bail!("injected authenticated snapshot rollover fault after candidate reservation");
        }
        journal
            .append(S::SNAPSHOT_PHASE, None, &current)
            .context("failed to publish compacted authenticated snapshot")?;
        let terminal_mac = journal
            .records()
            .last()
            .map(|record| record.mac.clone())
            .context("authenticated snapshot rollover lost its terminal MAC")?;
        intent.phase = SnapshotRolloverPhase::Ready;
        intent.next_identity = Some(journal.identity().clone());
        intent.next_terminal_mac = Some(terminal_mac.clone());
        let root_lock = BoundStateLock::acquire(&self.store_root, S::ROOT_LOCK_NAME)?;
        scavenge_snapshot_metadata_temps::<S>(&self.store_root, &self.logical_id)?;
        write_rollover_intent::<S>(
            journal.authenticator(),
            &self.store_root,
            &self.store_lock,
            &root_lock,
            &mut intent,
        )?;
        verify_root_inventory::<S>(journal.authenticator(), &self.store_root, &root_lock)?;
        drop(root_lock);
        if take_snapshot_fault(SnapshotFaultPoint::BeforeRollover) {
            bail!("injected authenticated snapshot rollover fault before atomic locator switch");
        }
        let mut retained_instances = self.locator.retained_instances.clone();
        retained_instances.push(RetainedSnapshotAnchor {
            identity: self.locator.active_identity.clone(),
            start_generation: self.locator.active_start_generation,
            end_generation: self.current.generation,
            terminal_token: self.current.token,
            terminal_mac: self.locator.terminal_mac.clone(),
        });
        if retained_instances.len() > 128 {
            bail!("authenticated snapshot retained-instance bound is exhausted");
        }
        let mut locator = SnapshotLocator {
            version: S::SNAPSHOT_FORMAT_VERSION,
            logical_id: self.logical_id.clone(),
            active_identity: journal.identity().clone(),
            active_start_generation: generation,
            generation,
            token,
            prior_token: self.current.token,
            prior_terminal_mac: self.locator.terminal_mac.clone(),
            terminal_mac,
            retained_instances,
            mac: AuthenticationTag::zero(),
        };
        let root_lock = BoundStateLock::acquire(&self.store_root, S::ROOT_LOCK_NAME)?;
        scavenge_snapshot_metadata_temps::<S>(&self.store_root, &self.logical_id)?;
        write_locator::<S>(
            journal.authenticator(),
            &self.store_root,
            &self.store_lock,
            &root_lock,
            &mut locator,
        )?;
        remove_rollover_intent::<S>(
            journal.authenticator(),
            &self.store_root,
            &self.store_lock,
            &root_lock,
            &intent,
        )?;
        verify_root_inventory::<S>(journal.authenticator(), &self.store_root, &root_lock)?;
        Ok(Self {
            journal,
            store_root: self.store_root,
            store_lock: self.store_lock,
            logical_id: self.logical_id,
            locator,
            current,
            spec: PhantomData,
        })
    }
}

fn begin_snapshot_initialization<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    logical_id: &str,
) -> Result<(SafeRoot, BoundStateLock, SnapshotInitIntent)> {
    validate_logical_id::<S>(logical_id)?;
    let root = AuthenticatedStateJournal::<S>::create_root(authenticator)?;
    let locator_name = snapshot_locator_name(logical_id);
    let init_name = snapshot_init_name(logical_id);
    let store_lock_name = snapshot_lock_name(logical_id);
    // Root-only bootstrap inspection never waits on a logical store lock. A
    // missing stable lock file is created under the root lock, released, then
    // reacquired before the root lock so every state mutation follows the
    // store-lock -> root-lock order used by commit, rollover, and recovery.
    let bootstrap_root_lock = BoundStateLock::acquire(&root, S::ROOT_LOCK_NAME)?;
    scavenge_snapshot_metadata_temps::<S>(&root, logical_id)?;
    let usage = verify_root_inventory::<S>(authenticator, &root, &bootstrap_root_lock)?;
    if root.direct_child_exists(&locator_name)? {
        bail!("authenticated snapshot logical store is already initialized");
    }
    let init_existed = root.direct_child_exists(&init_name)?;
    let store_lock_existed = root.direct_child_exists(&store_lock_name)?;
    let created_placeholder = if store_lock_existed {
        false
    } else {
        if init_existed {
            if usage.entries.saturating_add(2) > S::MAX_ROOT_ENTRIES {
                bail!("authenticated snapshot namespace cannot recover its logical bootstrap");
            }
            let _ = read_init_intent::<S>(authenticator, &root, logical_id)?;
        } else {
            ensure_new_logical_capacity::<S>(usage, 3)?;
            let mut intent = SnapshotInitIntent {
                version: S::SNAPSHOT_FORMAT_VERSION,
                logical_id: logical_id.to_string(),
                attempt: 1,
                physical_id: random_identifier()?,
                mac: AuthenticationTag::zero(),
            };
            write_init_intent::<S>(authenticator, &root, &bootstrap_root_lock, &mut intent)?;
        }
        let placeholder = BoundStateLock::try_acquire_exclusive(&root, &store_lock_name)
            .context("authenticated snapshot initialization lock could not be reserved")?;
        placeholder.verify(&root)?;
        drop(placeholder);
        true
    };
    bootstrap_root_lock.verify(&root)?;
    drop(bootstrap_root_lock);

    let store_lock = BoundStateLock::try_acquire_existing_exclusive(&root, &store_lock_name)
        .context("authenticated snapshot initialization is active elsewhere")?;
    let root_lock = BoundStateLock::acquire(&root, S::ROOT_LOCK_NAME)?;
    scavenge_snapshot_metadata_temps::<S>(&root, logical_id)?;
    verify_root_inventory::<S>(authenticator, &root, &root_lock)?;
    if root.direct_child_exists(&locator_name)? {
        bail!("authenticated snapshot logical store is already initialized");
    }
    let init_exists = root.direct_child_exists(&init_name)?;

    let mut intent = if init_exists {
        let mut intent = read_init_intent::<S>(authenticator, &root, logical_id)?;
        let continuing_fresh_bootstrap = created_placeholder
            && !root.direct_child_exists(&intent.physical_id)?
            && intent.attempt == 1;
        if !continuing_fresh_bootstrap {
            remove_abandoned_initialization_candidate::<S>(
                &root,
                &root_lock,
                &store_lock,
                &intent,
            )?;
            intent.attempt = intent
                .attempt
                .checked_add(1)
                .context("authenticated snapshot initialization attempt overflowed")?;
            if intent.attempt > 8 {
                bail!("authenticated snapshot initialization exceeded its bounded retry count");
            }
            intent.physical_id = random_identifier()?;
        }
        intent
    } else {
        bail!("authenticated snapshot stable lock has no signed initialization intent");
    };
    if init_exists {
        write_init_intent::<S>(authenticator, &root, &root_lock, &mut intent)?;
    }
    verify_root_inventory::<S>(authenticator, &root, &root_lock)?;
    root_lock.verify(&root)?;
    store_lock.verify(&root)?;
    drop(root_lock);
    Ok((root, store_lock, intent))
}

fn remove_abandoned_initialization_candidate<S: SnapshotSpec>(
    root: &SafeRoot,
    root_lock: &BoundStateLock,
    store_lock: &BoundStateLock,
    intent: &SnapshotInitIntent,
) -> Result<()> {
    if !root.direct_child_exists(&intent.physical_id)? {
        return Ok(());
    }
    root_lock.verify(root)?;
    store_lock.verify(root)?;
    let candidate = root
        .bind_existing_direct_child_directory(&intent.physical_id)
        .context("signed initialization candidate is missing or unsafe")?;
    let candidate_root = SafeRoot::open_existing(candidate.path())?;
    let instance_lock =
        BoundStateLock::try_acquire_exclusive(&candidate_root, S::INSTANCE_LOCK_NAME)
            .context("signed initialization candidate is still active")?;
    instance_lock.verify(&candidate_root)?;
    remove_direct_child_tree(
        root,
        &intent.physical_id,
        Some(candidate.identity()),
        TreeLinkPolicy::RejectLinksAndSpecialFiles,
    )?;
    root_lock.verify(root)?;
    store_lock.verify(root)
}

fn validate_logical_id<S: SnapshotSpec>(logical_id: &str) -> Result<()> {
    if logical_id.is_empty()
        || logical_id.len() > S::MAX_INSTANCE_ID_BYTES
        || matches!(logical_id, "." | "..")
        || !logical_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("authenticated snapshot logical id is not canonical or bounded");
    }
    Ok(())
}

fn snapshot_init_name(logical_id: &str) -> String {
    format!(".snapshot-init-{}.json", sha256_hex(logical_id.as_bytes()))
}

fn init_intent_mac_payload(intent: &SnapshotInitIntent) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        "snapshot_initialization",
        intent.version,
        &intent.logical_id,
        intent.attempt,
        &intent.physical_id,
    ))
    .context("failed to encode authenticated snapshot initialization intent")
}

fn validate_init_intent<S: SnapshotSpec>(
    intent: &SnapshotInitIntent,
    logical_id: &str,
) -> Result<()> {
    validate_logical_id::<S>(logical_id)?;
    intent.mac.validate()?;
    if intent.version != S::SNAPSHOT_FORMAT_VERSION
        || intent.logical_id != logical_id
        || intent.attempt == 0
        || intent.attempt > 8
        || intent.physical_id.len() != 64
        || !intent
            .physical_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("authenticated snapshot initialization intent is malformed");
    }
    Ok(())
}

fn read_init_intent<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    logical_id: &str,
) -> Result<SnapshotInitIntent> {
    let bytes = BoundedRegularReader::read_direct(
        root,
        snapshot_init_name(logical_id),
        S::MAX_RECORD_BYTES,
    )?;
    decode_init_intent::<S>(authenticator, logical_id, &bytes)
}

fn decode_init_intent<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    logical_id: &str,
    bytes: &[u8],
) -> Result<SnapshotInitIntent> {
    let intent: SnapshotInitIntent = serde_json::from_slice(bytes)
        .context("authenticated snapshot initialization intent is malformed")?;
    validate_init_intent::<S>(&intent, logical_id)?;
    authenticator.verify_tag(
        S::LOCATOR_DOMAIN,
        &init_intent_mac_payload(&intent)?,
        &intent.mac,
    )?;
    Ok(intent)
}

fn write_init_intent<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    lock: &BoundStateLock,
    intent: &mut SnapshotInitIntent,
) -> Result<()> {
    validate_init_intent::<S>(intent, &intent.logical_id)?;
    intent.mac = authenticator.sign(S::LOCATOR_DOMAIN, &init_intent_mac_payload(intent)?)?;
    let mut bytes = serde_json::to_vec(intent)?;
    bytes.push(b'\n');
    let name = snapshot_init_name(&intent.logical_id);
    AtomicStateWriter::write_direct_fenced(root, &name, &bytes, || lock.verify(root))
}

fn remove_init_intent<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    store_lock: &BoundStateLock,
    root_lock: &BoundStateLock,
    expected: &SnapshotInitIntent,
) -> Result<()> {
    let observed = read_init_intent::<S>(authenticator, root, &expected.logical_id)?;
    if &observed != expected {
        bail!("authenticated snapshot initialization intent changed before cleanup");
    }
    store_lock.verify(root)?;
    root_lock.verify(root)?;
    fs::remove_file(root.direct_child(snapshot_init_name(&expected.logical_id))?)?;
    File::open(root.path())?.sync_all()?;
    store_lock.verify(root)?;
    root_lock.verify(root)
}

fn recover_init_after_locator<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    store_lock: &BoundStateLock,
    root_lock: &BoundStateLock,
    locator: &SnapshotLocator,
) -> Result<()> {
    let name = snapshot_init_name(&locator.logical_id);
    if !root.direct_child_exists(&name)? {
        return Ok(());
    }
    let intent = read_init_intent::<S>(authenticator, root, &locator.logical_id)?;
    if intent.physical_id != locator.active_identity.run_id {
        bail!("authenticated snapshot locator has a mismatched initialization intent");
    }
    remove_init_intent::<S>(authenticator, root, store_lock, root_lock, &intent)?;
    root_lock.verify(root)
}

fn snapshot_locator_name(logical_id: &str) -> String {
    format!(
        ".snapshot-locator-{}.json",
        sha256_hex(logical_id.as_bytes())
    )
}

fn snapshot_lock_name(logical_id: &str) -> String {
    format!(".snapshot-store-{}.lock", sha256_hex(logical_id.as_bytes()))
}

fn snapshot_rollover_name(logical_id: &str) -> String {
    format!(
        ".snapshot-rollover-{}.json",
        sha256_hex(logical_id.as_bytes())
    )
}

fn rollover_intent_mac_payload(intent: &SnapshotRolloverIntent) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        "snapshot_rollover",
        intent.version,
        &intent.logical_id,
        intent.phase,
        &intent.previous_identity,
        intent.previous_start_generation,
        intent.previous_generation,
        intent.previous_token,
        &intent.previous_terminal_mac,
        &intent.candidate_run_id,
        &intent.expected_snapshot,
        &intent.next_identity,
        &intent.next_terminal_mac,
    ))
    .context("failed to encode authenticated snapshot rollover intent")
}

fn validate_rollover_intent<S: SnapshotSpec>(
    intent: &SnapshotRolloverIntent,
    logical_id: &str,
) -> Result<()> {
    validate_logical_id::<S>(logical_id)?;
    intent.mac.validate()?;
    intent.previous_terminal_mac.validate()?;
    if intent.version != S::SNAPSHOT_FORMAT_VERSION
        || intent.logical_id != logical_id
        || intent.previous_generation < intent.previous_start_generation
        || intent.previous_generation == 0
        || intent.previous_token == 0
        || intent.candidate_run_id.len() != 64
        || !intent
            .candidate_run_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("authenticated snapshot rollover intent is malformed");
    }
    match intent.phase {
        SnapshotRolloverPhase::Prepared
            if intent.next_identity.is_none() && intent.next_terminal_mac.is_none() => {}
        SnapshotRolloverPhase::Ready => {
            let identity = intent
                .next_identity
                .as_ref()
                .context("ready rollover intent has no next identity")?;
            let terminal = intent
                .next_terminal_mac
                .as_ref()
                .context("ready rollover intent has no next terminal MAC")?;
            terminal.validate()?;
            if identity.run_id != intent.candidate_run_id
                || identity.repository != intent.previous_identity.repository
            {
                bail!("ready rollover intent has a mismatched candidate identity");
            }
        }
        _ => bail!("authenticated snapshot rollover phase is inconsistent"),
    }
    Ok(())
}

fn rollover_intent_limit<S: SnapshotSpec>() -> u64 {
    S::MAX_RECORD_BYTES.saturating_mul(2)
}

fn read_rollover_intent<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    logical_id: &str,
) -> Result<SnapshotRolloverIntent> {
    let bytes = BoundedRegularReader::read_direct(
        root,
        snapshot_rollover_name(logical_id),
        rollover_intent_limit::<S>(),
    )?;
    decode_rollover_intent::<S>(authenticator, logical_id, &bytes)
}

fn decode_rollover_intent<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    logical_id: &str,
    bytes: &[u8],
) -> Result<SnapshotRolloverIntent> {
    let intent: SnapshotRolloverIntent = serde_json::from_slice(bytes)
        .context("authenticated snapshot rollover intent is malformed")?;
    validate_rollover_intent::<S>(&intent, logical_id)?;
    authenticator.verify_repository_binding(&intent.previous_identity.repository)?;
    authenticator.verify_tag(
        S::LOCATOR_DOMAIN,
        &rollover_intent_mac_payload(&intent)?,
        &intent.mac,
    )?;
    Ok(intent)
}

fn write_rollover_intent<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    store_lock: &BoundStateLock,
    root_lock: &BoundStateLock,
    intent: &mut SnapshotRolloverIntent,
) -> Result<()> {
    validate_rollover_intent::<S>(intent, &intent.logical_id)?;
    authenticator.verify_repository_binding(&intent.previous_identity.repository)?;
    intent.mac = authenticator.sign(S::LOCATOR_DOMAIN, &rollover_intent_mac_payload(intent)?)?;
    let mut bytes = serde_json::to_vec(intent)?;
    bytes.push(b'\n');
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > rollover_intent_limit::<S>() {
        bail!("authenticated snapshot rollover intent exceeds its byte bound");
    }
    let name = snapshot_rollover_name(&intent.logical_id);
    AtomicStateWriter::write_direct_fenced(root, &name, &bytes, || {
        store_lock.verify(root)?;
        root_lock.verify(root)
    })
}

fn remove_rollover_intent<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    store_lock: &BoundStateLock,
    root_lock: &BoundStateLock,
    expected: &SnapshotRolloverIntent,
) -> Result<()> {
    let observed = read_rollover_intent::<S>(authenticator, root, &expected.logical_id)?;
    if &observed != expected {
        bail!("authenticated snapshot rollover intent changed before cleanup");
    }
    store_lock.verify(root)?;
    root_lock.verify(root)?;
    fs::remove_file(root.direct_child(snapshot_rollover_name(&expected.logical_id))?)?;
    File::open(root.path())?.sync_all()?;
    store_lock.verify(root)?;
    root_lock.verify(root)
}

fn locator_matches_rollover_previous(
    locator: &SnapshotLocator,
    intent: &SnapshotRolloverIntent,
) -> bool {
    locator.active_identity == intent.previous_identity
        && locator.active_start_generation == intent.previous_start_generation
        && locator.generation == intent.previous_generation
        && locator.token == intent.previous_token
        && locator.terminal_mac == intent.previous_terminal_mac
}

fn locator_matches_rollover_next(
    locator: &SnapshotLocator,
    intent: &SnapshotRolloverIntent,
) -> bool {
    intent.phase == SnapshotRolloverPhase::Ready
        && intent
            .next_identity
            .as_ref()
            .is_some_and(|identity| &locator.active_identity == identity)
        && locator.active_start_generation == intent.previous_generation.saturating_add(1)
        && locator.generation == intent.previous_generation.saturating_add(1)
        && intent.next_terminal_mac.as_ref() == Some(&locator.terminal_mac)
}

fn validate_rollover_candidate<S, T>(
    journal: &AuthenticatedStateJournal<S>,
    intent: &SnapshotRolloverIntent,
) -> Result<AuthenticatedSnapshot<T>>
where
    S: SnapshotSpec,
    T: DeserializeOwned,
{
    if journal.instance_id() != intent.candidate_run_id || journal.records().len() != 1 {
        bail!("authenticated snapshot rollover candidate has an unexpected physical journal");
    }
    let record = &journal.records()[0];
    if record.phase != S::SNAPSHOT_PHASE
        || record.subject.is_some()
        || record.payload != intent.expected_snapshot
    {
        bail!("authenticated snapshot rollover candidate does not match its signed intent");
    }
    let snapshot: AuthenticatedSnapshot<T> = serde_json::from_value(record.payload.clone())
        .context("authenticated snapshot rollover payload is malformed")?;
    if snapshot.version != S::SNAPSHOT_FORMAT_VERSION
        || snapshot.generation != intent.previous_generation.saturating_add(1)
        || snapshot.token <= intent.previous_token
    {
        bail!("authenticated snapshot rollover generation or token is inconsistent");
    }
    Ok(snapshot)
}

fn recover_rollover<S, T>(
    authenticator: RepositoryAuthenticator,
    root: &SafeRoot,
    store_lock: &BoundStateLock,
    root_lock: &BoundStateLock,
    locator: &mut SnapshotLocator,
) -> Result<RepositoryAuthenticator>
where
    S: SnapshotSpec,
    T: Serialize + DeserializeOwned,
{
    let name = snapshot_rollover_name(&locator.logical_id);
    if !root.direct_child_exists(&name)? {
        return Ok(authenticator);
    }
    let mut intent = read_rollover_intent::<S>(&authenticator, root, &locator.logical_id)?;
    let locator_is_previous = locator_matches_rollover_previous(locator, &intent);
    let locator_is_next = locator_matches_rollover_next(locator, &intent);
    if !locator_is_previous && !locator_is_next {
        bail!("signed rollover intent does not continue the active snapshot locator");
    }

    let candidate_exists = root.direct_child_exists(&intent.candidate_run_id)?;
    if !candidate_exists {
        if locator_is_previous && intent.phase == SnapshotRolloverPhase::Prepared {
            remove_rollover_intent::<S>(&authenticator, root, store_lock, root_lock, &intent)?;
            verify_root_inventory::<S>(&authenticator, root, root_lock)?;
            return Ok(authenticator);
        }
        bail!("signed rollover intent refers to a missing physical journal");
    }

    let candidate = root.bind_existing_direct_child_directory(&intent.candidate_run_id)?;
    let candidate_root = SafeRoot::open_existing(candidate.path())?;
    const FIRST_RECORD: &str = "00000000000000000001.json";
    if !candidate_root.direct_child_exists(FIRST_RECORD)? {
        if locator_is_previous && intent.phase == SnapshotRolloverPhase::Prepared {
            let instance_lock =
                BoundStateLock::try_acquire_exclusive(&candidate_root, S::INSTANCE_LOCK_NAME)
                    .context("prepared rollover candidate is still active")?;
            instance_lock.verify(&candidate_root)?;
            remove_direct_child_tree(
                root,
                &intent.candidate_run_id,
                Some(candidate.identity()),
                TreeLinkPolicy::RejectLinksAndSpecialFiles,
            )?;
            remove_rollover_intent::<S>(&authenticator, root, store_lock, root_lock, &intent)?;
            verify_root_inventory::<S>(&authenticator, root, root_lock)?;
            return Ok(authenticator);
        }
        bail!("ready rollover candidate has no durable snapshot record");
    }

    let journal =
        AuthenticatedStateJournal::<S>::open_instance(authenticator, &intent.candidate_run_id)?;
    let snapshot = validate_rollover_candidate::<S, T>(&journal, &intent)?;
    let terminal_mac = journal
        .records()
        .last()
        .map(|record| record.mac.clone())
        .context("rollover candidate lost its terminal MAC")?;
    if intent.phase == SnapshotRolloverPhase::Prepared {
        intent.phase = SnapshotRolloverPhase::Ready;
        intent.next_identity = Some(journal.identity().clone());
        intent.next_terminal_mac = Some(terminal_mac.clone());
        write_rollover_intent::<S>(
            journal.authenticator(),
            root,
            store_lock,
            root_lock,
            &mut intent,
        )?;
    } else if intent.next_identity.as_ref() != Some(journal.identity())
        || intent.next_terminal_mac.as_ref() != Some(&terminal_mac)
    {
        bail!("ready rollover intent does not match its physical journal");
    }

    if locator_is_previous {
        let mut retained_instances = locator.retained_instances.clone();
        retained_instances.push(RetainedSnapshotAnchor {
            identity: locator.active_identity.clone(),
            start_generation: locator.active_start_generation,
            end_generation: locator.generation,
            terminal_token: locator.token,
            terminal_mac: locator.terminal_mac.clone(),
        });
        if retained_instances.len() > 128 {
            bail!("authenticated snapshot retained-instance bound is exhausted");
        }
        *locator = SnapshotLocator {
            version: S::SNAPSHOT_FORMAT_VERSION,
            logical_id: locator.logical_id.clone(),
            active_identity: journal.identity().clone(),
            active_start_generation: snapshot.generation,
            generation: snapshot.generation,
            token: snapshot.token,
            prior_token: intent.previous_token,
            prior_terminal_mac: intent.previous_terminal_mac.clone(),
            terminal_mac,
            retained_instances,
            mac: AuthenticationTag::zero(),
        };
        write_locator::<S>(
            journal.authenticator(),
            root,
            store_lock,
            root_lock,
            locator,
        )?;
    }
    remove_rollover_intent::<S>(
        journal.authenticator(),
        root,
        store_lock,
        root_lock,
        &intent,
    )?;
    verify_root_inventory::<S>(journal.authenticator(), root, root_lock)?;
    journal.into_authenticator()
}

#[derive(Debug, Clone, Copy)]
struct SnapshotRootUsage {
    entries: usize,
    physical_instances: usize,
    logical_stores: usize,
}

fn verify_root_inventory<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    root_lock: &BoundStateLock,
) -> Result<SnapshotRootUsage> {
    verify_root_inventory_inner::<S>(authenticator, root, root_lock, false)
}

fn verify_root_inventory_allowing_metadata_temps<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    root_lock: &BoundStateLock,
) -> Result<SnapshotRootUsage> {
    verify_root_inventory_inner::<S>(authenticator, root, root_lock, true)
}

fn verify_root_inventory_inner<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    root_lock: &BoundStateLock,
    allow_metadata_temps: bool,
) -> Result<SnapshotRootUsage> {
    if S::MAX_LOGICAL_STORES == 0 || S::MAX_ROOT_ENTRIES == 0 || S::MAX_PHYSICAL_INSTANCES == 0 {
        bail!("authenticated snapshot namespace capacity must be non-zero");
    }
    root_lock.verify(root)?;
    let mut entries = 0_usize;
    let mut observed = BTreeMap::<String, FileIdentity>::new();
    let mut expected = BTreeMap::<String, FileIdentity>::new();
    let mut owners = BTreeMap::<String, String>::new();
    let mut locators = BTreeMap::<String, SnapshotLocator>::new();
    let mut init_candidates = BTreeMap::<String, String>::new();
    let mut rollover_intents = BTreeMap::<String, SnapshotRolloverIntent>::new();
    let mut all_logicals = std::collections::BTreeSet::<String>::new();

    for entry in fs::read_dir(root.path()).context("failed to enumerate snapshot journal root")? {
        entries = entries
            .checked_add(1)
            .context("snapshot root entry count overflowed")?;
        if entries > S::MAX_ROOT_ENTRIES {
            bail!("authenticated snapshot root reached its namespace-wide entry capacity");
        }
        let entry = entry.context("failed to inspect snapshot root entry")?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("authenticated snapshot root entry is not UTF-8"))?;
        let metadata = fs::symlink_metadata(entry.path())?;
        let canonical_physical_name = is_canonical_physical_id(&name);

        if metadata.file_type().is_dir() {
            if !canonical_physical_name {
                bail!("unexpected directory in authenticated snapshot journal root");
            }
            let bound = root.bind_existing_direct_child_directory(&name)?;
            if observed.insert(name, bound.identity().clone()).is_some() {
                bail!("authenticated snapshot root contains a duplicate physical journal");
            }
            if observed.len() > S::MAX_PHYSICAL_INSTANCES {
                bail!("authenticated snapshot root reached its physical retention capacity");
            }
            continue;
        }

        if canonical_physical_name {
            bail!("authenticated snapshot physical journal entry is not a directory");
        }

        if let Some(hash) = snapshot_metadata_hash(&name, ".snapshot-locator-")? {
            let bytes = BoundedRegularReader::read_direct(root, &name, S::MAX_RECORD_BYTES)?;
            let wire: SnapshotLocator = serde_json::from_slice(&bytes)
                .context("authenticated snapshot locator is malformed")?;
            let locator = decode_locator::<S>(authenticator, &wire.logical_id, &bytes)?;
            verify_metadata_hash(hash, &locator.logical_id)?;
            all_logicals.insert(locator.logical_id.clone());
            if locators
                .insert(locator.logical_id.clone(), locator.clone())
                .is_some()
            {
                bail!("authenticated snapshot root repeats a logical locator");
            }
            for identity in locator
                .retained_instances
                .iter()
                .map(|anchor| &anchor.identity)
                .chain(std::iter::once(&locator.active_identity))
            {
                insert_physical_anchor(&mut expected, &mut owners, &locator.logical_id, identity)?;
            }
            continue;
        }

        if let Some(hash) = snapshot_metadata_hash(&name, ".snapshot-init-")? {
            let bytes = BoundedRegularReader::read_direct(root, &name, S::MAX_RECORD_BYTES)?;
            let wire: SnapshotInitIntent = serde_json::from_slice(&bytes)
                .context("authenticated snapshot initialization intent is malformed")?;
            let intent = decode_init_intent::<S>(authenticator, &wire.logical_id, &bytes)?;
            verify_metadata_hash(hash, &intent.logical_id)?;
            all_logicals.insert(intent.logical_id.clone());
            if init_candidates
                .insert(intent.logical_id.clone(), intent.physical_id.clone())
                .is_some()
            {
                bail!("authenticated snapshot root repeats a logical initialization intent");
            }
            insert_pending_physical_anchor(
                root,
                &mut expected,
                &mut owners,
                &intent.logical_id,
                &intent.physical_id,
            )?;
            continue;
        }

        if let Some(hash) = snapshot_metadata_hash(&name, ".snapshot-rollover-")? {
            let bytes =
                BoundedRegularReader::read_direct(root, &name, rollover_intent_limit::<S>())?;
            let wire: SnapshotRolloverIntent = serde_json::from_slice(&bytes)
                .context("authenticated snapshot rollover intent is malformed")?;
            let intent = decode_rollover_intent::<S>(authenticator, &wire.logical_id, &bytes)?;
            verify_metadata_hash(hash, &intent.logical_id)?;
            all_logicals.insert(intent.logical_id.clone());
            if rollover_intents
                .insert(intent.logical_id.clone(), intent.clone())
                .is_some()
            {
                bail!("authenticated snapshot root repeats a logical rollover intent");
            }
            match (&intent.next_identity, intent.phase) {
                (Some(identity), SnapshotRolloverPhase::Ready) => insert_physical_anchor(
                    &mut expected,
                    &mut owners,
                    &intent.logical_id,
                    identity,
                )?,
                (None, SnapshotRolloverPhase::Prepared) => insert_pending_physical_anchor(
                    root,
                    &mut expected,
                    &mut owners,
                    &intent.logical_id,
                    &intent.candidate_run_id,
                )?,
                _ => bail!("authenticated snapshot rollover phase is inconsistent"),
            }
            continue;
        }

        if name == S::ROOT_LOCK_NAME {
            continue;
        }
        if let Some(hash) = name
            .strip_prefix(".snapshot-store-")
            .and_then(|value| value.strip_suffix(".lock"))
        {
            validate_snapshot_logical_hash(hash)?;
            continue;
        }
        if is_legacy_retirement_metadata_name(&name) {
            let _ = BoundedRegularReader::read_direct(root, &name, S::MAX_RECORD_BYTES)?;
            continue;
        }
        if allow_metadata_temps && is_snapshot_metadata_temp_name(&name)? {
            let _ = BoundedRegularReader::read_direct(root, &name, S::MAX_RECORD_BYTES)?;
            continue;
        }

        bail!("unexpected file in authenticated snapshot journal root: {name}");
    }

    for (logical_id, candidate) in &init_candidates {
        if let Some(locator) = locators.get(logical_id) {
            if &locator.active_identity.run_id != candidate {
                bail!("authenticated snapshot initialization tail does not match its locator");
            }
        }
    }
    for (logical_id, intent) in &rollover_intents {
        let locator = locators
            .get(logical_id)
            .context("authenticated snapshot rollover intent has no signed logical locator")?;
        if !locator_matches_rollover_previous(locator, intent)
            && !locator_matches_rollover_next(locator, intent)
        {
            bail!("authenticated snapshot rollover intent does not continue its logical locator");
        }
    }
    if all_logicals.len() > S::MAX_LOGICAL_STORES {
        bail!("authenticated snapshot root reached its logical-store capacity");
    }
    if owners.len() > S::MAX_PHYSICAL_INSTANCES {
        bail!("authenticated snapshot root reached its physical retention capacity");
    }
    root_lock.verify(root)?;
    if observed != expected {
        let unexpected = observed
            .keys()
            .find(|run_id| !expected.contains_key(*run_id));
        if let Some(run_id) = unexpected {
            bail!("authenticated snapshot physical journal '{run_id}' is not anchored by any signed logical state");
        }
        bail!("authenticated snapshot physical journal inventory is incomplete or substituted");
    }
    Ok(SnapshotRootUsage {
        entries,
        physical_instances: owners.len(),
        logical_stores: all_logicals.len(),
    })
}

fn ensure_new_logical_capacity<S: SnapshotSpec>(
    usage: SnapshotRootUsage,
    additional_entries: usize,
) -> Result<()> {
    if usage.logical_stores >= S::MAX_LOGICAL_STORES
        || usage.entries.saturating_add(additional_entries) > S::MAX_ROOT_ENTRIES
        || usage.physical_instances >= S::MAX_PHYSICAL_INSTANCES
    {
        bail!("authenticated snapshot namespace has no capacity for another logical store");
    }
    Ok(())
}

fn ensure_rollover_capacity<S: SnapshotSpec>(usage: SnapshotRootUsage) -> Result<()> {
    if usage.entries.saturating_add(2) > S::MAX_ROOT_ENTRIES
        || usage.physical_instances >= S::MAX_PHYSICAL_INSTANCES
    {
        bail!("authenticated snapshot namespace has no retention capacity for rollover");
    }
    Ok(())
}

fn snapshot_temp_scan_budget<S: SnapshotSpec>() -> Result<usize> {
    let crash_entries = S::MAX_LOGICAL_STORES
        .checked_mul(SNAPSHOT_METADATA_FILES_PER_LOGICAL)
        .and_then(|entries| entries.checked_mul(SNAPSHOT_RESIDUE_FORMS_PER_FILE))
        .context("authenticated snapshot crash-residue capacity overflowed")?
        .max(SNAPSHOT_MIN_RECOVERABLE_RESIDUES);
    S::MAX_ROOT_ENTRIES
        .checked_add(crash_entries)
        .context("authenticated snapshot temp scan capacity overflowed")
}

fn scavenge_snapshot_metadata_temps<S: SnapshotSpec>(
    root: &SafeRoot,
    logical_id: &str,
) -> Result<()> {
    let current_hash = sha256_hex(logical_id.as_bytes());
    AtomicStateWriter::scavenge_direct_temp_namespaces_bounded(
        root,
        snapshot_temp_scan_budget::<S>()?,
        move |entries| snapshot_metadata_temp_targets::<S>(entries, &current_hash),
    )?;
    Ok(())
}

fn snapshot_metadata_temp_targets<S: SnapshotSpec>(
    entries: &[OsString],
    current_hash: &str,
) -> Result<BTreeSet<OsString>> {
    // Bound namespaces that are actually present before adding the caller's
    // prospective logical id. A create at quota must still be able to
    // scavenge safely and reach `ensure_new_logical_capacity`, which owns the
    // quota refusal and guarantees that no locator/init residue is created.
    let mut logical_hashes = BTreeSet::new();
    for entry in entries {
        let name = entry
            .to_str()
            .context("authenticated snapshot root entry is not UTF-8")?;
        if let Some(hash) = snapshot_logical_hash_from_root_entry(name)? {
            logical_hashes.insert(hash.to_string());
        }
        if let Some(target) = AtomicStateWriter::canonical_direct_temp_target(entry)? {
            let target = target
                .to_str()
                .context("authenticated snapshot temp target is not UTF-8")?;
            let hash = snapshot_metadata_target_hash(target)?
                .context("authenticated snapshot root contains a foreign atomic temp")?;
            logical_hashes.insert(hash.to_string());
        }
    }
    if logical_hashes.len() > S::MAX_LOGICAL_STORES {
        bail!("authenticated snapshot crash residue exceeds its logical-store capacity");
    }
    logical_hashes.insert(current_hash.to_string());
    let mut targets = BTreeSet::new();
    for hash in logical_hashes {
        targets.insert(OsString::from(format!(".snapshot-locator-{hash}.json")));
        targets.insert(OsString::from(format!(".snapshot-init-{hash}.json")));
        targets.insert(OsString::from(format!(".snapshot-rollover-{hash}.json")));
    }
    Ok(targets)
}

fn snapshot_logical_hash_from_root_entry(name: &str) -> Result<Option<&str>> {
    if let Some(hash) = name
        .strip_prefix(".snapshot-store-")
        .and_then(|value| value.strip_suffix(".lock"))
    {
        validate_snapshot_logical_hash(hash)?;
        return Ok(Some(hash));
    }
    snapshot_metadata_target_hash(name)
}

fn snapshot_metadata_target_hash(name: &str) -> Result<Option<&str>> {
    for prefix in [
        ".snapshot-locator-",
        ".snapshot-init-",
        ".snapshot-rollover-",
    ] {
        if let Some(hash) = name
            .strip_prefix(prefix)
            .and_then(|value| value.strip_suffix(".json"))
        {
            validate_snapshot_logical_hash(hash)?;
            return Ok(Some(hash));
        }
    }
    Ok(None)
}

fn is_snapshot_metadata_temp_name(name: &str) -> Result<bool> {
    let Some(target) = AtomicStateWriter::canonical_direct_temp_target(OsStr::new(name))? else {
        return Ok(false);
    };
    let target = target
        .to_str()
        .context("authenticated snapshot temp target is not UTF-8")?;
    Ok(snapshot_metadata_target_hash(target)?.is_some())
}

fn validate_snapshot_logical_hash(hash: &str) -> Result<()> {
    if hash.len() != 64
        || !hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("authenticated snapshot metadata filename hash is malformed");
    }
    Ok(())
}

fn snapshot_metadata_hash<'a>(name: &'a str, prefix: &str) -> Result<Option<&'a str>> {
    let Some(suffix) = name.strip_prefix(prefix) else {
        return Ok(None);
    };
    let hash = suffix
        .strip_suffix(".json")
        .context("authenticated snapshot metadata filename is malformed")?;
    if !is_canonical_physical_id(hash) {
        bail!("authenticated snapshot metadata filename hash is malformed");
    }
    Ok(Some(hash))
}

fn verify_metadata_hash(hash: &str, logical_id: &str) -> Result<()> {
    if sha256_hex(logical_id.as_bytes()) != hash {
        bail!("authenticated snapshot metadata filename does not match its logical id");
    }
    Ok(())
}

fn is_canonical_physical_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

fn insert_physical_anchor(
    expected: &mut BTreeMap<String, FileIdentity>,
    owners: &mut BTreeMap<String, String>,
    logical_id: &str,
    identity: &JournalIdentity,
) -> Result<()> {
    insert_physical_binding(
        expected,
        owners,
        logical_id,
        &identity.run_id,
        &identity.run_directory_identity,
    )
}

fn insert_physical_binding(
    expected: &mut BTreeMap<String, FileIdentity>,
    owners: &mut BTreeMap<String, String>,
    logical_id: &str,
    run_id: &str,
    identity: &FileIdentity,
) -> Result<()> {
    claim_physical_owner(owners, logical_id, run_id)?;
    if let Some(previous) = expected.insert(run_id.to_string(), identity.clone()) {
        if previous != *identity {
            bail!("authenticated snapshot physical journal identity is inconsistent");
        }
    }
    Ok(())
}

fn claim_physical_owner(
    owners: &mut BTreeMap<String, String>,
    logical_id: &str,
    run_id: &str,
) -> Result<()> {
    if let Some(owner) = owners.get(run_id) {
        if owner != logical_id {
            bail!("authenticated snapshot physical journal is claimed by multiple logical stores");
        }
    } else {
        owners.insert(run_id.to_string(), logical_id.to_string());
    }
    Ok(())
}

fn insert_pending_physical_anchor(
    root: &SafeRoot,
    expected: &mut BTreeMap<String, FileIdentity>,
    owners: &mut BTreeMap<String, String>,
    logical_id: &str,
    physical_id: &str,
) -> Result<()> {
    claim_physical_owner(owners, logical_id, physical_id)?;
    if !root.direct_child_exists(physical_id)? {
        return Ok(());
    }
    let bound = root.bind_existing_direct_child_directory(physical_id)?;
    insert_physical_binding(expected, owners, logical_id, physical_id, bound.identity())
}

fn locator_mac_payload(locator: &SnapshotLocator) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        locator.version,
        &locator.logical_id,
        &locator.active_identity,
        locator.active_start_generation,
        locator.generation,
        locator.token,
        locator.prior_token,
        &locator.prior_terminal_mac,
        &locator.terminal_mac,
        &locator.retained_instances,
    ))
    .context("failed to encode authenticated snapshot locator MAC payload")
}

fn validate_locator<S: SnapshotSpec>(locator: &SnapshotLocator, logical_id: &str) -> Result<()> {
    locator.mac.validate()?;
    locator.prior_terminal_mac.validate()?;
    locator.terminal_mac.validate()?;
    if locator.version != S::SNAPSHOT_FORMAT_VERSION
        || locator.logical_id != logical_id
        || locator.active_start_generation == 0
        || locator.generation < locator.active_start_generation
        || locator.token == 0
        || locator.prior_token >= locator.token
        || locator.retained_instances.len() > 128
    {
        bail!("authenticated snapshot locator is malformed or unsupported");
    }
    let active_records = locator
        .generation
        .checked_sub(locator.active_start_generation)
        .and_then(|value| value.checked_add(1))
        .context("authenticated snapshot locator generation range overflowed")?;
    if active_records > u64::try_from(S::MAX_RECORDS).unwrap_or(u64::MAX) {
        bail!("authenticated snapshot locator exceeds its active journal bound");
    }
    let mut expected_start = 1_u64;
    let mut previous_token = 0_u64;
    for anchor in &locator.retained_instances {
        anchor.terminal_mac.validate()?;
        if anchor.start_generation != expected_start
            || anchor.end_generation < anchor.start_generation
            || anchor.terminal_token <= previous_token
            || anchor.identity == locator.active_identity
            || anchor.identity.repository != locator.active_identity.repository
        {
            bail!("authenticated snapshot retained anchor chain is malformed");
        }
        expected_start = anchor
            .end_generation
            .checked_add(1)
            .context("authenticated snapshot retained generation overflowed")?;
        previous_token = anchor.terminal_token;
    }
    if locator.active_start_generation == 1 {
        if locator.prior_token != 0
            || locator.prior_terminal_mac != AuthenticationTag::zero()
            || !locator.retained_instances.is_empty()
        {
            bail!("initial authenticated snapshot locator has a false prior anchor");
        }
    } else {
        let immediate_prior = locator
            .retained_instances
            .last()
            .context("rolled authenticated snapshot locator lost its retained prior instance")?;
        if expected_start != locator.active_start_generation
            || immediate_prior.terminal_token != locator.prior_token
            || immediate_prior.terminal_mac != locator.prior_terminal_mac
        {
            bail!("rolled authenticated snapshot locator lost its immediate prior anchor");
        }
    }
    Ok(())
}

fn read_locator<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    logical_id: &str,
) -> Result<SnapshotLocator> {
    let name = snapshot_locator_name(logical_id);
    let bytes =
        BoundedRegularReader::read_direct(root, &name, S::MAX_RECORD_BYTES).with_context(|| {
            format!(
                "initialized authenticated snapshot namespace '{logical_id}' has no signed locator"
            )
        })?;
    decode_locator::<S>(authenticator, logical_id, &bytes)
}

fn decode_locator<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    logical_id: &str,
    bytes: &[u8],
) -> Result<SnapshotLocator> {
    let locator: SnapshotLocator =
        serde_json::from_slice(bytes).context("authenticated snapshot locator is malformed")?;
    validate_locator::<S>(&locator, logical_id)?;
    authenticator.verify_repository_binding(&locator.active_identity.repository)?;
    authenticator.verify_tag(
        S::LOCATOR_DOMAIN,
        &locator_mac_payload(&locator)?,
        &locator.mac,
    )?;
    Ok(locator)
}

fn verify_retained_instances<S, T>(
    mut authenticator: RepositoryAuthenticator,
    locator: &SnapshotLocator,
) -> Result<RepositoryAuthenticator>
where
    S: SnapshotSpec,
    T: DeserializeOwned,
{
    let mut previous_token = 0_u64;
    for anchor in &locator.retained_instances {
        let journal = AuthenticatedStateJournal::<S>::open(authenticator, &anchor.identity)
            .context("authenticated snapshot retained journal is missing or substituted")?;
        let expected_len = anchor
            .end_generation
            .checked_sub(anchor.start_generation)
            .and_then(|value| value.checked_add(1))
            .context("authenticated snapshot retained generation range overflowed")?;
        if u64::try_from(journal.records().len()).unwrap_or(u64::MAX) != expected_len {
            bail!("authenticated snapshot retained journal length does not match its anchor");
        }
        let mut terminal_token = None;
        for record in journal.records() {
            if record.phase != S::SNAPSHOT_PHASE || record.subject.is_some() {
                bail!("authenticated snapshot retained journal contains a non-snapshot record");
            }
            let snapshot: AuthenticatedSnapshot<T> = serde_json::from_value(record.payload.clone())
                .context("authenticated snapshot retained payload is malformed")?;
            let generation = anchor
                .start_generation
                .checked_add(record.sequence.saturating_sub(1))
                .context("authenticated snapshot retained generation overflowed")?;
            if snapshot.version != S::SNAPSHOT_FORMAT_VERSION
                || snapshot.generation != generation
                || snapshot.token <= previous_token
            {
                bail!("authenticated snapshot retained generation or token is non-monotonic");
            }
            previous_token = snapshot.token;
            terminal_token = Some(snapshot.token);
        }
        let terminal = journal
            .records()
            .last()
            .context("authenticated snapshot retained journal is empty")?;
        if terminal.mac != anchor.terminal_mac
            || terminal_token != Some(anchor.terminal_token)
            || previous_token != anchor.terminal_token
        {
            bail!("authenticated snapshot retained terminal evidence does not match its anchor");
        }
        authenticator = journal.into_authenticator()?;
    }
    Ok(authenticator)
}

fn verify_retained_instances_read_only<S, T>(
    mut authenticator: RepositoryAuthenticator,
    locator: &SnapshotLocator,
) -> Result<RepositoryAuthenticator>
where
    S: SnapshotSpec,
    T: DeserializeOwned,
{
    let mut previous_token = 0_u64;
    for anchor in &locator.retained_instances {
        let journal = AuthenticatedStateJournal::<S>::open_existing_read_only(
            authenticator,
            &anchor.identity,
        )
        .context(
            "authenticated snapshot retained journal is missing, transitional, or substituted",
        )?;
        let expected_len = anchor
            .end_generation
            .checked_sub(anchor.start_generation)
            .and_then(|value| value.checked_add(1))
            .context("authenticated snapshot retained generation range overflowed")?;
        if u64::try_from(journal.records().len()).unwrap_or(u64::MAX) != expected_len {
            bail!("authenticated snapshot retained journal length does not match its anchor");
        }
        let mut terminal_token = None;
        for record in journal.records() {
            if record.phase != S::SNAPSHOT_PHASE || record.subject.is_some() {
                bail!("authenticated snapshot retained journal contains a non-snapshot record");
            }
            let snapshot: AuthenticatedSnapshot<T> = serde_json::from_value(record.payload.clone())
                .context("authenticated snapshot retained payload is malformed")?;
            let generation = anchor
                .start_generation
                .checked_add(record.sequence.saturating_sub(1))
                .context("authenticated snapshot retained generation overflowed")?;
            if snapshot.version != S::SNAPSHOT_FORMAT_VERSION
                || snapshot.generation != generation
                || snapshot.token <= previous_token
            {
                bail!("authenticated snapshot retained generation or token is non-monotonic");
            }
            previous_token = snapshot.token;
            terminal_token = Some(snapshot.token);
        }
        let terminal = journal
            .records()
            .last()
            .context("authenticated snapshot retained journal is empty")?;
        if terminal.mac != anchor.terminal_mac
            || terminal_token != Some(anchor.terminal_token)
            || previous_token != anchor.terminal_token
        {
            bail!("authenticated snapshot retained terminal evidence does not match its anchor");
        }
        authenticator = journal.into_authenticator()?;
    }
    Ok(authenticator)
}

fn exact_current_from_journal<S, T>(
    journal: &AuthenticatedStateJournalSnapshot<S>,
    locator: &SnapshotLocator,
) -> Result<AuthenticatedSnapshot<T>>
where
    S: SnapshotSpec,
    T: DeserializeOwned,
{
    if journal.identity() != &locator.active_identity {
        bail!("authenticated snapshot locator selected the wrong journal identity");
    }
    let mut previous_token = locator.prior_token;
    let mut current = None;
    for record in journal.records() {
        if record.phase != S::SNAPSHOT_PHASE || record.subject.is_some() {
            bail!("authenticated snapshot journal contains a non-snapshot record");
        }
        let snapshot: AuthenticatedSnapshot<T> = serde_json::from_value(record.payload.clone())
            .context("authenticated snapshot payload is malformed")?;
        let expected_generation = locator
            .active_start_generation
            .checked_add(record.sequence.saturating_sub(1))
            .context("authenticated snapshot absolute generation overflowed")?;
        if snapshot.version != S::SNAPSHOT_FORMAT_VERSION
            || snapshot.generation != expected_generation
            || snapshot.token <= previous_token
        {
            bail!("authenticated snapshot generation or token is non-monotonic");
        }
        previous_token = snapshot.token;
        current = Some(snapshot);
    }
    let current = current
        .context("initialized authenticated snapshot namespace has no durable signed generation")?;
    let terminal_mac = journal
        .records()
        .last()
        .map(|record| record.mac.clone())
        .context("authenticated snapshot journal has no terminal MAC")?;
    if current.generation != locator.generation
        || current.token != locator.token
        || terminal_mac != locator.terminal_mac
    {
        bail!("authenticated snapshot locator does not exactly match its journal tail; recovery is required");
    }
    Ok(current)
}

fn write_locator<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    store_lock: &BoundStateLock,
    root_lock: &BoundStateLock,
    locator: &mut SnapshotLocator,
) -> Result<()> {
    validate_locator::<S>(locator, &locator.logical_id)?;
    locator.mac = authenticator.sign(S::LOCATOR_DOMAIN, &locator_mac_payload(locator)?)?;
    let mut bytes = serde_json::to_vec(locator)?;
    bytes.push(b'\n');
    if bytes.len() as u64 > S::MAX_RECORD_BYTES {
        bail!("authenticated snapshot locator exceeds its byte bound");
    }
    let name = snapshot_locator_name(&locator.logical_id);
    AtomicStateWriter::write_direct_fenced(root, &name, &bytes, || {
        store_lock.verify(root)?;
        root_lock.verify(root)
    })?;
    store_lock.verify(root)?;
    root_lock.verify(root)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotFaultPoint {
    BeforeInitial,
    AfterInitial,
    AfterRolloverIntent,
    AfterRolloverDirectory,
    BeforeRollover,
}

#[cfg(test)]
thread_local! {
    static SNAPSHOT_FAULT: std::cell::Cell<Option<SnapshotFaultPoint>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn set_snapshot_fault(point: SnapshotFaultPoint) {
    SNAPSHOT_FAULT.with(|slot| slot.set(Some(point)));
}

#[cfg(test)]
fn take_snapshot_fault(point: SnapshotFaultPoint) -> bool {
    SNAPSHOT_FAULT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(not(test))]
fn take_snapshot_fault(_point: SnapshotFaultPoint) -> bool {
    false
}

#[cfg(test)]
mod tests {
    #![allow(clippy::err_expect)]
    use super::*;
    use crate::{
        artifacts::{repository_auth_writer, state_auth::AuthenticationDomain},
        effect_wal::{DefaultEffectWalSpec, EFFECT_WAL_ROOT_NAME},
        safe_state::set_temp_scavenge_after_quarantine_fault,
        state_journal::JournalSpec,
    };
    use git2::Repository;
    use std::{fs, sync::mpsc, thread, time::Duration};
    use tempfile::TempDir;

    enum TestSnapshotSpec {}

    impl JournalSpec for TestSnapshotSpec {
        const FORMAT_VERSION: u32 = 1;
        const NAMESPACE: &'static str = "test_snapshot";
        const ROOT_NAME: &'static str = "test-snapshots-v1";
        const ROOT_LOCK_NAME: &'static str = ".test-snapshots.lock";
        const INSTANCE_LOCK_NAME: &'static str = ".snapshot.lock";
        const HEAD_FILE_NAME: &'static str = ".head.json";
        const RECORD_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0test-snapshot-record\0v1\0");
        const HEAD_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0test-snapshot-head\0v1\0");
        const MAX_RECORDS: usize = 8;
        const MAX_RECORD_BYTES: u64 = 64 * 1024;
        const MAX_TOTAL_BYTES: u64 = 256 * 1024;
        const MAX_PHASE_BYTES: usize = 32;
        const MAX_SUBJECT_BYTES: usize = 64;
        const MAX_INSTANCE_ID_BYTES: usize = 64;
    }

    impl SnapshotSpec for TestSnapshotSpec {
        const SNAPSHOT_FORMAT_VERSION: u32 = 1;
        const LOCATOR_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0test-snapshot-locator\0v1\0");
    }

    enum QuotaSnapshotSpec {}

    enum ManyQuotaSnapshotSpec {}

    impl JournalSpec for QuotaSnapshotSpec {
        const FORMAT_VERSION: u32 = 1;
        const NAMESPACE: &'static str = "quota_snapshot";
        const ROOT_NAME: &'static str = "quota-snapshots-v1";
        const ROOT_LOCK_NAME: &'static str = ".quota-snapshots.lock";
        const INSTANCE_LOCK_NAME: &'static str = ".quota-snapshot.lock";
        const HEAD_FILE_NAME: &'static str = ".head.json";
        const RECORD_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0quota-snapshot-record\0v1\0");
        const HEAD_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0quota-snapshot-head\0v1\0");
        const MAX_RECORDS: usize = 8;
        const MAX_RECORD_BYTES: u64 = 64 * 1024;
        const MAX_TOTAL_BYTES: u64 = 256 * 1024;
        const MAX_PHASE_BYTES: usize = 32;
        const MAX_SUBJECT_BYTES: usize = 64;
        const MAX_INSTANCE_ID_BYTES: usize = 64;
    }

    impl SnapshotSpec for QuotaSnapshotSpec {
        const SNAPSHOT_FORMAT_VERSION: u32 = 1;
        const LOCATOR_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0quota-snapshot-locator\0v1\0");
        const MAX_LOGICAL_STORES: usize = 2;
        const MAX_ROOT_ENTRIES: usize = 7;
        const MAX_PHYSICAL_INSTANCES: usize = 2;
    }

    impl JournalSpec for ManyQuotaSnapshotSpec {
        const FORMAT_VERSION: u32 = 1;
        const NAMESPACE: &'static str = "many_quota_snapshot";
        const ROOT_NAME: &'static str = "many-quota-snapshots-v1";
        const ROOT_LOCK_NAME: &'static str = ".many-quota-snapshots.lock";
        const INSTANCE_LOCK_NAME: &'static str = ".many-quota-snapshot.lock";
        const HEAD_FILE_NAME: &'static str = ".head.json";
        const RECORD_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0many-quota-snapshot-record\0v1\0");
        const HEAD_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0many-quota-snapshot-head\0v1\0");
        const MAX_RECORDS: usize = 8;
        const MAX_RECORD_BYTES: u64 = 64 * 1024;
        const MAX_TOTAL_BYTES: u64 = 256 * 1024;
        const MAX_PHASE_BYTES: usize = 32;
        const MAX_SUBJECT_BYTES: usize = 64;
        const MAX_INSTANCE_ID_BYTES: usize = 64;
    }

    impl SnapshotSpec for ManyQuotaSnapshotSpec {
        const SNAPSHOT_FORMAT_VERSION: u32 = 1;
        const LOCATOR_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0many-quota-snapshot-locator\0v1\0");
        const MAX_LOGICAL_STORES: usize = 9;
        const MAX_ROOT_ENTRIES: usize = 28;
        const MAX_PHYSICAL_INSTANCES: usize = 9;
    }

    fn repository() -> (TempDir, std::path::PathBuf) {
        let temp = TempDir::new().expect("tempdir");
        let path = temp.path().join("repo");
        Repository::init(&path).expect("repository");
        (temp, path)
    }

    fn authenticator(path: &std::path::Path) -> RepositoryAuthenticator {
        repository_auth_writer(path)
            .expect("auth writer")
            .into_authenticator()
            .expect("authenticator")
    }

    #[test]
    fn snapshots_round_trip_with_monotonic_generation_and_token() {
        let (_temp, path) = repository();
        let mut store = AuthenticatedSnapshotStore::<TestSnapshotSpec, Vec<String>>::create(
            authenticator(&path),
            "claims",
            4,
            vec!["first".to_string()],
        )
        .expect("create snapshot");
        assert_eq!(store.current().generation, 1);
        assert!(store.commit(4, Vec::new()).is_err());
        store
            .commit(9, vec!["second".to_string()])
            .expect("second generation");
        drop(store);

        let reopened = AuthenticatedSnapshotStore::<TestSnapshotSpec, Vec<String>>::open_instance(
            authenticator(&path),
            "claims",
        )
        .expect("reopen snapshot");
        assert_eq!(reopened.current().generation, 2);
        assert_eq!(reopened.current().token, 9);
        assert_eq!(reopened.current().value, vec!["second".to_string()]);
    }

    #[test]
    fn existing_only_snapshot_reader_refuses_metadata_residue_without_scavenging() {
        let (_temp, path) = repository();
        let store = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "claims",
            1,
            7,
        )
        .expect("create snapshot");
        let root_path = store.store_root.path().to_path_buf();
        drop(store);
        let root = SafeRoot::open_existing(&root_path).expect("snapshot root");
        let locator = snapshot_locator_name("claims");
        AtomicStateWriter::write_direct_fenced(&root, &locator, b"crash-temp", || {
            bail!("injected locator fence failure")
        })
        .err()
        .expect("leave metadata residue");
        let before = fs::read_dir(&root_path)
            .expect("root before read")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<BTreeSet<_>>();

        let error = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::read_existing_current(
            authenticator(&path),
            "claims",
        )
        .expect_err("existing-only reader must refuse transitional residue");

        assert!(error.to_string().contains("unexpected file"));
        let after = fs::read_dir(&root_path)
            .expect("root after read")
            .map(|entry| entry.expect("entry").file_name())
            .collect::<BTreeSet<_>>();
        assert_eq!(
            after, before,
            "read-only inspection scavenged metadata residue"
        );
    }

    #[test]
    fn default_effect_namespace_supports_multiple_logical_snapshots() {
        let (_temp, path) = repository();
        let first = AuthenticatedSnapshotStore::<DefaultEffectWalSpec, String>::create(
            authenticator(&path),
            "source-action-a",
            1,
            "planned-a".to_string(),
        )
        .expect("create first logical effect snapshot");
        assert_eq!(
            first
                .store_root
                .path()
                .file_name()
                .and_then(|name| name.to_str()),
            Some(EFFECT_WAL_ROOT_NAME)
        );
        drop(first);
        let second = AuthenticatedSnapshotStore::<DefaultEffectWalSpec, String>::create(
            authenticator(&path),
            "source-action-b",
            1,
            "planned-b".to_string(),
        )
        .expect("create second logical effect snapshot");
        drop(second);

        let mut first = AuthenticatedSnapshotStore::<DefaultEffectWalSpec, String>::open_instance(
            authenticator(&path),
            "source-action-a",
        )
        .expect("open first logical effect snapshot");
        first
            .commit(2, "started-a".to_string())
            .expect("commit first logical effect snapshot");
        drop(first);
        let second = AuthenticatedSnapshotStore::<DefaultEffectWalSpec, String>::open_instance(
            authenticator(&path),
            "source-action-b",
        )
        .expect("open second logical effect snapshot");
        assert_eq!(second.current().value, "planned-b");
    }

    #[test]
    fn replayed_locator_detects_only_its_unanchored_new_journal_in_multi_logical_root() {
        let (_temp, path) = repository();
        let first = AuthenticatedSnapshotStore::<DefaultEffectWalSpec, String>::create(
            authenticator(&path),
            "source-replay-a",
            1,
            "old-a".to_string(),
        )
        .expect("create first logical snapshot");
        let root = first.store_root.path().to_path_buf();
        let locator_path = root.join(snapshot_locator_name("source-replay-a"));
        let old_locator = fs::read(&locator_path).expect("old signed locator");
        let first = first
            .rollover(authenticator(&path), 2, "new-a".to_string())
            .expect("roll over first logical snapshot");
        let unanchored_new_run = first.identity().run_id.clone();
        drop(first);
        let second = AuthenticatedSnapshotStore::<DefaultEffectWalSpec, String>::create(
            authenticator(&path),
            "source-replay-b",
            1,
            "value-b".to_string(),
        )
        .expect("create unrelated logical snapshot");
        let unrelated_run = second.identity().run_id.clone();
        drop(second);
        fs::write(&locator_path, old_locator).expect("replay old locator for first logical store");

        let error = AuthenticatedSnapshotStore::<DefaultEffectWalSpec, String>::open_instance(
            authenticator(&path),
            "source-replay-a",
        )
        .err()
        .expect("replayed locator must expose its newer journal");
        let message = error.to_string();
        assert!(
            message.contains(&unanchored_new_run),
            "unexpected error: {message}"
        );
        assert!(
            !message.contains(&unrelated_run),
            "unrelated logical journal was blamed"
        );
    }

    #[test]
    fn other_logical_store_remains_usable_while_rollover_intent_is_pending() {
        let (_temp, path) = repository();
        let first = AuthenticatedSnapshotStore::<DefaultEffectWalSpec, String>::create(
            authenticator(&path),
            "source-pending-a",
            1,
            "old-a".to_string(),
        )
        .expect("create first logical snapshot");
        set_snapshot_fault(SnapshotFaultPoint::AfterRolloverDirectory);
        first
            .rollover(authenticator(&path), 2, "new-a".to_string())
            .err()
            .expect("leave signed prepared rollover candidate");

        let mut second = AuthenticatedSnapshotStore::<DefaultEffectWalSpec, String>::create(
            authenticator(&path),
            "source-pending-b",
            1,
            "planned-b".to_string(),
        )
        .expect("create unrelated logical store while first intent is pending");
        second
            .commit(2, "started-b".to_string())
            .expect("commit unrelated logical store");
        drop(second);
        let first = AuthenticatedSnapshotStore::<DefaultEffectWalSpec, String>::open_instance(
            authenticator(&path),
            "source-pending-a",
        )
        .expect("recover prepared first logical rollover");
        assert_eq!(first.current().value, "old-a");
    }

    #[test]
    fn namespace_quota_refuses_new_logical_store_before_creating_residue() {
        let (_temp, path) = repository();
        for logical_id in ["quota-a", "quota-b"] {
            let store = AuthenticatedSnapshotStore::<QuotaSnapshotSpec, u64>::create(
                authenticator(&path),
                logical_id,
                1,
                1,
            )
            .expect("create logical store within quota");
            drop(store);
        }
        let error = AuthenticatedSnapshotStore::<QuotaSnapshotSpec, u64>::create(
            authenticator(&path),
            "quota-c",
            1,
            1,
        )
        .err()
        .expect("quota+1 logical store must fail before creation");
        assert!(error.to_string().contains("capacity"));
        let repo = crate::git_repository::open(&path).expect("repo");
        let root = repo
            .commondir()
            .join("maco/state")
            .join(QuotaSnapshotSpec::ROOT_NAME);
        assert!(!root.join(snapshot_init_name("quota-c")).exists());
        assert!(!root.join(snapshot_lock_name("quota-c")).exists());
        assert_eq!(fs::read_dir(root).expect("quota root").count(), 7);
    }

    #[test]
    fn full_namespace_open_scavenges_its_locator_crash_temp_before_inventory() {
        let (_temp, path) = repository();
        for logical_id in ["quota-temp-a", "quota-temp-b"] {
            let store = AuthenticatedSnapshotStore::<QuotaSnapshotSpec, u64>::create(
                authenticator(&path),
                logical_id,
                1,
                1,
            )
            .expect("fill logical quota");
            drop(store);
        }
        let repo = crate::git_repository::open(&path).expect("repo");
        let root_path = repo
            .commondir()
            .join("maco/state")
            .join(QuotaSnapshotSpec::ROOT_NAME);
        let root = SafeRoot::open_existing(&root_path).expect("quota root");
        let locator_name = snapshot_locator_name("quota-temp-a");
        AtomicStateWriter::write_direct_fenced(&root, &locator_name, b"crash-temp", || {
            bail!("injected locator fence failure")
        })
        .err()
        .expect("leave one owner-private locator temp");
        assert_eq!(fs::read_dir(&root_path).expect("quota root").count(), 8);

        let reopened = AuthenticatedSnapshotStore::<QuotaSnapshotSpec, u64>::open_instance(
            authenticator(&path),
            "quota-temp-a",
        )
        .expect("responsible logical store scavenges before root inventory");
        assert_eq!(reopened.current().value, 1);
        assert_eq!(fs::read_dir(root_path).expect("quota root").count(), 7);
    }

    #[test]
    fn full_namespace_new_logical_refusal_scavenges_existing_logical_locator_temp() {
        let (_temp, path) = repository();
        for logical_id in ["quota-existing-a", "quota-existing-b"] {
            let store = AuthenticatedSnapshotStore::<QuotaSnapshotSpec, u64>::create(
                authenticator(&path),
                logical_id,
                1,
                1,
            )
            .expect("fill logical quota");
            drop(store);
        }
        let repo = crate::git_repository::open(&path).expect("repo");
        let root_path = repo
            .commondir()
            .join("maco/state")
            .join(QuotaSnapshotSpec::ROOT_NAME);
        let root = SafeRoot::open_existing(&root_path).expect("quota root");
        let existing_locator = snapshot_locator_name("quota-existing-a");
        AtomicStateWriter::write_direct_fenced(&root, &existing_locator, b"crash-temp", || {
            bail!("injected existing locator fence failure")
        })
        .err()
        .expect("leave canonical existing-logical locator temp");
        assert_eq!(fs::read_dir(&root_path).expect("root with temp").count(), 8);

        let error = AuthenticatedSnapshotStore::<QuotaSnapshotSpec, u64>::create(
            authenticator(&path),
            "quota-new-c",
            1,
            1,
        )
        .err()
        .expect("new logical store must be refused at quota");

        assert!(error.to_string().contains("capacity"));
        assert_eq!(
            fs::read_dir(&root_path).expect("clean quota root").count(),
            7
        );
        assert!(!root_path
            .join(snapshot_locator_name("quota-new-c"))
            .exists());
        assert!(!root_path.join(snapshot_init_name("quota-new-c")).exists());
        assert!(!root_path.join(snapshot_lock_name("quota-new-c")).exists());
        let physical_count = fs::read_dir(&root_path)
            .expect("quota root")
            .map(|entry| entry.expect("root entry"))
            .filter(|entry| entry.file_type().expect("entry type").is_dir())
            .count();
        assert_eq!(physical_count, 2, "new logical journal residue was created");
        for logical_id in ["quota-existing-a", "quota-existing-b"] {
            let reopened = AuthenticatedSnapshotStore::<QuotaSnapshotSpec, u64>::open_instance(
                authenticator(&path),
                logical_id,
            )
            .expect("existing logical store remains healthy");
            assert_eq!(reopened.current().value, 1);
        }
    }

    #[test]
    fn full_namespace_open_scavenges_nine_logical_temp_namespaces_in_one_pass() {
        let (_temp, path) = repository();
        let logical_ids = (0..9)
            .map(|index| format!("many-temp-{index}"))
            .collect::<Vec<_>>();
        for logical_id in &logical_ids {
            let store = AuthenticatedSnapshotStore::<ManyQuotaSnapshotSpec, u64>::create(
                authenticator(&path),
                logical_id,
                1,
                1,
            )
            .expect("fill many-logical namespace");
            drop(store);
        }
        let repo = crate::git_repository::open(&path).expect("repo");
        let root_path = repo
            .commondir()
            .join("maco/state")
            .join(ManyQuotaSnapshotSpec::ROOT_NAME);
        let root = SafeRoot::open_existing(&root_path).expect("many-logical root");
        assert_eq!(fs::read_dir(&root_path).expect("full root").count(), 28);
        for logical_id in &logical_ids {
            let locator_name = snapshot_locator_name(logical_id);
            AtomicStateWriter::write_direct_fenced(&root, &locator_name, b"crash-temp", || {
                bail!("injected locator fence failure")
            })
            .err()
            .expect("leave logical locator temp");
        }
        assert_eq!(
            fs::read_dir(&root_path).expect("root with temps").count(),
            37
        );

        let reopened = AuthenticatedSnapshotStore::<ManyQuotaSnapshotSpec, u64>::open_instance(
            authenticator(&path),
            &logical_ids[0],
        )
        .expect("one open scavenges every logical temp namespace");

        assert_eq!(reopened.current().value, 1);
        assert_eq!(fs::read_dir(root_path).expect("recovered root").count(), 28);
    }

    #[test]
    fn anchorless_logical_quarantine_survives_two_crashes_and_is_recovered_by_another_logical() {
        let (_temp, path) = repository();
        let store = AuthenticatedSnapshotStore::<ManyQuotaSnapshotSpec, u64>::create(
            authenticator(&path),
            "logical-a",
            1,
            1,
        )
        .expect("create anchored logical A");
        let root_path = store.store_root.path().to_path_buf();
        let root = SafeRoot::open_existing(&root_path).expect("snapshot root");
        drop(store);
        let baseline_entries = fs::read_dir(&root_path).expect("baseline root").count();
        let orphan_target = snapshot_locator_name("anchorless-logical-b");
        AtomicStateWriter::write_direct_fenced(&root, &orphan_target, b"partial", || {
            bail!("injected logical B write crash")
        })
        .err()
        .expect("leave anchorless logical B live temp");

        set_temp_scavenge_after_quarantine_fault();
        let first_restart =
            AuthenticatedSnapshotStore::<ManyQuotaSnapshotSpec, u64>::open_instance(
                authenticator(&path),
                "logical-a",
            )
            .err()
            .expect("logical A crashes after quarantining logical B");
        assert!(first_restart
            .to_string()
            .contains("injected state temp scavenging crash after quarantine"));
        assert_eq!(
            fs::read_dir(&root_path)
                .expect("root after first restart")
                .count(),
            baseline_entries + 1
        );

        let reopened = AuthenticatedSnapshotStore::<ManyQuotaSnapshotSpec, u64>::open_instance(
            authenticator(&path),
            "logical-a",
        )
        .expect("logical A recovers reversible logical B quarantine");

        assert_eq!(reopened.current().value, 1);
        assert_eq!(
            fs::read_dir(root_path)
                .expect("root after second restart")
                .count(),
            baseline_entries
        );
    }

    #[test]
    fn initialized_empty_instance_is_not_treated_as_empty_state() {
        let (_temp, path) = repository();
        let auth = authenticator(&path);
        let journal = AuthenticatedStateJournal::<TestSnapshotSpec>::create(auth, "empty")
            .expect("reserve empty journal");
        drop(journal);
        let error =
            AuthenticatedSnapshotStore::<TestSnapshotSpec, serde_json::Value>::open_instance(
                authenticator(&path),
                "empty",
            )
            .err()
            .expect("empty initialized namespace must fail");
        assert!(error.to_string().contains("no signed locator"));
    }

    #[test]
    fn rollover_continues_absolute_generation_and_retains_signed_prior_anchor() {
        let (_temp, path) = repository();
        let mut store = AuthenticatedSnapshotStore::<TestSnapshotSpec, String>::create(
            authenticator(&path),
            "rollover",
            2,
            "one".to_string(),
        )
        .expect("create");
        store.commit(5, "two".to_string()).expect("second");
        let old_identity = store.identity().clone();
        let old_directory = store.store_root.path().join(&old_identity.run_id);
        let store = store
            .rollover(authenticator(&path), 8, "three".to_string())
            .expect("rollover");
        assert_eq!(store.current().generation, 3);
        assert_eq!(store.current().token, 8);
        assert_ne!(store.identity(), &old_identity);
        assert_eq!(store.retained_instances(), vec![&old_identity]);
        assert!(old_directory.is_dir(), "prior journal must remain retained");
        drop(store);

        let reopened = AuthenticatedSnapshotStore::<TestSnapshotSpec, String>::open_instance(
            authenticator(&path),
            "rollover",
        )
        .expect("reopen rolled store");
        assert_eq!(reopened.logical_id(), "rollover");
        assert_eq!(reopened.current().generation, 3);
        assert_eq!(reopened.current().value, "three");
        assert_eq!(reopened.retained_instances().len(), 1);
    }

    #[test]
    fn rollover_faults_recover_only_candidates_bound_by_a_prepared_intent() {
        for fault in [
            SnapshotFaultPoint::AfterRolloverIntent,
            SnapshotFaultPoint::AfterRolloverDirectory,
        ] {
            let (_temp, path) = repository();
            let store = AuthenticatedSnapshotStore::<TestSnapshotSpec, String>::create(
                authenticator(&path),
                "rollover-prepared-crash",
                1,
                "old".to_string(),
            )
            .expect("create");
            set_snapshot_fault(fault);
            store
                .rollover(authenticator(&path), 2, "new".to_string())
                .err()
                .expect("injected prepared rollover crash");

            let reopened = AuthenticatedSnapshotStore::<TestSnapshotSpec, String>::open_instance(
                authenticator(&path),
                "rollover-prepared-crash",
            )
            .expect("prepared candidate recovers to old authority");
            assert_eq!(reopened.current().generation, 1);
            assert_eq!(reopened.current().value, "old");
        }
    }

    #[test]
    fn ready_rollover_fault_before_locator_switch_recovers_forward() {
        let (_temp, path) = repository();
        let store = AuthenticatedSnapshotStore::<TestSnapshotSpec, String>::create(
            authenticator(&path),
            "rollover-crash",
            1,
            "old".to_string(),
        )
        .expect("create");
        set_snapshot_fault(SnapshotFaultPoint::BeforeRollover);
        store
            .rollover(authenticator(&path), 2, "new".to_string())
            .err()
            .expect("injected rollover crash");

        let reopened = AuthenticatedSnapshotStore::<TestSnapshotSpec, String>::open_instance(
            authenticator(&path),
            "rollover-crash",
        )
        .expect("ready rollover recovers forward");
        assert_eq!(reopened.current().generation, 2);
        assert_eq!(reopened.current().value, "new");
    }

    #[test]
    fn replayed_old_locator_cannot_hide_a_retained_newer_physical_journal() {
        let (_temp, path) = repository();
        let store = AuthenticatedSnapshotStore::<TestSnapshotSpec, String>::create(
            authenticator(&path),
            "rollover-replay",
            1,
            "old".to_string(),
        )
        .expect("create");
        let locator_path = store
            .store_root
            .path()
            .join(snapshot_locator_name("rollover-replay"));
        let old_locator = fs::read(&locator_path).expect("old signed locator");
        let store = store
            .rollover(authenticator(&path), 2, "new".to_string())
            .expect("rollover");
        drop(store);
        fs::write(&locator_path, old_locator).expect("replay old signed locator");

        let error = AuthenticatedSnapshotStore::<TestSnapshotSpec, String>::open_instance(
            authenticator(&path),
            "rollover-replay",
        )
        .err()
        .expect("unanchored newer physical journal must be detected");
        let message = error.to_string();
        assert!(
            message.contains("physical journal inventory")
                || message.contains("unexpected directory")
                || message.contains("not anchored")
        );
    }

    #[test]
    fn one_record_locator_lag_recovers_but_older_signed_replay_fails_closed() {
        let (_temp, path) = repository();
        let mut store = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "locator-recovery",
            1,
            1,
        )
        .expect("create");
        let locator_path = store
            .store_root
            .path()
            .join(snapshot_locator_name("locator-recovery"));
        let generation_one_locator = fs::read(&locator_path).expect("generation one locator");
        store.commit(2, 2).expect("generation two");
        drop(store);
        fs::write(&locator_path, &generation_one_locator).expect("restore one-behind locator");
        let mut recovered = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::open_instance(
            authenticator(&path),
            "locator-recovery",
        )
        .expect("single-record crash window recovers");
        assert_eq!(recovered.current().generation, 2);
        recovered.commit(3, 3).expect("generation three");
        drop(recovered);

        fs::write(&locator_path, generation_one_locator).expect("replay older signed locator");
        let error = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::open_instance(
            authenticator(&path),
            "locator-recovery",
        )
        .err()
        .expect("multi-record locator replay must fail");
        assert!(error.to_string().contains("one-record crash window"));
    }

    #[test]
    fn missing_signed_locator_never_becomes_empty_state() {
        let (_temp, path) = repository();
        let store = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "missing-locator",
            1,
            7,
        )
        .expect("create");
        let locator = store
            .store_root
            .path()
            .join(snapshot_locator_name("missing-locator"));
        drop(store);
        fs::remove_file(locator).expect("remove locator");
        let error = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::open_instance(
            authenticator(&path),
            "missing-locator",
        )
        .err()
        .expect("missing locator must fail closed");
        assert!(error.to_string().contains("no signed locator"));
    }

    #[test]
    fn initial_create_crash_retries_with_a_new_random_physical_journal() {
        let (_temp, path) = repository();
        set_snapshot_fault(SnapshotFaultPoint::BeforeInitial);
        AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "initial-crash",
            1,
            1,
        )
        .err()
        .expect("injected initialization crash");

        let store = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "initial-crash",
            2,
            2,
        )
        .expect("retry initialization");
        assert_eq!(store.logical_id(), "initial-crash");
        assert_ne!(store.instance_id(), "initial-crash");
        assert_eq!(store.current().generation, 1);
        assert_eq!(store.current().token, 2);
    }

    #[test]
    fn initialization_pending_scavenges_metadata_residue_before_inventory() {
        let (_temp, path) = repository();
        set_snapshot_fault(SnapshotFaultPoint::BeforeInitial);
        AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "pending-scavenge",
            1,
            1,
        )
        .err()
        .expect("leave pending initialization");
        let repo = crate::git_repository::open(&path).expect("repo");
        let root_path = repo
            .commondir()
            .join("maco/state")
            .join(TestSnapshotSpec::ROOT_NAME);
        let root = SafeRoot::open_existing(&root_path).expect("snapshot root");
        let baseline_entries = fs::read_dir(&root_path).expect("pending root").count();
        for _ in 0..3 {
            AtomicStateWriter::write_direct_fenced(
                &root,
                snapshot_init_name("pending-scavenge"),
                b"partial",
                || bail!("injected pending metadata crash"),
            )
            .err()
            .expect("leave pending temp");
        }

        assert!(
            AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::initialization_pending(
                &authenticator(&path),
                "pending-scavenge",
            )
            .expect("pending inspection recovers residue")
        );
        assert_eq!(
            fs::read_dir(root_path)
                .expect("recovered pending root")
                .count(),
            baseline_entries
        );
    }

    #[test]
    fn locator_anchor_verification_remains_nonmutating_with_temp_residue() {
        let (_temp, path) = repository();
        let store = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "read-only-anchor",
            1,
            1,
        )
        .expect("create anchored store");
        let identity = store.identity().clone();
        let generation = store.current().generation;
        let root_path = store.store_root.path().to_path_buf();
        let root = SafeRoot::open_existing(&root_path).expect("snapshot root");
        drop(store);
        let baseline_entries = fs::read_dir(&root_path).expect("baseline root").count();
        AtomicStateWriter::write_direct_fenced(
            &root,
            snapshot_locator_name("read-only-anchor"),
            b"partial",
            || bail!("injected read-only residue"),
        )
        .err()
        .expect("leave locator temp");

        AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::verify_locator_anchor(
            &authenticator(&path),
            "read-only-anchor",
            &identity,
            generation,
        )
        .expect("read-only locator verification");

        assert_eq!(
            fs::read_dir(root_path)
                .expect("unmodified read-only root")
                .count(),
            baseline_entries + 1
        );
    }

    #[test]
    fn open_cleans_exact_init_intent_left_after_locator_publication() {
        let (_temp, path) = repository();
        set_snapshot_fault(SnapshotFaultPoint::AfterInitial);
        AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "locator-init-tail",
            1,
            9,
        )
        .err()
        .expect("injected post-locator crash");
        let repo = crate::git_repository::open(&path).expect("repo");
        let root = repo
            .commondir()
            .join("maco/state")
            .join(TestSnapshotSpec::ROOT_NAME);
        let intent = root.join(snapshot_init_name("locator-init-tail"));
        assert!(intent.exists());

        let store = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::open_instance(
            authenticator(&path),
            "locator-init-tail",
        )
        .expect("open recovers exact init tail");
        assert_eq!(store.current().value, 9);
        assert!(!intent.exists());
    }

    #[test]
    fn concurrent_create_cannot_replace_an_initialized_logical_store() {
        let (_temp, path) = repository();
        let first = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "concurrent-create",
            1,
            1,
        )
        .expect("first creator");
        let error = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "concurrent-create",
            2,
            2,
        )
        .err()
        .expect("second creator must fail");
        assert!(error.to_string().contains("already initialized"));
        assert_eq!(first.current().value, 1);
    }

    #[test]
    fn busy_logical_open_never_acquires_root_lock_before_store_lock() {
        let (_temp, path) = repository();
        let mut store = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "lock-order",
            1,
            1,
        )
        .expect("create held logical store");
        let (root_acquired_tx, root_acquired_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let open_path = path.clone();
        let worker = thread::spawn(move || {
            crate::safe_state::set_kernel_lock_after_flock_hook(move |lock_path| {
                if lock_path.file_name().and_then(|name| name.to_str())
                    == Some(TestSnapshotSpec::ROOT_LOCK_NAME)
                {
                    root_acquired_tx.send(()).expect("report root lock");
                    true
                } else {
                    false
                }
            });
            let error = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::open_instance(
                authenticator(&open_path),
                "lock-order",
            )
            .err()
            .expect("busy logical store must refuse concurrent open");
            done_tx.send(error.to_string()).expect("report open result");
        });
        let message = done_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("concurrent open must fail without waiting on the root lock");
        assert!(message.contains("active") || message.contains("lock"));
        assert!(
            root_acquired_rx.try_recv().is_err(),
            "concurrent open acquired the namespace root before the busy logical store lock"
        );
        worker.join().expect("open worker");
        store.commit(2, 2).expect("held store can still commit");
    }

    #[test]
    fn retained_journal_deletion_is_detected_on_open() {
        let (_temp, path) = repository();
        let store = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "retained-delete",
            1,
            1,
        )
        .expect("create");
        let old = store.identity().clone();
        let root = store.store_root.path().to_path_buf();
        let store = store
            .rollover(authenticator(&path), 2, 2)
            .expect("rollover");
        drop(store);
        fs::remove_dir_all(root.join(old.run_id)).expect("delete retained journal");
        let error = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::open_instance(
            authenticator(&path),
            "retained-delete",
        )
        .err()
        .expect("retained deletion must fail");
        assert!(error.to_string().contains("physical journal inventory"));
    }

    #[cfg(unix)]
    #[test]
    fn retained_journal_directory_substitution_is_detected_on_open() {
        use std::os::unix::fs::PermissionsExt;

        let (_temp, path) = repository();
        let store = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::create(
            authenticator(&path),
            "retained-substitute",
            1,
            1,
        )
        .expect("create");
        let old = store.identity().clone();
        let root = store.store_root.path().to_path_buf();
        let store = store
            .rollover(authenticator(&path), 2, 2)
            .expect("rollover");
        drop(store);
        let old_path = root.join(&old.run_id);
        fs::rename(&old_path, root.join("retained-original")).expect("move retained journal");
        fs::create_dir(&old_path).expect("replacement directory");
        fs::set_permissions(&old_path, fs::Permissions::from_mode(0o700))
            .expect("private replacement");
        let error = AuthenticatedSnapshotStore::<TestSnapshotSpec, u64>::open_instance(
            authenticator(&path),
            "retained-substitute",
        )
        .err()
        .expect("retained substitution must fail");
        let message = error.to_string();
        assert!(
            message.contains("physical journal inventory")
                || message.contains("unexpected directory")
        );
    }
}
