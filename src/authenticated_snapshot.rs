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
    safe_state::{AtomicStateWriter, BoundedRegularReader, SafeRoot},
    state_journal::{AuthenticatedStateJournal, JournalIdentity, JournalSpec},
};
use anyhow::{bail, Context, Result};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{fs, fs::File, marker::PhantomData};

pub(crate) trait SnapshotSpec: JournalSpec {
    const SNAPSHOT_FORMAT_VERSION: u32;
    const SNAPSHOT_PHASE: &'static str = "snapshot";
    const LOCATOR_DOMAIN: AuthenticationDomain;
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
        write_locator::<S>(
            journal.authenticator(),
            &store_root,
            &store_lock,
            &mut locator,
        )?;
        if take_snapshot_fault(SnapshotFaultPoint::AfterInitial) {
            bail!("injected authenticated snapshot initialization fault after locator publication");
        }
        remove_init_intent::<S>(journal.authenticator(), &store_root, &store_lock, &intent)?;
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
        let store_root = AuthenticatedStateJournal::<S>::existing_root(&authenticator)?;
        let root_lock = BoundStateLock::acquire(&store_root, S::ROOT_LOCK_NAME)?;
        if !store_root.direct_child_exists(snapshot_locator_name(logical_id))? {
            bail!(
                "initialized authenticated snapshot namespace '{logical_id}' has no signed locator"
            );
        }
        root_lock.verify(&store_root)?;
        drop(root_lock);
        let store_lock =
            BoundStateLock::try_acquire_exclusive(&store_root, &snapshot_lock_name(logical_id))
                .context("authenticated snapshot store is active elsewhere")?;
        let mut locator = read_locator::<S>(&authenticator, &store_root, logical_id)?;
        recover_init_after_locator::<S>(&authenticator, &store_root, &store_lock, &locator)?;
        let authenticator = verify_retained_instances::<S, T>(authenticator, &locator)?;
        let journal =
            AuthenticatedStateJournal::<S>::open(authenticator, &locator.active_identity)?;
        Self::from_journal(
            journal,
            store_root,
            store_lock,
            logical_id.to_string(),
            &mut locator,
        )
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
            write_locator::<S>(journal.authenticator(), &store_root, &store_lock, locator)?;
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
        write_locator::<S>(
            self.journal.authenticator(),
            &self.store_root,
            &self.store_lock,
            &mut self.locator,
        )?;
        Ok(&self.current)
    }

    /// Starts a compacted physical journal while preserving a signed anchor to
    /// the old terminal MAC. Publication order is new generation first,
    /// atomic locator switch second, and old-instance retention last.
    pub(crate) fn rollover(
        self,
        authenticator: RepositoryAuthenticator,
        token: u64,
        value: T,
    ) -> Result<Self> {
        if token <= self.current.token {
            bail!("authenticated snapshot rollover token must increase monotonically");
        }
        authenticator.verify_repository_binding(&self.locator.active_identity.repository)?;
        let generation = self
            .current
            .generation
            .checked_add(1)
            .context("authenticated snapshot rollover generation overflowed")?;
        let physical_id = random_identifier()?;
        let mut journal = AuthenticatedStateJournal::<S>::create(authenticator, &physical_id)?;
        if journal.root().identity() != self.store_root.identity() {
            bail!("authenticated snapshot rollover changed its journal root identity");
        }
        let current = AuthenticatedSnapshot {
            version: S::SNAPSHOT_FORMAT_VERSION,
            generation,
            token,
            value,
        };
        journal
            .append(S::SNAPSHOT_PHASE, None, &current)
            .context("failed to publish compacted authenticated snapshot")?;
        let terminal_mac = journal
            .records()
            .last()
            .map(|record| record.mac.clone())
            .context("authenticated snapshot rollover lost its terminal MAC")?;
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
        write_locator::<S>(
            journal.authenticator(),
            &self.store_root,
            &self.store_lock,
            &mut locator,
        )?;
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
    let root_lock = BoundStateLock::acquire(&root, S::ROOT_LOCK_NAME)?;
    root_lock.verify(&root)?;
    let locator_name = snapshot_locator_name(logical_id);
    if root.direct_child_exists(&locator_name)? {
        bail!("authenticated snapshot logical store is already initialized");
    }
    let init_name = snapshot_init_name(logical_id);
    let store_lock_name = snapshot_lock_name(logical_id);
    let init_exists = root.direct_child_exists(&init_name)?;
    let store_lock_exists = root.direct_child_exists(&store_lock_name)?;

    let (store_lock, mut intent) = if init_exists {
        let store_lock = BoundStateLock::try_acquire_exclusive(&root, &store_lock_name)
            .context("authenticated snapshot initialization is active elsewhere")?;
        let mut intent = read_init_intent::<S>(authenticator, &root, logical_id)?;
        intent.attempt = intent
            .attempt
            .checked_add(1)
            .context("authenticated snapshot initialization attempt overflowed")?;
        if intent.attempt > 8 {
            bail!("authenticated snapshot initialization exceeded its bounded retry count");
        }
        intent.physical_id = random_identifier()?;
        (store_lock, intent)
    } else {
        if store_lock_exists {
            bail!(
                "authenticated snapshot locator is missing after initialization; refusing recreation"
            );
        }
        let mut intent = SnapshotInitIntent {
            version: S::SNAPSHOT_FORMAT_VERSION,
            logical_id: logical_id.to_string(),
            attempt: 1,
            physical_id: random_identifier()?,
            mac: AuthenticationTag::zero(),
        };
        write_init_intent::<S>(authenticator, &root, &root_lock, &mut intent)?;
        let store_lock = BoundStateLock::try_acquire_exclusive(&root, &store_lock_name)
            .context("authenticated snapshot initialization lock could not be acquired")?;
        (store_lock, intent)
    };
    if init_exists {
        write_init_intent::<S>(authenticator, &root, &root_lock, &mut intent)?;
    }
    root_lock.verify(&root)?;
    store_lock.verify(&root)?;
    drop(root_lock);
    Ok((root, store_lock, intent))
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
    let intent: SnapshotInitIntent = serde_json::from_slice(&bytes)
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
    AtomicStateWriter::scavenge_direct_temps(root, &name)?;
    AtomicStateWriter::write_direct_fenced(root, &name, &bytes, || lock.verify(root))
}

fn remove_init_intent<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    lock: &BoundStateLock,
    expected: &SnapshotInitIntent,
) -> Result<()> {
    let observed = read_init_intent::<S>(authenticator, root, &expected.logical_id)?;
    if &observed != expected {
        bail!("authenticated snapshot initialization intent changed before cleanup");
    }
    lock.verify(root)?;
    fs::remove_file(root.direct_child(snapshot_init_name(&expected.logical_id))?)?;
    File::open(root.path())?.sync_all()?;
    lock.verify(root)
}

fn recover_init_after_locator<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    store_lock: &BoundStateLock,
    locator: &SnapshotLocator,
) -> Result<()> {
    let name = snapshot_init_name(&locator.logical_id);
    if !root.direct_child_exists(&name)? {
        return Ok(());
    }
    let root_lock = BoundStateLock::acquire(root, S::ROOT_LOCK_NAME)?;
    let intent = read_init_intent::<S>(authenticator, root, &locator.logical_id)?;
    if intent.physical_id != locator.active_identity.run_id {
        bail!("authenticated snapshot locator has a mismatched initialization intent");
    }
    remove_init_intent::<S>(authenticator, root, store_lock, &intent)?;
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
    let locator: SnapshotLocator =
        serde_json::from_slice(&bytes).context("authenticated snapshot locator is malformed")?;
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

fn write_locator<S: SnapshotSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    lock: &BoundStateLock,
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
    AtomicStateWriter::scavenge_direct_temps(root, &name)?;
    AtomicStateWriter::write_direct_fenced(root, &name, &bytes, || lock.verify(root))?;
    lock.verify(root)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SnapshotFaultPoint {
    BeforeInitial,
    AfterInitial,
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
        state_journal::JournalSpec,
    };
    use git2::Repository;
    use std::fs;
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
    fn rollover_fault_before_locator_switch_leaves_old_store_authoritative() {
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
        .expect("old locator remains authoritative");
        assert_eq!(reopened.current().generation, 1);
        assert_eq!(reopened.current().value, "old");
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
        let repo = Repository::open(&path).expect("repo");
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
        assert!(error.to_string().contains("retained journal"));
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
        assert!(error.to_string().contains("retained journal"));
    }
}
