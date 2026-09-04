//! Bounded, repository-authenticated append-only state journals.
//!
//! Published sequence records are immutable. Each record is MAC chained to its
//! predecessor, while an authenticated atomic head detects a missing or
//! truncated published tail. A single identity-bound kernel lock protects one
//! run for its full lifecycle.

// Generic discovery helpers are staged for snapshot/effect consumers while
// checkpoint callers continue to use the compatibility alias.
#![allow(dead_code)]

use crate::{
    artifacts::state_auth::{
        random_identifier, validate_repository_binding, AuthenticationDomain, AuthenticationTag,
        BoundStateLock, RepositoryAuthBinding, RepositoryAuthenticator,
    },
    safe_state::{identity_for_path, BoundedRegularReader, FileIdentity, SafeRoot},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, File, OpenOptions},
    io::Write,
    marker::PhantomData,
    path::Path,
};

#[cfg(test)]
use std::path::PathBuf;

#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

const JOURNAL_FORMAT_VERSION: u32 = 3;
pub(crate) const JOURNAL_ROOT_NAME: &str = "orchestration-checkpoints-v3";
const JOURNAL_ROOT_LOCK: &str = ".journals.lock";
const RUN_LOCK_NAME: &str = ".resume.lock";
const HEAD_FILE_NAME: &str = ".head.json";
const RECORD_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0orchestration-checkpoint-record\0v3\0");
const HEAD_DOMAIN: AuthenticationDomain =
    AuthenticationDomain::new(b"MACO\0orchestration-checkpoint-head\0v3\0");
const MAX_JOURNAL_RECORDS: usize = 4096;
const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024 * 1024;
const MAX_PHASE_BYTES: usize = 64;
const MAX_SUBJECT_BYTES: usize = 256;
const MAX_RUN_ID_BYTES: usize = 128;

/// Compile-time contract for one authenticated journal namespace. A spec owns
/// every path, domain, wire-version, and resource bound that can otherwise be
/// confused across durable-state consumers.
pub(crate) trait JournalSpec: Send + Sync + 'static {
    const FORMAT_VERSION: u32;
    const NAMESPACE: &'static str;
    const ROOT_NAME: &'static str;
    const ROOT_LOCK_NAME: &'static str;
    const INSTANCE_LOCK_NAME: &'static str;
    const HEAD_FILE_NAME: &'static str;
    const RECORD_DOMAIN: AuthenticationDomain;
    const HEAD_DOMAIN: AuthenticationDomain;
    const MAX_RECORDS: usize;
    const MAX_RECORD_BYTES: u64;
    const MAX_TOTAL_BYTES: u64;
    const MAX_PHASE_BYTES: usize;
    const MAX_SUBJECT_BYTES: usize;
    const MAX_INSTANCE_ID_BYTES: usize;
}

pub(crate) enum CheckpointJournalSpec {}

impl JournalSpec for CheckpointJournalSpec {
    const FORMAT_VERSION: u32 = JOURNAL_FORMAT_VERSION;
    const NAMESPACE: &'static str = "orchestration_checkpoint";
    const ROOT_NAME: &'static str = JOURNAL_ROOT_NAME;
    const ROOT_LOCK_NAME: &'static str = JOURNAL_ROOT_LOCK;
    const INSTANCE_LOCK_NAME: &'static str = RUN_LOCK_NAME;
    const HEAD_FILE_NAME: &'static str = HEAD_FILE_NAME;
    const RECORD_DOMAIN: AuthenticationDomain = RECORD_DOMAIN;
    const HEAD_DOMAIN: AuthenticationDomain = HEAD_DOMAIN;
    const MAX_RECORDS: usize = MAX_JOURNAL_RECORDS;
    const MAX_RECORD_BYTES: u64 = MAX_RECORD_BYTES;
    const MAX_TOTAL_BYTES: u64 = MAX_JOURNAL_BYTES;
    const MAX_PHASE_BYTES: usize = MAX_PHASE_BYTES;
    const MAX_SUBJECT_BYTES: usize = MAX_SUBJECT_BYTES;
    const MAX_INSTANCE_ID_BYTES: usize = MAX_RUN_ID_BYTES;
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalIdentity {
    pub version: u32,
    pub repository: RepositoryAuthBinding,
    pub run_id: String,
    pub journal_id: String,
    pub run_directory_identity: FileIdentity,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct JournalRecord {
    pub version: u32,
    pub identity: JournalIdentity,
    pub sequence: u64,
    pub previous_mac: AuthenticationTag,
    pub phase: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    pub payload: Value,
    pub mac: AuthenticationTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalHead {
    version: u32,
    identity: JournalIdentity,
    sequence: u64,
    last_record_mac: AuthenticationTag,
    record_bytes: u64,
    mac: AuthenticationTag,
}

pub(crate) struct AuthenticatedStateJournal<S: JournalSpec> {
    authenticator: RepositoryAuthenticator,
    journal_root: SafeRoot,
    run_root: SafeRoot,
    run_lock: BoundStateLock,
    identity: JournalIdentity,
    records: Vec<JournalRecord>,
    record_bytes: u64,
    head_dirty: bool,
    spec: PhantomData<S>,
}

pub(crate) type StateJournal = AuthenticatedStateJournal<CheckpointJournalSpec>;

impl<S: JournalSpec> AuthenticatedStateJournal<S> {
    pub(crate) fn existing_root(authenticator: &RepositoryAuthenticator) -> Result<SafeRoot> {
        validate_spec::<S>()?;
        authenticator.verify_epoch()?;
        open_existing_journal_root::<S>(authenticator)
    }

    pub(crate) fn create_root(authenticator: &RepositoryAuthenticator) -> Result<SafeRoot> {
        validate_spec::<S>()?;
        authenticator.verify_epoch()?;
        open_or_create_journal_root::<S>(authenticator)
    }

    pub(crate) fn create(authenticator: RepositoryAuthenticator, run_id: &str) -> Result<Self> {
        validate_spec::<S>()?;
        validate_instance_id::<S>(run_id)?;
        authenticator.verify_epoch()?;
        let journal_root = open_or_create_journal_root::<S>(&authenticator)?;
        let root_lock = BoundStateLock::acquire(&journal_root, S::ROOT_LOCK_NAME)?;
        root_lock.verify(&journal_root)?;
        let reserved = journal_root
            .reserve_direct_child_directory(run_id)
            .with_context(|| {
                format!(
                    "checkpoint run id '{run_id}' already exists or could not be reserved; choose a new run id"
                )
            })?;
        reserved.verify(&journal_root)?;
        let run_root = SafeRoot::open_existing(reserved.path())?;
        let run_lock = BoundStateLock::try_acquire_exclusive(&run_root, S::INSTANCE_LOCK_NAME)
            .with_context(|| format!("{} instance is already active", S::NAMESPACE))?;
        let identity = JournalIdentity {
            version: S::FORMAT_VERSION,
            repository: authenticator.binding().clone(),
            run_id: run_id.to_string(),
            journal_id: random_identifier()?,
            run_directory_identity: run_root.identity().clone(),
        };
        root_lock.verify(&journal_root)?;
        let journal = Self {
            authenticator,
            journal_root,
            run_root,
            run_lock,
            identity,
            records: Vec::new(),
            record_bytes: 0,
            head_dirty: false,
            spec: PhantomData,
        };
        journal.verify_boundaries()?;
        Ok(journal)
    }

    /// Opens an existing deterministic instance or initializes its reserved
    /// directory when no durable journal effect exists yet.
    ///
    /// This closes the crash window between reserving an instance directory
    /// and publishing its first record. Recovery never removes or replaces a
    /// directory: an existing instance is initialized only while both locks
    /// are held and its bounded inventory proves that it has no record, head,
    /// or temporary publication residue.
    pub(crate) fn open_or_initialize(
        authenticator: RepositoryAuthenticator,
        run_id: &str,
    ) -> Result<Self> {
        validate_spec::<S>()?;
        validate_instance_id::<S>(run_id)?;
        authenticator.verify_epoch()?;
        let journal_root = open_or_create_journal_root::<S>(&authenticator)?;
        let root_lock = BoundStateLock::acquire(&journal_root, S::ROOT_LOCK_NAME)?;
        root_lock.verify(&journal_root)?;
        let existed = journal_root.direct_child_exists(run_id)?;
        let reserved = if existed {
            journal_root
                .bind_existing_direct_child_directory(run_id)
                .with_context(|| format!("{} instance is missing or unsafe", S::NAMESPACE))?
        } else {
            journal_root
                .reserve_direct_child_directory(run_id)
                .with_context(|| format!("failed to reserve {} instance", S::NAMESPACE))?
        };
        reserved.verify(&journal_root)?;
        let run_root = SafeRoot::open_existing(reserved.path())?;
        let run_lock = BoundStateLock::try_acquire_exclusive(&run_root, S::INSTANCE_LOCK_NAME)
            .with_context(|| format!("{} instance is active elsewhere", S::NAMESPACE))?;
        let inventory = inventory_run_directory::<S>(&run_root)?;
        let had_records = !inventory.records.is_empty();

        let mut journal = if !had_records {
            if inventory.head_exists
                || !inventory.record_temps.is_empty()
                || !inventory.head_temps.is_empty()
            {
                bail!(
                    "{} empty instance has publication residue and cannot be initialized",
                    S::NAMESPACE
                );
            }
            let identity = JournalIdentity {
                version: S::FORMAT_VERSION,
                repository: authenticator.binding().clone(),
                run_id: run_id.to_string(),
                journal_id: random_identifier()?,
                run_directory_identity: run_root.identity().clone(),
            };
            Self {
                authenticator,
                journal_root,
                run_root,
                run_lock,
                identity,
                records: Vec::new(),
                record_bytes: 0,
                head_dirty: false,
                spec: PhantomData,
            }
        } else {
            let first_name = inventory
                .records
                .get(&1)
                .context("authenticated journal has records but no first record")?;
            let bytes =
                BoundedRegularReader::read_direct(&run_root, first_name, S::MAX_RECORD_BYTES)?;
            let locator: JournalRecord = serde_json::from_slice(&bytes)
                .with_context(|| format!("{} first record locator is malformed", S::NAMESPACE))?;
            validate_identity::<S>(&locator.identity)?;
            authenticator.verify_repository_binding(&locator.identity.repository)?;
            if locator.sequence != 1
                || locator.identity.run_id != run_id
                || locator.identity.run_directory_identity != *run_root.identity()
            {
                bail!(
                    "{} first record locator has the wrong instance binding",
                    S::NAMESPACE
                );
            }
            Self {
                authenticator,
                journal_root,
                run_root,
                run_lock,
                identity: locator.identity,
                records: Vec::new(),
                record_bytes: 0,
                head_dirty: false,
                spec: PhantomData,
            }
        };
        if had_records {
            journal.load_and_recover()?;
        }
        root_lock.verify(&journal.journal_root)?;
        journal.verify_boundaries()?;
        Ok(journal)
    }

    pub(crate) fn open(
        authenticator: RepositoryAuthenticator,
        expected: &JournalIdentity,
    ) -> Result<Self> {
        validate_spec::<S>()?;
        validate_identity::<S>(expected)?;
        authenticator.verify_epoch()?;
        authenticator.verify_repository_binding(&expected.repository)?;
        let journal_root = open_existing_journal_root::<S>(&authenticator)?;
        let reserved = journal_root
            .bind_existing_direct_child_directory(&expected.run_id)
            .context("authenticated checkpoint run directory is missing or unsafe")?;
        let run_root = SafeRoot::open_existing(reserved.path())?;
        if run_root.identity() != &expected.run_directory_identity {
            bail!("authenticated checkpoint run directory identity changed");
        }
        let run_lock = BoundStateLock::try_acquire_exclusive(&run_root, S::INSTANCE_LOCK_NAME)
            .with_context(|| format!("{} instance is active elsewhere", S::NAMESPACE))?;
        let mut journal = Self {
            authenticator,
            journal_root,
            run_root,
            run_lock,
            identity: expected.clone(),
            records: Vec::new(),
            record_bytes: 0,
            head_dirty: false,
            spec: PhantomData,
        };
        journal.load_and_recover()?;
        journal.verify_boundaries()?;
        Ok(journal)
    }

    /// Opens an existing authenticated journal without creating locks,
    /// scavenging crash residue, repairing its head, or publishing state.
    /// Transitional journals are refused instead of recovered.
    pub(crate) fn open_existing_read_only(
        authenticator: RepositoryAuthenticator,
        expected: &JournalIdentity,
    ) -> Result<Self> {
        validate_spec::<S>()?;
        validate_identity::<S>(expected)?;
        authenticator.verify_epoch()?;
        authenticator.verify_repository_binding(&expected.repository)?;
        let journal_root = open_existing_journal_root::<S>(&authenticator)?;
        let reserved = journal_root
            .bind_existing_direct_child_directory(&expected.run_id)
            .context("authenticated checkpoint run directory is missing or unsafe")?;
        let run_root = SafeRoot::open_existing(reserved.path())?;
        if run_root.identity() != &expected.run_directory_identity {
            bail!("authenticated checkpoint run directory identity changed");
        }
        let run_lock =
            BoundStateLock::try_acquire_existing_exclusive(&run_root, S::INSTANCE_LOCK_NAME)
                .with_context(|| {
                    format!(
                        "{} instance is active, incomplete, or missing its stable lock",
                        S::NAMESPACE
                    )
                })?;
        let mut journal = Self {
            authenticator,
            journal_root,
            run_root,
            run_lock,
            identity: expected.clone(),
            records: Vec::new(),
            record_bytes: 0,
            head_dirty: false,
            spec: PhantomData,
        };
        journal.load_without_recovery()?;
        journal.verify_boundaries()?;
        Ok(journal)
    }

    /// Opens a stable instance when its authenticated identity is not stored by
    /// the caller. The first record is locator material only: its identity is
    /// structurally bounded, then the normal `open` path authenticates the
    /// complete chain before any payload becomes authoritative.
    pub(crate) fn open_instance(
        authenticator: RepositoryAuthenticator,
        instance_id: &str,
    ) -> Result<Self> {
        let identity = Self::locate_instance(&authenticator, instance_id)?;
        Self::open(authenticator, &identity)
    }

    /// Locates and authenticates an existing stable instance strictly through
    /// the read-only open path. This never initializes, scavenges, repairs, or
    /// publishes journal state.
    pub(crate) fn open_instance_read_only(
        authenticator: RepositoryAuthenticator,
        instance_id: &str,
    ) -> Result<Self> {
        let identity = Self::locate_instance(&authenticator, instance_id)?;
        Self::open_existing_read_only(authenticator, &identity)
    }

    fn locate_instance(
        authenticator: &RepositoryAuthenticator,
        instance_id: &str,
    ) -> Result<JournalIdentity> {
        validate_spec::<S>()?;
        validate_instance_id::<S>(instance_id)?;
        authenticator.verify_epoch()?;
        let journal_root = open_existing_journal_root::<S>(&authenticator)?;
        let reserved = journal_root
            .bind_existing_direct_child_directory(instance_id)
            .with_context(|| format!("{} instance is missing or unsafe", S::NAMESPACE))?;
        let run_root = SafeRoot::open_existing(reserved.path())?;
        let first_name = record_file_name(1);
        let bytes = BoundedRegularReader::read_direct(&run_root, &first_name, S::MAX_RECORD_BYTES)
            .with_context(|| format!("{} instance has no durable first record", S::NAMESPACE))?;
        let locator: JournalRecord = serde_json::from_slice(&bytes)
            .with_context(|| format!("{} first record locator is malformed", S::NAMESPACE))?;
        validate_identity::<S>(&locator.identity)?;
        if locator.sequence != 1
            || locator.identity.run_id != instance_id
            || locator.identity.run_directory_identity != *run_root.identity()
        {
            bail!(
                "{} first record locator has the wrong instance binding",
                S::NAMESPACE
            );
        }
        Ok(locator.identity)
    }

    pub(crate) fn identity(&self) -> &JournalIdentity {
        &self.identity
    }

    pub(crate) fn root(&self) -> &SafeRoot {
        &self.journal_root
    }

    pub(crate) fn authenticator(&self) -> &RepositoryAuthenticator {
        &self.authenticator
    }

    pub(crate) fn records(&self) -> &[JournalRecord] {
        &self.records
    }

    pub(crate) fn instance_id(&self) -> &str {
        &self.identity.run_id
    }

    pub(crate) fn append<T: Serialize>(
        &mut self,
        phase: &str,
        subject: Option<&str>,
        payload: &T,
    ) -> Result<&JournalRecord> {
        validate_phase::<S>(phase)?;
        if let Some(subject) = subject {
            validate_subject::<S>(subject)?;
        }
        if self.records.len() >= S::MAX_RECORDS {
            bail!("{} journal reached its bounded record count", S::NAMESPACE);
        }
        self.verify_boundaries()?;
        if self.head_dirty {
            self.publish_head().context(
                "checkpoint journal must rewrite a dirty head before appending another record",
            )?;
        }
        let sequence = u64::try_from(self.records.len())
            .context("checkpoint sequence overflowed")?
            .checked_add(1)
            .context("checkpoint sequence overflowed")?;
        let previous_mac = self
            .records
            .last()
            .map(|record| record.mac.clone())
            .unwrap_or_else(AuthenticationTag::zero);
        let payload = serde_json::to_value(payload).context("failed to encode journal payload")?;
        let mut record = JournalRecord {
            version: S::FORMAT_VERSION,
            identity: self.identity.clone(),
            sequence,
            previous_mac,
            phase: phase.to_string(),
            subject: subject.map(ToOwned::to_owned),
            payload,
            mac: AuthenticationTag::zero(),
        };
        record.mac = self
            .authenticator
            .sign(S::RECORD_DOMAIN, &record_mac_payload(&record)?)?;
        let mut encoded =
            serde_json::to_vec(&record).context("failed to serialize journal record")?;
        encoded.push(b'\n');
        validate_record_size::<S>(encoded.len(), self.record_bytes)?;
        let name = record_file_name(sequence);
        durable_publish_no_replace::<S>(&self.run_root, &name, sequence, &encoded, || {
            self.verify_boundaries()
        })?;
        let encoded_len = u64::try_from(encoded.len()).context("record length overflowed")?;
        self.record_bytes = self
            .record_bytes
            .checked_add(encoded_len)
            .context("journal byte total overflowed")?;
        self.records.push(record);
        self.publish_head()?;
        self.verify_boundaries()?;
        self.records
            .last()
            .context("journal append lost its record")
    }

    pub(crate) fn into_authenticator(self) -> Result<RepositoryAuthenticator> {
        self.verify_boundaries()?;
        Ok(self.authenticator)
    }

    fn load_and_recover(&mut self) -> Result<()> {
        self.verify_boundaries()?;
        let inventory = inventory_run_directory::<S>(&self.run_root)?;
        let mut records = Vec::with_capacity(inventory.records.len());
        let mut total = 0_u64;
        let mut previous = AuthenticationTag::zero();
        for (expected_index, (sequence, name)) in inventory.records.iter().enumerate() {
            let expected_sequence = u64::try_from(expected_index)
                .context("checkpoint sequence overflowed")?
                .checked_add(1)
                .context("checkpoint sequence overflowed")?;
            if *sequence != expected_sequence {
                bail!("checkpoint journal has a missing, reordered, or duplicate sequence");
            }
            let bytes =
                BoundedRegularReader::read_direct(&self.run_root, name, S::MAX_RECORD_BYTES)?;
            total = total
                .checked_add(u64::try_from(bytes.len()).context("record length overflowed")?)
                .context("journal byte total overflowed")?;
            if total > S::MAX_TOTAL_BYTES {
                bail!("{} journal exceeds its aggregate byte bound", S::NAMESPACE);
            }
            let record: JournalRecord = serde_json::from_slice(&bytes)
                .context("checkpoint journal contains a truncated or malformed record")?;
            validate_record::<S>(&record, &self.identity, expected_sequence, &previous)?;
            self.authenticator.verify_tag(
                S::RECORD_DOMAIN,
                &record_mac_payload(&record)?,
                &record.mac,
            )?;
            previous = record.mac.clone();
            records.push(record);
        }
        if records.len() > S::MAX_RECORDS {
            bail!("{} journal exceeds its record-count bound", S::NAMESPACE);
        }
        self.records = records;
        self.record_bytes = total;
        self.recover_temporary_files(&inventory)?;
        self.verify_or_recover_head(inventory.head_exists)?;
        Ok(())
    }

    fn load_without_recovery(&mut self) -> Result<()> {
        self.verify_boundaries()?;
        let inventory = inventory_run_directory::<S>(&self.run_root)?;
        if !inventory.record_temps.is_empty() || !inventory.head_temps.is_empty() {
            bail!("authenticated journal has crash residue requiring recovery");
        }
        let mut records = Vec::with_capacity(inventory.records.len());
        let mut total = 0_u64;
        let mut previous = AuthenticationTag::zero();
        for (expected_index, (sequence, name)) in inventory.records.iter().enumerate() {
            let expected_sequence = u64::try_from(expected_index)
                .context("checkpoint sequence overflowed")?
                .checked_add(1)
                .context("checkpoint sequence overflowed")?;
            if *sequence != expected_sequence {
                bail!("checkpoint journal has a missing, reordered, or duplicate sequence");
            }
            let bytes =
                BoundedRegularReader::read_direct(&self.run_root, name, S::MAX_RECORD_BYTES)?;
            total = total
                .checked_add(u64::try_from(bytes.len()).context("record length overflowed")?)
                .context("journal byte total overflowed")?;
            if total > S::MAX_TOTAL_BYTES {
                bail!("{} journal exceeds its aggregate byte bound", S::NAMESPACE);
            }
            let record: JournalRecord = serde_json::from_slice(&bytes)
                .context("checkpoint journal contains a truncated or malformed record")?;
            validate_record::<S>(&record, &self.identity, expected_sequence, &previous)?;
            self.authenticator.verify_tag(
                S::RECORD_DOMAIN,
                &record_mac_payload(&record)?,
                &record.mac,
            )?;
            previous = record.mac.clone();
            records.push(record);
        }
        if records.len() > S::MAX_RECORDS {
            bail!("{} journal exceeds its record-count bound", S::NAMESPACE);
        }
        self.records = records;
        self.record_bytes = total;
        self.verify_head_exact(inventory.head_exists)
    }

    fn verify_head_exact(&self, head_exists: bool) -> Result<()> {
        if !head_exists {
            bail!("authenticated journal head is missing; recovery is required");
        }
        let last_sequence =
            u64::try_from(self.records.len()).context("checkpoint count overflowed")?;
        let last_mac = self
            .records
            .last()
            .map(|record| record.mac.clone())
            .context("authenticated journal has a head but no durable record")?;
        let bytes = BoundedRegularReader::read_direct(
            &self.run_root,
            S::HEAD_FILE_NAME,
            S::MAX_RECORD_BYTES,
        )?;
        let head: JournalHead = serde_json::from_slice(&bytes)
            .context("checkpoint journal head is truncated or malformed")?;
        validate_head::<S>(&head, &self.identity)?;
        self.authenticator
            .verify_tag(S::HEAD_DOMAIN, &head_mac_payload(&head)?, &head.mac)?;
        if head.sequence != last_sequence
            || head.last_record_mac != last_mac
            || head.record_bytes != self.record_bytes
        {
            bail!("authenticated journal head does not exactly match its published tail; recovery is required");
        }
        Ok(())
    }

    fn recover_temporary_files(&self, inventory: &RunInventory) -> Result<()> {
        if inventory.head_temps.len() > 1 || inventory.record_temps.len() > 1 {
            bail!("checkpoint journal has ambiguous crash residue");
        }
        if let Some(name) = inventory.head_temps.first() {
            remove_bound_temp::<S>(&self.run_root, name)?;
        }
        if let Some((sequence, name)) = inventory.record_temps.first() {
            let last = u64::try_from(self.records.len()).context("checkpoint count overflowed")?;
            if *sequence == last {
                let final_name = record_file_name(*sequence);
                remove_published_hardlink_residue::<S>(&self.run_root, name, &final_name)?;
            } else if *sequence == last.saturating_add(1) {
                remove_bound_temp::<S>(&self.run_root, name)?;
            } else {
                bail!("checkpoint journal temp does not belong to the final unpublished tail");
            }
        }
        sync_parent_directory(self.run_root.path())?;
        Ok(())
    }

    fn verify_or_recover_head(&self, head_exists: bool) -> Result<()> {
        let last_sequence =
            u64::try_from(self.records.len()).context("checkpoint count overflowed")?;
        let last_mac = self
            .records
            .last()
            .map(|record| record.mac.clone())
            .unwrap_or_else(AuthenticationTag::zero);
        if !head_exists {
            if last_sequence != 1 {
                bail!("checkpoint journal head is missing outside the recoverable first append");
            }
            return self.write_head();
        }
        let bytes = BoundedRegularReader::read_direct(
            &self.run_root,
            S::HEAD_FILE_NAME,
            S::MAX_RECORD_BYTES,
        )?;
        let head: JournalHead = serde_json::from_slice(&bytes)
            .context("checkpoint journal head is truncated or malformed")?;
        validate_head::<S>(&head, &self.identity)?;
        self.authenticator
            .verify_tag(S::HEAD_DOMAIN, &head_mac_payload(&head)?, &head.mac)?;
        if head.sequence > last_sequence {
            bail!("checkpoint journal published tail was truncated");
        }
        if head.sequence == last_sequence {
            if head.last_record_mac != last_mac || head.record_bytes != self.record_bytes {
                bail!("checkpoint journal head does not match its published tail");
            }
            return Ok(());
        }
        if head.sequence.saturating_add(1) != last_sequence {
            bail!("checkpoint journal head rollback exceeds the single crash window");
        }
        let indexed = usize::try_from(head.sequence).context("head sequence overflowed")?;
        let expected_old_mac = if indexed == 0 {
            AuthenticationTag::zero()
        } else {
            self.records[indexed - 1].mac.clone()
        };
        if head.last_record_mac != expected_old_mac || head.record_bytes >= self.record_bytes {
            bail!("checkpoint journal head rollback evidence is inconsistent");
        }
        self.write_head()
    }

    fn publish_head(&mut self) -> Result<()> {
        match self.write_head() {
            Ok(()) => {
                self.head_dirty = false;
                Ok(())
            }
            Err(error) => {
                self.head_dirty = true;
                Err(error)
            }
        }
    }

    fn write_head(&self) -> Result<()> {
        if self.records.is_empty() {
            bail!("checkpoint journal cannot publish an empty head");
        }
        self.verify_boundaries()?;
        let mut head = JournalHead {
            version: S::FORMAT_VERSION,
            identity: self.identity.clone(),
            sequence: u64::try_from(self.records.len()).context("checkpoint count overflowed")?,
            last_record_mac: self
                .records
                .last()
                .map(|record| record.mac.clone())
                .context("checkpoint head lost its record")?,
            record_bytes: self.record_bytes,
            mac: AuthenticationTag::zero(),
        };
        head.mac = self
            .authenticator
            .sign(S::HEAD_DOMAIN, &head_mac_payload(&head)?)?;
        let mut encoded = serde_json::to_vec(&head).context("failed to serialize journal head")?;
        encoded.push(b'\n');
        if u64::try_from(encoded.len()).unwrap_or(u64::MAX) > S::MAX_RECORD_BYTES {
            bail!("{} journal head exceeds its byte bound", S::NAMESPACE);
        }
        #[cfg(test)]
        if take_journal_head_write_fault() {
            bail!("injected checkpoint journal head write failure");
        }
        durable_replace::<S>(&self.run_root, S::HEAD_FILE_NAME, &encoded, || {
            self.verify_boundaries()
        })?;
        self.verify_boundaries()
    }

    fn verify_boundaries(&self) -> Result<()> {
        self.authenticator.verify_epoch()?;
        self.authenticator
            .verify_repository_binding(&self.identity.repository)?;
        self.journal_root.verify()?;
        self.run_root.verify()?;
        if self.run_root.identity() != &self.identity.run_directory_identity {
            bail!("checkpoint run directory identity changed");
        }
        self.run_lock.verify(&self.run_root)
    }
}

struct RunInventory {
    records: BTreeMap<u64, OsString>,
    record_temps: Vec<(u64, OsString)>,
    head_temps: Vec<OsString>,
    head_exists: bool,
}

fn open_or_create_journal_root<S: JournalSpec>(
    authenticator: &RepositoryAuthenticator,
) -> Result<SafeRoot> {
    authenticator.verify()?;
    let state_root = authenticator.state_root();
    let root_lock = BoundStateLock::acquire(state_root, S::ROOT_LOCK_NAME)?;
    root_lock.verify(state_root)?;
    let path = state_root.path().join(S::ROOT_NAME);
    let root = SafeRoot::open_or_create(&path)
        .context("failed to open owner-private checkpoint journal root")?;
    root_lock.verify(state_root)?;
    root.verify()?;
    Ok(root)
}

fn open_existing_journal_root<S: JournalSpec>(
    authenticator: &RepositoryAuthenticator,
) -> Result<SafeRoot> {
    authenticator.verify()?;
    let path = authenticator.state_root().path().join(S::ROOT_NAME);
    let root = SafeRoot::open_existing(&path)
        .context("authenticated checkpoint journal root is missing or unsafe")?;
    root.verify()?;
    Ok(root)
}

fn inventory_run_directory<S: JournalSpec>(root: &SafeRoot) -> Result<RunInventory> {
    root.verify()?;
    let mut inventory = RunInventory {
        records: BTreeMap::new(),
        record_temps: Vec::new(),
        head_temps: Vec::new(),
        head_exists: false,
    };
    let mut entries = 0_usize;
    for entry in fs::read_dir(root.path()).context("failed to enumerate checkpoint journal")? {
        entries = entries
            .checked_add(1)
            .context("journal entry count overflowed")?;
        if entries > S::MAX_RECORDS.saturating_add(8) {
            bail!("{} journal directory exceeds its entry bound", S::NAMESPACE);
        }
        let entry = entry.context("failed to inspect checkpoint journal entry")?;
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            bail!("checkpoint journal entry name is not UTF-8");
        };
        if text == S::INSTANCE_LOCK_NAME {
            continue;
        }
        if text == S::HEAD_FILE_NAME {
            if inventory.head_exists {
                bail!("checkpoint journal has a duplicate head");
            }
            inventory.head_exists = true;
            validate_private_state_file::<S>(&entry.path(), false)?;
            continue;
        }
        if is_head_temp_name(text) {
            validate_private_state_file::<S>(&entry.path(), false)?;
            inventory.head_temps.push(name);
            continue;
        }
        if let Some(sequence) = parse_record_temp_name(text) {
            validate_private_state_file::<S>(&entry.path(), true)?;
            inventory.record_temps.push((sequence, name));
            continue;
        }
        let sequence = parse_record_file_name(text)
            .with_context(|| format!("unknown checkpoint journal entry '{text}'"))?;
        validate_private_state_file::<S>(&entry.path(), true)?;
        if inventory.records.insert(sequence, name).is_some() {
            bail!("checkpoint journal has a duplicate sequence");
        }
    }
    validate_published_record_linkage(root, &inventory)?;
    root.verify()?;
    Ok(inventory)
}

#[cfg(unix)]
fn validate_published_record_linkage(root: &SafeRoot, inventory: &RunInventory) -> Result<()> {
    let last_sequence = inventory.records.keys().next_back().copied();
    for (sequence, name) in &inventory.records {
        let final_path = root.direct_child(name)?;
        let metadata = fs::symlink_metadata(&final_path)?;
        match metadata.nlink() {
            1 => {}
            2 => {
                if Some(*sequence) != last_sequence {
                    bail!("non-final published checkpoint record has an extra hard link");
                }
                let matching = inventory
                    .record_temps
                    .iter()
                    .filter(|(temp_sequence, _)| temp_sequence == sequence)
                    .collect::<Vec<_>>();
                if matching.len() != 1 {
                    bail!("published checkpoint record has an unbound extra hard link");
                }
                let temp_path = root.direct_child(&matching[0].1)?;
                let temp_metadata = fs::symlink_metadata(&temp_path)?;
                if temp_metadata.nlink() != 2
                    || temp_metadata.dev() != metadata.dev()
                    || temp_metadata.ino() != metadata.ino()
                {
                    bail!("published checkpoint record hard link is not its crash temp");
                }
            }
            _ => bail!("published checkpoint record has an unsafe hard-link count"),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn validate_published_record_linkage(_root: &SafeRoot, _inventory: &RunInventory) -> Result<()> {
    Ok(())
}

fn record_mac_payload(record: &JournalRecord) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        record.version,
        &record.identity,
        record.sequence,
        &record.previous_mac,
        &record.phase,
        &record.subject,
        &record.payload,
    ))
    .context("failed to encode checkpoint record MAC payload")
}

fn head_mac_payload(head: &JournalHead) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        head.version,
        &head.identity,
        head.sequence,
        &head.last_record_mac,
        head.record_bytes,
    ))
    .context("failed to encode checkpoint head MAC payload")
}

fn validate_identity<S: JournalSpec>(identity: &JournalIdentity) -> Result<()> {
    validate_repository_binding(&identity.repository)?;
    if identity.version != S::FORMAT_VERSION
        || identity.run_directory_identity.file == 0
        || identity.journal_id.len() != 64
        || !identity
            .journal_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("checkpoint journal identity is malformed or unsupported");
    }
    validate_instance_id::<S>(&identity.run_id)
}

fn validate_spec<S: JournalSpec>() -> Result<()> {
    let canonical_identifier = |value: &str| {
        !value.is_empty()
            && value.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
            })
    };
    let safe_component = |value: &str| {
        !value.is_empty()
            && !matches!(value, "." | "..")
            && !value
                .chars()
                .any(|character| matches!(character, '/' | '\\' | '\0'))
    };
    if S::FORMAT_VERSION == 0
        || !canonical_identifier(S::NAMESPACE)
        || !safe_component(S::ROOT_NAME)
        || !safe_component(S::ROOT_LOCK_NAME)
        || !safe_component(S::INSTANCE_LOCK_NAME)
        || !safe_component(S::HEAD_FILE_NAME)
        || S::ROOT_LOCK_NAME == S::INSTANCE_LOCK_NAME
        || S::INSTANCE_LOCK_NAME == S::HEAD_FILE_NAME
        || S::MAX_RECORDS == 0
        || S::MAX_RECORD_BYTES == 0
        || S::MAX_TOTAL_BYTES < S::MAX_RECORD_BYTES
        || S::MAX_PHASE_BYTES == 0
        || S::MAX_SUBJECT_BYTES == 0
        || S::MAX_INSTANCE_ID_BYTES == 0
    {
        bail!("authenticated journal spec is malformed or internally inconsistent");
    }
    Ok(())
}

pub(crate) fn validate_journal_identity(identity: &JournalIdentity) -> Result<()> {
    validate_identity::<CheckpointJournalSpec>(identity)
}

fn validate_record<S: JournalSpec>(
    record: &JournalRecord,
    identity: &JournalIdentity,
    sequence: u64,
    previous: &AuthenticationTag,
) -> Result<()> {
    if record.version != S::FORMAT_VERSION
        || &record.identity != identity
        || record.sequence != sequence
        || &record.previous_mac != previous
    {
        bail!("checkpoint journal record chain or identity is invalid");
    }
    validate_phase::<S>(&record.phase)?;
    if let Some(subject) = &record.subject {
        validate_subject::<S>(subject)?;
    }
    Ok(())
}

fn validate_head<S: JournalSpec>(head: &JournalHead, identity: &JournalIdentity) -> Result<()> {
    if head.version != S::FORMAT_VERSION
        || &head.identity != identity
        || head.sequence == 0
        || head.record_bytes > S::MAX_TOTAL_BYTES
    {
        bail!("checkpoint journal head is malformed or bound to another run");
    }
    Ok(())
}

fn validate_instance_id<S: JournalSpec>(run_id: &str) -> Result<()> {
    if run_id.is_empty()
        || run_id.len() > S::MAX_INSTANCE_ID_BYTES
        || matches!(run_id, "." | "..")
        || !run_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("checkpoint run id is not a bounded safe path component");
    }
    Ok(())
}

fn validate_phase<S: JournalSpec>(phase: &str) -> Result<()> {
    if phase.is_empty()
        || phase.len() > S::MAX_PHASE_BYTES
        || !phase
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
    {
        bail!("checkpoint phase is not a bounded canonical identifier");
    }
    Ok(())
}

fn validate_subject<S: JournalSpec>(subject: &str) -> Result<()> {
    if subject.is_empty()
        || subject.len() > S::MAX_SUBJECT_BYTES
        || !subject
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'/'))
    {
        bail!("checkpoint subject is not a bounded canonical identifier");
    }
    Ok(())
}

fn validate_record_size<S: JournalSpec>(encoded: usize, current_total: u64) -> Result<()> {
    let encoded = u64::try_from(encoded).context("checkpoint record length overflowed")?;
    if encoded == 0 || encoded > S::MAX_RECORD_BYTES {
        bail!("checkpoint record exceeds its byte bound");
    }
    if current_total
        .checked_add(encoded)
        .context("checkpoint journal byte total overflowed")?
        > S::MAX_TOTAL_BYTES
    {
        bail!("checkpoint journal exceeds its aggregate byte bound");
    }
    Ok(())
}

fn record_file_name(sequence: u64) -> OsString {
    OsString::from(format!("{sequence:020}.json"))
}

fn parse_record_file_name(name: &str) -> Result<u64> {
    let digits = name
        .strip_suffix(".json")
        .context("entry is not a canonical checkpoint record")?;
    if digits.len() != 20 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("entry is not a canonical checkpoint record");
    }
    let sequence = digits
        .parse::<u64>()
        .context("checkpoint sequence overflowed")?;
    if record_file_name(sequence).to_string_lossy() != name {
        bail!("checkpoint record filename is not canonical");
    }
    Ok(sequence)
}

fn record_temp_name(sequence: u64, nonce: &str) -> OsString {
    OsString::from(format!(".record-{sequence:020}-{nonce}.tmp"))
}

fn parse_record_temp_name(name: &str) -> Option<u64> {
    let body = name.strip_prefix(".record-")?.strip_suffix(".tmp")?;
    let (digits, nonce) = body.split_once('-')?;
    if digits.len() != 20
        || nonce.len() != 64
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return None;
    }
    digits.parse().ok()
}

fn head_temp_name(nonce: &str) -> OsString {
    OsString::from(format!(".head-{nonce}.tmp"))
}

fn is_head_temp_name(name: &str) -> bool {
    name.strip_prefix(".head-")
        .and_then(|value| value.strip_suffix(".tmp"))
        .is_some_and(|nonce| {
            nonce.len() == 64
                && nonce
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

fn durable_publish_no_replace<S: JournalSpec>(
    root: &SafeRoot,
    final_name: &std::ffi::OsStr,
    sequence: u64,
    contents: &[u8],
    mut fence: impl FnMut() -> Result<()>,
) -> Result<()> {
    root.verify()?;
    root.ensure_direct_child_absent(final_name)?;
    let nonce = random_identifier()?;
    let temp_name = record_temp_name(sequence, &nonce);
    let temp_path = root.direct_child(&temp_name)?;
    let final_path = root.direct_child(final_name)?;
    let mut file = open_new_private_file(&temp_path)?;
    file.write_all(contents)
        .context("failed to write checkpoint record temp")?;
    file.sync_all()
        .context("failed to persist checkpoint record temp")?;
    drop(file);
    fence()?;
    publish_no_replace(&temp_path, &final_path)?;
    sync_parent_directory(root.path())?;
    cleanup_published_temp_if_linked(&temp_path, &final_path)?;
    sync_parent_directory(root.path())?;
    fence()?;
    validate_private_state_file::<S>(&final_path, false)?;
    Ok(())
}

fn durable_replace<S: JournalSpec>(
    root: &SafeRoot,
    final_name: &str,
    contents: &[u8],
    mut fence: impl FnMut() -> Result<()>,
) -> Result<()> {
    root.verify()?;
    let nonce = random_identifier()?;
    let temp_name = head_temp_name(&nonce);
    let temp_path = root.direct_child(&temp_name)?;
    let final_path = root.direct_child(final_name)?;
    let mut file = open_new_private_file(&temp_path)?;
    file.write_all(contents)
        .context("failed to write checkpoint head temp")?;
    file.sync_all()
        .context("failed to persist checkpoint head temp")?;
    drop(file);
    fence()?;
    replace_atomic(&temp_path, &final_path)?;
    sync_parent_directory(root.path())?;
    fence()?;
    validate_private_state_file::<S>(&final_path, false)?;
    Ok(())
}

fn open_new_private_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    options.open(path).with_context(|| {
        format!(
            "failed to create private checkpoint temp {}",
            path.display()
        )
    })
}

#[cfg(unix)]
fn publish_no_replace(temp: &Path, final_path: &Path) -> Result<()> {
    fs::hard_link(temp, final_path).with_context(|| {
        format!(
            "failed to publish checkpoint record without replacement: {}",
            final_path.display()
        )
    })
}

#[cfg(target_os = "windows")]
fn publish_no_replace(temp: &Path, final_path: &Path) -> Result<()> {
    move_file_ex(temp, final_path, false)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn publish_no_replace(_temp: &Path, _final_path: &Path) -> Result<()> {
    bail!("durable no-replace checkpoint publication is unsupported on this platform")
}

#[cfg(unix)]
fn replace_atomic(temp: &Path, final_path: &Path) -> Result<()> {
    fs::rename(temp, final_path)
        .with_context(|| format!("failed to replace checkpoint head {}", final_path.display()))
}

#[cfg(target_os = "windows")]
fn replace_atomic(temp: &Path, final_path: &Path) -> Result<()> {
    move_file_ex(temp, final_path, true)
}

#[cfg(not(any(unix, target_os = "windows")))]
fn replace_atomic(_temp: &Path, _final_path: &Path) -> Result<()> {
    bail!("durable checkpoint head replacement is unsupported on this platform")
}

#[cfg(target_os = "windows")]
fn move_file_ex(temp: &Path, final_path: &Path, replace: bool) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const MOVEFILE_REPLACE_EXISTING: u32 = 0x0000_0001;
    const MOVEFILE_WRITE_THROUGH: u32 = 0x0000_0008;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn MoveFileExW(existing: *const u16, new: *const u16, flags: u32) -> i32;
    }
    let existing = temp
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let new = final_path
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let mut flags = MOVEFILE_WRITE_THROUGH;
    if replace {
        flags |= MOVEFILE_REPLACE_EXISTING;
    }
    let moved = unsafe { MoveFileExW(existing.as_ptr(), new.as_ptr(), flags) };
    if moved == 0 {
        return Err(std::io::Error::last_os_error()).with_context(|| {
            format!("failed durable checkpoint move to {}", final_path.display())
        });
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent_directory(directory: &Path) -> Result<()> {
    File::open(directory)
        .with_context(|| {
            format!(
                "failed to open checkpoint directory {}",
                directory.display()
            )
        })?
        .sync_all()
        .with_context(|| {
            format!(
                "failed to persist checkpoint directory {}",
                directory.display()
            )
        })
}

#[cfg(target_os = "windows")]
fn sync_parent_directory(directory: &Path) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    const GENERIC_READ: u32 = 0x8000_0000;
    const FILE_SHARE_READ: u32 = 0x0000_0001;
    const FILE_SHARE_WRITE: u32 = 0x0000_0002;
    const FILE_SHARE_DELETE: u32 = 0x0000_0004;
    const OPEN_EXISTING: u32 = 3;
    const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
    const INVALID_HANDLE_VALUE: *mut core::ffi::c_void = -1_isize as *mut core::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn CreateFileW(
            name: *const u16,
            access: u32,
            share: u32,
            security: *mut core::ffi::c_void,
            creation: u32,
            flags: u32,
            template: *mut core::ffi::c_void,
        ) -> *mut core::ffi::c_void;
        fn FlushFileBuffers(handle: *mut core::ffi::c_void) -> i32;
        fn CloseHandle(handle: *mut core::ffi::c_void) -> i32;
    }
    let name = directory
        .as_os_str()
        .encode_wide()
        .chain(Some(0))
        .collect::<Vec<_>>();
    let handle = unsafe {
        CreateFileW(
            name.as_ptr(),
            GENERIC_READ,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            std::ptr::null_mut(),
        )
    };
    if handle == INVALID_HANDLE_VALUE {
        return Err(std::io::Error::last_os_error()).context("failed to open checkpoint directory");
    }
    let flushed = unsafe { FlushFileBuffers(handle) };
    let flush_error = (flushed == 0).then(std::io::Error::last_os_error);
    unsafe {
        CloseHandle(handle);
    }
    if let Some(error) = flush_error {
        return Err(error).context("failed to persist checkpoint directory");
    }
    Ok(())
}

#[cfg(not(any(unix, target_os = "windows")))]
fn sync_parent_directory(_directory: &Path) -> Result<()> {
    bail!("checkpoint directory persistence is unsupported on this platform")
}

#[cfg(unix)]
fn cleanup_published_temp_if_linked(temp: &Path, final_path: &Path) -> Result<()> {
    let temp_identity = identity_for_path(temp)?;
    let final_identity = identity_for_path(final_path)?;
    if temp_identity != final_identity {
        bail!("published checkpoint record and temp do not share an inode");
    }
    fs::remove_file(temp).context("failed to remove linked checkpoint record temp")
}

#[cfg(not(unix))]
fn cleanup_published_temp_if_linked(temp: &Path, _final_path: &Path) -> Result<()> {
    if temp.exists() {
        bail!("checkpoint temp survived an atomic move unexpectedly");
    }
    Ok(())
}

fn remove_bound_temp<S: JournalSpec>(root: &SafeRoot, name: &std::ffi::OsStr) -> Result<()> {
    let path = root.direct_child(name)?;
    let before = validate_private_state_file::<S>(&path, false)?;
    let after = validate_private_state_file::<S>(&path, false)?;
    if before != after {
        bail!("checkpoint temp identity changed before recovery cleanup");
    }
    fs::remove_file(&path)
        .with_context(|| format!("failed to remove checkpoint temp {}", path.display()))?;
    root.verify()
}

fn remove_published_hardlink_residue<S: JournalSpec>(
    root: &SafeRoot,
    temp_name: &std::ffi::OsStr,
    final_name: &std::ffi::OsStr,
) -> Result<()> {
    let temp = root.direct_child(temp_name)?;
    let final_path = root.direct_child(final_name)?;
    #[cfg(unix)]
    {
        let temp_metadata = fs::symlink_metadata(&temp)?;
        let final_metadata = fs::symlink_metadata(&final_path)?;
        if temp_metadata.dev() != final_metadata.dev()
            || temp_metadata.ino() != final_metadata.ino()
            || temp_metadata.nlink() != 2
            || final_metadata.nlink() != 2
        {
            bail!("checkpoint hard-link crash residue is not bound to its published record");
        }
        fs::remove_file(&temp).context("failed to remove checkpoint hard-link crash residue")?;
        validate_private_state_file::<S>(&final_path, false)?;
        Ok(())
    }
    #[cfg(not(unix))]
    bail!("checkpoint published-temp residue is unsupported on this platform")
}

#[cfg(unix)]
fn validate_private_state_file<S: JournalSpec>(
    path: &Path,
    allow_two_links: bool,
) -> Result<FileIdentity> {
    let metadata = fs::symlink_metadata(path)
        .with_context(|| format!("failed to inspect checkpoint state {}", path.display()))?;
    let links_ok = metadata.nlink() == 1 || (allow_two_links && metadata.nlink() == 2);
    if metadata.file_type().is_symlink()
        || !metadata.file_type().is_file()
        || !links_ok
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > S::MAX_RECORD_BYTES
    {
        bail!("checkpoint state file is not a bounded private regular file");
    }
    identity_for_path(path)
}

#[cfg(not(unix))]
fn validate_private_state_file<S: JournalSpec>(
    path: &Path,
    _allow_two_links: bool,
) -> Result<FileIdentity> {
    bail!(
        "checkpoint state ACL validation is unsupported on this platform: {}",
        path.display()
    )
}

#[cfg(test)]
thread_local! {
    static JOURNAL_HEAD_WRITE_FAULT: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn set_journal_head_write_fault() {
    JOURNAL_HEAD_WRITE_FAULT.with(|slot| slot.set(true));
}

#[cfg(test)]
fn take_journal_head_write_fault() -> bool {
    JOURNAL_HEAD_WRITE_FAULT.with(|slot| slot.replace(false))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifacts::repository_auth_writer;
    use git2::Repository;
    use tempfile::TempDir;

    fn auth_repo() -> (TempDir, PathBuf, RepositoryAuthenticator) {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        Repository::init(&repo_path).expect("init repo");
        let auth = repository_auth_writer(&repo_path)
            .expect("create auth")
            .into_authenticator()
            .expect("release key writer");
        (temp, repo_path, auth)
    }

    fn journal_with_two_records() -> (TempDir, PathBuf, JournalIdentity) {
        let (temp, repo_path, auth) = auth_repo();
        let mut journal = StateJournal::create(auth, "run-a").expect("create journal");
        journal
            .append("planned", None, &serde_json::json!({"v": 1}))
            .expect("planned");
        journal
            .append(
                "command_started",
                Some("agent-a"),
                &serde_json::json!({"v": 2}),
            )
            .expect("started");
        let identity = journal.identity().clone();
        drop(journal);
        (temp, repo_path, identity)
    }

    fn reopen(repo_path: &Path, identity: &JournalIdentity) -> Result<StateJournal> {
        let repo = crate::git_repository::open(repo_path)?;
        let auth = RepositoryAuthenticator::open_existing(repo.commondir())?;
        StateJournal::open(auth, identity)
    }

    #[test]
    fn journal_round_trip_preserves_contiguous_authenticated_chain() {
        let (_temp, repo_path, identity) = journal_with_two_records();
        let journal = reopen(&repo_path, &identity).expect("reopen journal");
        assert_eq!(journal.records().len(), 2);
        assert_eq!(journal.records()[0].sequence, 1);
        assert_eq!(journal.records()[1].previous_mac, journal.records()[0].mac);
    }

    #[test]
    fn concurrent_open_is_excluded_for_full_journal_lifecycle() {
        let (_temp, repo_path, auth) = auth_repo();
        let mut journal = StateJournal::create(auth, "exclusive-run").expect("create journal");
        journal.append("planned", None, &()).expect("planned");
        let identity = journal.identity().clone();
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let competing_auth =
            RepositoryAuthenticator::open_existing(repo.commondir()).expect("auth");
        assert!(StateJournal::open(competing_auth, &identity).is_err());
        drop(journal);
        reopen(&repo_path, &identity).expect("lock released");
    }

    #[test]
    fn tampered_record_is_rejected() {
        let (_temp, repo_path, identity) = journal_with_two_records();
        let run = repo_path
            .join(".git/maco/state")
            .join(JOURNAL_ROOT_NAME)
            .join(&identity.run_id);
        fs::write(run.join(record_file_name(1)), b"{}\n").expect("tamper record");
        assert!(reopen(&repo_path, &identity).is_err());
    }

    #[test]
    fn truncated_published_tail_is_rejected_by_authenticated_head() {
        let (_temp, repo_path, identity) = journal_with_two_records();
        let run = repo_path
            .join(".git/maco/state")
            .join(JOURNAL_ROOT_NAME)
            .join(&identity.run_id);
        fs::remove_file(run.join(record_file_name(2))).expect("remove tail");
        let error = reopen(&repo_path, &identity)
            .err()
            .expect("tail truncation must fail");
        assert!(error.to_string().contains("truncated"));
    }

    #[test]
    fn reordered_record_contents_are_rejected() {
        let (_temp, repo_path, identity) = journal_with_two_records();
        let run = repo_path
            .join(".git/maco/state")
            .join(JOURNAL_ROOT_NAME)
            .join(&identity.run_id);
        let first = fs::read(run.join(record_file_name(1))).expect("first");
        let second = fs::read(run.join(record_file_name(2))).expect("second");
        fs::write(run.join(record_file_name(1)), second).expect("swap first");
        fs::write(run.join(record_file_name(2)), first).expect("swap second");
        assert!(reopen(&repo_path, &identity).is_err());
    }

    #[test]
    fn duplicate_or_unknown_sequence_entry_is_rejected() {
        let (_temp, repo_path, identity) = journal_with_two_records();
        let run = repo_path
            .join(".git/maco/state")
            .join(JOURNAL_ROOT_NAME)
            .join(&identity.run_id);
        fs::copy(
            run.join(record_file_name(2)),
            run.join("00000000000000000003.json"),
        )
        .expect("duplicate record");
        assert!(reopen(&repo_path, &identity).is_err());
    }

    #[test]
    fn wrong_repository_authenticator_is_rejected() {
        let (_temp, _repo_path, identity) = journal_with_two_records();
        let (_other_temp, _other_repo, other_auth) = auth_repo();
        let error = StateJournal::open(other_auth, &identity)
            .err()
            .expect("wrong repo");
        assert!(error.to_string().contains("different repository"));
    }

    #[test]
    fn final_unpublished_temp_is_removed_without_touching_records() {
        let (_temp, repo_path, identity) = journal_with_two_records();
        let run = repo_path
            .join(".git/maco/state")
            .join(JOURNAL_ROOT_NAME)
            .join(&identity.run_id);
        let temp_name = record_temp_name(3, &"a".repeat(64));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        options
            .open(run.join(&temp_name))
            .expect("create crash temp")
            .write_all(b"partial")
            .expect("write partial");
        let journal = reopen(&repo_path, &identity).expect("recover final temp");
        assert_eq!(journal.records().len(), 2);
        assert!(!run.join(temp_name).exists());
        assert!(run.join(record_file_name(2)).exists());
    }

    #[test]
    fn read_only_instance_open_refuses_crash_residue_without_recovery() {
        let (_temp, repo_path, identity) = journal_with_two_records();
        let run = repo_path
            .join(".git/maco/state")
            .join(JOURNAL_ROOT_NAME)
            .join(&identity.run_id);
        let temp_name = record_temp_name(3, &"a".repeat(64));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        options
            .open(run.join(&temp_name))
            .expect("create crash temp")
            .write_all(b"partial")
            .expect("write partial");
        let head_before = fs::read(run.join(HEAD_FILE_NAME)).expect("read stable head");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        let auth = RepositoryAuthenticator::open_existing(repo.commondir()).expect("auth");

        let error = StateJournal::open_instance_read_only(auth, &identity.run_id)
            .err()
            .expect("read-only open must refuse transitional journal state");

        assert!(error
            .to_string()
            .contains("crash residue requiring recovery"));
        assert!(run.join(temp_name).exists());
        assert_eq!(
            fs::read(run.join(HEAD_FILE_NAME)).expect("reread stable head"),
            head_before
        );
    }

    #[test]
    fn head_write_failure_then_retry_rewrites_dirty_head_instead_of_wedging() {
        let (_temp, repo_path, auth) = auth_repo();
        let mut journal = StateJournal::create(auth, "dirty-head").expect("create journal");
        journal
            .append("planned", None, &serde_json::json!({"v": 1}))
            .expect("first append");
        let identity = journal.identity().clone();

        set_journal_head_write_fault();
        let failed = journal
            .append(
                "command_started",
                Some("agent-a"),
                &serde_json::json!({"v": 2}),
            )
            .expect_err("injected head write failure");
        assert!(failed
            .to_string()
            .contains("injected checkpoint journal head write"));
        assert!(journal.head_dirty);
        assert_eq!(journal.records().len(), 2);

        journal
            .append(
                "command_finished",
                Some("agent-a"),
                &serde_json::json!({"v": 3}),
            )
            .expect("retry append after transient head failure");
        assert!(!journal.head_dirty);
        assert_eq!(journal.records().len(), 3);
        drop(journal);

        let reopened = reopen(&repo_path, &identity).expect("reopen after recovered dirty head");
        assert_eq!(reopened.records().len(), 3);
        assert_eq!(reopened.records()[2].phase, "command_finished");
    }
}
