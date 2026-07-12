//! Generic authenticated write-ahead journal for externally visible effects.
//!
//! Provider-specific reconciliation belongs to consumers. This module only
//! enforces the durable phase machine: an effect is planned before it starts,
//! a started effect must be observed before completion, and ambiguous started
//! effects are never silently converted back into a retryable plan.

// Provider integrations consume this crate-private foundation in follow-up
// changes; focused tests exercise the complete durable phase API now.
#![allow(dead_code)]

use crate::{
    artifacts::state_auth::{
        random_identifier, sha256_hex, AuthenticationDomain, AuthenticationTag, BoundStateLock,
        RepositoryAuthenticator,
    },
    safe_state::{AtomicStateWriter, BoundedRegularReader, SafeRoot},
    state_journal::{AuthenticatedStateJournal, JournalIdentity, JournalRecord, JournalSpec},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeMap, fs, fs::File};

pub(crate) const EFFECT_WAL_ROOT_NAME: &str = "authenticated-effect-wals-v1";

pub(crate) trait EffectWalSpec: JournalSpec {
    const EFFECT_FORMAT_VERSION: u32;
    const LOCATOR_DOMAIN: AuthenticationDomain;
}

pub(crate) enum DefaultEffectWalSpec {}

impl JournalSpec for DefaultEffectWalSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "effect_wal";
    const ROOT_NAME: &'static str = EFFECT_WAL_ROOT_NAME;
    const ROOT_LOCK_NAME: &'static str = ".effect-wals.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".effect-wal.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0effect-wal-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0effect-wal-head\0v1\0");
    const MAX_RECORDS: usize = 4096;
    const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 256;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

impl EffectWalSpec for DefaultEffectWalSpec {
    const EFFECT_FORMAT_VERSION: u32 = 1;
    const LOCATOR_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0effect-wal-locator\0v1\0");
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum EffectPhase {
    Planned,
    Started,
    Observed,
    Completed,
}

impl EffectPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Planned => "planned",
            Self::Started => "started",
            Self::Observed => "observed",
            Self::Completed => "completed",
        }
    }

    fn parse(value: &str) -> Result<Self> {
        match value {
            "planned" => Ok(Self::Planned),
            "started" => Ok(Self::Started),
            "observed" => Ok(Self::Observed),
            "completed" => Ok(Self::Completed),
            _ => bail!("effect WAL contains an unsupported phase"),
        }
    }

    fn follows(self, previous: Option<Self>) -> bool {
        matches!(
            (previous, self),
            (None, Self::Planned)
                | (Some(Self::Planned), Self::Started)
                | (Some(Self::Started), Self::Observed)
                | (Some(Self::Observed), Self::Completed)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EffectEvent {
    pub version: u32,
    pub sequence: u64,
    pub effect_id: String,
    pub phase: EffectPhase,
    pub data: Value,
}

#[derive(Serialize)]
struct EffectPayload<'a, T> {
    version: u32,
    data: &'a T,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EffectPayloadWire {
    version: u32,
    data: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectWalLocator {
    version: u32,
    logical_id: String,
    active_identity: JournalIdentity,
    sequence: u64,
    terminal_mac: AuthenticationTag,
    mac: AuthenticationTag,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectWalInitIntent {
    version: u32,
    logical_id: String,
    attempt: u32,
    physical_id: String,
    mac: AuthenticationTag,
}

pub(crate) struct EffectWal<S: EffectWalSpec = DefaultEffectWalSpec> {
    journal: AuthenticatedStateJournal<S>,
    store_root: SafeRoot,
    store_lock: BoundStateLock,
    logical_id: String,
    locator: EffectWalLocator,
    events: Vec<EffectEvent>,
    phases: BTreeMap<String, EffectPhase>,
}

impl<S: EffectWalSpec> EffectWal<S> {
    pub(crate) fn create_planned<T: Serialize>(
        authenticator: RepositoryAuthenticator,
        logical_id: &str,
        effect_id: &str,
        data: &T,
    ) -> Result<Self> {
        let (store_root, store_lock, intent) =
            begin_effect_initialization::<S>(&authenticator, logical_id)?;
        let mut journal =
            AuthenticatedStateJournal::<S>::create(authenticator, &intent.physical_id)?;
        if journal.root().identity() != store_root.identity() {
            bail!("effect WAL initialization changed its journal root identity");
        }
        if take_effect_fault(EffectWalFaultPoint::AfterPhysicalReservation) {
            bail!("injected effect WAL fault after physical journal reservation");
        }
        let payload = EffectPayload {
            version: S::EFFECT_FORMAT_VERSION,
            data,
        };
        let (event, terminal_mac) = {
            let record = journal.append("planned", Some(effect_id), &payload)?;
            (decode_event::<S>(record)?, record.mac.clone())
        };
        let mut locator = EffectWalLocator {
            version: S::EFFECT_FORMAT_VERSION,
            logical_id: logical_id.to_string(),
            active_identity: journal.identity().clone(),
            sequence: 1,
            terminal_mac,
            mac: AuthenticationTag::zero(),
        };
        if take_effect_fault(EffectWalFaultPoint::BeforeInitialLocator) {
            bail!("injected effect WAL fault before initial locator publication");
        }
        write_effect_locator::<S>(
            journal.authenticator(),
            &store_root,
            &store_lock,
            &mut locator,
        )?;
        if take_effect_fault(EffectWalFaultPoint::AfterInitialLocator) {
            bail!("injected effect WAL fault after initial locator publication");
        }
        remove_effect_init::<S>(journal.authenticator(), &store_root, &store_lock, &intent)?;
        let mut phases = BTreeMap::new();
        phases.insert(effect_id.to_string(), EffectPhase::Planned);
        Ok(Self {
            journal,
            store_root,
            store_lock,
            logical_id: logical_id.to_string(),
            locator,
            events: vec![event],
            phases,
        })
    }

    pub(crate) fn open_instance(
        authenticator: RepositoryAuthenticator,
        logical_id: &str,
    ) -> Result<Self> {
        let store_root = AuthenticatedStateJournal::<S>::existing_root(&authenticator)?;
        let root_lock = BoundStateLock::acquire(&store_root, S::ROOT_LOCK_NAME)?;
        if !store_root.direct_child_exists(effect_locator_name(logical_id))? {
            bail!("initialized effect WAL '{logical_id}' has no signed locator");
        }
        root_lock.verify(&store_root)?;
        drop(root_lock);
        let store_lock =
            BoundStateLock::try_acquire_exclusive(&store_root, &effect_store_lock_name(logical_id))
                .context("effect WAL is active elsewhere")?;
        let mut locator = read_effect_locator::<S>(&authenticator, &store_root, logical_id)?;
        recover_effect_init_after_locator::<S>(&authenticator, &store_root, &store_lock, &locator)?;
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
        locator: &mut EffectWalLocator,
    ) -> Result<Self> {
        let mut events = Vec::with_capacity(journal.records().len());
        let mut phases = BTreeMap::new();
        for record in journal.records() {
            let event = decode_event::<S>(record)?;
            let previous = phases.get(&event.effect_id).copied();
            if !event.phase.follows(previous) {
                bail!("effect WAL phase transition is invalid or ambiguous");
            }
            phases.insert(event.effect_id.clone(), event.phase);
            events.push(event);
        }
        let sequence = u64::try_from(events.len()).context("effect WAL sequence overflowed")?;
        let terminal_mac = journal
            .records()
            .last()
            .map(|record| record.mac.clone())
            .context("initialized effect WAL is empty")?;
        if sequence == locator.sequence {
            if terminal_mac != locator.terminal_mac {
                bail!("effect WAL locator does not match its journal tail");
            }
        } else if sequence == locator.sequence.saturating_add(1) {
            let anchor_index = usize::try_from(locator.sequence.saturating_sub(1))
                .context("effect WAL locator index overflowed")?;
            if journal
                .records()
                .get(anchor_index)
                .is_none_or(|record| record.mac != locator.terminal_mac)
            {
                bail!("effect WAL one-record locator recovery anchor is inconsistent");
            }
            locator.sequence = sequence;
            locator.terminal_mac = terminal_mac;
            write_effect_locator::<S>(journal.authenticator(), &store_root, &store_lock, locator)?;
        } else {
            bail!("effect WAL locator rollback exceeds the one-record crash window");
        }
        Ok(Self {
            journal,
            store_root,
            store_lock,
            logical_id,
            locator: locator.clone(),
            events,
            phases,
        })
    }

    pub(crate) fn identity(&self) -> &JournalIdentity {
        self.journal.identity()
    }

    pub(crate) fn logical_id(&self) -> &str {
        &self.logical_id
    }

    pub(crate) fn events(&self) -> &[EffectEvent] {
        &self.events
    }

    pub(crate) fn phase(&self, effect_id: &str) -> Option<EffectPhase> {
        self.phases.get(effect_id).copied()
    }

    pub(crate) fn planned<T: Serialize>(&mut self, effect_id: &str, data: &T) -> Result<()> {
        self.transition(effect_id, EffectPhase::Planned, data)
    }

    pub(crate) fn started<T: Serialize>(&mut self, effect_id: &str, data: &T) -> Result<()> {
        self.transition(effect_id, EffectPhase::Started, data)
    }

    pub(crate) fn observed<T: Serialize>(&mut self, effect_id: &str, data: &T) -> Result<()> {
        self.transition(effect_id, EffectPhase::Observed, data)
    }

    pub(crate) fn completed<T: Serialize>(&mut self, effect_id: &str, data: &T) -> Result<()> {
        self.transition(effect_id, EffectPhase::Completed, data)
    }

    fn transition<T: Serialize>(
        &mut self,
        effect_id: &str,
        phase: EffectPhase,
        data: &T,
    ) -> Result<()> {
        let previous = self.phases.get(effect_id).copied();
        if !phase.follows(previous) {
            bail!("effect WAL transition would skip, repeat, or retry an ambiguous phase");
        }
        let payload = EffectPayload {
            version: S::EFFECT_FORMAT_VERSION,
            data,
        };
        let record = self
            .journal
            .append(phase.as_str(), Some(effect_id), &payload)?;
        let event = decode_event::<S>(record)?;
        self.phases.insert(effect_id.to_string(), phase);
        self.events.push(event);
        self.locator.sequence = u64::try_from(self.events.len())?;
        self.locator.terminal_mac = self
            .journal
            .records()
            .last()
            .map(|record| record.mac.clone())
            .context("effect WAL transition lost its terminal MAC")?;
        write_effect_locator::<S>(
            self.journal.authenticator(),
            &self.store_root,
            &self.store_lock,
            &mut self.locator,
        )?;
        Ok(())
    }
}

fn effect_locator_name(logical_id: &str) -> String {
    format!(".effect-locator-{}.json", sha256_hex(logical_id.as_bytes()))
}

fn effect_init_name(logical_id: &str) -> String {
    format!(".effect-init-{}.json", sha256_hex(logical_id.as_bytes()))
}

fn effect_store_lock_name(logical_id: &str) -> String {
    format!(".effect-store-{}.lock", sha256_hex(logical_id.as_bytes()))
}

fn validate_effect_logical_id<S: EffectWalSpec>(logical_id: &str) -> Result<()> {
    if logical_id.is_empty()
        || logical_id.len() > S::MAX_INSTANCE_ID_BYTES
        || matches!(logical_id, "." | "..")
        || !logical_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        bail!("effect WAL logical id is not canonical or bounded");
    }
    Ok(())
}

fn begin_effect_initialization<S: EffectWalSpec>(
    authenticator: &RepositoryAuthenticator,
    logical_id: &str,
) -> Result<(SafeRoot, BoundStateLock, EffectWalInitIntent)> {
    validate_effect_logical_id::<S>(logical_id)?;
    let root = AuthenticatedStateJournal::<S>::create_root(authenticator)?;
    let root_lock = BoundStateLock::acquire(&root, S::ROOT_LOCK_NAME)?;
    if root.direct_child_exists(effect_locator_name(logical_id))? {
        bail!("effect WAL logical store is already initialized");
    }
    let init_name = effect_init_name(logical_id);
    let lock_name = effect_store_lock_name(logical_id);
    let init_exists = root.direct_child_exists(&init_name)?;
    let lock_exists = root.direct_child_exists(&lock_name)?;
    let (store_lock, mut intent) = if init_exists {
        let store_lock = BoundStateLock::try_acquire_exclusive(&root, &lock_name)
            .context("effect WAL initialization is active elsewhere")?;
        let mut intent = read_effect_init::<S>(authenticator, &root, logical_id)?;
        intent.attempt = intent
            .attempt
            .checked_add(1)
            .context("effect WAL initialization attempt overflowed")?;
        if intent.attempt > 8 {
            bail!("effect WAL initialization exceeded its bounded retry count");
        }
        intent.physical_id = random_identifier()?;
        (store_lock, intent)
    } else {
        if lock_exists {
            bail!("effect WAL locator is missing after initialization; refusing recreation");
        }
        let mut intent = EffectWalInitIntent {
            version: S::EFFECT_FORMAT_VERSION,
            logical_id: logical_id.to_string(),
            attempt: 1,
            physical_id: random_identifier()?,
            mac: AuthenticationTag::zero(),
        };
        write_effect_init::<S>(authenticator, &root, &root_lock, &mut intent)?;
        let store_lock = BoundStateLock::try_acquire_exclusive(&root, &lock_name)
            .context("effect WAL initialization lock could not be acquired")?;
        (store_lock, intent)
    };
    if init_exists {
        write_effect_init::<S>(authenticator, &root, &root_lock, &mut intent)?;
    }
    root_lock.verify(&root)?;
    store_lock.verify(&root)?;
    drop(root_lock);
    Ok((root, store_lock, intent))
}

fn effect_init_payload(intent: &EffectWalInitIntent) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        "effect_wal_initialization",
        intent.version,
        &intent.logical_id,
        intent.attempt,
        &intent.physical_id,
    ))
    .context("failed to encode effect WAL initialization intent")
}

fn validate_effect_init<S: EffectWalSpec>(
    intent: &EffectWalInitIntent,
    logical_id: &str,
) -> Result<()> {
    validate_effect_logical_id::<S>(logical_id)?;
    intent.mac.validate()?;
    if intent.version != S::EFFECT_FORMAT_VERSION
        || intent.logical_id != logical_id
        || intent.attempt == 0
        || intent.attempt > 8
        || intent.physical_id.len() != 64
        || !intent
            .physical_id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        bail!("effect WAL initialization intent is malformed");
    }
    Ok(())
}

fn read_effect_init<S: EffectWalSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    logical_id: &str,
) -> Result<EffectWalInitIntent> {
    let bytes =
        BoundedRegularReader::read_direct(root, effect_init_name(logical_id), S::MAX_RECORD_BYTES)?;
    let intent: EffectWalInitIntent =
        serde_json::from_slice(&bytes).context("effect WAL initialization intent is malformed")?;
    validate_effect_init::<S>(&intent, logical_id)?;
    authenticator.verify_tag(
        S::LOCATOR_DOMAIN,
        &effect_init_payload(&intent)?,
        &intent.mac,
    )?;
    Ok(intent)
}

fn write_effect_init<S: EffectWalSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    lock: &BoundStateLock,
    intent: &mut EffectWalInitIntent,
) -> Result<()> {
    validate_effect_init::<S>(intent, &intent.logical_id)?;
    intent.mac = authenticator.sign(S::LOCATOR_DOMAIN, &effect_init_payload(intent)?)?;
    let mut bytes = serde_json::to_vec(intent)?;
    bytes.push(b'\n');
    let name = effect_init_name(&intent.logical_id);
    AtomicStateWriter::scavenge_direct_temps(root, &name)?;
    AtomicStateWriter::write_direct_fenced(root, &name, &bytes, || lock.verify(root))
}

fn remove_effect_init<S: EffectWalSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    lock: &BoundStateLock,
    expected: &EffectWalInitIntent,
) -> Result<()> {
    let observed = read_effect_init::<S>(authenticator, root, &expected.logical_id)?;
    if &observed != expected {
        bail!("effect WAL initialization intent changed before cleanup");
    }
    lock.verify(root)?;
    fs::remove_file(root.direct_child(effect_init_name(&expected.logical_id))?)?;
    File::open(root.path())?.sync_all()?;
    lock.verify(root)
}

fn recover_effect_init_after_locator<S: EffectWalSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    store_lock: &BoundStateLock,
    locator: &EffectWalLocator,
) -> Result<()> {
    let name = effect_init_name(&locator.logical_id);
    if !root.direct_child_exists(&name)? {
        return Ok(());
    }
    let root_lock = BoundStateLock::acquire(root, S::ROOT_LOCK_NAME)?;
    let intent = read_effect_init::<S>(authenticator, root, &locator.logical_id)?;
    if intent.physical_id != locator.active_identity.run_id {
        bail!("effect WAL locator has a mismatched initialization intent");
    }
    remove_effect_init::<S>(authenticator, root, store_lock, &intent)?;
    root_lock.verify(root)
}

fn effect_locator_payload(locator: &EffectWalLocator) -> Result<Vec<u8>> {
    serde_json::to_vec(&(
        locator.version,
        &locator.logical_id,
        &locator.active_identity,
        locator.sequence,
        &locator.terminal_mac,
    ))
    .context("failed to encode effect WAL locator payload")
}

fn validate_effect_locator<S: EffectWalSpec>(
    locator: &EffectWalLocator,
    logical_id: &str,
) -> Result<()> {
    validate_effect_logical_id::<S>(logical_id)?;
    locator.mac.validate()?;
    locator.terminal_mac.validate()?;
    if locator.version != S::EFFECT_FORMAT_VERSION
        || locator.logical_id != logical_id
        || locator.sequence == 0
        || locator.sequence > u64::try_from(S::MAX_RECORDS).unwrap_or(u64::MAX)
    {
        bail!("effect WAL locator is malformed or unsupported");
    }
    Ok(())
}

fn read_effect_locator<S: EffectWalSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    logical_id: &str,
) -> Result<EffectWalLocator> {
    let bytes = BoundedRegularReader::read_direct(
        root,
        effect_locator_name(logical_id),
        S::MAX_RECORD_BYTES,
    )?;
    let locator: EffectWalLocator =
        serde_json::from_slice(&bytes).context("effect WAL locator is malformed")?;
    validate_effect_locator::<S>(&locator, logical_id)?;
    authenticator.verify_repository_binding(&locator.active_identity.repository)?;
    authenticator.verify_tag(
        S::LOCATOR_DOMAIN,
        &effect_locator_payload(&locator)?,
        &locator.mac,
    )?;
    Ok(locator)
}

fn write_effect_locator<S: EffectWalSpec>(
    authenticator: &RepositoryAuthenticator,
    root: &SafeRoot,
    lock: &BoundStateLock,
    locator: &mut EffectWalLocator,
) -> Result<()> {
    validate_effect_locator::<S>(locator, &locator.logical_id)?;
    locator.mac = authenticator.sign(S::LOCATOR_DOMAIN, &effect_locator_payload(locator)?)?;
    let mut bytes = serde_json::to_vec(locator)?;
    bytes.push(b'\n');
    let name = effect_locator_name(&locator.logical_id);
    AtomicStateWriter::scavenge_direct_temps(root, &name)?;
    AtomicStateWriter::write_direct_fenced(root, &name, &bytes, || lock.verify(root))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EffectWalFaultPoint {
    AfterPhysicalReservation,
    BeforeInitialLocator,
    AfterInitialLocator,
}

#[cfg(test)]
thread_local! {
    static EFFECT_WAL_FAULT: std::cell::Cell<Option<EffectWalFaultPoint>> =
        const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn set_effect_fault(point: EffectWalFaultPoint) {
    EFFECT_WAL_FAULT.with(|slot| slot.set(Some(point)));
}

#[cfg(test)]
fn take_effect_fault(point: EffectWalFaultPoint) -> bool {
    EFFECT_WAL_FAULT.with(|slot| {
        if slot.get() == Some(point) {
            slot.set(None);
            true
        } else {
            false
        }
    })
}

#[cfg(not(test))]
fn take_effect_fault(_point: EffectWalFaultPoint) -> bool {
    false
}

fn decode_event<S: EffectWalSpec>(record: &JournalRecord) -> Result<EffectEvent> {
    let effect_id = record
        .subject
        .clone()
        .context("effect WAL record is missing its effect id")?;
    let phase = EffectPhase::parse(&record.phase)?;
    let payload: EffectPayloadWire = serde_json::from_value(record.payload.clone())
        .context("effect WAL payload is malformed")?;
    if payload.version != S::EFFECT_FORMAT_VERSION {
        bail!("effect WAL payload version is unsupported");
    }
    Ok(EffectEvent {
        version: payload.version,
        sequence: record.sequence,
        effect_id,
        phase,
        data: payload.data,
    })
}

#[cfg(test)]
mod tests {
    #![allow(clippy::err_expect)]
    use super::*;
    use crate::artifacts::repository_auth_writer;
    use git2::Repository;
    use tempfile::TempDir;

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
    fn effect_wal_enforces_planned_started_observed_completed() {
        let (_temp, path) = repository();
        let mut wal = EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(&path),
            "run-a",
            "effect-a",
            &serde_json::json!({"request": 1}),
        )
        .expect("create planned WAL");
        wal.started("effect-a", &serde_json::json!({"attempt": 1}))
            .expect("started");
        assert!(wal.started("effect-a", &()).is_err());
        wal.observed("effect-a", &serde_json::json!({"receipt": "safe"}))
            .expect("observed");
        wal.completed("effect-a", &()).expect("completed");
        drop(wal);

        let reopened =
            EffectWal::<DefaultEffectWalSpec>::open_instance(authenticator(&path), "run-a")
                .expect("reopen WAL");
        assert_eq!(reopened.phase("effect-a"), Some(EffectPhase::Completed));
        assert_eq!(reopened.events().len(), 4);
    }

    #[test]
    fn started_only_state_remains_ambiguous_after_reopen() {
        let (_temp, path) = repository();
        let mut wal = EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(&path),
            "run-b",
            "effect-b",
            &(),
        )
        .expect("create planned WAL");
        wal.started("effect-b", &()).expect("started");
        drop(wal);
        let mut reopened =
            EffectWal::<DefaultEffectWalSpec>::open_instance(authenticator(&path), "run-b")
                .expect("reopen WAL");
        assert_eq!(reopened.phase("effect-b"), Some(EffectPhase::Started));
        assert!(reopened.planned("effect-b", &()).is_err());
        assert!(reopened.started("effect-b", &()).is_err());
        reopened
            .observed("effect-b", &())
            .expect("reconciled observation");
    }

    #[test]
    fn empty_physical_reservation_crash_retries_without_exposing_empty_wal() {
        let (_temp, path) = repository();
        set_effect_fault(EffectWalFaultPoint::AfterPhysicalReservation);
        EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(&path),
            "reservation-crash",
            "effect-c",
            &(),
        )
        .err()
        .expect("injected reservation crash");

        let wal = EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(&path),
            "reservation-crash",
            "effect-c",
            &serde_json::json!({"retry": 1}),
        )
        .expect("retry with new physical journal");
        assert_eq!(wal.logical_id(), "reservation-crash");
        assert_ne!(wal.identity().run_id, "reservation-crash");
        assert_eq!(wal.events().len(), 1);
        assert_eq!(wal.phase("effect-c"), Some(EffectPhase::Planned));
    }

    #[test]
    fn planned_record_without_locator_retries_from_signed_init_intent() {
        let (_temp, path) = repository();
        set_effect_fault(EffectWalFaultPoint::BeforeInitialLocator);
        EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(&path),
            "planned-crash",
            "effect-d",
            &(),
        )
        .err()
        .expect("injected pre-locator crash");
        let wal = EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(&path),
            "planned-crash",
            "effect-d",
            &(),
        )
        .expect("retry planned WAL");
        assert_eq!(wal.phase("effect-d"), Some(EffectPhase::Planned));
    }

    #[test]
    fn open_cleans_matching_init_tail_after_effect_locator_publication() {
        let (_temp, path) = repository();
        set_effect_fault(EffectWalFaultPoint::AfterInitialLocator);
        EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(&path),
            "effect-init-tail",
            "effect-e",
            &(),
        )
        .err()
        .expect("injected post-locator crash");
        let wal = EffectWal::<DefaultEffectWalSpec>::open_instance(
            authenticator(&path),
            "effect-init-tail",
        )
        .expect("open recovers exact init tail");
        assert_eq!(wal.phase("effect-e"), Some(EffectPhase::Planned));
    }
}
