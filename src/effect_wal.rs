//! Authenticated write-ahead state for externally visible effects.
//!
//! Each stable source-action key owns one logical authenticated snapshot. The
//! complete event sequence and phase index are committed together, so effect
//! recovery shares the same signed locator, root-wide inventory, capacity,
//! rollover, and lock-order model as every other authenticated snapshot.

#![allow(dead_code)]

use crate::{
    artifacts::state_auth::{AuthenticationDomain, RepositoryAuthenticator},
    authenticated_snapshot::{AuthenticatedSnapshotStore, SnapshotSpec},
    state_journal::{JournalIdentity, JournalSpec},
};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap;

pub(crate) const EFFECT_WAL_ROOT_NAME: &str = "authenticated-effect-wals-v1";

pub(crate) trait EffectWalSpec: SnapshotSpec {
    const EFFECT_FORMAT_VERSION: u32;
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
        AuthenticationDomain::new(b"MACO\0effect-wal-record\0v2\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0effect-wal-head\0v2\0");
    const MAX_RECORDS: usize = 4096;
    const MAX_RECORD_BYTES: u64 = 4 * 1024 * 1024;
    const MAX_TOTAL_BYTES: u64 = 64 * 1024 * 1024;
    const MAX_PHASE_BYTES: usize = 32;
    const MAX_SUBJECT_BYTES: usize = 256;
    const MAX_INSTANCE_ID_BYTES: usize = 128;
}

impl SnapshotSpec for DefaultEffectWalSpec {
    const SNAPSHOT_FORMAT_VERSION: u32 = 1;
    const LOCATOR_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0external-effect-snapshot-locator\0v1\0");
    const MAX_LOGICAL_STORES: usize = 4_096;
    const MAX_ROOT_ENTRIES: usize = 16_384;
    const MAX_PHYSICAL_INSTANCES: usize = 8_192;
}

impl EffectWalSpec for DefaultEffectWalSpec {
    const EFFECT_FORMAT_VERSION: u32 = 1;
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

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct EffectWalState {
    version: u32,
    logical_id: String,
    events: Vec<EffectEvent>,
    phases: BTreeMap<String, EffectPhase>,
}

pub(crate) struct EffectWal<S: EffectWalSpec = DefaultEffectWalSpec> {
    store: AuthenticatedSnapshotStore<S, EffectWalState>,
}

impl<S: EffectWalSpec> EffectWal<S> {
    pub(crate) fn open_or_create_planned<T: Serialize>(
        mut authenticator: impl FnMut() -> Result<RepositoryAuthenticator>,
        logical_id: &str,
        effect_id: &str,
        data: &T,
    ) -> Result<Self> {
        match Self::create_planned(authenticator()?, logical_id, effect_id, data) {
            Ok(wal) => Ok(wal),
            Err(create_error) => {
                let mut wal = Self::open_instance(authenticator()?, logical_id).with_context(|| {
                    format!(
                        "effect WAL could neither create nor open its authenticated logical store: create failed with {create_error:#}"
                    )
                })?;
                if wal.phase(effect_id).is_none() {
                    wal.planned(effect_id, data)?;
                }
                Ok(wal)
            }
        }
    }

    pub(crate) fn create_planned<T: Serialize>(
        authenticator: RepositoryAuthenticator,
        logical_id: &str,
        effect_id: &str,
        data: &T,
    ) -> Result<Self> {
        validate_effect_logical_id::<S>(logical_id)?;
        validate_effect_id::<S>(effect_id)?;
        let event = EffectEvent {
            version: S::EFFECT_FORMAT_VERSION,
            sequence: 1,
            effect_id: effect_id.to_string(),
            phase: EffectPhase::Planned,
            data: serde_json::to_value(data).context("failed to encode planned effect payload")?,
        };
        let mut phases = BTreeMap::new();
        phases.insert(effect_id.to_string(), EffectPhase::Planned);
        let state = EffectWalState {
            version: S::EFFECT_FORMAT_VERSION,
            logical_id: logical_id.to_string(),
            events: vec![event],
            phases,
        };
        validate_effect_state::<S>(&state, logical_id)?;
        let store = AuthenticatedSnapshotStore::create(authenticator, logical_id, 1, state)?;
        let wal = Self { store };
        wal.validate()?;
        Ok(wal)
    }

    pub(crate) fn open_instance(
        authenticator: RepositoryAuthenticator,
        logical_id: &str,
    ) -> Result<Self> {
        validate_effect_logical_id::<S>(logical_id)?;
        let store = AuthenticatedSnapshotStore::open_instance(authenticator, logical_id)?;
        let wal = Self { store };
        wal.validate()?;
        Ok(wal)
    }

    pub(crate) fn identity(&self) -> &JournalIdentity {
        self.store.identity()
    }

    pub(crate) fn logical_id(&self) -> &str {
        &self.store.current().value.logical_id
    }

    pub(crate) fn events(&self) -> &[EffectEvent] {
        &self.store.current().value.events
    }

    pub(crate) fn phase(&self, effect_id: &str) -> Option<EffectPhase> {
        self.store.current().value.phases.get(effect_id).copied()
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
        validate_effect_id::<S>(effect_id)?;
        let previous = self.phase(effect_id);
        if !phase.follows(previous) {
            bail!("effect WAL transition would skip, repeat, or retry an ambiguous phase");
        }
        let sequence = u64::try_from(self.events().len())
            .context("effect WAL sequence overflowed")?
            .checked_add(1)
            .context("effect WAL sequence exhausted")?;
        if sequence > u64::try_from(S::MAX_RECORDS).unwrap_or(u64::MAX) {
            bail!("effect WAL exceeds its bounded event count");
        }
        let event = EffectEvent {
            version: S::EFFECT_FORMAT_VERSION,
            sequence,
            effect_id: effect_id.to_string(),
            phase,
            data: serde_json::to_value(data)
                .context("failed to encode effect transition payload")?,
        };
        let mut next = self.store.current().value.clone();
        next.events.push(event);
        next.phases.insert(effect_id.to_string(), phase);
        validate_effect_state::<S>(&next, self.logical_id())?;
        self.store.commit(sequence, next)?;
        self.validate()
    }

    fn validate(&self) -> Result<()> {
        let current = self.store.current();
        validate_effect_state::<S>(&current.value, self.store.logical_id())?;
        let expected =
            u64::try_from(current.value.events.len()).context("effect WAL sequence overflowed")?;
        if current.token != expected {
            bail!("effect WAL snapshot token does not match its event sequence");
        }
        Ok(())
    }
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

fn validate_effect_id<S: EffectWalSpec>(effect_id: &str) -> Result<()> {
    if effect_id.is_empty() || effect_id.len() > S::MAX_SUBJECT_BYTES {
        bail!("effect WAL effect id is empty or exceeds its byte bound");
    }
    Ok(())
}

fn validate_effect_state<S: EffectWalSpec>(state: &EffectWalState, logical_id: &str) -> Result<()> {
    validate_effect_logical_id::<S>(logical_id)?;
    if state.version != S::EFFECT_FORMAT_VERSION
        || state.logical_id != logical_id
        || state.events.is_empty()
        || state.events.len() > S::MAX_RECORDS
        || state.phases.len() > S::MAX_RECORDS
    {
        bail!("effect WAL snapshot is malformed or exceeds its bounds");
    }
    let mut phases = BTreeMap::new();
    for (index, event) in state.events.iter().enumerate() {
        validate_effect_id::<S>(&event.effect_id)?;
        let sequence = u64::try_from(index)
            .context("effect WAL sequence overflowed")?
            .checked_add(1)
            .context("effect WAL sequence exhausted")?;
        let previous = phases.get(&event.effect_id).copied();
        if event.version != S::EFFECT_FORMAT_VERSION
            || event.sequence != sequence
            || !event.phase.follows(previous)
        {
            bail!("effect WAL event sequence or phase transition is invalid");
        }
        phases.insert(event.effect_id.clone(), event.phase);
    }
    if phases != state.phases {
        bail!("effect WAL phase index does not match its authenticated event sequence");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::err_expect)]

    use super::*;
    use crate::artifacts::repository_auth_writer;
    use git2::Repository;
    use std::fs;
    use tempfile::TempDir;

    enum TinyEffectWalSpec {}

    impl JournalSpec for TinyEffectWalSpec {
        const FORMAT_VERSION: u32 = 1;
        const NAMESPACE: &'static str = "tiny_effect_wal";
        const ROOT_NAME: &'static str = "tiny-authenticated-effect-wals-v1";
        const ROOT_LOCK_NAME: &'static str = ".tiny-effect-wals.lock";
        const INSTANCE_LOCK_NAME: &'static str = ".tiny-effect-wal.lock";
        const HEAD_FILE_NAME: &'static str = ".head.json";
        const RECORD_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0tiny-effect-wal-record\0v1\0");
        const HEAD_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0tiny-effect-wal-head\0v1\0");
        const MAX_RECORDS: usize = 8;
        const MAX_RECORD_BYTES: u64 = 64 * 1024;
        const MAX_TOTAL_BYTES: u64 = 256 * 1024;
        const MAX_PHASE_BYTES: usize = 32;
        const MAX_SUBJECT_BYTES: usize = 64;
        const MAX_INSTANCE_ID_BYTES: usize = 64;
    }

    impl SnapshotSpec for TinyEffectWalSpec {
        const SNAPSHOT_FORMAT_VERSION: u32 = 1;
        const LOCATOR_DOMAIN: AuthenticationDomain =
            AuthenticationDomain::new(b"MACO\0tiny-effect-snapshot-locator\0v1\0");
        const MAX_LOGICAL_STORES: usize = 2;
        const MAX_ROOT_ENTRIES: usize = 7;
        const MAX_PHYSICAL_INSTANCES: usize = 2;
    }

    impl EffectWalSpec for TinyEffectWalSpec {
        const EFFECT_FORMAT_VERSION: u32 = 1;
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
    fn default_effect_wals_share_one_snapshot_inventory_without_legacy_metadata() {
        let (_temp, path) = repository();
        let first = EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(&path),
            "source-a",
            "effect-a",
            &(),
        )
        .expect("first logical WAL");
        let first_identity = first.identity().clone();
        drop(first);
        let second = EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(&path),
            "source-b",
            "effect-b",
            &(),
        )
        .expect("second logical WAL");
        assert_ne!(second.identity(), &first_identity);
        drop(second);

        let first =
            EffectWal::<DefaultEffectWalSpec>::open_instance(authenticator(&path), "source-a")
                .expect("reopen first logical WAL");
        assert_eq!(first.phase("effect-a"), Some(EffectPhase::Planned));
        let root = path.join(".git/maco/state").join(EFFECT_WAL_ROOT_NAME);
        for entry in std::fs::read_dir(root).expect("effect root") {
            let name = entry
                .expect("effect root entry")
                .file_name()
                .into_string()
                .expect("UTF-8 entry");
            assert!(!name.starts_with(".effect-locator-"));
            assert!(!name.starts_with(".effect-init-"));
            assert!(!name.starts_with(".effect-store-"));
        }
    }

    #[test]
    fn effect_wal_rejects_multi_generation_locator_replay() {
        let (_temp, path) = repository();
        let mut wal = EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(&path),
            "source-replay",
            "effect-replay",
            &(),
        )
        .expect("create effect WAL");
        let root = path.join(".git/maco/state").join(EFFECT_WAL_ROOT_NAME);
        let logical_hash = crate::artifacts::state_auth::sha256_hex(b"source-replay");
        let locator = root.join(format!(".snapshot-locator-{logical_hash}.json"));
        let generation_one = std::fs::read(&locator).expect("generation-one locator");
        wal.started("effect-replay", &()).expect("started");
        wal.observed("effect-replay", &()).expect("observed");
        drop(wal);

        std::fs::write(locator, generation_one).expect("replay old signed locator");
        let error =
            EffectWal::<DefaultEffectWalSpec>::open_instance(authenticator(&path), "source-replay")
                .err()
                .expect("multi-generation replay must fail closed");
        assert!(error.to_string().contains("rollback exceeds"));
    }

    #[test]
    fn effect_wal_creation_obeys_snapshot_logical_and_root_quotas_without_residue() {
        let (_temp, path) = repository();
        for logical_id in ["tiny-a", "tiny-b"] {
            EffectWal::<TinyEffectWalSpec>::create_planned(
                authenticator(&path),
                logical_id,
                "effect",
                &(),
            )
            .expect("logical store within quota");
        }
        let error = EffectWal::<TinyEffectWalSpec>::create_planned(
            authenticator(&path),
            "tiny-c",
            "effect",
            &(),
        )
        .err()
        .expect("quota+1 must fail");
        assert!(error.to_string().contains("no capacity"));
        let root = path
            .join(".git/maco/state")
            .join(TinyEffectWalSpec::ROOT_NAME);
        assert_eq!(std::fs::read_dir(&root).expect("tiny root").count(), 7);
        let rejected_hash = crate::artifacts::state_auth::sha256_hex(b"tiny-c");
        assert!(!root
            .join(format!(".snapshot-locator-{rejected_hash}.json"))
            .exists());
    }

    #[test]
    fn default_effect_capacity_exceeds_the_legacy_scavenge_ceiling() {
        assert_eq!(DefaultEffectWalSpec::MAX_LOGICAL_STORES, 4_096);
        assert_eq!(DefaultEffectWalSpec::MAX_ROOT_ENTRIES, 16_384);
    }

    fn planned_wal_record_path(path: &std::path::Path, logical_id: &str) -> std::path::PathBuf {
        let wal = EffectWal::<DefaultEffectWalSpec>::create_planned(
            authenticator(path),
            logical_id,
            "effect-tamper",
            &serde_json::json!({"payload": "exact"}),
        )
        .expect("create tamper WAL");
        let physical_id = wal.identity().run_id.clone();
        let repository = crate::git_repository::open(path).expect("reopen tamper repository");
        let record = repository
            .commondir()
            .join("maco/state")
            .join(EFFECT_WAL_ROOT_NAME)
            .join(physical_id)
            .join("00000000000000000001.json");
        drop(wal);
        record
    }

    #[cfg(unix)]
    #[test]
    fn effect_wal_rejects_unknown_hardlink_rename_and_truncated_record_tampering() {
        let (_hardlink_temp, hardlink_repo) = repository();
        let hardlink_record = planned_wal_record_path(&hardlink_repo, "hardlink-tamper");
        fs::hard_link(
            &hardlink_record,
            hardlink_record.with_file_name("unknown-hardlink"),
        )
        .expect("create unknown hardlink");
        assert!(EffectWal::<DefaultEffectWalSpec>::open_instance(
            authenticator(&hardlink_repo),
            "hardlink-tamper"
        )
        .is_err());

        let (_rename_temp, rename_repo) = repository();
        let rename_record = planned_wal_record_path(&rename_repo, "rename-tamper");
        fs::rename(
            &rename_record,
            rename_record.with_file_name("renamed-record.json"),
        )
        .expect("rename WAL record");
        assert!(EffectWal::<DefaultEffectWalSpec>::open_instance(
            authenticator(&rename_repo),
            "rename-tamper"
        )
        .is_err());

        let (_truncate_temp, truncate_repo) = repository();
        let truncate_record = planned_wal_record_path(&truncate_repo, "truncate-tamper");
        let bytes = fs::read(&truncate_record).expect("read WAL record");
        fs::write(&truncate_record, &bytes[..bytes.len() / 2]).expect("truncate WAL record");
        assert!(EffectWal::<DefaultEffectWalSpec>::open_instance(
            authenticator(&truncate_repo),
            "truncate-tamper"
        )
        .is_err());
    }
}
