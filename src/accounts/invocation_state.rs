//! Per-request authenticated intent. An existing request never gets a replacement nonce.

use super::{
    invocation_protocol::InvocationRequest,
    provider::{BrokerAdmissionPolicy, BrokerAttemptMetadata},
};
use crate::{
    artifacts::{
        repository_auth_writer,
        state_auth::{random_identifier, sha256_hex, AuthenticationDomain},
    },
    state_journal::{AuthenticatedStateJournal, CheckpointJournalSpec, JournalSpec},
};
use anyhow::{bail, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

enum AccountInvocationSpec {}
impl JournalSpec for AccountInvocationSpec {
    const FORMAT_VERSION: u32 = 1;
    const NAMESPACE: &'static str = "account_invocation";
    const ROOT_NAME: &'static str = "account-invocations-v1";
    const ROOT_LOCK_NAME: &'static str = ".account-invocations.lock";
    const INSTANCE_LOCK_NAME: &'static str = ".attempt.lock";
    const HEAD_FILE_NAME: &'static str = ".head.json";
    const RECORD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0account-invocation-record\0v1\0");
    const HEAD_DOMAIN: AuthenticationDomain =
        AuthenticationDomain::new(b"MACO\0account-invocation-head\0v1\0");
    // Reuse the existing authenticated checkpoint storage bounds; no new storage budget.
    const MAX_RECORDS: usize = CheckpointJournalSpec::MAX_RECORDS;
    const MAX_RECORD_BYTES: u64 = CheckpointJournalSpec::MAX_RECORD_BYTES;
    const MAX_TOTAL_BYTES: u64 = CheckpointJournalSpec::MAX_TOTAL_BYTES;
    const MAX_PHASE_BYTES: usize = CheckpointJournalSpec::MAX_PHASE_BYTES;
    const MAX_SUBJECT_BYTES: usize = CheckpointJournalSpec::MAX_SUBJECT_BYTES;
    const MAX_INSTANCE_ID_BYTES: usize = CheckpointJournalSpec::MAX_INSTANCE_ID_BYTES;
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct InvocationIntent {
    pub endpoint_binding: String,
    pub expected_uid: u32,
    pub caller_uid: u32,
    pub request_id: String,
    pub request: InvocationRequest,
    pub admission: BrokerAdmissionPolicy,
    pub rolling_quota: Option<crate::budget_ledger::RollingBudgetQuota>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredRecord {
    version: u32,
    intent: Option<InvocationIntent>,
    metadata: BrokerAttemptMetadata,
}

pub(super) struct AccountIntentJournal {
    journal: AuthenticatedStateJournal<AccountInvocationSpec>,
}

impl AccountIntentJournal {
    pub fn open(repo: &Path, request_id: &str) -> Result<Self> {
        let authenticator = repository_auth_writer(repo)?.into_authenticator()?;
        let instance = sha256_hex(request_id.as_bytes());
        Ok(Self {
            journal: AuthenticatedStateJournal::open_or_initialize(authenticator, &instance)?,
        })
    }

    pub fn prior_metadata(&self) -> Result<Option<BrokerAttemptMetadata>> {
        let mut latest = None;
        for (index, record) in self.journal.records().iter().enumerate() {
            let decoded: StoredRecord = serde_json::from_value(record.payload.clone())?;
            if decoded.version != 1
                || (index == 0) != decoded.intent.is_some()
                || !matches!(
                    record.phase.as_str(),
                    "intent" | "prepared" | "reserved" | "start_requested" | "outcome"
                )
            {
                bail!("account invocation record is invalid");
            }
            latest = Some(decoded.metadata);
        }
        Ok(latest)
    }

    pub fn record_intent(
        &mut self,
        intent: InvocationIntent,
        metadata: &BrokerAttemptMetadata,
    ) -> Result<()> {
        if !self.journal.records().is_empty() {
            bail!("account invocation is already recorded");
        }
        self.journal.append(
            "intent",
            None,
            &StoredRecord {
                version: 1,
                intent: Some(intent),
                metadata: metadata.clone(),
            },
        )?;
        Ok(())
    }

    pub fn record(&mut self, phase: &str, metadata: &BrokerAttemptMetadata) -> Result<()> {
        self.journal.append(
            phase,
            None,
            &StoredRecord {
                version: 1,
                intent: None,
                metadata: metadata.clone(),
            },
        )?;
        Ok(())
    }

    pub fn reservation_id(&self) -> String {
        format!("account-provider/{}", self.journal.instance_id())
    }
}

pub(super) fn new_nonce() -> Result<String> {
    let random = random_identifier()?;
    let mut bytes = [0_u8; 16];
    for (byte, pair) in bytes.iter_mut().zip(random.as_bytes().chunks_exact(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair)?, 16)?;
    }
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    Ok(format!(
        "{}-{}-{}-{}-{}",
        &hex[..8],
        &hex[8..12],
        &hex[12..16],
        &hex[16..20],
        &hex[20..]
    ))
}
