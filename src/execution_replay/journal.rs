//! Read-only binding of already-authenticated journal records.
//!
//! Replay never opens, locks, appends, recovers, or publishes a durable
//! journal. A caller that has already authenticated a record through
//! `state_journal` copies the verified identity into checkpoint evidence.

use super::{
    AuthenticatedCheckpointEvidence, JournalId, LineageInconsistency, LineagePoint, ReplayError,
    RunId,
};
use crate::state_journal::JournalRecord;

/// Copies identity from a record the caller has already authenticated.
///
/// This is structural binding only. It does not verify the MAC, open a
/// journal, or take the instance lock, so inspection cannot contend with a
/// live run. Supervise and orchestrator resume own those journals and are
/// outside this lane; the function is the owned read-only adapter for a
/// later handoff.
#[allow(dead_code)]
pub(crate) fn checkpoint_evidence_from_authenticated_record(
    run_id: RunId,
    record: &JournalRecord,
) -> Result<AuthenticatedCheckpointEvidence, ReplayError> {
    if record.identity.run_id != run_id.as_str() {
        return Err(ReplayError::InconsistentLineage {
            run_id,
            detail: LineageInconsistency::CheckpointPointBinding,
        });
    }
    AuthenticatedCheckpointEvidence::from_authenticated_record(
        LineagePoint::new(run_id, record.sequence),
        JournalId::new(record.identity.journal_id.clone())?,
        record.sequence,
        record.mac.as_str(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        artifacts::state_auth::{AuthenticationTag, RepositoryAuthBinding},
        safe_state::FileIdentity,
        state_journal::{JournalIdentity, JournalRecord},
    };
    use serde_json::json;

    fn record(run_id: &str, journal_id: &str, sequence: u64, tag: &str) -> JournalRecord {
        JournalRecord {
            version: 3,
            identity: JournalIdentity {
                version: 3,
                repository: RepositoryAuthBinding {
                    version: 1,
                    repository_id: "repo".to_string(),
                    common_dir_path_sha256: "ab".repeat(32),
                    common_dir_identity: FileIdentity { device: 1, file: 2 },
                    key_identity: FileIdentity { device: 3, file: 4 },
                },
                run_id: run_id.to_string(),
                journal_id: journal_id.to_string(),
                run_directory_identity: FileIdentity { device: 5, file: 6 },
            },
            sequence,
            previous_mac: AuthenticationTag::zero(),
            phase: "checkpoint".to_string(),
            subject: None,
            payload: json!({ "kind": "checkpoint" }),
            mac: AuthenticationTag::parse(tag).expect("canonical tag"),
        }
    }

    #[test]
    fn copies_verified_identity_without_opening_a_journal() {
        let run_id = RunId::new("root").expect("run id");
        let tag = "cd".repeat(32);
        let evidence = checkpoint_evidence_from_authenticated_record(
            run_id.clone(),
            &record("root", "journal-a", 4, &tag),
        )
        .expect("bind authenticated record");
        assert_eq!(evidence.point(), &LineagePoint::new(run_id, 4));
        assert_eq!(evidence.journal_id().as_str(), "journal-a");
        assert_eq!(evidence.record_sequence(), 4);
        assert_eq!(evidence.record_tag(), tag);
    }

    #[test]
    fn refuses_a_record_bound_to_a_different_run() {
        let run_id = RunId::new("root").expect("run id");
        assert!(matches!(
            checkpoint_evidence_from_authenticated_record(
                run_id,
                &record("other", "journal-a", 1, &"ef".repeat(32)),
            ),
            Err(ReplayError::InconsistentLineage {
                detail: LineageInconsistency::CheckpointPointBinding,
                ..
            })
        ));
    }
}
