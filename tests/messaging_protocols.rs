use std::{
    collections::BTreeMap,
    fs,
    io::Write,
    path::{Path, PathBuf},
    sync::mpsc::{self, RecvTimeoutError},
    thread,
    time::Duration,
};

use multi_agent_coding_orchestrator::{
    hierarchy_ledger::{HierarchyLedgerSnapshot, RoleCategory},
    messaging::{
        store::StoreError, AcknowledgementOutcome, CredentialRegistry, EnvelopeValidationError,
        MessageEnvelope, MessageId, MessagingBroker, MessagingError, MessagingLimits,
        PresentedCredential, SpeakerGraph, TurnCompletionReason, TurnDefinitionError,
        TurnExpectation, TurnParticipant, TurnPolicy, TurnProtocolDefinition, TurnProtocolError,
        TurnProtocolLimits, TurnProtocolStatus, TurnProtocolStore,
    },
};
use serde_json::{json, Value};

fn hierarchy() -> HierarchyLedgerSnapshot {
    let mut hierarchy = HierarchyLedgerSnapshot::default();
    hierarchy.effective_categories.insert(
        "coordinator".to_string(),
        RoleCategory::DelegatingCoordinator,
    );
    hierarchy.effective_categories.insert(
        "worker-a".to_string(),
        RoleCategory::NonDelegatingTerminalWorker,
    );
    hierarchy.effective_categories.insert(
        "worker-b".to_string(),
        RoleCategory::NonDelegatingTerminalWorker,
    );
    hierarchy
        .effective_categories
        .insert("outsider".to_string(), RoleCategory::ReadOnlyResearcher);
    hierarchy
}

fn credentials() -> (CredentialRegistry, PresentedCredential, PresentedCredential) {
    let mut registry = CredentialRegistry::new(3).expect("credential registry");
    let coordinator = registry
        .register("coordinator", "coordinator-secret")
        .expect("coordinator credential");
    let worker_a = registry
        .register("worker-a", "worker-a-secret")
        .expect("worker-a credential");
    (registry, coordinator, worker_a)
}

fn fully_credentialed_credentials() -> (
    CredentialRegistry,
    PresentedCredential,
    PresentedCredential,
    PresentedCredential,
    PresentedCredential,
) {
    let mut registry = CredentialRegistry::new(4).expect("credential registry");
    let coordinator = registry
        .register("coordinator", "coordinator-secret")
        .expect("coordinator credential");
    let worker_a = registry
        .register("worker-a", "worker-a-secret")
        .expect("worker-a credential");
    let worker_b = registry
        .register("worker-b", "worker-b-secret")
        .expect("worker-b credential");
    let outsider = registry
        .register("outsider", "outsider-secret")
        .expect("outsider credential");
    (registry, coordinator, worker_a, worker_b, outsider)
}

fn journal_bytes(path: &Path) -> Vec<u8> {
    fs::read(path).expect("read complete journal")
}

fn journal_sidecar_path(path: &Path, suffix: &str) -> PathBuf {
    let mut sidecar = path.as_os_str().to_os_string();
    sidecar.push(suffix);
    sidecar.into()
}

fn create_attack_journal(path: &Path, payloads: &[&str]) {
    let hierarchy = hierarchy();
    let (registry, coordinator, _, _, _) = fully_credentialed_credentials();
    let mut broker =
        MessagingBroker::create(path, registry, &hierarchy, MessagingLimits::default())
            .expect("create attack-case broker");
    for payload in payloads {
        broker
            .send_direct(&coordinator, "worker-a", json!({"payload": *payload}))
            .expect("append attack-case message");
    }
}

fn open_attack_error(path: &Path, context: &str) -> MessagingError {
    let hierarchy = hierarchy();
    let (registry, _, _, _, _) = fully_credentialed_credentials();
    match MessagingBroker::open(path, registry, &hierarchy, MessagingLimits::default()) {
        Ok(broker) => {
            drop(broker);
            panic!("{context}: attacked journal unexpectedly opened")
        }
        Err(error) => error,
    }
}

fn replace_equal_length_once(bytes: &mut [u8], original: &[u8], replacement: &[u8]) {
    assert_eq!(original.len(), replacement.len());
    let positions = bytes
        .windows(original.len())
        .enumerate()
        .filter_map(|(index, candidate)| (candidate == original).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(positions.len(), 1, "expected one exact tamper target");
    let start = positions[0];
    bytes[start..start + replacement.len()].copy_from_slice(replacement);
}

fn turn_participants() -> Vec<TurnParticipant> {
    vec![
        TurnParticipant::new("coordinator", RoleCategory::DelegatingCoordinator),
        TurnParticipant::new("worker-a", RoleCategory::NonDelegatingTerminalWorker),
        TurnParticipant::new("worker-b", RoleCategory::NonDelegatingTerminalWorker),
    ]
}

fn turn_definition(policy: TurnPolicy, max_turns: u64) -> TurnProtocolDefinition {
    TurnProtocolDefinition::new(
        "session-1",
        "protocol-1",
        turn_participants(),
        policy,
        max_turns,
        TurnProtocolLimits::default(),
    )
    .expect("turn protocol definition")
}

fn turn_state_bytes(path: &Path) -> Vec<u8> {
    fs::read(path).expect("read complete turn state")
}

fn refresh_turn_state_checksum(bytes: &mut [u8]) {
    const STATE_MARKER: &[u8] = b"\"state\":";
    const CHECKSUM_MARKER: &[u8] = b",\"checksum\":\"";
    const CHECKSUM_DOMAIN: &[u8] = b"MACO\0turn-protocol-state\0v1\0";

    let state_start = bytes
        .windows(STATE_MARKER.len())
        .position(|candidate| candidate == STATE_MARKER)
        .map(|position| position + STATE_MARKER.len())
        .expect("turn state marker");
    let checksum_marker = bytes
        .windows(CHECKSUM_MARKER.len())
        .position(|candidate| candidate == CHECKSUM_MARKER)
        .expect("turn checksum marker");
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in CHECKSUM_DOMAIN
        .iter()
        .chain(&bytes[state_start..checksum_marker])
    {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let checksum = format!("{hash:016x}");
    let checksum_start = checksum_marker + CHECKSUM_MARKER.len();
    bytes[checksum_start..checksum_start + checksum.len()].copy_from_slice(checksum.as_bytes());
}

fn assert_direct_delivery(
    envelope: &MessageEnvelope,
    expected_id: &MessageId,
    expected_sequence: u64,
    expected_payload: &Value,
    expected_attempts: u32,
) {
    assert_eq!(&envelope.id, expected_id);
    assert_eq!(envelope.sequence, expected_sequence);
    assert_eq!(&envelope.payload, expected_payload);
    assert_eq!(envelope.recipients.len(), 1);
    let delivery = envelope
        .recipients
        .get("worker-a")
        .expect("worker-a delivery state");
    assert_eq!(delivery.delivery_attempts, expected_attempts);
    assert!(!delivery.acknowledged);
}

#[test]
fn bad_and_unknown_credentials_are_typed_and_append_nothing() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let journal = temporary.path().join("messages.jsonl");
    let (registry, _, _) = credentials();
    let mut broker =
        MessagingBroker::create(&journal, registry, &hierarchy(), MessagingLimits::default())
            .expect("create broker");
    let initial_bytes = journal_bytes(&journal);

    let bad = PresentedCredential::new("coordinator", "wrong-secret").expect("bad credential");
    match broker
        .send_direct(&bad, "worker-a", json!({"should": "not persist"}))
        .expect_err("bad credential must be refused")
    {
        MessagingError::BadCredential { agent_id } => assert_eq!(agent_id, "coordinator"),
        other => panic!("expected BadCredential, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), initial_bytes);

    let unknown =
        PresentedCredential::new("intruder", "intruder-secret").expect("unknown credential");
    match broker
        .send_direct(&unknown, "worker-a", json!({"should": "not persist"}))
        .expect_err("unknown credential must be refused")
    {
        MessagingError::UnknownCredential { agent_id } => assert_eq!(agent_id, "intruder"),
        other => panic!("expected UnknownCredential, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), initial_bytes);
}

#[test]
fn direct_recipient_refusals_are_typed_and_append_nothing() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let journal = temporary.path().join("messages.jsonl");
    let hierarchy = hierarchy();
    let (registry, coordinator, _) = credentials();
    let mut broker =
        MessagingBroker::create(&journal, registry, &hierarchy, MessagingLimits::default())
            .expect("create broker");
    let broker_id = broker.broker_instance_id().to_string();
    let initial_bytes = journal_bytes(&journal);

    match broker
        .send_direct(&coordinator, "unknown-worker", json!({"refused": 1}))
        .expect_err("unknown recipient must be refused")
    {
        MessagingError::UnknownRecipient { recipient_id } => {
            assert_eq!(recipient_id, "unknown-worker")
        }
        other => panic!("expected UnknownRecipient, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), initial_bytes);

    match broker
        .send_direct(&coordinator, "worker-b", json!({"refused": 2}))
        .expect_err("credential-missing recipient must be refused")
    {
        MessagingError::MisaddressedRecipient { recipient_id } => {
            assert_eq!(recipient_id, "worker-b")
        }
        other => panic!("expected MisaddressedRecipient, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), initial_bytes);

    let sent = broker
        .send_direct(&coordinator, "worker-a", json!({"accepted": true}))
        .expect("next valid direct send");
    assert_eq!(sent.sequence, 1);
    assert_eq!(
        sent.id.as_str(),
        format!("{broker_id}-00000000000000000001")
    );
}

#[test]
fn direct_delivery_redelivers_in_order_until_durable_ack_across_reopen() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let journal = temporary.path().join("messages.jsonl");
    let hierarchy = hierarchy();
    let limits = MessagingLimits::default();
    let (registry, coordinator, worker_a) = credentials();
    let first_payload = json!({"task": "first", "ordinal": 1});
    let second_payload = json!({"task": "second", "ordinal": 2});

    let mut broker =
        MessagingBroker::create(&journal, registry.clone(), &hierarchy, limits.clone())
            .expect("create broker");
    let broker_id = broker.broker_instance_id().to_string();
    let first_sent = broker
        .send_direct(&coordinator, "worker-a", first_payload.clone())
        .expect("send first");
    let second_sent = broker
        .send_direct(&coordinator, "worker-a", second_payload.clone())
        .expect("send second");
    assert_eq!(
        first_sent.id.as_str(),
        format!("{broker_id}-00000000000000000001")
    );
    assert_eq!(
        second_sent.id.as_str(),
        format!("{broker_id}-00000000000000000002")
    );
    assert_direct_delivery(&first_sent, &first_sent.id, 1, &first_payload, 0);
    assert_direct_delivery(&second_sent, &second_sent.id, 2, &second_payload, 0);

    let first_attempt = broker
        .receive_next(&worker_a)
        .expect("receive first")
        .expect("first message");
    assert_direct_delivery(&first_attempt, &first_sent.id, 1, &first_payload, 1);
    drop(broker);

    let mut reopened =
        MessagingBroker::open(&journal, registry.clone(), &hierarchy, limits.clone())
            .expect("reopen before acknowledgement");
    let repeated_first = reopened
        .receive_next(&worker_a)
        .expect("redeliver first")
        .expect("unacknowledged first message");
    assert_direct_delivery(&repeated_first, &first_sent.id, 1, &first_payload, 2);
    assert_eq!(
        reopened
            .acknowledge(&worker_a, &first_sent.id)
            .expect("acknowledge first"),
        AcknowledgementOutcome::Acknowledged
    );
    drop(reopened);

    let mut reopened =
        MessagingBroker::open(&journal, registry.clone(), &hierarchy, limits.clone())
            .expect("reopen after first acknowledgement");
    let next = reopened
        .receive_next(&worker_a)
        .expect("receive deterministic next")
        .expect("second message");
    assert_direct_delivery(&next, &second_sent.id, 2, &second_payload, 1);
    assert_eq!(
        reopened
            .acknowledge(&worker_a, &second_sent.id)
            .expect("acknowledge second"),
        AcknowledgementOutcome::Acknowledged
    );
    drop(reopened);

    let mut reopened = MessagingBroker::open(&journal, registry, &hierarchy, limits)
        .expect("reopen after all acknowledgements");
    assert!(reopened
        .receive_next(&worker_a)
        .expect("receive after durable acknowledgements")
        .is_none());
}

#[test]
fn direct_and_channel_authorization_failures_are_typed_and_non_mutating() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let journal = temporary.path().join("messages.jsonl");
    let hierarchy = hierarchy();
    let (registry, coordinator, worker_a, worker_b, outsider) = fully_credentialed_credentials();
    let mut broker =
        MessagingBroker::create(&journal, registry, &hierarchy, MessagingLimits::default())
            .expect("create broker");
    let direct = broker
        .send_direct(&coordinator, "worker-a", json!({"kind": "direct"}))
        .expect("send direct");

    let before_refusal = journal_bytes(&journal);
    match broker
        .acknowledge(&worker_b, &direct.id)
        .expect_err("non-recipient acknowledgement must be refused")
    {
        MessagingError::NonRecipientAcknowledgement {
            message_id,
            agent_id,
        } => {
            assert_eq!(message_id, direct.id);
            assert_eq!(agent_id, "worker-b");
        }
        other => panic!("expected NonRecipientAcknowledgement, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), before_refusal);

    let before_refusal = journal_bytes(&journal);
    match broker
        .receive_message(&worker_b, &direct.id)
        .expect_err("receive_message for a wrong principal must return typed NonRecipientDelivery")
    {
        MessagingError::NonRecipientDelivery {
            message_id,
            agent_id,
        } => {
            assert_eq!(message_id, direct.id);
            assert_eq!(agent_id, "worker-b");
        }
        other => panic!("expected NonRecipientDelivery, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), before_refusal);

    broker
        .create_channel(
            &coordinator,
            "team",
            ["coordinator", "worker-a", "worker-b"],
            ["coordinator"],
        )
        .expect("create governed channel");
    let broadcast = broker
        .publish_channel(&coordinator, "team", json!({"kind": "broadcast"}))
        .expect("publish governed broadcast");

    let before_refusal = journal_bytes(&journal);
    match broker
        .receive_next_from_channel(&outsider, "team")
        .expect_err("non-member channel receive must be refused")
    {
        MessagingError::NonMemberDelivery {
            channel_id,
            agent_id,
        } => {
            assert_eq!(channel_id, "team");
            assert_eq!(agent_id, "outsider");
        }
        other => panic!("expected NonMemberDelivery, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), before_refusal);

    let before_refusal = journal_bytes(&journal);
    match broker
        .acknowledge(&outsider, &broadcast.id)
        .expect_err("non-member channel acknowledgement must be refused")
    {
        MessagingError::NonMemberAcknowledgement {
            channel_id,
            message_id,
            agent_id,
        } => {
            assert_eq!(channel_id, "team");
            assert_eq!(message_id, broadcast.id);
            assert_eq!(agent_id, "outsider");
        }
        other => panic!("expected NonMemberAcknowledgement, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), before_refusal);

    let before_refusal = journal_bytes(&journal);
    match broker
        .publish_channel(&worker_b, "team", json!({"forbidden": true}))
        .expect_err("non-publisher broadcast must be refused")
    {
        MessagingError::UnauthorizedBroadcastPublication {
            channel_id,
            agent_id,
        } => {
            assert_eq!(channel_id, "team");
            assert_eq!(agent_id, "worker-b");
        }
        other => panic!("expected UnauthorizedBroadcastPublication, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), before_refusal);

    assert!(broker
        .receive_message(&worker_a, &direct.id)
        .expect("intended direct receive remains available")
        .is_some());
}

#[test]
fn governed_broadcast_has_exact_membership_and_independent_durable_acks() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let journal = temporary.path().join("messages.jsonl");
    let hierarchy = hierarchy();
    let limits = MessagingLimits::default();
    let (registry, coordinator, worker_a, worker_b, _) = fully_credentialed_credentials();
    let mut broker =
        MessagingBroker::create(&journal, registry.clone(), &hierarchy, limits.clone())
            .expect("create broker");
    broker
        .create_channel(
            &coordinator,
            "team",
            ["coordinator", "worker-a", "worker-b"],
            ["coordinator"],
        )
        .expect("create governed channel");
    let payload = json!({"task": "fan-out"});
    let broadcast = broker
        .publish_channel(&coordinator, "team", payload.clone())
        .expect("publish broadcast");
    assert_eq!(broadcast.payload, payload);
    assert_eq!(
        broadcast
            .recipients
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        vec!["coordinator", "worker-a", "worker-b"]
    );
    for recipient_id in ["coordinator", "worker-a", "worker-b"] {
        let state = &broadcast.recipients[recipient_id];
        assert_eq!(state.delivery_attempts, 0);
        assert!(!state.acknowledged);
    }

    let worker_a_delivery = broker
        .receive_next_from_channel(&worker_a, "team")
        .expect("worker-a receive")
        .expect("worker-a broadcast");
    assert_eq!(worker_a_delivery.id, broadcast.id);
    assert_eq!(
        worker_a_delivery.recipients["worker-a"].delivery_attempts,
        1
    );
    assert_eq!(
        broker
            .acknowledge(&worker_a, &broadcast.id)
            .expect("worker-a acknowledgement"),
        AcknowledgementOutcome::Acknowledged
    );

    let worker_b_delivery = broker
        .receive_next_from_channel(&worker_b, "team")
        .expect("worker-b receive")
        .expect("worker-b broadcast");
    assert_eq!(worker_b_delivery.id, broadcast.id);
    assert_eq!(
        worker_b_delivery.recipients["worker-a"].delivery_attempts,
        1
    );
    assert!(worker_b_delivery.recipients["worker-a"].acknowledged);
    assert_eq!(
        worker_b_delivery.recipients["worker-b"].delivery_attempts,
        1
    );
    assert!(!worker_b_delivery.recipients["worker-b"].acknowledged);
    assert_eq!(
        worker_b_delivery.recipients["coordinator"].delivery_attempts,
        0
    );
    assert!(!worker_b_delivery.recipients["coordinator"].acknowledged);

    let coordinator_delivery = broker
        .receive_next_from_channel(&coordinator, "team")
        .expect("coordinator receive")
        .expect("coordinator broadcast");
    assert_eq!(coordinator_delivery.id, broadcast.id);
    assert_eq!(
        coordinator_delivery.recipients["coordinator"].delivery_attempts,
        1
    );
    assert_eq!(
        broker
            .acknowledge(&coordinator, &broadcast.id)
            .expect("coordinator acknowledgement"),
        AcknowledgementOutcome::Acknowledged
    );
    drop(broker);

    let mut reopened =
        MessagingBroker::open(&journal, registry.clone(), &hierarchy, limits.clone())
            .expect("reopen with worker-b unacknowledged");
    assert!(reopened
        .receive_next_from_channel(&worker_a, "team")
        .expect("worker-a durable acknowledgement")
        .is_none());
    assert!(reopened
        .receive_next_from_channel(&coordinator, "team")
        .expect("coordinator durable acknowledgement")
        .is_none());
    let worker_b_redelivery = reopened
        .receive_next_from_channel(&worker_b, "team")
        .expect("worker-b redelivery")
        .expect("unacknowledged worker-b broadcast");
    assert_eq!(worker_b_redelivery.id, broadcast.id);
    assert_eq!(
        worker_b_redelivery.recipients["worker-a"].delivery_attempts,
        1
    );
    assert!(worker_b_redelivery.recipients["worker-a"].acknowledged);
    assert_eq!(
        worker_b_redelivery.recipients["worker-b"].delivery_attempts,
        2
    );
    assert!(!worker_b_redelivery.recipients["worker-b"].acknowledged);
    assert_eq!(
        worker_b_redelivery.recipients["coordinator"].delivery_attempts,
        1
    );
    assert!(worker_b_redelivery.recipients["coordinator"].acknowledged);
    assert_eq!(
        reopened
            .acknowledge(&worker_b, &broadcast.id)
            .expect("worker-b acknowledgement"),
        AcknowledgementOutcome::Acknowledged
    );
    drop(reopened);

    let mut reopened = MessagingBroker::open(&journal, registry, &hierarchy, limits)
        .expect("reopen after all member acknowledgements");
    for credential in [&coordinator, &worker_a, &worker_b] {
        assert!(reopened
            .receive_next_from_channel(credential, "team")
            .expect("durably acknowledged member")
            .is_none());
    }
}

#[test]
fn hierarchy_binding_controls_sender_identity_and_payload_cannot_escalate() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let journal = temporary.path().join("messages.jsonl");
    let hierarchy = hierarchy();
    let (registry, _, worker_a, _, _) = fully_credentialed_credentials();
    let mut broker =
        MessagingBroker::create(&journal, registry, &hierarchy, MessagingLimits::default())
            .expect("create broker");
    let forged_payload = json!({
        "sender_id": "coordinator",
        "sender_role": "delegating_coordinator",
        "role_category": "delegating_coordinator",
        "authority": {"delegate": true, "judge": true}
    });
    let envelope = broker
        .send_direct(&worker_a, "worker-b", forged_payload.clone())
        .expect("worker direct send");
    assert_eq!(envelope.sender_id, "worker-a");
    assert_eq!(
        envelope.sender_role,
        RoleCategory::NonDelegatingTerminalWorker
    );
    assert_eq!(envelope.payload, forged_payload);

    let before_refusal = journal_bytes(&journal);
    match broker
        .create_channel(
            &worker_a,
            "forged-authority",
            ["worker-a", "worker-b"],
            ["worker-a"],
        )
        .expect_err("payload claims cannot grant channel-creation authority")
    {
        MessagingError::UnauthorizedChannelCreator { agent_id } => {
            assert_eq!(agent_id, "worker-a")
        }
        other => panic!("expected UnauthorizedChannelCreator, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), before_refusal);
}

#[test]
fn payload_inspection_and_hostile_depth_are_typed_append_free_and_safely_dropped() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let journal = temporary.path().join("bounded-payloads.jsonl");
    let anchor = journal_sidecar_path(&journal, ".tail-anchor");
    let anchor_temp = journal_sidecar_path(&anchor, ".tmp");
    let hierarchy = hierarchy();
    let mut registry = CredentialRegistry::new(4).expect("credential registry");
    let coordinator = registry
        .register("coordinator", "c".repeat(256))
        .expect("coordinator credential");
    let worker_a = registry
        .register("worker-a", "a".repeat(256))
        .expect("worker-a credential");
    registry
        .register("worker-b", "b".repeat(256))
        .expect("worker-b credential");
    registry
        .register("outsider", "o".repeat(256))
        .expect("outsider credential");
    let limits = MessagingLimits {
        max_payload_bytes: 512 * 1024,
        ..MessagingLimits::default()
    };
    let mut broker = MessagingBroker::create(&journal, registry, &hierarchy, limits)
        .expect("create bounded-payload broker");

    let journal_before = journal_bytes(&journal);
    let anchor_before = fs::read(&anchor).expect("read anchor before inspection refusal");
    match broker
        .send_direct(&coordinator, worker_a.agent_id(), "x".repeat(300_000))
        .expect_err("over-budget credential inspection must be refused")
    {
        MessagingError::PayloadCredentialInspectionLimitExceeded { max_work } => {
            assert_eq!(max_work, 64 * 1024 * 1024)
        }
        other => panic!("expected PayloadCredentialInspectionLimitExceeded, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), journal_before);
    assert_eq!(
        fs::read(&anchor).expect("read anchor after inspection refusal"),
        anchor_before
    );
    assert!(!anchor_temp.exists());

    let mut hostile_depth = Value::Null;
    for _ in 0..256 {
        hostile_depth = Value::Array(vec![hostile_depth]);
    }
    match broker
        .send_direct(&coordinator, worker_a.agent_id(), hostile_depth)
        .expect_err("hostile payload depth must be refused")
    {
        MessagingError::Envelope(EnvelopeValidationError::PayloadNestingTooDeep { max_depth }) => {
            assert_eq!(max_depth, 128)
        }
        other => panic!("expected PayloadNestingTooDeep, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), journal_before);
    assert_eq!(
        fs::read(&anchor).expect("read anchor after hostile-depth refusal"),
        anchor_before
    );
    assert!(!anchor_temp.exists());

    let accepted = broker
        .send_direct(
            &coordinator,
            worker_a.agent_id(),
            json!({"status": "still-usable"}),
        )
        .expect("broker remains usable after iterative hostile-payload drop");
    assert_eq!(accepted.sequence, 1);
}

#[test]
fn journal_partial_and_complete_truncation_reorder_and_tamper_fail_closed() {
    let temporary = tempfile::tempdir().expect("temporary directory");

    let partial_path = temporary.path().join("partial-final-record.jsonl");
    create_attack_journal(&partial_path, &["first", "second"]);
    let mut partial_bytes = journal_bytes(&partial_path);
    assert_eq!(partial_bytes.pop(), Some(b'\n'));
    fs::write(&partial_path, partial_bytes).expect("remove only final newline");
    match open_attack_error(&partial_path, "partial final record") {
        MessagingError::Store(StoreError::TruncatedFinalRecord { record_index }) => {
            assert_eq!(record_index, 2)
        }
        other => panic!("expected TruncatedFinalRecord, got {other:?}"),
    }

    let complete_path = temporary.path().join("complete-final-record.jsonl");
    create_attack_journal(&complete_path, &["first", "second"]);
    let complete_bytes = journal_bytes(&complete_path);
    let final_record_start = complete_bytes[..complete_bytes.len() - 1]
        .iter()
        .rposition(|byte| *byte == b'\n')
        .map(|index| index + 1)
        .expect("journal has a penultimate newline");
    fs::write(&complete_path, &complete_bytes[..final_record_start])
        .expect("remove one complete final record");
    let _ = open_attack_error(
        &complete_path,
        "complete newline-terminated tail removal must fail closed via a durable tail anchor",
    );

    let reorder_path = temporary.path().join("reordered-records.jsonl");
    create_attack_journal(&reorder_path, &["first", "second"]);
    let reorder_bytes = journal_bytes(&reorder_path);
    let mut records = reorder_bytes
        .split_inclusive(|byte| *byte == b'\n')
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 3);
    records.swap(1, 2);
    fs::write(&reorder_path, records.concat()).expect("swap post-creation records");
    match open_attack_error(&reorder_path, "reordered records") {
        MessagingError::Store(StoreError::OutOfOrderSequence {
            record_index,
            expected,
            found,
        }) => {
            assert_eq!(record_index, 1);
            assert_eq!(expected, 1);
            assert_eq!(found, 2);
        }
        other => panic!("expected OutOfOrderSequence, got {other:?}"),
    }

    let payload_path = temporary.path().join("tampered-payload.jsonl");
    create_attack_journal(&payload_path, &["original-payload"]);
    let mut payload_bytes = journal_bytes(&payload_path);
    replace_equal_length_once(&mut payload_bytes, b"original-payload", b"tampered-payload");
    fs::write(&payload_path, payload_bytes).expect("tamper equal-length canonical payload");
    match open_attack_error(&payload_path, "equal-length payload tamper") {
        MessagingError::Store(StoreError::ChecksumMismatch { sequence }) => {
            assert_eq!(sequence, 1)
        }
        other => panic!("expected ChecksumMismatch, got {other:?}"),
    }

    let checksum_path = temporary.path().join("tampered-checksum.jsonl");
    create_attack_journal(&checksum_path, &["checksum-target"]);
    let mut checksum_bytes = journal_bytes(&checksum_path);
    const CHECKSUM_FIELD: &[u8] = b"\"checksum\":\"";
    let checksum_start = checksum_bytes
        .windows(CHECKSUM_FIELD.len())
        .rposition(|candidate| candidate == CHECKSUM_FIELD)
        .map(|index| index + CHECKSUM_FIELD.len())
        .expect("final checksum field");
    let checksum_end = checksum_start + 64;
    let original_checksum = checksum_bytes[checksum_start..checksum_end].to_vec();
    assert_ne!(original_checksum, vec![b'0'; 64]);
    checksum_bytes[checksum_start..checksum_end].fill(b'0');
    fs::write(&checksum_path, checksum_bytes).expect("write well-formed wrong checksum");
    match open_attack_error(&checksum_path, "well-formed checksum tamper") {
        MessagingError::Store(StoreError::ChecksumMismatch { sequence }) => {
            assert_eq!(sequence, 1)
        }
        other => panic!("expected ChecksumMismatch, got {other:?}"),
    }
}

#[test]
#[cfg(any(unix, windows))]
fn relative_path_transplant_between_working_directories_is_refused() {
    const CHILD_MODE: &str = "MACO_MESSAGING_RELATIVE_TRANSPLANT_CHILD";
    const RELATIVE_JOURNAL: &str = "messages.jsonl";

    match std::env::var(CHILD_MODE) {
        Ok(mode) => {
            let hierarchy = hierarchy();
            let limits = MessagingLimits::default();
            let (registry, _, _, _, _) = fully_credentialed_credentials();
            match mode.as_str() {
                "create" => {
                    let broker =
                        MessagingBroker::create(RELATIVE_JOURNAL, registry, &hierarchy, limits)
                            .expect("create relative-path source broker");
                    drop(broker);
                }
                "open-transplant" => {
                    match MessagingBroker::open(RELATIVE_JOURNAL, registry, &hierarchy, limits) {
                        Err(MessagingError::Store(StoreError::BrokerBindingMismatch)) => {}
                        Err(other) => panic!("expected BrokerBindingMismatch, got {other:?}"),
                        Ok(broker) => {
                            drop(broker);
                            panic!("relative-path transplant unexpectedly opened")
                        }
                    }
                }
                other => panic!("unknown relative-transplant child mode {other:?}"),
            }
            return;
        }
        Err(std::env::VarError::NotPresent) => {}
        Err(std::env::VarError::NotUnicode(_)) => {
            panic!("relative-transplant child mode is not Unicode")
        }
    }

    let temporary = tempfile::tempdir().expect("temporary directory");
    let source_directory = temporary.path().join("source-working-directory");
    let target_directory = temporary.path().join("target-working-directory");
    fs::create_dir(&source_directory).expect("create source working directory");
    fs::create_dir(&target_directory).expect("create target working directory");

    let executable = std::env::current_exe().expect("current integration-test executable");
    let create = std::process::Command::new(&executable)
        .arg("--exact")
        .arg("relative_path_transplant_between_working_directories_is_refused")
        .arg("--nocapture")
        .env(CHILD_MODE, "create")
        .current_dir(&source_directory)
        .output()
        .expect("run relative-path creation child");
    assert!(
        create.status.success(),
        "relative-path creation child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&create.stdout),
        String::from_utf8_lossy(&create.stderr)
    );

    let source_journal = source_directory.join(RELATIVE_JOURNAL);
    let target_journal = target_directory.join(RELATIVE_JOURNAL);
    assert!(source_journal.is_file(), "creation child did not run");
    fs::copy(&source_journal, &target_journal).expect("copy authenticated journal");
    fs::copy(
        journal_sidecar_path(&source_journal, ".tail-anchor"),
        journal_sidecar_path(&target_journal, ".tail-anchor"),
    )
    .expect("copy authenticated tail anchor");

    let open = std::process::Command::new(executable)
        .arg("--exact")
        .arg("relative_path_transplant_between_working_directories_is_refused")
        .arg("--nocapture")
        .env(CHILD_MODE, "open-transplant")
        .current_dir(&target_directory)
        .output()
        .expect("run relative-path transplant child");
    assert!(
        open.status.success(),
        "relative-path transplant child failed: stdout={} stderr={}",
        String::from_utf8_lossy(&open.stdout),
        String::from_utf8_lossy(&open.stderr)
    );
}

#[test]
fn equal_length_external_journal_tamper_blocks_append_and_reopen() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let journal = temporary.path().join("equal-length-tamper.jsonl");
    let anchor = journal_sidecar_path(&journal, ".tail-anchor");
    let hierarchy = hierarchy();
    let limits = MessagingLimits::default();
    let (registry, coordinator, _, _, _) = fully_credentialed_credentials();
    let mut broker = MessagingBroker::create(&journal, registry, &hierarchy, limits.clone())
        .expect("create equal-length-tamper broker");
    broker
        .send_direct(
            &coordinator,
            "worker-a",
            json!({"payload": "original-payload"}),
        )
        .expect("append tamper target");

    let anchor_before = fs::read(&anchor).expect("read anchor before external tamper");
    let mut tampered = journal_bytes(&journal);
    replace_equal_length_once(&mut tampered, b"original-payload", b"tampered-payload");
    fs::write(&journal, &tampered).expect("write equal-length external tamper");

    match broker
        .send_direct(&coordinator, "worker-a", json!({"must": "not-append"}))
        .expect_err("equal-length external modification must block append")
    {
        MessagingError::Store(StoreError::ExternalContentModification { expected_bytes }) => {
            assert_eq!(expected_bytes, tampered.len())
        }
        other => panic!("expected ExternalContentModification, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), tampered);
    assert_eq!(
        fs::read(&anchor).expect("read anchor after refused append"),
        anchor_before
    );
    assert!(matches!(
        broker.send_direct(&coordinator, "worker-a", json!({"still": "refused"})),
        Err(MessagingError::Store(StoreError::Poisoned))
    ));
    drop(broker);

    let (registry, _, _, _, _) = fully_credentialed_credentials();
    match MessagingBroker::open(&journal, registry, &hierarchy, limits) {
        Err(MessagingError::Store(StoreError::ChecksumMismatch { sequence })) => {
            assert_eq!(sequence, 1)
        }
        Err(other) => panic!("expected ChecksumMismatch on reopen, got {other:?}"),
        Ok(broker) => {
            drop(broker);
            panic!("equal-length tampered journal unexpectedly reopened")
        }
    }
}

#[test]
fn public_open_refuses_journals_over_byte_and_record_limits() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let hierarchy = hierarchy();
    let limits = MessagingLimits {
        max_credentials: 4,
        max_messages: 16,
        max_channels: 4,
        max_members_per_channel: 4,
        max_publishers_per_channel: 2,
        max_payload_bytes: 1_024,
        max_identifier_bytes: 64,
        max_journal_records: 16,
        max_journal_bytes: 4_096,
        max_delivery_attempts: 4,
    };

    let byte_limited = temporary.path().join("byte-limited.jsonl");
    let (registry, _, _, _, _) = fully_credentialed_credentials();
    let broker = MessagingBroker::create(&byte_limited, registry, &hierarchy, limits.clone())
        .expect("create byte-limited broker");
    drop(broker);
    fs::OpenOptions::new()
        .write(true)
        .open(&byte_limited)
        .expect("open journal for external growth")
        .set_len((limits.max_journal_bytes + 1) as u64)
        .expect("grow journal over byte limit");

    let (registry, _, _, _, _) = fully_credentialed_credentials();
    match MessagingBroker::open(&byte_limited, registry, &hierarchy, limits.clone()) {
        Err(MessagingError::Store(StoreError::JournalByteLimitExceeded { actual, max })) => {
            assert_eq!(actual, limits.max_journal_bytes + 1);
            assert_eq!(max, limits.max_journal_bytes);
        }
        Err(other) => panic!("expected JournalByteLimitExceeded, got {other:?}"),
        Ok(broker) => {
            drop(broker);
            panic!("byte-over-limit journal unexpectedly opened")
        }
    }

    let record_limited = temporary.path().join("record-limited.jsonl");
    let record_limits = MessagingLimits {
        max_journal_records: 1,
        ..limits
    };
    let (registry, _, _, _, _) = fully_credentialed_credentials();
    let broker =
        MessagingBroker::create(&record_limited, registry, &hierarchy, record_limits.clone())
            .expect("create record-limited broker");
    drop(broker);
    fs::OpenOptions::new()
        .append(true)
        .open(&record_limited)
        .expect("open journal for external record growth")
        .write_all(b"\n")
        .expect("grow journal over record limit");

    let (registry, _, _, _, _) = fully_credentialed_credentials();
    match MessagingBroker::open(&record_limited, registry, &hierarchy, record_limits) {
        Err(MessagingError::Store(StoreError::RecordLimitExceeded { actual, max })) => {
            assert_eq!(actual, 2);
            assert_eq!(max, 1);
        }
        Err(other) => panic!("expected RecordLimitExceeded, got {other:?}"),
        Ok(broker) => {
            drop(broker);
            panic!("record-over-limit journal unexpectedly opened")
        }
    }
}

#[test]
fn authority_role_change_is_refused_on_reopen_without_promotion() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let journal = temporary.path().join("authority-binding.jsonl");
    let original_hierarchy = hierarchy();
    let limits = MessagingLimits::default();
    let (registry, _, _, _, _) = fully_credentialed_credentials();
    let broker = MessagingBroker::create(&journal, registry, &original_hierarchy, limits.clone())
        .expect("create authority-bound broker");
    drop(broker);

    let mut promoted_hierarchy = original_hierarchy.clone();
    promoted_hierarchy
        .effective_categories
        .insert("worker-a".to_string(), RoleCategory::DelegatingCoordinator);
    let (registry, _, _, _, _) = fully_credentialed_credentials();
    match MessagingBroker::open(&journal, registry, &promoted_hierarchy, limits.clone()) {
        Err(MessagingError::Store(
            StoreError::BrokerBindingMismatch | StoreError::AuthorityBindingMismatch,
        )) => {}
        Err(other) => panic!("expected an authority binding mismatch, got {other:?}"),
        Ok(broker) => {
            drop(broker);
            panic!("broker reopened with promoted authority")
        }
    }

    let (registry, _, worker_a, _, _) = fully_credentialed_credentials();
    let mut reopened = MessagingBroker::open(&journal, registry, &original_hierarchy, limits)
        .expect("reopen with original authority");
    let before_refusal = journal_bytes(&journal);
    match reopened
        .create_channel(
            &worker_a,
            "promotion-refused",
            ["worker-a", "worker-b"],
            ["worker-a"],
        )
        .expect_err("persisted terminal worker must not gain coordinator authority")
    {
        MessagingError::UnauthorizedChannelCreator { agent_id } => {
            assert_eq!(agent_id, "worker-a")
        }
        other => panic!("expected UnauthorizedChannelCreator, got {other:?}"),
    }
    assert_eq!(journal_bytes(&journal), before_refusal);

    let sent = reopened
        .send_direct(&worker_a, "worker-b", json!({"authority": "unchanged"}))
        .expect("terminal worker remains a valid direct-message sender");
    assert_eq!(sent.sender_role, RoleCategory::NonDelegatingTerminalWorker);
}

#[test]
fn authenticated_tail_anchor_temps_recover_latest_public_message_state() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let hierarchy = hierarchy();
    let limits = MessagingLimits::default();
    let (registry, coordinator, worker_a, _, _) = fully_credentialed_credentials();

    let obsolete_journal = temporary.path().join("obsolete-anchor-temp.jsonl");
    let obsolete_anchor = journal_sidecar_path(&obsolete_journal, ".tail-anchor");
    let obsolete_anchor_temp = journal_sidecar_path(&obsolete_anchor, ".tmp");
    let mut broker = MessagingBroker::create(
        &obsolete_journal,
        registry.clone(),
        &hierarchy,
        limits.clone(),
    )
    .expect("create obsolete-temp broker");
    let earlier_anchor = fs::read(&obsolete_anchor).expect("capture earlier valid anchor");
    let obsolete_payload = json!({"recovery": "obsolete-prefix-temp"});
    let obsolete_sent = broker
        .send_direct(&coordinator, worker_a.agent_id(), obsolete_payload.clone())
        .expect("append message after earlier anchor");
    let committed_latest = fs::read(&obsolete_anchor).expect("capture committed latest anchor");
    drop(broker);
    fs::write(&obsolete_anchor_temp, earlier_anchor)
        .expect("place authenticated obsolete prefix at exact temp path");

    let mut reopened = MessagingBroker::open(
        &obsolete_journal,
        registry.clone(),
        &hierarchy,
        limits.clone(),
    )
    .expect("discard authenticated obsolete temp on reopen");
    assert!(!obsolete_anchor_temp.exists());
    assert_eq!(
        fs::read(&obsolete_anchor).expect("read retained latest anchor"),
        committed_latest
    );
    let obsolete_recovered = reopened
        .receive_next(&worker_a)
        .expect("receive after obsolete-temp recovery")
        .expect("later message survives obsolete-temp recovery");
    assert_eq!(obsolete_recovered.id, obsolete_sent.id);
    assert_eq!(obsolete_recovered.sequence, 1);
    assert_eq!(obsolete_recovered.payload, obsolete_payload);
    drop(reopened);

    let latest_journal = temporary.path().join("latest-anchor-temp.jsonl");
    let latest_anchor = journal_sidecar_path(&latest_journal, ".tail-anchor");
    let latest_anchor_temp = journal_sidecar_path(&latest_anchor, ".tmp");
    let mut broker = MessagingBroker::create(
        &latest_journal,
        registry.clone(),
        &hierarchy,
        limits.clone(),
    )
    .expect("create latest-temp broker");
    let committed_prefix = fs::read(&latest_anchor).expect("capture committed prefix anchor");
    let latest_payload = json!({"recovery": "latest-prepared-temp"});
    let latest_sent = broker
        .send_direct(&coordinator, worker_a.agent_id(), latest_payload.clone())
        .expect("append latest message");
    let prepared_latest = fs::read(&latest_anchor).expect("capture latest authenticated anchor");
    drop(broker);
    fs::write(&latest_anchor, committed_prefix).expect("restore committed prefix anchor");
    fs::write(&latest_anchor_temp, &prepared_latest)
        .expect("place copied latest anchor at exact temp path");

    let mut reopened = MessagingBroker::open(&latest_journal, registry, &hierarchy, limits)
        .expect("publish authenticated latest temp on reopen");
    assert!(!latest_anchor_temp.exists());
    assert_eq!(
        fs::read(&latest_anchor).expect("read published latest anchor"),
        prepared_latest
    );
    let latest_recovered = reopened
        .receive_next(&worker_a)
        .expect("receive after latest-temp publication")
        .expect("latest message survives prepared-temp publication");
    assert_eq!(latest_recovered.id, latest_sent.id);
    assert_eq!(latest_recovered.sequence, 1);
    assert_eq!(latest_recovered.payload, latest_payload);
}

#[test]
fn round_robin_recovers_without_repeated_acceptance_and_stops_at_bound() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("round-robin.json");
    let definition = turn_definition(TurnPolicy::RoundRobin, 3);
    let mut store =
        TurnProtocolStore::create(&path, definition.clone()).expect("create turn store");
    assert_eq!(store.state().completed_turns(), 0);
    assert_eq!(store.state().generation(), 0);
    assert_eq!(store.state().current_speaker(), Some("coordinator"));

    let first_expected = store.state().expectation();
    let first = store
        .complete_turn("coordinator", first_expected)
        .expect("complete coordinator turn");
    assert_eq!(first.receipt.speaker_id(), "coordinator");
    assert_eq!(first.receipt.expected(), first_expected);
    assert_eq!(first.receipt.completed_turns_after(), 1);
    assert_eq!(first.receipt.generation_after(), 1);
    assert_eq!(first.status, TurnProtocolStatus::Active);
    assert_eq!(first.next_speaker.as_deref(), Some("worker-a"));
    drop(store);

    let mut store = TurnProtocolStore::open(&path, &definition).expect("reopen after first turn");
    assert_eq!(store.state().completed_turns(), 1);
    assert_eq!(store.state().generation(), 1);
    assert_eq!(store.state().current_speaker(), Some("worker-a"));
    assert_eq!(store.state().last_speaker(), Some("coordinator"));
    let before_duplicate = turn_state_bytes(&path);
    match store
        .complete_turn("coordinator", first_expected)
        .expect_err("reopened exact completion must remain a duplicate")
    {
        TurnProtocolError::DoubleCompletion {
            speaker_id,
            expected,
        } => {
            assert_eq!(speaker_id, "coordinator");
            assert_eq!(expected, first_expected);
        }
        other => panic!("expected DoubleCompletion, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_duplicate);
    let second_expected = store.state().expectation();
    let second = store
        .complete_turn("worker-a", second_expected)
        .expect("complete worker-a turn");
    assert_eq!(second.receipt.speaker_id(), "worker-a");
    assert_eq!(second.receipt.expected(), second_expected);
    assert_eq!(second.receipt.completed_turns_after(), 2);
    assert_eq!(second.receipt.generation_after(), 2);
    assert_eq!(second.status, TurnProtocolStatus::Active);
    assert_eq!(second.next_speaker.as_deref(), Some("worker-b"));
    assert_ne!(first.receipt, second.receipt);
    drop(store);

    let mut store = TurnProtocolStore::open(&path, &definition).expect("reopen after second turn");
    assert_eq!(store.state().completed_turns(), 2);
    assert_eq!(store.state().generation(), 2);
    assert_eq!(store.state().current_speaker(), Some("worker-b"));
    assert_eq!(store.state().last_speaker(), Some("worker-a"));
    let third_expected = store.state().expectation();
    let third = store
        .complete_turn("worker-b", third_expected)
        .expect("complete worker-b turn");
    let completed_status = TurnProtocolStatus::Completed {
        reason: TurnCompletionReason::MaximumTurnsReached,
    };
    assert_eq!(third.receipt.speaker_id(), "worker-b");
    assert_eq!(third.receipt.expected(), third_expected);
    assert_eq!(third.receipt.completed_turns_after(), 3);
    assert_eq!(third.receipt.generation_after(), 3);
    assert_eq!(third.status, completed_status);
    assert_eq!(third.next_speaker, None);
    assert_ne!(first.receipt, third.receipt);
    assert_ne!(second.receipt, third.receipt);
    assert_eq!(store.state().completed_turns(), 3);
    assert_eq!(store.state().generation(), 3);
    assert_eq!(store.state().current_speaker(), None);
    assert_eq!(store.state().last_speaker(), Some("worker-b"));
    drop(store);

    let mut reopened = TurnProtocolStore::open(&path, &definition).expect("reopen completed turn");
    assert_eq!(reopened.state().status(), &completed_status);
    assert_eq!(reopened.state().completed_turns(), 3);
    assert_eq!(reopened.state().generation(), 3);
    assert_eq!(reopened.state().current_speaker(), None);
    match reopened
        .complete_turn("coordinator", reopened.state().expectation())
        .expect_err("completed protocol must refuse further completion")
    {
        TurnProtocolError::NotActive { status } => assert_eq!(status, completed_status),
        other => panic!("expected NotActive, got {other:?}"),
    }
}

#[test]
fn round_robin_wrong_speaker_stale_and_double_completion_fail_closed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("round-robin-refusals.json");
    let definition = turn_definition(TurnPolicy::RoundRobin, 3);
    let mut store = TurnProtocolStore::create(&path, definition).expect("create turn store");
    let initial_expected = store.state().expectation();

    let before_refusal = turn_state_bytes(&path);
    match store
        .complete_turn("worker-a", initial_expected)
        .expect_err("wrong round-robin speaker must be refused")
    {
        TurnProtocolError::WrongSpeaker {
            selected_speaker,
            actual_speaker,
        } => {
            assert_eq!(selected_speaker, "coordinator");
            assert_eq!(actual_speaker, "worker-a");
        }
        other => panic!("expected WrongSpeaker, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    store
        .complete_turn("coordinator", initial_expected)
        .expect("accept coordinator turn");

    let before_refusal = turn_state_bytes(&path);
    match store
        .complete_turn("coordinator", initial_expected)
        .expect_err("exact retry must be refused as a duplicate")
    {
        TurnProtocolError::DoubleCompletion {
            speaker_id,
            expected,
        } => {
            assert_eq!(speaker_id, "coordinator");
            assert_eq!(expected, initial_expected);
        }
        other => panic!("expected DoubleCompletion, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    let before_refusal = turn_state_bytes(&path);
    match store
        .complete_turn("worker-a", initial_expected)
        .expect_err("old generation must be refused")
    {
        TurnProtocolError::StaleGeneration { expected, actual } => {
            assert_eq!(expected, 0);
            assert_eq!(actual, 1);
        }
        other => panic!("expected StaleGeneration, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    let current_expected = store.state().expectation();
    let stale_counter = TurnExpectation::new(
        current_expected.completed_turns - 1,
        current_expected.generation,
    );
    let before_refusal = turn_state_bytes(&path);
    match store
        .complete_turn("worker-a", stale_counter)
        .expect_err("old completed-turn counter must be refused")
    {
        TurnProtocolError::StaleCompletedTurnCounter { expected, actual } => {
            assert_eq!(expected, stale_counter.completed_turns);
            assert_eq!(actual, current_expected.completed_turns);
        }
        other => panic!("expected StaleCompletedTurnCounter, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);
}

#[test]
fn model_selected_accepts_only_eligible_explicit_speakers_deterministically() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("model-selected.json");
    let definition = turn_definition(TurnPolicy::ModelSelected, 2);
    let mut store =
        TurnProtocolStore::create(&path, definition.clone()).expect("create turn store");
    assert_eq!(store.state().selected_speaker(), None);
    assert_eq!(store.state().current_speaker(), None);
    assert_eq!(store.state().completed_turns(), 0);
    assert_eq!(store.state().generation(), 0);

    let before_refusal = turn_state_bytes(&path);
    match store
        .complete_turn("worker-a", store.state().expectation())
        .expect_err("completion without an explicit speaker must be refused")
    {
        TurnProtocolError::NoSpeakerSelected => {}
        other => panic!("expected NoSpeakerSelected, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    let before_refusal = turn_state_bytes(&path);
    match store
        .select_speaker("outsider", store.state().expectation())
        .expect_err("nonparticipant selection must be refused")
    {
        TurnProtocolError::InvalidSelection { participant_id } => {
            assert_eq!(participant_id, "outsider")
        }
        other => panic!("expected InvalidSelection, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    let selected = store
        .select_speaker("worker-a", store.state().expectation())
        .expect("select worker-a");
    assert_eq!(selected.selected_speaker, "worker-a");
    assert_eq!(selected.completed_turns, 0);
    assert_eq!(selected.generation, 1);
    drop(store);

    let mut reopened = TurnProtocolStore::open(&path, &definition).expect("reopen selection");
    assert_eq!(reopened.state().selected_speaker(), Some("worker-a"));
    assert_eq!(reopened.state().current_speaker(), Some("worker-a"));
    assert_eq!(reopened.state().completed_turns(), 0);
    assert_eq!(reopened.state().generation(), 1);
    let selected_expected = reopened.state().expectation();

    let before_refusal = turn_state_bytes(&path);
    match reopened
        .select_speaker("worker-b", selected_expected)
        .expect_err("a second selection for the same turn must be refused")
    {
        TurnProtocolError::SpeakerAlreadySelected { speaker_id } => {
            assert_eq!(speaker_id, "worker-a")
        }
        other => panic!("expected SpeakerAlreadySelected, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    let before_refusal = turn_state_bytes(&path);
    match reopened
        .complete_turn("worker-b", selected_expected)
        .expect_err("only the model-selected speaker may complete")
    {
        TurnProtocolError::WrongSpeaker {
            selected_speaker,
            actual_speaker,
        } => {
            assert_eq!(selected_speaker, "worker-a");
            assert_eq!(actual_speaker, "worker-b");
        }
        other => panic!("expected WrongSpeaker, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    let completion = reopened
        .complete_turn("worker-a", selected_expected)
        .expect("complete selected speaker");
    assert_eq!(completion.receipt.speaker_id(), "worker-a");
    assert_eq!(completion.receipt.expected(), selected_expected);
    assert_eq!(completion.receipt.completed_turns_after(), 1);
    assert_eq!(completion.receipt.generation_after(), 2);
    assert_eq!(completion.status, TurnProtocolStatus::Active);
    assert_eq!(completion.next_speaker, None);
}

#[test]
fn graph_selected_accepts_only_eligible_speakers_deterministically() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("graph-selected.json");
    let graph = SpeakerGraph::new(
        "coordinator",
        BTreeMap::from([
            ("coordinator".to_string(), vec!["worker-a".to_string()]),
            ("worker-a".to_string(), vec!["worker-b".to_string()]),
            ("worker-b".to_string(), vec!["coordinator".to_string()]),
        ]),
    );
    let definition = turn_definition(TurnPolicy::GraphSelected { graph }, 4);
    let mut store =
        TurnProtocolStore::create(&path, definition.clone()).expect("create turn store");
    assert_eq!(store.state().current_speaker(), Some("coordinator"));

    let before_refusal = turn_state_bytes(&path);
    match store
        .select_speaker("worker-a", store.state().expectation())
        .expect_err("graph-selected policy must refuse explicit selection")
    {
        TurnProtocolError::SelectionNotAllowed { policy } => {
            assert_eq!(policy, definition.policy().kind())
        }
        other => panic!("expected SelectionNotAllowed, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    let before_refusal = turn_state_bytes(&path);
    match store
        .complete_turn("worker-a", store.state().expectation())
        .expect_err("wrong graph speaker must be refused")
    {
        TurnProtocolError::WrongSpeaker {
            selected_speaker,
            actual_speaker,
        } => {
            assert_eq!(selected_speaker, "coordinator");
            assert_eq!(actual_speaker, "worker-a");
        }
        other => panic!("expected WrongSpeaker, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    let first_expected = store.state().expectation();
    let first = store
        .complete_turn("coordinator", first_expected)
        .expect("complete graph coordinator");
    assert_eq!(first.next_speaker.as_deref(), Some("worker-a"));
    assert_eq!(first.receipt.completed_turns_after(), 1);
    assert_eq!(first.receipt.generation_after(), 1);
    drop(store);

    let mut store = TurnProtocolStore::open(&path, &definition).expect("reopen at worker-a");
    assert_eq!(store.state().current_speaker(), Some("worker-a"));
    assert_eq!(store.state().completed_turns(), 1);
    assert_eq!(store.state().generation(), 1);
    let second = store
        .complete_turn("worker-a", store.state().expectation())
        .expect("complete graph worker-a");
    assert_eq!(second.next_speaker.as_deref(), Some("worker-b"));
    drop(store);

    let mut store = TurnProtocolStore::open(&path, &definition).expect("reopen at worker-b");
    assert_eq!(store.state().current_speaker(), Some("worker-b"));
    assert_eq!(store.state().completed_turns(), 2);
    assert_eq!(store.state().generation(), 2);
    let third = store
        .complete_turn("worker-b", store.state().expectation())
        .expect("complete graph worker-b");
    assert_eq!(third.next_speaker.as_deref(), Some("coordinator"));
    drop(store);

    let reopened = TurnProtocolStore::open(&path, &definition).expect("reopen at coordinator");
    assert_eq!(reopened.state().current_speaker(), Some("coordinator"));
    assert_eq!(reopened.state().last_speaker(), Some("worker-b"));
    assert_eq!(reopened.state().completed_turns(), 3);
    assert_eq!(reopened.state().generation(), 3);
}

#[test]
fn free_form_accepts_only_eligible_explicit_speakers_deterministically() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("free-form.json");
    let definition = turn_definition(TurnPolicy::FreeForm, 2);
    let mut store =
        TurnProtocolStore::create(&path, definition.clone()).expect("create turn store");
    assert_eq!(store.state().selected_speaker(), None);
    assert_eq!(store.state().current_speaker(), None);

    let before_refusal = turn_state_bytes(&path);
    match store
        .select_speaker("outsider", store.state().expectation())
        .expect_err("free-form nonparticipant must be refused")
    {
        TurnProtocolError::InvalidSelection { participant_id } => {
            assert_eq!(participant_id, "outsider")
        }
        other => panic!("expected InvalidSelection, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    let selection = store
        .select_speaker("worker-b", store.state().expectation())
        .expect("select worker-b");
    assert_eq!(selection.selected_speaker, "worker-b");
    assert_eq!(selection.completed_turns, 0);
    assert_eq!(selection.generation, 1);
    drop(store);

    let mut reopened = TurnProtocolStore::open(&path, &definition).expect("reopen free-form");
    assert_eq!(reopened.state().selected_speaker(), Some("worker-b"));
    assert_eq!(reopened.state().current_speaker(), Some("worker-b"));
    assert_eq!(reopened.state().completed_turns(), 0);
    assert_eq!(reopened.state().generation(), 1);
    let selected_expected = reopened.state().expectation();

    let before_refusal = turn_state_bytes(&path);
    match reopened
        .complete_turn("worker-a", selected_expected)
        .expect_err("only the free-form selected speaker may complete")
    {
        TurnProtocolError::WrongSpeaker {
            selected_speaker,
            actual_speaker,
        } => {
            assert_eq!(selected_speaker, "worker-b");
            assert_eq!(actual_speaker, "worker-a");
        }
        other => panic!("expected WrongSpeaker, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);

    let completion = reopened
        .complete_turn("worker-b", selected_expected)
        .expect("complete free-form selected speaker");
    assert_eq!(completion.receipt.speaker_id(), "worker-b");
    assert_eq!(completion.receipt.expected(), selected_expected);
    assert_eq!(completion.receipt.completed_turns_after(), 1);
    assert_eq!(completion.receipt.generation_after(), 2);
    assert_eq!(completion.next_speaker, None);
}

#[test]
fn turn_definitions_and_graph_runtime_failures_are_typed_and_non_mutating() {
    let invalid_participant = TurnProtocolDefinition::new(
        "session-1",
        "protocol-1",
        vec![TurnParticipant::new(
            "invalid participant",
            RoleCategory::NonDelegatingTerminalWorker,
        )],
        TurnPolicy::RoundRobin,
        2,
        TurnProtocolLimits::default(),
    )
    .expect_err("invalid participant must be refused");
    match invalid_participant {
        TurnDefinitionError::InvalidParticipant { participant_id } => {
            assert_eq!(participant_id, "invalid participant")
        }
        other => panic!("expected InvalidParticipant, got {other:?}"),
    }

    let duplicate_participant = TurnProtocolDefinition::new(
        "session-1",
        "protocol-1",
        vec![
            TurnParticipant::new("worker-a", RoleCategory::NonDelegatingTerminalWorker),
            TurnParticipant::new("worker-a", RoleCategory::ReadOnlyReviewAuditor),
        ],
        TurnPolicy::RoundRobin,
        2,
        TurnProtocolLimits::default(),
    )
    .expect_err("duplicate participant must be refused");
    match duplicate_participant {
        TurnDefinitionError::DuplicateParticipant { participant_id } => {
            assert_eq!(participant_id, "worker-a")
        }
        other => panic!("expected DuplicateParticipant, got {other:?}"),
    }

    let invalid_graph = SpeakerGraph::new(
        "coordinator",
        BTreeMap::from([("coordinator".to_string(), vec!["outsider".to_string()])]),
    );
    let invalid_graph = TurnProtocolDefinition::new(
        "session-1",
        "protocol-1",
        turn_participants(),
        TurnPolicy::GraphSelected {
            graph: invalid_graph,
        },
        2,
        TurnProtocolLimits::default(),
    )
    .expect_err("graph transition outside the participants must be refused");
    match invalid_graph {
        TurnDefinitionError::InvalidGraphTransition { from, to } => {
            assert_eq!(from, "coordinator");
            assert_eq!(to, "outsider");
        }
        other => panic!("expected InvalidGraphTransition, got {other:?}"),
    }

    let temporary = tempfile::tempdir().expect("temporary directory");
    let missing_path = temporary.path().join("missing-transition.json");
    let missing_definition = turn_definition(
        TurnPolicy::GraphSelected {
            graph: SpeakerGraph::new("coordinator", BTreeMap::new()),
        },
        2,
    );
    let mut missing =
        TurnProtocolStore::create(&missing_path, missing_definition).expect("create missing graph");
    let before_refusal = turn_state_bytes(&missing_path);
    match missing
        .complete_turn("coordinator", missing.state().expectation())
        .expect_err("missing runtime transition must be refused")
    {
        TurnProtocolError::MissingGraphTransition { from } => {
            assert_eq!(from, "coordinator")
        }
        other => panic!("expected MissingGraphTransition, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&missing_path), before_refusal);
    assert_eq!(missing.state().completed_turns(), 0);

    let ambiguous_path = temporary.path().join("ambiguous-transition.json");
    let choices = vec!["worker-a".to_string(), "worker-b".to_string()];
    let ambiguous_definition = turn_definition(
        TurnPolicy::GraphSelected {
            graph: SpeakerGraph::new(
                "coordinator",
                BTreeMap::from([("coordinator".to_string(), choices.clone())]),
            ),
        },
        2,
    );
    let mut ambiguous = TurnProtocolStore::create(&ambiguous_path, ambiguous_definition)
        .expect("create ambiguous graph");
    let before_refusal = turn_state_bytes(&ambiguous_path);
    match ambiguous
        .complete_turn("coordinator", ambiguous.state().expectation())
        .expect_err("ambiguous runtime transition must be refused")
    {
        TurnProtocolError::AmbiguousGraphTransition {
            from,
            choices: actual,
        } => {
            assert_eq!(from, "coordinator");
            assert_eq!(actual, choices);
        }
        other => panic!("expected AmbiguousGraphTransition, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&ambiguous_path), before_refusal);
    assert_eq!(ambiguous.state().completed_turns(), 0);
}

#[test]
fn explicit_termination_is_durable_across_reopen() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("terminated.json");
    let definition = turn_definition(TurnPolicy::RoundRobin, 3);
    let mut store =
        TurnProtocolStore::create(&path, definition.clone()).expect("create turn store");
    let terminated_status = TurnProtocolStatus::Terminated {
        reason: "operator requested stop".to_string(),
    };
    let terminated = store
        .terminate("operator requested stop", store.state().expectation())
        .expect("terminate protocol");
    assert_eq!(terminated.status, terminated_status);
    assert_eq!(terminated.completed_turns, 0);
    assert_eq!(terminated.generation, 1);
    assert_eq!(store.state().current_speaker(), None);
    drop(store);

    let mut reopened =
        TurnProtocolStore::open(&path, &definition).expect("reopen terminated state");
    assert_eq!(reopened.state().status(), &terminated_status);
    assert_eq!(reopened.state().completed_turns(), 0);
    assert_eq!(reopened.state().generation(), 1);
    assert_eq!(reopened.state().current_speaker(), None);
    let before_refusal = turn_state_bytes(&path);
    match reopened
        .complete_turn("coordinator", reopened.state().expectation())
        .expect_err("terminated protocol must refuse completion")
    {
        TurnProtocolError::NotActive { status } => assert_eq!(status, terminated_status),
        other => panic!("expected NotActive, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&path), before_refusal);
}

#[test]
fn corrupt_turn_state_is_refused_with_typed_checksum_error() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let path = temporary.path().join("corrupt.json");
    let definition = turn_definition(TurnPolicy::RoundRobin, 3);
    TurnProtocolStore::create(&path, definition.clone()).expect("create turn store");
    let mut document: Value =
        serde_json::from_slice(&turn_state_bytes(&path)).expect("parse persisted turn document");
    document["state"]["generation"] = json!(1);
    fs::write(
        &path,
        serde_json::to_vec(&document).expect("serialize corrupted turn document"),
    )
    .expect("write corrupted turn document");

    match TurnProtocolStore::open(&path, &definition) {
        Err(TurnProtocolError::ChecksumMismatch) => {}
        Err(other) => panic!("expected ChecksumMismatch, got {other:?}"),
        Ok(_) => panic!("corrupt turn state unexpectedly opened"),
    }
}

#[test]
fn checksum_consistent_turn_invariant_corruption_is_refused() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let completed_path = temporary.path().join("completed-selection-count.json");
    let completed_definition = turn_definition(TurnPolicy::ModelSelected, 1);
    let mut completed = TurnProtocolStore::create(&completed_path, completed_definition.clone())
        .expect("create completed-selection store");
    completed
        .select_speaker("worker-a", completed.state().expectation())
        .expect("select final speaker");
    completed
        .complete_turn("worker-a", completed.state().expectation())
        .expect("complete final speaker");
    drop(completed);

    let mut completed_bytes = turn_state_bytes(&completed_path);
    replace_equal_length_once(
        &mut completed_bytes,
        b"\"completed_turns\":1,\"selection_count\":1,\"generation\":2",
        b"\"completed_turns\":1,\"selection_count\":2,\"generation\":3",
    );
    refresh_turn_state_checksum(&mut completed_bytes);
    fs::write(&completed_path, completed_bytes).expect("write checksum-consistent count tamper");
    match TurnProtocolStore::open(&completed_path, &completed_definition) {
        Err(TurnProtocolError::CorruptState { detail }) => {
            assert!(
                detail.contains("selection count"),
                "unexpected detail: {detail}"
            )
        }
        Err(other) => panic!("expected CorruptState, got {other:?}"),
        Ok(_) => panic!("completed state with a pending selection unexpectedly opened"),
    }

    let receipt_path = temporary.path().join("receipt-generation.json");
    let receipt_definition = turn_definition(TurnPolicy::FreeForm, 3);
    let mut receipt_store = TurnProtocolStore::create(&receipt_path, receipt_definition.clone())
        .expect("create receipt store");
    receipt_store
        .select_speaker("worker-a", receipt_store.state().expectation())
        .expect("select completed speaker");
    receipt_store
        .complete_turn("worker-a", receipt_store.state().expectation())
        .expect("complete selected speaker");
    receipt_store
        .select_speaker("worker-b", receipt_store.state().expectation())
        .expect("select pending speaker");
    receipt_store
        .terminate("operator stop", receipt_store.state().expectation())
        .expect("terminate with pending selection");
    drop(receipt_store);

    let mut receipt_bytes = turn_state_bytes(&receipt_path);
    replace_equal_length_once(
        &mut receipt_bytes,
        b"\"expected\":{\"completed_turns\":0,\"generation\":1},\"completed_turns_after\":1,\"generation_after\":2",
        b"\"expected\":{\"completed_turns\":0,\"generation\":2},\"completed_turns_after\":1,\"generation_after\":3",
    );
    refresh_turn_state_checksum(&mut receipt_bytes);
    fs::write(&receipt_path, receipt_bytes).expect("write checksum-consistent receipt tamper");
    match TurnProtocolStore::open(&receipt_path, &receipt_definition) {
        Err(TurnProtocolError::CorruptState { detail }) => {
            assert!(
                detail.contains("last completion receipt"),
                "unexpected detail: {detail}"
            )
        }
        Err(other) => panic!("expected CorruptState, got {other:?}"),
        Ok(_) => panic!("state with a forged receipt generation unexpectedly opened"),
    }
}

#[test]
fn selected_turn_speaker_composes_with_authenticated_send_and_refuses_unselected_principal() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let turn_path = temporary.path().join("selected-turn.json");
    let message_path = temporary.path().join("messages.jsonl");
    let definition = turn_definition(TurnPolicy::ModelSelected, 2);
    let mut turns =
        TurnProtocolStore::create(&turn_path, definition.clone()).expect("create turn protocol");
    let hierarchy = hierarchy();
    let (registry, _, worker_a, worker_b, _) = fully_credentialed_credentials();
    turns
        .select_speaker(worker_a.agent_id(), turns.state().expectation())
        .expect("select worker-a");
    let selected_expected = turns.state().expectation();

    let mut broker = MessagingBroker::create(
        &message_path,
        registry,
        &hierarchy,
        MessagingLimits::default(),
    )
    .expect("create messaging broker");
    let turn_before_authorization = turn_state_bytes(&turn_path);
    let messages_before_authorization = journal_bytes(&message_path);

    match turns.with_authorized_speaker(worker_b.agent_id(), selected_expected, || {
        broker.send_direct(
            &worker_b,
            worker_a.agent_id(),
            json!({"action": "unselected-send"}),
        )
    }) {
        Err(TurnProtocolError::WrongSpeaker {
            selected_speaker,
            actual_speaker,
        }) => {
            assert_eq!(selected_speaker, worker_a.agent_id());
            assert_eq!(actual_speaker, worker_b.agent_id());
        }
        Err(other) => panic!("expected WrongSpeaker, got {other:?}"),
        Ok(_) => panic!("unselected principal authorization must be refused"),
    }
    assert_eq!(turn_state_bytes(&turn_path), turn_before_authorization);
    assert_eq!(journal_bytes(&message_path), messages_before_authorization);

    let forged_worker_a = PresentedCredential::new(worker_a.agent_id(), "forged-worker-a-secret")
        .expect("well-formed forged credential");
    match turns
        .with_authorized_speaker(forged_worker_a.agent_id(), selected_expected, || {
            broker.send_direct(
                &forged_worker_a,
                worker_b.agent_id(),
                json!({"action": "forged-send"}),
            )
        })
        .expect("turn authorization checks the selected identity")
        .expect_err("forged selected-principal credential must be refused")
    {
        MessagingError::BadCredential { agent_id } => {
            assert_eq!(agent_id, worker_a.agent_id())
        }
        other => panic!("expected BadCredential, got {other:?}"),
    }
    assert_eq!(turn_state_bytes(&turn_path), turn_before_authorization);
    assert_eq!(journal_bytes(&message_path), messages_before_authorization);

    let payload = json!({"turn": selected_expected.generation, "action": "send"});
    let mut advancing =
        TurnProtocolStore::open(&turn_path, &definition).expect("open second turn handle");
    let (scope_started_tx, scope_started_rx) = mpsc::sync_channel(0);
    let (release_scope_tx, release_scope_rx) = mpsc::sync_channel(0);
    let scoped_worker_a = worker_a.clone();
    let scoped_worker_b = worker_b.clone();
    let scoped_payload = payload.clone();
    let scoped_send = thread::spawn(move || {
        let result =
            turns.with_authorized_speaker(scoped_worker_a.agent_id(), selected_expected, || {
                let result = broker.send_direct(
                    &scoped_worker_a,
                    scoped_worker_b.agent_id(),
                    scoped_payload,
                );
                scope_started_tx
                    .send(())
                    .expect("announce entered authorization scope");
                release_scope_rx
                    .recv_timeout(Duration::from_secs(5))
                    .expect("authorization scope release");
                result
            });
        (turns, broker, result)
    });

    scope_started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("authorized append began");
    assert_eq!(turn_state_bytes(&turn_path), turn_before_authorization);
    assert_ne!(journal_bytes(&message_path), messages_before_authorization);

    let (advancement_attempt_tx, advancement_attempt_rx) = mpsc::sync_channel(0);
    let (advancement_done_tx, advancement_done_rx) = mpsc::sync_channel(0);
    let advancing_worker_a = worker_a.clone();
    let advancing_worker_b = worker_b.clone();
    let advancement = thread::spawn(move || {
        advancement_attempt_tx
            .send(())
            .expect("announce turn advancement attempt");
        let completion = advancing
            .complete_turn(advancing_worker_a.agent_id(), selected_expected)
            .expect("complete after authorization scope releases");
        let reselection = advancing
            .select_speaker(
                advancing_worker_b.agent_id(),
                advancing.state().expectation(),
            )
            .expect("reselect after completion");
        advancement_done_tx
            .send((completion, reselection))
            .expect("report completed advancement");
        advancing
    });

    advancement_attempt_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("second handle attempted advancement");
    match advancement_done_rx.recv_timeout(Duration::from_millis(100)) {
        Err(RecvTimeoutError::Timeout) => {}
        Err(RecvTimeoutError::Disconnected) => {
            panic!("turn advancement worker disconnected while the scope was locked")
        }
        Ok(_) => panic!("turn advancement completed before authorization scope release"),
    }
    release_scope_tx
        .send(())
        .expect("release authorization scope");

    let (completion, reselection) = advancement_done_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("turn advancement completes after scope release");
    let advancing = advancement.join().expect("join advancement worker");
    let (_, _, protected_send) = scoped_send.join().expect("join authorized send worker");
    let envelope = protected_send
        .expect("selected speaker remains authorized through append")
        .expect("authenticated selected-speaker send");
    assert_eq!(envelope.sender_id, worker_a.agent_id());
    assert_eq!(
        envelope.sender_role,
        RoleCategory::NonDelegatingTerminalWorker
    );
    assert_eq!(envelope.payload, payload);
    assert_eq!(completion.receipt.expected(), selected_expected);
    assert_eq!(reselection.selected_speaker, worker_b.agent_id());
    assert_eq!(
        advancing.state().current_speaker(),
        Some(worker_b.agent_id())
    );
    assert_eq!(
        advancing.state().participant_role(worker_a.agent_id()),
        Some(RoleCategory::NonDelegatingTerminalWorker)
    );
}
