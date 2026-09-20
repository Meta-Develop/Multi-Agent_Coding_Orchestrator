use git2::Repository;
use multi_agent_coding_orchestrator::{
    decision_claim::{
        DecisionClaimError, DecisionClaimStatus, DecisionInputField, DecisionRecord,
        DecisionRegistry, DecisionRegistrySnapshot, DecisionScope,
    },
    decision_ref::{
        check_decision_ref, check_required_decision_ref, check_required_decision_ref_in_store,
        parse_decision_ref_cli, DecisionRef, DecisionRefError, StaleDecisionRefReason,
    },
};

fn scope(modules: &[&str], symbols: &[&str], topics: &[&str]) -> DecisionScope {
    DecisionScope::new(
        modules.iter().map(|value| (*value).to_string()),
        symbols.iter().map(|value| (*value).to_string()),
        topics.iter().map(|value| (*value).to_string()),
    )
    .expect("valid test scope")
}

fn resolved_registry() -> DecisionRegistry {
    let registry = DecisionRegistry::new();
    registry
        .claim_open(
            "api.transport",
            "Which transport should the API use?",
            "planner-a",
        )
        .expect("open claim");
    registry
        .resolve_claim(
            "api.transport",
            "planner-a",
            "Use HTTP",
            scope(&["api"], &[], &[]),
        )
        .expect("resolve claim");
    registry
}

#[test]
fn matching_resolved_question_key_passes() {
    let registry = resolved_registry();
    let reference = DecisionRef::new("api.transport").expect("valid reference");

    let record = check_decision_ref(&registry, &reference).expect("matching resolved ref");

    assert_eq!(record.question_key(), "api.transport");
    assert_eq!(record.resolution(), "Use HTTP");
    assert_eq!(record.deciding_assignment(), "planner-a");
    assert_eq!(record.scope(), &scope(&["api"], &[], &[]));
}

#[test]
fn matching_resolved_ref_accepts_expected_resolution_and_normalized_key() {
    let registry = resolved_registry();
    let reference = DecisionRef::new("  api.transport  ")
        .expect("trimmed key")
        .with_expected_resolution("  Use HTTP  ")
        .expect("trimmed resolution");

    let record = check_decision_ref(&registry, &reference).expect("normalized matching ref");
    assert_eq!(record.question_key(), "api.transport");
    assert_eq!(record.resolution(), "Use HTTP");
}

#[test]
fn missing_ref_fails_closed() {
    let registry = resolved_registry();

    assert_eq!(
        check_required_decision_ref(&registry, None).expect_err("missing ref"),
        DecisionRefError::MissingRef
    );
}

#[test]
fn missing_question_key_fails_closed() {
    let registry = resolved_registry();
    let reference = DecisionRef::new("storage.engine").expect("valid unused key");

    assert_eq!(
        check_decision_ref(&registry, &reference).expect_err("unknown key"),
        DecisionRefError::MissingQuestionKey {
            question_key: "storage.engine".to_string(),
        }
    );
}

#[test]
fn empty_and_invalid_question_keys_fail_closed() {
    assert_eq!(
        DecisionRef::new("").expect_err("empty key"),
        DecisionRefError::InvalidCitation(DecisionClaimError::EmptyInput {
            field: DecisionInputField::QuestionKey,
        })
    );
    assert_eq!(
        DecisionRef::new("   ").expect_err("whitespace key"),
        DecisionRefError::InvalidCitation(DecisionClaimError::EmptyInput {
            field: DecisionInputField::QuestionKey,
        })
    );
    assert_eq!(
        DecisionRef::new("api transport").expect_err("invalid key"),
        DecisionRefError::InvalidCitation(DecisionClaimError::InvalidInput {
            field: DecisionInputField::QuestionKey,
        })
    );
}

#[test]
fn stale_wrong_resolution_fails_closed() {
    let registry = resolved_registry();
    let reference = DecisionRef::new("api.transport")
        .expect("valid key")
        .with_expected_resolution("Use a local socket")
        .expect("valid resolution");

    assert_eq!(
        check_decision_ref(&registry, &reference).expect_err("stale resolution"),
        DecisionRefError::StaleRef {
            question_key: "api.transport".to_string(),
            reason: StaleDecisionRefReason::ResolutionMismatch {
                expected: "Use a local socket".to_string(),
                actual: "Use HTTP".to_string(),
            },
        }
    );
}

#[test]
fn superseded_claim_is_not_a_resolved_target() {
    let registry = DecisionRegistry::new();
    registry
        .claim_open(
            "api.transport",
            "Which transport should the API use?",
            "planner-a",
        )
        .expect("open claim");
    registry
        .supersede_claim("api.transport", "planner-a", Some("abandoned"))
        .expect("supersede claim");
    let reference = DecisionRef::new("api.transport").expect("valid key");

    assert_eq!(
        check_decision_ref(&registry, &reference).expect_err("superseded claim"),
        DecisionRefError::StaleRef {
            question_key: "api.transport".to_string(),
            reason: StaleDecisionRefReason::ClaimNotResolved {
                status: DecisionClaimStatus::Superseded,
            },
        }
    );
}

#[test]
fn resolved_claim_without_a_record_is_never_resolved() {
    let registry = resolved_registry();
    let snapshot = registry.snapshot().expect("snapshot");
    let registry = DecisionRegistry::from_snapshot(DecisionRegistrySnapshot {
        claims: snapshot.claims,
        records: Vec::new(),
    })
    .expect("resolved claim without a record");
    let reference = DecisionRef::new("api.transport").expect("valid key");

    assert_eq!(
        check_decision_ref(&registry, &reference).expect_err("never resolved"),
        DecisionRefError::StaleRef {
            question_key: "api.transport".to_string(),
            reason: StaleDecisionRefReason::NeverResolved,
        }
    );
}

#[test]
fn resolved_claim_identity_must_match_persisted_record() {
    let leftover = DecisionRecord::new(
        "api.transport",
        "Use a local socket",
        "planner-b",
        scope(&["api"], &[], &[]),
    )
    .expect("leftover record");
    let snapshot = resolved_registry().snapshot().expect("snapshot");
    let registry = DecisionRegistry::from_snapshot(DecisionRegistrySnapshot {
        claims: snapshot.claims,
        records: vec![leftover],
    })
    .expect("resolved claim with mismatched leftover record");
    let reference = DecisionRef::new("api.transport").expect("valid key");

    assert_eq!(
        check_decision_ref(&registry, &reference).expect_err("identity mismatch"),
        DecisionRefError::StaleRef {
            question_key: "api.transport".to_string(),
            reason: StaleDecisionRefReason::NeverResolved,
        }
    );
}

#[test]
fn leftover_record_is_stale_after_claim_is_superseded() {
    let leftover = DecisionRecord::new(
        "api.transport",
        "Use HTTP",
        "planner-a",
        scope(&["api"], &[], &[]),
    )
    .expect("leftover record");
    let registry = DecisionRegistry::new();
    registry
        .claim_open(
            "api.transport",
            "Which transport should the API use?",
            "planner-a",
        )
        .expect("open claim");
    registry
        .supersede_claim("api.transport", "planner-a", Some("abandoned"))
        .expect("supersede claim");

    // A later snapshot may still carry an older record after the live claim
    // was superseded; that identity is no longer a valid resolved target.
    let snapshot = registry.snapshot().expect("snapshot");
    let registry = DecisionRegistry::from_snapshot(DecisionRegistrySnapshot {
        claims: snapshot.claims,
        records: vec![leftover],
    })
    .expect("superseded claim with leftover record");
    let reference = DecisionRef::new("api.transport")
        .expect("valid key")
        .with_expected_resolution("Use HTTP")
        .expect("old resolution");

    assert_eq!(
        check_decision_ref(&registry, &reference).expect_err("superseded leftover record"),
        DecisionRefError::StaleRef {
            question_key: "api.transport".to_string(),
            reason: StaleDecisionRefReason::ClaimNotResolved {
                status: DecisionClaimStatus::Superseded,
            },
        }
    );
}

#[test]
fn open_claim_is_not_a_resolved_target() {
    let registry = DecisionRegistry::new();
    registry
        .claim_open(
            "api.transport",
            "Which transport should the API use?",
            "planner-a",
        )
        .expect("open claim");
    let reference = DecisionRef::new("api.transport").expect("valid key");

    assert_eq!(
        check_decision_ref(&registry, &reference).expect_err("open claim"),
        DecisionRefError::StaleRef {
            question_key: "api.transport".to_string(),
            reason: StaleDecisionRefReason::ClaimNotResolved {
                status: DecisionClaimStatus::Open,
            },
        }
    );
}

#[test]
fn resolved_record_without_live_claim_still_passes() {
    let record = DecisionRecord::new(
        "api.transport",
        "Use HTTP",
        "planner-a",
        scope(&["api"], &[], &[]),
    )
    .expect("resolved record");
    let registry = DecisionRegistry::from_snapshot(DecisionRegistrySnapshot {
        claims: Vec::new(),
        records: vec![record],
    })
    .expect("record-only snapshot");
    let reference = DecisionRef::new("api.transport").expect("valid key");

    let checked = check_decision_ref(&registry, &reference).expect("record is a resolved target");
    assert_eq!(checked.question_key(), "api.transport");
    assert_eq!(checked.resolution(), "Use HTTP");
}

#[test]
fn required_ref_fails_closed_when_store_is_missing() {
    let temp = tempfile::tempdir().expect("temporary repository");
    Repository::init(temp.path()).expect("initialize repository");
    let reference = DecisionRef::new("api.transport").expect("valid key");

    assert_eq!(
        check_required_decision_ref_in_store(temp.path(), Some(&reference))
            .expect_err("missing store"),
        DecisionRefError::StoreMissing
    );
    assert_eq!(
        check_required_decision_ref_in_store(temp.path(), None).expect_err("missing ref"),
        DecisionRefError::MissingRef
    );
}

#[test]
fn cli_citation_parses_key_and_optional_resolution() {
    let key_only = parse_decision_ref_cli(" api.transport ").expect("key-only citation");
    assert_eq!(key_only.question_key(), "api.transport");
    assert_eq!(key_only.expected_resolution(), None);

    let with_resolution = parse_decision_ref_cli("api.transport=Use HTTP").expect("keyed citation");
    assert_eq!(with_resolution.question_key(), "api.transport");
    assert_eq!(with_resolution.expected_resolution(), Some("Use HTTP"));

    assert_eq!(
        parse_decision_ref_cli("api transport").expect_err("invalid key"),
        DecisionRefError::InvalidCitation(DecisionClaimError::InvalidInput {
            field: DecisionInputField::QuestionKey,
        })
    );
    assert_eq!(
        parse_decision_ref_cli("api.transport=").expect_err("empty resolution"),
        DecisionRefError::InvalidCitation(DecisionClaimError::EmptyInput {
            field: DecisionInputField::Resolution,
        })
    );
}

#[test]
fn decision_ref_serde_round_trips_through_new() {
    let reference = DecisionRef::new("api.transport")
        .expect("valid key")
        .with_expected_resolution("Use HTTP")
        .expect("valid resolution");
    let json = serde_json::to_value(&reference).expect("serialize citation");
    assert_eq!(
        json,
        serde_json::json!({
            "question_key": "api.transport",
            "expected_resolution": "Use HTTP"
        })
    );
    let loaded: DecisionRef = serde_json::from_value(json).expect("deserialize citation");
    assert_eq!(loaded, reference);

    let invalid = serde_json::from_value::<DecisionRef>(serde_json::json!({
        "question_key": "api transport"
    }));
    assert!(invalid.is_err(), "invalid keys must fail closed at serde");
}
