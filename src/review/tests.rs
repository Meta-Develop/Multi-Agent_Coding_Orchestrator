use super::*;

fn model_review_lens(
    id: &str,
    backend_id: &str,
    model: &str,
    information_scope: ReviewInformationScope,
) -> ReviewLensConfig {
    ReviewLensConfig {
        id: id.to_string(),
        backend: ReviewLensBackendConfig::Model {
            backend_id: backend_id.to_string(),
            model: model.to_string(),
            reasoning_effort: None,
        },
        information_scope,
    }
}

fn bound_lens_verdict(
    lens: &ReviewLensConfig,
    verdict: ReviewLensVerdictStatus,
    binding: &str,
) -> ReviewLensVerdict {
    let coverage = ReviewLensCoverage {
        worker_ids: vec!["worker-a".to_string()],
        paths: vec![PathBuf::from("src/review.rs")],
    };
    let request_binding = sha256_hex(format!("request-{binding}").as_bytes());
    ReviewLensVerdict::for_lens(
        lens,
        request_binding,
        verdict,
        coverage,
        vec![(ReviewLensEvidenceKind::ModelReview, binding.to_string())],
    )
    .expect("test lens verdict must serialize")
}

#[cfg(unix)]
#[test]
fn review_snapshot_fails_closed_on_non_utf8_head_target() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let repository = git2::Repository::init(temp.path())?;
    let binding = ReviewRepositoryBinding::bind(temp.path())?;
    binding.snapshot()?;
    std::fs::write(repository.path().join("HEAD"), b"ref: refs/heads/non\xff\n")?;

    let error = binding.snapshot().expect_err("non-UTF-8 HEAD must fail");
    assert!(error
        .to_string()
        .contains("review HEAD symbolic target is not valid UTF-8"));
    Ok(())
}

#[test]
fn review_lens_scoped_requests_exclude_disallowed_information() -> Result<()> {
    let sources = ReviewLensRequestSources {
        child_transcript: "TRANSCRIPT-ONLY-MARKER",
        diff: "DIFF-ONLY-MARKER",
        output_report: "REPORT-ONLY-MARKER",
    };
    let diff_lens = model_review_lens(
        "diff-lens",
        "backend-a",
        "model-a",
        ReviewInformationScope::DiffOnly,
    );
    let diff_request = build_review_lens_request(&diff_lens, sources)?;
    let diff_json = serde_json::to_string(&diff_request)?;
    assert!(diff_json.contains("DIFF-ONLY-MARKER"));
    assert!(!diff_json.contains("TRANSCRIPT-ONLY-MARKER"));
    assert!(!diff_json.contains("REPORT-ONLY-MARKER"));
    assert!(!diff_json.contains("child_transcript"));
    assert!(!diff_json.contains("output_report"));
    assert_eq!(diff_request.backend_id, "backend-a");
    assert_eq!(diff_request.model, "model-a");

    let output_lens = model_review_lens(
        "output-lens",
        "backend-b",
        "model-b",
        ReviewInformationScope::OutputReportOnly,
    );
    let output_request = build_review_lens_request(&output_lens, sources)?;
    let output_json = serde_json::to_string(&output_request)?;
    assert!(output_json.contains("REPORT-ONLY-MARKER"));
    assert!(!output_json.contains("TRANSCRIPT-ONLY-MARKER"));
    assert!(!output_json.contains("DIFF-ONLY-MARKER"));
    assert!(!output_json.contains("child_transcript"));
    assert!(!output_json.contains("\"diff\""));
    assert_eq!(output_request.backend_id, "backend-b");
    assert_eq!(output_request.model, "model-b");

    let full_lens = model_review_lens(
        "full-lens",
        "backend-c",
        "model-c",
        ReviewInformationScope::FullChildTranscript,
    );
    let full_json = serde_json::to_string(&build_review_lens_request(&full_lens, sources)?)?;
    assert!(full_json.contains("TRANSCRIPT-ONLY-MARKER"));
    assert!(full_json.contains("DIFF-ONLY-MARKER"));
    assert!(full_json.contains("REPORT-ONLY-MARKER"));
    Ok(())
}

#[test]
fn review_lens_scoped_request_bounds_only_included_information() -> Result<()> {
    let lens = model_review_lens(
        "bounded-diff-lens",
        "bounded-backend",
        "bounded-model",
        ReviewInformationScope::DiffOnly,
    );
    let oversized_excluded = "t".repeat(REVIEW_INPUT_LIMIT_BYTES + 1);
    let request = build_review_lens_request(
        &lens,
        ReviewLensRequestSources {
            child_transcript: &oversized_excluded,
            diff: "small included diff",
            output_report: &oversized_excluded,
        },
    )?;
    assert!(matches!(
        request.information,
        ReviewLensScopedInformation::DiffOnly { .. }
    ));

    let oversized_included = "d".repeat(REVIEW_INPUT_LIMIT_BYTES + 1);
    let error = build_review_lens_request(
        &lens,
        ReviewLensRequestSources {
            child_transcript: "excluded",
            diff: &oversized_included,
            output_report: "excluded",
        },
    )
    .expect_err("oversized included diff must fail before cloning");
    assert!(error.to_string().contains("scoped input exceeds"));
    Ok(())
}

#[test]
fn review_lens_versioned_wires_reject_unsupported_versions() -> Result<()> {
    let lens = model_review_lens(
        "version-lens",
        "version-backend",
        "version-model",
        ReviewInformationScope::DiffOnly,
    );
    let request = build_review_lens_request(
        &lens,
        ReviewLensRequestSources {
            child_transcript: "transcript",
            diff: "diff",
            output_report: "report",
        },
    )?;
    let mut request_value = serde_json::to_value(request)?;
    request_value["version"] = serde_json::json!(REVIEW_SCHEMA_VERSION + 1);
    assert!(serde_json::from_value::<ReviewLensRequest>(request_value)
        .expect_err("unsupported request version must fail")
        .to_string()
        .contains("version is unsupported"));

    let aggregate = aggregate_review_lenses(
        std::slice::from_ref(&lens),
        ReviewAggregationPolicy::AllMustAccept,
        ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        },
        vec![bound_lens_verdict(
            &lens,
            ReviewLensVerdictStatus::Accept,
            "version-binding",
        )],
    )?;
    let mut aggregate_value = serde_json::to_value(aggregate)?;
    aggregate_value["version"] = serde_json::json!(REVIEW_SCHEMA_VERSION + 1);
    assert!(
        serde_json::from_value::<ReviewLensAggregate>(aggregate_value)
            .expect_err("unsupported aggregate version must fail")
            .to_string()
            .contains("version is unsupported")
    );
    Ok(())
}

#[test]
fn review_lens_deserialized_aggregate_is_explicitly_non_authoritative() -> Result<()> {
    let lens = model_review_lens(
        "aggregate-authority-lens",
        "aggregate-authority-backend",
        "aggregate-authority-model",
        ReviewInformationScope::DiffOnly,
    );
    let aggregate = aggregate_review_lenses(
        std::slice::from_ref(&lens),
        ReviewAggregationPolicy::AllMustAccept,
        ReviewCoverageRequirement::default(),
        vec![bound_lens_verdict(
            &lens,
            ReviewLensVerdictStatus::Accept,
            "aggregate-authority-binding",
        )],
    )?;
    assert_eq!(
        aggregate.authority(),
        ReviewLensAggregateAuthority::ParentComputed
    );

    let mut wire = serde_json::to_value(&aggregate)?;
    assert!(wire.get("authority").is_none());
    wire["decision"] = serde_json::json!("reject");
    wire["required_accepts"] = serde_json::json!(99);
    wire["validated_accepts"] = serde_json::json!(98);
    wire["rejected_lenses"] = serde_json::json!(97);
    wire["procedural_failures"] = serde_json::json!(96);
    wire["required_coverage"] = serde_json::json!({
        "worker_ids": ["unverified-worker"],
        "paths": ["unverified/path.rs"]
    });

    let deserialized: ReviewLensAggregate = serde_json::from_value(wire.clone())?;
    assert_eq!(
        deserialized.authority(),
        ReviewLensAggregateAuthority::DeserializedNonAuthoritative
    );
    assert_eq!(deserialized.required_accepts, 99);
    assert_eq!(deserialized.validated_accepts, 98);

    wire["authority"] = serde_json::json!("parent_computed");
    assert!(serde_json::from_value::<ReviewLensAggregate>(wire).is_err());
    Ok(())
}

#[test]
fn review_lens_tagged_wires_reject_unknown_fields() {
    assert!(
        serde_json::from_value::<ReviewLensBackendConfig>(serde_json::json!({
            "kind": "model",
            "backend_id": "backend-a",
            "model": "model-a",
            "reviewer": {"mode": "fake"},
            "unknown": true
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<ReviewLensScopedInformation>(serde_json::json!({
            "scope": "diff_only",
            "diff": "bounded",
            "unknown": true
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<ReviewAggregationPolicy>(serde_json::json!({
            "kind": "validated_quorum",
            "minimum_accepts": 1,
            "unknown": true
        }))
        .is_err()
    );
}

#[test]
fn review_lens_public_constructors_bind_safe_identity() -> Result<()> {
    let lens = model_review_lens(
        "constructor-lens",
        "constructor-backend",
        "constructor-model",
        ReviewInformationScope::OutputReportOnly,
    );
    let descriptor = ReviewLensDescriptor::from(&lens);
    assert_eq!(descriptor.id, lens.id);
    assert_eq!(descriptor.backend_id, "constructor-backend");
    assert_eq!(descriptor.model, "constructor-model");
    assert_eq!(
        descriptor.information_scope,
        ReviewInformationScope::OutputReportOnly
    );
    assert_eq!(
        descriptor.expected_evidence_kind,
        ReviewLensEvidenceKind::ModelReview
    );

    let request_binding = sha256_hex(b"constructor-request");
    let coverage = ReviewLensCoverage {
        worker_ids: vec!["worker-a".to_string()],
        paths: vec![PathBuf::from("src/review.rs")],
    };
    let verdict = ReviewLensVerdict::for_lens(
        &lens,
        request_binding.clone(),
        ReviewLensVerdictStatus::Accept,
        coverage.clone(),
        vec![(
            ReviewLensEvidenceKind::ModelReview,
            "ordinary confidential transcript sentence".to_string(),
        )],
    )?;
    assert_eq!(verdict.lens, descriptor);
    assert_eq!(verdict.request_binding, request_binding);
    assert_eq!(verdict.evidence[0].lens, verdict.lens);
    assert_eq!(verdict.evidence[0].coverage, coverage);
    assert_eq!(verdict.evidence[0].request_binding, verdict.request_binding);
    assert_eq!(
        verdict.evidence[0].binding,
        review_lens_evidence_content_identity("ordinary confidential transcript sentence")?
    );
    assert!(verdict.evidence[0].binding.starts_with("sha256:"));
    assert_eq!(verdict.evidence[0].binding.len(), 71);
    assert!(!serde_json::to_string(&verdict)?.contains("ordinary confidential transcript sentence"));
    Ok(())
}

#[test]
fn review_lens_malformed_evidence_digest_identities_fail_closed() -> Result<()> {
    let lens = model_review_lens(
        "malformed-evidence-lens",
        "malformed-evidence-backend",
        "malformed-evidence-model",
        ReviewInformationScope::DiffOnly,
    );
    let required = ReviewCoverageRequirement {
        worker_ids: vec!["worker-a".to_string()],
        paths: vec![PathBuf::from("src/review.rs")],
    };
    let base = bound_lens_verdict(
        &lens,
        ReviewLensVerdictStatus::Accept,
        "valid-evidence-content",
    );
    let valid_evidence_wire = serde_json::to_value(&base.evidence[0])?;
    let malformed = [
        "0".repeat(64),
        format!("sha256:{}", "0".repeat(63)),
        format!("sha256:{}", "A".repeat(64)),
        format!("SHA256:{}", "0".repeat(64)),
    ];

    for binding in malformed {
        let mut verdict = base.clone();
        verdict.evidence[0].binding = binding;
        let serialization_error = serde_json::to_string(&verdict.evidence[0])
            .expect_err("malformed public evidence must not serialize");
        assert!(serialization_error
            .to_string()
            .contains("sha256:<64 lowercase hex>"));
        let mut malformed_wire = valid_evidence_wire.clone();
        malformed_wire["binding"] = serde_json::Value::String(verdict.evidence[0].binding.clone());
        assert!(serde_json::from_value::<ReviewLensEvidence>(malformed_wire)
            .expect_err("malformed public evidence wire must not deserialize")
            .to_string()
            .contains("sha256:<64 lowercase hex>"));

        let aggregate = aggregate_review_lenses(
            std::slice::from_ref(&lens),
            ReviewAggregationPolicy::AllMustAccept,
            required.clone(),
            vec![verdict],
        )?;
        assert_eq!(
            aggregate.decision,
            ReviewAggregationDecision::ProceduralFailure
        );
        assert!(aggregate.lens_verdicts[0].evidence.is_empty());
        assert!(aggregate.lens_verdicts[0]
            .validation_errors
            .join("\n")
            .contains("sha256:<64 lowercase hex>"));
    }
    Ok(())
}

#[test]
fn review_lens_default_scope_templates_are_stable_cheap_and_local() {
    let lenses = cheap_default_review_lenses();

    assert_eq!(lenses.len(), 2);
    assert_eq!(lenses[0].id, DEFAULT_DIFF_REVIEW_LENS_ID);
    assert_eq!(
        lenses[0].information_scope,
        ReviewInformationScope::DiffOnly
    );
    assert_eq!(lenses[1].id, DEFAULT_OUTPUT_REVIEW_LENS_ID);
    assert_eq!(
        lenses[1].information_scope,
        ReviewInformationScope::OutputReportOnly
    );
    assert!(lenses.iter().all(|lens| {
        lens.information_scope != ReviewInformationScope::FullChildTranscript
            && !lens.backend.backend_id().is_empty()
            && !lens.backend.model().is_empty()
    }));
    assert_eq!(lenses[0].backend, lenses[1].backend);
    assert!(lenses
        .iter()
        .all(|lens| matches!(&lens.backend, ReviewLensBackendConfig::Model { .. })));
}

#[test]
fn review_lens_aggregate_omits_private_backend_configuration() -> Result<()> {
    let lenses = vec![
        ReviewLensConfig {
            id: "fake-private-config".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "fake-local".to_string(),
                model: "fake-model".to_string(),
                reasoning_effort: None,
            },
            information_scope: ReviewInformationScope::OutputReportOnly,
        },
        ReviewLensConfig {
            id: "external-private-config".to_string(),
            backend: ReviewLensBackendConfig::Model {
                backend_id: "external-direct".to_string(),
                model: "external-model".to_string(),
                reasoning_effort: None,
            },
            information_scope: ReviewInformationScope::DiffOnly,
        },
    ];
    let aggregate = aggregate_review_lenses(
        &lenses,
        ReviewAggregationPolicy::AllMustAccept,
        ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        },
        vec![
            bound_lens_verdict(&lenses[0], ReviewLensVerdictStatus::Accept, "private-a"),
            bound_lens_verdict(&lenses[1], ReviewLensVerdictStatus::Accept, "private-b"),
        ],
    )?;
    let serialized = serde_json::to_string(&aggregate)?;

    for marker in [
        "PRIVATE_FAKE_SUMMARY_MARKER",
        "PRIVATE_FAKE_FIX_MARKER",
        "PRIVATE_PROGRAM_MARKER",
        "PRIVATE_ARG_MARKER",
        "\"reviewer\"",
        "\"program\"",
        "\"args\"",
        "\"finding\"",
    ] {
        assert!(
            !serialized.contains(marker),
            "aggregate leaked private backend marker {marker}"
        );
    }
    assert!(serialized.contains("\"backend_id\":\"external-direct\""));
    assert!(serialized.contains("\"model\":\"external-model\""));
    Ok(())
}

#[test]
fn review_lens_model_backend_rejects_inert_reviewer_execution_fields() {
    let config = serde_json::json!({
        "id": "no-inert-dispatch-config",
        "backend": {
            "kind": "model",
            "backend_id": "openai",
            "model": "gpt-5",
            "reasoning_effort": "high",
            "reviewer": {
                "version": 1,
                "mode": "external_command",
                "program": "tools/PRIVATE_PROGRAM_MARKER",
                "args": ["PRIVATE_ARG_MARKER"],
                "timeout_seconds": 30
            }
        },
        "information_scope": "diff_only"
    });

    let error = serde_json::from_value::<ReviewLensConfig>(config)
        .expect_err("model lenses must reject unsupported reviewer execution settings");
    assert!(
        error.to_string().contains("unknown field `reviewer`"),
        "unexpected rejection: {error}"
    );
}

#[test]
fn review_lens_all_must_accept_preserves_reject_and_failure_verdicts() -> Result<()> {
    let lenses = vec![
        model_review_lens(
            "lens-a",
            "backend-a",
            "model-a",
            ReviewInformationScope::DiffOnly,
        ),
        model_review_lens(
            "lens-b",
            "backend-b",
            "model-b",
            ReviewInformationScope::OutputReportOnly,
        ),
    ];
    let required = ReviewCoverageRequirement {
        worker_ids: vec!["worker-a".to_string()],
        paths: vec![PathBuf::from("src/review.rs")],
    };
    let accepted = aggregate_review_lenses(
        &lenses,
        ReviewAggregationPolicy::AllMustAccept,
        required.clone(),
        vec![
            bound_lens_verdict(&lenses[0], ReviewLensVerdictStatus::Accept, "binding-a"),
            bound_lens_verdict(&lenses[1], ReviewLensVerdictStatus::Accept, "binding-b"),
        ],
    )?;
    assert_eq!(accepted.decision, ReviewAggregationDecision::Accept);
    assert_eq!(accepted.validated_accepts, 2);

    let rejected = aggregate_review_lenses(
        &lenses,
        ReviewAggregationPolicy::AllMustAccept,
        required.clone(),
        vec![
            bound_lens_verdict(&lenses[0], ReviewLensVerdictStatus::Accept, "binding-a"),
            bound_lens_verdict(&lenses[1], ReviewLensVerdictStatus::Reject, "binding-b"),
        ],
    )?;
    assert_eq!(rejected.decision, ReviewAggregationDecision::Reject);
    assert_eq!(rejected.rejected_lenses, 1);
    assert_eq!(
        rejected.lens_verdicts[1].reported_verdict,
        ReviewLensVerdictStatus::Reject
    );

    let failed = aggregate_review_lenses(
        &lenses,
        ReviewAggregationPolicy::AllMustAccept,
        required,
        vec![bound_lens_verdict(
            &lenses[0],
            ReviewLensVerdictStatus::Accept,
            "binding-a",
        )],
    )?;
    assert_eq!(
        failed.decision,
        ReviewAggregationDecision::ProceduralFailure
    );
    assert_eq!(failed.procedural_failures, 1);
    assert!(!failed.lens_verdicts[1].reported);
    assert_eq!(
        failed.lens_verdicts[1].effective_verdict,
        ReviewLensVerdictStatus::ProceduralFailure
    );
    Ok(())
}

#[test]
fn review_lens_acceptance_requires_coverage_and_bound_evidence() -> Result<()> {
    let lenses = vec![model_review_lens(
        "lens-a",
        "backend-a",
        "model-a",
        ReviewInformationScope::DiffOnly,
    )];
    let aggregate = aggregate_review_lenses(
        &lenses,
        ReviewAggregationPolicy::AllMustAccept,
        ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        },
        vec![ReviewLensVerdict {
            lens_id: lenses[0].id.clone(),
            lens: ReviewLensDescriptor::from(&lenses[0]),
            request_binding: sha256_hex(b"request-binding-a"),
            verdict: ReviewLensVerdictStatus::Accept,
            coverage: ReviewLensCoverage::default(),
            evidence: Vec::new(),
        }],
    )?;

    assert_eq!(
        aggregate.decision,
        ReviewAggregationDecision::ProceduralFailure
    );
    assert_eq!(
        aggregate.lens_verdicts[0].reported_verdict,
        ReviewLensVerdictStatus::Accept
    );
    assert_eq!(
        aggregate.lens_verdicts[0].effective_verdict,
        ReviewLensVerdictStatus::ProceduralFailure
    );
    let errors = aggregate.lens_verdicts[0].validation_errors.join("\n");
    assert!(errors.contains("lacks bound ModelReview evidence"));
    assert!(errors.contains("omitted required worker coverage"));
    assert!(errors.contains("omitted required path coverage"));
    Ok(())
}

#[test]
fn review_lens_aggregation_binds_verdict_to_parent_built_request() -> Result<()> {
    let lenses = vec![
        model_review_lens(
            "parent-bound-a",
            "provider-a",
            "model-a",
            ReviewInformationScope::DiffOnly,
        ),
        model_review_lens(
            "parent-bound-b",
            "provider-b",
            "model-b",
            ReviewInformationScope::OutputReportOnly,
        ),
    ];
    let sources = ReviewLensRequestSources {
        child_transcript: "private transcript",
        diff: "diff material",
        output_report: "output report material",
    };
    let requests = lenses
        .iter()
        .map(|lens| build_review_lens_request(lens, sources))
        .collect::<Result<Vec<_>>>()?;
    let mismatched = ReviewLensVerdict::for_lens(
        &lenses[0],
        requests[1].request_binding.clone(),
        ReviewLensVerdictStatus::Accept,
        ReviewLensCoverage::default(),
        vec![(
            ReviewLensEvidenceKind::ModelReview,
            "self-bound".to_string(),
        )],
    )?;
    let matching = ReviewLensVerdict::for_lens(
        &lenses[1],
        requests[1].request_binding.clone(),
        ReviewLensVerdictStatus::Accept,
        ReviewLensCoverage::default(),
        vec![(
            ReviewLensEvidenceKind::ModelReview,
            "parent-bound".to_string(),
        )],
    )?;

    let aggregate = aggregate_review_lenses_against_requests(
        &lenses,
        &requests,
        ReviewAggregationPolicy::AllMustAccept,
        ReviewCoverageRequirement::default(),
        vec![mismatched, matching],
    )?;
    assert_eq!(
        aggregate.decision,
        ReviewAggregationDecision::ProceduralFailure
    );
    assert!(aggregate.lens_verdicts[0]
        .validation_errors
        .join("\n")
        .contains("parent-built request"));
    Ok(())
}

#[test]
fn review_lens_aggregation_enforces_verdict_and_evidence_bounds() -> Result<()> {
    let lens = model_review_lens(
        "bounded-verdict-lens",
        "bounded-verdict-backend",
        "bounded-verdict-model",
        ReviewInformationScope::DiffOnly,
    );
    let required = ReviewCoverageRequirement {
        worker_ids: vec!["worker-a".to_string()],
        paths: vec![PathBuf::from("src/review.rs")],
    };
    let base = bound_lens_verdict(
        &lens,
        ReviewLensVerdictStatus::Accept,
        "bounded-verdict-binding",
    );

    let mut oversized_evidence = base.clone();
    oversized_evidence.evidence = vec![base.evidence[0].clone(); REVIEW_FINDING_LIMIT + 1];
    let aggregate = aggregate_review_lenses(
        std::slice::from_ref(&lens),
        ReviewAggregationPolicy::AllMustAccept,
        required.clone(),
        vec![oversized_evidence],
    )?;
    assert_eq!(
        aggregate.decision,
        ReviewAggregationDecision::ProceduralFailure
    );
    assert_eq!(
        aggregate.lens_verdicts[0].evidence.len(),
        REVIEW_FINDING_LIMIT
    );
    assert!(aggregate.lens_verdicts[0]
        .validation_errors
        .join("\n")
        .contains("evidence exceeds"));

    let error = aggregate_review_lenses(
        std::slice::from_ref(&lens),
        ReviewAggregationPolicy::AllMustAccept,
        required,
        vec![base; REVIEW_LENS_LIMIT + 1],
    )
    .expect_err("oversized verdict list must fail before map construction");
    assert!(error.to_string().contains("verdict list exceeds"));
    Ok(())
}

#[test]
fn review_lens_aggregate_retains_all_verdicts_within_public_output_bound() -> Result<()> {
    let lenses = (0..REVIEW_LENS_LIMIT)
        .map(|index| {
            model_review_lens(
                &format!("bounded-lens-{index}"),
                &format!("bounded-backend-{index}"),
                &format!("bounded-model-{index}"),
                ReviewInformationScope::DiffOnly,
            )
        })
        .collect::<Vec<_>>();
    let verdicts = lenses
        .iter()
        .enumerate()
        .map(|(index, lens)| {
            ReviewLensVerdict::for_lens(
                lens,
                sha256_hex(format!("bounded-request-{index}").as_bytes()),
                ReviewLensVerdictStatus::Accept,
                ReviewLensCoverage::default(),
                vec![(
                    ReviewLensEvidenceKind::ModelReview,
                    format!("bounded-evidence-{index}"),
                )],
            )
        })
        .collect::<Result<Vec<_>>>()?;

    let aggregate = aggregate_review_lenses(
        &lenses,
        ReviewAggregationPolicy::AllMustAccept,
        ReviewCoverageRequirement::default(),
        verdicts,
    )?;
    assert_eq!(aggregate.lens_verdicts.len(), REVIEW_LENS_LIMIT);
    assert!(aggregate
        .lens_verdicts
        .iter()
        .all(|verdict| verdict.reported));
    assert_eq!(aggregate.validated_accepts, aggregate.lens_verdicts.len());
    assert!(serde_json::to_vec(&aggregate)?.len() <= REVIEW_LENS_AGGREGATE_LIMIT_BYTES);
    Ok(())
}

#[test]
fn review_lens_maximal_evidence_aggregate_exceeding_public_bound_is_rejected() -> Result<()> {
    let lenses = (0..REVIEW_LENS_LIMIT)
        .map(|index| {
            model_review_lens(
                &format!("maximal-lens-{index}"),
                &format!("maximal-backend-{index}"),
                &format!("maximal-model-{index}"),
                ReviewInformationScope::OutputReportOnly,
            )
        })
        .collect::<Vec<_>>();
    let verdicts = lenses
        .iter()
        .enumerate()
        .map(|(lens_index, lens)| {
            let evidence = (0..REVIEW_FINDING_LIMIT)
                .map(|evidence_index| {
                    (
                        ReviewLensEvidenceKind::ModelReview,
                        format!("maximal-evidence-{lens_index}-{evidence_index}"),
                    )
                })
                .collect::<Vec<_>>();
            ReviewLensVerdict::for_lens(
                lens,
                sha256_hex(format!("maximal-request-{lens_index}").as_bytes()),
                ReviewLensVerdictStatus::Accept,
                ReviewLensCoverage::default(),
                evidence,
            )
        })
        .collect::<Result<Vec<_>>>()?;

    let error = aggregate_review_lenses(
        &lenses,
        ReviewAggregationPolicy::AllMustAccept,
        ReviewCoverageRequirement::default(),
        verdicts,
    )
    .expect_err("maximal aggregate must exceed the public output bound");
    assert!(error
        .to_string()
        .contains("exceeds its 262144 byte serialized JSON limit"));
    Ok(())
}

#[test]
fn review_lens_procedural_aggregate_omits_rejected_unsafe_metadata() -> Result<()> {
    let lens = model_review_lens(
        "sanitized-aggregate-lens",
        "sanitized-aggregate-backend",
        "sanitized-aggregate-model",
        ReviewInformationScope::DiffOnly,
    );
    let mut verdict = bound_lens_verdict(
        &lens,
        ReviewLensVerdictStatus::Accept,
        "initial-safe-binding",
    );
    verdict.request_binding = "PRIVATE_REQUEST_MARKER".to_string();
    verdict.coverage = ReviewLensCoverage {
        worker_ids: vec!["PRIVATE COVERAGE MARKER".to_string()],
        paths: vec![PathBuf::from("/private/ABSOLUTE_COVERAGE_MARKER")],
    };
    let mut secret_evidence = verdict.evidence[0].clone();
    secret_evidence.binding = "API_TOKEN=PRIVATE_SECRET_EVIDENCE_MARKER".to_string();
    secret_evidence.request_binding = verdict.request_binding.clone();
    secret_evidence.coverage = verdict.coverage.clone();
    let mut absolute_evidence = secret_evidence.clone();
    absolute_evidence.binding = "/private/ABSOLUTE_EVIDENCE_MARKER".to_string();
    let mut ordinary_evidence = secret_evidence.clone();
    ordinary_evidence.binding = "ORDINARY CONFIDENTIAL TRANSCRIPT EVIDENCE MARKER".to_string();
    verdict.evidence = vec![secret_evidence, absolute_evidence, ordinary_evidence];

    let aggregate = aggregate_review_lenses(
        std::slice::from_ref(&lens),
        ReviewAggregationPolicy::AllMustAccept,
        ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        },
        vec![verdict],
    )?;
    assert_eq!(
        aggregate.decision,
        ReviewAggregationDecision::ProceduralFailure
    );
    assert!(aggregate.lens_verdicts[0].request_binding.is_none());
    assert_eq!(
        aggregate.lens_verdicts[0].coverage,
        ReviewLensCoverage::default()
    );
    assert!(aggregate.lens_verdicts[0].evidence.is_empty());
    let serialized = serde_json::to_string(&aggregate)?;
    for marker in [
        "PRIVATE_REQUEST_MARKER",
        "PRIVATE COVERAGE MARKER",
        "ABSOLUTE_COVERAGE_MARKER",
        "PRIVATE_SECRET_EVIDENCE_MARKER",
        "ABSOLUTE_EVIDENCE_MARKER",
        "ORDINARY CONFIDENTIAL TRANSCRIPT EVIDENCE MARKER",
    ] {
        assert!(
            !serialized.contains(marker),
            "procedural aggregate leaked rejected marker {marker}"
        );
    }
    Ok(())
}

#[test]
fn review_lens_mismatched_evidence_metadata_fails_procedurally() -> Result<()> {
    let lens = model_review_lens(
        "metadata-lens",
        "metadata-backend",
        "metadata-model",
        ReviewInformationScope::DiffOnly,
    );
    let required = ReviewCoverageRequirement {
        worker_ids: vec!["worker-a".to_string()],
        paths: vec![PathBuf::from("src/review.rs")],
    };
    let base = bound_lens_verdict(&lens, ReviewLensVerdictStatus::Accept, "metadata-binding");
    let mut cases = Vec::new();

    let mut lens_id = base.clone();
    lens_id.evidence[0].lens.id = "other-lens".to_string();
    cases.push((lens_id, "evidence lens id"));

    let mut backend = base.clone();
    backend.evidence[0].lens.backend_id = "other-backend".to_string();
    cases.push((backend, "evidence backend id"));

    let mut model = base.clone();
    model.evidence[0].lens.model = "other-model".to_string();
    cases.push((model, "evidence model"));

    let mut scope = base.clone();
    scope.evidence[0].lens.information_scope = ReviewInformationScope::OutputReportOnly;
    cases.push((scope, "evidence information scope"));

    let mut coverage = base.clone();
    coverage.evidence[0].coverage = ReviewLensCoverage::default();
    cases.push((coverage, "evidence coverage"));

    let mut backend_configuration = base.clone();
    backend_configuration.evidence[0].backend_configuration_id =
        sha256_hex(b"other-backend-configuration");
    cases.push((backend_configuration, "backend configuration identity"));

    let mut request = base.clone();
    request.evidence[0].request_binding = sha256_hex(b"other-request");
    cases.push((request, "evidence request identity"));

    for (verdict, expected_error) in cases {
        let aggregate = aggregate_review_lenses(
            std::slice::from_ref(&lens),
            ReviewAggregationPolicy::AllMustAccept,
            required.clone(),
            vec![verdict],
        )?;
        assert_eq!(
            aggregate.decision,
            ReviewAggregationDecision::ProceduralFailure
        );
        assert_eq!(
            aggregate.lens_verdicts[0].reported_verdict,
            ReviewLensVerdictStatus::Accept
        );
        assert_eq!(
            aggregate.lens_verdicts[0].effective_verdict,
            ReviewLensVerdictStatus::ProceduralFailure
        );
        assert!(
            aggregate.lens_verdicts[0]
                .validation_errors
                .join("\n")
                .contains(expected_error),
            "missing validation error for {expected_error}"
        );
    }
    Ok(())
}

#[test]
fn review_lens_mismatched_verdict_identity_fails_procedurally() -> Result<()> {
    let lens = model_review_lens(
        "verdict-metadata-lens",
        "verdict-backend",
        "verdict-model",
        ReviewInformationScope::OutputReportOnly,
    );
    let required = ReviewCoverageRequirement {
        worker_ids: vec!["worker-a".to_string()],
        paths: vec![PathBuf::from("src/review.rs")],
    };
    let base = bound_lens_verdict(&lens, ReviewLensVerdictStatus::Accept, "verdict-binding");
    let mut cases = Vec::new();

    let mut id = base.clone();
    id.lens.id = "wrong-verdict-lens".to_string();
    cases.push((id, "verdict id"));

    let mut backend = base.clone();
    backend.lens.backend_id = "wrong-verdict-backend".to_string();
    cases.push((backend, "verdict backend id"));

    let mut model = base.clone();
    model.lens.model = "wrong-verdict-model".to_string();
    cases.push((model, "verdict model"));

    let mut scope = base.clone();
    scope.lens.information_scope = ReviewInformationScope::DiffOnly;
    cases.push((scope, "verdict information scope"));

    let mut request = base;
    request.request_binding = sha256_hex(b"wrong-verdict-request");
    cases.push((request, "evidence request identity"));

    for (verdict, expected_error) in cases {
        let aggregate = aggregate_review_lenses(
            std::slice::from_ref(&lens),
            ReviewAggregationPolicy::AllMustAccept,
            required.clone(),
            vec![verdict],
        )?;
        assert_eq!(
            aggregate.decision,
            ReviewAggregationDecision::ProceduralFailure
        );
        assert!(
            aggregate.lens_verdicts[0]
                .validation_errors
                .join("\n")
                .contains(expected_error),
            "missing validation error for {expected_error}"
        );
    }
    Ok(())
}

#[test]
fn review_lens_validated_quorum_keeps_disagreement_visible() -> Result<()> {
    let lenses = vec![
        model_review_lens(
            "lens-a",
            "backend-a",
            "model-a",
            ReviewInformationScope::DiffOnly,
        ),
        model_review_lens(
            "lens-b",
            "backend-b",
            "model-b",
            ReviewInformationScope::OutputReportOnly,
        ),
        model_review_lens(
            "lens-c",
            "backend-c",
            "model-c",
            ReviewInformationScope::DiffOnly,
        ),
    ];
    let aggregate = aggregate_review_lenses(
        &lenses,
        ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts: 2 },
        ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        },
        vec![
            bound_lens_verdict(&lenses[0], ReviewLensVerdictStatus::Accept, "binding-a"),
            bound_lens_verdict(&lenses[1], ReviewLensVerdictStatus::Accept, "binding-b"),
            bound_lens_verdict(&lenses[2], ReviewLensVerdictStatus::Reject, "binding-c"),
        ],
    )?;

    assert_eq!(aggregate.decision, ReviewAggregationDecision::Accept);
    assert_eq!(aggregate.validated_accepts, 2);
    assert_eq!(aggregate.rejected_lenses, 1);
    assert_eq!(aggregate.lens_verdicts.len(), 3);
    assert_eq!(
        aggregate.lens_verdicts[2].effective_verdict,
        ReviewLensVerdictStatus::Reject
    );
    Ok(())
}

#[test]
fn review_lens_validated_quorum_does_not_waive_all_worker_coverage() -> Result<()> {
    let lenses = vec![
        model_review_lens(
            "lens-a",
            "backend-a",
            "model-a",
            ReviewInformationScope::DiffOnly,
        ),
        model_review_lens(
            "lens-b",
            "backend-b",
            "model-b",
            ReviewInformationScope::OutputReportOnly,
        ),
        model_review_lens(
            "lens-c",
            "backend-c",
            "model-c",
            ReviewInformationScope::DiffOnly,
        ),
    ];
    let aggregate = aggregate_review_lenses(
        &lenses,
        ReviewAggregationPolicy::ValidatedQuorum { minimum_accepts: 2 },
        ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string(), "worker-b".to_string()],
            paths: vec![
                PathBuf::from("src/review.rs"),
                PathBuf::from("src/supervise.rs"),
            ],
        },
        vec![
            bound_lens_verdict(&lenses[0], ReviewLensVerdictStatus::Accept, "binding-a"),
            bound_lens_verdict(&lenses[1], ReviewLensVerdictStatus::Accept, "binding-b"),
            bound_lens_verdict(&lenses[2], ReviewLensVerdictStatus::Reject, "binding-c"),
        ],
    )?;

    assert_eq!(
        aggregate.decision,
        ReviewAggregationDecision::ProceduralFailure
    );
    assert_eq!(aggregate.validated_accepts, 0);
    assert_eq!(aggregate.procedural_failures, 2);
    for verdict in &aggregate.lens_verdicts[..2] {
        let errors = verdict.validation_errors.join("\n");
        assert!(errors.contains("worker-b"));
        assert!(errors.contains("src/supervise.rs"));
    }
    Ok(())
}

#[test]
fn review_lens_precomputed_process_evidence_participates_in_aggregation() -> Result<()> {
    let lenses = vec![ReviewLensConfig {
        id: "process-evidence".to_string(),
        backend: ReviewLensBackendConfig::Precomputed {
            backend_id: "verified-process-attestor".to_string(),
            model: "process-evidence-v1".to_string(),
            evidence_kind: ReviewLensEvidenceKind::ProcessEvidence,
        },
        information_scope: ReviewInformationScope::OutputReportOnly,
    }];
    let aggregate = aggregate_review_lenses(
        &lenses,
        ReviewAggregationPolicy::AllMustAccept,
        ReviewCoverageRequirement {
            worker_ids: vec!["worker-a".to_string()],
            paths: vec![PathBuf::from("src/review.rs")],
        },
        vec![ReviewLensVerdict::for_lens(
            &lenses[0],
            sha256_hex(b"process-evidence-request"),
            ReviewLensVerdictStatus::Accept,
            ReviewLensCoverage {
                worker_ids: vec!["worker-a".to_string()],
                paths: vec![PathBuf::from("src/review.rs")],
            },
            vec![(
                ReviewLensEvidenceKind::ProcessEvidence,
                "process-binding-v1".to_string(),
            )],
        )?],
    )?;

    assert_eq!(aggregate.decision, ReviewAggregationDecision::Accept);
    assert_eq!(aggregate.validated_accepts, 1);
    assert!(build_review_lens_request(
        &lenses[0],
        ReviewLensRequestSources {
            child_transcript: "excluded",
            diff: "excluded",
            output_report: "excluded",
        }
    )
    .is_err());
    Ok(())
}

#[test]
fn fake_review_constructs_passed_report_with_deterministic_identity() {
    let report = fake_review(ReviewPrOptions {
        repo: PathBuf::from("."),
        target: "#42".to_string(),
        reviewer: ReviewerConfig::default(),
        attempt: 1,
        changed_paths: vec![PathBuf::from("src/review.rs")],
        diff_summary: Some("changed src/review.rs".to_string()),
    });

    assert_eq!(report.status, ReviewReportStatus::Passed);
    assert!(report.success);
    assert_eq!(report.target, "#42");
    assert_eq!(report.reviewer.mode, ReviewerMode::Fake);
    assert_eq!(report.reviewer.reviewer_id, "autopilot-fake-reviewer");
    assert_eq!(report.reviewer.model, "deterministic-local-reviewer");
    assert_eq!(report.findings, Vec::<ReviewFinding>::new());
    assert_eq!(report.blocking_finding_count, 0);
    assert_eq!(report.diff_source, "sanitized_merge_candidate_summary");
    assert!(!report.ci_reaction_supported);
    assert_eq!(report.ci_reaction, "unsupported");
}

#[test]
fn sanitize_review_output_with_dot_repo_does_not_expand_empty_parent() {
    let output = sanitize_review_output(Path::new("."), b"plain diagnostics");

    assert_eq!(output.text, "plain diagnostics");
    assert!(!output.truncated);
}

#[test]
fn sanitize_review_output_redacts_canonical_repo_path() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let diagnostic = format!("failure in {}/src/review.rs", temp.path().display());

    let output = sanitize_review_output(temp.path(), diagnostic.as_bytes());

    assert_eq!(output.text, "failure in ./src/review.rs");
    Ok(())
}

#[test]
fn sanitize_review_output_rejects_control_and_external_path_diagnostics() {
    let control = sanitize_review_output(Path::new("."), b"unsafe\x1bdiagnostic");
    assert_eq!(control.text, "<redacted:control-character-diagnostic>");
    assert!(control.truncated);

    let external = sanitize_review_output(Path::new("."), b"failure in /private/sibling");
    assert_eq!(external.text, "<redacted:absolute-path-diagnostic>");
}

#[test]
fn fake_review_constructs_blocking_template_finding() {
    let report = fake_review(ReviewPrOptions {
        repo: PathBuf::from("."),
        target: "#43".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::Fake,
            blocking_attempts: 1,
            finding: Some(FakeReviewFindingTemplate {
                severity: "warning".to_string(),
                path: None,
                summary: "deterministic template finding".to_string(),
                suggested_fix: "apply the deterministic fix".to_string(),
            }),
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: vec![PathBuf::from("src/review.rs")],
        diff_summary: None,
    });

    assert_eq!(report.status, ReviewReportStatus::Blocked);
    assert!(!report.success);
    assert_eq!(report.blocking_finding_count, 1);
    assert_eq!(report.diff_source, "pr_target_only");
    assert_eq!(
        report.findings,
        vec![ReviewFinding {
            severity: "warning".to_string(),
            path: Some(PathBuf::from("src/review.rs")),
            summary: "deterministic template finding".to_string(),
            suggested_fix: "apply the deterministic fix".to_string(),
            blocking: true,
        }]
    );
    assert!(!report.ci_reaction_supported);
}

#[cfg(unix)]
#[test]
fn verified_reviewer_rejects_native_interpreter_stdin_eval_and_dispatch_forms() {
    let native_image = b"\x7fELF dedicated fixture";
    let cases = [
        ("/bin/sh", "/usr/bin/dash", Vec::<String>::new()),
        ("/bin/sh", "/usr/bin/dash", vec!["-s".to_string()]),
        (
            "/usr/bin/python3",
            "/usr/bin/python3.13",
            vec!["-c".to_string(), "review()".to_string()],
        ),
        (
            "/usr/bin/python3",
            "/usr/bin/python3.13",
            vec!["-".to_string()],
        ),
        (
            "/usr/bin/node",
            "/usr/bin/node",
            vec!["--eval".to_string(), "review()".to_string()],
        ),
        ("/usr/bin/node", "/usr/bin/node", vec!["-".to_string()]),
        (
            "/usr/bin/perl",
            "/usr/bin/perl5.40",
            vec!["-e".to_string(), "review()".to_string()],
        ),
        ("/usr/bin/perl", "/usr/bin/perl5.40", vec!["-".to_string()]),
        (
            "/usr/bin/ruby",
            "/usr/bin/ruby3.4",
            vec!["-e".to_string(), "review()".to_string()],
        ),
        ("/usr/bin/ruby", "/usr/bin/ruby3.4", vec!["-".to_string()]),
        (
            "/usr/bin/env",
            "/usr/bin/coreutils",
            vec!["python3".to_string(), "-".to_string()],
        ),
        (
            "/opt/reviewer-alias",
            "/usr/bin/python3.13",
            vec!["-".to_string()],
        ),
        (
            "/opt/reviewer-alias",
            "/usr/bin/busybox",
            vec!["sh".to_string()],
        ),
    ];

    for (configured, canonical, args) in cases {
        let error = validate_verified_reviewer_image(
            Path::new(configured),
            Path::new(canonical),
            &args,
            native_image,
        )
        .expect_err("native interpreter and dispatcher authority must fail closed");
        assert!(error
            .to_string()
            .contains("shell, language interpreter, or command dispatcher"));
    }
}

#[cfg(unix)]
#[test]
fn verified_reviewer_allows_direct_shebang_script_and_dedicated_binary() -> Result<()> {
    validate_verified_reviewer_image(
        Path::new("reviewer-script"),
        Path::new("/private/runtime/reviewer-script"),
        &[],
        b"#!/bin/sh\nexit 0\n",
    )?;
    validate_verified_reviewer_image(
        Path::new("reviewer-python-adapter"),
        Path::new("/opt/review/reviewer-python-adapter"),
        &["--strict".to_string()],
        b"\x7fELF dedicated reviewer fixture",
    )?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn reviewer_script_rejects_configured_and_canonical_dispatcher_shebangs() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let dispatcher = temp.path().join("env");
    std::fs::write(&dispatcher, b"native dispatcher fixture")?;
    std::fs::set_permissions(&dispatcher, std::fs::Permissions::from_mode(0o700))?;
    let script = format!("#!{}\nexit 0\n", dispatcher.display());
    let error = reviewer_script_interpreter(script.as_bytes())
        .expect_err("dispatcher shebang must fail closed");
    assert!(error.to_string().contains("command dispatchers"));
    Ok(())
}

#[cfg(unix)]
#[test]
fn bound_verified_reviewer_classifies_script_binary_and_interpreter_images() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    git2::Repository::init(temp.path())?;
    for (name, bytes) in [
        ("reviewer-binary", b"\x7fELF dedicated reviewer".as_slice()),
        ("sh", b"#!/bin/sh\nexit 0\n".as_slice()),
        ("python3", b"\x7fELF interpreter fixture".as_slice()),
    ] {
        let path = temp.path().join(name);
        std::fs::write(&path, bytes)?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    let repository = ReviewRepositoryBinding::bind(temp.path())?;

    let binary = BoundReviewerProgram::bind(&repository, Path::new("reviewer-binary"))?;
    validate_verified_reviewer_program(&repository, &binary, &[])?;
    let script = BoundReviewerProgram::bind(&repository, Path::new("sh"))?;
    validate_verified_reviewer_program(&repository, &script, &[])?;
    let interpreter = BoundReviewerProgram::bind(&repository, Path::new("python3"))?;
    assert!(
        validate_verified_reviewer_program(&repository, &interpreter, &["-".to_string()]).is_err()
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn sanitized_view_contains_only_selected_content_modes_and_internal_symlinks() -> Result<()> {
    use std::os::unix::fs::{symlink, MetadataExt, PermissionsExt};

    let temp = tempfile::tempdir()?;
    let repository = git2::Repository::init(temp.path())?;
    std::fs::write(temp.path().join(".gitignore"), "ignored/\n.maco/\n")?;
    std::fs::create_dir(temp.path().join("docs"))?;
    std::fs::set_permissions(
        temp.path().join("docs"),
        std::fs::Permissions::from_mode(0o750),
    )?;
    std::fs::write(temp.path().join("docs/tracked.txt"), "tracked\n")?;
    std::fs::set_permissions(
        temp.path().join("docs/tracked.txt"),
        std::fs::Permissions::from_mode(0o740),
    )?;
    symlink("docs/tracked.txt", temp.path().join("tracked-link"))?;
    let mut index = repository.index()?;
    for path in [
        Path::new(".gitignore"),
        Path::new("docs/tracked.txt"),
        Path::new("tracked-link"),
    ] {
        index.add_path(path)?;
    }
    index.write()?;
    std::fs::write(temp.path().join("untracked.txt"), "untracked\n")?;
    std::fs::create_dir(temp.path().join("ignored"))?;
    std::fs::write(temp.path().join("ignored/secret.txt"), "ignored-secret\n")?;
    std::fs::create_dir(temp.path().join(".maco"))?;
    std::fs::write(temp.path().join(".maco/auth-key"), "must-not-copy\n")?;

    let binding = ReviewRepositoryBinding::bind(temp.path())?;
    let view = SanitizedReviewerView::create(&binding)?;
    let view_path = view.path();
    assert!(!view_path.starts_with(temp.path()));
    assert_eq!(
        std::fs::read_to_string(view_path.join("docs/tracked.txt"))?,
        "tracked\n"
    );
    assert_eq!(
        std::fs::read_to_string(view_path.join("untracked.txt"))?,
        "untracked\n"
    );
    assert_eq!(
        std::fs::read_link(view_path.join("tracked-link"))?,
        PathBuf::from("docs/tracked.txt")
    );
    assert_eq!(
        std::fs::metadata(view_path.join("docs"))?.mode() & 0o7777,
        0o750
    );
    assert_eq!(
        std::fs::metadata(view_path.join("docs/tracked.txt"))?.mode() & 0o7777,
        0o740
    );
    assert_eq!(
        std::fs::symlink_metadata(view_path.join("tracked-link"))?.mode() & libc::S_IFMT,
        libc::S_IFLNK
    );
    assert!(!view_path.join("ignored").exists());
    assert!(!view_path.join(".git").exists());
    assert!(!view_path.join(".maco").exists());
    view.verify(&binding)?;
    drop(view);
    assert!(!view_path.exists());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn sanitized_view_binding_changes_with_content_mode_and_path() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let repository = git2::Repository::init(temp.path())?;
    std::fs::write(temp.path().join("entry"), "one")?;
    let mut index = repository.index()?;
    index.add_path(Path::new("entry"))?;
    index.write()?;
    let repository_binding = ReviewRepositoryBinding::bind(temp.path())?;

    let content_binding = {
        let view = SanitizedReviewerView::create(&repository_binding)?;
        view.binding().to_string()
    };
    std::fs::write(temp.path().join("entry"), "two")?;
    let changed_content_binding = {
        let view = SanitizedReviewerView::create(&repository_binding)?;
        view.binding().to_string()
    };
    assert_ne!(content_binding, changed_content_binding);

    std::fs::set_permissions(
        temp.path().join("entry"),
        std::fs::Permissions::from_mode(0o700),
    )?;
    let changed_mode_binding = {
        let view = SanitizedReviewerView::create(&repository_binding)?;
        view.binding().to_string()
    };
    assert_ne!(changed_content_binding, changed_mode_binding);

    std::fs::rename(temp.path().join("entry"), temp.path().join("renamed"))?;
    let mut index = repository.index()?;
    index.remove_path(Path::new("entry"))?;
    index.add_path(Path::new("renamed"))?;
    index.write()?;
    let changed_path_binding = {
        let view = SanitizedReviewerView::create(&repository_binding)?;
        view.binding().to_string()
    };
    assert_ne!(changed_mode_binding, changed_path_binding);
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn sanitized_view_rejects_tracked_or_changed_maco_paths() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let repository = git2::Repository::init(temp.path())?;
    std::fs::create_dir(temp.path().join(".maco"))?;
    std::fs::write(temp.path().join(".maco/tracked"), "tracked runtime")?;
    let mut index = repository.index()?;
    index.add_path(Path::new(".maco/tracked"))?;
    index.write()?;
    let binding = ReviewRepositoryBinding::bind(temp.path())?;
    assert!(SanitizedReviewerView::create(&binding).is_err());
    assert!(validate_sanitized_changed_paths(&[PathBuf::from(".maco/report.json")]).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn sanitized_view_rejects_external_dangling_symlinks_and_hardlinks() -> Result<()> {
    use std::os::unix::fs::symlink;

    let external = tempfile::tempdir()?;
    let external_repo = git2::Repository::init(external.path())?;
    symlink("/etc/passwd", external.path().join("escape"))?;
    external_repo.index()?.add_path(Path::new("escape"))?;
    external_repo.index()?.write()?;
    let binding = ReviewRepositoryBinding::bind(external.path())?;
    assert!(SanitizedReviewerView::create(&binding).is_err());

    let dangling = tempfile::tempdir()?;
    let dangling_repo = git2::Repository::init(dangling.path())?;
    symlink("missing", dangling.path().join("dangling"))?;
    let mut index = dangling_repo.index()?;
    index.add_path(Path::new("dangling"))?;
    index.write()?;
    let binding = ReviewRepositoryBinding::bind(dangling.path())?;
    assert!(SanitizedReviewerView::create(&binding).is_err());

    let hardlink_root = tempfile::tempdir()?;
    let repo_path = hardlink_root.path().join("repo");
    std::fs::create_dir(&repo_path)?;
    let hardlink_repo = git2::Repository::init(&repo_path)?;
    std::fs::write(hardlink_root.path().join("outside"), "hardlinked secret")?;
    std::fs::hard_link(
        hardlink_root.path().join("outside"),
        repo_path.join("hardlink"),
    )?;
    let mut index = hardlink_repo.index()?;
    index.add_path(Path::new("hardlink"))?;
    index.write()?;
    let binding = ReviewRepositoryBinding::bind(&repo_path)?;
    assert!(SanitizedReviewerView::create(&binding).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn sanitized_view_detects_source_and_view_races() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let repository = git2::Repository::init(temp.path())?;
    std::fs::write(temp.path().join("tracked"), "before")?;
    let mut index = repository.index()?;
    index.add_path(Path::new("tracked"))?;
    index.write()?;
    let binding = ReviewRepositoryBinding::bind(temp.path())?;
    let view = SanitizedReviewerView::create(&binding)?;
    std::fs::write(temp.path().join("tracked"), "after")?;
    assert!(view.verify(&binding).is_err());
    drop(view);

    std::fs::write(temp.path().join("tracked"), "before")?;
    let binding = ReviewRepositoryBinding::bind(temp.path())?;
    let view = SanitizedReviewerView::create(&binding)?;
    std::fs::write(view.path().join("tracked"), "tampered")?;
    assert!(view.verify(&binding).is_err());
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn sanitized_view_rejects_gitlink_sparse_case_depth_and_aggregate_bounds() -> Result<()> {
    let gitlink = tempfile::tempdir()?;
    let repository = git2::Repository::init(gitlink.path())?;
    let mut index = repository.index()?;
    index.add(&git2::IndexEntry {
        ctime: git2::IndexTime::new(0, 0),
        mtime: git2::IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        mode: 0o160000,
        uid: 0,
        gid: 0,
        file_size: 0,
        id: git2::Oid::ZERO_SHA1,
        flags: 0,
        flags_extended: 0,
        path: b"submodule".to_vec(),
    })?;
    index.write()?;
    let binding = ReviewRepositoryBinding::bind(gitlink.path())?;
    assert!(SanitizedReviewerView::create(&binding).is_err());

    let sparse = tempfile::tempdir()?;
    let repository = git2::Repository::init(sparse.path())?;
    std::fs::write(sparse.path().join("sparse"), "sparse")?;
    let mut index = repository.index()?;
    index.add_path(Path::new("sparse"))?;
    let mut sparse_entry = index
        .get_path(Path::new("sparse"), 0)
        .context("sparse index entry")?;
    sparse_entry.flags_extended |= 1 << 14;
    index.add(&sparse_entry)?;
    index.write()?;
    std::fs::remove_file(sparse.path().join("sparse"))?;
    let binding = ReviewRepositoryBinding::bind(sparse.path())?;
    assert!(SanitizedReviewerView::create(&binding).is_err());

    let case = SanitizedViewSelection {
        entries: BTreeMap::from([
            (PathBuf::from("Case/file"), SanitizedViewOrigin::default()),
            (PathBuf::from("case/other"), SanitizedViewOrigin::default()),
        ]),
    };
    assert!(validate_sanitized_view_paths(&case).is_err());
    let deep = SanitizedViewSelection {
        entries: BTreeMap::from([(
            (0..=REVIEW_PREWALK_MAX_DEPTH)
                .map(|_| "x")
                .collect::<PathBuf>(),
            SanitizedViewOrigin::default(),
        )]),
    };
    assert!(validate_sanitized_view_paths(&deep).is_err());

    let aggregate = tempfile::tempdir()?;
    git2::Repository::init(aggregate.path())?;
    std::fs::write(aggregate.path().join("entry"), "x")?;
    let root = SafeRoot::open_existing(aggregate.path())?;
    let reader = ReviewTreeReader::bind(&root)?;
    let mut total = REVIEW_SNAPSHOT_TOTAL_LIMIT_BYTES;
    assert!(reader
        .snapshot_entry(Path::new("entry"), &mut total)
        .is_err());
    Ok(())
}

#[test]
fn sanitized_view_rejects_special_modes_and_collapses_hidden_ancestors() {
    let entry = SnapshotTreeEntry::Regular {
        mode: unsigned_to_u32(libc::S_IFREG) | 0o4755,
        length: 1,
        sha256: [0; 32],
        identity: FileIdentity { device: 1, file: 1 },
        modified_seconds: 0,
        modified_nanoseconds: 0,
        changed_seconds: 0,
        changed_nanoseconds: 0,
    };
    assert!(validate_sanitized_view_entry_mode(&entry).is_err());

    let requested = BTreeSet::from([
        PathBuf::from("/data/primary"),
        PathBuf::from("/data/primary/.git"),
        PathBuf::from("/data/primary/.git/maco/state"),
        PathBuf::from("/data/worktrees"),
        PathBuf::from("/data/worktrees/review"),
    ]);
    let hidden = minimal_sanitized_hidden_roots(requested.clone());
    assert_eq!(
        hidden,
        vec![
            PathBuf::from("/data/primary"),
            PathBuf::from("/data/worktrees")
        ]
    );
    assert!(requested
        .iter()
        .all(|path| hidden.iter().any(|root| path.starts_with(root))));
    assert!(hidden.iter().enumerate().all(|(index, path)| hidden
        .iter()
        .enumerate()
        .all(|(other, candidate)| index == other
            || (!path.starts_with(candidate) && !candidate.starts_with(path)))));
}

#[cfg(target_os = "linux")]
#[test]
fn sanitized_confinement_exposes_only_view_store_and_materialized_reviewer() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let repository = git2::Repository::init(temp.path())?;
    let maco = repository.path().join("maco");
    let state = maco.join("state");
    std::fs::create_dir_all(&state)?;
    std::fs::set_permissions(&maco, std::fs::Permissions::from_mode(0o700))?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(state.join("auth.key"), "never-read-or-copied")?;
    let binding = ReviewRepositoryBinding::bind(temp.path())?;
    let runtime = trusted_linux_runtime_root()?;
    let view = runtime.join("sanitized-view-fixture");
    let materialized = runtime.join("materialized-reviewer-fixture");
    let profile = binding.sanitized_confinement_profile(&view, &materialized)?;

    assert!(profile.isolated_host_view());
    assert!(profile
        .visible_read_only_roots()
        .contains(&PathBuf::from("/nix/store")));
    assert!(profile.visible_read_only_roots().contains(&materialized));
    for original in [
        binding.worktree_root.path(),
        binding.git_dir_root.path(),
        binding.common_dir_root.path(),
        state.as_path(),
    ] {
        assert!(profile
            .hidden_roots()
            .iter()
            .any(|root| original.starts_with(root)));
    }
    assert!(profile.hidden_roots().iter().all(|root| {
        !view.starts_with(root)
            && !materialized.starts_with(root)
            && !root.starts_with(&view)
            && !root.starts_with(&materialized)
    }));
    Ok(())
}

#[cfg(unix)]
#[test]
fn external_review_drains_large_output_before_timeout() -> Result<()> {
    let temp = tempfile::tempdir()?;
    git2::Repository::init(temp.path())?;
    let command = external_echo_command(
        "#44",
        1,
        r#"["src/review.rs"]"#,
        "pr_target_only",
        "i=0; while [ \"$i\" -lt 256 ]; do printf '%4096s' ' ' >&2; i=$((i + 1)); done;",
    );
    let program = write_reviewer_script(temp.path(), "reviewer-large", &command)?;

    let report = external_review_simulation(ReviewPrOptions {
        repo: temp.path().to_path_buf(),
        target: "#44".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            program: Some(program),
            timeout_seconds: Some(3),
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: vec![PathBuf::from("src/review.rs")],
        diff_summary: None,
    })?;

    assert_eq!(report.status, ReviewReportStatus::Passed);
    assert!(report.success);
    assert_eq!(report.reviewer.mode, ReviewerMode::ExternalCommand);
    assert_eq!(
        report
            .diagnostics
            .as_ref()
            .and_then(|diagnostics| diagnostics.timeout_seconds),
        Some(3)
    );
    Ok(())
}

#[test]
fn reviewer_config_wires_are_versioned_strict_and_omission_compatible() -> Result<()> {
    let config: ReviewerConfig = serde_json::from_str(
        r#"{
                "mode": "fake",
                "blocking_attempts": 1,
                "finding": {
                    "severity": "warning",
                    "summary": "bounded finding",
                    "suggested_fix": "bounded fix"
                }
            }"#,
    )?;
    let serialized = serde_json::to_value(&config)?;
    assert_eq!(serialized["version"], REVIEW_SCHEMA_VERSION);
    assert_eq!(serialized["finding"]["version"], REVIEW_SCHEMA_VERSION);

    assert!(serde_json::from_str::<ReviewerConfig>(r#"{"version":2,"mode":"fake"}"#).is_err());
    assert!(serde_json::from_str::<ReviewerConfig>(r#"{"mode":"fake","unknown":true}"#).is_err());
    assert!(serde_json::from_str::<ReviewerConfig>(
        r#"{"mode":"fake","finding":{"summary":"x","suggested_fix":"y","unknown":true}}"#
    )
    .is_err());
    assert!(serde_json::from_str::<ReviewerConfig>(
        r#"{"mode":"fake","finding":{"version":2,"summary":"x","suggested_fix":"y"}}"#
    )
    .is_err());
    Ok(())
}

#[test]
fn review_entry_rejects_invalid_mode_combinations_and_bounds_before_repo_access() {
    let invalid_fake = review_pr(ReviewPrOptions {
        repo: PathBuf::from("/repository/does/not/exist"),
        target: "#1".to_string(),
        reviewer: ReviewerConfig {
            command: Some("true".to_string()),
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: Vec::new(),
        diff_summary: None,
    })
    .expect_err("fake command must be rejected");
    assert!(invalid_fake.to_string().contains("fake reviewer mode"));

    let invalid_external = review_pr(ReviewPrOptions {
        repo: PathBuf::from("/repository/does/not/exist"),
        target: "#1".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            blocking_attempts: 1,
            program: Some(PathBuf::from("reviewer")),
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: Vec::new(),
        diff_summary: None,
    })
    .expect_err("external fake fields must be rejected");
    assert!(invalid_external
        .to_string()
        .contains("fake blocking_attempts"));

    let invalid_timeout = review_pr(ReviewPrOptions {
        repo: PathBuf::from("/repository/does/not/exist"),
        target: "#1".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            program: Some(PathBuf::from("reviewer")),
            timeout_seconds: Some(REVIEW_TIMEOUT_LIMIT_SECONDS.saturating_add(1)),
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: Vec::new(),
        diff_summary: None,
    })
    .expect_err("oversized timeout must be rejected");
    assert!(invalid_timeout.to_string().contains("timeout_seconds"));

    let legacy_shell = review_pr(ReviewPrOptions {
        repo: PathBuf::from("/repository/does/not/exist"),
        target: "#1".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            command: Some("reviewer --unsafe-shell".to_string()),
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: Vec::new(),
        diff_summary: None,
    })
    .expect_err("legacy shell reviewer authority must fail before repository access");
    assert!(legacy_shell.to_string().contains("non-authoritative"));

    for shell_arg in ["-c", "-ec", "--command=unsafe"] {
        let shell_command = review_pr(ReviewPrOptions {
            repo: PathBuf::from("/repository/does/not/exist"),
            target: "#1".to_string(),
            reviewer: ReviewerConfig {
                mode: ReviewerMode::ExternalCommand,
                program: Some(PathBuf::from("/bin/sh")),
                args: vec![shell_arg.to_string(), "unsafe".to_string()],
                ..ReviewerConfig::default()
            },
            attempt: 1,
            changed_paths: Vec::new(),
            diff_summary: None,
        })
        .expect_err("shell command-string authority must fail before repository access");
        assert!(shell_command.to_string().contains("shell -c"));
    }

    let noncanonical_path = review_pr(ReviewPrOptions {
        repo: PathBuf::from("/repository/does/not/exist"),
        target: "#1".to_string(),
        reviewer: ReviewerConfig::default(),
        attempt: 1,
        changed_paths: vec![PathBuf::from("src//review.rs")],
        diff_summary: None,
    })
    .expect_err("noncanonical public paths must be rejected before repository access");
    assert!(noncanonical_path.to_string().contains("canonical"));
}

#[test]
fn fake_request_binding_frames_path_count_diff_presence_and_reviewer_config() {
    let base = ReviewPrOptions {
        repo: PathBuf::from("."),
        target: "#binding".to_string(),
        reviewer: ReviewerConfig::default(),
        attempt: 1,
        changed_paths: vec![PathBuf::from("a"), PathBuf::from("b")],
        diff_summary: None,
    };
    let ambiguous_without_framing = ReviewPrOptions {
        changed_paths: vec![PathBuf::from("a")],
        diff_summary: Some("b".to_string()),
        ..base.clone()
    };
    assert_ne!(
        fake_review_request_binding(&base),
        fake_review_request_binding(&ambiguous_without_framing)
    );
    let configured = ReviewPrOptions {
        reviewer: ReviewerConfig {
            blocking_attempts: 1,
            finding: Some(FakeReviewFindingTemplate {
                severity: "warning".to_string(),
                path: Some(PathBuf::from("a")),
                summary: "bounded".to_string(),
                suggested_fix: "repair".to_string(),
            }),
            ..ReviewerConfig::default()
        },
        ..base.clone()
    };
    assert_ne!(
        fake_review_request_binding(&base),
        fake_review_request_binding(&configured)
    );
}

#[test]
fn external_report_wire_is_strict_exact_bounded_and_sensitive_fail_closed() -> Result<()> {
    let options = ReviewPrOptions {
        repo: PathBuf::from("."),
        target: "#77".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            program: Some(PathBuf::from("reviewer")),
            ..ReviewerConfig::default()
        },
        attempt: 2,
        changed_paths: vec![PathBuf::from("src/review.rs")],
        diff_summary: Some("bounded diff".to_string()),
    };
    let mut report = fake_review(ReviewPrOptions {
        repo: options.repo.clone(),
        target: options.target.clone(),
        reviewer: ReviewerConfig::default(),
        attempt: options.attempt,
        changed_paths: options.changed_paths.clone(),
        diff_summary: options.diff_summary.clone(),
    });
    let expected_reviewer = ReviewerIdentity {
        mode: ReviewerMode::ExternalCommand,
        reviewer_id: "external-program-test".to_string(),
        model: "parent-bound-direct-program-v1".to_string(),
    };
    let expected_binding = "a".repeat(64);
    report.reviewer = expected_reviewer.clone();
    report.request_binding = expected_binding.clone();
    let accepted = serde_json::to_vec(&report)?;
    assert!(matches!(
        parse_external_review_report(&accepted, &options, &expected_reviewer, &expected_binding)?,
        ParsedExternalReview::Accepted(_)
    ));

    let mut unknown = serde_json::to_value(&report)?;
    unknown["unexpected"] = serde_json::json!(true);
    assert!(parse_external_review_report(
        &serde_json::to_vec(&unknown)?,
        &options,
        &expected_reviewer,
        &expected_binding
    )
    .is_err());

    let mut nested_unknown = serde_json::to_value(&report)?;
    nested_unknown["reviewer"]["unexpected"] = serde_json::json!(true);
    assert!(parse_external_review_report(
        &serde_json::to_vec(&nested_unknown)?,
        &options,
        &expected_reviewer,
        &expected_binding
    )
    .is_err());

    let mut legacy_mode = serde_json::to_value(&report)?;
    legacy_mode["reviewer"]["mode"] = serde_json::json!("external");
    assert!(parse_external_review_report(
        &serde_json::to_vec(&legacy_mode)?,
        &options,
        &expected_reviewer,
        &expected_binding
    )
    .is_err());
    let mut missing_version = serde_json::to_value(&report)?;
    missing_version
        .as_object_mut()
        .context("report object")?
        .remove("version");
    assert!(parse_external_review_report(
        &serde_json::to_vec(&missing_version)?,
        &options,
        &expected_reviewer,
        &expected_binding
    )
    .is_err());

    let mut mismatched = serde_json::to_value(&report)?;
    mismatched["attempt"] = serde_json::json!(3);
    assert!(parse_external_review_report(
        &serde_json::to_vec(&mismatched)?,
        &options,
        &expected_reviewer,
        &expected_binding
    )
    .is_err());

    let mut critical_nonblocking = serde_json::to_value(&report)?;
    critical_nonblocking["findings"] = serde_json::json!([{
        "severity": "critical",
        "summary": "critical issue",
        "suggested_fix": "repair it",
        "blocking": false
    }]);
    assert!(parse_external_review_report(
        &serde_json::to_vec(&critical_nonblocking)?,
        &options,
        &expected_reviewer,
        &expected_binding
    )
    .is_err());
    let mut unknown_severity = critical_nonblocking.clone();
    unknown_severity["findings"][0]["severity"] = serde_json::json!("urgent");
    assert!(parse_external_review_report(
        &serde_json::to_vec(&unknown_severity)?,
        &options,
        &expected_reviewer,
        &expected_binding
    )
    .is_err());

    let mut absolute_path = serde_json::to_value(&report)?;
    absolute_path["changed_paths"] = serde_json::json!(["/external/path"]);
    assert!(parse_external_review_report(
        &serde_json::to_vec(&absolute_path)?,
        &options,
        &expected_reviewer,
        &expected_binding
    )
    .is_err());

    let mut sensitive_path = serde_json::to_value(&report)?;
    sensitive_path["status"] = serde_json::json!("blocked");
    sensitive_path["success"] = serde_json::json!(false);
    sensitive_path["findings"] = serde_json::json!([{
        "severity": "error",
        "path": "/external/private/path",
        "summary": "bounded issue",
        "suggested_fix": "repair it",
        "blocking": true
    }]);
    sensitive_path["blocking_finding_count"] = serde_json::json!(1);
    assert!(matches!(
        parse_external_review_report(
            &serde_json::to_vec(&sensitive_path)?,
            &options,
            &expected_reviewer,
            &expected_binding
        )?,
        ParsedExternalReview::RejectedSensitive
    ));

    for unsafe_summary in [
        "API_TOKEN=top-secret",
        "-----BEGIN PRIVATE KEY-----",
        "/external/private/path",
        "control\u{0001}value",
    ] {
        let mut sensitive = serde_json::to_value(&report)?;
        sensitive["next_action"] = serde_json::json!(unsafe_summary);
        assert!(matches!(
            parse_external_review_report(
                &serde_json::to_vec(&sensitive)?,
                &options,
                &expected_reviewer,
                &expected_binding
            )?,
            ParsedExternalReview::RejectedSensitive
        ));
    }
    assert!(parse_external_review_report(
        &vec![b' '; REVIEW_JSON_LIMIT_BYTES + 1],
        &options,
        &expected_reviewer,
        &expected_binding
    )
    .is_err());
    assert!(parse_external_review_report(
        &[0xff, 0xfe],
        &options,
        &expected_reviewer,
        &expected_binding
    )
    .is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn exact_snapshot_detects_tracked_untracked_ignored_mode_symlink_and_head_changes() -> Result<()> {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = tempfile::tempdir()?;
    let repository = git2::Repository::init(temp.path())?;
    std::fs::write(temp.path().join(".gitignore"), "ignored/\n")?;
    std::fs::write(temp.path().join("tracked.txt"), "tracked-a")?;
    std::fs::write(temp.path().join("target-a.txt"), "target-a")?;
    std::fs::write(temp.path().join("target-b.txt"), "target-b")?;
    let mut index = repository.index()?;
    for path in [
        Path::new(".gitignore"),
        Path::new("tracked.txt"),
        Path::new("target-a.txt"),
        Path::new("target-b.txt"),
    ] {
        index.add_path(path)?;
    }
    index.write()?;
    let tree_id = index.write_tree()?;
    let tree = repository.find_tree(tree_id)?;
    let signature = git2::Signature::now("Review Test", "review@example.invalid")?;
    let commit = repository.commit(
        Some("HEAD"),
        &signature,
        &signature,
        "snapshot baseline",
        &tree,
        &[],
    )?;
    drop(tree);
    std::fs::write(temp.path().join("untracked.txt"), "untracked-a")?;
    std::fs::create_dir(temp.path().join("ignored"))?;
    std::fs::write(temp.path().join("ignored/secret.txt"), "ignored-a")?;
    symlink("target-a.txt", temp.path().join("link.txt"))?;
    std::fs::write(temp.path().join("reviewer.sh"), "#!/bin/sh\nexit 0\n")?;
    std::fs::set_permissions(
        temp.path().join("reviewer.sh"),
        std::fs::Permissions::from_mode(0o700),
    )?;

    let binding = ReviewRepositoryBinding::bind(temp.path())?;
    let program = MaterializedReviewerProgram::create(BoundReviewerProgram::bind(
        &binding,
        Path::new("reviewer.sh"),
    )?)?;
    let baseline = binding.snapshot()?;

    std::fs::write(temp.path().join("tracked.txt"), "tracked-b")?;
    let changed_content = binding.snapshot()?;
    assert_ne!(baseline, changed_content);
    let request = ReviewPrOptions {
        repo: temp.path().to_path_buf(),
        target: "#snapshot".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            program: Some(PathBuf::from("reviewer.sh")),
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: vec![PathBuf::from("tracked.txt")],
        diff_summary: Some("same labels".to_string()),
    };
    let identity = bound_external_reviewer_identity(&program.binding, &[])?;
    let baseline_binding = external_review_request_binding(
        &request,
        &baseline,
        &identity,
        &program.binding,
        None,
        REVIEW_DEFAULT_TIMEOUT_SECONDS,
    )?;
    assert_ne!(
        baseline_binding,
        external_review_request_binding(
            &request,
            &baseline,
            &identity,
            &program.binding,
            None,
            REVIEW_DEFAULT_TIMEOUT_SECONDS.saturating_add(1)
        )?
    );
    let sanitized_binding = external_review_request_binding(
        &request,
        &baseline,
        &identity,
        &program.binding,
        Some("sanitized-view-a"),
        REVIEW_DEFAULT_TIMEOUT_SECONDS,
    )?;
    assert_ne!(baseline_binding, sanitized_binding);
    assert_ne!(
        sanitized_binding,
        external_review_request_binding(
            &request,
            &baseline,
            &identity,
            &program.binding,
            Some("sanitized-view-b"),
            REVIEW_DEFAULT_TIMEOUT_SECONDS,
        )?
    );
    let changed_policy_payload = serde_json::to_vec(&ExternalReviewRequestBindingPayload {
        version: REVIEW_SCHEMA_VERSION,
        target: &request.target,
        attempt: request.attempt,
        changed_paths: &request.changed_paths,
        diff_summary: request.diff_summary.as_deref(),
        reviewer: &identity,
        program: &program.binding,
        args: &request.reviewer.args,
        sanitized_view_binding: None,
        effective_timeout_seconds: REVIEW_DEFAULT_TIMEOUT_SECONDS,
        sandbox_policy_version: REVIEW_SANDBOX_POLICY_VERSION.saturating_add(1),
        repository_snapshot: &baseline,
    })?;
    assert_ne!(
        baseline_binding,
        domain_sha256(EXTERNAL_REVIEW_REQUEST_DOMAIN, &changed_policy_payload)
    );
    let args_request = ReviewPrOptions {
        reviewer: ReviewerConfig {
            args: vec!["--bounded".to_string()],
            ..request.reviewer.clone()
        },
        ..request.clone()
    };
    let args_identity =
        bound_external_reviewer_identity(&program.binding, &args_request.reviewer.args)?;
    assert_ne!(
        baseline_binding,
        external_review_request_binding(
            &args_request,
            &baseline,
            &args_identity,
            &program.binding,
            None,
            REVIEW_DEFAULT_TIMEOUT_SECONDS
        )?
    );
    assert_ne!(
        external_review_request_binding(
            &request,
            &baseline,
            &identity,
            &program.binding,
            None,
            REVIEW_DEFAULT_TIMEOUT_SECONDS
        )?,
        external_review_request_binding(
            &request,
            &changed_content,
            &identity,
            &program.binding,
            None,
            REVIEW_DEFAULT_TIMEOUT_SECONDS
        )?
    );
    std::fs::write(temp.path().join("tracked.txt"), "tracked-a")?;
    let restored_content = binding.snapshot()?;
    assert_ne!(baseline, restored_content);
    assert_ne!(
        external_review_request_binding(
            &request,
            &baseline,
            &identity,
            &program.binding,
            None,
            REVIEW_DEFAULT_TIMEOUT_SECONDS
        )?,
        external_review_request_binding(
            &request,
            &restored_content,
            &identity,
            &program.binding,
            None,
            REVIEW_DEFAULT_TIMEOUT_SECONDS
        )?
    );

    let mut permissions = std::fs::metadata(temp.path().join("tracked.txt"))?.permissions();
    permissions.set_mode(0o700);
    std::fs::set_permissions(temp.path().join("tracked.txt"), permissions)?;
    assert_ne!(restored_content, binding.snapshot()?);
    let mut permissions = std::fs::metadata(temp.path().join("tracked.txt"))?.permissions();
    permissions.set_mode(0o644);
    std::fs::set_permissions(temp.path().join("tracked.txt"), permissions)?;
    let restored_mode = binding.snapshot()?;
    assert_ne!(restored_content, restored_mode);

    std::fs::write(temp.path().join("untracked.txt"), "untracked-b")?;
    assert_ne!(restored_mode, binding.snapshot()?);
    std::fs::write(temp.path().join("untracked.txt"), "untracked-a")?;
    let restored_untracked = binding.snapshot()?;
    assert_ne!(restored_mode, restored_untracked);
    std::fs::write(temp.path().join("ignored/secret.txt"), "ignored-b")?;
    assert_ne!(restored_untracked, binding.snapshot()?);
    std::fs::write(temp.path().join("ignored/secret.txt"), "ignored-a")?;
    let restored_ignored = binding.snapshot()?;
    assert_ne!(restored_untracked, restored_ignored);

    std::fs::remove_file(temp.path().join("link.txt"))?;
    symlink("target-b.txt", temp.path().join("link.txt"))?;
    assert_ne!(restored_ignored, binding.snapshot()?);
    std::fs::remove_file(temp.path().join("link.txt"))?;
    symlink("target-a.txt", temp.path().join("link.txt"))?;
    assert_ne!(restored_ignored, binding.snapshot()?);

    repository.reference("refs/heads/same-commit", commit, true, "test")?;
    std::fs::write(
        repository.path().join("HEAD"),
        "ref: refs/heads/same-commit\n",
    )?;
    let rebound = binding.snapshot()?;
    assert_eq!(rebound.head, baseline.head);
    assert_ne!(rebound.head_admin_sha256, baseline.head_admin_sha256);
    assert_ne!(rebound.head_symbolic_target, baseline.head_symbolic_target);
    Ok(())
}

#[cfg(unix)]
#[test]
fn snapshot_refuses_hardlinks_special_entries_external_symlinks_and_gitlinks() -> Result<()> {
    use std::os::unix::{ffi::OsStrExt, fs::symlink};

    let temp = tempfile::tempdir()?;
    let root = SafeRoot::open_existing(temp.path())?;
    let reader = ReviewTreeReader::bind(&root)?;
    std::fs::write(temp.path().join("hard-a"), "same")?;
    std::fs::hard_link(temp.path().join("hard-a"), temp.path().join("hard-b"))?;
    assert!(reader.snapshot_entry(Path::new("hard-a"), &mut 0).is_err());

    symlink("/external/path", temp.path().join("escape-link"))?;
    assert!(reader
        .snapshot_entry(Path::new("escape-link"), &mut 0)
        .is_err());

    let fifo = std::ffi::CString::new(temp.path().join("fifo").as_os_str().as_bytes())?;
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(reader.snapshot_entry(Path::new("fifo"), &mut 0).is_err());

    let repo_dir = tempfile::tempdir()?;
    let repository = git2::Repository::init(repo_dir.path())?;
    let mut index = repository.index()?;
    index.add(&git2::IndexEntry {
        ctime: git2::IndexTime::new(0, 0),
        mtime: git2::IndexTime::new(0, 0),
        dev: 0,
        ino: 0,
        mode: 0o160000,
        uid: 0,
        gid: 0,
        file_size: 0,
        id: git2::Oid::ZERO_SHA1,
        flags: 0,
        flags_extended: 0,
        path: b"submodule".to_vec(),
    })?;
    index.write()?;
    let binding = ReviewRepositoryBinding::bind(repo_dir.path())?;
    let error = binding.snapshot().expect_err("gitlink must fail closed");
    assert!(error.to_string().contains("gitlink/submodule"));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn descriptor_prewalk_rejects_oversized_ignored_file_before_git_status() -> Result<()> {
    let temp = tempfile::tempdir()?;
    git2::Repository::init(temp.path())?;
    std::fs::write(temp.path().join(".gitignore"), "ignored.bin\n")?;
    let ignored = File::create(temp.path().join("ignored.bin"))?;
    ignored.set_len(REVIEW_SNAPSHOT_FILE_LIMIT_BYTES.saturating_add(1))?;

    let binding = ReviewRepositoryBinding::bind(temp.path())?;
    let error = binding
        .snapshot()
        .expect_err("oversized ignored files must fail in descriptor prewalk");
    assert!(error.to_string().contains("prewalk"));
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
fn reviewer_program_materialization_binds_source_copy_and_interpreter() -> Result<()> {
    use std::os::unix::fs::{symlink, PermissionsExt};

    let temp = tempfile::tempdir()?;
    git2::Repository::init(temp.path())?;
    let relative = write_reviewer_script(temp.path(), "reviewer-script", "exit 0")?;
    let repository = ReviewRepositoryBinding::bind(temp.path())?;
    let source = BoundReviewerProgram::bind(&repository, &relative)?;
    let materialized = MaterializedReviewerProgram::create(source)?;
    assert_ne!(
        materialized.execution_path,
        temp.path().join("reviewer-script")
    );
    assert!(materialized.binding.interpreter_source.is_some());
    assert!(materialized.binding.interpreter_copy.is_some());
    materialized.verify(&repository)?;

    std::fs::write(temp.path().join("reviewer-script"), "#!/bin/sh\nexit 1\n")?;
    std::fs::set_permissions(
        temp.path().join("reviewer-script"),
        std::fs::Permissions::from_mode(0o700),
    )?;
    assert!(materialized.verify(&repository).is_err());

    let canonical_interpreter = Path::new("/bin/sh").canonicalize()?;
    let absolute = BoundReviewerProgram::bind(&repository, &canonical_interpreter)?;
    assert!(absolute.path.is_absolute());
    let symlink_path = temp.path().join("reviewer-link");
    symlink(&canonical_interpreter, &symlink_path)?;
    assert!(BoundReviewerProgram::bind(&repository, &symlink_path).is_err());
    Ok(())
}

#[cfg(unix)]
#[test]
fn review_profile_hides_bound_common_state_without_reading_keys() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let repository = git2::Repository::init(temp.path())?;
    let state = repository.path().join("maco/state");
    std::fs::create_dir_all(&state)?;
    std::fs::set_permissions(
        repository.path().join("maco"),
        std::fs::Permissions::from_mode(0o700),
    )?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(state.join("private.key"), "must-not-be-read-by-snapshot")?;

    let binding = ReviewRepositoryBinding::bind(temp.path())?;
    assert_eq!(
        binding.confinement_profile()?,
        StrictOfflineWorkspaceProfile::read_only(temp.path()).with_hidden_root(&state)
    );
    let snapshot = binding.snapshot()?;
    assert_eq!(snapshot.state_identity, binding.state.identity());
    Ok(())
}

#[cfg(unix)]
#[test]
fn external_simulation_rejects_truncated_stderr_and_applies_default_timeout() -> Result<()> {
    let temp = tempfile::tempdir()?;
    git2::Repository::init(temp.path())?;
    let truncated_program = write_reviewer_script(
            temp.path(),
            "reviewer-truncated",
            "cat >/dev/null; i=0; while [ \"$i\" -lt 1100 ]; do printf '%4096s' ' ' >&2; i=$((i + 1)); done",
        )?;
    let report = external_review_simulation(ReviewPrOptions {
        repo: temp.path().to_path_buf(),
        target: "#88".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            program: Some(truncated_program),
            timeout_seconds: None,
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: Vec::new(),
        diff_summary: None,
    })
    .expect_err("truncated stderr must be rejected");
    assert!(report.to_string().contains("stdout or stderr"));

    let command = external_echo_command("#89", 1, "[]", "pr_target_only", "");
    let accepted_program = write_reviewer_script(temp.path(), "reviewer-accepted", &command)?;
    let accepted = external_review_simulation(ReviewPrOptions {
        repo: temp.path().to_path_buf(),
        target: "#89".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            program: Some(accepted_program),
            timeout_seconds: None,
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: Vec::new(),
        diff_summary: None,
    })?;
    assert_eq!(
        accepted
            .diagnostics
            .and_then(|diagnostics| diagnostics.timeout_seconds),
        Some(REVIEW_DEFAULT_TIMEOUT_SECONDS)
    );

    let unsafe_program = write_reviewer_script(
        temp.path(),
        "reviewer-unsafe-diagnostics",
        &external_echo_command(
            "#90",
            1,
            "[]",
            "pr_target_only",
            "printf 'API_TOKEN=top-secret' >&2;",
        ),
    )?;
    let unsafe_diagnostics = external_review_simulation(ReviewPrOptions {
        repo: temp.path().to_path_buf(),
        target: "#90".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            program: Some(unsafe_program),
            timeout_seconds: Some(30),
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: Vec::new(),
        diff_summary: None,
    })?;
    assert_eq!(unsafe_diagnostics.status, ReviewReportStatus::Failed);
    assert!(!unsafe_diagnostics.success);
    let diagnostics = unsafe_diagnostics
        .diagnostics
        .context("failed review diagnostics")?;
    assert_eq!(
        diagnostics.stderr.text,
        "<redacted:unsafe-external-review-diagnostics>"
    );
    assert!(!diagnostics.stderr.text.contains("top-secret"));
    Ok(())
}

#[cfg(unix)]
fn external_echo_command(
    target: &str,
    attempt: usize,
    changed_paths_json: &str,
    diff_source: &str,
    stderr_prefix: &str,
) -> String {
    format!(
        r#"input=$(cat); request_binding=$(printf '%s' "$input" | sed -n 's/.*"request_binding":"\([^"]*\)".*/\1/p'); reviewer_id=$(printf '%s' "$input" | sed -n 's/.*"reviewer_id":"\([^"]*\)".*/\1/p'); model=$(printf '%s' "$input" | sed -n 's/.*"model":"\([^"]*\)".*/\1/p'); {stderr_prefix} printf '{{"version":1,"status":"passed","success":true,"target":"{target}","reviewer":{{"mode":"external_command","reviewer_id":"%s","model":"%s"}},"attempt":{attempt},"request_binding":"%s","findings":[],"blocking_finding_count":0,"changed_paths":{changed_paths_json},"diff_source":"{diff_source}","ci_reaction_supported":false,"ci_reaction":"unsupported","next_action":"human review"}}\n' "$reviewer_id" "$model" "$request_binding""#
    )
}

#[cfg(unix)]
fn write_reviewer_script(repo: &Path, name: &str, body: &str) -> Result<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    let path = repo.join(name);
    std::fs::write(&path, format!("#!/bin/sh\nset -eu\n{body}\n"))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))?;
    Ok(PathBuf::from(name))
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires exclusive strict-systemd runtime validation"]
fn strict_external_reviewer_cannot_read_hidden_common_state() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let temp = tempfile::tempdir()?;
    let repository = git2::Repository::init(temp.path())?;
    let state = repository.path().join("maco/state");
    std::fs::create_dir_all(&state)?;
    std::fs::set_permissions(
        repository.path().join("maco"),
        std::fs::Permissions::from_mode(0o700),
    )?;
    std::fs::set_permissions(&state, std::fs::Permissions::from_mode(0o700))?;
    std::fs::write(state.join("private.key"), "hidden")?;
    let program = write_reviewer_script(
        temp.path(),
        "reviewer-hidden-state",
        "cat .git/maco/state/private.key >/dev/null; exit 99",
    )?;
    let report = external_review(ReviewPrOptions {
        repo: temp.path().to_path_buf(),
        target: "#90".to_string(),
        reviewer: ReviewerConfig {
            mode: ReviewerMode::ExternalCommand,
            program: Some(program),
            timeout_seconds: Some(30),
            ..ReviewerConfig::default()
        },
        attempt: 1,
        changed_paths: Vec::new(),
        diff_summary: None,
    })?;
    assert_eq!(report.status, ReviewReportStatus::Failed);
    Ok(())
}
