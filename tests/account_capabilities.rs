use multi_agent_coding_orchestrator::{
    accounts::{
        evaluation::{
            evaluate_observation, AccountBoundCandidate, AccountPolicyInput, OperationalReason,
            PolicyEvidence, PreviewInput,
        },
        protocol::*,
        AccountClient, AccountClientConfig, AccountError,
    },
    optimizer::{
        action::CanonicalEffort,
        evaluation_fn::{EvaluatedPolicy, EvaluationOutcome, RejectionReason},
        ids::PolicyId,
    },
    selection::{CandidateKey, ReasoningEffort},
};
use serde_json::json;
#[cfg(target_os = "linux")]
use serde_json::Value;
use std::time::Duration;

fn inventory() -> AccountList {
    serde_json::from_value(json!({"schema_version":1,"accounts":[
        {"alias":"first","provider":"openai","runtime":"codex","enabled":true},
        {"alias":"second","provider":"openai","runtime":"codex","enabled":true}
    ]}))
    .unwrap()
}

fn discovery(alias: &str) -> AccountDiscovery {
    serde_json::from_value(json!({
        "schema_version":1,"observation_id":"00000000-0000-4000-8000-000000000001",
        "account":{"alias":alias,"provider":"openai","runtime":"codex","enabled":true},
        "observed_at":100,"expires_at":null,
        "auth":{"state":"remote_validated","provenance":"codex_rate_limits"},
        "models":{"state":"observed","provenance":"codex_model_list","entitlement":"unknown",
            "items":[{"id":"example-model","supported_reasoning_efforts":["high"],"default_reasoning_effort":"high"}]},
        "quota":{"state":"observed","provenance":"codex_rate_limits","windows":[
            {"limit_id":"shared","window":"primary","used_percent":20.0,"window_duration_mins":300,"resets_at":1000}]},
        "availability":"unknown","failure":null
    })).unwrap()
}

fn input(alias: &str) -> PreviewInput {
    PreviewInput {
        schema_version: 1,
        account_alias: alias.into(),
        quality_threshold_bp: 8000,
        policies: vec![AccountPolicyInput {
            policy_id: PolicyId::new(format!("{alias}-policy")).unwrap(),
            binding: AccountBoundCandidate {
                account_alias: alias.into(),
                candidate: CandidateKey {
                    runtime: "codex".into(),
                    model: "example-model".into(),
                    effort: ReasoningEffort::High,
                },
            },
            evidence: Some(PolicyEvidence {
                evaluation: EvaluatedPolicy {
                    policy_id: PolicyId::new(format!("{alias}-policy")).unwrap(),
                    certified_quality: true,
                    quality_lower_confidence_bp: 9000,
                    cost_to_certification_micros: 100,
                    resource_constraints_satisfied: true,
                    effort: CanonicalEffort::High,
                },
            }),
        }],
    }
}

fn reason(
    report: &multi_agent_coding_orchestrator::accounts::evaluation::AccountPreview,
) -> RejectionReason {
    let EvaluationOutcome::Infeasible { rejected, .. } = &report.evaluation else {
        panic!("metadata cannot authorize a feasible winner")
    };
    rejected[0].reason.clone()
}

#[test]
fn identical_runtime_models_on_two_accounts_keep_distinct_bindings() {
    let first = input("first");
    let second = input("second");
    assert_eq!(
        first.policies[0].binding.candidate,
        second.policies[0].binding.candidate
    );
    assert_ne!(first.policies[0].binding, second.policies[0].binding);
    for input in [first, second] {
        let report = evaluate_observation(
            &input,
            inventory(),
            Some(Ok(discovery(&input.account_alias))),
            101,
        )
        .unwrap();
        assert_eq!(
            report.policies[0].binding.account_alias,
            input.account_alias
        );
        assert_eq!(
            report.observation.unwrap().account.alias,
            input.account_alias
        );
        assert!(!report.execution_ready);
    }
}

#[test]
fn manual_pin_and_complete_policy_identity_and_effort_are_exact() {
    let mut preview = input("first");
    preview.policies[0].binding.account_alias = "second".into();
    assert_eq!(preview.validate(), Err(AccountError::InvalidInput));
    preview = input("first");
    preview.policies[0]
        .evidence
        .as_mut()
        .unwrap()
        .evaluation
        .policy_id = PolicyId::new("other-policy").unwrap();
    assert_eq!(preview.validate(), Err(AccountError::InvalidInput));
    preview = input("first");
    preview.policies[0]
        .evidence
        .as_mut()
        .unwrap()
        .evaluation
        .effort = CanonicalEffort::Low;
    assert_eq!(preview.validate(), Err(AccountError::InvalidInput));
    preview = input("first");
    preview.policies.push(preview.policies[0].clone());
    assert_eq!(preview.validate(), Err(AccountError::InvalidInput));
    assert!(matches!(
        evaluate_observation(
            &input("first"),
            inventory(),
            Some(Ok(discovery("second"))),
            101
        ),
        Err(AccountError::Protocol)
    ));
}

#[test]
fn real_evaluator_preserves_quality_floor_and_caller_resource_conjunction() {
    let mut preview = input("first");
    let observe = || Some(Ok(discovery("first")));
    let report = evaluate_observation(&preview, inventory(), observe(), 101).unwrap();
    assert_eq!(reason(&report), RejectionReason::ProviderResourceConstraint);
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::ModelEntitlementUnknown));
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::ObservationNeedsRevalidation));
    assert!(!report.execution_ready && report.revalidation_required);
    preview.policies[0]
        .evidence
        .as_mut()
        .unwrap()
        .evaluation
        .certified_quality = false;
    assert_eq!(
        reason(&evaluate_observation(&preview, inventory(), observe(), 101).unwrap()),
        RejectionReason::Uncertified
    );
    preview.policies[0]
        .evidence
        .as_mut()
        .unwrap()
        .evaluation
        .certified_quality = true;
    preview.policies[0]
        .evidence
        .as_mut()
        .unwrap()
        .evaluation
        .quality_lower_confidence_bp = 7999;
    assert_eq!(
        reason(&evaluate_observation(&preview, inventory(), observe(), 101).unwrap()),
        RejectionReason::QualityConfidenceBelowThreshold {
            observed_bp: 7999,
            threshold_bp: 8000
        }
    );
    preview.quality_threshold_bp = 7999;
    assert_eq!(preview.validate(), Err(AccountError::InvalidInput));
    preview = input("first");
    preview.policies[0]
        .evidence
        .as_mut()
        .unwrap()
        .evaluation
        .resource_constraints_satisfied = false;
    let report = evaluate_observation(&preview, inventory(), observe(), 101).unwrap();
    assert_eq!(
        report.policies[0].caller_resource_constraints_satisfied,
        Some(false)
    );
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::CallerResourceConstraint));
    preview.policies[0].evidence = None;
    let report = evaluate_observation(&preview, inventory(), observe(), 101).unwrap();
    assert!(!report.policies[0].evidence_supplied);
    assert_eq!(
        report.policies[0].caller_resource_constraints_satisfied,
        None
    );
    assert_eq!(reason(&report), RejectionReason::InvalidCost);
}

#[test]
fn unknown_stale_disabled_refused_and_exhausted_metadata_stays_explicit() {
    let mut observed = discovery("first");
    observed.auth = AuthObservation {
        state: AuthState::Unknown,
        provenance: AuthProvenance::None,
    };
    observed.quota = QuotaObservation {
        state: ObservationState::Unknown,
        provenance: QuotaProvenance::None,
        windows: vec![],
    };
    let report =
        evaluate_observation(&input("first"), inventory(), Some(Ok(observed)), 100_000).unwrap();
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::AuthUnknown));
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::QuotaUnknown));
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::ObservationNeedsRevalidation));
    assert!(report.observation.unwrap().quota.windows.is_empty());
    let mut observed = discovery("first");
    observed.quota.windows[0].used_percent = 100.0;
    let report =
        evaluate_observation(&input("first"), inventory(), Some(Ok(observed)), 1001).unwrap();
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::QuotaExhausted));
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::QuotaResetNeedsRevalidation));
    let mut listed = inventory();
    listed.accounts[0].enabled = false;
    let report = evaluate_observation(&input("first"), listed, None, 101).unwrap();
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::AccountDisabled));
    let report = evaluate_observation(
        &input("first"),
        inventory(),
        Some(Err(AccountError::Refused)),
        101,
    )
    .unwrap();
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::DiscoveryRefused));
    let report = evaluate_observation(&input("unknown"), inventory(), None, 101).unwrap();
    assert!(report.policies[0]
        .operational_reasons
        .contains(&OperationalReason::AccountNotListed));
}

#[test]
fn protocol_rejects_duplicate_identity_unknown_fields_and_malformed_observations() {
    let mut listed = inventory();
    listed.accounts.push(listed.accounts[0].clone());
    assert_eq!(listed.validate(), Err(AccountError::Protocol));
    let base = discovery("first");
    let mut mutations = Vec::new();
    let mut bad = base.clone();
    bad.models.items.push(bad.models.items[0].clone());
    mutations.push(bad);
    let mut bad = base.clone();
    bad.models.items[0]
        .supported_reasoning_efforts
        .push(ModelEffort::High);
    mutations.push(bad);
    let mut bad = base.clone();
    bad.models.items[0].default_reasoning_effort = Some(ModelEffort::Low);
    mutations.push(bad);
    let mut bad = base.clone();
    bad.quota.windows[0].used_percent = 100.1;
    mutations.push(bad);
    let mut bad = base.clone();
    bad.quota.windows[0].window_duration_mins = Some(0);
    mutations.push(bad);
    let mut bad = base.clone();
    bad.quota.state = ObservationState::Unknown;
    mutations.push(bad);
    let mut bad = base.clone();
    bad.auth.provenance = AuthProvenance::CodexAccountRead;
    mutations.push(bad);
    let mut bad = base.clone();
    bad.expires_at = Some(1000);
    mutations.push(bad);
    let mut bad = base.clone();
    bad.observation_id = "not-a-uuid".into();
    mutations.push(bad);
    for bad in mutations {
        assert_eq!(bad.validate(), Err(AccountError::Protocol));
    }
    let mut value = serde_json::to_value(base).unwrap();
    value["credential"] = json!("discarded");
    assert!(serde_json::from_value::<AccountDiscovery>(value).is_err());
    let mut value = serde_json::to_value(discovery("first")).unwrap();
    value.as_object_mut().unwrap().remove("expires_at");
    assert!(serde_json::from_value::<AccountDiscovery>(value).is_err());
    let mut value = serde_json::to_value(input("first")).unwrap();
    value["policies"][0]["evidence"]["evaluation"]["model_quality"] = json!(true);
    assert!(serde_json::from_value::<PreviewInput>(value).is_err());
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::{
        fs,
        io::{BufRead, BufReader, Write},
        os::unix::{fs::PermissionsExt, net::UnixListener},
        process::Command,
        thread,
    };

    fn service(
        replies: Vec<Vec<u8>>,
    ) -> (
        tempfile::TempDir,
        AccountClientConfig,
        thread::JoinHandle<Vec<Value>>,
    ) {
        let count = replies.len();
        let mut replies = replies.into_iter();
        service_with(count, move |_| replies.next().unwrap())
    }

    fn service_with(
        count: usize,
        mut respond: impl FnMut(&Value) -> Vec<u8> + Send + 'static,
    ) -> (
        tempfile::TempDir,
        AccountClientConfig,
        thread::JoinHandle<Vec<Value>>,
    ) {
        // Use the checkout's trusted ancestry, not a world-writable temporary root.
        let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o750)).unwrap();
        let socket = temp.path().join("broker.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        let handle = thread::spawn(move || {
            let mut requests = Vec::new();
            for _ in 0..count {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = String::new();
                BufReader::new(&stream).read_line(&mut request).unwrap();
                let request = serde_json::from_str(&request).unwrap();
                let reply = respond(&request);
                requests.push(request);
                let _ = stream.write_all(&reply);
            }
            requests
        });
        let config = AccountClientConfig {
            socket,
            expected_uid: unsafe { libc::geteuid() },
            timeout: Duration::from_secs(MAX_REQUEST_SECONDS),
        };
        (temp, config, handle)
    }

    fn reply(result: impl serde::Serialize) -> Vec<u8> {
        let mut bytes = serde_json::to_vec(&json!({"id":1,"ok":true,"result":result})).unwrap();
        bytes.push(b'\n');
        bytes
    }

    #[test]
    fn delayed_listing_uses_completion_time_for_observation_freshness() {
        let (_temp, config, server) = service_with(2, |request| {
            if request["capability"] == "accounts.list" {
                // Cross a Unix-second boundary before the discovery attempt starts.
                thread::sleep(Duration::from_secs(1));
                reply(inventory())
            } else {
                let mut observed = discovery("first");
                observed.observed_at = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                reply(observed)
            }
        });
        let report = multi_agent_coding_orchestrator::accounts::evaluation::preview(
            &AccountClient::new(config).unwrap(),
            &input("first"),
        )
        .unwrap();
        assert!(!report.policies[0]
            .operational_reasons
            .contains(&OperationalReason::ObservationFromFuture));
        assert!(report.policies[0]
            .operational_reasons
            .contains(&OperationalReason::ObservationNeedsRevalidation));
        server.join().unwrap();
    }

    #[test]
    fn request_deadline_refuses_a_silent_service() {
        let (_temp, mut config, server) = service_with(1, |_| {
            thread::sleep(Duration::from_millis(100));
            reply(inventory())
        });
        config.timeout = Duration::from_millis(10);
        assert_eq!(
            AccountClient::new(config).unwrap().list(),
            Err(AccountError::Timeout)
        );
        server.join().unwrap();
    }

    #[test]
    fn real_socket_cli_lists_discovers_and_previews_only_the_pinned_account() {
        let (temp, config, server) = service(vec![reply(inventory()), reply(discovery("second"))]);
        let policies = temp.path().join("policies.json");
        fs::write(&policies, serde_json::to_vec(&input("second")).unwrap()).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_maco"))
            .args(["accounts", "--broker-socket"])
            .arg(&config.socket)
            .args([
                "--broker-uid",
                &config.expected_uid.to_string(),
                "preview",
                "second",
                "--policies",
            ])
            .arg(&policies)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["account_alias"], "second");
        assert_eq!(report["execution_ready"], false);
        assert!(report["evaluation"].get("Infeasible").is_some());
        let requests = server.join().unwrap();
        assert_eq!(
            requests,
            vec![
                json!({"id":1,"capability":"accounts.list","arguments":{}}),
                json!({"id":1,"capability":"accounts.discover","arguments":{"alias":"second"}})
            ]
        );
    }

    #[test]
    fn closed_socket_responses_reject_wrong_identity_outcome_duplicates_and_enums() {
        let mut bad_enum = serde_json::to_value(inventory()).unwrap();
        bad_enum["accounts"][0]["provider"] = json!("other");
        let cases = vec![
            b"{\"id\":2,\"ok\":true,\"result\":{\"schema_version\":1,\"accounts\":[]}}\n".to_vec(),
            b"{\"id\":1,\"id\":1,\"ok\":true,\"result\":{\"schema_version\":1,\"accounts\":[]}}\n".to_vec(),
            b"{\"id\":1,\"ok\":true,\"result\":{\"schema_version\":1,\"accounts\":[]},\"error\":{\"code\":\"internal\",\"message\":\"private\"}}\n".to_vec(),
            b"{\"id\":1,\"ok\":false,\"result\":{\"schema_version\":1,\"accounts\":[]}}\n".to_vec(),
            b"{\"id\":1,\"ok\":false,\"error\":{\"code\":\"new_error\",\"message\":\"private\"}}\n".to_vec(),
            b"{\"id\":1,\"ok\":true,\"result\":{\"schema_version\":1,\"accounts\":[]}}".to_vec(),
            reply(bad_enum), vec![b'x'; MAX_FRAME_BYTES + 1],
        ];
        for bytes in cases {
            let (_temp, config, server) = service(vec![bytes]);
            assert_eq!(
                AccountClient::new(config).unwrap().list(),
                Err(AccountError::Protocol)
            );
            server.join().unwrap();
        }
    }

    #[test]
    fn socket_refusal_discards_upstream_text() {
        let (_temp, config, server) = service(vec![b"{\"id\":1,\"ok\":false,\"error\":{\"code\":\"access_denied\",\"message\":\"private-token-path-and-email\"}}\n".to_vec()]);
        let error = AccountClient::new(config)
            .unwrap()
            .discover("first")
            .unwrap_err();
        assert_eq!(error, AccountError::Refused);
        assert!(!error.to_string().contains("private"));
        server.join().unwrap();
    }

    #[test]
    fn unsafe_modes_owners_and_symlinks_are_refused_before_request() {
        let (temp, config, server) = service(vec![]);
        server.join().unwrap();
        // Keep a listener alive so endpoint mode failures cannot be connection errors.
        let socket = temp.path().join("safe.sock");
        let _listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
        let mut config = AccountClientConfig { socket, ..config };
        config.expected_uid ^= 1;
        assert_eq!(
            AccountClient::new(config.clone()).unwrap().list(),
            Err(AccountError::UnsafeEndpoint)
        );
        config.expected_uid ^= 1;
        fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            AccountClient::new(config.clone()).unwrap().list(),
            Err(AccountError::UnsafeEndpoint)
        );
        fs::set_permissions(&config.socket, fs::Permissions::from_mode(0o660)).unwrap();
        let link = temp.path().join("link.sock");
        std::os::unix::fs::symlink(&config.socket, &link).unwrap();
        assert_eq!(
            AccountClient::new(AccountClientConfig {
                socket: link,
                ..config.clone()
            })
            .unwrap()
            .list(),
            Err(AccountError::UnsafeEndpoint)
        );
        fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o770)).unwrap();
        assert_eq!(
            AccountClient::new(config).unwrap().list(),
            Err(AccountError::UnsafeEndpoint)
        );
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_is_explicit() {
    let client = AccountClient::new(AccountClientConfig {
        socket: "unused.sock".into(),
        expected_uid: 0,
        timeout: Duration::from_secs(MAX_REQUEST_SECONDS),
    })
    .unwrap();
    assert_eq!(client.list(), Err(AccountError::UnsupportedPlatform));
}
