mod support;

use multi_agent_coding_orchestrator::accounts::{invocation_protocol::*, protocol::ModelEffort};
use serde_json::{json, Value};

fn request(alias: &str) -> InvocationRequest {
    InvocationRequest {
        alias: alias.into(),
        selection_revision: 1,
        model: "example-model".into(),
        reasoning_effort: ModelEffort::High,
        policy_digest: digest(b"complete test policy"),
        input: InvocationInput::WorkProposal {
            prompt: "Return a proposal.".into(),
        },
    }
}

#[test]
fn request_identity_changes_with_every_frozen_policy_input() {
    let original = request("first");
    let expected = original.digest().unwrap();
    for change in 0..6 {
        let mut modified = original.clone();
        match change {
            0 => modified.alias = "second".into(),
            1 => modified.selection_revision += 1,
            2 => modified.model = "another-model".into(),
            3 => modified.reasoning_effort = ModelEffort::Low,
            4 => modified.policy_digest = digest(b"changed complete policy"),
            _ => modified.input = InvocationInput::QuotaWarmup {},
        }
        assert_ne!(modified.digest().unwrap(), expected);
    }
    assert!(serde_json::from_value::<InvocationInput>(
        json!({"kind":"quota_warmup","prompt":"execute something"})
    )
    .is_err());
}

#[test]
fn wire_proposals_and_usage_reject_extra_and_missing_fields() {
    assert!(serde_json::from_str::<InvocationProposal>(
        r#"{"summary":"a","summary":"b","commands":[],"patches":[],"notes":[]}"#
    )
    .is_err());
    assert!(serde_json::from_value::<InvocationProposal>(json!({"summary":"a","commands":[{"command":"x","purpose":"implement"}],"patches":[],"notes":[]})).is_err());
    assert!(serde_json::from_value::<InvocationTokens>(
        json!({"input_tokens":1,"output_tokens":2,"total_tokens":3})
    )
    .is_err());
    assert!(serde_json::from_value::<InvocationTokens>(json!({"input_tokens":1,"cached_input_tokens":0,"output_tokens":2,"reasoning_output_tokens":0,"total_tokens":-1})).is_err());
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use multi_agent_coding_orchestrator::{
        accounts::{
            provider::{
                AccountBrokerProvider, AccountBrokerProviderConfig, BrokerAdmissionPolicy,
                BrokerChargeKind, BrokerProviderFailure,
            },
            AccountClientConfig,
        },
        llm::{LlmProvider, LlmRequest, PromptContext, ProviderError, Redactor, RequestBudget},
    };
    use std::{
        collections::BTreeMap,
        fs,
        io::{BufRead, BufReader, Write},
        os::unix::{fs::PermissionsExt, net::UnixListener},
        path::{Path, PathBuf},
        process::{Command, Stdio},
        sync::{
            atomic::{AtomicBool, Ordering},
            Arc, Mutex,
        },
        thread,
        time::{Duration, Instant, SystemTime, UNIX_EPOCH},
    };
    use tempfile::TempDir;

    #[derive(Clone, Copy)]
    enum Behavior {
        Complete,
        MissingUsage,
        LoseStart,
        PartialUnknown,
        ChangedGeneration,
        Refused,
        RateLimited,
        PartialThenUnknown,
        PartialThenRegressiveFinal,
        HoldPartial,
        LargePatch,
    }

    struct Shared {
        calls: Vec<Value>,
        attempts: BTreeMap<String, Value>,
        starts: usize,
        behavior: Behavior,
        fenced: bool,
    }
    struct Fixture {
        _temp: TempDir,
        repo: PathBuf,
        selection: PathBuf,
        config: AccountClientConfig,
        state: Arc<Mutex<Shared>>,
        stop: Arc<AtomicBool>,
        server: Option<thread::JoinHandle<()>>,
    }

    impl Fixture {
        fn new(behavior: Behavior) -> Self {
            let temp = tempfile::tempdir_in(env!("CARGO_MANIFEST_DIR")).unwrap();
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
            let repo = temp.path().join("repo");
            let git = git2::Repository::init(&repo).unwrap();
            fs::write(repo.join("README.md"), "original\n").unwrap();
            let mut index = git.index().unwrap();
            index.add_path(Path::new("README.md")).unwrap();
            index.write().unwrap();
            let tree_id = index.write_tree().unwrap();
            let tree = git.find_tree(tree_id).unwrap();
            let signature = git2::Signature::now("Fixture", "fixture@example.invalid").unwrap();
            git.commit(Some("HEAD"), &signature, &signature, "fixture", &tree, &[])
                .unwrap();
            let socket = temp.path().join("broker.sock");
            let listener = UnixListener::bind(&socket).unwrap();
            fs::set_permissions(&socket, fs::Permissions::from_mode(0o660)).unwrap();
            listener.set_nonblocking(true).unwrap();
            let config = AccountClientConfig {
                socket,
                expected_uid: unsafe { libc::geteuid() },
                timeout: Duration::from_secs(5),
            };
            let selection = temp.path().join("selection");
            fs::create_dir(&selection).unwrap();
            fs::set_permissions(&selection, fs::Permissions::from_mode(0o700)).unwrap();
            save_selection(&selection, &config, "first", 1);
            let state = Arc::new(Mutex::new(Shared {
                calls: Vec::new(),
                attempts: BTreeMap::new(),
                starts: 0,
                behavior,
                fenced: false,
            }));
            let stop = Arc::new(AtomicBool::new(false));
            let server_state = Arc::clone(&state);
            let server_stop = Arc::clone(&stop);
            let server_repo = repo.clone();
            let server = thread::spawn(move || {
                while !server_stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            stream
                                .set_read_timeout(Some(Duration::from_secs(5)))
                                .unwrap();
                            let mut line = String::new();
                            BufReader::new(&stream).read_line(&mut line).unwrap();
                            let message: Value = serde_json::from_str(&line).unwrap();
                            let mut state = server_state.lock().unwrap();
                            state.calls.push(message.clone());
                            let result = produce(&message, &mut state, &server_repo);
                            if let Some(result) = result {
                                let response =
                                    json!({"id":message["id"],"ok":true,"result":result});
                                let mut bytes = serde_json::to_vec(&response).unwrap();
                                bytes.push(b'\n');
                                if let Err(error) = stream.write_all(&bytes) {
                                    assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
                                }
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(25))
                        }
                        Err(error) => panic!("synthetic Broker accept: {error}"),
                    }
                }
            });
            Self {
                _temp: temp,
                repo,
                selection,
                config,
                state,
                stop,
                server: Some(server),
            }
        }

        fn provider_config(&self, alias: &str) -> AccountBrokerProviderConfig {
            AccountBrokerProviderConfig {
                client: self.config.clone(),
                repo: self.repo.clone(),
                selection_state: self.selection.clone(),
                alias: alias.into(),
                model: "example-model".into(),
                reasoning_effort: ModelEffort::High,
                admission: BrokerAdmissionPolicy {
                    max_tokens: RequestBudget::default().max_total_tokens * 2,
                    window_seconds: 86400,
                    require_hard_spend_cap: false,
                },
            }
        }

        fn provider(&self, alias: &str) -> AccountBrokerProvider {
            AccountBrokerProvider::new(self.provider_config(alias)).unwrap()
        }
        fn select(&self, alias: &str, revision: u64) {
            save_selection(&self.selection, &self.config, alias, revision);
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::Release);
            self.server.take().unwrap().join().unwrap();
        }
    }

    fn save_selection(path: &Path, config: &AccountClientConfig, alias: &str, revision: u64) {
        let mut bytes = b"MACO-account-management-endpoint-v1\0".to_vec();
        bytes.extend_from_slice(&config.expected_uid.to_be_bytes());
        bytes.extend_from_slice(config.socket.as_os_str().as_encoded_bytes());
        let endpoint = digest(&bytes)[7..].to_string();
        fs::write(path.join("selection.json"), serde_json::to_vec(&json!({"schema_version":1,"endpoint_binding":endpoint,"selection":{"revision":revision,"selected_alias":alias}})).unwrap()).unwrap();
        fs::set_permissions(
            path.join("selection.json"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
    }

    fn llm_request(id: &str, provider: &AccountBrokerProvider) -> LlmRequest {
        let mut context = PromptContext::new("Return a proposal.", "fixture-agent");
        context.provider_capabilities = provider.capabilities();
        let mut request = LlmRequest::new(
            id,
            "example-model",
            context.assemble_prompt(&Redactor::new()),
        );
        request.metadata.insert(
            "maco_agent_policy".into(),
            json!({"claims":["README.md"],"commands":"disabled","validation":[]}).to_string(),
        );
        request
    }

    fn produce(message: &Value, state: &mut Shared, repo: &Path) -> Option<Value> {
        let args = &message["arguments"];
        let nonce = args["request_nonce"].as_str().unwrap();
        match message["capability"].as_str().unwrap() {
            "accounts.invocation.prepare" => {
                if matches!(state.behavior, Behavior::Refused) {
                    return Some(
                        json!({"schema_version":1,"outcome":"refused","reason":"identity_unverified"}),
                    );
                }
                let request: InvocationRequest =
                    serde_json::from_value(args["request"].clone()).unwrap();
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs();
                let pool = if request.alias == "first" {
                    "00000000-0000-4000-8000-000000000003"
                } else {
                    "00000000-0000-4000-8000-000000000004"
                };
                let attempt = json!({"attempt_id":"00000000-0000-4000-8000-000000000002","request_nonce":nonce,
                    "binding":{"alias":request.alias,"provider":"openai","runtime":"codex","account_pool_id":pool,
                    "credential_generation":"00000000-0000-4000-8000-000000000005","selection_revision":request.selection_revision,
                    "model":request.model,"reasoning_effort":request.reasoning_effort,"policy_digest":request.policy_digest,
                    "prompt_digest":digest(request.input.prompt().as_bytes()),"request_digest":request.digest().unwrap()},
                    "state":"prepared","effect":"not_dispatched","prepared_at":now,"started_at":null,"broker_deadline":null,"finished_at":null,
                    "proposal":null,"usage":{"state":"unknown","snapshot":null},"failure":null});
                state.attempts.insert(nonce.to_string(), attempt);
            }
            "accounts.invocation.start" => {
                state.starts += 1;
                let records = journal_records(&repo.join(".git").join("maco"));
                state.fenced = records.iter().any(|r| r["phase"] == "start_requested")
                    && records
                        .iter()
                        .any(|r| r["payload"]["kind"] == "reservation");
                let attempt = state.attempts.get_mut(nonce).unwrap();
                let now = attempt["prepared_at"].as_u64().unwrap();
                attempt["started_at"] = json!(now);
                attempt["broker_deadline"] = json!(now + 60);
                attempt["finished_at"] = json!(now);
                attempt["state"] = json!("completed");
                attempt["effect"] = json!("terminal_observed");
                attempt["proposal"] =
                    json!({"summary":"proposal","commands":[],"patches":[],"notes":[]});
                let counters = json!({"input_tokens":120,"cached_input_tokens":10,"output_tokens":30,"reasoning_output_tokens":10,"total_tokens":150});
                attempt["usage"] = json!({"state":"final","snapshot":{"source":"codex_thread_token_usage","total":counters,"last":counters}});
                match state.behavior {
                    Behavior::MissingUsage => {
                        attempt["usage"] = json!({"state":"unknown","snapshot":null})
                    }
                    Behavior::ChangedGeneration => {
                        attempt["binding"]["credential_generation"] =
                            json!("00000000-0000-4000-8000-000000000099")
                    }
                    Behavior::PartialUnknown => {
                        attempt["state"] = json!("unknown");
                        attempt["effect"] = json!("possibly_dispatched");
                        attempt["proposal"] = Value::Null;
                        attempt["failure"] = json!("transport_lost");
                        attempt["usage"]["state"] = json!("partial");
                    }
                    Behavior::LoseStart => return None,
                    Behavior::RateLimited => {
                        attempt["state"] = json!("failed");
                        attempt["failure"] = json!("rate_limited");
                        attempt["proposal"] = Value::Null;
                    }
                    Behavior::PartialThenUnknown
                    | Behavior::PartialThenRegressiveFinal
                    | Behavior::HoldPartial => {
                        attempt["state"] = json!("running");
                        attempt["effect"] = json!("possibly_dispatched");
                        attempt["finished_at"] = Value::Null;
                        attempt["proposal"] = Value::Null;
                        let high = RequestBudget::default().max_total_tokens + 1;
                        let counters = json!({"input_tokens":high,"cached_input_tokens":0,"output_tokens":0,"reasoning_output_tokens":0,"total_tokens":high});
                        attempt["usage"] = json!({"state":"partial","snapshot":{"source":"codex_thread_token_usage","total":counters,"last":counters}});
                    }
                    Behavior::LargePatch => {
                        attempt["proposal"]["patches"] =
                            json!([{"path":"README.md","unified_diff":"x".repeat(40 * 1024)}]);
                    }
                    _ => {}
                }
            }
            "accounts.invocation.status" => {
                let attempt = state.attempts.get_mut(nonce).unwrap();
                match state.behavior {
                    Behavior::PartialThenUnknown => {
                        attempt["state"] = json!("unknown");
                        attempt["finished_at"] = attempt["prepared_at"].clone();
                        attempt["failure"] = json!("transport_lost");
                        attempt["usage"] = json!({"state":"unknown","snapshot":null});
                    }
                    Behavior::PartialThenRegressiveFinal => {
                        attempt["state"] = json!("completed");
                        attempt["effect"] = json!("terminal_observed");
                        attempt["finished_at"] = attempt["prepared_at"].clone();
                        attempt["proposal"] =
                            json!({"summary":"proposal","commands":[],"patches":[],"notes":[]});
                        let counters = json!({"input_tokens":120,"cached_input_tokens":10,"output_tokens":30,"reasoning_output_tokens":10,"total_tokens":150});
                        attempt["usage"] = json!({"state":"final","snapshot":{"source":"codex_thread_token_usage","total":counters,"last":counters}});
                    }
                    _ => {}
                }
            }
            other => panic!("unexpected provider discovery or operation: {other}"),
        }
        Some(json!({"schema_version":1,"outcome":"attempt","attempt":state.attempts[nonce]}))
    }

    fn journal_records(root: &Path) -> Vec<Value> {
        let mut result = Vec::new();
        if !root.is_dir() {
            return result;
        }
        for entry in fs::read_dir(root).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                result.extend(journal_records(&path));
            } else if path
                .file_name()
                .and_then(|n| n.to_str())
                .is_some_and(|name| {
                    name.len() == 25
                        && name[..20].bytes().all(|c| c.is_ascii_digit())
                        && name.ends_with(".json")
                })
            {
                result.push(serde_json::from_slice(&fs::read(path).unwrap()).unwrap());
            }
        }
        result
    }

    #[test]
    fn final_usage_has_durable_reservation_and_replay_never_starts_again() {
        let fixture = Fixture::new(Behavior::Complete);
        let mut provider = fixture.provider("first");
        assert_eq!(provider.capabilities().max_context_tokens, None);
        let response = provider
            .complete(llm_request("task-one", &provider))
            .unwrap();
        assert_eq!(response.usage.total_tokens, 150);
        let metadata = response.broker_attempt.unwrap();
        assert_eq!(metadata.accounting.charged_tokens, Some(150));
        assert_eq!(
            metadata.accounting.charge_kind,
            Some(BrokerChargeKind::ObservedFinal)
        );
        assert!(metadata.accounting.settled);
        assert!(fixture.state.lock().unwrap().fenced);
        let mut replay = fixture.provider("first");
        assert!(
            matches!(replay.complete(llm_request("task-one", &replay)), Err(ProviderError::AccountBroker(error)) if error.reason == BrokerProviderFailure::ReplayBlocked)
        );
        assert_eq!(fixture.state.lock().unwrap().starts, 1);
    }

    #[test]
    fn lost_start_reply_recovers_only_status_with_same_identity() {
        let fixture = Fixture::new(Behavior::LoseStart);
        let mut provider = fixture.provider("first");
        assert!(provider
            .complete(llm_request("lost-reply", &provider))
            .is_ok());
        let state = fixture.state.lock().unwrap();
        assert_eq!(state.starts, 1);
        assert_eq!(
            state
                .calls
                .iter()
                .map(|c| c["capability"].as_str().unwrap())
                .collect::<Vec<_>>(),
            vec![
                "accounts.invocation.prepare",
                "accounts.invocation.start",
                "accounts.invocation.status"
            ]
        );
    }

    #[test]
    fn missing_partial_and_rebound_outcomes_cannot_return_a_proposal() {
        for behavior in [
            Behavior::MissingUsage,
            Behavior::PartialUnknown,
            Behavior::ChangedGeneration,
        ] {
            let fixture = Fixture::new(behavior);
            let mut provider = fixture.provider("first");
            let error = provider
                .complete(llm_request("uncertain", &provider))
                .unwrap_err();
            let ProviderError::AccountBroker(error) = error else {
                panic!("typed attempt evidence required");
            };
            assert!(error.attempt.accounting.settled);
            assert_eq!(
                error.attempt.accounting.charge_kind,
                Some(BrokerChargeKind::ConservativeReservation)
            );
            assert_eq!(
                error.attempt.accounting.charged_tokens,
                Some(RequestBudget::default().max_total_tokens)
            );
            assert_eq!(fixture.state.lock().unwrap().starts, 1);
        }
    }

    #[test]
    fn later_unknown_or_regressive_final_preserves_the_highest_observed_total() {
        for behavior in [
            Behavior::PartialThenUnknown,
            Behavior::PartialThenRegressiveFinal,
        ] {
            let fixture = Fixture::new(behavior);
            let mut provider = fixture.provider("first");
            let Err(ProviderError::AccountBroker(error)) =
                provider.complete(llm_request("partial-first", &provider))
            else {
                panic!("uncertain or regressive usage must stop proposal application");
            };
            let high = RequestBudget::default().max_total_tokens + 1;
            assert_eq!(error.attempt.observed_token_lower_bound, Some(high as u64));
            assert_eq!(error.attempt.accounting.charged_tokens, Some(high));
            assert_eq!(
                error.attempt.accounting.charge_kind,
                Some(BrokerChargeKind::ConservativeReservation)
            );
            assert_eq!(
                error.reason,
                if matches!(behavior, Behavior::PartialThenUnknown) {
                    BrokerProviderFailure::RemoteFailed
                } else {
                    BrokerProviderFailure::Protocol
                }
            );
            let records = journal_records(&fixture.repo.join(".git/maco"));
            let settled: Vec<_> = records
                .iter()
                .filter(|r| r["payload"]["kind"] == "reservation_reconciled")
                .collect();
            assert_eq!(settled.len(), 1);
            assert_eq!(settled[0]["payload"]["tokens"], high);
            assert_eq!(settled[0]["payload"]["requests"], 1);
        }
    }

    #[test]
    fn complete_patch_payload_obeys_output_bound_after_usage_settlement() {
        let fixture = Fixture::new(Behavior::LargePatch);
        let mut provider = fixture.provider("first");
        let Err(ProviderError::AccountBroker(error)) =
            provider.complete(llm_request("large-diff", &provider))
        else {
            panic!("full patch contents must count against the output limit");
        };
        assert_eq!(error.reason, BrokerProviderFailure::LocalOutputLimit);
        assert_eq!(error.attempt.accounting.charged_tokens, Some(150));
        assert!(error.attempt.accounting.settled);
        assert_eq!(
            fs::read_to_string(fixture.repo.join("README.md")).unwrap(),
            "original\n"
        );
    }

    #[test]
    fn caller_process_floor_fixture() {
        let Some(root) = std::env::var_os("MACO_INVOCATION_CRASH_FIXTURE") else {
            return;
        };
        let root = PathBuf::from(root);
        let mut provider = AccountBrokerProvider::new(AccountBrokerProviderConfig {
            client: AccountClientConfig {
                socket: root.join("broker.sock"),
                expected_uid: unsafe { libc::geteuid() },
                timeout: Duration::from_secs(5),
            },
            repo: root.join("repo"),
            selection_state: root.join("selection"),
            alias: "first".into(),
            model: "example-model".into(),
            reasoning_effort: ModelEffort::High,
            admission: BrokerAdmissionPolicy {
                max_tokens: RequestBudget::default().max_total_tokens * 2,
                window_seconds: 86400,
                require_hard_spend_cap: false,
            },
        })
        .unwrap();
        let _result = provider.complete(llm_request("crash-task", &provider));
        panic!("parent must terminate this caller while its remote attempt is still running");
    }

    #[test]
    fn process_death_recovers_observed_floor_before_a_different_task_is_admitted() {
        let fixture = Fixture::new(Behavior::HoldPartial);
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "linux::caller_process_floor_fixture",
                "--nocapture",
            ])
            .env("MACO_INVOCATION_CRASH_FIXTURE", fixture._temp.path())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = Instant::now() + fixture.config.timeout;
        let observed = loop {
            let records = journal_records(&fixture.repo.join(".git/maco"));
            let has_floor = records
                .iter()
                .any(|r| r["payload"]["kind"] == "reservation_observed_floor");
            let polled = fixture
                .state
                .lock()
                .unwrap()
                .calls
                .iter()
                .any(|c| c["capability"] == "accounts.invocation.status");
            // A status call proves the preceding floor publication returned successfully.
            if has_floor && polled {
                break true;
            }
            if Instant::now() >= deadline || child.try_wait().unwrap().is_some() {
                break false;
            }
            thread::sleep(Duration::from_millis(25));
        };
        if child.try_wait().unwrap().is_none() {
            child.kill().unwrap();
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            observed,
            "caller never durably observed the floor: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(!output.status.success());
        fixture.state.lock().unwrap().behavior = Behavior::Complete;
        for id in ["different-task", "another-different-task"] {
            let mut provider = fixture.provider("first");
            assert!(
                matches!(provider.complete(llm_request(id, &provider)), Err(ProviderError::AccountBroker(error)) if error.reason == BrokerProviderFailure::BudgetRefused)
            );
        }
        let records = journal_records(&fixture.repo.join(".git/maco"));
        let reservation = records
            .iter()
            .find(|r| r["payload"]["kind"] == "reservation")
            .unwrap();
        let settled: Vec<_> = records
            .iter()
            .filter(|r| r["payload"]["kind"] == "reservation_reconciled")
            .collect();
        assert_eq!(settled.len(), 1);
        assert_eq!(
            settled[0]["payload"]["tokens"],
            RequestBudget::default().max_total_tokens + 1
        );
        assert_eq!(settled[0]["payload"]["requests"], 1);
        assert_eq!(
            settled[0]["payload"]["pool"],
            reservation["payload"]["pool"]
        );
        assert_eq!(settled[0]["payload"]["recovered_after_process_death"], true);
        assert!(settled[0]["payload"]["cost_usd"].is_null());
        assert_eq!(fixture.state.lock().unwrap().starts, 1);
    }

    #[test]
    fn selection_endpoint_and_hard_cap_refusals_happen_before_broker_access() {
        let fixture = Fixture::new(Behavior::Complete);
        let mut provider = fixture.provider("second");
        assert!(provider
            .complete(llm_request("wrong-pin", &provider))
            .is_err());
        let mut config = fixture.provider_config("first");
        config.client.socket = fixture.config.socket.with_file_name("other.sock");
        let mut other = AccountBrokerProvider::new(config).unwrap();
        assert!(other
            .complete(llm_request("wrong-endpoint", &other))
            .is_err());
        let mut config = fixture.provider_config("first");
        config.admission.require_hard_spend_cap = true;
        assert!(matches!(
            AccountBrokerProvider::new(config),
            Err(ProviderError::UnsupportedCapability(_))
        ));
        assert!(fixture.state.lock().unwrap().calls.is_empty());
    }

    #[test]
    fn same_runtime_accounts_keep_distinct_attribution_without_discovery() {
        let fixture = Fixture::new(Behavior::Complete);
        let mut first = fixture.provider("first");
        let one = first.complete(llm_request("first-work", &first)).unwrap();
        fixture.select("second", 2);
        let mut second = fixture.provider("second");
        let two = second
            .complete(llm_request("second-work", &second))
            .unwrap();
        assert_ne!(
            one.broker_attempt.unwrap().binding.unwrap().account_pool_id,
            two.broker_attempt.unwrap().binding.unwrap().account_pool_id
        );
        let records = journal_records(&fixture.repo.join(".git").join("maco"));
        let pools = records
            .iter()
            .filter(|r| r["payload"]["kind"] == "reservation")
            .map(|r| r["payload"]["pool"]["account"].clone())
            .collect::<Vec<_>>();
        assert_eq!(pools.len(), 2);
        assert_ne!(pools[0], pools[1]);
        assert_eq!(fixture.state.lock().unwrap().starts, 2);
    }

    #[test]
    fn explicit_refusal_and_frame_overflow_never_reserve_or_start() {
        let fixture = Fixture::new(Behavior::Refused);
        let mut provider = fixture.provider("first");
        assert!(provider
            .complete(llm_request("refused", &provider))
            .is_err());
        assert_eq!(fixture.state.lock().unwrap().starts, 0);
        assert!(provider
            .last_attempt()
            .unwrap()
            .accounting
            .reservation_id
            .is_none());
        let fixture = Fixture::new(Behavior::Complete);
        let mut provider = fixture.provider("first");
        let mut request = llm_request("oversize", &provider);
        request.prompt.sections[0].body = "\"".repeat(32 * 1024);
        assert!(provider.complete(request).is_err());
        assert!(fixture.state.lock().unwrap().calls.is_empty());
    }

    #[test]
    fn rate_limit_latch_follows_exact_account_attribution_after_manual_switch() {
        let fixture = Fixture::new(Behavior::RateLimited);
        let mut first = fixture.provider("first");
        assert!(first
            .complete(llm_request("limited-first", &first))
            .is_err());
        fixture.state.lock().unwrap().behavior = Behavior::Complete;
        fixture.select("second", 2);
        let mut second = fixture.provider("second");
        assert!(second
            .complete(llm_request("allowed-second", &second))
            .is_ok());
        fixture.select("first", 3);
        let mut first = fixture.provider("first");
        assert!(
            matches!(first.complete(llm_request("still-limited-first", &first)), Err(ProviderError::AccountBroker(error)) if error.reason == BrokerProviderFailure::BudgetRefused)
        );
        assert_eq!(fixture.state.lock().unwrap().starts, 2);
    }

    #[test]
    fn real_agent_cli_keeps_missing_usage_proposal_unapplied_and_reports_attempt(
    ) -> anyhow::Result<()> {
        crate::support::require_containment!(
            "real_agent_cli_keeps_missing_usage_proposal_unapplied_and_reports_attempt"
        );
        let fixture = Fixture::new(Behavior::MissingUsage);
        let task = fixture._temp.path().join("task.md");
        fs::write(&task, "Return a README proposal.").unwrap();
        let output = Command::new(env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator"))
            .arg("agent")
            .arg("run")
            .arg(&task)
            .args([
                "--agent-id",
                "account-fixture",
                "--path",
                "README.md",
                "--provider",
                "account-broker",
                "--model",
                "example-model",
                "--reasoning-effort",
                "high",
                "--account-alias",
                "first",
                "--broker-admission-tokens",
                "49152",
                "--json",
            ])
            .arg("--broker-socket")
            .arg(&fixture.config.socket)
            .arg("--broker-uid")
            .arg(fixture.config.expected_uid.to_string())
            .arg("--account-state-dir")
            .arg(&fixture.selection)
            .arg("--repo")
            .arg(&fixture.repo)
            .output()
            .unwrap();
        assert!(!output.status.success());
        let report: Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(
            report["broker_attempt"]["observed_state"],
            "completed",
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(report["broker_attempt"]["usage"]["state"], "unknown");
        assert_eq!(
            report["broker_attempt"]["accounting"]["charge_kind"],
            "conservative_reservation"
        );
        assert_eq!(
            fs::read_to_string(fixture.repo.join("README.md")).unwrap(),
            "original\n"
        );
        assert_eq!(fixture.state.lock().unwrap().starts, 1);
        Ok(())
    }
}
