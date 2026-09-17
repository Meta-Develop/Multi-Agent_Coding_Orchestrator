//! Public M6 router and relay contract tests. Network tests use loopback fakes;
//! no vendor endpoint or process is used.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{Response, StatusCode};
use axum::routing::any;
use axum::Router as AxumRouter;

use coding_agent_manager_lib::model::{
    ProviderQuotaList, QuotaListError, QuotaListErrorKind, QuotaListOutcome, QuotaSnapshot,
    QuotaSource, RouteRule,
};
use coding_agent_manager_lib::relay::{
    CoreTranslator, RelayConfig, RelayQuotaSource, RelayServer, RelayTarget, RelayUpstreamAuth,
    RoutedRelayTarget, WireFormat,
};
use coding_agent_manager_lib::router::{
    validate_rules, RouteAccount, RouteError, RouteRuleField, RouterState,
};
use coding_agent_manager_lib::storage::Secret;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

fn timestamp(value: &str) -> OffsetDateTime {
    OffsetDateTime::parse(value, &Rfc3339).expect("test timestamp")
}

fn now() -> OffsetDateTime {
    timestamp("2030-01-01T00:00:00Z")
}

fn rule(pattern: &str, provider: &str, target: &str) -> RouteRule {
    RouteRule {
        match_model: pattern.to_owned(),
        provider_id: provider.to_owned(),
        target_model: target.to_owned(),
        max_utilization: None,
    }
}

fn gated_rule(pattern: &str, provider: &str, target: &str, ceiling: f32) -> RouteRule {
    RouteRule {
        max_utilization: Some(ceiling),
        ..rule(pattern, provider, target)
    }
}

fn account(provider: &str, account: &str) -> RouteAccount {
    RouteAccount {
        provider_id: provider.to_owned(),
        account_id: account.to_owned(),
    }
}

fn snapshot(
    account: &str,
    model: Option<&str>,
    utilization: f32,
    resets_at: Option<&str>,
) -> QuotaSnapshot {
    QuotaSnapshot {
        account_id: account.to_owned(),
        model: model.map(str::to_owned),
        utilization,
        window_label: Some("FAKE-window".to_owned()),
        resets_at: resets_at.map(str::to_owned),
        captured_at: "2029-12-31T23:59:00Z".to_owned(),
        source: QuotaSource::Header,
    }
}

fn available(provider: &str, snapshots: Vec<QuotaSnapshot>) -> ProviderQuotaList {
    ProviderQuotaList {
        provider_id: provider.to_owned(),
        plan_label: None,
        snapshots,
        outcome: QuotaListOutcome::Available,
    }
}

fn no_signal(provider: &str) -> ProviderQuotaList {
    ProviderQuotaList {
        provider_id: provider.to_owned(),
        plan_label: None,
        snapshots: Vec::new(),
        outcome: QuotaListOutcome::NoSignal,
    }
}

fn failed(provider: &str) -> ProviderQuotaList {
    ProviderQuotaList {
        provider_id: provider.to_owned(),
        plan_label: None,
        snapshots: Vec::new(),
        outcome: QuotaListOutcome::Failed {
            error: QuotaListError {
                kind: QuotaListErrorKind::Other,
                path: None,
                message: "FAKE-quota-collection-failed".to_owned(),
            },
        },
    }
}

#[test]
fn route_rule_wire_contract_is_camel_case_and_closed() {
    let value = serde_json::to_value(gated_rule("model-*", "provider-a", "upstream-a", 0.5))
        .expect("serialize rule");
    assert_eq!(
        value,
        serde_json::json!({
            "matchModel": "model-*",
            "providerId": "provider-a",
            "targetModel": "upstream-a",
            "maxUtilization": 0.5
        })
    );

    let unknown = serde_json::json!({
        "matchModel": "model-*",
        "providerId": "provider-a",
        "targetModel": "upstream-a",
        "maxUtilization": null,
        "accountId": "FAKE-account-must-not-enter-rule"
    });
    assert!(serde_json::from_value::<RouteRule>(unknown).is_err());
}

#[test]
fn ordered_exact_and_prefix_matching_are_case_sensitive() {
    let rules = vec![
        rule("model-*", "provider-a", "upstream-a"),
        rule("model-pro", "provider-b", "upstream-b"),
    ];
    let accounts = vec![
        account("provider-a", "account-a"),
        account("provider-b", "account-b"),
    ];
    let mut router = RouterState::default();

    let selection = router
        .select_next(&rules, &accounts, &[], "model-pro", 0, now())
        .expect("ordered prefix match");
    assert_eq!(selection.rule_index, 0);
    assert_eq!(selection.provider_id, "provider-a");
    assert_eq!(selection.account_id, "account-a");
    assert_eq!(selection.target_model, "upstream-a");

    assert_eq!(
        router.select_next(&rules, &accounts, &[], "MODEL-pro", 0, now()),
        Err(RouteError::UnmatchedModel)
    );

    let exact = vec![rule("model-pro", "provider-b", "upstream-b")];
    assert_eq!(
        router.select_next(&exact, &accounts, &[], "model-pro-plus", 0, now()),
        Err(RouteError::UnmatchedModel)
    );
}

#[test]
fn validation_rejects_bad_fields_without_echoing_them() {
    let invalid_patterns = ["", "model-*suffix", "model-**"];
    for pattern in invalid_patterns {
        let rules = [rule(pattern, "provider-a", "upstream-a")];
        assert_eq!(
            validate_rules(&rules),
            Err(RouteError::InvalidRule {
                rule_index: 0,
                field: RouteRuleField::MatchModel,
            })
        );
    }

    let bad_provider = [rule("model", "   ", "upstream")];
    assert!(matches!(
        validate_rules(&bad_provider),
        Err(RouteError::InvalidRule {
            field: RouteRuleField::ProviderId,
            ..
        })
    ));
    let bad_target = [rule("model", "provider", "   ")];
    assert!(matches!(
        validate_rules(&bad_target),
        Err(RouteError::InvalidRule {
            field: RouteRuleField::TargetModel,
            ..
        })
    ));
    for ceiling in [-0.01, 1.01, f32::INFINITY, f32::NAN] {
        let rules = [gated_rule("model", "provider", "upstream", ceiling)];
        assert!(matches!(
            validate_rules(&rules),
            Err(RouteError::InvalidRule {
                field: RouteRuleField::MaxUtilization,
                ..
            })
        ));
    }

    let submitted = "FAKE-secret-shaped-submitted-value";
    let error = validate_rules(&[rule(submitted, "provider", "")]).expect_err("invalid target");
    assert!(!error.to_string().contains(submitted));
}

#[test]
fn quota_uses_the_conservative_maximum_and_allows_equality() {
    let rules = vec![
        gated_rule("model", "provider-a", "upstream-a", 0.6),
        rule("model", "provider-b", "upstream-b"),
    ];
    let accounts = vec![
        account("provider-a", "account-a"),
        account("provider-b", "account-b"),
    ];
    let at_ceiling = vec![available(
        "provider-a",
        vec![
            snapshot("account-a", Some("upstream-a"), 0.4, None),
            snapshot("account-a", None, 0.6, None),
        ],
    )];
    let mut router = RouterState::default();
    assert_eq!(
        router
            .select_next(&rules, &accounts, &at_ceiling, "model", 0, now())
            .expect("equal utilization remains eligible")
            .provider_id,
        "provider-a"
    );

    let above = vec![available(
        "provider-a",
        vec![
            snapshot("account-a", Some("upstream-a"), 0.7, None),
            snapshot("account-a", None, 0.6, None),
        ],
    )];
    assert_eq!(
        router
            .select_next(&rules, &accounts, &above, "model", 0, now())
            .expect("above-ceiling route falls through")
            .provider_id,
        "provider-b"
    );
}

#[test]
fn every_missing_or_unusable_quota_case_makes_a_gated_rule_ungateable() {
    let rules = vec![
        gated_rule("model", "provider-a", "upstream-a", 0.8),
        rule("model", "provider-b", "upstream-b"),
    ];
    let accounts = vec![
        account("provider-a", "account-a"),
        account("provider-b", "account-b"),
    ];
    let mut invalid = snapshot("account-a", Some("upstream-a"), 0.2, None);
    invalid.captured_at = "not-a-timestamp".to_owned();
    let cases = vec![
        Vec::new(),
        vec![no_signal("provider-a")],
        vec![failed("provider-a")],
        vec![available(
            "provider-a",
            vec![snapshot("wrong-account", Some("upstream-a"), 0.2, None)],
        )],
        vec![available(
            "provider-a",
            vec![snapshot("account-a", Some("wrong-model"), 0.2, None)],
        )],
        vec![available("provider-a", Vec::new())],
        vec![available("provider-a", vec![invalid])],
    ];

    for quotas in cases {
        let selection = RouterState::default()
            .select_next(&rules, &accounts, &quotas, "model", 0, now())
            .expect("ungateable preferred rule must skip");
        assert_eq!(selection.provider_id, "provider-b");
    }
}

#[test]
fn ungated_rule_is_eligible_without_a_quota_signal() {
    let rules = [rule("model", "provider-a", "upstream-a")];
    let accounts = [account("provider-a", "account-a")];
    let selection = RouterState::default()
        .select_next(
            &rules,
            &accounts,
            &[no_signal("provider-a")],
            "model",
            0,
            now(),
        )
        .expect("ungated rule");
    assert_eq!(selection.account_id, "account-a");
    assert_eq!(selection.quota_resets_at, None);
}

#[test]
fn selection_returns_the_latest_applicable_future_reset() {
    let rules = [rule("model", "provider-a", "upstream-a")];
    let accounts = [account("provider-a", "account-a")];
    let quotas = [available(
        "provider-a",
        vec![
            snapshot(
                "account-a",
                Some("upstream-a"),
                0.2,
                Some("2030-01-01T00:10:00Z"),
            ),
            snapshot("account-a", None, 0.3, Some("2030-01-01T01:00:00Z")),
            snapshot(
                "account-a",
                Some("wrong-model"),
                0.9,
                Some("2030-01-02T00:00:00Z"),
            ),
            snapshot(
                "account-a",
                Some("upstream-a"),
                0.1,
                Some("2029-12-31T23:00:00Z"),
            ),
        ],
    )];
    let selection = RouterState::default()
        .select_next(&rules, &accounts, &quotas, "model", 0, now())
        .expect("selection");
    assert_eq!(
        selection.quota_resets_at,
        Some(timestamp("2030-01-01T01:00:00Z"))
    );
}

#[test]
fn unmatched_and_matching_but_ineligible_are_distinct() {
    let rules = [gated_rule("model-a", "provider-a", "upstream-a", 0.8)];
    let accounts = [account("provider-a", "account-a")];
    let mut router = RouterState::default();

    assert_eq!(
        router.select_next(&[], &accounts, &[], "model-a", 0, now()),
        Err(RouteError::UnmatchedModel)
    );
    assert_eq!(
        router.select_next(&rules, &accounts, &[], "model-b", 0, now()),
        Err(RouteError::UnmatchedModel)
    );
    assert_eq!(
        router.select_next(&rules, &accounts, &[], "model-a", 0, now()),
        Err(RouteError::NoEligibleRoute)
    );
}

#[test]
fn missing_or_duplicate_accounts_are_errors_not_fallback() {
    let rules = vec![
        rule("model", "provider-a", "upstream-a"),
        rule("model", "provider-b", "upstream-b"),
    ];
    let fallback_only = [account("provider-b", "account-b")];
    assert_eq!(
        RouterState::default().select_next(&rules, &fallback_only, &[], "model", 0, now()),
        Err(RouteError::MissingRouteAccount { rule_index: 0 })
    );

    let duplicate = [
        account("provider-a", "account-a"),
        account("provider-a", "account-a-duplicate"),
        account("provider-b", "account-b"),
    ];
    assert_eq!(
        RouterState::default().select_next(&rules, &duplicate, &[], "model", 0, now()),
        Err(RouteError::DuplicateRouteAccounts { rule_index: 0 })
    );
}

#[test]
fn throttle_skips_until_expiry_and_same_account_later_rules_stay_skipped() {
    let rules = vec![
        rule("model", "provider-a", "upstream-a-first"),
        rule("model", "provider-a", "upstream-a-second"),
        rule("model", "provider-b", "upstream-b"),
    ];
    let accounts = vec![
        account("provider-a", "account-a"),
        account("provider-b", "account-b"),
    ];
    let mut router = RouterState::default();
    let first = router
        .select_next(&rules, &accounts, &[], "model", 0, now())
        .expect("first account");
    let deadline = now() + Duration::minutes(10);
    router.record_rate_limit(&first, deadline);

    let failover = router
        .select_next(&rules, &accounts, &[], "model", first.rule_index + 1, now())
        .expect("same account skipped, next account selected");
    assert_eq!(failover.rule_index, 2);
    assert_eq!(failover.account_id, "account-b");

    let after_expiry = router
        .select_next(
            &rules,
            &accounts,
            &[],
            "model",
            0,
            deadline + Duration::seconds(1),
        )
        .expect("expired account eligible again");
    assert_eq!(after_expiry.rule_index, 0);
    assert_eq!(after_expiry.account_id, "account-a");
}

#[test]
fn rate_limit_deadline_updates_monotonically() {
    let rules = [rule("model", "provider-a", "upstream-a")];
    let accounts = [account("provider-a", "account-a")];
    let mut router = RouterState::default();
    let selection = router
        .select_next(&rules, &accounts, &[], "model", 0, now())
        .expect("selection");
    let later = now() + Duration::hours(1);
    let earlier = now() + Duration::minutes(5);

    router.record_rate_limit(&selection, later);
    router.record_rate_limit(&selection, earlier);
    assert_eq!(
        router.throttle_until("provider-a", "account-a"),
        Some(later)
    );
}

#[derive(Clone)]
struct StaticQuotaSource {
    quotas: Vec<ProviderQuotaList>,
}

impl RelayQuotaSource for StaticQuotaSource {
    fn snapshot(&self) -> Vec<ProviderQuotaList> {
        self.quotas.clone()
    }
}

#[derive(Clone)]
struct FakeUpstreamState {
    name: &'static str,
    status: StatusCode,
    retry_after: Option<&'static str>,
    requests: Arc<StdMutex<Vec<CapturedRequest>>>,
    order: Arc<StdMutex<Vec<String>>>,
}

#[derive(Debug)]
struct CapturedRequest {
    headers: HashMap<String, String>,
    body: serde_json::Value,
}

struct FakeUpstream {
    url: String,
    requests: Arc<StdMutex<Vec<CapturedRequest>>>,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl FakeUpstream {
    async fn start(
        name: &'static str,
        status: StatusCode,
        retry_after: Option<&'static str>,
        order: Arc<StdMutex<Vec<String>>>,
    ) -> Self {
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind fake upstream");
        let address = listener.local_addr().expect("fake upstream address");
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let state = FakeUpstreamState {
            name,
            status,
            retry_after,
            requests: Arc::clone(&requests),
            order,
        };
        let app = AxumRouter::new()
            .fallback(any(capture_upstream_request))
            .with_state(state);
        let (shutdown, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async move {
                    let _ = shutdown_rx.await;
                })
                .await
                .expect("serve fake upstream");
        });
        Self {
            url: format!("http://{address}/"),
            requests,
            shutdown: Some(shutdown),
            task,
        }
    }

    fn count(&self) -> usize {
        self.requests.lock().expect("captured requests").len()
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.expect("join fake upstream");
    }
}

async fn capture_upstream_request(
    State(state): State<FakeUpstreamState>,
    request: Request,
) -> Response<Body> {
    let mut headers = HashMap::new();
    for name in [
        "authorization",
        "x-api-key",
        "x-goog-api-key",
        "openai-organization",
        "openai-project",
        "x-goog-user-project",
        "cookie",
    ] {
        if let Some(value) = request.headers().get(name) {
            headers.insert(
                name.to_owned(),
                value.to_str().expect("fake header value").to_owned(),
            );
        }
    }
    let body = to_bytes(request.into_body(), 1024 * 1024)
        .await
        .expect("read fake request");
    let body = serde_json::from_slice(&body).expect("fake request JSON");
    state
        .requests
        .lock()
        .expect("captured requests")
        .push(CapturedRequest { headers, body });
    state
        .order
        .lock()
        .expect("request order")
        .push(state.name.to_owned());

    let mut builder = Response::builder()
        .status(state.status)
        .header("content-type", "application/json");
    if let Some(retry_after) = state.retry_after {
        builder = builder.header("retry-after", retry_after);
    }
    builder
        .body(Body::from(format!(r#"{{"servedBy":"{}"}}"#, state.name)))
        .expect("fake response")
}

fn ephemeral_relay() -> RelayConfig {
    RelayConfig {
        bind_address: "127.0.0.1".to_owned(),
        port: 0,
        auth_token: None,
    }
}

fn routed_target(
    provider_id: &str,
    account_id: &str,
    upstream: &FakeUpstream,
    dialect: WireFormat,
    token: &str,
) -> RoutedRelayTarget {
    let target = RelayTarget::new(&upstream.url, dialect)
        .expect("relay target")
        .with_auth(RelayUpstreamAuth::bearer(Secret::new(
            token.as_bytes().to_vec(),
        )))
        .expect("relay target auth");
    RoutedRelayTarget::new(provider_id, account_id, target).expect("routed target")
}

fn quota_source() -> Arc<dyn RelayQuotaSource> {
    Arc::new(StaticQuotaSource { quotas: Vec::new() })
}

async fn start_routed_server(
    rules: Vec<RouteRule>,
    targets: Vec<RoutedRelayTarget>,
) -> RelayServer {
    RelayServer::start_routed(
        ephemeral_relay(),
        rules,
        targets,
        quota_source(),
        Arc::new(CoreTranslator),
    )
    .await
    .expect("start routed relay")
}

async fn routed_request(port: u16, model: &str) -> reqwest::Response {
    reqwest::Client::new()
        .post(format!("http://127.0.0.1:{port}/v1/chat/completions"))
        .header("authorization", "Bearer FAKE-client-authorization")
        .header("x-api-key", "FAKE-client-x-api-key")
        .header("x-goog-api-key", "FAKE-client-google-api-key")
        .header("openai-organization", "FAKE-client-organization")
        .header("openai-project", "FAKE-client-project")
        .header("x-goog-user-project", "FAKE-client-google-project")
        .header("cookie", "session=FAKE-client-cookie")
        .header("content-type", "application/json")
        .body(
            serde_json::to_vec(&serde_json::json!({
                "model": model,
                "messages": [{ "role": "user", "content": "FAKE-prompt" }]
            }))
            .expect("request JSON"),
        )
        .send()
        .await
        .expect("send routed request")
}

#[tokio::test]
async fn routed_first_success_uses_only_its_selected_account_and_credential() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let first = FakeUpstream::start("first", StatusCode::OK, None, Arc::clone(&order)).await;
    let later = FakeUpstream::start("later", StatusCode::OK, None, Arc::clone(&order)).await;
    let unrelated =
        FakeUpstream::start("unrelated", StatusCode::OK, None, Arc::clone(&order)).await;
    let server = start_routed_server(
        vec![
            rule("client-model", "provider-a", "target-a"),
            rule("client-model", "provider-b", "target-b"),
        ],
        vec![
            routed_target(
                "provider-a",
                "account-a",
                &first,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-a",
            ),
            routed_target(
                "provider-b",
                "account-b",
                &later,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-b",
            ),
            routed_target(
                "provider-unrelated",
                "account-unrelated",
                &unrelated,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-unrelated",
            ),
        ],
    )
    .await;

    let response = routed_request(server.status().port, "client-model").await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(order.lock().expect("request order").as_slice(), ["first"]);
    assert_eq!(later.count(), 0);
    assert_eq!(unrelated.count(), 0);

    {
        let requests = first.requests.lock().expect("first requests");
        let captured = requests.first().expect("selected request");
        assert_eq!(
            captured.headers.get("authorization").map(String::as_str),
            Some("Bearer FAKE-selected-a")
        );
        for stripped in [
            "x-api-key",
            "x-goog-api-key",
            "openai-organization",
            "openai-project",
            "x-goog-user-project",
            "cookie",
        ] {
            assert!(
                !captured.headers.contains_key(stripped),
                "forwarded {stripped}"
            );
        }
        assert_eq!(captured.body["model"], "target-a");
    }

    server.stop().await.expect("stop relay");
    first.stop().await;
    later.stop().await;
    unrelated.stop().await;
}

#[tokio::test]
async fn routed_429_fails_over_then_immediately_skips_the_throttled_account() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let limited = FakeUpstream::start(
        "limited",
        StatusCode::TOO_MANY_REQUESTS,
        Some("120"),
        Arc::clone(&order),
    )
    .await;
    let fallback = FakeUpstream::start("fallback", StatusCode::OK, None, Arc::clone(&order)).await;
    let server = start_routed_server(
        vec![
            rule("client-model", "provider-a", "target-a"),
            rule("client-model", "provider-b", "target-b"),
        ],
        vec![
            routed_target(
                "provider-a",
                "account-a",
                &limited,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-a",
            ),
            routed_target(
                "provider-b",
                "account-b",
                &fallback,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-b",
            ),
        ],
    )
    .await;

    let first = routed_request(server.status().port, "client-model").await;
    assert_eq!(first.status(), StatusCode::OK);
    let second = routed_request(server.status().port, "client-model").await;
    assert_eq!(second.status(), StatusCode::OK);
    assert_eq!(
        order.lock().expect("request order").as_slice(),
        ["limited", "fallback", "fallback"]
    );
    assert_eq!(limited.count(), 1);
    assert_eq!(fallback.count(), 2);

    server.stop().await.expect("stop relay");
    limited.stop().await;
    fallback.stop().await;
}

#[tokio::test]
async fn routed_exhaustion_after_rate_limit_returns_the_sanitized_429() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let limited = FakeUpstream::start(
        "limited",
        StatusCode::TOO_MANY_REQUESTS,
        Some("75"),
        Arc::clone(&order),
    )
    .await;
    let server = start_routed_server(
        vec![rule("client-model", "provider-a", "target-a")],
        vec![routed_target(
            "provider-a",
            "account-a",
            &limited,
            WireFormat::OpenAiChatCompletions,
            "FAKE-selected-a",
        )],
    )
    .await;

    let response = routed_request(server.status().port, "client-model").await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(response.headers().get("retry-after").unwrap(), "75");
    let body = response.text().await.expect("sanitized rate-limit body");
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&body).expect("rate-limit JSON"),
        serde_json::json!({ "error": { "message": "relay upstream returned an error" } })
    );
    assert!(!body.contains("FAKE-"));
    assert_eq!(order.lock().expect("request order").as_slice(), ["limited"]);

    server.stop().await.expect("stop relay");
    limited.stop().await;
}

#[tokio::test]
async fn routed_unmatched_request_contacts_no_selected_or_unrelated_target() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let selected = FakeUpstream::start("selected", StatusCode::OK, None, Arc::clone(&order)).await;
    let unrelated =
        FakeUpstream::start("unrelated", StatusCode::OK, None, Arc::clone(&order)).await;
    let server = start_routed_server(
        vec![rule("known-model", "provider-a", "target-a")],
        vec![
            routed_target(
                "provider-a",
                "account-a",
                &selected,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-a",
            ),
            routed_target(
                "provider-unrelated",
                "account-unrelated",
                &unrelated,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-unrelated",
            ),
        ],
    )
    .await;

    let response = routed_request(server.status().port, "unknown-model").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(order.lock().expect("request order").is_empty());
    assert_eq!(selected.count(), 0);
    assert_eq!(unrelated.count(), 0);

    server.stop().await.expect("stop relay");
    selected.stop().await;
    unrelated.stop().await;
}

#[tokio::test]
async fn routed_non_rate_limit_failure_never_contacts_a_later_rule() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let failed = FakeUpstream::start(
        "failed",
        StatusCode::INTERNAL_SERVER_ERROR,
        None,
        Arc::clone(&order),
    )
    .await;
    let fallback = FakeUpstream::start("fallback", StatusCode::OK, None, Arc::clone(&order)).await;
    let server = start_routed_server(
        vec![
            rule("client-model", "provider-a", "target-a"),
            rule("client-model", "provider-b", "target-b"),
        ],
        vec![
            routed_target(
                "provider-a",
                "account-a",
                &failed,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-a",
            ),
            routed_target(
                "provider-b",
                "account-b",
                &fallback,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-b",
            ),
        ],
    )
    .await;

    let response = routed_request(server.status().port, "client-model").await;
    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(order.lock().expect("request order").as_slice(), ["failed"]);
    assert_eq!(fallback.count(), 0);

    server.stop().await.expect("stop relay");
    failed.stop().await;
    fallback.stop().await;
}

#[tokio::test]
async fn routed_translation_failure_never_contacts_a_later_rule() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let incompatible =
        FakeUpstream::start("incompatible", StatusCode::OK, None, Arc::clone(&order)).await;
    let fallback = FakeUpstream::start("fallback", StatusCode::OK, None, Arc::clone(&order)).await;
    let server = start_routed_server(
        vec![
            rule("client-model", "provider-a", "target-a"),
            rule("client-model", "provider-b", "target-b"),
        ],
        vec![
            routed_target(
                "provider-a",
                "account-a",
                &incompatible,
                WireFormat::AnthropicMessages,
                "FAKE-selected-a",
            ),
            routed_target(
                "provider-b",
                "account-b",
                &fallback,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-b",
            ),
        ],
    )
    .await;

    let response = routed_request(server.status().port, "client-model").await;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert!(order.lock().expect("request order").is_empty());
    assert_eq!(incompatible.count(), 0);
    assert_eq!(fallback.count(), 0);

    server.stop().await.expect("stop relay");
    incompatible.stop().await;
    fallback.stop().await;
}

#[tokio::test]
async fn routed_missing_or_ambiguous_target_catalog_is_rejected_before_bind() {
    let order = Arc::new(StdMutex::new(Vec::new()));
    let available =
        FakeUpstream::start("available", StatusCode::OK, None, Arc::clone(&order)).await;
    let rules = vec![
        rule("client-model", "provider-missing", "target-missing"),
        rule("client-model", "provider-b", "target-b"),
    ];
    let missing = RelayServer::start_routed(
        ephemeral_relay(),
        rules,
        vec![routed_target(
            "provider-b",
            "account-b",
            &available,
            WireFormat::OpenAiChatCompletions,
            "FAKE-selected-b",
        )],
        quota_source(),
        Arc::new(CoreTranslator),
    )
    .await;
    assert!(missing.is_err());

    let duplicate_rules = vec![rule("client-model", "provider-b", "target-b")];
    let ambiguous = RelayServer::start_routed(
        ephemeral_relay(),
        duplicate_rules,
        vec![
            routed_target(
                "provider-b",
                "account-b-one",
                &available,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-b-one",
            ),
            routed_target(
                "provider-b",
                "account-b-two",
                &available,
                WireFormat::OpenAiChatCompletions,
                "FAKE-selected-b-two",
            ),
        ],
        quota_source(),
        Arc::new(CoreTranslator),
    )
    .await;
    assert!(ambiguous.is_err());
    assert_eq!(available.count(), 0);
    assert!(order.lock().expect("request order").is_empty());

    available.stop().await;
}
