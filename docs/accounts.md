# Account capability discovery and policy preview

`maco accounts` queries an explicitly configured Linux capability service. The
current service protocol supports registered OpenAI accounts using the Codex
runtime. Discovery does not inspect local credentials, change a global login,
invoke a model, or switch accounts automatically. Each discovery and preview
requires one exact account alias. Listing aliases performs no provider discovery.

```sh
maco accounts --broker-socket "$BROKER_SOCKET" --broker-uid "$BROKER_UID" list
maco accounts --broker-socket "$BROKER_SOCKET" --broker-uid "$BROKER_UID" discover example
maco accounts --broker-socket "$BROKER_SOCKET" --broker-uid "$BROKER_UID" preview example --policies policy-input.json
```

Discovery and preview results are JSON. Errors expose fixed codes without upstream messages or
endpoint paths. Other platforms return `unsupported_platform`. There is no
implicit endpoint, account fallback, or automatic discovery across registrations.
Disabled and unlisted accounts cannot become eligible through a manual pin.

The Linux client requires the configured service UID on the socket and its
runtime directory, socket permissions `0660`, and a runtime directory with no
world access or group write permission (`0700` and `0750` are compatible).
Ancestors must be owned by root or the expected service UID and must not be
group/other writable. Component-wise descriptor-relative opens refuse symlinks;
the connection checks `SO_PEERCRED` and the socket inode before sending a request.
The request deadline includes connection and all I/O. `--timeout-seconds` may be
set from 1 to 60; the default is the service contract maximum of 60 seconds.
Each newline-terminated JSON frame is at most 64 KiB, including the newline.

The discovery request vocabulary is `accounts.list` with `{}` and
`accounts.discover` with `{"alias":"example"}`. Each request has an integer
`id`, `capability`, and `arguments`. A reply carries the matching `id` and either
`ok:true,result` or `ok:false,error:{code,message}`. Conflicting outcomes,
duplicate fields, unknown fields and enum variants, malformed bounds, and
duplicate account/model identities are refused. The public DTOs in
`src/accounts/protocol.rs` define the version 1 result schema.

## Local account management

```sh
maco accounts --broker-socket "$BROKER_SOCKET" --broker-uid "$BROKER_UID" \
  manage --state-dir "$PRIVATE_ACCOUNT_STATE" --bind 127.0.0.1:0
```

The command prints one local URL and serves a Japanese account-management screen.
Port zero, the default, chooses an available port. Only an explicit loopback
address is accepted. Keep the terminal running and open its URL in a browser.
This server is separate from the read-only Scope server.

The screen lists registered aliases without querying providers. Choose an enabled
account with **このアカウントを使う**. Refresh queries only that selected alias;
page load and list refresh do not discover account metadata. Quota displays show
the reported window duration, usage percentage and reset time. A countdown passing
zero does not imply replenishment: another explicit refresh is needed.

**ログイン / 再認証** starts the optional managed device-login capability for that
exact alias. The service must explicitly enable it. Open the fixed official device
page and enter the opaque code displayed as text. The screen polls only an existing
login operation; it does not invoke a model. A completed login does not select an
account. Cancellation stops this login operation and does not promise logout,
revocation, or rollback of credentials already saved by the provider.

Login handles and request nonces are scoped to the service process lifetime. Status
recovery after reload never replays login start. A terminal replacement requires
the previous handle and a fresh nonce created by an explicit click. Unknown
completion requires a status check or another explicit user action. The displayed
operation deadline is distinct from the unknown server-side device-code expiry.
The closed login DTOs and fixed verification URL are in `src/accounts/login_protocol.rs`.

Manual selection is stored with a revision in an owner-private directory, bound
to the configured service endpoint and UID. Atomic writes and a kernel lock protect
the selection; stale revisions and reuse with another endpoint are refused. Saved
selection is a preference for future integration, not an execution grant. It does
not modify an active task or the supervisor's dispatch. This release does not run
models, schedule inference after quota resets, or provide other provider backends.

The local URL contains a random session secret in its fragment. The browser clears
the fragment and retains the secret only in that tab's session storage for reload.
Every API read and write is a POST with exact Host/Origin checks and a session
Bearer header. Bootstrap assets are local, there is no CORS, and a restrictive CSP
and no-referrer policy apply. Requests, login codes, verification URLs and provider
details are not logged or persisted. The only durable data is the endpoint digest,
manual alias and revision. Use a separate private state directory per endpoint.

HTTP header, connection and concurrency bounds match Scope (16 KiB headers,
5-second header/write timeout and 64 connections); bodies and API responses use
the 64 KiB account frame bound. Body reads have a complete 60-second deadline and
each backend request retains the configured account-client deadline. These bounds
are not account quota or model budget settings.

Discovery contains sanitized aliases, model/effort metadata, authentication
provenance and quota-window observations. A local login or model list does not
prove remote authentication or model entitlement. Unknown quota has no inferred
balance, token count or unlimited allowance. Passing a reported reset time does
not replenish quota in this client; it requires another observation.

Every observation has its own `observation_id`. That identifies a metadata
attempt, not a credential or policy revision. `observed_at` marks the attempt
start, not the provider's catalog freshness. Version 1 always has null
`expires_at`, unknown model entitlement, and unknown or unavailable generation
availability. Even a fresh successful discovery therefore requires revalidation
and cannot authorize execution.

The preview input binds each complete execution policy to an account, model and
effort. Existing model-only `CandidateKey` values remain unchanged; the
`AccountBoundCandidate` wrapper keeps two accounts with the same model distinct.
Policy identities must be unique, and every binding must match the manual pin.
The policy's effort must match the candidate exactly. Preview currently accepts
the selector's `low`, `medium`, `high`, `xhigh`, `max`, and `ultra` efforts;
discovery also preserves `none` and `minimal` without silently coercing them.

This example intentionally supplies no quality or cost evidence:

```json
{
  "schema_version": 1,
  "account_alias": "example",
  "quality_threshold_bp": 8000,
  "policies": [{
    "policy_id": "example-policy",
    "binding": {
      "account_alias": "example",
      "candidate": {"runtime": "codex", "model": "example-model", "effort": "high"}
    },
    "evidence": null
  }]
}
```

When evidence exists, `evidence` is
`{"evaluation": <the existing optimizer EvaluatedPolicy JSON>}`. Its exact
policy identity, certified-quality conjunction, confidence lower bound, total
cost to certification, caller resource constraint, and canonical effort are
caller-supplied complete-policy evidence. The preview does not authenticate or
create that evidence. Quality labels or catalog entries for a naked model are
not certificates for a complete execution policy.

The CLI calls the existing `EvaluationFunction` with the supplied policy
evidence. It preserves the shipped hard quality floor of 8000 basis points
(a caller can raise it), and ANDs the caller's resource condition with account
operational conditions. Missing evidence stays uncertified; its internal invalid
cost sentinel is not an estimate. No model is run to fill metadata or evidence.
The report includes per-policy blockers and the content digest of the sorted
listed account descriptors, separate from the discovery observation identity.
The digest is only inventory content identity, not an authorization revision.

Under version 1's unknown entitlement/availability and null expiry, operational
feasibility remains unproven, so the actual evaluation is infeasible even when
caller quality/cost evidence passes. `execution_ready` is always false and
`revalidation_required` always true. This metadata preview is not connected to
supervisor dispatch, publication permission, OAuth UI, quota-reset inference,
or charged execution. Those require separately implemented and verified runtime
authority; this command never claims that manual execution switching is ready.
