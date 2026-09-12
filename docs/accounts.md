# Account capability discovery and policy preview

`maco accounts` queries an explicitly configured Linux capability service. The
current service protocol supports registered OpenAI accounts using the Codex
runtime. It does not discover credentials, log in, change a global login,
invoke a model, or switch accounts automatically. Each discovery and preview
requires one exact account alias. Listing aliases performs no provider discovery.

```sh
maco accounts --broker-socket "$BROKER_SOCKET" --broker-uid "$BROKER_UID" list
maco accounts --broker-socket "$BROKER_SOCKET" --broker-uid "$BROKER_UID" discover example
maco accounts --broker-socket "$BROKER_SOCKET" --broker-uid "$BROKER_UID" preview example --policies policy-input.json
```

All results are JSON. Errors expose fixed codes without upstream messages or
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

The closed request vocabulary is `accounts.list` with `{}` and
`accounts.discover` with `{"alias":"example"}`. Each request has an integer
`id`, `capability`, and `arguments`. A reply carries the matching `id` and either
`ok:true,result` or `ok:false,error:{code,message}`. Conflicting outcomes,
duplicate fields, unknown fields and enum variants, malformed bounds, and
duplicate account/model identities are refused. The public DTOs in
`src/accounts/protocol.rs` define the version 1 result schema.

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
