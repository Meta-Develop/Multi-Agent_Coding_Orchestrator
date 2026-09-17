# MACO integration: manual account authority

Status: proposed version 1 contract tracked in [MACO issue #409](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/409).
The original design discussion is [CAM issue #16](https://github.com/Meta-Develop/Coding-Agent-Manager/issues/16).
This document specifies work to implement and review. It does not advertise a
working headless service, Codex launch adapter, or reset scheduler.

Coding Agent Manager owns accounts, login, and credential use.
[Multi-Agent Coding Orchestrator (MACO)](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator)
owns task execution, resource admission, proposal validation, and review. The
integration lets MACO request an operation using one explicitly selected account.
It does not choose another account when that operation cannot proceed.

## 1. Current implementation

These are repository implementation facts, not evidence that a vendor accepts a
credential or grants access to a model. Provider behavior remains subject to the
confidence markers in [the research notes](research/README.md).

| Existing seam                                              | Available today                                                                                                         | Required addition                                                                                                                                                  |
| ---------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ProviderAdapter` in `src-tauri/src/providers/mod.rs`      | Provider detection, account listing, capability declarations, and provider-specific lifecycle hooks.                    | Account-scoped observations and fixed operation capabilities.                                                                                                      |
| `StoredAccountRegistry` in the same module                 | Atomic versioned pending/complete/deleting metadata; at most one selected complete account per provider.                | Cross-process coordination, selection revisions, and account incarnation identity. The current mutex protects only one process.                                    |
| `launch_spec_for`, `select_launch_account`, `spawn_launch` | Adapter/account validation and core-owned child environment for Gemini and Grok. Credentials remain inside native code. | An immutable operation binding and structured lifecycle/result channel. Existing launch inherits stdio and returns a PID.                                          |
| `providers/codex_cli.rs`                                   | Isolated vendor login, stored-account listing, and a backed-up live `auth.json` switch.                                 | Managed account selection and isolated operation launch. Codex does not advertise `launch-tool`. Byte equality with live credentials is not remote authentication. |
| `providers/gemini_oauth.rs` and `providers/gemini_cli.rs`  | Native Google loopback OAuth and managed Gemini launch selection.                                                       | Integration lifecycle projections and verified subscription/model evidence. OAuth alone does not establish Google AI Pro entitlement.                              |
| `commands.rs` and the Accounts UI                          | Manual account actions and asynchronous waiting for blocking login.                                                     | Shared authority service calls and recoverable login progress. No common login status/cancel operation exists.                                                     |
| `model.rs`, `ProviderAdapter::quota`, and Dashboard        | Sourced snapshots and distinct available/no-signal/failed outcomes.                                                     | Every current adapter returns no numeric quota. Model discovery, quota persistence, and reset scheduling are absent.                                               |
| `main.rs`, `lib.rs`, and `Cargo.toml`                      | The default desktop feature retains Tauri; `--no-default-features` builds the native library without it.                | A headless authority service and shared service entry point; the library build does not implement them.                                                            |

The relay is a separate interface. Its runtime targets do not consume managed
account selection, and its ordered rules can advance after HTTP 429. The MACO
account route must not enter that fallback path. Existing relay behavior is not
changed by this proposal.

## 2. Deployment and authority

The first deployment places the manager authority and MACO in the same Linux/WSL
environment. The authority owns the managed account homes and credential store.
It runs independently of a webview. Desktop commands and headless commands use
the same native account service below the Tauri boundary; they must not maintain
competing account registries.

The initial transport is a local Unix socket with configured server identity and
an explicit caller policy. Both sides verify the peer using operating-system
credentials. Endpoint traversal must reject unsafe links, ownership, or writable
ancestry; filesystem permission and peer checks are required before dispatch.
The service must not become reachable through the unauthenticated relay.

A later Windows interface connects to this same authority through a separately
reviewed authenticated transport. It must not copy credentials to Windows or
silently select a Windows account instead. That transport is not part of version
1 implementation readiness. Unsupported platforms report that limitation.

Authentication is not proof of a user gesture. Selection and login mutations
belong to the explicit operator control path, not model-supplied plans, prompts,
or metadata. A MACO execution caller receives only the operation permissions
needed to observe and use its frozen selection.

The security rules in [SECURITY_MODEL.md](SECURITY_MODEL.md) continue to apply.
Only native adapter code resolves a credential or derives a managed home. IPC
must not accept arbitrary executables, arguments, working directories,
environment maps, credential locations, or upstream endpoints. Fixed operation
profiles belong to protected operator configuration and compiled adapters.

## 3. Version and request boundary

The proposed protocol uses UTF-8 JSON with a versioned envelope. Field names use
the existing camelCase convention. An operation tag selects a closed request
type; there is no generic command or argument passthrough.

```json
{
  "protocolVersion": 1,
  "requestId": "example-request",
  "operation": "selection.get",
  "providerId": "codex-cli"
}
```

A response echoes `protocolVersion` and `requestId` and contains exactly one of
`result` or `error`. Errors have a closed `code`, not raw subprocess output,
upstream error text, or filesystem paths. The version 1 codes are
`invalid-request`, `unsupported-version`, `access-denied`, `unsupported-operation`,
`unknown-account`, `stale-selection`, `stale-account`, `busy`,
`reauthentication-required`, `unavailable`, `state-unavailable`, and
`outcome-unknown`. A failed observation is data in its operation result when the
request itself was accepted; it must not masquerade as an empty successful list.

Unknown fields, duplicate fields, unknown operation/enum values, malformed
identifiers, and invalid numeric values are refusals. Missing optional evidence
has an explicit representation; absence must not acquire a numeric default.

The framing format, byte bounds, request deadlines, and identifier encodings
must be pinned in the implementation's wire schema before a client is enabled.
They are not inherited from the relay or from vendor model capacities. The
authority must enforce finite operator-configured admission and response bounds,
and the client must enforce compatible bounds independently. Oversized input or
output is refused, never truncated into a valid-looking request or proposal.

`authority.describe` returns the protocol version, opaque authority identity,
implemented operations, and applicable local transport bounds. Advertising an
operation is a promise that its implementation exists, not that every provider
supports it. Caller authentication precedes even this response.

## 4. Selection and account identity

A selection binding has the following fields:

| Field                                | Meaning                                                                                                                                                               |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `authorityId`                        | Opaque identity of this manager state. A different authority is not interchangeable.                                                                                  |
| `providerId`                         | Exact registered adapter, such as `codex-cli`.                                                                                                                        |
| `accountId` and `accountIncarnation` | Manager-assigned account identifier plus an opaque incarnation distinguishing replacement or re-created material. Neither is a vendor principal or credential digest. |
| `selectionRevision`                  | Opaque equality token changed by a selection mutation or invalidation. Clients do not parse it as a number.                                                           |

Selection remains per provider, matching the existing registry. MACO operator
configuration must name the provider and hold the returned exact binding; it
must not iterate other providers' selections when the requested route fails.
An account label, masked identity, list position, runtime name, or model name is
never an execution binding.

An ordinary verified refresh of the same account may preserve its incarnation.
An explicit replacement login or delete/re-create must invalidate it. If the
adapter cannot establish that an external change preserves identity, it must
refuse the old binding rather than assume continuity. Account identity is for
attribution; it proves no shared billing or quota boundary between accounts.

| Operation         | Closed input and effect                                                                                                                                                                                       |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `accounts.list`   | `providerId`; returns non-secret manager records and separately identified local observations. No login, remote model/quota probe, or automatic selection.                                                    |
| `selection.get`   | `providerId`; returns the selection binding or an explicit unselected result.                                                                                                                                 |
| `selection.set`   | Exact `providerId`, `accountId`, `accountIncarnation`, and expected revision from `selection.get`; changes selection only after validation. An unselected result also carries a revision for compare-and-set. |
| `account.observe` | Exact selection binding and an explicit set drawn from `auth`, `models`, and `quota`; queries only that account. Unsupported categories remain explicit.                                                      |

Selection validation and its atomic update require a shared cross-process lock.
The authority must re-read and compare state under that lock, without losing
concurrent settings. Incomplete/deleting accounts cannot be selected or launched.
Malformed state must be preserved and refused, not replaced with an empty
registry. An explicit initialization/recovery path is required when durable
state is absent or invalid.

Account use also requires a shared lease on the exact incarnation. Observation
and operation use hold that lease while accessing managed material. Replacement
login, deletion, or other incarnation-changing writes must wait or refuse while
it is in use; they cannot change a running child's identity underneath its
binding. Verified same-account refresh may continue under the adapter's documented
coordination. Changing the future selection is permitted and does not require
replacing active material. After caller death, unresolved child use remains a
barrier to replacement until recovery establishes that use has ended. A registry
lock cannot prevent arbitrary external credential edits; detected conflicting
changes invalidate the old binding and leave uncertain outcomes explicit.

Observation results identify the binding, observation time, provenance, and
freshness separately from their content. Each category distinguishes unknown,
observed, unavailable, and failed states. Model records name exact IDs and
supported/default efforts when known; listing a model does not prove entitlement.
Quota records retain the actual provider window identity, utilization, reset
time, and duration when available. Unknown values are not zero or unlimited.
Neither observation nor a passed local reset timestamp authorizes inference.

## 5. Explicit login lifecycle

Login may target an unselected account only after a direct user action naming
that account. This exception permits adding or repairing an account; it does not
permit model discovery or inference on unselected accounts.

The closed operations are `login.start`, `login.status`, and `login.cancel`.
Start names the provider/account, existing incarnation when replacing material,
auth kind, and an idempotency key. Status and cancel name only the issued login
handle and its account binding. A retry with the same key and same request reads
the original attempt; changing its contents is rejected.

Login states are `waiting-for-user`, `in-progress`, `ready`, `cancelled`, `failed`,
and `unknown`. Provider-specific UI data must have a reviewed, typed projection
before exposure. Tokens, arbitrary callback URLs, and raw vendor output never
cross the interface. Any transient authorization URL or code is confined to the
explicit login UI, never logs, persisted history, or account metadata. A local
operation deadline must not be described as vendor credential/code expiry.

Ready means provisioning completed under the adapter's documented checks. It
does not prove model entitlement or quota. It never activates an account.
Status recovery, page reload, and expired handles must not restart login.
Cancellation preserves an already terminal result and must not claim vendor
revocation. Reauthentication failure leaves a truthful recoverable state.

## 6. Frozen operation lifecycle

The initial operation kind is `work-proposal`: one fresh proposal turn, with no
provider-owned workspace mutation, nested orchestration, or independent review.
The adapter must establish the provider's tool restrictions before advertising
this kind. A later `reset-probe` kind has a fixed small inference request and
cannot propose workspace actions. It is not enabled by this document.

| Operation           | Closed input and effect                                                                                                                                                                                                                     |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `operation.prepare` | Exact selection binding, operation kind, model ID, reasoning effort, prompt/context payload, complete caller policy digest, local admission requirements, and an idempotency key. Validates and durably records intent; no model inference. |
| `operation.start`   | Issued operation handle and immutable binding digest only. Revalidates the selection/account and begins at most the one prepared operation.                                                                                                 |
| `operation.status`  | Issued operation handle and binding digest only. Returns known state; never launches or retries a provider turn.                                                                                                                            |
| `operation.cancel`  | Issued operation handle and binding digest only. Requests cancellation of that operation; cannot retarget it or cancel another account's work.                                                                                              |

Prepare returns an opaque handle and a digest binding every accepted request
field, authority, caller identity, account incarnation, and selected revision.
The digest's canonical encoding must be part of the wire schema. A digest is an
integrity join, not a quality certificate or proof of provider containment.
Reusing an idempotency key with different request content is a refusal.

MACO records its exact request intent and reserves resources after prepare and
before start. Start acquires the account-use lease and rechecks selection and
incarnation under the shared registry lock. It records durable dispatch admission
while still holding that lock. This record is the acceptance point: selection
changes and material replacement cannot slip between revalidation and admission.
A mismatch before this point refuses start without inference. After admission,
the registry lock may be released, but the incarnation lease protects material
through child use and recovery. A later manual switch affects future admissions,
including when the accepted child has not yet started. Status/cancellation of an
accepted operation may still be resolved after selection changes, without probing
the newly selected account or starting another inference.

States are `prepared`, `running`, `completed`, `refused`, `cancelled`, and
`unknown`. State alone is insufficient for accounting: results also distinguish
`not-started`, `possibly-started`, and `finished` dispatch outcomes. A cancellation
request or local timeout is not proof that remote work stopped or consumed zero.

The authority must durably record the dispatch decision before effectful start.
A repeated start cannot create another child or turn. Lost replies, restart, or
an uncertain provider outcome retain the same operation identity. The client
may query status; it must not invent a new key and replay automatically. If
recovery cannot prove the state, report unknown and refuse automatic restart.
Detected state loss, corruption, or rollback requires explicit recovery; ordinary
authenticated files alone cannot detect every coordinated storage rollback.

Completed results contain the structured proposal and separately sourced usage
when available. Unknown or partial usage remains explicit; cumulative snapshots
must not be summed. MACO must durably retain any authenticated observed lower
bound before continuing and settle conservatively after an ambiguous outcome.
A release is not a claim of actual zero usage. Known token counts do not imply
known monetary cost. Results exceeding local bounds are not applied as proposals.

Local admission, output, and deadline limits are not provider-enforced spending
ceilings. A caller requiring a hard provider ceiling must be refused unless the
adapter has independently established that enforcement. No capacity, price, or
enforcement guarantee is invented to satisfy admission.

## 7. MACO quality and review boundary

The complete policy includes the exact account/model/effort binding, caller
resource constraints, guardian behavior, actual validator requirements, and
review topology. MACO freezes these inputs for its operation and joins later
evidence by actual run, assignment, and candidate identity. A model label alone
is not a policy identity with execution authority.

The manager provides account facts and operation results. MACO's evaluator
retains its hard quality floor and the conjunction of caller resource limits.
Catalog availability creates neither certified quality nor cost evidence. The
evaluator may return no feasible candidate. Any model optimization stays within
the explicitly selected account; account switching is never an optimizer action.

A manually requested route is distinct from optimizer certification. It may run
only when the actual caller policy permits uncertified manual execution. Missing
required certification remains a refusal. Every proposal still passes the real
MACO guardian and configured independent review; manager success must not
substitute for a role-specific report, candidate review, or publication gate.

## 8. Later reset actions and provider coverage

The requested 5-hour and 7-day actions are independent explicit opt-ins. A future
scheduler must bind each action to the selected account/incarnation/revision,
model, observed provider window, and durable operation identity. It must use the
same operation engine and account checks, not a second inference path.

No action fires from an unknown/stale signal, a subscription label, login time,
or a locally assumed reset schedule. Selection change or authentication failure
pauses the action. Restart, duplicate observations, and ambiguous outcomes cannot
replay it. The UI must not claim that the inference resets or replenishes quota.
No account rotation or rate-limit bypass is requested.

GitHub Copilot requires a researched adapter. Existing Gemini OAuth does not
establish Google AI Pro model access or quota. These capabilities remain
unsupported until provider-specific evidence and tests exist. Account cards,
visible selection, login progress/cancellation, and clear model/quota/error
states are the UX goals; no code, assets, or text from another manager may be
copied under [CONTRIBUTING.md](../CONTRIBUTING.md).

## 9. Implementation acceptance

Before enabling a client, review the complete wire schema and its closed
provider-specific projections, transport bounds, identifier encoding, and
idempotency/recovery rules. The native service must be shared with desktop
commands rather than introducing credential logic into the webview.

Synthetic tools, credentials, and injected roots must demonstrate:

- Unauthorized/malformed requests are refused before credential or provider
  access; metadata exposes no credential, path, or raw provider error.
- Concurrent selection updates preserve settings; stale revision, account
  replacement, and cross-authority requests refuse without dispatch.
- Concurrent replacement login/deletion and start cannot cross the admission
  point with inconsistent identity: either replacement wins and start refuses,
  or admitted use retains its incarnation and replacement waits/refuses. A later
  manual selection change leaves that admitted operation's binding intact.
- Login requires explicit action, does not auto-select, survives status recovery
  without replay, and preserves truthful failure/cancellation state.
- Only the selected account is observed or invoked. Authentication errors,
  missing models, rate limits, and transport failures never fall through.
- Lost replies and process death cannot duplicate dispatch or understate an
  already observed usage floor; proposals remain unapplied on uncertain results.
- The genuine MACO consumer retains resource admission, guardian, and review
  gates, with unsupported or missing evidence reported accurately.

The reset scheduler, additional providers, and Windows transport require their
own corresponding acceptance tests before advertisement. Follow
[TESTING.md](TESTING.md) and keep any real-account acceptance check separate from
the credential-free automated suite.
