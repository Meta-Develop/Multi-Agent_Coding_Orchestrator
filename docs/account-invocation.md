# Manually selected Broker agent proposals

On Linux, `maco agent run --provider account-broker` requests one proposal through
an explicitly configured capability service and applies accepted proposals through
the existing agent guardian. The service must implement invocation protocol v1,
have an approved Codex catalog, a verified managed account identity, and an explicit
operation deadline. Metadata discovery and successful device login alone do not
supply this execution binding. No deployed service or successful live inference
is implied by the client implementation.

Select the account in the account-management screen first. Supply that exact alias,
model and reasoning effort when starting a task:

```sh
maco agent run task.md --agent-id implementation --path README.md \
  --provider account-broker --model "$APPROVED_MODEL" --reasoning-effort high \
  --broker-socket "$BROKER_SOCKET" --broker-uid "$BROKER_UID" \
  --account-state-dir "$ACCOUNT_STATE_DIR" --account-alias "$SELECTED_ALIAS" \
  --broker-admission-tokens "$LOCAL_TOKEN_ADMISSION" \
  --request-id task-identity --repo . --json
```

The alias must match the saved manual selection. Its revision is frozen into the
durable intent before prepare; subsequent manual changes apply to future tasks.
There is no automatic account/model fallback, discovery of other aliases, or
provider command execution inside Broker. Existing claim, patch/path, command
permission and validation gates continue to govern local proposal application.
Provider-proposed commands remain disabled unless explicitly requested.

`--broker-admission-tokens` is required and limits local rolling admission. The
existing 24-hour accounting horizon is the default; change it explicitly with
`--broker-admission-window-seconds`. Neither is a provider quota/reset window.
The request reserves its existing local token budget before start. Caller-bound
rolling constraints are frozen into the policy digest and durable intent, and the
same snapshot governs admission. Exact final usage replaces the reservation;
missing or partial usage is conservatively charged and stops proposal application.
Observed cumulative totals are retained monotonically in the authenticated budget
ledger before further polling. A later unknown observation or caller-process death
cannot discard that lower bound; a regressive final counter stops application.
Reopening the ledger recovers the greater of reservation and observed lower bound
for the original account and single request. The complete serialized proposal,
including patch contents, must fit the local output limit after usage is settled.
Cost is explicitly unknown and is never reported as zero.

Codex does not expose an enforced output-token limit on this route. Its internal
continuations and network retries may consume more than the local reservation.
Input/output limits and operation deadlines cannot guarantee a remote token or
spend cap. `--require-provider-spend-cap` therefore refuses this provider. A caller
requiring a monetary guarantee is also refused when no reliable price exists.
Unknown provider capacity remains absent in `ProviderCapabilities`; local budgets
are not substituted for it.

The four fixed operations are `accounts.invocation.prepare`, `start`, `status`
and `cancel`. Closed DTOs are in `src/accounts/invocation_protocol.rs`. The client
checks the frozen policy/request digests, model/effort, opaque credential generation
and account attribution identity. The latter is endpoint/peer/provider scoped for
accounting; it does not prove provider quota sharing or capacity. Framing remains
64 KiB, without truncation, and IPC deadlines remain at most 60 seconds. Background
turns have a separate protected service deadline.

Authenticated local intent and budget journals are written before start. A lost
start reply triggers status for the same nonce and binding, never a second start
or a replacement nonce. A recorded `--request-id` is refused on rerun, including
after restart: inspect the retained attempt and accounting before deciding on any
new task. A new request identity authorizes new work; it is not a recovery switch.
Broker status replay proves a remote outcome, not whether MACO already applied a
proposal. Automatic local application recovery is not implemented.

JSON success and failure reports retain `broker_attempt` evidence: safe binding,
observed state/effect, final/partial/unknown usage, and observed or conservative
accounting. `start_requested` plus an old prepared observation must not be read as
proof of non-dispatch. Detected journal corruption/loss fails closed; authenticated
files alone cannot detect arbitrary coordinated rollback of all local storage.
An existing workspace-wide rate-limit latch is preserved, while an account latch
applies only to that account's attribution pool after manual switching.

This unit connects the production agent-run caller. Supervisor dispatch remains a
separate required integration. Warmup protocol data cannot schedule a request;
5h/7d scheduling, provider reset observations, Copilot and Google subscription
adapters are not implemented by this client. Proposal success creates neither an
optimizer quality certificate nor an external-agent containment receipt.
