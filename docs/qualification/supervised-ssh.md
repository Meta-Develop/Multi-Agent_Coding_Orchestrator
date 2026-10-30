# Supervised SSH qualification

Status: **not qualified**. The attempt adapter has deterministic injected-transport
coverage. Supervisor dispatch supports explicitly installed trusted embedding
configuration, with authenticated lifecycle receipts and collection recovery.
Normal CLI dispatch still refuses SSH before launch because there is no shipped
lifecycle SSH client or operator trust-config loader for that dispatch.
The existing atomic command SSH client speaks a different protocol. Do not use it
to manufacture lifecycle receipts or treat a direct remote command as supervised
execution.

The adapter requires an explicit `ExecutorSelection::Ssh`, an exactly matching
`SshConfig`, and a lifecycle transport factory that uses that validated trust.
Host ID, endpoint, user, port, helper, and workspace root must all match. It
rechecks local trust-file ownership, permissions, and file identity before each
transport operation. The transport must retain strict host-key checking, explicit
identity, bounded reads/timeouts, and noninteractive execution.

Coordinator input readers supply bounded bytes. `SupervisedPaths` only translates
declared absolute local paths into relative manifest paths; it does no filesystem
reading or symlink resolution. The input manifest, launch specification, output
policy, run, assignment, attempt number, and coordinator nonce bind the lifecycle
keys. The cancellation token and termination policy stay fixed for that attempt.
Remote output remains candidate evidence; no `ExternalAgentRun` is deserialized
or fabricated from it.

An uncertain launch is queried using the submitted identity and never relaunched.
`NotFound` preserves uncertainty. A lost collection reply reuses the exact
execution identity, collection key, and policy. Stage uncertainty remains an
operator reconciliation gate. Cancellation uses the existing lifecycle
TERM/grace/KILL/wait sequence, and collection requires a terminal observation.
The attempt adapter never calls workspace cleanup on drop or error. The supervisor
requests it separately after authenticated collection persistence, idempotent local
import, successful local recapture, and durable import/recapture receipts.

## Deterministic checks

Run these only on an admitted validation host. They contact no SSH host:

```sh
cargo fmt --all -- --check
cargo test --locked -p multi-agent-coding-orchestrator --lib external_agent::executor::supervised_tests::selected_transport_binds_host_attempt_and_paths -- --exact
cargo test --locked -p multi-agent-coding-orchestrator --lib external_agent::executor::supervised_tests::lost_launch_reconciles_before_cancellation_without_relaunch -- --exact
cargo test --locked -p multi-agent-coding-orchestrator --lib external_agent::executor::supervised_tests::cancellation_keeps_custody_until_terminal_proof -- --exact
cargo test --locked -p multi-agent-coding-orchestrator --lib external_agent::executor::supervised_tests::lost_collection_reuses_exact_key_and_never_cleans_up -- --exact
cargo test --locked -p multi-agent-coding-orchestrator --lib supervise::remote_execution::tests::lost_reply_restart_never_duplicates_launch -- --exact
cargo test --locked -p multi-agent-coding-orchestrator --lib supervise::remote_execution::tests::cleanup_requires_persisted_imported_collection -- --exact
cargo test --locked -p multi-agent-coding-orchestrator --lib supervise::remote_execution::tests::selected_supervisor_dispatch_requires_explicit_trust_and_keeps_local_default -- --exact
```

## Opt-in two-host gate (do not run as part of deterministic checks)

The live gate remains unproven. An embedding caller can configure
`supervise::remote_execution::SupervisedSshHost::configure` with matching
`SshConfig`, a lifecycle transport factory, and a trusted
`SupervisedSshCoordinator`. `bind_supervised_ssh_hosts` captures that configuration
when loading the plan, including for scheduler threads. A plan cannot install
these capabilities. Missing, changed, or revoked trust refuses without Local
fallback. Attached parent messaging and hosted pre-action review require an
equivalent remote capability and currently refuse SSH.

The coordinator integration supplies bounded frozen inputs, imports the validated
candidate idempotently using its exact collection key, and recaptures the local
candidate and held native runtime evidence. Remote JSON cannot manufacture that
native evidence. Existing claim, budget, containment, acceptance, and publication
gates still apply to the returned run. No default integration or real wire client
is installed by this API.
After native recapture returns, receipt or cleanup failures retain that run's
observations for normal supervisor usage settlement and mark it nonpublishable.

Receipts live in the repository-authenticated `supervised-ssh-v1` journal namespace.
The stable run/assignment/optional Worker/attempt tuple selects one exclusively
locked journal. Its first intent retains the nonce; checkpoints bind the exact
stage key, session, workspace, launch key, PID/PGID/start token, and collection
policy. Launch intent is written before launch. A restart queries that submitted
identity, including when the reply was lost; `NotFound` does not authorize replay.
Collections use bounded chunks with an authenticated final digest/commit before
import. An interrupted collection retries its original key. Failed persistence,
import, or recapture preserves remote output. Cleanup is recorded before its
effect and reconciled using the exact cleanup key only after the import barrier.
Stage uncertainty remains an operator gate.

An embedding caller resumes with `SupervisedSshHost::dispatch` using the identical
identity, command, scopes, and frozen inputs. A completed collection is restored
and revalidated locally, without fetching remote output again; native runtime
evidence must be recaptured, never restored from serialized flags. The general
CLI `supervise resume` still refuses uncertain assignments: reconciliation of
remote custody alone does not settle the interrupted scheduler's accounting or
accept its candidate. A future operator integration must document its actual
trust-loader, recovery/accounting handoff, and fault-control commands before a
live qualification can begin.

Use an existing authenticated, explicitly trusted second host and a disposable
qualification repository. Do not create credentials, guess endpoints, weaken
host trust, change shared services, or interrupt other work. All values below
must come from reviewed operator configuration. `MACO_BIN` is the absolute path
to the accepted installed binary. `SSH_PLAN` is a reviewed plan containing one
substantive bounded source edit with an explicit SSH executor. `EVIDENCE` is an
existing private directory. Choose a fresh `RUN_ID` and use it throughout.

After an operator integration makes the CLI route available, the exact supervisor
commands are:

```sh
"$MACO_BIN" supervise plan "$SSH_PLAN" --repo "$COORD_REPO" --json > "$EVIDENCE/plan.json"
"$MACO_BIN" supervise run "$SSH_PLAN" --repo "$COORD_REPO" --run-id "$RUN_ID" \
  --runtime codex --codex-bin codex \
  --machine-global-config "$MACHINE_GLOBAL_CONFIG" \
  --machine-global-runtime-root-id "$RUNTIME_ROOT_ID" --json > "$EVIDENCE/run.json"
"$MACO_BIN" supervise collect "$RUN_ID" --repo "$COORD_REPO" --json > "$EVIDENCE/collect.json"
```

These commands currently must refuse SSH dispatch. There is deliberately no
invented trust-loader flag, lifecycle helper command, or lost-reply switch here.
The follow-up must document its actual trust-loader and fault-control commands
before a live qualification can begin.

Run separate cases for ordinary completion, cancellation, and reply loss. For
cancellation, `CANCEL_REQUEST` must be an operator-authored typed request bound to
the exact live assignment and run. Repeat that same request to test idempotent
delivery. For reply loss, the reviewed transport fault control must withhold only
the selected reply, preserve the remote workload, and record its exact key. Resume
the same run rather than starting another run:

```sh
"$MACO_BIN" steer submit "$CANCEL_REQUEST" --repo "$COORD_REPO" --json > "$EVIDENCE/cancel-first.json"
"$MACO_BIN" steer submit "$CANCEL_REQUEST" --repo "$COORD_REPO" --json > "$EVIDENCE/cancel-retry.json"
"$MACO_BIN" steer evidence "$RUN_ID" --repo "$COORD_REPO" --json > "$EVIDENCE/steering.json"
"$MACO_BIN" supervise resume "$RUN_ID" --repo "$COORD_REPO" --json > "$EVIDENCE/resume.json"
"$MACO_BIN" supervise collect "$RUN_ID" --repo "$COORD_REPO" --json > "$EVIDENCE/collect-resumed.json"
```

Acceptance requires independent evidence for the selected remote host and
containment, staged-source digest, exact run/assignment/attempt/session/process
start identity, authentic usage/events, one launch despite reply loss, terminal
process custody after cancellation, durable collection before local import,
successful local recapture before cleanup, and no surviving owned workload. Retain
the exact cleanup receipt and prove unrelated remote workspaces were untouched.
Claims, validation, acceptance, and publication remain coordinator-owned. No live
case or successful two-host qualification is claimed by the offline tests.
