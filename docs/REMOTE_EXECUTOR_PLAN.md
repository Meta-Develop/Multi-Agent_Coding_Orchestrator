# Remote Agent Executor Plan

**Status:** Planned. Rust implementation and the first laptop pilot are deferred until the owner's NixOS laptop is repaired.

## Motivation

MACO currently launches and observes external agents as local processes operating on local worktrees. The next architecture should let the MACO control plane summon an agent on another host without weakening the safety properties that already exist at the coordinator: isolated worktrees, path claims, bounded artifacts, candidate inspection, review evidence, and human-controlled merge/apply gates.

The target is an executor abstraction, not a second orchestration system. The coordinator prepares an assignment and a staged workspace, records its lifecycle, asks an executor to run it, collects a patch and declared evidence, and then evaluates those results through the existing local safety path. Remote execution must not make a remote worktree authoritative for claims or integration.

```text
                         coordinator-owned authority
  plan + claims + isolated worktree + lifecycle/checkpoint + merge gates
                              |
                              v
                      AgentExecutor boundary
                       /                 \
              LocalExecutor          SshExecutor
                   |                      |
            local process       stage -> launch -> observe
                                      -> terminate -> collect
                                             |
                                             v
                              patch + bounded output bundle
                                             |
                                             v
                    isolated coordinator worktree -> inspect -> review
                                             |
                                             v
                               human preview / merge / apply
```

## Verified current anchors

The following anchors describe the current tree and supersede older design notes whose line references or symbol names have drifted.

| Concern | Current source anchor | Design consequence |
| --- | --- | --- |
| External runner variants | `src/external_agent.rs:1137-1158` | Existing variants remain local implementations; remote execution belongs behind a new executor boundary. |
| Injectable supervise callback | `src/supervise.rs:248-255` | This callback is the narrowest existing injection seam for executor-backed assignment execution. |
| Production callback wiring | `src/supervise/plan_api.rs:871-879` | Production construction should select and inject an executor here rather than spread transport selection through the scheduler. |
| Direct supervise invocation sites | `src/supervise/assignment_execution.rs:878-885` and `src/supervise/assignment_execution.rs:1892` | There are exactly two direct invocation sites to route through the executor seam. |
| Command-local paths | `src/external_agent.rs:176-184` | Command data carries local `PathBuf` values that cannot be serialized as remote path identity without translation. |
| Command construction | `src/supervise/assignment_execution.rs:658-664` | Construction currently binds coordinator-local paths before launch; the native design needs a path manifest. |
| Prompt input | `src/external_agent.rs:1519-1557` and `src/external_agent.rs:1759-1774` | Prompts are read locally and forwarded on standard input; the remote protocol must preserve bounded stdin forwarding. |
| Output argv and final stdin marker | `src/external_agent.rs:5733-5752` and `src/external_agent.rs:5768-5830` | Arguments include local output paths and a final `-`; remote launch must translate only declared path-bearing arguments and retain stdin semantics. |
| Custom executable refusal | `src/external_agent.rs:1409-1474` and `src/external_agent.rs:1499-1516` | A custom `--codex-bin` is accepted only for diagnostics and is refused as a launch authority. |
| CLI surface | `src/cli.rs:1004-1006` | The existing `--codex-bin` flag must not be described as a working remote-executor hook. |
| Local cleanup dispatch | `src/process_runner.rs:4396-4434` | Cleanup decisions are currently dispatched against locally owned process state. |
| Unix process control | `src/process_runner.rs:4081-4085` and `src/process_runner.rs:8425-8527` | Process groups, `TERM`, and eventual `KILL` are local Unix mechanisms and need a remote control channel. |
| Coordinator state location | `src/sync_store.rs:220-236` | Claims and related coordination state are rooted in the coordinator's Git common directory. |
| Platform identity limitations | `src/agent_lifecycle.rs:471-474`, `src/agent_lifecycle.rs:528-535`, and `src/agent_lifecycle.rs:554-557` | Unsupported non-Unix/Linux identity checks fail closed; they do not report a process as live by default. |
| Process identity | `src/agent_lifecycle.rs:81-92` | Local lifecycle identity already combines PID and process start identity, establishing the minimum needed to resist PID reuse. |
| Orchestration checkpoint family | `src/orchestrator.rs:49`, `src/orchestrator.rs:237-263`, and `src/orchestrator.rs:282-299` | The orchestration journal has its own schema version and checkpoint records. |
| Supervise checkpoint family | `src/supervise/checkpoint.rs:9` and `src/supervise/checkpoint.rs:72-93` | Supervise checkpoints are a separate versioned family and must be migrated independently. |
| Orchestrator patch writer | `src/orchestrator.rs:3614-3619` and `src/orchestrator.rs:4293-4320` | The current patch-writing path is the basis for patch-first collection; the old function name is no longer current. |
| Supervise candidate inspection | `src/supervise/repository.rs:317-410` | Supervise derives the local Git diff and changed-path evidence that remote results must re-enter. |
| Live heartbeat | `src/live_claim.rs:321-338`, `src/live_claim.rs:735-748`, `src/live_claim.rs:829-869`, and `src/live_claim.rs:2685-2721` | Existing heartbeat persistence can expose remote-run progress without transferring claim authority. |

### Corrections to stale assumptions

- Old source line numbers must not be carried into implementation tasks; the table above records the current anchors.
- The old claim that `process_is_running` returns true on every unsupported platform is false. Current unsupported identity paths fail closed.
- The old patch-writer name has been replaced; implementation should follow the writer at the current `src/orchestrator.rs` anchors rather than resurrecting `write_agent_patch`.
- There are two checkpoint families: the orchestration checkpoint/journal and the separate supervise checkpoint. A remote schema change must version both.

## Current local-only assumptions

Remote support requires exactly three categories of local assumptions to be made explicit:

1. **Local filesystem and path identity.** Prompt files, output files, worktree roots, and other `PathBuf` values are resolved as coordinator-local absolute paths. Some of those paths are embedded in argv. A remote host cannot interpret them directly, and a returned path cannot be trusted merely because its spelling resembles a coordinator path.
2. **Local process identity and control.** PID/start-time binding, Unix process-group identity, liveness probes, cleanup dispatch, and the `TERM`-then-`KILL` sequence refer to processes in the coordinator's kernel namespace. A remote PID or PGID has meaning only when bound to a host, transport session, start identity, and run nonce, and it can be controlled only through an authenticated executor channel.
3. **Coordinator-local Git common-directory coordination state.** Durable path claims and orchestration authority live under the coordinator repository's Git common directory. A remote checkout cannot acquire, release, or override those claims independently. The coordinator remains the single claim authority throughout staging, execution, collection, and integration.

## Protocol invariants

All phases preserve these invariants:

- The coordinator validates the plan, owns claims, creates the isolated candidate context, and makes every acceptance decision.
- The executor receives a bounded assignment and returns observations. It does not gain merge, apply, claim, or coordinator-state authority.
- Paths crossing the boundary use logical manifest names. Neither side treats an untrusted absolute pathname from the other side as authority.
- Launch, status, termination, and collection use an idempotency key bound to the run, assignment, host, staged-input digest, and nonce.
- A patch is the primary code result. Extra outputs are opt-in, declared, size-bounded bundles with individual digests.
- Every lifecycle transition is recorded durably before the next external effect when that ordering is required for safe recovery.
- An uncertain launch is reconciled by identity/status lookup. It is never automatically resent.
- Collection does not imply acceptance. Results still pass local diff, changed-path, audit, validation, preview, and human merge gates.

## Phase A: zero-Rust wrapper protocol spike

Phase A tests the wire and lifecycle protocol without changing Rust. It is deliberately not a production MACO execution path.

### Scope

A fixed local wrapper and a fixed remote helper exercise this sequence:

1. Read the already-rendered prompt as bounded local input and forward its exact bytes on standard input.
2. Stage a versioned manifest, optional schema files, and a bounded remote workspace snapshot. Every staged entry has a logical name, type, byte limit, and checksum.
3. Allocate a fresh remote workspace under the helper's configured root and translate only manifest-declared argv paths into that workspace. Preserve the final `-` argument so the remote process reads the prompt from stdin.
4. Start the fixed remote helper over SSH. The helper constructs argv from typed fields; neither caller-controlled paths nor arguments are interpolated into a shell command.
5. Record the host alias, session, nonce, remote process-group identity, start observation, and launch receipt before reporting the run as launched.
6. Retrieve the final-message file, logs, and any declared output files. Reject undeclared files, links, special files, path escapes, checksum mismatches, truncation, and per-file or aggregate size-limit violations.
7. On timeout or cancellation, ask the helper to send remote `TERM` to the bound process group, wait for a bounded grace period, then send remote `KILL`. Collect the resulting termination receipt and remaining bounded logs.
8. Destroy only the remote workspace whose receipt and nonce match this run; uncertain cleanup remains recorded for operator reconciliation.

The optional schema stage exists so prompt/report contracts can be tested without assuming they are preinstalled remotely. The remote workspace stage may begin as an archive for the spike, but its reader must be no-follow, entry-bounded, byte-bounded, and checksum-verifying.

### Critical limitation

The verified custom `--codex-bin` path cannot launch an alternate executable today: it is diagnostic-only and explicitly refused. Therefore Phase A must be run manually/out-of-band, or as a nonpublishable simulation using test inputs. It is not a verified `maco supervise` run, and its acceptance evidence must not be presented as proof that current supervise execution is remotely enabled or production-safe.

### Phase A acceptance checklist

- [ ] Exact prompt bytes reach remote stdin, including a test whose argv ends with `-`.
- [ ] Manifest path translation maps all declared prompt/output/workspace paths and rejects an unmapped absolute path.
- [ ] Optional schema and workspace staging verify checksums and reject a link, an escape, an oversized entry, and oversized aggregate input.
- [ ] The remote helper returns checksummed, bounded final-message, log, and declared-output artifacts; an undeclared output is rejected.
- [ ] A timeout demonstrates the remote `TERM` grace period followed by `KILL`, with a receipt tied to the same host/session/nonce/process identity.
- [ ] A lost SSH response produces an uncertain state and a status-only reconciliation attempt, never an automatic launch resend.
- [ ] All evidence is labeled protocol-spike or nonpublishable, and no result claims successful `maco supervise` execution.

These criteria prove only the protocol mechanics and failure behavior.

## Phase B: native executor abstraction

Phase B introduces a typed Rust SPI at the existing callback/`run_external_agent` seam.

### API shape

Add an `AgentExecutor` trait with typed operations rather than a single transport-specific command:

```text
stage(assignment, input_manifest) -> StagedAssignment
launch(staged, launch_spec) -> LaunchReceipt
status(execution_identity) -> ExecutionStatus
wait(execution_identity, deadline) -> ExecutionOutcome
terminate(execution_identity, policy) -> TerminationReceipt
collect(execution_identity, output_policy) -> CollectedResult
```

`LocalExecutor` must reproduce current local behavior and serve as the compatibility baseline. `SshExecutor` implements the same contract over a fixed remote helper. The supervisor receives an executor through the injectable callback; the two direct assignment invocation sites call that seam rather than selecting transports themselves.

### Native transport and identity requirements

- Represent argv as a bounded vector of typed arguments. Remote construction must never use shell interpolation.
- Introduce an opaque host identity that is stable for the run and distinct from an endpoint, username, address, or credential.
- Send a versioned path manifest that maps logical prompt, schema, workspace, final-message, log, and declared-output names to executor-local paths.
- Stage and collect with no-follow traversal, regular-file/type checks, entry and byte bounds, per-object checksums, aggregate checksums, and stable-before/after identity checks.
- Bind remote process-group control to host identity, transport session, remote PID, remote process-group ID, remote start time, and a random run nonce. Remote timeout and cancellation use a typed `TERM`-then-`KILL` request and return a cleanup receipt.
- Separate transport loss from process outcome. `unknown_after_launch` is a durable outcome requiring reconciliation, not a retryable launch failure.

### Checkpoint evolution and resume

Remote records need at least the requested fields `host`, `transport`, and `remote_pid`. They also need `remote_start_time`, `remote_session_id`, and `remote_nonce`, because a PID can be reused and SSH reconnects can cross sessions. Record the staged-input digest, remote workspace identity, launch idempotency key, process-group identity, last confirmed lifecycle state, collection manifest digest, and cleanup receipt when available.

Implementation must bump `CHECKPOINT_STATE_VERSION` for the orchestration checkpoint family and separately bump the supervise checkpoint version. Old schemas must never be interpreted under new semantics. The implementation must either provide a narrowly tested explicit migration for a supported old state or refuse it with precise start-new-run/reconcile guidance. A checkpoint that proves submission but cannot prove whether launch occurred resumes as uncertain; it may issue identity-bound status/collect/terminate operations but must not resend launch automatically.

### Patch-first collection

The executor first returns a bounded, checksummed patch plus its declared changed-path manifest. MACO imports that patch into a fresh isolated child worktree on the coordinator. It then recaptures the candidate locally and reuses the existing supervise diff inspection, path-boundary checks, worker/auditor evidence checks, validation binding, merge preview, and human apply gates. A remote report cannot substitute for this local recapture.

Non-patch output is allowed only through declared bundles. Each bundle has a schema, media/type declaration, path allowlist, per-file and aggregate limits, and checksums. General remote filesystem synchronization is not part of collection.

### Phase B acceptance checklist

- [ ] A fake transport drives every typed operation and deterministically covers success, nonzero exit, timeout, lost response, malformed receipt, checksum failure, and cleanup uncertainty.
- [ ] `LocalExecutor` passes parity tests for prompt stdin, argv, output capture, timeout, cancellation, lifecycle records, and current local safety behavior.
- [ ] Cancellation reaches the correct remote process group and records both the `TERM` attempt and any required `KILL` escalation.
- [ ] Resume from an uncertain launch performs status/reconciliation only and proves that launch is not duplicated.
- [ ] Collection rejects an oversized patch, checksum mismatch, absolute or escaping patch path, symlink/special-file staging entry, undeclared output, and changed paths outside the assignment.
- [ ] Checkpoint tests prove both schema families were bumped and that old schemas are either explicitly migrated or refused.
- [ ] One opt-in SSH assignment completes stage, launch, wait, patch collection, local isolated import, local diff/path/audit validation, and cleanup without applying to the primary worktree.

## Phase C: inventory-selected execution fabric

Phase C selects an executor host from operator-reviewed inventory instead of requiring a host choice in each assignment. The selector consumes opaque host IDs and capabilities from `agent_files/inventory/hosts.yaml`: platform, available executor/runtime capabilities, access class, cost class, and concurrency capacity. Endpoint details and secrets remain in machine-local configuration or a credential manager and never appear in plans, checkpoints, logs, patches, or public artifacts.

### Scheduling and power lifecycle

Before dispatch, the selector filters hosts by required platform/capability/access, excludes hosts without available concurrency, and applies the configured cost preference. It records the selected opaque host ID and the inventory revision/digest used for the decision.

Pre-dispatch power-on and post-collection power-off hooks integrate with WS2 through a narrow provider boundary rather than implementing Proxmox lifecycle logic inside MACO. Both hooks are idempotent and return receipts. The run records the environment state observed before power-on and whether this run's receipt proves that it started the environment. Safe stop is permitted only for an environment recorded as started by this run; a previously running environment, unknown start result, foreign receipt, active dependent lease, or uncertain ownership blocks automatic power-off.

The coordinator updates `live_claim` heartbeat evidence while selection, power transition, execution, collection, and cleanup are in progress, and it writes durable run artifacts for each state transition. Those heartbeats communicate liveness only. Claims remain the single coordinator's local Git common-directory authority. A claim RPC or distributed claim service is documented future work only and is not introduced in Phase C.

### Phase C acceptance checklist

- [ ] One assignment selects an opaque host from the reviewed inventory using capability, access, platform, cost, and concurrency fields without serializing endpoint secrets.
- [ ] Repeated power-on, status, collection, and safe-stop calls reconcile by idempotency key rather than duplicating effects.
- [ ] The lifecycle records inventory selection, WS2 power-on receipt, live heartbeat, execution identity, patch/output collection, and cleanup receipts.
- [ ] Patch collection re-enters the Phase B local isolated import and all coordinator safety gates.
- [ ] Safe stop powers off only the environment whose start receipt proves it was started by this run; pre-existing, foreign, or uncertain environments remain running and produce an actionable reconciliation state.
- [ ] One full selected-host -> power-on -> heartbeat -> execute -> patch -> collect -> safe-stop lifecycle completes with no automatic primary merge/apply.

## Security and failure semantics

Remote execution adds external effects whose result can become uncertain even when the local caller receives an error. The design uses write-ahead lifecycle records and the following rules:

- **Uncertain external effects:** persist intent before stage, launch, termination, cleanup, or power effects as appropriate. After a lost response, query by the same identity and idempotency key. Never infer that an error means the remote effect did not occur.
- **Lost SSH:** mark the last confirmed state and preserve the host/session/nonce binding. Reconnect for read-only status first. If identity cannot be proven, stop with manual reconciliation rather than acting on a possibly reused PID or workspace.
- **Duplicate/retry behavior:** safe observation operations may retry; effectful operations reconcile first. Launch is never automatically resent after an uncertain submission. Collection may resume only against the same immutable output manifest.
- **Identity binding:** a remote PID alone is insufficient. Every lifecycle or cleanup operation binds host, transport, session, start time, process-group identity, nonce, staged-input digest, and assignment/run identity.
- **Cleanup receipts:** termination, workspace removal, and power transitions return receipts that describe the exact bound target and observed final state. Missing receipts remain visible; cleanup success is never fabricated from transport closure.
- **Primary isolation:** remote output enters only a coordinator-owned isolated child worktree. It cannot write the primary worktree, mutate coordinator claim state, or bypass path/audit/validation gates.
- **Human merge boundary:** successful execution and collection produce a candidate, not an accepted integration. Existing preview and explicit human merge/apply policy remains authoritative.

## Non-goals

- No Rust implementation is included now.
- No claim RPC or distributed lock is included now.
- No executor, SSH helper, inventory service, or power hook is publicly exposed.
- No Proxmox lifecycle implementation is added inside MACO; WS2 remains an adapter boundary.
- No automatic merge or apply is introduced.
- No general filesystem synchronization is supported outside patches and declared bounded output bundles.
- No laptop pilot begins until the owner's NixOS laptop is repaired.
- No sibling repository is edited by this plan.

## Implementation sequence and dependencies

1. **Repair and preflight the pilot host.** Confirm the owner's NixOS laptop is healthy before effectful pilot work. This is a release dependency, not a reason to weaken tests or simulate production evidence.
2. **Freeze the Phase A protocol.** Define the manifest, launch/status/termination receipts, identity tuple, checksums, bounds, and uncertain-state vocabulary. Run only the manual/out-of-band or nonpublishable protocol spike.
3. **Introduce the Phase B seam.** Add `AgentExecutor`, route the callback and the two invocation sites through it, and land `LocalExecutor` parity before enabling SSH selection.
4. **Version durable state.** Update and test the orchestration checkpoint family and the separate supervise checkpoint family, including explicit old-schema refusal or migration.
5. **Implement `SshExecutor`.** Add safe argv transfer, bounded staging, lifecycle/status/termination, patch-first collection, and fake-transport failure coverage.
6. **Reconnect local safety gates.** Import remote patches into isolated coordinator worktrees and prove that existing path, audit, validation, preview, and human merge gates remain authoritative.
7. **Pilot one assignment.** After host repair, run the opt-in Phase B SSH acceptance case. Do not expand concurrency until uncertain launch, cancellation, and cleanup evidence have been reviewed.
8. **Add the Phase C selector and hooks.** Consume the reviewed host inventory, then integrate idempotent WS2 power and heartbeat lifecycle boundaries.
9. **Run the full fabric acceptance case.** Prove selected-host execution, patch-first collection, safe stop, and no automatic primary mutation before considering broader rollout.

The dependency order is intentional: Phase A stabilizes the protocol vocabulary; LocalExecutor parity protects current behavior; durable schema changes precede resumable remote effects; `SshExecutor` precedes inventory selection; and inventory-selected power lifecycle is accepted only after patch-first local integration is proven.
