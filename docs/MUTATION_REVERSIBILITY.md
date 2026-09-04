# Mutation Reversibility Policy

## Status and enforcement boundary

This document defines version 4 of MACO's mutation taxonomy in
`src/mutation_taxonomy.rs`. Every production Supervisor entrypoint derives one
canonical `EffectiveSupervisorMutationManifest` from the post-override loaded
plan, exact run and parent identity, execution runtime, worktree mode, semantic
mode, and applicable lifecycle effects. Manifest `demonstrated_gates` are an
auditable binding to the existing production authorities selected by that
control flow, not authority themselves. They are supplied explicitly by the
private common Supervisor or authenticated queue builder; they are never
manufactured from taxonomy rows. The authorizer independently derives the
exact required set from the registry, rejects missing or unrelated evidence,
and consumes its non-cloneable, non-serializable authority into a
canonical-SHA-256-bound grant. The common scheduler consumes that grant before
`prepare_supervisor_run` can reserve an artifact, register a process, create a
checkpoint, or write any other run state. Authority or a grant for one manifest
cannot admit another.

The Supervisor dispatch manifest is persisted as private authenticated run
evidence. "Exact" means the complete mutation surface reachable in the
selected post-override mode, not a post-hoc list of whichever success/failure
branch happened to run. Thus `bound-create-or-reuse` includes worktree creation
because absence of a reusable lane can select that branch, and a generated
queue includes both release and refusal-record branches. Primary-worktree
execution, existing-only re-audit, managed verified execution, nonpublishable
Fake simulation, retention-bound quarantine, unbound output cleanup, and
blocking semantic coordination remain conditional and mutually exclusive where
the production control flow is exclusive. Supervisor does not install hooks,
so `hook-install` is absent from every Supervisor manifest. The hook rows
remain for the independently owned worktree-guard integration.

Generated follow-up queue reservation, enqueue/commit, claim/release, refusal
evidence, and exact generated-plan staging use the same typed manifest and
authorizer before queue creation or any staging write. Each generated
subordinate then enters the same common Scheduler admission as a root plan.
Autopilot consumes its source authority into the source grant before its own
process registration or artifact reservation, then transfers that grant to the
common Scheduler. A source manifest denial therefore creates no Autopilot or
Supervisor artifact; later queue or subordinate denials can use only the
already-admitted outer lifecycle to persist refusal evidence and never supply
authority for another dispatch.

`SemanticIntentStore::claim` durably acquires blocking intent immediately
before an assignment is admitted. As with path claims, releasing an exact token
relinquishes exclusion and is classified separately as Irreversible.
Supervisor cleanup records the durable assignment-completed or aggregate
final-report release plan before the corresponding exact-token releases.

The hook rows cover the independently owned worktree-guard integration without
coupling this taxonomy port to the guard implementation files. Only a verified
MACO-owned, prior-hook-preserving install qualifies as `hook-install`.
Read-only verification is `hook-verify`; removal of the captured guard binding
is `hook-uninstall`. An arbitrary hook rewrite, deletion, or replacement is
unlisted and therefore fails closed.

The registry names operation boundaries, not whole commands. A command that
composes multiple operations inherits the most restrictive classification of
any operation it can perform. The taxonomy is policy input only: an `Allow`
decision does not bypass repository cleanliness, path claims, semantic
coordination, containment, primary-worktree integrity, review, validation,
publication journaling, or any other existing gate.

## Definition

A mutation is **Reversible** only when MACO can cheaply and deterministically
restore the pre-operation state from retained state without:

- losing user data, intended build output, or audit and acceptance evidence;
- relying on best-effort reconstruction or rerunning an agent, build, or
  remote service;
- requiring cooperation from another process, user, forge, or remote system;
- leaving an externally visible effect such as a pushed ref, pull request, or
  issue; or
- changing state outside the bounded MACO-controlled recovery surface.

All conditions are required. Local, idempotent, re-creatable, or usually safe
does not imply Reversible. Recomputing deleted output is not an undo from
retained state, and a compensating remote action is another external effect.

Read-only previews are Reversible because no undo is needed. Creation is
Reversible only when it creates an isolated, initially disposable container
without adopting later work placed inside it. Worktree creation and worktree
removal are therefore separate operations.

## Governing rule: unlisted fails closed

Every operation absent from the registry is Irreversible until it is reviewed
and classified. An empty or unknown operation ID, a new command or mode, an
expanded effect boundary, or an internally inconsistent row receives
`taxonomy-review-required` and is refused. Only an exact listed Reversible row
with no explicit gate receives `Allow`. A listed Irreversible row returns its
reviewed explicit gate and cannot enter the autonomous dispatch set.

Consequences of this rule:

1. A composite operation is Irreversible if any possible child operation is
   Irreversible or unlisted.
2. `--force`, `--apply`, an acknowledgement, or a capability can satisfy a
   reviewed gate; none changes the classification.
3. Prepare and commit phases are classified by what each phase can do.
4. Failure and partial completion do not change the original classification;
   cleanup and reconciliation are classified independently.

## Reviewed explicit gates

- `explicit-init-cli`: only the explicit `init` CLI reaches repository
  initialization.
- `explicit-megafile-telemetry-seed-cli`: only explicit megafile seeding
  persists repository sampling telemetry.
- `offline-migration-apply-attestation`: migration apply requires explicit
  apply plus the applicable provenance and digest attestations while known
  state locks are idle.
- `explicit-worktree-destructive-cleanup`: GC and sweep remain previews unless
  the caller explicitly selects their destructive mode; target-only reclaim
  retains the lane but still deletes build output.
- `force-worktree-remove`: removal requires the exact verified managed binding,
  the force flag, and the exclusive removal lifecycle.
- `worktree-delete-branch`: branch deletion is a separate explicit phase of
  managed worktree removal.
- `exact-claim-release-authority`: path-claim release requires the exact held
  token or an explicit agent target. Supervisor completion persists its
  release plan before terminal release.
- `exact-semantic-intent-release-authority`: semantic-intent release requires
  the exact held token or an explicit agent target. Supervisor completion
  persists the semantic release plan before terminal release.
- `live-override-actor-reason`: live-claim override requires the override actor
  and a nonempty bounded audit reason.
- `merge-apply`: only explicit merge apply reaches the bound
  preview/validation/apply controller.
- `explicit-merge-arbitrate-cli`: only explicit merge arbitration launches the
  external arbiter; later approval is a separate gate.
- `primary-plan-cli-double-opt-in`: primary-worktree execution requires both
  the plan declaration and the matching CLI opt-in.
- `explicit-real-forge-durable-wal-start`: real publication or issue creation
  requires explicit real-forge selection and a started durable effect record
  before invocation.
- `explicit-artifact-prune-apply`: artifact retention deletes only when
  preview is disabled and all risky candidate acknowledgements apply.
- `machine-global-operation-id-bearer`: permanent purge requires the exact
  durable retention operation and its secret bearer token.
- `worktree-guard-uninstall-authority`: primary uninstall is an explicit guard
  operation; managed uninstall occurs only inside the already-gated exact
  managed-lane removal lifecycle.
- `internal-sealed-pinned-exec-capability`: pinned executable replacement is a
  crate-internal sealed capability, not public authority.
- `exact-agent-process-selector`: process stop resolves an exact selector, or
  uses the explicit bounded run-wide stop form.
- `bounded-external-scope-event-api`: external Scope event append accepts only
  its bounded role and event vocabulary.
- `bound-supervisor-run-lifecycle-authority`: the exact canonical manifest
  binds run artifacts, authenticated finalization, checkpoint/orchestration
  journals, coordination bootstrap, claim telemetry, process registration,
  scratch cleanup, and refusal evidence before the common scheduler prepares
  the run.
- `verified-supervisor-process-lifecycle-authority`: a verified non-Fake
  Supervisor manifest binds child/auditor spawn, output evidence writes and
  unbound cleanup, and exact process termination paths. Retention-bound output
  instead uses the existing reversible `machine-global-quarantine` operation.
- `verified-supervisor-primary-object-import-authority`: verified managed-child
  execution binds the child commit whose objects may be imported into the
  primary object database.
- `bound-supervisor-field-guide-mutation-authority`: the exact verified run
  manifest binds field-guide append or deterministic curation to that run.
- `bound-generated-follow-up-queue-lifecycle-authority`: the authenticated
  source plan, source run, and generated task count bind queue
  writes, commits, releases, and refusal evidence before queue reservation.

## Registry

| Operation ID | Classification | Justification | Explicit gate ID |
| --- | --- | --- | --- |
| `repository-initialize` | Irreversible | Establishes repository identity without retaining a MACO rollback bundle for prior filesystem and Git state. | `explicit-init-cli` |
| `megafile-telemetry-seed` | Irreversible | Persists coordination telemetry and no supported operation restores the exact prior authenticated telemetry state. | `explicit-megafile-telemetry-seed-cli` |
| `state-migration-preview` | Reversible | Validates and reports migration work without changing durable state. | `none` |
| `state-migration-apply` | Irreversible | Rewrites authenticated durable state and does not retain a supported lossless rollback to the legacy representation. | `offline-migration-apply-attestation` |
| `worktree-create` | Reversible | Creates an isolated lane and branch that can be removed before work is added without losing pre-existing state. | `none` |
| `worktree-gc-preview` | Reversible | Only classifies and reports candidates; it does not remove lanes, targets, branches, or artifacts. | `none` |
| `worktree-garbage-collect` | Irreversible | Removes lanes or leftover directories and may destroy work or forensic state even when guarded by cleanliness checks. | `explicit-worktree-destructive-cleanup` |
| `worktree-target-reclaim` | Irreversible | Deletes build output; rebuilding is recomputation rather than restoration from retained state. | `explicit-worktree-destructive-cleanup` |
| `worktree-remove` | Irreversible | Deletes a working directory and can discard uncommitted or untracked work even when an exact managed binding is selected. | `force-worktree-remove` |
| `worktree-branch-delete` | Irreversible | Deletes a Git reference and MACO does not promise a retained, lossless ref restoration path. | `worktree-delete-branch` |
| `claim-acquire` | Reversible | The bounded coordination record can be released without changing claimed user data. | `none` |
| `claim-renew` | Reversible | Extends only the owner's bounded lease metadata and the claim remains releasable. | `none` |
| `claim-release` | Irreversible | Relinquishes exclusion immediately; another actor can acquire the paths, so the same ownership state cannot be recreated deterministically. | `exact-claim-release-authority` |
| `semantic-intent-acquire` | Reversible | Adds a bounded planning intent that can be released without changing the repository content it describes. | `none` |
| `semantic-intent-release` | Irreversible | Relinquishes semantic planning exclusion immediately, so the same conflict and ownership state cannot be recreated deterministically. | `exact-semantic-intent-release-authority` |
| `claim-override-release` | Irreversible | Overrides another owner's live coordination state and may invalidate decisions made from the prior ownership record. | `live-override-actor-reason` |
| `merge-preview` | Reversible | Reads candidate and primary state to produce a report without applying the candidate. | `none` |
| `merge-apply` | Irreversible | Mutates the primary worktree and index without a general retained-state rollback guarantee. | `merge-apply` |
| `merge-arbitration-proposal` | Irreversible | Launches an external arbiter and persists proposal evidence; costs and external execution cannot be undone. | `explicit-merge-arbitrate-cli` |
| `sandbox-worktree-edit` | Reversible | The isolated clean lane retains its Git baseline, so tracked changes and newly created files can be discarded locally. | `none` |
| `sandbox-worktree-commit` | Reversible | The predecessor commit and objects remain local and retained, allowing the private branch to move back without primary or remote effects. | `none` |
| `primary-worktree-mutation` | Irreversible | Changes the user's active checkout without a universal snapshot-and-restore contract. | `primary-plan-cli-double-opt-in` |
| `publication-preview` | Reversible | Builds a local report without pushing a ref or creating a forge object. | `none` |
| `publication-push` | Irreversible | Creates a remote-visible ref; deleting or moving it later would be another external effect. | `explicit-real-forge-durable-wal-start` |
| `pull-request-create` | Irreversible | Creates a remote review object and notifications that cannot be erased by a local rollback. | `explicit-real-forge-durable-wal-start` |
| `issue-create` | Irreversible | Creates a remote-visible issue and may trigger notifications or automation. | `explicit-real-forge-durable-wal-start` |
| `artifact-prune-preview` | Reversible | Reports retention candidates without deleting run artifacts or evidence. | `none` |
| `artifact-prune` | Irreversible | Deletes run, audit, or acceptance evidence; retention policy does not make that evidence recoverable. | `explicit-artifact-prune-apply` |
| `machine-global-quarantine` | Reversible | Moves the complete declared target set into retained quarantine with a durable restore operation and no purge. | `none` |
| `machine-global-restore` | Reversible | Restores retained quarantined bytes to their original declared coordinates without deleting their contents. | `none` |
| `machine-global-purge` | Irreversible | Permanently deletes quarantined bytes and already requires the dedicated bearer capability. | `machine-global-operation-id-bearer` |
| `hook-install` | Reversible | Adds only verified MACO-owned conditional hook state, leaves prior hook bytes untouched and chained, and can remove that exact owned state. | `none` |
| `hook-verify` | Reversible | Reads and validates the exact guard ownership, configuration, hook bytes, and prior-hook binding without changing them. | `none` |
| `hook-uninstall` | Irreversible | Deletes the captured guard binding and owned hook state without retaining the complete pre-uninstall state for deterministic restoration. | `worktree-guard-uninstall-authority` |
| `pinned-executable-exec` | Irreversible | Replaces the running process and may initiate effects that cannot be rolled back by the original process. | `internal-sealed-pinned-exec-capability` |
| `agent-process-stop` | Irreversible | Terminates a live process; restarting cannot restore its exact in-memory execution state. | `exact-agent-process-selector` |
| `scope-event-append` | Irreversible | Emits durable observability history whose removal would destroy audit evidence and whose consumers cannot be rewound. | `bounded-external-scope-event-api` |
| `supervisor-run-artifact-reserve` | Reversible | Reserves a new isolated run-artifact container before it contains accepted work or evidence. | `none` |
| `supervisor-run-artifact-write-append` | Irreversible | Writes durable run evidence whose exact prior artifact state has no supported lossless restoration path. | `bound-supervisor-run-lifecycle-authority` |
| `supervisor-run-artifact-authenticated-finalize` | Irreversible | Commits authenticated terminal run evidence and intentionally makes the finalized artifact immutable. | `bound-supervisor-run-lifecycle-authority` |
| `supervisor-scratch-evidence-cleanup` | Irreversible | Deletes or consumes private scratch evidence after import, and recomputation is not restoration from retained state. | `bound-supervisor-run-lifecycle-authority` |
| `supervisor-refusal-evidence-write` | Irreversible | Persists refusal evidence in the bound run lifecycle and no supported operation restores the exact prior audit history. | `bound-supervisor-run-lifecycle-authority` |
| `supervisor-checkpoint-journal-lifecycle` | Irreversible | Creates and advances authenticated checkpoint history used for recovery and dispatch ordering. | `bound-supervisor-run-lifecycle-authority` |
| `supervisor-orchestration-journal-lifecycle` | Irreversible | Creates and appends authenticated orchestration history whose removal would destroy audit evidence. | `bound-supervisor-run-lifecycle-authority` |
| `supervisor-coordination-store-bootstrap` | Irreversible | May initialize repository-bound authenticated coordination state without a supported rollback to the absent namespace. | `bound-supervisor-run-lifecycle-authority` |
| `supervisor-claim-acquisition-telemetry` | Irreversible | Appends authenticated claim-frequency telemetry after claim acquisition and does not rewind consumers to the prior history. | `bound-supervisor-run-lifecycle-authority` |
| `supervisor-mandatory-control-provision` | Reversible | Creates bounded control directories only inside a disposable managed child lane and retains the lane baseline. | `none` |
| `supervisor-primary-object-database-import` | Irreversible | Imports verified child commit objects into the primary object database without a supported exact object-pruning rollback. | `verified-supervisor-primary-object-import-authority` |
| `supervisor-process-register` | Irreversible | Persists current-run process identity and best-effort guard cleanup cannot guarantee restoration if unregister fails. | `bound-supervisor-run-lifecycle-authority` |
| `supervisor-process-spawn` | Irreversible | Starts an external child or auditor whose execution time and possible effects cannot be undone. | `verified-supervisor-process-lifecycle-authority` |
| `supervisor-process-output-stage` | Reversible | Creates an exclusive private output-staging container under the reviewed runtime root before output is accepted. | `none` |
| `supervisor-process-output-write` | Irreversible | Writes child or auditor output and execution evidence that cannot be rolled back without discarding run evidence. | `verified-supervisor-process-lifecycle-authority` |
| `supervisor-process-output-cleanup` | Irreversible | Removes private process-output staging or setup residue and does not retain a byte-for-byte restore operation for every path. | `verified-supervisor-process-lifecycle-authority` |
| `supervisor-process-terminate` | Irreversible | Terminates a bound child process on cancellation, timeout, or failed containment and cannot restore its exact execution state. | `verified-supervisor-process-lifecycle-authority` |
| `supervisor-field-guide-mutation` | Irreversible | Appends or deterministically curates authenticated field-guide state used by later runs. | `bound-supervisor-field-guide-mutation-authority` |
| `generated-follow-up-queue-reserve` | Reversible | Reserves a new source-bound queue container before generated tasks are committed. | `none` |
| `generated-follow-up-queue-write-append` | Irreversible | Writes authenticated generated-follow-up lifecycle records whose exact prior audit state is not restored. | `bound-generated-follow-up-queue-lifecycle-authority` |
| `generated-follow-up-queue-authenticated-commit` | Irreversible | Commits the source-bound generated task batch and terminal observations into authenticated queue history. | `bound-generated-follow-up-queue-lifecycle-authority` |
| `generated-follow-up-queue-claim` | Reversible | Claims one exact queued item inside the bounded queue and can release it before dispatch. | `none` |
| `generated-follow-up-queue-release` | Irreversible | Releases or terminalizes a queued item and cannot deterministically recreate the same intervening queue ownership state. | `bound-generated-follow-up-queue-lifecycle-authority` |
| `generated-follow-up-refusal-evidence-write` | Irreversible | Persists a generated-item refusal in authenticated queue history without a supported audit rewind. | `bound-generated-follow-up-queue-lifecycle-authority` |
| `generated-supervisor-plan-stage` | Reversible | Creates a private temporary exact-plan staging file that is retained only for the bounded subordinate call. | `none` |
