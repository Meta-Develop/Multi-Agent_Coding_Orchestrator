# Mutation Reversibility Policy

## Status and scope

This document defines version 2 of MACO's mutation taxonomy in
`src/mutation_taxonomy.rs`. Enforcement is current, not inert:
production has two exact checks through
`mutation_taxonomy::autonomous_decision_for_supervisor_child_dispatch`:

- The `follow_up_profile_gate` closure inside
  `src/autopilot.rs::run_autopilot_with_profile_retention_and_dispatch` checks
  the exact loaded Autopilot source plan before incrementing the child-dispatch
  admission count. Every
  result other than `Allow` becomes the existing typed
  `ApprovalReviewDenial::HumanReviewRequired`, is saved as the before-dispatch
  denial, and is returned without source dispatch. Autopilot preserves the
  decision's gate ID for its Refused status and gate-specific next action.
- `src/supervise/follow_up_cascade.rs::run_generated_follow_up_cascade` checks
  each exact reloaded and equality-verified generated plan after cancellation
  checks and before both the caller callback and durable dispatch marker. This
  central boundary covers ordinary direct supervise, Autopilot, and resumed
  generated-follow-up queues, including queues reopened by
  `resume_supervisor_plan_file_cascade_with_runner`, even when the caller
  callback returns `Ok(None)`.

That decision evaluates every entry in the production constant
`mutation_taxonomy::SUPERVISOR_CHILD_DISPATCH_MUTATIONS`: `worktree-create`,
`hook-install`, `claim-acquire`, `sandbox-worktree-edit`, and
`sandbox-worktree-commit`. These are the workspace mutations that a sandbox
Supervisor child dispatch admits before the child runs. `claim-release` is not
silently treated as part of that Reversible set: it is an Irreversible
cleanup operation admitted by an exact held token or explicit targeted release.
For concurrent, overlapping, or hierarchical assignments, Supervisor records
the durable assignment-completed checkpoint before per-assignment release. Its
remaining aggregate release follows the durable `final_report_planned` record.
Standalone agent cleanup does not claim either stronger ordering.

The caller callback remains afterward for Autopilot profile and budget gates.
The later primary-integrity, retention-binding, claim, containment,
validation, review, and external-effect gates also remain required.

The registry names operation boundaries rather than declaring whole commands
safe. A command that composes several operations inherits the most restrictive
classification of any operation it may perform.

## Definition

A mutation is **Reversible** only when MACO can cheaply and deterministically
restore the pre-operation state from retained, authenticated state, without:

- losing user data, build output that was the purpose of the operation, or
  audit and acceptance evidence;
- relying on best-effort reconstruction or rerunning an agent, build, or remote
  service;
- requiring cooperation from another process, user, forge, or remote system;
- leaving an externally visible effect, such as a pushed ref, pull request, or
  issue; or
- changing state outside the bounded MACO-controlled recovery surface.

All conditions are required. Being local, likely safe, idempotent, or
re-creatable is not enough. Recomputing deleted output is not an undo from
retained state. A compensating remote action is another external effect, not a
rollback of the original effect.

Read-only previews and dry-runs are Reversible because they require no undo.
Creation is Reversible only when its boundary creates an isolated, initially
disposable container and excludes later work placed inside it. Worktree
creation and later removal are therefore separate operations.

The Reversible `hook-install` row is deliberately narrower than arbitrary hook changes.
It covers only `src/worktree.rs::install_worktree_guard`, reached explicitly
for the primary checkout through `install_primary_worktree_guard` and
internally for registered managed lanes through
`install_managed_worktree_guard` or
`ensure_registered_managed_worktree_guard`. Installation adds an exact
worktree-conditional include and MACO-owned hook directory. It does not move,
rewrite, chmod, or delete the previously effective hooks; dispatchers chain
them at their effective resolved path. The separate `hook-verify` row covers
the read-only `verify_worktree_guard` boundary. `hook-uninstall` is classified
Irreversible: although `uninstall_worktree_guard` verifies the owned state,
removes only the exact MACO include/tree, and safely exposes the unchanged
prior hooks, it deletes its captured guard binding. A later install
reconstructs state; it does not restore retained complete pre-uninstall state.
Primary uninstall therefore needs the explicit guard-uninstall CLI, while
managed uninstall is admitted only inside the already-gated exact managed-lane
removal. Arbitrary hook replacement, deletion, or mutation remains unlisted
and fails closed.

## Governing rule: unlisted fails closed

Every operation not present in the registry is Irreversible until it is
explicitly reviewed and classified. An empty or unrecognized operation ID,
new command, new mode, expanded effect boundary, or inconsistent registry row
receives `taxonomy-review-required` and is refused. Only an exact listed
Reversible row with no explicit gate receives `Allow`. A listed Irreversible
row returns its reviewed `ExplicitMutationGate` and cannot enter autonomous
flow.

Additional rules follow from that default:

1. A composite operation is Irreversible if any possible child operation is
   Irreversible or unlisted.
2. `--force`, `--apply`, an acknowledgement, or a capability can satisfy a
   reviewed gate; none changes the operation's classification.
3. Prepare and commit phases are classified by what each phase can actually do.
4. Failure or partial completion does not change the original classification;
   cleanup and reconciliation are classified independently.

The taxonomy is not authorization. `Allow` does not bypass path claims,
repository cleanliness, plan binding, primary-worktree protection,
pre-action review, containment, validation, publication journaling, or any
other existing safeguard. Likewise, a returned explicit gate identifies the
minimum reviewed admission boundary; its evidence must still be validated by
the operation owner.

## Reviewed explicit gates

- `explicit-init-cli`: `cli::Cli::run` reaches
  `worktree::WorktreeManager::init_repository` only through `Command::Init`;
  discovery and ordinary orchestration do not initialize.
- `explicit-megafile-telemetry-seed-cli`: `RepoMegafileSubcommand::Seed`
  explicitly reaches `MegafileStore::record_file_samples`.
- `offline-migration-apply-attestation`:
  `state_migration::migrate_repository_state_with_options` receives explicit
  apply plus the provenance/digest acknowledgements and verifies all known
  state locks before `apply_migration`.
- `explicit-worktree-destructive-cleanup`: destructive cleanup is selected at
  `WorktreeCommand::run`. `WorktreeManager::gc` uses `dry_run=true` for preview;
  sweep/lifecycle require their own apply flags before destructive cleanup.
- `force-worktree-remove`: `WorktreeManager::remove` refuses unless `force=true`,
  then requires an exact verified managed binding and an exclusive removal
  lease. `WorktreeSubcommand::Remove` supplies that gate through `--force`;
  internal orchestration supplies it only for its exact disposable managed lane.
- `worktree-delete-branch`: `WorktreeManager::remove` receives the separate
  explicit `delete_branch=true` authorization for its ref-deletion phase.
- `exact-claim-release-authority`: `SyncStore::release` receives the exact token
  held from acquisition or explicitly selected by `SyncSubcommand::Release`;
  `release_by_agent` receives an explicit agent target. Supervisor has two
  distinct durable-before-release paths. When
  `release_assignment_resources_after_completion` selects per-assignment
  release for concurrent, overlapping, or hierarchical work,
  `record_completed_assignment_checkpoint` persists the assignment-completed
  checkpoint before `release_concurrent_assignment`. For remaining aggregate
  resources, `persist_supervisor_final_report` persists
  `final_report_planned` before `release_collected_scheduler_resources`, with
  resume reconciliation through `complete_planned_scheduler_resource_release`.
  Standalone cleanup in `agent::run_agent_with_provider_runtime` releases before
  constructing its final report, so this gate does not overclaim universal
  durable-record order.
- `live-override-actor-reason`: `live_claim::override_release` validates the
  override actor and a nonempty bounded audit reason.
- `merge-apply`: explicit `MergeSubcommand::Apply` reaches
  `run_merge_apply_controller` and the bound preview/validation/apply gates.
- `explicit-merge-arbitrate-cli`: explicit `MergeSubcommand::Arbitrate` reaches
  `merge::arbitrate_merge`. `--approve` governs acceptance after the arbiter
  call and is not misrepresented as the pre-launch gate.
- `primary-plan-cli-double-opt-in`: both
  `execution_target.kind=primary_worktree` and `--allow-primary-worktree` reach
  `supervise::validate_execution_target_opt_in`.
- `explicit-real-forge-durable-wal-start`: the explicit publish/create API
  selects a real forge, and `publication::execute_external_effect_with_wal`
  persists `EffectWal::started` before `provider.invoke`. A receipt is
  necessarily post-effect reconciliation evidence, not a pre-effect gate.
- `explicit-artifact-prune-apply`: `artifacts::prune_runs_with_policy` or
  `prune_artifacts_with_policy` receives `dry_run=false`; the policy additionally
  requires `reclaim_unverifiable` and `external_writers_stopped` when those
  risky candidate classes are eligible.
- `machine-global-operation-id-bearer`: `MachineGlobalStore::purge` receives
  the exact durable retention operation ID and its secret bearer token.
- `worktree-guard-uninstall-authority`: primary removal is the explicit
  `WorktreeGuardSubcommand::Uninstall` call to
  `uninstall_primary_worktree_guard`; managed removal reaches private
  `uninstall_bound_managed_worktree_guard` only after its worktree-removal gate.
- `internal-sealed-pinned-exec-capability`: pinned executable replacement is
  crate-internal and requires `ProcessSpec::with_pinned_direct_executable`
  before `pinned_exec::execute_verified_request`; it is not public authority.
- `exact-agent-process-selector`: `AgentRegistry::stop_selector`
  resolves an exact selector, or `stop_run` is reached by explicit bounded
  `agents stop --all --run-id`.
- `bounded-external-scope-event-api`:
  `orchestration_event::append_external_orchestration_event` accepts only its
  bounded external role/event vocabulary; `ScopeSubcommand::Event` is the CLI
  caller.

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
| `hook-install` | Reversible | Adds only verified MACO-owned conditional hook state, leaves prior hook bytes untouched and chained, and uninstall removes that exact state to restore the prior effective hook configuration. | `none` |
| `hook-verify` | Reversible | Reads and validates the exact guard ownership, configuration, hook bytes, and prior-hook binding without changing them. | `none` |
| `hook-uninstall` | Irreversible | Deletes the captured guard binding and owned hook state; exposing the unchanged prior hooks is safe, but it does not retain the complete pre-uninstall guard state for deterministic restoration. | `worktree-guard-uninstall-authority` |
| `pinned-executable-exec` | Irreversible | Replaces the running process and may initiate effects that cannot be rolled back by the original process. | `internal-sealed-pinned-exec-capability` |
| `agent-process-stop` | Irreversible | Terminates a live process; restarting cannot restore its exact in-memory execution state. | `exact-agent-process-selector` |
| `scope-event-append` | Irreversible | Emits durable observability history whose removal would destroy audit evidence and whose consumers cannot be rewound. | `bounded-external-scope-event-api` |
