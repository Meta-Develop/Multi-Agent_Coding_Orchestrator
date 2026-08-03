# Release Notes

## 0.2.0

Release-readiness memo for the current local-first CLI release line of the
Multi-Agent Coding Orchestrator.

### Implemented Scope

- Local Git repository initialization and linked worktree management.
- Durable exclusive path claims for coordinating edit ownership.
- Local JSON orchestration plan validation and command-backed execution with
  dependency ordering, timeouts, per-agent validation commands, optional patch
  output, checkpoint writes, checkpoint resume, completed-agent skipping, and
  path-boundary checks.
- Safe `reuse=reset` handling for clean, unclaimed stale worktrees, with
  refusal for dirty, untracked, or actively claimed worktrees.
- Read-only repository mapping, including parser-backed Rust semantic maps and
  symbol/path/risk queries. Risk reports include touched symbols, dependency
  impacts, and impacted files for changed paths. Repository intelligence now
  excludes local-only `.agents/temp`, `.agents/storage`, and `.agents/live`
  paths while preserving durable `.agents` documentation.
- Standalone repo-local semantic intent coordination commands:
  `maco coord preview/claim/status/release/release-agent` for path, module, and
  symbol intents.
- Worktree diff collection, orchestration result collection, merge preview, and
  guarded merge apply with dirty-primary, stale-base, unclaimed-edit,
  validation, and apply-check gates.
- Direct `merge preview/apply --validation-report <file>` support for external
  validation JSON, including machine-readable blocked apply reports with
  blocker details, related paths, and distinct missing, not-run, skipped, and
  failed validation blockers.
- `merge preview/apply --require-validation` requires at least one passed
  validation report. `merge apply --validation-command <command>` validates a
  temporary merged candidate before applying to the primary worktree; failure
  blocks and leaves the primary worktree unchanged.
- Provider-neutral LLM provider listing and prompt preview without network
  calls or provider credentials.
- Local fake-provider-backed `maco agent run` execution in isolated worktrees
  with durable claims, boundary checks, validation, merge-preview reporting, and
  no real network providers by default.
- Opt-in process-level supervisor-of-orchestrators mode with `maco supervise`
  plan/run/status/collect, serial Codex CLI child subprocess execution,
  isolated child worktrees, durable path claims, semantic coordination metadata,
  structured reports, and no-network fake subprocess tests by default.
- `maco supervise run` verifies actual child worktree Git-visible changes
  against the supervisor's starting primary HEAD, rejects unauthorized paths,
  and uses `max_child_assignments` as a child assignment fan-out budget rather
  than a parallel execution limit. `max_child_processes` remains accepted as a
  legacy JSON alias.
- `maco supervise artifacts list/latest/prune`,
  `maco autopilot artifacts list/latest/prune`, and
  `maco inbox artifacts list/latest/prune` inspect and prune durable run
  artifacts with generated run ids, explicit run-id reuse refusal, dry-run
  pruning, and keep-count retention.
- First local-first autopilot workflow with
  `maco autopilot plan/run/status/collect`. It normalizes task files or JSON
  plans, writes durable `.maco/autopilot/runs/<run-id>/` artifacts, launches
  supervised child work through a fake local subprocess by default, publishes
  through the PR safety gates, runs an independent reviewer, and records repair
  attempts for validation failures or blocking review findings.
- Autopilot and inbox use path-scoped safety refusals before launching work:
  overlapping durable sync claims, semantic coordination intents, and
  active/blocked live claim locks block only the overlapping target paths and
  return machine-readable path and lock details.
- Autopilot task-to-path proposals are now conservative helpers informed by
  repository paths, Rust semantic names, and task wording instead of defaulting
  only to `README.md`; claim gates remain authoritative.
- Standalone `maco review pr <number|url>` command with a deterministic fake
  structured review report by default. Review findings include severity, path,
  summary, suggested fix, and blocking status. CI reaction is reported as
  unsupported with `ci_reaction_supported=false`.
- Fake-first inbox reaction loop with
  `maco inbox scan/run/status/collect/watch`. It uses deterministic local fake
  issue and PR data by default, redacts public JSON, skips unsafe or duplicate
  items, converts issue intake plus PR review and failing CI context into
  autopilot plans, writes `.maco/inbox/runs/<run-id>/` artifacts, and preserves
  the no-network, no-credentials, no-automatic-merge default.
- Fake PR review and failing CI context enrich inbox-generated repair plans
  with paths, reasons, and validation expectations. Richer live GitHub review
  and CI reaction remains explicit opt-in and future hardening work.
- Opt-in PR and issue publication adapters. `maco pr preview` and
  `maco issue preview` are non-creating previews. `maco pr publish --forge
  fake|github` and `maco issue create --forge fake|github` either use the
  deterministic local-only fake forge or, with explicit `--forge github`, shell
  out to local `git` and `gh`. PR preview and publish support
  `--require-validation` and block missing validation evidence.
- Public `maco live` liveness commands for repo-local Markdown claims:
  status, validation, heartbeat refresh, and project-owner override release to
  handoff with audit logging.
- Command-backed orchestration and opt-in provider-proposed commands execute
  trusted local shell commands. Worktrees and path claims are repository change
  controls, not OS or filesystem sandboxes; path claims enforce Git-visible
  repository changes.

### Verification Expectations

This document does not authorize tagging, pushing, publishing a crate, or
creating a GitHub release. Before any separate release-manager operation, run
the project checks from a clean working tree:

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
```

If Rust is not available globally, run the same commands through the documented
Nix shell.

### Known Limitations And Risks

- Merge apply uses Git apply safety checks and reports blockers, but conflict
  classification is not yet semantic or symbol-aware.
- Full semantic task planning and automatic path-claim proposal are not implemented.
  Current task-to-path defaults are conservative helper proposals only; they do
  not replace human review or claim gates.
- Bounded parallel supervisor child execution is explicitly deferred. Supervisor
  child execution remains serial, and `max_child_assignments` is a fan-out
  budget, not a concurrency limit.
- PR and issue publication are intentionally minimal. The fake forge is
  local-only and covered by no-network tests. GitHub mode depends on local
  `git` and `gh` setup and is selected only with explicit `--forge github` for
  direct PR commands or `forge_mode: "github"` for autopilot plans. Issue
  triage metadata is limited to title, body, and labels. Inbox GitHub intake is
  also explicit opt-in; deterministic fake data remains the default. Richer
  live GitHub PR status, check, review import, stale metadata handling, and CI
  reaction remain future work.
- Autopilot intentionally omits automatic merge. It accepts and reports
  `auto_merge=true`, but always writes `auto_merge_performed=false` and leaves
  human review and merge as the next action. Inbox reactions keep the same
  boundary and do not apply or merge repaired work automatically.
- Live claim liveness uses human-readable Markdown parsing. Missing timestamps
  are reported as stale risk instead of blocking command execution, and
  malformed timestamps are reported as unknown liveness.
- Real network LLM providers are still absent. `maco agent run` currently
  supports only the deterministic local fake provider.
- Real Codex authentication and provider execution for `maco supervise` are
  opt-in operator responsibilities. Default tests use fake subprocesses and do
  not require network access, provider credentials, or a real Codex login.
- Repo-level validation commands run in the primary worktree after agent
  commands complete; use per-agent validation for checks that need to see
  unmerged agent worktree changes.
- `merge apply --validation-command` validates the candidate merged state before
  primary mutation, but `merge apply` does not automatically run post-apply
  validation after a successful primary apply. Release managers should run
  final project checks after accepted changes are applied.

### Release Operations

This memo does not tag a commit, push a branch, publish a crate, create a
GitHub release, or publish any release artifact. Those operations remain
separate release-manager actions.

## 0.1.0

Release-readiness memo for the first local-first CLI slice of the Multi-Agent
Coding Orchestrator.

### Implemented Scope

- Local Git repository initialization and linked worktree management.
- Durable exclusive path claims for coordinating edit ownership.
- Local JSON orchestration plan validation and command-backed execution with
  dependency ordering, timeouts, per-agent validation commands, optional patch
  output, checkpoint writes, checkpoint resume, completed-agent skipping, and
  path-boundary checks.
- Safe `reuse=reset` handling for clean, unclaimed stale worktrees, with
  refusal for dirty, untracked, or actively claimed worktrees.
- Read-only repository mapping, including parser-backed Rust semantic maps and
  symbol/path/risk queries. Risk reports include touched symbols, dependency
  impacts, and impacted files for changed paths.
- Worktree diff collection, orchestration result collection, merge preview, and
  guarded merge apply with dirty-primary, stale-base, unclaimed-edit,
  validation, and apply-check gates.
- Direct `merge preview/apply --validation-report <file>` support for external
  validation JSON, including machine-readable blocked apply reports with
  blocker details and related paths.
- Provider-neutral LLM provider listing and prompt preview without network
  calls or provider credentials.
- Local fake-provider-backed `maco agent run` execution in isolated worktrees
  with durable claims, boundary checks, validation, merge-preview reporting, and
  no real network providers by default.

### Verification Expectations

This document does not authorize tagging, pushing, publishing a crate, or
creating a GitHub release. Before any separate release-manager operation, run
the project checks from a clean working tree:

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
```

If Rust is not available globally, run the same commands through the documented
Nix shell.

### Known Limitations And Risks

- Merge apply uses Git apply safety checks and reports blockers, but conflict
  classification is not yet semantic or symbol-aware.
- Semantic task planning and automatic path-claim proposal are not implemented.
- Real network LLM providers are not configured by default. `maco agent run`
  currently supports only the deterministic local fake provider.
- Repo-level validation commands run in the primary worktree after agent
  commands complete; use per-agent validation for checks that need to see
  unmerged agent worktree changes.

### Release Operations

This memo does not tag a commit, push a branch, publish a crate, create a
GitHub release, or publish any release artifact. Those operations remain
separate release-manager actions.
