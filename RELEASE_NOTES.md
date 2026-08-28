# Release Notes

## 0.3.0

Release-readiness memo for the current 0.3.0 local-first CLI release line of
the Multi-Agent Coding Orchestrator.

### Implemented Scope

- Crate packaging metadata now includes crates.io keywords and categories for
  command-line and development-tool discovery.
- Task-path proposal helpers are more precise: word-boundary symbol matching,
  no arbitrary first-file fallback, Git-ignore-aware planning repository walks,
  and degraded-scan diagnostics surfaced in autopilot and inbox reports.
- Supervisor child-report enforcement is hardened with lenient JSON report
  recovery from noisy child output, structural failure for assigned workers
  that do not report, parent audit of zero-worker children with non-empty
  diffs, primary-worktree integrity rechecks, opt-in corrective retry through
  `max_child_retries`, and claim-conflict diagnostics that name current owners.
- Supervise evidence handling now includes worker-evidence cross-checks,
  canonical child-report artifacts, per-assignment task override, and stable
  child-diff baselines for auditable child results.
- `maco supervise run` now defaults `--max-concurrent-children` to `auto`,
  deriving a resource-bounded child-execution limit from measured host
  capacity. A positive numeric value remains available as an explicit override,
  with `--max-concurrent-children 1` selecting serial execution. Disjoint path
  sets can run concurrently; overlapping assignments serialize with scan-ahead
  scheduling under the sync claim overlap rules. Retries and parent audits
  retain their assignment slot, ordinary failures remain isolated, fatal
  aborts stop new starts and join active calls, plan-indexed outcomes preserve
  deterministic report order, journal appends are synchronized, and concurrent
  invocations use unique scratch roots. Zero is rejected before artifacts are
  reserved. `max_child_assignments` remains the plan fan-out budget rather than
  the concurrency bound.
- New terminal cross-runtime CONSULTANT role with `maco consult ask` and
  `maco consult artifacts list/latest/prune`. Consultation is fake-first by
  default, supports explicit read-only Codex and Claude CLI adapters, and can
  be wired into supervise planning only by opt-in configuration.
- Focused inbox unit tests cover the reaction loop and fixed two exposed bugs:
  token-like `privacy_scan` predicate matching and `.maco` runtime-path
  filtering in lock-overlap checks.
- `maco inbox run` / `inbox watch` and `maco inbox workspace run` / `workspace
  watch` execute. `inbox run` accepts optional rolling-quota ceilings
  `--max-rolling-tokens`, `--max-rolling-cost-usd`, and
  `--rolling-window-seconds`. A quota is bound only when at least one ceiling
  is set; the window defaults to 86400 seconds. `inbox watch` and workspace
  run/watch do not expose those flags. Non-dry-run `github_git`, `github_pr`,
  and `github_full` still fail closed until an external reviewer is bound.
- `maco supervise run` and `maco autopilot run` accept optional
  `--role-category` (`delegating_coordinator`,
  `non_delegating_terminal_worker`, `read_only_researcher`,
  `read_only_review_auditor`). Resume of an existing supervise run refuses a
  new override.
- `maco eval-harness run-v2` always parses the v2 manifest schema. `maco
  evaluation rescore` re-scores a stored results document under a named
  objective profile without overwriting the stored file. Real network
  providers remain refused.
- `maco worktree remove --force` has a hardened removal fallback and
  idempotent re-removal behavior for safer cleanup of stale or partially
  removed agent worktrees.

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

- Richer merge conflict classification remains a known limitation. Current
  apply uses Git apply safety checks and reports structured blockers, but does
  not classify conflicts by symbol or dependency impact.
- Full semantic task planning remains roadmap work. Current task-to-path
  proposals are conservative helpers for autopilot and inbox defaults; claim
  gates remain authoritative.
- Consultant results are advisory evidence only. Real Codex and Claude
  consultant adapters are explicit local-process opt-ins, remain read-only, and
  do not override assigned ownership, validation, review, or merge gates.
- Effectful `maco supervise run` executes through the live supervisor gates
  after acquiring the capability-bound repository-cleanliness input and
  creating managed child worktrees. A dirty primary fails with the required
  remedy before worktree creation. The in-process Fake runtime is always
  non-publishable. Plan, status, collect, resume, re-audit, and artifact
  inspection remain available.
- PR and issue publication remain intentionally narrow and opt-in for live
  GitHub paths. Fake forge and fake inbox data stay the no-network defaults.
- Real network LLM providers remain absent from `maco agent run` and must be
  separately approved, adapter-bound, and covered by no-network invariant
  tests before introduction.
- Automatic merge remains intentionally absent. Autopilot and inbox can record
  merge intent, but leave human review and merge as the next action.

### Release Operations

This memo does not tag a commit, push a branch, publish a crate, create a
GitHub release, or publish any release artifact. Those operations remain
separate release-manager actions.

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
- Cross-repository inbox workspace supervision with
  `maco inbox workspace scan/run/watch --config <path>`. Workspace configs
  select enabled repositories, per-repo or default permission modes, per-repo
  item limits, issue/PR inclusion, labels, strict failure behavior, and safety
  flags. Aggregate reports use public-safe config and artifact paths, include
  repo counts and per-repo scan or run reports, continue across repository
  refusals in non-strict mode, fail the aggregate command in strict mode, and
  write workspace artifacts under `.maco/inbox-workspace/runs/<run-id>/`.
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
- Workspace inbox is cross-repository supervision, not approval or merge
  automation. Safety flags do not enable automatic approval or automatic merge;
  workspace reports keep `auto_approval_performed=false` and
  `auto_merge_performed=false`. GitHub PR publication and source comments remain
  limited to explicitly configured permission modes, and Git-only publication
  does not create GitHub PRs.
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
