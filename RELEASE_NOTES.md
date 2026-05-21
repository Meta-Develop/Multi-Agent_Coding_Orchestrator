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
  impacts, and impacted files for changed paths.
- Standalone repo-local semantic intent coordination commands:
  `maco coord preview/claim/status/release/release-agent` for path, module, and
  symbol intents.
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
- Opt-in process-level supervisor-of-orchestrators mode with `maco supervise`
  plan/run/status/collect, serial Codex CLI child subprocess execution,
  isolated child worktrees, durable path claims, semantic coordination metadata,
  structured reports, and no-network fake subprocess tests by default.
- `maco supervise run` verifies actual child worktree Git-visible changes
  against the supervisor's starting primary HEAD, rejects unauthorized paths,
  and treats `max_child_processes` as a child assignment fan-out budget rather
  than a parallel execution limit.
- First local-first autopilot workflow with
  `maco autopilot plan/run/status/collect`. It normalizes task files or JSON
  plans, writes durable `.maco/autopilot/runs/<run-id>/` artifacts, launches
  supervised child work through a fake local subprocess by default, publishes
  through the PR safety gates, runs an independent reviewer, and records repair
  attempts for validation failures or blocking review findings.
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
- Opt-in PR and issue publication adapters. `maco pr preview` and
  `maco issue preview` are non-creating previews. `maco pr publish --forge
  fake|github` and `maco issue create --forge fake|github` either use the
  deterministic local-only fake forge or, with explicit `--forge github`, shell
  out to local `git` and `gh`.
- Public `maco live` liveness commands for repo-local Markdown claims:
  status, validation, heartbeat refresh, and project-owner override release to
  handoff with audit logging.
- Command-backed orchestration and opt-in provider-proposed commands execute
  trusted local shell commands. Worktrees and path claims are repository change
  controls, not OS or filesystem sandboxes; path claims enforce Git-visible
  repository changes.

### Verification Expectations

Before tagging, pushing, or publishing a release, run the project
checks from a clean working tree:

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
- PR and issue publication are intentionally minimal. The fake forge is
  local-only and covered by no-network tests. GitHub mode depends on local
  `git` and `gh` setup and is selected only with explicit `--forge github` for
  direct PR commands or `forge_mode: "github"` for autopilot plans. Issue
  triage metadata is limited to title, body, and labels. Inbox GitHub intake is
  also explicit opt-in; deterministic fake data remains the default. Richer PR
  status, check, review import, and CI reaction remain future work.
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
- `merge apply` does not automatically run post-apply validation. Merge gates
  use supplied validation reports, so release managers should run final project
  checks after accepted changes are applied.

### Release Operations

This memo does not tag a commit, push a branch, publish a crate, or publish any
release artifact. Those operations remain separate release-manager actions.

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

Before tagging, pushing, or publishing a release, run the project
checks from a clean working tree:

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

This memo does not tag a commit, push a branch, publish a crate, or publish any
release artifact. Those operations remain separate release-manager actions.
