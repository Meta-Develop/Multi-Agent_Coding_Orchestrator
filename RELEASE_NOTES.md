# Release Notes

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
- Opt-in process-level supervisor-of-orchestrators mode with `maco supervise`
  plan/run/status/collect, serial Codex CLI child subprocess execution,
  isolated child worktrees, durable path claims, semantic coordination metadata,
  structured reports, and no-network fake subprocess tests by default.
- `maco supervise run` verifies actual child worktree Git-visible changes
  against the supervisor's starting primary HEAD, rejects unauthorized paths,
  and treats `max_child_processes` as a child assignment fan-out budget rather
  than a parallel execution limit.
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
  `git` and `gh` setup and is selected only with explicit `--forge github`.
  Issue triage metadata is limited to title, body, and labels. Richer PR
  status, check, and review import remain future work.
- Live claim liveness uses human-readable Markdown parsing. Missing timestamps
  are reported as stale risk instead of blocking command execution, and
  malformed timestamps are reported as unknown liveness.
- Real network LLM providers are not configured by default. `maco agent run`
  currently supports only the deterministic local fake provider.
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
