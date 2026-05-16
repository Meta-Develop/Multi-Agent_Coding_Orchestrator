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
