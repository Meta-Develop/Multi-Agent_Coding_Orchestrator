# Release Notes

## 0.1.0

Release-candidate memo for the first local-first CLI slice of the Multi-Agent
Coding Orchestrator.

### Implemented Scope

- Local Git repository initialization and linked worktree management.
- Durable exclusive path claims for coordinating edit ownership.
- Local JSON orchestration plan validation and command-backed execution with
  dependency ordering, timeouts, per-agent validation commands, optional patch
  output, checkpoint writes, and path-boundary checks.
- Read-only repository mapping, including parser-backed Rust semantic maps and
  symbol/path queries.
- Worktree diff collection, orchestration result collection, merge preview, and
  guarded merge apply with dirty-primary, stale-base, unclaimed-edit,
  validation, and apply-check gates.
- Provider-neutral LLM provider listing and prompt preview without network
  calls or provider credentials.

### Verification Expectations

Before tagging, pushing, or publishing a release candidate, run the project
checks from a clean working tree:

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
```

If Rust is not available globally, run the same commands through the documented
Nix shell.

### Known Limitations And Risks

- Checkpoints can be written, but checkpoint resume behavior is not implemented.
- `reuse=reset` is parsed but intentionally refused because destructive
  worktree cleanup needs an explicit safety design and tests.
- Merge apply uses Git apply safety checks and reports blockers, but conflict
  classification is not yet semantic or symbol-aware.
- Semantic task planning and automatic path-claim proposal are not implemented.
- Real network LLM providers, provider-backed agent execution, and `maco agent
  run` are not implemented.
- Direct `merge preview` and `merge apply` commands do not yet accept external
  validation reports; collected orchestration summaries should be used when
  validation state matters.

### Release Operations

This memo does not tag a commit, push a branch, publish a crate, or publish any
release artifact. Those operations remain separate release-manager actions.
