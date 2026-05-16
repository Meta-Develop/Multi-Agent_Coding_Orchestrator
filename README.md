# Multi-Agent Coding Orchestrator

Rust CLI and runtime foundation for a local-first multi-agent coding orchestrator.

## Project Purpose

This project is a local-first control plane for coordinating multiple coding
agents against one Git repository. It is designed to isolate work in disposable
Git worktrees, reserve edit boundaries with path claims, run validation, collect
agent output, and eventually integrate LLM-backed coding agents without letting
provider-specific behavior bypass the local safety model.

The goal is not only to call an LLM. The goal is to make parallel coding work
reviewable and recoverable:

- understand the repository before splitting work
- assign each agent a clear set of files or directories
- run each agent in an isolated worktree
- prevent overlapping edits through shared path claims
- collect diffs, summaries, validation results, and patches
- preview and apply merge candidates with conflict reporting

## Current Status

The current implementation covers a release-candidate local command-line slice:

- `maco init` initializes a Git repository.
- `maco worktree create <agent-id>` creates a linked Git worktree for branch `maco/<agent-id>`.
- `maco worktree list` lists registered agent worktrees.
- `maco worktree remove <agent-id>` removes an agent worktree, refusing dirty worktrees unless `--force` is passed.
- `SyncCoordinator` provides an in-memory exclusive path-claim layer for local agent coordination.
- `maco sync claim <agent-id> <path>...` records durable exclusive path claims.
- `maco sync release <token>` releases one durable claim.
- `maco sync release-agent <agent-id>` releases all claims for an agent.
- `maco sync owner <path>` reports the owner of a path, if one exists.
- `maco sync status` lists active durable claims.
- `maco repo map` prints a read-only repository file map with coarse file categories and Git status.
- `maco repo map --semantic` builds a parser-backed Rust semantic map for modules, symbols, impls, imports, public re-exports, module declarations, import dependencies, and parse errors.
- `maco repo query symbol <name>` and `maco repo query path <path>` search the semantic Rust map.
- `maco orchestrate validate <plan-file>` validates a local JSON orchestration plan.
- `maco orchestrate run <plan-file>` creates or reuses clean agent worktrees, claims paths, runs configured local shell commands, runs per-agent validation commands in agent worktrees, enforces path-claim boundaries, optionally writes patches and checkpoints, releases claims, and emits a run summary.
- `maco worktree diff` collects a registered agent worktree diff and uses active sync claims when `--claim` is omitted.
- `maco orchestrate collect` reads a prior JSON run summary and builds merge candidates with validation reports from agent summaries.
- `maco merge preview` and `maco merge apply` collect agent output and gate primary-worktree integration with dirty-primary, stale-base, unclaimed-edit, validation, and apply-check safety reports.
- `maco llm providers` and `maco llm prompt-preview` expose the provider-neutral prompt boundary without network calls.

## Roadmap

Implemented release-candidate foundations:

1. Result collection, merge preview, and guarded patch apply for agent worktrees.
2. Parser-backed Rust repository maps for modules, symbols, impls, imports, and
   dependency edges.
3. Local orchestration with dependency scheduling, path claims, timeouts,
   per-agent validation, repo-level validation, run ids, and checkpoint writes.
4. Provider-neutral LLM adapter boundaries with deterministic fake-provider
   tests.

Remaining release-readiness work:

1. Add checkpoint resume behavior. Checkpoints are written today, but runs do
   not resume from them.
2. Implement or remove `reuse=reset`. The value is parsed and serialized but
   intentionally refused because it would need destructive Git cleanup.
3. Add richer merge conflict classification and validation gates around merge
   apply. Current apply uses `git apply` safety checks and reports blockers, but
   does not classify conflicts by symbol or dependency impact.
4. Add semantic task planning that proposes path claims and orchestration plans.
5. Add opt-in real LLM providers and provider-backed agent execution only after
   explicit approval and additional invariant tests.
6. Add semantic-map caching and broader language adapters after the Rust path is
   stable.

Network-facing LLM behavior should remain optional. The default development and
test workflow should continue to run without provider credentials.

Durable sync state is stored under the Git common metadata directory at
`$(git rev-parse --git-common-dir)/maco/state/claims.json`, so the primary
worktree and linked agent worktrees share the same claim state.

Default linked worktrees are created outside the repository at
`../.maco/worktrees/<repo-name>/<agent-id>`.

## Development

If Rust is available globally:

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
```

If Rust is not available globally, use Nix:

```bash
nix develop path:$PWD
```

Inside that shell, run the same Cargo commands.

For one-shot checks:

```bash
nix develop path:$PWD -c cargo fmt -- --check
nix develop path:$PWD -c cargo test
nix develop path:$PWD -c cargo clippy --all-targets -- -D warnings
```

## CLI Examples

Inspect a repository:

```bash
cargo run -- repo map --repo . --json
cargo run -- repo map --semantic --repo . --json
cargo run -- repo query symbol WorktreeManager --repo . --json
cargo run -- repo query path src/worktree.rs --repo . --json
```

Create a worktree from the current repository HEAD:

```bash
cargo run -- worktree create agent-a --repo . --json
```

List worktrees:

```bash
cargo run -- worktree list --repo .
```

Remove a clean worktree and delete its default branch:

```bash
cargo run -- worktree remove agent-a --repo . --delete-branch
```

Claim paths for an agent:

```bash
cargo run -- sync claim agent-a src README.md --repo . --json
```

Check the current owner for a path:

```bash
cargo run -- sync owner src/lib.rs --repo .
```

List active claims:

```bash
cargo run -- sync status --repo . --json
```

Release one claim by token:

```bash
cargo run -- sync release 1 --repo .
```

Release all claims for an agent:

```bash
cargo run -- sync release-agent agent-a --repo .
```

Run a local orchestration plan:

```json
{
  "default_timeout_seconds": 600,
  "worktree_reuse_policy": "clean",
  "repo_validation_commands": [
    {
      "name": "repo smoke",
      "command": "cargo test",
      "timeout_seconds": 300
    }
  ],
  "agents": [
    {
      "id": "agent-a",
      "paths": ["src"],
      "command": "cargo test",
      "validation_commands": [
        {
          "name": "agent fmt",
          "command": "cargo fmt -- --check",
          "timeout_seconds": 60
        }
      ],
      "env": {
        "RUST_BACKTRACE": "1"
      }
    },
    {
      "id": "agent-b",
      "paths": ["README.md"],
      "depends_on": ["agent-a"],
      "timeout_seconds": 60,
      "command": "printf '# Updated\\n' > README.md"
    }
  ]
}
```

```bash
cargo run -- orchestrate validate plan.json --json
cargo run -- orchestrate run plan.json --repo . --jobs 2 --patch-dir .maco/patches --reuse clean --run-id demo --checkpoint-dir .maco/checkpoints --json
```

The orchestrator validates that plan paths do not overlap, dependencies are
known and acyclic, commands are non-empty, and timeouts are positive. It creates
or reuses a linked worktree for each agent id according to
`worktree_reuse_policy` or CLI `--reuse`, claims all requested paths before
running commands, runs dependency-ready agents up to `--jobs`, runs each
agent's `validation_commands` in that agent worktree after its command succeeds,
verifies that each command only changed claimed paths, and releases claims at
the end. Use `--keep-claims` to leave acquired claims active for debugging.
`clean` is the default reuse policy, `required` requires existing clean
worktrees, `fresh` refuses existing worktrees, and `reset` is parsed but refused.

Run summaries include command status, duration, timeout state, changed paths,
unclaimed changed paths, captured stdout/stderr summaries, and optional patch
paths. `--patch-dir` writes per-agent `git diff --binary HEAD` patches for
changed worktrees. Repo-level validation commands currently run in the primary
worktree after agent commands complete; use agent validation commands for checks
that must see unmerged agent worktree changes.

Collect and preview agent output:

```bash
cargo run -- worktree diff agent-a --repo . --json
cargo run -- worktree diff agent-a --repo . --claim src --full-diff --json
cargo run -- orchestrate collect summary.json --repo . --json
cargo run -- merge preview agent-a --repo . --claim src --json
cargo run -- merge apply agent-a --repo . --claim src
cargo run -- merge apply agent-a --repo . --claim src --force-dirty-primary --force-stale-base --force-unclaimed-edits
```

Merge apply refuses dirty primary worktrees, stale agent bases, unclaimed edits,
validation failures, and apply conflicts unless the matching explicit force flag
is passed. Apply-check failures themselves are still blocking unless
`--force-apply-conflicts` allows a successful three-way apply check. Validation
failures are considered when validation reports are supplied from collected run
summaries; direct `merge preview/apply` commands do not yet accept external
validation-report input.

Preview the local LLM boundary without credentials or network access:

```bash
cargo run -- llm providers --json
cargo run -- llm prompt-preview task.md --agent-id agent-a --path src/lib.rs --repo . --json
```

There is not yet a network provider, `maco agent run`, or provider-backed
orchestration command.

Cleanup examples:

```bash
cargo run -- sync status --repo . --json
cargo run -- worktree remove agent-a --repo . --delete-branch
```
