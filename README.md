# Multi-Agent Coding Orchestrator

Rust CLI and runtime foundation for a local-first multi-agent coding orchestrator.

The current implementation covers the local command-line MVP:

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
- `maco orchestrate validate <plan-file>` validates a local JSON orchestration plan.
- `maco orchestrate run <plan-file>` creates or reuses clean agent worktrees, claims paths, runs configured local shell commands, enforces path-claim boundaries, releases claims, and emits a run summary.

Later phases will add AST-level semantic repository intelligence, LLM agent
wrappers, richer merge automation, and production-grade cancellation.

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
  "agents": [
    {
      "id": "agent-a",
      "paths": ["src"],
      "command": "cargo test",
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
cargo run -- orchestrate run plan.json --repo . --jobs 2 --patch-dir .maco/patches --json
```

The orchestrator validates that plan paths do not overlap, dependencies are
known and acyclic, commands are non-empty, and timeouts are positive. It creates
or reuses a clean linked worktree for each agent id, claims all requested paths
before running commands, runs dependency-ready agents up to `--jobs`, verifies
that each command only changed claimed paths, and releases claims at the end.
Use `--keep-claims` to leave acquired claims active for debugging.

Run summaries include command status, duration, timeout state, changed paths,
unclaimed changed paths, captured stdout/stderr summaries, and optional patch
paths. `--patch-dir` writes per-agent `git diff --binary HEAD` patches for
changed worktrees.

Cleanup examples:

```bash
cargo run -- sync status --repo . --json
cargo run -- worktree remove agent-a --repo . --delete-branch
```
