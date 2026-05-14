# Multi-Agent Coding Orchestrator

Rust CLI and runtime foundation for a local-first multi-agent coding orchestrator.

The current implementation covers Phase 1 and the first Phase 2 foundation:

- `maco init` initializes a Git repository.
- `maco worktree create <agent-id>` creates a linked Git worktree on `maco/<agent-id>`.
- `maco worktree list` lists registered agent worktrees.
- `maco worktree remove <agent-id>` removes an agent worktree, refusing dirty worktrees unless `--force` is passed.
- `SyncCoordinator` provides an in-memory exclusive path-claim layer for local agent coordination.

Later phases will add the AST repository mapper, LLM agent wrappers, and orchestration loop.

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
