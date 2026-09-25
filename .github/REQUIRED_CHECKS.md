# Required checks for `main`

The `main` branch ruleset should require these stable pull-request check names:

- `Required Rust CI gate`
- `Required account manager CI gate`
- `Cargo.lock, RustSec, licenses, bans, and sources`
- `Cargo.toml rust-version`

Both required gate jobs use `if: always()` and fail unless every named dependency
reports `success`. The Rust gate combines repository portability, the existing
Linux aggregate, and the macOS/Windows portable-build matrix. The Linux aggregate
fails unless every Linux library shard and the integration/binary partition pass;
its own formatting, all-target check, and strict Clippy run in those shards. The
account manager gate combines the desktop lockfile, frontend, and all headless
core/desktop matrix jobs. A skipped, cancelled, or failed dependency fails its
gate, so the ruleset needs only these stable aggregate contexts instead of each
matrix-generated context.

All four workflows run on every pull request. Keep the gate job names stable when
changing workflow internals, or update the ruleset and this file in the same
reviewed change. Require current-head checks; do not treat a successful check on
an earlier commit as acceptance of a later push. Before enabling enforcement,
verify a small test pull request: auto-merge must wait while a required gate is
queued/running, and a deliberately failed gate must block merge. After restoring
the passing test, verify it can merge.

For an emergency, only the repository owner should change the ruleset or use a
configured owner-only pull-request bypass. Record the reason and affected PR in
the issue or PR before bypass, then restore enforcement and verify the GitHub
ruleset audit entry. Routine automation must not use a bypass.
