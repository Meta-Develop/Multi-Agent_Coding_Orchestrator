# Rust test review loop

Use the repository toolchain and a delegated systemd user scope on Linux. On
the shared CT101 build host, **every** build/test/lint command goes through
`lane-check <assigned-slot> <timeout-seconds> '<command>'`. It supplies the Nix
development environment, target directory, disk guard and slot lock. Run Cargo
sequentially within your slot. Do not run the hosted-runner setup scripts on a
developer machine.

For example, with slot `s2` assigned:

```sh
lane-check s2 120 'cargo fmt --all -- --check'
lane-check s2 1200 'cargo clippy --locked --all-targets -- -D warnings'
lane-check s2 2700 'bash .github/scripts/run-linux-ci-cargo-test-partition.sh lib supervise-fixtures-budget'
```

For a focused change, use the narrowest relevant module first, then its complete
shard before handing off. A module filter includes all its tests:

```sh
lane-check s2 1200 'cargo test --locked --lib supervise::tests::budget::'
```

| Changed module / tests | Complete partition command suffix |
| --- | --- |
| `autopilot` | `lib autopilot` |
| `supervise::assignment_execution::bound_parent_turn*` | `lib supervise-bound` |
| `supervise::assignment_execution::decomposition_tests` | `lib supervise-decomposition` |
| `supervise::assignment_execution::managed_parent_controller_tests` | `lib supervise-parent` |
| Other assignment execution, except attached parent capture | `lib supervise-nested` |
| Other `supervise`, including attached parent capture | `lib supervise-core` |
| `supervise::tests::budget`, `prompts_gates` | `lib supervise-fixtures-budget` |
| `supervise::tests::licensed_breakage` | `lib supervise-fixtures-licensed` |
| `supervise::tests::plan_runtime`, `run_artifacts`, `qualification_handoff`, `reaudit` | `lib supervise-fixtures-runtime` |
| Other `supervise::tests`, including new fixture modules | `lib supervise-fixtures` |
| `external_agent` | `lib external-agent` |
| `worktree` | `lib worktree` |
| Other library modules | `lib rest` |
| `tests/merge_cli.rs`, `tests/pr_issue_cli.rs` | `non-lib merge` |
| Other integration tests, binaries, examples and benchmarks | `non-lib other` |
| Rust documentation examples, including `compile_fail` | `doc` |

These are ownership groups, not substring filters. Mandatory safety preflights
and diagnostic cases retain their original owners (`rest`, `supervise-core`,
`supervise-fixtures`), even when their module is otherwise assigned elsewhere.
For the authoritative exact names in a library shard, build/enumerate without
running any test bodies:

```sh
lane-check s2 1200 'python3 .github/scripts/linux_ci_library_shards.py supervise-fixtures-runtime --list'
```

Every invocation derives the full library inventory from libtest, partitions it
exactly once, and asks libtest to confirm that the execution filters select
precisely the assigned names. Unknown modules go into a fallback group. The
normal partition command still runs its safety checks; a successful inventory
query does not replace a test run. Shared runtime, scheduler and authority
changes warrant all affected partitions, often the complete matrix.

Doctests have a separate required execution because neither `--lib` nor explicit
integration targets run them. The `supervise-decomposition` CI job runs them
after its source-bound build and checks the full inventory against all thirteen
library shards, both integration shards and rustdoc. The check compares test
occurrences, so repeated names in separate binaries remain distinct; explicit
Criterion benchmarks are retained in addition to Cargo's default test set.
Missing, duplicated or extra test occurrences fail the check, including newly
added doctests.

```sh
lane-check s2 1800 'python3 .github/scripts/linux_ci_cargo_test_partition.py verify-inventory'
lane-check s2 1200 'cargo test --locked --doc'
```

The inventory command builds and lists tests without running their bodies. Use
`bash .github/scripts/run-linux-ci-cargo-test-partition.sh doc` for the delegated
CI wrapper's equivalent doctest execution.

The `rest` shard's main-helper preflight also needs a Nix package from the same
source and its verified helper digests. Set `MACO_SOURCE_MANIFEST_SHA256` before
compiling, and supply the three `MACO_CURSOR_MAIN_HELPER_*FOR_TEST` values from
the package qualification in [the CI workflow](../.github/workflows/ci.yml).
The development shell supplies build tools; package qualification is a separate
step. Keep a missing-package preflight failure visible when that setup is absent.
A container exposing the kernel `/proc` root as UID 65534 also cannot satisfy
the native gate's UID 0 check; this partition needs a suitable host or namespace.

The runner reports compilation plus inventory time separately from body time.
The first invocation builds the harness; subsequent shards in the same slot
reuse it. CI caches dependencies only, with keys including the toolchain,
lockfile, manifests and Cargo configuration. Only successful `main` runs save
caches; pull requests restore dependencies without publishing cache entries.
Workspace binaries are rebuilt
after the same-run Nix package has been verified. No test binaries or package
receipts are reused from another CI run.

The test profile already disables debuginfo and retains debug assertions and
overflow checks. Keep the default three test threads when comparing
measurements; do not compare a warm test run with a cold build. Prefer a module
filter for a focused edit and a complete shard for the corresponding review gate.

Repository script checks (also required when changing partition ownership):

```sh
lane-check s2 300 'python3 -m unittest discover -s scripts/tests -p "test_*.py"'
lane-check s2 300 'python3 -m unittest discover -s .github/scripts -p "test_*.py"'
lane-check s2 120 'python3 scripts/check_repository_portability.py'
```
