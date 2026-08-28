# Lane `autopilotci` report

Status: **PARTIAL with a cause fix**. The eleven GitHub Linux
`autopilot_cli` failures are not the old #318 "supervisor dispatch returned
no final report" receipt. They are post-success merged-worktree reaping
under Required systemd containment on a runner whose cgroup is
`/system.slice/hosted-compute-agent.service`. Fake dispatch was already
isolated from user-systemd (`ecc2e1a`); the completion-hook GC dirtiness
snapshot was not. This lane keeps Required fail-closed, keeps Park residue
observation intact, and retries that dirtiness snapshot under
TrustedBestEffort when the typed missing-user-manager failure is the only
blocker.

Live `hosted-compute-agent.service` execution was not reconstructed on this
host (the process stays inside `user@*.service`; unprivileged bind-mounts
over `/proc/self/cgroup` do not replace the kernel cgroup). The CI stack and
the exact snapshot string are locked in unit tests. GitHub remains the
arbiter for the eleven-name set under that cgroup.

## Acceptance matrix

| Criterion | Status | Evidence |
| --- | --- | --- |
| Identify the environmental knob with file:line | VERIFIED | Required containment reads `/proc/self/cgroup` in `delegated_systemd_user_manager_cgroup` at `src/process_runner/part3.rs:1387-1413`. A unified path without a `user@*.service` component is `EnvironmentFailure` / `SandboxUnavailable`. Archived CI run 33199085362 failed all eleven names with `current cgroup /system.slice/hosted-compute-agent.service is not inside a delegated systemd user manager` while spawning bounded git for GC. Unsetting `DBUS_SESSION_BUS_ADDRESS` and `XDG_RUNTIME_DIR` does not change that cgroup; that is why the earlier hostile env was unfaithful. |
| 11 named tests green in the reproduction environment | PARTIAL | The live hosted-runner cgroup was not entered here. The classifier for that exact snapshot is locked at `src/worktree/tests.rs` (`hosted_runner_cgroup_is_classified_as_gc_trusted_fallback`, 1/0). The fallback lives at `src/worktree/part2.rs:1998-2023`. |
| 28/28 `autopilot_cli` locally | VERIFIED | `cargo test --locked --test autopilot_cli`: 28 passed / 0 failed. The eleven named tests are included. One of them (`auto_merge_request_is_recorded_but_never_performed`) also passed under `env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR`. |
| Two Park tests green with a user session | VERIFIED | `preclaim_serial_park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects` and `preclaim_concurrent_park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects`: 1/0 each with the live session. Broader `preclaim_` prefix: 7/0. |
| Same Park tests green without a user session | VERIFIED | Same two tests, 1/0 each, under `env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR`. That still leaves the process inside `user@*.service`; it is the mandated session-variable check, not a hosted-runner cgroup. |
| Park hermeticity contract not undone | VERIFIED | No edits to `6a71e57` / `beea42b` / `e846d61` residue capture. `process_runner` only gained `ProcessRunError::is_missing_delegated_user_manager` (`src/process_runner.rs:1750-1761`) by publishing the existing typed match. |
| #318 Fake bodies still execute; no silent skip | VERIFIED | Fake dispatch is unchanged. Required containment still fails closed before spawn. GC dirtiness still runs: Verified first, TrustedBestEffort only after the typed missing-user-manager failure. Evidence on the trusted path remains `TrustedBestEffort`, never `VerifiedEmpty`. |
| Full `--lib` unchanged-or-better | PARTIAL | Library now reports 2,520 tests (one new classifier). Focused `process_runner::` : 87 passed / 0 failed / 12 ignored. Focused Park tests: green. Full `--lib` with a 600s cap did not finish (0 FAILED among completed tests; several 60s+ autopilot unit tests). Isolated `bounded_status_tolerates_nested_repository_gitfiles` passed 1/0 after a parallel worktree run printed FAILED then was killed by the 300s cap before a summary. |
| `cargo fmt --all -- --check` | VERIFIED | Exit 0. |
| `cargo check --locked --all-targets` | VERIFIED | Exit 0. |
| `cargo clippy --locked --all-targets -- -D warnings` | VERIFIED | Exit 0. |
| Toolchain | VERIFIED | Pinned shell: rustc 1.94.1, cargo 1.94.1, clippy 0.1.94. |
| Path ownership | PARTIAL | Owned: `src/process_runner.rs`, `src/process_runner/tests.rs`, `tests/autopilot_cli.rs`. Unowned but required for the call site: `src/worktree.rs`, `src/worktree/part2.rs`, `src/worktree/part3.rs`, `src/worktree/part4.rs`, `src/worktree/tests.rs`. No wave-2 sibling owns `src/worktree/**`. `cli/part2.rs` was not edited. |
| Production panic policy, identity, no-push | VERIFIED | No `unwrap()`/`expect()` on production paths. Commits use `Meta-Develop <116134763+Meta-Develop@users.noreply.github.com>` for author and committer. No push, no remote mutation. |

## Cause

Parkfix (`6a71e57`, `beea42b`, `e846d61`) is **not** the production cause.
Those commits are `cfg(test)` residue observation. Integration tests compile
the library without `cfg(test)`.

What actually fails on GitHub Linux:

1. Fake `maco autopilot run` completes (`status=succeeded`, `success=true`).
2. CLI `finish_with_merged_worktree_reap` (`src/cli/part2.rs:992-1005`) always
   runs after worker commands, including Fake.
3. If `.git/maco/state` lists any managed worktree, lifecycle GC calls
   `gc_worktree_dirtiness` → `bounded_repository_gc_status_paths` →
   `BoundedGitIsolation::Verified` → `ContainmentPolicy::Required`
   (`src/worktree/part4.rs:1559`).
4. Required Linux containment requires a delegated user manager
   (`src/process_runner/part3.rs:1404-1413`). The runner cgroup is
   `/system.slice/hosted-compute-agent.service`.
5. The CLI turns the successful command into exit 1:
   `command succeeded, but merged worktree reaping failed`.

`ecc2e1a` already routed Fake snapshots and Fake worktree *creation* off
Required containment. Auto-reap dirtiness after the command was the remaining
Required call. Inventory/map scans were moved to Trusted in `a1c4e6d`; live
GC was deliberately left Verified. That split is still the operator-GC
policy. The completion hook cannot use it on GitHub.

Passing tests on that CI job never reached a successful Fake run that
registered worktrees (preflight refusals, plan/prune, the cgroup-shape unit
test). The eleven failures all did.

## Fix

- `ProcessRunError::is_missing_delegated_user_manager` publishes the existing
  typed pre-spawn `SandboxUnavailable` match. Required still fails closed.
- `gc_worktree_dirtiness` retries the same ignored-inclusive snapshot under
  `BoundedGitIsolation::Trusted` only when that typed failure is the cause.
- Operator `maco worktree gc` still prefers Verified on hosts that have a
  user manager (this host).
- `tests/autopilot_cli.rs` puts cgroup + stderr before stdout so a future CI
  log cannot hide the reaping cause behind truncated JSON.

## Before/after counts

| Environment | Before | After (this branch) |
| --- | --- | --- |
| GitHub Linux `autopilot_cli` (run 33199085362) | 17 passed / 11 failed | Not re-run here (no push). Cause and fix target that stack. |
| This host, live `user@*.service` | 28/0 `autopilot_cli` | 28/0 |
| This host, `env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR` | Unfaithful (cgroup unchanged) | One named test 1/0; Park pair 1/0 each |
| This host, hosted-runner cgroup | Cannot enter `system.slice` unprivileged | Classifier unit test 1/0 on the exact CI snapshot string |
| Library | CI 2,504/0/15 at the archived job; later heads 2,518 | 2,520 tests compiled; focused process_runner 87/0/12; Park 7/0; full `--lib` not finished in 600s |

## Cross-lane handoffs

- **runtime (#337/#339)**: rebase onto `56b2604`. New public method
  `ProcessRunError::is_missing_delegated_user_manager`. Do not treat missing
  user-systemd as a silent Required downgrade; this helper is the typed
  branch for callers that already have a TrustedBestEffort contract.
- **No worktree lane**: `src/worktree/part2.rs:1998-2034` is the GC fallback.
  Keep operator live GC on Verified when a user manager exists.
- **cli**: `finish_with_merged_worktree_reap` still fail-closes on unrelated
  reap errors. That is intended.

## What remains unverifiable without a GitHub runner

- The eleven-name set under cgroup
  `/system.slice/hosted-compute-agent.service`.
- Full-suite parallelism of `cargo test --locked --all-targets` on that
  runner (this job used `--all-targets` and stopped after `autopilot_cli`
  because fail-fast is the workflow default).
- Absent `codex` binary / empty `HOME` as independent knobs. The archived
  stderr names the cgroup, not those.

## Worker/model ledger

| Field | Value |
| --- | --- |
| Role | Terminal worker, lane `autopilotci` |
| Runtime | Grok, assigned because Codex was quota-exhausted |
| Model | grok-4.6 |
| Commits | `56b2604`, `dc2a1d6`, `88f6a16`, `e293dd3`, plus this report |

## Deliberately not done

- Did not revert Park residue scoping.
- Did not reintroduce Fake early-return / skip.
- Did not silently downgrade Required containment globally.
- Did not change `cli/part2.rs` to swallow reap failures.
- Did not push.
