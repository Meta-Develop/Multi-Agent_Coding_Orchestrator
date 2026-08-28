# Parkfix2: hermetic pre-claim Park evidence

Status: **BLOCKED / PARTIAL**. The owned fixed-cause rework is implemented and locally committed, every focused and hostile check passes, and the code review is accepted. Final acceptance is blocked because the exact full-library gate ended at **2,502 passed / 1 failed / 15 ignored**, not the required **2,503 / 0 / 15**. The finite measurement fuse is exhausted at **12/12**. The parkfix2.DONE marker is intentionally absent.

## Acceptance matrix

| Criterion | State | Evidence |
|---|---|---|
| Deterministic Park decision and authenticated pending checkpoint | VERIFIED | Both named tests pass together; the decisive serial test passes with strict containment explicitly disabled. |
| Typed Park finding, authority, journal, checkpoint, and zero assignment side effects | VERIFIED | The original assertions remain active in src/supervise/scheduler/decomposition_tests.rs:1990-2028 and 2030-2275. |
| Per-invocation evidence isolation and consumption | VERIFIED | Private cfg(test) TLS/RAII provider at src/supervise/scheduler.rs:73-157; explicit guard drop at src/supervise/scheduler/decomposition_tests.rs:1988. |
| Initial/final equality and final integrity semantics | VERIFIED | Two equal, nonempty raw snapshots are consumed; completeness and the unchanged comparison remain at src/supervise/scheduler.rs:3057-3066 and 4017-4049. |
| PATH, DBUS/XDG, HOME, and combined hostile setups | VERIFIED | Attempts 4-7 pass after the attempt-3 fixed-cause correction. |
| fmt, locked all-target check, clippy with -D warnings, portability | VERIFIED | Attempts 8-11 pass. |
| Exact full library result 2,503 / 0 / 15 | MISSING | Attempt 12 produced 2,502 / 1 / 15 because an unowned process_runner cleanup assertion failed. |
| GitHub-hosted-runner confirmation | MISSING | Remote and GitHub mutation were forbidden; only a future hosted run can confirm that surface. |

## Fixed cause and rework

Commit 74e03b6724fe5ce4a246502aa7d8c777dc4f1aa2 is accepted diagnostics. Commit 5fc58d6e0ba1dec27952fbd197942c6161af0add added deterministic PreclaimRunEvidence, but it was incomplete: after the decision was persisted, scheduler initialization still executed the ambient strict primary-worktree probe. Under the faithful O2 setup, that probe failed before parked_preclaim_outcome ran. The persisted decision correctly remained limited_scope=Yes, clear_verification_path=Yes, autonomously_completable=No, but the report never received the typed Park finding.

Commit 895eb852dad925cd4ec0ba49256b216fdcca67ec replaces the preclaim-only override with one private, test-only, per-invocation provider. It contains exactly one deterministic preclaim value and a queue initialized from exactly two deterministic, equal, materially nonempty PrimaryWorktreeSnapshot values. TLS confines evidence to the invoking test thread; a mutex serializes provider-backed invocations; active-but-exhausted access panics; RAII clears on success or unwind; and normal guard drop asserts that the preclaim value and both snapshots were consumed.

The helper still runs the real Codex/verified scheduler path and retains the persisted-decision, typed-finding, authority, journal, checkpoint, and zero-side-effect assertions. The sibling autonomously_completable=yes test is unchanged. The equal snapshots exercise the unchanged no-difference branch; they do not inject a finished decision, select Fake/simulation, skip the typed finding, or weaken integrity semantics.

## Production-compiled line justification

All provider storage, guard, exhaustion checks, and deterministic snapshot construction are cfg(test). The production-compiled edits are limited to these routing lines:

- src/supervise/scheduler.rs:3057-3060 routes initial acquisition through the wrapper; the completeness rejection at lines 3061-3066 is unchanged.
- src/supervise/scheduler.rs:3094-3104 retains test injection for preclaim evidence and the exact production fallback PreclaimRunEvidence::acquire(repo, runtime, execution_runtime).
- src/supervise/scheduler.rs:3106-3115 introduces the only primary-snapshot wrapper; its production tail remains the exact ambient strict primary_worktree_snapshot(repo, execution_runtime) call.
- src/supervise/scheduler.rs:4018 routes only final acquisition through the wrapper; inspection, primary_integrity_changes, scope filtering, findings, and failure semantics at lines 4019-4049 are unchanged.

No new preclaim.rs rework was required.

## Ambient inputs and injection boundary

| Input | Production acquisition | Classification and test injection method |
|---|---|---|
| Assignment/requested plan | Viability reads the typed assignment, including environment requirements at src/supervise/scheduler/preclaim.rs:507-535. | **Injected and fixture-controlled:** the Park assignment and worker network requirements are constructed at src/supervise/scheduler/decomposition_tests.rs:1864-1877 and loaded at 1894-1902. This is the sole source of `autonomously_completable`; the real evaluator still derives No. |
| Repository map and semantic risk | Ambient scans occur in src/supervise/scheduler/preclaim.rs:205-224; the production fallback is src/supervise/scheduler.rs:3094-3104. Map absence can change `clear_verification_path`, completeness, and reason, but not autonomous completion. | **Injected and fixture-controlled for this test:** deterministic verified maps are built at src/supervise/scheduler/decomposition_tests.rs:1912-1933 and consumed once. Production remains ambient. |
| Initial primary HEAD/index/status/worktree state | The production acquisition is src/supervise/scheduler.rs:3057-3066 through the strict fallback at 3106-3115; strict Git execution begins at src/supervise/primary_integrity.rs:603-610. | **Injected and fixture-controlled for this test:** a materially nonempty raw snapshot is built at src/supervise/scheduler/decomposition_tests.rs:1934-1972 and queue item 1 is consumed. Production remains ambient and strict. |
| Final primary state | Final acquisition and comparison remain at src/supervise/scheduler.rs:4017-4049 through the same strict fallback. | **Injected and fixture-controlled for this test:** equal queue item 2 is consumed and the unchanged comparator runs. Production remains ambient and strict. |
| Runtime and catalog | Runtime participates in preclaim evidence at src/supervise/scheduler/preclaim.rs:198-224; catalog is a later selector input. | **Injected and fixture-controlled:** Codex is set at src/supervise/scheduler/decomposition_tests.rs:1881-1882 and in the evidence at 1912-1933; the deterministic catalog is built at 1894-1896. The catalog is **non-verdict** for this Park result because no child is selected. |
| PATH/Codex and HOME/Git configuration | Preflight only applies relative `Path::exists` to the configured runtime binary at src/run_ops.rs:549-570; verified Git sanitizes its environment at src/supervise/primary_integrity.rs:603-630. | **Non-verdict for viability and not decision-injected.** PATH and HOME remain ambient for reachable preflight/filesystem behavior, while the four hostile fixtures vary them explicitly. The snapshot provider prevents only the ambient strict-containment Git probe in this test. |
| Environment, TMPDIR, and DBUS/XDG | `TMPDIR` selects outer tempfile placement; `MACO_BOUNDED_STATUS_RUNTIME_ROOT` can affect bounded-map scratch placement; `MACO_TEST_DISABLE_STRICT_CONTAINMENT` is checked at src/process_runner/part3.rs:300-311. The launcher clears and reconstructs XDG at src/process_runner/part3.rs:570-579. | **Still ambient but non-verdict for viability.** The commands set lane-private TMPDIR and explicitly vary DBUS/XDG; attempts 2, 5, and 7 set the test containment switch. These values do not inject dimensions or a finished decision. |
| Session/kernel containment state | Strict Linux containment reads effective UID and owner-private runtime state at src/process_runner/part3.rs:1701-1710 and the delegated user-manager cgroup at 1379-1390. | **Still ambient in production and verdict-materialization-critical there.** It is not decision input. The test-only raw snapshot provider bypasses this probe only for the two snapshot acquisitions. |
| Git/filesystem state | Repository scans, Git metadata/index, trusted Git, permissions, devices, capacity, and concurrent mutation are ambient production inputs; the fixture repository is created at src/supervise/scheduler/decomposition_tests.rs:817-830. | **Fixture-controlled contents, still-ambient substrate:** repository files and the two raw integrity views are deterministic, but tempfile/Git creation and artifact filesystem operations still use the host filesystem. None inject autonomous completion. |
| Process registry | Repository-local registry state, PID, process start time, argv, and liveness are consulted before preclaim through src/run_ops.rs:141-150. | **Still ambient and non-verdict:** a collision can abort preparation, but it cannot alter the preclaim dimensions. No registry result is injected. |
| Preflight, artifacts, and time | Git-status, repository-map, sync, and runtime captures are written at src/run_ops.rs:211-250; relative runtime existence is captured at 549-570; the clock is read at 583-587. Journal/checkpoint and report writes remain reachable. | **Still ambient and non-verdict for viability:** capture failures are recorded, while storage or clock failures can abort/finalize the run. The fixture does not replace these paths; its assertions prove the expected artifacts and absence of assignment side effects. |
| Admission, quota, and configuration | Host resource, quota, and objective-profile inputs are later preparation/admission inputs, not viability dimensions. | **Fixture-controlled and non-verdict for viability:** host resources are explicitly overridden at src/supervise/scheduler/decomposition_tests.rs:1883-1893, quota is thread-local and absent, and plan metadata is fixture-local at 1897-1902. Other production configuration remains ambient outside this test. |

## Measurement fuse

Before post-repair measurement, this report durably declared 11 planned attempts plus one fixed-cause reserve. Every timeout, abort, failed precondition, and repeat consumed an attempt. Attempt 3 failed its checked precondition because codex and git occupied the same PATH component. A read-only diagnostic printed proven_cause=shared_path_component. The corrected overlay retained all executables except codex, and attempt 4 consumed the sole reserve.

Final usage: **12/12 attempts; 1/1 reserve; no rerun permitted**.

The command transcript uses the authorized placeholders $PARKFIX2_TARGET and $PARKFIX2_TMP for the lane's machine-local target and temporary directories.

## Exact command and outcome ledger

1. PASS — compiler/tool versions and both named tests:

~~~sh
timeout 300s nix develop path:$PWD -c env CARGO_TARGET_DIR="$PARKFIX2_TARGET" TMPDIR="$PARKFIX2_TMP" bash -euo pipefail -c 'rustc --version; cargo --version; cargo clippy --version; cargo test --locked --lib park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects -- --nocapture'
~~~

rustc 1.94.1 (e408947bf 2026-03-25); cargo 1.94.1 (29ea6fb6a 2026-03-24); clippy 0.1.94 (e408947bfd 2026-03-25). Result: 2 passed, 0 failed, 0 ignored, 2,516 filtered out.

2. PASS — exact decisive O2 reproduction:

~~~sh
timeout 300s nix develop path:$PWD -c env CARGO_TARGET_DIR="$PARKFIX2_TARGET" TMPDIR="$PARKFIX2_TMP" MACO_TEST_DISABLE_STRICT_CONTAINMENT=1 cargo test --locked --lib supervise::scheduler::decomposition_tests::preclaim_serial_park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects -- --exact --nocapture
~~~

Result: 1 passed, 0 failed, 2,517 filtered out.

3. FAILED PRECONDITION, exit 125:

~~~sh
timeout 300s nix develop path:$PWD -c env CARGO_TARGET_DIR=$PARKFIX2_TARGET TMPDIR=$PARKFIX2_TMP bash -euo pipefail -c '
IFS=: read -r -a path_parts <<< "$PATH"
filtered_path=
for part in "${path_parts[@]}"; do
  [[ -n "$part" ]] || part=.
  if [[ -e "$part/codex" || -L "$part/codex" ]]; then
    continue
  fi
  filtered_path="${filtered_path}${filtered_path:+:}${part}"
done
[[ -n "$filtered_path" ]] || { echo "precondition failed: filtered PATH is empty" >&2; exit 125; }
export PATH="$filtered_path"
hash -r
if command -v codex >/dev/null 2>&1; then echo "precondition failed: codex still resolves" >&2; exit 125; fi
for tool in cargo rustc git cc ld; do
  command -v "$tool" >/dev/null 2>&1 || { echo "precondition failed: required tool unavailable: $tool" >&2; exit 125; }
done
echo "precondition passed: codex absent; Rust toolchain and linker executable"
cargo test --locked --lib park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects -- --nocapture
'
~~~

Git no longer resolved because it shared `<system-bin>` with codex, so no product assertion ran. Fixed-cause output: `codex_path=<system-bin>/codex`; `git_path=<system-bin>/git`; `proven_cause=shared_path_component`.

4. PASS, reserve consumed — corrected checked PATH hostile:

~~~sh
timeout 300s nix develop path:$PWD -c env CARGO_TARGET_DIR=$PARKFIX2_TARGET TMPDIR=$PARKFIX2_TMP bash -euo pipefail -c '
rm_bin=$(command -v rm)
ln_bin=$(command -v ln)
mktemp_bin=$(command -v mktemp)
overlay_prefix="${TMPDIR%/}/parkfix2-path-overlay."
path_overlay=$("$mktemp_bin" -d "${overlay_prefix}XXXXXX")
case "$path_overlay" in "$overlay_prefix"*) ;; *) echo "unsafe PATH overlay" >&2; exit 125;; esac
cleanup_overlay() { "$rm_bin" -rf -- "$path_overlay"; }
trap cleanup_overlay EXIT
IFS=: read -r -a path_parts <<< "$PATH"
filtered_path=
for part in "${path_parts[@]}"; do
  [[ -n "$part" ]] || part=.
  if [[ -e "$part/codex" || -L "$part/codex" ]]; then
    for candidate in "$part"/*; do
      [[ -f "$candidate" || -L "$candidate" ]] || continue
      [[ -x "$candidate" ]] || continue
      name=${candidate##*/}
      [[ "$name" != codex ]] || continue
      if [[ ! -e "$path_overlay/$name" && ! -L "$path_overlay/$name" ]]; then
        "$ln_bin" -s -- "$candidate" "$path_overlay/$name"
      fi
    done
    continue
  fi
  filtered_path="${filtered_path}${filtered_path:+:}${part}"
done
export PATH="$path_overlay${filtered_path:+:}${filtered_path}"
hash -r
if command -v codex >/dev/null 2>&1; then echo "precondition failed: codex still resolves" >&2; exit 125; fi
for tool in cargo rustc git cc ld; do
  command -v "$tool" >/dev/null 2>&1 || { echo "precondition failed: required tool unavailable: $tool" >&2; exit 125; }
done
echo "precondition passed: codex absent; Rust toolchain, Git, and linker executable"
cargo test --locked --lib park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects -- --nocapture
'
~~~

Result: 2 passed, 0 failed, 2,516 filtered out. The overlay cleanup trap removed only its validated temporary directory.

5. PASS — absent DBUS/XDG plus the explicit containment-disable switch:

~~~sh
timeout 300s nix develop path:$PWD -c env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR CARGO_TARGET_DIR="$PARKFIX2_TARGET" TMPDIR="$PARKFIX2_TMP" MACO_TEST_DISABLE_STRICT_CONTAINMENT=1 cargo test --locked --lib supervise::scheduler::decomposition_tests::preclaim_serial_park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects -- --exact --nocapture
~~~

Result: 1 passed, 0 failed, 2,517 filtered out.

6. PASS — initially empty HOME:

~~~sh
timeout 300s nix develop path:$PWD -c env CARGO_TARGET_DIR=$PARKFIX2_TARGET TMPDIR=$PARKFIX2_TMP bash -euo pipefail -c '
rm_bin=$(command -v rm)
find_bin=$(command -v find)
home_prefix="${TMPDIR%/}/parkfix2-home."
test_home=$(mktemp -d "${home_prefix}XXXXXX")
case "$test_home" in "$home_prefix"*) ;; *) echo "unsafe temporary HOME path" >&2; exit 125;; esac
cleanup_home() { "$rm_bin" -rf -- "$test_home"; }
trap cleanup_home EXIT
[[ -z "$("$find_bin" "$test_home" -mindepth 1 -print -quit)" ]] || { echo "precondition failed: temporary HOME is not empty" >&2; exit 125; }
export HOME="$test_home"
echo "precondition passed: HOME started empty"
cargo test --locked --lib park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects -- --nocapture
'
~~~

Result: 2 passed, 0 failed, 2,516 filtered out.

7. PASS — combined hostile:

~~~sh
timeout 300s nix develop path:$PWD -c env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR CARGO_TARGET_DIR=$PARKFIX2_TARGET TMPDIR=$PARKFIX2_TMP MACO_TEST_DISABLE_STRICT_CONTAINMENT=1 bash -euo pipefail -c '
rm_bin=$(command -v rm)
ln_bin=$(command -v ln)
find_bin=$(command -v find)
mktemp_bin=$(command -v mktemp)
task_cargo_home=${CARGO_HOME:-${HOME%/}/.cargo}
[[ -d "$task_cargo_home" ]] || { echo "precondition failed: stable Cargo home unavailable" >&2; exit 125; }
export CARGO_HOME="$task_cargo_home"
home_prefix="${TMPDIR%/}/parkfix2-combined-home."
test_home=$("$mktemp_bin" -d "${home_prefix}XXXXXX")
overlay_prefix="${TMPDIR%/}/parkfix2-combined-path."
path_overlay=$("$mktemp_bin" -d "${overlay_prefix}XXXXXX")
case "$test_home" in "$home_prefix"*) ;; *) echo "unsafe temporary HOME path" >&2; exit 125;; esac
case "$path_overlay" in "$overlay_prefix"*) ;; *) echo "unsafe PATH overlay" >&2; exit 125;; esac
cleanup_combined() { "$rm_bin" -rf -- "$test_home" "$path_overlay"; }
trap cleanup_combined EXIT
[[ -z "$("$find_bin" "$test_home" -mindepth 1 -print -quit)" ]] || { echo "precondition failed: HOME not empty" >&2; exit 125; }
export HOME="$test_home"
IFS=: read -r -a path_parts <<< "$PATH"
filtered_path=
for part in "${path_parts[@]}"; do
  [[ -n "$part" ]] || part=.
  if [[ -e "$part/codex" || -L "$part/codex" ]]; then
    for candidate in "$part"/*; do
      [[ -f "$candidate" || -L "$candidate" ]] || continue
      [[ -x "$candidate" ]] || continue
      name=${candidate##*/}
      [[ "$name" != codex ]] || continue
      if [[ ! -e "$path_overlay/$name" && ! -L "$path_overlay/$name" ]]; then
        "$ln_bin" -s -- "$candidate" "$path_overlay/$name"
      fi
    done
    continue
  fi
  filtered_path="${filtered_path}${filtered_path:+:}${part}"
done
export PATH="$path_overlay${filtered_path:+:}${filtered_path}"
hash -r
! command -v codex >/dev/null 2>&1 || { echo "precondition failed: codex resolves" >&2; exit 125; }
[[ ! -v DBUS_SESSION_BUS_ADDRESS ]] || { echo "precondition failed: DBUS present" >&2; exit 125; }
[[ ! -v XDG_RUNTIME_DIR ]] || { echo "precondition failed: XDG present" >&2; exit 125; }
for tool in cargo rustc git cc ld; do command -v "$tool" >/dev/null 2>&1 || { echo "precondition failed: missing $tool" >&2; exit 125; }; done
echo "preconditions passed: no codex, empty HOME, no DBUS/XDG, containment disabled"
cargo test --locked --lib park_has_authenticated_pending_checkpoint_and_no_assignment_side_effects -- --nocapture
'
~~~

Result: 2 passed, 0 failed, 2,516 filtered out.

8. PASS, exit 0:

~~~sh
timeout 300s nix develop path:$PWD -c env CARGO_TARGET_DIR="$PARKFIX2_TARGET" TMPDIR="$PARKFIX2_TMP" cargo fmt --all -- --check
~~~

9. PASS, 1m35s:

~~~sh
timeout 1200s nix develop path:$PWD -c env CARGO_TARGET_DIR="$PARKFIX2_TARGET" TMPDIR="$PARKFIX2_TMP" cargo check --locked --all-targets
~~~

10. PASS, 1m27s:

~~~sh
timeout 1800s nix develop path:$PWD -c env CARGO_TARGET_DIR="$PARKFIX2_TARGET" TMPDIR="$PARKFIX2_TMP" cargo clippy --locked --all-targets -- -D warnings
~~~

11. PASS:

~~~sh
timeout 300s nix develop path:$PWD -c env CARGO_TARGET_DIR="$PARKFIX2_TARGET" TMPDIR="$PARKFIX2_TMP" bash -euo pipefail -c 'python3 --version; python3 -B scripts/check_repository_portability.py'
~~~

Python 3.13.12; repository portability check passed (387 tracked paths).

12. FAILED, exit 101:

~~~sh
timeout 2700s nix develop path:$PWD -c env CARGO_TARGET_DIR="$PARKFIX2_TARGET" TMPDIR="$PARKFIX2_TMP" cargo test --locked --lib
~~~

Result: **2,502 passed; 1 failed; 15 ignored; 0 measured; 0 filtered out; 2352.01s**. Sole failure: process_runner::tests::external_codex_outer_sandbox_enforces_control_and_report_write_boundaries. At src/process_runner/tests.rs:3697, the assertion reported that strict backend refusal left maco-process-377476-2606.service active with containment processes. A later read-only check found the unit not-found, inactive/dead, result success, and none of the reported processes present. Later quiescence does not convert the failed gate to a pass.

## Review and commits

A terminal REVIEW_AUDITOR reviewed the final source before measurement and returned ACCEPT with no findings. It confirmed provider isolation, fail-closed exhaustion, nonempty snapshots, explicit consumption, real Codex/verified execution, unchanged sibling yes-test, exact production fallbacks, and unchanged final integrity comparison. No source changed after that verdict before commit.

Local commits:

- 74e03b6724fe5ce4a246502aa7d8c777dc4f1aa2 — accepted assertion diagnostics.
- 5fc58d6e0ba1dec27952fbd197942c6161af0add — useful but incomplete preclaim-only seam.
- 895eb852dad925cd4ec0ba49256b216fdcca67ec — fixed-cause hermetic preclaim plus two-snapshot provider.
- The logical report commit is the commit containing this document; it deliberately contains no DONE marker.

No push, merge, rebase, reset, clean, amend, history rewrite, remote mutation, or GitHub mutation occurred.

## Model and outcome ledger

All current delegated roles exposed gpt-5.6-sol, xhigh, and service tier default. Cost is recorded as bounded leaf turns and mandatory review/rework cycles.

| Attempt | Class, risk, boundedness | Context, horizon, gate | Outcome and cost | Failure class |
|---|---|---|---|---|
| Prior O1 forensics | diagnosis; medium trust-boundary; read-only bounded | medium; short; fixed-cause evidence | accepted; 1 execution plus parent review | none |
| Prior implementation at 5fc58d6 | test seam; medium; owned files | medium; short; O2 acceptance | rejected after 1 execution and 1 O2 review | incomplete evidence boundary |
| Seam researcher | design research; medium; read-only bounded | medium; short; advisory | accepted; 1 execution plus parent review | none |
| Validation researcher | command/fuse design; medium; read-only bounded | medium; short; advisory | accepted; 1 execution plus parent review | none |
| Provider worker | implementation; medium; two owned source files | medium; short; code gate | accepted after one small nonempty-snapshot rework; 2 execution turns plus parent review | initial fixture too weak |
| Budget/report worker | report setup; low; one report | small; short; pre-measurement gate | accepted; 1 execution plus parent review | none |
| Code auditor | acceptance review; medium; read-only bounded | medium; short; mandatory code gate | ACCEPT; 1 review, no re-review | none |
| Source-commit worker | Git lifecycle; low; two exact paths | small; short; delivery | accepted; 1 execution plus hooks | none |
| First final-report worker | evidence writing; low; one report | large; short; documentation | interrupted without mutation | orchestration timeout |
| Bounded report worker | evidence writing; low; one report | medium; short; documentation | interrupted without mutation | orchestration timeout |
| Report-apply worker | mechanical report mutation; low; one report | small; short; documentation | interrupted after deleting the ignored draft; no accepted artifact | orchestration timeout |
| O1 fallback report restore | evidence writing; low; one authorized report | medium; short; documentation | delegated leaves unavailable; direct fallback restore, pending audit | degraded execution path |
| Final report auditor | acceptance evidence; medium; read-only | medium; short; mandatory report gate | REJECT; 1 review; documentation rework required | incomplete literal command and ambient-input evidence |
| Report rework worker | mechanical evidence correction; low; one report | medium; short; documentation | completed; 1 execution; mandatory re-review ACCEPT | none |
| Report re-review auditor | acceptance evidence; medium; read-only | medium; short; mandatory report gate | ACCEPT; 1 re-review; no further rework | none |

Terra and Fast/priority were not used. Luna is ineligible for audit/acceptance, and the recorded MultiAgent V2 Luna environment rejection was not retried. Inherited user configuration contained service_tier = "priority"; the actual O1 launch explicitly overrode it with service_tier="default", and every leaf retained default. The MACO wrapper reported a missing external orchestrator manifest, so the lane used the documented native-terminal fallback. That is an environment/tooling fallback, not a model-quality failure.

The wave posterior remains Sol/xhigh for medium-risk trust-boundary implementation and acceptance gates. Local evidence is accepted with one small fixture rework; the final blocker is an unrelated cleanup assertion rather than a model-capability failure. There is no evidence basis to demote an acceptance gate.

## Cross-lane handoff and limitations

The remaining acceptance failure is outside this lane's source authority: investigate process_runner::tests::external_codex_outer_sandbox_enforces_control_and_report_write_boundaries and strict-refusal cleanup ordering around src/process_runner/tests.rs:3697 under a separately authorized finite fuse. Do not treat the later disappearance of the transient unit as a pass for this run.

Local hostile evidence shows that parkfix2 no longer depends on codex PATH visibility, a populated HOME, or inherited DBUS/XDG values. It does not prove GitHub-hosted behavior. Because this task forbids remote/GitHub mutation, runner confirmation remains explicitly unverified until the committed tree is exercised there.

## Preserved state

The unrelated pre-existing .maco/wave2/reports/parkfix.md remains untouched with Git object hash 6595d45a50db3ad25c170f5d40ab8be5dee55f4c. Files under .agents, unowned source, manifests, lockfiles, workflows, remotes, and GitHub state were not edited. The intended terminal Git state after the report commit is that parkfix.md is the only dirty path. The missing DONE marker is deliberate while the full-library gate remains failed.
