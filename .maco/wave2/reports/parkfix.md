# Parkfix report: durable typed preclaim Park findings

Status: **FUSE_STOPPED / PARTIAL**. Commit
`9152ec51efa61b61c26144579370cde68cdaa273` fixes the owned #92 defect, and the
focused/static acceptance surfaces pass. The required full-library target of
2,503 passed / 0 failed / 15 ignored was not obtained before the fixed
10-attempt validation fuse was exhausted. The independent auditor returned
`ACCEPT_WITH_PARTIAL_GATE`. Therefore `parkfix.DONE` is intentionally absent
and the Codex goal is not complete.

## Acceptance matrix

| Criterion | Status | Evidence |
| --- | --- | --- |
| Every Park decision yields a first-class finding with typed verdict and all three viability dimensions | VERIFIED | `PreclaimDecision` carries disposition, dimensions, and authority at `src/supervise/scheduler/preclaim.rs:170-190`; every Park is constructed through `parked_decision` at `src/supervise/scheduler/preclaim.rs:1025-1058`; `parked_preclaim_outcome` now derives `verdict`, `limited_scope`, `clear_verification_path`, and `autonomously_completable` from that decision at `src/supervise/scheduler/preclaim.rs:1145-1169`. |
| Missing-evidence Park is durable and explicitly typed | VERIFIED | `src/supervise/scheduler/decomposition_tests.rs:2176-2221` checks the exact typed finding, the persisted decision, empty claim tokens/paths, and an empty claim-store snapshot. |
| Serial and concurrent authenticated Park tests pass without a user session | VERIFIED | Attempt 4: 6 passed / 0 failed / 0 ignored / 2,512 filtered out, including the two named tests at `src/supervise/scheduler/decomposition_tests.rs:2158-2174`. |
| Same focused tests pass with a user session present | VERIFIED | Attempt 5: 6 passed / 0 failed / 0 ignored / 2,512 filtered out. |
| Park remains before claim, worktree, runner, and concurrent spawn | VERIFIED | Serial exits on Park at `src/supervise/scheduler.rs:1556-1566`, before assignment start at line 1591; concurrent exits on Park at `src/supervise/scheduler.rs:1754-1765`, before assignment start and thread creation at lines 1790 and 1807. The shared assertions at `src/supervise/scheduler/decomposition_tests.rs:1921-1937` cover zero runner calls, claims, releases, orchestrator reports, commands, environment failures, and gate denials. |
| Decision is journalled before claim/admission state | VERIFIED | Prepared decisions are evaluated and persisted before selector, quota-ledger attachment, or admission at `src/supervise/scheduler.rs:3252-3267`; direct scheduler decisions persist before return at `src/supervise/scheduler/preclaim.rs:1090-1106`; private evidence and the observable Gate event are appended at `src/supervise/scheduler/preclaim.rs:1109-1143`. |
| Authority floor is preserved | VERIFIED | The typed authority remains part of every decision at `src/supervise/scheduler/preclaim.rs:170-190`; fail-closed policy propagation remains at `src/supervise/scheduler/preclaim.rs:742-788`. The patch changes no decision, policy, admission, authority, or claim control flow. |
| Formatting, locked all-target check, and warnings-denied Clippy | VERIFIED | Attempts 7, 8, and 9 all exited 0. |
| Toolchain provenance | VERIFIED | Pinned shell reported `rustc 1.94.1`, `cargo 1.94.1`, and `clippy 0.1.94`; detailed output is task-local in `tool-versions.log`. |
| Portability gate | VERIFIED | Not required for this change: the patch adds only Rust formatting of existing typed values and a unit-test assertion, with no OS APIs, path handling, `libc`, configuration, or platform-specific branches. No portability command was spent. |
| Path ownership, production panic policy, identity, and privacy | VERIFIED | Commit `9152ec51` changes only `src/supervise/scheduler/preclaim.rs` and `src/supervise/scheduler/decomposition_tests.rs`; the production change adds no `unwrap()` or `expect()`. The exact three-key identity and composing authorship guard passed. This report contains no owner-local absolute path; raw logs remain task-local and untracked. |
| Independent review | VERIFIED | `/root/review_auditor` inspected all four prior leaf scopes, the committed diff, validation logs/counts, typed finding contract, no-side-effect behavior, journal order, authority, ownership, and production panic policy. Verdict: `ACCEPT_WITH_PARTIAL_GATE`; no rework was requested or performed. |
| Full CI-shaped locked library suite reaches 2,503 / 0 / 15 | PARTIAL | Attempt 6 reached 2,502 / 1 / 15 with one unowned `process_runner` containment-residue failure. Attempt 10 timed out before an aggregate after all six owned preclaim tests passed in-stream and two unowned containment-dependent tests had failed. |
| Completion marker and goal | MISSING | `parkfix.DONE` is withheld and the goal remains incomplete because the full-library aggregate is not VERIFIED and the fuse has no remaining attempt. |

## Environmental difference and cause

The mandated focused reproduction did **not** show a session-variable result
difference before mutation. With both session variables absent, attempt 1
passed 5 / 0 / 0 with 2,513 filtered out. With the live session variables
present, attempt 2 produced the same counts. The bounded CI-shaped widening in
attempt 3 also passed the same five tests with default harness parallelism.
Thus the two CI failures could not be reproduced locally by changing those
variables alone.

The archived CI source run was nevertheless exact: 2,501 passed / 2 failed /
15 ignored. The only failures were the serial and concurrent authenticated
preclaim Park tests at the finding predicate now located at
`src/supervise/scheduler/decomposition_tests.rs:1934-1937`. All 29 lower-level
preclaim tests passed, and all assertions preceding the finding predicate in
the shared helper passed. That proves the CI run parked correctly and produced
no assignment side effects; its report finding simply did not contain the
required typed viability text.

The environment-sensitive input is repository evidence acquisition, not a
direct DBUS/XDG read in the owned code. Repository-map and semantic-map scan
errors are converted to absent evidence with `.ok()` at
`src/supervise/scheduler/preclaim.rs:219-223`. Absent evidence selects a valid
fail-closed Park path at `src/supervise/scheduler/preclaim.rs:794-810`. The
precise CI-only scan/input divergence was not reconstructed locally, so no
stronger environmental claim is made.

Before the patch, `parked_preclaim_outcome` rendered only `decision.reason`.
Valid Park branches do not have to repeat the decision dimensions in their
free-form reasons; in particular, the missing-evidence branch can carry an
`autonomously_completable` dimension different from the substring expected by
the two high-level tests. That made a typed decision durable in the decision
journal but not first-class in the final report finding.

The fix at `src/supervise/scheduler/preclaim.rs:1145-1169` derives the verdict
and all three dimensions directly from `PreclaimDecision`, then preserves the
reason as supplemental context. This is a cause fix because every Park outcome
now exposes typed viability regardless of which environment-sensitive reason
branch selected it. The regression at
`src/supervise/scheduler/decomposition_tests.rs:2176-2221` exercises the
missing-map/risk/runtime path and requires the exact finding plus the persisted
decision and zero claim state. No assertion was weakened, removed, ignored, or
made optional.

## Before/after counts

| Evidence point | Session shape | Result |
| --- | --- | --- |
| Archived CI baseline | Linux CI, no user systemd | 2,501 passed / 2 failed / 15 ignored; both failures were the serial/concurrent authenticated Park finding assertion. |
| Attempt 1, before mutation | DBUS/XDG absent, focused, one test thread | 5 passed / 0 failed / 0 ignored / 2,513 filtered out. |
| Attempt 2, before mutation | DBUS/XDG present, focused, one test thread | 5 passed / 0 failed / 0 ignored / 2,513 filtered out. |
| Attempt 3, before mutation | DBUS/XDG absent, focused, default parallelism | 5 passed / 0 failed / 0 ignored / 2,513 filtered out. |
| Attempt 4, after fix | DBUS/XDG absent, focused, one test thread | 6 passed / 0 failed / 0 ignored / 2,512 filtered out. |
| Attempt 5, after fix | DBUS/XDG present, focused, one test thread | 6 passed / 0 failed / 0 ignored / 2,512 filtered out. |
| Attempt 6, after fix | DBUS/XDG absent, full library | 2,502 passed / 1 failed / 15 ignored; only the unowned `process_runner` test failed. All scheduler/preclaim tests passed. |
| Attempt 10, after fix | DBUS/XDG absent, full library | Exit 124 at 40 minutes; no aggregate. All six owned preclaim tests passed in-stream; two unowned containment-dependent tests emitted `FAILED`. |

The focused count increased from five to six because the missing-evidence
regression is now named with the `preclaim_` prefix and is included in the
mandated filter.

## Exact command ledger and fuse

Owner-local cache roots are redacted in this tracked report. In the commands
below, `<cargo-target>` and `<task-tmp>` denote the fixed lane-specific roots;
the task-local attempt ledger retains the verbatim local commands. Every Rust
command ran through the pinned Nix shell, and every suite was bounded by
`timeout 40m`.

Common prefix:

```sh
export CARGO_TARGET_DIR=<cargo-target> TMPDIR=<task-tmp>
```

1. `timeout 40m env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR nix develop path:$PWD -c cargo test --locked --lib supervise::scheduler::decomposition_tests::preclaim_ -- --test-threads=1` — exit 0; 5 / 0 / 0; 2,513 filtered.
2. `timeout 40m nix develop path:$PWD -c cargo test --locked --lib supervise::scheduler::decomposition_tests::preclaim_ -- --test-threads=1` with the live session variables present — exit 0; 5 / 0 / 0; 2,513 filtered.
3. `timeout 40m env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR nix develop path:$PWD -c cargo test --locked --lib supervise::scheduler::decomposition_tests::preclaim_` — exit 0; 5 / 0 / 0; 2,513 filtered.
4. `timeout 40m env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR nix develop path:$PWD -c cargo test --locked --lib supervise::scheduler::decomposition_tests::preclaim_ -- --test-threads=1` — exit 0; 6 / 0 / 0; 2,512 filtered.
5. `timeout 40m nix develop path:$PWD -c cargo test --locked --lib supervise::scheduler::decomposition_tests::preclaim_ -- --test-threads=1` with the live session variables present — exit 0; 6 / 0 / 0; 2,512 filtered.
6. `timeout 40m env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR nix develop path:$PWD -c cargo test --locked --lib` — exit 101; 2,502 / 1 / 15.
7. `timeout 40m nix develop path:$PWD -c cargo fmt --all -- --check` — exit 0.
8. `timeout 40m nix develop path:$PWD -c cargo check --locked --all-targets` — exit 0.
9. `timeout 40m nix develop path:$PWD -c cargo clippy --locked --all-targets -- -D warnings` — exit 0, no warnings.
10. `timeout 40m env -u DBUS_SESSION_BUS_ADDRESS -u XDG_RUNTIME_DIR nix develop path:$PWD -c cargo test --locked --lib` — exit 124 before aggregate; all six owned preclaim tests observed passing, with two unowned failures already emitted.

Fuse state: **10 of 10 consumed; 0 remain**. Attempt 6's exact transient
runner processes and units had disappeared without manual cleanup before the
single fixed-cause rerun was authorized. Attempt 10 still encountered unowned
containment instability and timed out. No further measurement, retry, or gate
is authorized. Raw logs and SHA-256 values are retained under
`.maco/o2-autopilot/runs/w2-parkfix-c3/tasks/o2-0001/`; they are not added to
tracked history.

## Cross-lane handoff

The owners of Linux process containment and autopilot test isolation should
investigate the following user-systemd-free failures; this lane made no foreign
code change:

- `process_runner::tests::external_codex_outer_sandbox_enforces_control_and_report_write_boundaries` at `src/process_runner/tests.rs:3697`: attempt 6 observed transient process/unit residue beyond its three-second audit deadline while `systemctl --user` could not connect with the session variables absent. The exact residue cleared after suite exit. The same test failed in-stream in attempt 10.
- `autopilot::tests::fake_forge_with_fake_reviewer_is_local_and_non_authoritative`: failed in-stream in attempt 10 on the same user-systemd-free full-suite run. The timeout prevented an aggregate failure body, so the failure is only classified to its unowned containment-dependent path.

These failures block only the requested full-library aggregate acceptance.
They did not fail an owned scheduler/preclaim test, and they were not chased in
the parkfix lane.

## Task and model ledger

All launched orchestrators and leaves used `gpt-5.6-sol`, `xhigh` reasoning,
and `service_tier=default`. The inherited user Codex config exposed
`service_tier="priority"`; that setting was observed and reported, and every
O1/child launch explicitly overrode it with `service_tier="default"`.
Fast/priority service therefore was not retained or used. Terra and Luna were
not used. Native leaf execution did not expose reliable per-agent token or
monetary totals, so execution cost is reported as concrete validation attempts
and review passes rather than invented figures.

| Task / agent | Role and bounded cost | Outcome | Review / rework |
| --- | --- | --- | --- |
| MACO preflight | `.agents/scripts/maco` launch preflight; no model leaf and 0 validation attempts | Environment rejection because `.agents/external/multi-agent-coding-orchestrator/Cargo.toml` was absent. Switched once to the approved Codex O1 fallback; MACO was not repaired in this lane. | Not a model-quality failure. |
| Initial O1 shell composition | O1 fallback launcher construction; no model launch and 0 validation attempts | A missing newline after `set -o pipefail` joined shell tokens, so no model launched and no final or other model evidence was produced. Corrected once and relaunched. | Shell-construction failure, not a model-quality failure; consumed 0/10 fuse. |
| O1 attempt 1 | O1 child orchestrator; instruction/preflight work only, 0 validation attempts | Rejected for orchestration execution: it claimed three active leaves but emitted zero native spawn events and three waits with empty receiver/state evidence, then stopped before source mutation. | Environment/orchestration rejection, not model-quality failure; consumed 0/10 fuse. |
| O1 attempt 2 (`/root`) | O1 child orchestrator; manager-only coordination of six native leaves and the fixed 10-attempt fuse | Corrected dispatch: actual native agents and work were proven live by concrete canonical task names, child processes, and delegated outputs. Its JSON event stream nevertheless repeatedly serialized wait telemetry with `receiver_thread_ids=[]` and `agents_states={}`; that is a telemetry limitation/defect, not evidence that the agents were absent. | Consolidated research, authorized one minimal implementation, accepted independent audit as partial-gate, and withheld DONE. |
| `/root/ci_log_forensics` | RESEARCHER; one read-only CI-log analysis, 0 validation attempts | Recovered the exact 2,501 / 2 / 15 baseline, both failing assertions, and proof that lower-level preclaim behavior passed. | Consolidated by O1; no rework. |
| `/root/scheduler_trace` | RESEARCHER; one read-only owned-source trace, 0 validation attempts | Mapped typed decisions, every Park constructor, persistence, finding conversion, serial/concurrent exits, evidence-sensitive branch, and ordering/authority invariants. | Consolidated by O1; no rework. |
| `/root/reproduce_env` | TERMINAL_WORKER; attempts 1-3 plus task-local ledger | Focused defect did not reproduce in either session shape or CI-shaped default parallelism; proposed and executed only the authorized bounded widening. | Evidence accepted by O1; no rework. |
| `/root/implement_park_finding` | TERMINAL_WORKER; two owned files, attempts 4-10, tool-version capture, and one source commit | Implemented the 14-insertion/5-deletion cause fix and regression; focused and static gates passed; full-library gate remained partial only on unowned failures. Source commit `9152ec51efa61b61c26144579370cde68cdaa273`. | Reviewed independently; no implementation rework. |
| `/root/review_auditor` | REVIEW_AUDITOR; one read-only diff/evidence pass, 0 new validation attempts | `ACCEPT_WITH_PARTIAL_GATE`; no owned-code, scope, privacy, ordering, authority, or production panic-policy finding. | No re-review or rework cycle required. |
| `/root/report_parkfix` | TERMINAL_WORKER; one report-only synthesis and scoped report commit, 0 validation attempts | Produced this VERIFIED/PARTIAL/MISSING report without source, evidence, DONE, or remote mutation. | Parent O1 retains final acceptance; no rework in this lane. |
| `/root/report_correction` | TERMINAL_WORKER; Sol, `xhigh`, default tier; one nondelegating report-only correction, 0 validation attempts | Accepted subject to root read-only audit. This single direct-O2 leaf exception was justified by the tiny bounded report-only scope and the greater cost of O1 wrapping; it changed no source, evidence, DONE marker, or remote state. | Root performs the final read-only audit; no validation or fuse use. |

Total measurable execution cost was 10 validation attempts: six test-suite
invocations and three static gates plus the final full-library invocation as
enumerated above. The mandatory independent review cost was one read-only
auditor pass. There were no worker rework or auditor re-review cycles.
