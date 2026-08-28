# Parkfix2 process-runner cleanup lane

## Role and scope

- Role: terminal worker under O1 child orchestrator `/root` for autonomous O2 `o2-0002`, run `w2-parkfix2-0828224122-1`.
- Current worker scope: create this report and perform exactly one safe pre-mutation focused reproduction; no source mutation.
- Owned write path: `.maco/wave2/reports/parkfix2-cleanup.md` only.
- Preserved pre-existing state: `.maco/wave2/reports/parkfix.md` was already modified and is unrelated.

## Validation and measurement fuse

This fresh fuse was written durably before the first focused reproduction.

- Immutable total: **12 attempts**.
- Initial usage before any reproduction or gate: **0/12 used; 12 remaining**.
- The total will not be reset, extended, or weakened. Exhaustion leaves unmet gates failed or blocked.
- Every launched pre-mutation reproduction, timeout, abort, failed precondition, post-change focused run, formatting check, locked check, locked clippy, portability run, full-library run, and reserve use consumes one attempt from this same total regardless of outcome.

Planned allocation:

1. Pre-mutation exact focused reproduction.
2. Post-change exact focused test.
3. Post-change no-DBUS/XDG exact focused test.
4. `cargo fmt --all -- --check`.
5. `cargo check --locked --all-targets`.
6. `cargo clippy --locked --all-targets -- -D warnings`.
7. Repository portability check.
8. `cargo test --locked --lib`.
9. Pooled fixed-cause reserve 1.
10. Pooled fixed-cause reserve 2.
11. Pooled fixed-cause reserve 3.
12. Pooled fixed-cause reserve 4.

Attempt ledger before reproduction: no attempts launched; usage **0/12**.

Current fuse usage after attempt 1: **1/12 used; 11 remaining**.

## Worker/model outcome ledger

| Field | Evidence |
|---|---|
| Task class | Safe pre-mutation containment-lifecycle reproduction and durable evidence capture |
| Role/boundedness | Non-delegating native terminal worker; exact one-report write scope and one focused test command |
| Risk | Low mutation risk, but medium-risk containment/failure evidence |
| Context/horizon | Bounded single-test lifecycle observation; short horizon |
| Acceptance role | Evidence producer only; parent O1 and later independent review retain acceptance authority |
| Selected runtime | `gpt-5.6-sol`, reasoning effort `xhigh`, `service_tier=default` inherited; no Fast/priority |
| Selection basis | No exact lower-cost accepted-task evidence; Sol is supported; Luna is ineligible/unavailable for MultiAgent V2 spawning; Terra is prohibited |
| Execution/review cost | One fused focused-test attempt; parent review remains required |
| Rework/re-review | None before reproduction |
| Outcome/failure class | Accepted evidence capture; focused failure did not reproduce before mutation, which is evidence rather than proof of absence |

## Pre-mutation focused reproduction

Attempt 1 command (launched exactly once):

```text
timeout 600s nix develop path:$PWD -c env CARGO_TARGET_DIR=/native/local/cache/cargo-targets/w2-parkfix2-cleanup TMPDIR=/native/local/tmp/w2-parkfix2-cleanup cargo test --locked --lib process_runner::tests::external_codex_outer_sandbox_enforces_control_and_report_write_boundaries -- --exact --nocapture --test-threads=1
```

- Result: exit `0`; the focused failure did **not** reproduce before mutation.
- Counts: `1 passed; 0 failed; 0 ignored; 0 measured; 2517 filtered out`.
- Test runtime: `0.78s`; fresh-target build completed in `2m 24s`.
- Exact test: `process_runner::tests::external_codex_outer_sandbox_enforces_control_and_report_write_boundaries ... ok`.
- Containment observation: the test output emitted no transient unit name and no process identifier. Therefore no own-unit follow-up observation was possible or performed; no process or unit was controlled.
- Interpretation boundary: this pass is non-reproduction evidence only. It does not disprove the previously observed cleanup/observation race and does not authorize speculative mutation or blind repetition.
- Fuse after result: **1/12 used; 11 remaining**.
