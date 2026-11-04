This is an offline JSON-lines app-server peer for the authored nested Worker
controller tests. It performs local source edits, records the actual command and
timestamps in the precreated Worker journal, and supplies deterministic model
and usage messages. It never contacts a provider or launches another agent.

The test-only Rust runner replaces provider executable and account preflight.
It uses the production app-server driver, authenticated request endpoint,
ExternalCodex containment profile, descriptor capture, journal capture, budget
settlement, frozen-yield controller and final parent collection. Real process
containment evidence is required; Python is not admitted as a production Codex
executable. The active cancellation case starts an ordinary sleeping descendant
to exercise cancellation and process-tree drain.

The authored fixture plan is validated and gives the two Workers disjoint source
paths. The initial parent has the Worker request tool and read-only source; the
final parent has read-only source and no request tool or Worker journal capability.
Both coordination turns attempt a source write and require the outer sandbox to
reject it. The receipt replay case discards an acknowledgment at the peer and
resubmits the same request; separate IPC tests cover a dropped socket response.

These tests stop at final parent collection. They do not qualify provider
executable preflight, independent review-lens dispatch, or crash recovery launches.

The isolated cases bind an ordered combined candidate before the final parent
turn. The final peer reads both edits, compiles their actual Rust functions in
private temporary storage, and runs a combined assertion returning 42. Source
writes still fail under the outer sandbox. Rejection restores the held base
without materializing commits; post-capture drift retains authority for recovery.
Overlapping candidate edits refuse before a final parent can run. The same
cases use explicit Worker token limits and the production host-held invocation
receipt to check terminal claim bookkeeping and warnings against distinct,
verified Worker budget settlements (including missing and unverified negatives).

The final peer receives the absolute compiler in a read-only projection of the
selected sysroot, resolved before containment. User-home rustup shims are hidden
by `ProtectHome=tmpfs` on hosted runners; Nix store executables remain visible.
The masked-shim regression reproduces that distinction inside the real sandbox.
Compiler failures include captured stderr. No timing or quiescence gate is relaxed.
Collector-side rejection of a successful report with self-authored gate denials
must also restore the base and leave both Worker HEADs untouched. Serial cases
retain the exact dispatch sequence; isolated cases require the exact Worker set.

A successful final report that omits its changed paths must use acceptance's
supervisor-corrected path set before the terminal handoff. Real private Git index
locks exercise partial Worker materialization failure and a later parent import
rejection: both retain sibling leases, captures, the frozen source and the parent
union claim for supervisor recovery. No rollback drops an advanced private ref.
