# Issue 22 step 2 recursion safety argument

The source supervisor report and its Issue #9 event journal are immutable once
finalized. That source journal records generation of the exact licensed
follow-up tasks. A separate authenticated durable queue records command-level
lifecycle transitions, while each subordinate ordinary supervisor run owns its
own Issue #9 journal and checkpoints. Queue evidence therefore does not rewrite
or masquerade as source-journal evidence.

## 1. What bounds the number of rounds, and what happens at the bound?

The command permits exactly the source round plus one generated follow-up
batch. Every generated plan carries the fixed cascade depth. If an
authenticated terminal report from that generated batch contains further
follow-up tasks, those tasks are retained as report evidence but are never
admitted to this queue or another queue. The cascade outcome carries the
established typed `approval_review`/`permission_expansion` refusal, while the
subordinate queue item is terminal. The typed refusal is not misrepresented as
a queue event or an invitation to dispatch outside the command.

## 2. What bounds the work per round when a round can generate more follow-ups than it consumes?

The source plan is validated against its existing assignment limit, and queue
admission accepts only the exact declared licensed dependents. Each generated
plan contains exactly one ordinary assignment and uses Issue #20's existing
`derived_generated_follow_up_budget`; the queue does not invent or substitute a
second execution budget. Its fixed storage-admission limit bounds durable queue
material only and is not an execution-budget concept.

## 3. How does failure, gate refusal, or interruption leave resumable work without loss or silent rerun?

The durable lifecycle distinguishes a fully staged batch, a claimed item that
has not started, a dispatch-start checkpoint, and a finalized subordinate run.
A staged batch is completed idempotently. A pre-dispatch profile, primary, or
retention-identity refusal records its typed denial and releases the claimed
item to `Enqueued`; an unreadable retention configuration instead uses the
established typed `EnvironmentFailure` category `probe_failed`, journals that
failure on the same release, and is equally retryable. An explicit invocation
of the same run ID can retry after the operator corrects the refused condition.
After dispatch starts, a finalized subordinate outcome is not enough by itself.
The one observation-and-acknowledgement transition first authenticates the
persisted final report, compares that report with the returned or reconciled
report, and compares the complete authenticated persisted
`LoadedSupervisorPlan` with the immutable queued generated plan. Only that
structural plan/report match can record an observation, acknowledge the item, or
contribute child-start evidence. The queue's raw observation and acknowledgement
reducers are private, so the compiler rejects direct sibling cascade calls. Its only
crate-visible terminal transition consumes an opaque, non-cloneable capability
bound to the queue instance and item; the sibling queue module cannot construct
that capability, and the cascade constructs it only after the authenticated
report-byte and exact immutable queued-plan comparisons. A mismatched
`DispatchStarted` item becomes
`HeldAmbiguous` with the established typed permission-expansion refusal; an
already unresolved mismatch remains nonterminal. Direct successful returns,
immediate-error reconciliation, and later reconciliation share this transition,
so none has an unverified acknowledgement bypass. A newly observed failure
stops sibling admission for that invocation; a later explicit invocation of the
same run ID may continue remaining pending items but never reruns the
acknowledged item. A
status-classified `Active` subordinate with its live bound run lock remains
`DispatchStarted`. Only an authenticated `Interrupted` or `Uncertain`
subordinate becomes `HeldAmbiguous` and requires reconciliation rather than
silently returning to pending. Once that exact subordinate later has an
authenticated finalized report, a subsequent invocation first compares the
subordinate artifact's complete authenticated `LoadedSupervisorPlan` with the
immutable queued generated plan, then observes and acknowledges it without
dispatching it again. A same-ID subordinate with a different plan stays held
and takes a typed permission-expansion refusal. If the outer Autopilot call
fails after a durable start marker, dispatch evidence reuses Issue #34's
`RoleUsageObservation` vocabulary instead of defining a lookalike uncertainty
enum. A structurally valid authenticated subordinate child-start checkpoint
maps to `SupervisorAggregate`; marker-only, unreadable, or otherwise incomplete
evidence maps to the canonical `NotProcessObservable`. Autopilot reports `true`
only for `SupervisorAggregate`; every unknown or other observation fails closed
rather than finalizing a false execution claim. Checkpoint MAC authentication
alone is not semantic execution evidence: the ordinary supervise checkpoint
analyzer must first accept the complete prepared binding, typed transitions,
and lifecycle ordering before a `child_dispatch_started` phase can be counted.
For child dispatch specifically, that exact assignment must have a preceding
`assignment_started` transition and still be in `Started`: an unknown assignment
or a prepared-but-pending assignment yields no dispatch evidence, while malformed
records and a dispatch recorded after assignment completion remain structural
errors.
Direct `supervise run` can resume the same command and run ID from its
authenticated finalized source artifacts, so it does not rerun the source
round. It can also recover an Autopilot-origin queue by presenting that exact
authenticated source run, normalized plan, primary baseline, and retention
binding: the queue slot is derived from those execution-basis fields, while the
original Autopilot entrypoint and outer run ID remain immutable provenance.
Autopilot outer-artifact interruption still has no safe same-command
outer-artifact resume binding, and this design does not claim one.

## 4. What stops a follow-up task from regenerating itself indefinitely?

Every generated assignment has `licensed_breakage: None`, and the complete
generated document is reloaded through the full ordinary plan loader before
dispatch. Stable source, queue, batch, item, and subordinate run identifiers
make replay observable and deduplicated. Exact declared-dependent binding plus
the fixed cascade depth prevents a generated task from licensing itself or
opening another execution round; any third-round evidence takes the typed
permission-expansion refusal described above.

Automatic merge and apply remain absent. Generated work stays isolated behind
ordinary supervise gates; publication, arbitration, merge preview, and merge
apply remain separate human-directed commands.
