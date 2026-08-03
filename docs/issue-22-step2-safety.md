# Issue 22 step 2 recursion safety argument

The source supervisor report and its Issue #9 event journal are immutable once
finalized. That source journal records generation of the exact licensed
follow-up tasks. A separate authenticated durable queue records command-level
lifecycle transitions, while each subordinate ordinary supervisor run owns its
own Issue #9 journal and checkpoints. Queue evidence therefore does not rewrite
or masquerade as source-journal evidence.

## 1. What bounds the number of rounds, and what happens at the bound?

The command permits exactly the source round plus one generated follow-up
batch. Every generated plan carries the fixed cascade depth, and evidence that
the generated batch produced another licensed follow-up is retained but cannot
start a third round: it produces the established typed
`approval_review`/`permission_expansion` refusal. The refusal is terminal queue
evidence, not an invitation to dispatch outside the command.

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
A staged batch is completed idempotently; a pre-start claim can be released;
and a finalized subordinate is authenticated and acknowledged without
re-execution. An active or ambiguous started subordinate is held rather than
silently returned to pending, while a typed gate refusal is recorded as a
terminal outcome. Direct `supervise run` can resume the same command and run ID
from its authenticated finalized source artifacts, so it does not rerun the
source round. Autopilot outer-artifact interruption has no safe same-command
resume because there is no authenticated outer resume binding, and this design
does not claim one.

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
