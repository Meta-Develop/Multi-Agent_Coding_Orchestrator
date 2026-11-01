# Nested writable token-control qualification (#714)

Status: implementation prepared; a new real contained attempt is still required.
Preserve `qualification-nested-budget-ct101-01`, `-03`, AUD714 and the earlier failure records.
Follow the [shared evidence contract](README.md); never run in the owner desktop
or an occupied checkout. The [fixture](../../examples/supervise/nested-codex-budget-qualification.json)
uses two execution parents, three terminal Workers, and effective width one.
Both parents and Workers use `gpt-6.1-sol/high`; independent review retains
`xhigh` and the three default review lenses. No retries or gate corrections.

The first parent dispatches only `admission-worker`. Its meaningful repair of
`test_admission.py` must pass independent unittest execution and parent/Auditor
acceptance before the second parent runs. The fixture's explicit
`assignment_schedule` makes the second parent depend on the first: the scheduler
waits for the first outcome and suppresses stage two when that outcome fails.
The parent reports technical completion using only its own checks; unavailable
future Auditor acceptance is never a validation prerequisite. In the current
report protocol, `status=succeeded, accepted=true, rejected=false` means provisional
technical success; only MACO's subsequent independent review can accept it.
Actual technical or evidence failures remain failed, including after a positive
Auditor verdict. The second parent queues
`settlement-worker` and `refusal-worker`; the former starts the real settlement
repair with a deliberately small observation threshold, and the latter is
refused after exhaustion. The whole run is expected to be rejected even though
the first stage produced an accepted candidate. Preserve the first stage's
acceptance separately from final run acceptance; never publish the failed run.

The CT101 harness must assert **hard_tokens = 650000** (previously 65000).
Admission estimates remain 4000 per parent/Auditor and 1000 per Worker.
`worker_live_token_limits` explicitly bounds the granted allowance to 240000
for `admission-worker` and 1000 for each second-stage Worker. These are
within-turn observation thresholds, not provider-call spending guarantees.
The allocator grants the smaller of the requested threshold and available
hard balance; it never enlarges an issued grant or overlaps reservations.
A required threshold on an unsupported runtime/route is refused before release.
Each child retains a 1200-second timeout; the outer deadline remains 3600 seconds.

Arithmetic is based on the -01 trace: parent usage was 43233, then Worker
cumulative notices were 19325 and 39121 before any edit. The old grant was
65000 - 43233 = 21767, so the second notice interrupted seed inspection.
The new first-Worker threshold is 240000: 200879 beyond that pre-edit floor,
and 48769 beyond the original incident Worker's 191231 terminal total.
The old uniform 65000-token coordinator/reviewer allowance is invalidated by
-03's **168672-token continuation**. Reassessing the whole envelope uses -03's
measured first parent 27942, continuation 168672 and three Auditors
92786 + 20689 + 15039 = **325128** total coordinator/reviewer tokens.
Add the full 240000 first-Worker allowance and a 65000 planning allowance for
the still-unmeasured second parent: **630128**. Including a replay of the
19325-token crossing notice gives **649453**, leaving only **547** below
**q714 = 650000**, which is unchanged. The previous whole-run envelope was only
128 tokens lower before the crossing notice; raising the ceiling is not required
by this arithmetic. The narrow margin and possible later drain notices make this
a finite planning assumption, not a spending guarantee or assurance of success.
Unused allowance is released on settlement; no retry or automatic increase follows.

The second-Worker threshold remains 1000 regardless of how cheaply stage one
finishes. A replay of its first observed 19325-token notice would immediately
cross 1000; later trustworthy drain notices still increase its settled floor.
The 1000-token estimate is unchanged and is distinct from the live grant.
`live_token_grant_exhausted` latches the run stop even if the aggregate ceiling has spare room,
so the queued third Worker receives a real typed refusal. No output padding,
spending target, or intentional infinite loop is needed. Provider notices and
usage can vary: early first-stage exhaustion, failed review, no crossing notice,
or timeout without observed exhaustion makes the attempt inconclusive.
Do not automatically retry or change the ceiling.

Before each eligible Worker provider release, `budget/dispatch-N.admitted.json` and the authenticated
`live_budget_admitted` checkpoint bind grant ID/amount, exact reservation,
run/assignment/parent/attempt, runtime, command digest, non-secret selected
account authority/provider/account/incarnation/revision, and admission balances.
`run_budget.dispatch_bindings` in collect/final reports retains that identity
and adds the host-authenticated thread/turn and exactly one charge. The
`*.settled.json` receipt and checkpoint are written before fallible completion
acceptance. The receipt records the actual non-secret account route honestly;
`local_auth` is accepted. Selected-account binding is supported but is not
required for this qualification. Thread and
turn IDs do not exist at admission and are reconciled from the trusted runner,
never from Worker JSON. A restored public report cannot supply live authority.

Admission checkpoints also retain the complete budget snapshot and reservation.
If the process dies before usage arrives, `supervise resume` journals one
`live_budget_recovered` disposition at the existing reservation estimate floor,
marks usage incomplete, and keeps dispatch blocked; repeated resume does not
charge again. Collect exposes the authenticated budget before and after that
reconciliation. Failed admission writes distinguish an unpublished binding
from a published admission. If release was withheld, scheduler closure retains
its `not_started` disposition; a crash before closure remains conservative. Command receipts hash the launch seal, including input
lists, bounded input content/file identities, source declarations and confinement.
Each private Worker `command.json` retains `command_seal_snapshot`, the exact
non-secret version-2 hash preimage (including redacted confinement, input receipts,
route flags and grant ID). Recompute SHA256 over its compact UTF-8 JSON encoding
with sorted keys (`ensure_ascii=False`, separators `(',', ':')` in Python) and
compare with the admission receipt's `command_sha256`. No credential contents are
included. A `local_auth` route must not be relabelled as a selected account.

```bash
fixture=examples/supervise/nested-codex-budget-qualification.json
run_id=qualification-nested-budget-ct101-02
sha256sum "$fixture" > "$OUT/fixture-sha256.txt"
"$maco" supervise plan "$fixture" --repo "$repo" --json > "$OUT/checked-plan.json" || exit 1
if timeout --signal=TERM --kill-after=30s 3600 systemd-run --user --scope --quiet -p Delegate=yes \
  --working-directory="$repo" -- "$maco" supervise run "$fixture" \
  --runtime codex --repo "$repo" --run-id "$run_id" --codex-bin codex \
  --max-concurrent-children 1 --provider-inflight-limit 1 \
  --machine-global-config "$config" --machine-global-runtime-root-id runtime --json \
  > "$OUT/run.json" 2> "$OUT/run.stderr"; then rc=0; else rc=$?; fi
printf '%s\n' "$rc" > "$OUT/run.exit"
if "$maco" supervise collect "$run_id" --repo "$repo" --json \
  > "$OUT/collect.json" 2> "$OUT/collect.stderr"; then rc=0; else rc=$?; fi
printf '%s\n' "$rc" > "$OUT/collect.exit"
```

Use a fresh run id and evidence directory for an explicitly authorized rerun.
A single run cannot guarantee exhaustion at the desired stage. If the parent
exhausts first, a Worker never launches, both Workers finish below the ceiling,
or the timeout fires without token exhaustion, record **inconclusive**, not pass.
Do not automatically retry, raise the ceiling or weaken admission. The operator
can prepare a separately reviewed finite ceiling from observed setup/Worker
usage if another run is authorized, preserving both plans and their evidence.

Acceptance requires all of the following, cross-linked by exact run, assignment,
attempt, reservation, account, thread and turn identities:

- Actual native writable sandbox, disjoint path claims, source/executable
  identity, authenticated serial dispatch, journal and schema bindings.
- Before each Worker, settled usage, outstanding reservations, estimate and
  exact remaining live grant. Capture multiple within-turn cumulative usage
  notices correlated to that Worker's thread/turn; unrelated notices are excluded.
- An observed notice reaches or exceeds the live grant, triggers interrupt,
  and receives a terminal completion/drain acknowledgement. Retain every later
  trustworthy drain observation; final settlement must include the largest
  trustworthy cumulative floor and must not sum cumulative notices.
- One settlement for the exact reservation, including rejected/partial output;
  zero residual reservations and no additional provider dispatch after observed
  exhaustion. A refused subsequent dispatch/reservation must be visible in the
  production journal; do not launch a separate paid probe to manufacture it.
- Independent review of the actual retained candidate and command observations,
  expected rejection of incomplete output, honest usage accounting as described
  below, and exact owned child/cgroup quiescence. Timeout or process cancellation
  alone is not token-control qualification. Native source mutation must still
  be observed to prove the writable sandbox's edit confinement; an unchanged
  candidate does not establish that part of acceptance.

The first retained Linux container attempt observed Worker 1's
19,325 then 39,121 cumulative tokens against a 21,767-token live grant. The
interrupted terminal arrived 10 ms after the crossing notice, with no later
usage notice. Worker 2 received a typed admission refusal without dispatch;
both reservations settled and none remained. The 43,233-token parent charge
plus the Worker's 39,121-token floor gives 82,354 accounted tokens, **a lower
bound**, with Worker and run `usage_complete=false`. The reliable usage
aggregate excludes that incomplete Worker sample. These observations prove
the stop/refusal behavior, not complete final consumption or full acceptance.

For an interrupted turn, retain the largest trustworthy correlated cumulative
observation through the bounded drain, charge it once as incomplete, and retain
the missing-usage flag. An interrupted terminal acknowledges stopping; it does
not certify the last cumulative notice as final usage. Codex 0.162.0 supplied
no final usage certification in this attempt. Neither another identical notice
nor a successful interrupt response would establish completeness. Complete
actual consumption remains unknown unless the provider supplies a trustworthy
final usage observation with explicit finality for that exact interrupted turn.
Do not infer zero unobserved consumption, label the floor complete, or relax
dispatch/publication gates. Stop/refusal qualification can use this explicitly
incomplete lower bound; any claim of complete actual usage remains unproven
until that separate provider observation exists.

After verified writer quiescence, isolated Worker collection retains the
runner-held journals, raw response and native stream before report parsing or
cancellation rejection. A private `*.candidate.json` manifest beside the raw
response binds the run, parent/Worker attempt, exact reservation, source commit,
candidate tree, changed paths, and the SHA256/size of a binary `*.candidate.patch`.
These artifacts carry no acceptance or continuation authority. Evidence-import
or candidate-capture failure remains a rejection and must be reported; it cannot
be replaced with a claimed successful review.

The shared-parent review handoff also retains `reports/<parent>.candidate.json`
and its binary `.candidate.patch` before Auditor launch, even when the parent
reports failure. The packet binds parent and Worker validation observations to
that held candidate and supplies separately bounded, redacted excerpts of each
authenticated original Worker journal and native transcript with their complete
byte counts and SHA256 identities. Post-review recapture must match the held
candidate. Evidence retention cannot turn a failed report into an accepted one.

Both assigned files are recognized runnable test targets, so preflight does not
depend on a new generic authored-check capability. The independent reviewer
must reconstruct each retained candidate in a separate checkout of the manifest's
exact source commit, apply its binary patch, verify the resulting tree matches
`candidate_tree`, and run these commands there. An empty patch denotes the
unchanged base; still verify its tree and run the checks. Verify existing test
bodies were preserved (a Worker can otherwise weaken its own test). For interrupted output,
review and reject the actual partial or unchanged candidate, retain command exit
codes/stdout/stderr with its manifest binding, and report failing seed tests as
failures. Do not substitute tests on the original seed or the parent checkout
for a changed Worker's candidate. This review is an independent offline step
after quiescence; exhaustion authorizes no further provider review call:

```bash
python3 -B -m unittest discover -s examples/supervise/qualification-data -p test_admission.py -v
python3 -B -m unittest discover -s examples/supervise/qualification-data -p test_settlement.py -v
git diff --check
```

Admission must reject `(100, 0, 60, 60)` and accept `(100, 20, 30, 50)`;
cumulative notices `20,35,35,40` settle at 40, retaining 40 after a stale 35.
Report-persistence failure must still leave consumed=40, no active A, and
settled[A]=40. Identical replay changes nothing; conflicting replay refuses.
Unknown usage raises before effects. Both seeds intentionally fail before repair.

The original failure on `e66870bdd507fd4f732719ba0679e69e90ec277d` remains:
220,000 ceiling; 137,035 settled before Worker two; 82,965 remaining;
16,000 reservation; 191,231 terminal Worker usage; 328,266 total (108,266 over).
It was delayed observation, not duplicate settlement. Preserve that evidence.
The correction interrupts **after an observed usage notice**; it does not prove
a hard provider-call spending limit, a monetary bound, or an absence of overshoot.

Before live work, reuse the exact `managed_worker_live_budget` exhaustion/drain
and changed/stopped/released-grant regressions, plus
`nested_worker_final_live_budget_preserves_shortened_timeout_none_and_failed_report_floor`
in the admitted Linux environment. Providerless tests do not satisfy this gate.
Keep #692 settlement-order evidence separate. Closure requires the real
exhaustion evidence above and independent acceptance, not fixture preparation.

Before accepting a fresh attempt, map every target, version probe, catalog probe
and journal helper to its owner and typed containment/quiescence receipt. An
empty process-group watchdog alone does not certify all helpers. The old -01
run lacks that complete mapping and has no accepted candidate; preserve it as
positive stop/refusal evidence with those explicit limits. Preparation and
providerless regressions do not close the real-qualification criterion.

MACO retains `logs/catalog.helper-inventory.json` for its local Codex catalog
process, including a failed catalog return, and a `*.helper-inventory.json`
beside each private command summary for its target and fixed version probe.
Each inventory identifies the run/owner/attempt and embeds the typed process
tree and side-effect receipts. A missing receipt refuses collection; an
unverified receipt is retained as unverified and cannot establish quiescence.
These are historical diagnostics, never restored launch or cleanup authority.

This inventory covers direct MACO catalog, version-probe and target launches.
Provider-spawned journal wrappers and their commands remain inside the target's
owned process boundary, but MACO does not observe each wrapper launch separately
(including one that fails before appending a journal record). It therefore does
not claim a complete per-wrapper inventory. CAM service internals and the
operator's build/launcher/watchdog processes are also outside this supervisor's
spawn scope. A fresh qualification must retain separate ownership evidence for
those helpers before claiming the complete qualification contract above. Existing
live evidence is unchanged and is not retroactively upgraded by these receipts.
