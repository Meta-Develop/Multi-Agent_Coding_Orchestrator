# Nested writable token-control qualification (#714)

Status: prepared; real within-turn exhaustion is unproven. Follow the
[shared preparation and evidence contract](README.md) before running.
The [fixture](../../examples/supervise/nested-codex-budget-qualification.json)
has one execution parent and exactly two disjoint terminal Workers, requested
serially, on `gpt-6.1-sol` / `high` for both the delegating parent and terminal
Workers; independent control/review roles retain `xhigh`.
The bundled task/authority priors admit `high` and `xhigh` for these localized
changes. The original `medium` requests failed selection before release.
Native runtime delegation is prohibited; nested dispatch goes through
the authenticated coordinator channel. No retries or gate corrections are
authorized by the fixture.

The revised finite ceiling is 65,000 run tokens, with admission estimates of 4,000 for
the parent/reviewer and 1,000 per Worker. Each child has a 1,200-second timeout;
the outer command has a 3,600-second deadline. Estimates do not bound actual
consumption and the Worker live grant is the remaining admitted allowance,
not its 1,000-token estimate. The meaningful task repairs two deliberately
flawed Python test fixtures with disjoint ownership. It does not pad output
or request unlimited turns to force usage.

The retained `qualification-nested-budget-c31` attempt on
`f16ed38fcab1eb37ac7ee6c1b7a3aeff4fc09fe2` is **inconclusive**. Its original
32,000-token plan admitted the real parent on `gpt-6.1-sol` / `high`, which
settled 41,684 tokens before either Worker launched: 41,495 input and 189
output. The 27,264 cached input tokens are included in input, not added again.
The parent exceeded that ceiling by 9,684; both Worker preparations were
refused, so no within-turn Worker interruption or drain was exercised.
Preserve that original checked plan, fixture, usage receipts and retained run
alongside the revised checked plan and its evidence; do not rewrite c31's result.

The revised ceiling budgets 1.5 times observed parent usage:
`41,684 * 3 / 2 = 62,526`, plus a 2,474-token remaining grant, totaling 65,000.
This leaves 23,316 tokens of headroom over the observed parent usage (20,842
for setup variation plus 2,474 for Worker 1). With no other outstanding
reservations, parent usage of 41,684 leaves Worker 1 a live grant of 23,316;
usage of 62,526 leaves 2,474. Both admit its unchanged 1,000-token estimate.
The parent estimate remains 4,000: it is an admission estimate, not a cap on
the parent's turn. No task, effort, gate, timeout or retry setting changes.

Even the larger 23,316-token grant is less than one eighth of the original
incident Worker's 191,231-token usage. This makes Worker 1 reaching the grant
during its native turn plausible with substantial margin, while allowing
50% parent setup growth. It is not a usage prediction or guarantee: setup can
vary, Worker 1 can finish cheaply, and cumulative usage notices can arrive
late or overshoot. After Worker 1 reaches its actual grant, observed exhaustion
must stop dispatch and Worker 2 must be refused; capture that refusal in the
same run. Parent-first exhaustion or failure to reach Worker exhaustion remains
inconclusive. This fixture revision prepares a separately reviewable plan;
it does not authorize another live attempt or establish qualification.

```bash
fixture=examples/supervise/nested-codex-budget-qualification.json
run_id=qualification-nested-budget-01
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
- Independent review of actual fixture changes and command observations,
  expected rejection of incomplete output, complete accounted usage, and exact
  owned child/cgroup quiescence. Timeout or process cancellation alone is not
  token-control qualification.

Both assigned files are recognized runnable test targets, so preflight does not
depend on a new generic authored-check capability. The independent reviewer
must run these commands against the actual candidate and verify existing test
bodies were preserved (a Worker can otherwise weaken its own test):

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
