# Nested writable token-control qualification (#714)

Status: prepared; real within-turn exhaustion is unproven. Follow the
[shared preparation and evidence contract](README.md) before running.
The [fixture](../../examples/supervise/nested-codex-budget-qualification.json)
has one execution parent and exactly two disjoint terminal Workers, requested
serially, on `gpt-6.1-sol` / `medium`; independent control/review roles retain
`xhigh`. Native runtime delegation is prohibited; nested dispatch goes through
the authenticated coordinator channel. No retries or gate corrections are
authorized by the fixture.

The finite ceiling is 32,000 run tokens, with admission estimates of 4,000 for
the parent/reviewer and 1,000 per Worker. Each child has a 1,200-second timeout;
the outer command has a 3,600-second deadline. Estimates do not bound actual
consumption and the Worker live grant is the remaining admitted allowance,
not its 1,000-token estimate. The meaningful task repairs two deliberately
flawed Python test fixtures with disjoint ownership. It does not pad output
or request unlimited turns to force usage.

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
