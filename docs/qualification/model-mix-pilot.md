# Bounded model-mix pilot

This is an ordinary-task observation pilot for #631, with three requested arms:
all `gpt-6.1-sol`; Sol control/review with a `grok-4.6` Worker; and the same
control/review with a `grok-4.7` Worker. Every role requests `xhigh` and
`fail_closed`. Each cell starts from the same isolated source commit and task,
with the same held-out ledger checks and three default review information
scopes (full transcript, output only, diff only). Sessions are fresh; there is
one Worker/provider in flight, no retries or gate corrections, a 1,200-second
child timeout, a 3,600-second cell deadline, and a 160,000-token hard ledger
limit including review overhead. Reservations are positive. The default is
one repetition: three cells, at most 480,000 ledger tokens. A larger repetition
count requires a separately approved manifest; budget exhaustion is a retained
failure, with no automatic larger rerun. This fixture does not cover a separate
design/review task stratum or qualify production/default selection.

The substantive task repairs the committed ledger fixture's admission,
monotonic observation and idempotent settlement behavior while preserving its
tests. The caller plan is
[`model-mix-pilot-plan.json`](../../examples/supervise/model-mix-pilot-plan.json);
the comparison declaration is
[`model-mix-pilot-manifest.json`](../../examples/supervise/model-mix-pilot-manifest.json).
The manifest's `worker_runtime` is an intervention on the single direct Worker,
never a change to the parent runtime or a nested-worker grant. Omission preserves
legacy model-only observation. Runtime-bound arms must explicitly declare
model, effort and fail-closed selection for all six roles. Partial bindings,
differing role sets, Fake,
nested assignments and runtime bindings missing from the executable allowlist
are rejected. All effective plans are checked before any artifact reservation
or paid cell. Only role models and the explicit Worker runtime can differ.

With the accepted executable and this checkout, validate offline:

```bash
"$maco" evaluation experiment examples/supervise/model-mix-pilot-manifest.json \
  --validate-only --provider-plan examples/supervise/model-mix-pilot-plan.json --json
```

This command calls no provider, needs no account, creates no run and establishes
only declaration comparability. It emits manifest, original caller-plan,
common-plan and per-profile effective-plan SHA256 hashes. The live comparison
hash also binds the resolved source commit/tree and frozen runtime executable
allowlist. Per-cell evidence retains the manifest/profile digest, original and
effective plan, requested runtime/model/effort for every declared role and
explicitly unknown observed model/effort when unavailable. Catalog resolution,
requested effort and usage labels are insufficient provider identity evidence.
Observed model and effort are projected per role only from authenticated,
dispatch-bound native evidence after the cell's finalized artifacts and live
report are verified, and only when every retained dispatch for that role
agrees. Codex app-server and exec runs can supply both fields. Grok, Claude and
Gemini supply only their native model, so their effort stays unknown; Cursor
supplies neither. Missing, mismatched or tampered evidence stays unknown and
later paid cells are withheld.

Prepare live inputs under the [shared prerequisites](README.md). Copy the caller
plan outside the evaluated repository. Complete the existing
[`operator-pricing.template.json`](../../examples/supervise/operator-pricing.template.json)
mechanism in that operator-owned plan's top-level pricing fields: exact account/model/plan
scopes for both runtimes, contract id/revision/effective/expiry/source and a
normalized price-map digest. The fixture contains no price or price contract.
The applicable contract is an operator input; do not substitute public API
list prices or serialized zero cost. Keep provider-reported USD, contract cost
equivalents and Build allowance consumption distinct. Quota conversion and
unavailable reasoning counts stay unknown; reasoning included in output must
not be charged twice. Preserve the completed pricing contract unchanged across
arms. Freeze dated admissible priors/capability evidence for Sol, standard 4.6
and standard 4.7 at xhigh in the source repository, and use its exact commit.

After those gates and explicit paid-run approval, the exact live command is:

```bash
env MACO_GROK_BIN="$grok" MACO_GROK_INTERACTION_PROTOCOL=headless_streaming_json \
  "$maco" evaluation experiment "$manifest" \
  --execute-held-out --execution real-provider --allow-real-provider \
  --source-repo "$repo" --base-commit "$source_commit" \
  --provider-plan "$plan_outside_source" --runtime codex --runtime-bin "$codex" \
  --additional-runtime-bin "grok=$grok" --prior-data "$prior" \
  --machine-global-config "$config" --machine-global-runtime-root-id runtime \
  --repo "$artifact_owner" --json
```

`$manifest` is the reviewed pilot manifest; `$source_commit` is the canonical
40-character commit containing the source fixture and operator priors, and
`$prior` is its repository-relative prior-data path. Record the accepted
executable identity separately from this source snapshot. No live call is
authorized by offline validation. Runtime admission, selected account/capacity,
confinement and served identity are separate gates.

A failed or unmeasured cell withholds all later paid cells; withheld cells are
retained as explicit failures so the report cannot claim a complete comparison.
Unknown per-role identity currently triggers this stop even if execution
succeeds. Do not launch the remaining arms separately to circumvent it.
Preserve usage, failures/rework, churn, wall time, held-out results, all review
lenses, pricing provenance and independent acceptance per cell. Compare complete
accepted-task cost including review and failure overhead. The existing summary
and Pareto remain observations only. `production_eligible`,
`eligible_for_production_economics` and `eligible_to_justify_named_default` stay
false, including when every external measurement eventually becomes available.
