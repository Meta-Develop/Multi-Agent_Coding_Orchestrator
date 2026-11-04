# Dated public benchmark priors

`--prior-data <repository-relative.json>` accepts an optional `public_benchmarks`
array in the existing strict version-1 operator snapshot. It is frozen, hashed,
archived and replayed with the operator rows. Existing snapshots without this
array retain their behavior. No benchmark rows are bundled by this mechanism.

For each terminal task class, name a reference runtime/model/**requested effort**
and supply its row alongside the candidate rows. Every row records benchmark ID,
benchmark version, metric, an exact higher-is-better fraction (numerator and
positive denominator, each a u32), runtime, model, requested effort, HTTPS source
URL (absolute HTTPS, with a nonempty host and no userinfo), publication date and
read date. Use the actual source publication/update
date; a new read does not refresh old evidence. Do not import a score with an
unstated effort, infer effort from a column contradicted by a footnote, or copy
scores between efforts. If the publication date or effort is unknown, retain
that evidence outside the active row set until it is established.

For an exact lane/task pair the selector calculates:

```
relative_quality_bp = min(10000, floor(10000 * lane_score / reference_score))
```

Both rows must have exactly the same benchmark ID, version and metric. The
reference score must be positive. Publication and read dates for **both** rows
must fall within the inclusive `max_age_days` window before the frozen
evaluation date, with publication <= read <= evaluation date. The window
defaults to 90 days and can be narrowed to 1..90. The production reader freezes
the current UTC date in the effective dataset as
`public_benchmarks_evaluated_on`; replay retains it, so old snapshots cannot
refresh stale evidence on a new run. The pure selector never reads the clock;
direct inputs without that field use the explicit dataset `published_on` date.
Future snapshot publications are refused. Prepare fresh dated evidence for a
new evaluation; replay uses the original evaluation date.
Missing references, missing effort, stale/future dates, mismatched benchmarks or
versions, and unmapped tasks produce **unknown**, never a fabricated zero or an
eligible public comparison. Ambiguous duplicate lane/task mappings across
snapshots are rejected, including across different benchmarks. Choose one
reviewed benchmark for each lane/task mapping; there is no cross-benchmark ranking
or averaging. Both exported normalization APIs reject ambiguous inputs, including
duplicate reference identities, before choosing any row. Unknown comparisons do
not become exploratory eligible candidates. Within a snapshot's configured task
classes, every candidate without an exact operator class-fit needs a valid public
comparison. Deleting its row or its public-only model identity leaves it refused,
including when an observed catalog still advertises that model and effort. A
public lane also remains refused outside its mapped task classes. Exact operator
class-fits retain their existing behavior.

The existing 8000-bp floor applies to the **relative** quality (or a stricter loaded
role floor). For example, entirely synthetic scores of 45/100 and reference
50/100 produce 9000 bp. This is relative coding evidence, not a 90% prediction of
local acceptance and not class-fit/authority sample counts. Actual task outcomes
can constrain quality; they cannot rescue an unknown public comparison.

Public evidence can extend the exact effort menu for bounded Worker/Researcher
execution: at most medium risk, context and horizon, with bounded or tightly
bounded scope. It grants no supervisor, delegation, review, acceptance, failure
classification, publication or other judgment authority. Existing model
prohibitions, capability ceilings, account/catalog access, effort support,
quota/admission, environment, role and launch gates still apply. Existing
operator rows, reviewer strength and authority evidence are unchanged; new
public-only identities have strength zero and all judgment roles prohibited.
An explicit capability policy remains required where the static executor path
requires one; public evidence is not a capability grant.

Production uses the frozen loaded routing evaluation function to compare eligible
lanes per task. Public scores do not manufacture measured class-fit samples;
policies requiring such samples still refuse an unsampled lane. Optional
`cost_per_task_microunits` is retained as a benchmark task-cost routing proxy,
never token pricing, Build quota consumption or complete accepted-cycle cost.
Absent costs remain null. Public-only cost estimates retain the loaded-policy
uncertainty penalty because independent review/rework costs are unknown. Real
accepted-cycle observations take precedence. The legacy cost selector still
requires its existing operator class-fit/cost evidence; public-only snapshots
are intended for the production loaded-routing path.

To add dated evidence:

1. Create a version-1 operator snapshot with dataset ID, revision, `published_on`,
   `models` (empty if no operator updates) and `capability_policy` (explicit source
   and models, empty if no capability updates).
2. Add a `public_benchmarks` entry with explicit `task_classes`, `reference_lane`,
   optional `max_age_days`, and `rows`. Include the named reference row and exact
   candidate efforts from the same benchmark/version/metric.
3. Retain the source URL and both dates for every row. Omit unknown costs; do not
   fill review or rework costs with zero. Review the chosen reference and task
   applicability. Freeze the accepted repository-relative file with `--prior-data`.
4. Check selection preflight and retain the snapshot digest before release. A
   selected lane is not live qualification or independent acceptance.

The shape below is **entirely synthetic** and confers no real model eligibility:

```json
{
  "task_classes": ["localized_code_change", "review_gate"],
  "reference_lane": {
    "runtime": "codex", "model": "synthetic-reference", "effort": "low"
  },
  "max_age_days": 90,
  "rows": [
    {
      "benchmark_id": "synthetic-coding", "benchmark_version": "v1",
      "metric": "pass@1", "score": {"numerator": 50, "denominator": 100},
      "runtime": "codex", "model": "synthetic-reference", "requested_effort": "low",
      "source_url": "https://example.invalid/synthetic-benchmark",
      "published_on": "2026-10-15", "read_on": "2026-11-03"
    },
    {
      "benchmark_id": "synthetic-coding", "benchmark_version": "v1",
      "metric": "pass@1", "score": {"numerator": 45, "denominator": 100},
      "runtime": "codex", "model": "synthetic-worker", "requested_effort": "low",
      "source_url": "https://example.invalid/synthetic-benchmark",
      "published_on": "2026-10-15", "read_on": "2026-11-03"
    }
  ]
}
```

`review_gate` is also the Researcher's terminal task class; its presence here does
not admit a review/acceptance authority role. The [Grok evidence checkpoint](grok-public-2026-11-03.md)
contains no reference comparison and continues to grant nothing by itself.

The reference lane is chosen per task class. The
[Terminal-Bench 4.0 snapshot](public-tb4-2026-11-04.md) maps only bounded
`localized_code_change` to `codex` / `gpt-6.1-sol` / `low`, the cheapest
requested effort of the Codex model already used for that class. Review,
research, delegation, and every judgment role stay unmapped, so a public-only
lane remains refused there. That file grants no capability, no class-fit
samples, and no live qualification.
