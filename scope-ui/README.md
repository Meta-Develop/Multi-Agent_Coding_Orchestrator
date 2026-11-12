# MACO Scope UI

Loopback web client for `maco scope serve`. This is a client, never an
authority: every view either reads the existing Scope HTTP API or re-scores a
file the operator supplies. There are no write endpoints and no telemetry.

## Pages

- **Live** — the existing live-first multi-project observer (`/api/stream`,
  `/api/projects`). Graph projection query `?view=` is unchanged.
- **Catalog** — run inventory from `/api/projects`, plus a local switch-cost
  evidence import (see below).
- **Objective** — named weight-profile preview against a recorded evaluation
  summary or results JSON. Export is a local download only.

Page routing uses `#/live`, `#/catalog`, `#/objective` so it does not collide
with the live observer's `?view=session|repository|combined` contract.

## Switch-cost evidence import

The Catalog page can chart recorded invocations from one or more local
`switch-cost/live-evidence.json` artifacts (`schema_version: 1`, an
`invocations` array). Use the file picker to select several artifacts at once;
they are read in the browser tab and kept in memory only. Nothing is uploaded,
written to the server, persisted, or fetched over the network.

Two horizontal bar charts are rendered:

- recorded invocation counts and shares per model group;
- measured `input_tokens + output_tokens` and shares per model group.

A **Group by** control switches both charts between the resolved/observed model
(`resolved_model`), requested model (`requested_model`), Role category,
Role category x requested model, and Run outcome. Role matching ignores case: Manager includes
manager, childorchestrator, orchestrator and supervisor; Review includes auditor,
reviewer and review; Worker includes worker; Other includes missing or any other
role. Category labels list their raw roles, for example `Review (Auditor)`.
A missing model
is shown as `Unknown`; a missing `resolved_model` is never replaced by
`requested_model`. `cached_input_tokens` is already part of `input_tokens` and
is never added again. The Run outcome grouping uses `collection.run_outcomes`
from collected artifacts, joined by `optimization_run_id`; invocations without
a recorded outcome, including every directly imported live-evidence artifact,
show as `Unknown outcome`. `Accepted run` means MACO's native final result, not
later human or root acceptance.

Token mass counts only records where both `input_tokens` and `output_tokens`
are nonnegative safe integers and their sum is safe. Null, missing, partial,
negative, fractional or unsafe usage stays unknown and is excluded, never
counted as zero; a known zero is valid. Token percentages are explicitly over
the known measured subtotal, and measured tokens with an unknown model stay in
`Unknown`. Counts, numeric percentages and coverage are shown next to every
bar. Every group retains its invocation count bar and percentage regardless of
token availability. In the token chart, a group with no measured usage shows `unavailable` and an em dash
rather than a fabricated zero. When no measured tokens exist at all the share
is an em dash rather than `NaN`, infinity or an arbitrary 100%.

Totals are accumulated exactly, so individually safe records that sum beyond
`Number.MAX_SAFE_INTEGER` still print their full digit count. When such a
subtotal cannot be represented as a `Number`, the percentage is shown as
unavailable instead of a rounded or fabricated share.

Records are deduplicated by (`optimization_run_id`, `invocation_id`, `started_at`)
with missing `started_at` treated as null, across
all imported files and repeated snapshots. Identical duplicates collapse;
all rows of a conflicting identity are excluded and listed in the error region instead of being
silently chosen. Conflicts are detected on `role`, `backend`, `provider`,
`requested_model`, `resolved_model`, `input_tokens`, `cached_input_tokens` and
`output_tokens`, including fractional or unsafe counters that never qualify
for token mass. Malformed or empty artifacts are rejected with an actionable
message, and a rejected artifact contributes no records to the charts.

Collected schema-version-1 artifacts import the same way, including invocations
with `record_source: "codex_exec_jsonl"`. An optional top-level `collection`
object adds one notice listing numeric `files_scanned`, `artifacts_parsed` and
`identical_duplicates`, plus the lengths of `invalid_artifacts`, `conflicts` and
`external_sources` arrays; missing values are omitted. The collector command
`node scope-ui/scripts/collect-usage.mjs [--external-manifest FILE] [--out FILE] [--svg FILE] [--summary] ROOT...`
writes one importable artifact. Clear also invalidates pending file reads.
`--svg FILE` writes a standalone SVG chart of the same merged invocations and
run outcomes that `--summary` describes, with token shares by role category,
requested model, run outcome and role category by requested model; it can be
combined with `--out` and `--summary`.

The collector also reads each scanned run's native final result from
`<run>/reports/supervisor-final.json` and emits `collection.run_outcomes`
and `run_outcome_conflicts`, joining invocations to outcomes by
`optimization_run_id`. The `--summary` output adds a `By run outcome:`
section and a `Known tokens per accepted run:` line that divides all known
measured tokens — accepted, not accepted and unknown invocations together —
by the number of accepted runs. Accepted here means MACO's own native final
result, not any later human or root acceptance.
A `By Worker model per run:` section follows it, grouping only runs with
a native outcome by the sorted, de-duplicated `requested_model` values of
their Worker invocations (`(no Worker)` when a run has none). Each row
counts every role of each run: accepted and not accepted runs, total known
tokens, tokens per accepted run, and how many runs are incomplete.

All recorded roles are in scope, including control/review roles, retries and
failed attempts, each invocation counted once. The charts describe the supplied
artifacts only — not the whole account, unrecorded outer Managers, planned
roles, candidate proposals or aggregate supervisor totals. Model attribution
comes from the recorded `resolved_model` (or `requested_model` when that
grouping is selected); a requested name is never presented as a provider
identity. No economic, pricing, quota or model-credit claims are made.

## Commands

No npm dependencies. Node's built-in test runner is enough:

```bash
node --test tests/*.test.mjs
node scripts/build.mjs
```

The build writes `src/scope/placeholder.html`, which the Scope server already
embeds via `include_str!`. Do not edit that generated file by hand.

## Verification

Tests are headless. They do not open a window. GUI sandboxing is not required
for this package.
