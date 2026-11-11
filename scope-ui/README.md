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

A **Group by** control switches between the resolved/observed model
(`resolved_model`) and the requested model (`requested_model`). A missing model
is shown as `Unknown`; a missing `resolved_model` is never replaced by
`requested_model`. `cached_input_tokens` is already part of `input_tokens` and
is never added again.

Token mass counts only records where both `input_tokens` and `output_tokens`
are nonnegative safe integers and their sum is safe. Null, missing, partial,
negative, fractional or unsafe usage stays unknown and is excluded, never
counted as zero; a known zero is valid. Token percentages are explicitly over
the known measured subtotal, and measured tokens with an unknown model stay in
`Unknown`. Counts, numeric percentages and coverage are shown next to every
bar. A model group with no measured usage shows `unavailable` and an em dash
rather than a fabricated zero. When no measured tokens exist at all the share
is an em dash rather than `NaN`, infinity or an arbitrary 100%.

Totals are accumulated exactly, so individually safe records that sum beyond
`Number.MAX_SAFE_INTEGER` still print their full digit count. When such a
subtotal cannot be represented as a `Number`, the percentage is shown as
unavailable instead of a rounded or fabricated share.

Records are deduplicated by `optimization_run_id` plus `invocation_id` across
all imported files and repeated snapshots. Identical duplicates collapse;
conflicting rows are rejected and listed in the error region instead of being
silently chosen. Conflicts are detected on `role`, `backend`, `provider`,
`requested_model`, `resolved_model`, `input_tokens`, `cached_input_tokens` and
`output_tokens`, including fractional or unsafe counters that never qualify
for token mass. Malformed or empty artifacts are rejected with an actionable
message, and a rejected artifact contributes no records to the charts.

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
