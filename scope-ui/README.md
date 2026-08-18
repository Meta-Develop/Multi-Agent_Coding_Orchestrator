# MACO Scope UI

Loopback web client for `maco scope serve`. This is a client, never an
authority: every view either reads the existing Scope HTTP API or re-scores a
file the operator supplies. There are no write endpoints and no telemetry.

## Pages

- **Live** — the existing live-first multi-project observer (`/api/stream`,
  `/api/projects`). Graph projection query `?view=` is unchanged.
- **Catalog** — run inventory from `/api/projects`.
- **Objective** — named weight-profile preview against a recorded evaluation
  summary or results JSON. Export is a local download only.

Page routing uses `#/live`, `#/catalog`, `#/objective` so it does not collide
with the live observer's `?view=session|repository|combined` contract.

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
