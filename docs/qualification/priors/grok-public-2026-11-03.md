# Public Grok qualification prior evidence, 2026-11-03

The adjacent [version-1 operator snapshot](grok-public-2026-11-03.json) is
repository-relative and parseable by `--prior-data`. It adds **no eligibility**:
both `models` arrays are empty, preserving bundled priors and capability policy.
It is an evidence checkpoint, not an accepted prior admitting either fixture.
Do not use it to release a qualification. The selector still refuses 4.6/low
with `effort_incompatible` and 4.7/xhigh with `model_unavailable`.

All rows were read on 2026-11-03. Source dates are publication/update dates
where stated, otherwise explicitly dated read snapshots, not inferred
experiment dates. Scores retain each benchmark's own units.

| Model / effort | Public result | Source date | Primary source |
| --- | --- | --- | --- |
| grok-4.6 / low | DeepSWE v1.1 pass@1: 0.41648106904231624 (187 passes / 449 attempts, 113 tasks, four runs) | 2026-09-22 leaderboard update | [Datacurve DeepSWE](https://deepswe.datacurve.ai/), embedded `mini_swe_agent_grok_4_6_low` row; select all effort levels |
| grok-4.6 / low | CursorBench 4.0: 33.4% | 2026-11-03 read snapshot; publication date unstated | [Cursor's leaderboard](https://cursor.com/cursorbench), `Grok 4.6 Low` row |
| grok-4.7 / xhigh | CursorBench 4.0: 46.3%; Terminal-Bench 4.0: 37.6% | 2026-09-21 | [Official Grok 4.7 announcement](https://x.ai/news/grok-4-7), xHigh column |
| grok-4.7 / xhigh | No public per-effort DeepSWE v1.1 score in these sources | 2026-09-21 announcement; 2026-09-22 leaderboard update | [Official announcement](https://x.ai/news/grok-4-7) marks 71.0% with `* high effort`; [Datacurve leaderboard](https://deepswe.datacurve.ai/) has no 4.7 row in the inspected embedded data |

The announcement's DeepSWE footnote overrides its xHigh column heading for
that cell. Never import 71.0% as xhigh or copy a 4.6 high/xhigh score to low.
The DeepSWE low row comes from the publisher's embedded data, rather than the
default best-effort chart. Its public API benchmark cost is not Build quota
consumption or MACO execution plus independent-review/rework cost.

The [dated public benchmark mechanism](README.md) now supports a relative
lane/reference comparison on exactly the same benchmark/version/metric within
a stated date window. It preserves unknown costs and does not invent class-fit
samples or judgment authority. The unchanged 8000-bp floor applies to this
relative quality, rather than directly to raw coding success fractions.

This checkpoint has no named reference lane or paired reference rows, and its
strict JSON contains no `public_benchmarks`. It therefore still adds no
`ModelPrior` or capability eligibility. Before either live run, a separately
reviewed dated snapshot must supply the exact requested effort, matching
reference evidence and terminal task applicability through that mechanism.
A raw public score alone does not establish local acceptance.

After that prior gate, selected-account authentication, exact advertised
model/effort, principal/incarnation/revision, available capacity, Codex control,
Linux containment and independent acceptance remain separate requirements.
No live qualification, ordinary ACP admission, pricing or savings follows from
this checkpoint.
