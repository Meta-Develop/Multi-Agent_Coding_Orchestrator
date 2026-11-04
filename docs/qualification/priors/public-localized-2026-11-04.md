# Localized code change, VulcanBench Frontier v4, read 2026-11-04

The adjacent [version-1 operator snapshot](public-localized-2026-11-04.json)
is repository-relative and parseable by `--prior-data`. It maps only
`localized_code_change`. Both `models` arrays are empty, so it adds no
operator class-fit, no capability eligibility, and no judgment authority.
Passing selection preflight with this file is not live qualification.

The reference lane is `codex` / `gpt-6.1-sol` / `high`. The 8000 bp floor
applies to `min(10000, floor(10000 * lane_score / reference_score))`.
`review_gate`, research, delegation, and every non-terminal authority role
stay unmapped. Child orchestration uses the same class string with delegating
authority and a shape outside the bounded terminal ceiling, so this evidence
does not apply there.

## Active rows

Benchmark `vulcanbench-frontier`, version `v4`, metric
`hidden_behaviours_fixed`, 231 hidden behaviours, higher is better. Re-read
on 2026-11-04.

Reference, published 2026-10-01. The page header is "October 1, 2026 · 115
runs · Code quality protocol v3.18" on
<https://vulcanbench.com/benchmarks/swe-v4-gpt61-sol-v318.html>.
The page says "Of the 231 hidden behaviours the tasks test for, it fixes 225
at Low, 228 at Medium and all 231 from High up." The High column is 231/231.
"effort labels are Codex's own." The run is "GPT-6.1 Sol works in Codex".
The page also says "Frontier v4 therefore no longer separates GPT-6.1 Sol's
top levels on correctness" and "read GPT-6.1 Sol's High to Max columns as at
the suite's correctness ceiling." Extra-high and Max are the same 231/231 and
are not stored. The ceiling means this metric separates weakly once a lane
clears every hidden behaviour.

Candidates, published 2026-10-04. The page header is "October 4, 2026 · 92
runs · Code quality protocol v3.20" on
<https://vulcanbench.com/benchmarks/swe-v4-grok47-cursor-v320.html>.
The page says "Cursor exposes four Grok 4.7 variants (grok-4.7-low, -medium,
-high and -xhigh)" and "Of the 231 hidden behaviours the tasks test for, it
fixes 213 at Low, 215 at Medium (the timed-out run counts as fixing none),
230 at High and all 231 at Extra-high." Extra-high is the `grok-4.7-xhigh`
variant and is stored as `xhigh`. The harness line is "Grok 4.7 works in
Cursor's agent CLI" and "this is Grok 4.7 in Cursor." Sol's column is Codex.
Those are different harnesses, so the ratio is a public relative prior for
the same hidden-behaviour suite, not a claim that the agents ran the same
tool.

| Lane | Fraction | Published | Relative bp | At the 8000 floor |
| --- | --- | --- | --- | --- |
| gpt-6.1-sol high (reference) | 231/231 | 2026-10-01 | 10000 | reference |
| grok-4.7 high | 230/231 | 2026-10-04 | 9956 | passes this class |
| grok-4.7 xhigh | 231/231 | 2026-10-04 | 10000 | passes this class |

Combined score is not the metric. Grok's column is protocol v3.20 judged by
Muse Spark 1.3 and GPT-6.1 Sol. Sol's column is protocol v3.18 judged by Muse
Spark 1.3 and Grok 4.6. The Grok page says the combined score "is not strictly
comparable with the other columns." Hidden behaviours are the shared test
count on Frontier v4.

## Withheld

Grok 4.7 low fixes 213 of 231 on the same page (`floor(10000 * 213/231) = 9220`).
That cell is dated and effort-explicit, and it is still not an active row.
The same lane's Artificial Analysis Terminal-Bench 4.0 read is 16.2% against
sol low 30.8%, which is 5259 bp and below 8000. Those two reads conflict, so
low stays pending. Medium (215/231) is not imported. grok-4.6, DeepSeek, and
`review_gate` rows are not imported.

## Terminal-Bench 4.0, still pending

Artificial Analysis Terminal-Bench 4.0 cells were re-read on 2026-11-04 and
still have no publication date, so they stay outside the active rows.
<https://artificialanalysis.ai/models/releases/comparisons/gpt-6-1-sol-vs-grok-4-7>
prints sol low 30.8% (payload `0.308080808080808`), grok-4.7 xhigh 25.8%
(`0.257575757575758`), high 24.7% (`0.247474747474747`), and low 16.2%
(`0.161616161616162`). The page has no `dateModified` or `datePublished`.
The September 29, 2026 Sol article says "a 12 point jump in Terminal-Bench
4.0" and does not print 30.8. The September 21, 2026 Grok article says "+4.5
percentage points" and a separate Grok Build "18% to 33%". The October 27,
2026 Index v5 article and
<https://x.com/ArtificialAnlys/status/2115265133467635877> say Terminal-Bench
4.0 stays in the index and do not print these cells. The November 3, 2026
changelog entry is a CritPt regrade. Wayback has no capture of the comparison
page. Pending arithmetic only: 8376, 8019, and 5259 bp against sol low.
