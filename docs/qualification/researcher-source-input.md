# Read-only supplied-source qualification (#689)

Status: prepared; real supplied-source review is unproven. Follow the
[shared preparation and evidence contract](README.md). The
[fixture](../../examples/supervise/qualification-researcher-source-input.json)
uses one non-delegating read-only Researcher on `gpt-6.1-sol` / `medium` and
independent default review lenses. It declares exactly one nonempty snapshot
file, [source-packet.md](../../examples/supervise/qualification-data/source-packet.md),
SHA256 `1cfe51c5e96a38d3dabe431faf3b50e34b2512221c585e80d3b313cd3a87f53e`.
Its flawed ledger proposal gives the review concrete source observations and
counterexamples; it is not an empty diff or a receipt-only exercise.

The packet must already be committed in the selected managed snapshot. Do not
stage an ambient parent file, infer mounts from task text, grant directory
visibility, or refresh the hash to excuse drift. The outer/inner profile probes
and release-time identity/hash revalidation must succeed before provider release.

```bash
fixture=examples/supervise/qualification-researcher-source-input.json
run_id=qualification-researcher-source-01
printf '%s  %s\n' \
  1cfe51c5e96a38d3dabe431faf3b50e34b2512221c585e80d3b313cd3a87f53e \
  examples/supervise/qualification-data/source-packet.md | sha256sum --check || exit 1
git ls-files --error-unmatch examples/supervise/qualification-data/source-packet.md || exit 1
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

The plan has a finite 160,000-token ceiling, 4,000-token parent/Researcher/reviewer
estimates, no retries and a 1,200-second child timeout. These are admission
estimates, not provider-call caps. A timeout or insufficient allowance is a
retained failed/inconclusive attempt, not a reason to remove the bounds.

Required acceptance evidence:

- Exact source commit, packet bytes/hash, staged regular-file identity,
  declaration/assignment receipt and successful actual outer and inner
  containment visibility probes before release. No broader directory capability.
- Authentic contained read commands and results that inspect the actual packet.
  The report must cite `admit`, `observe`, and `complete` with real line ranges,
  demonstrate the two 60-token reservations against ceiling 100, distinguish
  cumulative 20/35/35/40 observations from deltas, identify persistence-before-
  settlement failure and unknown-to-zero coercion, and discuss duplicate replay.
  Reviewers verify those observations against source, rather than accepting
  repetition of the task or case list.
- Native Researcher schema, read-only/no-delegation enforcement, no candidate
  writes, complete trustworthy usage, all independent lens results and final
  acceptance. A clean diff alone is not successful review. A diff-only lens
  must not claim it inspected a source packet it never received; its limited
  evidence is explicit and cannot replace source-aware independent review.
- Exact owned process cleanup and released reservations, including failure
  paths. Unknown helper ownership/usage remains conservative, never invented zero.

Before dispatch, run the existing missing/changed/hash/symlink/authority,
write-denial and actual-profile source-input regressions, the pinned providerless
inner-sandbox case where installed, and the NotStarted versus unknown-helper
accounting/late-refusal regressions. Do not mutate live input capabilities to
conduct paid negative probes. Retain the historical missing-mount failures and
the 195,972-token failed review (41,321 Researcher, 154,651 Auditor); none of its
lenses inspected the packet. Incomplete historical evidence and prior 0/3 lens
results remain failures. This qualification does not close #629 or #680.
