# Read-only supplied-source qualification (#689)

Status: prepared; real supplied-source review is unproven. Follow the
[shared preparation and evidence contract](README.md). The
[fixture](../../examples/supervise/qualification-researcher-source-input.json)
uses one non-delegating read-only Researcher on `gpt-6.1-sol` / `xhigh` and
independent default review lenses. It declares exactly one nonempty snapshot
file, [source-packet.md](../../examples/supervise/qualification-data/source-packet.md),
SHA256 `1cfe51c5e96a38d3dabe431faf3b50e34b2512221c585e80d3b313cd3a87f53e`.
Its flawed ledger proposal gives the review concrete source observations and
counterexamples; it is not an empty diff or a receipt-only exercise.

The bundled `review_gate` prior admits `xhigh` for the Researcher. The original
`medium` preference passed plan parsing but was refused by live selection with
`effort_incompatible`, before any provider assignment. This correction supplies
no new account or quality evidence.

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
if timeout --signal=TERM --kill-after=30s 5400 systemd-run --user --scope --quiet -p Delegate=yes \
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

The plan has a finite 240,000-token ceiling, 4,000-token parent/Researcher/reviewer
estimates, no retries and a 1,200-second child timeout. The ceiling adds roughly
20% headroom to the historical supplied-source failure: 41,321 Researcher +
154,651 Auditor = 195,972 tokens; 195,972 × 1.20 = 235,166.4, rounded up to
240,000 (44,028 tokens, about 22.5% headroom). Historical positive routes used
[130,507 tokens](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/680#issuecomment-5850136768)
and [127,944 tokens](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/631#issuecomment-5868103079);
neither qualifies this fixture or proves its current `xhigh` consumption.

The outer command deadline is 5,400 seconds: four serial invocations (one
Researcher and three review lenses) × at most 1,200 seconds = 4,800 seconds,
plus 600 seconds for overhead and finalization. The 30-second kill grace remains
separate. These bounds are admission limits, not provider spending caps; role
estimates do not cap actual usage. A timeout or insufficient allowance is a
retained failed/inconclusive attempt, not a reason to remove the bounds.

The retained proof for **C1/C2** is the `researcher_input_receipts[]` field in
`logs/<researcher-id>[.attempt-N].summary.json`.
Each input records the snapshot-relative `path` and `input_path`,
`expected_sha256`, observed `sha256`, `bytes`, launch-bound `identity`
(`[device, inode]`), `regular_file=true` and `symlink=false`. The independent
`outer_preflight`, `inner_preflight` and `pre_provider_revalidation` fields
record `status=passed` with the observed hash/length, `status=not_attempted`,
or `status=refused` with a typed `reason` (`preparation_failed`,
`process_failed`, `read_mismatch`, or `identity_or_content_changed`). A failed
read also retains its observed hash/length when available, never source bytes,
helper paths, environment or credentials. Early snapshot validation can refuse
before an identity receipt exists; that attempt cannot prove successful release.

These are additive fields in the existing unversioned private process summary;
the versioned public final/collect report schemas are unchanged. The summary is
bound by its target-containment receipt's `command_summary_sha256` and the final
artifact manifest. Finalized collection checks each declared input against the
retained plan and requires complete outer/inner/revalidation receipts for every
launched attempt and at least one proven launch per accepted source assignment.
Missing, inconsistent or tampered evidence cannot produce clean acceptance.
Older source-input runs without these receipts remain readable as historical
artifacts but cannot be collected as clean accepted runs. These preparation
receipts prove identity and visibility before release; authentic native command
observations and independent review still prove substantive source inspection.

Required acceptance evidence:

- Exact source commit, packet bytes/hash, staged regular-file identity,
  declaration/assignment receipt and successful actual outer and inner
  containment visibility probes before release. No broader directory capability.
- Authentic contained read commands and results that inspect the actual packet.
  For Codex, each `commands_run[].command` is a one-element array holding the exact
  command submitted to the tool, for example
  `["nl -ba examples/supervise/qualification-data/source-packet.md"]`.
  MACO decodes exactly one literal `/bin/bash -lc` or `/bin/bash -c` wrapper from
  the native event; the submitted string is compared byte-for-byte, without
  normalizing whitespace, quoting or nested shells. Unknown/malformed wrappers
  fail closed. Host start/completion wrappers must agree exactly, and each claim
  consumes a distinct completed, correlated execution with matching cwd/status/exit.
  All native commands must be accounted for, and validation entries reference
  distinct successful claims. The historical report claiming `/bin/bash -c '…'`
  against a native `/bin/bash -lc '…'` event remains rejected; reports cannot infer
  host wrappers from process listings. Native stdout and timing remain outside
  the report's authenticated command fields.
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
the [195,972-token failed review](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/680#issuecomment-5862565454)
(41,321 Researcher, 154,651 Auditor); none of its lenses inspected the packet.
The earlier bad-contract attempt consumed 212,868 tokens before the final lens;
the new ceiling leaves only 27,132 tokens beyond that partial trajectory and
does not guarantee completion. Incomplete historical evidence and prior 0/3 lens
results remain failures. This qualification does not close #629 or #680.
