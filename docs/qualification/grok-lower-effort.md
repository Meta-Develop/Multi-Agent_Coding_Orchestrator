# Lower-effort writable qualification (#688)

Status: prepared; `grok-4.6` / `low` eligibility and live acceptance are unknown.
Follow the [shared preparation and evidence contract](README.md) and the
[managed Grok prerequisites](../OPERATOR_QUICKSTART.md#grok-runtime).
The [fixture](../../examples/supervise/qualification-grok-lower-effort.json)
assigns one substantive ledger repair to a terminal Worker and keeps
supervision, all independent review, acceptance and publication on qualified
control roles. It requests canonical `low`, standard headless streaming JSON,
and fail-closed availability; it never rewrites the request to `xhigh`.

Before a live run, record that the selected CAM account is `work2`, its exact
principal/incarnation and selection revision, the installed executable/version,
and its observed menu/catalog digest supporting **both** `grok-4.6` and `low`.
Record capacity without inventing a balance. A catalog banner is not inference
authentication proof. The current frozen task/authority priors must independently
admit the exact lane. The bundled terminal prior historically selects `xhigh`;
parser success or generic protocol support does not establish a `low` prior.
Until all gates are established, record **unknown/refused before release** and
do not run a paid probe, switch accounts or silently select another effort.
Any necessary evidence-backed prior update is a separate reviewed change.

The retained Grok CLI 1.0.60 streaming-json terminal exposes model labels as
`end.modelUsage` object keys. Its label `grok-4.6-build` is preserved verbatim.
The protocol exposes no served-effort field. Native usage evidence therefore records
`served_identity.observed_effort: null` explicitly. Model suffixes, the requested
`--reasoning-effort`, configuration and text/tool content cannot fill that gap.
The field-name-only [receipt projection](../../tests/fixtures/runtime_adapter/grok/headless-cli-1.0.60-identity.json)
pins this observation without retaining conversation content.

Model matching uses only two explicit label pairs: `grok-4.6` / `grok-4.6-build`
and `grok-4.7` / `grok-4.7-build`. The first is backed by the retained accepted
`e2e-mixed-main-ba41-c30b` headless Worker log (SHA-256
`ef06c217147682fb3e1d8e29bc4c511b8bd401fb29c916cde06c0f6af8d5a3a2`).
The second is backed by the [#616 CLI 1.0.41 native headless receipt](https://github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator/issues/616#issuecomment-5827977323):
request `grok-4.7`, terminal `modelUsage` key `grok-4.7-build`.
These mappings establish label compatibility only, without pricing, billing,
effort or ACP qualification claims. Unknown labels never match; no suffix or
prefix rule applies. Multiple labels, including both members of a known pair,
remain ambiguous.

Managed headless **writable publication** requires original parent-held complete
native usage and one complete, valid model label matching the admitted command
on every turn. Missing model labels refuse publication because the retained CLI
normally emits them; this preserves the accepted c30b terminal shape. Duplicate,
ambiguous, malformed or mismatched identity also refuses publication while native
token charges remain available. Observed effort must be canonical and match.

The existing standard `grok-4.6` / `xhigh` and `grok-4.7` / `xhigh` headless lanes
keep publication when served effort is explicitly unknown. This preserves their
existing admission; it does not claim that requested effort was observed. Every
qualification-only model/effort lane, including #688 `low`, requires **both**
matching observed model and effort. CLI 1.0.60 cannot pass that strict gate until
a source-qualified served-effort observation is available. This identity policy
adds no selection eligibility or priors. Public or restored identity fields cannot
recreate the private capture. Prior admission and selected-account live acceptance
remain separate gates; do not launch the lower-effort qualification while its
served effort is unknown.

Offline validation (does not evaluate those account/prior gates):

```bash
fixture=examples/supervise/qualification-grok-lower-effort.json
sha256sum "$fixture" > "$OUT/fixture-sha256.txt"
"$maco" supervise plan "$fixture" --repo "$repo" --json > "$OUT/checked-plan.json" || exit 1
```

After the exact eligibility gates pass, run with the existing managed account:

```bash
export MACO_GROK_BIN="$(readlink -f "$(command -v grok)")"
test -f "$MACO_GROK_BIN" && test ! -L "$MACO_GROK_BIN" || exit 1
unset MACO_GROK_INTERACTION_PROTOCOL
"$MACO_GROK_BIN" --version > "$OUT/grok-version.txt"
sha256sum "$MACO_GROK_BIN" > "$OUT/grok-sha256.txt"
run_id=qualification-grok-low-01
if timeout --signal=TERM --kill-after=30s 3600 systemd-run --user --scope --quiet -p Delegate=yes \
  --working-directory="$repo" -- env MACO_GROK_BIN="$MACO_GROK_BIN" \
  "$maco" supervise run "$fixture" --runtime codex --repo "$repo" \
  --run-id "$run_id" --codex-bin codex --max-concurrent-children 1 --provider-inflight-limit 1 \
  --machine-global-config "$config" --machine-global-runtime-root-id runtime --json \
  > "$OUT/run.json" 2> "$OUT/run.stderr"; then rc=0; else rc=$?; fi
printf '%s\n' "$rc" > "$OUT/run.exit"
if "$maco" supervise collect "$run_id" --repo "$repo" --json \
  > "$OUT/collect.json" 2> "$OUT/collect.stderr"; then rc=0; else rc=$?; fi
printf '%s\n' "$rc" > "$OUT/collect.exit"
```

The 160,000-token ceiling, positive role estimates, 1,200-second child timeout
and zero retries bound this attempt; they do not assert a strict spending cap.
Use `--prior-data` only if an accepted evidence-backed repository-relative
snapshot already establishes the exact lower-effort eligibility; retain its
digest. Do not fabricate a snapshot to get through selection.

Acceptance requires requested **and observed served** model/effort identity,
the opaque proof bound to exact executable, account, cwd, output/schema,
permissions, headless protocol and native-delegation denial; complete native
whole-invocation usage; genuine command/read/edit/check observations; and a
valid terminal WorkerReport. Only
`examples/supervise/qualification-data/test_grok_ledger.py` may change. Independent
reviewers must check admission, cumulative usage, replay and unknown-usage
behavior, inspect the candidate manifest/diff, and independently accept or reject. All default
lenses, final control authority and exact owned-process quiescence remain required.

The independent reviewer runs the recognized test target against the actual
candidate and checks that existing test bodies and signatures are preserved:

```bash
python3 -B -m unittest discover -s examples/supervise/qualification-data -p test_grok_ledger.py -v
git diff --check
```

It must reject admission `(100,0,60,60)`, accept `(100,20,30,50)`, retain a floor
of 40 for notices `20,35,35,40,35`, and settle A=40 exactly once while releasing
A and recording settled[A]=40. Unknown usage and conflicting replay refuse
before effects. The seed intentionally fails before repair; passing unchanged
or deleted tests is not qualification. No generic authored-check expansion is needed.

Reuse canonical-effort/protocol separation and principal/effort drift tests,
plus existing missing/mismatched identity, absent usage, invalid schema,
widened path and native-delegation refusal regressions before release. Retain
any real negative-case receipts; providerless negatives alone do not establish
real selected-account qualification. Reject ambiguous `deep`, unknown effort,
ACP/headless mismatch, launch drift and silent upgrades. Headless containment
does not qualify ACP (#616). A prior `xhigh` mixed run, native CLI success or
working account is insufficient. One accepted run makes no cost/quality,
quota-saving or model-equivalence claim; #631 requires separate measurements.
