# Grok 4.7 ACP managed-child qualification (#616)

Status: prepared; Linux credential-confined, account-bound ACP execution remains
unproven. Follow the [shared preparation contract](README.md) and
[managed Grok prerequisites](../OPERATOR_QUICKSTART.md#grok-runtime).
The [fixture](../../examples/supervise/qualification-grok47-acp.json) reuses
#688's substantive ledger repair and frozen task assessment, changing only
Worker selection to `grok-4.7` / `xhigh`. It has one non-delegating terminal
Worker, Codex supervision/control/review, 160,000 hard tokens, a 1,200-second
child timeout, and zero retries or gate corrections. The seed tests deliberately
fail until the actual assigned implementation is repaired.

Before release, retain non-secret evidence for the selected CAM `work2`
principal/incarnation and selection revision, valid Codex control account,
exact Grok executable/version/digest, current 4.7/xhigh catalog and available
capacity. Require verified Linux containment and account-confined credential
visibility. An accepted dated, evidence-backed repository-relative operator
prior snapshot must independently admit the exact 4.7/xhigh Worker lane; set
`prior47` to that existing snapshot. There is no invented qualification prior
in this fixture. Unknown eligibility/capacity blocks release. Do not switch
accounts, install replacements or retry a paid failure to evade these gates.

Offline validation (does not contact a provider):

```bash
fixture=examples/supervise/qualification-grok47-acp.json
sha256sum "$fixture" > "$OUT/fixture-sha256.txt"
"$maco" supervise plan "$fixture" --repo "$repo" --json > "$OUT/checked-plan.json" || exit 1
```

After independent review of the implementation, fixture, prior and prerequisites,
the exact live command is:

```bash
export MACO_GROK_BIN="$(readlink -f "$(command -v grok)")"
test -f "$MACO_GROK_BIN" && test ! -L "$MACO_GROK_BIN" || exit 1
test -n "$prior47" && test -f "$repo/$prior47" || exit 1
"$MACO_GROK_BIN" --version > "$OUT/grok-version.txt"
sha256sum "$MACO_GROK_BIN" > "$OUT/grok-sha256.txt"
sha256sum "$repo/$prior47" > "$OUT/prior-sha256.txt"
run_id=qualification-grok47-acp-01
if timeout --signal=TERM --kill-after=30s 3600 systemd-run --user --scope --quiet -p Delegate=yes \
  --working-directory="$repo" -- env MACO_GROK_BIN="$MACO_GROK_BIN" \
  MACO_GROK_INTERACTION_PROTOCOL=acp_stdio \
  "$maco" supervise run "$fixture" --runtime codex --repo "$repo" \
  --run-id "$run_id" --codex-bin codex --qualify-grok47-acp --prior-data "$prior47" \
  --max-concurrent-children 1 --provider-inflight-limit 1 \
  --machine-global-config "$config" --machine-global-runtime-root-id runtime --json \
  > "$OUT/run.json" 2> "$OUT/run.stderr"; then rc=0; else rc=$?; fi
printf '%s\n' "$rc" > "$OUT/run.exit"
if "$maco" supervise collect "$run_id" --repo "$repo" --json \
  > "$OUT/collect.json" 2> "$OUT/collect.stderr"; then rc=0; else rc=$?; fi
printf '%s\n' "$rc" > "$OUT/collect.exit"
```

The flag is a qualification-only exception, not capability promotion. Without
it, selecting `acp_stdio` for writable 4.7 yields the typed refusal
`writable_grok47_acp_qualification_required`. It requires an explicit fresh
plan/run ID and Codex runtime. There is no environment or plan field granting
the exception, no inherited authority in a Worker process, and no resumption
of this authority. Before it becomes usable, the parent validates the bounded
shape and archives `qualification/grok47-acp.json` in the authenticated run
manifest. Retain that receipt with the frozen plan, prior, selection and
account evidence. A failed evidence write cannot admit the Worker. Every
existing gate still applies; 4.6 ACP and 4.7 headless behavior are unchanged.

Acceptance requires all of the following evidence from the same live run:

- The operator exception receipt bound to the exact run and assignment; exact
  executable/account/cwd/schema/permission binding; immutable ACP argv with
  `--sandbox strict`, `--no-leader`, `GROK_SUBAGENTS=0` and `GROK_MEMORY=0`.
- Real account-confined managed-child execution, parent ACP `session/prompt`
  with `_meta.outputSchema`, successful terminal schema receipt and production
  WorkerReport/publication validation. Retain matching requested and
  client-resolved 4.7/xhigh identity; client resolution is not backend attestation.
- Complete native whole-invocation usage, budget settlement, parent-bound
  read/command/edit/check journal, candidate manifest/diff, and no out-of-scope
  changes. Only `examples/supervise/qualification-data/test_grok_ledger.py`
  may change. No outstanding reservation or surviving exact owned child.
- Independent default review lenses and final Codex acceptance after checking
  the actual candidate with the command below. Keep the original test bodies
  and function signatures. Admission `(100,0,60,60)` must refuse and
  `(100,20,30,50)` must pass; notices `20,35,35,40,35` retain floor 40. Settle
  A=40 exactly once, release its reservation, accept identical replay, and
  refuse unknown usage or conflicting replay before effects.

```bash
python3 -B -m unittest discover -s examples/supervise/qualification-data -p test_grok_ledger.py -v
git diff --check
```

Before live release, retain passing refusal/opt-in regressions plus existing
missing/mismatched account/identity, schema error, absent usage, widened-path
and native-delegation negatives. Providerless tests, native schema receipts,
headless success and exit 0 alone do not prove this qualification. A failed or
incomplete run leaves #616 open. Even a successful qualification needs reviewed
acceptance evidence and a separate explicit admission-policy change before
ordinary 4.7 ACP writable promotion. No production prior, pricing, quality,
quota-saving or economics claim follows from this one run.
