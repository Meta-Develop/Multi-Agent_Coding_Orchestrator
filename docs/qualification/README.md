# Live qualification preparation

These fixtures prepare separate acceptance gates for [nested token control](nested-codex-budget.md),
[read-only source inspection](researcher-source-input.md), a
[lower-effort writable lane](grok-lower-effort.md),
[4.7 ACP managed-child execution](grok47-acp.md), and a
[cross-runtime model-mix pilot](model-mix-pilot.md). None records a passed live run.
Plan validation is offline and does not assert account access, selector
eligibility, containment, provider identity, usage, or successful acceptance.

Use an admitted Linux host, or an already configured WSL guest meeting the
[operator prerequisites](../OPERATOR_QUICKSTART.md). Use the accepted executable
and a clean disposable target repository containing the committed fixtures,
source packet and original test fixtures. Run qualifications serially. Preserve
existing shared state, account selection and other runs; never reset them to
make a fixture pass. Do not run these commands in an occupied working checkout.
An existing selected account is required; these instructions do not set up auth.

In Bash, set exact existing paths and a fresh private evidence directory:

```bash
export repo=/path/to/clean/qualification-checkout
export maco=/path/to/accepted/maco
export config=/path/to/existing/machine-global.json
export OUT=/path/to/private/new-qualification-evidence
umask 077
mkdir -m 700 "$OUT" || exit 1
cd "$repo" || exit 1
test -z "$(git status --porcelain)" || exit 1
git rev-parse HEAD > "$OUT/source-commit.txt"
git status --porcelain > "$OUT/source-status.txt"
"$maco" --version > "$OUT/maco-version.txt"
sha256sum "$maco" > "$OUT/maco-sha256.txt"
codex --version > "$OUT/codex-version.txt"
sha256sum "$(readlink -f "$(command -v codex)")" > "$OUT/codex-sha256.txt"
"$maco" machine-global status --config "$config" --json > "$OUT/machine-global-status.json" || exit 1
```

The existing config must admit runtime root id `runtime`; otherwise use its
reviewed id in every command. Do not create a substitute config or bypass
containment. Record accepted build source/dirty identity as well as the target
snapshot commit; a target commit alone does not identify the executable.
Record selected account id, principal/incarnation, selection revision, observed
catalog revision/digest, model menu and available capacity from existing
non-secret authority receipts. Never copy auth files or process environments.
Unknown capacity or identity remains unknown and can block live admission.

Each page gives the exact offline and live command. Offline commands need no
provider, login or delegated desktop. The JSON stdout is the normalized checked
plan; preserve it beside the fixture SHA256. The fixtures freeze the shipped
policy and carry deterministic `policy_heuristic` assessments. These are
declaration estimates, not account support or measured quality. Changing task,
scope, policy or hash-bound notes requires regenerating the corresponding
assessment/contract through accepted tooling and validating replay again.
Changing an effort preference alone does not create selector eligibility.

The Codex fixtures request efforts admitted by the bundled role/task priors:
`high` for the delegating parent and terminal writable Workers, and `xhigh` for
Researcher and control/review roles. A providerless regression runs the live
selection bridge against every qualification plan with synthetic model
membership and the bundled priors. It requires the Codex fixtures to pass,
the deliberate `grok-4.6` / `low` fixture to refuse with `effort_incompatible`,
and the `grok-4.7` / `xhigh` ACP fixture to refuse before provider release with
`model_unavailable` for its Worker. The bundled priors have no row admitting
that 4.7 task profile; a live ACP run requires an accepted evidence-backed
`--prior-data` snapshot admitting the exact lane. The qualification flag does
not supply a prior or override this refusal.
Synthetic membership establishes no account access or live admission. Effort
preferences are outside the routing declaration and task-bound verification
contracts, so this correction preserves their hashes and validates replay
through the ordinary plan loader.

Keep the full private run directory `.maco/o2/runs/<run-id>` and any returned
cascade/follow-up run ids, not just stdout. Capture collection independently of
the launch status, including expected budget rejection. The final report is
`.maco/o2/runs/<run-id>/reports/supervisor-final.json` when finalization reaches
that stage. A missing report is a failure needing retained raw evidence.
Retain authenticated journals, command/result observations, schema bytes and
digest, native usage, path claims/candidate manifest, budget ledger, containment
and owned-process exit receipts. Do not treat exit 0 as sufficient evidence.

Independent acceptance must cite real source observations and inspect the
candidate (or justify rejection), preserve all default review lenses and
strong control roles, and verify no surviving owned child or outstanding
reservation. Never publish credentials, private journals or raw transcripts.
Record a redacted result with date, source/executable hashes, run id, exact
command, exit statuses, evidence locations, acceptance decision, remaining
unknowns and reviewer identity. Publication and integration are separate gates.
