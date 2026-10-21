# Operator quickstart

One `maco supervise run` on Linux, or on WSL2 when that guest already has a
systemd user session. Native Windows is refused before spawn. The commands
below are the ones the CLI accepts.

## Host

Writable runs use the Linux systemd and cgroup v2 backend. Before spawn,
`delegated_systemd_user_manager_cgroup` reads `/proc/self/cgroup` and accepts
the process only when a unified `0::` line contains `user@<uid>.service`.
Otherwise admission fails with `current cgroup <path> is not inside a
delegated systemd user manager`. That manager cgroup must also expose
`cgroup.controllers` and `cgroup.kill`.

```bash
uid=$(id -u)
export XDG_RUNTIME_DIR=/run/user/$uid
export DBUS_SESSION_BUS_ADDRESS=unix:path=$XDG_RUNTIME_DIR/bus
repo=/path/to/target-repo
base=$XDG_RUNTIME_DIR/maco-e2e
```

A shell that is not already in that manager is placed there by:

```bash
systemd-run --user --scope --quiet -p Delegate=yes \
  --working-directory="$repo" -- <command>
```

`Delegate=yes` is the scope property this command passes. The Rust check
does not parse that property name. It requires the `user@*.service` membership
above. The delegated-scope CI script is for
ephemeral GitHub-hosted runners only. Do not enable lingering or start a user
manager as an install step.

Unverified: this repository does not document a `wsl.conf` stanza. The guest
must already be running systemd with `user@<uid>.service`.

Reviewed `machine-global.json` (version 1).
`state_root` and the runtime root are distinct owner-private `0700`
directories. The runtime root is a canonical directory inside `/run/user/<uid>`.
The config file is mode `0600`.

```bash
install -d -m 0700 "$base" \
  "$base/state" \
  "$base/runtime"
```

```json
{
  "version": 1,
  "state_root": "/run/user/UID/maco-e2e/state",
  "roots": [
    {
      "id": "runtime",
      "path": "/run/user/UID/maco-e2e/runtime",
      "protected_paths": [],
      "quarantine_grace_seconds": 86400
    }
  ]
}
```
For a new shared state domain, write this object once to `$base/machine-global.json`.
When reusing a state root, copy the config that established it byte-for-byte
(`install -m 0600 /path/to/established/machine-global.json "$base/machine-global.json"`).
Do not reserialize it: durable state binds the exact config bytes, including
whitespace. The same paths in differently formatted JSON are a different
binding. Do not delete or rewrite durable state to bypass a mismatch.
```bash
chmod 0600 "$base/machine-global.json"
```
JSON does not expand variables, so write the literal expanded value of `$XDG_RUNTIME_DIR` (for example `/run/user/1000`) in place of `/run/user/UID`. `--repo .` is
the git working directory passed as `--working-directory`.

## Build

Use the reviewed checkout explicitly, including when reusing a Cargo target
directory shared with another checkout:
```bash
checkout=/absolute/path/to/reviewed-checkout
nix develop "$checkout" --command cargo build \
  --manifest-path "$checkout/Cargo.toml" --locked --release --bin maco
maco="${CARGO_TARGET_DIR:-$checkout/target}/release/maco"
"$maco" --version
git -C "$checkout" rev-parse HEAD
```
The binary is `target/release/maco`, or `$CARGO_TARGET_DIR/release/maco` when `CARGO_TARGET_DIR` is set.
Its `source_revision` must match that checkout; `source_state=dirty` is expected
when building reviewed uncommitted changes. Version identity alone cannot prove
which uncommitted changes were included. Run the plan checks below with this
same executable before dispatch.

## Codex runtime

Prerequisites:

- Logical `codex` resolves to the first existing path of
  `/run/current-system/sw/bin/codex`, `/usr/bin/codex`, or `/bin/codex`. The
  canonical file must be a root-owned, executable, non-symlink regular file,
  not group- or world-writable, with non-symlink ancestors. Run
  `--version` on whichever of those three paths exists.
- For the Codex-only command below, pass the canonical trusted file as
  `--runtime-bin`. Logical `--codex-bin codex` is also supported for ordinary
  routing; an absolute path must canonicalize to the same trusted file.
- Catalog preflight runs `codex debug models` once, with a 30 second limit,
  and requires a validated `auth.json`.
- Unset `MACO_CAM_AUTHORITY_SOCKET` and `CODEX_HOME`. With the
  socket unset, a local CAM registry selection is used when one exists.
  Otherwise Codex reads `$CODEX_HOME/auth.json`, or `$HOME/.codex/auth.json`
  when `CODEX_HOME` is unset. `auth.json` must be a non-symlink regular file.
- Unverified: this repository does not document a vendor `codex login`
  command. Login stays owner-operated.
Set: `repo=/path/to/target-repo`, `base=$XDG_RUNTIME_DIR/maco-e2e`, `run_id=example-1`, `maco=/path/to/target/release/maco`. `goal.md` is a plain-text goal file the operator writes.
For the README append smoke test, `goal.md` contains exactly:

```text
Update `README.md`: append one final line that reads exactly `Hello from MACO`. Do not change any other file.
```

Start from a clean scratch repository with an existing tracked regular
`README.md`. Keep the goal file outside that repository. For a Codex-only
run, set `codex_executable` to the canonical path of the trusted Codex entry
above (for example, `readlink -f /usr/bin/codex`), then run:

```bash
unset MACO_CAM_AUTHORITY_SOCKET CODEX_HOME
"$maco" machine-global status --config "$base/machine-global.json" --json
timeout --signal=TERM 3600 systemd-run --user --scope --quiet -p Delegate=yes \
  --working-directory="$repo" -- \
  "$maco" supervise run --runtime codex --repo . --run-id "$run_id" \
    --from-goal "$base/goal.md" --only-runtime codex --runtime-bin "$codex_executable" \
    --machine-global-config "$base/machine-global.json" \
    --machine-global-runtime-root-id runtime --json
"$maco" supervise collect "$run_id" --repo "$repo" --json
```
`supervise run` prints JSON and exits 0 only when `follow_up_cascade_success`
is true. Otherwise it exits with `supervise run failed`. `collect` reads the
durable run and exits with `supervise run failed` when that report is not
success. `collect` is outside the scope.

`--runtime codex` names the primary runtime and permits automatic selection
of other observed runtimes. `--only-runtime codex` restricts selection and
launch to Codex and requires matching `--runtime codex` plus an absolute
`--runtime-bin`. It conflicts with `--additional-runtime-bin`. The executable
allowlist is frozen, archived, inherited by workers and follow-ups, and
restored on resume. An existing unrestricted run cannot acquire this
constraint on resume; use a fresh run id. No model, viability, or acceptance
gate is bypassed. Omit `--only-runtime` for the mixed plan below.

The durable report is
`<repo>/.maco/o2/runs/<run-id>/reports/supervisor-final.json`.

## Grok runtime

The bundled priors support Grok for bounded terminal Worker implementation,
and explicitly prohibit delegation, acceptance gates, review, audit, failure
classification, and publication authority. `supervise run --runtime grok`
therefore cannot pass supervisor selection with these priors: the supervisor
requires `review_gate` / `acceptance_gate` authority. Successful CAM login does
not grant that authority. Use Codex for supervision and control roles, with
qualified Grok models on direct Worker assignments as shown below.

Prerequisites:

- Complete the Codex prerequisites above as well as the Grok setup below.
- `MACO_GROK_BIN` is an absolute path to a non-symlink regular file. Ambient
  `PATH` and relative paths are refused. The Nix default
  `/run/current-system/sw/bin/grok` may be a symlink and is canonicalized. An
  explicit override may not itself be a symlink. Set
  `MACO_GROK_BIN=$(readlink -f "$(command -v grok)")`, then
  `test -f "$MACO_GROK_BIN" && test ! -L "$MACO_GROK_BIN"`.
  `$HOME/.grok/bin/grok` is an example install location. Use `readlink -f` on
  that path when `grok` is not on `PATH`.
- Bubblewrap is installed. Run `bwrap --version`. Headless and ACP launches
  pass the installed Grok 1.0.60 profile `--sandbox off` and force `--no-leader`.
  MACO requires its verified systemd containment, worktree-scoped writable
  binds, private home, credential isolation and current network policy before
  launch. The command report's `stderr` records
  `inner_sandbox=disabled_outer_containment_enforced`. No uncontained fallback
  is provided. MACO does not ship `bwrap`; install it with
  `sudo apt-get install -y bubblewrap`.
- A complete CAM `grok-cli` account must be selected. Grok has no local-auth
  fallback. `~/.grok` and `XAI_API_KEY` are not the launch path. With
  `MACO_GROK_BIN` set and no selection, catalog discovery fails closed:
  `live Grok catalog requires a complete Coding Agent Manager selected grok-cli account`.
- CAM data is `$XDG_DATA_HOME/coding-agent-manager`, or
  `$HOME/.local/share/coding-agent-manager` when `XDG_DATA_HOME` is unset.
  The managed home is `{data}/accounts/grok-cli/<id>`. Launch admits its
  exact `auth.json`, optional `config.toml`, and optional native
  `models_cache.json` into a private runtime `GROK_HOME` as held read-only
  files. The ambient managed home stays hidden; unrelated files are not
  exposed. MACO removes `GROK_AUTH_PATH` and `XAI_API_KEY`. The cache keeps its
  native bytes and identity metadata; its presence grants no model authority
  and does not establish model resolution, usage, or successful completion.
- Leave `MACO_CAM_AUTHORITY_SOCKET` unset unless that authority is the
  selection source. A configured socket with no carried Grok binding is a
  refusal.
- The Grok program comes from `MACO_GROK_BIN`; `--codex-bin codex` below
  configures the Codex control runtime. Held-out evaluation, where `--runtime-bin` must
  match `MACO_GROK_BIN`, is outside this quickstart.
- Unset `MACO_GROK_INTERACTION_PROTOCOL`. Unset, the protocol is
  headless streaming JSON. The only other accepted value is `acp_stdio`.
Owner device login. `cam-grok-setup` is Linux-only and does not start login.
The Nix `maco` package includes the binary. From a source checkout:
```bash
cargo run --locked -p coding-agent-manager --bin cam-grok-setup -- prepare <id>
```
`status` and `complete` are run with the same binary (either the Nix-installed `cam-grok-setup` or the same `cargo run --locked -p coding-agent-manager --bin cam-grok-setup --` prefix).

`<id>` cannot contain `__` or end with `_`. The documented example id is
`work`. `prepare` prints:
```text
env -u GROK_AUTH_PATH GROK_HOME='…' grok --no-auto-update login --device-auth
```
The owner runs that printed command in their own terminal and completes the
vendor device code. Then:
```bash
cam-grok-setup status
cam-grok-setup complete <id> --incarnation <n>
```
`<n>` is `accountIncarnation` from `status` for that pending account.
`prepare` does not select the account. `complete` validates `auth.json` and
selects it. `prepare` refuses an id whose managed home already exists. This
tool has no delete or overwrite command.

Unset:
```bash
unset MACO_CAM_AUTHORITY_SOCKET CODEX_HOME XAI_API_KEY MACO_GROK_INTERACTION_PROTOCOL
```
CAM model observation is separate from login. The Grok adapter reads
`{data}/accounts/grok-cli/<id>/models_cache.json`; an absent cache produces
`Unknown` model metadata. An observation without models or supported efforts
admits no candidates, even if a separate CLI listing succeeds. The native
cache must contain valid model/effort metadata; do not fabricate metadata or
copy credentials into it. Fresh device login alone may leave this prerequisite
unmet. Inspect `normalized_input.catalogs` in the final report's
`role_economics_profile.execution.selection_decisions[].provenance` for the
actual admitted catalog. `account-observe-models-unobserved-sha256:` with
`models: []` means CAM supplied no usable observed models. The work2 account's
operator-reported native catalog on 2026-10-17 lists `grok-4.7` (default),
`grok-4.7-build-fast`, `grok-4.6`, and `grok-4.5`, and its cache exists.
The run must still admit the selected model and effort from CAM-bound metadata.

Set: `repo=/path/to/target-repo`, `base=$XDG_RUNTIME_DIR/maco-e2e`, `run_id=example-1`, `maco=/path/to/target/release/maco`.
Copy the complete example plan for the exact README append task:

```bash
install -m 0600 examples/supervise/mixed-codex-grok-plan.json "$base/plan.json"
"$maco" supervise plan "$base/plan.json" --repo "$repo" --json
```

[examples/supervise/mixed-codex-grok-plan.json](../examples/supervise/mixed-codex-grok-plan.json) assigns one direct, non-delegating
Grok Worker to `README.md`, with `grok-4.6` / `xhigh` and fail-closed model
fallback. It also includes `resolved_routing_policy` and
`task_routing_assessment`. The assessment replays the exact declared task,
fragment, and worker scope against the bundled frozen policy. Its risk,
complexity, horizon, and context are explicitly `policy_heuristic`, not measured
runtime evidence. Omitting it leaves task risk unknown; selection refuses with
`task.risk must be known before candidate evaluation` even when preclaim passed.
The non-spawning JSON plan check validates the document and replay; it does not
check live account/catalog eligibility or run the selector. Notes are opaque to
that check, so parser success alone does not prove that an older executable
understands the verification contract. The wrapper also probes goal lowering.

The assignment repeats the exact literal edit task and carries a typed
`maco-preclaim-v1` verification contract bound to its id, phase, role, category,
path, and the SHA-256 of the assignment task's UTF-8 bytes (without a trailing
newline). The contract requests verification; it grants no override. Pre-claim
still requires acquired repository/risk evidence and a readable Git-visible
regular `README.md`. A vague task, or a missing or stale contract, is parked.
When changing this example, regenerate the whole plan from a bounded literal
goal on a host with trusted system Git. Preserve the generated policy,
assessment, assignment task, category, and verification contract; then add only
the Grok runtime/model binding. For example:

```bash
python3 - "$base/plan.json" "$base/goal.md" <<'PYGOAL'
import json
import pathlib
import sys

pathlib.Path(sys.argv[2]).write_text(json.loads(pathlib.Path(sys.argv[1]).read_text())["task"])
PYGOAL
"$maco" supervise plan --from-goal "$base/goal.md" --repo "$repo" --json > "$base/generated-plan.json"
python3 - "$base/generated-plan.json" "$base/plan.json" <<'PYPLAN'
import json
import pathlib
import sys

plan = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert plan["resolved_routing_policy"] and plan["task_routing_assessment"]
[worker] = plan["assignments"]
assert worker["role"] == "worker"
assert worker["role_category"] == "non_delegating_terminal_worker"
assert worker["assigned_paths"] == ["README.md"]
worker["runtime"] = "grok"
plan["role_models"] = {"worker": {
    "model": "grok-4.6", "reasoning_effort": "xhigh",
    "unavailable_model_fallback": "fail_closed",
}}
pathlib.Path(sys.argv[2]).write_text(json.dumps(plan, indent=2) + "\n")
PYPLAN
"$maco" supervise plan "$base/plan.json" --repo "$repo" --json
```

Generated assignment ids can differ from the shipped plan. Do not substitute a
new task into hash-bound notes or edit assessment scores/digests by hand.

The verification path is to preserve the original README bytes, append the
single literal line with a terminating newline, run `git diff --check`, and
confirm the diff and changed-path list contain only that append to `README.md`.
The shipped plan includes these execution and verification steps in both the
root task and assignment task. It also tells the worker to omit optional
`--changed-path`, letting the wrapper derive each operation's changes. A
read-only check must not declare an earlier edit as a change made by that check.
The worker must follow the supervisor's execution-journal instructions;
Codex control roles review the evidence before acceptance.

This requests the existing `grok-4.6` terminal-worker prior and its `xhigh`
selector effort; both must be supported by the account's observed catalog.
It is a supported routing configuration, not a guarantee of current provider
availability. Unknown or newer model ids need an evidence-backed operator
prior via `--prior-data` before use; a similar name is insufficient. Keep
delegating assignments and all control roles on Codex. The remaining role
models are selected automatically; the explicit Worker preference cannot
bypass qualification gates.

The supervisor plan is **positional**; there is no `--supervisor-plan` flag.
`--from-goal FILE` is an alternative source that decomposes a goal/spec and
conflicts with the positional plan. Use the positional JSON plan to preserve
this authored worker runtime and role category. Direct workers must explicitly
declare `role_category: non_delegating_terminal_worker`; a `role: worker` alone
is rejected. Unspecified control roles use the selected `--runtime codex`.

`--prior-data` is **optional**, including with a positional plan. Omit it for
this `grok-4.6` / `xhigh` example: the supervisor adds the bundled terminal
economics to the base selector priors. An error's contextual `Usage:` line
can include supplied options; use `--help` to establish the contract.
If extending the evidence for a new model, `--prior-data` must name a regular,
non-symlink file **relative to the target repository**. It contains strict JSON
`OperatorPriorSnapshot` version 1: `schema_version`, `dataset_id`, `revision`,
`published_on`, `models` (dated `ModelPrior` rows), and `capability_policy`
(`id`, positive `version`, `source`, `models`). Capability rows require `model`,
`capability`, explicit `eligible`, dated `as_of`, and `evidence`. A raw catalog,
plan, credentials, or the bundled version-2 `PriorDataset` file is not this
format. Rows extend or update bundled evidence, must satisfy the validation
and date floors (the bundled dataset is published 2026-10-15), and do not
replace live catalog or authority gates. `models` arrays may be empty to retain
the bundled rows; the optional file is unnecessary for that case. See the
full [`ModelPrior` fields](../src/selection/types.rs#L317) for prior rows.

Evidence from this checkout (`"$maco" supervise run --help` and
`"$maco" supervise plan --help`, abbreviated):

```text
Usage: maco supervise run [OPTIONS] [SUPERVISOR_PLAN]
Arguments:
  [SUPERVISOR_PLAN]  JSON supervisor plan file to run
Options:
  --from-goal <FILE>                 High-level goal/spec file to decompose and run through the supervisor gates
  --only-runtime <ONLY_RUNTIME>     Restrict selection and dispatch; requires matching --runtime and absolute --runtime-bin
  --prior-data <REPO_RELATIVE_FILE>  Repository-relative strict versioned operator prior/capability snapshot

Usage: maco supervise plan [OPTIONS] [TASK_FILE]
  [TASK_FILE]  Plain-text task/spec file or JSON supervisor plan file
```

The argument declarations and source exclusivity are in
[`RunSuperviseArgs`](../src/cli.rs#L1815); optional prior binding is in
[`SuperviseSubcommand::Run`](../src/cli.rs#L1299). The prior format and bounded
repository-local reader are in
[`prior_input.rs`](../src/supervise/prior_input.rs#L48), with row merging and
validation in `bind_from_bytes`. The bundled Grok prior is constructed in
[`base_selector_priors_with_terminal_worker_economics`](../src/supervise/selection_bridge.rs#L2518),
using [`grok-4.6` / `xhigh` constants](../src/optimizer/objective.rs#L479).
The explicit worker category check is in
[`validate_supervisor_plan_in_repo`](../src/supervise/plan_validation.rs#L349).

Validate locally without starting a runtime:

```bash
"$maco" supervise plan "$base/plan.json" --repo "$repo" --json
```

Check the existing machine-global state before launching either runtime:

```bash
"$maco" machine-global status --config "$base/machine-global.json" --json
```

A config mismatch must be corrected by supplying the established config,
without resetting the shared state. External-agent staging also checks the
durable binding before allocation, so an incompatible config cannot launch a
provider and fail only when cleanup is attempted.

Run the mixed plan:

```bash
timeout --signal=TERM 3600 systemd-run --user --scope --quiet -p Delegate=yes \
  --working-directory="$repo" -- \
  env MACO_GROK_BIN="$MACO_GROK_BIN" \
  "$maco" supervise run "$base/plan.json" \
    --runtime codex --repo . --run-id "$run_id" --codex-bin codex \
    --machine-global-config "$base/machine-global.json" \
    --machine-global-runtime-root-id runtime --json
"$maco" supervise collect "$run_id" --repo "$repo" --json
```
The report path is the same
`<repo>/.maco/o2/runs/<run-id>/reports/supervisor-final.json` path as Codex.

The example [`examples/supervise/mixed-codex-grok-plan.json`](../examples/supervise/mixed-codex-grok-plan.json)
and executable [`scripts/run-mixed-codex-grok.sh`](../scripts/run-mixed-codex-grok.sh)
use this contract for the exact README append task. Export `maco`, `repo`, `base`,
`run_id`, and `OUT` together with the session and Grok variables above, then
run `./scripts/run-mixed-codex-grok.sh` from the checkout root (Python 3 is required).
The script first saves the non-spawning shared-state
check to `$OUT/machine-global-status.json` and `$OUT/machine-global-status.stderr`,
then copies the plan into a fresh directory under `$base`. It records the
executable identity in `$OUT/maco-version.txt` and `$OUT/maco-sha256.txt`, validates the plan into
`$OUT/checked-plan.json`, and lowers its exact task via non-spawning
`supervise plan --from-goal` into `$OUT/generated-plan.json`. The generated plan
and normalized checked plan must retain the same direct-worker verification
contract, task, scope, resolved policy SHA-256 and source, assessment policy
SHA-256 and provenance, and every routing feature value (including risk,
complexity, horizon, and context tokens). Generated assignment ids and their
declaration digests can differ. Exactly one direct non-delegating execution
Worker is required;
paired planning/execution coordinators and extra workers are incompatible with
this example. A mismatch fails before runtime launch with the failing plan and
contract check named; rebuild using the explicit manifest path above.
The captured `e2e-mixed-r39v1b` generated plan had two coordinators, a nested
worker, and no typed verification contract or routing assessment. That output
cannot be accepted as equivalent to this plan. Its `maco-version.txt` reported
`a3988f8a73e50e7749c223b3b67cd964648e7396` / `clean`; verify the rebuilt
executable's recorded identity and behavior before retrying.
The scratch goal and plan stay outside the target repository. The script writes run
stdout to `$OUT/run.json` and stderr to `$OUT/run.stderr`,
and returns maco's status through `systemd-run --scope`. Use a fresh run id and
a clean target repository; the plan copy requires no target-repository change.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `current cgroup <path> is not inside a delegated systemd user manager` | The process is outside `user@<uid>.service`. Re-run under `systemd-run --user --scope --quiet -p Delegate=yes` with `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` set as above. The user session must already be up. |
| Sandboxed or hosted runner with no systemd user manager. Tests print `SKIP <test>: current cgroup <path> is not inside a delegated systemd user manager`. | Same admission rule. GitHub-hosted runners do not provide that manager. The delegated-scope CI script is only for those ephemeral runners. |
| `explicit Grok executable may not be a symlink` | `MACO_GROK_BIN` is a symlink. Set it with `readlink -f` to the real file, then `test -f` and `test ! -L`. |
| `CAM model/effort metadata is unobserved or unusable` | CAM login completed but no usable model observation was supplied. Check the selected account's native `models_cache.json` and the saved selector catalog; a separate CLI listing does not replace CAM-bound metadata. |
| `the loaded Grok priors explicitly prohibit this judgment authority` | Use the mixed Codex-control / Grok-Worker plan above. The bundled Grok priors do not authorize supervisors or other judgment roles. |
| `You are not authenticated.` followed by a valid `grok models` listing, exit 0 | Grok 1.0.60 prints this banner even for a working CAM work2 session. Catalog discovery ignores auth banners and flags, records `auth=not_asserted_by_catalog` in catalog revision evidence, and checks only bounded valid model availability, successful exit and verified containment. Do not renew login based on this banner. |
| `provider_auth_required` in a Grok worker failure | The worker inference emitted a 401/403/unauthenticated error in its stream or bounded private native inference log. The run fails closed as an environment authentication failure. Check the selected CAM account's native login; a model listing cannot establish authentication. |
| `network_unavailable` with native `dns error: failed to lookup address information` | Grok's own `strict` profile prevented inference DNS on the WSL host, where `/etc/resolv.conf` resolves to `/mnt/wsl/resolv.conf`. An earlier resolver-profile run also returned no tool progress. MACO now passes `--sandbox off` inside required outer containment; inspect the bounded redacted native inference tail. |

The round-1 `e2e-r34-readme` run was labeled Codex-only but its selection ledger
chose `grok:grok-4.6:xhigh`. The worker timed out after 1200 seconds with only
`available_commands` events and no terminal report or usable usage evidence.
That capture does not establish why the provider stalled. A verified-empty
process tree remains containment evidence on a failed/timed-out adapter run;
it does not prove successful completion or authorize acceptance. Missing
native usage stays unknown. Inspect the command record's `timed_out`, `error`,
and raw log alongside the selection ledger before diagnosing a host
containment problem.

The round-3 evidence (`e2e-mixed-r36r2`) passed preclaim and selection but again
timed out after 1200 seconds with only two `available_commands` events. No
WorkerReport or README diff was produced; the independent auditors therefore
rejected missing implementation and validation evidence. Their process records
also report `failed to clean private external-agent output staging:
machine-global config changed; refusing to reinterpret durable state`, despite
exit code 0 and complete Codex model/usage evidence. The run supplied a 201-byte
config while shared state was bound to the established 239-byte config. Copy
the established shared config unchanged for subsequent runs.

The launch code previously projected only Grok auth/config into its private
home, dropping the selected CAM account's native model cache even when CAM
used that cache for selection. It now projects that exact optional cache
read-only. This fixes the loss of runtime input; the captured timeout does not
identify the native provider's internal stall. Live mixed and Codex-only
success/acceptance still require an external run with valid shared config and
native runtime evidence. Missing usage and missing final reports remain
unknown/failed, respectively.

The R37 capture (`e2e-mixed-r37v0`) instead stopped before any assignment started:
`assignment 'readme-worker' has an invalid requested-plan maco-preclaim-v1 directive`.
The captured plan has the correct task digest and the direct-worker contract.
The release executable found in the C target directory reports
`source_revision=a3988f8a73e50e7749c223b3b67cd964648e7396`, `source_state=clean`;
its Cargo build record names `/mnt/d/home/repos/github.com/Meta-Develop/Multi-Agent_Coding_Orchestrator`,
whose contract enum supports only the paired variants. It lacks
`direct_existing_git_visible_regular_file_edit`. The reviewed C checkout is
`f57624faede65ace53ff2966ac3f515338f7bb8a` plus uncommitted changes and supports
that variant. This executable mismatch predicts the observed parser refusal;
the R37 capture does not record an executable hash, so its use of this on-disk
binary is an inference. It supplies no new evidence about Grok execution or usage. The wrapper's goal
lowering preflight detects this incompatibility without a provider launch.

The subsequent `e2e-mixed-r37r1` capture passed the current direct-worker
contract: `clear_verification_path=yes` and `disposition=claim`. It selected
`grok:grok-4.6:xhigh`, then recorded `external agent timed out after 1200
seconds` (1202436 ms). The entire worker transcript consists of two
`available_commands` events; there is no text, tool call, terminal event,
WorkerReport, validation result, or changed path. The first parent auditor
reported: `the complete child transcript contains only command-availability
events and no terminal WorkerReport for assignment 'readme-worker'` and
`No validation results were supplied for the assigned README.md scope`.
All parent review lenses rejected the missing execution evidence. No shared
config cleanup error appears in this capture. The older executable mismatch
and config reserialization therefore do not explain this later timeout.

The standalone diagnostic is [`scripts/diagnose-grok-launch.sh`](../scripts/diagnose-grok-launch.sh).
Its R38 capture initially failed even `--help` with
`No such file or directory`: `ProtectHome=tmpfs` hid its home-installed Grok
executable. The existing diagnostic's exact executable bind fixes that separate
harness defect. Later H (AF_NETLINK allowed) and I (no SystemCallFilter) still
stalled; J resolved `api.x.ai` and `grok.com` inside Grok's tool bwrap. Those
results do not justify changing MACO's systemd or outer bwrap policy. The
uncommitted R38 diagnostic fixes are retained for their demonstrated harness
issues; no additional diagnostics or speculative outer-policy changes are added.

R39's parent-host isolation on WSL with Grok 1.0.60 established the inference
failure independently of MACO. With `--sandbox strict`, the private native log
recorded five `shell.turn.inference_retry` failures:
`client error (Connect): dns error: failed to lookup address information: Try again`
for `https://cli-chat-proxy.grok.com/v1/responses`; stdout contained only
`available_commands` and the process hit the 90-second timeout. The otherwise
identical invocation without `--sandbox` answered in seconds with `rc=0` and
text/usage/end events. `/etc/resolv.conf` resolves to `/mnt/wsl/resolv.conf`,
with nameserver `10.255.255.254` (WSL DNS tunnelling). The latest production
capture, `e2e-mixed-r38b1`, recorded `timed_out=true`, 1202812 ms, and only two
`available_commands` events. Its missing implementation/report and the parent
review rejection follow from that failure; they provide no usage evidence.

The first R39 fix supplied a strict-derived resolver profile. It restored
inference in `e2e-mixed-r39t1`, but the worker still performed no tools. Its
held report said `status: pending`, `remaining_risk: Assignment not started.`,
with empty `commands_run` and `files_changed`. The resulting report records
`stacked review-lens gate did not accept: ProceduralFailure`. Preclaim had
already recorded `clear_verification_path=yes`, `disposition=claim`, so this
was not a plan viability gap. The parent then tested the exact assignment
prompt and schema without the inner profile: 12 tool calls at xhigh and 16
at default effort before its 300-second probe timeout. The same prompt with
`--sandbox strict` produced no tool calls or model output in 150 seconds.
Those probes supported disabling the inner profile. The subsequent
`e2e-mixed-r39u1` run confirms tools execute with `off`: its native stream has
10 `tool_call` events and the diff appends the requested line. This supersedes
the earlier claim that the inner profile was the only remaining cause.

Headless Workers and reviewers, and ACP launches, now explicitly select
`--sandbox off`. The installed binary's embedded documentation lists
`off, workspace, devbox, read-only, strict` and says
`Sandbox disabled (profile: off)`; `--no-leader --sandbox off --help` parses
successfully. `--no-leader` keeps tools in the contained process rather than
attaching to a shared leader. The unused `maco-strict-resolver` profile and
its private-file generation are removed; regression tests assert both launch
templates select `off` and need no resolver profile. This removes the inner
restriction on WSL's resolved resolver target. The selected CAM
credentials/config/cache, systemd `ProtectSystem=strict`, `ProtectHome=tmpfs`,
`PrivateUsers`, exact writable binds, inaccessible credential roots and
existing bwrap/network policy remain required. Astra and the bundled Grok
authority limits remain enforced. The command report's `stderr` records
`inner_sandbox=disabled_outer_containment_enforced`; containment failure
refuses release. The R34 plan and wrapper's `maco repo base run_id OUT`
interface and byte-for-byte shared machine-global config remain unchanged.

A bounded, successful headless Worker stream returning `pending`/not-started
with no tool events or commands is `worker_no_progress`. MACO permits exactly
one `--resume <sessionId>` inside the same contained unit/private `GROK_HOME`,
with the prompt `Perform the assignment now using your tools, then return the
final report.` The continuation keeps the original total deadline, model,
effort, schema and restrictions. A second idle report, invalid session ID,
or changed resumed session fails closed; ordinary review and acceptance still
apply to progress. Native spend from both turns is retained for private budget
accounting; missing usage stays incomplete. The report's stream-usage evidence
continues to describe the final captured stream only.

Before destroying a failed/timed-out Grok unit's private home, the runner reads
at most the last 64 KiB of `logs/unified.jsonl` and retains up to eight inference
failure entries. Free-form fields are redacted into allowlisted event/error
labels. Observed DNS/connect failures are classified `network_unavailable`
environment failures, preventing model-quality attribution. A timeout alone,
missing logs, or other inference errors leave the cause unknown; usage and
completion still require their native evidence. Unit tests cover launch argv,
outer policy, bounded continuation and its failure path. The latest live results
and remaining Codex issue are recorded below.

`e2e-mixed-r39u1` failed after editing, with `exit_code=0`, `timed_out=false`,
and `runtime adapter output validation failed: Grok runtime returned a terminal
structuredOutputError`. The terminal error says the absolute worker `cwd`
`does not match` the published relative-path pattern. This was a code contract
conflict: the worker must copy the absolute journal `cwd` byte-for-byte, while
the launch schema incorrectly used the public report path constraint. Private
terminal WorkerReport schemas (native and Codex) now admit a nonempty exact
journal cwd; the parent still rejects a command/cwd pair absent from the held
journal. Public aggregate schemas retain their path restrictions.

The native log contains 10 `tool_call` events and a final `end` whose
`structuredOutput` is null, with `structuredOutputError` identifying that schema
mismatch. It also begins with premature text JSON containing `commands_run: []`
and `files_changed: []`. That text is progress, not a final report. The adapter
uses the last completed turn's `end.structuredOutput` as authoritative. If a
bounded same-session continuation contains two ends, only the last supplies the
report. An explicit native schema error still fails closed. When structured
output is absent without a native schema error, a direct worker may fall back
only to the last complete unwrapped JSON object after its final native tool
call/update, validated against the exact schema bytes held from launch argv.
Text preceding a later tool call, malformed tails, changed sessions, extra
continuations and post-terminal data cannot supply a report. The result goes
through the same descriptor-held staging/capture path used for Codex; ordinary
journal reconciliation, actual Git-path inspection and pre/post-audit candidate
content binding still apply. Wire reports cannot recreate that private custody.

The bound `journal-append` operation now accepts `--auto-timestamps` instead of
explicit start/end arguments. Use the exact provided prefix followed by
`--cwd <exact assigned worktree> --auto-timestamps -- <original argv>`; the wrapper
gets real UTC timestamps itself and records the end after command execution.
Codex and Grok workers must run `journal-append` commands one at a time, never
in parallel tool calls, including read-only validations. Wait for completion
before starting the next invocation. Accidental concurrent appends wait for the
exclusive journal lock for up to 30 seconds; a timeout fails closed without
executing the waiting command or replacing or repairing the journal. Each lock
covers the complete observation, command execution and durable append sequence.
Do not run `date`, invent timestamps, or execute the command separately. For
native edits, call the prefix with
`--cwd <exact assigned worktree> --auto-timestamps --observe-changes -- true`
before editing and immediately after editing. These times describe observations,
not an unobserved edit's execution time. With this default protocol both records
contain `["true"]`: report those observations and wrapped verification commands
in `WorkerReport.commands_run`, and describe the native edit in findings. Omit
the native `apply_patch`/`Edit` command itself from `commands_run`.
If the report needs native `apply_patch` argv, replace only the post-edit
observation's `-- true` with `-- apply_patch '<exact full native patch>'`, passing
the complete patch as one shell-quoted argument. Observation never executes argv;
do not apply the patch again. Only that payload-bearing record supports the exact
`["apply_patch", "<exact full native patch>"]` command in the report. A `true`
observation and observed content digests do not establish a native tool's argv.
Legacy explicit timestamp pairs remain
supported and cannot be combined with `--auto-timestamps`. Journal identity,
observed content continuity and terminal failure checks still apply.
`WorkerReport.commands_run` copies the inner command array and exact absolute
cwd from the journal. Avoid reporting wrapper argv; repeated automatic-timestamp
wrappers remain ambiguous and cannot be matched to a particular journal row.

The same run invoked `tail -n 1 README.md` with `--changed-path README.md`.
The wrapper printed `Hello from MACO` then correctly failed with
`declared --changed-path values do not match observed changed paths; mismatch
preserved in journal; stop`. The command did not change any bytes. The worker
subsequently claimed `status=succeeded` despite that failure. The plan and
shared journal instructions now explicitly say to omit that optional flag for
read-only validation, and to report a failed terminal outcome after an append
error. The missing valid WorkerReport, empty validation coverage and parent
review rejection follow from these failures; they are not DNS evidence.
The subsequent mixed result and Codex regression are recorded below.

The parent subsequently verified `e2e-mixed-r39x1` with `success=true`,
`accepted=true`, 14 Grok tool calls, three accepting Codex auditor lenses and
complete native usage. The Codex-only `e2e-codex-r39x1` encountered HTTP 429 in
all three auditor lenses; that is a transient provider failure. The follow-up
`e2e-codex-r39x1b` exposed a separate guidance regression. Its native Codex log
records a completed `fileChange` appending `Hello from MACO`. Its journal records
two `command:["true"]`, `phase:"native_edit"` observations, the second with
`changed_paths:["README.md"]` and a content digest. But the worker's incoming
report also listed `command:["apply_patch", "*** Begin Patch…"]` without a
matching journal entry. The supervisor correctly reported `commands_run entries
are not supported by execution journal`; the implementation lens agreed that
the diff was correct but `Required execution provenance is inadequate`.

Compared with `f57624fa`, the automatic-timestamp guidance newly directed the
worker to repeat the same `--observe-changes -- true` prefix after the edit,
while retaining the instruction `Preserve the full apply_patch record when
recording native tool argv`. This conflated observed bytes with command identity.
The shared worker guidance now distinguishes the two supported protocols above,
including what to omit from the report. The exact command/cwd journal check is
unchanged. Because that check rejected the child, the supervisor did not capture
a pre-auditor accepted candidate; the later `accepted report has no pre-auditor
supervisor candidate binding` diagnostic and review rejection follow from the
same provenance failure. They do not justify bypassing candidate binding.
Regression coverage exercises native edits with both observation protocols and
wrapped Grok-style edits using real journal snapshots, accepts exact report
commands, and rejects an unjournaled or altered native patch. The parent must
rerun both live paths after this guidance correction.

The subsequent `e2e-mixed-r39r1` run stopped before worker launch with
`live Grok catalog observation failed closed` caused by
`Grok runtime model catalog requires owner authentication`. Its preclaim
record says `clear_verification_path=yes`, `disposition=claim`; no worker
transcript, native inference tail, or final report exists. The refusal came
from MACO's pre-existing catalog-header check in `f57624fa`, not a new R38b2 or
R39r1 authentication check. Comparing those patches shows cache projection,
resolver-profile and failure-evidence changes, but no change to that check.

At 21:44 JST the parent ran the same CAM work2 account without the inner
sandbox and received `rc=0` with text/usage/end. At 21:45 it also confirmed
`grok --no-auto-update models` returned exit 0 and the full list including
`grok-4.6` after printing `You are not authenticated.` Its native log recorded
`auth: silent refresh Renewed` and `has_cached_token=true`. An expired token
on disk does not establish a failed refresh or an invalid session. The stopped
worker's renewal prerequisite and negative-banner regression were based on
that unsupported inference and have been removed. No owner login is needed
for the account established valid by this evidence.

The subsequent `e2e-mixed-r39s1` stopped with
`Grok runtime model catalog native authentication evidence is unobserved`.
Its real preclaim record again says `clear_verification_path=yes`,
`disposition=claim`, and it has no worker transcript. The added native-auth
boolean requirement was another false catalog gate: `models` does not establish
session authentication. The partial R39s2 workaround added a separate ACP
initialization solely to obtain that boolean. Both that probe and all native-auth
boolean parsing, plumbing and catalog refusals have been removed.

The parent's 22:20 JST directive establishes that the same work2 home always
prints `You are not authenticated.` followed by the full model list, exit 0,
while direct inference succeeds with a reply and `rc=0`. No catalog banner or
auth flag is a valid authentication signal. Catalog observation now establishes
only availability: bounded complete parseable model output, successful exit,
verified empty process ownership and verified confinement. The requested model
must still be available to selection. Display preamble is ignored; the model
list grammar, completeness and duplicate/default checks remain enforced.
Catalog revision evidence explicitly records `auth=not_asserted_by_catalog`;
model access remains unasserted. No extra auth process is launched.

Authentication is established by worker inference. Bounded worker error events
(including ACP JSON-RPC errors) or the redacted private native inference tail
reporting 401/403/unauthenticated fail closed as `provider_auth_required`.
Successful response text mentioning those strings does not establish an auth
failure. DNS/connect failures remain `network_unavailable`; timeout alone and
missing evidence remain unknown. These environment failures cannot produce
acceptance or model-quality evidence. Selected CAM binding, credential
isolation and all MACO gates remain in force. The subsequent
`e2e-mixed-r39z1` and `e2e-codex-r39z1` reports both recorded `success=true`
and `accepted=true` with the worker-guidance correction (integrated as
`cd794fec`). Those results precede the script relocation and stricter routing
comparison documented here; both live paths still need rerunning for this revision.
