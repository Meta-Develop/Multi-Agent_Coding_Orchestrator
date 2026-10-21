#!/usr/bin/env bash
set -euo pipefail

# Required exported inputs; machine-global.json and the user session already exist.
: "${maco:?Set maco to the absolute path of the built maco executable}"
: "${repo:?Set repo to the target repository}"
: "${base:?Set base to the directory containing machine-global.json}"
: "${run_id:?Set run_id to a fresh run id}"
: "${OUT:?Set OUT to the output directory}"
: "${XDG_RUNTIME_DIR:?Export XDG_RUNTIME_DIR}"
: "${DBUS_SESSION_BUS_ADDRESS:?Export DBUS_SESSION_BUS_ADDRESS}"
: "${MACO_GROK_BIN:?Export MACO_GROK_BIN}"

maco=$(realpath -- "$maco")
repo=$(cd -- "$repo" && pwd -P)
base=$(cd -- "$base" && pwd -P)
test -x "$maco"
test -f "$base/machine-global.json"
mkdir -p -- "$OUT"
OUT=$(cd -- "$OUT" && pwd -P)
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)

# Durable state binds the exact config bytes. Fail before any provider launch
# if a reserialized copy points at an already-bound shared state domain.
if ! "$maco" machine-global status --config "$base/machine-global.json" --json \
  >"$OUT/machine-global-status.json" 2>"$OUT/machine-global-status.stderr"; then
  cat -- "$OUT/machine-global-status.stderr" >&2
  echo 'Machine-global preflight failed. For a config mismatch, copy the established shared config byte-for-byte; do not reserialize it or reset its durable state.' >&2
  exit 1
fi

# The positional plan accepts an absolute path. Keep inputs outside the target
# repository so staging them does not dirty its primary worktree. Grok 4.6/xhigh
# uses the bundled prior; no --prior-data file or credentials need copying.
plan_dir=$(mktemp -d "$base/mixed-codex-grok-input.XXXXXXXX")
install -m 0600 -- "$script_dir/../examples/supervise/mixed-codex-grok-plan.json" "$plan_dir/plan.json"

# A plan parser alone can accept opaque notes from a newer checkout. Probe the
# same executable's goal lowering as well, before launching any native runtime.
"$maco" --version >"$OUT/maco-version.txt"
sha256sum -- "$maco" >"$OUT/maco-sha256.txt"
"$maco" supervise plan "$plan_dir/plan.json" --repo "$repo" --json \
  >"$OUT/checked-plan.json" 2>"$OUT/checked-plan.stderr"
python3 - "$plan_dir/plan.json" "$plan_dir/goal.md" <<'PYGOAL'
import json
import pathlib
import sys

plan = json.loads(pathlib.Path(sys.argv[1]).read_text())
pathlib.Path(sys.argv[2]).write_text(plan["task"], encoding="utf-8")
PYGOAL
"$maco" supervise plan --from-goal "$plan_dir/goal.md" --repo "$repo" --json \
  >"$OUT/generated-plan.json" 2>"$OUT/generated-plan.stderr"
python3 - "$plan_dir/plan.json" "$OUT/checked-plan.json" "$OUT/generated-plan.json" <<'PYCOMPAT'
import hashlib
import json
import pathlib
import sys

def contract_shape(plan):
    assignments = plan["assignments"]
    if not isinstance(assignments, list) or len(assignments) != 1:
        raise ValueError("expected exactly one direct execution worker; got "
                         f"{len(assignments)} assignments (paired/coordinator lowering is incompatible)")
    worker = assignments[0]
    if (worker["phase"], worker["role"], worker["role_category"]) != (
        "execution", "worker", "non_delegating_terminal_worker"
    ) or worker.get("worker_assignments"):
        raise ValueError("expected a direct non-delegating execution worker")
    notes = worker["notes"]
    if not isinstance(notes, str) or not notes.startswith("maco-preclaim-v1:"):
        raise ValueError("missing typed worker verification contract")
    directive = json.loads(notes.removeprefix("maco-preclaim-v1:"))
    if not isinstance(directive, dict) or set(directive) != {"verification_contract"}:
        raise ValueError("expected a verification contract without overrides")
    contract = directive["verification_contract"]
    binding = contract["execution_assignment"]
    for field in ("id", "phase", "role", "role_category"):
        if binding[field] != worker[field]:
            raise ValueError("verification contract is not bound to the worker")
    if binding["task_sha256"] != hashlib.sha256(worker["task"].encode()).hexdigest():
        raise ValueError("verification contract task digest mismatch")
    if not plan["resolved_routing_policy"] or not plan["task_routing_assessment"]:
        raise ValueError("missing replayable routing assessment")
    return {field: worker[field] for field in (
        "phase", "role", "role_category", "task", "assigned_paths"
    )}, contract["kind"], contract["assigned_path"]

def routing_shape(plan):
    policy = plan["resolved_routing_policy"]
    assessment = plan["task_routing_assessment"]
    if assessment["policy_sha256"] != policy["sha256"]:
        raise ValueError("routing assessment policy SHA-256 does not match the resolved policy")
    # Declaration digests bind assignment ids, which goal lowering may rename.
    # Compare the policy identity, provenance, and every derived feature instead.
    return (policy["sha256"], policy["source"], assessment["provenance"],
            assessment["features"])

try:
    authored, checked, generated = [json.loads(pathlib.Path(arg).read_text()) for arg in sys.argv[1:]]
    expected = contract_shape(authored)
    expected_routing = routing_shape(authored)
    for label, plan in (("checked plan", checked), ("goal lowering", generated)):
        try:
            if contract_shape(plan) != expected:
                raise ValueError("differs from the documented direct worker contract")
            if routing_shape(plan) != expected_routing:
                raise ValueError("differs from the documented routing policy, provenance, or features")
        except (KeyError, TypeError, ValueError) as error:
            raise ValueError(f"{label}: {error}") from error
except (KeyError, TypeError, ValueError) as error:
    sys.exit(f"Mixed-plan compatibility preflight failed: {error}. Rebuild maco from the reviewed checkout with an explicit --manifest-path; inspect maco-version.txt. No runtime was launched.")
PYCOMPAT

# --scope waits for maco and propagates its exit status. exec preserves it here.
exec systemd-run --user --scope --quiet -p Delegate=yes \
  --working-directory="$repo" -- \
  "$maco" supervise run "$plan_dir/plan.json" \
    --runtime codex --repo . --run-id "$run_id" --codex-bin codex \
    --machine-global-config "$base/machine-global.json" \
    --machine-global-runtime-root-id runtime --json \
    >"$OUT/run.json" 2>"$OUT/run.stderr"
