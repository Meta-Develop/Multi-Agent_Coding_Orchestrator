# Multi-Agent Coding Orchestrator

Rust CLI and runtime foundation for a local-first multi-agent coding orchestrator.

## Project Purpose

This project is a local-first control plane for coordinating multiple coding
agents against one Git repository. It is designed to isolate work in disposable
Git worktrees, reserve edit boundaries with path claims, run validation, collect
agent output, and eventually integrate LLM-backed coding agents without letting
provider-specific behavior bypass the local safety model.

The goal is not only to call an LLM. The goal is to make parallel coding work
reviewable and recoverable:

- understand the repository before splitting work
- assign each agent a clear set of files or directories
- run each agent in an isolated worktree
- prevent overlapping edits through shared path claims
- collect diffs, summaries, validation results, and patches
- preview and apply merge candidates with conflict reporting

## Current Status

The current implementation covers a local-first command-line slice:

- `maco init` initializes a Git repository.
- `maco worktree create <agent-id>` derives the capability-bound repository cleanliness input at command start: creation proceeds only when the primary repository is observed clean, and a dirty primary fails with the required remedy.
- `maco worktree list` lists verified registered agent worktrees. `maco worktree pending` is a strict existing-only authenticated reader: absent state returns an empty list, while transitional or invalid state is refused without creating locks, migrating, scavenging, recovering, or writing.
- `maco worktree remove <agent-id> --force` performs explicitly authorized cleanup of authenticated managed state; non-force removal is temporarily disabled.
- `maco worktree gc` removes clean, inactive managed worktrees while retaining branch refs, protects tracked changes and unapproved untracked-only lanes plus active leases/claims, supports an exact repeatable untracked-path allowlist for reviewed full-lane cleanup, offers a liveness-checked target-only mode that retains lanes and branches, removes retained `target/` build artifacts by default, supports dry-run and max-age/max-count/apparent-byte retention filters, reports estimated reclaimable and reclaimed bytes, and routes unregistered leftover directories through recoverable machine-global quarantine.
- `maco worktree sweep --workspace <path>` discovers both workspace-managed `.maco/worktrees/<repo>` roots and exact repository-local `<repo>/.worktrees` roots, then aggregates the existing per-root GC reports. It is dry-run by default; removal requires `--apply`, an unresolved repository is reported as a typed per-root failure without aborting later roots, and a total discovery miss is reported separately from an inspected root with nothing to reclaim.
- `SyncCoordinator` provides an in-memory exclusive path-claim layer for local agent coordination.
- `maco sync claim <agent-id> <path>...` records durable exclusive path claims.
- `maco sync release <token>` releases one durable claim.
- `maco sync release-agent <agent-id>` releases all claims for an agent.
- `maco sync owner <path>` reports the owner of a path, if one exists.
- `maco sync status` lists active durable claims.
- `maco repo map` prints a read-only repository file map with coarse file
  categories and Git status while excluding runtime-only `.maco` output and
  local `.agents/temp`, `.agents/storage`, and `.agents/live` coordination data.
- `maco repo map --semantic` builds a parser-backed Rust semantic map for modules, symbols, impls, imports, public re-exports, module declarations, import dependencies, and parse errors.
- `maco repo query symbol <name>` and `maco repo query path <path>` search the semantic Rust map.
- `maco repo query risk --path <path> --json` reports touched symbols, dependency impacts, and impacted files for changed Rust paths.
- `maco coord preview/claim/status/release/release-agent` provides standalone
  repo-local semantic intent coordination for paths, modules, and symbols
  without automatic task planning.
- `maco orchestrate validate <plan-file>` validates a local JSON orchestration plan.
- `maco orchestrate run <plan-file>` runs a local JSON orchestration plan. Verified assignment creation derives the capability-bound repository cleanliness input before creating managed worktrees; a dirty primary repository fails with the required remedy.
- `maco orchestrate resume <checkpoint-file>` authenticates the repository-bound v3 journal, validates repository HEAD, plan snapshot, worktree metadata, path boundaries, and claims, then reruns validation/capture for completed commands without rerunning those commands.
- `maco worktree diff` collects a registered agent worktree diff and uses active sync claims when `--claim` is omitted.
- `maco orchestrate collect` reads a prior JSON run summary and builds merge candidates with validation reports from agent summaries.
- `maco merge preview` and `maco merge apply` collect one stable agent snapshot and gate primary-worktree integration with dirty-primary, stale-base, unclaimed-edit, candidate-bound validation, and apply-check safety reports. Their JSON reports also include advisory semantic classification for overlapping symbols, impls, modules, imports, signatures, and dependent files. Both commands accept external validation JSON with `--validation-report`; `--require-validation` accepts passed reports only when their envelope contains the exact current `candidate.validation_binding` (or a passed `merge apply --validation-command`).
- `maco merge apply --validation-command <command>` validates a temporary merged
  candidate before mutating the primary worktree. A command failure or a
  recursive candidate-state change, including an initialized or uninitialized
  submodule change, blocks the apply and leaves the primary worktree unchanged.
- `maco pr preview` checks whether an agent worktree or `--from-branch` task branch is ready to publish without contacting a forge.
- `maco pr publish --forge fake|github` turns a safe agent worktree result into a local agent-worktree commit when validation is not required, or publishes a committed `--from-branch` task branch through the same gates. `--squash-onto <base>` builds a deterministic import commit on a disjoint base lineage, and `--exclude <path>` refuses referenced-but-missing exclusions. Publication re-previews the exact candidate before either emitting a deterministic fake PR URL or, with explicit `--forge github`, publishing an OID-bound remote ref and verifying the resulting GitHub receipt. A durable transaction journal reconciles a lost push or `gh` response when the same command is rerun. With `--require-validation`, publication is a two-stage workflow: commit or preview first, validate that exact binding, then publish with the bound envelope.
- `maco issue preview` redacts issue bodies without creating anything.
- `maco issue create --forge fake|github` creates a deterministic fake issue URL locally or, with explicit `--forge github`, shells out to `gh issue create`.
- `maco live status`, `maco live validate`, `maco live apply`,
  `maco live heartbeat`, `maco live release`, and `maco live override-release`
  expose and safely mutate repo-local Markdown claim liveness for active,
  blocked, ready-for-review, handoff, and done work.
- `maco llm providers` and `maco llm prompt-preview` expose the provider-neutral prompt boundary without network calls.
- `maco agent run` executes one agent assignment in an isolated managed worktree. Verified assignment creation derives the capability-bound repository cleanliness input before creating the worktree; a dirty primary repository fails with the required remedy.
- `maco supervise plan <task-or-plan-file>` normalizes the existing plain-text
  task or JSON plan form, while `maco supervise plan --from-goal <file>`
  explicitly decomposes a high-level goal/spec into a validated full supervisor
  plan.
- `maco supervise run <task-or-plan-file>` and
  `maco supervise run --from-goal <file>` accept the same mutually exclusive
  positional-plan or high-level-goal inputs as `supervise plan`, then execute
  the resulting validated plan through the live supervisor gates. Optional
  `--role-category` stamps every assignment (and nested worker assignment) as
  `selection_source=operator_override`; omitting it keeps automatic selection
  derived from the plan role. Resume of an existing run refuses a new
  `--role-category`. The command selects the Codex runtime by default. Normalized planning-phase Codex
  children receive a read-only workspace and read-only access to their own Git
  worktree metadata in both the outer systemd containment and inner Codex
  permission profile. Only their exact private final-message staging root is
  writable. Execution-phase children retain native workspace-write and their
  existing bounded writable Git metadata; the optional app-server duplex
  reviewer is not their release path. Writable access to the
  primary checkout remains fail-closed because Codex cannot force a blocking
  client callback for every in-sandbox action. The command requires
  `--machine-global-config` and
  `--machine-global-runtime-root-id` so private runtime output-staging cleanup
  cannot silently take the unbound deletion bypass. The private staging
  directory is created beneath that exact reviewed runtime root, not an
  independently discovered per-user runtime directory. It still acquires the repository-cleanliness
  capability and creates capability-bound managed child worktrees before that
  safety gate. External child sessions receive the three report contracts as
  individually validated read-only files in both sandbox layers; their schema
  directory and run-artifact parent are not exposed. Parent review-lens
  sessions receive only the auditor contract. The in-process Fake runtime executes the same depth, claim,
  journal, review-lens, economics, KPI, and final primary-integrity gates
  without launching an external executable; its successful output is always
  non-publishable. `maco supervise plan/status/collect` remain available. The
  supervisor scheduler launches opt-in O1 child orchestrators through the
  Codex CLI in isolated child worktrees under an O2 supervisor, with
  conservative network-bound fan-out as the default. Admission composes that
  ceiling with configured provider quota and measured/configured host capacity,
  and launches hierarchy-ready assignments concurrently only while their
  normalized claim scopes are disjoint; `--max-concurrent-children 1` is the
  explicit serial opt-out. Overlapping scopes are never admitted together. The
  swarm-health cascade circuit breaker from Issue #24 is the admission safety
  backstop for this higher default: a trip stops pending admissions and drains
  active assignments without weakening the resource or claim gates. Each child
  is instructed to read `AGENTS.md` and project-local `.agents` guidance before
  acting, use Codex native SubAgent/delegated-worker mechanisms for terminal
  worker/researcher assignments when available, preserve the O1/O2 subprocess
  launch boundary of the outer verified MACO sandbox with verified systemd
  cgroup ownership evidence plus the fixed `maco_external_codex` inner
  permission profile, enable goals and multi-agent support only for the
  supervisor role, leave O1/O2 hierarchy and enforced audit gates to MACO/Codex
  CLI subprocess workflows, report peer-O2 escalation candidates instead of
  taking them over, and preserve structured reporting without applying worker
  changes to the primary worktree automatically.
- `maco supervise status` reports durable supervisor run artifact state without
  launching workers or applying changes.
- `maco supervise collect` reads the structured supervisor final report and
  preserves the same no-automatic-primary-apply boundary.
- `maco supervise artifacts list/latest/prune` inspects or prunes durable
  supervisor run artifacts.
- `maco consult ask` asks a terminal read-only cross-runtime consultant for
  advisory help, using deterministic fake mode by default or an explicit
  Codex/Claude-compatible executable when selected. Consultant runs write local
  artifacts under `.maco/consult/runs/<run-id>/`: parent-owned files live in
  `trusted/`, while a real external result is isolated under `incoming/`.
- `maco consult artifacts list/latest/prune` inspects or prunes durable
  consultant run artifacts.
- `.agents/scripts/o2-autopilot` runs bounded autonomous O2 supervisors under
  a separate human/user-directed root O2. The root O2 is out-of-band and is not
  counted against autonomous depth; autonomous O2-to-O2 follow-up uses
  `NEXT_O2_TASKS.tsv` durable queue state and run ledgers such as `STATE.tsv`,
  `HEARTBEAT.tsv`, task prompts, captured outputs, and `SUMMARY.md`.
- `maco autopilot plan/run/status/collect` provides the local-first autopilot
  workflow: normalize a positional task/plan or decompose `--from-goal <file>`,
  then pass the validated plan through the live depth-2 supervisor path in
  fake/local mode by default. `autopilot run` accepts the same
  `--role-category` operator override as `supervise run`. Accepted, publishable
  licensed-breakage follow-ups enter the authenticated durable bounded
  command-level queue and execute through ordinary supervise gates. Fake or
  otherwise non-publishable follow-ups remain deferred. Autopilot writes
  public-safe reports under `.maco/autopilot/runs/<run-id>/` but never
  publishes, merges, or applies a result to the primary worktree.
- `maco autopilot artifacts list/latest/prune` inspects or prunes durable
  autopilot run artifacts.
- `maco artifacts prune --family <family>` applies one retention policy to any
  authenticated run store, the external O2 driver store, legacy workspace
  inbox runs, or direct `.maco/program-*` logs. Policies can combine count,
  age, and apparent-byte ceilings and always report byte totals.
- `maco review pr <number|url>` emits an independent fake structured review
  report by default, with `ci_reaction_supported=false`.
- `maco inbox scan/run/status/collect/watch` provides a fake-first reaction
  loop for issue intake, pull request review feedback, and failing CI checks,
  converting safe inbox items into Autopilot repair plans without network access
  or automatic merge by default. `inbox run` accepts optional rolling-quota
  ceilings `--max-rolling-tokens`, `--max-rolling-cost-usd`, and
  `--rolling-window-seconds`.
- `maco inbox workspace scan/run/watch` supervises the same inbox loop across
  a workspace JSON of repositories. `scan` reports per-repository intake
  without launching Autopilot; `run` and `watch` execute the same per-repository
  inbox path used by `maco inbox run`.
- `maco inbox artifacts list/latest/prune` inspects or prunes durable inbox run
  artifacts.
- `maco evaluation run` generates deterministic fake model-mix fixture results
  from a versioned manifest and digest-bound plan. `maco evaluation experiment`
  runs the same goal/spec under multiple profiles through isolated Fake
  supervise. `maco evaluation rescore` re-scores a stored results document
  under a named objective profile without overwriting the stored file. Real
  providers remain refused.
- `maco eval-harness run` completes a declared role mix through the local fake
  provider. Version 2 manifests are routed to the Issue #26 v2 operator path;
  `maco eval-harness run-v2` always parses that v2 schema. Real network
  providers are refused; v2 output is not production-eligible.
- `maco optimizer library|preference|replay` inspects the starter policy
  library, operator preference profiles, and stored decision replay snapshots.
  It does not launch supervise or change production model defaults.
- `maco scope serve` is a localhost-only observability backend. `maco scope
  event` appends one disclosure-safe external orchestration event. Neither
  command launches supervise or mutates source trees.
- `maco agents list` inspects live MACO-launched agent process records.
  `maco agents stop` stops one unambiguous process or every process in one
  explicitly selected run.

## Roadmap

Implemented local foundations:

1. Result collection, merge preview, and guarded patch apply for agent worktrees.
2. Parser-backed Rust repository maps for modules, symbols, impls, imports, and
   dependency edges, plus semantic risk reports for changed paths.
3. Retained local orchestration internals with dependency scheduling, path claims, timeouts,
   per-agent validation, repo-level validation, run ids, checkpoint writes,
   safe checkpoint resume, and guarded `reuse=reset`.
4. Provider-neutral LLM adapter boundaries with deterministic fake-provider
   tests; public `maco agent run` executes the local `fake` provider in an
   isolated managed worktree. Real network providers remain planned and are
   refused until configured.

Known limitations and roadmap for 0.3.0:

1. Semantic merge conflict classification is advisory and Rust-only. It is
   bounded by parser-map coverage and reports degraded confidence when a
   conflict path cannot be resolved; Git safety checks remain authoritative.
2. Goal/spec planning now proposes independent supervisor assignments with path
   and Rust semantic scopes. The proposal remains conservative and Rust-first;
   richer semantic planning, broader language adapters, and automatic refinement
   remain post-0.3.0 work. Runtime claim gates remain authoritative.
3. PR and issue publication are intentionally narrow. The fake forge is
   deterministic and local-only. GitHub publication is opt-in with explicit
   `--forge github` and shells out to local `git` and `gh`; tests cover the
   fake adapter without network access. Remote push, PR creation, and the
   post-create receipt check are not one globally atomic operation; the durable
   receipt supports detection and retry reconciliation rather than claiming
   cross-service atomicity. The supervise-backed Autopilot spine does not call
   either forge; legacy `forge_mode` plan data is inert there. Inbox intake
   keeps deterministic fake data as the default;
   GitHub inbox scanning is selected only with an explicit GitHub source.
   Issue triage metadata remains minimal.
4. Real LLM providers remain post-0.3.0 roadmap work and must be opt-in,
   explicitly approved, and covered by additional invariant tests.
5. Semantic-map caching and broader language adapters are post-0.3.0 roadmap
   work after the Rust path is stable.
6. Automatic merge remains intentionally absent. Autopilot can record
   `auto_merge=true` as a request, but always reports
   `auto_merge_performed=false` and leaves human review and merge as the next
   action.

Network-facing LLM behavior should remain optional. The default development and
test workflow should continue to run without provider credentials.

Durable sync state is shared through the Git common metadata directory. Current
claims live in the repository-authenticated `authenticated-claims-state-v1`
snapshot namespace; `claims.json` is retained only as a signed version-3
retirement tombstone that makes legacy version-2 writers fail closed.

### Authenticated state migration and foundations

`maco state migrate --repo . --json` is a non-mutating dry-run for legacy
`maco/state` data. `maco state migrate --repo . --apply --json` is the explicit
offline apply path. Migration refuses active known kernel locks, unexpected
entries, links, non-owner files, oversized state, malformed JSON, or invalid
legacy checksums before changing anything. Apply holds all legacy consumer
locks, hardens the state root to `0700` and files to `0600`, then records
claims, semantic intents, and the optional managed-worktree registry (including
an explicit missing entry) in a signed generation-one manifest. An
owner-private transaction outside the state root makes a crash between chmod
and manifest publication forward-recoverable; ordinary pre-publication errors
restore original modes, and successful apply writes an idempotent audit
receipt.

Checksum-less version-1 `claims.json` has no cryptographic provenance that MACO
can verify. Recover it only after taking the repository offline and independently
verifying both the file's origin and its exact bytes. The digest pins the
operator-reviewed bytes; it does not authenticate who created them or make
untrusted claims trustworthy. MACO still validates the strict claims-v1
structure and repository-relative paths, rejects a digest mismatch, and records
the operator-attested unauthenticated-import provenance in the signed migration
manifest.

#### Offline recovery for an unanchored claims journal

Use this procedure only for the exact failure where the reviewed current
development binary reports an authenticated claims physical journal that is not
anchored by any signed logical state, while the legacy `claims.json` is the
checksum-less version-1 state independently reviewed by the operator. Do not
use it for a different inventory, authentication, rollback, or incomplete
initialization error.

The repository must remain offline for the entire procedure: stop every MACO
writer and verify that none can restart. Do not delete, replace, or "repair"
`claims.lock`; a lock error is a reason to abort. Run the commands below from
one Bash session, replace the two absolute placeholders, and stop on every
unexpected result:

```bash
set -euo pipefail
umask 077
unset GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_INDEX_FILE
unset GIT_OBJECT_DIRECTORY GIT_ALTERNATE_OBJECT_DIRECTORIES

REPO=/absolute/path/to/repository
REPO=$(realpath -e -- "$REPO")
DEV=/absolute/path/to/reviewed-current-dev-maco
PINNED_PATH="$REPO/.agents/scripts/maco"
test -x "$PINNED_PATH"
test -f "$PINNED_PATH"
test ! -L "$PINNED_PATH"
PINNED=$(realpath -e -- "$PINNED_PATH")
COMMON=$(git -C "$REPO" rev-parse --path-format=absolute --git-common-dir)
COMMON=$(realpath -e -- "$COMMON")
STATE="$COMMON/maco/state"
ORPHAN="$STATE/authenticated-claims-state-v1"
RECOVERY_BASE="$COMMON/maco/offline-recovery"

test -x "$DEV"
mv --version | grep -F 'GNU coreutils' >/dev/null
mv --no-copy --help >/dev/null
test -d "$STATE"
test -d "$ORPHAN"
test ! -L "$ORPHAN"
test -f "$STATE/claims.json"
test ! -L "$STATE/claims.json"
test ! -L "$RECOVERY_BASE"

install -d -m 0700 -- "$RECOVERY_BASE"
test ! -L "$RECOVERY_BASE"
RECOVERY=$(mktemp -d "$RECOVERY_BASE/issue33.XXXXXXXX")
chmod 0700 -- "$RECOVERY"
test "$(stat -c %a -- "$RECOVERY")" = 700
```

First prove the current failure. Both fixed fragments must occur in stderr; a
successful command or any other error is outside this procedure:

```bash
set +e
"$DEV" sync status --repo "$REPO" --json \
  >"$RECOVERY/dev-before.stdout" \
  2>"$RECOVERY/dev-before.stderr"
DEV_STATUS=$?
set -e

test "$DEV_STATUS" -ne 0
grep -Fq "authenticated snapshot physical journal '" \
  "$RECOVERY/dev-before.stderr"
grep -Fq "is not anchored by any signed logical state" \
  "$RECOVERY/dev-before.stderr"
```

The development command acquires the live persistent kernel lock before
reporting the inventory error. Bind that lock's identity and copy the exact
plaintext claims bytes before invoking the pin:

```bash
test -f "$STATE/claims.lock"
test ! -L "$STATE/claims.lock"
LIVE_CLAIMS_LOCK_ID=$(stat -c '%d:%i:%s:%f:%h' -- "$STATE/claims.lock")

cp -- "$STATE/claims.json" "$RECOVERY/claims-v1.reviewed.json"
chmod 0600 -- "$RECOVERY/claims-v1.reviewed.json"
cmp -s -- "$STATE/claims.json" "$RECOVERY/claims-v1.reviewed.json"
```

The registry pin must never run against the live repository: its legacy
create-new PID lock is incompatible with the live persistent kernel lock and
could otherwise fail on or remove a stale parseable `claims.lock`. Instead,
create an isolated throwaway Git repository under the owner-private recovery
directory, prove that it has a different Git common directory, and give it only
the copied plaintext claims-v1. For this incident, the exact reviewed wrapper
has SHA-256
`93b76ebff318fb75e44f8ce48b5b48b4bad5435045d9fe736c4e1fc587a0d814`.
Its own project-root resolution must bind it to `REPO`, and its manifest path
must resolve inside the reviewed attached checkout. That checkout must be
commit `373550870f9986224bc8b57a9b13019a3da02516` with a clean index and
worktree, including no untracked files. The commit reads and writes plaintext
claims-v1 and contains no authenticated-claims journal writer. Its isolated
output therefore proves only which copied plaintext claim view it interpreted;
it does not prove that the captured orphan journal was emitted by that pin.

```bash
PINNED_WRAPPER_SHA256=93b76ebff318fb75e44f8ce48b5b48b4bad5435045d9fe736c4e1fc587a0d814
test "$(sha256sum -- "$PINNED" | cut -d ' ' -f 1)" \
  = "$PINNED_WRAPPER_SHA256"
PINNED_WRAPPER_ID=$(stat -c '%d:%i:%s:%f:%h' -- "$PINNED")
PINNED_PROJECT_ROOT=$(cd -- "$(dirname -- "$PINNED")/../.." && pwd -P)
test "$PINNED_PROJECT_ROOT" = "$REPO"

PINNED_CHECKOUT=$(realpath -e -- \
  "$PINNED_PROJECT_ROOT/.agents/external/multi-agent-coding-orchestrator")
test "$(realpath -e -- \
  "$PINNED_PROJECT_ROOT/.agents/external/multi-agent-coding-orchestrator/Cargo.toml")" \
  = "$PINNED_CHECKOUT/Cargo.toml"
test "$(realpath -e -- "$(git -C "$PINNED_CHECKOUT" rev-parse --show-toplevel)")" \
  = "$PINNED_CHECKOUT"
PINNED_HEAD=$(git -C "$PINNED_CHECKOUT" rev-parse --verify 'HEAD^{commit}')
printf '%s\n' "$PINNED_HEAD" >"$RECOVERY/pinned-head.txt"
test "$PINNED_HEAD" = 373550870f9986224bc8b57a9b13019a3da02516
git -C "$PINNED_CHECKOUT" status --porcelain=v1 \
  --untracked-files=all --ignore-submodules=none \
  >"$RECOVERY/pinned-checkout-status.before"
test ! -s "$RECOVERY/pinned-checkout-status.before"

PINNED_STAGE="$RECOVERY/pinned-plaintext-stage"
test ! -e "$PINNED_STAGE"
git init --quiet -- "$PINNED_STAGE"
PINNED_STAGE_COMMON=$(git -C "$PINNED_STAGE" \
  rev-parse --path-format=absolute --git-common-dir)
PINNED_STAGE_COMMON=$(realpath -e -- "$PINNED_STAGE_COMMON")
test "$PINNED_STAGE_COMMON" != "$COMMON"
test "$(stat -c %d -- "$PINNED_STAGE_COMMON")" \
  = "$(stat -c %d -- "$RECOVERY")"

PINNED_STATE="$PINNED_STAGE_COMMON/maco/state"
test ! -L "$PINNED_STATE"
install -d -m 0700 -- "$PINNED_STATE"
test ! -L "$PINNED_STATE"
cp -- "$RECOVERY/claims-v1.reviewed.json" "$PINNED_STATE/claims.json"
chmod 0600 -- "$PINNED_STATE/claims.json"
cmp -s -- \
  "$RECOVERY/claims-v1.reviewed.json" \
  "$PINNED_STATE/claims.json"

CARGO_NET_OFFLINE=true \
CARGO_INCREMENTAL=0 \
CARGO_TARGET_DIR="$RECOVERY/pinned-cargo-target" \
  "$PINNED" sync status --repo "$PINNED_STAGE" --json \
  >"$RECOVERY/pinned-claims-view.json" \
  2>"$RECOVERY/pinned-claims-view.stderr"
test ! -e "$PINNED_STATE/claims.lock"
test "$(stat -c '%d:%i:%s:%f:%h' -- "$PINNED")" = "$PINNED_WRAPPER_ID"
test "$(sha256sum -- "$PINNED" | cut -d ' ' -f 1)" \
  = "$PINNED_WRAPPER_SHA256"
test "$(git -C "$PINNED_CHECKOUT" rev-parse --verify 'HEAD^{commit}')" \
  = "$PINNED_HEAD"
git -C "$PINNED_CHECKOUT" status --porcelain=v1 \
  --untracked-files=all --ignore-submodules=none \
  >"$RECOVERY/pinned-checkout-status.after"
test ! -s "$RECOVERY/pinned-checkout-status.after"
cmp -s -- \
  "$RECOVERY/pinned-checkout-status.before" \
  "$RECOVERY/pinned-checkout-status.after"
cmp -s -- "$STATE/claims.json" "$RECOVERY/claims-v1.reviewed.json"
test "$(stat -c '%d:%i:%s:%f:%h' -- "$STATE/claims.lock")" \
  = "$LIVE_CLAIMS_LOCK_ID"

jq -e 'type == "object" and .version == 1
  and (.next_token | type == "number")
  and (.claims | type == "array")' \
  "$RECOVERY/claims-v1.reviewed.json" >/dev/null
jq -e 'type == "array"' "$RECOVERY/pinned-claims-view.json" >/dev/null
jq -S '.claims' "$RECOVERY/claims-v1.reviewed.json" \
  >"$RECOVERY/raw-claims.sorted.json"
jq -S '.' "$RECOVERY/pinned-claims-view.json" \
  >"$RECOVERY/pinned-claims.sorted.json"
cmp -s -- \
  "$RECOVERY/raw-claims.sorted.json" \
  "$RECOVERY/pinned-claims.sorted.json"
jq '.next_token' "$RECOVERY/claims-v1.reviewed.json"
```

The last command only displays `next_token`: it is not present in the pinned
status array and must be reviewed separately with the entire copied claims-v1
file.

Inventory and hash every entry in the orphan namespace before changing its
active path. The inventory includes type, mode, ownership, size, device, inode,
link count, path, and symlink target; the hash list covers every regular file.
The `-P` and `-xdev` boundaries prevent following links or crossing a mounted
filesystem. Abort if any visited entry is nevertheless on another device.

```bash
inventory_tree() {
  (
    cd -- "$1"
    find -P . -xdev \
      -printf '%y\t%m\t%U\t%G\t%s\t%D\t%i\t%n\t%P\t%l\0' |
      LC_ALL=C sort -z
  )
}

hash_tree() {
  (
    cd -- "$1"
    find -P . -xdev -type f -print0 |
      LC_ALL=C sort -z |
      xargs -0r sha256sum -z --
  )
}

ORPHAN_DEVICE=$(stat -c %d -- "$ORPHAN")
while IFS= read -r -d '' ENTRY; do
  test "$(stat -c %d -- "$ENTRY")" = "$ORPHAN_DEVICE"
done < <(find -P "$ORPHAN" -xdev -print0)

inventory_tree "$ORPHAN" >"$RECOVERY/orphan.inventory.before"
hash_tree "$ORPHAN" >"$RECOVERY/orphan.sha256.before"
sync -f -- "$RECOVERY"
```

The prerequisite checks above require GNU Coreutils `mv` with `--no-copy`.
Prove the orphan namespace and recovery directory are on the same filesystem,
then atomically quarantine the complete namespace with one rename. `--no-copy`
makes a failed rename fail closed instead of falling back to copy-and-delete.
Do not copy individual journals or synthesize a locator. The quarantined
namespace is forensic evidence and must never be adopted, re-anchored, restored
into active state, or used as migration input.

```bash
test "$(stat -c %d -- "$ORPHAN")" = "$(stat -c %d -- "$RECOVERY")"
test "$(stat -c %d -- "$STATE")" = "$(stat -c %d -- "$RECOVERY")"
QUARANTINED="$RECOVERY/authenticated-claims-state-v1"
test ! -e "$QUARANTINED"

mv --no-copy -T -- "$ORPHAN" "$QUARANTINED"
test ! -e "$ORPHAN"
sync -f -- "$STATE" "$RECOVERY"

inventory_tree "$QUARANTINED" >"$RECOVERY/orphan.inventory.after"
hash_tree "$QUARANTINED" >"$RECOVERY/orphan.sha256.after"
cmp -s -- \
  "$RECOVERY/orphan.inventory.before" \
  "$RECOVERY/orphan.inventory.after"
cmp -s -- \
  "$RECOVERY/orphan.sha256.before" \
  "$RECOVERY/orphan.sha256.after"
sync -f -- "$RECOVERY"
```

If any command after the rename fails, keep all writers offline and leave the
quarantine in place for investigation; do not automatically move it back.

Manually inspect the complete `claims-v1.reviewed.json`, including
`next_token`, agent ids, tokens, and every path. Compute the digest independently
of MACO, paste the reviewed lowercase value, and verify it against both the
review copy and the still-active plaintext file:

```bash
sha256sum -- "$RECOVERY/claims-v1.reviewed.json"
read -r -p "Paste the reviewed lowercase SHA-256: " EXPECTED
test "${#EXPECTED}" -eq 64
case "$EXPECTED" in
  *[!0-9a-f]*) exit 1 ;;
esac
test "$(sha256sum -- "$RECOVERY/claims-v1.reviewed.json" | cut -d ' ' -f 1)" \
  = "$EXPECTED"
test "$(sha256sum -- "$STATE/claims.json" | cut -d ' ' -f 1)" \
  = "$EXPECTED"
cmp -s -- "$STATE/claims.json" "$RECOVERY/claims-v1.reviewed.json"
```

Run the attested migration with the reviewed development binary. Dry-run must
report `ready` or `already_applied`; apply must report `applied` or
`already_applied`:

```bash
"$DEV" state migrate --repo "$REPO" \
  --acknowledge-unauthenticated-claims-v1 \
  --expected-claims-v1-sha256 "$EXPECTED" \
  --json >"$RECOVERY/migration-dry-run.json"
jq -e '.mode == "dry_run"
  and (.status == "ready" or .status == "already_applied")' \
  "$RECOVERY/migration-dry-run.json" >/dev/null

"$DEV" state migrate --repo "$REPO" --apply \
  --acknowledge-unauthenticated-claims-v1 \
  --expected-claims-v1-sha256 "$EXPECTED" \
  --json >"$RECOVERY/migration-apply.json"
jq -e '.mode == "apply"
  and (.status == "applied" or .status == "already_applied")' \
  "$RECOVERY/migration-apply.json" >/dev/null
```

Finally, let the development binary create/open the new authenticated claims
snapshot from the signed claims-v1 migration, compare its claims to the pinned
plaintext view, and inspect worktree cleanup without removing anything. A
legitimate dry-run can report eligible worktrees, targets, or orphan directories,
so require only `dry_run == true` and review every reported entry rather than
requiring zero counts.

```bash
"$DEV" sync status --repo "$REPO" --json \
  >"$RECOVERY/dev-claims-after.json"
jq -e 'type == "array"' "$RECOVERY/dev-claims-after.json" >/dev/null
jq -S '.' "$RECOVERY/dev-claims-after.json" \
  >"$RECOVERY/dev-claims-after.sorted.json"
cmp -s -- \
  "$RECOVERY/pinned-claims.sorted.json" \
  "$RECOVERY/dev-claims-after.sorted.json"

"$DEV" worktree gc --repo "$REPO" --dry-run --json \
  >"$RECOVERY/worktree-gc-dry-run.json"
jq -e '.dry_run == true' "$RECOVERY/worktree-gc-dry-run.json" >/dev/null

inventory_tree "$QUARANTINED" >"$RECOVERY/orphan.inventory.final"
hash_tree "$QUARANTINED" >"$RECOVERY/orphan.sha256.final"
cmp -s -- \
  "$RECOVERY/orphan.inventory.before" \
  "$RECOVERY/orphan.inventory.final"
cmp -s -- \
  "$RECOVERY/orphan.sha256.before" \
  "$RECOVERY/orphan.sha256.final"
sync -f -- "$STATE" "$RECOVERY"
```

Review the migration, sync-status, and GC reports and keep the full quarantine
before resuming writers. Never run the registry-pinned writer against the live
repository at any point; its only permitted invocation is against the isolated
pre-migration staging repository above. After migration, resume only the
reviewed development binary. The new authenticated claims snapshot is
supported by the attested claims-v1 migration; the captured orphan journal
remains unanchored and unadopted. Neither its writer provenance nor its
authorization as the current logical state was established. The wrapper checks
bind the reviewed script bytes, its project root, its resolved manifest, and the
clean pinned source checkout before and after the isolated invocation. They do
not independently attest Cargo, rustc, cached dependencies, or the wider
toolchain, and they do not defend against a hostile same-UID process racing and
restoring checked paths during execution; the exclusive offline operator
boundary remains a prerequisite.

The first open of each migrated claims, semantic-intent, or managed-worktree
consumer performs a recoverable retirement transaction while holding its
legacy kernel lock. It copies the exact signed-manifest legacy bytes into a
bounded owner-private sidecar, binds both original and sidecar identities and
digests in an HMAC intent, atomically replaces the legacy filename with a
pending version-3 tombstone, publishes the full authenticated snapshot, and
then activates the tombstone and removes the sidecar. Crashes before the
tombstone leave only the old state; crashes after it recover forward from the
signed sidecar, while old writers always reject version 3. Migration dry-run
and repeated apply verify the original signed manifest entry, active tombstone,
exact authenticated snapshot locator, every held legacy consumer lock, and the
identity-bound transaction root before and after producing a result, without
adopting a tombstone on first use.

The typed authenticated-state foundation uses immutable HMAC-chained journals,
signed atomic heads, and full-lifecycle instance locks. Snapshot stores add a
signed stable locator containing the active journal identity, absolute
generation and token, and retained prior terminal anchors. Rollover publishes a
signed prepared intent before its candidate journal can exist, publishes and
authenticates the replacement generation, then atomically switches that
locator. A bounded physical-journal inventory rejects a signed old-locator
replay that leaves newer evidence present; a prepared pre-switch crash either
recovers forward from the bound candidate or leaves the old locator
authoritative. Old journals remain present and are verified on open. A missing
locator, a substituted or deleted retained journal, an unbound physical
journal, or locator replay beyond the single-record crash window fails closed.
Snapshot inventory is namespace-wide: every signed logical locator and pending
initialization/rollover intent contributes to one bounded union of physical
journals. Namespace-specific quotas bound logical stores, total root entries,
and retained physical journals; the external-effect namespace permits 4,096
logical source-action stores within its larger finite root budget. Capacity is
checked before a new logical store or rollover candidate is created. Reaching a
quota fails closed and requires operator archival or other explicit manual
intervention; MACO does not auto-delete exactly-once receipts or retry the
external effect to recover capacity.
Managed-worktree snapshots retain only active incarnations. Retired nonce lease
files are queued with signed inode identities and scavenged only after an
exclusive lock proves them inactive; active, foreign, or rebound lease paths
are never unlinked. Effect WALs likewise publish a durable
`planned` record before returning to a caller and require the ordered
`planned -> started -> observed -> completed` reconciliation sequence.

Every authenticated namespace must be registered in the first-key consumer
registry before it can be created. The entire sensitive state root must also be
masked from every untrusted child process; authentication does not compensate
for exposing its key. Local HMAC evidence detects partial mutation and rollback
relative to retained current evidence, but no local design without an external
monotonic anchor can detect a coherent restoration of every artifact needed to
form an older mutually consistent namespace (its locator, tombstone, journals,
heads, and transaction evidence), or restoration of an older key/epoch and all
state authenticated by it as one whole snapshot.

## Semantic coordination

Semantic coordination adds a typed blackboard of structured intents, not
free-form agent chat. Durable semantic state is repo-local in the Git common
metadata directory's `authenticated-semantic-state-v1` snapshot namespace, so
the primary worktree and linked agent worktrees see the same planning state.
The legacy `semantic_intents.json` pathname is only the signed retirement
tombstone.

Hard path claims remain the write boundary. Semantic intents sit earlier in the
workflow as a planning and coordination layer: blocking conflicts can prevent an
intent from being claimed, while advisory conflicts can warn about likely
overlap without reserving files. MVP semantic analysis is Rust-only.

```bash
maco coord preview agent-a --path src/lib.rs --symbol WorktreeManager --repo . --json
maco coord claim agent-a --path src/lib.rs --module crate::worktree --repo . --json
maco coord status --repo . --json
maco coord release <token> --repo . --json
maco coord release-agent agent-a --repo . --json
```

Orchestration opts in with `--semantic-coordination off|warn|block`; the
default is `off`.

Orchestration commands, validation commands, and opt-in provider-proposed shell
commands are trusted local shell commands. `maco` isolates work with Git
worktrees and path-claim checks, but it is not an OS or filesystem sandbox.
Path claims enforce Git-visible repository changes; they do not prevent a
trusted command from reading or writing arbitrary local filesystem paths.

File-backed CLI inputs are opened as bounded regular files without following
links in any path component. Multiply linked files, special files, and inputs
that exceed their command-specific size or structural limits are refused before
worktrees, claims, or run artifacts are created. Repository discovery for task
planning, prompt excerpts, repository maps, and Autopilot dirty-state checks is
also depth-, entry-, path-, byte-, and time-bounded. Prompt excerpt paths must
be repository-relative; a missing path or directory may still be named as a
claim scope, but neither is read as prompt content.

## Machine-global claims and recoverable retention

`maco machine-global` coordinates paths outside Git repositories without making
arbitrary absolute paths claimable. Every invocation requires an explicit
`--config` file; MACO never infers a root from `HOME`, repository location,
pathname spelling, or process environment. The config file is bounded, strict
version-1 JSON opened without following links in any path component. Its own
path, `state_root`, and every declared root must be existing, exact canonical
absolute paths. The config file itself must be a current-user-owned,
single-link regular file that is not group- or world-writable. `state_root`
must be an owner-private `0700` directory and must not intersect a declared
root. Declared roots may not overlap one another. Unknown fields, `.` or `..`
components, symbolic links, non-canonical spellings, and changed root
identities fail closed. On Linux, the state root and every declared root are
also bound to their `statx` mount id. Duplicate filesystem identities are
rejected. Two configured paths on the same device but different mounts are
rejected conservatively as possible bind aliases; paths on one mount retain the
component-aware overlap check. An existing coordinate whose parent or leaf
crosses away from its declared root's mount is refused.

```json
{
  "version": 1,
  "state_root": "/srv/maco-machine-global-state",
  "roots": [
    {
      "id": "runtime-sessions",
      "path": "/srv/agent-runtime/sessions",
      "protected_paths": [
        {
          "coordinate": {
            "root_id": "runtime-sessions",
            "relative": "active"
          },
          "retryability": "not_retryable"
        }
      ],
      "quarantine_grace_seconds": 86400
    }
  ]
}
```

The config is the reviewed authority ceiling. Commands carry a root id and a
strict root-relative path. Privacy-safe structured success, status, and typed
denial JSON omits configured absolute roots; local diagnostic errors may
identify a configured path for operator repair. Containment uses path
components, so `state` does not contain `state-backup`. An absolute value
supplied to retention `--path` is refused as an undeclared destructive target
and its `GateDenial` contains only a fingerprint. Claim conflicts and
destructive intersections report privacy-safe root-id-relative coordinates. A
denied `--json` command emits the typed `GateDenial` object on standard output
and exits unsuccessfully.

```bash
maco machine-global claim repair-agent \
  --root-id runtime-sessions \
  --path active/session-42 \
  --correlation repair-42 \
  --config /etc/maco/machine-global.json \
  --json

maco machine-global owner \
  --root-id runtime-sessions \
  --path active/session-42/cache \
  --config /etc/maco/machine-global.json \
  --json

maco machine-global status \
  --config /etc/maco/machine-global.json \
  --json

maco machine-global release repair-agent <claim-token> \
  --config /etc/maco/machine-global.json \
  --json
```

Successful claim output contains a random bearer token needed for release.
`status` and `owner` deliberately return redacted claim summaries without
tokens. Keep the config bytes stable while durable state exists: changing the
reviewed config causes the store to refuse reinterpretation of existing state.
Independent repositories coordinate when they use the same config and
`state_root`. The owner-private state envelope checksum detects accidental or
partial corruption; it is not authentication against a hostile same-UID
process that can rewrite the state and checksum coherently.

Retention accepts the complete target set up front and checks every source and
hidden quarantine sibling against active claims, configured protected paths,
and other active retention reservations before the first rename. Current
retention targets are existing directories on Linux. Each accepted target is
atomically renamed beside its original pathname to a hidden
`.maco-quarantine-v1-*` sibling, which keeps the move on the same filesystem.
The returned operation records the root-relative source, hidden sibling name,
deterministic `.maco-delete-v2-*` purge-cleanup sibling, inode identity,
quarantine time, purge deadline, and a random operation token. The source,
quarantine, and cleanup coordinates are all reserved and preflighted. Status
reports omit the token.

```bash
maco machine-global retention quarantine cleanup-agent \
  --root-id runtime-sessions \
  --path expired/session-17 \
  --path expired/session-18 \
  --correlation retention-2026-07-30 \
  --config /etc/maco/machine-global.json \
  --json

maco machine-global retention restore cleanup-agent <operation-id> \
  --correlation restore-session-17 \
  --config /etc/maco/machine-global.json \
  --json

maco machine-global retention purge cleanup-agent <operation-id> \
  --token <operation-token> \
  --correlation purge-session-17 \
  --config /etc/maco/machine-global.json \
  --json
```

Restore uses an atomic no-replace rename and refuses an occupied or rebound
original path. Restore intentionally requires the recorded owner but not the
purge bearer token, so an operator can recover after a crash that occurred
before the token was returned; the full live-claim and protected-path preflight
still applies. Purge requires the operation owner and bearer token, uses MACO's
trusted system clock, refuses before the configured positive grace period, and
reruns the complete claim/protected-path preflight before permanent removal.
Purge completes a mount-confined link/special-file audit while the tree still
has its restorable quarantine name. It then moves the tree to its recorded
cleanup sibling, repeats the identity- and mount-confined audit, and only then
deletes the verified tree. Resuming an already-renamed cleanup residue starts
with the same audit at that cleanup name. If a quarantine or cleanup pathname
is unavailable, collides, cannot be renamed, is full, or cannot be safely
inspected, the operation fails closed. MACO never falls back to direct deletion
or a cross-filesystem copy. A multi-target I/O failure can leave an explicitly
recorded partially quarantined operation. Quarantine does not resume such an
operation: restore it to a consistent source layout, then start a fresh
quarantine attempt.

### Cooperative enforcement and known bypasses

Machine-global enforcement is cooperative. A destructive path is protected only when
the caller opens the same reviewed configuration and state root, declares the target
under the correct root ID, and performs the mutation through the gate. This is not
syscall interposition and is not a host-wide guarantee: a hand-run shell command, a
directly launched agent, or an arbitrary child process can still modify or delete data
without consulting MACO.

`merge arbitrate` requires `--machine-global-config` and
`--machine-global-runtime-root-id`. Its external-agent output staging cleanup is routed
through the machine-global gate. An intersecting active claim produces the existing
typed `GateDenial`, leaves the staging directory in place, and makes the run
non-publishable. An allowed cleanup is quarantined; the public run record carries only
the retention operation ID, while the purge token remains in a mode-0600 private
receipt beside the JSON log. This is a launch-time obligation for that orchestrator
path, not protection against commands launched outside it.

`supervise run` requires the same `--machine-global-config` and
`--machine-global-runtime-root-id` pair. Every child-orchestrator launch and every
parent acceptance-auditor review-lens launch carries that binding to its private
output-staging cleanup. Missing programmatic bindings fail before verified dispatch;
the CLI rejects missing or partial pairs. Cleanup denials remain typed `GateDenial`
values and preserve the staged directory. Nested workers and the child-side advisory
auditor run inside the enclosing child session rather than as separate host
`ExternalAgentCommand` launches, so the child-orchestrator staging gate covers that
session's host output staging.

`worktree gc` accepts `--machine-global-config`,
`--machine-global-worktree-root-id`, and `--machine-global-correlation` as one
all-or-none binding. A destructive run that discovers unregistered directories refuses
before touching those directories when the binding is absent. With the binding, GC
collects the complete orphan set and sends it through one machine-global quarantine
preflight before the first directory moves. A denial leaves every orphan in place and
is returned in the existing typed `GateDenial` envelope. The GC report carries the
public retention operation ID only; it does not serialize the bearer purge token.

The audit was performed from mutation sinks outward, rather than from cleanup command
names inward. It enumerated direct filesystem removal, descriptor-relative unlink,
rename/replacement, truncating/open-for-write operations, the safe-state recursive
removal and quarantine wrappers, Git worktree/reference mutation, spawned command or
systemd cleanup, explicit Rust `Drop` implementations, and dependency-owned RAII
destructors such as `tempfile::TempDir`. Each production caller's target was then
traced to one of:
repository worktree, separate Git common directory, managed external worktree root,
private runtime/temp root, user-selected output root, or machine-global state/config
root. Finally, CLI path-bearing arguments and generic child-process destinations were
cross-checked against that sink inventory. Test-only mutation fixtures were excluded
only after locating their enclosing test module, rather than by filename or keyword.

The current cleanup/retention audit is:

| Path | Gate status | Reason and attribution boundary |
| --- | --- | --- |
| Unregistered direct-child directories found by `worktree gc` | Routed | These may be nonempty arbitrary external directories and therefore match the destructive incident shape; treating routing as optional would be unjustified. GC requires an explicit reviewed binding when such targets exist, preflights the complete orphan set, quarantines allowed targets, and reports a typed denial plus logical actor `maco-worktree-gc` when refused. |
| Pre-worktree final reservation and staging setup rollback/recovery/finalization | Known transactional bypass, attributed | These paths exist before the child is a repository worktree, but they are not adopted retention targets: MACO creates the exclusive reservation and authenticated create intent, binds the exact inode, removes only a still-empty reservation/staging root, and preserves changed, nonempty, or unbound paths for manual recovery. Final replacement accepts only the verified clean staged worktree. Routing these transaction-internal names into retention quarantine would break the idempotent create protocol rather than protect pre-existing data. While retained, the authenticated operation records agent, phase, root/path identity, and branch; each direct mutation also emits its fixed operation label with `process_attribution=not_process_observable`. |
| Machine-global state-root lock/state/temp maintenance | Known infrastructure bypass | The state root is deliberately disjoint from declared data roots: the gate must lock and replace its own bounded authenticated state before it can evaluate a claim, so recursively gating that state is ill-founded. State writes and temp cleanup are identity-bound, bounded, and lock-fenced. The fixed private state root and filenames identify the machine-global subsystem, but successful bootstrap/temp cleanup is not durably process-observable. Retention purge is not included in this bypass: it rechecks the gate and retains its owner, operation ID, coordinates, identities, and final `purged` phase. |
| External-agent output staging used by `merge arbitrate` or `supervise run` | Routed | Creation resolves the explicitly declared root ID first and places the private staging directory beneath that exact reviewed machine-global runtime root. Cleanup revalidates the same directory/root binding. Supervise applies the binding to child-orchestrator and parent review-lens auditor launches; review-lens temporary Git workspaces therefore reach this same runtime-staging cleanup path. Refusals use `GateDenial`; allowed operations use the existing retention record. |
| Parent review-lens isolated Git workspaces under `/tmp/maco-review-lens-*` | Known process-owned ephemeral bypass | `tempfile` creates an unpredictable, exclusively owned directory for one lens; no operator, sibling agent, or caller supplies or adopts its path. `TempDir::drop` recursively removes that leaf, so this is a distinct deletion from the routed `/run/user/<uid>` output staging. Its hazard is materially weaker than shared staging, while routing it through the runtime-root binding would misrepresent an independently created `/tmp` leaf as part of that reviewed root. The supervisor run and lens identity provide logical context while their artifacts remain, but successful `Drop` cleanup is not durably process-observable. Any change that accepts a caller path or permits adoption must route the cleanup instead of relying on this exception. |
| External-agent output staging used without a machine-global binding by other entrypoints | Known bypass, attributed | `supervise run` and `merge arbitrate` do not take this path. For callers that genuinely lack a reviewed binding, completed cleanup records `actor=maco-external-agent`, `operation=delete_private_output_staging`, the reason, and `process_attribution=not_process_observable` in the serialized run; early `Drop` cleanup emits the same actor/operation marker before deletion. This identifies the cooperative bypass without claiming process-level observation. |
| External-agent staging setup rollback | Known empty-directory bypass, attributed | If exclusive output reservation fails, setup emits `actor=maco-external-agent`, `operation=delete_empty_output_staging_setup_rollback`, and `process_attribution=not_process_observable` before removing only the newly created, still-empty staging directory. No external data was accepted into that directory. |
| Bounded worktree-status crash scavenging under `/tmp/maco-worktree-status-<uid>` | Known bypass | It removes only identity-bound, bounded files from MACO's per-user status root, but no reviewed root configuration is available at that call site. The call site and per-user root identify the subsystem; the deleting process is not durably observed. |
| Merge private-runtime orphan scavenging and close cleanup under `/run/user/<uid>` or `/tmp/maco-runtime-<uid>` | Known bypass | Runtime teardown and orphan recovery must also work before a repository/configuration is available. Owner records carry PID, process start time, boot ID, and runtime kind while present, but successful deletion removes those records; this is not durable deletion attribution. |
| Orchestrator cleanup of user-selected `--patch-dir` and `--checkpoint-dir` reservations | Known bypass | Exclusive leaf reservation prevents overwrite, but cleanup is still direct because these optional roots are not declared machine-global roots. The enclosing run, agent, and reservation identify the logical actor while present; process-level deletion attribution is not durable. |
| Reviewer program/view cleanup in the private runtime root | Known bypass | These are current-run private runtime files and cleanup must work without a reviewed machine-global configuration. The run/reviewer context identifies the logical actor while records remain; successful `Drop` cleanup is not durably attributed. |
| Process-runner and pinned-exec systemd unit/runtime/descriptor cleanup | Known bypass | systemd can remove `RuntimeDirectory` content outside the Rust cleanup path, so the machine-global API cannot wrap every deletion without changing the runtime ceiling. Unit, runtime, and actor metadata provide operational context, not universal process-observable attribution. |
| Publication secret-buffer zeroing in the private runtime root | Known intentional overwrite | The overwrite is identity-checked secret erasure, not retention. Publication/run context identifies the logical actor, but the erasure is not process-observable after the fact. |
| Repository Git-common maintenance: authenticated snapshots, state migration/journals and effect ledgers, repository lock records, and managed-worktree metadata | Known bypass | A separate Git directory can place this authenticated repository state physically outside a worktree. Cleanup and overwrite are bounded to identity-checked leaves under repository-bound locks, but these paths must also work before a machine-global config is supplied. Signed intents, journals, repository identity, and run/operation IDs provide logical attribution where retained; successful temp/intent cleanup is not durable process attribution. |
| Process-runner tee destinations | Conditional capability surface | Current production callers use repository/run-local destinations. Any future caller that supplies an external destination must route it through the gate or add it here as a reasoned, attributable bypass. |

Repository-local retention is outside this machine-global audit: artifact pruning under
`.maco`, live-claim cleanup under `.agents`, supervise reporting artifacts, and deletion
of a managed worktree's own files operate inside a repository worktree. Git-common
metadata for those operations is covered separately above because it may use a separate
Git directory.

The retention API currently supports directory retention only on Linux. Coordinate
comparison assumes case-sensitive filesystem spelling; case-insensitive or casefolded
alias behavior is not established as supported, so such roots should not be declared.
The mount policy is intentionally conservative and does not claim to detect every
conceivable physical alias.

Default linked worktrees are created outside the repository at
`../.maco/worktrees/<repo-name>/<agent-id>`. Completed task branches can be
cleaned with `maco worktree gc`; branch refs remain available for later
recreation, while dirty, claimed, or leased worktrees are left in place.

## Local Artifact Boundaries

Runtime artifacts are local operator evidence, not source files. Autopilot,
inbox, and supervisor runs write under `.maco/.../runs/<run-id>/`; generated run
ids are collision checked, and an explicit `--run-id` is refused when that run
directory already exists. Use each command family's nested artifact helpers to
inspect or prune that family's run directories:

```bash
cargo run -- autopilot artifacts list --repo . --json
cargo run -- autopilot artifacts latest --repo . --json
cargo run -- autopilot artifacts prune --repo . --keep 10 \
  --max-age-seconds 2592000 --max-total-bytes 2147483648 \
  --unfinalized-grace-seconds 604800 --dry-run --json
cargo run -- inbox artifacts list --repo . --json
cargo run -- supervise artifacts latest --repo . --json
cargo run -- consult artifacts list --repo . --json
```

The repository-level command reaches stores that have no nested producer
command. Its accepted families and roots are:

| `--family` | retained items |
|---|---|
| `autopilot` | `.maco/autopilot/runs/<run-id>` |
| `consult` | `.maco/consult/runs/<run-id>` |
| `inbox` | `.maco/inbox/runs/<run-id>` |
| `supervise` | `.maco/o2/runs/<run-id>` |
| `o2-autopilot` | `.maco/o2-autopilot/runs/<run-id>` |
| `inbox-workspace` | `.maco/inbox-workspace/runs/<run-id>` legacy residue |
| `program` | each direct `.maco/program-*` directory, including its `logs/` |

For example, preview program-log retention without touching the real store:

```bash
cargo run -- artifacts prune --family program --repo . --keep 3 \
  --max-age-seconds 2592000 --max-total-bytes 1073741824 \
  --unfinalized-grace-seconds 604800 \
  --acknowledge-external-writers-stopped --dry-run --json
```

Count, age, total-byte, and unfinalized-grace ceilings are independent
maximums: an item is a candidate when any applicable ceiling is exceeded.
Thus an abandoned unfinalized run expires after its grace even when fewer than
`--keep` runs exist. Ordering uses the newest bounded descendant activity time,
so appends to an active transcript refresh its age. `--max-total-bytes` counts
apparent regular-file bytes; the JSON report
includes per-item `bytes`, `age_seconds`, and `selected_by`, plus
`scanned_bytes`, inventory-snapshot `retained_bytes`, planned
`projected_retained_bytes`, `would_reclaim_bytes` for dry-run, and actual
`reclaimed_bytes` for apply. Refused trees may change concurrently after their
snapshot, so these are not filesystem quota measurements. A dry-run never
counts planned deletion as actual reclamation.

Fresh marker-missing runs are pinned for `--unfinalized-grace-seconds` (seven
days by default). A held authenticated writer lock also pins a run regardless
of age. Once a marker-missing run is both selected, older than the grace, and
idle, retention rechecks its identity, byte count, activity, and finalization
state before using the same identity-bound quarantine and no-follow deletion
path as finalized runs. A present but invalid finalization marker remains
refused unless `--reclaim-unverifiable` explicitly puts it under the same
grace, idle-lock, identity, activity, and state rechecks. This opt-in bounds
abandoned corrupt runs without silently treating damaged evidence as a normal
crash. External and legacy stores have no cooperative writer lock, so both
dry-run and apply refuse their candidates unless
`--acknowledge-external-writers-stopped` is supplied. That acknowledgement,
the grace, and refreshed descendant activity form the active-run boundary;
the acknowledgement must not be supplied while a same-UID writer can mutate
the store. Marker-missing legacy runs inside authenticated roots also require
this acknowledgement when their cooperative writer lock file is absent.

Retention deliberately does not compress transcripts in this version. A
finalized authenticated file is immutable because its exact path, length, and
digest are covered by the finalization MAC; rewriting it as gzip would destroy
the evidence contract. External journals can still be append targets and have
no common rotation handshake. The report therefore records
`compression_strategy: none_requires_writer_migration`, counts
`compressible_log_bytes`, and reports `compressed_bytes: 0`. Compression needs
a writer-side, crash-safe format migration rather than an in-place prune
rewrite. The reusable `ArtifactRetentionPolicy`, `prune_runs_with_policy`, and
`prune_artifacts_with_policy` APIs are consumed by the opt-in worktree lifecycle
scheduler described below. Its aggregate dry-run reports artifact and worktree
reclamation together before either store is changed.

## Cross-runtime consultant

`maco consult ask` is a read-only second-opinion path for stuck agents. It does
not create worktrees, claim paths, apply patches, or mutate repository files.
The fake runtime is the default and needs no network or external binaries:

```bash
cargo run -- consult ask \
  --repo . \
  --question "Why is this validation failing after the worker change?" \
  --context-path README.md \
  --json
```

Real runtime adapters are explicit and local-process only. Codex consultant
mode uses a read-only sandbox and does not enable goals or multi-agent worker
delegation:

```bash
cargo run -- consult ask \
  --repo . \
  --runtime codex \
  --consultant-bin codex \
  --question-file consult-question.md \
  --context-path src/supervise.rs \
  --json
```

Claude consultant mode is currently refused before launch because MACO cannot
enforce an equivalent inner read-only permission contract. Supplying an
executable does not weaken that refusal. Selecting `runtime: claude-code` or
`runtime: gemini-cli` on a supervise assignment is accepted, but writable
managed-worktree launch stays refused under their current capability values
because release requires verified native side-effect confinement. Writable
primary-worktree release uses the separate
`blocking_pre_action_callback == All` gate. The command form below demonstrates
the expected fail-closed consultant response; it does not launch Claude.

```bash
cargo run -- consult ask \
  --repo . \
  --runtime claude \
  --consultant-bin claude \
  --question "What narrow fix should I inspect next?" \
  --context-path tests/supervise_cli.rs \
  --json
```

For execution-phase Codex launches in a managed linked worktree, MACO grants
read-write access only to that worktree's own per-worktree Git directory.
Planning-phase launches bind that same directory read-only. The common Git
allowlist is read-only: `objects/`, `refs/`, `config`, `packed-refs`,
`info/exclude`, and optional `shallow`. The primary `HEAD`, `index`, and
`config.worktree`, MACO common state, and peer worktree entries are not exposed.
The same exact allowlist applies to the outer process confinement and the inner
Codex filesystem policy; primary merge, apply, and publish gates remain in force.

Launch fails closed when Git markers or allowlisted metadata contain symlinks,
hard-link aliases, special files, or object alternates. Recreate the launch
repository with `git clone --no-hardlinks` and without `--reference` before
retrying; MACO does not repack the primary repository as remediation.

Consultant advice is advisory evidence only. It does not override project
rules, assigned ownership, validation requirements, review gates, or merge
gates.

Durable project guidance under `.agents/docs`, `.agents/skills`, and
`.agents/workflows` may appear in repository maps. Local-only agent scratch
state under `.agents/temp`, `.agents/storage`, and `.agents/live` is excluded
from repository maps, semantic maps, and task-path proposal helpers.

## Install

Install `maco` once as a machine-global binary. Do not invoke it through a
per-repository `cargo run` wrapper around a pinned checkout. See
[`docs/PACKAGING.md`](docs/PACKAGING.md) for the install, update, and version
contract.

On Nix:

```bash
nix profile install path:$PWD#maco
maco --version
```

On hosts without Nix:

```bash
cargo install --locked --path . --bin maco
maco --version
```

`maco --version` prints the crate version from `Cargo.toml`. After install,
`maco` runs from any working directory.

## Development

The authoritative local environment for CI parity is the repository's Nix
development shell:

```bash
nix develop path:$PWD
```

It provides the Rust toolchain selected by `rust-toolchain.toml`, including
Clippy and rustfmt, plus the Python interpreter used by the
repository-portability gate. An ambient system toolchain is not evidence of CI
parity.

Run the CI-equivalent Linux and repository-portability gates with:

```bash
export CARGO_INCREMENTAL=0
nix develop path:$PWD -c rustc --version --verbose
nix develop path:$PWD -c cargo --version --verbose
nix develop path:$PWD -c cargo clippy --version
nix develop path:$PWD -c python3 -m unittest discover -s scripts/tests -p 'test_*.py'
nix develop path:$PWD -c python3 scripts/check_repository_portability.py
nix develop path:$PWD -c cargo fmt --all -- --check
nix develop path:$PWD -c cargo check --locked --all-targets
nix develop path:$PWD -c cargo clippy --locked --all-targets -- -D warnings
nix develop path:$PWD -c cargo test --locked --all-targets
```

Full verification is a one-shot sweep, so CI and this recipe disable Cargo's
incremental cache; ordinary edit/build cycles retain Cargo's default incremental
behavior. This reproduces the Linux CI toolchain and tracked-path portability
gate. It cannot compile or link target-specific code on actual macOS or Windows runners.
Before treating a branch as fully CI-green, push it or open a draft pull request
and wait for both the `macos-latest` and `windows-latest` `portable-build` jobs;
a draft pull request is the cheapest honest way to close that residual gap.

GitHub-hosted Linux runners do not provide the delegated systemd user manager
required by strict containment. Containment-dependent lib tests and CLI
integration tests share the same cgroup probe and print one `SKIP <test>:
<reason>` line when that manager is absent. CI runs plain
`cargo test --locked --all-targets`; tests decide at runtime whether to execute.
A Linux runner inside a delegated user manager runs the complete suite.

The Nix development shell also pins the supply-chain tools through
`flake.lock`. Audit the exact Cargo lockfile and enforce the repository policy
with:

```bash
nix develop path:$PWD -c cargo audit --deny warnings
nix develop path:$PWD -c cargo deny --locked check -D warnings advisories bans licenses sources
```

The `path:$PWD` flake reference addresses the current worktree explicitly. The
flake exports the installable `maco` package and `apps` outputs documented in
[`docs/PACKAGING.md`](docs/PACKAGING.md), plus the development shell used by
these gates. Release contents of the Cargo package remain selected
independently by Cargo, whose package manifest excludes `.agents`, `.github`,
`.maco`, and `AGENTS.md`.

`cargo fetch --locked` is the explicit online boundary for Rust dependencies in
a fresh checkout. Once that checksum-verified closure is present in the Cargo
cache, the build can be repeated without dependency resolution or network
access:

```bash
cargo fetch --locked
cargo check --locked --offline --all-targets
```

The Nix shell pins the Rust/native toolchain, while `Cargo.lock` pins crates.io
versions and checksums. The Cargo configuration forces the checksum-verified
`libgit2` and zlib sources from that closure instead of ambient system copies.
Dependency unification removes `foldhash` and therefore needs no Zlib license
exception for that crate. Separately, the vendored `libz-sys@1.1.28` build
embeds stock zlib: `deny.toml` records its combined crate/native license
expression and accepts Zlib only for that exact crate version.
The project does not keep a separate crate mirror or RustSec database snapshot,
so a completely empty machine still needs the explicit fetch steps before
offline verification.

### Coordination benchmarks

Run the bounded Criterion suite with:

```bash
cargo bench --no-run
cargo bench
```

Every case in `benches/coordination.rs` owns an isolated, committed
`tempfile` plus `git2` repository fixture. Fixture construction and public-API
success probes run outside the timed loops. The groups measure:

- `claim_acquire_release`: persisted `SyncStore` claim plus release for one
  path by token and a four-path claim by agent.
- `claim_contention`: two disjoint successful claim/release cycles started
  together, and an overlapping ownership handoff that completes two successful
  claim/release cycles.
- `claim_concurrency_disjoint`: successful disjoint claim/release throughput at
  bounded thread counts of 1, 4, and 8.
- `repository_queries`: public small-repository inventory scan, semantic scan,
  and semantic risk query over a precomputed map.

The suite uses 10 samples, a 300 ms warm-up, and a 700 ms measurement window per
case so a complete local run stays modest.

**DEFERRED SCOPE:** This first issue #25 increment does not benchmark:

- managed-worktree registry create/list/remove lifecycle or merge preview/apply
  throughput, because successful setup requires the capability-bound managed
  worktree API tracked by issue #11;
- semantic merge-conflict classification, because
  `classify_semantic_conflicts` is currently crate-private;
- ntfs3 filesystem-profile sweeps; p50/p95/p99 and lock wait/hold
  instrumentation; state amplification; published concurrency limits; or CI
  regression thresholds.

### Provisional model-mix evaluation fixtures

**Artifact notice for this README section:** this section itself documents only
provisional deterministic fake evidence over a hand-authored plan. This section
is ineligible evidence for production use, production economics, or any
production/default model decision.

`tests/fixtures/model_mix_evaluation` is the phase-A contract for the Issue #26
model-mix evaluation harness. The records are deterministic fake evidence
generated by `src/evaluation.rs`; no provider, supervisor, held-out command, or
hand-authored plan was executed to produce them. Cost-shaped values are
synthetic fixture data rather than prices.

The version-1 experiment fixture set contains (the current results/summary wire
schema is version 4; version 3 remains the pre-objective-selection readable
legacy):

- `hand-authored-plan-v1.json` explicitly identifies itself as a provisional
  hand-authored plan used only to generate deterministic fake evidence. It is
  ineligible for production use or production/default decisions. It is inert
  input whose exact bytes are bound by the manifest's SHA-256 digest.
- `manifest-v1.json` explicitly identifies itself as a provisional manifest for
  deterministic fake evidence over that hand-authored plan. It is ineligible
  for production use or production/default decisions. The strict
  `EvaluationManifest` binds the goal, declared base commit, plan digest,
  wall-time and dispatch limits, held-out commands, three repetitions, and
  every complete role/model profile.
- `runs-v1.json` explicitly identifies itself as provisional deterministic fake
  run evidence over that hand-authored plan. It is ineligible for production
  use or production/default decisions. The strict `EvaluationResults` snapshot
  uses fake seed 26; its 12 synthetic runs cover four profiles and retain fake
  success, failure, and timeout outcomes. Every repetition records synthetic
  dispatch, error, usage, cost, wall-time, churn, conflict, diff, held-out, and
  review values. Per-role usage is explicitly serialized as `synthetic_fake`
  (`RoleUsageObservation::SyntheticFake`), never process-observed. Result
  validation rejects synthetic dispatch or wall-time values above the manifest
  limits and rejects missing, unexpected, or over-256-byte execution error
  evidence.
- `summary-v1.json` explicitly identifies itself as a provisional deterministic
  fake summary over that hand-authored plan. It is ineligible for production
  use or production/default decisions. The strict `EvaluationSummary`
  projection contains validated synthetic aggregates and a synthetic
  cost-versus-quality Pareto frontier. Its quality axis retains held-out
  validation, breadth, and anti-shortcut components, so test pass rate, LOC,
  or low cost alone cannot stand in for quality. Integral metric and quality
  means are exact machine-readable rationals with `total` and `count` fields,
  including when the total is not divisible by the number of repetitions.
- `supervisor-final-execution-v2.json` is a synthetic, shape-compatible bounded
  projection of a `supervisor-final.json` envelope carrying
  execution/economics schema v2. The
  harness consumes assignment lifecycle counts, configured and achieved
  concurrency, the explicit policy-observation marker, every role's resolved
  model and reasoning effort, and aggregate usage/cost. Its paired
  `supervisor-final-execution-v1-legacy.json` fixture proves that configured
  values from an older report are not substituted for missing observations.

Results schema v3 added a separate `execution_telemetry_comparability` value
on each same-repetition dispatch comparison. Schema v4 is the current scored
wire: it requires canonical `objective_scoring` provenance and is the family
`maco evaluation rescore --family evaluation` accepts. Resolved model/effort
differences remain dispatch-selection evidence; assignment, fan-out, and usage
differences remain execution-telemetry evidence and do not masquerade as a
model-selection difference. A report without economics schema v2, complete
resolved role bindings, achieved mean concurrency, or complete aggregate usage
is explicitly `incomparable`. Legacy results schema v2 remains readable and
maps a missing execution comparison to `incomparable`; no missing count, width,
model, effort, token, or cost is defaulted to zero or to a configured value.

Phase A does **not** establish Issue #26 requirement-4 observed
isolated-repository-state comparability. It checks consistency among declared
manifest inputs and generated fixture fields only, with status
`not_established_deferred_to_phase_b`. Its `declared_inputs_digest` is not an
observed checkout, worktree, tree, HEAD, or dirty-state fingerprint, and it
cannot detect genuine repository-state divergence. Observing and refusing
non-equivalent isolated starting states through the real goal-to-integration
path is deferred to Phase B and Issue #22.

Actual real-model executions, observed isolated-worktree identity, and any
production/Pareto conclusion remain Issue #26 Phase B. That phase is currently
blocked on Issue #77's writable end-to-end real-provider path; the Phase-A
adapter and fixtures do not claim that a provider executed the recorded model
slug.

The runner entry point itself requires the exact supplied plan bytes, binds
them to the manifest digest, and validates them before a deterministic fake run
can begin. Invalid or unlabelled input returns
`EvaluationError::InvalidHandAuthoredPlan`; a digest mismatch returns
`EvaluationError::HandAuthoredPlanBindingMismatch`. Plan validation is not an
optional caller-side preflight.

Validate the typed fixture contract and exact deterministic snapshot without
running a supervisor, provider, or held-out command:

```bash
cargo test evaluation::tests --lib
```

The ignored regeneration test is an explicit maintainer action:

```bash
cargo test evaluation::tests::regenerate_committed_evaluation_fixtures \
  -- --ignored --exact
```

The same fixture generator is also the `maco evaluation run` CLI. It still
generates deterministic fake evidence from a versioned manifest and a
digest-bound hand-authored plan; it does not inspect the repository or execute
a provider, supervisor, or held-out command. `--execution` defaults to
`deterministic-fake`. `--allow-real-provider` acknowledges a future real
provider path and is still refused by the current runner.
`maco evaluation experiment` runs the same goal/spec under multiple profiles
through isolated Fake supervise and likewise refuses real-provider execution.

```bash
cargo run -- evaluation run tests/fixtures/model_mix_evaluation/manifest-v1.json \
  --plan-file tests/fixtures/model_mix_evaluation/hand-authored-plan-v1.json --json
```

### Local fake eval-harness

`maco eval-harness run <manifest.json>` completes each declared role mix
through the local fake provider and records mix plus per-role outcomes. Version
1 manifests use the v1 local-fake path. Version 2 manifests are routed to the
Issue #26 v2 operator path. `maco eval-harness run-v2 <manifest.json>` always
parses the v2 manifest schema and refuses a v1 document. Both commands accept
`--json`. Real network providers are refused. A v2 `provider_request` of
`real_provider` fails closed: omitting the explicit opt-in is
`RealProviderOptInRequired`, and `allow_real_provider=true` is still
`RealProviderUnavailable`. The v2 local fake path emits machine-readable
comparable results (`schema` such as `eval_harness_comparable_fake_results_v2`)
with `production_eligible=false` and does not write cwd artifacts.

```bash
cargo run -- eval-harness run tests/fixtures/eval_harness/manifest-v2.json --json
cargo run -- eval-harness run-v2 tests/fixtures/eval_harness/manifest-v2.json --json
```

Real-provider experiments are a strict future opt-in boundary. A future runner
must require an explicit operator choice of provider and models, obtain
credentials outside committed fixtures, start every repetition from a freshly
verified equivalent isolated state, retain failures rather than filtering them,
and write new evidence without replacing phase-A fixtures. The v1 phase-A
schema and fake harness exercise unsuccessful-result retention and bounded
limit/outcome observability only; they do not execute Issue #22 or a real
provider. Merely having credentials or real-looking model labels must never opt
in.

Phase B remains required: once the Issue #22 path is available, one command
must rerun every profile and repetition from the bound goal and base through
goal-to-integration, use the v1 outcome and dispatch-count fields, enforce
the same limits and held-out grading contract, and emit schema-compatible run
and Pareto results without replacing these phase-A fixtures. The phase-A
fixtures do not claim that command exists.
Gate-policy/classifier corpus experiments remain separate and depend on the
Issue #28 production broker path.

### Operator objective profiles

Supervisor routing accepts a named, versioned objective profile. The built-in
`maco-default-objective-v1` profile preserves the existing quality weighting
exactly: held-out validation 50%, breadth 25%, and anti-shortcut quality 25%.
Its tradeoff weights preserve the current cost-first selector behavior. The
profile contains no switch-cost term.

Repository-specific profiles may be declared only in the fixed repository-root
file `maco-objective-profiles.json`. MACO opens that file through its bounded,
no-follow repository-local reader and rejects symlinks, path aliases, unsupported
schema versions, unknown fields, duplicate profile IDs, invalid names, and
weights that are out of range or do not sum to 100. The CLI never accepts an
alternate profile-file path.

Selection precedence is `--objective-profile NAME` over the authored
`objective_profile` plan field over the built-in default. Both `maco supervise
plan` and `maco supervise run` expose the flag; the plan command records the
request in its normalized output, while the run command resolves the effective
profile once against the discovered repository before selector initialization.
Unknown profile names and invalid override files fail before child dispatch.
Retries and budget degradation reuse that frozen resolution instead of reading
mutable configuration again.

New `supervisor-final.json` reports retain the resolved profile under
`role_economics_profile.resolved_objective_profile`, including its immutable
ID, version, built-in or repository-override source, content hash, quality
weights, and every effective tradeoff weight. Older reports remain readable;
the generated schema requires this evidence for newly finalized reports.

Supervisor routing interprets the default 100%-monetary profile as the exact
legacy selector baseline. Nonzero retry/rework and human-review weights are
supported as explicit monetary cost-proxy adjustments, proportional to their
weights relative to the nonzero monetary baseline. They are not retry rates,
review load, or independent observations. A nonzero quota weight fails closed
because this branch has no typed, contract-backed per-runtime quota evidence;
a nonzero latency weight likewise fails closed because it has no typed
per-candidate observed or predicted latency evidence. Missing evidence is never
scored as numeric zero.

The 50/25/25 quality decomposition is frozen for evaluation-side consumers;
supervisor selector hard quality and authority gates remain unchanged and
non-weightable. Operator profile selection and immutable review evidence are
live. Historical rescoring of stored evaluation documents is available as
`maco evaluation rescore` and does not overwrite the stored results file. The
GUI tracked by #152 remains planned.

### Historical evaluation rescoring

`maco evaluation rescore` re-scores a validated stored results document under a
different named objective profile. The stored file is never overwritten. The
command requires:

- a positional manifest path matching the selected family
- `--results <file>` for the stored document
- `--family evaluation|experiment`
- `--objective-profile <name>` resolved from the repository override file or
  the built-in profiles
- optional `--repo` (default `.`) used only to resolve that named profile
- optional `--json`

`--family evaluation` expects stored `EvaluationResults` schema v4 plus an
`EvaluationManifest`. `--family experiment` expects stored `ExperimentResults`
schema v2 plus an `ExperimentManifest`. Missing `--results`, `--family`, or
`--objective-profile`, and an unknown family name, fail at argument parsing.
Unknown profile names fail before scoring. The JSON envelope records
`kind=historical_rescore`, the original and applied profile bindings, the
complete original stored document, and only the preference-bearing selection
recomputed from the stored preference-free Pareto evidence.

```bash
cargo run -- evaluation rescore tests/fixtures/model_mix_evaluation/manifest-v1.json \
  --results tests/fixtures/model_mix_evaluation/runs-v1.json \
  --family evaluation --objective-profile maco-default-objective-v1 --json
```

### Provisional named effort default

When a supervisor plan supplies no `role_models` override, MACO selects the
named `provisional-phase-a-hybrid-effort-v1` profile. Every role's ordinary
default model binding is the single standard slug `gpt-5.6-sol`; cheaper model
tiers are not availability substitutes in the default profile. The effort
fallbacks remain `xhigh` for the supervisor, child orchestrator, and auditor,
`medium` for workers, and `high` for the gate classifier. A per-role
`role_models` entry can still replace authored role data, but the acceptance
gate and review-auditor hard floors remain enforced.

Each default role selection retains the ordered-catalog data shape and typed
resolution observations. Its ordinary availability `models` list is empty, so
the default path never silently substitutes a cheaper slug. The separately
named `budget_degrade_models` list remains available only to the typed
mechanical-Worker degradation ladder. MACO consults the authenticated runtime
catalog once; when `gpt-5.6-sol` is present, every default role resolves to it.

The chain is ordinary plan/profile data and round-trips without a code-shape
change:

```json
{
  "model": "gpt-5.6-sol",
  "reasoning_effort": "xhigh",
  "unavailable_model_fallback": {
    "ordered_catalog_chain": {
      "models": [],
      "budget_degrade_models": ["gpt-5.6-terra", "gpt-5.6-luna"],
      "on_exhausted": "runtime_default"
    }
  }
}
```

The compatibility name `all-frontier-v1` remains available when a plan supplies
the public `all_frontier_role_models()` data explicitly. Historical execution
telemetry using `provisional-phase-a-hybrid-model-tier-v2` remains readable,
but newly finalized reports use the effort-only name.

An assignment may select a typed `reasoning_effort` value (`minimal`, `low`,
`medium`, `high`, `xhigh`, `max`, or `ultra`). Missing assignment values use
the role fallback. The selected task effort applies to child, nested-worker,
gate-classifier, and review-auditor duties; gate-classifier duties clamp at
`high` and review-auditor duties clamp at `xhigh`. The clamp is retained as
`resolution_observation=hard_floor_clamped` rather than silently rewriting the
authored request.

The availability fallback order and the economics downgrade order are distinct
data. `models` answers which advertised model may substitute when the primary
is absent. `budget_degrade_models` is a monotone cheaper-tier list consulted for
an explicitly mechanical Worker assignment after a run crosses a soft budget
ceiling or when the scheduler observes the low-difficulty mechanical trigger;
an arbitrary plan fallback is never assumed to be cheaper.

### Budget-pressure degradation

The scheduler consumes `BudgetAction::Degrade` before admitting new work, but
never lowers a child-orchestrator, gate, or auditor judgment binding. Worker
degradation is available only when every Worker in that assignment declares a
typed `mechanical_duty`. The scheduler first selects a distinct,
runtime-advertised, authority-eligible model from the requested plan's Worker
`budget_degrade_models`, then lowers Worker effort on the next applicable rung,
and only then halves the remaining fan-out bound (never below one). If the
Worker ladder has no eligible target, the model rung refuses explicitly and
does not advance to fan-out. A hard ceiling still halts new dispatch and drains
already-started assignments. Concurrent admission waits until each newly
spawned assignment has either committed its child budget reservation or
completed without one, so the next policy decision cannot race past an
invisible reservation.

`mechanical_duty` accepts `apply_explicit_text_replacement`,
`run_preselected_command`, `format_preselected_files`,
`enumerate_declared_artifacts`, or `validate_against_fixed_schema`. Omission is
fail-closed for Worker model and effort degradation; mixed marked/unmarked
Worker assignments retain their ordinary role bindings.

Every applied rung is retained in
`role_economics_profile.execution.budget_degradations` with the assignment ID,
typed trigger (`budget_pressure` or `low_difficulty_mechanical`), budget reasons,
the Worker binding before and after the change, and the full effective child
model, effort, and fan-out. The assignment selection ledger projects the
resulting Worker model and effort without rewriting judgment-role rows.
`observation=admission_policy_resolved` deliberately says that this is
scheduler admission evidence; `commands_run` remains the process evidence for
a dispatch that actually started. When assignments use different mechanical
Worker bindings, the aggregate Worker role binding is marked
`assignment_specific` instead of claiming one model or effort for the whole
run.

### CLI run ceilings

`maco supervise run` and `maco autopilot run` accept the same per-supervisor-run
hard ceilings:

- `--max-tokens` (`--max-total-tokens` alias)
- `--max-cost-usd` (`--max-total-cost-usd` alias)
- `--max-duration-seconds` (`--max-total-duration-seconds` alias)

Token, cost, and duration values must be finite positive values. Token and cost
flags tighten an authored or goal-derived plan's `run_budget` values by taking
the minimum. If the resulting hard ceiling is below a plan soft threshold, the
soft threshold is clamped to the hard ceiling. Duration likewise composes with
`run_budget.max_duration_seconds` by taking the minimum and stops new admission
once elapsed time reaches the bound. The effective limits, elapsed seconds, and
remaining duration are retained in `supervisor-final.json`. When any CLI ceiling
is supplied, the run budget ledger also retains the original plan and CLI
values under `run_budget.sources` so the override is visible independently of
the composed `limits`.

The same two commands also accept optional workspace rolling-quota ceilings:

- `--max-rolling-tokens`
- `--max-rolling-cost-usd`
- `--rolling-window-seconds`

A rolling quota is bound only when at least one of `--max-rolling-tokens` or
`--max-rolling-cost-usd` is set; `--rolling-window-seconds` alone does not
create a quota. Values must be finite and positive. When a ceiling is set and
the window is omitted, the window defaults to 86400 seconds (24 hours). These
ceilings apply across supervise/autopilot runs in the workspace rolling
ledger; they are distinct from the per-run `--max-tokens` / `--max-cost-usd` /
`--max-duration-seconds` flags. `maco inbox run` exposes the same three rolling
flags for inbox Autopilot dispatches and rejects the per-run supervise
ceilings.

Autopilot propagates the per-run limits to its source and generated follow-up
supervise dispatches. Completed run-budget results also update MACO's
authenticated rolling workspace ledger; in-flight reservations remain local to
the run.

### Repository-local quota pools

`maco supervise run` and `maco autopilot run` accept an optional
`--quota-config REPO_RELATIVE_FILE`. The path is resolved inside `--repo` with
no symlink traversal, and the bounded JSON file is parsed with unknown fields
denied. When the flag is omitted, admission and selection retain their existing
behavior.

The file declares operator-known entitlements. MACO does not call provider
billing, quota, rate-limit, or pricing endpoints: availability and marginal
cost come only from this config plus completed results in the authenticated
workspace ledger. For example, this source pool may degrade only to the exact
declared alternative. Prices are operator-declared config evidence, never live
quotes:

```json
{
  "version": 1,
  "pools": [
    {
      "runtime": "codex",
      "account": "operator-primary",
      "pool_kind": "subscription_included",
      "window": "calendar_month",
      "nominal_capacity": { "units": 1000000 },
      "rate_limits": { "max_concurrent_sessions": 2 },
      "exhaustion_behavior": "degrade",
      "declared_list_price_microunits": 1000,
      "authorized_alternatives": [
        {
          "runtime": "cursor",
          "account": "operator-backup",
          "window": "calendar_month"
        }
      ]
    },
    {
      "runtime": "cursor",
      "account": "operator-backup",
      "pool_kind": "metered",
      "window": "calendar_month",
      "nominal_capacity": "unknown",
      "rate_limits": { "max_concurrent_sessions": 1 },
      "exhaustion_behavior": "fail_closed",
      "declared_list_price_microunits": 5000
    }
  ]
}
```

A bounded source at zero remaining capacity obeys its configured behavior.
`fail_closed` refuses dispatch. `degrade` considers only exact
`authorized_alternatives`, and each alternative must still pass catalog,
runtime, authority, policy, and publication gates; if none remains eligible,
selection refuses. Debug overrides cannot bypass quota exhaustion. The selected
pool state and exhaustion decision are retained as typed selection provenance
and assignment-ledger evidence. `max_concurrent_sessions` also tightens the
resolved scheduler fan-out.

On the production Codex path, the no-override child-orchestrator and auditor
commands are constructed with the profile's explicit model and resolved
assignment effort. Worker selection remains declarative data in the child
orchestrator prompt because nested workers are not launched as separately
process-observable commands; it is not per-worker model or usage evidence. The
supervisor entry completes the reported role profile rather than claiming that
the running supervisor launches itself. The `gate_classifier` entry currently
has only the deterministic-fake evaluation boundary described above; Issue
#28's writable production gate remains deferred.

Before a verified Codex run schedules any assignment, MACO invokes the trusted
system Codex CLI's non-bundled `codex debug models` command exactly once. The
preflight requires a validated `auth.json`, runs in the contained parent-Codex
network profile with a private `HOME` and `CODEX_HOME`, bounds and validates the
JSON catalog, and rechecks both the auth source and executable identity after
the command. Explicit custom executables never receive auth or provider network
access. Missing auth, a failed/nonzero command, unsafe containment, truncated or
malformed output, an empty catalog, duplicate slugs, or invalid slug syntax
fails closed before any child or auditor dispatch.

Exact slug membership in that immutable per-run catalog determines availability
for child and auditor command construction. A present slug remains explicit in
argv. An absent slug is `unavailable`, so the configured fallback is applied
before budget reservation and spawn-event dispatch:

| Configured fallback | Known-unavailable behavior |
| --- | --- |
| `runtime_default` | Clear the explicit model while preserving the configured reasoning effort, allowing the runtime to choose its default model. |
| `fail_closed` | Refuse the selection rather than dispatch with another model. |
| `local_deterministic_fake` | Use the deterministic local fallback only with the Fake runtime; reject it for Codex. |

The Fake runtime performs no catalog command and treats configured provider
models as unavailable, so its declared local fallback remains local. The Codex
CLI can return an in-memory or cached catalog when an online refresh fails;
therefore membership is runtime-advertised availability at preflight time, not
proof of a fresh entitlement check or a guarantee that a later provider launch
will succeed. MACO does not retry by cycling model names.

The single-slug model binding follows the evidence-backed cost-per-accepted-task
decision. Assignment-level effort matching is operationally selected but has
not yet been evaluated with real-provider resolved-effort telemetry, so the
combined profile remains `production_eligible=false`. Genuine Issue #26
evidence is required before its effort policy can be qualified for production
or revised on empirical grounds.

### Same-run context-switch cost

Automatic routing includes a conservative objective-profile cost when a role
changes model or runtime after an earlier assignment in the same supervisor
run. The built-in profile configures 10,000 microunits for a model change on
the same runtime and 25,000 microunits for a runtime change. Initial selection,
staying on the exact runtime/model pair, and changing only reasoning effort on
that same pair configure and charge zero. The effort-only case is deliberately
zero because this contract models runtime/model re-priming rather than every
assignment parameter change.

These defaults are inferred operating policy, not measured transition
telemetry. Operators can tune them through the existing versioned objective
profile. The charged term is normalized inside the existing checked
cost-per-accepted-task objective as
`ceil(configured switch cost × 10,000 / candidate posterior-quality basis points)`.
It therefore generally differs from the configured value unless candidate
quality is 10,000 basis points. Malformed values, zero-quality normalization,
intermediate or result overflow, and total-score overflow fail closed. The state
boundary is the previous assignment for the same role in the current supervisor
run, not process-global or cross-run mutable state.

Serialized selection evidence records the previous choice in the normalized
input and records each candidate's typed transition, configured switch cost,
charged switch term, and checked total score. The selected choice and runner-up
scores repeat the transition and charged term, so the finalized supervisor
artifact can reconstruct why staying or switching won.

This bounded Issue #201 increment does not implement measured transition
fitting, replay correction, oscillation telemetry or alarms, or safe-set policy
promotion. It also does not recreate Issue #150's profile loader, repository
override, or command-line override surface.

### Platform boundary

Linux is the fully supported security-sensitive runtime path. macOS and Windows
adapters cover portable Git, process, and state operations, but commands that
depend on Linux-only primitives such as `renameat2`, descriptor-confined review
views, or systemd containment return an explicit unsupported-platform error.
They do not silently fall back to weaker path or process checks. The Nix flake
evaluates Linux and Darwin development shells; Windows builds require a separate
Rust target/toolchain and are not provided by this flake.

## CLI Examples

Inspect a repository:

```bash
cargo run -- repo map --repo . --json
cargo run -- repo map --semantic --repo . --json
cargo run -- repo megafile query --repo . --json
cargo run -- repo megafile seed --repo . --json
cargo run -- repo megafile query src/lib.rs --repo . --json
cargo run -- repo query symbol WorktreeManager --repo . --json
cargo run -- repo query path src/worktree.rs --repo . --json
cargo run -- repo query risk --path src/worktree.rs --repo . --json
```

`repo map` and `repo megafile query` are read-only. In particular, querying an
uninitialized repository reports `initialized=false` and does not create an
authentication key, state directory, lock, or telemetry snapshot. Size
telemetry is written only by the explicit `repo megafile seed` command. The
sampler is language-agnostic: it reads bounded regular repository files and
records bytes and physical lines, including binary files, without requiring a
Rust parser. The authenticated report exposes the bounded retained event
history as `records` plus current per-path `assessments`; events include size
samples, claims, merge collisions, and accepted decompositions.

All megafile thresholds are configurable with `--file-bytes`, `--file-lines`,
`--growth-bytes`, `--growth-lines`, `--claim-count`, `--collision-count`, and
`--activity-window-records`. When none is supplied, the JSON calibration is
`bootstrap_provisional`: the defaults are operating starting points, not
empirically calibrated policy. Any override labels the assessment
`configured`. Before using megafile blocking or decomposition acceptance in a
real run, operators must review authenticated telemetry produced by real
repository activity and revise the provisional values with explicit configured
thresholds; bootstrap values are not production acceptance criteria. Continue
revising configured values when later real-run size, claim, or collision data
shows that the calibration no longer represents the repository. History is
bounded to 16,384 logical records and authenticated
snapshot storage is also bounded; older logical events are evicted, so this is
operational recent history rather than an indefinite audit archive.

Managed worktree creation derives a capability-bound repository cleanliness
input at command start and creates a linked worktree when the primary is
observed clean. A dirty primary fails with the required remedy before the
worktree is created:

```bash
cargo run -- worktree create agent-a --repo . --json
cargo run -- worktree create agent-b --repo . --gc-max-count 10 --gc-max-age-seconds 604800 --json
cargo run -- worktree create task-r2 --repo . \
  --supersede-retry-predecessor --apply-retry-supersession \
  --o2-launch-retention-defaults --json
```

List worktrees:

```bash
cargo run -- worktree list --repo .
```

Dry-run lifecycle cleanup for completed managed worktrees and retained Rust build
artifacts:

```bash
cargo run -- worktree gc --repo . --dry-run --json
cargo run -- worktree gc --repo . --dry-run \
  --allow-untracked-path TASK.md --json
cargo run -- worktree gc --repo . --targets-only --dry-run --json
cargo run -- worktree gc --repo . --targets-only
cargo run -- worktree gc --repo . \
  --machine-global-config /exact/path/to/machine-global.json \
  --machine-global-worktree-root-id worktrees \
  --machine-global-correlation scheduled-worktree-gc \
  --max-count 10 --max-age-seconds 604800 --max-total-bytes 10737418240 --json
cargo run -- worktree gc --repo . \
  --machine-global-config /exact/path/to/machine-global.json \
  --machine-global-worktree-root-id worktrees \
  --machine-global-correlation manual-worktree-gc \
  --keep-targets
```

GC classifies tracked changes separately from untracked-only paths. Tracked
changes always protect the lane. Untracked-only lanes are also protected by
default and report their complete bounded path set; full-lane cleanup is
eligible only when every such path exactly matches a repeatable
`--allow-untracked-path <repo-relative-path>` value. This is an exact path list,
not a glob or blanket ignore, and is bounded to 128 entries and 64 KiB in
aggregate because a workspace sweep copies it into each per-root report.
Repository-ignored files are included in this classification and need the same
exact authorization. Only documented MACO runtime categories (`target/`,
`.maco/`, `.maco-cache/`, and the `.agent[s]` temp/storage/live roots) remain
separately disposable. An
untracked file may be a worker's only copy of real output. Apply mode repeats
the bounded status classification immediately before journaling full-lane
removal and protects the lane if a new tracked or unapproved untracked path
appeared. GC removal records the exact, platform-lossless clean or untracked-path
classification and the target's absent/present filesystem identity in its
authenticated recovery journal, then revalidates both immediately before
quarantine. New explicit removals record a distinct origin. Explicit `--force`
bypasses dirtiness but never target liveness; a legacy operation with no origin
is always ambiguous in every unfinished recovery phase and cannot continue until
the operator reruns the explicit force-removal command to reauthorize it. That
command replaces the pending branch-deletion choice with its current explicit
choice rather than inheriting a stale journal value. GC also keeps
worktrees with
active MACO execution leases or active path claims for the same agent id.
Without retention filters, every eligible inactive managed worktree is selected
for removal. `--max-total-bytes` adds a size dimension to `--max-count` and
`--max-age-seconds`: after age/count exclusions, GC walks eligible lanes from
newest to oldest and retains the newest prefix whose combined apparent size is
within the byte budget. Protected or otherwise ineligible lanes are not charged
to that retention budget, so it is not a global on-disk ceiling. Apparent size
is filesystem metadata length, not allocated blocks or a promise about physical
disk space, and sums descendants only rather than the lane root inode itself.
The report exposes the
apparent bytes considered and estimates for bytes reclaimable and actually
reclaimed; full-lane estimates already include `target/`, while target-only
estimates count only `target/`, so they are not double-counted. Sizing is a
bounded, descriptor-relative, non-symlink-following walk; Linux additionally
confines the walk to the lane's exact mount. A timeout, limit, unsupported
platform, invalid target binding, or other sizing failure reports
`size_measurement_failed` and protects that lane instead of guessing. Retained
clean worktrees keep the checkout but lose their `target/` directory unless
`--keep-targets` is set. A second pass prunes
unregistered direct-child directories left under the managed worktree root. A
destructive second pass requires the three-part machine-global binding above, treats
all discovered orphans as one preflight set, and uses recoverable quarantine rather
than direct deletion. Dry-run discovery remains non-mutating and does not require the
binding.

The byte counters cover authenticated managed lanes and managed `target/`
cleanup only; orphan quarantine is reported by orphan counts and is not included
in the byte estimates. Creation-time size retention reserves the newly created
lane before considering older lanes. If that new lane alone exceeds the budget,
it remains reserved and the effective byte allowance for older lanes is zero.

`--targets-only` removes eligible `target/` directories while retaining every
managed lane, branch, untracked file, and registered association. Because it is
a separate operation, it rejects `--keep-targets`, every retention filter
(including `--max-total-bytes`),
untracked-path allowances, and machine-global orphan-cleanup bindings, and it
does not run orphan pruning. Tracked changes, active claims, and active leases
still protect the target; an untracked-only lane does not require an allowlist
because the lane and its files remain. On Linux, every target deletion scans a
bounded `/proc` snapshot for same-user processes. Explicit `CARGO_TARGET_DIR`
values are resolved in the process's own view: absolute paths through
`/proc/<pid>/root` and relative paths through `/proc/<pid>/cwd`. Canonical path
containment and bounded ancestor identity checks in both directions detect
aliases across mount namespaces without assuming textual path equality. Process
paths retain their `/proc/<pid>/root` access path for identity checks. Observer
canonical-path comparisons are used only when the process and observer mount
namespace identities match; a different namespace relies on rooted filesystem
identities and incomplete evidence is unknown. The
detector also parses bounded process command lines for split and `--name=value`
forms of Cargo's `--target-dir` and `--manifest-path` and rustc's `--out-dir`.
An explicit output under the target is live; a manifest inside the lane with no
explicit output protects the default Cargo target. The fallback association
scan always runs, even after a readable environment or command line has no
explicit target: a cargo/rustc/rustdoc/sccache-like process with a `cwd` inside
the lane protects the default Cargo target, while a process `cwd`, executable,
or readable file descriptor inside the target is live. File descriptors are
read with `readlink`; recognized non-filesystem `pipe`, `socket`, `anon_inode`,
and synthetic `memfd` or `dmabuf` targets are skipped, while deleted filesystem
links under the target still protect it. Environment, command-line, cwd,
executable, file-descriptor, bound, read, or timeout failures are unknown, not
clear for a possible build process. Linux user-manager helpers, non-build
systemd user services, and non-build processes with a readable command line but
an unreadable mount namespace are skipped because they do not execute build
work themselves; any cargo/rustc descendant remains a separately scanned
process. A live match is reported as `live_target`; an incomplete,
oversized, timed-out, or unreconciled scan is reported as
`target_liveness_unknown`, and both refuse deletion. Reports include bounded
typed PID, source, and cause evidence in JSON and human output.

The target directory's filesystem identity is bound before the liveness probe.
Target-only deletion passes that expected identity into the handle-relative tree
remover, and full-lane deletion rechecks it immediately before recording the
removal operation. Replacement is reported as `target_identity_changed` and the
lane is retained. The same protections apply to a target included in full-lane
removal. Recovery from a prepared removal rebinds the source, refuses any GC
target absent/present or identity change, reruns the real liveness detector for
every target including explicit-force removals, and revalidates the exact GC
dirtiness state before quarantine. On non-Linux platforms the detector conservatively reports
unknown, so target deletion remains disabled until a native detector is
implemented. These checks run at the removal boundary to narrow the race, but a
non-cooperating process can still start or create output after the final check.

Sweep every repository group beneath one workspace. The first command is a
dry-run because workspace sweeps never remove anything unless `--apply` is
explicitly supplied:

```bash
cargo run -- worktree sweep --workspace /exact/path/to/workspace --json
cargo run -- worktree sweep --workspace /exact/path/to/workspace \
  --apply --max-count 10 --max-age-seconds 604800 --json
cargo run -- worktree sweep --workspace /exact/path/to/workspace \
  --apply --keep-targets
```

The sweep discovers workspace-managed `.maco/worktrees/<repo>` roots through the
same default-root function used by managed creation. It also recognizes the
exact canonical `.worktrees` child of either the workspace repository itself or
a direct repository child; custom per-creation roots have no persisted
repository-level configuration to discover. The aggregate report identifies
each root kind and distinguishes roots that were inspected from roots skipped
before GC and roots whose GC attempt failed. `discovery_status` is
`no_roots_discovered` for a total miss and `roots_discovered` even when every
inspected root has zero actions; human output prints an explicit warning for the
former. Each root includes its resolved repository when available, a typed
failure when resolution or GC fails, and its nested GC summary. A failure in one
root does not stop later roots from being inspected. Retention flags and
`--keep-targets` are passed independently to each discovered root, so
`--max-count` and `--max-total-bytes` are per-root limits and dirty worktrees or
lanes with active leases or claims remain protected. Existing machine-global quarantine gates
also remain in force; the sweep does not weaken them. A workspace-managed group
is associated only when it is the exact result of the creation default-root
function. In particular, `<repo>/.maco/worktrees` is not adopted as that
repository's managed root because its creation default is
`<repo-parent>/.maco/worktrees/<repo>`; sweep the parent workspace for that
layout, or use the separately validated `<repo>/.worktrees` convention.

Repository-local dry-runs also preview healthy Git-registered lanes that predate
the authenticated MACO worktree registry. A stale linked-worktree child cannot
override the exact primary-repository association used to discover that root.
When the host cannot open legacy MACO state safely, the root remains a typed
`failed` result, but the nested dry-run report still classifies registered lanes
and exposes exact untracked paths, byte estimates, merge state, and target
liveness. The fallback status probe is read-only and ignores ignored files, like
ordinary `git status`; it exists only to make legacy lanes visible. It never
grants apply-mode removal authority: destructive sweep still requires a valid
authenticated MACO binding and safe private state.

Run the repository-local lifecycle scheduler only with the automation features
that the operator intends to inspect. The scheduler is dry-run by default, and
every feature is off by default, so the bare command preserves the existing
manual `worktree gc` and artifact-prune behavior:

```bash
cargo run -- worktree lifecycle --repo . --json
cargo run -- worktree lifecycle --repo . \
  --auto-reap-merged --trunk-ref refs/heads/main \
  --retry-successor issue-65-r2 \
  --startup-reconciliation --o2-launch-retention --json
cargo run -- worktree lifecycle --repo . --apply \
  --auto-reap-merged --trunk-ref refs/heads/main \
  --startup-reconciliation \
  --destructive-reconciliation \
  --machine-global-config /exact/path/to/machine-global.json \
  --machine-global-worktree-root-id worktrees \
  --machine-global-correlation lifecycle-2026-08-12 --json
```

The report aggregates worktree classification/reclamation, startup
reconciliation, and scheduled artifact retention into one human summary or one
JSON document. `--apply` is required before any enabled lifecycle action can
mutate state. Merged and retry-predecessor lanes still pass through the ordinary
GC cleanliness, exact untracked-path allowlist, size, target-liveness, active
lease, active claim, and machine-global quarantine guards. Retry derivation is
from the exact `--retry-successor <AGENT_ID>`; both generations must have live,
verified authenticated bindings under one root and one canonical branch
family. A missing, stale, or ambiguous generation is reported and retained.
Worktree creation can invoke that same classifier with
`--supersede-retry-predecessor`; destructive reaping remains a separate
`--apply-retry-supersession` opt-in once capability-bound production creation
is available.

Merged-lane automation requires an exact local reference such as
`--trunk-ref refs/heads/main`. It never treats an arbitrary current or detached
`HEAD` as trunk, and it re-resolves ancestry at the deletion boundary. A merge
apply only applies a patch to the primary checkout and does not advance the
trunk reference, so `merge apply --auto-reap-merged --trunk-ref ...` reports a
just-applied lane as unmerged. After the integration commit or fast-forward, a
finalization rerun classifies and, with `--apply-auto-reap`, reaps the fully
merged lane. The post-reap Git prune pass is limited to the exact selected
lane; unrelated stale registrations are counted as protected and left intact.

The `--o2-launch-retention` profile schedules only the actual O2-launch run
store: it keeps the newest 10 runs and gives idle unfinalized artifacts a
seven-day grace. Managed worktree metadata has no trustworthy O2-origin tag, so
this flag deliberately does not broaden worktree deletion to every managed
lane. Merged-lane retention is independently explicit through
`--auto-reap-merged`, `--trunk-ref`, and the worktree age/count/apparent-byte
limits. Artifact count/grace can be overridden with `--artifact-keep` and
`--artifact-unfinalized-grace-seconds`; artifact age and apparent-byte ceilings
are also available. Artifact safety decisions are
never inferred: `--reclaim-unverifiable` and
`--acknowledge-external-writers-stopped` are separately named opt-ins and are
rejected unless `--o2-launch-retention` schedules artifact pruning. Do not
acknowledge stopped external writers while any same-UID writer may still append
to that store.

Startup reconciliation distinguishes authenticated records whose expected
directory or Git registration is missing, exact authenticated stale Git
registrations, and direct on-disk lane directories that are present under a
known or explicitly selected managed root but deregistered. Detection and reporting require
`--startup-reconciliation`. Destructive resolution requires all three of
`--startup-reconciliation`, `--destructive-reconciliation`, and `--apply`, and
then remains subject to authenticated identity, pending-operation recovery,
active claims, active execution leases, and apply-boundary state rechecks.
Missing-both records are forgotten without deleting their preserved branch;
an exact missing-path Git registration is pruned individually. Present
deregistered directories are never deleted directly: they require the reviewed
machine-global config/root/correlation binding and move into recoverable
quarantine. Unauthenticated Git registrations, duplicate names across roots,
and other unverifiable findings fail closed and remain visible in the aggregate
report.

Perform explicitly authorized force cleanup and delete a MACO-owned branch:

```bash
cargo run -- worktree remove agent-a --repo . --force --delete-branch
```

Claim paths for an agent:

```bash
cargo run -- sync claim agent-a src README.md --repo . --json
cargo run -- sync claim agent-b src/large.c --repo . --file-lines 2000 --claim-count 4 --json
```

Claims remain backward compatible at the top-level JSON fields and also return
the typed `claim` and `warnings` fields. A threshold crossing is warn-only at
claim time; it does not weaken or bypass the exclusive claim gate. The
authenticated claim is committed first and its claim-frequency event is then
written to the authenticated megafile history. If that second write fails, the
command fails closed and states that the claim token remains durable; inspect
`sync status` and explicitly release that token before retrying instead of
blindly creating a second claim. The event journal is observability only and is
not a megafile authority.

Check the current owner for a path:

```bash
cargo run -- sync owner src/lib.rs --repo .
```

List active claims:

```bash
cargo run -- sync status --repo . --json
```

Release one claim by token:

```bash
cargo run -- sync release 1 --repo .
```

Release all claims for an agent:

```bash
cargo run -- sync release-agent agent-a --repo .
```

Run a local orchestration plan:

```json
{
  "default_timeout_seconds": 600,
  "worktree_reuse_policy": "clean",
  "repo_validation_commands": [
    {
      "name": "repo smoke",
      "command": "cargo test",
      "timeout_seconds": 300
    }
  ],
  "agents": [
    {
      "id": "agent-a",
      "paths": ["src"],
      "command": "cargo test",
      "validation_commands": [
        {
          "name": "agent fmt",
          "command": "cargo fmt -- --check",
          "timeout_seconds": 60
        }
      ],
      "env": {
        "RUST_BACKTRACE": "1"
      }
    },
    {
      "id": "agent-b",
      "paths": ["README.md"],
      "depends_on": ["agent-a"],
      "timeout_seconds": 60,
      "command": "printf '# Updated\\n' > README.md"
    }
  ]
}
```

```bash
cargo run -- orchestrate validate plan.json --json
cargo run -- orchestrate run plan.json --repo . --jobs 2 --patch-dir .maco/patches --reuse clean --run-id demo --checkpoint-dir .maco/checkpoints --json
cargo run -- orchestrate resume .maco/checkpoints/demo.json --repo . --plan-file plan.json --jobs 2 --patch-dir .maco/patches --json
```

The orchestrator validator checks that plan paths do not overlap, dependencies
are known and acyclic, commands are non-empty, and timeouts are positive.
Verified `orchestrate run` derives the capability-bound repository cleanliness
input before assignment worktrees are created; a dirty primary repository is
refused with the required remedy. Execution
creates or reuses a linked worktree for each agent id according to
`worktree_reuse_policy` or CLI `--reuse`, claims all requested paths before
running commands, runs dependency-ready agents up to `--jobs`, and releases
claims at the end. A failed agent skips only its transitive dependents;
independent branches continue. Dependency edges control execution order and
failure propagation only: predecessor edits are not injected into a dependent
agent's worktree, which starts from the captured run base. Use `--keep-claims`
to leave acquired claims active for debugging.
`clean` is the default reuse policy, `required` requires existing clean
worktrees, `fresh` refuses existing worktrees, and `reset` moves a clean,
unclaimed stale worktree to the current primary HEAD while refusing dirty,
untracked, or actively claimed worktrees.

Run summaries include command status, duration, timeout state, changed paths,
unclaimed changed paths, captured stdout/stderr summaries, candidate bindings,
and optional patch paths. Each agent's `validation_commands` sees that agent's
bound candidate state. A validation command that changes Git-visible candidate
state fails validation, even when the command otherwise exits successfully.
`--patch-dir` writes the already captured per-agent binary patch against the run
base, the primary HEAD captured for that run.

Repo-level validation materializes the exact successful, non-overlapping agent
patch set in plan order into a disposable managed worktree based on the captured
run base; it never runs against or writes the primary worktree. The summary and
checkpoint bind this target to the base object id, combined diff digest, changed
paths, candidate count, and patch sizes. Repo validation also fails if it mutates
that materialized state. A run with no candidate changes records and validates
an explicit base-only target.

Patch and checkpoint output roots are created owner-private when absent. An
existing root must be owned by the current user with mode `0700`; output leaves
are `0600`, single-link regular files. Roots overlapping a child worktree are
refused, and patch/checkpoint writes retain descriptor capabilities instead of
reopening post-child paths.

`maco orchestrate resume <checkpoint-file>` treats the external JSON file only
as a bounded repository-locator/reference envelope. Its repository binding and
MAC are verified before the journal run id, plan path, or saved state becomes
authoritative. The owner-private v3 journal lives under the repository common
directory, holds a full-lifecycle exclusive run lock, and uses immutable,
contiguous, previous-MAC-linked records plus an authenticated durable head.
This detects mutation, truncation, duplication, and reordering relative to the
current authenticated head. The guarantee depends on the owner-private state
root remaining secret and being hidden from child processes; without an
external monotonic anchor it cannot detect rollback to an older coherent
record prefix and matching authenticated head under the same key, nor
restoration of an entire older valid key, journal, and head snapshot by an
attacker who obtained them.

Resume also requires the filename, repository, primary HEAD, plan snapshot, and
worktree bindings to match. A `command_started` record without a durable
completion is an uncertain outcome and is never retried automatically. A
completed command carries an exact worktree-state binding; resume compares the
live state to it, reruns validation, and recaptures the candidate without
rerunning the command. Completed candidates and repo validation are recaptured
and rerun before success is restored. Unauthenticated checkpoint v1/v2 files
are refused with guidance to start a new v3 run.

Collect and preview agent output:

```bash
cargo run -- worktree diff agent-a --repo . --json
cargo run -- worktree diff agent-a --repo . --claim src --full-diff --json
cargo run -- orchestrate collect summary.json --repo . --json
cargo run -- merge preview agent-a --repo . --claim src --json
cargo run -- merge preview agent-a --repo . --claim src --validation-report validation.json --json
cargo run -- merge preview agent-a --repo . --claim src --require-validation --validation-report validation.json --json
cargo run -- merge preview agent-a --repo . --claim src/large.c --block-megafiles --json
cargo run -- merge apply agent-a --repo . --claim src --validation-report validation.json
cargo run -- merge apply agent-a --repo . --claim src --require-validation --validation-command "cargo test" --json
cargo run -- merge apply agent-a --repo . --claim src \
  --auto-reap-merged --trunk-ref refs/heads/main --apply-auto-reap --json
cargo run -- merge apply split-large-c --repo . --claim src/large.c --claim src/large/ --block-megafiles --decomposition-target src/large.c --decomposition-run-id issue19-split-large-c --json
cargo run -- merge apply agent-a --repo . --claim src --force-dirty-primary --force-stale-base --force-unclaimed-edits
```

Merge apply refuses dirty primary worktrees, stale agent bases, unclaimed edits,
validation failures, and apply conflicts unless the matching explicit force flag
is passed. Apply-check failures themselves are still blocking unless
`--force-apply-conflicts` allows a successful three-way apply check.

Megafile merge policy is also warn-only by default. `safety.megafile_warnings`
contains the authenticated threshold assessments without changing readiness.
`--block-megafiles` makes threshold-crossing changed paths blocking. For CLI
schema compatibility this policy currently reuses the existing
`excluded_reference` `ApplyBlocker`; its `ApplyBlockerDetail` is unambiguous:
the exact paths, a megafile-specific message, available validation
reports/commands, and a `megafile_decomposition` next-safe operation are
included, while `safety.megafile` and `safety.megafile_warnings` carry the
typed assessment. A future dedicated `megafile_threshold_exceeded` blocker
would require a coordinated versioned update of all exhaustive blocker
consumers.

`merge preview` never records a collision. `merge apply` records paths when its
direct apply check detects a collision, including the direct-check failure that
is allowed to continue via a successful opt-in three-way check. That write uses
the authenticated durable megafile store before a blocked merge decision is
returned. An authenticity or persistence failure aborts the decision and never
turns a blocked merge into an apply.

### Public gate-denial contract

`gate_denial::GateDenial` is the versioned public envelope for passing a gate
denial to correction consumers. It carries a typed reason family, derived
retryability, canonical verified owner/path context, a typed `GateCheckSource`,
a responsible route, and a typed non-executable next-safe operation. The public
source discriminator distinguishes claim acquisition, budget admission, auditor
and future approval review, validation, primary drift, Git apply check, merge
scope, validation binding and state, sandbox policy, containment, primary
integrity, and external side effects without parsing prose. Reason/source
mismatches are rejected by both constructors and validated deserialization.

The public budget-admission reason carries a `BudgetAdmissionDenial` drawn from
a finite, value-free set: `new_dispatch_stopped`, `missing_cost_estimate`,
`hard_token_ceiling`, or `hard_cost_ceiling`. Numeric limits, reservations, and
consumption remain in the structured run-budget report instead of becoming part
of the denial's stable identity. Every budget-admission denial is `not_retryable`,
routes to the child or controller, and derives
`NextSafeOperation::ReviewRunBudgetAndStartNewRun`
(`review_run_budget_and_start_new_run` on the serialized surface). A new run
may start only after the budget or scope is corrected.

Sandbox denials carry the existing `SandboxDenialEvidence` type without a second
schema. Its evidence-level retryability is reporting data, not execution
authority: `GateDenial::from_sandbox_denial` always fails closed as
`not_retryable` and escalates sandbox policy. A future retry would require a
separate trusted supervisor-created execution context that this module does not
provide. Containment failure, primary-integrity failure, and ambiguous or
completed external effects are also unconditionally non-retryable.

Merge callers should adapt `ApplyBlockerDetail` or `ApplyBlocker` before
flattening anything to prose and must supply the trusted typed source check. The
adapter uses only blocker kind, blocked disposition, failed check status,
source, and canonical paths. Reviewer messages, validation diagnostics,
validation commands, and the legacy free-text `next_safe_operation` are never
inputs to corrective-prompt rendering.

Routing is explicit and fixed:

| Denial family | Responsible route |
| --- | --- |
| Pre-launch claim-acquisition conflict | Planner or parent |
| Budget admission | Child or controller |
| Auditor or validation repair | Child or controller |
| Merge remediation, including `unclaimed_edits` | Integration controller |

The dedicated `from_claim_conflict` constructor creates the pre-launch
claim-conflict family with its typed narrow-or-replan operation. Merge-phase
`ApplyBlocker::UnclaimedEdits` is merge remediation and never routes to the
planner/parent.

Containment and sandbox escalation also route to the child/controller.
Primary-integrity and external-side-effect reconciliation route to the
integration controller. Corrective prompts contain only fixed policy vocabulary
plus validated canonical identities and JSON-quoted repository-relative paths.

The stable denial ID is a deterministic SHA-256 identity of envelope version,
typed reason, typed source check, and canonical verified context. It deliberately
excludes the correction-correlation ID. Issue 28 lifecycle consumers should
therefore dedupe the same denied condition by stable denial ID while using the
separately validated correction-correlation ID to associate events with one
correction attempt. Starting a new correction lifecycle changes the correlation
ID, not the stable denial ID; changing the reason, source check, or verified
context changes the stable ID.

`--decomposition-target` never self-authorizes decomposition work. It must be
paired with `--decomposition-run-id` naming a verified finalized supervise
artifact. That run must be real/publishable and accepted successful, and its
accepted O1 id must equal the merge candidate agent id. The exact candidate,
supervisor, O1, and successful typed worker `files_changed` sets must all equal
the target plus the completion's normalized non-empty `replacement_paths`.
The worker completion must match the accepted child aggregation and supervisor
final `decomposition_candidates`, while the parent-launched accepted read-only
auditor must cover the worker and every candidate path. This reuses the
authenticated finalized artifact reader; an arbitrary JSON report, unfinished
run directory, fake run, bare target, mismatched agent, or unrelated extra edit
is rejected.

The worker and child cannot self-assert the content identity. After path,
journal, and diff inspection, the supervisor uses the isolated two-matching
candidate snapshot gate to derive the full candidate validation binding
(primary HEAD, agent HEAD, merge base, agent id, and raw-diff object id), writes
that binding into the normalized completion evidence before launching the
parent auditor, and re-captures it after the auditor. A missing capture or any
content, path, or base change across that review fails the run before
finalization.

Merge independently re-captures the current candidate under the same isolated
two-matching snapshot gate and requires its full canonical binding to equal the
supervisor-derived binding in the authenticated finalized run. Thus changing
target or replacement bytes after review is rejected even when the exact path
set and run id are reused. The exact target must also be modified smaller than
its primary candidate base or deleted. Every evidence-bound replacement must
be a new regular file absent from that base and non-empty in the candidate.
Only those evidence-bound replacement paths are recorded; ordinary changed
paths cannot be relabeled as decomposition output. The target also must be the
exact authenticated threshold-crossing path and have an exact (not merely
ancestor) path claim. All ordinary dirty-primary, stale-base, claim,
validation, review, and apply gates remain in force; verified evidence bypasses
only its target's opt-in megafile policy blocker. An
`accepted_decomposition` history event is written only after the primary patch
was successfully applied. A blocked/failed/no-op candidate cannot create it.
If the post-apply authenticated write fails, the command reports that the merge
was already applied and must not be retried blindly. The accepted event starts
a new activity/size epoch; run a later explicit seed to establish the new file
size baseline.

When an apply check reports overlapping paths, both commands add
`safety.semantic_conflicts` to the existing JSON report. The parser-backed Rust
map identifies touched symbols, impls, modules, imports, and signature changes;
the existing semantic risk query supplies dependency impacts and impacted
files. Import-only and conservative formatting-only overlaps are low risk.
`advisory=true` means this classification never changes readiness or force
behavior. `degraded`, `confidence`, and `notes` expose unsupported paths, parse
errors, or bounded truncation instead of presenting an unresolved overlap as a
confident classification.

Validation failures are considered when validation reports are supplied from
collected run summaries or from direct `--validation-report` JSON files.
External validation JSON may be a single report, an array, an object with
`validation`,
`validations`, or `reports`, or an orchestration summary with per-agent
validation. Those legacy forms remain useful as advisory evidence, but they are
unbound and do **not** satisfy `--require-validation`. Required external
evidence must use an envelope whose `validation_binding` is copied verbatim
from the current preview and whose `reports` contains a passed report:

```json
{
  "validation_binding": {
    "version": 1,
    "agent_id": "agent-a",
    "primary_head": "<40-character object id or null>",
    "agent_head": "<40-character object id or null>",
    "merge_base": "<40-character object id or null>",
    "diff_oid": "<40-character object id>"
  },
  "reports": [
    { "name": "cargo test", "status": "passed", "paths": ["src"] }
  ]
}
```

For `merge preview`, copy `candidate.validation_binding`; for `pr preview`,
copy `preview.candidate.validation_binding`. Any candidate, HEAD, base, or diff
change invalidates that envelope. `--require-validation` also blocks when
validation evidence is missing, only `not_run`, only `skipped`, or failed
without a bound passed report. JSON readiness details distinguish `validation_missing`,
`validation_not_run`, `validation_skipped`, and `validation_failed`, include
related paths when available, and report the next safe operation.

`merge apply --validation-command <command>` creates an independent standalone
temporary repository for each command. It materializes the reviewed base through
a private Git directory and controlled object alternate, applies the agent diff,
and runs the command there before applying anything to the primary worktree. A
failed command blocks the apply. A successful command is also
rejected if it changes the candidate's HEAD, index, tracked files,
non-ignored untracked files, or recursive submodule state. For an initialized
submodule, checking records the `.git` marker identity plus the recursive
repository fingerprint, so ignored build output is outside the comparison. For
an uninitialized submodule, a bounded raw-path fallback detects initialization,
marker removal, or checkout deletion. That fallback fails closed if it exceeds
8,192 entries, 64 MiB total content, or 16 MiB for one file. Candidate capture
uses the same entry, total-content, and single-file limits before it writes new
temporary objects; Git stdin and output are bounded separately and an exceeded
limit fails closed. The tool does not initialize or fetch submodules during this
check. Repository-index fingerprints likewise use a 64 MiB no-follow bounded
read and require a stable real regular file owned by the current user, with one
link and no group/world write permission.

The races addressed by the merge and publication boundary are concrete: a
candidate can change while validation runs, another local process can start a
merge or publication, a branch can move between preview and push, and GitHub can
create a pull request even when the local `gh` process loses its response.
Ambient Git repository, config, trace, filter, and temporary-directory variables
can also redirect an otherwise read-only command. Candidate capture therefore
uses a private Git directory, private index, private object directory, and a
verified alternate to the repository's object database. It does not read the
real repository's local or worktree config, global config, `info/attributes`, or
`info/exclude`; external clean/process filters, external diff drivers, textconv,
hooks, and the `ext` transport are unavailable in that context. Worktree
`.gitattributes` and `.gitignore` still apply when their behavior does not depend
on omitted private config. This deliberately excludes repository-local and
global ignore/attribute rules from candidate meaning; move any review-relevant
rule into the tracked worktree files.

Temporary state uses an owner-only runtime below `/run/user/<uid>` or a `0700`
child of the canonical root-owned sticky temporary directory. This also handles
Darwin's usual `/tmp` symlink by validating its canonical target. Candidate
capture, candidate validation, publication Git, and private `gh` directories
carry a versioned `0600` owner record with PID, process-start identity, Linux
boot identity, creation time, kind, and a name-bound nonce. A persistent,
single-link runtime-root lock serializes bounded scanning, reservation
publication, and normal cleanup without unlinking the lock inode. After a crash,
the next entry reclaims only a dead or PID-reused owner whose record and file
identity still match. Interrupted reservations at each owner-record publication
stage are recognizable under that lock. Corrupt, foreign, symlinked, or
unverifiable entries are retained per directory and counted diagnostically;
they do not authorize deletion or turn one entry into a global scan failure.
The scan and deletion walks have direct-directory, entry, and depth limits.
On Unix, cleanup stays anchored to no-follow directory descriptors and uses
`fstatat`/`unlinkat`, refuses a device transition before descending, and never
follows a symlink or hard link outside the managed directory. Platforms without
that handle-relative cleanup backend refuse private temporary-context creation;
Windows therefore fails closed before creating one rather than relying on a
verify-then-path-delete sequence.
Internal `git` and `gh` commands resolve only through the fixed
`/run/current-system/sw/bin`, `/usr/bin`, or `/bin` entries, then verify the
canonical executable and its ancestors are root-owned and non-writable. An
arbitrary `PATH` entry is never a candidate, including a directly named
immutable Nix store output whose build provenance is not established. User Nix
profiles and Homebrew therefore fail closed at this boundary.

Every merge validation, local Git, network Git, and `gh` child has a finite total
deadline, bounded stdin/output, and required process-tree containment. Success is
accepted only after the runner proves its owned process tree empty. On Linux this
requires a trusted user systemd manager and cgroup v2; Windows uses a Job Object,
but trusted Windows Git/`gh` executable and ACL resolution is not implemented,
so Git-dependent paths still fail closed there. Required containment currently
has no strict Darwin backend, so Git-dependent merge/publication paths fail
closed on Darwin rather than silently using process-group compatibility. These
controls prevent a completed command from leaving a delayed child. They do not
make a trusted validation command an adversarial filesystem sandbox while it is
running.

Safety-sensitive crate-internal direct launches can additionally bind the
entry executable before the systemd start gate opens. That opt-in path records
the source device, inode, mode, length, and SHA-256 digest; authenticates the
bounded launch descriptor against the digest fixed in the transient unit's
argument vector; copies the verified image into a sealed Linux memory file; and
executes the sealed descriptor instead of reopening the source pathname. Script
launches pin and seal both the script and its native shebang interpreter.
Dispatcher shebangs such as `env`/`env -S`, native loader hooks, and common
shell/language startup hooks are refused. Bootstrap requires the currently running
`maco` executable and every path ancestor to be root-owned and non-writable to
the invoking user, so `cargo run`, development outputs, and user-local installs
fail closed for this authority. Ordinary shell and direct commands do not opt in
and retain their existing behavior. This pins the entry images, not their
dynamic-library or language-module dependency closure.

Candidate validation additionally starts from a cleared environment with a fixed
root-owned system `PATH`, private `HOME`, `TMP*`, and XDG directories, and an
empty private global Git config. Shell startup hooks, provider credentials,
proxy/custom-CA routing, SSH-agent state, and ambient user configuration are not
inherited. Captured validation diagnostics are bounded and redact registered
credential, authentication, cookie/session, proxy/CA, and shell-startup values
before they enter a validation report.

Merge apply and PR publication share a kernel-managed advisory lock on the
stable repo-common file `.git/maco/state/repository-mutation.lock`. The file is
not deleted when the operation finishes; closing or crashing the process
releases the kernel lock. Its typed owner record contains the operation, PID,
process-start identity when available, nonce, and creation time for diagnostics.
The owner record does not decide whether the lock is live. A locked malformed
record is refused, while an unlocked stale record is replaced by the next lock
holder.

Validation evidence remains bound to the exact candidate snapshot described
above. Git and GitHub publication use a unique OID-derived remote ref and push
the reviewed lowercase object ID with a create-only lease. External publication
accepts only a bounded, canonical `https://host/repository/path(.git)` origin;
GitHub identities and selectors are stored and checked as exact canonical
`host/owner/repository` values.
HTTP, SSH, SCP, Git helpers, URL userinfo, query/fragment credentials, escapes,
and relative paths are refused. Local and `file://` bare remotes also fail
closed: a concurrent same-UID process could otherwise alter the remote config
during `receive-pack`, after preflight but before a hook or helper decision.

Network Git runs against a private bare context. The real repo-common
`maco/state`, primary/source worktrees, repo-common object database, and sibling
runtimes are masked. An observation-only `ls-remote` context has an empty object
database. Before a push, trusted offline code walks the exact reachable closure
of the reviewed commit and copies only those commit, tree, and blob objects into
the private object database. The walk has object-count, aggregate-byte, commit-
and tree-depth bounds; rejects self/duplicate parents and commit cycles; and
does not traverse gitlinks into another repository. The private database is
rewalked and enumerated to prove that it contains the same closure, no extra
object, and no Git/http alternate before it is exposed read-only to the network
child. Source stores containing Git/http alternates, promisor metadata, or
partial-clone configuration are refused before materialization. The child receives a
cleared, exact environment and a fixed trusted `git`; proxy, custom CA, askpass,
credential helpers, tracing, HOME, SSH-agent, and ambient Git config inputs are
absent. On Linux the effective unit must prove `PrivateNetwork=no`, exactly
`AF_INET AF_INET6`, bounded resources, exact mounts, and masked same-user IPC
sockets. Other platforms fail closed until an equivalent verified backend
exists.

HTTPS authentication is token-only. `github.com` accepts no explicit port or
canonical `:443` (which is normalized away), and accepts `GH_TOKEN` or
`GITHUB_TOKEN`. Any enterprise authority, including a non-default port or a
localhost/private endpoint, must first be explicitly allowlisted by an exact
canonical `GH_HOST` or `GITHUB_HOST` value; an unapproved authority is rejected
before any token variable is read. An approved enterprise authority accepts
`GH_ENTERPRISE_TOKEN` or `GITHUB_ENTERPRISE_TOKEN`. If both permitted host or
token variables are present they must be identical. The token is never placed
in argv, the child environment, reports, or journals. A private 0600 config binds `Authorization: Basic
base64("x-access-token:" + token)` to the exact canonical repository URL,
requires TLS verification, disables redirects, proxies, askpass, and credential
helpers, and is rebound read-only. Its path/open-file identity, owner, mode,
single-link count, bounded exact bytes, and containing runtime identity are
checked immediately before and after every command. Raw and encoded token forms
are redacted from bounded output. On normal success and ordinary error returns,
config erasure is an explicit fallible step: the same inode is overwritten,
synced, reread as zero bytes, and only then is the private runtime closed; token
and remote-binding scratch buffers are also cleared before release. A process
crash cannot promise memory or file overwriting, so any residue remains in an
owner-only runtime with a PID/process-start/boot-bound owner record and is
handled by the bounded dead-owner scavenger on the next private-runtime entry.

GitHub publication requires an explicit expected creator login in
`GH_EXPECTED_AUTHOR` or `GITHUB_EXPECTED_AUTHOR` before token selection; bot
logins such as `release-bot[bot]` are accepted when named exactly. Each
source-backed external effect derives a stable SHA-256 identity from its effect
transport provider (`git` or `github`), source provider, exact host-qualified
repository, source action revision, and operation; source-less
effects additionally bind their exact target and payload. The PR branch and
hidden version-2 `maco-external-effect` marker are deterministically derived
from that identity;
run IDs, agent IDs, attempts, and random values do not affect them. Publication
observes the remote head and exact base OIDs before PR creation, reads the
resulting PR with `gh pr view`, and requires exact title, marker-bound body,
creator login, `headRefOid`, `baseRefOid`, head/base branch, same head-repository
owner/name, `isCrossRepository=false`, open state, and draft/ready value before persisting
any PR receipt fields or advancing the receipt phase. A PR already present for
the unique branch before this transaction records a create attempt is treated
as a front-run and rejected. After a recorded create attempt, crash/lost-response
reconciliation adopts only a receipt satisfying the same hidden marker and all
of those provenance fields.
The HTTPS origin is also parsed into a bound host/owner/repository identity.
Every `gh pr` and `gh issue` call receives that explicit host-qualified
`--repo`;
`gh` receives a private 0600 `hosts.yml` and an explicit environment allowlist
containing only OS/locale essentials, fixed PATH, `GH_CONFIG_DIR`, and disabled
prompts; token variables are not inherited. HOME, Git config, proxy, custom CA,
ambient repository, debug, pager, and forced-TTY routing are absent. Its current
directory is that private config runtime, while repo state and source/primary
worktrees are masked. Config identity and bytes are rechecked around every
allowlisted PR/issue subcommand. The receipt URL must identify the same bound
repository and exact PR or issue number.
Publication observes the remote head and base again after that receipt. A
mismatch is reported as blocked rather than published.

Git pushes, GitHub PRs, GitHub issues, and inbox source comments use an
authenticated repository-local effect WAL with `planned`, `started`,
`observed`, and `completed` phases. `started` is durable immediately before the
provider call. Recovery from `started` performs lookup only and proceeds only
for exactly one marker-bound receipt; zero, multiple, or failed lookups require
manual reconciliation and never resend. `observed` and `completed` receipts are
re-fetched and checked against the exact repository, object ID, URL, operation,
marker, target, payload, and provider-specific provenance; source-backed effects
also bind the source provider, canonical host, repository selector, and source
action revision separately from the effect transport. A deleted, closed, or
mutated remote object therefore blocks without another provider call.
Immediately before a new effect, the complete source freshness snapshot must
still match. After a source comment changes volatile `updatedAt`, recovery uses
the stable action revision so the comment can be adopted without weakening
title/body/label/head/base checks. Comment discovery reads every bounded REST
page and then exact-views each marker candidate; truncation or bounds failure is
fail closed.

The effect WAL bounds each record and enforces finite namespace-wide logical
store, root-entry, and retained-journal quotas. It deliberately performs no
automatic garbage collection or retry of exactly-once effects. Reaching
capacity fails closed. Any operator-managed archival or recovery must preserve
the authenticated receipt evidence; deleting that evidence can forfeit the
exactly-once guarantee.

The new path does not create plaintext records under
`.git/maco/state/publication-transactions/`. If any legacy plaintext publication
journal entry exists, publication stops with an explicit signed-migration
requirement and neither adopts, signs, overwrites, nor deletes it. This is an
intentional seam for a future migration command. The JSON
`publication_receipt` remains a public summary of the verified remote result;
the authenticated effect WAL is the recovery authority.

These checks do not make Git hosting operations globally atomic. Another actor
can still move or delete a remote object after a completed re-verification. A
later run detects that change and blocks rather than recreating the effect. The
repo-common lock coordinates this tool's local operations only, and journal
durability still depends on the underlying filesystem. Managed paths reject
pre-existing symlinks (and Windows reparse points), but path-based checks do not
claim protection from a hostile same-user process replacing components during
the check; this boundary coordinates non-adversarial concurrent local actors.
`merge apply` also does
not run project checks after a successful primary apply, so release managers
should run final verification after accepting changes. With `--json`, a blocked
apply emits a machine-readable report with readiness blockers, blocker details,
and related paths before exiting with an error.

Preview and publish agent worktree changes as a pull request:

```bash
cargo run -- pr preview agent-a --repo . --claim README.md --json
cargo run -- pr preview agent-a --repo . --claim README.md --require-validation --validation-report validation.json --json
cargo run -- pr publish agent-a --repo . --claim README.md --forge fake --json
cargo run -- pr publish agent-a --repo . --claim README.md --forge fake --require-validation --validation-report validation.json --json
cargo run -- pr publish agent-a --repo . --claim README.md --forge github --ready --json
cargo run -- pr preview --from-branch task/docs --repo . --json
cargo run -- pr publish --from-branch task/docs --repo . --forge fake --require-validation --validation-report validation.json --json
cargo run -- pr publish --from-branch task/docs --squash-onto main --exclude .agents --repo . --forge fake --json
```

`maco pr preview` uses the same merge-preview gates as `merge apply` and never
pushes or creates a pull request. `maco pr publish --forge fake|github` refuses
dirty-primary, stale-base, unclaimed-edit, validation, and apply-check blockers.
`maco pr preview|publish --from-branch <task-branch>` uses the same gates for a
committed primary task branch instead of a managed agent worktree. When
`--claim` is omitted in branch mode, all changed paths in the branch candidate
are treated as the reviewed publication scope; pass `--claim` to keep the
unclaimed-edit gate narrow.

`--squash-onto <base>` builds a deterministic import commit whose parent is the
named local base branch and whose tree is the task branch snapshot, so PR
publication works even when the task branch and base branch have disjoint
history. `--exclude <path>` removes repository-local agent context from that
published snapshot. Publication refuses with an `excluded_reference` blocker if
the remaining tree still refers to an excluded path, for example from
`Cargo.toml` or a Rust `mod` declaration.

With `--require-validation`, use this exact two-stage workflow:

1. Commit the candidate in the agent worktree and leave it clean.
2. Run `maco pr preview ... --json` and validate that exact committed snapshot.
3. Copy `preview.candidate.validation_binding` verbatim into the envelope shown
   above and add the passed validation report.
4. Run `maco pr publish ... --require-validation --validation-report <envelope>`.

Required worktree publication never creates an internal commit, because doing so
would change the binding after review. A dirty required worktree candidate is
blocked with the commit -> preview -> validate -> publish recovery sequence.
Branch `--squash-onto` and `--exclude` previews build the same deterministic
import commit that publish will recheck, so the validation binding remains
stable across the two-stage flow. Without `--require-validation`, publish may
commit safe uncommitted changes in the agent worktree only, but it re-previews
the clean commit and checks it again immediately before external publication.
The fake forge returns deterministic
`fake://pr/...` URLs and never uses the network. GitHub publication runs only
when `--forge github` is passed and shells out to local `git` and `gh` using the
transaction and verification sequence above.

Preview and create issues:

```bash
cargo run -- issue preview --title "Bug title" --body "API_TOKEN=secret" --json
cargo run -- issue preview --title "Bug title" --body-file issue.md --forge github --json
cargo run -- issue create --title "Bug title" --body-file issue.md --label bug --forge fake --json
cargo run -- issue create --title "Bug title" --body-file issue.md --label bug --forge github --json
```

`maco issue preview` redacts secret-looking body assignments and reports
`created=false`. `maco issue create --forge fake|github` uses the deterministic
local-only fake forge or, with explicit `--forge github`, shells out to
`gh issue create` through the same contained, allowlisted process boundary.
Issue triage is intentionally minimal: title, body, and labels. Unlike PR
publication, issue creation does not yet have a write-ahead receipt or retry
reconciliation protocol; if the remote creates an issue but the response is
lost, an operator retry can duplicate it. Treat an ambiguous issue-create result
as a manual reconciliation point.

Inspect and refresh live work claims:

```bash
cargo run -- live status --repo . --json
cargo run -- live validate --repo . --json
cargo run -- live apply ../claim-drafts/claim-id.md --repo . --by owner-id --json
cargo run -- live heartbeat claim-id --repo . --by owner-id --json
cargo run -- live release claim-id --repo . --by owner-id --status done --reason "claim completed" --json
cargo run -- live override-release claim-id --repo . --by project-owner --reason "stale claim owner unavailable" --json
```

`maco live status` reports each claim's owner, status, owned files, lock state,
and liveness. `active` and `blocked` claims are treated as locks. A claim is
stale when its heartbeat, updated timestamp, or date fallback is older than its
configured stale-after window. `maco live validate` reports missing or malformed
claim fields. The existing claim directory is bound without changing its
permissions. It accepts at most 256 entries: canonical `.md` claim files plus
the optional `CLAIM_TEMPLATE.md` and empty `.maco-live-claims.lock` control
files. Every entry is read without following links, with a 64 KiB per-file
limit, strict UTF-8 and bounded filename, line, field, timestamp, owner, path,
and item-count grammar. Links, hard links, special files, nested directories,
unsupported extras, and any invalid claim make the board fail closed.
All reads and mutations hold the same stable board lock and compare the sorted
entry names plus each entry's identity and bytes before accepting a snapshot.
Component-aware ancestor/equality overlap between `active` or `blocked` owned
paths is a board validation error. Canonical crash residue from the atomic
claim writer is scavenged under that lock; unknown or malformed residue is
left in place and refused for manual inspection.

Supported owner mutation flows are `apply`, `heartbeat`, and `release`.
`apply` is create-only: an existing claim ID is always refused, including after
that claim reaches a terminal state. Change scope by releasing or handing off
the prior claim, then submit a new claim ID. A draft must describe a fresh
`active` initial generation with one matching Claim header and Claim ID, an
owner exactly matching `--by`, equal canonical UTC `Created`, `Updated`, and
`Heartbeat` values no more than five minutes old, and no pre-existing audit
log. Old, future, terminal-state, and audit-replay drafts fail closed.

The draft parent and leaf are bounded and opened through a no-follow parent
descriptor. Their identity and content are rebound to the same observation as
the claim board; drafts inside or aliasing the board, hard links to board
entries, and ancestor-link replacement are refused. The proposed whole board
must remain valid and free of active path overlap. `heartbeat` is limited to
`active` or `blocked` claims and requires `--by` to exactly match the recorded
owner. `override-release` is also limited to those states and requires a claim
that is provably stale; a fresh, future-dated, or otherwise unknown liveness
result is refused. Its required `--by` value is an audited actor label, not an
authentication credential, and `--reason` is bounded and rejects
control-character injection. `release` requires the exact recorded owner and
moves the claim to `done` or `handoff`; `override-release` is the audited
stale-claim administrative exception.

Supported API operations coordinate through the stable board lock. On Linux,
create uses `renameat2(RENAME_NOREPLACE)` and existing-claim mutations prefer
an exchange CAS that checks the exchanged old inode and bytes and rolls back a
refused generation. Filesystems that specifically report exchange as
unsupported use a recoverable no-replace transaction instead: the old and new
identities, content digests, and unchanged whole-board generation are bound into
an old-generation residue, and the next lock-held board open rolls back or
finalizes only an exact known crash state. Other exchange failures remain
fail-closed. Direct edits below `.agents/live/claims/` are unsupported: the lock
and CAS narrow cooperating API races, but do not claim complete exclusion or
detection of a non-cooperating same-UID process holding and editing a file
descriptor across the operation. Audit growth is compacted into a bounded
digest entry, and heartbeat writes reserve release headroom. Mutation timestamps
always use the process's real system clock and refuse future/rollback heartbeat
generations; public `--now` injection is available only for the observational
`status` and `validate` commands.

Preview the local LLM boundary without credentials or network access:

```bash
cargo run -- llm providers --json
cargo run -- llm prompt-preview task.md --agent-id agent-a --path src/lib.rs --repo . --json
```

Run a deterministic local fake-provider proposal in an isolated worktree:

```json
{
  "summary": "update README",
  "commands": [
    {
      "command": "printf '# Updated\\n' > README.md",
      "working_directory": null,
      "purpose": "implement"
    }
  ],
  "patches": [],
  "notes": []
}
```

```bash
cargo run -- agent run task.md --agent-id agent-a --path README.md --fake-proposal proposal.json --validation "cargo test" --repo . --json
```

The retained agent runner accepts only the local `fake` provider and executes
in an isolated managed worktree after deriving the capability-bound
repository-cleanliness input. Other provider names are refused. It renders
the same provider-neutral prompt boundary used by `llm prompt-preview`.
Provider-proposed shell commands are disabled by default: the command above
reports a refusal for the proposed `printf` command and tells you to rerun with
`--allow-provider-commands` if you trust the proposal. Patch-only fake proposals
can run without that opt-in. When command execution is explicitly allowed,
the retained agent runner applies fake-provider proposed patches and commands inside the
agent worktree, runs provider-proposed and CLI-supplied validation commands,
collects a merge candidate and preview, reports path-boundary violations, and
releases durable claims unless `--keep-claims` is supplied. Real network
providers remain unconfigured by default.

```bash
cargo run -- agent run task.md --agent-id agent-a --path README.md --fake-proposal proposal.json --allow-provider-commands --validation "cargo test" --repo . --json
```

Run an opt-in supervisor-of-orchestrators plan:

```markdown
# goal.md

- Update the README examples.
- Update `src/cli.rs` and the `PlanSuperviseArgs` contract.
- Add focused coverage in `tests/supervise_cli.rs`.
```

```json
{
  "version": 1,
  "task": "coordinate README and Rust follow-up work",
  "max_depth": 2,
  "max_child_assignments": 2,
  "max_child_retries": 0,
  "child_timeout_seconds": 600,
  "assignments": [
    {
      "id": "docs-child",
      "phase": "execution",
      "assigned_paths": ["README.md"],
      "worker_assignments": [
        {
          "id": "docs-worker",
          "assigned_paths": ["README.md"]
        }
      ]
    },
    {
      "id": "rust-child",
      "phase": "execution",
      "assigned_paths": ["src/lib.rs"],
      "semantic_symbols": ["WorktreeManager"],
      "worker_assignments": [
        {
          "id": "rust-worker",
          "assigned_paths": ["src/lib.rs"],
          "semantic_symbols": ["WorktreeManager"]
        }
      ]
    }
  ]
}
```

```bash
# Explicitly decompose a high-level goal/spec:
cargo run -- supervise plan --from-goal goal.md --repo . --json
# Preserve the positional form for either plain-text tasks or authored JSON plans:
cargo run -- supervise plan supervisor-plan.json --repo . --json
# Selects the default Codex runtime and uses native workspace-write in managed worktrees:
cargo run -- supervise run supervisor-plan.json --repo . --run-id supervise-demo \
  --codex-bin codex \
  --quota-config config/operator-quota.json \
  --machine-global-config /exact/path/to/machine-global.json \
  --machine-global-runtime-root-id runtime --json
# Operator role-category override recorded as selection_source=operator_override:
cargo run -- supervise run supervisor-plan.json --repo . --run-id supervise-role \
  --runtime fake --role-category non_delegating_terminal_worker \
  --machine-global-config /exact/path/to/machine-global.json \
  --machine-global-runtime-root-id runtime --json
# Decompose the goal and execute that same validated plan through the live gates:
cargo run -- supervise run --from-goal goal.md --repo . \
  --run-id supervise-goal-demo --codex-bin codex \
  --machine-global-config /exact/path/to/machine-global.json \
  --machine-global-runtime-root-id runtime --json
# Explicit serial opt-out:
cargo run -- supervise run supervisor-plan.json --repo . --run-id supervise-serial \
  --codex-bin codex --max-concurrent-children 1 \
  --machine-global-config /exact/path/to/machine-global.json \
  --machine-global-runtime-root-id runtime --json
cargo run -- supervise status supervise-demo --repo . --json
cargo run -- supervise collect supervise-demo --repo . --json
cargo run -- supervise artifacts latest --repo . --json
```

`supervise plan` and `supervise run` each require exactly one input source. The
positional `TASK_FILE` keeps its existing contract: valid JSON is normalized as
an authored supervisor plan, and other UTF-8 text is treated as a task
specification.
`--from-goal <FILE>` is mutually exclusive with the positional input and always
treats the bounded UTF-8 file as a high-level goal/spec, even if its contents
happen to be valid JSON.

`supervise run` and `autopilot run` accept optional `--role-category`. Omitted
keeps automatic selection derived from the plan role. When set, the CLI stamps
every assignment and nested `worker_assignments` entry with that category and
`selection_source=operator_override` before launch. Accepted values are
`delegating_coordinator`, `non_delegating_terminal_worker`,
`read_only_researcher`, and `read_only_review_auditor` (hyphen aliases are
accepted). Unknown names fail at argument parsing, before repository access.
Resume of an existing supervise run refuses `--role-category`; the frozen
categories from the original launch remain in force. The override does not
bypass role-authority admission: a weak-model coordinator remains a typed
refusal.

`supervise run` and `autopilot run` persist launch preflight evidence under
`preflight/` (git status, repository map, sync status, and in-process runtime
probe outcomes, each with an explicit success/failure marker). They also append
an operator heartbeat ledger at `liveness/heartbeat.jsonl` and write
`SUMMARY.md` at finalization. A second launch targeting the same repository
refuses while another live supervise or autopilot process is still registered;
stale leftover records are reported without blocking. `--force-live-run` is
launch-only and does not authorize killing, interrupting, reverting, or
discarding another run.

### Explicit bounded primary-worktree target

Managed child worktrees remain the default. An authored plan can opt one
assignment into the existing primary checkout only by declaring an exact-file
scope and the operator separately passing `--allow-primary-worktree`:

```json
{
  "version": 1,
  "task": "update one local deployment file",
  "max_child_retries": 0,
  "max_gate_corrections": 0,
  "execution_target": {
    "kind": "primary_worktree",
    "claim_paths": ["local/deploy.txt"]
  },
  "assignments": [{
    "id": "local-deploy",
    "phase": "execution",
    "assigned_paths": ["local/deploy.txt"],
    "worker_assignments": []
  }]
}
```

```bash
cargo run -- supervise run primary-plan.json --repo . \
  --run-id bounded-primary-deploy --allow-primary-worktree \
  --codex-bin codex \
  --machine-global-config /exact/path/to/machine-global.json \
  --machine-global-runtime-root-id runtime --json
```

The declaration and flag are a double opt-in; either one without the other is
refused before run artifacts or claims are created. This deliberately small
mode accepts one assignment, 1-16 disjoint exact files below a top-level
directory, an aggregate snapshot of at most 1 MiB, and an exact match between
`claim_paths` and `assigned_paths`. It rejects `.` and top-level scopes,
directories, symlinks, missing parent directories, `.git` overlap, retries,
gate corrections, generated follow-ups, evidence-only re-audit, licensed
breakage, and decomposition evidence.

The supervisor acquires the ordinary durable path claim before checking the
scope and holds it through child execution and parent audit. Git-visible dirty
state in a declared file is refused even with `--allow-dirty-primary`; an
existing ignored/local-only file is permitted only after its exact bytes and
mode are captured as the baseline. During and after the run, changes to HEAD,
the index, or any path outside the exact declared files fail integrity gates.
Claims are released on success and failure. Supervisor-owned findings in both
the child report and final report state `primary_worktree` intent and list the
declared scope, and accepted changes already reside in the primary checkout—no
managed-worktree merge step exists.

This opt-in does not relax the existing external-Codex containment,
machine-global retention, primary-target pre-action review, or acceptance
gates. In particular, the primary-writable coverage gate still refuses release
when no universal blocking callback exists; managed-worktree native
workspace-write admission does not authorize this mode. The fake runtime does
not execute a primary-worktree target.

Goal/spec planning fragments the source and emits one nested subtree per
disjoint workstream: a depth-2 read-only planning root followed by a depth-3
execution child with a real `parent_assignment_id`. Every normalized assignment
carries a required typed `phase`; schedule identity and flattened index are
validated before that authority is consumed at launch. Every recursive
assignment must declare `planning` or `execution`. Omitted, mixed
present/absent, null, and unknown phases are rejected rather than inheriting
writable execution authority. The execution child keeps
the proposed `assigned_paths`, worker assignment, and any parser-backed Rust
`semantic_symbols` and `semantic_modules`. These are proposed path claims and
semantic intents; `supervise run` still acquires and enforces the authoritative
runtime claims. Fragments whose scopes overlap are coalesced, and the complete
proposal is checked for cross-subtree path, module, and symbol disjointness
before the validated plan is emitted or any child can launch.

Exact Rust symbol matches take precedence over broader module-file and module
declaration matches. This keeps a shared module root or other large declaration
file from transitively coalescing otherwise independent implementation files.
Assignments that genuinely edit different symbols in the same file still
coalesce: writable ownership and merge validation are file-granular, so
sub-file ownership would not be a sound concurrency boundary. Authored plans
that set `max_child_assignments` to `1` while one assignment contains multiple
independent path or worker scopes emit a
`planning_width_pinned_to_one` validation warning; the structured warning is
also available from the planning API for run-report telemetry.

Library callers may opt into provider-backed proposal through
`propose_task_decomposition_with_optional_provider`. With no provider, that API
uses the same deterministic heuristic planner described above. With a provider,
the response must be a recursive `ProviderRecursiveTaskPlan` (or a flat
`ProviderTaskPlan`, accepted as a forest of leaves) JSON object in the existing
provider-neutral `WorkProposal.summary`; commands and patches are rejected.
Deterministic validation is authoritative: inventoried file paths, fragment
coverage, depth/width bounds, exact internal-node fragment unions, concurrent
branch disjointness, and completed-scope protection are checked before a
proposal is accepted. A `TaskPlanningSession` can feed completed/failed
assignments, coverage gaps, and bounded notes into at most two provider re-plan
attempts. Invalid responses and failed provider calls count against that cap.
Validated sessions lower through
`supervisor_plan_from_task_planning_session` and can be bound to one future
authenticated supervise run for feedback re-planning. The local `FakeProvider`
exercises this boundary; no network provider is configured or selected by
supervise, so the CLI remains heuristic/offline by default.

The emitted document is directly usable as a supervisor plan and preserves
lowering traceability through top-level `spec_fragment_ids`, per-assignment
`spec_fragment_ids`, and `assignment_schedule`. Unmatched fragments appear as
`coverage_gaps` instead of disappearing. After execution, the final report's
`assignment_traceability` connects those fragments and assignments to produced
changed paths and candidate diff bindings; missing reports, no-change results,
and missing diff bindings add runtime coverage gaps.

Depth is plan data. Authored plans may use recursive `child_assignments` up to
their configured `max_depth` (currently 2 through 32), and normalization records
each assignment's `parent_assignment_id`, depth, and flattened index. The
scheduler validates that graph in parent-before-child order and admits a
descendant only after its parent has produced an accepted successful outcome
and released its assignment resources. A failed parent suppresses its
descendants transitively without stopping unrelated roots. Every node that is
actually admitted follows the ordinary assignment path: managed worktree
creation, path claims, semantic coordination, hierarchy-parented journal
events, child and worker reports, candidate inspection and binding,
review-auditor evidence, traceability, resource release, and final acceptance.
Admission uses validated assignment ids and parent links rather than generated
name suffixes or a fixed tree depth, leaving the schedule representation
available for future runtime-appended nodes.

Zero-work plans fail closed. Goal/spec input with no repository path, Rust
module, or Rust symbol match returns an actionable error asking for a concrete
scope. The older Issue #14 description's claim that `supervise run` silently
succeeded with an empty assignment list was already stale before this CLI
surface: supervisor plan validation already rejected an empty `assignments`
array. The run path continues to use that library validation and does not
reimplement a second empty-plan check.

`maco supervise run` has a default Codex runtime and admits writable production
execution only inside a verified managed child worktree. Its file-entry path
acquires the repository-cleanliness capability used to create that worktree,
claims each assignment's paths, records semantic coordination metadata when the
plan requests it, and writes structured logs and reports under the run
directory. Managed-worktree Codex uses native workspace-write execution under
the outer confinement boundary; the Issue 28 universal-review coverage gate
remains mandatory for a writable primary-checkout target. The in-process Fake
runtime executes the same depth, claim, journal, review-lens, economics, KPI,
and final primary-integrity gates without launching an external executable;
its successful output is always non-publishable.
Child/model final-message bytes are confined to `incoming/`; normalized child
reports and `supervisor-final.json` are parent-owned under `reports/`. A live
external child requires two distinct writable artifact capabilities in both the
outer and native sandboxes: the descriptor-held incoming report/journal root,
and the private final-message staging root beneath the reviewed machine-global
runtime root. Neither is source-workspace authority. Release must fail closed
unless both exact capabilities are verified; the parent retains descriptors
for bounded reads and atomic final writes.
The full local report schemas remain the authoritative acceptance gate. Current
external providers, including Codex, reject their draft-2020-12 conditional
forms, so child and parent-auditor launches omit the provider `--output-schema`
hint instead of staging a hidden primary-artifact path or weakening the schema.
The parent still parses and validates every collected final message before it
can enter accepted evidence.
Worker prompts also include a structured execution journal path under
`incoming/worker-journals/<worker-id>.jsonl`. Terminal workers append JSONL
records with `command`, `cwd`, `start_timestamp`, `end_timestamp`, and
`changed_paths`; the supervisor imports them into
`logs/workers/<child-id>/<worker-id>.jsonl` and rejects material mismatches
against WorkerReport evidence, assigned paths, or the supervisor-inspected Git
diff.
Each Codex CLI child orchestrator is instructed to read `AGENTS.md` and
project-local `.agents` guidance before acting. The generated prompt contract is
user-directed root O2 -> autonomous O2 supervisor -> O1 child orchestrator ->
terminal worker/researcher/review-auditor. Human-invoked agents are treated as
the user-directed root O2: they are out-of-band supervisors, can launch several
bounded autonomous O2 supervisors, and are not counted against autonomous
`task_depth`. Workers, researchers, and review auditors are terminal. Workers
must attest `no_further_delegation=true` in their WorkerReport, and review
auditors must attest it in their AuditorReport. Embedded worker prompt
templates begin with `ROLE: TERMINAL_WORKER`; embedded review auditor prompt
templates begin with `ROLE: REVIEW_AUDITOR`; both must be passed to terminal
sessions without preamble. Native SubAgent/delegated-worker use is limited to
lightweight terminal worker and researcher roles; O1 child orchestrators must
not bind O1 or O2 roles to native SubAgent sessions. Durable roles use canonical
role names only; runtime labels belong in the runtime bridge and `AGENT_LABEL`,
never in `ROLE`. O1 child orchestrators must not spawn peer O2 supervisors;
when they discover newly large cross-cutting problems, they report peer-O2
escalation candidates upward in their structured report instead of taking those
scopes over. The user-root O2 or an autonomous O2 durable queue may then launch
bounded peer O2 supervisors as separate MACO/Codex CLI subprocess scopes.

Long-running O2 supervision is durable run state, not one expanding LLM context.
Autonomous O2 runs carry context through `STATE.tsv`, `HEARTBEAT.tsv`,
`queue.tsv`, `NEXT_O2_TASKS.tsv`, task prompts, captured final messages,
event streams, and `SUMMARY.md` under `.maco/o2-autopilot/runs/<run-id>/`.

O1/O2 subprocess orchestration uses MACO's verified outer process-tree and
side-effect boundary plus verified systemd cgroup ownership evidence and the
fixed `maco_external_codex` inner permission profile. Goals and multi-agent
features are enabled only for the supervisor role; inner model-generated
network access remains disabled. Nested O2/O1 subprocess chains must go through
the same validated MACO launch path instead of invoking a raw Codex process or
selecting a broader sandbox mode. Within that boundary, an O1 assigned a
managed child worktree uses native workspace-write and launches supplied
terminal worker templates through runtime-native SubAgent support; it does not
switch to app-server merely because an optional duplex reviewer is present.
Before each such writable launch, the parent revalidates the managed disposable
worktree binding, the exact authenticated held-claim token and paths, and the
runtime's verified native side-effect confinement together. A successful
decision is persisted as strict, parent-owned private evidence at
`assignments/<assignment>.attempt-<n>.worktree-writable-admission.json`, with
its matching schema under `schemas/`; primary-worktree targets never receive
this admission record and continue through the universal callback gate.

### Native managed-worktree execution and duplex primary review

Managed-worktree Codex runs through the native CLI workspace-write path under
the ordinary contained process runner. It does not require the optional hosted
duplex reviewer and therefore does not select app-server for normal isolated
child execution. Issue 28's crate-internal, line-oriented app-server transport
is retained for the stricter primary-writable review boundary. Its protocol
handler receives only a bounded borrowed session after executable validation,
containment attachment, lifecycle registration, tee setup, and the start gate;
it cannot obtain or retain `Child`, raw stdio handles, or an uncontained
`Command`. The writable app-server configuration selects
`approvals_reviewer="user"`; the upstream `auto_review` mode remains experiment
evidence only.

The live Codex 0.144.4 schema exposes client callbacks for approval requests
that Codex chooses to surface. `AskForApproval` has no mode that forces every
in-sandbox read, write, destructive operation, or tool action through the
client. Consequently, approval callbacks alone cannot prove universal
review-before-action, including for sensitive reads, and a static filesystem
sandbox cannot distinguish an allowed claimed write from a forbidden delete
of that same path. MACO therefore refuses writable primary-checkout release
before starting the child. This callback limitation is not a managed-worktree
admission condition: that narrower target is disposable, claim-bound, and
validated before any later publication. Removing the primary-target gate
requires a future protocol mechanism that blocks every relevant proposed
action; the existing callback tests are not evidence that such coverage
already exists.

For surfaced requests, the retained duplex implementation derives policy input
from server lifecycle items, never treats best-effort or missing manifests as a
deterministic allow, appends a redacted authenticated orchestration-journal
record before sending `accept`, and sends a typed `GateDenial` to the same
thread and expected turn before `decline` or `cancel`. The denied item and turn
cannot terminalize until that steer request is acknowledged. Journal failure,
malformed protocol, timeout, cancellation, permission expansion, and missing
manifest all fail closed. Trusted records carry a stable run/review-session
correlation, structured rationale, measured per-decision latency, terminal
item/turn/process evidence, and native review metrics with distinct
action-denial and eligible-run-interruption denominators plus measured p50/p95.

Focused tests run a fake app-server as a real subprocess through the same
interactive runner. The Linux required-containment variant proves both
`VerifiedEmpty` process-tree evidence and verified strict-offline-workspace
side-effect evidence while exercising journal-before-accept ordering, typed
denial/acknowledgement before decline on the same child, absence of a
post-approval action marker on denial or journal failure, and protocol-loss
evidence retention. It skips only when required containment itself is
unavailable; ownership or protocol failures remain failures. Separate
trusted-best-effort compatibility tests are explicitly nonpublishable and do
not claim verified evidence. These tests validate the bounded duplex
primary-review path; managed-worktree coverage instead exercises native
workspace-write launch and does not claim universal action interception.

For worker assignments, child orchestrators launch the supplied terminal
worker templates through Codex native SubAgent/delegated-worker mechanisms so
the project manager/worker boundary is preserved. If no delegated-worker
mechanism is available, the child stops before mutation and reports the exact
blocked worker task. For child assignments with workers,
the retained supervisor runner requires structured terminal audit evidence before
accepting the child report: the parent launches a read-only `REVIEW_AUDITOR`
subprocess and requires an accepted AuditorReport with `role=auditor`,
`no_further_delegation=true`, `read_only=true`, and coverage for all assigned
worker ids. A child-side review auditor is advisory unless the parent MACO/O2
acceptance gate collects and accepts it. The accepted parent-launched
AuditorReport is appended to the child `audit_reports` field.
If a child declares worker assignments but returns zero `worker_reports`, the
child report is rejected as structurally incomplete. If a child has no worker
assignments but leaves a non-empty child worktree diff, the retained runner
still launches the parent read-only `REVIEW_AUDITOR` and requires it to cover
the child orchestrator id and changed paths.
The retained supervisor runner does not apply worker changes to the primary worktree
automatically. Omitting `--max-concurrent-children` selects `auto`, whose
network-bound entrypoint ceiling is a conservative four children rather than the
host CPU count. Final admission takes the minimum of that entrypoint ceiling (or
the explicit positive flag), the optional plan/CLI maximum, a configured provider
in-flight quota, and host memory/file-descriptor/disk bounds. There is no live
provider probing: `provider_inflight_limit` and `--provider-inflight-limit` are
operator-supplied quota data. Host available/per-child inputs can likewise be
specified in a plan's `concurrency` object or with the corresponding
`--host-*-available-*` and `--host-*-per-child-*` flags. Missing host observations
fall back conservatively to one child. Zero inputs are rejected before dispatch.
`max_child_assignments` separately bounds plan fan-out; it is not the concurrency
limit.

```json
{
  "concurrency": {
    "max_concurrent_children": 8,
    "provider_inflight_limit": 6,
    "host_memory_per_child_mib": 1024,
    "host_fds_per_child": 128,
    "host_disk_per_child_mib": 512,
    "host_fallback_children": 1
  }
}
```

Every newly finalized `supervisor-final.json` carries
`role_economics_profile.schema_version=6` plus execution telemetry: planned,
started, and completed assignment counts; the resolved configured child bound;
scheduler-observed peak and active-interval mean concurrency; configured and
resolved model/reasoning bindings for every role; resolved effort for every
assignment duty in `assignment_effort_bindings`; and usage/cost with explicit
observation markers. `concurrency.policy_input` contains canonical JSON for
evaluation compatibility, while `concurrency.policy_input_details` retains the
typed entrypoint, plan, CLI, provider-quota, measured/configured host-resource,
and resolved-minimum inputs with `scheduler_observed` provenance. Missing
catalog, runtime-default model, nested-worker usage, and unpriced cost values
remain explicit unavailable observations. A width-one run with multiple
independent assignment or spec scopes emits a final-report warning. Readers
continue accepting historical reports that omit this block or carry economics
profile schema versions 1 through 5; the generated schema describes the required
version 6 contract for newly finalized reports. Version 4 profiles and the
withdrawn model-tier profile name remain deserializable compatibility input.

A worker assignment may opt into `"kind":"megafile_decomposition"` only with an
exact canonical `"target_path"` inside its assigned paths. Ordinary assignments
must omit `target_path`. Accepted worker reports preserve that typed pair,
bounded `bloated_file_flags`, and exact decomposition output evidence through
the child report. A successful decomposition worker must list the exact target
in `files_changed` and return
`decomposition_completion={"target_path":"...","replacement_paths":["..."]}`
with at least one distinct canonical replacement also present in
`files_changed`; target-only, ordinary, unrelated, and no-op pseudo-completions
are rejected. The supervisor final report deduplicates flags into
`bloated_file_flags` and merge-ready output evidence into
`decomposition_candidates`. The latter name is deliberate: supervisor work
remains isolated, so successful worker/report evidence is not an accepted
decomposition. Only a later successful `merge apply --decomposition-target
... --decomposition-run-id ...` using that same finalized run evidence writes
the authoritative `accepted_decomposition` history record.

In `auto` mode, every hierarchy-ready assignment from independent roots can run
concurrently up to the measured host-capacity bound, but only when normalized
path sets are disjoint. Equality, ancestor, and descendant relationships use
the same overlap semantics as path claims. Same-lineage scope overlap is
permitted by validation because parent admission gates serialize ancestors and
descendants; cross-subtree overlap remains rejected. The scheduler scans ahead
for later ready, disjoint roots, so a waiting descendant or active overlap does
not impose unnecessary head-of-line blocking. Retries and the parent review
auditor remain inside the assignment's slot. An ordinary assignment failure
suppresses its descendants but does not stop unrelated roots; a fatal scheduler
abort stops new starts and joins every active call before returning.

Before admitting more ready work, the Issue #24 swarm-health cascade circuit
breaker evaluates recent coordination outcomes. Repeated coordination failures
trip the breaker, journal the transition, stop pending assignment admission,
drain active assignments, release their resources, and expose the trip plus
recovery guidance in status/final-report evidence. The breaker is the safety
backstop that makes a higher automatic default practical; it does not raise the
measured capacity bound or allow overlapping claims to run together.

Concurrent outcomes are stored by plan index, keeping final reports, command
records, findings, releases, and deterministic artifacts in plan order. Event
journal appends are synchronized and well formed, although completion events
may interleave. Concurrent invocations use unique bounded scratch roots to
avoid collisions; an effective width of `1` retains the legacy literal scratch
names.
`max_child_retries` defaults to `0` and may be set up to `2`; retries are only
used for child report-shape failures such as missing or invalid report JSON or
the wrong report id/role, and the retry prompt includes corrective feedback.
`max_child_processes` is accepted only as a legacy JSON alias and normalized out
of reports. The command refuses to start when the primary worktree is dirty; use
`--allow-dirty-primary` only when the operator has reviewed that state. The
primary worktree dirty-path set is rechecked after each child process and any
newly dirty primary paths fail that child assignment. Tests use
fake subprocesses by default and do not require network access, provider
credentials, or a real Codex login.

Run the fake-first autopilot workflow:

`maco autopilot run` is a deliberately narrow capability spine. One command
normalizes a positional task/plan or decomposes `--from-goal <file>` through the
same planner used by `supervise plan`, performs typed preflight checks, builds a
single validated supervisor plan with `max_depth: 2`, and invokes the public
`supervise run` implementation. Omit `--codex-bin` for the deterministic
in-process Fake runtime. Every run must name the reviewed machine-global
configuration and runtime root used by supervise output-staging cleanup.
The spine shape is fixed: an omitted `max_depth` or integer `max_depth: 2` is
accepted. Any other integer depth, or any non-empty
`assignments[*].child_assignments`, is a typed
`approval_review`/`permission_expansion` refusal before supervise dispatch;
malformed or non-integer depth input is invalid. When an accepted, publishable
source run produces licensed-breakage follow-ups, a separate authenticated
durable command-level queue admits the exact generated plans and chains one
bounded generated batch through those same ordinary supervise gates. Fake and
otherwise non-publishable source runs leave their generated tasks deferred.

This increment does not revive the legacy Autopilot repair/publication loop.
Plan fields for outer validation, reviewer, forge, repair count, publish mode,
and `auto_merge` remain accepted for input compatibility but cannot dispatch
those effects. Supplying the legacy `--reviewer-command` fails closed. The
supervisor's own worker/auditor gates are authoritative. A successful result is
isolated and non-publishable in Fake mode, so Fake-generated follow-ups cannot
enter the effectful queue. Autopilot never applies a result to the primary
worktree, publishes it, or merges it. Human-reviewed arbitration and explicit
preview/apply remain separate commands.

```json
{
  "version": 1,
  "task": {
    "title": "Update README",
    "body": "Make the README clearer without touching Rust code."
  },
  "assigned_paths": ["README.md"],
  "semantic_symbols": [],
  "semantic_modules": [],
  "validation_commands": ["cargo test"],
  "max_repair_attempts": 1,
  "forge_mode": "fake",
  "reviewer": {
    "mode": "fake"
  },
  "publish_mode": "draft_only",
  "auto_merge": false
}
```

```bash
cargo run -- autopilot plan autopilot-plan.json --repo . --json
cargo run -- autopilot run autopilot-plan.json --repo . --run-id readme-demo \
  --codex-bin codex \
  --quota-config config/operator-quota.json \
  --machine-global-config /etc/maco/machine-global.json \
  --machine-global-runtime-root-id runtime --json
cargo run -- autopilot run --from-goal goal.md --repo . \
  --run-id readme-goal-demo \
  --machine-global-config /etc/maco/machine-global.json \
  --machine-global-runtime-root-id runtime --json
cargo run -- autopilot status readme-demo --repo . --json
cargo run -- autopilot collect readme-demo --repo . --json
cargo run -- autopilot artifacts latest --repo . --json
cargo run -- review pr 123 --repo . --json
cargo run -- review pr 123 --repo . --reviewer-program tools/reviewer --reviewer-arg strict --json
```

Plain task files are accepted too; the first non-empty line becomes the title.
When a plan omits `assigned_paths`, autopilot uses a conservative task-to-path
proposal helper that looks at repository paths, Rust semantic names, and common
task wording instead of defaulting only to `README.md`. The helper is only a
starting point: hard sync claims, semantic coordination, live locks, and PR
safety gates remain authoritative, and ambiguous tasks are kept conservative.
Autopilot stores
`plan.json`, `supervisor-plan.json`, `supervisor-report.json`, `pr-report.json`,
`review-report.json`, and `final-report.json` under
`.maco/autopilot/runs/<run-id>/`. The final report embeds the exact typed
`SupervisorFinalReport`: `GateDenial`, `EnvironmentFailure` (including
`runtime_model_catalog_unavailable`), role economics/usage attribution, and
autonomy KPIs are composed rather than translated into a second vocabulary.
Autopilot does not recompute KPI rates or denominators; the supervisor aggregate
is the only KPI observation. Reports use repo-relative paths and omit nested
merge-preview paths and full diffs.

The disabled legacy implementation remains source-only design reference for a
deterministic child subprocess, forge, reviewer, repair loop, and publication
receipts. It is not called by `autopilot run`; forge, PR, review, validation,
repair, push, and merge operations in that loop remain unreachable. The legacy
`--reviewer-command` shell-string option is retained only for an explicit
fail-closed compatibility error and cannot grant real review authority. The
following external-review rules document that disabled reference surface, not
an active Autopilot dispatch. A JSON reviewer configuration uses
`mode: "external_command"`, a canonical
repo-relative or absolute `program`, and bounded `args`. PATH lookup, shell
strings, and shell `-c` are refused. The independent review report uses a
separate reviewer identity from the child worker, includes
structured findings with `blocking`, and currently reports
`ci_reaction_supported=false`. Reviewer configuration serializes as version 1;
an omitted config version remains accepted for compatibility, while unknown
fields are rejected recursively. Fake mode rejects external-program fields.
External-command mode rejects fake-only fields and uses a 300-second timeout
unless an explicit 1-to-86400-second value is provided. Program symlinks are
rejected; a script must use a single absolute shebang interpreter, whose
canonical regular-file identity and content are bound as well. A configured
native shell, language interpreter, or command dispatcher cannot act as the
authoritative reviewer program, including stdin/eval forms such as `sh -s`,
`python -`, or `node --eval`; this prevents the review request JSON itself from
becoming executable program text. A reviewer script with a direct native
shebang remains supported, while dispatcher shebangs are refused.

An external reviewer receives strict version-1 JSON on standard input and must
return one strict UTF-8 JSON object on standard output. The JSON result is
limited to 256 KiB, process capture is limited to 4 MiB per stream, truncated
output is refused, and nested unknown fields or mismatched target, attempt,
repository-relative paths, reviewer identity, or request binding are rejected.
The selected program and any script interpreter are opened without following
links, bounded and hashed, then copied with create-new semantics into an
owner-private runtime directory. Verified authority captures the materialized
program and, for scripts, its materialized native interpreter before the
systemd start gate opens. The bounded request descriptor is authenticated by a
digest fixed in the transient unit's argument vector; the helper revalidates
the bound identity and content, copies each entry image into a sealed memory
file, and executes by descriptor rather than reopening the launch pathname.
The source pathname is not passed to the process runner. This closes the
same-UID pathname-replacement gap for the entry images, but does not pin their
dynamic-library or language-module dependency closure. The authority path also
requires the running `maco` helper and all of its ancestors to be root-owned and
non-writable, so development and user-local binaries fail closed. Test-only
nonpublishable simulation remains unpinned and cannot create an authority
receipt. The parent derives the reviewer identity from the copied bytes and
bounded argv, and binds each request to the pre-run repository
snapshot, canonical request, sanitized-view manifest digest, effective timeout,
and sandbox-policy version;
the reviewer must echo that binding. Report strings alone do not grant real
publication authority: the Review boundary also returns a non-serializable
in-process receipt bound to the same repository, direct program and argv,
target, attempt, changed paths, diff summary, request binding, and derived
reviewer identity. Autopilot requires that exact receipt together with a
version-1 successful `Passed` report before Git or GitHub publication. Fake
review, the legacy shell-string input, and a syntactically plausible but
unreceipted report remain non-authoritative. A bounded descriptor prewalk rejects
oversized or excessive ignored/untracked trees before Git status construction.
Verified review separately constructs an owner-private sanitized view outside
the source repository. Its descriptor-stable manifest contains existing tracked
entries plus untracked non-ignored entries, their ordinary permission and
executable bits, and internal relative symlinks only when the lexical target is
a selected regular file or directory. `.git`, ignored content, and untracked or
ignored `.maco` runtime data are absent. A tracked `.maco` entry or a requested
changed path below `.maco` fails closed because an authoritative reviewer may
not pass content it was not shown. Gitlinks, sparse-missing or unmerged index
entries, case and file/directory collisions, hard links, special mode bits,
special files, escaping or dangling links, and bounded path/depth/count/byte
overflows also fail closed. Files are copied from no-follow source descriptors into
create-new destination descriptors, and the selected source and view manifests
are reverified before and after execution. The reviewer runs with this view as
its working directory; canonical changed paths and the bounded diff summary
remain parent-supplied JSON input, so Git administrative state is unnecessary.

The complete parent snapshot still covers
tracked, untracked, and ignored content, modes, link targets, file generations,
Git HEAD/ref/index/packed-ref state, and linked-worktree identities. Hard links,
special files, external links, and gitlinks fail closed. Concurrent changes to
those enumerated worktree entries, bound program/interpreter files, HEAD and its
bound ref, packed refs, index, worktree backlink, or bound MACO-state identity
invalidate the result; unrelated Git administrative files are not claimed as
part of this snapshot. Sensitive output is redacted and converted into a
blocking failed review.

The verified external-review runtime enforces both a read-only view and a
restricted root namespace with no network access. A read-only tmpfs replaces
the unit root. The configured path and bind sets re-expose the sanitized view,
the secret-free materialized reviewer program/interpreter directory needed by
the sealing helper, `/nix/store`, exact root-owned guardian/helper executable
aliases, and the identity-bound unit runtime. The policy also requests
systemd-managed private `/proc` and `/dev` views under the existing `Protect*`,
`ProcSubset`, and `PrivateDevices` checks. The original worktree, Git
directory and common directory (including MACO state and authentication keys),
and their parent data roots must have effective `InaccessiblePaths` properties
and verified systemd inaccessible-placeholder mounts before the start gate is
released. The authentication key is neither read for view construction nor
copied into the child namespace. Private `HOME`/`TMPDIR`, the descriptor,
mount report, and start/owner gates live only in the verified unit runtime.
Unexpected entries in the configured `BindReadOnlyPaths`, `ReadOnlyPaths`,
`BindPaths`, `ReadWritePaths`, and `InaccessiblePaths` sets, or a missing or
mismatched required mount or mask, fail closed. This does not claim a complete
allow-list inventory of systemd-created API VFS mounts such as `/proc`, `/dev`,
or `/sys`; their exact runtime layout remains part of strict-runtime validation.
The configured Nix-store view does not expose a general `/usr` or `/etc`;
non-Nix loader/library layouts therefore remain unsupported rather than
widening the host view. The reviewer can still inspect the explicitly visible
whole `/nix/store`, its own materialized entry images, and the systemd-created
API VFS surface. Those remain confidentiality boundaries; the source worktree
and ignored files are instead required to stay behind verified inaccessible
masks.

Autopilot refuses launch when the primary worktree is dirty unless
`--allow-dirty-primary` is supplied, or when active sync claims, semantic
intents, or active/blocked live claim locks overlap its target paths. These
checks run before artifact reservation and again immediately before supervisor
dispatch. Refusal JSON uses the shared `GateDenial` envelope. The supervisor
then remains responsible for bounded depth, claim admission, repository
cleanliness, journal, breaker, child/auditor acceptance, evidence-only re-audit,
and final primary-integrity checks. Plan files and nested task, path, semantic,
review, and command collections remain bounded and validated before dispatch.
External finding summaries, suggested fixes, next actions, diagnostics, and
finding paths remain available in bounded review artifacts but are never copied
into a later supervisor task. Retry prompts contain only a parent-selected
fixed reason code and validated blocking/severity counts.
Autopilot never auto-merges: `auto_merge=true` is accepted and reported as
requested, but `auto_merge_performed` is always `false`.

### Autopilot spine safety ledger

| Protection re-enabled or consumed | Satisfaction and retained failure path | Fail-capable evidence |
| --- | --- | --- |
| Repository-cleanliness capability and primary isolation | Issue #11 (`42f51aa`) capability-binds managed worktree creation. Autopilot checks dirty primary and repository bindings twice; supervise compares its final primary snapshot and fails the run on drift. The E2E independently compares complete HEAD identity/tree, exact index storage/entries, every HEAD- or index-tracked worktree path's content or link target, mode, missing/type state, and raw porcelain-v2 status flags. No result is applied to primary. | `autopilot_rechecks_dirty_primary_immediately_before_supervisor_dispatch`, `dirty_primary_refusal_emits_public_json`, and `fake_autopilot_depth_two_e2e_is_gated_durable_and_primary_untouched` fail if the pre-dispatch guard, typed dirty denial, or complete before/after snapshot equality regresses. `primary_git_snapshot_detects_complete_state_drift` independently fails unless otherwise omitted tracked content, mode, index storage/entries, status flags, and HEAD/tree changes are observable. |
| Typed path ownership | Issue #29 (`a38d6bc`) provides `GateDenial`. Overlapping durable sync claims, semantic intents, and live locks all become `claim_conflict`; the command finalizes a refusal without starting supervise. | `active_sync_claim_is_a_typed_preflight_refusal`, `active_semantic_intent_is_a_typed_preflight_refusal`, and `active_live_lock_is_a_typed_preflight_refusal` independently seed each store and fail if its guard is bypassed. |
| Depth, scheduling, journal, and breaker gates | Issues #9 (`1a9642e`, `6bc7e44`), #10 (`9b87d2d` through `61d1179`), and #24 (`d5b46ee`) made these live supervise gates. Autopilot accepts only the fixed depth-2, non-recursive assignment spine and calls that public path; other integer depths and non-empty recursive assignments become a typed `approval_review`/`permission_expansion` refusal before supervise dispatch, while malformed depth is invalid. Goal decomposition now uses the same validated in-tool planner from both live run entrypoints. Accepted publishable licensed-breakage follow-ups may add one command-level generated batch; evidence for a further batch becomes a typed `permission_expansion` refusal. | `fake_autopilot_depth_two_e2e_is_gated_durable_and_primary_untouched` requires a terminal worker, read-only auditor, review-lens aggregate, and durable supervise report. `autopilot_run_refuses_max_depth_three_with_typed_permission_expansion` and `autopilot_run_refuses_recursive_assignments_with_typed_permission_expansion` require a nonzero CLI result, the exact typed denial, a null embedded supervisor result, and no `.maco/o2` dispatch artifacts. Existing supervise journal/scheduler/breaker tests remain unchanged. |
| Writable-child containment boundary | Managed-worktree Codex uses native workspace-write under the verified outer boundary and does not require an app-server `All` callback. The primary-writable target still fails closed when universal callback coverage is absent, and Autopilot does not bypass that refusal. Fake executes in process and never invokes `codex_bin` or task text. | Managed-worktree launch tests require native execution and retained child-worktree isolation; the primary-target coverage test retains the containment refusal; `fake_runtime_never_executes_codex_bin_or_task_text_and_is_never_publishable` fails if Fake launches an executable or becomes publishable. |
| Acceptance lenses, megafile evidence, re-audit, claim lifecycle, and timing | Issues #16 (`9a88d44`), #19 (`098eb6a`), #30 (`80cce22`), structural extractions #45 (`bfb59ba`) and #49 (`8399ad8`, merged by `8bda772`), #50 (`f9b4b33`), #51 (`76bc21c`), and #53 (`469e3a6`) are consumed through the complete supervisor report rather than reimplemented. Their own failure paths continue to make the supervisor non-successful/non-publishable. | The depth-2 E2E requires worker, auditor, and `review_lens_aggregate` output. Existing focused supervise tests for each gate remain load-bearing and unchanged by the Autopilot wrapper. |
| Typed environment failures | Issues #31 (`5655419`) and #47 (`74369ac`) provide `EnvironmentFailure`, including `runtime_model_catalog_unavailable`. Autopilot embeds the supervisor report unchanged and performs no dispatch/publication after catalog failure. | `runtime_catalog_failure_composes_typed_environment_failure_without_dispatch` uses a missing Codex runtime and fails unless the exact typed category is nested in the Autopilot report. |
| Economics and KPI composition | Issues #34 (`285c517`) and #35 (`60ad4f9`) provide role economics, honest usage attribution including `not_process_observable`, and supervisor KPIs. Autopilot passes those fields through without inventing cost observations or recomputing rates. | `public_json_shape_is_stable_and_sanitized` requires the nested role-economics profile and `supervisor_aggregate` KPI observation. Existing supervisor economics/KPI gate tests retain their refusal assertions. |
| Machine-global destructive staging cleanup | Issues #44 (`0217cfb`), #48 (`5b3d8ba`), and #54 (`4491bf3`, merged by `a76a4b9`) bind both child-orchestrator and parent review-lens auditor staging cleanup through `SupervisorRunOptions`. CLI omission fails in argument parsing; programmatic omission fails before repository/plan effects; missing/partial or denied binding refuses cleanup and preserves staging. Fake creates no external staging and therefore records no fabricated cleanup. | `autopilot_run_cli_requires_machine_global_binding_before_effect_artifacts`, `autopilot_missing_retention_binding_fails_before_any_repository_or_runtime_side_effect`, and existing `supervise_dispatch_refuses_a_missing_staging_cleanup_binding` plus child/auditor binding tests fail if any reached destructive launch loses its binding. |
| Human-only integration | Issue #17 (`9f92b3e`) exposes arbitration only as an opt-in proposal. Generated follow-ups can run only as isolated ordinary supervisor work; Autopilot never calls publication, arbitration, or merge preview/apply, and legacy `auto_merge` is recorded only. | `auto_merge_request_is_recorded_but_never_performed` asserts the false capability fields and exact primary HEAD/index/files; `legacy_reviewer_command_refuses_before_autopilot_artifacts` and the legacy validation/reviewer plan tests fail if the legacy publication loop becomes reachable. |

The load-bearing CLI contract changed explicitly: previously every
`AutopilotSubcommand::Run` returned one unconditional unavailable error and its
integration test required zero run artifacts. It now requires a complete
machine-global binding, performs typed preflight and pre-dispatch checks, and
delegates exactly once to live supervise; the missing-binding test retains the
old before-effects refusal boundary. Effectful `maco inbox run` and
`maco inbox watch` callers are live again: they dispatch selected item work
through that same Autopilot spine, so they inherit its machine-global binding
requirement whenever item work launches Autopilot.

Run the fake-first inbox reaction loop:

```json
{
  "version": 1,
  "repository": {"version": 1},
  "permission_mode": "fake",
  "selection": {"version": 1, "max_items": 2},
  "max_repair_attempts": 1,
  "default_validation_commands": [
    {"version": 1, "name": "smoke", "command": "cargo test", "timeout_seconds": 60}
  ],
  "default_assigned_paths": ["README.md"],
  "privacy": {"version": 1, "allow_private_bodies": false}
}
```

```bash
cargo run -- inbox scan --repo . --json
cargo run -- inbox run --repo . --run-id inbox-demo --json
cargo run -- inbox run --repo . --run-id inbox-codex --permission github_local --codex-bin codex --json
cargo run -- inbox run --repo . --run-id inbox-quota \
  --max-rolling-tokens 42000 --max-rolling-cost-usd 12.5 --json
cargo run -- inbox status inbox-demo --repo . --json
cargo run -- inbox collect inbox-demo --repo . --json
cargo run -- inbox watch --repo . --poll-seconds 60 --once --json
cargo run -- inbox artifacts list --repo . --json
```

`maco-inbox.json` is optional. Without it, `maco inbox scan` uses deterministic
fake local data: one safe issue candidate, one PR candidate with requested review
changes and failing CI context, one unsafe item that is skipped, and duplicate
skipping evidence. Public JSON uses the typed schema fields `version`, `repo`,
`action_policy`, `github_enabled`, `success`, `refused`, `refusals`,
`candidate_count`, `selected_count`, `items`, and `next_action`; `repo` is the
public `"."` placeholder rather than a local absolute path. Item bodies are
bounded summaries with token-like values redacted, private key material refused,
and local absolute paths such as `/mnt/...`, `/home/...`, or `C:\Users\...`
rejected.

Inbox config files are bounded to 256 KiB, must be regular UTF-8 files, and are
opened without following a link. Unknown fields and unsupported schema versions
are rejected at every config level before scanning or acting. Omitted versions
remain compatible with version 1, and legacy validation-command strings remain
accepted. Selection is limited to 100 items, 32 labels, 32 validation commands,
128 assigned paths, 64 privacy terms, and 8 repair attempts; individual labels,
commands, paths, timeouts, body-summary limits, repository selectors, and
`codex_bin` paths are also bounded and reject control characters or noncanonical
values. CLI overrides pass through the same validation.

Each issue or pull request includes a versioned `source_snapshot` binding. It
binds the source provider, canonical repository selector, opaque durable local
repository identity, issue/PR kind and positive number, stable `source_key`,
`updatedAt`, and—for pull requests—the exact `headRefOid` and `baseRefOid`.
The deterministic digest is validated when deserialized and again before an
item is used. Duplicate detection remains stable by repository, kind, and number
while the snapshot digest separately identifies the observed source revision.
Fake fixtures use fixed timestamps and canonical fake OIDs for reproducibility.

`maco inbox run` and `maco inbox watch` execute effectfully: item work
dispatches through Autopilot, whose supervisor cascade derives the
capability-bound repository cleanliness input before creating managed
worktrees. `scan`, `status`, `collect`, and read-only artifact inspection
remain available. The fake-first reaction flow described below is the
executable behavior; the unbound Fake reviewer still stops as nonpublishable
before real publication effects.

`maco inbox run` accepts optional workspace rolling-quota ceilings
`--max-rolling-tokens`, `--max-rolling-cost-usd`, and
`--rolling-window-seconds`. A quota is bound only when at least one of
`--max-rolling-tokens` or `--max-rolling-cost-usd` is set; `--rolling-window-seconds`
alone is ignored. Values must be finite and positive. When a ceiling is set
and the window is omitted, the window defaults to 86400 seconds (24 hours).
These flags are inbox-run ceilings across Autopilot dispatches in the
workspace rolling ledger; they are not the supervise/autopilot per-run
`--max-tokens` / `--max-cost-usd` / `--max-duration-seconds` flags, which
`inbox run` rejects. `inbox watch` and `inbox workspace run|watch` do not
expose the rolling-quota flags. When a rolling quota refuses further work,
the run records `status=refused` and the next action asks the operator to
increase or wait for the quota.

Inbox runs write public-safe artifacts under `.maco/inbox/runs/<run-id>/`,
including `scan-report.json`, `selected-items.json`, `item-<n>-plan.json`,
`item-<n>-autopilot-report.json`, `item-<n>-github-report.json`, and
`final-report.json`. Reports use repository-relative paths and do not include
full diffs, raw secret values, credentials, or local absolute paths.

GitHub inbox intake is explicit opt-in. `--permission fake` is the default and
does not require network access or credentials. `github_read` reads live issues
and PRs through `gh` but only writes plans and reports. `github_local` reads live
GitHub and runs local repair with fake PR publication and no source comments.
`github_pr` reads live GitHub, runs repair, and publishes a draft PR through the
GitHub forge without commenting on the source item. `github_full` also comments
on the source issue or PR after success. `github_git` reads live GitHub issue/PR
items through `gh`, runs repair, pushes the branch through real Git, and does
not create a GitHub PR or comment on the source item. Hyphen aliases such as
`github-read` are accepted. Legacy `--github` and `action_policy: "github"` keep
the old full behavior unless `permission_mode` explicitly overrides them. Fake
PR review and failing CI context are converted into autopilot repair plans with
assigned paths, reasons, and validation expectations. Inbox also preserves the
same path-scoped safety boundary as autopilot: it refuses dirty primary worktree
files, active local locks, active sync claims, active semantic intents, and
active/blocked live claim locks only when they overlap selected target paths,
while ignoring its own `.maco/**` and `.maco-cache/**` runtime artifacts.
Refusal JSON includes paths and lock details. Inbox never performs automatic
merge; human review remains the next action after a successful reaction.
Live GitHub intake uses the same pinned trusted `gh` network boundary as
publication: private host-specific token/config state, a minimal environment,
bounded capture and timeout, an exact host-qualified `--repo`, and a fixed
allowlist for issue/PR list arguments. Intake snapshots store the canonical
source host separately and fail closed if the origin host, owner, or repository
changes. GitHub source JSON is schema-strict: every requested field must be
present with its declared type; only `author: null` and PR
`reviewDecision: null` are accepted as explicit provider nulls.
Until an external reviewer identity and result are explicitly bound into the
publication evidence, non-dry-run `github_git`, `github_pr`, and `github_full`
runs fail closed; their dry-run plans and read-only intake remain available.

Run the cross-repository inbox workspace supervisor:

```json
{
  "version": 1,
  "default_permission_mode": "github_read",
  "default_max_items_per_repo": 2,
  "strict": false,
  "repositories": [
    {
      "version": 1,
      "id": "orchestrator",
      "path": "../Multi-Agent_Coding_Orchestrator",
      "enabled": true,
      "permission_mode": "github_local",
      "max_items": 1,
      "labels": ["bug"],
      "include_pull_requests": true,
      "include_issues": true
    },
    {
      "version": 1,
      "id": "docs",
      "path": "../project-docs",
      "enabled": false,
      "include_pull_requests": true,
      "include_issues": true
    }
  ],
  "safety": {
    "version": 1,
    "require_clean_primary": true,
    "require_validation_for_publication": true,
    "allow_auto_approval": false,
    "allow_auto_merge": false
  }
}
```

```bash
cargo run -- inbox workspace scan --config workspace-inbox.json --json
cargo run -- inbox workspace run --config workspace-inbox.json --run-id workspace-demo --json
cargo run -- inbox workspace run --config workspace-inbox.json --run-id workspace-dry --dry-run --json
cargo run -- inbox workspace watch --config workspace-inbox.json --poll-seconds 60 --once --json
```

`maco inbox workspace scan`, `run`, and `watch` are implemented. `scan` reads
the workspace config and reports per-repository intake without launching
Autopilot. `run` writes aggregate artifacts under
`.maco/inbox-workspace/runs/<run-id>/` and then executes each enabled
repository through the same inbox run path used by `maco inbox run`. `watch`
polls that run path; `--once` performs a single iteration and returns. `--dry-run`
plans item work and writes reports without launching Autopilot. Workspace
run/watch do not accept the inbox rolling-quota flags; those apply only to
`maco inbox run`.
The retained aggregate design reports `version`, a public-safe `config_path`,
`strict`, repo counts, and one entry per repository with `id`, `enabled`,
`permission_mode`, `status`, `success`, `refused`, optional `message`, and an
embedded `scan_report` or `run_report`. Per-repo repair artifacts remain under
each repository's `.maco/inbox/runs/<run-id>/` tree. Public reports must not
expose local temp paths, credentials, raw secrets, or private bodies.
Workspace configs use the same 256 KiB bounded, no-follow UTF-8 loading and
strict unknown-field/version rules. They support at most 64 uniquely identified
repositories; repository IDs, paths, labels, per-repository item counts, and
canonical resolved-path collisions are validated before any repository scan.

`strict: false` keeps scanning or running later repositories when one repository
is disabled, empty, dirty, or refused; the per-repo entry records the failure.
`strict: true` turns a repository refusal or failure into an aggregate command
failure. Permission modes inherit from `default_permission_mode` and can be
overridden per repository. `github_read` only scans and plans through `gh`,
`github_local` can run local repair without source comments, `github_git` can
plan or perform Git branch publication without GitHub PR creation, and
`github_pr`/`github_full` are used only when explicitly configured. Workspace
inbox is cross-repository supervision, not approval or merge automation:
automatic approval and automatic merge are unsupported, and reports keep
`auto_approval_performed=false` and `auto_merge_performed=false`.

Cleanup examples:

```bash
cargo run -- sync status --repo . --json
cargo run -- worktree pending --repo . --json
cargo run -- worktree remove agent-a --repo . --force --delete-branch
```
