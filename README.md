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
- `maco worktree create <agent-id>` creates a linked Git worktree for branch `maco/<agent-id>`.
- `maco worktree list` lists registered agent worktrees.
- `maco worktree remove <agent-id>` removes an agent worktree, refusing dirty worktrees unless `--force` is passed.
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
- `maco orchestrate run <plan-file>` creates or reuses agent worktrees, claims paths, runs configured local shell commands, runs per-agent validation commands in agent worktrees, enforces path-claim boundaries, optionally writes patches and checkpoints, releases claims, and emits a run summary.
- `maco orchestrate resume <checkpoint-file>` authenticates the repository-bound v3 journal, validates repository HEAD, plan snapshot, worktree metadata, path boundaries, and claims, then reruns validation/capture for completed commands without rerunning those commands.
- `maco worktree diff` collects a registered agent worktree diff and uses active sync claims when `--claim` is omitted.
- `maco orchestrate collect` reads a prior JSON run summary and builds merge candidates with validation reports from agent summaries.
- `maco merge preview` and `maco merge apply` collect one stable agent snapshot and gate primary-worktree integration with dirty-primary, stale-base, unclaimed-edit, candidate-bound validation, and apply-check safety reports. Both commands accept external validation JSON with `--validation-report`; `--require-validation` accepts passed reports only when their envelope contains the exact current `candidate.validation_binding` (or a passed `merge apply --validation-command`).
- `maco merge apply --validation-command <command>` validates a temporary merged
  candidate before mutating the primary worktree. A command failure or a
  recursive candidate-state change, including an initialized or uninitialized
  submodule change, blocks the apply and leaves the primary worktree unchanged.
- `maco pr preview` checks whether an agent worktree is ready to publish without mutating the primary worktree or contacting a forge.
- `maco pr publish --forge fake|github` turns a safe agent worktree result into a local agent-worktree commit when validation is not required, re-previews the resulting clean commit, then either emits a deterministic fake PR URL or, with explicit `--forge github`, publishes an OID-bound remote ref and verifies the resulting GitHub receipt. A durable transaction journal reconciles a lost push or `gh` response when the same command is rerun. With `--require-validation`, publication is a two-stage workflow: commit first, preview and validate that exact binding, then publish with the bound envelope.
- `maco issue preview` redacts issue bodies without creating anything.
- `maco issue create --forge fake|github` creates a deterministic fake issue URL locally or, with explicit `--forge github`, shells out to `gh issue create`.
- `maco live status`, `maco live validate`, `maco live heartbeat`, and
  `maco live override-release` expose repo-local Markdown claim liveness for
  active, blocked, handoff, and done work.
- `maco llm providers` and `maco llm prompt-preview` expose the provider-neutral prompt boundary without network calls.
- `maco agent run` runs a local fake-provider-backed proposal in an isolated worktree with durable claims, boundary checks, validation, merge-preview reporting, and no real network providers by default.
- `maco supervise plan` normalizes an opt-in supervisor task or JSON plan for
  Codex CLI subprocess orchestration.
- `maco supervise run` serially launches opt-in O1 child orchestrators through
  the Codex CLI in isolated child worktrees under an O2 supervisor. Each child
  is instructed to read `AGENTS.md` and project-local `.agents` guidance before
  acting, use Codex native SubAgent/delegated-worker mechanisms for terminal
  worker/researcher assignments when available, preserve the O1/O2 subprocess
  launch boundary of the outer verified MACO sandbox with verified systemd
  cgroup ownership evidence plus the fixed `maco_external_codex` inner
  permission profile, enable goals and multi-agent support only for the
  supervisor role, leave O1/O2 hierarchy and enforced audit gates to MACO/Codex
  CLI subprocess workflows, report peer-O2 escalation candidates instead of
  taking them over, and preserve structured reporting without applying worker
  changes to the primary worktree
  automatically.
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
- `maco autopilot plan/run/status/collect` provides the first local-first
  autopilot workflow: normalize a task or plan, run a supervised child worker in
  fake/local mode by default, publish through the PR safety gates, run an
  independent reviewer, and write public-safe reports under
  `.maco/autopilot/runs/<run-id>/`.
- `maco autopilot artifacts list/latest/prune` inspects or prunes durable
  autopilot run artifacts.
- `maco review pr <number|url>` emits an independent fake structured review
  report by default, with `ci_reaction_supported=false`.
- `maco inbox scan/run/status/collect/watch` provides a fake-first reaction
  loop for issue intake, pull request review feedback, and failing CI checks,
  converting safe inbox items into autopilot repair plans without network access
  or automatic merge by default.
- `maco inbox artifacts list/latest/prune` inspects or prunes durable inbox run
  artifacts.

## Roadmap

Implemented local foundations:

1. Result collection, merge preview, and guarded patch apply for agent worktrees.
2. Parser-backed Rust repository maps for modules, symbols, impls, imports, and
   dependency edges, plus semantic risk reports for changed paths.
3. Local orchestration with dependency scheduling, path claims, timeouts,
   per-agent validation, repo-level validation, run ids, checkpoint writes,
   safe checkpoint resume, and guarded `reuse=reset`.
4. Provider-neutral LLM adapter boundaries with deterministic fake-provider
   tests and local fake-provider-backed `maco agent run` execution.

Known limitations and roadmap for 0.3.0:

1. Richer merge conflict classification is a known limitation. Current apply
   uses Git apply safety checks and reports structured blockers, but does not
   classify conflicts by symbol or dependency impact.
2. Semantic task planning, including automatic path-claim and orchestration-plan
   proposal, is post-0.3.0 roadmap work. Current task-to-path proposals are
   conservative helpers for autopilot and inbox defaults; claim gates remain
   authoritative.
3. PR and issue publication are intentionally narrow. The fake forge is
   deterministic and local-only. GitHub publication is opt-in with explicit
   `--forge github` and shells out to local `git` and `gh`; tests cover the
   fake adapter without network access. Remote push, PR creation, and the
   post-create receipt check are not one globally atomic operation; the durable
   receipt supports detection and retry reconciliation rather than claiming
   cross-service atomicity. Autopilot keeps the same boundary:
   GitHub publication is selected only by a plan's explicit
   `forge_mode: "github"`. Inbox intake keeps deterministic fake data as the default;
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

Durable sync state is stored under the Git common metadata directory at
`$(git rev-parse --git-common-dir)/maco/state/claims.json`, so the primary
worktree and linked agent worktrees share the same claim state.

## Semantic coordination

Semantic coordination adds a typed blackboard of structured intents, not
free-form agent chat. Durable semantic state is repo-local under the Git common
metadata directory at
`$(git rev-parse --git-common-dir)/maco/state/semantic_intents.json`, so the
primary worktree and linked agent worktrees see the same planning state.

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

Default linked worktrees are created outside the repository at
`../.maco/worktrees/<repo-name>/<agent-id>`.

## Local Artifact Boundaries

Runtime artifacts are local operator evidence, not source files. Autopilot,
inbox, and supervisor runs write under `.maco/.../runs/<run-id>/`; generated run
ids are collision checked, and an explicit `--run-id` is refused when that run
directory already exists. Use each command family's nested artifact helpers to
inspect or prune only that family's run directories:

```bash
cargo run -- autopilot artifacts list --repo . --json
cargo run -- autopilot artifacts latest --repo . --json
cargo run -- autopilot artifacts prune --repo . --keep 10 --dry-run --json
cargo run -- inbox artifacts list --repo . --json
cargo run -- supervise artifacts latest --repo . --json
cargo run -- consult artifacts list --repo . --json
```

`prune` orders runs newest first, keeps the requested number, and supports
`--dry-run` before deletion. It is scoped to the selected family root, such as
`.maco/autopilot/runs`, `.maco/consult/runs`, `.maco/inbox/runs`, or
`.maco/o2/runs`. Run pruning is currently for quiescent operator-owned roots;
do not prune concurrently with an active run or an untrusted same-UID path
mutator. Finalized-only descriptor-relative deletion remains planned work.

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
executable does not weaken that refusal. The command form below demonstrates
the expected fail-closed response; it does not launch Claude.

```bash
cargo run -- consult ask \
  --repo . \
  --runtime claude \
  --consultant-bin claude \
  --question "What narrow fix should I inspect next?" \
  --context-path tests/supervise_cli.rs \
  --json
```

Consultant advice is advisory evidence only. It does not override project
rules, assigned ownership, validation requirements, review gates, or merge
gates.

Durable project guidance under `.agents/docs`, `.agents/skills`, and
`.agents/workflows` may appear in repository maps. Local-only agent scratch
state under `.agents/temp`, `.agents/storage`, and `.agents/live` is excluded
from repository maps, semantic maps, and task-path proposal helpers.

## Development

If Rust is available globally:

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
```

If Rust is not available globally, use Nix:

```bash
nix develop path:$PWD
```

Inside that shell, run the same Cargo commands.

For one-shot checks:

```bash
nix develop path:$PWD -c cargo fmt -- --check
nix develop path:$PWD -c cargo test
nix develop path:$PWD -c cargo clippy --all-targets -- -D warnings
```

## CLI Examples

Inspect a repository:

```bash
cargo run -- repo map --repo . --json
cargo run -- repo map --semantic --repo . --json
cargo run -- repo query symbol WorktreeManager --repo . --json
cargo run -- repo query path src/worktree.rs --repo . --json
cargo run -- repo query risk --path src/worktree.rs --repo . --json
```

Create a worktree from the current repository HEAD:

```bash
cargo run -- worktree create agent-a --repo . --json
```

List worktrees:

```bash
cargo run -- worktree list --repo .
```

Remove a clean worktree and delete its default branch:

```bash
cargo run -- worktree remove agent-a --repo . --delete-branch
```

Claim paths for an agent:

```bash
cargo run -- sync claim agent-a src README.md --repo . --json
```

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

The orchestrator validates that plan paths do not overlap, dependencies are
known and acyclic, commands are non-empty, and timeouts are positive. It creates
or reuses a linked worktree for each agent id according to
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
cargo run -- merge apply agent-a --repo . --claim src --validation-report validation.json
cargo run -- merge apply agent-a --repo . --claim src --require-validation --validation-command "cargo test" --json
cargo run -- merge apply agent-a --repo . --claim src --force-dirty-primary --force-stale-base --force-unclaimed-edits
```

Merge apply refuses dirty primary worktrees, stale agent bases, unclaimed edits,
validation failures, and apply conflicts unless the matching explicit force flag
is passed. Apply-check failures themselves are still blocking unless
`--force-apply-conflicts` allows a successful three-way apply check. Validation
failures are considered when validation reports are supplied from collected run
summaries or from direct `--validation-report` JSON files. External validation
JSON may be a single report, an array, an object with `validation`,
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
the reviewed object with a create-only lease. Network Git runs against a private
bare context and structurally reads none of the real repository's local,
worktree, included, global, or system config. The raw origin URL is supplied as
guarded child-only config data, not an argument, process display, journal field,
or on-disk temporary config. Proxy, custom CA, askpass, credential-helper, HOME,
and custom SSH routing variables are absent. `ssh://`, `git+ssh://`,
`ssh+git://`, and SCP-style origins with an optional user (including userless
`host:path` and bracketed IPv6 hosts) are structurally classified as SSH. Every
such origin uses a trusted absolute `ssh` with user config disabled, batch mode,
`ProxyCommand=none`, and local commands disabled. Default identity and certificate
files, PKCS#11/security-key providers, GSSAPI, host-based, password, and
keyboard-interactive authentication are disabled; agent forwarding and adding
keys to the agent are also disabled. `SSH_AUTH_SOCK` is therefore the only
preserved SSH data-auth input. Host authentication is separate and fail-closed:
user known-host files and DNS/update discovery are disabled, strict host-key
checking is enabled, and `GlobalKnownHostsFile` is bound to the canonical target
of a root-owned, non-writable `/etc/ssh/ssh_known_hosts` (or
`ssh_known_hosts2`). If neither system file exists, is trusted, or contains the
requested host, an administrator must provision it before SSH publication can
succeed. Ambiguous authorities and unsupported URL schemes are refused. HTTPS
Git publication therefore requires credentials in
unencoded URL userinfo or another transport that needs no inherited helper.
Query, fragment, and percent-encoded credential forms are refused because
reliable transport and error redaction semantics cannot be guaranteed.

GitHub publication observes the remote head and exact base OIDs before PR
creation, reads the resulting PR with `gh pr view`, and requires matching
`headRefOid`, `baseRefOid`, base branch, open state, and draft/ready value before
persisting any PR receipt fields or advancing the receipt phase.
The HTTPS/SSH origin is also parsed into a bound host/owner/repository identity.
Every `gh pr` and `gh issue create` call receives that explicit `--repo`;
`gh` receives an empty private config directory and an explicit environment
allowlist containing only OS/locale essentials plus GitHub token variables.
HOME, proxy, custom CA, ambient repository, debug, pager, and forced-TTY routing
are absent. Its current directory is that private config runtime, whose identity,
owner record, and owner-only mode are rechecked immediately before each spawn;
the potentially hostile source worktree is never the `gh` current directory.
The receipt URL must identify the same repository and PR number.
Publication observes the remote head and base again after that receipt. A
mismatch is reported as blocked rather than published.

Publication writes versioned, append-only transaction records below the common
`.git/maco/state/publication-transactions/` directory. Record replacement is
atomic, the latest 32 records are kept for each transaction, and Unix creates
the managed directories with mode `0700` and key/journal files with mode
`0600`. Journal directory entries, retained record count, and individual record
bytes have strict upper bounds. Loading uses no-follow bounded reads and rejects
non-regular, symlink/reparse, foreign-owned, exposed, or multiply linked records,
identity/size changes, non-contiguous retained sequences, receipt field changes,
and incomplete or contract-invalid GitHub receipts. Windows rejects reparse
points and verifies file identity, but this
workflow does not claim to tighten inherited Windows ACLs. A repo-common random
key derives a one-way binding digest from the remote name and raw URL, so a
credential or endpoint change cannot reuse an older transaction while the raw
URL remains absent from the journal. User information, query values, fragments,
raw credentials, and unredacted command errors are represented only by that
keyed binding and the redacted display value. If the binding key is missing
while prior transaction entries exist, publication fails closed instead of
creating a new key. The JSON
`publication_receipt` reports the monotonic
phase (`prepared`, `push_observed`, `pr_observed`, or `completed`), expected and
observed head OIDs, exact expected base OID, remote ref, PR URL and verified PR
fields, whether creation was attempted, whether a contract-checked receipt
attributed the PR to this transaction, whether reconciliation found an existing PR, and the
last redacted error. A PR recovered only through `list`/`view` after a lost
response is conservatively reported as `created_by_transaction=false` and
`observed_existing_pr=true`. Rerun the same `pr publish` command: it reconciles
the remote ref and existing PR before attempting another write. A completed
transaction is idempotent.

These checks do not make Git hosting operations globally atomic. Another actor
can still move or delete the remote ref after a check, and PR creation plus the
post-create `gh pr view` verification spans multiple remote operations. The
post-create check detects a mismatch; it cannot prevent a later one. The
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
```

`maco pr preview` uses the same merge-preview gates as `merge apply` and never
pushes or creates a pull request. `maco pr publish --forge fake|github` refuses
dirty-primary, stale-base, unclaimed-edit, validation, and apply-check blockers.

With `--require-validation`, use this exact two-stage workflow:

1. Commit the candidate in the agent worktree and leave it clean.
2. Run `maco pr preview ... --json` and validate that exact committed snapshot.
3. Copy `preview.candidate.validation_binding` verbatim into the envelope shown
   above and add the passed validation report.
4. Run `maco pr publish ... --require-validation --validation-report <envelope>`.

Required publication never creates an internal commit, because doing so would
change the binding after review. A dirty required candidate is blocked with the
commit -> preview -> validate -> publish recovery sequence. Without
`--require-validation`, publish may commit safe uncommitted changes in the agent
worktree only, but it re-previews the clean commit and checks it again immediately
before external publication. The fake forge returns deterministic
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
cargo run -- live heartbeat claim-id --repo . --by owner-id --json
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

`heartbeat` is limited to `active` or `blocked` claims and requires `--by` to
exactly match the recorded owner. `override-release` is also limited to those
states and requires a claim that is provably stale; a fresh, future-dated, or
otherwise unknown liveness result is refused. Its required `--by` value is an
audited actor label, not an authentication credential, and `--reason` is
bounded and rejects control-character injection. Mutations run under a stable
board lock, compare the exact file identity and content generation, then use a
fenced, durable atomic replacement so concurrent or rebound-file changes are
refused instead of overwriting them. `--now` is available on live subcommands
for deterministic test runs.

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

`maco agent run` currently accepts only the local `fake` provider. It renders
the same provider-neutral prompt boundary used by `llm prompt-preview`.
Provider-proposed shell commands are disabled by default: the command above
reports a refusal for the proposed `printf` command and tells you to rerun with
`--allow-provider-commands` if you trust the proposal. Patch-only fake proposals
can run without that opt-in. When command execution is explicitly allowed,
`maco agent run` applies fake-provider proposed patches and commands inside the
agent worktree, runs provider-proposed and CLI-supplied validation commands,
collects a merge candidate and preview, reports path-boundary violations, and
releases durable claims unless `--keep-claims` is supplied. Real network
providers remain unconfigured by default.

```bash
cargo run -- agent run task.md --agent-id agent-a --path README.md --fake-proposal proposal.json --allow-provider-commands --validation "cargo test" --repo . --json
```

Run an opt-in supervisor-of-orchestrators plan:

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
cargo run -- supervise plan supervisor-plan.json --repo . --json
cargo run -- supervise run supervisor-plan.json --repo . --run-id supervise-demo --codex-bin codex --json
cargo run -- supervise status supervise-demo --repo . --json
cargo run -- supervise collect supervise-demo --repo . --json
cargo run -- supervise artifacts latest --repo . --json
```

`maco supervise run` is opt-in process-level orchestration. It shells out to the
configured Codex-compatible executable, creates isolated child worktrees, claims
each assignment's paths, records semantic coordination metadata when the plan
requests it, and writes structured logs and reports under the run directory.
Child/model final-message bytes are confined to `incoming/`; normalized child
reports and `supervisor-final.json` are parent-owned under `reports/`. Only the
incoming root is granted writable to an external child. The parent retains file
descriptors for bounded reads and atomic final writes.
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
selecting a broader sandbox mode. The ordinary workspace-write profile is not
used for these chains because nested Codex state DB access can collide, corrupt,
or fail under workspace-scoped restrictions.

For worker assignments, child orchestrators should use Codex native
SubAgent/delegated-worker mechanisms when available only for terminal worker or
researcher execution so the project manager/worker boundary is preserved. If no
delegated-worker mechanism is available, the child should stop before mutation
and report the exact blocked worker task. For child assignments with workers,
`maco supervise run` requires structured terminal audit evidence before
accepting the child report: the parent launches a read-only `REVIEW_AUDITOR`
subprocess and requires an accepted AuditorReport with `role=auditor`,
`no_further_delegation=true`, `read_only=true`, and coverage for all assigned
worker ids. A child-side review auditor is advisory unless the parent MACO/O2
acceptance gate collects and accepts it. The accepted parent-launched
AuditorReport is appended to the child `audit_reports` field.
If a child declares worker assignments but returns zero `worker_reports`, the
child report is rejected as structurally incomplete. If a child has no worker
assignments but leaves a non-empty child worktree diff, `maco supervise run`
still launches the parent read-only `REVIEW_AUDITOR` and requires it to cover
the child orchestrator id and changed paths.
`maco supervise run` does not apply worker changes to the primary worktree
automatically. Child orchestrator execution is currently serial: the supervisor
starts and waits for one child process at a time.
`max_child_assignments` bounds the number of child assignments in the plan, and
therefore the allowed fan-out, but it is not a parallel execution limit yet.
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
cargo run -- autopilot run autopilot-plan.json --repo . --run-id readme-demo --json
cargo run -- autopilot status readme-demo --repo . --json
cargo run -- autopilot collect readme-demo --repo . --json
cargo run -- autopilot artifacts latest --repo . --json
cargo run -- review pr 123 --repo . --json
```

Plain task files are accepted too; the first non-empty line becomes the title.
When a plan omits `assigned_paths`, autopilot uses a conservative task-to-path
proposal helper that looks at repository paths, Rust semantic names, and common
task wording instead of defaulting only to `README.md`. The helper is only a
starting point: hard sync claims, semantic coordination, live locks, and PR
safety gates remain authoritative, and ambiguous tasks are kept conservative.
Autopilot stores
`plan.json`, `supervisor-report.json`, `pr-report.json`, `review-report.json`,
and `final-report.json` under `.maco/autopilot/runs/<run-id>/`. These reports
use repo-relative paths and omit nested merge-preview paths and full diffs.

By default, autopilot creates a deterministic fake child subprocess locally, uses
the fake forge, and runs the fake reviewer. It does not require network access,
credentials, or a real Codex binary. Passing `--codex-bin` opts into an external
Codex-compatible executable. Setting `forge_mode` to `github` in the plan opts
into `git push` and `gh pr create`; fake remains the default. Passing
`--reviewer-command` opts into an external reviewer command. The independent
review report uses a separate reviewer identity from the child worker, includes
structured findings with `blocking`, and currently reports
`ci_reaction_supported=false`. Reviewer configuration serializes as version 1;
an omitted config version remains accepted for compatibility, while unknown
fields are rejected recursively. Fake mode rejects external-command fields,
and external-command mode requires a bounded command, rejects fake-only fields,
and uses a 300-second timeout unless an explicit 1-to-86400-second value is
provided.

An external reviewer receives strict version-1 JSON on standard input and must
return one strict UTF-8 JSON object on standard output. The JSON result is
limited to 256 KiB, process capture is limited to 4 MiB per stream, truncated
output is refused, and nested unknown fields or mismatched target, attempt,
repository-relative paths, reviewer identity, or request binding are rejected.
The parent derives the reviewer identity from the full command and binds each
request to the exact pre-run repository snapshot, canonical request, and
command digest; the reviewer must echo that binding. The snapshot covers
tracked, untracked, and ignored content, modes, link targets, file generations,
Git HEAD/ref/index/packed-ref state, and linked-worktree identities. Hard links,
special files, external links, and gitlinks fail closed, and any concurrent
repository or administrative-state mutation invalidates the result. Sensitive
output is redacted and converted into a blocking failed review.

The verified external-review runtime enforces the integrity boundary with a
read-only workspace and no network access. This is not yet a confidentiality
boundary: the reviewer still sees the source worktree, including ignored
files, and host-readable sibling roots may remain visible. A sanitized reviewer
view and global read isolation remain integration follow-up work.

Autopilot refuses to launch when the primary worktree is dirty unless
`--allow-dirty-primary` is supplied, when active sync claims overlap its target
paths, when active semantic intents overlap those paths, or when active/blocked
live claim locks overlap those paths. Refusal JSON includes the refusal kind,
paths, and lock details such as owner, sync or semantic token, or live claim id
when available. It also relies on the existing supervise and PR safety gates for
stale/dirty child worktree reuse and unclaimed edits. Blocking review findings
or failed validation trigger repair attempts up to `max_repair_attempts`.
Autopilot never auto-merges: `auto_merge=true` is accepted and reported as
requested, but `auto_merge_performed` is always `false`.

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

`maco inbox run` processes selected candidates through the same fake-first
autopilot flow unless config `action_policy` or CLI `--dry-run` selects dry-run
mode. `--max-items` overrides config selection for a scan, run, or watch command.
`--codex-bin` on `run` or `watch`, or `codex_bin` in `maco-inbox.json`, passes a
Codex-compatible executable through to autopilot; omitted keeps deterministic
fake child execution. `timeout_seconds` is honored for validation commands that
do not return.

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

Workspace inbox supervises the same inbox flow across multiple configured local
repositories. The aggregate JSON reports `version`, a public-safe `config_path`,
`strict`, repo counts, and one entry per repository with `id`, `enabled`,
`permission_mode`, `status`, `success`, `refused`, optional `message`, and an
embedded `scan_report` or `run_report`. Workspace run artifacts are written
under `.maco/inbox-workspace/runs/<run-id>/`, while per-repo repair artifacts
remain under each repository's `.maco/inbox/runs/<run-id>/` tree. Public reports
must not expose local temp paths, credentials, raw secrets, or private bodies.
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
cargo run -- worktree remove agent-a --repo . --delete-branch
```
