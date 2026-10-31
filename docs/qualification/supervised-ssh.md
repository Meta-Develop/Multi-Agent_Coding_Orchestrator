# Supervised SSH qualification

Status: **not qualified**. The shipped Linux lifecycle client/helper and operator
trust loader support a bounded **candidate-only** CLI route. Native provider
admission, network/account capabilities, trusted usage recapture, worktree import,
and scheduler recovery/accounting are not implemented for this route. It cannot
publish or accept an assignment. A live two-host qualification remains an owner
gate; the deterministic tests contact no SSH host and make no provider calls.

The atomic command SSH client uses a different protocol and is not a source of
supervised lifecycle receipts. Only its fixed OpenSSH option construction is reused.

## Operator trust

An assignment may explicitly select `{"kind":"ssh","target":{...}}`. Omission
keeps local execution. Plan data cannot load trust, install a transport, or change
credentials. `maco supervise run PLAN --ssh-trust TRUST.json` explicitly loads
operator capabilities before parsing the plan. Unknown/mismatched targets refuse
without Local fallback. Attached messaging, hosted pre-action review, non-Codex
adapters, and additional native runtime capabilities remain unsupported.

Create a private regular JSON file (mode 0600, owned by the invoking user), with
no symbolic-link ancestors or hard links. Parent directories must not be writable
by other users, except a sticky temporary-directory ancestor. Use existing,
reviewed credentials only. Do not generate keys or modify authorized_keys for this
qualification. Example shape (replace all example values with reviewed values):

```json
{
  "version": 1,
  "ssh_binary": "/usr/bin/ssh",
  "targets": [{
    "target": {
      "host_id": "reviewed-target",
      "endpoint": "reviewed.example.invalid",
      "user": "reviewed-user",
      "port": 22,
      "helper": "/opt/maco/bin/maco",
      "root": "/srv/maco/candidates"
    },
    "identity_file": "/operator/ssh/identity",
    "known_hosts_file": "/operator/ssh/known_hosts",
    "limits": {
      "max_workspace_entries": 1024,
      "max_workspace_bytes": 16777216,
      "max_file_bytes": 1048576,
      "max_stdout_bytes": 1048576,
      "max_stderr_bytes": 65536,
      "max_event_count": 1024,
      "max_event_bytes": 1048576,
      "max_request_bytes": 33554432,
      "max_receipt_bytes": 33554432,
      "connect_timeout_millis": 5000,
      "execution_timeout_millis": 15000,
      "cancellation_grace_millis": 1000,
      "poll_interval_millis": 50
    }
  }]
}
```

The plan's target must match host ID, endpoint, user, port, helper, and root
exactly. Identity and known-hosts paths are never accepted from a plan. Paths
containing OpenSSH expansion syntax (`$`, `%`, or `~`) are rejected, including
literal `${VARIABLE}` file names. All path components are opened without
following symlinks; ancestors must be owned by root or the invoking user and
must not be writable by others (apart from sticky temporary-directory ancestors).

The loader pins complete source-file identity (device, inode, size, owner, mode,
link count, nanosecond mtime/ctime) and a content digest. It rechecks both before
each exec. It copies the bounded validated bytes into anonymous, write-sealed
memfds; no credential bytes are printed, logged, or persisted on disk. OpenSSH
reads identity and known-hosts bytes through parent-owned `/proc/PID/fd/N` paths,
which remain held through child cleanup even if OpenSSH closes inherited FDs.
The executable is also a sealed snapshot and executes through an inherited
`/proc/self/fd/N`, so replacement between validation and exec cannot select
another image. A source change revokes subsequent calls until explicit reload.

OpenSSH receives `-F /dev/null`, `BatchMode=yes`, `StrictHostKeyChecking=yes`,
`IdentitiesOnly=yes`, `IdentityAgent=none`, explicit `-i` and
`UserKnownHostsFile`, disabled global known-hosts/DNS trust, disabled password and
keyboard-interactive authentication, one bounded connection attempt, no proxy,
no forwarding, and no TTY. The client removes agent/askpass/display environment
hooks. Data is sent on stdin, never interpolated into the remote command.

The local SSH transport requires a delegated cgroup-v2 scope. Run the coordinator
under `systemd-run --user --scope --quiet -p Delegate=yes ...`. Each call creates
a private child cgroup, attaches before exec, and uses `cgroup.kill` for all
remaining local descendants, including processes that call `setsid`. Stdin and
stdout are nonblocking. One absolute deadline covers validation, serialization,
child exit, pipe completion, decoding and cleanup. Source-file validation streams
SHA-256 in 16 KiB read/hash chunks and checks the same deadline between chunks
and ancestor-path steps; it never hashes a whole executable without interruption.
Snapshot copying and sealing occur only at trust load, before per-operation
deadlines start. Request serialization and frame copying also check bounded
chunks. A reserved part of that budget
is used for bounded reaping. A cleanup that cannot be proved by the deadline is
an uncertain transport failure; there are no pipe-reader/writer threads to join.
This cleanup never targets the actual remote workload.

Before recording stage or launch intent, the coordinator revalidates trust and
checks that it can create, inspect, kill and remove an empty private cgroup.
Missing delegation returns the `systemd-run --user --scope -p Delegate=yes` remedy
without a stage checkpoint or SSH child. Repair the prerequisite and retry the
same assignment identity. If a local prerequisite changes after preflight, a
bounded typed `NotStarted` result restores and persists the preceding retryable
state. After SSH starts, lost replies still require the original reconciliation
rules; they never become permission to relaunch.


Install the same reviewed binary on the remote host. Its root directory must
already exist, be canonical, owned by the remote user and mode 0700. The remote
Linux host must support the existing required user-systemd/cgroup-v2 containment
backend. The helper has no fallback to uncontained execution. Its current profile
is an offline workspace, with separate staged inputs and output directories;
networked provider execution requires a future reviewed runtime profile.
Runtime program names are literals (for example `codex`), not coordinator-local
absolute paths. A reviewed fixture can be installed as `ROOT/bin/codex` in a
private `bin` directory; otherwise the helper uses the fixed system PATH.

## Lifecycle contract

The fixed command is `maco __supervised-ssh-helper ROOT HOST_ID`. It accepts one
frame and emits one frame: eight magic bytes `MACOLC01`, an unsigned big-endian
64-bit JSON length, and exactly that many UTF-8 JSON bytes. Trailing bytes, unknown
fields, invalid scalar types, and over-limit frames are rejected. The global
frame ceiling is 64 MiB; the client further restricts request/reply sizes from
operator limits. Outgoing serialization stops at its cap before expanding the
rest of a value. Typed helper replies avoid a full `serde_json::Value` copy, and
patch appends check the remaining capacity before copying a line. Collection replies account for JSON byte-array expansion and
are revalidated against the policy's artifact/count limits before acceptance.

Operations are `stage`, `launch`, `status`, `wait`, `control`, `collect`, and
`cleanup`. They use the typed `SshTransport` request/receipt structures. Host,
run, assignment, attempt/nonce, staged-input digest, launch spec, output policy,
session, workspace, launch key, PID/PGID/start token bind every operation.
Stage keys name private sessions. The helper serializes requests with a root
lock, persists intent/receipts with fsync+rename, and never replays a submitted
launch. The detached runner retains native process ownership independently of
an SSH connection. Control requests signal its cancellation token; the existing
native backend performs TERM/grace/KILL/wait. Only verified native quiescence
produces a terminal receipt. A vanished runner without such a receipt remains
uncertain, even when its PID is absent.

A lost launch reply is queried, never relaunched. `NotFound` preserves uncertainty.
A lost collection reply reuses the same identity/key/policy and immutable saved
collection receipt. Stage uncertainty remains an operator gate. Cleanup removes
only that session's workspace after terminal collection and explicit coordinator
authorization; receipts/tombstones remain for exact-key reconciliation.

The coordinator journals authenticated intent before effects and commits bounded
collection chunks and their final digest before import. Remote results are
candidate evidence, never an `ExternalAgentRun`. The current CLI coordinator
stages bounded tracked files and prompt/schema inputs, translates declared paths,
and persists the collected candidate, then refuses import/native recapture.
It retains the remote workspace and leaves the local worktree unchanged. Hidden
runtime/credential-like tracked paths are refused. No serialized usage/native
flags can bypass existing claim, containment, accounting or acceptance gates.

## Deterministic checks

On the assigned build lane, with no SSH host or provider:

```sh
lane-check s1 120 'cargo fmt --check'
lane-check s1 1200 'cargo clippy --locked --all-targets -- -D warnings'
lane-check s1 1200 'cargo test --locked --lib external_agent::executor'
lane-check s1 1200 'cargo test --locked --lib supervise::remote_execution'
lane-check s1 1200 'cargo test --locked --test supervised_ssh_lifecycle -- --test-threads=1'
```

The integration test runs the actual helper through a local fake SSH executable.
The simulated remote helper runs in a separate delegated scope, modeling another
host rather than escaping transport cleanup accidentally. Five permanent
`review_` probes cover the independently reproduced trust/deadline defects;
additional tests cover immutable snapshots and serialization/patch bounds.
It covers completion, explicit cleanup, cancellation, lost launch/collection
replies, trust tampering/replacement/permissions, strict host-key arguments,
plan-only refusal, and candidate persistence before the native import gate.

## Live operator gate (not yet qualified)

Use only an already trusted second host and a disposable repository. No live
commands are part of deterministic testing. `MACO_BIN`, `SSH_PLAN`, `SSH_TRUST`,
`COORD_REPO`, `EVIDENCE`, `RUN_ID`, and machine-global binding values below are
reviewed operator inputs. The current candidate-only route cannot pass the full
live acceptance gate; these commands exercise the available dispatch boundary:

```sh
"$MACO_BIN" supervise plan "$SSH_PLAN" --repo "$COORD_REPO" --json > "$EVIDENCE/plan.json"
systemd-run --user --scope --quiet -p Delegate=yes "$MACO_BIN" supervise run "$SSH_PLAN" --repo "$COORD_REPO" --run-id "$RUN_ID" \
  --ssh-trust "$SSH_TRUST" --runtime codex --codex-bin codex \
  --machine-global-config "$MACHINE_GLOBAL_CONFIG" \
  --machine-global-runtime-root-id "$RUNTIME_ROOT_ID" --json > "$EVIDENCE/run.json"
"$MACO_BIN" supervise collect "$RUN_ID" --repo "$COORD_REPO" --json > "$EVIDENCE/collect.json"
```

The fixture must already be installed and emit bounded candidate data without
provider access. Completion currently ends at the native import refusal. For
cancellation, use an operator-authored typed request bound to the live assignment:

```sh
"$MACO_BIN" steer submit "$CANCEL_REQUEST" --repo "$COORD_REPO" --json > "$EVIDENCE/cancel-first.json"
"$MACO_BIN" steer submit "$CANCEL_REQUEST" --repo "$COORD_REPO" --json > "$EVIDENCE/cancel-retry.json"
"$MACO_BIN" steer evidence "$RUN_ID" --repo "$COORD_REPO" --json > "$EVIDENCE/steering.json"
```

Lost-reply qualification currently has exact offline commands only:

```sh
lane-check s1 1200 'cargo test --locked --test supervised_ssh_lifecycle lost_launch_and_collection_replies_reuse_identity_without_relaunch -- --exact'
```

There is no production reply-loss switch. A live fault wrapper, immutable frozen
input recovery and scheduler accounting handoff must be reviewed before live
reply-loss/restart qualification. General `supervise resume` continues to refuse
uncertain assignments; transport reconciliation alone cannot settle scheduling
or accept a candidate. Do not start a replacement run to bypass that refusal.

Full qualification still requires independent native provider usage/events,
containment, exact staged-source/session/start identity, one launch across reply
loss, terminal cancellation custody, durable collection before idempotent import,
trusted local recapture before cleanup, no surviving owned workload, and proof
that unrelated workspaces were untouched. No live qualification is claimed.
