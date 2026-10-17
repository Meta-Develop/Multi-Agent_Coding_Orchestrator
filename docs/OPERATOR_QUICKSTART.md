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
Write this object to `$base/machine-global.json`.
```bash
chmod 0600 "$base/machine-global.json"
```
JSON does not expand variables, so write the literal expanded value of `$XDG_RUNTIME_DIR` (for example `/run/user/1000`) in place of `/run/user/UID`. `--repo .` is
the git working directory passed as `--working-directory`.

## Build

From the repository root:
```bash
nix develop --command cargo build --locked --release --bin maco
```
The binary is `target/release/maco`, or `$CARGO_TARGET_DIR/release/maco` when `CARGO_TARGET_DIR` is set.

## Codex runtime

Prerequisites:

- Logical `codex` resolves to the first existing path of
  `/run/current-system/sw/bin/codex`, `/usr/bin/codex`, or `/bin/codex`. The
  canonical file must be a root-owned, executable, non-symlink regular file,
  not group- or world-writable, with non-symlink ancestors. Run
  `--version` on whichever of those three paths exists.
- Pass `--codex-bin codex`. An absolute `--codex-bin` is
  accepted only when it canonicalizes to that same trusted file.
- Catalog preflight runs `codex debug models` once, with a 30 second limit,
  and requires a validated `auth.json`.
- Unset `MACO_CAM_AUTHORITY_SOCKET` and `CODEX_HOME`. With the
  socket unset, a local CAM registry selection is used when one exists.
  Otherwise Codex reads `$CODEX_HOME/auth.json`, or `$HOME/.codex/auth.json`
  when `CODEX_HOME` is unset. `auth.json` must be a non-symlink regular file.
- Unverified: this repository does not document a vendor `codex login`
  command. Login stays owner-operated.
Set: `repo=/path/to/target-repo`, `base=$XDG_RUNTIME_DIR/maco-e2e`, `run_id=example-1`, `maco=/path/to/target/release/maco`. `goal.md` is a plain-text goal file the operator writes.
Run:

```bash
unset MACO_CAM_AUTHORITY_SOCKET CODEX_HOME
timeout --signal=TERM 3600 systemd-run --user --scope --quiet -p Delegate=yes \
  --working-directory="$repo" -- \
  "$maco" supervise run --runtime codex --repo . --run-id "$run_id" \
    --from-goal "$base/goal.md" --codex-bin codex \
    --machine-global-config "$base/machine-global.json" \
    --machine-global-runtime-root-id runtime --json
"$maco" supervise collect "$run_id" --repo . --json
```
`supervise run` prints JSON and exits 0 only when `follow_up_cascade_success`
is true. Otherwise it exits with `supervise run failed`. `collect` reads the
durable run and exits with `supervise run failed` when that report is not
success. `collect` is outside the scope.

The durable report is
`<repo>/.maco/o2/runs/<run-id>/reports/supervisor-final.json`.

## Grok runtime

Prerequisites:

- `MACO_GROK_BIN` is an absolute path to a non-symlink regular file. Ambient
  `PATH` and relative paths are refused. The Nix default
  `/run/current-system/sw/bin/grok` may be a symlink and is canonicalized. An
  explicit override may not itself be a symlink. Set
  `MACO_GROK_BIN=$(readlink -f "$(command -v grok)")`, then
  `test -f "$MACO_GROK_BIN" && test ! -L "$MACO_GROK_BIN"`.
  `$HOME/.grok/bin/grok` is an example install location. Use `readlink -f` on
  that path when `grok` is not on `PATH`.
- Bubblewrap is installed. Run `bwrap --version`. Headless
  launch always passes `--sandbox strict`. MACO does not ship `bwrap`.
  Install it with `sudo apt-get install -y bubblewrap`.
  Unverified: no captured failure text for a missing `bwrap`.
- A complete CAM `grok-cli` account must be selected. Grok has no local-auth
  fallback. `~/.grok` and `XAI_API_KEY` are not the launch path. With
  `MACO_GROK_BIN` set and no selection, catalog discovery fails closed:
  `live Grok catalog requires a complete Coding Agent Manager selected grok-cli account`.
- CAM data is `$XDG_DATA_HOME/coding-agent-manager`, or
  `$HOME/.local/share/coding-agent-manager` when `XDG_DATA_HOME` is unset.
  The managed home is `{data}/accounts/grok-cli/<id>`. Launch sets
  `GROK_HOME` there and removes `GROK_AUTH_PATH` and `XAI_API_KEY`.
- Leave `MACO_CAM_AUTHORITY_SOCKET` unset unless that authority is the
  selection source. A configured socket with no carried Grok binding is a
  refusal.
- Do not pass `--codex-bin` or `--runtime-bin` on this path. The Grok program
  comes from `MACO_GROK_BIN`. Held-out evaluation, where `--runtime-bin` must
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
Set: `repo=/path/to/target-repo`, `base=$XDG_RUNTIME_DIR/maco-e2e`, `run_id=example-1`, `maco=/path/to/target/release/maco`. `goal.md` is a plain-text goal file the operator writes.
Run:
```bash
timeout --signal=TERM 3600 systemd-run --user --scope --quiet -p Delegate=yes \
  --working-directory="$repo" -- \
  env MACO_GROK_BIN="$MACO_GROK_BIN" \
  "$maco" supervise run --runtime grok --repo . --run-id "$run_id" \
    --from-goal "$base/goal.md" \
    --machine-global-config "$base/machine-global.json" \
    --machine-global-runtime-root-id runtime --json
"$maco" supervise collect "$run_id" --repo . --json
```
The report path is the same
`<repo>/.maco/o2/runs/<run-id>/reports/supervisor-final.json` path as Codex.

## Troubleshooting

| Symptom | Action |
| --- | --- |
| `current cgroup <path> is not inside a delegated systemd user manager` | The process is outside `user@<uid>.service`. Re-run under `systemd-run --user --scope --quiet -p Delegate=yes` with `XDG_RUNTIME_DIR` and `DBUS_SESSION_BUS_ADDRESS` set as above. The user session must already be up. |
| Sandboxed or hosted runner with no systemd user manager. Tests print `SKIP <test>: current cgroup <path> is not inside a delegated systemd user manager`. | Same admission rule. GitHub-hosted runners do not provide that manager. The delegated-scope CI script is only for those ephemeral runners. |
| `explicit Grok executable may not be a symlink` | `MACO_GROK_BIN` is a symlink. Set it with `readlink -f` to the real file, then `test -f` and `test ! -L`. |
| `live Grok catalog observation failed closed` caused by `Grok runtime model catalog requires owner authentication` | The catalog began with `You are not authenticated.` The owner redoes device login: `prepare`, the printed `grok --no-auto-update login --device-auth`, `status`, then `complete`. If that id's managed home already exists, `prepare` refuses it. No replacement command is documented. |
