# Packaging and global install

`maco` is an ordinary command-line program. The supported invocation surface
is a machine-global `maco` on `PATH`, not a per-repository `cargo run` wrapper
around a pinned checkout.

This document covers the current install and version contract. It does not
add commands. The CLI remains the existing `maco` binary from `src/bin/maco.rs`.

## Nix

The repository flake exports `packages.<system>.maco` (also `packages.default`)
and matching `apps` so `nix profile install` and `nix run` work. The package
builds the release `maco` binary with the Rust toolchain selected by
`rust-toolchain.toml`.

On Linux the same locked root-workspace build also includes the existing
`coding-agent-manager` binaries `account-authority` and `cam-grok-setup`.
The output contains all three binaries under `bin/`, with
`source-manifest.json` beside that directory. It also installs identical
manifest bytes at `share/maco/source-manifest.json`, the protected main
declaration at `share/maco/main-helper.json`, and a setup declaration at
`share/maco/grok-setup-helper.json`.
Darwin retains the `maco`-only output. The app and default package still select
`maco`; packaging does not start an authority or provider.

The deterministic manifest records `schema_version: 1`, `source_revision`,
`source_state`, and sorted relative source entries. Regular files carry their
SHA-256, size, and executable bit; symbolic links carry a SHA-256 of their link
target bytes and are not followed. It binds the immutable package fileset,
including both crates, the root lockfile, flake definition/lockfile, and Rust
toolchain file. It excludes the desktop source and private runtime data; it is
not a manifest of the entire repository. It contains no build timestamps or
machine-local source paths. Dirty and unknown inputs remain dirty and unknown.

The Linux build exports `MACO_SOURCE_MANIFEST_SHA256` from those generated
manifest bytes before Cargo compilation. This is a build-phase input read,
with no import-from-derivation. After stripping and other binary fixups, the
package writes a deterministic declaration with exactly four fields:

```json
{
  "schema": "maco-source-bound-main-helper-v1",
  "binary_sha256": "<SHA-256 of final bin/maco>",
  "source_manifest_sha256": "<SHA-256 of installed manifest bytes>",
  "main_entry_sha256": "<SHA-256 of immutable src/bin/maco.rs>"
}
```

The setup declaration has schema `maco-source-bound-grok-setup-helper-v1`
and exactly `binary_sha256`, `source_manifest_sha256`, and `setup_entry_sha256`
in addition to `schema`. It binds the final setup ELF, the same source manifest,
and immutable `account-manager/core/src/bin/grok_setup.rs`. Packaging checks
its metadata-only `--help` route without preparing an account or starting
vendor login.

The main and setup binaries are regular native ELFs. Both manifest copies and
the declarations are regular, bounded files installed with mode
0444. The Linux install check verifies these hashes, exact declaration fields,
ELF header, CLI version/revision/state, helper `--help`, and identical manifest
copies. Store finalization supplies root ownership after the build user exits;
installCheck does not claim to have passed protected root-owned runtime capture
inside the build sandbox. It performs no login or listener startup and does
not establish runtime containment.

Linux additionally exports `packages.<system>.runtime-test-helpers`. Its five
links resolve to genuine locked Nix store executables: coreutils `env`, `sleep`
and `stat`, Bash `sh`, and util-linux `findmnt`. This output supplies existing
runtime test prerequisites without replacing the main binary or changing the
default package/app. Darwin receives neither this output nor the Linux main
declaration and compile binding.

### Source-bound Linux CI

Rust CI calls the reusable Nix package workflow once. The producer evaluates
the Linux and Darwin package derivations and builds only the Linux package and
helper output. Evaluation and build use both `--no-update-lock-file` and
`--no-write-lock-file`, sandboxing, one build job and one core. The lockfile hash
must remain unchanged. Only checksum-verified official Nix 2.35.2 is installed,
and only on ephemeral GitHub-hosted Linux runners; the shared installer passes
an allowlisted environment without credential exports to curl and the official
installer. The package workflow also supports manual diagnostics but has no
separate automatic PR/push build.

The producer exports the complete public runtime closure with standard
`nix-store --export` and uploads only that payload and its public JSON receipt.
Independent producer outputs bind the artifact ID, receipt/payload hashes,
selected checkout revision, lockfile, exact store roots, installed manifest,
final main ELF and entry source. The producer also validates the setup
declaration and exposes the final setup ELF hash as `grok_setup_sha256`.
The existing closure receipt schema and consumer checks are preserved; the
payload covers the setup binary and its declaration in the same package root.
The three library shards and integration job
download that exact artifact in the same run. They verify hashes before parsing
the receipt or importing into a real Nix store, retain normal signature/trust
policy, and check protected ancestry, final bytes and checkout source entries.
No consumer rebuilds the Nix source package.

Before its first Cargo compilation, each consumer sets the same
`MACO_SOURCE_MANIFEST_SHA256` and the existing
`MACO_CURSOR_MAIN_HELPER_FOR_TEST`, `MACO_CURSOR_MAIN_HELPER_SHA256_FOR_TEST`
and `MACO_CURSOR_MAIN_HELPER_SOURCE_SHA256_FOR_TEST` qualification inputs from
that verified package. The genuine helper output precedes other PATH entries.
Package and controller use the exact PR head (or push SHA), not different
synthetic-merge and head sources. Existing delegated user-manager, namespace,
cgroup and test partition gates still run; missing producer/import/binding
fails the required aggregate rather than skipping tests. No credentials,
private homes, mutable caches or deployment records enter the artifact.

This CI package is a candidate for that source revision. It does not establish
accepted default-branch installation, fresh-shell invocation, persistent CAM
authority or provider/runtime acceptance. The deployment gates below still
apply.

From a checkout of this repository:

```bash
nix profile install path:$PWD#maco
maco --version
```

From GitHub, after the revision you want is on the default branch or another
ref:

```bash
nix profile install github:Meta-Develop/Multi-Agent_Coding_Orchestrator#maco
```

One-shot execution without a profile install:

```bash
nix run path:$PWD -- --version
```

A NixOS or Home Manager configuration can take the same package from this
flake's `packages` output or from the `overlays.default` attribute, which
exposes `maco`.

Updating the installed binary is a machine-level operation: upgrade the
profile, or bump the flake input that points at this repository and rebuild
the host or Home Manager generation. That single update applies to every
working directory. Repositories no longer carry their own orchestrator pin
for launch.

The flake still exports the development shell used for CI-parity Cargo
gates. That shell is not the install path.

## Non-Nix hosts

From a checkout, install the existing `maco` binary into Cargo's binary
directory:

```bash
cargo install --locked --path . --bin maco
maco --version
```

Re-run that command to update. A crates.io publication is not part of this
slice; when one exists, `cargo install --locked maco` (or the published crate
name) is the same global-binary contract.

## Linux CAM authority endpoint

The standard Linux client endpoint is `maco/account-authority.sock` beneath
`XDG_RUNTIME_DIR` when that directory is absolute, non-symlink, owned by the
effective user, and has no group/world permissions. Otherwise the client uses
`/run/user/<effective-uid>/maco/account-authority.sock`. The connection still
checks socket ancestry and the authority enforces same-UID peers. Explicit
`--cam-authority-socket` and `MACO_CAM_AUTHORITY_SOCKET` overrides are preserved.
This default does not enable authority transport on Windows.

The headless authority needs its own long-lived process under the same Linux
user as MACO. For a systemd user installation, the minimal service settings are:

```ini
[Service]
ExecStart=<accepted-package>/bin/account-authority --socket-path %t/maco/account-authority.sock
RuntimeDirectory=maco
RuntimeDirectoryMode=0700
UMask=0077
Restart=on-failure

[Install]
WantedBy=default.target
```

Replace `<accepted-package>` with the absolute immutable package path containing
the accepted `maco` and `account-authority` binaries and their source binding.
The user's normal `XDG_RUNTIME_DIR` must match the user manager's `%t` directory.
Keep the service stopped until that package is accepted; inspect any existing
authority before starting it, because the server replaces an existing socket.
Enable the unit for normal user-manager sessions. Persistence beyond the last
login depends on the host's approved user-manager lifetime; do not enable
lingering or start a manager as an installation workaround.

Run the service as the operator user, never as root. Retain the existing CAM
data directory: `$XDG_DATA_HOME/coding-agent-manager`, or
`$HOME/.local/share/coding-agent-manager` when `XDG_DATA_HOME` is unset.
The service and MACO must share that data-directory identity. Installing the
service does not complete owner OAuth or select a pending account.

The package output supplies the Linux binaries and source manifest, not their
host deployment. The Windows GUI additionally requires its existing private
`authority-connection.json` record and the fixed root-protected WSL launcher
`/usr/local/libexec/maco-account-authority` resolving to the accepted package's
`bin/account-authority`. That record binds the distribution, non-root user/UID,
socket, helper path and ELF SHA-256, source-manifest SHA-256, and authority ID.
Use hashes of the final installed helper and manifest, not intermediate build
artifacts. The relay verifies those bindings and protected package ancestry;
a user-writable Cargo install alone does not meet that deployment contract.

Installing that launcher, connection record, and same-user persistent service
is a separate reviewed deployment step. This flake does not write them, enable
lingering, change user-manager lifetime, install the Windows GUI, or select an
account. Package checks do not establish accepted-default-branch status,
fresh-shell invocation, GUI-to-WSL principal continuity, owner login, or actual
delegated Linux runtime containment; each still needs its own acceptance proof.

## Version recording

`maco --version` and `maco -V` print this text, plus a trailing newline:

```
maco {package_version}
package_version={package_version}
source_revision={40-lowercase-hex-or-empty}
source_state={clean|dirty|unknown}
```

`package_version` is the crate version. `source_revision` is empty, or 40
lowercase hexadecimal digits. `source_state` is `clean`, `dirty`, or
`unknown`.

A Cargo install from a git checkout records that identity at compile time by
probing git in `CARGO_MANIFEST_DIR`.

The Nix package fileset does not include `.git`, so that probe cannot see the
flake checkout. It does include `build.rs`, which applies the packager
environment before the values are compiled in. The derivation passes
`MACO_SOURCE_REVISION` and `MACO_SOURCE_STATE`. When `self.rev` is a non-null
string, the state is `clean` and the revision is `self.rev`. Otherwise, when
`self.dirtyRev` is a non-null string, the state is `dirty` and the revision is
the 40-digit commit inside `self.dirtyRev`, without Nix's `-dirty` suffix.
Otherwise the state is `unknown` and the revision is empty. The install check
requires `maco --version` to contain the package version and the exact
`source_revision` and `source_state` lines from those inputs.

Source archives and `cargo package` have no git metadata. Set
`MACO_SOURCE_REVISION` and `MACO_SOURCE_STATE` together for those builds. If
that pair is absent, the identity is unknown.

`unknown` and `dirty` are explicit. A revision is recorded only for `clean` or
`dirty` when it is 40 hexadecimal digits. A dirty value may also arrive as
that commit plus a `-dirty` suffix; the suffix is removed and the state stays
`dirty`. Any other combination is `unknown` with an empty revision.

The build script asks Cargo to rerun it when the package inputs (`src`, tests,
benches, assets, schemas, docs, scripts, the manifest, the lockfile, the
flake, and this build script) change, and when the git HEAD, index, or current
branch ref changes. Git resolves those paths, including when `.git` is a
linked-worktree gitfile. An incremental rebuild therefore re-probes a dirty
worktree instead of reusing a clean stamp from the previous build script run.

The running binary does not read the repository it orchestrates. The printed
identity is the one recorded at compile time.

Enforcement of a repository minimum or required orchestrator version stays
deferred and is not part of this identity surface.
