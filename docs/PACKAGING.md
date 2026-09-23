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
flake checkout. The derivation passes `MACO_SOURCE_REVISION` and
`MACO_SOURCE_STATE` instead. When `self.rev` is a non-null string, the state
is `clean` and the revision is `self.rev`. Otherwise, when `self.dirtyRev` is
a non-null string, the state is `dirty` and the revision is `self.dirtyRev`.
Otherwise the state is `unknown` and the revision is empty. The install check
still requires the package version in `maco --version`, and it requires
`source_state=` to appear.

Source archives and `cargo package` have no git metadata. Set
`MACO_SOURCE_REVISION` and `MACO_SOURCE_STATE` together for those builds. If
that pair is absent, the identity is unknown.

`unknown` and `dirty` are explicit. A revision is recorded only for `clean` or
`dirty` when it is 40 hexadecimal digits. Any other combination is `unknown`
with an empty revision.

The running binary does not read the repository it orchestrates. The printed
identity is the one recorded at compile time.

Enforcement of a repository minimum or required orchestrator version stays
deferred and is not part of this identity surface.
