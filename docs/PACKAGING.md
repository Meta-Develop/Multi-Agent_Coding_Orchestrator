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

`maco --version` prints the crate version from `Cargo.toml` through the
existing Clap `version` flag. Example: `maco 0.3.0`. The Nix package
install-check requires that same version string.

That is the current version surface for a globally installed binary. Run
artifacts, ledgers, and a repository-declared minimum or required
orchestrator version are later work on issue 220. This slice does not change
supervise, orchestrate, or runtime adapter behavior.
