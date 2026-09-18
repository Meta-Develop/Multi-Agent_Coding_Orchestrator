# Account manager source in MACO

This directory imports the owned Coding Agent Manager application from commit
`953f37ed77c302f9624854c0fbdf2811e70d9fd0` (source tree
`ce7ee9eda0f29ba9424e478d03a5e56cf8d0d588`). Public source, fixtures, assets,
documentation, and lockfiles are retained. Git metadata, local agent context,
credentials, and build outputs are excluded. The original Gemini OAuth module
is the one source exclusion; its independent replacement and historical notice
are described in [OAUTH_PROVENANCE.md](OAUTH_PROVENANCE.md).

The application retains its [GPL-3.0-or-later license](../LICENSE), names, Tauri
identifier, and existing data-directory identity:
`ProjectDirs::from("dev", "metadevelop", "coding-agent-manager")`. This import
does not migrate or duplicate credentials. Headless `coding-agent-manager`
(`account-manager/core`) is a MACO root workspace member; the repository root
`Cargo.lock` resolves MACO and that crate. The desktop shell
(`coding-agent-manager-desktop` under `src-tauri/`) keeps a separate
`src-tauri/Cargo.lock` and path-depends on `../core` (one source tree, no copy).
`package-lock.json` remains independent of MACO's Rust dependencies. The scoped
native dependency correction and remaining desktop audit warnings are recorded in
[DEPENDENCY_AUDIT.md](DEPENDENCY_AUDIT.md) (desktop lock only; root supply-chain
CI does not waive them globally).

## Native core build

Run these commands from the **MACO repository root** with Node 22 (desktop only)
and the Rust toolchain in `rust-toolchain.toml`. Linux core builds need a C
toolchain, `pkg-config`, and D-Bus development files for the existing Secret
Service backend. GTK and WebKit are required only for desktop builds.

```bash
cargo check --locked -p coding-agent-manager --no-default-features --all-targets
cargo clippy --locked -p coding-agent-manager --no-default-features --all-targets -- -D warnings
cargo test --locked -p coding-agent-manager --no-default-features
```

The resulting library exposes the existing provider, storage, launch, quota,
relay, and router modules without compiling Tauri. There is no headless account
service or MACO invocation adapter in this unit. The proposed manual authority
contract in [MACO_INTEGRATION.md](MACO_INTEGRATION.md) remains future work.

Release packaging verifies headless tarballs with
`cargo package --locked --workspace --no-default-features` at the repository
root (see the root supply-chain workflow).

## Existing desktop build

The desktop shell crate enables the `desktop` feature by default. It includes
Tauri commands, runtime, build helper, and the `coding-agent-manager` binary.
Packaged Tauri builds also enable `custom-protocol`, which retains the desktop
feature. Command-module unit tests live in the shell crate; headless integration
tests and goldens live under `core/`.

From `account-manager/`:

```bash
npm ci
npm run typecheck
npm run lint
npm run format:check
npm test
npm run build
```

From the MACO repository root (desktop uses the standalone `src-tauri` manifest
and lockfile):

```bash
cargo test --locked -p coding-agent-manager --no-default-features
cargo fmt --locked --manifest-path account-manager/src-tauri/Cargo.toml --all -- --check
cargo check --locked --manifest-path account-manager/src-tauri/Cargo.toml --all-targets
cargo clippy --locked --manifest-path account-manager/src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --locked --manifest-path account-manager/src-tauri/Cargo.toml -p coding-agent-manager-desktop
```

From `account-manager/`:

```bash
npm run tauri:dev
```

Use the platform prerequisites in [DEVELOPMENT.md](DEVELOPMENT.md). The imported
Nix development shell supplies desktop libraries, but its packaged application
output wraps a prebuilt, hash-addressed binary; it does not build this source.
That old hash is not proof of an integrated MACO release. Source-built packaging
and installation are separate work.

## Integration boundary

The first shared account authority will run on Linux/WSL. A future desktop
client must use that same authority rather than copy credentials between
Windows and Linux. No MACO account selection, login dispatch, model discovery,
evaluation evidence, inference, or quota-reset scheduler is enabled by this
source import. In particular, it adds no automatic account switch or fallback.
The application retains its existing desktop functions and their documented
limitations; its inherited relay/router settings are not MACO execution policy.

The root [account-manager CI workflow](../../.github/workflows/account-manager.yml)
is active. Workflows under this imported directory remain source history only.
