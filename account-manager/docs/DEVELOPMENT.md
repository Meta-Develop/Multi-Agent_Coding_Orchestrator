# Development

## 1. Prerequisites

| Platform | Requirements                                                                                            |
| -------- | ------------------------------------------------------------------------------------------------------- |
| All      | Node.js 22 (`.nvmrc`), Rust 1.94.1 (`rust-toolchain.toml`)                                              |
| Linux    | `webkit2gtk-4.1`, `gtk3`, `libsoup-3.0`, `librsvg`, `libsecret`, `openssl`, `pkg-config`, a C toolchain |
| macOS    | Xcode Command Line Tools                                                                                |
| Windows  | Visual Studio Build Tools with the C++ workload; WebView2 runtime (present on Windows 11)               |

### NixOS and Nix users

Most NixOS hosts do not provide `webkit2gtk-4.1` system-wide, so a bare
`cargo build` fails at the `pkg-config` step. Use the dev shell:

```bash
nix develop
npm install
npm run tauri:dev
```

The shell pins Node 22 and a Rust toolchain, exports `PKG_CONFIG_PATH` and
`LD_LIBRARY_PATH` for the WebKit stack, and sets
`WEBKIT_DISABLE_DMABUF_RENDERER=1` — without which `tauri dev` opens a blank
window on many Nix-provided GPU stacks.

`flake.nix` must be **tracked by git** for `nix develop` to see it. A brand-new
file that has never been `git add`ed produces
`error: Path 'flake.nix' … is not tracked by Git`.

### Installing on a Nix host

The inherited flake package is a wrapper around a previously built binary with
a configured hash. It does not build this integrated source, and intentionally
fails if that binary is absent from the Nix store. Its existing hash is not a
release of MACO's account manager. A source-built MACO installation package is
separate pending work; use the local source build in
[`MACO_SOURCE.md`](MACO_SOURCE.md) for development.

Official GitHub release installers are not published yet (`FR-10` / M7). The
Linux flake package wraps the release binary from the documented Tauri build
and installs a desktop entry:

```bash
nix develop --command bash -lc 'npm ci && npm run tauri:build'
nix hash file --sri "$CARGO_TARGET_DIR/release/coding-agent-manager"
nix-store --add-fixed sha256 \
  "$CARGO_TARGET_DIR/release/coding-agent-manager"
```

Put the SRI hash in `unwrappedSha256` in `flake.nix`, then:

```bash
nix build .#coding-agent-manager
nix profile install .#coding-agent-manager
```

`packages.default` and `packages.coding-agent-manager` are the same output.
Home Manager can take that output from this flake. The wrapper sets
`WEBKIT_DISABLE_DMABUF_RENDERER=1`. If `CARGO_TARGET_DIR` is unset, the binary
is `src-tauri/target/release/coding-agent-manager`.

If the root filesystem is small, point `CARGO_TARGET_DIR`, `CARGO_HOME`, and
the npm cache at a larger volume before `tauri:build`. Do not put those
directories on `/`.

On NixOS, `npm run tauri:build` with bundle target `all` may fail while
producing the AppImage (`xdg-open` is not at `/usr/bin/xdg-open`). The
release binary, `.deb`, and `.rpm` are already written before that step.
The flake package wraps the binary, not the AppImage.

## 2. Commands

| Command                           | What it does                                               |
| --------------------------------- | ---------------------------------------------------------- |
| `npm run dev`                     | Vite dev server only, no native window. Fast UI iteration. |
| `npm run tauri:dev`               | Full application with hot reload.                          |
| `npm run tauri:build`             | Production bundles for the current platform.               |
| `npm run typecheck`               | `tsc --noEmit` over `src/` and over `vite.config.ts`.      |
| `npm run lint` / `lint:fix`       | ESLint.                                                    |
| `npm run format` / `format:check` | Prettier.                                                  |
| `npm run rust:check`              | `cargo check --all-targets`.                               |
| `npm run rust:test`               | `cargo test`.                                              |
| `npm run rust:clippy`             | `cargo clippy --all-targets -- -D warnings`.               |
| `npm run rust:fmt`                | `cargo fmt --all`.                                         |

Run the Rust commands inside `nix develop` on NixOS.

The native core also builds without the desktop dependencies. See
[`MACO_SOURCE.md`](MACO_SOURCE.md) for locked headless and desktop commands and
the distinction between a library build and a running account service.

## 3. Project layout

```text
src/                     React front end — presentation only
  lib/tauri.ts           The one typed boundary to Rust
  types/index.ts         Mirrors src-tauri/src/model.rs
src-tauri/src/
  commands.rs            Tauri IPC surface — the only file that may use tauri::
  providers/             One module per managed tool
  storage/               Credential persistence
  relay/                 Protocol adaptation
  router/                Rule evaluation
  model.rs  error.rs     Domain types and error taxonomy
docs/                    Specification, architecture, research, ADRs
```

The layering rules and why they exist are in
[`ARCHITECTURE.md`](ARCHITECTURE.md) §3.

## 4. Coding conventions

### TypeScript

- Strict mode, including `noUncheckedIndexedAccess` and
  `exactOptionalPropertyTypes`. They are on deliberately; do not relax them for
  one call site.
- No `invoke` outside `src/lib/tauri.ts`.
- `console.log` is an ESLint error. The Rust side owns logging, because the Rust
  side is where redaction is enforced.
- Use the `@/` alias, not deep relative paths.

### Rust

- `rustfmt` defaults with `max_width = 100`.
- `clippy` with `-D warnings` — CI enforces it.
- An error variant carries what failed and, where safe, which path. It never
  carries a value read from a credential file.
- `todo!()` and `unimplemented!()` do not ship. Unfinished behaviour returns
  `Error::NotImplemented`, so it surfaces as a clean message instead of a panic.

### Both

- Change `src/types/index.ts` and `src-tauri/src/model.rs` in the same commit.
  They are one contract in two languages.

## 5. Adding a provider adapter

1. **Research first.** Write `docs/research/<provider>.md` with confidence
   markers before writing code. See [`research/README.md`](research/README.md).
2. Create `src-tauri/src/providers/<provider>.rs` implementing
   `ProviderAdapter`. Put every path claim in a doc comment with its marker.
3. Register it in `providers::registry()`.
4. Start with `detect()`, `config_paths()`, and `list_accounts()`. Leave
   `add_account()`, `activate_account()`, and `delete_account()` returning
   `Error::NotImplemented` until the switching mechanics are
   `[verified-local]` or `[verified-docs]`. Advertise a capability only
   when the matching method is implemented (`NFR-8`).
5. Add fixtures under `src-tauri/tests/fixtures/<provider>/` and wire up the
   contract tests — see [`TESTING.md`](TESTING.md).
6. Set `maturity` honestly: `planned` until it reads, `experimental` until it
   switches reliably, `supported` only after the contract tests pass on all
   three platforms. Maturity is not the UI gate for add, switch, or
   delete; `descriptor().capabilities` is.
7. Update [`PROVIDER_MATRIX.md`](PROVIDER_MATRIX.md) and the README table.

## 6. Debugging

| Symptom                                           | Cause and fix                                                                                          |
| ------------------------------------------------- | ------------------------------------------------------------------------------------------------------ |
| Blank window under `tauri dev` on Linux           | WebKit DMA-BUF renderer. Set `WEBKIT_DISABLE_DMABUF_RENDERER=1`; the dev shell already does.           |
| `pkg-config` cannot find `webkit2gtk-4.1`         | Not in `nix develop`, or the distro package is missing.                                                |
| `error: Path 'flake.nix' … is not tracked by Git` | `git add flake.nix`.                                                                                   |
| Front end builds, native window does not open     | Check the Rust log in the terminal running `tauri:dev`; a panic in `run()` closes the window silently. |
| `invoke` rejects with "command not found"         | The command is missing from `generate_handler!` in `lib.rs`.                                           |
| Rust changes not picked up                        | The Tauri CLI watches `src-tauri/`; Vite deliberately ignores it. Restart `tauri:dev`.                 |

## 7. Working with real credentials

Don't. Development and tests use fixtures, never a live account — see
[`TESTING.md`](TESTING.md) §4. If you must reproduce something against a real
installation, do it read-only, and never paste a file's contents into an issue,
a commit, or a test.
