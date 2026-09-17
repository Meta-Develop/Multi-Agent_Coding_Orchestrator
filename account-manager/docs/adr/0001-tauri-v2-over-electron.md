# 0001. Tauri v2 over Electron

- **Status**: Accepted
- **Date**: 2026-08-18

## Context

The application needs a cross-platform desktop UI, and it needs privileged
native access: OS credential services, arbitrary file paths under `$HOME`,
process detection, and a long-lived local HTTP listener.

Two properties dominate the choice. First, most of this application's real work
is native, not visual — the UI is a thin surface over filesystem and keychain
operations. Second, it handles credentials, so a smaller trusted computing base
is worth real effort.

## Decision

Build on Tauri v2, with a Rust backend and a React + TypeScript front end
rendered in the platform webview.

## Consequences

- The privileged half of the application is Rust: memory-safe, with a type
  system that can express "this value is a secret and must not be serialised".
  `Secret` implementing neither `Debug` nor `Serialize` is a compile-time
  guarantee, not a code-review convention.
- Bundles are single-digit megabytes rather than a hundred, because the webview
  is the platform's.
- The IPC boundary is explicit: only commands listed in `generate_handler!`
  exist. That gives a small, auditable surface between untrusted UI and
  privileged core — the boundary `SECURITY_MODEL.md` §2 depends on.
- **Cost**: rendering differs across WebKitGTK, WKWebView, and WebView2, so
  cross-platform UI testing is genuinely required.
- **Cost**: Linux builds need `webkit2gtk-4.1` present at build time, which is
  awkward on NixOS and is why this repository ships a `flake.nix`.
- **Cost**: contributors need both a Rust and a Node toolchain.

## Alternatives considered

- **Electron.** The largest ecosystem and the most uniform rendering. Rejected
  because the privileged code would be JavaScript with full Node access, the
  bundle is an order of magnitude larger, and keychain access needs native
  modules anyway — paying Electron's costs without avoiding Rust's.
- **Wails (Go).** Similar architecture with easier cross-compilation. Rejected
  for a smaller desktop ecosystem and weaker library support for the specific
  credential-service and protocol-translation work this project needs.
- **A CLI with no GUI.** Cheapest to build, and genuinely appealing. Rejected
  because the quota dashboard and one-click switching — the two things that make
  this better than a shell script — are inherently visual. A headless mode
  remains planned for the Docker relay, which is why nothing below `commands.rs`
  may depend on Tauri.
