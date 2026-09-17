# Architecture decision records

An ADR records a decision that was expensive to make and would be expensive to
re-litigate: what was decided, why, what it costs, and what was rejected.

## When to write one

Write an ADR when a choice constrains future work — a framework, a storage
model, a security posture, a licence. Do not write one for a choice a future
contributor could reverse in an afternoon.

## Process

1. Copy [`0000-template.md`](0000-template.md) to `NNNN-short-title.md` with the
   next free number.
2. Open it as `Proposed` in a pull request.
3. On merge, set it to `Accepted`.
4. A superseded ADR is never edited or deleted. Set its status to
   `Superseded by NNNN` and write the new one. The record of what was believed,
   and when, is the point.

## Index

| #                                                                  | Title                                              | Status   |
| ------------------------------------------------------------------ | -------------------------------------------------- | -------- |
| [0001](0001-tauri-v2-over-electron.md)                             | Tauri v2 over Electron                             | Accepted |
| [0002](0002-provider-adapter-plugin-architecture.md)               | Provider adapter architecture, compiled in         | Accepted |
| [0003](0003-os-keychain-first-credential-storage.md)               | OS keychain first, encrypted file as fallback      | Accepted |
| [0004](0004-local-relay-protocol-translation.md)                   | Local relay with protocol translation              | Accepted |
| [0005](0005-gpl-3-0-license.md)                                    | GPL-3.0-or-later                                   | Accepted |
| [0006](0006-clean-room-independent-implementation.md)              | Clean-room independent implementation              | Accepted |
| [0007](0007-reading-other-implementations.md)                      | Reading other implementations                      | Accepted |
| [0008](0008-vendor-written-auth-json-for-stored-codex-accounts.md) | Vendor-written auth.json for stored Codex accounts | Proposed |
| [0009](0009-launch-environment-account-selection.md)               | Launch-environment account selection               | Proposed |
