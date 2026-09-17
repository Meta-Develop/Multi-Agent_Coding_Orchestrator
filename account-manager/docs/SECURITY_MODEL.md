# Security model

This application exists to hold, move, and write other people's credentials. A
bug here does not produce a broken feature; it produces a leaked account. This
document is therefore a design constraint, not a formality.

## 1. Assets

| Asset                                          | Why it matters                                                                                        |
| ---------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| OAuth access and refresh tokens                | Direct account access. A refresh token is long-lived and often not revocable per-device.              |
| API keys                                       | Direct account access, usually billable.                                                              |
| Account identities (emails, org ids, user ids) | Personally identifying; useful for targeted phishing.                                                 |
| Non-secret account-selection metadata          | Integrity matters: changing the selected id can launch a tool under the wrong account.                |
| The user's existing tool configs               | Destroying one locks the user out of a working tool.                                                  |
| Vendor-written stored account homes            | Codex and Grok homes contain plaintext vendor credentials under the application data directory.       |
| Child environments containing injected secrets | The selected tool needs the secret, and same-user processes may be able to inspect its environment.   |
| Backups of managed tool configs                | May contain the same secrets as the originals. Grok stored homes are deliberately not backed up here. |

## 2. Trust boundaries

```text
[ Vendor APIs ]  <--network-->  [ Rust core ]  <--IPC-->  [ Webview ]
                                     |
                                     +--filesystem--> [ Managed tool configs ]
                                     +--filesystem--> [ Stored account directories ]
                                     +--platform-->   [ OS credential service ]
                                     +--spawn/env-->  [ Managed tool child ]
```

- **Webview is untrusted with secrets.** It renders masked identities and opaque
  account ids. A cross-site-scripting bug in the UI must not be able to read a
  token, because the token was never sent there.
- **Adapters are trusted code, compiled in.** This is exactly why v1 has no
  runtime plugin system: a third-party adapter would run with access to every
  credential the application holds.
- **Core owns child creation.** Adapters declare a fixed command, absolute
  working directory, and exact child environment changes. The webview cannot
  supply an arbitrary executable, path, argument list, or environment map.
- **The managed child is trusted with its own credential.** A secret is resolved
  from `CredentialStore` only at spawn and applied only to that child's
  environment. Some operating systems let another process running as the same
  user inspect a child's environment or memory. That residual risk cannot be
  removed by this application.
- **The relay is a network boundary inside the machine.** Anything listening on
  a socket is reachable by every process on the host, and by the network if
  bound wrongly.

## 3. Threats and controls

| #   | Threat                                                           | Control                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| --- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| T1  | Local malware reads secrets from disk                            | Secrets accepted for managed storage go to the OS credential service or encrypted-file fallback; those backends have no plaintext mode. Vendor-written Codex, Grok, and Gemini OAuth homes are narrow plaintext exceptions under the application data directory, protected only by filesystem permissions. See [ADR 0008](adr/0008-vendor-written-auth-json-for-stored-codex-accounts.md) and [ADR 0009](adr/0009-launch-environment-account-selection.md).            |
| T2  | Secrets leak through logs, crash reports, or diagnostics         | `Secret` implements neither `Debug` nor `Serialize` and zeroes on drop. Error variants carry kinds and paths, never values. Diagnostic exports are built from an allowlist of fields, not by serialising state.                                                                                                                                                                                                                                                        |
| T3  | Secrets leak through the UI                                      | Secrets never cross the IPC boundary. Identities are masked before they leave Rust.                                                                                                                                                                                                                                                                                                                                                                                    |
| T4  | Relay exposed to the network                                     | Binds to `127.0.0.1` by default. A non-loopback binding is rejected unless an auth token is set — enforced in `RelayConfig::validate`, with tests. The UI states the risk in plain language before the opt-in.                                                                                                                                                                                                                                                         |
| T5  | Malicious or compromised dependency                              | Lockfiles committed; `cargo audit` and `npm audit` in CI; dependency additions reviewed; the dependency set is kept deliberately small.                                                                                                                                                                                                                                                                                                                                |
| T6  | Backup files leak secrets                                        | Backups live in the application data directory with `0600` permissions on Unix, are covered by retention pruning, and are never included in a diagnostic bundle. A backup taken before a Codex config switch includes live `auth.json` and is credential material. Grok homes are never copied into the backup store under the launch-environment design.                                                                                                              |
| T7  | A switch corrupts a working config                               | Every manager mutation of a managed-tool file takes a timestamped backup, writes atomically, verifies, and restores on failure (`NFR-4`). Pure account-metadata selection and child-environment injection replace no managed-tool file and therefore require no config backup.                                                                                                                                                                                         |
| T8  | Token refresh races produce a revoked token                      | Per-account async lock; a refresh failure marks the account as needing re-auth rather than retrying blindly.                                                                                                                                                                                                                                                                                                                                                           |
| T9  | A user is tricked into importing someone else's credential       | Import always shows exactly which file was read and which identity was found, before anything is stored.                                                                                                                                                                                                                                                                                                                                                               |
| T10 | Telemetry or update checks leak usage patterns                   | No telemetry, no analytics, no automatic update check that transmits identity (`NFR-7`).                                                                                                                                                                                                                                                                                                                                                                               |
| T11 | Local malware reads a stored vendor account home                 | Codex homes live at `{data_dir}/accounts/codex-cli/{account_id}` and Grok homes at `{data_dir}/accounts/grok-cli/{account_id}`. They are weaker than `CredentialStore` and rely on filesystem permissions. The manager may move opaque Codex bytes under ADR 0008. For Grok it may perform transient, zeroized structure validation, but it never interprets, extracts, logs, copies, backs up, rewrites, or deletes the home or its credential values under ADR 0009. |
| T12 | A child launch exposes credentials through output or environment | Child stdio is inherited and never captured. Core resolves a credential only at spawn and applies it to the exact adapter-declared child variable; it never mutates process-global environment or includes a value in IPC, metadata, logs, errors, or results. Same-user operating-system inspection of the child environment remains possible.                                                                                                                        |
| T13 | External provider state changes after validation                 | Environment-selected adapters validate current and target state before selection and validate again before launch. Known lock, session, settings, or path conflicts fail closed. External-process time-of-check/time-of-use races cannot be eliminated and remain a documented residual risk.                                                                                                                                                                          |

## 4. What this project will never do

- Store a secret it receives in plaintext, in any mode, behind any flag. The
  only documented exceptions are vendor-written account homes: stored Codex
  homes under [ADR 0008](adr/0008-vendor-written-auth-json-for-stored-codex-accounts.md)
  and retained Grok homes under
  [ADR 0009](adr/0009-launch-environment-account-selection.md). This application
  does not compose the credential values in those files.
- Send a credential through webview IPC, or anywhere except to the vendor it
  belongs to through the managed tool's local config or exact child
  environment.
- Collect telemetry, analytics, or usage statistics.
- Bind the relay to a non-loopback interface without an explicit opt-in and an
  authentication token.
- Include secret material in a log, an error message, a crash report, or a
  diagnostic export.
- Mutate the application process environment to select an account.
- Accept an arbitrary executable, argument list, working directory, or
  environment map over IPC as an account-launch request.
- Interpret, extract, log, copy, restore, back up, rewrite, or delete a stored
  Grok home or its credential values. Structure-only validation uses a
  transient, zeroized input buffer.
- Modify a managed tool's config without a restorable backup.
- Ship a feature whose purpose is to circumvent a vendor's rate limits, terms of
  service, or pricing.

## 5. Backup and restore

- A backup is taken before the first manager write to a managed tool's file,
  covering every path the operation can replace.
- Backups are timestamped and immutable once written.
- Retention is user-configurable with a floor: the most recent backup per
  provider is never pruned automatically.
- Restore is offered explicitly in the UI, including for configs the application
  did not itself break.
- For Codex CLI, that snapshot includes the live `auth.json`. The backup is
  another copy of the credential, stored under the application data directory
  with `0600` on Unix, the same as any other captured secret file.
- Launch-environment selection writes only application-owned non-secret
  metadata and a future child environment. It does not trigger `NFR-4` because
  no managed-tool file is replaced.
- Stored Grok homes are not backed up, copied, or restored by this application.

## 6. Stored Codex accounts

A stored Codex account is a directory this application created, not a
secret it wrote into the credential store. Layout:

```text
{data_dir}/accounts/codex-cli/{account_id}/auth.json
```

`{data_dir}` is the application data directory from
`paths::project_dirs()`. The live tool home (`~/.codex`, or `$CODEX_HOME`
when that is set) is not one of these directories.

On Unix the account directory is created `0700`. The `auth.json` inside it
is written by `codex login`, so its mode is whatever that CLI creates.
This application does not chmod the file and does not encrypt it. See
[ADR 0008](adr/0008-vendor-written-auth-json-for-stored-codex-accounts.md).

`add_account` must not mutate the live tool home. It creates the directory,
spawns `codex login` with `CODEX_HOME` pointing at it, and inherits stdio
so the CLI's prompts and URL appear on the launching terminal. This
application never captures that output. A failed attempt removes the
directory it created and leaves sibling accounts alone.

`delete_account` removes only that directory. It does not touch the live
home, so deleting the account that is currently active does not sign the
tool out.

## 7. Stored Grok homes

A stored Grok account is a manager-created home in which the vendor writes its
own credential state. Layout:

```text
{data_dir}/accounts/grok-cli/{account_id}/auth.json
```

The account path is derived inside Rust core from the provider and account ids.
It is not an arbitrary path accepted from IPC or stored metadata. The manager
launches the vendor's login against that home. The vendor writes `auth.json` and
any related state. This is the narrow Grok plaintext exception to `FR-3`.

The manager may validate that `auth.json` is a regular top-level JSON object
using a transient, zeroized input buffer. It never interprets, extracts, or
logs credential values and never copies, restores, backs up, rewrites, or
deletes the home. Activation changes only non-secret selection metadata. Launch
sets the derived home as `GROK_HOME` on the child and removes an inherited
`GROK_AUTH_PATH` that would bypass it.

Before changing selection, the adapter checks the vendor auth lock and active
sessions for the current and target homes. It checks again before launch. A
held lock, active session, unreadable gate, or ambiguous state is a refusal.
An external process can still change state after a check; the application does
not claim a cross-process transaction.

`delete_account` forgets the metadata and retains the vendor home. The
credential remains on disk and usable by any process explicitly pointed at
that path. Destruction is a separate manual operation outside this lifecycle.

## 8. Reporting

Vulnerability reporting is described in [`../SECURITY.md`](../SECURITY.md).
Anything in §4 being false is a vulnerability, not a bug report.
