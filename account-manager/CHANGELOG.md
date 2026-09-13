# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- MACO source integration with a native `--no-default-features` core build;
  the existing desktop application remains the default. Build and integration
  boundaries are documented in `docs/MACO_SOURCE.md`.
- Independently implemented Gemini browser OAuth with PKCE, bounded loopback
  callbacks, one token exchange, and credential-marker-last recovery. The
  excluded previous module and retained notices are documented in
  `docs/OAUTH_PROVENANCE.md`.
- Project foundation: Tauri v2 + React + TypeScript application skeleton that
  builds and runs, with routed pages for Dashboard, Accounts, Providers, Relay,
  Router, and Settings.
- `ProviderAdapter` contract and adapters for Claude Code, Codex CLI, Cursor,
  Grok CLI, and Gemini CLI, each documenting its researched config paths with
  confidence markers.
- `CredentialStore` contract with implemented OS-keychain and encrypted-file
  backends; no plaintext backend exists by design.
- `RelayConfig` validation refusing a non-loopback binding without an
  authentication token, with tests.
- Documentation set: specification with numbered requirements, architecture,
  security model, development and testing guides, roadmap, release process,
  glossary, provider matrix, five provider research notes, and nine ADRs.
- `flake.nix` dev shell providing the Tauri v2 Linux prerequisites.
- CI across Linux, macOS, and Windows; desktop release workflow configuration
  for platform bundles.
- Backup subsystem: timestamped snapshots over an adapter's declared config
  paths, restore that returns the tree to its captured state including files
  that were absent and Unix permission bits, and retention that never prunes a
  provider's newest backup (`NFR-4`).
- Atomic write helper that every config write goes through: temporary file,
  `fsync`, rename, and owner-only permissions at creation (`NFR-4`).
- OS-keychain credential store for macOS Keychain, Windows Credential Manager,
  and Freedesktop Secret Service, with error mapping that never forwards stored
  bytes (`FR-3`, `NFR-1`).
- Encrypted-file fallback store: Argon2id key derivation from a user passphrase
  with its parameters recorded in the file, ChaCha20-Poly1305 authenticated
  encryption, a verifier that reports a wrong passphrase separately from a
  tampered file, and a refusal to read or write a newer schema version. Those
  backends still have no plaintext mode, behind any flag (`FR-3`, `NFR-1`).
- Codex CLI adapter: add a stored account by running the vendor's
  `codex login` with `CODEX_HOME` pointed at a per-account directory under
  the application data directory. The CLI writes `auth.json` itself. This
  application does not compose credential JSON and retains the vendor-written
  `auth.json` as documented by ADR 0008. Adding does not switch the live home.
- Codex CLI `list_accounts` merges those stored copies with the live
  on-disk identity. A stored account is marked active only when its
  `auth.json` is byte-identical to the live file.
- Codex CLI `activate_account` switches by replacing the live `auth.json`
  behind a restorable backup, and refuses while a process named `codex`
  is running. The write is a local file replacement. It is not proven
  that the vendor accepts the copied credential
  (`docs/research/codex-cli.md` §5).
- Codex CLI `delete_account` forgets a stored copy without signing the
  tool out.
- `ProviderDescriptor.capabilities` so the UI offers only the operations an
  adapter implements (`NFR-8`). Maturity is not that gate.
- Architecture decision record 0008: stored Codex accounts keep the
  vendor-written `auth.json` on disk, a documented deviation from
  `FR-3`.
- Accounts page: add, switch, and delete, with confirmations, only where
  the adapter advertises the matching capability and the row is a stored
  copy. Sign-in still runs in the launching terminal.
- Provider-neutral launch-environment account selection with versioned,
  atomic metadata states for pending, complete, and deleting accounts.
  `LaunchSpec` keeps executable, arguments, working directory, environment,
  and secret resolution inside the Rust core (`FR-3`, `NFR-1`).
- Gemini CLI managed API-key accounts. Keys are stored through
  `CredentialStore`, selected through non-secret metadata, resolved only at
  child spawn, and injected as `GEMINI_API_KEY` into that app-owned child.
  Add, select, launch, and delete leave the Gemini configuration tree
  unchanged.
- Gemini CLI in-app Google OAuth add. The flow is a loopback
  authorization-code exchange adapted from Antigravity Manager, using
  Gemini CLI's published installed-app client. Tokens are written only to
  an isolated `GEMINI_CLI_HOME` as `oauth_creds.json` plus
  `google_accounts.json` and managed `settings.json`
  `security.auth.selectedType: oauth-personal`. Launch sets that home and
  `GOOGLE_GENAI_USE_GCA=true`. Forgetting an OAuth account retains the
  home. Listing may include a read-only `gemini-cli-on-disk` row when live
  `oauth_creds.json` is present. The live `~/.gemini` tree is not written
  or swapped.
- Grok CLI managed accounts. Each vendor-written home stays under the
  application data directory; selection starts an app-owned child with
  `GROK_HOME` set to that home and inherited `GROK_AUTH_PATH` removed. The
  application never copies, rewrites, backs up, or deletes the managed
  `auth.json`, and forgetting an account retains its vendor home. See ADR 0009
  for the narrow plaintext-home exception.
- Claude Code isolated vendor-login add, crash-safe two-file switch of the
  live `~/.claude` identity pair, and delete of a stored copy that does not
  sign out live Claude. The Accounts page offers Sign in, Switch, and Delete
  when the adapter advertises those capabilities. The id `claude-code-on-disk`
  is reserved for the live identity. Vendor acceptance of a copied credential
  remains untested.
- Claude Code 2.1.212 identity write-path research marked `[verified-local]`:
  only top-level `claudeAiOauth` in `.credentials.json` and `oauthAccount` in
  `~/.claude.json` are identity fields. The two-file switch uses a paired
  backup, durable recovery journal, fail-closed process and lock checks, and
  surgical field preservation.
- Read-only Cursor CLI account listing through `cursor-agent status`, with
  masked identities and fail-closed parsing. Cursor remains experimental and
  advertises no mutating capability because its credential store and write
  path are still unknown (`NFR-8`).
- Quota visibility for all five providers. The Dashboard renders available,
  no-signal, and failed collection states distinctly in list and grid views.
  Every current adapter returns an empty snapshot vector because no numeric
  signal has a verified research basis; Claude Code may also return the
  non-credential `billingType` plan label (`FR-5`, `NFR-8`).
- A local relay with six OpenAI, Anthropic, and Gemini ingress paths, all 12
  ordered non-streaming text-format pairs, bounded event-by-event streaming on
  supported routes, OpenAI Images to and from Gemini image translation,
  reasoning-budget mapping with explicit errors, and an auth-token requirement
  for non-loopback listeners. The translation suite contains 74 golden cases
  (`FR-6`, `FR-8`, partial `FR-9`).
- Ordered account-aware routing from a case-sensitive exact or trailing-`*`
  model pattern to provider and target model. Rules are stored atomically in a
  versioned `route-rules.json`; quota gates fail closed, unmatched requests
  error explicitly, and fallback occurs only after HTTP 429. The later usable
  numeric `Retry-After` or quota reset sets the throttle deadline, with 60
  seconds used when neither exists (`FR-7`).
- Routed relay targets configured through provider-namespaced runtime
  environment groups. Routed requests strip client credentials and account
  selectors before injecting only the selected target authentication, and
  persisted rules take effect on the next relay start.

### Changed

- Dashboard home shows one row or card per account with display name, provider,
  sourced remaining quota, window, and reset time together. Accounts without a
  snapshot still appear with an explicit no-signal state and no invented
  percentage (`FR-5`, `NFR-8`).
- Relicensed from GPL-3.0-or-later to CC-BY-NC-SA-4.0 so this project can
  share a licence with `lbjlaq/Antigravity-Manager`. The grant is
  non-commercial and share-alike. Copies already received under
  GPL-3.0-or-later are not revoked.
- Desktop chrome: sidebar mark and nav affordance, page canvas, card and table
  frames, status chips, and button treatments. Labels, capability gates, and
  error distinctions are unchanged.
- Accounts add flow is numbered and OAuth-first where the adapter can start
  sign-in (Claude Code, Codex CLI, Grok CLI, Gemini CLI). Gemini titles the
  primary path Sign in to Gemini CLI and keeps Import API key as a secondary
  control. Cursor still offers no add control (`NFR-8`).
- Gemini account listings use the ordinary `listed` outcome. The Accounts page
  no longer describes Gemini as API-key-only or as lacking Google OAuth.
- Provider sections on Accounts, Dashboard, and Providers use a left color
  rail, initial mark, and vendor chip keyed by provider id. Brand-adjacent
  hues only; no vendor marks.
- Page chrome drops the canvas gradient, floating page card, and stacked
  shadows in favor of hairlines, stronger ink contrast, and more space
  between provider groups. Route pages lazy-load in production.
- Declared minimum supported Rust version raised to 1.88, matching what the
  dependency tree already required.
- Linux CI dependency list now names `libdbus-1-dev` explicitly rather than
  relying on it arriving transitively.

### Fixed

- `add_account` no longer occupies the Tauri command thread for the duration of
  vendor login; the invoke still waits for the same login result.

### Notes

The credential stores and the backup machinery are implemented and exercised
by the M1 exit-criteria suite. Codex CLI can add a stored account, switch
the live `auth.json`, and delete a stored copy. That switch is a local
file replacement; it is not proven against the vendor. Gemini isolated-home
OAuth, Gemini API-key, and Grok accounts can be selected for app-owned launches
without changing each tool's default home. Live `~/.gemini` file-swap remains
out of scope. Claude Code rewrites the live `~/.claude` identity pair behind
a restorable backup. Cursor remains read-only. The relay and
router are implemented only to the boundaries recorded in `docs/ROADMAP.md`.

[Unreleased]: https://github.com/Meta-Develop/Coding-Agent-Manager/commits/main
