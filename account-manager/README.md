# Coding Agent Manager

Account, credential, quota, relay, and routing manager for AI coding agents.

Coding Agent Manager is a pre-alpha desktop application with provider-specific
account operations. It does not offer the same switch mechanism for every
provider: Codex CLI uses a legacy configuration-file replacement, Claude Code
rewrites the live `~/.claude` identity pair, Gemini CLI and Grok CLI use
account selection for app-owned launches, and Cursor is read-only.

> **Status: pre-alpha.** All five adapters are experimental. Codex CLI can add,
> switch, and delete stored copies, but its copied-credential switch is not
> proven against the vendor. Claude Code can add an isolated vendor login,
> switch the live `~/.claude` identity pair behind a restorable backup, and
> forget a stored copy without signing out live Claude. That copied-credential
> switch is also unproven against the vendor. Gemini Google OAuth, Gemini
> API-key, and Grok accounts can be added, selected, launched, and forgotten
> through app-owned launch paths. Cursor does not implement account mutation.
> See
> [`docs/ROADMAP.md`](docs/ROADMAP.md) for what lands when, and
> [`docs/PROVIDER_MATRIX.md`](docs/PROVIDER_MATRIX.md) for what is known
> about each tool today.

## Supported providers

| Provider    | Vendor    | Auth             | Adapter status | Capabilities                                                     | Notes                                                                                                                                                                                                                                                                                                                                                            |
| ----------- | --------- | ---------------- | -------------- | ---------------------------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Claude Code | Anthropic | OAuth, API key   | Experimental   | `add-account`, `switch-account`, `delete-account`                | Isolated vendor login into a managed home. Switch rewrites live `~/.claude` identity fields behind a restorable backup. Forgetting a stored copy does not sign out live Claude. Vendor acceptance of a copied credential remains untested.                                                                                                                       |
| Codex CLI   | OpenAI    | OAuth, API key   | Experimental   | `add-account`, `switch-account`, `delete-account`                | Replaces live `auth.json` behind a restorable backup. Vendor acceptance of a copied credential remains untested.                                                                                                                                                                                                                                                 |
| Cursor      | Anysphere | Unknown, API key | Experimental   | None                                                             | Lists the Cursor CLI identity through `cursor-agent status`. Credential storage and switching remain unknown.                                                                                                                                                                                                                                                    |
| Grok CLI    | xAI       | OAuth, API key   | Experimental   | `add-account`, `switch-account`, `delete-account`, `launch-tool` | Selects a retained managed `GROK_HOME` for an app-owned child and removes inherited `GROK_AUTH_PATH`. Forgetting removes manager metadata but retains the vendor home. This does not affect Grok started elsewhere.                                                                                                                                              |
| Gemini CLI  | Google    | OAuth, API key   | Experimental   | `add-account`, `switch-account`, `delete-account`, `launch-tool` | OAuth add writes an isolated `GEMINI_CLI_HOME` via in-app Google loopback, including managed `oauth-personal` settings. Listing may include a read-only `gemini-cli-on-disk` row. Launch sets that home and `GOOGLE_GENAI_USE_GCA=true`. API-key accounts inject `GEMINI_API_KEY` only into an app-owned child. Live `~/.gemini` file-swap remains out of scope. |

Antigravity, Windsurf, GitHub Copilot, OpenCode, Aider, and Cline are planned
behind the same adapter interface. Adding one does not require changing core
code — see [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## What it does

Shipped today:

- **Account operations.** Codex CLI can add, switch, and delete stored copies.
  Claude Code can add an isolated vendor login, switch the live `~/.claude`
  identity pair, and forget a stored copy without signing out live Claude.
  Gemini Google OAuth, Gemini API-key, and Grok accounts can be selected for
  app-owned launches. Gemini OAuth launch sets child-only `GEMINI_CLI_HOME` and
  `GOOGLE_GENAI_USE_GCA=true`. Gemini API-key selection injects `GEMINI_API_KEY`
  only into the child. Grok selection sets child-only `GROK_HOME` and removes
  inherited `GROK_AUTH_PATH`.
- **Listing.** Claude Code, Codex CLI, Cursor CLI, Grok CLI, and Gemini CLI can
  list their implemented account surfaces, with identities masked. Gemini may
  also list a read-only live `gemini-cli-on-disk` OAuth row.
- **Secure storage.** OS keychain first, encrypted file only as a
  fallback, for secrets this application itself stores. Stored Codex
  accounts are vendor-written files — see
  [`docs/adr/0008-vendor-written-auth-json-for-stored-codex-accounts.md`](docs/adr/0008-vendor-written-auth-json-for-stored-codex-accounts.md).
- **Quota visibility.** The Dashboard has list and grid views and distinguishes
  available, no-signal, and failed collection states. Every current provider
  reports no numeric signal because none has a verified research basis.
- **Relay.** A loopback listener exposes six OpenAI, Anthropic, and Gemini
  paths. It implements all 12 ordered non-streaming text pairs, bounded
  streaming on the routes listed in
  [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), and OpenAI Images to and from
  Gemini image translation.
- **Routing.** Ordered, persisted model rules select one configured account
  target per provider. Fallback occurs only after HTTP 429, and rule changes
  apply on the next relay start.

Still open for v1:

- `FR-2` remains incomplete; see
  [`docs/ROADMAP.md`](docs/ROADMAP.md) for the implemented provider paths and
  remaining safety bars.
- Cursor mutation. Claude and Codex copied-credential switches remain unproven
  against their vendors.
- `FR-9` defaults, per-route overrides, and precedence.
- Relay integration with provider-selected managed accounts and the deferred
  real-agent end-to-end check.
- Installable and signed release artifacts, including the headless Docker
  image.

The full requirement list, numbered and referenceable, is in
[`docs/SPEC.md`](docs/SPEC.md).

## Screenshots

_Placeholder — screenshots will be added once the Accounts page is
stable enough to photograph._

## Quick start

```bash
git clone https://github.com/Meta-Develop/Coding-Agent-Manager.git
cd Coding-Agent-Manager
npm install
npm run tauri:dev
```

### Building on NixOS

This repository ships a dev shell, because Tauri v2 needs `webkit2gtk-4.1`,
which most NixOS hosts do not provide system-wide:

```bash
nix develop
npm install
npm run tauri:build
```

There are no official GitHub release installers yet. On a Nix host, wrap that
Linux binary with `nix build .#coding-agent-manager` and install it with
`nix profile install .#coding-agent-manager`, or add the same flake output to
Home Manager. The hash-and-wrap steps are in
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

Full prerequisites for every platform are in
[`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md).

### Routed relay targets

The desktop relay loads persisted rules when it starts. For every provider id
named by those rules, configure one runtime environment group. Replace `<KEY>`
with the provider id uppercased and with hyphens changed to underscores:

| Variable                                              | Required | Value                                                                                                                                  |
| ----------------------------------------------------- | -------- | -------------------------------------------------------------------------------------------------------------------------------------- |
| `CODING_AGENT_MANAGER_RELAY_TARGET_<KEY>_URL`         | Yes      | Base URL ending in `/`, with no credentials, query, or fragment. Use HTTPS, except that HTTP is accepted for loopback hosts.           |
| `CODING_AGENT_MANAGER_RELAY_TARGET_<KEY>_DIALECT`     | Yes      | One of `openai-chat-completions`, `openai-responses`, `openai-images-generations`, `anthropic-messages`, or `gemini-generate-content`. |
| `CODING_AGENT_MANAGER_RELAY_TARGET_<KEY>_ACCOUNT_ID`  | Yes      | Nonempty account identifier for the provider target.                                                                                   |
| `CODING_AGENT_MANAGER_RELAY_TARGET_<KEY>_AUTH_TOKEN`  | No       | Runtime-only upstream token.                                                                                                           |
| `CODING_AGENT_MANAGER_RELAY_TARGET_<KEY>_AUTH_HEADER` | No       | Header name used with `_AUTH_TOKEN`. Omit it, or use `authorization`, for Bearer authentication.                                       |

A partial group fails relay startup. `_AUTH_HEADER` without `_AUTH_TOKEN` also
fails. These variables are runtime target configuration; they are not provider
adapter account-selection integration.

## Documentation

| Document                                           | What it covers                                        |
| -------------------------------------------------- | ----------------------------------------------------- |
| [`docs/SPEC.md`](docs/SPEC.md)                     | Numbered functional and non-functional requirements   |
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)     | Layering, adapter contract, relay and router design   |
| [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) | Threat model and controls for handling credentials    |
| [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md)       | Environment setup, commands, adding an adapter        |
| [`docs/TESTING.md`](docs/TESTING.md)               | Test strategy, including testing without real secrets |
| [`docs/ROADMAP.md`](docs/ROADMAP.md)               | Milestones M0 through v1.0                            |
| [`docs/research/`](docs/research/)                 | Per-provider evidence notes with confidence markers   |
| [`docs/adr/`](docs/adr/)                           | Architecture decision records                         |

## Security

This application handles credentials. Its controls include no telemetry,
keeping secrets out of logs, binding the relay to loopback unless it is
explicitly configured otherwise with an auth token, and using a recoverable
backup for every managed-tool configuration replacement. The reasoning is in
[`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md); to report a vulnerability,
see [`SECURITY.md`](SECURITY.md).

## Contributing

Contributions are welcome, especially provider research and new adapters. Start
with [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Relationship to other projects

Coding Agent Manager is an independent implementation. It was inspired by the
_problem_ that [`lbjlaq/Antigravity-Manager`][upstream] solves for a single
vendor, and applies a provider-adapter design across multiple coding agents.
The imported snapshot's previous Gemini OAuth implementation was attributed to
that project. It is excluded from this MACO source import and independently
replaced using official Google protocol facts; see
[`docs/OAUTH_PROVENANCE.md`](docs/OAUTH_PROVENANCE.md). The historical credit is
retained in [`NOTICE`](NOTICE). This project is not a fork of it. The original
design reasoning is recorded in
[`docs/adr/0006-clean-room-independent-implementation.md`](docs/adr/0006-clean-room-independent-implementation.md).

[upstream]: https://github.com/lbjlaq/Antigravity-Manager

**This project is not affiliated with, endorsed by, or sponsored by Anthropic,
OpenAI, Anysphere, xAI, Google, or any other vendor whose tools it manages.**
All product names are trademarks of their respective owners. Using this tool to
manage your own accounts is your responsibility under each vendor's terms of
service.

## License

[GPL-3.0-or-later](LICENSE) © Meta-Develop
