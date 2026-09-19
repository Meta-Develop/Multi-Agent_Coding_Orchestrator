# GitHub Copilot (GitHub)

## 1. Identity

- Tools: GitHub Copilot in supported IDEs and on GitHub.com, and GitHub
  Copilot CLI (`copilot`, npm package `@github/copilot`).
- Vendor: GitHub.
- Version observed on host: **not observed**. This note is not a
  `[verified-local]` record. Nobody on this project opened a signed-in
  Copilot CLI or IDE install for this research.
- OS observed: **not observed**.
- First-party public tree inspected (2026-09-20): repository
  `github/copilot-cli` at commit
  `d418dbf1061152afa17500cbc69478f8dce153d8` (2026-09-17). That tree
  publishes README, changelog, and install packaging. Its changelog
  heading is `1.0.86 - 2026-09-17`. The tree is **not** the CLI
  application source. A published binary was not unpacked and was not
  run.

The GitHub Copilot extension for GitHub CLI (`gh copilot`) is retired
and replaced by GitHub Copilot CLI `[verified-docs]`. This note does not
treat `gh copilot` as a current adapter target. Historical storage for
that extension remains `[unknown]`.

This update was made from official GitHub Docs and the public
`github/copilot-cli` packaging tree. It is not an on-host observation of
a signed-in install. Claims from official documentation are
`[verified-docs]`. Claims taken from the pinned packaging files are
`[verified-docs]` (prose) unless the file is executable install logic,
in which case they are `[verified-source]` for that script only. Neither
marker is `[verified-local]`. Application source for credential writes
was not published in the inspected tree, so no `[verified-source]`
credential-schema claim is made.

Pinned first-party packaging and docs-source files:

- https://raw.githubusercontent.com/github/copilot-cli/d418dbf1061152afa17500cbc69478f8dce153d8/README.md
- https://raw.githubusercontent.com/github/copilot-cli/d418dbf1061152afa17500cbc69478f8dce153d8/changelog.md
- https://raw.githubusercontent.com/github/docs/419d2fdffc6188147565196fe9225be3c951fa6f/content/copilot/reference/copilot-cli-reference/cli-config-dir-reference.md

Official vendor documentation checked on 2026-09-20:

- <https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-copilot-cli>
- <https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/install-copilot-cli>
- <https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/authenticate-copilot-cli>
- <https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/troubleshoot-copilot-cli-auth>
- <https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference>
- <https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-config-dir-reference>
- <https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/use-byok-models>
- <https://docs.github.com/en/copilot/how-tos/use-copilot-for-common-tasks/use-copilot-in-the-cli>
- <https://docs.github.com/en/copilot/get-started/plans>
- <https://docs.github.com/en/copilot/concepts/billing/usage-based-billing-for-individuals>
- <https://docs.github.com/en/copilot/how-tos/manage-and-track-spending/monitor-ai-usage>
- <https://docs.github.com/en/copilot/concepts/network-settings>
- <https://docs.github.com/en/copilot/reference/copilot-allowlist-reference>
- <https://docs.github.com/en/copilot/how-tos/set-up/install-copilot-extension>
- <https://docs.github.com/en/copilot/how-tos/configure-personal-settings/authenticate-to-ghecom>
- <https://docs.github.com/en/copilot/troubleshooting-github-copilot/troubleshooting-common-issues-with-github-copilot>
- <https://docs.github.com/en/copilot/reference/copilot-billing/request-based-billing-legacy/monitor-premium-requests>

Install surfaces named by official docs `[verified-docs]`:

- npm: `npm install -g @github/copilot` (Node.js 22 or later)
- WinGet: `winget install GitHub.Copilot`
- Homebrew: `brew install --cask copilot-cli` (install page) / `brew
install copilot-cli` (CLI README at the pinned commit)
- macOS/Linux install script: `https://gh.io/copilot-install`
- Direct binaries from the `github/copilot-cli` releases page

Windows requires PowerShell v6 or higher `[verified-docs]`. An
organization or enterprise can disable Copilot CLI by policy
`[verified-docs]`.

## 2. Config locations

The Copilot CLI configuration and state directory is `~/.copilot`, that
is `$HOME/.copilot`. `COPILOT_HOME` replaces that entire directory
`[verified-docs]`. `--config-dir` is a deprecated alias for the same
directory and is not the preferred override `[verified-docs]`. Previous
XDG-based configuration locations are migrated to `~/.copilot` at
startup when `COPILOT_HOME` is unset `[verified-docs]`. The exact former
XDG path is `[unknown]`.

Windows official examples use
`C:\Users\YOUR-USER\.copilot\…` `[verified-docs]`. That is a
placeholder, not a machine-local path. `%USERPROFILE%\.copilot` is the
expected expansion `[inferred]` and still needs a real-host
confirmation.

The cache directory is **not** moved by `COPILOT_HOME`. Override it
separately with `COPILOT_CACHE_HOME` `[verified-docs]`.

| Path                                                                                                                             | Purpose                                                                           | Marker            |
| -------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------- | ----------------- |
| `~/.copilot` / `$HOME/.copilot`                                                                                                  | Default CLI config and state directory                                            | `[verified-docs]` |
| `$COPILOT_HOME`                                                                                                                  | Replaces the entire `~/.copilot` tree                                             | `[verified-docs]` |
| `~/.copilot/config.json`                                                                                                         | Automatically managed application state, including authentication data            | `[verified-docs]` |
| `~/.copilot/settings.json`                                                                                                       | User-editable settings (JSONC). Older user settings in `config.json` migrate here | `[verified-docs]` |
| `~/.copilot/providers.json`                                                                                                      | BYOK provider and model registry. Override path with `COPILOT_PROVIDERS_CONFIG`   | `[verified-docs]` |
| `~/.copilot/permissions-config.json`                                                                                             | Saved tool and directory approvals per project                                    | `[verified-docs]` |
| `~/.copilot/lsp-config.json`                                                                                                     | User-level LSP server definitions                                                 | `[verified-docs]` |
| `~/.copilot/mcp-config.json`                                                                                                     | User-level MCP server definitions                                                 | `[verified-docs]` |
| `~/.copilot/mcp-oauth-config/`                                                                                                   | MCP OAuth fallback when keychain storage is unavailable. Not the GitHub login     | `[verified-docs]` |
| `~/.copilot/mcp-secrets/`                                                                                                        | MCP secret-placeholder fallback. Not the GitHub login                             | `[verified-docs]` |
| `~/.copilot/session-state/`, `command-history-state/`, `session-store.db`                                                        | Session history and cross-session data                                            | `[verified-docs]` |
| `~/.copilot/logs/`, `agents/`, `skills/`, `hooks/`, `extensions/`, `instructions/`, `installed-plugins/`, `plugin-data/`, `ide/` | Customizations, plugins, logs, IDE-integration state                              | `[verified-docs]` |
| `~/Library/Caches/copilot`                                                                                                       | macOS cache (not under `COPILOT_HOME`)                                            | `[verified-docs]` |
| `$XDG_CACHE_HOME/copilot` or `~/.cache/copilot`                                                                                  | Linux cache (not under `COPILOT_HOME`)                                            | `[verified-docs]` |
| `%LOCALAPPDATA%/copilot`                                                                                                         | Windows cache (not under `COPILOT_HOME`)                                          | `[verified-docs]` |
| `.github/copilot/settings.json`                                                                                                  | Repository-shared settings                                                        | `[verified-docs]` |
| `.github/copilot/settings.local.json`                                                                                            | Personal repository overrides                                                     | `[verified-docs]` |
| OS keychain service `copilot-cli`                                                                                                | Default OAuth-token store after `copilot login`                                   | `[verified-docs]` |
| IDE / editor GitHub account store                                                                                                | VS Code, Visual Studio, JetBrains, and other IDE sign-in                          | `[unknown]`       |

Deleting `config.json` resets application state including authentication
and requires re-authentication `[verified-docs]`.

Managed (MDM / file) settings are a separate policy layer, not a user
credential store `[verified-docs]`:

| Platform | Location                                                                                                       |
| -------- | -------------------------------------------------------------------------------------------------------------- |
| macOS    | MDM plist `com.github.copilot`; file `/Library/Application Support/GitHubCopilot/managed-settings.json`        |
| Windows  | MDM registry `HKLM\SOFTWARE\Policies\GitHubCopilot`; file `%ProgramFiles%\GitHubCopilot\managed-settings.json` |
| Linux    | `/etc/github-copilot/managed-settings.json`                                                                    |

## 3. Credential format

No signed-in file was opened. No token, email, user id, or account id
was recorded. The shapes below are **names and store identities only**.

### OS keychain (default OAuth store)

After interactive `copilot login` / `/login`, the CLI stores the OAuth
token in the operating-system credential store under service name
`copilot-cli` `[verified-docs]`:

| Platform | Store named by docs                                                                   |
| -------- | ------------------------------------------------------------------------------------- |
| macOS    | Keychain Access. Official lookup: `security find-generic-password -s copilot-cli`     |
| Windows  | Credential Manager / Windows Vault                                                    |
| Linux    | libsecret (GNOME Keyring, KWallet). Official lookup: `secret-tool search copilot-cli` |

The exact Windows target / generic-credential name beyond the service
string `copilot-cli`, the keychain account attribute, and the secret
payload fields are `[unknown]`.

### Plaintext fallback in `config.json`

If the system keychain is unavailable, the CLI prompts:

```text
System keychain unavailable. Store token in plaintext config file? (y/N)
```

Accepting that prompt stores the token in a plaintext configuration
file at `~/.copilot/config.json` (or under `COPILOT_HOME`)
`[verified-docs]`. Setting `storeTokenPlaintext` to `true` in
`settings.json` allows that plaintext path when no system keychain is
available; the documented default is `false` `[verified-docs]`.

`config.json` is automatically managed and includes authentication
data. Official docs name these application-state fields that remain in
`config.json` after user settings migrate to `settings.json`
`[verified-docs]`:

- `loggedInUsers`
- `installedPlugins`
- `firstLaunchAt`
- `staff`

The JSON type of `loggedInUsers`, whether it holds tokens or only
identities, whether a current-user pointer exists, and every other key
that appears on a real signed-in host are `[unknown]`. This note does
not invent a schema.

### Environment-variable tokens

Supported token types `[verified-docs]`:

| Token type                                                                                 | Prefix        | Supported                     |
| ------------------------------------------------------------------------------------------ | ------------- | ----------------------------- |
| OAuth token from `copilot login`                                                           | `gho_`        | Yes                           |
| Fine-grained PAT with account permission **Copilot Requests**, owned by a personal account | `github_pat_` | Yes                           |
| GitHub App user-to-server                                                                  | `ghu_`        | Yes, via environment variable |
| Classic PAT                                                                                | `ghp_`        | No                            |

Never record a real token. If a shape must be shown, use
`"access_token": "<redacted>"`.

### GitHub CLI fallback

When no environment variable and no stored token is found, Copilot CLI
can use `gh auth token` `[verified-docs]`. The GitHub CLI credential
store itself is outside this note. Its path and format remain
`[unknown]` here.

### IDE GitHub sign-in

Official IDE docs describe signing in with a GitHub account in the
editor. They do not identify a Copilot-specific credential file
`[verified-docs]`. The IDE store is `[unknown]`. Whether the editor and
`copilot` share one credential is `[unknown]`.

## 4. Authentication flow

GitHub authentication is required for GitHub-hosted Copilot CLI usage.
BYOK (own LLM provider keys) does not require GitHub authentication,
but `/delegate`, the GitHub MCP server, and GitHub Code Search then
stay unavailable `[verified-docs]`. `COPILOT_OFFLINE=true` skips GitHub
authentication and GitHub network contact; the CLI then talks only to
the configured BYOK provider `[verified-docs]`.

Interactive GitHub auth `[verified-docs]`:

1. **OAuth browser (web) flow** — default on a local terminal. The CLI
   opens a browser and completes on a local loopback callback.
   `copilot login --web-flow` forces this path.
2. **OAuth device-code flow** — default on remote / headless
   environments (SSH, Codespaces, dev containers, CI).
   `copilot login --device-code` forces this path.
3. **`copilot login --with-token`** — read a token from stdin instead of
   starting OAuth.
4. **`/login`** inside an interactive session — same OAuth choice,
   including GitHub.com vs GitHub Enterprise Cloud with data residency
   (`*.ghe.com`). `copilot login --host HOST` sets the host.

After a successful interactive login, the token is stored in the system
credential store, or in plaintext under `~/.copilot/` / `COPILOT_HOME`
if no store is found `[verified-docs]`. Token lifetime and expiration
depend on account or organization settings `[verified-docs]`.

Non-interactive GitHub auth, checked in this order `[verified-docs]`:

1. `COPILOT_GITHUB_TOKEN`
2. `GH_TOKEN`
3. `GITHUB_TOKEN`
4. OAuth token from the system keychain
5. GitHub CLI (`gh auth token`)

An environment variable silently overrides a stored OAuth token
`[verified-docs]`. Exception: in GitHub Codespaces, the automatically
injected `GITHUB_TOKEN` does not take precedence over an account signed
in with `/login`. An explicitly exported `GITHUB_TOKEN`,
`COPILOT_GITHUB_TOKEN`, or `GH_TOKEN` still does `[verified-docs]`.

The authenticate page's check order names the keychain and does not
name plaintext `config.json`. The same page and the command reference
say the plaintext file is the fallback **store** when the keychain is
missing. Whether a later command reads that plaintext file, and where
that read sits relative to the five-step list, is `[unknown]`.

`/logout` removes the locally stored token and does not revoke it on
GitHub `[verified-docs]`. Revocation is a separate GitHub.com OAuth-app
action.

IDE authentication is a GitHub account sign-in in the editor
`[verified-docs]`. For GHE.com, VS Code uses `Github-enterprise: Uri`
plus `github.copilot.advanced.authProvider` set to `"github-enterprise"`
`[verified-docs]`. That is editor settings, not a discovered credential
file.

## 5. Account switching mechanics

Official Copilot CLI switching `[verified-docs]`:

- The CLI can remember more than one login and remembers the last-used
  account.
- `/user list` lists available accounts.
- `/user switch` switches to a different stored account.
- Adding another account: `copilot login` from a new terminal, or
  `/login` inside the CLI, then authorize the other account.
- `/logout` drops the local token.

Those commands are the vendor-supported switch. Their on-disk or
keychain write protocol was not observed. Implementing
`activate_account` by editing `config.json` or the `copilot-cli`
keychain item is **not** established.

`COPILOT_HOME` relocates the whole config directory `[verified-docs]`.
That is a candidate isolated-home mechanism. It has not been probed
against any binary on this host. Whether it relocates keychain lookup,
or only files under the directory, is `[unknown]`. Cache paths stay
put unless `COPILOT_CACHE_HOME` is set `[verified-docs]`.

Environment-variable tokens select an identity for a process this
application launches, without writing the live store `[verified-docs]`.
They also **override** a stored OAuth login for that process
`[verified-docs]`. That is a launch-time override, not a durable switch
of the interactive last-used account.

Under `.agents/docs/PROJECT_RULES.md` and `docs/research/README.md`, a
**write** path may not rest on `[inferred]` or `[unknown]`. Safe to
**read** from docs (detect, do not write):

- Presence of the documented `copilot-cli` keychain service name.
- Presence of `~/.copilot/config.json` as application state, not as a
  proven token map.
- Documented slash commands `/user list` and `/user switch` as the
  vendor UI.
- Launch-time `COPILOT_GITHUB_TOKEN` / `GH_TOKEN` / `GITHUB_TOKEN` for a
  child process.

Still unsafe to **write**:

- Replacing `config.json`, rewriting `loggedInUsers`, or pairing those
  writes with a keychain edit.
- Assuming `COPILOT_HOME` is enough to switch identity the way
  `CODEX_HOME` was probed for Codex. That probe has not been done here.
- Treating `gh auth` as a Copilot account this manager may rewrite.
- Treating IDE GitHub sign-in as the same store as Copilot CLI.

A write-safe Copilot adapter is `[unknown]`. Until a signed-in host
observation or published application source closes the store and switch
questions, any Copilot adapter must remain **read-only** for credential
files and the OS keychain. Shipping `activate_account` against this
note would be the lock-out path this project exists to avoid.

## 6. Quota and usage signals

Official billing unit for current individual and organization plans is
**GitHub AI Credits** `[verified-docs]`. Official docs state that 1 AI
credit equals `$0.01` USD `[verified-docs]`. Included credits do not
carry over. Individual included usage resets at `00:00:00` UTC on the
first day of each calendar month `[verified-docs]`. Code completions
and next-edit suggestions are not billed in AI credits on paid plans
`[verified-docs]`. Copilot CLI usage draws from the same AI-credit
allowance as the IDE and GitHub.com `[verified-docs]`.

Vendor-published individual paid-plan table, fetched 2026-09-20 from
the official plans and individual billing pages `[verified-docs]`. These
are not local measurements and must not be hard-coded into an adapter:

| Plan         | Price per month (USD) | Base credits | Flex allotment | Total monthly AI credits |
| ------------ | --------------------- | ------------ | -------------- | ------------------------ |
| Copilot Pro  | 10                    | 1,000        | 500            | 1,500                    |
| Copilot Pro+ | 39                    | 3,900        | 3,100          | 7,000                    |
| Copilot Max  | 100                   | 10,000       | 10,000         | 20,000                   |

Vendor-published organization seats, same fetch `[verified-docs]`:
Copilot Business `$19` USD per granted seat per month with 1,900 AI
credits per user per month; Copilot Enterprise `$39` USD per granted
seat per month with 3,900 AI credits per user per month. Additional
organization usage is documented at `$0.01` USD per AI credit.

Copilot Free and Copilot Student are documented as having an AI-credit
allowance. Copilot Free is documented as 2,000 code completions per
month `[verified-docs]`.

Where official docs say to **look** at usage `[verified-docs]`:

- Individual: GitHub.com **Billing and licensing → AI usage**, or
  Copilot settings → Usage.
- Business / Enterprise member: Copilot settings → Usage this cycle.
- IDE status-bar / Copilot icon quota UI in VS Code, Visual Studio,
  JetBrains, Xcode, and Eclipse.
- Copilot CLI `/usage` (session metrics; token-based-billing rows may
  show AI credits).
- Copilot CLI `/clikit` (preview; docs mention quota info).
- `copilot help billing`.
- REST billing report endpoints for user / org / enterprise AI-credit
  and legacy premium-request usage. Those endpoints are account-admin
  or user billing APIs, not a local file.

A older **premium request** model is still documented as legacy
`[verified-docs]`. The pinned `github/copilot-cli` README still says
each prompt reduces a monthly premium-request quota by one. Current
billing docs use AI credits. Which counter a given CLI binary displays
is `[unknown]` without a host install. Official usage-based-billing
docs recommend Copilot CLI **1.0.48** or later so clients do not show
outdated billing terminology `[verified-docs]`.

No local quota or price file is documented `[unknown]`. Nothing
machine-readable on disk has been observed. A write-safe quota or price
adapter is `[unknown]`.

## 7. API surface and base-URL override

GitHub-hosted Copilot traffic uses GitHub Copilot service hosts, not a
user-documented plan-session base-URL override `[verified-docs]`.
Official allowlist / troubleshooting hosts include
`https://copilot-proxy.githubusercontent.com`,
`https://origin-tracker.githubusercontent.com`,
`https://api.githubcopilot.com`, `https://*.githubcopilot.com/*`, and
plan-scoped `https://*.individual.githubcopilot.com`,
`https://*.business.githubcopilot.com`, and
`https://*.enterprise.githubcopilot.com` `[verified-docs]`. GHE.com uses
`https://copilot-proxy.SUBDOMAIN.ghe.com/` and related subdomain hosts
`[verified-docs]`. `https://api.github.com/copilot_internal/*` is listed
for user management `[verified-docs]`.

HTTP proxy for Copilot: `HTTPS_PROXY`, `https_proxy`, `HTTP_PROXY`,
`http_proxy` (highest priority first). An `https://` proxy URL is
documented as unsupported `[verified-docs]`.

BYOK **does** override the model endpoint for Copilot CLI
`[verified-docs]`. When `providers.json` declares any provider or
model, it takes precedence over legacy `COPILOT_PROVIDER_*` environment
variables `[verified-docs]`. Environment variables:

- `COPILOT_PROVIDER_BASE_URL` (required for env-based BYOK)
- `COPILOT_PROVIDER_TYPE` — `openai` (default), `azure`, or `anthropic`
- `COPILOT_PROVIDER_API_KEY`, `COPILOT_PROVIDER_BEARER_TOKEN`
- `COPILOT_PROVIDER_API_KEY_COMMAND` (prints a fresh key; outranks
  `COPILOT_PROVIDER_API_KEY`)
- `COPILOT_PROVIDER_WIRE_API`, `COPILOT_PROVIDER_AZURE_API_VERSION`
- `COPILOT_PROVIDER_MODEL_ID`, `COPILOT_PROVIDER_WIRE_MODEL`
- `COPILOT_MODEL` (also `--model`)

`openai` is documented as the OpenAI Chat Completions-compatible shape
(OpenAI, Ollama, vLLM, and similar) `[verified-docs]`. Whether a
manager relay can sit in front of **GitHub-hosted** Copilot plan
traffic the way some OpenAI-compatible clients accept a base URL is
`[unknown]`. BYOK is a different billing and auth path and does not
prove that override.

## 8. Risks and constraints

- **The live credential is probably not a single swappable file.**
  Official docs put the OAuth token in the OS keychain first, and only
  then in plaintext `config.json`. Writing `config.json` while the
  keychain still holds `copilot-cli` can no-op or desynchronize
  identity `[inferred]`. A write path must not assume Codex-style
  `auth.json` replacement.
- **Environment variables silently win.** A leftover `GH_TOKEN` or
  `GITHUB_TOKEN` overrides `copilot login` `[verified-docs]`. A manager
  that exports GitHub tokens for `gh` can change the Copilot identity
  of a child without touching the store.
- **Classic PATs are rejected.** `ghp_` in an env var is ignored
  interactively and refuses non-interactive start if it is the only
  credential `[verified-docs]`.
- **Org policy can disable the CLI** even with a valid GitHub login
  `[verified-docs]`. Authentication is not entitlement.
- **`/logout` is local-only.** The GitHub OAuth grant remains until
  revoked on github.com `[verified-docs]`.
- **`config.json` is not a settings file.** User edits belong in
  `settings.json`. Deleting or rewriting `config.json` resets
  authentication `[verified-docs]`.
- **`loggedInUsers` is a field name, not a switch API.** Docs say not
  to edit `config.json`. Multi-account state may live in the keychain,
  in that field, or in both `[unknown]`.
- **MCP OAuth / MCP secrets are a different store.** Do not treat
  `mcp-oauth-config/` or `mcp-secrets/` as the GitHub Copilot login
  `[verified-docs]`.
- **IDE and CLI may be independent.** Switching one is not known to
  switch the other `[unknown]`.
- **`gh copilot` is retired.** Detect `copilot`, not a `gh` extension
  leftover `[verified-docs]`.
- **Namespace collision.** Other tools can also use a `~/.copilot`
  directory name. Official detection should use the documented file set
  plus the `copilot` binary, not the directory name alone `[inferred]`.
- **Billing terminology is in motion.** Premium-request text still
  appears in older and packaging docs. Hard-coding a price or a quota
  counter from this note would go stale.

## 9. Open questions

- **Credential store.** What is the exact on-disk or keychain payload
  after a real `copilot login`? Is the token only in the `copilot-cli`
  keychain item, only in `config.json`, or both? What is the
  `loggedInUsers` schema (key names only)? What is the Windows
  Credential Manager target name?
- **Switching.** Does `/user switch` persist for the next process, or
  only inside the current interactive session? Must the keychain and
  `config.json` move together? Does `COPILOT_HOME` relocate identity
  the way `CODEX_HOME` does for Codex, including keychain lookup?
- **Quota / price.** Is there any local, machine-readable quota or
  price file? Can `/usage` or `copilot help billing` be parsed as a
  stable schema? Which counter (AI credits vs premium requests) does a
  given CLI version print? Vendor list prices change; what snapshot is
  safe for a dashboard?
- **Write-safe adapter.** Is there any adapter write — isolated
  `COPILOT_HOME`, env-only launch, or a documented non-interactive
  account select — that is safe against a live default home and a
  running `copilot` process? Until that is proven, do not implement
  credential-file or keychain writes.
- Does plaintext `config.json` appear in the runtime credential
  check order, and under what `storeTokenPlaintext` / prompt outcome?
- Do the IDE and Copilot CLI share one GitHub OAuth grant?
- Does a copied keychain item or a copied `config.json` still work
  against the vendor?
- What happens when `COPILOT_GITHUB_TOKEN` and a stored multi-account
  keychain login disagree across an interactive `/user switch`?
- Windows and macOS paths, confirmed on real hosts.
- Historical `gh copilot` extension storage, if any leftover hosts
  still matter.
