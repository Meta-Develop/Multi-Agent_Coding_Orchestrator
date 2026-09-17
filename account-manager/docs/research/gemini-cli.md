# Gemini CLI (Google)

## 1. Identity

- Tool: `gemini`.
- Vendor: Google.
- Version observed on host: **0.47.0** `[verified-local]`.
- OS observed: Linux (NixOS), August 2026.
- Source inspected (August 2026): official repository `google-gemini/gemini-cli`
  at `main` commit `571851b1077a51cef757146ce13f9da887326bec` (2026-08-18),
  package version `0.56.0-nightly.20260806.g761f604c1`. The same OAuth path
  constants were also present on the `v0.47.0` tag. That source tag does not
  prove that the locally installed binary was built from it.

This update was made from first-party source inspection in August 2026. It is
not a second on-host observation of a signed-in install. A directory listing of
`~/.gemini` on this host still shows `projects.json` only (plus two leftover
`projects.json.<uuid>.tmp` files). No `oauth_creds.json`, `google_accounts.json`,
or `settings.json` exists here. File contents under `~/.gemini` were not read.

Pinned code evidence for every `[verified-source]` claim below:

- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/config/storage.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/utils/paths.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/utils/userAccountManager.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/code_assist/oauth2.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/code_assist/oauth-credential-storage.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/core/contentGenerator.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/cli/src/config/settings.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/cli/src/config/settingsSchema.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/cli/src/validateNonInterActiveAuth.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/cli/src/gemini.tsx

Additional compatibility, type, and documentation citations:

- https://raw.githubusercontent.com/google-gemini/gemini-cli/v0.47.0/packages/core/src/config/storage.ts
- https://raw.githubusercontent.com/googleapis/google-auth-library-nodejs/main/src/auth/credentials.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/main/docs/reference/configuration.md

Claims established by inspecting first-party code at the pinned revision are
marked `[verified-source]`. Claims from prose documentation remain
`[verified-docs]`. Neither marker is `[verified-local]`: nobody on this project
has yet opened these files on a signed-in host, and source does not prove the
installed `0.47.0` binary matches.

## 2. Config locations

The global directory is `GEMINI_DIR` = `.gemini` under `homedir()`. `homedir()`
returns `$GEMINI_CLI_HOME` when that variable is set, otherwise `os.homedir()`.
On Linux that is `~/.gemini` `[verified-source]`.

| Path                              | Purpose                                                                       | Marker              |
| --------------------------------- | ----------------------------------------------------------------------------- | ------------------- |
| `~/.gemini/projects.json`         | Project registry; empty on the observed host                                  | `[verified-local]`  |
| `~/.gemini/settings.json`         | User settings, including `security.auth.selectedType`                         | `[verified-source]` |
| `~/.gemini/oauth_creds.json`      | Default-path OAuth tokens for the CLI Google login (`OAUTH_FILE`)             | `[verified-source]` |
| `~/.gemini/google_accounts.json`  | Active email plus historical emails (`GOOGLE_ACCOUNTS_FILENAME`). Not tokens. | `[verified-source]` |
| `~/.gemini/mcp-oauth-tokens.json` | MCP OAuth tokens, not the CLI Google login                                    | `[verified-source]` |
| `~/.gemini/a2a-oauth-tokens.json` | A2A OAuth tokens, not the CLI Google login                                    | `[verified-source]` |
| `~/.gemini/installation_id`       | Installation id. Not a credential.                                            | `[verified-source]` |
| `$GEMINI_CLI_HOME/.gemini/…`      | Relocates the whole global dir when `GEMINI_CLI_HOME` is set                  | `[verified-source]` |
| `$GOOGLE_APPLICATION_CREDENTIALS` | Secondary credential file tried after `oauth_creds.json`                      | `[verified-source]` |

`settings.json` is also stated in official configuration docs as
`~/.gemini/settings.json` `[verified-docs]`.

Settings merge in this order, with later sources winning: schema defaults,
system defaults, user settings, trusted workspace settings, and system settings.
`GEMINI_CLI_SYSTEM_SETTINGS_PATH` overrides the platform system-settings path
`[verified-source]`.

When `GEMINI_FORCE_ENCRYPTED_FILE_STORAGE=true`, the CLI stores the Google login
in a keychain-backed store under service `gemini-cli-oauth` and key
`main-account` instead of writing `oauth_creds.json` `[verified-source]`. Whether
that flag is on by default on any real OS is `[unknown]`.

macOS and Windows are expected to use the same `.gemini` layout under the user
home directory, because the code joins `os.homedir()` with `.gemini`
`[inferred]`. That still needs confirmation on a real host.

## 3. Credential format

### `~/.gemini/oauth_creds.json`

One flat `google-auth-library` `Credentials` object, written by
`JSON.stringify(credentials, null, 2)` with mode `0o600` `[verified-source]`.
The key names and optional field types below come from the cited
`google-auth-library` interface `[verified-docs]`. The on-disk subset is whatever
the OAuth client currently holds, so a given file may omit some of these keys.
Not observed on a signed-in host.

```jsonc
{
  "access_token": "<redacted>", // string | null
  "refresh_token": "<redacted>", // string | null
  "expiry_date": 0, // number | null, milliseconds
  "token_type": "<string>", // string | null, typically "Bearer"
  "id_token": "<redacted>", // string | null
  "scope": "<string>", // space-delimited scopes
}
```

The writer serialises a single object, not a map of identities. Encrypted
storage uses the same Google `Credentials` fields under the single key
`main-account`. This file holds **one** token set `[verified-source]`.

### `~/.gemini/google_accounts.json`

Interface `UserAccounts` in `userAccountManager.ts` `[verified-source]`. Key
names only. Values are email strings; never record a real one.

```jsonc
{
  "active": "<redacted>", // string | null — current Google account email
  "old": ["<redacted>"], // string[] — previously used emails
}
```

`old` is a history list, not a second live login. Caching a new email moves the
previous `active` into `old` and writes a new `active`. Clearing credentials
sets `active` to `null` and appends the former active email to `old`. Tokens
are not stored in this file `[verified-source]`.

## 4. Authentication flow

Two documented modes `[verified-docs]`:

1. **OAuth sign-in** through a Google account, in a browser
   `[verified-docs]`. Its source auth type is `oauth-personal`
   (`AuthType.LOGIN_WITH_GOOGLE`) `[verified-source]`.
2. **Gemini Developer API key** supplied through `GEMINI_API_KEY`. For
   `AuthType.USE_GEMINI`, the source resolves that variable into the content
   generator's API key and disables Vertex mode. Its auth type string is
   `gemini-api-key` `[verified-source]`.

On successful OAuth, the CLI writes `oauth_creds.json` (unless encrypted
storage is forced) and then writes the signed-in email into
`google_accounts.json` `[verified-source]`. The selected auth **mode** is stored
separately as `security.auth.selectedType` in `settings.json`
`[verified-source]`. That field is a mode (`oauth-personal`, `gemini-api-key`,
and others), not an account identity.

`getAuthTypeFromEnv()` inspects environment variables in this order
`[verified-source]`: `GOOGLE_GENAI_USE_GCA=true` → OAuth;
`GOOGLE_GENAI_USE_VERTEXAI=true` → Vertex; `GOOGLE_GEMINI_BASE_URL` → gateway;
`GEMINI_API_KEY` → Gemini Developer API; then `CLOUD_SHELL=true` or
`GEMINI_CLI_USE_COMPUTE_ADC=true` → compute ADC.

For non-interactive validation, configured `security.auth.selectedType` wins;
the environment detector is used only when it is absent. If merged
`security.auth.enforcedType` exists and differs from the effective type, the
CLI refuses authentication `[verified-source]`.

When loading dotenv files, the CLI sets only keys not already present in the
process environment. A `GEMINI_API_KEY` supplied to the launched child is
therefore not overwritten by a dotenv entry `[verified-source]`.

Interactive startup behavior when `selectedType` is absent and both
`oauth_creds.json` and `GEMINI_API_KEY` are present remains `[unknown]`.

## 5. Account switching mechanics

- **API-key accounts**: switching the credential is purely environmental — set
  `GEMINI_API_KEY` for the launched process `[verified-source]`. No Gemini file
  is touched by credential selection. For non-interactive launches, this selects
  Gemini Developer API auth when `selectedType` is already `gemini-api-key`, or
  when it is absent and no earlier environment selector is set. Another
  configured type wins over environment detection, and an incompatible
  `enforcedType` refuses authentication.
- **OAuth accounts**: knowing the files exist does **not** establish a switch.
  Source shows enough to list and detect, not enough to write.

What the source does establish about OAuth identity `[verified-source]`:

- `oauth_creds.json` is one `Credentials` document. There is no per-account
  key inside it.
- `google_accounts.json` can name several emails, but only `active` is current.
  `old` emails have no token in that file and no second file of their own.
- Logout (`clearCachedCredentialFile`) deletes `oauth_creds.json` (or the
  keychain entry), nulls `active`, and keeps the email in `old`. It also
  clears an in-process `oauthClientPromises` cache.
- Login writes tokens and then the email. The two files are updated by
  different functions. Nothing in the inspected code swaps a stored token set
  by rewriting `google_accounts.json` alone.

What remains `[unknown]` for an OAuth switch, and must stay `[unknown]`:

- Whether replacing `oauth_creds.json` on disk is enough for the next process
  to use that identity.
- Whether `google_accounts.json` must be rewritten in the same operation.
- Whether `settings.json` `security.auth.selectedType` must also move.
- Whether the CLI caches identity anywhere else (keychain, in-memory cache of
  an already-running process, ADC / `GOOGLE_APPLICATION_CREDENTIALS`).
- Whether a refresh rewrite racing a switch can lose one side's write.

Do not implement a live-home OAuth file-swap against this note.

Isolated-home OAuth add has already shipped. In-app Google loopback writes
an isolated `GEMINI_CLI_HOME` with the Gemini CLI file pair
(`oauth_creds.json` plus `google_accounts.json`) and a managed
`settings.json` whose `security.auth.selectedType` is `oauth-personal`.
Those writes follow the `[verified-source]` `GEMINI_CLI_HOME` relocation
and the Credentials, `UserAccounts`, and settings shapes above. They do
not write live `~/.gemini/settings.json`. This is not a signed-in host
observation.

This application also lists a live `~/.gemini` OAuth row when
`oauth_creds.json` exists. That listing is read-only: it detects the
file, masks `google_accounts.json` `active`, and treats `old` as
history. The live row omits `expires_at` by design: the creds check
is presence-only and does not parse token fields. It does not write
the live tree. File-swap of the live `~/.gemini` tree remains
`[unknown]` and out of scope.

## 6. Quota and usage signals

`[unknown]`. Free-tier limits are documented as request-rate limits
`[verified-docs]`, but no local signal was observed.

## 7. API surface and base-URL override

Gemini `generateContent` format `[verified-docs]`. Google also publishes an
OpenAI-compatible endpoint `[verified-docs]`, which gives the relay two possible
integration shapes for the same vendor.

## 8. Risks and constraints

Reading and detecting OAuth state is now in bounds, including a
read-only live listing of `~/.gemini` when `oauth_creds.json` is
present. Writing an OAuth switch of that live tree is not.
`docs/research/README.md` and `.agents/docs/PROJECT_RULES.md` allow a
read/detect path to rest on `[verified-source]` or `[verified-docs]`. They
forbid a write path from resting on `[inferred]` or `[unknown]`.

Safe to **read** (key names and presence only; never log values):

- Existence of `~/.gemini/oauth_creds.json` as a signed-in-token signal.
- `google_accounts.json` shape: `active` and `old`. Mask emails before display.
- `settings.json` `security.auth.selectedType` as the selected **mode**.
- Treat `old` as historical emails, not as concurrently usable logins.

Still unsafe to **write**:

- Replacing `oauth_creds.json`, rewriting `google_accounts.json`, or pairing
  those writes as a switch. The switch mechanism itself is `[unknown]`.
- Assuming the file path is the only store. Encrypted/keychain storage is a
  real code path.
- Assuming a running CLI will notice a file swap. There is an in-process
  client cache.
- Shipping an OAuth switch as the first Gemini adapter path.

The API-key path remains the only write-safe switch of an already-configured
live home. Isolated-home OAuth add has already shipped and still does not
replace files under the live `~/.gemini` tree. Live listing is read-only.
A live-home OAuth file-swap must still wait until a signed-in host
observation, or equivalent, closes the `[unknown]` items in §5. No
`[verified-local]` signed-in claim is made here.

## 9. Open questions

Answered by this update and removed:

- Where are OAuth credentials persisted after `gemini` sign-in?
- Is there a settings file? (Yes. `~/.gemini/settings.json`.)
- Does `oauth_creds.json` hold one identity or several? (One.)

Still open:

- Does the CLI support multiple concurrent OAuth accounts natively, with more
  than one live token set? Source says no for these two files. A signed-in host
  could still surprise us.
- Does `settings.json` carry account identity beyond auth **mode**? Source
  shows `selectedType` / `enforcedType` / `useExternal` only. Confirm on a
  signed-in host that no other identity field appears.
- In interactive startup, what does the CLI do when `selectedType` is absent
  and both `oauth_creds.json` and `GEMINI_API_KEY` are present?
- Does replacing `oauth_creds.json` switch the next process to that identity?
  Must `google_accounts.json` move with it?
- Is `GEMINI_FORCE_ENCRYPTED_FILE_STORAGE` ever on by default, and does a
  default install write to the OS keychain rather than `oauth_creds.json`?
- Which `Credentials` keys actually appear on disk after a real sign-in?
- Windows and macOS paths, confirmed on real hosts.
- Local quota or usage signal, confirmed on a real host.
