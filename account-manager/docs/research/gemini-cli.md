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

Pinned Code Assist entitlement evidence for §6a, same revision
`571851b1077a51cef757146ce13f9da887326bec`:

- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/code_assist/types.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/code_assist/setup.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/code_assist/server.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/billing/billing.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/packages/core/src/config/config.ts
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/docs/resources/quota-and-pricing.md
- https://raw.githubusercontent.com/google-gemini/gemini-cli/571851b1077a51cef757146ce13f9da887326bec/docs/resources/faq.md

The same `UserTierId` named constants, `LoadCodeAssistResponse` / `RetrieveUserQuotaResponse` field names, and the Google AI Pro row in `quota-and-pricing.md` were still present on official `main` commit `cfbcaa8df13ea4610bb379b377b56d62980c0032` (2026-09-18). That later tip is a second pin, not a second host observation.

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

## 6a. Google AI Pro / subscription entitlement

This section is the #409 evidence record for Google AI Pro (and related
Gemini subscription) entitlement through **the same Gemini CLI**. It does
not replace §6. No adapter, cargo, or live-account change is implied.

Existing Gemini OAuth files and a successful `oauth-personal` login do
**not** establish Google AI Pro model access or quota. That matches
`docs/MACO_INTEGRATION.md` §8. The local credential shapes in §3 have no
subscription, plan, tier, or remaining-quota keys `[verified-source]`.
`security.auth.selectedType` remains an auth **mode**, not a plan
`[verified-source]`.

### Official serving status

Official Google developer documentation, last updated 2026-09-02 UTC when
fetched on 2026-09-20, states that starting 2026-06-18 Gemini Code Assist
IDE extensions **stopped serving** requests for Gemini Code Assist for
individuals, Google AI Pro, and Google AI Ultra, and that this also
applies to Gemini CLI. As part of that deprecation, Login with Google is
no longer a way to access those consumer tiers in the IDE extensions or
Gemini CLI `[verified-docs]`:

- https://developers.google.com/gemini-code-assist/docs/deprecations/code-assist-individuals
- https://developers.google.com/gemini-code-assist/docs/deprecations

The 2026-05-19 Google Developers Blog announcement gives the same
2026-06-18 consumer cutoff and says Gemini Code Assist Standard or
Enterprise licenses, and paid Gemini / Gemini Enterprise Agent Platform
API keys, remain valid Gemini CLI paths `[verified-docs]`:

- https://developers.googleblog.com/en/an-important-update-transitioning-gemini-cli-to-antigravity-cli/

Those pages are official vendor prose. They are not Git-SHA pins. The
consumer-account page recorded `Last updated 2026-09-02 UTC` on fetch.

The official Gemini for Google Cloud quotas page, last updated
2026-09-16 UTC when fetched on 2026-09-20, documents combined Gemini CLI
/ agent-mode daily request limits only for Code Assist **Standard** and
**Enterprise**. It does not name Google AI Pro or Ultra as a current
Gemini CLI quota edition `[verified-docs]`:

- https://developers.google.com/gemini-code-assist/resources/quotas

Pinned Gemini CLI documentation at `571851b1077a51cef757146ce13f9da887326bec`
still describes Google-account login as including Gemini Code Assist
(Individual), Google AI Pro, and Google AI Ultra, and tells subscribers
to confirm AI Pro / Ultra at https://one.google.com
`[verified-docs]`. The same table and FAQ text remain on
`cfbcaa8df13ea4610bb379b377b56d62980c0032`. That is a documentation
conflict with the later official deprecation pages, not a local
observation. Do not treat the pinned CLI table as proof that a current
OAuth session still receives AI Pro.

### Remote fields in the same CLI

Google-account (`oauth-personal`) traffic uses the Code Assist private
API at `https://cloudcode-pa.googleapis.com` / `v1internal`
(`[verified-source]`; overridable with `CODE_ASSIST_ENDPOINT` /
`CODE_ASSIST_API_VERSION`). Entitlement is requested after auth, not
read from `oauth_creds.json`.

`CodeAssistServer.loadCodeAssist` POSTs `loadCodeAssist` and deserialises
`LoadCodeAssistResponse` `[verified-source]`:

```jsonc
{
  "currentTier": {
    /* GeminiUserTier or null */
  },
  "allowedTiers": [
    /* GeminiUserTier */
  ],
  "ineligibleTiers": [
    /* IneligibleTier */
  ],
  "cloudaicompanionProject": "<redacted>",
  "paidTier": {
    /* GeminiUserTier or null */
  },
}
```

`GeminiUserTier` key names `[verified-source]`:

```jsonc
{
  "id": "<string>", // UserTierId
  "name": "<string>",
  "description": "<string>",
  "userDefinedCloudaicompanionProject": false,
  "isDefault": false,
  "privacyNotice": {},
  "hasAcceptedTos": false,
  "hasOnboardedPreviously": false,
  "availableCredits": [
    {
      "creditType": "GOOGLE_ONE_AI", // or "CREDIT_TYPE_UNSPECIFIED"
      "creditAmount": "<string>", // int64 JSON string; no value recorded here
    },
  ],
}
```

Named `UserTierId` constants in that source are only `free-tier`,
`legacy-tier`, and `standard-tier`. The TypeScript type is those
constants **or** `string`, and the comment says the listed IDs are a
subset because the server list is updated often `[verified-source]`.
There is **no** named `UserTierId` constant for Google AI Pro or Ultra
at either pinned revision. Mapping any returned `id` or `name` onto
"Google AI Pro" is therefore `[unknown]` until a live response is
observed.

`setupUser` prefers `paidTier.id` / `paidTier.name` over
`currentTier.id` / `currentTier.name`, then falls back to
`UserTierId.STANDARD` when both IDs are missing `[verified-source]`.
That STANDARD fallback is a client default, not a vendor entitlement
observation. On a VPC-SC `SECURITY_POLICY_VIOLATED` error,
`loadCodeAssist` also synthesises `{ currentTier: { id: UserTierId.STANDARD } }`
and does not call the server a second time `[verified-source]`. Treat a
bare `standard-tier` id from those paths as untrusted for plan
detection.

Returned `UserData` (`projectId`, `userTier`, `userTierName`,
`paidTier`, `hasOnboardedPreviously`) is cached in process memory
(WeakMap + 30s TTL), not written under `.gemini` `[verified-source]`.
`Config.getUserTier`, `getUserTierName`, and `getUserPaidTier` read that
in-memory Code Assist server object `[verified-source]`.

`G1_CREDIT_TYPE` is the string `GOOGLE_ONE_AI`. The billing helper sums
`availableCredits` entries of that type. The type comment calls them
"Google One AI credits". That is a **credit wallet** field, not a
subscription-plan enum. Presence of `GOOGLE_ONE_AI` is not established
as proof of Google AI Pro `[verified-source]`; whether a live account
returns it is `[unknown]`.

`CodeAssistServer.retrieveUserQuota` POSTs `retrieveUserQuota` with
`{ project, userAgent? }` and deserialises `RetrieveUserQuotaResponse`
`[verified-source]`:

```jsonc
{
  "buckets": [
    {
      "remainingAmount": "<string>",
      "remainingFraction": 0,
      "resetTime": "<string>",
      "tokenType": "<string>",
      "modelId": "<string>",
    },
  ],
}
```

`Config.refreshUserQuota` keeps `lastRetrievedQuota` and a
`modelQuotas` map **in memory only**. `storage.ts` at this pin has no
quota filename `[verified-source]`. When `remainingAmount` is present
and `remainingFraction > 0`, the client **computes**
`limit = round(remaining / remainingFraction)`. When `remainingAmount`
is absent, the client sets `limit = 100` and scales remaining from the
fraction `[verified-source]`. That `100` is a client placeholder, not a
vendor field. A future Observed row must use the raw bucket fields
(`remainingAmount`, `remainingFraction`, `resetTime`, `modelId`,
`tokenType`) and must not publish that placeholder as quota.

Official CLI docs say `/stats model` shows the current session's token
usage and "the limits associated with your current quota"
`[verified-docs]`. That command was not run here.

### Can any field become Observed?

This update did not sign in, call `loadCodeAssist` or
`retrieveUserQuota`, or read a signed-in home. **No** subscription,
plan, tier, or quota field is Observed in this note. Published daily
request figures in the pinned CLI quota table and on the Cloud quotas
page are catalog text `[verified-docs]`. They are not remaining-quota
observations, and they are not repeated here as if they were measured.

Fields that **can** become Observed later, without inventing numbers,
if a live authenticated Code Assist call returns them and the values
are recorded as received:

| Field                                                               | RPC                                                     | Marker if observed live |
| ------------------------------------------------------------------- | ------------------------------------------------------- | ----------------------- |
| `paidTier.id`, `paidTier.name`                                      | `loadCodeAssist`                                        | `[verified-local]`      |
| `currentTier.id`, `currentTier.name`                                | `loadCodeAssist`                                        | `[verified-local]`      |
| `allowedTiers[]` / `ineligibleTiers[]` `id` / `tierId` / `tierName` | `loadCodeAssist`                                        | `[verified-local]`      |
| `availableCredits[].creditType`                                     | `loadCodeAssist`                                        | `[verified-local]`      |
| `availableCredits[].creditAmount`                                   | `loadCodeAssist` or generate-content `remainingCredits` | `[verified-local]`      |
| `buckets[].remainingAmount`                                         | `retrieveUserQuota`                                     | `[verified-local]`      |
| `buckets[].remainingFraction`                                       | `retrieveUserQuota`                                     | `[verified-local]`      |
| `buckets[].resetTime`                                               | `retrieveUserQuota`                                     | `[verified-local]`      |
| `buckets[].modelId`                                                 | `retrieveUserQuota`                                     | `[verified-local]`      |
| `buckets[].tokenType`                                               | `retrieveUserQuota`                                     | `[verified-local]`      |

Fields that **cannot** become Observed from material already in hand:

| Candidate                                                        | Why it stays unobserved                                                 |
| ---------------------------------------------------------------- | ----------------------------------------------------------------------- |
| Any key in `oauth_creds.json` / `google_accounts.json`           | No plan, tier, or quota keys `[verified-source]`.                       |
| `security.auth.selectedType`                                     | Auth mode only `[verified-source]`.                                     |
| Named `UserTierId` `free-tier` / `legacy-tier` / `standard-tier` | Client constants, not an AI Pro label `[verified-source]`.              |
| Client `UserTierId.STANDARD` fallback or VPC-SC stub             | Synthesised locally `[verified-source]`.                                |
| Client `modelQuotas.limit`, including `limit = 100`              | Derived or invented in `refreshUserQuota` `[verified-source]`.          |
| Pinned CLI or Cloud published daily maxima                       | Catalog `[verified-docs]`, not an account reading.                      |
| Google One "Manage subscription" confirmation                    | Official FAQ path `[verified-docs]`; not a CLI field; not fetched here. |

Until a live `loadCodeAssist` / `retrieveUserQuota` response is
recorded, Google AI Pro entitlement through Gemini CLI remains
`[unknown]`. After the official 2026-06-18 consumer shutdown, that live
call may fail rather than return an AI Pro tier. Either outcome still
needs observation; do not infer it.

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
- After the official 2026-06-18 consumer shutdown, does a current
  Google-account `loadCodeAssist` or `retrieveUserQuota` call still
  return a paid tier, or does it fail for AI Pro / Ultra / individual
  accounts?
- Which live `paidTier.id` / `paidTier.name` (if any) correspond to
  Google AI Pro? Source has no named AI Pro `UserTierId`.
- Does a live `retrieveUserQuota` bucket include `remainingAmount`, or
  only `remainingFraction` (the client then invents `limit = 100`)?
- Does `GOOGLE_ONE_AI` `availableCredits` appear on a real AI Pro
  account, and is it a subscription proof or only a credit wallet?
