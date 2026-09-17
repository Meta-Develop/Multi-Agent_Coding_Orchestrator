# Grok CLI (xAI)

## 1. Identity

- Tool: `grok`, shipped as Grok Build.
- Vendor: xAI / SpaceXAI.
- Version observed: **0.2.93** `[verified-local]`.
- OS observed: Linux (NixOS), August 2026.
- Source inspected (August 2026): first-party repository `xai-org/grok-build`
  (Apache-2.0). The README states that this tree is the Rust source for the
  `grok` CLI/TUI installed via `x.ai/cli/install.sh`, and that it is synced
  periodically from the SpaceXAI monorepo. The examined tree is GitHub commit
  `d92c5b0b8582fda358de1f97446aa74af44a464f`, whose `SOURCE_REV` is
  `9dccd1f00ec13332134a37750b64c047b14dc120`.

This update was made from first-party source and the user guide shipped in
that tree. It is not a second on-host observation of the 0.2.93 binary.
Findings from the tree describe the published source. They do not, by
themselves, prove that this host's binary matches it.

Claims established by inspecting first-party Rust source at the pinned revision
are marked `[verified-source]`. Claims stated in the repository README or
shipped user guide remain `[verified-docs]`. Neither marker is the same as
`[verified-local]` against this host's binary: the tree can lag the shipped CLI.

Pinned-source provenance and documentation:

- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/README.md
- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/SOURCE_REV
- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/crates/codegen/xai-grok-pager/docs/user-guide/02-authentication.md

Code evidence for every `[verified-source]` claim below:

- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/crates/codegen/xai-grok-shell/src/auth/model.rs
- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/crates/codegen/xai-grok-shell/src/auth/config.rs
- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/crates/codegen/xai-grok-shell/src/auth/manager.rs
- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/crates/codegen/xai-grok-shell/src/auth/manager/lock.rs
- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/crates/codegen/xai-grok-shell/src/auth/storage.rs
- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/crates/codegen/xai-grok-shell/src/auth/recovery.rs
- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/crates/codegen/xai-grok-home/src/lib.rs
- https://raw.githubusercontent.com/xai-org/grok-build/d92c5b0b8582fda358de1f97446aa74af44a464f/crates/codegen/xai-grok-active-sessions/src/lib.rs

## 2. Config locations

The grok home is `$GROK_HOME` when that variable is set and non-empty,
otherwise `<home>/.grok`. The env value is returned verbatim, not
canonicalized `[verified-source]`. On this host the default home
`~/.grok` is what was listed `[verified-local]`. `$GROK_HOME` itself was
not exercised against 0.2.93.

| Path                                                                       | Purpose                                   | Marker              |
| -------------------------------------------------------------------------- | ----------------------------------------- | ------------------- |
| `$GROK_HOME` or `~/.grok`                                                  | Whole client home                         | `[verified-source]` |
| `~/.grok/auth.json`                                                        | Credentials, keyed per provider scope     | `[verified-local]`  |
| `~/.grok/auth.json.lock`                                                   | Advisory lock for the above               | `[verified-local]`  |
| `~/.grok/config.toml`                                                      | Client configuration, marketplace sources | `[verified-local]`  |
| `~/.grok/managed_config.lock`, `.config-init.lock`                         | Config locks                              | `[verified-local]`  |
| `~/.grok/active_sessions.json`                                             | Running session registry                  | `[verified-local]`  |
| `~/.grok/active_sessions.lock`                                             | Lock for that registry                    | `[verified-local]`  |
| `~/.grok/models_cache.json`                                                | Cached model list                         | `[verified-local]`  |
| `~/.grok/agent_id`, `sessions/`, `logs/`, `skills/`, `bundled/`, `vendor/` | Client state                              | `[verified-local]`  |

The session lock file is named `active_sessions.lock`, not
`active_sessions.json.lock` `[verified-source]`. An earlier reading of the
local listing as `active_sessions.json` plus `.lock` was ambiguous on that
point.

`$GROK_AUTH_PATH`, when set, overrides the `auth.json` path independently of
the grok home `[verified-source]`. A `$GROK_HOME` relocation then no longer
moves the credential file.

macOS is expected to use the same `~/.grok` layout `[inferred]`. Windows is
expected to use `%USERPROFILE%\.grok` `[inferred]`. Both need confirmation on
a real host.

## 3. Credential format

`~/.grok/auth.json` `[verified-local]` is a JSON object whose keys look like
`"<oidc-issuer>::<client-uuid>"`. That observation still holds. The keys are
not user identities. They are **provider scopes** computed from configuration
as `"{issuer}::{client_id}"` `[verified-source]`. `AuthStore` is a map from
scope string to `GrokAuth`. `AuthManager` computes one scope at construction
and every read, write, and clear of the session token targets that single key.

Reserved non-OIDC keys also exist in the same file `[verified-source]`:

- `xai::api_key` — plain API-key auth (`grok login --api-key`, desktop login).
- `https://accounts.x.ai/sign-in` — legacy pre-OIDC scope. A WebLogin token
  under that key is skipped on lookup and forces re-authentication.

Several entries in a real file usually mean these reserved scopes sitting
beside the current OIDC scope, not two user accounts. The default client id
is a configuration constant, not a property of the signed-in user, so two
different xAI accounts compute the same `"{issuer}::{client_id}"` key. A
team principal and a personal principal also produce the same base scope.
Logging in as a second account therefore overwrites the first
`[verified-source]`.

On-host shape, key names only `[verified-local]`:

```jsonc
{
  "<issuer>::<client-uuid>": {
    "key": "<redacted>",
    "auth_mode": "<string>",
    "create_time": "<timestamp string>",
    "user_id": "<redacted>",
    "email": "<redacted>",
    "first_name": "<redacted>",
    "profile_image_asset_id": "<redacted>",
    "principal_type": "<string>",
    "principal_id": "<redacted>",
    "team_id": "<redacted>",
    "coding_data_retention_opt_out": false,
    "refresh_token": "<redacted>",
    "expires_at": "<timestamp string>",
    "oidc_issuer": "<url>",
    "oidc_client_id": "<uuid>",
  },
}
```

`GrokAuth` in the published source declares further optional fields that this
host's file was not compared against: `last_name`, `team_name`, `team_role`,
`organization_id`, `organization_name`, `organization_role`,
`user_blocked_reason`, `team_blocked_reasons`, and the deprecated
`has_grok_code_access`. Several of the locally observed strings are `Option`
in the struct. That field-set comparison remains `[unknown]`.

## 4. Authentication flow

OIDC — the entry carries `oidc_issuer` and `oidc_client_id` alongside a
`refresh_token` and an `expires_at`, so both the flow and the lifetime are
locally observable `[verified-local]`.

`grok login` starts the sign-in flow again and **replaces** the cached
session. `grok logout` clears cached credentials
`[verified-docs]`. There is no "select a different map entry" command
`[verified-source]`.

An API-key mode is first-class: `AuthMode::ApiKey`, the `xai::api_key` scope,
and `XAI_API_KEY` `[verified-source]`. The earlier inference from the
`auth_mode` field name is now backed by vendor source and the user guide.

Grok refreshes access tokens automatically in the background. Credentials
without a server-provided expiry fall back to a 30-day lifetime
`[verified-docs]`.

Auth precedence, highest to lowest `[verified-docs]`:

1. Per-model `api_key` or `env_key` under `[model.<name>]` in `config.toml`.
2. The active session token in `auth.json`.
3. `XAI_API_KEY`.

A `config.toml` per-model key therefore outranks a swapped session file.

## 5. Account switching mechanics

The earlier note recorded several keys in `auth.json` and inferred that the
CLI selects an active identity. The observation of several keys was right.
The interpretation was wrong. The CLI does not pick among user identities in
that map. It reads and writes one provider-scope key. A second login overwrites
that key. Switching by marking a different entry active is not a mechanism
this tool has `[verified-source]`.

`$GROK_HOME` is the switching mechanism worth designing around. Keep one grok
home per account and point the environment variable at the right one. That
never mutates a file the user's default home owns. It only works for sessions
this application launches, or for shells the user configures. It has not been
probed against 0.2.93 on this host the way `CODEX_HOME` was probed for Codex.

**Refresh-token family revocation.** Restoring a previously saved `auth.json`
can revoke the live grant. The CLI refreshes access tokens in the background
and rewrites the file. The snapshot then holds a refresh token the holder has
already spent. Sending that spent token to the IdP double-spends the family
and revokes it. An adapter that writes `auth.json` in place while a grok
process is running, or that restores a snapshot onto a home that process is
using, can brick the account. Refuse the write.

Under `.agents/docs/PROJECT_RULES.md`, a write path may depend only on
`[verified-local]`, `[verified-source]`, or `[verified-docs]` claims. A write
path may rest on pointing `$GROK_HOME` at a per-account directory that already
contains that account's `auth.json`, because the vendor home crate is the
single source of truth and returns a non-empty `$GROK_HOME` verbatim. It may
not rest on treating `auth.json` map keys as switchable user identities, on
copying a saved `auth.json` over a home a grok process is using, or on assuming
`$GROK_AUTH_PATH` still follows `$GROK_HOME`.

An in-place swap of `auth.json` is still a candidate only when no grok process
holds that home, and only after the lock protocol below has been acquired.
Even then, a saved snapshot can already be stale relative to a refresh the
CLI performed while it was running. Vendor acceptance of a copied file against
the live 0.2.93 binary remains `[unknown]`.

`active_sessions.json` records open TUI sessions. `list_in` enumerates the
recorded entries. `collect_crashed` returns entries whose PIDs are dead and
drops them from the file `[verified-source]`. A switch performed while a session
is registered against the target home should be refused.

### Lock protocol for `auth.json.lock`

This is the vendor's own contract `[verified-source]`. Implement against it.
Do not invent a simpler flock.

- The lock file is `auth.json.lock` next to `auth.json`.
- Mutual exclusion is `flock(LOCK_EX|LOCK_NB)` on that file.
- The holder writes a `PID:UNIX_TIMESTAMP` record into the lock file and
  re-dates it on a heartbeat of about 5 seconds while a refresh-sized hold
  is live.
- A waiter that sees a **dead** holder PID unlinks the lock file immediately
  and retries on a fresh inode (unlink-to-break).
- A waiter that sees a **live** holder whose timestamp is older than 60
  seconds treats it as stuck. It does not break on first sight. It
  re-observes for about 12 seconds of awake time, then unlinks if still
  stale. Breaking earlier can double-spend a refresh token the holder has
  already sent and revoke the token family.
- Callers about to spend a refresh token or write `auth.json` must
  re-validate that the held lock still refers to the live `(inode, dev)` of
  `auth.json.lock`. A lock broken by unlink lives on a deleted inode.
- Advisory non-blocking acquires (cleanup, logout) take the flock only if
  it is free. They still write holder info so waiters can identify them.

### Write protocol for `auth.json`

Vendor write path `[verified-source]`:

- Unique temp name `auth.json.<pid>.<seq>.tmp` beside the target.
- Write, flush, `sync_all`, then rename into place. On Windows the target is
  removed first because rename cannot replace.
- Re-assert owner-only mode (`0600` on Unix) after the rename.
- A drop guard removes the temp file on any failure before rename.
- If the atomic path fails with disk full, an in-place truncate-and-rewrite
  is attempted, with a best-effort restore of the prior bytes on failure.
- A corrupt file is renamed aside to `auth.json.corrupt.<millis>` before a
  recovery write.
- Reads re-tighten permissions on the live file.

## 6. Quota and usage signals

`models_cache.json` exists and may carry availability information. Its
contents were not inspected `[unknown]`. No quota counter was observed
`[verified-local]`.

## 7. API surface and base-URL override

xAI publishes an OpenAI-compatible API
(`https://docs.x.ai/docs/overview`) `[verified-docs]`. The CLI accepts
`GROK_CLI_CHAT_PROXY_BASE_URL` as an API-endpoint override pointing at a
proxy `[verified-docs]`. Whether that override is honoured for a plan
session the way a relay needs it, rather than only for enterprise OIDC, is
untested on this host `[unknown]`.

## 8. Risks and constraints

- **Background refresh races any in-place write.** A running CLI rewrites
  `auth.json` on its own refresh schedule `[verified-source]`. A snapshot taken
  while the CLI runs goes stale. Restoring it can revoke the token family
  (§5). Refuse a write while any process named `grok` is using that home,
  and while `auth.json.lock` is held or `active_sessions.json` lists a live
  PID.
- **A running CLI adopts a swapped file on its next 401.** Recovery first
  re-reads `auth.json` under the lock and accepts a differing on-disk token
  `[verified-source]`. The user guide also states that changes to `auth.json`
  are picked up on the next API call without a restart `[verified-docs]`. That
  is not a safe switch mechanism. It is how a restored stale snapshot gets
  spent.
- **`config.toml` outranks `auth.json`.** A per-model `api_key` or `env_key`
  wins over the session token, which wins over `XAI_API_KEY`
  `[verified-docs]`. Switching homes or files does not change the identity
  the CLI actually uses if `config.toml` still supplies a key.
- **Namespace collision.** `superagent-ai/grok-cli` is an unaffiliated
  community CLI. Its README stores settings in `~/.grok/user-settings.json`.
  Its storage layer writes `~/.grok/grok.db`. The presence of `~/.grok`
  alone does not identify the official CLI `[verified-docs]`. Detect the
  official tree by `auth.json` / `config.toml` / the `grok` binary, not by
  the directory name. Evidence, GitHub commit
  `fb97af83f06dca873281d60168430f06c8de6324`:

  - https://raw.githubusercontent.com/superagent-ai/grok-cli/fb97af83f06dca873281d60168430f06c8de6324/README.md
  - https://raw.githubusercontent.com/superagent-ai/grok-cli/fb97af83f06dca873281d60168430f06c8de6324/src/storage/db.ts

- Advisory locks are real here, not decorative. The protocol is in §5.
  Ignoring it risks corrupting the credential file and, worse, revoking the
  live grant.
- The entry contains personal fields (`email`, `first_name`,
  `profile_image_asset_id`). They must be masked before display and must
  never be written to a log or a diagnostic bundle.

## 9. Open questions

- Does the shipped 0.2.93 binary match this source at `SOURCE_REV`
  `9dccd1f00ec13332134a37750b64c047b14dc120`?
- What does the on-host file's key set look like against `GrokAuth`'s
  fields? Extra keys, missing keys, and whether `coding_data_retention_opt_out`
  is present.
- Does `$GROK_HOME` relocate credential lookup for 0.2.93 on this host the
  way `CODEX_HOME` does for Codex? The source says it does. That has not been
  probed locally.
- Does a copied `auth.json` still succeed at a model request against the
  vendor, when no grok process is using the home?
- Does `models_cache.json` expose anything quota-shaped?
- Windows and macOS paths, confirmed on real hosts.
