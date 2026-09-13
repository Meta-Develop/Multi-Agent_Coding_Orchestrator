# Claude Code (Anthropic)

## 1. Identity

- Tool: `claude`, distributed as Claude Code.
- Vendor: Anthropic.
- Version observed: **2.1.212** `[verified-local]`.
- OS observed: Linux (NixOS), August 2026.

The write-path claims below were checked on 2026-08-20 against Anthropic's
installed vendor-distributed native executable resolved from `claude`
(SHA-256 `e86c501459949ec5df0873b0be9608a6b1ac20604c095510ffad4d9fec4730e6`).
Its embedded build metadata identifies version `2.1.212`, build time
`2026-07-16T16:40:30Z`, and Git SHA
`8b2783a8f907ce5c5ad1241ecdbab0ff3301c617` `[verified-local]`.

## 2. Config locations

| Path                                                                                     | Purpose                          | Marker             |
| ---------------------------------------------------------------------------------------- | -------------------------------- | ------------------ |
| `~/.claude/.credentials.json`                                                            | OAuth credentials                | `[verified-local]` |
| `~/.claude.json`                                                                         | Global client state and identity | `[verified-local]` |
| `~/.claude/settings.json`                                                                | User settings                    | `[verified-local]` |
| `~/.claude/projects/`, `sessions/`, `history.jsonl`, `shell-snapshots/`, `file-history/` | Session and history data         | `[verified-local]` |
| `~/.claude/plugins/`, `cache/`, `telemetry/`, `ide/`                                     | Client-managed state             | `[verified-local]` |

Session and history data belong to the machine and the user, not to an account.
A switch must leave them alone.

## 3. Credential format

`~/.claude/.credentials.json` `[verified-local]`, key names only. On the
observed 2.1.212 installation its only top-level key was `claudeAiOauth`:

```jsonc
{
  "claudeAiOauth": {
    "accessToken": "<redacted>",
    "refreshToken": "<redacted>",
    "expiresAt": 0, // epoch milliseconds
    "refreshTokenExpiresAt": 0,
    "scopes": ["<string>"],
    "subscriptionType": "<string>",
    "rateLimitTier": "<string>",
  },
}
```

The vendor's `H8t` token-persistence function read-modify-writes exactly the
top-level `claudeAiOauth` member. It replaces that object with
`accessToken`, `refreshToken`, `expiresAt`, `refreshTokenExpiresAt`, `scopes`,
`subscriptionType`, `rateLimitTier`, and optional `clientId`; it does not
replace the surrounding credential document `[verified-local]`.

`~/.claude.json` is a large document whose top level includes `oauthAccount`,
`userID`, `machineID`, `mcpServers`, `projects`, and many caches and onboarding
flags `[verified-local]`. A key-and-type-only inspection found this shape for
`oauthAccount` (values were neither printed nor recorded):

```jsonc
{
  "oauthAccount": {
    "accountUuid": "<redacted>",
    "emailAddress": "<redacted>",
    "organizationUuid": "<redacted>",
    "displayName": "<redacted>",
    "hasExtraUsageEnabled": false,
    "billingType": "<string>",
    "accountCreatedAt": "<string>",
    "subscriptionCreatedAt": "<string>",
    "ccOnboardingFlags": {},
    "claudeCodeTrialEndsAt": null,
    "claudeCodeTrialDurationDays": null,
    "seatTier": null,
    "profileFetchedAt": 0,
    "organizationRole": "<string>",
    "workspaceRole": null,
    "organizationName": "<redacted>",
    "organizationType": "<string>",
    "organizationRateLimitTier": "<string>",
    "userRateLimitTier": null,
  },
}
```

The object is forward-compatible client state: the adapter should copy the
whole `oauthAccount` object rather than maintain a nested-field allowlist
`[verified-local]`.

## 4. Authentication flow

- `claude` performs a browser sign-in producing the OAuth material above
  `[verified-docs]`.
- `expiresAt` and `refreshTokenExpiresAt` are both present, so both lifetimes
  are locally observable — useful for showing expiry state without a network
  call (`FR-2`).
- `subscriptionType` and `rateLimitTier` are present locally, which gives the
  dashboard a plan label even where no usage counter exists `[verified-local]`.
- On the observed Linux build, with standard production OAuth and no separate
  secure-storage override, `CLAUDE_CONFIG_DIR=<isolated-dir> claude auth login`
  resolves credentials to `<isolated-dir>/.credentials.json` and global state
  to `<isolated-dir>/.claude.json`. The source resolves the credential directory
  from `CLAUDE_SECURESTORAGE_CONFIG_DIR` first, then `CLAUDE_CONFIG_DIR`, so an
  isolated login runner must set both variables to the same new empty directory.
  This verifies the two config write targets only; no authentication or network
  probe was run `[verified-local]`.
- In the vendor `aOt` login path, Claude Code clears the previous Anthropic
  auth, writes `oauthAccount` through `b8t`, writes `claudeAiOauth` through
  `H8t`, and then augments `oauthAccount` with roles. `b8t`'s only top-level
  mutation of `~/.claude.json` is `oauthAccount`; `H8t`'s only top-level
  mutation of `.credentials.json` is `claudeAiOauth` `[verified-local]`.

## 5. Account switching mechanics

Identity is **split across two files**: OAuth material is the
`claudeAiOauth` object in `.credentials.json`, and the corresponding account
profile is the `oauthAccount` object in `~/.claude.json`. The vendor login path
writes both objects, and its auth-status path reads identity from
`oauthAccount`; a complete offline OAuth switch therefore has to move both
objects `[verified-local]`.

The exact switch allowlist for 2.1.212 is `[verified-local]`:

| File                          | Replace from stored account      | Preserve from live file      |
| ----------------------------- | -------------------------------- | ---------------------------- |
| `~/.claude/.credentials.json` | top-level `claudeAiOauth` object | every other top-level member |
| `~/.claude.json`              | top-level `oauthAccount` object  | every other top-level member |

No other top-level field in `~/.claude.json` is account identity. In
particular, `userID` and `machineID` have separate vendor `get-or-create`
functions that generate and persist random identifiers independently of
login. `projects`, `mcpServers`, caches, onboarding flags, and unknown future
top-level fields are outside the switch allowlist and must survive unchanged
`[verified-local]`.

A correct switch therefore has to:

1. Back up both files.
2. Validate both stored objects and both live documents before the first write.
3. Read-modify-write `claudeAiOauth` in `.credentials.json` atomically.
4. Read-modify-write `oauthAccount` in `~/.claude.json` atomically.
5. If either write or verification fails, restore both files from the same
   pre-switch backup before reporting failure.

That "surgical edit of a large, client-owned document" is the reason Claude Code
is a medium-difficulty adapter rather than a low one. The client rewrites
`~/.claude.json` frequently, so the edit must be a read-modify-write that
tolerates concurrent rewrites, not a stored whole-file replacement.

Claude Code serializes the two files independently `[verified-local]`:

- Its credential backend takes a write lock on a `.storage-write` target under
  the Claude config directory, re-reads the credential object under that lock,
  applies a mutation, and atomically replaces `.credentials.json`.
- Its global-config writer takes `~/.claude.json.lock`, re-reads
  `~/.claude.json` under the lock, applies the mutation, makes a backup, and
  atomically replaces `~/.claude.json`. It contains explicit stale-write and
  auth-loss checks.
- The two locks are independent. There is no vendor transaction or common lock
  spanning both files; the observed vendor login itself updates
  `oauthAccount` before it writes `claudeAiOauth`.

Consequently two atomic renames are not by themselves a two-file transaction.
An external adapter that does not participate in both vendor locks must refuse
to switch while a Claude process may be running, and must treat the pair as one
backup/rollback unit. If process state cannot be determined, the safe result is
to refuse the write `[verified-local]`.

`ANTHROPIC_API_KEY` provides a separate API-key path that bypasses the OAuth
files entirely `[verified-docs]`.

## 6. Quota and usage signals

`rateLimitTier` names the tier but is not a counter `[verified-local]`. Usage
utilisation appears in client-side caches under keys such as
`cachedUsageUtilization` in `~/.claude.json` `[verified-local]`, but whether
that is stable, documented, or safe to depend on is `[unknown]`.

## 7. API surface and base-URL override

Anthropic Messages format. `ANTHROPIC_BASE_URL` redirects the client
`[verified-docs]`, which makes Claude Code a viable relay client. Whether the
override is honoured under plan authentication rather than an API key is
`[unknown]`.

## 8. Risks and constraints

- `~/.claude.json` is large, frequently rewritten, and undocumented. Editing it
  is the highest-risk write in the initial adapter set.
- The file mixes account identity with machine state, so a naive whole-file swap
  would move a user's project list and MCP servers between accounts.
- The vendor has independent per-file locks but no cross-file transaction. A
  third-party switch that races a running Claude process can still produce a
  mutually inconsistent pair even if each individual replacement is atomic
  `[verified-local]`.

## 9. Open questions

- Are `cachedUsageUtilization` and related keys a dependable quota source?
- Windows and macOS paths, confirmed on real hosts.
