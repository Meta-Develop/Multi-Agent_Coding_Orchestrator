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

`rateLimitTier` names the tier but is not a counter `[verified-local]`.

This section records official 2026-09-20 Claude Code 5-hour / 7-day window
_surfaces_. It does not establish Observed utilization, `resetsAt`, or
price. Claude `account.observe` quota stays unknown. `reset-probe` and
`operation.prepare` stay unadvertised.

Official pages re-fetched 2026-09-20 (vendor prose, not a host probe and
not Observed CAM JSON):

- <https://code.claude.com/docs/en/statusline>
- <https://code.claude.com/docs/en/costs>
- <https://code.claude.com/docs/en/errors>

### Statusline `rate_limits`

The statusline command receives session JSON on stdin. Official docs name
these window fields `[verified-docs]`
(<https://code.claude.com/docs/en/statusline>):

- `rate_limits.five_hour.used_percentage` and
  `rate_limits.seven_day.used_percentage`: percentage of the 5-hour or
  7-day rate limit consumed, from 0 to 100.
- `rate_limits.five_hour.resets_at` and
  `rate_limits.seven_day.resets_at`: Unix epoch seconds when that window
  resets.
- Optional `rate_limits.spend_limit.used_percentage` and
  `rate_limits.spend_limit.resets_at`: behind a Claude apps gateway, the
  percentage used of the spend limit that applies to you, and the Unix
  epoch seconds when its period resets. The percentage runs from 0 to
  100, or above 100 once you exceed the limit. Requires Claude Code
  v2.1.251 or later.

The same page describes `five_hour` as a rolling window and `seven_day`
as a weekly window `[verified-docs]`
(<https://code.claude.com/docs/en/statusline>).

Presence `[verified-docs]`
(<https://code.claude.com/docs/en/statusline>):

- The `rate_limits` object appears only for claude.ai Pro and Max
  subscribers, or behind a Claude apps gateway that sets a spend limit,
  and only after the first API response in the session.
- Each window (`five_hour`, `seven_day`, `spend_limit`) may be
  independently absent.
- Claude Code drops a window once its `resets_at` time passes.
- Absence is not zero. A missing object or window is not
  `utilization = 0`.

That JSON is statusline script stdin, not non-interactive Observed quota.
Do not parse these fields into CAM Observed utilization, `resetsAt`, or
price.

### Interactive `/usage`

`/usage` is an interactive plan-bar and session-cost screen, not
non-interactive Observed JSON `[verified-docs]`
(<https://code.claude.com/docs/en/costs>).

- The Session block's `Total cost` is computed locally from token counts
  at list price, unless a managed `modelPricing` table is in effect. The
  official page calls the figure an estimate and points at the Claude
  Console Usage page for authoritative billing. Session `Total cost` is
  catalog / estimate, not Observed billed USD.
- Claude Max and Pro subscribers have usage included in their
  subscription, so the session cost figure is not a billing counter.
  Subscribers see plan usage bars, activity stats, and a usage breakdown
  on the same interactive screen.
- When the usage-request fails, most often because the usage endpoint is
  rate limited, `/usage` may show the last usage bars loaded on that
  machine within the past 60 minutes, with a `Showing last-known usage`
  note. Those last-known bars are stale, not Observed.

### Teams and Enterprise windows

On Claude for Teams and Enterprise plans, each member's Claude Code
usage draws from a per-seat allowance that resets on a rolling five-hour
window and a weekly window `[verified-docs]`
(<https://code.claude.com/docs/en/costs>). The allowance is shared with
Claude chat and Cowork. The errors page names the corresponding
interactive messages `You've hit your session limit` and
`You've hit your weekly limit` `[verified-docs]`
(<https://code.claude.com/docs/en/errors>). Those messages are vendor UI,
not Observed CAM quota.

### Vendor wait is not CAM `reset-probe`

On Claude Code v2.1.234 or later, an interactive session signed in with
a claude.ai subscription can wait and continue the interrupted task
after the plan window resets. Developers can pick that wait from
`/rate-limit-options`. Fleet control is the managed setting
`autoContinueAtUsageLimit` `[verified-docs]`
(<https://code.claude.com/docs/en/costs>). The errors page describes the
same vendor wait line,
`Usage limit reached · continuing automatically at 3:45pm · esc to cancel`
`[verified-docs]` (<https://code.claude.com/docs/en/errors>). That is
Claude waiting on its own reset, not CAM `reset-probe`. Do not advertise
`reset-probe` or `operation.prepare` from this note.

### Local caches stay `[unknown]`

Usage utilisation appears in client-side caches under keys such as
`cachedUsageUtilization` in `~/.claude.json` `[verified-local]`, but
whether that is stable, documented, or safe to depend on is `[unknown]`.
Do not parse `cachedUsageUtilization` or other `~/.claude.json` caches
as Observed quota.

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
- Official statusline `rate_limits` and interactive `/usage` are vendor
  surfaces, not CAM Observed quota `[verified-docs]`
  (<https://code.claude.com/docs/en/statusline>,
  <https://code.claude.com/docs/en/costs>). Treating a missing window as
  zero, treating session `Total cost` as Observed billed USD, or treating
  last-known `/usage` bars as live Observed would invent quota.
- Do not parse `cachedUsageUtilization` or other `~/.claude.json` caches as
  Observed quota. Those keys remain `[unknown]`.
- Vendor `autoContinueAtUsageLimit` and `/rate-limit-options` are Claude
  waiting on its own reset `[verified-docs]`
  (<https://code.claude.com/docs/en/costs>). They are not CAM
  `reset-probe`. This note does not advertise `reset-probe` or
  `operation.prepare`.

## 9. Open questions

- Are `cachedUsageUtilization` and related `~/.claude.json` cache keys a
  dependable quota source? Still `[unknown]`. Do not parse them as
  Observed quota.
- Official 2026-09-20 pages name statusline stdin `rate_limits` and
  interactive `/usage` only
  (<https://code.claude.com/docs/en/statusline>,
  <https://code.claude.com/docs/en/costs>,
  <https://code.claude.com/docs/en/errors>). They do not publish a
  non-interactive Observed quota JSON. Observed utilization, `resetsAt`,
  and price remain absent. Claude `account.observe` quota stays unknown.
- Windows and macOS paths, confirmed on real hosts.
