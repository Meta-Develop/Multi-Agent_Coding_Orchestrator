# Cursor (Anysphere)

## 1. Identity

- Tools: the Cursor editor, and `cursor-agent`, its CLI.
- Vendor: Anysphere.
- Version observed: `cursor-agent` **2026.06.26** `[verified-local]`.
- OS observed: Linux (NixOS), August 2026.

## 2. Config locations

| Path                                                  | Purpose                                        | Marker             |
| ----------------------------------------------------- | ---------------------------------------------- | ------------------ |
| `~/.config/cursor/cli-config.json`                    | CLI settings — no credential material observed | `[verified-local]` |
| `~/.cursor/agents/`                                   | Agent state                                    | `[verified-local]` |
| `~/.cursor/projects/`                                 | Project state                                  | `[verified-local]` |
| `~/.cursor/extensions/`, `plugins/`, `skills-cursor/` | Editor and CLI extensions                      | `[verified-local]` |
| `~/.cursor/ai-tracking/ai-code-tracking.db`           | Local SQLite tracking database                 | `[verified-local]` |
| `~/.cursor/argv.json`                                 | Electron launch arguments                      | `[verified-local]` |
| Credential store                                      | **Not found**                                  | `[unknown]`        |

## 3. Credential format

`~/.config/cursor/cli-config.json` was inspected in full at the key-name level
and contains only settings `[verified-local]`:

```jsonc
{
  "version": 0,
  "editor": { "vimMode": false },
  "display": {
    "showLineNumbers": false,
    "showThinkingBlocks": false,
    "showStatusIndicators": false,
    "showStatusLineRunningTime": false,
  },
  "notifications": false,
  "hints": false,
  "rewind": false,
  "suggestNextPrompt": false,
  "hasChangedDefaultModel": false,
  "permissions": { "allow": ["<string>"], "deny": [] },
  "approvalMode": "<string>",
  "sandbox": { "mode": "<string>", "networkAccess": "<string>" },
  "network": { "useHttp1ForAgent": false },
  "attribution": {
    "attributeCommitsToAgent": false,
    "attributePRsToAgent": false,
  },
}
```

No token, key, or session field appears anywhere in it.

## 4. Authentication flow

- `cursor-agent login` uses a browser authentication flow. The documentation
  does not identify its protocol, so the adapter reports that path as
  `AuthKind::Unknown` `[verified-docs]`.
- The CLI also accepts an API key through `CURSOR_API_KEY` or `--api-key`
  `[verified-docs]`.
- `cursor-agent status` reports whether the CLI is authenticated, account
  information, and the current endpoint configuration `[verified-docs]`.
- Cursor says browser-login credentials are stored securely and locally, but
  does not identify the store `[verified-docs]`.

Official sources checked on 2026-08-20:

- <https://docs.cursor.com/en/cli/reference/authentication>
- <https://docs.cursor.com/en/cli/reference/parameters>

Since no credential file was found in either observed config location, the
session most plausibly lives in the OS keyring or inside the editor's Electron
storage (`Local Storage`, `Network/Cookies`, or a `Local State`-encrypted blob)
`[inferred]`.

## 5. Account switching mechanics

Read-only CLI account discovery does not require the credential path:
`cursor-agent status` is the vendor-documented account-status surface
`[verified-docs]`. The two checked official pages do not specify a stable
machine-readable schema `[verified-docs]`. The adapter recognizes the inferred
text markers `Logged in as`, `Logged in`, `Login successful!`, `not
authenticated`, `authentication required`, and `not logged in` `[inferred]`.
An unfamiliar response is a read error, not evidence that the user is logged
out. If an authenticated response
contains an email after `Logged in as`, the adapter masks it before returning a
single active, unstored CLI account. It otherwise returns the same account with
no display identity and `AuthKind::Unknown` `[inferred]`.

This path lists only the CLI identity. Whether the editor and CLI authenticate
independently remains `[unknown]`, so an editor installation without
`cursor-agent` has no evidence-backed account source.

Switching is `[unknown]`, and deliberately so. Until the store is found, the
Cursor adapter must remain **read-only** and must not implement
`activate_account`.

This is a design position, not a gap to be filled by guessing. Writing a switch
against an unverified credential store is the single most likely way this
project could lock a user out of a working tool.

## 6. Quota and usage signals

`[unknown]`. `ai-tracking/ai-code-tracking.db` is a local SQLite database whose
schema was not inspected; it tracks code attribution rather than quota
`[inferred]`.

## 7. API surface and base-URL override

`[unknown]`.

## 8. Risks and constraints

- If the credential lives in the OS keyring, switching may be feasible and clean.
  If it lives in Electron storage encrypted with an OS-bound key, switching may
  be infeasible without reimplementing that encryption — which would be both
  brittle and ethically questionable.
- Editor and CLI may authenticate independently. Both need establishing.
- The human-readable `status` format may change. Unknown output must fail closed
  instead of being treated as a logged-out account `[inferred]`.

## 9. Open questions

- Where does `cursor-agent login` persist its session? This blocks switching.
- Do the editor and the CLI share one credential?
- Does a keyring entry exist, and under what service name?
- Is there a supported multi-account mechanism already?
- Does `cursor-agent status` offer a documented machine-readable output mode?
- Does `cursor-agent status` make a network request when local authentication
  state is sufficient?
