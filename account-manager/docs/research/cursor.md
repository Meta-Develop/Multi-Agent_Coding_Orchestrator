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
| `~/.cursor/auth.json`                                 | File store (`AGENT_CLI_CREDENTIAL_STORE=file`) | `[verified-docs]`  |
| macOS Keychain `cursor-access-token`                  | Staff-named Keychain service                   | `[verified-docs]`  |
| macOS Keychain `cursor-refresh-token`                 | Staff-named Keychain service                   | `[verified-docs]`  |
| macOS Keychain `cursor-api-key`                       | Staff-named Keychain service                   | `[verified-docs]`  |
| Default persist (Linux/Windows)                       | **Not found**                                  | `[unknown]`        |

## 3. Credential format

The file-store document at `~/.cursor/auth.json` is named `[verified-docs]`
when `AGENT_CLI_CREDENTIAL_STORE=file`. Its schema is `[unknown]`. This note
and the adapter record presence of that regular file only; they do not read,
parse, or log it. An empty `~/.cursor` directory or a missing file is not
credentials.

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

- Official docs document browser login as `agent login` (this note's observed
  binary is `cursor-agent`). The documentation still does not identify the
  protocol, so the adapter reports that path as `AuthKind::Unknown`
  `[verified-docs]`.
- Set `NO_OPEN_BROWSER=1` to print the login URL without opening a browser
  `[verified-docs]`.
- `agent logout` signs out and clears stored authentication `[verified-docs]`.
- The CLI also accepts an API key through `CURSOR_API_KEY` or `--api-key`
  `[verified-docs]`.
- `agent status` (alias `whoami`) reports whether the CLI is authenticated,
  account information, and the current endpoint configuration
  `[verified-docs]`.
- `agent status --format json` is a documented machine-readable status mode
  `[verified-docs]`. The pages below do not specify that JSON schema
  `[verified-docs]`.
- Cursor says browser-login credentials are stored securely and locally, but
  does not identify a write-safe store path `[verified-docs]`.

Official sources re-checked on 2026-09-20. Canonical CLI pages now live under
`cursor.com/docs`. The 2026-08-20 `docs.cursor.com/en/cli/reference/...` URLs
no longer serve those pages.

Primary persist pages:

- <https://cursor.com/docs/cli/reference/authentication>
- <https://cursor.com/docs/cli/reference/parameters>

Also checked for a persist path on 2026-09-20:

- <https://cursor.com/docs/cli/reference/configuration>
- <https://cursor.com/docs/cli/reference/output-format>
- <https://cursor.com/docs/cli/overview>
- <https://cursor.com/docs/cli/installation>
- <https://cursor.com/docs/cli/using>
- <https://cursor.com/docs/cli/headless>
- <https://cursor.com/docs/cli/changelog>
- <https://cursor.com/help/integrations/cli>
- <https://cursor.com/docs/sdk/typescript>
- Previously cited: <https://docs.cursor.com/en/cli/reference/authentication>
- Previously cited: <https://docs.cursor.com/en/cli/reference/parameters>

Related official persist statements:

- The 2026-08-11 CLI changelog says the Windows uninstaller can delete
  `~/.cursor`, "the folder that stores CLI credentials" `[verified-docs]`.
  That is a directory claim, not a default-persist file or keyring service
  name.
- The 2026-06-29 CLI changelog documents `AGENT_CLI_CREDENTIAL_STORE=file` to
  store credentials unencrypted in an owner-only file for sandboxes without
  macOS Keychain `[verified-docs]`. It does not name that file.
- Cursor forum staff (Mohit, 2026-08-04) named the file-store path and the
  macOS Keychain services `[verified-docs]`. After
  `export AGENT_CLI_CREDENTIAL_STORE=file` and `agent login`, "Tokens land
  in `~/.cursor/auth.json` with restricted permissions." Keychain cleanup
  uses `security delete-generic-password -s cursor-access-token -a
cursor-user` and the same for `cursor-refresh-token` and `cursor-api-key`.
  Source:
  <https://forum.cursor.com/t/errsecitemnotfound-couldnt-find-your-saved-login-in-the-macos-keychain/167325>
  The thread is a macOS Keychain bug. The named `~/.cursor/auth.json` is
  the file-store path, not proof of Linux or Windows default persist.
- The 2026-07-20 and March 2026 CLI changelogs mention macOS Keychain
  failures at CLI startup and over SSH `[verified-docs]`. They do not name
  the Keychain service.
- Configuration docs describe `cli-config.json` as CLI settings, not
  credentials `[verified-docs]`.
- SDK docs store `Cursor.auth.login()` keys in `~/.cursor/sdk/auth.json` and
  say that stored login does not read credentials from a local Cursor app
  installation `[verified-docs]`. That path is not the CLI persist location.

File-store path `~/.cursor/auth.json` is therefore `[verified-docs]` when
`AGENT_CLI_CREDENTIAL_STORE=file`. macOS Keychain service names
`cursor-access-token`, `cursor-refresh-token`, and `cursor-api-key` are
`[verified-docs]`. Default Linux and Windows persist targets remain
`[unknown]`. An Electron Local Storage / `Network/Cookies` /
`Local State` guess is still `[inferred]` and is **not write-safe**.
Isolated HOME relocation is not officially documented (no `GROK_HOME`
equivalent). Naming these stores does not make switch write-safe.

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

Switching is `[unknown]`, and deliberately so. Naming the file-store path
and the macOS Keychain services does not make a write-safe switch. Isolated
HOME relocation is not officially documented (no `GROK_HOME` equivalent).
The Cursor adapter must remain **read-only** and must not implement
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

- Where does default `cursor-agent login` persist on Linux and Windows
  (exact file path or keyring service name)? File-store path
  `~/.cursor/auth.json` is named only when `AGENT_CLI_CREDENTIAL_STORE=file`
  `[verified-docs]`. macOS Keychain service names are named
  `[verified-docs]`. Default Linux/Windows persist remains `[unknown]`. This
  still blocks switching and live OAuth write paths. Official 2026-09-20
  docs still do not name a write-safe store.
- Do the editor and the CLI share one credential?
- Is there a supported multi-account mechanism already?
- What is the schema of `agent status --format json`? The `--format json`
  flag is documented `[verified-docs]`; the payload is not.
- Does `cursor-agent status` make a network request when local authentication
  state is sufficient?
