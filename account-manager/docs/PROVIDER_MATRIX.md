# Provider matrix

One-page comparison of every provider in scope. Detail and evidence live in
[`research/`](research/); this table is the summary an implementer reads first.

Confidence markers follow [`research/README.md`](research/README.md).
Observations were made on Linux (NixOS) in August 2026 against the tool versions
listed in each research note.

| Provider        | Descriptor auth kinds | Maturity     | Capabilities                                                     | Implemented account behavior                                                                                                                                                                                                                                                                                                                                                                                                        | Quota signal                                                                                       |
| --------------- | --------------------- | ------------ | ---------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| **Codex CLI**   | OAuth, API key        | Experimental | `add-account`, `switch-account`, `delete-account`                | Adds a manager-created stored account populated by vendor login, replaces live `auth.json` behind a restorable backup, and forgets stored copies. Local `login status` follows the replaced file `[verified-local]`; vendor acceptance of a copied credential is untested `[unknown]`.                                                                                                                                              | Empty snapshot vector. No verified numeric signal.                                                 |
| **Grok CLI**    | OAuth, API key        | Experimental | `add-account`, `switch-account`, `delete-account`, `launch-tool` | Creates and retains a managed vendor home. Selection affects only an app-owned child by setting `GROK_HOME` and removing inherited `GROK_AUTH_PATH`; forgetting metadata does not delete the home. Those vendor environment semantics are `[verified-source]`; the local binary binding is unproven.                                                                                                                                | Empty snapshot vector. No counter observed `[verified-local]`; `models_cache.json` is `[unknown]`. |
| **Claude Code** | OAuth, API key        | Experimental | `add-account`, `switch-account`, `delete-account`                | Isolated `claude auth login` into a managed home. Switch copies stored `claudeAiOauth` and `oauthAccount` into the live `~/.claude` pair behind a restorable backup and journal. Forgetting a stored copy does not sign out live Claude. Vendor acceptance of a copied credential is untested `[unknown]`.                                                                                                                          | Empty snapshot vector. `billingType` may supply a plan label, not utilization.                     |
| **Gemini CLI**  | OAuth, API key        | Experimental | `add-account`, `switch-account`, `delete-account`, `launch-tool` | OAuth add is in-app Google loopback that writes an isolated `GEMINI_CLI_HOME`, including managed `oauth-personal` settings. Listing may include a read-only `gemini-cli-on-disk` OAuth row when live `oauth_creds.json` is present. Launch sets that home and `GOOGLE_GENAI_USE_GCA=true`. Forgetting OAuth metadata retains the home. API-key accounts stay in `CredentialStore`. Live `~/.gemini` file-swap remains out of scope. | Empty snapshot vector. Published limits do not establish current utilization.                      |
| **Cursor**      | Unknown, API key      | Experimental | None                                                             | Read-only Cursor CLI listing through `cursor-agent status`. Browser authentication and API-key input are documented, but credential storage and switching remain unknown.                                                                                                                                                                                                                                                           | Empty snapshot vector. No verified numeric signal.                                                 |

`ProviderDescriptor.capabilities` uses the wire values `add-account`,
`switch-account`, `delete-account`, and `launch-tool`. “Switch” for Grok and
Gemini means selection for an app-owned launch; it does not change the account
used by a tool started from another shell.

The established credential locations and relay-relevant overrides remain:

| Provider        | Credential location or selector                                                                                                                                                                                                                                             | Base-URL override                                                                       |
| --------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------- |
| **Codex CLI**   | `~/.codex/auth.json` `[verified-local]`; managed copies under the application data directory                                                                                                                                                                                | OpenAI-compatible base URL `[verified-docs]`                                            |
| **Grok CLI**    | Default `~/.grok/auth.json` `[verified-local]`; selected managed home via `GROK_HOME` `[verified-source]`                                                                                                                                                                   | `GROK_CLI_CHAT_PROXY_BASE_URL` `[verified-docs]`; plan session `[unknown]`              |
| **Claude Code** | `~/.claude/.credentials.json` and `~/.claude.json` `[verified-local]`; managed copies under the application data directory                                                                                                                                                  | `ANTHROPIC_BASE_URL` `[verified-docs]`                                                  |
| **Gemini CLI**  | Managed API keys in `CredentialStore`; isolated OAuth homes under the application data directory write `oauth_creds.json`, `google_accounts.json`, and managed `settings.json`. Live `~/.gemini` OAuth may list as a read-only `gemini-cli-on-disk` row `[verified-source]` | API-key mode `[verified-docs]`; OAuth launch uses `GEMINI_CLI_HOME` `[verified-source]` |
| **Cursor**      | Not found in `~/.cursor/` or `~/.config/cursor/cli-config.json` `[verified-local]`                                                                                                                                                                                          | `[unknown]`                                                                             |

## What this implies for sequencing

The remaining implementation and verification order is now narrower:

1. **Codex CLI first.** It is the only provider whose entire credential
   state is one readable document. Add, list, local switch, and delete are
   in place. A switch verified by the vendor accepting the copied
   credential is still the cheapest remaining end-to-end proof.
2. **Grok CLI second.** Managed-home launch selection is implemented without
   mutating the default home. A real vendor/account run remains before the M2
   exit criterion can close.
3. **Claude Code third.** Isolated add and the crash-safe two-file switch are
   implemented with the safety bar. Vendor acceptance of a copied credential
   remains untested.
4. **Gemini CLI fourth.** The API-key path meets its M3 exit criterion.
   Isolated-home OAuth add and read-only live listing are implemented.
   Live-home OAuth file-swap remains unimplemented.
5. **Cursor last.** Read-only CLI listing is implemented. Mutation remains
   blocked until the credential store and write path are `[verified-local]`.

This ordering is reflected in [`ROADMAP.md`](ROADMAP.md).

## Open questions blocking implementation

| Question                                                                                                                                  | Blocks                                                              |
| ----------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------- |
| Where does `cursor-agent login` persist its session?                                                                                      | Cursor add, switch, and delete                                      |
| Is replacing Gemini `oauth_creds.json`, with coordinated `google_accounts.json` and settings state, sufficient for a next-process switch? | Gemini OAuth switching                                              |
| Does any provider expose a verified machine-readable current-usage signal?                                                                | Provider-backed numeric rows and production `max_utilization` gates |
| Do Claude Code and Codex CLI honour a base-URL override in plan-auth mode, or only in API-key mode?                                       | Real-agent `FR-6` verification for those tools                      |
| Does swapping `~/.codex/auth.json` invalidate a session server-side?                                                                      | The M2 real-vendor exit criterion for Codex                         |
