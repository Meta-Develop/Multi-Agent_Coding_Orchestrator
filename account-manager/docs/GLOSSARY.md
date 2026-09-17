# Glossary

| Term                          | Meaning here                                                                                                                                                                       |
| ----------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Account**                   | One identity with one vendor, as tracked by this application. Its id is assigned locally, never by the vendor.                                                                     |
| **Adapter**                   | The module implementing `ProviderAdapter` for one managed tool. The only code that knows a vendor's file layout.                                                                   |
| **Capability**                | A mutating operation an adapter implements: `add-account`, `switch-account`, or `delete-account`. The UI offers a button only when the adapter lists it.                           |
| **Backup**                    | A timestamped snapshot of every file an adapter is about to modify, taken before the first write.                                                                                  |
| **Confidence marker**         | `[verified-local]`, `[verified-docs]`, `[inferred]`, or `[unknown]`, attached to every factual claim in `research/`.                                                               |
| **Credential store**          | The backend holding secrets: the OS credential service, or the encrypted-file fallback.                                                                                            |
| **Dialect** / **wire format** | One vendor's HTTP request and response schema: OpenAI, Anthropic Messages, or Gemini `generateContent`.                                                                            |
| **Managed tool**              | An AI coding agent this application manages, e.g. Codex CLI.                                                                                                                       |
| **Masked identity**           | A vendor identity reduced for display, e.g. `a***@example.com`. The only identity form that crosses to the webview.                                                                |
| **Maturity**                  | How complete an adapter is: `planned`, `experimental`, or `supported`. Shown in the UI so it cannot overstate itself. Not the gate for add, switch, or delete buttons.             |
| **Stored account**            | An account backed by a vendor-written home (`VendorHome`) or a credential-store secret resolved only at child spawn (`CredentialStore`). No vendor file exists for the latter.     |
| **Profile**                   | A named set of provider→account bindings, so several tools switch together.                                                                                                        |
| **Provider**                  | A managed tool plus its vendor, e.g. Claude Code / Anthropic.                                                                                                                      |
| **Quota snapshot**            | An observation of remaining quota at a point in time, with its source and age. Disposable cache.                                                                                   |
| **Relay**                     | The local HTTP server that accepts one dialect and forwards in another.                                                                                                            |
| **Route rule**                | One ordered mapping from an inbound model pattern to a provider, an upstream model, and an optional quota gate.                                                                    |
| **Secret**                    | Token, key, or equivalent. Never crosses the IPC boundary, never logged, zeroed on drop.                                                                                           |
| **Switch**                    | Making a different account active for a provider, without re-authentication.                                                                                                       |
| **Switch verification**       | Specified as confirming that the tool reports the expected identity. The implemented Codex switch re-reads the written `auth.json` instead; it does not ask the CLI or the vendor. |
