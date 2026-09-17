# Functional specification — v1

Status: draft. Requirement ids are stable once assigned; if a requirement is
dropped, its id is retired rather than reused.

## 1. Purpose

Give a developer who holds multiple accounts across multiple AI coding agents a
single place to see them, switch between them, and understand what quota each
one has left — without logging out, logging back in, or hand-editing config
files.

## 2. Target users

- Developers with a personal and a work account on the same tool.
- Developers who use several agents (Claude Code, Codex CLI, Cursor, Grok CLI,
  Gemini CLI) and hit different rate limits at different times.
- Small teams sharing a pool of accounts across machines.

## 3. Non-goals

- Not a proxy for circumventing a vendor's rate limits, terms, or pricing.
- Not a credential-sharing service. Credentials stay on the user's machine.
- Not an agent runtime. It manages the tools; it does not replace them.
- Not a telemetry or analytics product. Nothing leaves the machine.

## 4. Domain model

| Entity          | Fields                                                                             | Lifecycle                                            |
| --------------- | ---------------------------------------------------------------------------------- | ---------------------------------------------------- |
| `Provider`      | `id`, `displayName`, `vendor`, `authKinds`, `maturity`                             | Static, compiled in.                                 |
| `Adapter`       | implements the provider contract                                                   | One per provider; selected by `id`.                  |
| `Account`       | `id`, `providerId`, `label`, `maskedIdentity`, `authKind`, `isActive`, `expiresAt` | Created on import or login; deleted on user request. |
| `Credential`    | opaque `SecretRef` into the credential store                                       | Written on login/refresh; deleted with its account.  |
| `Profile`       | named set of `(provider → account)` bindings                                       | Optional grouping so several tools switch together.  |
| `QuotaSnapshot` | `accountId`, `model`, `utilization`, `resetsAt`, `capturedAt`, `source`            | Polled or observed; disposable cache.                |
| `RouteRule`     | `matchModel`, `providerId`, `targetModel`, `maxUtilization`                        | User-authored, ordered list.                         |
| `RelaySession`  | inbound format, resolved account, upstream format                                  | Per request; never persisted.                        |

`Account.id` is assigned by this application, never by the vendor, so a vendor
changing its identifier scheme cannot orphan local state.

## 5. Functional requirements

### Accounts and switching

- **FR-1 — Multi-account management.** The user can import, label, list, and
  delete accounts per provider. Switching the active account for a provider is
  one action and completes without the user re-authenticating.
- **FR-2 — Credential handling.** The application supports OAuth 2.0
  authorization-code with PKCE and API-key accounts. It refreshes tokens
  automatically before expiry and on demand, and it surfaces expiry state.
- **FR-3 — Secure storage.** Secrets are stored in the OS credential service
  when one is available, and in an encrypted local file otherwise. There is no
  plaintext storage mode.
- **FR-4 — Provider adapters.** Each supported tool is reached through one
  adapter that owns knowledge of that tool's config and credential locations.
  Adding a provider requires a new adapter module and a registry entry, and no
  change to core code.

### Visibility

- **FR-5 — Quota dashboard.** For each account, the application shows remaining
  quota, the rate-limit window, the reset time, and any error state, in both a
  list and a grid view. Where a provider exposes no usable signal, the UI says
  so rather than showing a fabricated number.

### Relay and routing

- **FR-6 — Local relay.** A local HTTP server accepts requests in the OpenAI,
  Anthropic, or Gemini wire format and forwards them to a chosen account,
  translating between formats as needed, including streaming responses.
- **FR-7 — Smart routing.** The user defines ordered rules mapping an inbound
  model name to a provider and upstream model, optionally gated on remaining
  quota. On a rate-limit response the router fails over to the next matching
  rule.
- **FR-8 — Image generation.** The relay supports image-generation requests
  with size and quality controls for providers that offer them.
- **FR-9 — Reasoning budget.** For models exposing a thinking or reasoning
  budget, the user can set a default and a per-route override.

### Platform

- **FR-10 — Packaging.** The application ships as a Windows NSIS installer, a
  macOS `.dmg` for Intel and Apple Silicon, Linux `.deb` / `.rpm` / AppImage,
  and a Docker image running the relay headlessly.

## 6. Non-functional requirements

- **NFR-1 — Secret confidentiality.** A secret is never written to a log, an
  error message, a crash report, a diagnostic export, or the UI. Identities are
  masked for display. Violating this is a release blocker, not a bug.
- **NFR-2 — Startup.** Cold start to an interactive window in under two seconds
  on a mid-range machine. Provider detection is asynchronous and never blocks
  the first paint.
- **NFR-3 — Offline behaviour.** Every local operation — listing accounts,
  switching, viewing cached quota — works with no network. Operations that
  genuinely need the network say so before they fail.
- **NFR-4 — Data-loss safety.** No file belonging to a managed tool is replaced
  without first writing a timestamped backup that the application can restore.
  A failed switch leaves the previous state intact.
- **NFR-5 — Cross-platform parity.** Every feature works on Windows, macOS, and
  Linux, or is explicitly and visibly unavailable on a platform.
- **NFR-6 — Accessibility.** Full keyboard navigation, visible focus, labelled
  controls, and contrast meeting WCAG 2.1 AA in both light and dark themes.
- **NFR-7 — No telemetry.** The application makes no network request that the
  user did not initiate, other than to vendor APIs on their behalf.
- **NFR-8 — Honest state.** The UI never claims a capability an adapter does not
  have. Adapter maturity is shown, and unimplemented surfaces are labelled.

## 7. User flows

### First run

1. The application detects which managed tools are installed (`FR-4`).
2. It offers to import any account it can already see, showing exactly which
   files it read.
3. It establishes a credential store (`FR-3`); if none is available it explains
   the consequence instead of silently degrading.

### Adding an account

1. The user picks a provider and an auth kind.
2. For OAuth, the application runs an authorization-code + PKCE flow in the
   system browser and captures the callback on loopback.
3. For an API key, the key is accepted, validated with one lightweight call, and
   stored (`FR-2`, `FR-3`).

### Switching an account

1. The user selects an account and confirms.
2. The application writes a timestamped backup of every file it is about to
   touch (`NFR-4`).
3. It writes the new credential material through the adapter, atomically.
4. It verifies the tool now reports the expected identity, and reports the
   result. On failure it restores the backup.

### Recovering a corrupted config

1. The application detects an unparsable managed file.
2. It refuses to write, lists available backups with timestamps, and offers a
   restore. It never "repairs" a file it does not fully understand.

### Running the relay

1. The user starts the relay; it binds to loopback (`NFR-1`).
2. Exposing it on another interface requires an explicit opt-in and an auth
   token; the UI states the risk in plain language.
3. Requests are routed by the rule list (`FR-7`) and translated as needed
   (`FR-6`).

## 8. Out of scope for v1

- Team or cloud sync of accounts between machines.
- Mobile builds.
- A plugin system loading third-party adapters at runtime. Adapters are compiled
  in for v1, because a runtime-loaded adapter would be code with access to every
  credential the application holds.
- Automated account creation or sign-up.
