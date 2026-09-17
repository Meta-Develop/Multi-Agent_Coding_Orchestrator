# Roadmap

Milestones are sequenced by dependency, not by ambition. The ordering follows
one rule: **nothing writes to a user's config until the thing that restores it
works.**

Requirement ids refer to [`SPEC.md`](SPEC.md). Provider ordering and its
justification are in [`PROVIDER_MATRIX.md`](PROVIDER_MATRIX.md).

---

## M0 — Foundation ✅

**Goal.** A repository that builds, a specified product, and an adapter contract
worth implementing against.

- Tauri v2 + React + TypeScript skeleton that builds and runs.
- `ProviderAdapter` and `CredentialStore` contracts defined.
- Five adapter modules registered, each carrying its researched config paths.
- Full documentation set: spec, architecture, security model, research notes,
  ADRs.
- CI on Linux, macOS, and Windows.

**Exit criteria.** `npm run typecheck`, `npm run lint`, `cargo check`,
`cargo test`, and `cargo clippy -D warnings` all pass in CI on all three
platforms.

---

## M1 — Safe foundations ✅

**Goal.** The machinery that makes writing to someone's config defensible.

Satisfies: `FR-3`, `NFR-1`, `NFR-4`.

- Backup subsystem: timestamped snapshots over `config_paths()`, restore,
  retention with a never-prune floor.
- Atomic write helper: temp file, `fsync`, rename.
- `CredentialStore` implemented for the OS keychain on all three platforms.
- Encrypted-file fallback with passphrase derivation.
- Secret redaction proven by test, including the fixture-leak grep.

**Exit criteria.** A forced failure at any point during a simulated switch
leaves the fixture tree byte-identical to its pre-switch state. No secret
appears in any log, error, or diagnostic under test.

---

## M2 — First adapters: Codex CLI and Grok CLI

**Goal.** Prove the contract end to end on the two providers whose credential
state is a single readable document.

Satisfies: `FR-1`, `FR-2`, `FR-4`.

The Grok implementation item is resolved, but M2 remains incomplete because the
Codex switch and Grok launch path still need real vendor/account proof.

Done:

- Codex CLI: read, list, add via isolated `codex login` (`CODEX_HOME` at
  a per-account directory), switch by replacing the live `auth.json`
  behind a restorable backup, delete a stored copy without signing out.
  Maturity remains `experimental`. The adapter does not switch by
  relocating `CODEX_HOME` at launch, and it does not claim the vendor
  accepts a copied credential.
- Grok CLI: read and list signed-in OIDC identities, detect the official CLI,
  and manage retained vendor homes. Selection is non-secret metadata; an
  app-owned child receives the selected `GROK_HOME` and has inherited
  `GROK_AUTH_PATH` removed. The application does not relocate, copy, rewrite,
  back up, or delete `auth.json`.
- Accounts page: add, list, switch, and delete, gated on
  `ProviderDescriptor.capabilities`, with confirmations. It distinguishes the
  active tool identity from the account selected for an app-owned launch.
- Adapter contract suite over the registry, including a capability
  guard.

Still open:

- Real Codex and Grok checks in which each tool reports the expected identity.
  Grok's pinned first-party source is `[verified-source]`, but that does not
  claim the local binary matches that revision.

**Exit criteria.** A real switch on a real machine, verified by the tool
reporting the expected identity, with a working restore. Both adapters at
`experimental`. Both descriptors are `experimental`; local fake tests cover
the implementation, but the real vendor/account checks have not been run.

---

## M3 — Claude Code and Gemini CLI

**Goal.** The two-file switch, and the file-free switch.

Satisfies: `FR-1`, `FR-2` for two more providers.

- Claude Code: surgical read-modify-write of the identity fields in
  `~/.claude.json` and `.credentials.json`, preserving `projects`,
  `mcpServers`, and machine state, atomic across both files.
- Gemini CLI: API-key accounts via `GEMINI_API_KEY`. OAuth add is in-app
  Google loopback writing an isolated `GEMINI_CLI_HOME`, including managed
  `oauth-personal` settings. Listing may include a read-only live
  `gemini-cli-on-disk` row. File-swap of the live `~/.gemini` home remains
  out of scope.

M3 is partial. Claude Code isolated add and the two-file switch are
implemented with the safety bar: a paired backup, a durable journal with
process-death recovery, fail-closed lock and process checks, surgical
preservation of every other field, failure injection across write and recovery
phases, and the `FR-2` write scope. Vendor acceptance of a copied credential
is untested.

Gemini API-key account management is implemented through
`CredentialStore` and non-secret launch selection. Gemini OAuth add writes
only a managed home; launch sets `GEMINI_CLI_HOME` and
`GOOGLE_GENAI_USE_GCA=true`. Listing can show the live on-disk OAuth identity
as a read-only row. Neither path writes or swaps the live `~/.gemini` tree.

**Exit criteria.** Claude Code switch preserves every machine-scoped field,
proven by fixture diff. Gemini API-key switching works without touching a file.
Those criteria are met. Live Gemini file-swap remains out of scope.

---

## M4 — Quota visibility ✅

**Goal.** Show what is actually knowable, and nothing more.

Satisfies: `FR-5`, `NFR-8`.

- Quota collection per adapter, returning empty where no signal exists.
- Dashboard with list and grid views, plan labels, reset times, error states.
- Explicit "no quota signal available" rendering — never a fabricated number.

All five current adapters return an explicit empty snapshot vector because no
numeric quota signal has a verified research basis. Claude Code may additionally
show the non-credential `billingType` plan label. Snapshots are collected on
demand and are not cached or persisted.

**Exit criteria.** Every provider either shows a sourced number with its
`capturedAt` age, or states that it publishes no signal. Met: the current state
for every provider is no signal, and collection failures render separately.

---

## M5 — Relay

**Goal.** One local endpoint, three dialects.

Satisfies: `FR-6`, `FR-8`, `FR-9`.

- Loopback HTTP listener with per-dialect path prefixes.
- OpenAI ⇄ Anthropic ⇄ Gemini translation, non-streaming then streaming.
- Image-generation passthrough with size and quality controls.
- Reasoning-budget mapping, with explicit errors on unmappable fields.
- Non-loopback binding gated on an auth token, enforced and tested.

M5 is partial. The implemented subset has six ingress paths, all 12 ordered
non-streaming text-format pairs, and 74 golden cases. Supported streaming routes
translate event by event. Cross-dialect streaming requests from OpenAI
Responses and cross-dialect streaming targets to OpenAI Responses are explicit
errors. Gemini-target tool-call streams that would require partial argument
assembly are also rejected. Image translation is limited to OpenAI Images and
Gemini; Anthropic image endpoints are rejected.

Still open:

- `FR-9` user defaults, per-route overrides, and precedence.
- Integration between relay targets and provider-selected managed accounts.
- A real coding agent driven through the relay against another provider. This
  check is deferred because it requires real accounts.

**Exit criteria.** Golden-file coverage for every case in
[`TESTING.md`](TESTING.md) §5, and a real coding agent driven through the relay
against a different vendor's account. The golden-file criterion is met; the
real-account criterion is deferred.

---

## M6 — Routing ✅

**Goal.** Spend the right account's quota.

Satisfies: `FR-7`.

- Ordered rules: model pattern → provider + upstream model.
- Quota-gated rules, using M4's signals.
- Failover on rate-limit responses, with throttle-until tracking.
- No implicit fallback: an unmatched request errors.

Rules use case-sensitive exact or one trailing-`*` model match and select a
provider plus target model. The native core stores the ordered document
atomically in versioned `route-rules.json`; changes apply on the next relay
start. Each selected provider must resolve to exactly one configured account
target. Quota gates fail closed when M4 data is absent, failed, malformed, or
irrelevant.

Fallback occurs only after HTTP 429. Translation, network, and non-429 failures
do not advance to another rule. The throttle deadline is the later usable
numeric `Retry-After` or M4 reset, or 60 seconds when neither is available.
Routed requests strip client credential and account-selection headers before
injecting only the selected target authentication. The desktop path ignores the
legacy singleton target variables.

**Exit criteria.** A rate-limited account demonstrably fails over, and no
request is ever served by an account no rule selected. Met by local fake
acceptance tests; no real credential was used.

---

## M7 — Cursor, and packaging

**Goal.** Close the initial provider set and ship installable artifacts.

Satisfies: `FR-10`, and `FR-4` for Cursor.

- Cursor: detection and read-only support. Switching only if and when its
  credential store becomes `[verified-local]`.
- Signed Windows NSIS installer, macOS `.dmg` for both architectures, Linux
  `.deb` / `.rpm` / AppImage, Docker image for the headless relay.
- Release workflow producing checksummed artifacts.

M7 is partial. Cursor detection and read-only Cursor CLI account listing through
`cursor-agent status` are implemented. The adapter is `experimental`, masks the
reported identity, and advertises no capabilities. Adding, switching, and
deleting remain blocked until the credential store and write path are
`[verified-local]`.

Packaging and signing work did not land in this wave. Platform-specific Windows
and macOS verification is blocked on the current NixOS host and remains for
platform CI or matching hosts. The headless Docker artifact is unimplemented.

**Exit criteria.** A user can install from a release artifact on each platform
and complete a switch. Not met.

---

## v1.0

Every `FR-*` either satisfied or explicitly deferred with a recorded reason;
every `NFR-*` satisfied; adapters honestly labelled; documentation matching
behaviour.

## Beyond v1

Antigravity, Windsurf, GitHub Copilot, OpenCode, Aider, and Cline adapters.
Profiles that switch several tools at once. Optional encrypted export for moving
accounts between the user's own machines. A runtime plugin system, only if a
credible sandbox for third-party adapter code exists — see
[`adr/0002-provider-adapter-plugin-architecture.md`](adr/0002-provider-adapter-plugin-architecture.md).
