# Testing

## 1. Strategy

| Layer                | Tool                               | What it covers                                                                                                           |
| -------------------- | ---------------------------------- | ------------------------------------------------------------------------------------------------------------------------ |
| Domain and core      | `cargo test`                       | Registry integrity, storage, launch selection, quota states, relay transport, and router behavior.                       |
| Adapter contract     | `cargo test` over fixtures         | Every registry adapter follows the shared capability, mutation, path, and secret-leak rules.                             |
| Protocol translation | 74 paired golden cases             | Requests, responses, errors, and supported streams across OpenAI, Anthropic, and Gemini dialects.                        |
| Front end            | TypeScript, ESLint, Vitest + jsdom | Rust/TypeScript contract plus component behavior for Accounts and Dashboard.                                             |
| End to end           | Local fake acceptance tests        | Launch environments and routed relay behavior without real credentials. Real-vendor account proof remains a manual gate. |

## 2. Contract tests

Every adapter is exercised by the same test body, parameterised over the
registry. A new adapter therefore inherits the whole suite for free, and cannot
quietly skip a rule.

The contract asserts:

- `id()` is stable, kebab-case, and unique across the registry.
- `descriptor().maturity` is not `supported` unless `list_accounts()` succeeds.
- `descriptor().capabilities` matches the implemented legacy or managed
  lifecycle path for add, switch, delete, and launch (`NFR-8`). The probe id is
  not a safe path component, so an implementation refuses before creating a
  directory, writing the live home, resolving a credential, or spawning the
  vendor CLI.
- `config_paths()` returns absolute paths for empty, spaced, and nonexistent
  injected roots. The production `$HOME`-unset path is explicitly not tested
  because mutating the process environment would race parallel tests.
- `detect()` is side-effect free: running it twice leaves the fixture home byte
  for byte identical.
- `list_accounts()` never returns a field containing a value that appears in the
  fixture's secret material. This is the automated form of `NFR-1`.
- A refused legacy `activate_account()` leaves the fixture tree unchanged.
  Launch-environment selection is covered through `managed_account_plan()` and
  `launch_spec()` because those adapters intentionally leave direct activation
  unimplemented. Backup-before-write and restore-on-failure (`NFR-4`) are
  proven in the Codex CLI adapter unit tests, not in this shared body.

## 3. Fixtures

```text
src-tauri/tests/fixtures/<provider>/
  home/                   synthetic $HOME tree the adapter sees
  expected/accounts.json expected list_accounts() result

src-tauri/tests/fixtures/{gemini,grok,quota}/
  ...                     feature-specific synthetic configuration trees
```

Fixture rules:

- Every secret-shaped value is an obvious fake: `FAKE-access-token-0001`. The
  leak test greps for that prefix, which only works if real values never appear.
- Fixtures are copied into a `tempfile::TempDir` per test; a test never touches
  a real `$HOME`. Adapters take their root from an injected base path for this
  reason.
- Fixtures are derived from documented schemas, never from a copied personal
  config.

## 4. Never test with a real credential

- No test, script, or CI job may read the developer's real `$HOME`.
- No real token, key, cookie, or account identifier belongs in this repository,
  in any branch, at any time. Git history is forever.
- CI runs with no vendor credential configured. A test that would need one is a
  test that is testing the vendor, not this project.

## 5. Golden-file translation tests

`relay::translate` is a pure function, which makes it exactly the kind of thing
golden files test well:

```text
src-tauri/tests/golden/<from>-to-<to>/
  NNN-<case>.input.json
  NNN-<case>.expected.json
```

The harness currently exercises 74 paired input/expected cases. It covers all
12 ordered non-streaming text-format request and response pairs, supported
streaming sequences, OpenAI Images to and from Gemini, reasoning mapping, and
fields with no counterpart. Errors name the rejected field rather than silently
dropping it.

Streaming goldens also pin the implemented boundaries: cross-dialect OpenAI
Responses targets are rejected, cross-dialect streaming request sources from
OpenAI Responses are rejected, and Gemini-target tool-call streams that would
require partial argument accumulation are rejected. Listener tests cover both
Gemini `generateContent` paths and `streamGenerateContent` paths. At runtime,
after response headers are sent, a streaming translation failure terminates as
a generic transport failure rather than a field-specific HTTP response.

The relay uses `storage::Secret` only as its in-memory secret representation;
it does not call `CredentialStore`. Transport tests therefore construct only
obvious fake runtime tokens and assert that routed client credential and account
headers are stripped before target authentication is applied.

## 6. Coverage expectations

- Core, adapters, and translation: meaningful coverage of every branch that
  writes to disk or handles a secret. These are the paths where a bug costs a
  user their login. Codex CLI `add_account` is covered in that adapter's
  unit tests (fresh directory, vendor-login failure cleanup, no live-home
  mutation).
- UI: type checking, lint, and component tests. Accounts and Dashboard tests
  cover capability-gated actions, launch-selection state, and distinct quota
  no-signal/failure rendering.
- Router and routed relay Rust tests: local fake targets prove case-sensitive
  exact and trailing-`*` selection, fail-closed quota gates, one account per
  selected provider, explicit unmatched errors, HTTP-429-only fallback,
  throttle deadlines, credential stripping, persistence, and persisted-rule
  activation. There is no Router component test.
- A pull request adding a write path without a test for its failure-and-restore
  case does not get merged.

The real coding-agent-through-relay check is deliberately not part of CI because
it requires real provider accounts. It remains an M5 exit-criterion check on a
disposable account setup.

## 7. Running

```bash
nix develop        # on NixOS
npm run typecheck
npm run lint
npm run format:check
npm test
cargo fmt --manifest-path src-tauri/Cargo.toml --all -- --check
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets -- -D warnings
cargo test --manifest-path src-tauri/Cargo.toml
```

The active MACO [account-manager workflow](../../.github/workflows/account-manager.yml)
runs type checking, lint, format checking, Vitest, and the frontend build. Rust
checks, Clippy, and existing tests run with both the default desktop feature and
`--no-default-features` on Linux, macOS, and Windows. The headless dependency
check refuses Tauri, GTK, and WebKit packages in the resolved build graph.
The imported `.github/workflows` directory is historical source payload; nested
workflows are not executed by GitHub Actions.
