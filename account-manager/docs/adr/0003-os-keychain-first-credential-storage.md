# 0003. OS keychain first, encrypted file as fallback

- **Status**: Accepted
- **Date**: 2026-08-18

## Context

The application holds OAuth refresh tokens and API keys for several vendors at
once. A refresh token is long-lived and frequently cannot be revoked per-device,
so a single leak is not a small incident.

Notably, several of the tools being managed store these credentials as plain
JSON in the home directory. Copying that posture would make this application a
convenient single place to steal everything from.

## Decision

Store secrets in the OS credential service — macOS Keychain, Windows Credential
Manager, Freedesktop Secret Service — whenever one is available. Where none is,
use an encrypted file whose key is derived from a user passphrase. **There is no
plaintext mode, behind any flag.**

## Consequences

- Secrets inherit the platform's protections: OS-level access control, lock-screen
  integration, and existing enterprise policy.
- On a headless Linux host with no Secret Service, the application still works,
  which matters for the planned Docker relay.
- Refusing to degrade to plaintext means the application will sometimes tell a
  user it cannot store their credential. That is the correct outcome, and the
  message explains what to install or enable.
- `Secret` implements neither `Debug` nor `Serialize`, and zeroes on drop. The
  type system, not review discipline, is what keeps a token out of a log.
- **Cost**: three separate platform integrations, each with its own failure
  modes and its own testing burden.
- **Cost**: passphrase management for the fallback — prompting, caching policy,
  and recovery when it is forgotten. There is no recovery; the accounts are
  re-added. That is stated up front rather than discovered.

## Alternatives considered

- **Plaintext JSON, like the tools being managed.** Rejected. Aggregating every
  credential the user owns into one plaintext file is strictly worse than the
  status quo it replaces.
- **Encrypted file only, no keychain.** Simpler and uniform. Rejected because it
  discards real OS protections and forces a passphrase prompt on every user,
  including those whose platform already solved this.
- **Keychain only, no fallback.** Rejected: it breaks headless Linux, and the
  Docker relay is a v1 deliverable (`FR-10`).
- **Delegating storage to each managed tool.** Rejected: several store plaintext,
  and the application would then have no way to hold an account that is not
  currently active — which is the entire feature.
