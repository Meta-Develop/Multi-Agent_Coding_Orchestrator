# 0002. Provider adapter architecture, compiled in

- **Status**: Accepted
- **Date**: 2026-08-18

## Context

The project targets five providers at launch and at least six more later. Each
stores credentials differently, in different places, in different formats, and
each will change independently and without notice.

Two questions had to be answered together: how is provider-specific knowledge
isolated, and can third parties add providers at runtime?

## Decision

Every provider is reached through a `ProviderAdapter` trait implementation.
Adapters are **compiled into the binary** and registered in `providers::registry()`.
There is no runtime plugin loading in v1.

## Consequences

- Core code never branches on a vendor. Adding a provider is a new module and
  one registry line — verifiable by grepping core for a vendor name and finding
  nothing.
- The uniform contract makes a shared contract-test suite possible: a new
  adapter inherits every rule, including the secret-leak assertion, and cannot
  quietly skip one.
- The trait is the place to enforce cross-cutting policy. `activate_account()`
  is documented as the only mutating method, so "must back up first" has exactly
  one place to be checked.
- **Cost**: adding a provider requires a release. Acceptable — adapters need
  research and testing anyway, so they were never going to be same-day.
- **Cost**: users cannot write their own adapters. This is the real price, and
  it is paid deliberately.

## Alternatives considered

- **Runtime plugin system (dynamic libraries or WASM).** Rejected for v1: a
  plugin runs inside the process that holds every credential the user owns.
  Making that safe needs a capability sandbox in which an adapter can reach one
  provider's paths and nothing else. That is a serious piece of engineering and
  it is not a launch feature. Revisit only with a credible sandbox — noted in
  `ROADMAP.md` under "Beyond v1".
- **Declarative adapters (config files describing paths and formats).** Very
  appealing until the second provider. Claude Code needs a surgical
  read-modify-write of a large client-owned JSON document, and Grok CLI needs
  advisory-lock handling. Neither is expressible declaratively, and a
  half-declarative system is worse than either alternative.
- **One module per provider with no shared trait.** Rejected: it makes the
  contract-test suite impossible, which is what keeps `NFR-1` and `NFR-4`
  enforced rather than merely documented.
