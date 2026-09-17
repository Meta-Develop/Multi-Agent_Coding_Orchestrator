# 0006. Clean-room independent implementation

- **Status**: Accepted
- **Date**: 2026-08-18

## Context

This project was started after seeing [`lbjlaq/Antigravity-Manager`][upstream],
which solves one-click account switching for a single vendor's tool. The idea
generalises: the same daily friction exists across every AI coding agent, and
nothing manages them together.

That project is licensed CC-BY-NC-SA-4.0 — a share-alike, non-commercial
licence. Deriving from it would carry that licence forward, including the
non-commercial restriction, which conflicts with `0005` and would make the
result unusable by developers managing work accounts.

## Decision

Implement independently, from scratch. No code, asset, string, documentation, or
licence text is taken from the upstream project. What is shared is the problem
statement, which is not copyrightable.

Concretely:

- The architecture was derived from the requirements in `SPEC.md`, not from
  upstream's structure.
- Every provider fact in `research/` comes from direct observation on a real
  machine or from official vendor documentation, each carrying a confidence
  marker.
- The licence is GPL-3.0-or-later on the project's own terms (`0005`).
- The README credits the upstream project as inspiration and states plainly that
  this is not a fork.

## Consequences

- The project is free to choose its own licence, architecture, and scope.
- Attribution is a matter of honesty rather than legal obligation, and the README
  gives it clearly.
- **Cost**: no reuse of upstream's solved problems. Everything is rebuilt,
  including things upstream already got right.
- **Cost**: contributors must not paste upstream code. `CONTRIBUTING.md` states
  this, and a pull request that appears to contain upstream code is closed
  rather than modified.

## Alternatives considered

- **Fork and extend upstream.** Fastest start. Rejected: it inherits
  CC-BY-NC-SA-4.0 and its non-commercial restriction, it inherits an architecture
  built for one vendor, and this project's central abstraction — a provider
  adapter contract — would have to be retrofitted through the whole codebase.
- **Ask upstream to relicense.** Not this project's decision to depend on, and
  it would still leave the single-vendor architecture.
- **Contribute multi-provider support upstream instead.** Considered seriously.
  Rejected because it is a different product, not a feature: multi-provider
  changes the domain model, the storage layer, and the UI, and it would be an
  unreasonable thing to push onto someone else's focused project.

[upstream]: https://github.com/lbjlaq/Antigravity-Manager
