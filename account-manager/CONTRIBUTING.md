# Contributing

Thanks for considering a contribution. This project handles other people's
credentials, so a few of the rules below are stricter than you may be used to.
They exist for a reason, and each states its reason.

## Before you start

- Read [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) — especially the layering
  rules and the adapter contract.
- Read [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) if you will touch
  anything near a credential. That is most things.
- For a substantial change, open an issue first so the design can be discussed
  before you write it.

## Ground rules

1. **Never commit a real credential.** Not in a test, not in a fixture, not in
   an issue, not "temporarily". Git history is permanent. Fixtures use obviously
   fake values with a `FAKE-` prefix; the leak test depends on that prefix
   meaning what it says.
2. **Never paste code from another project**, including from
   `lbjlaq/Antigravity-Manager`. This project is a clean-room implementation
   (see [ADR 0006](docs/adr/0006-clean-room-independent-implementation.md)), and
   a pull request containing third-party code is closed rather than reworked.
3. **Research before you write an adapter.** A wrong path claim locks someone
   out of a working tool. See
   [`docs/research/README.md`](docs/research/README.md).
4. **Don't overstate what works.** Adapter maturity, and the `NotImplemented`
   placeholders, exist so the UI cannot promise something it cannot do
   (`NFR-8`).

## Development setup

See [`docs/DEVELOPMENT.md`](docs/DEVELOPMENT.md). On NixOS, `nix develop` first.

## Branches and commits

- Branch from `main`: `feat/<slug>`, `fix/<slug>`, `docs/<slug>`,
  `chore/<slug>`, or `research/<provider>`.
- [Conventional Commits](https://www.conventionalcommits.org/): `feat:`, `fix:`,
  `docs:`, `test:`, `refactor:`, `chore:`, `ci:`. Scope with the provider id
  where it applies — `feat(codex-cli): read accounts from auth.json`.
- Keep a commit to one logical change. A commit that mixes a refactor with a
  behaviour change is hard to review and harder to revert.

## Pull requests

Before opening, run:

```bash
npm run typecheck && npm run lint && npm run format:check
npm run rust:test && npm run rust:clippy
```

In the description, say what changed, why, and how you verified it. Link the
issue and any `FR-*` / `NFR-*` ids the change touches.

### Review checklist

- [ ] No secret in code, tests, fixtures, logs, or error messages.
- [ ] A new write path has a test for its failure-and-restore case.
- [ ] `src/types/index.ts` and `src-tauri/src/model.rs` still agree.
- [ ] Layering respected: nothing below `commands.rs` references `tauri::`; no
      adapter references another adapter.
- [ ] Provider path claims carry a confidence marker, and no write path relies
      on an `[inferred]` or `[unknown]` claim.
- [ ] Documentation updated when behaviour changed.
- [ ] `CHANGELOG.md` updated under `Unreleased` for a user-visible change.

## Proposing a new provider adapter

1. Open an issue using the **New provider** template.
2. Land `docs/research/<provider>.md` first, on its own. It is reviewable
   independently and is valuable even if the adapter never ships.
3. Then the adapter, starting read-only: `detect`, `config_paths`,
   `list_accounts`. Leave `activate_account` returning `NotImplemented` until
   the switching mechanics are verified.
4. Then switching, with fixtures and contract tests.

Splitting it this way means each pull request is reviewable, and a stalled
adapter still leaves the research behind.

## Sign-off

Sign your commits off with `git commit -s`, certifying the
[Developer Certificate of Origin](https://developercertificate.org/). It is how
we record that you have the right to contribute what you are contributing —
which matters more than usual for a clean-room project.

## Code of conduct

Participation is covered by [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
