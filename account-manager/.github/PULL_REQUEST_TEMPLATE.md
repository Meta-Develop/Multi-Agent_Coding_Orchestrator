## What changed

<!-- One paragraph. What this does, and why. -->

## Related

<!-- Closes #123. Requirement ids from docs/SPEC.md, e.g. FR-4, NFR-1. -->

## How this was verified

<!-- Commands run and their results. "CI is green" is not a verification. -->

```
npm run typecheck && npm run lint && npm run format:check
npm run rust:test && npm run rust:clippy
```

## Checklist

- [ ] No secret in code, tests, fixtures, logs, or error messages.
- [ ] A new write path has a test for its failure-and-restore case (`NFR-4`).
- [ ] `src/types/index.ts` and `src-tauri/src/model.rs` still agree.
- [ ] Layering respected: nothing below `commands.rs` uses `tauri::`; no adapter references another adapter.
- [ ] Provider path claims carry a confidence marker; no write path relies on `[inferred]` or `[unknown]`.
- [ ] Adapter `maturity` is honest (`NFR-8`).
- [ ] Documentation updated where behaviour changed.
- [ ] `CHANGELOG.md` updated under `Unreleased` for a user-visible change.
- [ ] Commits are signed off (`git commit -s`).
- [ ] This contains no code copied from another project.
