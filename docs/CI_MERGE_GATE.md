# Main branch CI merge gate

The active `main-required-ci` repository ruleset requires these GitHub Actions
checks from the GitHub Actions app before a pull request can merge into `main`:

- `Required Rust CI gate`
- `Required account manager CI gate`
- `Cargo.lock, RustSec, licenses, bans, and sources`
- `Cargo.toml rust-version`

The Rust gate in `.github/workflows/ci.yml` succeeds only when repository
portability, the Linux gate, and the macOS/Windows portable-build matrix all
succeed. The Linux gate waits for every partition of `Linux library tests`
(including `autopilot`, `rest`, and `supervise`) and `Linux integration tests`.
The account-manager gate in `.github/workflows/account-manager.yml` waits for
the `desktop-lock`, `frontend`, and `rust` jobs. Keep these four gate names
stable when editing workflows; a renamed or missing required check blocks
merging.

The ruleset does not allow a bypass actor. Repository auto-merge is enabled, so
an ordinary auto-merge request waits for the required checks. The ruleset uses
non-strict status checks: the head does not have to be rebased onto the latest
`main` merely because another pull request merged, but merge conflicts still
block completion. A repository administrator can change the ruleset for an
emergency; record the reason and restore the required checks afterward.
