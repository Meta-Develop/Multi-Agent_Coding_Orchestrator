# Release process

## Versioning

Semantic versioning. Until v1.0, minor versions may break compatibility, and the
changelog says so explicitly when they do.

Three files carry the version and must agree:

- `package.json`
- `src-tauri/Cargo.toml`
- `src-tauri/tauri.conf.json`

CI fails the release if they disagree.

## Steps

1. Confirm `main` is green on all three platforms.
2. Move `CHANGELOG.md`'s `Unreleased` section under the new version heading with
   today's date. Every user-visible change is listed; "various fixes" is not a
   changelog entry.
3. Bump the version in the three files above in one commit:
   `chore(release): v0.2.0`.
4. Tag `v0.2.0` and push the tag. The release workflow builds every platform,
   attaches checksummed artifacts, and opens a draft release.
5. Review the draft: verify the artifact list is complete and the checksums are
   attached.
6. Publish.

## Artifacts

| Platform  | Artifacts                                             |
| --------- | ----------------------------------------------------- |
| Windows   | NSIS `.exe` installer                                 |
| macOS     | `.dmg` for `aarch64` and `x86_64`                     |
| Linux     | `.deb`, `.rpm`, AppImage                              |
| Container | Multi-architecture image running the relay headlessly |

Each artifact ships with a SHA-256 checksum. Signing keys, when they exist, live
in repository secrets and never in the tree.

## Security releases

A fix for a credential-exposure issue ships as a patch release on its own, ahead
of any queued feature work, with the advisory published at the same time. See
[`../SECURITY.md`](../SECURITY.md).

## Pre-1.0 caveat

Until v1.0, releases are for evaluation. The README states the current status,
and it is updated in the same commit as the version bump.
