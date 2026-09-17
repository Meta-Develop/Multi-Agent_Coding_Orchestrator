# 0008. Vendor-written auth.json for stored Codex accounts

- **Status**: Proposed
- **Date**: 2026-08-19

## Context

`FR-3` and [0003](0003-os-keychain-first-credential-storage.md) say secrets
go to the OS credential service or an encrypted file. There is no plaintext
storage mode. That decision still governs every secret this application
itself writes: tokens it refreshes, keys it accepts, anything it would put
in `Secret`.

Codex CLI already keeps its own session as a plaintext `auth.json` in the
tool home. The add-account path that shipped does not ingest that document.
It creates a per-account directory under the application data directory,
sets `CODEX_HOME` to that directory, and runs the vendor's `codex login`.
The CLI performs the browser sign-in and writes `auth.json` in whatever
shape it currently uses. This application never composes a field, never
parses a token, and never copies the document into the credential store.

A stored account is therefore a second copy of a file the vendor's own
tool already keeps in the same form in `~/.codex`. The alternative is to
pull that document into the credential store and write it back out on
every switch. That would satisfy `FR-3` as written. It would also mean
this application handles the vendor's tokens on every operation rather
than never.

## Decision

Keep each stored Codex account as a directory at
`{data_dir}/accounts/codex-cli/{account_id}` containing the `auth.json`
the vendor CLI wrote. Create that directory at `0700` on Unix. Do not
encrypt it, and do not move the document into the OS credential service
or the encrypted-file store.

This application does not set or check the mode of the vendor-written
file. Protection of the stored copy is the directory mode on Unix and
the application data directory's ACL on Windows.

This is a documented deviation from `FR-3` as written, not an oversight:
a stored Codex account is a directory containing an `auth.json` that the
vendor's own CLI wrote, kept inside a `0700` directory, and not encrypted
by this application.

This decision does not supersede 0003. 0003 still applies to secrets this
application itself stores.

## Consequences

- Add, list, switch, and delete can treat the stored document as bytes.
  They do not have to learn the vendor's schema, and a vendor format
  change does not require this application to compose a new file.
- Switching is a validated replacement of the live `auth.json`. Listing
  marks a stored account active only when its file is byte-identical to
  the live one. Neither step decodes a token.
- An attacker who can read the user's files can read every stored Codex
  account. Filesystem permissions are weaker than an encrypted store
  against that attacker. The live tool home is already in that weaker
  class. This decision adds more copies of the same class, under the
  application data directory rather than next to `~/.codex`.
- A backup taken before a switch captures the live `auth.json` and is
  therefore also credential material (threat T6).
- `FR-3` as written is not satisfied for stored Codex accounts. A reader
  of the specification who does not read this ADR will be misled.
- **Cost**: the stored-account tree is a new secret surface that the
  keychain backends do not cover. Review and incident response have to
  treat those directories as credential stores.
- **Cost**: this application cannot rotate, redact, or wrap the stored
  document without starting to handle the tokens it currently never
  sees.

## Alternatives considered

- **Pull the document into the credential store and materialise it on
  every switch.** Satisfies `FR-3` as written. Rejected: every add,
  list, switch, and delete would then handle the vendor's tokens.
  `NFR-1` is cheaper when those bytes never enter this process as
  something it understands. The vendor's own tool already persists the
  same document in plaintext in the tool home, so the encrypted copy
  would sit beside a plaintext one the user already has.
- **Encrypt the per-account directory with the encrypted-file key.**
  Closer to `FR-3`. Rejected for the same reason: this application
  would decrypt the document on every list (byte comparison) and every
  switch. The live home would remain plaintext.
- **Do not keep a second copy. Switch only by pointing `CODEX_HOME` at
  a launch-time home.** Avoids a stored plaintext copy this application
  created. Rejected: this application does not launch Codex, and users
  run the CLI and the VS Code extension against the default home. A
  stored copy is what makes a switch without re-authentication possible
  for those sessions.

Revisit if any of these become true: the specification is changed so
`FR-3` no longer forbids this shape; a launcher exists that can point
`CODEX_HOME` at a store-backed home without persisting the file; or
evidence shows a copied `auth.json` is rejected by the vendor, in which
case the switch premise fails and the storage location is moot.
