# 0005. GPL-3.0-or-later

- **Status**: Accepted
- **Date**: 2026-08-18

## Context

The project is public from day one. It is also a tool that handles credentials,
which makes two things matter more than usual: users must be able to audit what
it does with their secrets, and improvements to that handling should stay
available to everyone.

The owner's existing public desktop utilities use GPL-3.0, so this also matches
established practice in the same account.

## Decision

License under GPL-3.0-or-later. The full licence text is in `LICENSE`.

## Consequences

- Anyone distributing a modified version must publish their source, so a fork
  that weakens credential handling cannot be shipped as a closed binary.
- The GPL-3 anti-tivoisation and patent provisions apply, which suits a desktop
  tool intended to be inspected and rebuilt by its users.
- **Cost**: the project cannot be embedded in proprietary software. This is the
  intended effect, not a side effect.
- **Cost**: some contributors avoid copyleft. Accepted.
- Dependencies must be licence-compatible. Permissive dependencies (MIT,
  Apache-2.0, BSD) are fine; adding a dependency under an incompatible copyleft
  licence is a blocking review comment.

## Alternatives considered

- **MIT or Apache-2.0.** Maximum adoption and the easiest contribution story.
  Rejected: a permissive licence allows a closed fork of a credential manager,
  and users of that fork would have no way to audit it.
- **AGPL-3.0.** Stronger, and it would cover the relay if someone ran it as a
  network service. Rejected as disproportionate for a desktop application whose
  relay is loopback-bound by design; AGPL's network clause mostly adds friction
  for ordinary users here.
- **CC-BY-NC-SA-4.0**, as used by the project that inspired this one. Rejected:
  Creative Commons licences are not designed for software, the non-commercial
  restriction is famously ambiguous, and it would make the project unusable
  inside any company — including by developers managing their own work accounts,
  who are a core audience.
