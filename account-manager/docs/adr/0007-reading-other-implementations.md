# 0007. Reading other implementations

- **Status**: Accepted
- **Date**: 2026-08-19

## Context

`0006` forbids taking code, assets, strings, documentation, or licence text
from `lbjlaq/Antigravity-Manager`. That project's CC-BY-NC-SA-4.0 licence
would carry a non-commercial restriction into this GPL-3.0-or-later
codebase, which `0005` already rejected. That reasoning is unchanged and
must survive this decision.

`0006` also stated a stronger claim: that this is a clean-room
implementation that would not look at other projects at all. That was more
than the legal problem required. Copyright protects expression, not ideas
or facts. Studying how another project solves a problem, and then writing
an independent implementation, is lawful. The copy ban was aimed at
copying expression, not at remaining ignorant of existing solutions.

The stronger claim has a practical cost as well as a legal one.
Contributors who have seen another account manager or relay still need a
way to use that understanding without treating the other project's source
as evidence about what a managed tool actually does.

This project's write-path safety argument rests on
`docs/research/README.md`. A write path may not depend on an `[inferred]`
claim. Opening other implementations as reading material makes unverified
claims easier to acquire. The marker rules therefore have to be stated
here, not assumed.

Verified licences of the projects the owner named:

| Project                                          | SPDX                                 |
| ------------------------------------------------ | ------------------------------------ |
| `farion1231/cc-switch`                           | MIT                                  |
| `router-for-me/CLIProxyAPI`                      | MIT                                  |
| `manaflow-ai/subrouter`                          | MIT                                  |
| `errhythm/cc-swap`                               | MIT                                  |
| `VictorMinemu/CC-Router`                         | MIT                                  |
| `christiandoxa/prodex`                           | Apache-2.0                           |
| `Dicklesworthstone/coding_agent_account_manager` | NOASSERTION                          |
| `lbjlaq/Antigravity-Manager`                     | NOASSERTION (CC-BY-NC-SA per `0006`) |
| `router-for-me/EasyCLIProxyAPI`                  | no licence file                      |

A `NOASSERTION` result is not a licence grant. It is not a candidate for
any later decision to vendor code.

## Decision

Permit reading other implementations for understanding. Continue to forbid
copying code, assets, or text from any project.

A claim learned from another implementation is a hypothesis, not evidence.
Another project's source shows what that project believes about a tool, a
path, or a protocol. It does not show what the tool does. The only things
that show what the tool does are a local observation and official vendor
documentation — `[verified-local]` and `[verified-docs]` in
`docs/research/README.md`.

A fact found by reading another implementation enters `docs/research/`
only with the marker its own verification earns, exactly like any other
claim. Until that verification exists, the strongest honest marker is
`[inferred]`. "Another project does it this way" is `[inferred]` at best.
It is a fast way to form a hypothesis and no substitute for verifying one.

A write path may not depend on an `[inferred]` or `[unknown]` claim. That
rule does not relax because the hypothesis came from a widely used
repository, a confident README, or a comment that happens to be right.

This decision does not vendor anyone else's code. MIT and Apache-2.0
projects are one-way compatible with GPL-3.0-or-later, so a future
decision to vendor code from them would be lawful if attribution were
preserved. That is a different decision and has not been made. Until it
is, the copy ban applies to those projects too.

Two named projects remain off-limits for both reading-into-code and
copying:

- `lbjlaq/Antigravity-Manager`, for the licence reasons recorded in `0006`.
- `router-for-me/EasyCLIProxyAPI`, which has no licence file. All rights
  are reserved.

`0006` is narrowed, not superseded.

## Consequences

- Contributors may read other implementations — other than the off-limits
  projects named above — as inspiration, then write original code.
- The copy ban is unchanged. A pull request that pastes third-party code,
  assets, or text is still closed rather than reworked.
- `0006`'s clean-room claim about `lbjlaq/Antigravity-Manager` stands.
  That project stays off-limits.
- The research marker discipline is stricter in practice, not looser.
  Permission to read is permission to form hypotheses faster. It is not
  permission to skip `[verified-local]` or `[verified-docs]`. An
  `[inferred]` claim still cannot support a write path.
- **Cost**: reviewers must distinguish inspiration from copying, which is
  harder than a total reading ban.
- **Cost**: unlicensed and CC-BY-NC-SA sources remain a contamination
  risk if they are read into code. They stay off-limits.
- **Cost**: this ADR does not authorise vendoring, even from
  licence-compatible projects. A later ADR would have to do that
  explicitly.

## Alternatives considered

- **Keep the total reading ban.** Simplest contamination story. Rejected:
  it overstates the legal problem, and it forbids a lawful way to form
  hypotheses that still have to be verified against the real tool.
- **Permit copying from MIT and Apache-2.0 projects.** Licence-compatible,
  with attribution. Rejected: that is a vendoring decision, not this one.
  Copying remains forbidden until a later ADR says otherwise.
- **Permit reading `lbjlaq/Antigravity-Manager` but not copying it.**
  Rejected: `0006` stands. Its licence would still contaminate this
  codebase if expression were carried across, and the project has already
  paid the cost of independent implementation.
- **Treat another project's source as `[verified-docs]` or equivalent.**
  Rejected: another project's code is a claim about what its author
  believes, not an observation of the managed tool and not official vendor
  documentation.
