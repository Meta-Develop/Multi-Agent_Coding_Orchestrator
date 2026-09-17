# Security policy

## Reporting a vulnerability

**Do not open a public issue for a security problem.**

Report it privately through GitHub Security Advisories:
[Report a vulnerability](https://github.com/Meta-Develop/Coding-Agent-Manager/security/advisories/new).

Please include:

- What the issue is and why it matters.
- Steps to reproduce, or a proof of concept.
- Affected version, platform, and provider if relevant.
- Anything you have found about impact or exploitability.

**Never include a real credential in a report.** If reproducing needs one, say
so and describe its shape; the fixtures make a redacted repro possible.

## What to expect

| Stage                  | Target                                             |
| ---------------------- | -------------------------------------------------- |
| Acknowledgement        | Within 3 days                                      |
| Initial assessment     | Within 7 days                                      |
| Fix or mitigation plan | Within 30 days for a confirmed high-severity issue |

This is a volunteer-maintained project; these are honest targets, not a
contractual SLA. You will get a real answer either way.

## Supported versions

Pre-1.0, only the latest release is supported. After 1.0 this table will list
supported lines.

## Scope

In scope, and treated as high severity:

- Any path by which a credential can be read by something that should not read
  it — a log, an error message, a crash report, a diagnostic export, the
  webview, another process.
- The relay accepting a request it should have rejected, or binding somewhere it
  should not.
- A switch that destroys a user's config without a restorable backup.
- Anything that makes a statement in
  [`docs/SECURITY_MODEL.md`](docs/SECURITY_MODEL.md) §4 false. Those are
  promises; a violation is a vulnerability by definition.

Out of scope:

- Vulnerabilities in the vendor tools this project manages. Report those to
  their vendors.
- An attacker who already has full local access as the user. That threat model
  is stated in `docs/SECURITY_MODEL.md` §2.
- Findings from an automated scanner with no demonstrated impact.

## Disclosure

Coordinated. We will agree a disclosure date with you, publish an advisory, and
credit you unless you prefer otherwise. A fix for a credential-exposure issue
ships as its own patch release, ahead of queued feature work.
