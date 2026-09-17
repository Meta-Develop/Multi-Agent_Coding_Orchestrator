# Provider research notes

These notes are the evidence base every provider adapter is written against.
An adapter writes to files that a user depends on for their working login; a
wrong path claim here becomes a locked-out account there. Treat these documents
as load-bearing.

## Confidence markers

Every factual claim carries exactly one marker:

| Marker              | Means                                                                                                                                                  |
| ------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `[verified-local]`  | Observed directly on a real installation. The note records the tool version and the OS.                                                                |
| `[verified-source]` | Observed in first-party source code at an immutable revision with exact source citations. This does not prove that a locally installed binary matches. |
| `[verified-docs]`   | Stated in official vendor documentation. The note cites the URL.                                                                                       |
| `[inferred]`        | Reasoned from other evidence, not directly confirmed. Safe to design around, never safe to write against.                                              |
| `[unknown]`         | Not established. Listed in the note's "Open questions" section.                                                                                        |

Rules:

- Never upgrade a marker without new evidence, and record what that evidence was.
- An `[inferred]` or `[unknown]` claim must not be relied on by a code path that
  **writes**. Reading and detecting are fine.
- A confident guess is worse than an honest `[unknown]`, because the next person
  cannot tell the difference between the two once it is written down.

## Redaction rules

These notes are public. When documenting a credential file:

- Record **key names and structure**. Never record a value.
- Use `"access_token": "<redacted>"` for shapes.
- Never include a real email address, user id, organisation id, account id,
  device id, or machine-local absolute home path.
- Never paste a raw file. Reproduce its schema by hand.

## How observations were made

The August 2026 baseline was collected on a NixOS Linux host by listing
directory structures and reading JSON **key names only** through a script that
prints types rather than values. No credential value was read, stored, or
transmitted at any point.

## Note template

Each note follows the same section order:

1. Identity — name, vendor, version observed, OS observed
2. Config locations — per OS, with markers
3. Credential format — key names and structure only
4. Authentication flow
5. Account switching mechanics
6. Quota and usage signals
7. API surface and base-URL override
8. Risks and constraints
9. Open questions
