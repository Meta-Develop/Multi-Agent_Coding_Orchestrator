# Published JSON schema contracts

MACO publishes Draft 2020-12 schemas for the machine-readable outputs below. Consumers should pin the versioned filename and `$id`; unversioned aliases are intentionally not provided.

| Artifact | Producer | Published schema | Artifact discriminator |
| --- | --- | --- | --- |
| Repository map | `maco repo map --json` | `schemas/repository-map-v1.schema.json` | Schema filename/`$id` only |
| Semantic risk report | `maco repo query risk --json` | `schemas/semantic-risk-report-v1.schema.json` | Schema filename/`$id` only |
| Merge preview report | `maco merge preview --json` | `schemas/merge-preview-report-v1.schema.json` | Schema filename/`$id` only |
| Merge apply report | `maco merge apply --json` | `schemas/merge-apply-report-v1.schema.json` | Schema filename/`$id` only |
| Newly finalized supervisor report | `supervisor-final.json` | `schemas/supervisor-final-report-v1.schema.json` | Top-level `version: 1`; economics `schema_version: 5` |

Each `$id` is the corresponding raw file URL under the repository's `main/schemas/` directory. The apply schema uses confined sibling references to the preview schema, so consumers should keep the downloaded schema files together. No schema reference requires a package registry or another network dependency.

Merge preview v1 includes the closed `freshness_watermark` version-1 object and the full patch used to derive its candidate diff OID. Merge apply v1 covers both the ordinary applied/nothing-to-apply/blocked envelope and the structured `status: "refused"` freshness error emitted before an apply report can be built. On an ordinary report, `review_bound: true` is paired only with `review_binding_status: "matched"`; an in-command preview that was not supplied for review emits `review_bound: false` and `review_binding_status: "not_supplied"`. A supplied preview that is rejected before binding emits `review_bound: false` with `review_binding_status: "not_bound"`; an in-command freshness refusal with no supplied preview remains `not_supplied`.

## Compatibility rules

Fixed Rust objects are closed with `additionalProperties: false`, and current enum values are explicit. Adding or removing a field, changing requiredness or nullability, or extending a closed enum requires a new published schema version. Existing `v1` files should not be rewritten into a breaking contract.

Some embedded values are already separately evolving artifact families. The optional merge lifecycle subobjects and the supervisor's gate, orchestration, traceability, and environment subrecords therefore retain open compatibility boundaries. Their container type and top-level field are still fixed. This document identifies these exceptions.

The repository-map, semantic-risk, and merge reports do not currently serialize an artifact version member. Their contract version is selected out of band through the schema filename and `$id`; consumers must not infer it from another numeric field. The newly finalized supervisor schema describes current finalized reports, not historical reports that happen to share top-level `version: 1` but predate economics schema version 5.

JSON Schema `maxLength` counts Unicode code points, while several Rust producer limits count encoded bytes. The published limits are useful interoperable bounds, but they do not replace producer-side byte accounting. Unsigned Rust integers can also exceed the exact IEEE-754 integer range; consumers should use an integer-capable JSON representation.

## Fixtures and validation

Every published schema has at least one accepted and one deliberately rejected fixture in `fixtures/schemas/`. `fixtures/schemas/manifest.json` binds each invalid fixture to an exact instance path and failed keyword, so a negative fixture cannot accidentally become accepted or fail only for an unrelated reason.

Run the dependency-free gate from the repository root:

```bash
python3 scripts/check_json_schemas.py
python3 -m unittest scripts.tests.test_check_json_schemas -v
```

The checker uses only the Python standard library. It rejects duplicate object keys, non-standard numeric constants (`NaN` and infinities), unresolved or non-confined references, malformed keyword values, and every unsupported JSON Schema keyword before validating an instance. Its supported assertion vocabulary covers types, constants/enums, closed objects, arrays and uniqueness, string patterns/lengths, numeric bounds, local and declared-sibling references, composition, conditionals, and `contains` cardinality. Booleans are not treated as integers, and JSON-aware equality is used for `const`, `enum`, and `uniqueItems`.

Schema and fixture discovery is closed: every `schemas/*.schema.json`, `fixtures/schemas/*.valid.json`, and `fixtures/schemas/*.invalid.json` file must appear exactly once in the manifest. Checked-in fixtures are also rejected if they contain the current checkout path or recognizable user-home path forms.

## Path privacy boundary

The semantic-risk report and newly finalized supervisor report use repository-relative or explicit sentinel paths at their public reporting boundaries. The supervisor schema permits either native path separator while rejecting absolute, drive-prefixed, traversal, and control-character forms for its published path fields.

Current producers have unresolved privacy gaps:

- Repository-map `root` is an absolute discovered worktree path.
- Merge preview/apply `candidate.metadata.worktree_path` and `primary_repo_root` are absolute local paths. Optional lifecycle and free-text diagnostics may carry additional local path text.
- Supervisor command `stdout`, `stderr`, and `error` capture, findings, remaining-risk text, and other free-form diagnostics can still contain paths supplied by child processes or tools even though typed supervisor path fields are sanitized.

The published schemas keep those fields as opaque strings so they validate the real current output; declaring them repository-relative would create a false contract. Fixtures use synthetic `/workspace/repository` values and contain no developer or checkout paths. Consumers should scrub free-form diagnostics before republishing them. Producer-side sanitization requires implementation changes outside this schema publication and is not implied by these contracts.

The supervisor currently also writes a per-run generated schema as private evidence. That legacy sidecar is a partial, open compatibility document and has no stable `$id`; it is not the published 51-field newly-finalized contract. Giving both documents the same identity before their validation semantics match would be incorrect, so the versioned file under `schemas/` is the external contract.
