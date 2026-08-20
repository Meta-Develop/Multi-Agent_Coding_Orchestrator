# Issue 33 synthetic authenticated claims journal

`generate_authenticated_claims_state_v1.py` deterministically writes the
compact checkout tree `state/j/` and its SHA-256 manifest. The test helper
installs the files under the authentic runtime path
`authenticated-claims-state-v1/<physical-journal-id>/`; only the checked-in
source layout is shortened so a default Windows checkout remains below
`MAX_PATH`. Regenerate it from the repository root with:

```bash
python3 tests/fixtures/issue33/generate_authenticated_claims_state_v1.py
```

Every identity is fixture-only. The repository authentication key is 32 bytes
of `0x33`; repository, run, journal, and temporary-file identifiers are SHA-256
digests of labels beginning with `MACO Issue 33 synthetic fixture`; and the
device/file values are the conspicuous reserved test constants `33333333` and
`33000001` through `33000003`. They were not read from a filesystem, Git
repository, MACO run, or operator environment.

The generator implements the v1 repository-authentication frame and the
authenticated-claims record/head domains. It constructs four canonical
snapshot records, chains their HMAC-SHA-256 tags, and signs the matching head.
Three records are durable fixture entries; the fourth record and head use the
canonical temporary-file forms exercised by the original Issue 33 state shape.
The generator verifies the complete chain and head before writing any output.
`authenticated-claims-state-v1.sha256` binds the exact compact source inventory
and bytes.

The chosen proof property is independent of those contents: the fixture root
contains the physical journal but deliberately contains no signed logical
locator or initialization/rollover intent that anchors it. The development
build inventories physical journals before it opens their records, so the
expected result is exactly:

```text
authenticated snapshot physical journal 'd9741d2f810d605133ddfb24bca389e7f1e96fd2a3da1bc5ca236da56519306f' is not anchored by any signed logical state
```

The structurally valid HMAC chain prevents an unrelated integrity defect from
being baked into the evidence even though the anchoring refusal occurs first.

For the fail-capability neuter, pass `--anchor-synthetic-identity`. This adds a
validly signed `claims` initialization intent for the synthetic run to the
fixture namespace. That optional file is not part of the committed fixture;
the Issue 33 test helper installs it only when present. With it present, root
inventory recognizes the physical identity as logically anchored and the
test's exact unanchored-error assertion must fail. Running the generator again
without the flag restores the publishable fixture.

## Same-state asymmetry regression

The operator-provided registry-backed wrapper is deliberately not a default
test dependency. Run the ignored effectful regression explicitly:

```bash
MACO_ISSUE33_PINNED_WRAPPER=/absolute/path/to/project/.agents/scripts/maco \
  cargo test --test cli_smoke \
  cli_issue33_same_installed_state_proves_dev_pinned_asymmetry_and_gc_failure \
  -- --ignored --exact
```

The environment variable is mandatory: an absent, relative, non-file, or
non-executable wrapper is a test failure, never a skip. The test installs the
generated state once in a temporary repository, runs the pinned wrapper first,
then asserts the development `sync status` and pre-recovery dry-run `worktree
gc` failures against that same repository. It also asserts that the claims and
physical-journal bytes remain unchanged across all three observations. The
wrapper must have SHA-256
`93b76ebff318fb75e44f8ce48b5b48b4bad5435045d9fe736c4e1fc587a0d814`
and resolve its attached package to clean Git checkout
`66f59aa253868d1dd909b012e04c548e7b669d2f`; both bindings are rechecked after
the pinned invocation. Its nested Cargo build runs offline and writes its
target only inside the test temporary directory.
