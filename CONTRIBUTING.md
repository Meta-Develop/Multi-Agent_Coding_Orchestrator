# Contributing

## Development Setup

The authoritative local environment for CI parity is the repository's Nix
development shell:

```bash
nix develop path:$PWD
```

It provides the Rust toolchain selected by `rust-toolchain.toml` and the Python
interpreter used by the repository-portability gate. An ambient system
toolchain is not evidence of CI parity.

## Verification

Run these one-shot gates before sending changes for review:

```bash
nix develop path:$PWD -c rustc --version --verbose
nix develop path:$PWD -c cargo --version --verbose
nix develop path:$PWD -c cargo clippy --version
nix develop path:$PWD -c python3 -m unittest discover -s scripts/tests -p 'test_*.py'
nix develop path:$PWD -c python3 scripts/check_repository_portability.py
nix develop path:$PWD -c cargo fmt --all -- --check
nix develop path:$PWD -c cargo check --locked --all-targets
nix develop path:$PWD -c cargo clippy --locked --all-targets -- -D warnings
nix develop path:$PWD -c cargo test --locked --all-targets
nix develop path:$PWD -c cargo audit --deny warnings
nix develop path:$PWD -c cargo deny --locked check -D warnings advisories bans licenses sources
```

These commands reproduce the Linux CI toolchain, the tracked-path portability
gate, and the supply-chain job. The development shell pins `cargo-audit` and
`cargo-deny` to the same releases CI installs.

They cannot compile or link target-specific code on actual macOS or Windows
runners. Before treating a branch as fully CI-green, push it or open a draft
pull request and wait for both the `macos-latest` and `windows-latest`
`portable-build` jobs; a draft pull request is the cheapest honest way to close
that residual gap.

## Tests

Keep tests focused on the behavior changed by the patch. Prefer small unit
tests for pure logic and CLI/integration tests for user-visible command
behavior.

Production code must not use `unwrap()` or `expect()`. Return contextual errors
instead. Test code may use them when a failing setup step should fail the test
immediately.

Environment-gated or platform-gated tests must state the reason explicitly in
their `#[ignore = "..."]`, skip message, or assertion context.

## Commits

Write imperative, neutral, technical commit messages. Do not add tool,
automation, or authorship attribution to commit messages.
