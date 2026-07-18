# Contributing

## Development Setup

Use the Nix development shell when you want the repository-pinned native tools:

```bash
nix develop .
```

Inside the shell, run Cargo normally. If Rust is already available on your
system, you can run the same Cargo commands without Nix.

## Verification

Run these gates before sending changes for review:

```bash
cargo fmt -- --check
cargo test
cargo clippy --all-targets -- -D warnings
```

Use `--locked` when checking release or CI parity against `Cargo.lock`.

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
