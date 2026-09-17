# Documentation index

## Start here

| Document                                 | Read it when                                                                                                          |
| ---------------------------------------- | --------------------------------------------------------------------------------------------------------------------- |
| [`SPEC.md`](SPEC.md)                     | You need to know what the product must do. Requirements are numbered `FR-*` / `NFR-*` and referenced everywhere else. |
| [`ARCHITECTURE.md`](ARCHITECTURE.md)     | You are about to write or review code.                                                                                |
| [`DEVELOPMENT.md`](DEVELOPMENT.md)       | You are setting up, building, or debugging.                                                                           |
| [`SECURITY_MODEL.md`](SECURITY_MODEL.md) | You touch anything near a credential. Which is most things.                                                           |
| [`TESTING.md`](TESTING.md)               | You are writing tests, especially around credentials.                                                                 |
| [`ROADMAP.md`](ROADMAP.md)               | You want to know what is next and why.                                                                                |
| [`RELEASE.md`](RELEASE.md)               | You are cutting a release.                                                                                            |
| [`GLOSSARY.md`](GLOSSARY.md)             | A term in these documents is not obvious.                                                                             |

## Reference

| Document                                   | What it holds                                                             |
| ------------------------------------------ | ------------------------------------------------------------------------- |
| [`PROVIDER_MATRIX.md`](PROVIDER_MATRIX.md) | One-page comparison of every provider's auth, storage, and switchability. |
| [`research/`](research/)                   | Per-provider evidence notes. Every claim carries a confidence marker.     |
| [`adr/`](adr/)                             | Architecture decision records — what was decided, and what was rejected.  |

## Conventions

- Everything here is written in **English**.
- Requirements are referenced by id (`FR-3`, `NFR-1`), never by paraphrase, so
  code, tests, issues, and the roadmap all point at the same thing.
- Claims about a third-party tool's on-disk behaviour carry a confidence marker
  — see [`research/README.md`](research/README.md). Guessing a config path and
  writing to it is how a manager tool destroys someone's login.
- Diagrams are Mermaid code blocks, so they diff and review as text.
