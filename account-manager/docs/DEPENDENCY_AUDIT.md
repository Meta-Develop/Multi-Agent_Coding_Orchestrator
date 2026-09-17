# Imported dependency audit disposition

This records the source import's dependency review on 2026-09-13. It is not a
blanket exception for later upgrades. The application keeps its own Cargo
lockfile; MACO's root lockfile and `deny.toml` policy are separate.

## Native dependency correction

The imported lock contained yanked `chacha20` 0.10.1 through
`chacha20poly1305`, used by the encrypted credential store. The lock now selects
the unyanked 0.10.2 patch release. RustCrypto documents an SSE backend correction
in its [changelog][chacha-changelog], and [crates.io][chacha-release] declares
Rust 1.85 as its minimum. The patch preserves the existing credential format and
does not add a credential migration. No other package version is upgraded.

## Remaining desktop warnings

`cargo audit --deny warnings` over the complete application lockfile remains
unsuccessful because of the following inherited desktop dependencies. These are
kept visible; no advisory ignore list or broad license/dependency exception is
introduced. The initial inspection used cargo-audit 0.22.2 and RustSec database
commit `b50980aad8b8f14f77e25a97b32dd94bf008b0af`.

| Locked package             | Advisory                                                            | Resolved Linux desktop path                                          |
| -------------------------- | ------------------------------------------------------------------- | -------------------------------------------------------------------- |
| `glib` 0.18.5              | [RUSTSEC-2024-0429][glib-advisory], unsound string-variant iterator | Tauri → GTK → glib                                                   |
| `proc-macro-error` 1.0.4   | [RUSTSEC-2024-0370][macro-advisory], unmaintained                   | Tauri → GTK → gtk3-macros                                            |
| `unic-char-property` 0.9.0 | [RUSTSEC-2025-0081][property-advisory], unmaintained                | Tauri → tauri-utils → urlpattern → unic-ucd-ident                    |
| `unic-char-range` 0.9.0    | [RUSTSEC-2025-0075][range-advisory], unmaintained                   | Tauri → tauri-utils → urlpattern → unic-ucd-ident                    |
| `unic-common` 0.9.0        | [RUSTSEC-2025-0080][common-advisory], unmaintained                  | Tauri → tauri-utils → urlpattern → unic-ucd-ident → unic-ucd-version |
| `unic-ucd-ident` 0.9.0     | [RUSTSEC-2025-0100][ident-advisory], unmaintained                   | Tauri → tauri-utils → urlpattern                                     |
| `unic-ucd-version` 0.9.0   | [RUSTSEC-2025-0098][version-advisory], unmaintained                 | Tauri → tauri-utils → urlpattern → unic-ucd-ident                    |

The glib advisory identifies a fix in 0.20 or newer; the locked GTK 0.18 series
requires glib 0.18. Source inspection of the resolved Linux desktop packages
found `VariantStrIter` and `array_iter_str` only within glib's implementation,
documentation, and tests. It found no call from this application or its resolved
dependents. That is a call-site inventory, not a proof covering generated code
or every runtime path, and the warning remains unresolved. This import does not
replace GTK or patch third-party implementation code.

The unmaintained-crate advisories list no patched versions. Replacing their
upstream consumers is separate dependency work. All seven warning packages are
absent from the resolved `--no-default-features` native core graph. That graph
exclusion does not make the whole-lock desktop audit pass.

[chacha-changelog]: https://github.com/RustCrypto/stream-ciphers/blob/master/chacha20/CHANGELOG.md
[chacha-release]: https://crates.io/crates/chacha20/0.10.2
[glib-advisory]: https://rustsec.org/advisories/RUSTSEC-2024-0429.html
[macro-advisory]: https://rustsec.org/advisories/RUSTSEC-2024-0370.html
[property-advisory]: https://rustsec.org/advisories/RUSTSEC-2025-0081.html
[range-advisory]: https://rustsec.org/advisories/RUSTSEC-2025-0075.html
[common-advisory]: https://rustsec.org/advisories/RUSTSEC-2025-0080.html
[ident-advisory]: https://rustsec.org/advisories/RUSTSEC-2025-0100.html
[version-advisory]: https://rustsec.org/advisories/RUSTSEC-2025-0098.html
