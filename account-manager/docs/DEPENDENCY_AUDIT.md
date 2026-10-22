# Desktop dependency audit

The desktop shell has a separate Cargo lockfile and supply-chain policy. The
2026-10-22 update selects Tauri 2.12.5, tauri-build 2.7.4 and opener 2.7.2,
including urlpattern 0.6.0. This removes the five unmaintained `unic-*` crates.
The root workspace and the explicit keyring-core/native-store migration keep
separate, exception-free advisory policies.

From the repository root, run:

```bash
cargo audit --deny warnings
cargo deny --locked check -D warnings advisories bans licenses sources
python3 scripts/check_desktop_supply_chain.py
```

Use the repository-pinned Nix development shell for the tools. The last command
first checks the exact affected package versions and sources, then runs
`cargo audit --deny warnings` on the desktop lockfile with only the reviewed
advisory IDs, followed by `cargo deny` with the desktop policy. CI runs all
three checks. `--check-only` validates exception scope without network access.

## Remaining upstream constraints

Five desktop-only advisories have no compatible patched release in the current
Tauri stack. An unqualified audit of the desktop lockfile still reports them;
the policy passes with these explicit dispositions, not with zero advisories.
Their exact versions, rationale and removal conditions are in
`src-tauri/Cargo.toml` under `package.metadata.desktop-advisories`. The checker
rejects changed versions, additional versions, source replacements, missing
packages and differences between the manifest and the deny ignore list.
`cargo deny` also rejects unused exceptions and checks transitive unsoundness.

| Advisory                                                                   | Exact package            | Constraint and removal condition                                                                     |
| -------------------------------------------------------------------------- | ------------------------ | ---------------------------------------------------------------------------------------------------- |
| [RUSTSEC-2024-0370](https://rustsec.org/advisories/RUSTSEC-2024-0370.html) | `proc-macro-error` 1.0.4 | Build-time dependency of GTK3/glib macros. Remove when Tauri drops this macro stack.                 |
| [RUSTSEC-2024-0429](https://rustsec.org/advisories/RUSTSEC-2024-0429.html) | `glib` 0.18.5            | GTK3 0.18 cannot use patched glib >=0.20. Remove when Tauri supports compatible patched bindings.    |
| [RUSTSEC-2026-0371](https://rustsec.org/advisories/RUSTSEC-2026-0371.html) | `zbus_names` 4.3.4       | Opener 2.7.2 requires zbus 5; name types moved into zbus 6. Remove when released opener migrates.    |
| [RUSTSEC-2026-0370](https://rustsec.org/advisories/RUSTSEC-2026-0370.html) | `zvariant` 5.15.0        | Opener's zbus 5 serialization stack; replacement is in zbus 6. Remove when released opener migrates. |
| [RUSTSEC-2026-0372](https://rustsec.org/advisories/RUSTSEC-2026-0372.html) | `zvariant_derive` 5.15.0 | Build-time derives for that serialization stack. Remove when released opener migrates.               |

Source inspection found no `VariantStrIter` or `array_iter_str` call in the
application or inspected resolved GTK/Tauri dependents. This is a call-site
inventory, not proof of runtime unreachability. Opener's zbus path implements
Linux file-manager integration; the application's login command uses URL
opening. No GUI or credential service is exercised by the supply-chain checks.

The eliminated advisories are RUSTSEC-2025-0075 (`unic-char-range`),
RUSTSEC-2025-0080 (`unic-common`), RUSTSEC-2025-0081 (`unic-char-property`),
RUSTSEC-2025-0098 (`unic-ucd-version`) and RUSTSEC-2025-0100 (`unic-ucd-ident`),
all formerly at 0.9.0.

## Licenses and duplicate versions

`src-tauri/deny.toml` preserves the root's narrow license allow list and strict
source policy. Exact-package exceptions cover the owned GPL desktop package,
the BSD compression dependencies, MPL CSS parser dependencies and Zlib-licensed
foldhash. These do not grant blanket license permission to future dependencies.
Incompatible versions required by GTK, Tauri and platform bindings have exact
version duplicate allowances with their immediate dependency paths and removal
conditions. The policy still rejects new unreviewed duplicates and licenses.

The encrypted credential format and DH-encrypted Secret Service configuration
are unchanged. `scripts/check_keyring_crypto.py` continues to check both graphs.
