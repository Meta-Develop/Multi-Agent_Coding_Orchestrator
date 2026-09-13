# Codex CLI (OpenAI)

## 1. Identity

- Tool: `codex`, distributed as `codex-cli`.
- Vendor: OpenAI.
- Version observed: **0.144.4** `[verified-local]`.
- OS observed: Linux (NixOS), August 2026.

## 2. Config locations

| Path                    | Purpose                                         | Marker             |
| ----------------------- | ----------------------------------------------- | ------------------ |
| `~/.codex/auth.json`    | Credentials                                     | `[verified-local]` |
| `~/.codex/config.toml`  | Client configuration, per-project trust entries | `[verified-local]` |
| `$CODEX_HOME`           | Overrides the whole `~/.codex` directory        | `[verified-docs]`  |
| `$CODEX_HOME/auth.json` | Credential lookup when `CODEX_HOME` is set      | `[verified-local]` |

On Linux (NixOS) with 0.144.4, `CODEX_HOME` relocated credential lookup for
`codex login status`. The CLI reported identity from that directory's
`auth.json` and did not fall back to the default home `[verified-local]`.
Whether `CODEX_HOME` also relocates `config.toml` and the rest of the
directory was not tested. That broader override remains `[verified-docs]`.

macOS is expected to use the same `~/.codex` layout `[inferred]`. Windows is
expected to use `%USERPROFILE%\.codex` `[inferred]`. Both need confirmation on a
real host.

## 3. Credential format

`~/.codex/auth.json` `[verified-local]`, key names only:

```jsonc
{
  "auth_mode": "<string>", // e.g. a plan-based or api-key mode
  "OPENAI_API_KEY": null, // null while signed in through a plan
  "tokens": {
    "id_token": "<redacted>",
    "access_token": "<redacted>",
    "refresh_token": "<redacted>",
    "account_id": "<redacted>",
  },
  "last_refresh": "<timestamp string>",
}
```

The whole credential state is one flat document. That single fact is what makes
Codex the cheapest first adapter.

## 4. Authentication flow

- `codex login` performs a browser-based sign-in `[verified-docs]`.
- An API key can be supplied instead, in which case `OPENAI_API_KEY` is
  populated and `tokens` is expected to be absent or unused `[inferred]`.
- `last_refresh` suggests the CLI refreshes on its own schedule and rewrites the
  file in place `[inferred]`.

## 5. Account switching mechanics

Two candidate strategies:

1. **Swap `auth.json`.** Back up, write the target account's document
   atomically, and let the CLI pick it up on next start. `auth.json` is the
   file `login status` reports from `[verified-local]`. In a full copy of a
   populated live Codex home, that file alone decided the reported identity
   `[verified-local]`. The live default home was not mutated. As a directory
   of files the copy differed from it only by path, which is what
   `CODEX_HOME` substitutes.
2. **Relocate `CODEX_HOME`.** Keep one directory per account and point the
   environment variable at the right one. On this host, with 0.144.4,
   `CODEX_HOME` relocated the whole credential lookup `[verified-local]`.
   This never mutates a file the user's default home owns. It only works for
   sessions this application launches or for shells the user configures.

Under `.agents/docs/PROJECT_RULES.md`, a write path may depend only on
`[verified-local]` or `[verified-docs]` claims. A write path may now rest on
replacing `auth.json` in the resolved Codex home — the default home or a
`CODEX_HOME` directory — because that file alone decides the identity
`login status` reports, including in a populated home. It may not rest on
treating `login status` as proof the credential works against the vendor, or
on assuming the server-side session remains valid after a copy. An adapter
that writes this way must refuse while a Codex process is using the home
(§8).

Observation 1 (2026-08-19), Linux (NixOS), `codex-cli` 0.144.4. No API
request was made. No credential value was read. The real Codex home was not
modified: its `auth.json` mtime was unchanged, and a final
`codex login status` still reported "Logged in using ChatGPT".

A temporary directory stood in as `CODEX_HOME`. Command shape:

1. `CODEX_HOME=<empty temp dir> codex login status` → **"Not logged in"**.
2. `codex login status` (real home, untouched) → **"Logged in using ChatGPT"**.
3. `cp -p` of `auth.json` from the real home into the temp directory, then
   `CODEX_HOME=<temp> codex login status` → **"Logged in using ChatGPT"**.
4. Remove the copied `auth.json`, then the same command → **"Not logged in"**.
5. Real home rechecked → still **"Logged in using ChatGPT"**.

Two claims follow, and only these two:

- `auth.json` alone determined the reported identity for a given
  `CODEX_HOME`. Placing it made the CLI report signed-in. Removing it made
  the CLI report signed-out. Nothing else in the directory was needed
  `[verified-local]`.
- `CODEX_HOME` relocated the whole credential lookup `[verified-local]`.

Observation 2 (2026-08-19), Linux (NixOS), `codex-cli` 0.144.4. No API
request was made. No credential value was read. The real Codex home was not
modified: its `auth.json` mtime was unchanged throughout, and a final
`codex login status` against the real home still reported
"Logged in using ChatGPT".

The entire live Codex home was copied with `cp -a` into a temporary
directory — more than forty entries, including `config.toml`, `sessions/`,
`history.jsonl`, several SQLite databases, `installation_id`,
`models_cache.json`, and `version.json`. Command shape:

1. `CODEX_HOME=<copy> codex login status` → **"Logged in using ChatGPT"**.
2. Move `auth.json` aside inside the copy, leaving every other entry in
   place, then the same command → **"Not logged in"**.
3. Move `auth.json` back, then the same command → **"Logged in using ChatGPT"**.
4. Real home rechecked → still **"Logged in using ChatGPT"**, `auth.json`
   mtime unchanged.

What this adds to observation 1: the first probe used an empty directory, so
it could not rule out another file in a populated home participating in
identity. This one used a byte-for-byte copy of a real, fully populated home
and showed that `auth.json` alone decides. As a directory of files, the
copy differed from the live home only by path, which is what `CODEX_HOME`
substitutes. The copy had no long-running Codex process attached. That
difference does not add a second identity file. It is a write hazard (§8).

Two further claims follow, and only these two:

- In a populated Codex home, `auth.json` alone determined the reported
  identity. Other files present in a live home did not supply it when
  `auth.json` was absent `[verified-local]`.
- Relocating that populated home with `CODEX_HOME` produced the same
  `login status` result as the live home, then followed the presence of
  `auth.json` `[verified-local]`.

`login status` reports what the CLI believes. Neither probe showed that a
copied or restored file still works against the vendor. No model request
was made, so the vendor's acceptance of a moved credential is untested.
Both probes used one account. Neither alternated two identities. Whether
replacing `auth.json` invalidates the session server-side remains
`[unknown]`.

## 6. Quota and usage signals

No local quota file was observed `[verified-local]`. Rate-limit information is
expected on API responses as headers `[inferred]`. Nothing usable for a
dashboard has been confirmed `[unknown]`.

## 7. API surface and base-URL override

Codex speaks OpenAI's wire format. An OpenAI-compatible base URL can be
configured `[verified-docs]`, which makes it a natural client for the relay.
Whether an override is honoured while authenticated through a plan rather than
an API key is `[unknown]` and matters for `FR-6`.

## 8. Risks and constraints

- A long-running Codex process on the default home is a write constraint, not
  an edge case. On this host the VS Code Codex extension runs
  `codex app-server` continuously with no `CODEX_HOME` set, so it reads the
  same `~/.codex` an in-place switch would replace `[verified-local]`. At
  observation the live `auth.json` mtime was 23 hours old, so that process
  is not rewriting the file constantly. It can still rewrite the file on
  its own refresh schedule. An adapter that replaces `auth.json` must
  refuse while any process named `codex` is running. A concurrent refresh
  can overwrite the switch or lose the process's refresh write, and a
  long-running process may keep using a cached identity instead of the
  file just written. The cache question remains `[unknown]`. The
  refresh-rewrite itself remains `[inferred]` from `last_refresh`. The
  refusal is required because the home is shared with a live process, not
  because the rewrite has been timed.
- `config.toml` accumulates per-project trust entries. A switch must not discard
  them. They are not credentials and belong to the machine, not the account.
- With `CODEX_HOME` set to a directory under the system temporary tree, 0.144.4
  refused to create PATH helper binaries ("Refusing to create helper binaries
  under temporary dir") `[verified-local]`. A per-account home must not live
  in a temporary directory.

## 9. Open questions

- Does a copied `auth.json` still succeed at a model request against the vendor?
- Does replacing `auth.json` invalidate the session server-side?
- What happens when two distinct identities alternate, via `CODEX_HOME` or an
  in-place swap?
- Does a long-running Codex process cache identity independently of `auth.json`?
- On what schedule does a long-running `codex app-server` rewrite `auth.json`?
  Observation 2 saw a 23-hour-old mtime while that process was running, so
  the rewrite is not continuous. Whether a refresh still races a switch
  remains `[inferred]` from `last_refresh`.
- Must a working session under a relocated `CODEX_HOME` also have `config.toml`
  and other client files, or is `auth.json` enough beyond `login status`?
- Is there a lock file or advisory locking around `auth.json`?
- Windows and macOS paths, confirmed on real hosts.
- Are rate-limit headers exposed anywhere a manager could read them?
