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
dashboard has been confirmed `[unknown]`. Official ChatGPT / Codex plan-price
and billed-spend catalog pages are recorded in §6a. Those pages are not a
local quota file and are not Observed spend.

## 6a. ChatGPT plan price / billed-spend surfaces

This section is the #149 evidence record for official Codex billed-spend and
plan-price surfaces. It does not replace §6. No adapter, Rust selection, CPO,
or catalog-number change is implied. This update did not run a host probe,
did not invoke `codex`, and did not call a vendor billing API. Official
catalog prose is `[verified-docs]`. Nothing here is `[verified-local]`.

**Refuse.** Do not treat any figure on these pages, any MACO placeholder
rate, any interactive `/status` or `/usage` reading, or any `0`/`0` token
tuple as Observed billed USD. Observed spend waits for a proven
non-interactive numeric billed-spend field. Until that field exists,
inventing Observed USD is out of scope.

### Official catalog pages

Fetched 2026-09-20. These URLs are official vendor prose, not Git-SHA pins
and not a host observation:

- https://chatgpt.com/codex/pricing/
- https://developers.openai.com/codex/pricing
- https://learn.chatgpt.com/docs/pricing.md
- https://developers.openai.com/codex/codex-manual.md
- https://learn.chatgpt.com/docs/codex-manual.md
- https://developers.openai.com/codex/auth
- https://developers.openai.com/codex/cli/reference.md
- https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan
- https://help.openai.com/en/articles/20001106
- https://learn.chatgpt.com/docs/enterprise/chatgpt-work-usage-and-cost.md

`developers.openai.com/codex/codex-manual.md` and
`learn.chatgpt.com/docs/codex-manual.md` are the official Codex manual
twins listed from the Codex docs index `[verified-docs]`. The Help Center
Codex rate card is
https://help.openai.com/en/articles/20001106. A direct fetch of that URL
returned HTTP 403 on 2026-09-20; the fetched pricing pages already publish
the credit-per-million-token catalog and point to a credit-based rate card
versus an Enterprise USD rate card `[verified-docs]`.

Those pages publish monthly ChatGPT plan prices, estimated local-message
ranges per five-hour window, credits-per-million-token tables, Fast-mode
multipliers, and optional credit top-ups. The estimates are explicitly
**not** fixed message limits; the pages tell the reader to check a usage
dashboard for current limits and reset times `[verified-docs]`. The
published numbers are catalog text only. They are not remaining-quota
observations, not invoices, and they are not repeated here as if they were
measured.

### Two billing paths

Official authentication docs name two sign-in methods and two billing
paths `[verified-docs]`:

1. **ChatGPT subscription / workspace allowance.** Sign in with ChatGPT.
   Codex is included on Free, Go, Plus, Pro, Business, Edu, and Enterprise.
   Local messages and cloud chats share the plan's usage allowance. Weekly
   limits may also apply. After the included allowance, eligible plans can
   spend **credits**. ChatGPT Work, Codex, ChatGPT for Excel, and Workspace
   Agents share that allowance and credit pool when those features exist on
   the plan `[verified-docs]`.
2. **API-key per-token billing.** Sign in with an OpenAI Platform API key.
   Official auth copy: OpenAI bills API-key usage through the OpenAI
   Platform account at standard API rates; with an API key, Codex uses
   standard API pricing instead of included ChatGPT plan credits
   `[verified-docs]`. Cloud Codex features are unavailable on this path.

These are different meters. A ChatGPT-plan allowance or credit draw is not
Platform API token USD. Platform API token USD is not a ChatGPT-plan
allowance. Do not collapse them into one Observed USD number.

Enterprise agreements add a third **catalog** billing mode, still not
Observed: token-based Enterprise contracts are billed in USD against the
Enterprise USD rate card and the workspace agreement, instead of deducting
credits `[verified-docs]`. Credit-based Enterprise/Edu workspaces stay on
the credit rate card. Official Work/Codex cost guidance says usage reports
and dollar estimates are planning or monitoring tools, not issued invoices,
and that consuming committed credits is not by itself a new invoice charge
`[verified-docs]`.

Help Center copy for ChatGPT Desktop: estimated dollar values appear only
when the workspace enables member cost visibility, and they are planning
estimates, not invoices `[verified-docs]`. That desktop estimate is not a
CLI field and is not Observed billed spend.

### Interactive `/status` and `/usage`

Official CLI reference documents both commands as **in-session TUI slash
commands** `[verified-docs]`:

- `/status` — display session configuration and token usage; confirm the
  active model, approval policy, writable roots, remaining context
  capacity, and (in the Codex-app command list) rate limits. Pricing pages
  say: to see remaining limits during an **active** Codex CLI session, use
  `/status`.
- `/usage` — view account token usage or redeem a rate-limit reset from
  inside the TUI (`/usage daily`, `/usage weekly`, `/usage cumulative`).
  If the session lacks Codex service-account auth, the CLI shows a
  sign-in requirement.

`codex login status` reports the authentication method only
`[verified-docs]`. It is not a spend field.

An interactive TUI reading is not a non-interactive Observed billed-spend
field. Official docs do not document a `codex status`, `codex usage
--json`, or `codex exec` billed-USD command `[verified-docs]` for the
pages fetched here. Whether some other unpublished RPC later exposes
percent-used windows is `[unknown]` and still would not be billed USD
unless that field is proven.

### MACO placeholder catalog is not a vendor list

In this repository, `src/llm/provider.rs`
`DEFAULT_MODEL_PRICING_CATALOG_NOTICE` states that the default catalog
holds "Project policy placeholder rates for offline admission and
reporting. These are not vendor list prices." Those placeholders must not
be copied into an Observed spend row. Official list prices, credit tables,
and estimated message ranges from the pages above must also not be copied
into Rust as Observed. This note records the refuse; it does not change
any `.rs` catalog number.

### Production Codex child evidence

Parent-owned Codex evidence in this repository (`CodexParentTurnUsage`)
records `input_tokens`, `output_tokens`, `cached_input_tokens`, and
`reasoning_output_tokens` when a `turn.completed` usage object is usable.
That schema has no billed-USD or cost field. Supervisor reports keep
`cost_usd` as `None` unless a proven cost field is supplied. Token counts
are not Observed USD.

A `turn.completed` usage object of `0`/`0` input and output tokens is
treated as `CodexParentTurnUsage::Unknown` (`usage_unavailable`: "no
token notification arrived"), not as zero dollars. Missing usage is
Unknown. Do not rewrite either case as Observed `$0`.

### CAM quota has no environment-spend field

CAM `QuotaSnapshot` carries `utilization`, optional `windowLabel` /
`resetsAt`, and a source. There is no environment-spend, billed-USD, or
invoice field. Codex `quota()` returns an empty vector because §6 found
no local quota file. `account.observe` quota for Codex is Unknown with no
content and must not serialize empty snapshots as invented zeros. This
slice must not invent a CAM environment-spend field to hold catalog
prices.

### Can any field become Observed?

This update did not sign in, run `/status` or `/usage`, launch
`codex exec`, or read a billing dashboard. **No** plan price, credit
balance, allowance remaining, or billed-USD field is Observed in this
note.

No billed-spend field on the fetched pages is ready to become Observed.
A future Observed USD row requires a live **non-interactive** vendor
response that returns a numeric billed-spend or invoice-charge field,
recorded as received. Help Center and pricing pages point remaining
limits and credit balance at a usage dashboard or an active TUI
`/status`; neither is that non-interactive field `[verified-docs]`.
`turn.completed.usage` token counts already captured by parent-owned
Codex evidence stay token evidence. They still cannot become Observed
USD.

Fields that **cannot** become Observed from material already in hand:

| Candidate                                                          | Why it stays unobserved                                                                            |
| ------------------------------------------------------------------ | -------------------------------------------------------------------------------------------------- |
| chatgpt.com / developers.openai.com plan prices and message ranges | Catalog `[verified-docs]`, not an account reading.                                                 |
| Credits-per-million-token or Enterprise USD rate cards             | Catalog `[verified-docs]`. Applying a rate card to tokens is inference, not Observed billed spend. |
| Desktop or admin "estimated dollar" views                          | Official copy: planning estimates, not invoices `[verified-docs]`.                                 |
| Interactive `/status` or `/usage`                                  | TUI session commands `[verified-docs]`, not a non-interactive billed-spend field.                  |
| `codex login status`                                               | Auth method only `[verified-docs]`.                                                                |
| MACO `DEFAULT_MODEL_PRICING_CATALOG` placeholders                  | Project notice: not vendor list prices.                                                            |
| Official list prices copied into Rust                              | Catalog text must not be relabeled Observed.                                                       |
| `turn.completed` token counts, including `0`/`0`                   | Tokens only; `0`/`0` is Unknown, not `$0`.                                                         |
| CAM `QuotaSnapshot` / Codex `quota()` empty vector                 | No environment-spend field; empty is no signal, not zero dollars.                                  |
| Collapsing ChatGPT-plan credits with Platform API token USD        | Official docs keep the paths distinct `[verified-docs]`.                                           |

Until a non-interactive numeric billed-spend field is proven and
recorded as received, Codex billed spend remains `[unknown]`. Do not
infer it from catalog prices, placeholder rates, token counts, or a
missing field.

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
- Does any non-interactive Codex CLI, `codex exec --json`, or documented
  app-server method expose a billed-USD or invoice-charge field?
- Which live numeric field, if any, is billed spend on the ChatGPT-plan
  path versus the Platform API-key path? Official docs keep the meters
  distinct.
- If a future non-interactive read returns remaining allowance or credit
  balance only, can that become Observed quota without being relabeled
  Observed USD?
