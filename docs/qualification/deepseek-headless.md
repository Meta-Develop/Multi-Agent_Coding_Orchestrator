# DeepSeek Harness headless qualification

Status: prepared. No live provider run has passed. Writable admission stays
closed. Follow the [shared preparation contract](README.md) and the
[DeepSeek Harness runtime](../OPERATOR_QUICKSTART.md#deepseek-harness-runtime)
prerequisites.

Protocol pin: deepseek-harness **0.2.2-alpha.3**. Published npm package
observed separately: `@deepseek-ai/dsh@0.2.1-rc.5`. Record both
`dsh --version` and `node --version`. Refuse the run when
`dsh --profile headless --help` does not show `--json`, `--permission-mode`,
`--approval-policy`, `--session-id`, `--patch`, and a trailing `-` task.
The owner install note asks for Node >= 22.19. The pinned protocol source
declares `engines.node >= 24.9.0`.

This runtime is read-only Researcher only. It does not use ACP. It has no
Coding Agent Manager provider. Requested effort (`off`, `low`, `high`, or
`max`) is the identity. A served model is checked only when the NDJSON stream
reports one. Telemetry and session-log upload are forced off on every launch.
`--qualify-deepseek-headless` does not promote `RuntimeCapabilities` and does
not set `production_qualified`. Without a later source change, writable
admission remains `writable_deepseek_headless_qualification_required`.

Selection requires a routing prior file containing a dated prior for the exact
`deepseek:<model>` pair and effort, plus a frozen canonical DeepSeek executable
binding alongside Codex. This page does not invent that prior.
`DEEPSEEK_API_KEY` is supplied by the launch environment only. Do not copy it
into the evidence directory, the worktree, or the command line.

Offline checks (no provider call):

```bash
export MACO_DSH_BIN="$(readlink -f "$(command -v dsh)")"
test -f "$MACO_DSH_BIN" && test ! -L "$MACO_DSH_BIN" || exit 1
"$MACO_DSH_BIN" --version > "$OUT/dsh-version.txt"
node --version > "$OUT/node-version.txt"
sha256sum "$MACO_DSH_BIN" > "$OUT/dsh-sha256.txt"
"$MACO_DSH_BIN" --profile headless --help > "$OUT/dsh-headless-help.txt" || exit 1
```

Compare `$OUT/dsh-headless-help.txt` with the pinned argv before any live run.
A help or flag mismatch stops qualification.

After a key exists in the launch environment and an accepted prior admits the
model, the root runs this read-only Researcher shape. Do not add
`--permission-mode workspace-write`, `--add-dir`, or a writable worker. The
flag below is a marker, not a write grant.
Supply `DEEPSEEK_API_KEY` as an exported launch-environment variable before
running; the scope inherits it. Keep its value out of command arguments.

```bash
export MACO_DSH_BIN="$(readlink -f "$(command -v dsh)")"
test -f "$MACO_DSH_BIN" && test ! -L "$MACO_DSH_BIN" || exit 1
test -n "${DEEPSEEK_API_KEY:-}" || exit 1
test -n "$prior_dsh" && test -f "$repo/$prior_dsh" || exit 1
codex_executable="$(readlink -f "$(command -v codex)")"
test -f "$codex_executable" && test -x "$codex_executable" || exit 1
run_id=qualification-deepseek-headless-01
if timeout --signal=TERM --kill-after=30s 3600 systemd-run --user --scope --quiet -p Delegate=yes \
  --working-directory="$repo" -- env MACO_DSH_BIN="$MACO_DSH_BIN" \
  "$maco" supervise run "$fixture" --runtime codex --repo "$repo" \
  --run-id "$run_id" --runtime-bin "$codex_executable" \
  --additional-runtime-bin "deepseek=$MACO_DSH_BIN" \
  --qualify-deepseek-headless --prior-data "$prior_dsh" \
  --max-concurrent-children 1 --provider-inflight-limit 1 \
  --machine-global-config "$config" --machine-global-runtime-root-id runtime --json \
  > "$OUT/run.json" 2> "$OUT/run.stderr"; then rc=0; else rc=$?; fi
printf '%s\n' "$rc" > "$OUT/run.exit"
if "$maco" supervise collect "$run_id" --repo "$repo" --json \
  > "$OUT/collect.json" 2> "$OUT/collect.stderr"; then rc=0; else rc=$?; fi
printf '%s\n' "$rc" > "$OUT/collect.exit"
```

`$fixture` is an explicit fresh plan under Codex supervision whose only model
assignment is a Linux read-only Researcher on runtime `deepseek`, with no
nested assignments. Success
still requires exit 0, `final.reason.kind` of `completed`, empty
`commands_run` and `validation_results`, and an exact normalized assigned path
in a native `read` call's absolute `file_path` with a matching successful, untruncated
`tool_result`. Denied shell calls, filename substrings, missing or duplicate
call identities, and truncated captures cannot prove inspection. The parent
retains the redacted NDJSON separately and parses only the unique completed
`final.text` as the ResearcherReport. Each attempt's exclusive launch patch
is delivered as an immutable snapshot; launch evidence records its SHA-256
and requested model/effort. The sandbox exposes the exact executable, so a
custom wrapper must use runtime dependencies already visible in the sandbox
(for example, a Nix store closure); adjacent installation files are not exposed.
A writable worker in that plan must still fail with
`writable_deepseek_headless_qualification_required` and
`production_qualified: false`.
