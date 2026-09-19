# Work-proposal tool restrictions

This note answers one advertisement question for
[`MACO_INTEGRATION.md`](../MACO_INTEGRATION.md) §6: can any current CAM
provider adapter **establish** provider tool restrictions sufficient to
advertise `work-proposal`?

`work-proposal` is one fresh proposal turn, with no provider-owned
workspace mutation, nested orchestration, or independent review. The
adapter must establish those restrictions **before** advertising the
kind. A prepare digest is an integrity join, not a containment proof.

This is a docs-only companion to the already-noted providers. Persist,
quota, and price evidence stays in those notes and is not restated or
upgraded here.

## 1. Identity

- Subject: CAM `work-proposal` tool-restriction advertisement.
- Scope: already-noted providers only — Codex CLI, Claude Code, Cursor
  CLI, Gemini CLI, GitHub Copilot CLI, and Grok CLI.
- Vendor: none for this note. Each provider's vendor is recorded in its
  existing note.
- Version observed: **not a local install**. Official vendor pages were
  fetched on 2026-09-20. Installed binary versions remain those in the
  linked notes and are not upgraded here.
- OS observed: **not observed** for this note.

Linked identity and persist notes (not rewritten):

- [codex-cli.md](codex-cli.md)
- [claude-code.md](claude-code.md)
- [cursor.md](cursor.md)
- [gemini-cli.md](gemini-cli.md)
- [github-copilot.md](github-copilot.md)
- [grok-cli.md](grok-cli.md)

CAM protocol facts for this checkout, not vendor claims: advertised
operations stay the eight selection/login/observe operations;
`operation.prepare` is decoded for `work-proposal` and then refused as
`UnsupportedOperation` until a provider advertises tool restrictions.

Official pages checked on 2026-09-20:

Codex (OpenAI):

- <https://developers.openai.com/codex/sandboxing>
- <https://developers.openai.com/codex/non-interactive-mode>
- <https://developers.openai.com/codex/cli/reference>
- <https://developers.openai.com/codex/config-reference>
- <https://developers.openai.com/codex/permissions>
- <https://developers.openai.com/codex/subagents>
- <https://developers.openai.com/codex/concepts/sandboxing/auto-review>
- <https://developers.openai.com/codex/config-advanced>

Claude Code (Anthropic):

- <https://code.claude.com/docs/en/permissions>
- <https://code.claude.com/docs/en/cli-reference>
- <https://code.claude.com/docs/en/tools-reference>
- <https://code.claude.com/docs/en/settings>
- <https://code.claude.com/docs/en/permission-modes>
- <https://code.claude.com/docs/en/subagents>
- <https://code.claude.com/docs/en/tools>
- <https://code.claude.com/docs/en/agent-sdk/permissions>

Cursor CLI (Anysphere):

- <https://cursor.com/docs/cli/overview>
- <https://cursor.com/docs/cli/reference/configuration>
- <https://cursor.com/docs/cli/reference/permissions>
- <https://cursor.com/docs/cli/reference/parameters>
- <https://cursor.com/docs/cli/headless>
- <https://cursor.com/docs/reference/sandbox>
- <https://cursor.com/docs/agent/security/run-modes>

Gemini CLI (Google):

- <https://geminicli.com/docs/reference/configuration/>
- <https://geminicli.com/docs/cli/cli-reference/>
- <https://geminicli.com/docs/cli/plan-mode/>
- <https://geminicli.com/docs/cli/sandbox/>
- <https://geminicli.com/docs/core/subagents/>
- <https://geminicli.com/docs/reference/policy-engine/>

GitHub Copilot CLI (GitHub):

- <https://docs.github.com/en/copilot/concepts/agents/copilot-cli/about-copilot-cli>
- <https://docs.github.com/en/copilot/how-tos/copilot-cli/use-copilot-cli/allowing-tools>
- <https://docs.github.com/en/copilot/how-tos/copilot-cli/set-up-copilot-cli/configure-copilot-cli>
- <https://docs.github.com/en/copilot/reference/copilot-cli-reference/cli-command-reference>
- <https://docs.github.com/en/copilot/how-tos/cloud-and-local-sandboxes/configuring-local-sandbox-settings>

Grok CLI (xAI):

- <https://docs.x.ai/build/features/permissions>
- <https://docs.x.ai/build/features/sandbox>
- <https://docs.x.ai/build/cli/reference>
- <https://docs.x.ai/build/settings/reference>
- <https://docs.x.ai/build/features/subagents>
- <https://docs.x.ai/build/modes-and-commands>

## 2. Config locations

These paths are permission, sandbox, or approval surfaces named by
official vendor documentation. Credential-store paths stay in the linked
notes and are not upgraded here.

| Provider           | Documented restriction-related path or override                                                                                                                                                     | Marker            |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------- |
| Codex CLI          | `$CODEX_HOME/config.toml` keys `approval_policy`, `sandbox_mode`, `approvals_reviewer`, `default_permissions`, `features.multi_agent`, `[agents]`, `[permissions.<name>]`; project `.codex/agents/` | `[verified-docs]` |
| Claude Code        | `~/.claude/settings.json`, project `.claude/settings.json`, managed settings; `permissions.allow` / `ask` / `deny`, `permissions.defaultMode`, `sandbox.*`                                          | `[verified-docs]` |
| Cursor CLI         | `~/.cursor/cli-config.json` (global) and `.cursor/cli.json` (project): `permissions.allow` / `deny`, `approvalMode`, `sandbox.mode`, `sandbox.networkAccess`; optional `sandbox.json`               | `[verified-docs]` |
| Gemini CLI         | `~/.gemini/settings.json` (`general.defaultApprovalMode`, `general.plan.*`, `tools.sandbox`, `tools.allowed`, `tools.exclude`, `security.toolSandboxing`); `~/.gemini/policies/*.toml`              | `[verified-docs]` |
| GitHub Copilot CLI | `~/.copilot/permissions-config.json`; `~/.copilot/settings.json` (`allowedUrls`, `subagents.*`); `$COPILOT_HOME` relocates that tree; managed MDM / file settings                                   | `[verified-docs]` |
| Grok CLI           | `~/.grok/config.toml` (`[ui].permission_mode`, `[permission]`, `[sandbox]`, `[subagents]`); `~/.grok/sandbox.toml` and project `.grok/sandbox.toml`; `GROK_SANDBOX`, `GROK_SUBAGENTS`               | `[verified-docs]` |

Windows, macOS, and Linux expansions of those homes, other than the
placeholder examples already published by the vendors, remain
`[unknown]` here. They are not taken from the persist notes.

## 3. Credential format

Out of scope. Key names and store identities stay in the linked notes.
This note does not add, copy, or upgrade a credential schema.

## 4. Authentication flow

Out of scope. Login and token-lifetime claims stay in the linked notes.

## 5. Account switching mechanics

Out of scope. Switching and write-safety claims stay in the linked
notes. A tool-restriction flag is not an account switch.

## 6. Quota and usage signals

Out of scope. Quota, utilization, and price markers stay in the linked
notes and are not upgraded here.

## 7. API surface and base-URL override

Base-URL override claims stay in the linked notes and are not upgraded
here. This section records only the documented **tool / sandbox /
approval / allowed-tools** surface for a work-proposal launch, then
whether that surface can **prove** the §6 constraints.

The four required proofs are:

1. **One fresh proposal turn** — exactly one new proposal inference, not
   a multi-turn agent loop, resume, or implement-after-plan.
2. **No provider-owned workspace mutation** — the provider cannot edit
   the workspace, run mutating shell, or apply a plan.
3. **No nested orchestration** — no child agents, fleets, workers, or
   cloud handoff.
4. **No independent review** — no second-model classifier, reviewer
   agent, or provider-owned review role.

A documented flag is not a containment proof. Official docs that
describe a control still leave enforcement, composition, and headless
behavior `[unknown]` unless the same official page states that the
control actually prevents the forbidden action.

### Codex CLI

Documented surface `[verified-docs]`:

- Sandbox modes: `read-only`, `workspace-write`, `danger-full-access`.
  CLI: `--sandbox`. Config: `sandbox_mode`.
- Approval policies: `on-request`, `never`, and a granular table.
  CLI: `--ask-for-approval`. Config: `approval_policy`. Official docs
  say Codex and ChatGPT Work no longer support selecting `untrusted`.
- `read-only`: the agent can inspect files, but it cannot edit files or
  run commands **without approval**.
- `never`: the agent does not stop for approval prompts. Official docs
  do not say `never` plus `read-only` denies every mutating action.
- `codex exec` is the non-interactive entry. Default sandbox for
  `codex exec` is read-only. Docs show how to **allow edits**
  (`--sandbox workspace-write`) and how to resume a prior exec.
- `--disable` force-disables a feature flag (`features.<name>=false`).
  `features.multi_agent` enables `spawn_agent`, `send_input`,
  `resume_agent`, `wait_agent`, and `close_agent` and is on by default.
- Subagent workflows are enabled by default. Current local releases
  spawn after a direct request **or** applicable `AGENTS.md` / skill
  instructions. Built-in agents include `default`, `worker`, and
  `explorer`. `agents.enabled` can disable multi-agent tools.
- `approvals_reviewer` is `user` (default) or `auto_review`.
  `auto_review` routes eligible approvals to a **separate reviewer
  agent**. That is independent review. It does not change the sandbox
  boundary. Actions already allowed inside the sandbox skip review.
- Beta permission profiles (`:read-only`, `:workspace`,
  `:danger-full-access`, custom `[permissions.<name>]`) govern
  sandboxed local commands. Connectors, MCP, browser, computer-use, and
  approved escalations use other controls.
- Official `codex exec` flag table does not name a max-turns or
  allowed-tools list. JSONL events include `turn.started` /
  `turn.completed`, so an exec can emit more than one turn.

| Required proof          | Official docs prove it? | Why not                                                                                                                                                             |
| ----------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| One fresh proposal turn | No                      | `codex exec` runs until the task finishes and can `resume`. No documented one-turn bound.                                                                           |
| No workspace mutation   | No                      | `read-only` still permits edits and commands after approval. `never` skips prompts; docs do not say those actions fail closed.                                      |
| No nested orchestration | No                      | Multi-agent tools are on by default and also follow project/skill instructions. Docs do not prove `--disable` plus `agents.enabled=false` removes every spawn path. |
| No independent review   | No                      | `auto_review` is a documented reviewer agent. Docs do not prove an adapter can lock `approvals_reviewer=user` against config, profile, or enterprise overlay.       |

Conclusion: **stay-unadvertised**.

### Claude Code

Documented surface `[verified-docs]`:

- Permission modes: `default` (Manual), `acceptEdits`, `plan`, `auto`,
  `dontAsk`, `bypassPermissions`. CLI: `--permission-mode`.
- `--allowedTools` / `--allowed-tools` pre-approve tools. They do **not**
  restrict unlisted tools. Unlisted tools fall through to the permission
  mode. Combined with `bypassPermissions`, allowlists still approve
  every remaining tool.
- `--tools` restricts built-in tools. `""` disables all built-ins;
  `"default"` keeps all. The flag does not affect MCP tools.
- `--disallowedTools` adds deny rules. A bare name removes the tool;
  `"*"` removes every tool; `"mcp__*"` removes MCP tools.
- `dontAsk` auto-denies every tool call that would prompt. Only
  `permissions.allow` matches and read-only Bash can run.
- `plan`: Claude reads files, **runs shell commands to explore**, and
  writes a plan, but does not edit source. Edits stay blocked until the
  plan is approved, except sessions that have bypass permissions
  available.
- When auto mode is available, `useAutoModeDuringPlan` defaults to on
  and a **classifier reviews shell commands during planning**.
- `auto` uses a second model (the classifier) instead of the user.
  Official docs call this a background safety check. That is independent
  review. Built-in starting mode on Pro, Max, and Team interactive
  sessions is `auto`. `claude -p` and the Agent SDK start in `default`.
- `Agent` spawns a subagent. Deny `Agent` to block delegation.
  Built-in `Explore` and `Plan` subagents exist; plan mode can delegate
  research to the Plan subagent. `CLAUDE_CODE_DISABLE_EXPLORE_PLAN_AGENTS=1`
  removes those two types (v2.1.198+).
- Sandbox settings apply to **Bash**, not every tool.
- `-p` is non-interactive. Repeated permission blocks abort the
  session. Official docs do not bound `-p` to one model turn.

| Required proof          | Official docs prove it? | Why not                                                                                                                                                           |
| ----------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| One fresh proposal turn | No                      | `-p` runs until completion or abort. No documented one-turn bound.                                                                                                |
| No workspace mutation   | No                      | Plan mode still runs shell. `allowedTools` does not remove Edit/Bash. `--tools ""` plus MCP deny is described, not proven as workspace-immutable for a CAM child. |
| No nested orchestration | No                      | `Agent` and built-in Explore/Plan subagents are documented. Denying them is a surface, not a proof that every spawn path is gone.                                 |
| No independent review   | No                      | Auto-mode classifier, including during plan when the setting is on, is independent review.                                                                        |

Conclusion: **stay-unadvertised**.

### Cursor CLI

Documented surface `[verified-docs]`:

- Modes: Agent (default), Plan (`--mode=plan` / `--plan`), Ask
  (`--mode=ask`). Ask is "read-only exploration without making changes".
- Print/headless: `-p` / `--print`. Parameters page: print "has access
  to all tools, including write and shell". Headless page: combine
  `--print` with `--force` / `--yolo` to modify files; **without
  `--force`, changes are only proposed, not applied**.
- `permissions.allow` / `permissions.deny` tokens: `Shell(...)`,
  `Read(...)`, `Write(...)`, `WebFetch(...)`, `Mcp(...)`. Deny wins.
- `approvalMode`: `allowlist`, `auto-review`, `unrestricted`.
  Auto-review runs allowlisted calls, sandboxes supported shell, and
  sends other calls to an **Auto-review classifier**.
- `--sandbox enabled|disabled`. `sandbox.json` types include
  `workspace_readwrite`, `workspace_readonly`, and `insecure_none`.
- Cloud Agent handoff: prepend `&` to send work to a Cloud Agent.
  `agent worker` starts a private cloud worker. `-w` / `--worktree`
  creates a git worktree under `~/.cursor/worktrees/`.
- Official pages do not name a `--no-subagents`, `--max-turns`, or
  built-in-tool allowlist flag comparable to `--tools`.

| Required proof          | Official docs prove it? | Why not                                                                                                                                                                 |
| ----------------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| One fresh proposal turn | No                      | `-p` runs a prompt to completion. No documented one-turn bound.                                                                                                         |
| No workspace mutation   | No                      | Parameters and headless pages disagree on whether print can write or only propose. Shell access is documented either way. Ask-mode composition with `-p` is not stated. |
| No nested orchestration | No                      | Cloud Agent handoff and `agent worker` are documented. No official disable that proves they cannot run.                                                                 |
| No independent review   | No                      | `auto-review` is a documented classifier. Docs do not prove an adapter can lock it off.                                                                                 |

Conclusion: **stay-unadvertised**.

### Gemini CLI

Documented surface `[verified-docs]`:

- `--approval-mode`: `default`, `auto_edit`, `yolo`, `plan`.
  `general.defaultApprovalMode` accepts `default`, `auto_edit`, `plan`.
  YOLO is command-line only.
- Official description: `plan` is read-only mode for tool calls and
  requires experimental planning to be enabled.
- `--allowed-tools` is **deprecated**. Docs say to use the Policy
  Engine (`~/.gemini/policies/*.toml`). `tools.allowed` still bypasses
  confirmation; `tools.exclude` excludes tools from discovery.
- Plan Mode allowed tools include read filesystem/search tools,
  `ask_user`, read-only MCP tools, `activate_skill`, **research
  subagents** `codebase_investigator` and `cli_help` (enabled by
  default), and `write_file` / `replace` only for `.md` files under
  `~/.gemini/tmp/<...>/plans/` or a custom plans directory. A custom
  plans directory must sit inside the project root.
- Approving a plan exits Plan Mode and starts implementation.
- **Non-interactive Plan Mode:** the policy engine auto-approves
  `enter_plan_mode` and `exit_plan_mode`. When exiting Plan Mode to
  execute the plan, Gemini CLI **automatically switches to YOLO mode**.
  Official example: `gemini --approval-mode plan -p "..."`.
- `--sandbox` / `GEMINI_SANDBOX` / `tools.sandbox` enable sandboxing.
  Sandbox expansion can request extra paths or network for a command.
- Subagents can be denied in policy by treating the agent name as
  `toolName`. Official docs do not name a CLI `--no-subagents` flag.
- Official CLI table does not name a max-turns flag.

| Required proof          | Official docs prove it? | Why not                                                                                                                    |
| ----------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| One fresh proposal turn | No                      | Non-interactive plan is documented to exit into YOLO implementation.                                                       |
| No workspace mutation   | No                      | Same YOLO transition. Custom plan directories write inside the project.                                                    |
| No nested orchestration | No                      | Research subagents are enabled by default in Plan Mode.                                                                    |
| No independent review   | No                      | Official docs do not prove the absence of a reviewer/classifier, and plan approval is a review step before implementation. |

Conclusion: **stay-unadvertised**.

### GitHub Copilot CLI

Documented surface `[verified-docs]`:

- Copilot CLI can execute shell, read and write files, fetch URLs, and
  **delegate to specialized sub-agents**.
- Read-only operations (search, file read, read-only shell) are allowed
  automatically. Mutating shell, file writes, and URLs need approval
  unless pre-allowed.
- Two layers: `--available-tools` / `--excluded-tools` hide tools from
  the model; `--allow-tool` / `--deny-tool` grant or deny permission.
  If both availability flags are set, the allowlist is used and the
  denylist is ignored. Deny wins over allow, including `--allow-all`.
- Availability values include `bash` / `powershell`, `apply_patch`,
  `create`, `edit`, `view`, `task` ("Run subagents"), `list_agents`,
  `read_agent`, `write_agent`, `ask_user`, `glob`, `grep`, `skill`,
  `web_fetch`.
- Permission kinds include `read`, `shell`, `write`, `url`, `memory`,
  and MCP server names. `--deny-tool=write` denies file writing.
- `--allow-all` / `--yolo` enables all tools, paths, and URLs.
- `-p` / `--prompt` runs programmatically and exits after completion.
  `COPILOT_TASK_WAIT_TIMEOUT_SECONDS` is how long `-p` waits for
  **pending background agents or shell commands** (default 600s).
- Subagent limits: `COPILOT_SUBAGENT_MAX_CONCURRENT` default 32;
  `COPILOT_SUBAGENT_MAX_DEPTH` default 4. `/fleet` enables parallel
  subagent execution. `/delegate` opens a remote PR workflow.
- Built-in `code-review` and `security-review` agents perform reviews.
  `code-review` can hand off security portions to `security-review`.
- `--plan` / `--mode autopilot` and `COPILOT_PLAN_THEN_AUTOPILOT`
  request plan-then-autopilot.
- Local sandbox is experimental (`--sandbox`, `/sandbox`). Cloud
  sandbox is `copilot --cloud`. Official docs do not treat sandbox
  enablement as a proof that writes cannot happen.
- Session flags are not written to `permissions-config.json`. Saved
  location approvals still apply unless denied.

| Required proof          | Official docs prove it? | Why not                                                                                                                                                      |
| ----------------------- | ----------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| One fresh proposal turn | No                      | `-p` waits for background agents/shell and can continue via `--resume`. No documented one-turn bound.                                                        |
| No workspace mutation   | No                      | Read-only shell is auto-allowed; mutating shell exists unless excluded. `write` deny does not, by itself, remove `bash` / `apply_patch` / `create` / `edit`. |
| No nested orchestration | No                      | `task`, `/fleet`, `/delegate`, and default subagent depth/concurrency are documented. Excluding `task` is a surface, not a proof against every agent entry.  |
| No independent review   | No                      | `code-review` and `security-review` are provider-owned reviewers.                                                                                            |

Conclusion: **stay-unadvertised**.

### Grok CLI

Documented surface `[verified-docs]`:

- Permission modes: Ask (default), Auto (classifier auto-approves safe
  tools; dangerous ones may still prompt), Always-approve
  (`grok --always-approve`). Auto is independent review.
- `--allow` / `--deny` and `[permission]` rules. Deny wins. Filters
  include `Bash`, `Edit`, `Read`, `Grep`, `MCPTool`, `WebFetch`,
  `WebSearch`.
- `--tools` / `--disallowed-tools` allow or remove built-in tools.
  Claude Code flag aliases are accepted where they overlap, including
  `--dangerously-skip-permissions`.
- `--sandbox` / `GROK_SANDBOX` / `[sandbox].profile`. Built-in
  profiles: `off` (default), `workspace`, `devbox`, `read-only`,
  `strict`. `read-only` writes only `~/.grok/` and temp; child network
  blocked (Linux only; no-op on macOS). `strict` still writes CWD,
  `~/.grok/`, and temp.
- `--no-subagents` disables subagents for the session. `--no-plan`
  disables plan. `--max-turns` sets a maximum number of agent turns.
- Subagents are independent child sessions. Official subagents page:
  enabled by default when the setting is unset. Built-in types:
  `general-purpose`, `explore`, `plan`. Settings reference also lists
  `GROK_SUBAGENTS` with default `0` and `[subagents].enabled`. Those
  two default statements conflict, so the effective default is
  `[unknown]`.
- Headless `dontAsk` is documented only under Enterprise Deployments,
  not as a generally available CAM-owned flag.
- Plan mode keeps edit tools limited; the plan review UI is not skipped
  under auto or always-approve.
- `-w` / `--worktree` starts a session in a new git worktree.

| Required proof          | Official docs prove it? | Why not                                                                                                                                                              |
| ----------------------- | ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| One fresh proposal turn | No                      | `--max-turns` exists. Official docs do not define a turn as one proposal with no tools and no follow-up.                                                             |
| No workspace mutation   | No                      | `read-only` still leaves Bash unaddressed unless separately denied. `strict` writes the CWD.                                                                         |
| No nested orchestration | No                      | `--no-subagents` is a surface. Docs do not prove it covers ACP (`grok agent stdio`), worktrees, or every child path. Default-on vs `GROK_SUBAGENTS=0` is unresolved. |
| No independent review   | No                      | Auto mode is a classifier. Plan review UI is a provider review step.                                                                                                 |

Conclusion: **stay-unadvertised**.

## 8. Risks and constraints

- **Advertise nothing.** No provider on this list can prove the
  conjunction in [`MACO_INTEGRATION.md`](../MACO_INTEGRATION.md) §6.
  `work-proposal` stays unadvertised. `operation.prepare` stays decoded
  and `UnsupportedOperation`. `ADVERTISED_OPERATIONS` stays eight
  operations. This note is not authority to implement
  `operation.start`, `operation.status`, or `operation.cancel`.
- **A documented control is not adapter establishment.** §6 requires
  the adapter to establish restrictions **before** advertising. Official
  pages describe flags, modes, and files. They do not prove that a CAM
  child inherits only those settings, that user/project/managed overlays
  cannot widen them, or that the vendor runtime enforces them after
  prompt injection, skills, MCP, or resume.
- **Plan modes are not work-proposal.** Claude plan still runs shell
  and may use a classifier. Gemini non-interactive plan exits into
  YOLO and implements. Grok and Copilot plan flows have review or
  autopilot follow-through. Cursor Plan is "before coding", not a
  single frozen proposal turn.
- **Read-only sandboxes still escalate.** Codex `read-only` allows
  mutation after approval. Grok `read-only` still writes `~/.grok/`
  and temp. Copilot auto-allows some shell. Cursor print both "has
  write tools" and "proposes without `--force`".
- **Nested orchestration is on or reachable by default** for Codex
  multi-agent, Claude `Agent` / Explore / Plan, Gemini research
  subagents, Copilot `task` / `/fleet` / `/delegate`, Grok subagents,
  and Cursor Cloud Agent / `agent worker`.
- **Independent review is a first-class vendor feature** (Codex
  `auto_review`, Claude auto-mode classifier, Cursor auto-review,
  Copilot `code-review` / `security-review`, Grok Auto). Work-proposal
  forbids it.
- **Do not invent flags or proofs.** Anything not on the official
  pages in §1 is `[unknown]`. Source inspection, `--help` not quoted
  by those pages, and local binaries are out of scope for this note.
- Persist, quota, and price markers in the linked notes are unchanged.

## 9. Open questions

These remain `[unknown]`. They do not authorize advertisement.

Shared:

- Does any vendor document a single invocation that is exactly one
  fresh proposal turn and then exits with no further tool loop?
- Can a CAM adapter prove, from official docs alone, that user,
  project, managed, and enterprise overlays cannot re-enable write,
  spawn, or reviewer tools for that child?
- Does "workspace mutation" in §6 include vendor-home writes
  (`~/.codex`, `~/.claude`, `~/.cursor`, `~/.gemini`, `~/.copilot`,
  `~/.grok`) and temp plan files?
- Are Windows and macOS enforcement of each sandbox the same as the
  Linux stories on the official pages?

Codex CLI:

- Does `approval_policy = "never"` plus `sandbox_mode = "read-only"`
  fail closed on edits and commands, or run them?
- Does `--disable` of `multi_agent`, or `agents.enabled = false`,
  stop `AGENTS.md` / skill-requested delegation?
- Can an adapter pin `approvals_reviewer = "user"` so `auto_review`
  cannot start?

Claude Code:

- Where does plan mode write the plan file? Workspace or vendor home?
- Does `--tools ""` plus `--disallowedTools "mcp__*"` plus `dontAsk`
  still allow Skill, hooks, or classifier review?
- Does deny `Agent` also block built-in Explore/Plan without
  `CLAUDE_CODE_DISABLE_EXPLORE_PLAN_AGENTS`?

Cursor CLI:

- When `-p` is used without `--force`, can Shell still mutate the
  workspace?
- Does `--mode=ask` apply to `-p`, and does it remove write/shell?
- Is there an official way to disable Cloud Agent handoff, the
  `agent worker` command, and auto-review for one print run?

Gemini CLI:

- Is there any official non-interactive mode that **cannot** exit
  Plan Mode into YOLO?
- Is there an official CLI flag that disables all subagents for one
  `-p` run?
- Does `tools.exclude` survive Policy Engine rules that allow a
  research subagent?

GitHub Copilot CLI:

- Does `--excluded-tools=task` plus `--deny-tool=write` plus excluding
  `bash`, `apply_patch`, `create`, and `edit` still leave a mutating
  path (PowerShell, MCP, skills, `/delegate`, `/fleet`)?
- Can `-p` be configured to refuse background agents instead of
  waiting `COPILOT_TASK_WAIT_TIMEOUT_SECONDS`?
- Can `code-review` / `security-review` be proven absent?

Grok CLI:

- Which default is authoritative: subagents enabled when unset, or
  `GROK_SUBAGENTS` default `0`?
- Is `dontAsk` available outside Enterprise Deployments?
- Does `--max-turns 1` with `--no-subagents` and `--sandbox read-only`
  still allow Bash writes to the workspace or temp?

Until those questions have official answers that prove the §6
conjunction, every listed provider stays unadvertised.
