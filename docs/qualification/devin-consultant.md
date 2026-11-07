# Official Devin CLI read-only consultant

The entry point is `maco consult ask --runtime devin`, with explicit
`--consultant-bin`, `--model`, and `--reviewed-workspace`. The fake consultant
remains the default. Writing, managed parents, primary writes, cloud handoff,
resume, native JSON stdout, effort flags, served-model identity and usage
accounting are unsupported for Devin.

Prerequisites: Linux, cgroup v2 and a delegated systemd user manager supported
by MACO's required containment backend; an independently installed official
Devin executable; account access to an exact model; and native login completed
outside MACO. The executable must be an absolute canonical regular file; ambient
PATH resolution and symlink executables are refused by the existing boundary.
No login prompt or fallback runs inside the consultant.

After reviewing the repository and choosing a model available to the account:

```bash
repo=$(pwd -P)
devin_executable="$(readlink -f "$(command -v devin)")"
maco consult ask --repo "$repo" --runtime devin --consultant-bin "$devin_executable" \
  --model provider/exact-model-v1 --reviewed-workspace "$repo" \
  --question "Explain the likely cause from the source." \
  --context-path README.md --json
```

The model is a placeholder, not an advertised catalog entry. Supply an exact
model slug; automatic/default/latest aliases, Astra/Fusion and any effort
request are refused. The Rust API is `ask_devin_consultant` with
`ConsultAskOptions` and `DevinConsultOptions { model, reviewed_workspace }`.

`--print` cannot interactively trust a new workspace. A fresh private HOME cannot
honestly inherit undocumented native trust metadata. Therefore the explicit
reviewed-workspace input must equal the canonical repository root before MACO
uses the documented CI `--respect-workspace-trust=false` flag. This is an operator
authorization for that exact folder. Ordinary unattended task authority does
not authorize another folder. Direct adapter rendering retains the vendor's
default trust behavior, and direct uncontained adapter execution is refused.

`ExternalDevin` uses strict common hardening, provider network access limited to
AF_UNIX/AF_INET/AF_INET6, restricted namespaces and denied mount syscalls. The
workspace is read-only; no writable artifact capability is granted. Prompt,
schema and executable are exact read-only inputs. Repository `.devin` is hidden.
Required containment fails before target spawn on unsupported platforms or an
unavailable backend. Neither native `--sandbox` nor another vendor's evidence
qualifies this route.

MACO pins a user config with `subagents_enabled=false`, `attribution=false`,
`auto_update=false`, `notify="never"`, `permission_mode="normal"`, and all eight
`read_config_from` imports disabled: agents_standard, cursor, windsurf, claude,
copilot, opencode, zed and cloud. The same immutable bytes back `--config` and
private HOME's `.config/devin/config.json`. The config ancestor is also a
read-only mount so the child cannot replace it through a writable parent.
The child cannot enable project hooks through the hidden `.devin` directory.
Server-side organization policy and `/etc/devin/system.json` remain machine and
account policy; these local controls do not claim to pin them.

Credentials come only from `$XDG_DATA_HOME/devin/credentials.toml`, or
`$HOME/.local/share/devin/credentials.toml` when XDG_DATA_HOME is unset. MACO
requires a bounded regular single-link file without symlink components, owned
by the current user, without group/other permissions. Missing, malformed or
unsafe material fails before the target. A held read-only snapshot of this one
file is projected to private HOME's `.local/share/devin/credentials.toml`; its
ambient directory is hidden. No account directory is shared and no token goes
on argv or in the child environment. Bounded TOML string values and their JSON
escaped forms feed the existing redactor before captured output is stored.
Credential-bearing strings shorter than the redactor's minimum are refused;
unrecognized material without bounded string secrets is also refused.

The CLI emits plain bounded stdout. The prompt requests MACO's existing
ConsultantReport JSON contract; ordinary parsing accepts the report and MACO
replaces untrusted runtime, run id, duration, exit information and safety fields.
Only successful completion with verified-empty process custody and verified
`ExternalDevin` evidence can produce successful Devin advice. Advice grants no
merge, write or publication authority.

Synthetic fixtures cover argv, config validation, native credential custody,
redaction, profile projection, preflight identity and report normalization.
Real executable/version behavior, config precedence, account/model access,
workspace refusal behavior and provider completion remain unrun. An operator
must qualify those separately; fixture evidence is not paid live evidence.

Official references: [commands](https://docs.devin.ai/cli/reference/commands),
[user configuration](https://docs.devin.ai/cli/reference/configuration/config-file),
[native authentication](https://docs.devin.ai/cli/enterprise/devin-auth),
[sandbox](https://docs.devin.ai/cli/sandbox), and
[permissions](https://docs.devin.ai/cli/reference/permissions).
