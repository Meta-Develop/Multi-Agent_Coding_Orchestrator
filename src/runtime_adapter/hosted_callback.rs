//! MACO-owned blocking pre-action gate and Claude Code PreToolUse host.
//!
//! Every proposed tool, filesystem, or destructive action is reviewed. Allow is
//! required before the action may proceed. Deny is fail-closed and journaled.
//! A missing or incomplete callback is also fail-closed.
//!
//! `blocking_pre_action_callback == All` is returned only for a Claude Code
//! adapter that has actually attached this host. The static
//! [`RuntimeCapabilities::CLAUDE_CODE`] descriptor stays `None` so an unattached
//! production launch cannot claim coverage.

use super::{AdapterId, RuntimeCapabilities};
use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::BTreeSet,
    fs::{self, OpenOptions},
    io::Write,
    path::{Path, PathBuf},
};

pub const HOSTED_CALLBACK_JOURNAL_VERSION: u32 = 1;
pub const CLAUDE_PRETOOLUSE_EVENT: &str = "PreToolUse";
const ALL_TOOLS_MATCHER: &str = "*";
const HOOK_FILE_NAME: &str = "maco-hosted-pretooluse";
const ALLOW_TOOLS_FILE_NAME: &str = "allow-tools";
const JOURNAL_FILE_NAME: &str = "journal.jsonl";
const ATTACHMENT_FILE_NAME: &str = "attachment.json";
const SETTINGS_FILE_NAME: &str = "settings.json";
const CLAUDE_CONFIG_DIR_NAME: &str = "claude-config";

const PRETOOLUSE_HOOK_SCRIPT: &str = r#"#!/bin/sh
set -eu
DIR="${MACO_HOSTED_CALLBACK_DIR:-__MACO_HOSTED_CALLBACK_DIR__}"
if [ ! -d "$DIR" ]; then
  printf '%s\n' '{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"MACO hosted callback directory is missing"}}'
  exit 0
fi
request=$(cat)
tool_name=$(printf '%s' "$request" | sed -n 's/.*"tool_name"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | head -n 1)
allow_file="$DIR/allow-tools"
journal="$DIR/journal.jsonl"
decision="deny"
reason="MACO hosted callback denied the action"
if [ -n "$tool_name" ] && [ -f "$allow_file" ] && grep -Fxq "$tool_name" "$allow_file"; then
  decision="allow"
  reason="MACO hosted callback allowed a listed tool"
fi
printf '%s\n' "{\"source\":\"pretooluse-hook\",\"tool_name\":\"${tool_name}\",\"decision\":\"${decision}\",\"reason\":\"${reason}\"}" >> "$journal"
printf '%s\n' "{\"hookSpecificOutput\":{\"hookEventName\":\"PreToolUse\",\"permissionDecision\":\"${decision}\",\"permissionDecisionReason\":\"${reason}\"}}"
exit 0
"#;

/// Kind of proposed child action that must pass the hosted gate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedActionKind {
    Tool,
    Filesystem,
    Destructive,
}

/// Fail-closed review outcome. Only [`HostedCallbackDecision::Allow`] lets an action proceed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum HostedCallbackDecision {
    Allow,
    Deny,
}

/// One proposed tool, filesystem, or destructive action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProposedHostedAction {
    pub kind: HostedActionKind,
    pub tool_name: String,
    pub tool_input: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

/// Explicit allow-list. The default is deny-all; an empty list still reviews every action.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct HostedCallbackPolicy {
    allow_tools: BTreeSet<String>,
}

impl HostedCallbackPolicy {
    pub fn deny_all() -> Self {
        Self::default()
    }

    pub fn allow_tools<I, S>(tools: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            allow_tools: tools.into_iter().map(Into::into).collect(),
        }
    }

    fn allows(&self, tool_name: &str) -> bool {
        !tool_name.is_empty() && self.allow_tools.contains(tool_name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct HostedCallbackJournalRecord {
    pub version: u32,
    pub decision: HostedCallbackDecision,
    pub kind: HostedActionKind,
    pub tool_name: String,
    pub reason: String,
    pub fail_closed: bool,
    pub action_proceeds: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedHookResult {
    pub decision: HostedCallbackDecision,
    pub kind: HostedActionKind,
    pub tool_name: String,
    pub reason: String,
    pub stdout: String,
    pub fail_closed: bool,
}

impl HostedHookResult {
    pub fn action_proceeds(&self) -> bool {
        matches!(self.decision, HostedCallbackDecision::Allow)
    }

    pub fn permission_decision(&self) -> &'static str {
        match self.decision {
            HostedCallbackDecision::Allow => "allow",
            HostedCallbackDecision::Deny => "deny",
        }
    }
}

/// MACO-owned blocking reviewer. Unattached instances deny every action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedPreActionGate {
    attached: bool,
    policy: HostedCallbackPolicy,
    journal_path: Option<PathBuf>,
    records: Vec<HostedCallbackJournalRecord>,
}

impl HostedPreActionGate {
    pub fn unattached() -> Self {
        Self {
            attached: false,
            policy: HostedCallbackPolicy::deny_all(),
            journal_path: None,
            records: Vec::new(),
        }
    }

    pub fn attached(policy: HostedCallbackPolicy) -> Self {
        Self {
            attached: true,
            policy,
            journal_path: None,
            records: Vec::new(),
        }
    }

    pub fn attached_from(attachment: &HostedCallbackAttachment) -> Result<Self> {
        Ok(Self {
            attached: true,
            policy: attachment.load_policy()?,
            journal_path: Some(attachment.journal_path().to_path_buf()),
            records: Vec::new(),
        })
    }

    pub fn is_attached(&self) -> bool {
        self.attached
    }

    pub fn records(&self) -> &[HostedCallbackJournalRecord] {
        &self.records
    }

    pub fn review(&mut self, action: &ProposedHostedAction) -> Result<HostedCallbackJournalRecord> {
        let (decision, reason, fail_closed) = if !self.attached {
            (
                HostedCallbackDecision::Deny,
                "hosted callback is not attached".to_string(),
                true,
            )
        } else if action.tool_name.trim().is_empty() {
            (
                HostedCallbackDecision::Deny,
                "proposed action omitted a tool name".to_string(),
                true,
            )
        } else if self.policy.allows(&action.tool_name) {
            (
                HostedCallbackDecision::Allow,
                "hosted callback allowed a listed tool".to_string(),
                false,
            )
        } else {
            (
                HostedCallbackDecision::Deny,
                "hosted callback denied the action".to_string(),
                true,
            )
        };
        let record = HostedCallbackJournalRecord {
            version: HOSTED_CALLBACK_JOURNAL_VERSION,
            decision,
            kind: action.kind,
            tool_name: action.tool_name.clone(),
            reason,
            fail_closed,
            action_proceeds: matches!(decision, HostedCallbackDecision::Allow),
        };
        if let Some(path) = &self.journal_path {
            append_journal_record(path, &record)?;
        }
        self.records.push(record.clone());
        Ok(record)
    }
}

/// Durable proof that Claude Code PreToolUse is hosted for every tool action.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostedCallbackAttachment {
    callback_dir: PathBuf,
    claude_config_dir: PathBuf,
    hook_path: PathBuf,
    settings_path: PathBuf,
    journal_path: PathBuf,
    allow_tools_path: PathBuf,
}

impl HostedCallbackAttachment {
    pub fn callback_dir(&self) -> &Path {
        &self.callback_dir
    }

    pub fn claude_config_dir(&self) -> &Path {
        &self.claude_config_dir
    }

    pub fn hook_path(&self) -> &Path {
        &self.hook_path
    }

    pub fn settings_path(&self) -> &Path {
        &self.settings_path
    }

    pub fn journal_path(&self) -> &Path {
        &self.journal_path
    }

    pub fn covers_all_actions(&self) -> bool {
        verify_pretooluse_host(self).is_ok()
    }

    fn load_policy(&self) -> Result<HostedCallbackPolicy> {
        load_allow_tools(&self.allow_tools_path)
    }
}

/// Writes Claude `settings.json` plus a fail-closed PreToolUse hook command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudePreToolUseHost {
    attachment: HostedCallbackAttachment,
}

impl ClaudePreToolUseHost {
    pub fn attach(root: impl AsRef<Path>) -> Result<Self> {
        let callback_dir = root.as_ref().join("hosted-callback");
        let claude_config_dir = callback_dir.join(CLAUDE_CONFIG_DIR_NAME);
        fs::create_dir_all(&claude_config_dir).with_context(|| {
            format!(
                "failed to create hosted callback directory {}",
                claude_config_dir.display()
            )
        })?;
        let hook_path = callback_dir.join(HOOK_FILE_NAME);
        let settings_path = claude_config_dir.join(SETTINGS_FILE_NAME);
        let journal_path = callback_dir.join(JOURNAL_FILE_NAME);
        let allow_tools_path = callback_dir.join(ALLOW_TOOLS_FILE_NAME);
        let attachment_path = callback_dir.join(ATTACHMENT_FILE_NAME);

        let hook = PRETOOLUSE_HOOK_SCRIPT.replace(
            "__MACO_HOSTED_CALLBACK_DIR__",
            &unix_path_display(&callback_dir),
        );
        fs::write(&hook_path, hook)
            .with_context(|| format!("failed to write PreToolUse hook {}", hook_path.display()))?;
        set_executable(&hook_path)?;
        fs::write(&allow_tools_path, "").with_context(|| {
            format!(
                "failed to write hosted callback allow-list {}",
                allow_tools_path.display()
            )
        })?;
        fs::write(&journal_path, "").with_context(|| {
            format!(
                "failed to create hosted callback journal {}",
                journal_path.display()
            )
        })?;

        let settings = json!({
            "hooks": {
                "PreToolUse": [{
                    "matcher": ALL_TOOLS_MATCHER,
                    "hooks": [{
                        "type": "command",
                        "command": unix_path_display(&hook_path)
                    }]
                }]
            }
        });
        fs::write(&settings_path, serde_json::to_vec_pretty(&settings)?).with_context(|| {
            format!(
                "failed to write Claude PreToolUse settings {}",
                settings_path.display()
            )
        })?;
        let proof = json!({
            "version": HOSTED_CALLBACK_JOURNAL_VERSION,
            "adapter": AdapterId::ClaudeCode.as_str(),
            "hook_event": CLAUDE_PRETOOLUSE_EVENT,
            "matcher": ALL_TOOLS_MATCHER,
            "covers_all_actions": true,
        });
        fs::write(&attachment_path, serde_json::to_vec_pretty(&proof)?).with_context(|| {
            format!(
                "failed to write hosted callback attachment {}",
                attachment_path.display()
            )
        })?;

        let attachment = HostedCallbackAttachment {
            callback_dir,
            claude_config_dir,
            hook_path,
            settings_path,
            journal_path,
            allow_tools_path,
        };
        verify_pretooluse_host(&attachment)?;
        Ok(Self { attachment })
    }

    pub fn attachment(&self) -> &HostedCallbackAttachment {
        &self.attachment
    }

    pub fn into_attachment(self) -> HostedCallbackAttachment {
        self.attachment
    }

    pub fn gate(&self) -> Result<HostedPreActionGate> {
        HostedPreActionGate::attached_from(&self.attachment)
    }
}

/// Review a Claude PreToolUse stdin payload. Deny emits a blocking hook response.
pub fn review_pretooluse(gate: &mut HostedPreActionGate, stdin: &[u8]) -> Result<HostedHookResult> {
    let (action, parse_error) = match parse_pretooluse_action(stdin) {
        Ok(action) => (action, None),
        Err(error) => (
            ProposedHostedAction {
                kind: HostedActionKind::Tool,
                tool_name: String::new(),
                tool_input: Value::Null,
                session_id: None,
                cwd: None,
            },
            Some(error.to_string()),
        ),
    };
    let record = gate.review(&action)?;
    let mut result = hook_result_from_record(&record);
    if let Some(error) = parse_error {
        result.fail_closed = true;
        result.decision = HostedCallbackDecision::Deny;
        result.reason = format!("hosted callback failed closed: {error}");
        result.stdout = pretooluse_response(HostedCallbackDecision::Deny, &result.reason);
    }
    Ok(result)
}

/// Adapter-id consult used by tests and future launch wiring.
///
/// A hosted All-callback can still grant primary-writable release. Isolated
/// worktree launch no longer waits for that attachment.
pub fn writable_leaf_launch_refusal_with_host(
    adapter: AdapterId,
    host: Option<&HostedCallbackAttachment>,
) -> Option<&'static str> {
    if adapter == AdapterId::ClaudeCode
        && host.is_some_and(HostedCallbackAttachment::covers_all_actions)
    {
        return RuntimeCapabilities::CLAUDE_CODE
            .with_hosted_blocking_callback()
            .worktree_writable_refusal();
    }
    adapter.writable_leaf_launch_refusal()
}

/// Hermetic runner that feeds committed PreToolUse fixtures into the hosted gate.
pub struct HostedCallbackFixtureRunner;

impl HostedCallbackFixtureRunner {
    pub fn fixture_path(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/runtime_adapter/hosted_callback")
            .join(name)
    }

    pub fn review_fixture(gate: &mut HostedPreActionGate, name: &str) -> Result<HostedHookResult> {
        let path = Self::fixture_path(name);
        let bytes = fs::read(&path).with_context(|| {
            format!("failed to read hosted callback fixture {}", path.display())
        })?;
        review_pretooluse(gate, &bytes)
    }
}

fn parse_pretooluse_action(stdin: &[u8]) -> Result<ProposedHostedAction> {
    if stdin.is_empty() {
        bail!("PreToolUse payload is missing");
    }
    let value: Value = serde_json::from_slice(stdin).context("PreToolUse payload is not JSON")?;
    let event = value
        .get("hook_event_name")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !event.is_empty() && event != CLAUDE_PRETOOLUSE_EVENT {
        bail!("PreToolUse payload event {event} is not {CLAUDE_PRETOOLUSE_EVENT}");
    }
    let tool_name = value
        .get("tool_name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .trim()
        .to_string();
    let tool_input = value.get("tool_input").cloned().unwrap_or(Value::Null);
    Ok(ProposedHostedAction {
        kind: classify_action(&tool_name, &tool_input),
        tool_name,
        tool_input,
        session_id: value
            .get("session_id")
            .and_then(Value::as_str)
            .map(str::to_string),
        cwd: value.get("cwd").and_then(Value::as_str).map(str::to_string),
    })
}

fn classify_action(tool_name: &str, tool_input: &Value) -> HostedActionKind {
    match tool_name {
        "Delete" => HostedActionKind::Destructive,
        "Read" | "Write" | "Edit" | "NotebookEdit" | "Grep" | "Glob" | "LS" => {
            HostedActionKind::Filesystem
        }
        "Bash" | "Shell" => {
            let command = tool_input
                .get("command")
                .and_then(Value::as_str)
                .unwrap_or("");
            if command_looks_destructive(command) {
                HostedActionKind::Destructive
            } else {
                HostedActionKind::Tool
            }
        }
        _ => HostedActionKind::Tool,
    }
}

fn command_looks_destructive(command: &str) -> bool {
    let lowered = command.to_ascii_lowercase();
    ["rm ", "rm\t", "rm -", "dd ", "mkfs", "shred ", "truncate "]
        .iter()
        .any(|needle| lowered.contains(needle))
}

fn hook_result_from_record(record: &HostedCallbackJournalRecord) -> HostedHookResult {
    HostedHookResult {
        decision: record.decision,
        kind: record.kind,
        tool_name: record.tool_name.clone(),
        reason: record.reason.clone(),
        stdout: pretooluse_response(record.decision, &record.reason),
        fail_closed: record.fail_closed,
    }
}

fn pretooluse_response(decision: HostedCallbackDecision, reason: &str) -> String {
    let payload = json!({
        "hookSpecificOutput": {
            "hookEventName": CLAUDE_PRETOOLUSE_EVENT,
            "permissionDecision": match decision {
                HostedCallbackDecision::Allow => "allow",
                HostedCallbackDecision::Deny => "deny",
            },
            "permissionDecisionReason": reason,
        }
    });
    format!("{payload}\n")
}

fn append_journal_record(path: &Path, record: &HostedCallbackJournalRecord) -> Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("failed to open hosted callback journal {}", path.display()))?;
    let line =
        serde_json::to_string(record).context("failed to serialize hosted callback journal")?;
    file.write_all(line.as_bytes())
        .and_then(|_| file.write_all(b"\n"))
        .with_context(|| {
            format!(
                "failed to append hosted callback journal {}",
                path.display()
            )
        })?;
    Ok(())
}

fn load_allow_tools(path: &Path) -> Result<HostedCallbackPolicy> {
    if !path.exists() {
        return Ok(HostedCallbackPolicy::deny_all());
    }
    let text = fs::read_to_string(path).with_context(|| {
        format!(
            "failed to read hosted callback allow-list {}",
            path.display()
        )
    })?;
    Ok(HostedCallbackPolicy::allow_tools(
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty() && !line.starts_with('#')),
    ))
}

fn verify_pretooluse_host(attachment: &HostedCallbackAttachment) -> Result<()> {
    if !attachment.hook_path.is_file() {
        bail!(
            "hosted PreToolUse hook is missing: {}",
            attachment.hook_path.display()
        );
    }
    let settings = fs::read(&attachment.settings_path).with_context(|| {
        format!(
            "failed to read hosted PreToolUse settings {}",
            attachment.settings_path.display()
        )
    })?;
    let value: Value =
        serde_json::from_slice(&settings).context("hosted PreToolUse settings are not JSON")?;
    if !settings_cover_all_pretooluse(&value) {
        bail!("hosted PreToolUse settings do not match every tool action");
    }
    Ok(())
}

fn settings_cover_all_pretooluse(value: &Value) -> bool {
    let Some(groups) = value
        .get("hooks")
        .and_then(|hooks| hooks.get(CLAUDE_PRETOOLUSE_EVENT))
        .and_then(Value::as_array)
    else {
        return false;
    };
    groups.iter().any(|group| {
        let matcher = group
            .get("matcher")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let covers_all = matcher.is_empty() || matcher == ALL_TOOLS_MATCHER;
        let has_command = group
            .get("hooks")
            .and_then(Value::as_array)
            .is_some_and(|hooks| {
                hooks.iter().any(|hook| {
                    hook.get("type").and_then(Value::as_str) == Some("command")
                        && hook
                            .get("command")
                            .and_then(Value::as_str)
                            .is_some_and(|command| !command.is_empty())
                })
            });
        covers_all && has_command
    })
}

fn unix_path_display(path: &Path) -> String {
    path.display().to_string().replace('\\', "/")
}

fn set_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = fs::metadata(path)
            .with_context(|| format!("failed to inspect hook {}", path.display()))?
            .permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(path, permissions)
            .with_context(|| format!("failed to mark hook executable {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Effective capabilities for an optional Claude PreToolUse host.
pub fn capabilities_with_hosted_callback(
    host: Option<&HostedCallbackAttachment>,
) -> RuntimeCapabilities {
    if host.is_some_and(HostedCallbackAttachment::covers_all_actions) {
        RuntimeCapabilities::CLAUDE_CODE.with_hosted_blocking_callback()
    } else {
        RuntimeCapabilities::CLAUDE_CODE
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime_adapter::{
        AgentRuntimeAdapter, BlockingPreActionCallback, CapabilityMatrix, ClaudeCodeAdapter,
        WorkspaceWritability,
    };
    use std::{
        io::Write,
        process::{Command, Stdio},
    };

    fn review_named(gate: &mut HostedPreActionGate, name: &str) -> HostedHookResult {
        HostedCallbackFixtureRunner::review_fixture(gate, name).expect("fixture review")
    }

    #[test]
    fn deny_blocks_the_proposed_action() {
        let mut gate = HostedPreActionGate::attached(HostedCallbackPolicy::deny_all());
        let result = review_named(&mut gate, "pretooluse-bash-rm.json");
        assert_eq!(result.decision, HostedCallbackDecision::Deny);
        assert!(!result.action_proceeds());
        assert_eq!(result.kind, HostedActionKind::Destructive);
        assert!(result.stdout.contains("\"permissionDecision\":\"deny\""));
        assert_eq!(gate.records().len(), 1);
        assert!(!gate.records()[0].action_proceeds);
    }

    #[test]
    fn missing_callback_is_fail_closed() {
        let mut gate = HostedPreActionGate::unattached();
        let result = review_named(&mut gate, "pretooluse-write.json");
        assert!(!gate.is_attached());
        assert_eq!(result.decision, HostedCallbackDecision::Deny);
        assert!(result.fail_closed);
        assert!(!result.action_proceeds());
        assert!(result.reason.contains("not attached"));
    }

    #[test]
    fn malformed_payload_is_fail_closed() {
        let mut gate = HostedPreActionGate::attached(HostedCallbackPolicy::deny_all());
        let result = review_named(&mut gate, "pretooluse-malformed.json");
        assert_eq!(result.decision, HostedCallbackDecision::Deny);
        assert!(result.fail_closed);
        assert!(!result.action_proceeds());
        assert!(result.stdout.contains("\"permissionDecision\":\"deny\""));
    }

    #[test]
    fn allow_list_is_required_before_an_action_proceeds() {
        let mut gate = HostedPreActionGate::attached(HostedCallbackPolicy::allow_tools(["Read"]));
        let allowed = review_named(&mut gate, "pretooluse-read.json");
        assert_eq!(allowed.decision, HostedCallbackDecision::Allow);
        assert!(allowed.action_proceeds());
        let denied = review_named(&mut gate, "pretooluse-write.json");
        assert_eq!(denied.decision, HostedCallbackDecision::Deny);
        assert!(!denied.action_proceeds());
    }

    #[test]
    fn adapter_admits_writable_only_when_the_gate_is_attached() -> Result<()> {
        let mut adapter = ClaudeCodeAdapter::from_environment();
        assert_eq!(adapter.capabilities(), RuntimeCapabilities::CLAUDE_CODE);
        assert!(!adapter.capabilities().admits_writable_release());
        adapter.require_writable_release().expect_err("unattached");
        assert_eq!(
            writable_leaf_launch_refusal_with_host(AdapterId::ClaudeCode, None),
            Some("side_effect_confinement != verified")
        );

        let temp = tempfile::tempdir()?;
        adapter.attach_hosted_pretooluse(temp.path())?;
        assert!(adapter
            .hosted_callback()
            .is_some_and(HostedCallbackAttachment::covers_all_actions));
        assert_eq!(
            adapter.capabilities().blocking_pre_action_callback,
            BlockingPreActionCallback::All
        );
        assert_eq!(
            adapter.capabilities().writable_workspace,
            WorkspaceWritability::Supported
        );
        assert!(adapter.capabilities().admits_writable_release());
        adapter.require_writable_release()?;
        assert_eq!(
            writable_leaf_launch_refusal_with_host(
                AdapterId::ClaudeCode,
                adapter.hosted_callback()
            ),
            Some("side_effect_confinement != verified")
        );
        assert_eq!(
            AdapterId::ClaudeCode.writable_leaf_launch_refusal(),
            Some("side_effect_confinement != verified")
        );
        assert_eq!(
            AdapterId::ClaudeCode.writable_launch_refusal(
                crate::runtime_adapter::WritableLaunchTarget::PrimaryWorktree
            ),
            Some("blocking_pre_action_callback != All")
        );
        assert_eq!(
            AdapterId::ClaudeCode.capabilities(),
            RuntimeCapabilities::CLAUDE_CODE
        );
        Ok(())
    }

    #[test]
    fn production_descriptors_stay_fail_closed_and_codex_stays_commands_only() {
        assert_eq!(
            RuntimeCapabilities::CODEX.blocking_pre_action_callback,
            BlockingPreActionCallback::CommandsOnly
        );
        assert!(!RuntimeCapabilities::CODEX.admits_writable_release());
        assert!(!RuntimeCapabilities::FAKE.admits_writable_release());
        assert_eq!(
            RuntimeCapabilities::FAKE.writable_workspace,
            WorkspaceWritability::Unsupported
        );
        assert_eq!(
            RuntimeCapabilities::CLAUDE_CODE.blocking_pre_action_callback,
            BlockingPreActionCallback::None
        );
        let matrix = CapabilityMatrix::all_known();
        for row in &matrix.adapters {
            assert_eq!(row.capabilities, row.adapter.capabilities());
            assert_eq!(
                row.admits_writable_release,
                row.capabilities.admits_writable_release()
            );
            if row.adapter == AdapterId::Codex {
                assert!(!row.admits_writable_release);
                assert!(row.admits_worktree_writable);
            } else {
                assert!(!row.admits_writable_release);
                assert!(!row.admits_worktree_writable);
            }
        }
        let markdown = matrix.to_markdown();
        assert!(markdown.contains("worktree_writable"));
        assert!(markdown.contains("| admitted |"));
        assert!(!markdown.lines().any(|line| {
            line.starts_with("| claude-code |") && line.contains("| supported |") && {
                line.split('|').nth(2).map(str::trim) == Some("supported")
            }
        }));
    }

    #[test]
    fn incomplete_settings_do_not_cover_all_actions() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let host = ClaudePreToolUseHost::attach(temp.path())?;
        assert!(host.attachment().covers_all_actions());
        fs::write(
            host.attachment().settings_path(),
            r#"{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command","command":"/bin/false"}]}]}}"#,
        )?;
        assert!(!host.attachment().covers_all_actions());
        assert_eq!(
            capabilities_with_hosted_callback(Some(host.attachment())),
            RuntimeCapabilities::CLAUDE_CODE
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn hosted_hook_subprocess_deny_blocks_and_journals() -> Result<()> {
        let temp = tempfile::tempdir()?;
        let host = ClaudePreToolUseHost::attach(temp.path())?;
        let fixture = HostedCallbackFixtureRunner::fixture_path("pretooluse-bash-rm.json");
        let mut child = Command::new(host.attachment().hook_path())
            .env("MACO_HOSTED_CALLBACK_DIR", host.attachment().callback_dir())
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("spawn hosted PreToolUse hook")?;
        {
            let stdin = child.stdin.as_mut().context("hook stdin")?;
            stdin.write_all(&fs::read(fixture)?)?;
        }
        let output = child.wait_with_output().context("wait for hosted hook")?;
        assert_eq!(output.status.code(), Some(0));
        let stdout = String::from_utf8(output.stdout).context("hook stdout")?;
        assert!(stdout.contains("\"permissionDecision\":\"deny\""));
        let journal = fs::read_to_string(host.attachment().journal_path())?;
        assert!(journal.contains("\"decision\":\"deny\""));
        Ok(())
    }
}
