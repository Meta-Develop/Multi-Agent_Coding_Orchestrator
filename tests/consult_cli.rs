use anyhow::{Context, Result};
use git2::{Repository, Signature};
use multi_agent_coding_orchestrator::{
    artifacts::{ArtifactFileDisposition, ArtifactRunReader, RunArtifactFamily},
    orchestrator::RunId,
};
use serde_json::Value;
use std::{fs, path::Path, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn consult_ask_fake_runtime_writes_report_and_artifacts() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let report = run_success_json(&[
        "consult",
        "ask",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "consult-fake",
        "--question",
        "Why is validation failing with token abcdefghijklmnopqrstuvwxyz1234567890 at /home/example/repo?",
        "--context-path",
        "README.md",
        "--json",
    ])?;

    assert_eq!(report["success"], true);
    assert_eq!(report["status"], "succeeded");
    assert_eq!(report["runtime"], "fake");
    assert_eq!(report["no_further_delegation"], true);
    assert_eq!(report["read_only"], true);
    assert!(report["question_summary"]
        .as_str()
        .context("question summary")?
        .contains("<redacted:token>"));
    assert!(report["question_summary"]
        .as_str()
        .context("question summary")?
        .contains("<redacted:local-path>"));
    assert!(repo_path
        .join(".maco/consult/runs/consult-fake/trusted/question.md")
        .exists());
    assert!(repo_path
        .join(".maco/consult/runs/consult-fake/trusted/consultant-report.json")
        .exists());
    assert!(repo_path
        .join(".maco/consult/runs/consult-fake/trusted/raw.log")
        .exists());
    assert!(repo_path
        .join(".maco/consult/runs/consult-fake/trusted/schemas/consultant-report.schema.json")
        .exists());
    assert!(!repo_path
        .join(".maco/consult/runs/consult-fake/incoming")
        .exists());
    assert!(!repo_path
        .join(".maco/consult/runs/consult-fake/capture")
        .exists());

    let run_id = RunId::new("consult-fake")?;
    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Consult, &run_id)?;
    let finalization = reader.finalization();
    assert!(!finalization.publish_requested);
    assert!(!finalization.publishable);
    assert_eq!(finalization.files.len(), 4);
    assert_eq!(
        finalization
            .files
            .iter()
            .find(|record| record.path == Path::new("trusted/question.md"))
            .context("question manifest record")?
            .disposition,
        ArtifactFileDisposition::PrivateEvidence
    );
    assert_eq!(
        finalization
            .files
            .iter()
            .find(|record| record.path == Path::new("trusted/raw.log"))
            .context("raw manifest record")?
            .disposition,
        ArtifactFileDisposition::PrivateEvidence
    );
    assert_eq!(
        finalization
            .files
            .iter()
            .find(|record| record.path == Path::new("trusted/consultant-report.json"))
            .context("final report manifest record")?
            .disposition,
        ArtifactFileDisposition::Publishable
    );
    let reader_report: Value =
        serde_json::from_slice(&reader.read("trusted/consultant-report.json")?)?;
    assert_eq!(reader_report, report);

    Ok(())
}

#[test]
fn consult_operational_refusal_is_redacted_and_finalized() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let report = run_failure_json(&[
        "consult",
        "ask",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "consult-refused",
        "--question=-----BEGIN PRIVATE KEY-----\nnever-persist-this\n-----END PRIVATE KEY-----",
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert_eq!(report["question_summary"], "<redacted:refused-question>");
    let run_dir = repo_path.join(".maco/consult/runs/consult-refused");
    let question = fs::read(run_dir.join("trusted/question.md"))?;
    let raw = fs::read(run_dir.join("trusted/raw.log"))?;
    let final_report = fs::read(run_dir.join("trusted/consultant-report.json"))?;
    let marker = fs::read(run_dir.join(".maco-artifact-final.json"))?;
    for artifact in [&question, &raw, &final_report, &marker] {
        assert!(!String::from_utf8_lossy(artifact).contains("never-persist-this"));
    }
    assert_eq!(
        String::from_utf8(question)?,
        "ROLE: CONSULTANT\nAGENT_KIND: consultant\nAGENT_LABEL: consult-refused\nPARENT_THREAD_ID: none\nTHREAD_DEPTH: 2\nNO_FURTHER_DELEGATION: true\nConsult request refused before a question could be safely persisted.\n"
    );
    assert_eq!(raw, b"consult request refused before subprocess launch\n");

    let run_id = RunId::new("consult-refused")?;
    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Consult, &run_id)?;
    assert!(!reader.finalization().publish_requested);
    assert!(!reader.finalization().publishable);
    assert!(!run_dir.join("incoming").exists());
    assert!(!run_dir.join("capture").exists());

    let missing_bin = run_failure_json(&[
        "consult",
        "ask",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "consult-missing-bin",
        "--runtime",
        "codex",
        "--question",
        "Safe question",
        "--json",
    ])?;
    assert_eq!(missing_bin["success"], false);
    assert!(missing_bin["exit_info"]["error"]
        .as_str()
        .context("missing-bin refusal")?
        .contains("--consultant-bin"));
    let missing_bin_id = RunId::new("consult-missing-bin")?;
    ArtifactRunReader::open(&repo_path, RunArtifactFamily::Consult, &missing_bin_id)?;
    let missing_bin_dir = repo_path.join(".maco/consult/runs/consult-missing-bin");
    assert!(!missing_bin_dir.join("incoming").exists());
    assert!(!missing_bin_dir.join("capture").exists());
    Ok(())
}

#[test]
fn consult_artifact_reader_rejects_tampered_final_report() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    run_success_json(&[
        "consult",
        "ask",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "consult-tamper",
        "--question",
        "Need a bounded second opinion",
        "--json",
    ])?;
    let run_id = RunId::new("consult-tamper")?;
    ArtifactRunReader::open(&repo_path, RunArtifactFamily::Consult, &run_id)?;
    fs::write(
        repo_path.join(".maco/consult/runs/consult-tamper/trusted/consultant-report.json"),
        b"{}\n",
    )?;
    let error = match ArtifactRunReader::open(&repo_path, RunArtifactFamily::Consult, &run_id) {
        Ok(_) => anyhow::bail!("tampered finalized report unexpectedly passed verification"),
        Err(error) => error,
    };
    let message = format!("{error:#}");
    assert!(
        message.contains("length changed")
            || message.contains("digest changed")
            || message.contains("contents changed")
            || message.contains("does not match its manifest"),
        "unexpected tamper error: {message}"
    );

    run_success_json(&[
        "consult",
        "ask",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "consult-marker-tamper",
        "--question",
        "Need another bounded second opinion",
        "--json",
    ])?;
    let marker_path =
        repo_path.join(".maco/consult/runs/consult-marker-tamper/.maco-artifact-final.json");
    let mut marker: Value = serde_json::from_slice(&fs::read(&marker_path)?)?;
    marker["hmac_sha256"] = Value::String("0".repeat(64));
    let mut marker_bytes = serde_json::to_vec_pretty(&marker)?;
    marker_bytes.push(b'\n');
    fs::write(&marker_path, marker_bytes)?;
    let marker_run_id = RunId::new("consult-marker-tamper")?;
    let marker_error =
        match ArtifactRunReader::open(&repo_path, RunArtifactFamily::Consult, &marker_run_id) {
            Ok(_) => anyhow::bail!("tampered HMAC marker unexpectedly passed verification"),
            Err(error) => error,
        };
    assert!(
        format!("{marker_error:#}").contains("HMAC verification failed"),
        "unexpected marker tamper error: {marker_error:#}"
    );
    Ok(())
}

#[test]
fn consult_artifacts_list_latest_prune_and_refuse_run_id_reuse() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    for run_id in ["consult-one", "consult-two"] {
        run_success_json(&[
            "consult",
            "ask",
            "--repo",
            path_str(&repo_path)?,
            "--run-id",
            run_id,
            "--question",
            "Need a second opinion",
            "--json",
        ])?;
    }

    let listed = run_success_json(&[
        "consult",
        "artifacts",
        "list",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(listed["family"], "consult");
    assert_eq!(listed["runs"].as_array().context("listed runs")?.len(), 2);
    assert_eq!(listed["runs"][0]["final_report_status"], "succeeded");

    let latest = run_success_json(&[
        "consult",
        "artifacts",
        "latest",
        "--repo",
        path_str(&repo_path)?,
        "--json",
    ])?;
    assert_eq!(latest["run"]["run_id"], "consult-two");

    let refused = run_failure_json(&[
        "consult",
        "ask",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "consult-two",
        "--question",
        "reuse should fail",
        "--json",
    ])?;
    assert_eq!(refused["status"], "refused");
    assert_eq!(refused["family"], "consult");
    assert!(refused["message"]
        .as_str()
        .context("refusal message")?
        .contains("already exists"));

    let dry_prune = run_success_json(&[
        "consult",
        "artifacts",
        "prune",
        "--repo",
        path_str(&repo_path)?,
        "--keep",
        "1",
        "--dry-run",
        "--json",
    ])?;
    assert_eq!(dry_prune["delete_candidate_count"], 1);
    assert_eq!(dry_prune["deleted_count"], 0);

    let prune = run_success_json(&[
        "consult",
        "artifacts",
        "prune",
        "--repo",
        path_str(&repo_path)?,
        "--keep",
        "1",
        "--json",
    ])?;
    assert_eq!(prune["delete_candidate_count"], 1);
    assert_eq!(prune["deleted_count"], 1);
    assert!(repo_path.join(".maco/consult/runs/consult-two").exists());
    assert!(!repo_path.join(".maco/consult/runs/consult-one").exists());

    Ok(())
}

#[test]
fn consult_custom_codex_is_confined_but_never_publishable() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_codex = write_fake_codex_consultant(temp.path())?;
    let target_launch_marker = temp.path().join("fake-codex-target-started");
    let report = run_failure_json(&[
        "consult",
        "ask",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "consult-codex",
        "--runtime",
        "codex",
        "--consultant-bin",
        path_str(&fake_codex)?,
        "--question",
        "What should I inspect?",
        "--context-path",
        "README.md",
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert_eq!(report["runtime"], "codex");
    assert_eq!(report["no_further_delegation"], true);
    assert_eq!(report["read_only"], true);
    assert_eq!(report["exit_info"]["exit_code"], Value::Null);
    assert_eq!(report["exit_info"]["timed_out"], false);
    let error = report["exit_info"]["error"]
        .as_str()
        .context("fail-closed external error")?;
    assert!(
        error.contains("version preflight")
            || error.contains("strict-offline version diagnostic")
            || error.contains("process-tree ownership")
            || error.contains("containment"),
        "unexpected fail-closed error: {error}"
    );
    assert!(
        error.contains("external target was not started")
            || error.contains("version preflight")
            || error.contains("process-tree ownership")
            || error.contains("containment"),
        "refusal did not prove a pre-target boundary: {error}"
    );
    assert!(!target_launch_marker.exists());
    assert!(report["caveats"]
        .as_array()
        .context("caveats")?
        .iter()
        .any(|caveat| caveat.as_str().is_some_and(|text| {
            text.contains("failed to capture Codex consultant report from reserved descriptor")
        })));
    let command = report["exit_info"]["command"]
        .as_array()
        .context("command")?;
    assert!(command_contains_sequence(command, &["-a", "never"]));
    assert!(command.iter().any(|arg| arg == "--strict-config"));
    assert!(command
        .iter()
        .any(|arg| arg == "default_permissions=\"maco_external_codex\""));
    assert!(command
        .iter()
        .any(|arg| { arg == "permissions.maco_external_codex.network={enabled=false}" }));
    assert!(
        command_contains_sequence(
            command,
            &[
                "-c",
                "permissions.maco_external_codex.network={enabled=false}",
                "-c",
                "<redacted:local-path>",
                "-c",
                "shell_environment_policy.inherit=\"core\"",
            ],
        ),
        "unexpected public confinement command: {command:?}"
    );
    assert!(!command.iter().any(|arg| {
        arg.as_str()
            .is_some_and(|text| text.starts_with("permissions.maco_external_codex.filesystem="))
    }));
    let repo_path_text = path_str(&repo_path)?;
    let fake_codex_text = path_str(&fake_codex)?;
    assert!(!command.iter().any(|arg| {
        arg.as_str()
            .is_some_and(|text| text.contains(repo_path_text) || text.contains(fake_codex_text))
    }));
    assert!(command_contains_sequence(
        command,
        &["--output-last-message", "<redacted:local-path>"]
    ));
    assert!(!command.iter().any(|arg| arg == "--sandbox"));
    assert!(!command.iter().any(|arg| arg == "--enable"));
    let public_report = serde_json::to_string(&report).context("serialize public report")?;
    assert!(!public_report.contains(repo_path_text));
    assert!(!public_report.contains(fake_codex_text));
    assert!(!public_report.contains(path_str(temp.path())?));

    let run_dir = repo_path.join(".maco/consult/runs/consult-codex");
    assert_eq!(fs::read(run_dir.join("trusted/raw.log"))?, b"");
    assert!(!run_dir.join("incoming").exists());
    assert!(!run_dir.join("capture").exists());
    assert!(run_dir.join(".maco-artifact-final.json").exists());

    let run_id = RunId::new("consult-codex")?;
    let reader = ArtifactRunReader::open(&repo_path, RunArtifactFamily::Consult, &run_id)?;
    let finalization = reader.finalization();
    assert_eq!(
        finalization.final_report,
        Path::new("trusted/consultant-report.json")
    );
    assert!(!finalization.publish_requested);
    assert!(!finalization.publishable);
    let stored_report: Value =
        serde_json::from_slice(&reader.read("trusted/consultant-report.json")?)?;
    assert_eq!(stored_report, report);
    assert_eq!(
        fs::read_to_string(repo_path.join("README.md"))?,
        "# Test Repo\n"
    );

    Ok(())
}

#[test]
fn consult_claude_adapter_is_refused_before_launch() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_claude = write_fake_claude_consultant(temp.path())?;
    let report = run_failure_json(&[
        "consult",
        "ask",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "consult-claude",
        "--runtime",
        "claude",
        "--consultant-bin",
        path_str(&fake_claude)?,
        "--question",
        "What should I inspect?",
        "--context-path",
        "README.md",
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert_eq!(report["runtime"], "claude");
    assert!(report["exit_info"]["error"]
        .as_str()
        .context("external refusal")?
        .contains("no enforceable inner read-only permission contract"));
    let command = report["exit_info"]["command"]
        .as_array()
        .context("command")?;
    assert!(command_contains_sequence(
        command,
        &["-p", "--output-format", "json"]
    ));
    assert!(!command
        .iter()
        .any(|arg| arg.as_str().is_some_and(|text| text.contains("danger"))));
    assert_eq!(
        fs::read(repo_path.join(".maco/consult/runs/consult-claude/trusted/raw.log"))?,
        b""
    );
    assert!(!repo_path
        .join(".maco/consult/runs/consult-claude/incoming")
        .exists());
    assert!(!repo_path
        .join(".maco/consult/runs/consult-claude/capture")
        .exists());

    Ok(())
}

#[test]
fn consult_claude_refusal_precedes_result_envelope_parsing() -> Result<()> {
    let temp = TempDir::new().context("tempdir")?;
    let repo_path = create_committed_repo(temp.path())?;
    let fake_claude = write_fake_claude_missing_result(temp.path())?;
    let report = run_failure_json(&[
        "consult",
        "ask",
        "--repo",
        path_str(&repo_path)?,
        "--run-id",
        "consult-claude-missing-result",
        "--runtime",
        "claude",
        "--consultant-bin",
        path_str(&fake_claude)?,
        "--question",
        "What should I inspect?",
        "--json",
    ])?;

    assert_eq!(report["success"], false);
    assert_eq!(report["status"], "failed");
    assert_eq!(report["runtime"], "claude");
    assert!(report["exit_info"]["error"]
        .as_str()
        .context("external refusal")?
        .contains("no enforceable inner read-only permission contract"));
    assert_eq!(
        fs::read(
            repo_path.join(".maco/consult/runs/consult-claude-missing-result/trusted/raw.log")
        )?,
        b""
    );

    Ok(())
}

fn write_fake_codex_consultant(root: &Path) -> Result<std::path::PathBuf> {
    let path = root.join("fake-codex-consultant");
    fs::write(
        &path,
        r#"#!/bin/sh
set -eu
if [ "${1:-}" = "--version" ]; then
  printf '%s\n' 'codex-cli 0.142.3'
  exit 0
fi
: > "${0%/*}/fake-codex-target-started"
report=
cd_arg=
goals=false
multi_agent=false
prompt_arg=
while [ "$#" -gt 0 ]; do
  case "$1" in
    exec)
      shift
      ;;
    --cd)
      cd_arg="$2"
      shift 2
      ;;
    --output-last-message)
      report="$2"
      shift 2
      ;;
    --enable)
      case "$2" in
        goals) goals=true ;;
        multi_agent) multi_agent=true ;;
      esac
      shift 2
      ;;
    -*)
      prompt_arg="$1"
      shift
      ;;
    *)
      prompt_arg="$1"
      shift
      ;;
  esac
done
if [ "$prompt_arg" != "-" ]; then
  echo "expected stdin prompt marker" >&2
  exit 64
fi
prompt_body="$(cat)"
case "$prompt_body" in
  "ROLE: CONSULTANT"*)
    consultant_role_prefix=true
    ;;
  *)
    consultant_role_prefix=false
    ;;
esac
printf '{"event":"fake-codex-consult","cd_arg":"%s","consultant_role_prefix":%s,"goals":%s,"multi_agent":%s}\n' "$cd_arg" "$consultant_role_prefix" "$goals" "$multi_agent"
mkdir -p "$(dirname "$report")"
cat > "$report" <<JSON
{
  "version": 1,
  "run_id": "consult-codex",
  "runtime": "codex",
  "question_summary": "external value should be normalized",
  "answer": "fake codex consultant answer",
  "confidence": "high",
  "references": ["README.md"],
  "caveats": [],
  "no_further_delegation": true,
  "read_only": true,
  "duration_ms": 1,
  "exit_info": {"command": [], "exit_code": 0, "timed_out": false},
  "success": true,
  "status": "succeeded"
}
JSON
"#,
    )
    .context("write fake codex consultant")?;
    make_executable(&path)?;
    Ok(path)
}

fn write_fake_claude_consultant(root: &Path) -> Result<std::path::PathBuf> {
    let path = root.join("fake-claude-consultant");
    fs::write(
        &path,
        r#"#!/bin/sh
set -eu
if [ "$1" != "-p" ] || [ "$2" != "--output-format" ] || [ "$3" != "json" ]; then
  echo "unexpected claude args: $*" >&2
  exit 64
fi
prompt_body="$(cat)"
case "$prompt_body" in
  "ROLE: CONSULTANT"*)
    :
    ;;
  *)
    echo "missing consultant role prefix" >&2
    exit 64
    ;;
esac
cat <<'JSON'
{"result":"{\"version\":1,\"run_id\":\"consult-claude\",\"runtime\":\"claude\",\"question_summary\":\"external value should be normalized\",\"answer\":\"fake claude consultant answer\",\"confidence\":\"medium\",\"references\":[\"README.md\"],\"caveats\":[],\"no_further_delegation\":true,\"read_only\":true,\"duration_ms\":1,\"exit_info\":{\"command\":[],\"exit_code\":0,\"timed_out\":false},\"success\":true,\"status\":\"succeeded\"}"}
JSON
"#,
    )
    .context("write fake claude consultant")?;
    make_executable(&path)?;
    Ok(path)
}

fn write_fake_claude_missing_result(root: &Path) -> Result<std::path::PathBuf> {
    let path = root.join("fake-claude-missing-result");
    fs::write(
        &path,
        r#"#!/bin/sh
set -eu
if [ "$1" != "-p" ] || [ "$2" != "--output-format" ] || [ "$3" != "json" ]; then
  echo "unexpected claude args: $*" >&2
  exit 64
fi
cat >/dev/null
cat <<'JSON'
{"message":"no result here"}
JSON
"#,
    )
    .context("write fake claude missing result")?;
    make_executable(&path)?;
    Ok(path)
}

fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))
            .with_context(|| format!("chmod {}", path.display()))?;
    }
    Ok(())
}

fn command_contains_sequence(command: &[Value], expected: &[&str]) -> bool {
    command.windows(expected.len()).any(|window| {
        window
            .iter()
            .zip(expected)
            .all(|(value, expected)| value.as_str() == Some(*expected))
    })
}

fn run_success_json(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if !output.status.success() {
        anyhow::bail!(
            "maco command failed: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse json")
}

fn run_failure_json(args: &[&str]) -> Result<Value> {
    let output = Command::new(BIN).args(args).output().context("run maco")?;
    if output.status.success() {
        anyhow::bail!(
            "maco command unexpectedly succeeded: {}",
            String::from_utf8_lossy(&output.stdout)
        );
    }
    serde_json::from_slice(&output.stdout).with_context(|| {
        format!(
            "parse failure json: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        )
    })
}

fn create_committed_repo(root: &Path) -> Result<std::path::PathBuf> {
    let repo_path = root.join("repo");
    let output = Command::new(BIN)
        .args(["init", "--repo", path_str(&repo_path)?, "--json"])
        .output()
        .context("init repo")?;
    if !output.status.success() {
        anyhow::bail!("init failed: {}", String::from_utf8_lossy(&output.stderr));
    }
    for protected_root in [".maco", ".maco-cache", ".codex", ".agents"] {
        fs::create_dir_all(repo_path.join(protected_root))
            .with_context(|| format!("create protected root {protected_root}"))?;
    }
    fs::write(repo_path.join(".gitignore"), ".maco/\n").context("write gitignore")?;
    fs::write(repo_path.join("README.md"), "# Test Repo\n").context("write readme")?;
    let repo = Repository::open(&repo_path).context("open repo")?;
    commit_all(&repo, "initial")?;
    Ok(repo_path)
}

fn commit_all(repo: &Repository, message: &str) -> Result<()> {
    let mut index = repo.index().context("index")?;
    index
        .add_all(["*"], git2::IndexAddOption::DEFAULT, None)
        .context("add all")?;
    index.write().context("write index")?;
    let tree_id = index.write_tree().context("write tree")?;
    let tree = repo.find_tree(tree_id).context("find tree")?;
    let signature = Signature::now("Test User", "test@example.com").context("signature")?;
    let parents = match repo.head() {
        Ok(head) => {
            let commit = head.peel_to_commit().context("head commit")?;
            vec![commit]
        }
        Err(_) => Vec::new(),
    };
    let parent_refs = parents.iter().collect::<Vec<_>>();
    repo.commit(
        Some("HEAD"),
        &signature,
        &signature,
        message,
        &tree,
        &parent_refs,
    )
    .context("commit")?;
    Ok(())
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))
}
