use anyhow::{Context, Result};
use std::process::Command;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn supervise_and_autopilot_help_advertise_role_category_override() -> Result<()> {
    for command in ["supervise", "autopilot"] {
        let output = Command::new(BIN)
            .arg(command)
            .arg("run")
            .arg("--help")
            .output()
            .with_context(|| format!("render {command} run help"))?;
        assert!(
            output.status.success(),
            "{command} run --help failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("--role-category"),
            "{command} run help omitted --role-category: {stdout}"
        );
        assert!(
            stdout.contains("operator_override") || stdout.contains("operator role-category"),
            "{command} run help omitted operator-override recording: {stdout}"
        );
    }
    Ok(())
}

#[test]
fn supervise_and_autopilot_reject_unknown_role_category_before_launch() -> Result<()> {
    for command in ["supervise", "autopilot"] {
        let output = Command::new(BIN)
            .arg(command)
            .arg("run")
            .arg("plan.json")
            .arg("--role-category")
            .arg("weak_model")
            .arg("--machine-global-config")
            .arg("/tmp/maco-machine-global.json")
            .arg("--machine-global-runtime-root-id")
            .arg("runtime")
            .output()
            .with_context(|| format!("parse {command} unknown role category"))?;
        assert!(
            !output.status.success(),
            "{command} accepted an unknown role category"
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("role category") || stderr.contains("role-category"),
            "{command} refusal omitted the flag name: {stderr}"
        );
    }
    Ok(())
}
