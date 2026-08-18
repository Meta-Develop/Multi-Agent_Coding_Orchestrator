use anyhow::{Context, Result};
use std::{fs, process::Command};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_multi-agent-coding-orchestrator");

#[test]
fn scope_help_lists_serve_subcommand() -> Result<()> {
    let output = Command::new(BIN)
        .args(["scope", "--help"])
        .output()
        .context("run scope help")?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).context("scope help utf8")?;
    assert!(help.contains("serve"));
    assert!(help.contains("observability"));
    Ok(())
}

#[test]
fn scope_serve_help_lists_repository_workspace_and_bind_options() -> Result<()> {
    let output = Command::new(BIN)
        .args(["scope", "serve", "--help"])
        .output()
        .context("run scope serve help")?;
    assert!(output.status.success());
    let help = String::from_utf8(output.stdout).context("scope serve help utf8")?;
    assert!(help.contains("--repo"));
    assert!(help.contains("--workspace"));
    assert!(help.contains("--bind"));
    assert!(help.contains("127.0.0.1:7878"));
    Ok(())
}

#[test]
fn scope_serve_refuses_non_loopback_binds_without_writing_watched_state() -> Result<()> {
    for bind in ["0.0.0.0:0", "192.0.2.1:7878"] {
        let temp = TempDir::new().context("tempdir")?;
        let output = Command::new(BIN)
            .current_dir(temp.path())
            .args(["scope", "serve", "--bind", bind])
            .output()
            .with_context(|| format!("run scope serve with {bind}"))?;

        assert!(!output.status.success(), "{bind} unexpectedly succeeded");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("loopback"),
            "unexpected refusal for {bind}: {stderr}"
        );
        assert!(!temp.path().join(".maco").exists());
        assert_eq!(
            fs::read_dir(temp.path()).context("read tempdir")?.count(),
            0
        );
    }
    Ok(())
}
