#![cfg(unix)]

use anyhow::{bail, Context, Result};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_maco");
#[test]
fn primary_guard_lifecycle_blocks_maco_commit_and_push_and_preserves_custom_hooks() -> Result<()> {
    let fixture = GuardFixture::new("primary-lifecycle")?;
    let custom = install_relative_custom_hooks(&fixture.primary)?;
    let hooks_configuration_before = local_hooks_path_bytes(&fixture.primary)?;
    let pre_commit_before = fs::read(&custom.pre_commit).context("read original pre-commit")?;
    let pre_push_before = fs::read(&custom.pre_push).context("read original pre-push")?;

    let installed = run_guard_json("install", &fixture.primary)?;
    assert_eq!(installed["status"], "installed");
    assert_eq!(installed["mode"], "primary");
    assert_ne!(effective_hooks_path(&fixture.primary)?, "custom-hooks");
    assert_eq!(fs::read(&custom.pre_commit)?, pre_commit_before);
    assert_eq!(fs::read(&custom.pre_push)?, pre_push_before);

    let verified = run_guard_json("verify", &fixture.primary)?;
    assert_eq!(verified["status"], "verified");
    let reinstalled = run_guard_json("install", &fixture.primary)?;
    assert_eq!(reinstalled["status"], "already_installed");
    assert_eq!(reinstalled["hooks_path"], installed["hooks_path"]);

    assert_commit_succeeds(&fixture.primary, "main.txt", "main\n", "main branch change")?;
    git_success(&fixture.primary, &["switch", "-q", "-c", "feature/example"])?;
    assert_commit_succeeds(
        &fixture.primary,
        "feature.txt",
        "feature\n",
        "feature branch change",
    )?;
    git_success(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/feature/example"],
    )?;

    let pre_commit_log = fs::read_to_string(fixture.common_dir.join("custom-pre-commit.log"))
        .context("read custom pre-commit log")?;
    assert_eq!(pre_commit_log, "pre-commit\npre-commit\n");
    let pre_push_args = fs::read_to_string(fixture.common_dir.join("custom-pre-push.args"))
        .context("read custom pre-push arguments")?;
    assert!(pre_push_args.contains("remote=origin\n"));
    assert!(pre_push_args.contains(&format!("location={}\n", fixture.origin.display())));
    let pre_push_stdin = fs::read_to_string(fixture.common_dir.join("custom-pre-push.stdin"))
        .context("read custom pre-push stdin")?;
    assert!(pre_push_stdin.contains("refs/heads/feature/example"));

    git_success(&fixture.primary, &["switch", "-q", "main"])?;
    git_success(&fixture.primary, &["switch", "-q", "-c", "maco/blocked"])?;
    stage_file(&fixture.primary, "blocked.txt", "blocked primary commit\n")?;
    let blocked_commit = git(
        &fixture.primary,
        &["commit", "-m", "blocked primary commit"],
    )?;
    assert_guard_refusal(&blocked_commit, "commit", "maco/blocked")?;

    let prepared_commit = git(
        &fixture.primary,
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "commit",
            "-m",
            "prepare blocked push fixture",
        ],
    )?;
    assert!(
        prepared_commit.status.success(),
        "command-scoped trusted hook isolation must prepare the push fixture: {}",
        String::from_utf8_lossy(&prepared_commit.stderr)
    );
    let blocked_push = git(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/maco/blocked"],
    )?;
    assert_guard_refusal(&blocked_push, "push", "maco/blocked")?;
    assert!(!bare_ref_exists(
        &fixture.origin,
        "refs/heads/maco/blocked"
    )?);
    let environment_bypass = git_with_environment(
        &fixture.primary,
        &["push", "origin", "HEAD:refs/heads/maco/blocked"],
        &[("MACO_GUARD_ALLOW", "1")],
    )?;
    assert!(
        !environment_bypass.status.success(),
        "an untrusted environment variable must not bypass the branch guard"
    );

    let removed = run_guard_json("uninstall", &fixture.primary)?;
    assert_eq!(removed["status"], "removed");
    assert_eq!(effective_hooks_path(&fixture.primary)?, "custom-hooks");
    assert_eq!(
        local_hooks_path_bytes(&fixture.primary)?,
        hooks_configuration_before,
        "uninstall must restore the exact prior core.hooksPath value bytes"
    );
    assert_eq!(fs::read(&custom.pre_commit)?, pre_commit_before);
    assert_eq!(fs::read(&custom.pre_push)?, pre_push_before);
    let absent = run_guard_json("uninstall", &fixture.primary)?;
    assert_eq!(absent["status"], "already_absent");

    Ok(())
}

#[test]
fn primary_guard_chains_relative_receive_hooks_from_the_git_directory() -> Result<()> {
    let fixture = GuardFixture::new("relative-receive")?;
    let relative_hooks_name = "relative-receive-hooks";
    let relative_hooks = fixture.common_dir.join(relative_hooks_name);
    fs::create_dir(&relative_hooks).context("create relative receive hooks directory")?;
    let worktree_relative_hooks = fixture.primary.join(relative_hooks_name);
    fs::create_dir(&worktree_relative_hooks).context("create relative worktree hooks directory")?;
    let worktree_reference_transaction = worktree_relative_hooks.join("reference-transaction");
    fs::write(
        &worktree_reference_transaction,
        b"#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf 'reference-worktree\\n' >> \"$common/relative-reference-worktree.log\"\n",
    )?;
    fs::set_permissions(
        &worktree_reference_transaction,
        fs::Permissions::from_mode(0o700),
    )?;
    let hook_scripts = [
        (
            "pre-receive",
            "#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf 'pre-receive\\n' >> \"$common/relative-receive.log\"\ncat >> \"$common/relative-receive.stdin\"\n",
        ),
        (
            "update",
            "#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf 'update:%s\\n' \"$1\" >> \"$common/relative-receive.log\"\n",
        ),
        (
            "post-receive",
            "#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf 'post-receive\\n' >> \"$common/relative-receive.log\"\ncat >> \"$common/relative-receive.stdin\"\n",
        ),
        (
            "post-update",
            "#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf 'post-update:%s\\n' \"$*\" >> \"$common/relative-receive.log\"\n",
        ),
        (
            "reference-transaction",
            "#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf 'reference-gitdir:%s\\n' \"$1\" >> \"$common/relative-receive.log\"\n",
        ),
    ];
    for (name, script) in hook_scripts {
        let hook = relative_hooks.join(name);
        fs::write(&hook, script.as_bytes())
            .with_context(|| format!("write relative {name} hook"))?;
        fs::set_permissions(&hook, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("make relative {name} hook executable"))?;
    }
    git_success(
        &fixture.primary,
        &["config", "core.hooksPath", relative_hooks_name],
    )?;

    let installed = run_guard_json("install", &fixture.primary)?;
    assert_eq!(installed["status"], "installed");
    let guard_root = fixture.common_dir.join("maco-worktree-guard");
    assert_eq!(
        PathBuf::from(fs::read_to_string(guard_root.join("previous-hooks-path"))?.trim_end()),
        fixture.primary.join(relative_hooks_name)
    );
    assert_eq!(
        PathBuf::from(
            fs::read_to_string(guard_root.join("previous-git-dir-hooks-path"))?.trim_end()
        ),
        relative_hooks
    );

    // Changing the underlying local value proves receive-pack reaches the
    // guard's conditional include and then chains the install-time path. If
    // the include were inactive, this deliberately nonexistent path would
    // silently disable the receive hooks and the log assertions would fail.
    git_success(
        &fixture.primary,
        &["config", "core.hooksPath", "disabled-receive-hooks"],
    )?;
    assert_ne!(
        effective_hooks_path(&fixture.primary)?,
        "disabled-receive-hooks"
    );
    git_success(&fixture.primary, &["branch", "reference-worktree-probe"])?;
    assert!(
        fs::read_to_string(fixture.common_dir.join("relative-reference-worktree.log"))?
            .contains("reference-worktree")
    );

    let source = fixture.temp.path().join("receive-source");
    command_success(
        Command::new("git")
            .args(["clone", "-q"])
            .arg(&fixture.primary)
            .arg(&source),
        "clone receive source",
    )?;
    git_success(&source, &["config", "user.name", "Receive Hook Test"])?;
    git_success(
        &source,
        &["config", "user.email", "receive-hook@example.invalid"],
    )?;
    assert_commit_succeeds(&source, "receive.txt", "first\n", "first receive")?;
    git_success(
        &source,
        &["push", "origin", "HEAD:refs/heads/received-through-guard"],
    )?;

    let first_log = fs::read_to_string(fixture.common_dir.join("relative-receive.log"))?;
    for expected in [
        "pre-receive",
        "update:refs/heads/received-through-guard",
        "post-receive",
        "post-update:refs/heads/received-through-guard",
        "reference-gitdir:",
    ] {
        assert!(
            first_log.contains(expected),
            "missing receive hook log: {expected}"
        );
    }
    let first_stdin = fs::read_to_string(fixture.common_dir.join("relative-receive.stdin"))?;
    assert!(first_stdin.contains("refs/heads/received-through-guard"));
    for (name, script) in hook_scripts {
        assert_eq!(
            fs::read(relative_hooks.join(name))?,
            script.as_bytes(),
            "guard must preserve relative {name} hook bytes"
        );
    }

    git_success(
        &fixture.primary,
        &["config", "core.hooksPath", relative_hooks_name],
    )?;
    let verified = run_guard_json("verify", &fixture.primary)?;
    assert_eq!(verified["status"], "verified");
    let removed = run_guard_json("uninstall", &fixture.primary)?;
    assert_eq!(removed["status"], "removed");
    assert_eq!(effective_hooks_path(&fixture.primary)?, relative_hooks_name);

    assert_commit_succeeds(&source, "receive.txt", "second\n", "second receive")?;
    git_success(
        &source,
        &["push", "origin", "HEAD:refs/heads/received-after-uninstall"],
    )?;
    let restored_log = fs::read_to_string(fixture.common_dir.join("relative-receive.log"))?;
    assert_eq!(restored_log.matches("pre-receive\n").count(), 2);
    assert!(restored_log.contains("update:refs/heads/received-after-uninstall"));

    Ok(())
}

#[test]
fn managed_worktree_create_cli_fails_closed_without_repository_cleanliness_capability() -> Result<()>
{
    let fixture = GuardFixture::new("managed-create-capability")?;
    let expected_branch = "workers/registered-lane";
    let worktree_root = fixture.temp.path().join("managed-worktrees");
    let worktrees_before = git_stdout(&fixture.primary, &["worktree", "list", "--porcelain"])?;
    let branches_before = git_stdout(&fixture.primary, &["for-each-ref", "refs/heads"])?;
    let output = Command::new(BIN)
        .args(["worktree", "create", "registered-lane", "--repo"])
        .arg(&fixture.primary)
        .args(["--worktree-root"])
        .arg(&worktree_root)
        .args(["--branch", expected_branch, "--json"])
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .context("run unsupported managed worktree create")?;
    assert!(
        !output.status.success(),
        "public managed worktree creation must fail without a repository-cleanliness capability"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "managed worktree creation is unsupported without a capability-bound repository cleanliness input"
        ),
        "unexpected managed worktree creation refusal: {stderr}"
    );
    assert!(!worktree_root.exists());
    assert!(!fixture.common_dir.join("worktrees").exists());
    assert!(!fixture.common_dir.join("maco").exists());
    assert_eq!(
        git_stdout(&fixture.primary, &["worktree", "list", "--porcelain"])?,
        worktrees_before
    );
    assert_eq!(
        git_stdout(&fixture.primary, &["for-each-ref", "refs/heads"])?,
        branches_before
    );

    Ok(())
}

#[test]
fn primary_guard_install_refuses_non_maco_state_collision_without_overwrite() -> Result<()> {
    let fixture = GuardFixture::new("state-collision")?;
    let collision = fixture.common_dir.join("maco-worktree-guard");
    fs::create_dir(&collision).context("create non-MACO guard-state collision")?;
    let sentinel = collision.join("owner-data");
    fs::write(&sentinel, b"foreign guard state\n").context("write collision sentinel")?;

    let output = run_guard("install", &fixture.primary)?;
    assert!(!output.status.success());
    assert_eq!(fs::read(&sentinel)?, b"foreign guard state\n");
    assert_eq!(
        git_optional_stdout(&fixture.primary, &["config", "--get", "core.hooksPath"])?,
        None
    );
    assert_eq!(
        fs::read_dir(&collision)
            .context("enumerate collision after refusal")?
            .count(),
        1
    );

    Ok(())
}

#[test]
fn guard_honors_worktree_config_precedence_and_verify_is_physically_read_only() -> Result<()> {
    let fixture = GuardFixture::new("worktree-config")?;
    install_relative_custom_hooks(&fixture.primary)?;
    git_success(
        &fixture.primary,
        &["config", "extensions.worktreeConfig", "true"],
    )?;
    git_success(
        &fixture.primary,
        &["config", "--worktree", "core.hooksPath", "custom-hooks"],
    )?;
    let worktree_hooks_before = worktree_hooks_path_bytes(&fixture.primary)?;

    let installed = run_guard_json("install", &fixture.primary)?;
    assert_eq!(installed["status"], "installed");
    let guard_root = fixture.common_dir.join("maco-worktree-guard");
    assert_eq!(
        fs::read_to_string(guard_root.join("include-level"))?,
        "worktree\n"
    );
    assert_eq!(
        effective_hooks_path(&fixture.primary)?,
        installed["hooks_path"]
            .as_str()
            .context("installed guard report has no hooks path")?
    );

    neuter_guard_tree(&guard_root)?;
    let repository_config = fixture.common_dir.join("config");
    let worktree_config = fixture.common_dir.join("config.worktree");
    let repository_before = fs::read(&repository_config)?;
    let worktree_before = fs::read(&worktree_config)?;
    let guard_before = guard_tree_snapshot(&guard_root)?;
    let verified = run_guard_json("verify", &fixture.primary)?;
    assert_eq!(verified["status"], "verified");
    assert_eq!(fs::read(&repository_config)?, repository_before);
    assert_eq!(fs::read(&worktree_config)?, worktree_before);
    assert_eq!(guard_tree_snapshot(&guard_root)?, guard_before);

    restore_guard_tree_permissions(&guard_root)?;
    let removed = run_guard_json("uninstall", &fixture.primary)?;
    assert_eq!(removed["status"], "removed");
    assert_eq!(
        worktree_hooks_path_bytes(&fixture.primary)?,
        worktree_hooks_before,
        "uninstall must restore the byte-exact worktree-level hooks value"
    );
    assert_eq!(effective_hooks_path(&fixture.primary)?, "custom-hooks");
    Ok(())
}

struct GuardFixture {
    temp: TempDir,
    primary: PathBuf,
    origin: PathBuf,
    common_dir: PathBuf,
}

impl GuardFixture {
    fn new(name: &str) -> Result<Self> {
        let temp = TempDir::new().context("create guard fixture root")?;
        let primary = temp.path().join(name);
        let origin = temp.path().join(format!("{name}-origin.git"));

        command_success(
            Command::new("git")
                .args(["init", "-q", "-b", "main"])
                .arg(&primary),
            "initialize primary repository",
        )?;
        git_success(&primary, &["config", "user.name", "Casey Morgan"])?;
        git_success(
            &primary,
            &["config", "user.email", "casey.morgan@example.com"],
        )?;
        stage_file(&primary, "README.md", "# Guard fixture\n")?;
        git_success(&primary, &["commit", "-q", "-m", "initial fixture"])?;

        command_success(
            Command::new("git")
                .args(["init", "--bare", "-q"])
                .arg(&origin),
            "initialize local bare origin",
        )?;
        git_success(&primary, &["remote", "add", "origin", path_text(&origin)?])?;
        let common_dir = PathBuf::from(git_stdout(
            &primary,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        )?);

        Ok(Self {
            temp,
            primary,
            origin,
            common_dir,
        })
    }
}

struct CustomHooks {
    pre_commit: PathBuf,
    pre_push: PathBuf,
}

fn install_relative_custom_hooks(repo: &Path) -> Result<CustomHooks> {
    let hooks = repo.join("custom-hooks");
    fs::create_dir(&hooks).context("create custom hooks directory")?;
    let pre_commit = hooks.join("pre-commit");
    let pre_push = hooks.join("pre-push");
    fs::write(
        &pre_commit,
        b"#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf 'pre-commit\\n' >> \"$common/custom-pre-commit.log\"\n",
    )
    .context("write custom pre-commit")?;
    fs::write(
        &pre_push,
        b"#!/bin/sh\ncommon=$(git rev-parse --path-format=absolute --git-common-dir) || exit 1\nprintf 'remote=%s\\nlocation=%s\\n' \"$1\" \"$2\" >> \"$common/custom-pre-push.args\"\ncat >> \"$common/custom-pre-push.stdin\"\n",
    )
    .context("write custom pre-push")?;
    fs::set_permissions(&pre_commit, fs::Permissions::from_mode(0o700))
        .context("make custom pre-commit executable")?;
    fs::set_permissions(&pre_push, fs::Permissions::from_mode(0o700))
        .context("make custom pre-push executable")?;
    git_success(repo, &["config", "core.hooksPath", "custom-hooks"])?;
    Ok(CustomHooks {
        pre_commit,
        pre_push,
    })
}

fn run_guard_json(operation: &str, repo: &Path) -> Result<Value> {
    let output = run_guard(operation, repo)?;
    if !output.status.success() {
        bail!(
            "maco worktree guard {operation} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    serde_json::from_slice(&output.stdout).context("parse worktree guard JSON")
}

fn run_guard(operation: &str, repo: &Path) -> Result<Output> {
    Command::new(BIN)
        .args([
            "worktree",
            "guard",
            operation,
            "--repo",
            path_text(repo)?,
            "--json",
        ])
        .output()
        .with_context(|| format!("run maco worktree guard {operation}"))
}

fn stage_file(repo: &Path, relative: &str, contents: &str) -> Result<()> {
    fs::write(repo.join(relative), contents)
        .with_context(|| format!("write fixture path {relative}"))?;
    git_success(repo, &["add", relative])
}

fn assert_commit_succeeds(
    repo: &Path,
    relative: &str,
    contents: &str,
    message: &str,
) -> Result<()> {
    stage_file(repo, relative, contents)?;
    git_success(repo, &["commit", "-q", "-m", message])
}

fn assert_guard_refusal(output: &Output, action: &str, branch: &str) -> Result<()> {
    if output.status.success() {
        bail!("guard unexpectedly allowed {action} from {branch}");
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("MACO worktree guard")
            && stderr.contains(action)
            && stderr.contains(branch),
        "unexpected guard refusal for {action} from {branch}: {stderr}"
    );
    Ok(())
}

fn effective_hooks_path(repo: &Path) -> Result<String> {
    git_stdout(repo, &["config", "--get", "core.hooksPath"])
}

fn local_hooks_path_bytes(repo: &Path) -> Result<Vec<u8>> {
    let output = git(
        repo,
        &["config", "--local", "--null", "--get", "core.hooksPath"],
    )?;
    if !output.status.success() {
        bail!(
            "read local core.hooksPath bytes failed in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output.stdout)
}

fn worktree_hooks_path_bytes(repo: &Path) -> Result<Vec<u8>> {
    let output = git(
        repo,
        &["config", "--worktree", "--null", "--get", "core.hooksPath"],
    )?;
    if !output.status.success() {
        bail!(
            "read worktree core.hooksPath bytes failed in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output.stdout)
}

fn guard_tree_snapshot(root: &Path) -> Result<BTreeMap<PathBuf, (Vec<u8>, u32)>> {
    let mut snapshot = BTreeMap::new();
    for entry in fs::read_dir(root).context("enumerate guard root for snapshot")? {
        let entry = entry?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)?;
        if metadata.is_dir() {
            for hook in fs::read_dir(&path)? {
                let hook = hook?.path();
                let hook_metadata = fs::symlink_metadata(&hook)?;
                snapshot.insert(
                    hook.strip_prefix(root)?.to_path_buf(),
                    (fs::read(&hook)?, hook_metadata.permissions().mode()),
                );
            }
        } else {
            snapshot.insert(
                path.strip_prefix(root)?.to_path_buf(),
                (fs::read(&path)?, metadata.permissions().mode()),
            );
        }
    }
    Ok(snapshot)
}

fn neuter_guard_tree(root: &Path) -> Result<()> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o555))?;
    let hooks = root.join("hooks");
    fs::set_permissions(&hooks, fs::Permissions::from_mode(0o555))?;
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path == hooks {
            continue;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    }
    for entry in fs::read_dir(hooks)? {
        fs::set_permissions(entry?.path(), fs::Permissions::from_mode(0o555))?;
    }
    Ok(())
}

fn restore_guard_tree_permissions(root: &Path) -> Result<()> {
    fs::set_permissions(root, fs::Permissions::from_mode(0o700))?;
    let hooks = root.join("hooks");
    fs::set_permissions(&hooks, fs::Permissions::from_mode(0o700))?;
    for entry in fs::read_dir(root)? {
        let path = entry?.path();
        if path == hooks {
            continue;
        }
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    for entry in fs::read_dir(hooks)? {
        fs::set_permissions(entry?.path(), fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn bare_ref_exists(repo: &Path, reference: &str) -> Result<bool> {
    let output = Command::new("git")
        .arg("--git-dir")
        .arg(repo)
        .args(["rev-parse", "--verify", "--quiet", reference])
        .output()
        .context("inspect local bare remote ref")?;
    match output.status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        _ => bail!(
            "failed to inspect bare ref {reference}: {}",
            String::from_utf8_lossy(&output.stderr)
        ),
    }
}

fn git_success(repo: &Path, args: &[&str]) -> Result<()> {
    let output = git(repo, args)?;
    if !output.status.success() {
        bail!(
            "git {args:?} failed in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(())
}

fn git_stdout(repo: &Path, args: &[&str]) -> Result<String> {
    let output = git(repo, args)?;
    if !output.status.success() {
        bail!(
            "git {args:?} failed in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    String::from_utf8(output.stdout)
        .context("decode Git stdout")
        .map(|value| value.trim().to_string())
}

fn git_optional_stdout(repo: &Path, args: &[&str]) -> Result<Option<String>> {
    let output = git(repo, args)?;
    match output.status.code() {
        Some(0) => String::from_utf8(output.stdout)
            .context("decode optional Git stdout")
            .map(|value| Some(value.trim().to_string())),
        Some(1) => Ok(None),
        _ => bail!(
            "git {args:?} failed in {}: {}",
            repo.display(),
            String::from_utf8_lossy(&output.stderr)
        ),
    }
}

fn git(repo: &Path, args: &[&str]) -> Result<Output> {
    git_with_environment(repo, args, &[])
}

fn git_with_environment(
    repo: &Path,
    args: &[&str],
    environment: &[(&str, &str)],
) -> Result<Output> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo)
        .args(args)
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .env_remove("MACO_GUARD_ALLOW");
    for (name, value) in environment {
        command.env(name, value);
    }
    command.output().context("run fixture Git command")
}

fn command_success(command: &mut Command, label: &str) -> Result<()> {
    command_output(command, label).map(|_| ())
}

fn command_output(command: &mut Command, label: &str) -> Result<Output> {
    let output = command
        .env_remove("GIT_DIR")
        .env_remove("GIT_WORK_TREE")
        .env_remove("GIT_COMMON_DIR")
        .env_remove("GIT_INDEX_FILE")
        .output()
        .with_context(|| label.to_string())?;
    if !output.status.success() {
        bail!(
            "{label} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    Ok(output)
}

fn path_text(path: &Path) -> Result<&str> {
    path.to_str()
        .with_context(|| format!("fixture path is not UTF-8: {}", path.display()))
}
