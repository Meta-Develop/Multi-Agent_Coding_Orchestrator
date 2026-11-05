#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output};

use coding_agent_manager_lib::model::StoredAccountMetadata;

#[test]
fn default_data_directory_is_cam_xdg_directory_not_ordinary_grok_home() {
    let root = tempfile::tempdir().unwrap();
    let xdg = root.path().join("xdg");
    let output = Command::new(env!("CARGO_BIN_EXE_cam-grok-setup"))
        .env("HOME", root.path())
        .env("XDG_DATA_HOME", &xdg)
        .env("GROK_HOME", root.path().join("must-not-create-grok"))
        .env("GROK_AUTH_PATH", root.path().join("must-not-create-auth"))
        .env("PATH", root.path().join("no-programs"))
        .args(["prepare", "work"])
        .stdin(std::process::Stdio::null())
        .output()
        .unwrap();
    assert!(output.status.success());
    let data = xdg.join("coding-agent-manager");
    assert!(data.join("stored-accounts.json").is_file());
    assert!(data.join("accounts/grok-cli/work").is_dir());
    assert!(!root.path().join("must-not-create-grok").exists());
    assert!(!root.path().join("must-not-create-auth").exists());
    assert!(!root.path().join(".grok").exists());
}

#[test]
fn binary_owner_flow_never_launches_login_and_uses_only_managed_home() {
    let root = tempfile::tempdir().unwrap();
    let user = root.path().join("user");
    let bin = root.path().join("bin");
    let data = root.path().join("data");
    fs::create_dir_all(user.join(".grok")).unwrap();
    fs::create_dir(&bin).unwrap();
    let default_auth = user.join(".grok/auth.json");
    fs::write(&default_auth, b"FAKE-default-credential").unwrap();
    let marker = root.path().join("unexpected-login");
    let fake_grok = bin.join("grok");
    fs::write(
        &fake_grok,
        format!(
            "#!/bin/sh\nif [ \"${{1:-}}\" = login ] || [ \"${{2:-}}\" = login ]; then printf launched > '{}'; exit 99; fi\nexit 0\n",
            marker.display()
        ),
    )
    .unwrap();
    fs::set_permissions(&fake_grok, fs::Permissions::from_mode(0o700)).unwrap();
    let run = |args: &[&str]| -> Output {
        Command::new(env!("CARGO_BIN_EXE_cam-grok-setup"))
            .env("HOME", &user)
            .env("XDG_DATA_HOME", root.path().join("unused-xdg"))
            .env("GROK_HOME", user.join(".grok"))
            .env("GROK_AUTH_PATH", &default_auth)
            .env("PATH", &bin)
            .args(["--data-dir", data.to_str().unwrap()])
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    };
    let prepared = run(&["prepare", "work"]);
    assert!(prepared.status.success());
    assert!(String::from_utf8(prepared.stdout)
        .unwrap()
        .contains("grok --no-auto-update login --device-auth"));
    let status = run(&["status"]);
    assert!(status.status.success());
    let accounts: Vec<StoredAccountMetadata> = serde_json::from_slice(&status.stdout).unwrap();
    let incarnation = &accounts[0].account_incarnation;
    assert!(!run(&["complete", "work", "--incarnation", incarnation])
        .status
        .success());
    let auth = data.join("accounts/grok-cli/work/auth.json");
    assert!(!auth.exists());
    fs::write(&auth, include_bytes!("fixtures/grok/valid-auth.json")).unwrap();
    let completed = run(&["complete", "work", "--incarnation", incarnation]);
    assert!(completed.status.success());
    assert!(!run(&["complete", "work", "--incarnation", incarnation])
        .status
        .success());
    assert!(!marker.exists());
    assert_eq!(fs::read(default_auth).unwrap(), b"FAKE-default-credential");
    for output in [status.stdout, completed.stdout.clone(), completed.stderr] {
        assert!(!String::from_utf8(output).unwrap().contains("FAKE"));
    }
    assert!(!root.path().join("unused-xdg").exists());
    let text = String::from_utf8(completed.stdout.clone()).unwrap();
    assert!(text.contains("model metadata is still unobserved"));
    assert!(text.contains("refresh-models work"));
}

const GROK_CACHE: &str = r#"{"fetched_at":"2026-09-29T23:27:32.759696216Z","auth_method":"session","origin":"https://cli-chat-proxy.grok.com/v1/models","models":{"grok-4.7":{"info":{"hidden":false,"reasoning_effort":"high","reasoning_efforts":[{"id":"high","value":"high","default":true},{"id":"low","value":"low","default":false}]}},"grok-4.6":{"info":{"hidden":false,"reasoning_effort":"medium","reasoning_efforts":[{"id":"medium","value":"medium","default":true}]}}}}"#;

struct FakeGrok {
    _root: tempfile::TempDir,
    bin: PathBuf,
    data: PathBuf,
    mode: PathBuf,
    env_file: PathBuf,
    argv_file: PathBuf,
    cwd_file: PathBuf,
    stdin_file: PathBuf,
    marker: PathBuf,
}

impl FakeGrok {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        let record = root.path().join("record");
        fs::create_dir_all(&bin).unwrap();
        fs::create_dir_all(&record).unwrap();
        let mode = record.join("mode");
        let env_file = record.join("env");
        let argv_file = record.join("argv");
        let cwd_file = record.join("cwd");
        let stdin_file = record.join("stdin");
        let marker = record.join("login");
        fs::write(&mode, b"fail").unwrap();
        let program = bin.join("grok");
        fs::write(
            &program,
            format!(
                r#"#!/bin/sh
cp /proc/self/environ '{env}'
printf '%s\n' "$@" > '{argv}'
pwd -P > '{cwd}'
readlink /proc/self/fd/0 > '{stdin}' || true
printf 'VENDOR-STDOUT-SECRET\n'
printf 'VENDOR-STDERR-SECRET\n' >&2
if [ "${{1:-}}" = login ] || [ "${{2:-}}" = login ]; then
  printf launched > '{marker}'
  exit 99
fi
mode=$(cat '{mode}')
if [ "$mode" = fail ]; then
  exit 7
fi
umask 077
cat > "$GROK_HOME/models_cache.json" <<'EOF'
{cache}
EOF
exit 0
"#,
                env = env_file.display(),
                argv = argv_file.display(),
                cwd = cwd_file.display(),
                stdin = stdin_file.display(),
                marker = marker.display(),
                mode = mode.display(),
                cache = GROK_CACHE,
            ),
        )
        .unwrap();
        fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
        Self {
            data: root.path().join("data"),
            bin,
            mode,
            env_file,
            argv_file,
            cwd_file,
            stdin_file,
            marker,
            _root: root,
        }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_cam-grok-setup"))
            .env("HOME", self._root.path().join("user"))
            .env("PATH", &self.bin)
            .env("OPENAI_API_KEY", "FAKE-openai")
            .env("XAI_API_KEY", "FAKE-xai")
            .env("GROK_AUTH_PATH", "FAKE-grok-auth")
            .env("CODEX_API_KEY", "FAKE-codex")
            .args(["--data-dir", self.data.to_str().unwrap()])
            .args(args)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap()
    }
}

fn assert_vendor_was_contained(fake: &FakeGrok, home: &std::path::Path) {
    assert!(!fake.marker.exists(), "catalog refresh must not run login");
    assert_eq!(
        fs::read_to_string(&fake.argv_file).unwrap(),
        "--no-auto-update\nmodels\n"
    );
    let cwd = fs::read_to_string(&fake.cwd_file).unwrap();
    assert_eq!(
        std::path::Path::new(cwd.trim()).canonicalize().unwrap(),
        home.canonicalize().unwrap()
    );
    assert_eq!(
        fs::read_to_string(&fake.stdin_file).unwrap().trim(),
        "/dev/null"
    );
    let environ = String::from_utf8(fs::read(&fake.env_file).unwrap()).unwrap();
    for secret in ["FAKE-openai", "FAKE-xai", "FAKE-grok-auth", "FAKE-codex"] {
        assert!(!environ.contains(secret), "{secret} reached the vendor");
    }
    for name in [
        "OPENAI_API_KEY",
        "XAI_API_KEY",
        "GROK_AUTH_PATH",
        "CODEX_API_KEY",
    ] {
        assert!(
            !environ
                .split('\0')
                .any(|entry| entry.starts_with(&format!("{name}="))),
            "{name} was present"
        );
    }
    assert!(
        environ.contains(&format!("GROK_HOME={}", home.display()))
            || environ.contains(&format!(
                "GROK_HOME={}",
                home.canonicalize().unwrap().display()
            ))
    );
}

fn prepared_account(fake: &FakeGrok) -> String {
    assert!(fake.run(&["prepare", "work"]).status.success());
    let status = fake.run(&["status"]);
    assert!(status.status.success());
    let accounts: Vec<StoredAccountMetadata> = serde_json::from_slice(&status.stdout).unwrap();
    let home = fake.data.join("accounts/grok-cli/work");
    fs::write(
        home.join("auth.json"),
        include_bytes!("fixtures/grok/valid-auth.json"),
    )
    .unwrap();
    accounts[0].account_incarnation.clone()
}

fn observe_count(fake: &FakeGrok) -> usize {
    use coding_agent_manager_lib::account_authority::ObservationOutcome;
    use coding_agent_manager_lib::providers::grok_cli::GrokCliAdapter;
    use coding_agent_manager_lib::providers::ProviderAdapter;
    let status = fake.run(&["status"]);
    let accounts: Vec<StoredAccountMetadata> = serde_json::from_slice(&status.stdout).unwrap();
    let adapter = GrokCliAdapter::default().with_data_dir(&fake.data);
    let observation = adapter.observe_models_for_account(&accounts[0]).unwrap();
    assert_eq!(observation.outcome, ObservationOutcome::Observed);
    observation.content.unwrap().models.len()
}

#[test]
fn catalog_success_reports_observed_model_count_without_vendor_secrets() {
    let fake = FakeGrok::new();
    fs::write(&fake.mode, b"success").unwrap();
    let incarnation = prepared_account(&fake);
    let completed = fake.run(&["complete", "work", "--incarnation", &incarnation]);
    let stdout = String::from_utf8(completed.stdout).unwrap();
    let stderr = String::from_utf8(completed.stderr).unwrap();
    assert!(completed.status.success(), "{stdout}{stderr}");
    assert!(stdout.contains("Observed 2 models."));
    assert!(!stdout.contains("FAKE"));
    assert!(!stdout.contains("VENDOR-STDOUT-SECRET"));
    assert!(!stderr.contains("VENDOR-STDERR-SECRET"));
    let json: serde_json::Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
    assert_eq!(json["event"], "setup-complete");
    assert_eq!(json["modelObservation"], "observed");
    assert_eq!(json["modelCount"], 2);
    let home = fake.data.join("accounts/grok-cli/work");
    assert_vendor_was_contained(&fake, &home);
    assert_eq!(observe_count(&fake), 2);
}

#[test]
fn catalog_failure_warns_and_refresh_models_can_recover() {
    let fake = FakeGrok::new();
    let incarnation = prepared_account(&fake);
    let completed = fake.run(&["complete", "work", "--incarnation", &incarnation]);
    assert!(completed.status.success());
    let stdout = String::from_utf8(completed.stdout).unwrap();
    assert!(stdout.contains("model metadata is still unobserved"));
    assert!(stdout.contains("refresh-models work"));
    assert!(!fake
        .data
        .join("accounts/grok-cli/work/models_cache.json")
        .exists());
    let accounts: Vec<StoredAccountMetadata> =
        serde_json::from_slice(&fake.run(&["status"]).stdout).unwrap();
    assert!(accounts[0].is_selected);
    assert_eq!(
        accounts[0].state,
        coding_agent_manager_lib::model::StoredAccountState::Complete
    );

    fs::write(&fake.mode, b"success").unwrap();
    let refreshed = fake.run(&["refresh-models", "work"]);
    assert!(refreshed.status.success());
    let stdout = String::from_utf8(refreshed.stdout).unwrap();
    assert!(stdout.contains("Observed 2 models."));
    assert!(!stdout.contains("VENDOR-STDOUT-SECRET"));
    let json: serde_json::Value = serde_json::from_str(stdout.lines().last().unwrap()).unwrap();
    assert_eq!(json["event"], "refresh-models");
    assert_eq!(json["modelCount"], 2);
    assert_eq!(observe_count(&fake), 2);
    let home = fake.data.join("accounts/grok-cli/work");
    assert_vendor_was_contained(&fake, &home);
}
