#![cfg(target_os = "linux")]

use std::fs;
use std::os::unix::fs::PermissionsExt;
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
            "#!/bin/sh\nprintf launched > '{}'\nexit 99\n",
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
        .contains("grok login --device-auth"));
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
    for output in [status.stdout, completed.stdout, completed.stderr] {
        assert!(!String::from_utf8(output).unwrap().contains("FAKE"));
    }
    assert!(!root.path().join("unused-xdg").exists());
}
