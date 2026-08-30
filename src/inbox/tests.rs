use super::*;
use crate::worktree::WorktreeManager;
use serde_json::json;
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn dirty_primary_paths_fails_closed_on_non_utf8_git_status_path() -> Result<()> {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};

    let temp = tempfile::tempdir()?;
    Repository::init(temp.path())?;
    fs::write(
        temp.path()
            .join(OsString::from_vec(vec![b'n', b'o', b'n', 0xff])),
        b"untracked",
    )?;

    let error = dirty_primary_paths(temp.path()).expect_err("non-UTF-8 status must fail");
    assert!(error
        .to_string()
        .contains("primary worktree status path is not valid UTF-8"));
    Ok(())
}

#[cfg(unix)]
use std::{
    ffi::CString,
    os::unix::{ffi::OsStrExt, fs::symlink},
};

#[test]
fn effectful_inbox_library_entries_fail_closed_before_input_or_artifact_access() {
    let temp = TempDir::new().expect("tempdir");
    let missing_repo = temp.path().join("repo-that-does-not-exist");
    let missing_config = temp.path().join("config-that-does-not-exist");
    let run_id = RunId::new("inbox-failclosed").expect("run id");
    run_inbox(InboxRunOptions {
        repo: missing_repo.clone(),
        run_id: run_id.clone(),
        github: true,
        permission_mode: None,
        dry_run: false,
        max_items: None,
        codex_bin: Some(temp.path().join("worker-must-not-run")),
        machine_global: None,
    })
    .expect_err("inbox run must fail closed");
    watch_inbox(InboxWatchOptions {
        repo: missing_repo,
        poll_seconds: 1,
        once: false,
        github: true,
        permission_mode: None,
        dry_run: false,
        max_items: None,
        codex_bin: None,
        machine_global: None,
    })
    .expect_err("inbox watch must fail closed");
    run_workspace_inbox(InboxWorkspaceRunOptions {
        config: missing_config.clone(),
        run_id,
        dry_run: false,
        codex_bin: None,
        machine_global: None,
    })
    .expect_err("workspace inbox run must fail closed");
    watch_workspace_inbox(InboxWorkspaceWatchOptions {
        config: missing_config,
        poll_seconds: 1,
        once: false,
        dry_run: false,
        codex_bin: None,
        machine_global: None,
    })
    .expect_err("workspace inbox watch must fail closed");

    assert_eq!(fs::read_dir(temp.path()).expect("read temp").count(), 0);
}

#[test]
fn config_schema_defaults_versions_and_rejects_unknown_fields_at_every_level() {
    let compatible: InboxConfig = serde_json::from_value(json!({
        "default_validation_commands": ["true", {"command": "cargo test"}]
    }))
    .expect("legacy-compatible config");
    let compatible = validate_config(compatible).expect("validate compatible config");
    assert_eq!(compatible.version, INBOX_SCHEMA_VERSION);
    assert_eq!(compatible.repository.version, INBOX_SCHEMA_VERSION);
    assert_eq!(compatible.selection.version, INBOX_SCHEMA_VERSION);
    assert_eq!(compatible.privacy.version, INBOX_SCHEMA_VERSION);
    assert!(compatible
        .default_validation_commands
        .iter()
        .all(|command| command.version == INBOX_SCHEMA_VERSION));

    for (label, value) in [
        ("top", json!({"unknown": true})),
        ("repository", json!({"repository": {"unknown": true}})),
        ("selection", json!({"selection": {"unknown": true}})),
        ("privacy", json!({"privacy": {"unknown": true}})),
        (
            "validation command",
            json!({"default_validation_commands": [{"command": "true", "unknown": true}]}),
        ),
    ] {
        assert!(
            serde_json::from_value::<InboxConfig>(value).is_err(),
            "{label} unknown field was accepted"
        );
    }

    for (label, value) in [
        (
            "workspace top",
            json!({"repositories": [{"id": "repo", "path": "."}], "unknown": true}),
        ),
        (
            "workspace repository",
            json!({"repositories": [{"id": "repo", "path": ".", "unknown": true}]}),
        ),
        (
            "workspace safety",
            json!({"repositories": [{"id": "repo", "path": "."}], "safety": {"unknown": true}}),
        ),
    ] {
        assert!(
            serde_json::from_value::<InboxWorkspaceConfig>(value).is_err(),
            "{label} unknown field was accepted"
        );
    }
}

#[test]
fn config_schema_rejects_unsupported_versions_at_every_level() {
    for value in [
        json!({"version": 2}),
        json!({"repository": {"version": 2}}),
        json!({"selection": {"version": 2}}),
        json!({"privacy": {"version": 2}}),
        json!({"default_validation_commands": [{"version": 2, "command": "true"}]}),
    ] {
        let config: InboxConfig = serde_json::from_value(value).expect("parse version fixture");
        assert!(validate_config(config).is_err());
    }

    for value in [
        json!({"version": 2, "repositories": [{"id": "repo", "path": "."}]}),
        json!({"repositories": [{"version": 2, "id": "repo", "path": "."}]}),
        json!({"repositories": [{"id": "repo", "path": "."}], "safety": {"version": 2}}),
    ] {
        let config: InboxWorkspaceConfig =
            serde_json::from_value(value).expect("parse workspace version fixture");
        assert!(validate_workspace_config(config).is_err());
    }
}

#[test]
fn repository_config_and_cli_overrides_enforce_bounded_canonical_values() {
    let oversized_commands = (0..MAX_VALIDATION_COMMANDS)
        .map(|_| json!({"command": "x".repeat(MAX_VALIDATION_COMMAND_BYTES)}))
        .collect::<Vec<_>>();
    for (label, value) in [
        (
            "owner without name",
            json!({"repository": {"owner": "acme"}}),
        ),
        (
            "invalid owner",
            json!({"repository": {"owner": "-acme", "name": "repo"}}),
        ),
        (
            "invalid branch",
            json!({"repository": {"default_branch": "refs/../main"}}),
        ),
        (
            "selection count",
            json!({"selection": {"max_items": MAX_SELECTION_ITEMS + 1}}),
        ),
        (
            "selection disabled",
            json!({"selection": {"issues": false, "pull_requests": false}}),
        ),
        (
            "action permission conflict",
            json!({"action_policy": "github", "permission_mode": "fake"}),
        ),
        (
            "label control",
            json!({"selection": {"labels": ["bad\nlabel"]}}),
        ),
        (
            "repair attempts",
            json!({"max_repair_attempts": MAX_REPAIR_ATTEMPTS + 1}),
        ),
        (
            "validation count",
            json!({"default_validation_commands": vec!["true"; MAX_VALIDATION_COMMANDS + 1]}),
        ),
        (
            "validation timeout",
            json!({"default_validation_commands": [{"command": "true", "timeout_seconds": MAX_TIMEOUT_SECONDS + 1}]}),
        ),
        (
            "assigned path count",
            json!({"default_assigned_paths": vec!["README.md"; MAX_ASSIGNED_PATHS + 1]}),
        ),
        (
            "absolute assigned path",
            json!({"default_assigned_paths": ["/tmp/outside"]}),
        ),
        (
            "privacy term count",
            json!({"privacy": {"blocked_terms": vec!["term"; MAX_PRIVACY_TERMS + 1]}}),
        ),
        (
            "privacy body limit",
            json!({"privacy": {"max_body_chars": MAX_BODY_LIMIT + 1}}),
        ),
        (
            "codex path",
            json!({"codex_bin": "x".repeat(MAX_CODEX_PATH_BYTES + 1)}),
        ),
        (
            "serialized total",
            json!({"default_validation_commands": oversized_commands}),
        ),
    ] {
        let config: InboxConfig = serde_json::from_value(value).expect("parse bound fixture");
        assert!(validate_config(config).is_err(), "{label} was accepted");
    }

    assert!(validate_cli_source_options(false, None, Some(MAX_SELECTION_ITEMS + 1), None).is_err());
    assert!(
        validate_cli_source_options(true, Some(InboxPermissionMode::Fake), None, None).is_err()
    );
    assert!(validate_cli_source_options(
        false,
        None,
        None,
        Some(Path::new(&"x".repeat(MAX_CODEX_PATH_BYTES + 1)))
    )
    .is_err());
}

#[test]
fn workspace_config_enforces_counts_ids_paths_labels_and_strict_safety() {
    for (label, value) in [
        ("empty repositories", json!({"repositories": []})),
        (
            "repository count",
            json!({"repositories": (0..=MAX_WORKSPACE_REPOSITORIES).map(|index| json!({"id": format!("repo-{index}"), "path": format!("repo-{index}")})).collect::<Vec<_>>() }),
        ),
        (
            "invalid id",
            json!({"repositories": [{"id": "../repo", "path": "."}]}),
        ),
        (
            "case-folded duplicate id",
            json!({"repositories": [{"id": "Repo", "path": "one"}, {"id": "repo", "path": "two"}]}),
        ),
        (
            "disabled selectors",
            json!({"repositories": [{"id": "repo", "path": ".", "include_issues": false, "include_pull_requests": false}]}),
        ),
        (
            "max items",
            json!({"default_max_items_per_repo": MAX_SELECTION_ITEMS + 1, "repositories": [{"id": "repo", "path": "."}]}),
        ),
        (
            "label count",
            json!({"repositories": [{"id": "repo", "path": ".", "labels": vec!["bug"; MAX_LABELS + 1]}]}),
        ),
        (
            "auto approval",
            json!({"repositories": [{"id": "repo", "path": "."}], "safety": {"allow_auto_approval": true}}),
        ),
        (
            "unclean primary",
            json!({"repositories": [{"id": "repo", "path": "."}], "safety": {"require_clean_primary": false}}),
        ),
    ] {
        let config: InboxWorkspaceConfig =
            serde_json::from_value(value).expect("parse workspace bound fixture");
        assert!(
            validate_workspace_config(config).is_err(),
            "{label} was accepted"
        );
    }

    let temp = TempDir::new().expect("tempdir");
    let config = validate_workspace_config(
        serde_json::from_value(json!({
            "repositories": [
                {"id": "first", "path": "."},
                {"id": "second", "path": "."}
            ]
        }))
        .expect("parse collision fixture"),
    )
    .expect("validate collision fixture shape");
    let loaded = LoadedWorkspaceConfig {
        config,
        config_dir: temp.path().to_path_buf(),
        public_config_path: PathBuf::from("workspace.json"),
    };
    assert!(workspace_repo_specs(&loaded).is_err());
}

#[cfg(unix)]
#[test]
fn repository_and_workspace_configs_reject_links_special_files_oversize_and_non_utf8() {
    let (temp, repo) = temp_repo();
    let config = repo.join(CONFIG_FILE);
    let external = temp.path().join("external-config.json");
    fs::write(&external, b"{}\n").expect("external config");
    symlink(&external, &config).expect("config symlink");
    assert!(load_config(&repo).is_err());
    fs::remove_file(&config).expect("remove symlink");

    let fifo = CString::new(config.as_os_str().as_bytes()).expect("FIFO path");
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(load_config(&repo).is_err());
    fs::remove_file(&config).expect("remove FIFO");

    fs::create_dir(&config).expect("config directory");
    assert!(load_config(&repo).is_err());
    fs::remove_dir(&config).expect("remove config directory");

    fs::write(&config, vec![b'x'; MAX_CONFIG_BYTES as usize + 1]).expect("oversized config");
    assert!(load_config(&repo).is_err());
    fs::write(&config, [0xff, 0xfe]).expect("non-UTF8 config");
    assert!(load_config(&repo).is_err());

    let workspace = temp.path().join("workspace.json");
    fs::remove_file(&config).expect("remove repo config");
    symlink(&external, &workspace).expect("workspace symlink");
    assert!(load_workspace_config(&workspace).is_err());
    fs::remove_file(&workspace).expect("remove workspace symlink");
    let fifo = CString::new(workspace.as_os_str().as_bytes()).expect("workspace FIFO path");
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    assert!(load_workspace_config(&workspace).is_err());
    fs::remove_file(&workspace).expect("remove workspace FIFO");
    fs::create_dir(&workspace).expect("workspace directory");
    assert!(load_workspace_config(&workspace).is_err());
    fs::remove_dir(&workspace).expect("remove workspace directory");
    fs::write(&workspace, vec![b'x'; MAX_CONFIG_BYTES as usize + 1])
        .expect("oversized workspace config");
    assert!(load_workspace_config(&workspace).is_err());
    fs::write(&workspace, [0xff, 0xfe]).expect("non-UTF8 workspace config");
    assert!(load_workspace_config(&workspace).is_err());
}

#[cfg(unix)]
#[test]
fn workspace_config_binds_the_canonical_parent_before_resolving_repo_paths() {
    let temp = TempDir::new().expect("tempdir");
    let real = temp.path().join("real");
    fs::create_dir(&real).expect("real config directory");
    let alias = temp.path().join("alias");
    symlink(&real, &alias).expect("parent alias");
    let config = real.join("workspace.json");
    fs::write(
        &config,
        serde_json::to_vec(&json!({
            "repositories": [{"id": "repo", "path": "missing-repo"}]
        }))
        .expect("workspace JSON"),
    )
    .expect("workspace config");

    let loaded = load_workspace_config(&alias.join("workspace.json")).expect("load config");
    assert_eq!(
        loaded.config_dir,
        fs::canonicalize(&real).expect("canonical real")
    );
}

#[test]
fn workspace_repository_projection_uses_config_relative_paths_and_enabled_flags() {
    let temp = TempDir::new().expect("tempdir");
    let config_dir = temp.path().join("config");
    let first = config_dir.join("first");
    let second = config_dir.join("second");
    fs::create_dir_all(&first).expect("first repository");
    fs::create_dir(&second).expect("second repository");
    let config = config_dir.join("workspace.json");
    fs::write(
        &config,
        serde_json::to_vec(&json!({
            "repositories": [
                {"id": "first", "path": "first"},
                {"id": "second", "path": "second", "enabled": false}
            ]
        }))
        .expect("workspace JSON"),
    )
    .expect("workspace config");

    let repositories =
        load_workspace_repositories(&config).expect("project workspace repositories");

    assert_eq!(
        repositories,
        vec![
            WorkspaceRepository {
                id: "first".to_string(),
                path: fs::canonicalize(first).expect("canonical first repository"),
                enabled: true,
            },
            WorkspaceRepository {
                id: "second".to_string(),
                path: fs::canonicalize(second).expect("canonical second repository"),
                enabled: false,
            },
        ]
    );
}

#[cfg(unix)]
#[test]
fn workspace_repository_projection_preserves_strict_no_follow_loading() {
    let temp = TempDir::new().expect("tempdir");
    let external = temp.path().join("external.json");
    fs::write(
        &external,
        br#"{"repositories":[{"id":"repo","path":".","unknown":true}]}"#,
    )
    .expect("strict schema fixture");
    assert!(load_workspace_repositories(&external).is_err());

    let linked = temp.path().join("workspace.json");
    symlink(&external, &linked).expect("workspace symlink");
    assert!(load_workspace_repositories(&linked).is_err());
}

#[test]
fn source_snapshot_binding_is_deterministic_validated_and_identity_stable() {
    let identity = publication::stable_external_digest(b"repository-identity");
    let first = InboxSourceSnapshotBinding::for_pull_request(
        InboxSourceProvider::Github,
        "github.example",
        "github.example/acme/repo",
        identity.clone(),
        42,
        "2026-07-08T00:00:00Z",
        "OPEN",
        "1".repeat(40),
        "2".repeat(40),
        "3".repeat(64),
        "4".repeat(64),
    )
    .expect("first binding");
    let second = InboxSourceSnapshotBinding::for_pull_request(
        InboxSourceProvider::Github,
        "github.example",
        "github.example/acme/repo",
        identity,
        42,
        "2026-07-08T00:00:00Z",
        "OPEN",
        "1".repeat(40),
        "2".repeat(40),
        "3".repeat(64),
        "4".repeat(64),
    )
    .expect("second binding");
    assert_eq!(first, second);
    assert_eq!(first.source_key(), "github_pr:42");
    assert_eq!(first.digest(), first.deterministic_digest().unwrap());

    let encoded = serde_json::to_value(&first).expect("serialize binding");
    let decoded: InboxSourceSnapshotBinding =
        serde_json::from_value(encoded.clone()).expect("deserialize binding");
    assert_eq!(decoded, first);
    let mut tampered_identity = encoded.clone();
    tampered_identity["repository_identity"] = json!("f".repeat(64));
    assert!(serde_json::from_value::<InboxSourceSnapshotBinding>(tampered_identity).is_err());
    let mut tampered = encoded;
    tampered["updated_at"] = json!("not-a-timestamp");
    assert!(serde_json::from_value::<InboxSourceSnapshotBinding>(tampered).is_err());

    assert!(InboxSourceSnapshotBinding::for_pull_request(
        InboxSourceProvider::Github,
        "github.example",
        "github.example/acme/repo",
        publication::stable_external_digest(b"repository-identity"),
        42,
        "2026-07-08T00:00:00Z",
        "OPEN",
        "not-an-oid".to_string(),
        "2".repeat(40),
        "3".repeat(64),
        "4".repeat(64),
    )
    .is_err());
    assert!(InboxSourceSnapshotBinding::for_pull_request(
        InboxSourceProvider::Github,
        "other.example",
        "github.example/acme/repo",
        publication::stable_external_digest(b"repository-identity"),
        42,
        "2026-07-08T00:00:00Z",
        "OPEN",
        "1".repeat(40),
        "2".repeat(40),
        "3".repeat(64),
        "4".repeat(64),
    )
    .is_err());

    let config = InboxConfig::default();
    let context = SourceRepositoryBindingContext {
        host: "fake".to_string(),
        selector: ".".to_string(),
        identity: publication::stable_external_digest(b"fake-repository"),
    };
    let mut candidates = fake_issue_candidates(&config).into_iter();
    let first_item = issue_item(
        candidates.next().expect("first fake issue"),
        &config,
        &context,
        &BTreeMap::new(),
    )
    .expect("first fake item");
    let duplicate_item = issue_item(
        candidates.next().expect("duplicate fake issue"),
        &config,
        &context,
        &BTreeMap::new(),
    )
    .expect("duplicate fake item");
    assert_eq!(first_item.source_key, duplicate_item.source_key);
    assert_eq!(first_item.source_snapshot, duplicate_item.source_snapshot);
}

#[test]
fn source_repository_binding_matches_configured_owner_name_and_is_locally_durable() {
    let (temp, repo_path) = temp_repo();
    let repo = crate::git_repository::open(&repo_path).expect("open repository");
    repo.remote("origin", "https://github.com/acme/inbox.git")
        .expect("create origin");
    let mut config = InboxConfig::default();
    config.repository.owner = Some("acme".to_string());
    config.repository.name = Some("inbox".to_string());
    let config = validate_config(config).expect("validate repository config");

    let first = source_repository_binding_context(&repo_path, &config, true)
        .expect("first repository binding");
    let second = source_repository_binding_context(&repo_path, &config, true)
        .expect("second repository binding");
    assert_eq!(first.host, "github.com");
    assert_eq!(first.selector, "github.com/acme/inbox");
    assert_eq!(first.identity, second.identity);
    assert_eq!(first.identity.len(), 64);
    assert!(first
        .identity
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));

    drop(repo);
    let moved_repo = temp.path().join("moved-repo");
    fs::rename(&repo_path, &moved_repo).expect("move repository");
    let moved = source_repository_binding_context(&moved_repo, &config, true)
        .expect("moved repository binding");
    assert_eq!(first.identity, moved.identity);
    InboxSourceSnapshotBinding::for_issue(
        InboxSourceProvider::Fake,
        moved.host.clone(),
        moved.selector.clone(),
        moved.identity.clone(),
        7,
        "2026-07-08T00:00:00Z",
        "OPEN",
        "3".repeat(64),
        "4".repeat(64),
    )
    .expect("fake intake snapshot bound to canonical local origin");

    let wrong_url = json!({
        "number": 7,
        "title": "wrong repository",
        "body": "body",
        "url": "https://github.com/acme/different/issues/7",
        "author": null,
        "updatedAt": "2026-07-08T00:00:00Z",
        "state": "OPEN",
        "labels": []
    });
    let raw = raw_issue_from_value(&moved_repo, &wrong_url, &config, &moved).expect("raw issue");
    assert!(issue_item(raw, &config, &moved, &BTreeMap::new()).is_err());

    let mut exact_url = wrong_url;
    exact_url["title"] = json!("exact repository");
    exact_url["url"] = json!("https://github.com/acme/inbox/issues/7");
    let raw = raw_issue_from_value(&moved_repo, &exact_url, &config, &moved).expect("raw issue");
    let exact_item =
        issue_item(raw, &config, &moved, &BTreeMap::new()).expect("exact bound issue item");
    let guard = exact_item
        .source_snapshot
        .external_source_guard()
        .expect("source guard conversion")
        .expect("GitHub source guard");
    let moved_repository = crate::git_repository::open(&moved_repo).expect("open moved repository");
    moved_repository
        .remote_set_url("origin", "https://other.example/acme/inbox.git")
        .expect("swap origin host");
    assert!(publication::revalidate_external_source(&moved_repo, &guard).is_err());

    let mut mismatch = config;
    mismatch.repository.name = Some("different".to_string());
    assert!(source_repository_binding_context(&moved_repo, &mismatch, true).is_err());
}

#[test]
fn raw_github_candidates_fail_closed_on_malformed_identity_and_nested_values() {
    let source = test_source_repository_binding();
    let mut pr = valid_raw_pr_value();
    pr.as_object_mut().unwrap().remove("headRefOid");
    assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

    let mut pr = valid_raw_pr_value();
    pr["updatedAt"] = json!("invalid");
    assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

    let mut pr = valid_raw_pr_value();
    pr["files"] = json!([{"path": "/tmp/outside"}]);
    assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

    let mut pr = valid_raw_pr_value();
    pr["labels"] = json!((0..=MAX_LABELS)
        .map(|index| json!({"name": format!("label-{index}")}))
        .collect::<Vec<_>>());
    assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

    let mut pr = valid_raw_pr_value();
    pr["title"] = json!("x".repeat(MAX_GITHUB_TITLE_BYTES + 1));
    assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

    let mut pr = valid_raw_pr_value();
    pr["author"] = json!({"login": "bad\nlogin"});
    assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

    let mut pr = valid_raw_pr_value();
    pr["statusCheckRollup"] = json!(vec![json!({"name": "ci"}); MAX_GITHUB_CHECKS + 1]);
    assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

    let mut pr = valid_raw_pr_value();
    pr["latestReviews"] = json!(vec![json!({"state": "APPROVED"}); MAX_GITHUB_REVIEWS + 1]);
    assert!(raw_pr_from_value(&pr, &InboxConfig::default(), &source).is_err());

    assert!(validate_count(
        MAX_GITHUB_ITEMS + 1,
        "gh issue list items",
        MAX_GITHUB_ITEMS
    )
    .is_err());

    let (_temp, repo) = temp_repo();
    let issue = json!({
        "number": 0,
        "title": "issue",
        "body": "body",
        "updatedAt": "2026-07-08T00:00:00Z",
        "state": "OPEN"
    });
    assert!(raw_issue_from_value(&repo, &issue, &InboxConfig::default(), &source).is_err());
}

#[test]
fn real_publication_mode_fails_closed_before_intake_or_artifacts() {
    let (_temp, repo) = temp_repo();
    let error = run_inbox(InboxRunOptions {
        repo: repo.clone(),
        run_id: RunId::new("reviewer-refusal").expect("run id"),
        github: false,
        permission_mode: Some(InboxPermissionMode::GithubGit),
        dry_run: false,
        max_items: Some(1),
        codex_bin: None,
        machine_global: None,
    })
    .expect_err("real publication must fail closed before effectful intake");
    let error = format!("{error:#}");
    assert!(
        error.contains("explicitly bound external reviewer"),
        "expected external-reviewer refusal: {error}"
    );
    assert!(!repo.join(".maco/inbox/runs/reviewer-refusal").exists());
}

#[test]
fn assigned_paths_for_issue_falls_back_to_config_default() {
    let config = InboxConfig::default();
    let item = make_issue_item(1, "No candidate paths", Vec::new());

    let paths = assigned_paths_for_item(&item, &config).expect("assigned paths");

    assert_eq!(paths, vec![PathBuf::from("README.md")]);
}

#[test]
fn summarize_text_bounds_body_summary_by_chars() {
    let bounded = summarize_text("abcdef", 3);

    assert_eq!(bounded.text, "abc");
    assert!(bounded.truncated);

    let exact = summarize_text("abc", 3);

    assert_eq!(exact.text, "abc");
    assert!(!exact.truncated);
}

#[test]
fn github_json_parser_rejects_oversized_truncated_and_non_utf8_source() {
    assert!(parse_gh_json_bytes(vec![b' '; GH_OUTPUT_LIMIT + 1], "gh test").is_err());
    assert!(parse_gh_json_bytes(vec![0xff, 0xfe], "gh test").is_err());
    assert_eq!(
        parse_gh_json_bytes(b"[]".to_vec(), "gh test").expect("bounded JSON"),
        json!([])
    );
}

#[test]
fn privacy_scan_redacts_token_like_values_and_refuses_body() {
    let token = "abc123456789012345678901234567890xyz";
    let policy = InboxPrivacyPolicy {
        max_body_chars: 512,
        ..InboxPrivacyPolicy::default()
    };

    let scan = privacy_scan(&format!("observed value {token}"), &policy);

    assert!(!scan.safe);
    assert!(scan
        .reasons
        .contains(&"secret_like_content_redacted".to_string()));
    assert!(scan.body_summary.contains("<redacted:token>"));
    assert!(!scan.body_summary.contains(token));
}

#[test]
fn private_key_material_is_replaced_with_refusal_marker() {
    let body = "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----";

    let scan = privacy_scan(body, &InboxPrivacyPolicy::default());

    assert!(!scan.safe);
    assert!(scan.reasons.contains(&"private_key_material".to_string()));
    assert_eq!(scan.body_summary, "<redacted:private-key-material>");
}

#[test]
fn local_absolute_paths_are_detected_and_redacted() {
    let body = r"Paths: /mnt/d/home/project, /home/example/repo, C:\Users\Example\secret.txt";

    let scan = privacy_scan(body, &InboxPrivacyPolicy::default());

    assert!(!scan.safe);
    assert!(scan.reasons.contains(&"local_absolute_path".to_string()));
    assert_eq!(
        scan.body_summary.matches("<redacted:local-path>").count(),
        3
    );
    assert!(!scan.body_summary.contains("/mnt/d/home"));
    assert!(!scan.body_summary.contains("/home/example"));
    assert!(!scan.body_summary.contains(r"C:\Users"));
}

#[test]
fn blocked_terms_in_titles_extend_privacy_reasons() {
    let mut privacy = privacy_scan("safe body", &InboxPrivacyPolicy::default());

    extend_privacy_reasons(
        &mut privacy,
        "title",
        "Regression exposes api key handling",
        &InboxPrivacyPolicy::default(),
    );

    assert!(!privacy.safe);
    assert!(privacy
        .reasons
        .contains(&"title_blocked_term:api key".to_string()));
}

#[test]
fn sanitize_public_text_rewrites_repo_paths_without_leaking_absolutes() {
    let repo = Path::new("/mnt/d/home/project/repo");

    let sanitized = sanitize_public_text(
        repo,
        "repo path /mnt/d/home/project/repo/src/inbox.rs parent /mnt/d/home/project",
        512,
    );

    assert_eq!(
        sanitized.text,
        "repo path ./src/inbox.rs parent <repo-parent>"
    );
    assert!(!sanitized.text.contains("/mnt/d/home/project"));
}

#[test]
fn permission_mode_parse_normalizes_hyphen_aliases() {
    assert_eq!(
        InboxPermissionMode::parse("github-read").expect("github-read"),
        InboxPermissionMode::GithubRead
    );
    assert_eq!(
        InboxPermissionMode::parse("github_read").expect("github_read"),
        InboxPermissionMode::GithubRead
    );
    assert_eq!(
        InboxPermissionMode::parse("github-full").expect("github-full"),
        InboxPermissionMode::GithubFull
    );
}

#[test]
fn permission_mode_parse_accepts_legacy_github_alias_and_rejects_unknown() {
    assert_eq!(
        InboxPermissionMode::parse("github").expect("github alias"),
        InboxPermissionMode::GithubFull
    );

    let error = InboxPermissionMode::parse("github-write").expect_err("unknown mode");

    assert!(error.contains("expected one of"));
}

#[test]
fn permission_mode_deserializes_hyphen_aliases() {
    let mode: InboxPermissionMode =
        serde_json::from_str(r#""github-local""#).expect("deserialize alias");

    assert_eq!(mode, InboxPermissionMode::GithubLocal);
}

#[test]
fn legacy_github_flag_and_action_policy_promote_to_full_permission() {
    let config = InboxConfig::default();

    assert_eq!(
        effective_permission_mode(&config, true, None),
        InboxPermissionMode::GithubFull
    );

    let config = InboxConfig {
        action_policy: InboxActionPolicy::Github,
        ..InboxConfig::default()
    };

    assert_eq!(
        effective_permission_mode(&config, false, None),
        InboxPermissionMode::GithubFull
    );
}

#[test]
fn effective_action_policy_preserves_dry_run_and_maps_github_intake() {
    assert_eq!(
        effective_action_policy(InboxActionPolicy::DryRun, InboxPermissionMode::GithubFull),
        InboxActionPolicy::DryRun
    );
    assert_eq!(
        effective_action_policy(InboxActionPolicy::Fake, InboxPermissionMode::GithubRead),
        InboxActionPolicy::Github
    );
    assert_eq!(
        effective_action_policy(InboxActionPolicy::Github, InboxPermissionMode::Fake),
        InboxActionPolicy::Fake
    );
}

#[test]
fn apply_scan_decisions_enforces_max_items() {
    let mut items = vec![
        make_issue_item(1, "first", vec![PathBuf::from("README.md")]),
        make_issue_item(2, "second", vec![PathBuf::from("src/lib.rs")]),
        make_issue_item(3, "third", vec![PathBuf::from("docs/guide.md")]),
    ];

    apply_scan_decisions(&mut items, 2);

    assert!(items[0].selected);
    assert!(items[1].selected);
    assert!(!items[2].selected);
    assert_eq!(items[2].skip_reason.as_deref(), Some("selection_limit"));
}

#[test]
fn apply_scan_decisions_marks_duplicates_within_current_scan() {
    let mut duplicate = make_issue_item(1, "duplicate", vec![PathBuf::from("README.md")]);
    duplicate.item_id = "issue-1-copy".to_string();
    let mut items = vec![
        make_issue_item(1, "first", vec![PathBuf::from("README.md")]),
        duplicate,
    ];

    apply_scan_decisions(&mut items, 4);

    assert!(items[0].selected);
    assert!(!items[1].selected);
    assert!(items[1].duplicate.duplicate);
    assert_eq!(items[1].skip_reason.as_deref(), Some("duplicate"));
    assert_eq!(
        items[1].duplicate.reason.as_deref(),
        Some("duplicate inbox candidate in current scan")
    );
}

#[test]
fn label_overrides_are_trimmed_sorted_and_used_by_fake_candidates() {
    let (temp, repo) = temp_repo();
    let loaded = load_config_with_config_overrides(
        &repo,
        InboxConfigOverrides {
            labels: Some(vec![
                "needs-work".to_string(),
                " bug ".to_string(),
                "needs-work".to_string(),
            ]),
            ..InboxConfigOverrides::default()
        },
    )
    .expect("load config");

    assert_eq!(
        loaded.config.selection.labels,
        vec!["bug".to_string(), "needs-work".to_string()]
    );
    assert_eq!(
        fake_issue_candidates(&loaded.config)[0].labels,
        loaded.config.selection.labels
    );
    drop(temp);
}

#[test]
fn selected_target_paths_include_only_selected_items() {
    let config = InboxConfig::default();
    let mut skipped = make_issue_item(2, "skipped", vec![PathBuf::from("src/lib.rs")]);
    skipped.selected = false;
    let items = vec![
        make_issue_item(1, "selected", vec![PathBuf::from("README.md")]),
        skipped,
    ];

    let paths = selected_target_paths(&items, &config).expect("target paths");

    assert_eq!(paths, vec![PathBuf::from("README.md")]);
}

#[test]
fn preflight_ignores_dirty_runtime_artifacts() {
    let (_temp, repo) = temp_repo();
    fs::create_dir_all(repo.join(".maco/inbox/runs/run-1")).expect("create .maco");
    fs::write(
        repo.join(".maco/inbox/runs/run-1/final-report.json"),
        "{}\n",
    )
    .expect("write .maco artifact");
    fs::create_dir_all(repo.join(".maco-cache")).expect("create cache");
    fs::write(repo.join(".maco-cache/state.json"), "{}\n").expect("write cache artifact");

    let refusals = preflight_refusals(&repo, &[PathBuf::from("src/inbox.rs")]).expect("preflight");

    assert!(refusals.is_empty());
}

#[test]
fn preflight_refuses_only_overlapping_sync_claims() {
    let (_temp, repo) = temp_repo();
    SyncStore::open(&repo)
        .expect("open store")
        .claim_paths("agent-a", ["docs"])
        .expect("claim docs");

    let unrelated = preflight_refusals(&repo, &[PathBuf::from("src/inbox.rs")]).expect("preflight");

    assert!(unrelated.is_empty());

    let overlapping =
        preflight_refusals(&repo, &[PathBuf::from("docs/guide.md")]).expect("preflight");

    assert_eq!(overlapping.len(), 1);
    assert_eq!(overlapping[0].kind, "active_sync_claims");
    assert_eq!(overlapping[0].paths, vec![PathBuf::from("docs")]);
}

#[test]
fn preflight_ignores_runtime_artifact_sync_claims() {
    let (_temp, repo) = temp_repo();
    SyncStore::open(&repo)
        .expect("open store")
        .claim_paths("agent-a", [".maco/inbox/runs/run-1"])
        .expect("claim runtime path");

    let refusals = preflight_refusals(
        &repo,
        &[PathBuf::from(".maco/inbox/runs/run-1/final-report.json")],
    )
    .expect("preflight");

    assert!(refusals.is_empty());
}

#[test]
fn scan_report_public_json_uses_placeholder_repo_and_omits_absolute_paths() {
    let (temp, repo) = temp_repo();

    let report = scan_inbox(InboxScanOptions {
        repo: repo.clone(),
        github: false,
        permission_mode: None,
        max_items: Some(1),
        action_policy_override: None,
    })
    .expect("scan inbox");
    let public_json = serde_json::to_string(&report).expect("serialize report");

    assert_eq!(report.repo, PathBuf::from("."));
    let snapshot = &report.items[0].source_snapshot;
    snapshot.validate().expect("public snapshot binding");
    assert_eq!(snapshot.repository_selector(), ".");
    assert_eq!(snapshot.repository_identity().len(), 64);
    assert!(!public_json.contains(repo.to_str().expect("utf8 repo path")));
    assert!(!public_json.contains(temp.path().to_str().expect("utf8 temp path")));
}

#[test]
fn issue_task_body_and_title_include_public_issue_context() {
    let config = InboxConfig::default();
    let mut item = make_issue_item(7, "Repair inbox summaries", vec![PathBuf::from("src")]);
    let issue = item.issue.as_mut().expect("issue");
    issue.url = Some("https://github.example/repo/issues/7".to_string());
    issue.body_summary = "Summary with <redacted:token>".to_string();

    let plan =
        autopilot_plan_for_item(&item, &config, InboxPermissionMode::GithubPr).expect("plan");

    assert_eq!(plan.task.title, "Inbox issue: Repair inbox summaries");
    assert!(plan
        .task
        .body
        .contains("React to GitHub issue #7.\nURL: https://github.example/repo/issues/7"));
    assert!(plan.task.body.contains("Summary with <redacted:token>"));
    assert_eq!(plan.assigned_paths, vec![PathBuf::from("src")]);
    assert_eq!(plan.forge_mode, AutopilotForgeMode::Github);
}

#[test]
fn pr_task_body_includes_paths_checks_reviews_and_validation_expectation() {
    let item = make_pr_item(
        42,
        "Fix failing inbox CI",
        vec![PathBuf::from("src/inbox.rs")],
    );

    let body = task_body_for_item(&item);

    assert!(body.contains("React to GitHub PR #42."));
    assert!(body.contains("Changed files:\n- src/inbox.rs"));
    assert!(body.contains("- ci status=completed conclusion=failure summary=ci failed"));
    assert!(body.contains("requested change summary"));
    assert!(body.contains("address failing check context: ci"));
}

#[test]
fn raw_pr_candidate_parsing_deduplicates_labels_files_and_failed_checks() {
    let value = json!({
        "number": 9,
        "title": "PR title",
        "body": "body",
        "url": "https://github.example/acme/repo/pull/9",
        "updatedAt": "2026-07-08T00:00:00Z",
        "state": "OPEN",
        "author": {"login": "author"},
        "headRefName": "feature",
        "baseRefName": "main",
        "headRefOid": "1111111111111111111111111111111111111111",
        "baseRefOid": "2222222222222222222222222222222222222222",
        "isDraft": false,
        "isCrossRepository": false,
        "labels": [{"name": "z"}, {"name": "a"}, {"name": "a"}],
        "files": [{"path": "src/../src/inbox.rs"}, {"path": "src/inbox.rs"}],
        "statusCheckRollup": [
            {"name": "ci", "status": "completed", "conclusion": "failure", "detailsUrl": "fake://ci"}
        ],
        "reviewDecision": "CHANGES_REQUESTED",
        "latestReviews": [
            {"state": "CHANGES_REQUESTED", "author": {"login": "reviewer"}, "body": "please adjust"}
        ]
    });

    let raw = raw_pr_from_value(
        &value,
        &InboxConfig::default(),
        &test_source_repository_binding(),
    )
    .expect("raw pr");

    assert_eq!(raw.labels, vec!["a".to_string(), "z".to_string()]);
    assert_eq!(raw.changed_files, vec![PathBuf::from("src/inbox.rs")]);
    assert!(raw.review_feedback.requested_changes);
    assert!(check_failed(
        raw.checks[0].conclusion.as_deref(),
        raw.checks[0].status.as_deref()
    ));
}

fn temp_repo() -> (TempDir, PathBuf) {
    let temp = TempDir::new().expect("tempdir");
    let repo = temp.path().join("repo");
    WorktreeManager::init_repository(&repo, "main").expect("init repo");
    (temp, repo)
}

fn test_source_repository_binding() -> SourceRepositoryBindingContext {
    SourceRepositoryBindingContext {
        host: "github.example".to_string(),
        selector: "github.example/acme/repo".to_string(),
        identity: publication::stable_external_digest(b"inbox-test-source-repository"),
    }
}

fn make_issue_item(number: u64, title: &str, assigned_paths: Vec<PathBuf>) -> InboxItem {
    let source_key = format!("github_issue:{number}");
    InboxItem {
        item_id: format!("issue-{number}"),
        source_key: source_key.clone(),
        source_snapshot: test_source_snapshot(InboxItemKind::Issue, number),
        kind: InboxItemKind::Issue,
        title: title.to_string(),
        url: None,
        issue: Some(GithubIssueCandidate {
            number,
            title: title.to_string(),
            url: None,
            author: None,
            labels: Vec::new(),
            updated_at: Some("1970-01-01T00:00:00Z".to_string()),
            body_summary: String::new(),
            body_truncated: false,
            assigned_paths,
            path_proposal: planning::TaskPathProposalDiagnostics::default(),
        }),
        pull_request: None,
        privacy: safe_privacy(),
        duplicate: duplicate_result(&source_key, &BTreeMap::new()),
        selected: true,
        skip_reason: None,
    }
}

fn make_pr_item(number: u64, title: &str, changed_files: Vec<PathBuf>) -> InboxItem {
    let source_key = format!("github_pr:{number}");
    InboxItem {
        item_id: format!("pr-{number}"),
        source_key: source_key.clone(),
        source_snapshot: test_source_snapshot(InboxItemKind::PullRequest, number),
        kind: InboxItemKind::PullRequest,
        title: title.to_string(),
        url: Some(format!("https://github.example/repo/pull/{number}")),
        issue: None,
        pull_request: Some(GithubPrCandidate {
            number,
            title: title.to_string(),
            url: Some(format!("https://github.example/repo/pull/{number}")),
            author: Some("author".to_string()),
            labels: vec!["needs-work".to_string()],
            updated_at: Some("2026-07-08T00:00:00Z".to_string()),
            head_ref: Some("feature/inbox".to_string()),
            base_ref: Some("main".to_string()),
            is_draft: false,
            source_trust: GithubPrSourceTrust::TrustedTargetRepository,
            head_repository: Some("acme/repo".to_string()),
            changed_files,
            checks: vec![GithubCheckSummary {
                name: "ci".to_string(),
                status: Some("completed".to_string()),
                conclusion: Some("failure".to_string()),
                details_url: None,
                summary: "ci failed".to_string(),
            }],
            review_feedback: GithubReviewFeedbackSummary {
                review_decision: Some("CHANGES_REQUESTED".to_string()),
                requested_changes: true,
                unresolved_thread_count: Some(1),
                reviewer_logins: vec!["reviewer".to_string()],
                summaries: vec!["requested change summary".to_string()],
            },
            body_summary: "PR body summary".to_string(),
            body_truncated: false,
        }),
        privacy: safe_privacy(),
        duplicate: duplicate_result(&source_key, &BTreeMap::new()),
        selected: true,
        skip_reason: None,
    }
}

fn test_source_snapshot(kind: InboxItemKind, number: u64) -> InboxSourceSnapshotBinding {
    match kind {
        InboxItemKind::Issue => InboxSourceSnapshotBinding::for_issue(
            InboxSourceProvider::Fake,
            "fake",
            ".",
            publication::stable_external_digest(b"inbox-test-repository"),
            number,
            "1970-01-01T00:00:00Z",
            "OPEN",
            "3".repeat(64),
            "4".repeat(64),
        ),
        InboxItemKind::PullRequest => InboxSourceSnapshotBinding::for_pull_request(
            InboxSourceProvider::Fake,
            "fake",
            ".",
            publication::stable_external_digest(b"inbox-test-repository"),
            number,
            "1970-01-01T00:00:00Z",
            "OPEN",
            "1111111111111111111111111111111111111111".to_string(),
            "2222222222222222222222222222222222222222".to_string(),
            "3".repeat(64),
            "4".repeat(64),
        ),
    }
    .expect("test source snapshot")
}

fn valid_raw_pr_value() -> Value {
    json!({
        "number": 42,
        "title": "Bounded PR",
        "body": "Please repair the failing check.",
        "url": "https://github.example/acme/repo/pull/42",
        "author": {"login": "reviewer"},
        "labels": [{"name": "bug"}],
        "updatedAt": "2026-07-08T00:00:00Z",
        "state": "OPEN",
        "headRefName": "feature/inbox",
        "baseRefName": "main",
        "headRefOid": "1111111111111111111111111111111111111111",
        "baseRefOid": "2222222222222222222222222222222222222222",
        "isDraft": false,
        "files": [{"path": "src/inbox.rs"}],
        "reviewDecision": "CHANGES_REQUESTED",
        "latestReviews": [],
        "statusCheckRollup": [{
            "name": "ci",
            "status": "completed",
            "conclusion": "failure",
            "detailsUrl": "https://github.example/acme/repo/actions/1"
        }]
    })
}

fn safe_privacy() -> PrivacyScanResult {
    PrivacyScanResult {
        safe: true,
        reasons: Vec::new(),
        redactions: RedactionSummary::default(),
        body_summary: String::new(),
        body_truncated: false,
    }
}
