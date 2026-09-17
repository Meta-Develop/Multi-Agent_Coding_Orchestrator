//! M4 quota-honesty contract against hermetic provider homes.

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use coding_agent_manager_lib::error::Error;
use coding_agent_manager_lib::providers::claude_code::ClaudeCodeAdapter;
use coding_agent_manager_lib::providers::codex_cli::CodexCliAdapter;
use coding_agent_manager_lib::providers::cursor::CursorAdapter;
use coding_agent_manager_lib::providers::gemini_cli::GeminiCliAdapter;
use coding_agent_manager_lib::providers::grok_cli::GrokCliAdapter;
use coding_agent_manager_lib::providers::{self, ProviderAdapter};

const PROVIDER_IDS: [&str; 5] = [
    "claude-code",
    "codex-cli",
    "cursor",
    "grok-cli",
    "gemini-cli",
];
const CLAUDE_PLAN_LABEL: &str = "FAKE-CLAUDE-PLAN";
const MALFORMED_MARKER: &str = "FAKE-CLAUDE-MALFORMED";

#[test]
fn every_registered_provider_has_an_honest_read_only_quota_decision() {
    let registered: Vec<_> = providers::registry()
        .iter()
        .map(|adapter| adapter.id())
        .collect();
    assert_eq!(registered, PROVIDER_IDS);

    for id in registered {
        let fixture = StagedFixture::new(id);
        let adapter = adapter_for_fixture(id, fixture.root());
        let before_quota = TreeSnapshot::capture(fixture.root());

        let snapshots = adapter
            .quota()
            .unwrap_or_else(|error| panic!("`{id}` quota collection failed: {error}"));
        assert!(
            snapshots.is_empty(),
            "`{id}` fabricated a numeric quota signal"
        );
        assert!(
            TreeSnapshot::capture(fixture.root()) == before_quota,
            "`{id}` numeric quota collection modified its fixture tree"
        );

        let before_plan = TreeSnapshot::capture(fixture.root());
        let plan_label = adapter
            .plan_label()
            .unwrap_or_else(|error| panic!("`{id}` plan-label collection failed: {error}"));
        let expected_plan = (id == "claude-code").then_some(CLAUDE_PLAN_LABEL.to_string());
        assert_eq!(plan_label, expected_plan, "`{id}` plan-label decision");

        assert!(
            TreeSnapshot::capture(fixture.root()) == before_plan,
            "`{id}` plan-label collection modified its fixture tree"
        );
    }
}

#[test]
fn malformed_claude_plan_state_fails_without_echoing_file_content() {
    let fixture = StagedFixture::new("claude-code-malformed");
    let home = fixture.root().join("home");
    assert!(
        !home.join(".claude/.credentials.json").exists(),
        "the plan-label fixture must not contain a credential document"
    );
    let before = TreeSnapshot::capture(fixture.root());
    let error = ClaudeCodeAdapter::with_home(home)
        .plan_label()
        .expect_err("malformed plan state must fail closed");

    assert!(
        matches!(
            &error,
            Error::ConfigRead { provider, .. } if provider == "claude-code"
        ),
        "malformed plan state must be a provider-scoped read error"
    );
    for rendered in [format!("{error}"), format!("{error:?}")] {
        assert!(!rendered.contains(MALFORMED_MARKER));
        assert!(!rendered.contains("FAKE-"));
    }
    assert!(
        TreeSnapshot::capture(fixture.root()) == before,
        "Claude plan-label failure modified its fixture tree"
    );
}

fn adapter_for_fixture(id: &str, root: &Path) -> Box<dyn ProviderAdapter> {
    let home = root.join("home");
    let data_dir = root.join("data");
    let workspace = root.join("workspace");
    match id {
        "claude-code" => Box::new(ClaudeCodeAdapter::with_home(home)),
        "codex-cli" => Box::new(
            CodexCliAdapter::with_home(home)
                .with_data_dir(data_dir)
                .with_tool_running(false)
                .with_login_runner(forbid_vendor_login),
        ),
        "cursor" => Box::new(CursorAdapter::with_home(home)),
        "grok-cli" => Box::new(
            GrokCliAdapter::with_home(home)
                .with_data_dir(data_dir)
                .with_working_directory(workspace)
                .with_program(root.join("bin/grok"))
                .with_login_runner(forbid_vendor_login),
        ),
        "gemini-cli" => Box::new(GeminiCliAdapter::with_test_context(
            home,
            data_dir,
            workspace,
            root.join("system-settings.json"),
            root.join("system-defaults.json"),
            None,
        )),
        other => {
            panic!("`{other}` is registered but quota_visibility.rs has no hermetic adapter arm")
        }
    }
}

fn forbid_vendor_login(_home: &Path) -> io::Result<i32> {
    panic!("quota collection attempted to start a vendor login")
}

struct StagedFixture {
    temp: tempfile::TempDir,
}

impl StagedFixture {
    fn new(name: &str) -> Self {
        let temp = tempfile::tempdir().expect("quota fixture TempDir");
        copy_tree(&fixture_root().join(name), temp.path());
        fs::create_dir_all(temp.path().join("data")).expect("fixture data directory");
        fs::create_dir_all(temp.path().join("workspace")).expect("fixture workspace directory");
        Self { temp }
    }

    fn root(&self) -> &Path {
        self.temp.path()
    }
}

fn fixture_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/quota")
}

#[derive(PartialEq, Eq)]
struct TreeSnapshot(BTreeMap<PathBuf, TreeNode>);

#[derive(PartialEq, Eq)]
enum TreeNode {
    Directory { mode: u32 },
    File { mode: u32, bytes: Vec<u8> },
}

impl TreeSnapshot {
    fn capture(root: &Path) -> Self {
        let mut nodes = BTreeMap::new();
        collect_tree(root, root, &mut nodes);
        Self(nodes)
    }
}

fn collect_tree(root: &Path, path: &Path, nodes: &mut BTreeMap<PathBuf, TreeNode>) {
    let metadata = fs::symlink_metadata(path)
        .unwrap_or_else(|error| panic!("inspect quota fixture {}: {error}", path.display()));
    if path != root {
        let relative = path.strip_prefix(root).expect("fixture path under root");
        let node = if metadata.is_dir() {
            TreeNode::Directory {
                mode: permission_mode(&metadata),
            }
        } else if metadata.is_file() {
            TreeNode::File {
                mode: permission_mode(&metadata),
                bytes: fs::read(path).unwrap_or_else(|error| panic!("read quota fixture: {error}")),
            }
        } else {
            panic!("quota fixture contains a special file")
        };
        nodes.insert(relative.to_path_buf(), node);
    }

    if metadata.is_dir() {
        for entry in fs::read_dir(path).expect("read quota fixture directory") {
            collect_tree(root, &entry.expect("quota fixture entry").path(), nodes);
        }
    }
}

#[cfg(unix)]
fn permission_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o777
}

#[cfg(not(unix))]
fn permission_mode(_metadata: &fs::Metadata) -> u32 {
    0
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).unwrap_or_else(|error| {
        panic!(
            "create fixture destination {}: {error}",
            destination.display()
        )
    });
    for entry in fs::read_dir(source)
        .unwrap_or_else(|error| panic!("read fixture source {}: {error}", source.display()))
    {
        let entry = entry.expect("quota fixture entry");
        let target = destination.join(entry.file_name());
        let file_type = entry.file_type().expect("quota fixture file type");
        if file_type.is_dir() {
            copy_tree(&entry.path(), &target);
        } else if file_type.is_file() {
            fs::copy(entry.path(), target).expect("copy quota fixture file");
        } else {
            panic!("quota fixture contains a special file")
        }
    }
}
