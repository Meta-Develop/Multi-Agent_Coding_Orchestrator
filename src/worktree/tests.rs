use super::*;
use git2::{Oid, Signature};
use tempfile::TempDir;

#[cfg(unix)]
#[test]
fn bounded_status_parsers_are_lossless_and_fail_closed() {
    let parsed =
        parse_porcelain_v1_z(b" M src/lib.rs\0?? new file.rs\0", 2).expect("parse status records");
    assert_eq!(parsed[0], (PathBuf::from("src/lib.rs"), [b' ', b'M']));
    assert_eq!(parsed[1], (PathBuf::from("new file.rs"), [b'?', b'?']));
    assert!(parse_porcelain_v1_z(b" M ../escape\0", 2).is_err());
    assert!(parse_porcelain_v1_z(b"bad\0", 2).is_err());

    let visible = parse_nul_paths(b"README.md\0src/lib.rs\0", 2).expect("parse visible paths");
    assert_eq!(
        visible,
        vec![PathBuf::from("README.md"), PathBuf::from("src/lib.rs")]
    );
    assert!(parse_nul_paths(b"../escape\0", 2).is_err());
}

#[cfg(target_os = "linux")]
fn init_bounded_status_runtime_root_repo(temp: &TempDir) -> PathBuf {
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    repo_path
}

#[cfg(target_os = "linux")]
fn canonical_target_dir() -> Option<PathBuf> {
    fs::canonicalize(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target")).ok()
}

#[cfg(target_os = "linux")]
fn path_on_other_filesystem(reference: &Path) -> Option<PathBuf> {
    let mut candidates = vec![PathBuf::from("/tmp")];
    if let Some(target) = canonical_target_dir() {
        candidates.push(target);
    }
    candidates
        .into_iter()
        .find(|candidate| candidate.is_dir() && !existing_paths_share_device(reference, candidate))
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_runtime_root_uses_an_explicit_override() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = init_bounded_status_runtime_root_repo(&temp);
    let override_root = temp.path().join("override-status-root");
    let config = BoundedStatusRuntimeRootConfig {
        explicit_root: Some(override_root.clone()),
        tmpdir: Some(temp.path().join("ignored-tmpdir")),
        prefer_shared_tmp: true,
    };
    let root = open_bounded_status_runtime_root(&repo_path, &config).expect("open override");
    assert_eq!(root.path(), override_root.as_path());
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_runtime_root_honors_tmpdir_when_shared_tmp_is_enabled() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = init_bounded_status_runtime_root_repo(&temp);
    let tmpdir = temp.path().join("status-tmp");
    fs::create_dir(&tmpdir).expect("tmpdir");
    let config = BoundedStatusRuntimeRootConfig {
        explicit_root: None,
        tmpdir: Some(tmpdir.clone()),
        prefer_shared_tmp: true,
    };
    let root = open_bounded_status_runtime_root(&repo_path, &config).expect("open tmpdir root");
    assert_eq!(
        root.path(),
        tmpdir
            .join(shared_bounded_status_runtime_root_name())
            .as_path()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_runtime_root_fails_closed_when_the_explicit_root_is_empty() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = init_bounded_status_runtime_root_repo(&temp);
    let config = BoundedStatusRuntimeRootConfig {
        explicit_root: Some(PathBuf::new()),
        tmpdir: None,
        prefer_shared_tmp: true,
    };
    let error = open_bounded_status_runtime_root(&repo_path, &config)
        .expect_err("empty explicit root must fail closed");
    let message = format!("{error:#}");
    assert!(
        message.contains(BOUNDED_STATUS_RUNTIME_ROOT_ENV),
        "unexpected empty-root error: {message}"
    );
    assert!(
        message.contains("empty"),
        "unexpected empty-root error: {message}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_runtime_root_fails_closed_when_the_explicit_root_is_a_file() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = init_bounded_status_runtime_root_repo(&temp);
    let file_root = temp.path().join("not-a-directory");
    fs::write(&file_root, b"nope").expect("write file root");
    let config = BoundedStatusRuntimeRootConfig {
        explicit_root: Some(file_root),
        tmpdir: None,
        prefer_shared_tmp: true,
    };
    let error = open_bounded_status_runtime_root(&repo_path, &config)
        .expect_err("file explicit root must fail closed");
    let message = format!("{error:#}");
    assert!(
        message.contains(BOUNDED_STATUS_RUNTIME_ROOT_ENV),
        "unexpected file-root error: {message}"
    );
    assert!(
        message.contains("unusable"),
        "unexpected file-root error: {message}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_runtime_root_fails_closed_when_the_explicit_root_crosses_filesystems() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = init_bounded_status_runtime_root_repo(&temp);
    let Some(foreign_parent) = path_on_other_filesystem(temp.path()) else {
        return;
    };
    let foreign_root = foreign_parent.join(format!(
        "maco-test-bounded-status-crossfs-{}",
        std::process::id()
    ));
    let config = BoundedStatusRuntimeRootConfig {
        explicit_root: Some(foreign_root.clone()),
        tmpdir: None,
        prefer_shared_tmp: true,
    };
    let error = open_bounded_status_runtime_root(&repo_path, &config)
        .expect_err("cross-filesystem explicit root must fail closed");
    let _ = fs::remove_dir_all(&foreign_root);
    let message = format!("{error:#}");
    assert!(
        message.contains("different filesystem"),
        "unexpected cross-filesystem error: {message}"
    );
    assert!(
        message.contains(BOUNDED_STATUS_RUNTIME_ROOT_ENV),
        "cross-filesystem error must name the override: {message}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_runtime_root_skips_an_unusable_tmpdir_and_uses_a_worktree_local_root() {
    let Some(host) = canonical_target_dir() else {
        return;
    };
    if existing_paths_share_device(&host, Path::new("/tmp")) {
        return;
    }
    let temp = TempDir::new_in(&host).expect("tempdir on target filesystem");
    let repo_path = init_bounded_status_runtime_root_repo(&temp);
    let foreign_parent = PathBuf::from("/tmp");
    let config = BoundedStatusRuntimeRootConfig {
        explicit_root: None,
        tmpdir: Some(foreign_parent.clone()),
        prefer_shared_tmp: true,
    };
    let root = open_bounded_status_runtime_root(&repo_path, &config)
        .expect("unusable TMPDIR must fall back to a same-filesystem root");
    assert_eq!(
        existing_path_device(root.path()),
        existing_path_device(&repo_path),
        "fallback root {} is not on the worktree filesystem",
        root.path().display()
    );
    assert!(
        !root.path().starts_with(&foreign_parent),
        "fallback still used the unusable TMPDIR {}",
        root.path().display()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_runtime_root_test_default_stays_isolated_from_shared_tmp() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = init_bounded_status_runtime_root_repo(&temp);
    let root = bounded_status_runtime_root(&repo_path).expect("test default root");
    assert!(
        !root
            .path()
            .ends_with(shared_bounded_status_runtime_root_name()),
        "test default used the shared per-user tmp root {}",
        root.path().display()
    );
    assert!(
        root.path().starts_with(temp.path()),
        "test default root {} was not isolated next to the fixture",
        root.path().display()
    );
}

fn empty_bounded_index(extensions: &[(&[u8; 4], &[u8])]) -> Vec<u8> {
    let mut bytes = b"DIRC\0\0\0\x02\0\0\0\0".to_vec();
    for (signature, payload) in extensions {
        bytes.extend_from_slice(*signature);
        bytes.extend_from_slice(
            &u32::try_from(payload.len())
                .expect("extension length")
                .to_be_bytes(),
        );
        bytes.extend_from_slice(payload);
    }
    let checksum = sha1_digest(&bytes).expect("index checksum");
    bytes.extend_from_slice(&checksum);
    bytes
}

fn refresh_bounded_index_checksum(bytes: &mut Vec<u8>) {
    bytes.truncate(bytes.len() - 20);
    let checksum = sha1_digest(bytes).expect("refresh index checksum");
    bytes.extend_from_slice(&checksum);
}

fn append_bounded_index_extension(index: &[u8], signature: &[u8; 4], payload: &[u8]) -> Vec<u8> {
    let checksum_start = index.len().checked_sub(20).expect("index checksum");
    let mut extended = index[..checksum_start].to_vec();
    extended.extend_from_slice(signature);
    extended.extend_from_slice(
        &u32::try_from(payload.len())
            .expect("extension length")
            .to_be_bytes(),
    );
    extended.extend_from_slice(payload);
    let checksum = sha1_digest(&extended).expect("extended index checksum");
    extended.extend_from_slice(&checksum);
    extended
}

#[test]
fn bounded_index_accepts_only_plain_entries_and_safe_optional_caches() {
    let resolve_undo = b"README.md\x00100644\x000\x000\x00\
        \x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\
        \x11\x11\x11\x11\x11\x11\x11\x11\x11\x11";

    validate_bounded_index_bytes(&empty_bounded_index(&[])).expect("plain empty index");
    validate_bounded_index_bytes(&empty_bounded_index(&[(b"TREE", b"")]))
        .expect("ordinary TREE cache extension");
    validate_bounded_index_bytes(&empty_bounded_index(&[(b"REUC", resolve_undo)]))
        .expect("resolve-undo cache extension");
    validate_bounded_index_bytes(&empty_bounded_index(&[
        (b"TREE", b""),
        (b"REUC", resolve_undo),
    ]))
    .expect("unique safe optional extensions");

    let duplicate = empty_bounded_index(&[(b"REUC", resolve_undo), (b"REUC", b"")]);
    let duplicate_error =
        validate_bounded_index_bytes(&duplicate).expect_err("duplicate REUC must fail closed");
    assert!(duplicate_error.to_string().contains("duplicate"));

    let mut truncated = empty_bounded_index(&[(b"REUC", resolve_undo)]);
    truncated[16..20].copy_from_slice(
        &u32::try_from(resolve_undo.len() + 1)
            .expect("malformed extension length")
            .to_be_bytes(),
    );
    refresh_bounded_index_checksum(&mut truncated);
    let truncated_error = validate_bounded_index_bytes(&truncated)
        .expect_err("truncated REUC payload must fail closed");
    assert!(truncated_error.to_string().contains("payload is truncated"));

    let stateful_error = validate_bounded_index_bytes(&empty_bounded_index(&[(b"FSMN", b"")]))
        .expect_err("stateful optional extension must fail closed");
    assert!(stateful_error.to_string().contains("stateful optional"));
    let required_error = validate_bounded_index_bytes(&empty_bounded_index(&[(b"link", b"")]))
        .expect_err("required extension must fail closed");
    assert!(required_error.to_string().contains("required or stateful"));

    let mut entry = b"DIRC\0\0\0\x02\0\0\0\x01".to_vec();
    entry.extend_from_slice(&[0; 62]);
    entry[12 + 24..12 + 28].copy_from_slice(&0o100644_u32.to_be_bytes());
    entry[12 + 60..12 + 62].copy_from_slice(&1_u16.to_be_bytes());
    entry.push(b'a');
    entry.push(0);
    let checksum = sha1_digest(&entry).expect("entry checksum");
    entry.extend_from_slice(&checksum);
    validate_bounded_index_bytes(&entry).expect("ordinary SHA-1 index entry");

    let mut all_zero_checksum = entry.clone();
    let checksum_start = all_zero_checksum.len() - 20;
    all_zero_checksum[checksum_start..].fill(0);
    assert!(validate_bounded_index_bytes(&all_zero_checksum).is_err());

    let mut tampered = entry.clone();
    tampered[12 + 24] ^= 1;
    assert!(validate_bounded_index_bytes(&tampered).is_err());

    let mut gitlink = entry.clone();
    gitlink[12 + 24..12 + 28].copy_from_slice(&0o160000_u32.to_be_bytes());
    refresh_bounded_index_checksum(&mut gitlink);
    validate_bounded_index_bytes(&gitlink).expect("gitlink is an opaque index path");

    let mut sparse_directory = entry.clone();
    sparse_directory[12 + 24..12 + 28].copy_from_slice(&0o040000_u32.to_be_bytes());
    refresh_bounded_index_checksum(&mut sparse_directory);
    let sparse_error = validate_bounded_index_bytes(&sparse_directory)
        .expect_err("sparse-directory entry must fail closed");
    assert_eq!(
        sparse_error.to_string(),
        "bounded-status rejects sparse-directory index entries"
    );

    let mut assume_unchanged = entry.clone();
    assume_unchanged[12 + 60..12 + 62].copy_from_slice(&(0x8000_u16 | 1).to_be_bytes());
    refresh_bounded_index_checksum(&mut assume_unchanged);
    let assume_unchanged_error = validate_bounded_index_bytes(&assume_unchanged)
        .expect_err("assume-unchanged entry must fail closed");
    assert_eq!(
        assume_unchanged_error.to_string(),
        "bounded-status rejects assume-unchanged index entries"
    );

    let mut extended = entry;
    extended[12 + 60..12 + 62].copy_from_slice(&(0x4000_u16 | 1).to_be_bytes());
    refresh_bounded_index_checksum(&mut extended);
    let extended_error =
        validate_bounded_index_bytes(&extended).expect_err("extended entry must fail closed");
    assert_eq!(
        extended_error.to_string(),
        "bounded-status rejects extended index flags"
    );
}

#[test]
fn bounded_git_index_records_accept_gitlinks_but_reject_sparse_directories_and_hidden_state() {
    let oid = "0000000000000000000000000000000000000000";
    let gitlink = format!("H 160000 {oid} 0\tvendor/sdk\0");
    validate_bounded_git_index_records(gitlink.as_bytes(), 1)
        .expect("gitlink record is an opaque index path");

    let sparse_directory = format!("S 040000 {oid} 0\tsparse-directory\0");
    let error = validate_bounded_git_index_records(sparse_directory.as_bytes(), 1)
        .expect_err("sparse-directory record must fail closed");
    assert_eq!(
        error.to_string(),
        "bounded-status rejects sparse-directory index entries"
    );

    for hidden in [
        format!("S 100644 {oid} 0\tskip-worktree\0"),
        format!("h 100644 {oid} 0\tassume-unchanged\0"),
    ] {
        let error = validate_bounded_git_index_records(hidden.as_bytes(), 1)
            .expect_err("hidden index state must fail closed");
        assert_eq!(
            error.to_string(),
            "bounded-status rejects hidden index-entry state"
        );
    }
}

#[test]
fn internal_sha1_matches_nist_abc_vector() {
    assert_eq!(
        sha1_digest(b"abc").expect("SHA-1 digest"),
        [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d,
        ]
    );
}

#[test]
fn bounded_head_rejects_sha256_shaped_direct_object_ids() {
    let sha256_head = format!("{}\n", "a".repeat(64));
    let error = validate_bounded_head(sha256_head.as_bytes())
        .expect_err("SHA-256-shaped direct HEAD must fail closed");

    assert_eq!(
        error.to_string(),
        "bounded-status supports only SHA-1 repositories"
    );
}

#[test]
fn bounded_head_resolution_distinguishes_normal_and_unborn_branches() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let unborn = RepositoryBindingGuard::bind(&repo_path).expect("bind unborn repo");
    let unborn_head = unborn
        .read_git_relative(Path::new("HEAD"), MAX_WORKTREE_HEAD_BYTES)
        .expect("read unborn HEAD");
    assert!(std::str::from_utf8(
        &resolve_bounded_head(&unborn, &unborn_head).expect("resolve unborn HEAD")
    )
    .expect("UTF-8 unborn HEAD")
    .starts_with("ref: refs/heads/main"));

    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let oid = commit_readme(&repo).expect("commit README");
    let committed = RepositoryBindingGuard::bind(&repo_path).expect("bind committed repo");
    let committed_head = committed
        .read_git_relative(Path::new("HEAD"), MAX_WORKTREE_HEAD_BYTES)
        .expect("read committed HEAD");
    assert_eq!(
        std::str::from_utf8(
            &resolve_bounded_head(&committed, &committed_head).expect("resolve committed HEAD")
        )
        .expect("UTF-8 committed HEAD")
        .trim(),
        oid.to_string()
    );
}

#[test]
fn repository_binding_rejects_git_association_replacement() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let binding = RepositoryBindingGuard::bind(&repo_path).expect("bind repository");
    fs::rename(repo_path.join(".git"), repo_path.join(".git-displaced"))
        .expect("displace git marker");
    fs::create_dir(repo_path.join(".git")).expect("replace git marker");

    assert!(binding.verify().is_err());
}

#[test]
fn effectful_worktree_cleanliness_entries_fail_closed_before_repository_access() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo-must-not-be-opened");
    let manager = WorktreeManager::new(&repo_path);
    let create_error = manager
        .create(WorktreeCreateOptions {
            agent_id: "worker".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(temp.path().join("must-not-be-created")),
        })
        .expect_err("worktree create must fail closed");
    let remove_error = manager
        .remove("worker", false, true)
        .expect_err("non-force removal must fail closed");

    let create_message = format!("{create_error:#}");
    assert!(
        create_message.contains("failed to open repository")
            && create_message.contains("cleanliness capability"),
        "{create_message}"
    );
    assert!(remove_error.to_string().contains("capability-bound"));
    assert_eq!(fs::read_dir(temp.path()).expect("read temp").count(), 0);
}

#[test]
fn neutral_worktree_rejects_each_normalized_source_identity_before_repository_access() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo-must-not-be-opened");
    let worktree_root = temp.path().join("must-not-be-created");
    let manager = WorktreeManager::new(&repo_path);

    for source_agent_ids in [
        [" arbiter ".to_string(), "source-b".to_string()],
        ["source-a".to_string(), "\tarbiter\n".to_string()],
    ] {
        let error = manager
            .create_neutral_for_test(NeutralWorktreeCreateOptions {
                arbiter_agent_id: "arbiter".to_string(),
                source_agent_ids,
                base_oid: Oid::ZERO_SHA1,
                worktree_root: Some(worktree_root.clone()),
            })
            .expect_err("arbiter identity equal to either source must be refused");
        assert!(error
            .to_string()
            .contains("must differ from both normalized source agent ids"));
    }

    assert!(!repo_path.exists());
    assert!(!worktree_root.exists());
}

#[test]
fn neutral_worktree_refuses_inherited_durable_claim_without_mutating_it() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let base_oid = commit_readme(&repo).expect("initial commit");
    let claims = SyncStore::open(&repo_path).expect("open claims");
    let inherited = claims
        .claim_paths("neutral-arbiter", ["src"])
        .expect("seed inherited claim");
    let manager = WorktreeManager::new(&repo_path);

    let error = manager
        .create_neutral_for_test(NeutralWorktreeCreateOptions {
            arbiter_agent_id: "neutral-arbiter".to_string(),
            source_agent_ids: ["source-a".to_string(), "source-b".to_string()],
            base_oid,
            worktree_root: Some(worktree_root.clone()),
        })
        .expect_err("inherited durable claim must be refused");

    assert!(error
        .to_string()
        .contains("active durable path claim; refusing inherited claim authority"));
    assert_eq!(
        claims.snapshot().expect("claims after refusal"),
        vec![inherited]
    );
    assert!(repo
        .find_branch("maco/neutral-arbiter", BranchType::Local)
        .is_err());
    assert!(!worktree_root.join("neutral-arbiter").exists());
}

#[test]
fn neutral_worktree_refuses_preexisting_default_branch() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let base_oid = commit_readme(&repo).expect("initial commit");
    let base = repo.find_commit(base_oid).expect("find base commit");
    repo.branch("maco/neutral-arbiter", &base, false)
        .expect("seed branch");
    let manager = WorktreeManager::new(&repo_path);

    let error = manager
        .create_neutral_for_test(NeutralWorktreeCreateOptions {
            arbiter_agent_id: "neutral-arbiter".to_string(),
            source_agent_ids: ["source-a".to_string(), "source-b".to_string()],
            base_oid,
            worktree_root: Some(worktree_root.clone()),
        })
        .expect_err("preexisting default branch must be refused");

    assert!(error
        .to_string()
        .contains("requires a fresh MACO-owned default branch"));
    assert_eq!(
        repo.find_branch("maco/neutral-arbiter", BranchType::Local)
            .expect("preexisting branch remains")
            .get()
            .target(),
        Some(base_oid)
    );
    assert!(manager
        .list_managed_verified()
        .expect("list managed worktrees")
        .is_empty());
    assert!(!worktree_root.join("neutral-arbiter").exists());
}

#[test]
fn neutral_worktree_refuses_existing_managed_identity() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let base_oid = commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let existing = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "neutral-arbiter".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root.clone()),
        })
        .expect("seed managed worktree");

    let error = manager
        .create_neutral_for_test(NeutralWorktreeCreateOptions {
            arbiter_agent_id: "neutral-arbiter".to_string(),
            source_agent_ids: ["source-a".to_string(), "source-b".to_string()],
            base_oid,
            worktree_root: Some(worktree_root),
        })
        .expect_err("existing managed identity must be refused");

    assert!(error
        .to_string()
        .contains("already has managed worktree state; refusing reuse"));
    assert_eq!(
        manager
            .list_managed_verified()
            .expect("list existing managed worktree"),
        vec![existing]
    );
}

#[test]
fn neutral_worktree_uses_fresh_default_branch_at_exact_base_without_claim() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let exact_base_oid = commit_readme(&repo).expect("initial commit");
    let newer_oid = commit_descendant(&repo, "README.md", "# Newer\n").expect("newer commit");
    let manager = WorktreeManager::new(&repo_path);

    let record = manager
        .create_neutral_for_test(NeutralWorktreeCreateOptions {
            arbiter_agent_id: "neutral-arbiter".to_string(),
            source_agent_ids: ["source-a".to_string(), "source-b".to_string()],
            base_oid: exact_base_oid,
            worktree_root: Some(worktree_root),
        })
        .expect("create neutral worktree");

    assert_eq!(record.name, "neutral-arbiter");
    assert_eq!(record.branch, "maco/neutral-arbiter");
    assert_eq!(
        repo.find_branch(&record.branch, BranchType::Local)
            .expect("fresh neutral branch")
            .get()
            .target(),
        Some(exact_base_oid)
    );
    assert_eq!(
        repo.head()
            .expect("primary HEAD")
            .target()
            .expect("primary HEAD target"),
        newer_oid
    );
    assert_eq!(
        fs::read_to_string(record.path.join("README.md")).expect("read neutral README"),
        "# Test\n"
    );
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
    let lock = store.lock().expect("registry lock");
    let registry = store.load(&lock).expect("registry");
    let binding = registry
        .records
        .get("neutral-arbiter")
        .expect("neutral binding");
    assert!(binding.branch_created_by_maco);
    assert_eq!(binding.base_oid, exact_base_oid.to_string());
    assert_eq!(binding.created_branch_oid, exact_base_oid.to_string());
    assert!(SyncStore::open(&repo_path)
        .expect("open claims")
        .snapshot()
        .expect("claims after neutral create")
        .is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn neutral_worktree_production_cleanliness_seam_uses_exact_base_without_claim() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let exact_base_oid = commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let cleanliness = manager
        .acquire_repository_cleanliness()
        .expect("capture clean repository capability");

    let record = manager
        .create_neutral_with_repository_cleanliness(
            NeutralWorktreeCreateOptions {
                arbiter_agent_id: "neutral-production-arbiter".to_string(),
                source_agent_ids: ["agent-a".to_string(), "agent-b".to_string()],
                base_oid: exact_base_oid,
                worktree_root: Some(worktree_root),
            },
            &cleanliness,
        )
        .expect("create production capability-bound neutral worktree");

    assert_eq!(record.name, "neutral-production-arbiter");
    assert_eq!(record.branch, "maco/neutral-production-arbiter");
    assert_eq!(
        repo.find_branch("maco/neutral-production-arbiter", BranchType::Local)
            .expect("fresh neutral branch")
            .get()
            .target(),
        Some(exact_base_oid)
    );
    assert!(SyncStore::open(&repo_path)
        .expect("open claims")
        .snapshot()
        .expect("claims after production neutral create")
        .is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn repository_cleanliness_capability_creates_clean_managed_worktree() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let cleanliness = manager
        .acquire_repository_cleanliness()
        .expect("capture clean repository capability");

    let record = manager
        .create_with_repository_cleanliness(
            WorktreeCreateOptions {
                agent_id: "capability-worker".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root),
            },
            &cleanliness,
        )
        .expect("create capability-bound worktree");

    assert_eq!(record.name, "capability-worker");
    assert_eq!(record.branch, "maco/capability-worker");
    assert!(record.path.join("README.md").is_file());
    assert!(bounded_repository_status_paths(
        &record.path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_GC_STATUS_TIMEOUT,
    )
    .expect("inspect created worktree")
    .is_empty());
    assert_eq!(
        manager.list_managed_verified().expect("list worktrees"),
        vec![record]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn public_create_derives_cleanliness_from_a_clean_repository() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);

    let record = manager
        .create(WorktreeCreateOptions {
            agent_id: "public-create-worker".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root),
        })
        .expect("public create derives cleanliness from a clean repository");

    assert_eq!(record.name, "public-create-worker");
    assert_eq!(record.branch, "maco/public-create-worker");
    assert!(record.path.join("README.md").is_file());
    assert_eq!(
        manager.list_managed_verified().expect("list worktrees"),
        vec![record]
    );
}

#[cfg(target_os = "linux")]
#[test]
fn repository_cleanliness_capability_refuses_dirty_primary_before_create() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let cleanliness = manager
        .acquire_repository_cleanliness()
        .expect("capture clean repository capability");
    fs::write(repo_path.join("README.md"), "dirty\n").expect("dirty primary");

    let error = manager
        .create_with_repository_cleanliness(
            WorktreeCreateOptions {
                agent_id: "must-not-exist".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.clone()),
            },
            &cleanliness,
        )
        .expect_err("dirty primary must be refused");

    assert!(error.to_string().contains("primary repository is dirty"));
    assert!(!worktree_root.exists());
    assert!(repo
        .find_branch("maco/must-not-exist", BranchType::Local)
        .is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn repository_cleanliness_capability_rejects_cross_repository_use() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let first_path = temp.path().join("first");
    let second_path = temp.path().join("second");
    WorktreeManager::init_repository(&first_path, "main").expect("init first repo");
    WorktreeManager::init_repository(&second_path, "main").expect("init second repo");
    commit_readme(&crate::git_repository::open(&first_path).expect("open first"))
        .expect("commit first");
    commit_readme(&crate::git_repository::open(&second_path).expect("open second"))
        .expect("commit second");
    let first = WorktreeManager::new(&first_path);
    let second = WorktreeManager::new(&second_path);
    let cleanliness = first
        .acquire_repository_cleanliness()
        .expect("capture first capability");
    let second_worktrees = temp.path().join("second-worktrees");

    let error = second
        .create_with_repository_cleanliness(
            WorktreeCreateOptions {
                agent_id: "cross-repository".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(second_worktrees.clone()),
            },
            &cleanliness,
        )
        .expect_err("cross-repository capability must be refused");

    assert!(error.to_string().contains("different managed repository"));
    assert!(!second_worktrees.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn repository_cleanliness_capability_rejects_binding_drift() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let cleanliness = manager
        .acquire_repository_cleanliness()
        .expect("capture repository capability");
    fs::rename(repo_path.join(".git"), repo_path.join(".git-displaced"))
        .expect("displace git directory");
    fs::create_dir(repo_path.join(".git")).expect("replace git directory");

    let error = manager
        .create_with_repository_cleanliness(
            WorktreeCreateOptions {
                agent_id: "binding-drift".to_string(),
                branch: None,
                base: None,
                worktree_root: Some(worktree_root.clone()),
            },
            &cleanliness,
        )
        .expect_err("binding drift must be refused");

    let message = format!("{error:#}");
    assert!(
        message.contains("association changed") || message.contains("failed to open repository"),
        "unexpected binding-drift error: {message}"
    );
    assert!(!worktree_root.exists());
}

#[test]
fn pending_inspection_is_read_only_and_force_cleanup_is_explicit() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let oid = commit_readme(&repo).expect("initial commit");
    let root = SafeRoot::open_or_create_managed(&worktree_root).expect("worktree root");
    let manager = WorktreeManager::new(&repo_path);
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
    let lock = store.lock().expect("registry lock");
    let mut registry = store.load(&lock).expect("registry");
    let name = "agent-pending".to_string();
    let staging_root = root.path().join("pending-stage");
    registry.operations.insert(
        name.clone(),
        ManagedWorktreeOperation {
            kind: ManagedWorktreeOperationKind::Create,
            phase: ManagedWorktreeOperationPhase::CreateIntent,
            name: name.clone(),
            root: root.path().to_path_buf(),
            root_identity: root.identity().clone(),
            path: root.path().join(&name),
            prepared_path_identity: None,
            staging_root: Some(staging_root.clone()),
            staging_root_identity: None,
            staging_path: Some(staging_root.join(&name)),
            staged_path_identity: None,
            staged_metadata: None,
            branch: "maco/agent-pending".to_string(),
            base_oid: oid.to_string(),
            branch_preexisting_oid: None,
            branch_ownership: ManagedBranchOwnership::Unknown,
            owned_branch_oid: None,
            binding: None,
            delete_branch: false,
            force: false,
            expected_branch_oid: None,
            gc_dirtiness_checksum: None,
            removal_safety: None,
            worktree_quarantine_path: None,
            worktree_quarantine_identity: None,
            metadata_quarantine_path: None,
            metadata_quarantine_identity: None,
        },
    );
    store.save(&lock, &mut registry).expect("save intent");
    drop(lock);
    drop(store);
    drop(repo);

    let pending = manager
        .pending_operations()
        .expect("inspect pending intent");
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].name, name);
    assert_eq!(pending[0].kind, "create");
    assert_eq!(pending[0].phase, "create_intent");
    assert!(!pending[0].force);
    assert!(manager
        .list_managed_verified()
        .expect("list without recovery")
        .is_empty());
    assert_eq!(
        manager
            .pending_operations()
            .expect("intent must remain pending"),
        pending
    );
    assert!(!root.path().join(&name).exists());
    assert!(!staging_root.exists());

    let authenticated_root_path = repo_path
        .join(".git/maco/state")
        .join(ManagedSnapshotSpec::ROOT_NAME);
    let authenticated_root =
        SafeRoot::open_existing(&authenticated_root_path).expect("authenticated root");
    let locator_name = fs::read_dir(&authenticated_root_path)
        .expect("authenticated entries")
        .map(|entry| entry.expect("authenticated entry").file_name())
        .find(|entry| {
            entry
                .to_str()
                .is_some_and(|name| name.starts_with(".snapshot-locator-"))
        })
        .expect("managed snapshot locator");
    AtomicStateWriter::write_direct_fenced(
        &authenticated_root,
        &locator_name,
        b"crash-temp",
        || bail!("injected locator temp"),
    )
    .expect_err("leave transitional metadata residue");
    let residue_inventory = fs::read_dir(&authenticated_root_path)
        .expect("inventory with residue")
        .map(|entry| entry.expect("residue entry").file_name())
        .collect::<std::collections::BTreeSet<_>>();
    let error = manager
        .pending_operations()
        .expect_err("pending reader must refuse transitional metadata");
    assert!(error.to_string().contains("unexpected file"));
    assert_eq!(
        fs::read_dir(&authenticated_root_path)
            .expect("inventory after refusal")
            .map(|entry| entry.expect("residue entry").file_name())
            .collect::<std::collections::BTreeSet<_>>(),
        residue_inventory,
        "pending inspection scavenged metadata residue"
    );

    let cleanup_error = manager
        .remove(&name, true, false)
        .expect_err("force must recover the intent before reporting no binding");
    assert!(cleanup_error
        .to_string()
        .contains("has no create-time managed binding"));
    assert!(manager
        .pending_operations()
        .expect("inspect cleaned operations")
        .is_empty());
}

#[test]
fn pending_inspection_of_fresh_repository_creates_no_maco_state() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let common_dir = repo.path().to_path_buf();
    assert!(!common_dir.join("maco").exists());

    let pending = WorktreeManager::new(&repo_path)
        .pending_operations()
        .expect("fresh repository has no pending operations");

    assert!(pending.is_empty());
    assert!(!common_dir.join("maco").exists());
}

#[test]
fn linked_worktree_rejects_shadow_branch_and_exclude_authority() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let linked_path = temp.path().join("linked");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let first = commit_readme(&repo).expect("first commit");
    let second = commit_descendant(&repo, "README.md", "# Second\n").expect("second commit");
    let first_commit = repo.find_commit(first).expect("find first commit");
    let branch = repo
        .branch("topic", &first_commit, false)
        .expect("create topic");
    let reference = branch.into_reference();
    let mut options = WorktreeAddOptions::new();
    options.reference(Some(&reference));
    repo.worktree("linked-authority", &linked_path, Some(&options))
        .expect("create linked worktree");
    repo.find_reference("refs/heads/topic")
        .expect("find topic")
        .set_target(second, "advance authoritative topic")
        .expect("advance topic");
    let binding = RepositoryBindingGuard::bind(&linked_path).expect("bind linked worktree");
    let shadow_ref = binding.git_dir().join("refs/heads/topic");
    fs::create_dir_all(shadow_ref.parent().expect("shadow ref parent"))
        .expect("create shadow ref parent");
    fs::write(&shadow_ref, format!("{first}\n")).expect("write shadow ref");
    let head = binding
        .read_git_relative(Path::new("HEAD"), MAX_WORKTREE_HEAD_BYTES)
        .expect("read linked HEAD");
    assert!(resolve_bounded_head(&binding, &head).is_err());

    fs::remove_file(&shadow_ref).expect("remove shadow ref");
    let common_exclude = binding.common_dir().join("info/exclude");
    fs::create_dir_all(common_exclude.parent().expect("common exclude parent"))
        .expect("create common exclude parent");
    fs::write(&common_exclude, b"common-only\n").expect("write common exclude");
    let shadow_exclude = binding.git_dir().join("info/exclude");
    fs::create_dir_all(shadow_exclude.parent().expect("shadow exclude parent"))
        .expect("create shadow exclude parent");
    fs::write(&shadow_exclude, b"shadow\n").expect("write shadow exclude");
    assert!(validate_bounded_git_text_inputs(
        &linked_path,
        binding.git_dir(),
        binding.common_dir(),
        Instant::now() + Duration::from_secs(2),
    )
    .is_err());

    fs::remove_file(&shadow_exclude).expect("remove shadow exclude");
    let inputs = validate_bounded_git_text_inputs(
        &linked_path,
        binding.git_dir(),
        binding.common_dir(),
        Instant::now() + Duration::from_secs(2),
    )
    .expect("accept common exclude");
    assert!(inputs
        .info_exclude
        .expect("effective exclude")
        .starts_with(b"common-only\n"));
}

#[cfg(unix)]
#[test]
fn bounded_git_input_preflight_rejects_unsafe_ignore_and_gitmodules_files() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let ignore = repo_path.join(".gitignore");
    let oversized = fs::File::create(&ignore).expect("create ignore");
    oversized
        .set_len(MAX_WORKTREE_GIT_TEXT_FILE_BYTES + 1)
        .expect("size ignore");
    let deadline = Instant::now() + Duration::from_secs(2);
    assert!(
        validate_bounded_git_text_inputs(&repo_path, repo.path(), repo.commondir(), deadline,)
            .is_err()
    );

    fs::remove_file(&ignore).expect("remove ignore");
    let outside = temp.path().join("outside-ignore");
    fs::write(&outside, "target/\n").expect("write outside ignore");
    symlink(&outside, &ignore).expect("link ignore");
    let deadline = Instant::now() + Duration::from_secs(2);
    let linked_ignore_error =
        validate_bounded_git_text_inputs(&repo_path, repo.path(), repo.commondir(), deadline);
    assert_eq!(
        linked_ignore_error
            .err()
            .expect("symlinked ignore file must fail closed")
            .to_string(),
        "Git ignore input is not a safe single-link regular file"
    );

    fs::remove_file(&ignore).expect("remove linked ignore");
    let gitmodules = repo_path.join(".gitmodules");
    fs::write(
        &gitmodules,
        b"[submodule \"vendor/sdk\"]\n\tpath = vendor/sdk\n\turl = ../sdk\n",
    )
    .expect("write gitmodules");
    validate_bounded_git_text_inputs(
        &repo_path,
        repo.path(),
        repo.commondir(),
        Instant::now() + Duration::from_secs(2),
    )
    .expect("safe root gitmodules must be tolerated as bounded text input");

    let oversized_gitmodules = fs::File::create(&gitmodules).expect("recreate gitmodules");
    oversized_gitmodules
        .set_len(MAX_WORKTREE_GIT_TEXT_FILE_BYTES + 1)
        .expect("size gitmodules");
    validate_bounded_git_text_inputs(
        &repo_path,
        repo.path(),
        repo.commondir(),
        Instant::now() + Duration::from_secs(2),
    )
    .err()
    .expect("oversized gitmodules must retain the bounded text-input cap");

    fs::remove_file(&gitmodules).expect("remove oversized gitmodules");
    let outside_gitmodules = temp.path().join("outside-gitmodules");
    fs::write(&outside_gitmodules, b"[submodule \"vendor/sdk\"]\n")
        .expect("write outside gitmodules");
    symlink(&outside_gitmodules, &gitmodules).expect("link gitmodules");
    let linked_gitmodules_error = validate_bounded_git_text_inputs(
        &repo_path,
        repo.path(),
        repo.commondir(),
        Instant::now() + Duration::from_secs(2),
    )
    .err()
    .expect("symlinked gitmodules must fail closed");
    assert_eq!(
        linked_gitmodules_error.to_string(),
        "Git submodule metadata is not a safe single-link regular file"
    );

    fs::remove_file(&gitmodules).expect("remove linked gitmodules");
    fs::hard_link(&outside_gitmodules, &gitmodules).expect("hard-link gitmodules");
    let hard_linked_gitmodules_error = validate_bounded_git_text_inputs(
        &repo_path,
        repo.path(),
        repo.commondir(),
        Instant::now() + Duration::from_secs(2),
    )
    .err()
    .expect("multi-link gitmodules must fail closed");
    assert_eq!(
        hard_linked_gitmodules_error.to_string(),
        "Git submodule metadata is not a safe single-link regular file"
    );

    fs::remove_file(&gitmodules).expect("remove hard-linked gitmodules");
    fs::write(&gitmodules, b"[submodule \"vendor/sdk\"]\n").expect("restore safe gitmodules");
    validate_bounded_git_text_inputs(
        &repo_path,
        repo.path(),
        repo.commondir(),
        Instant::now() + Duration::from_secs(2),
    )
    .expect("restored safe root gitmodules must pass prevalidation");

    let alternates = repo.commondir().join("objects/info/alternates");
    fs::create_dir_all(alternates.parent().expect("alternates parent"))
        .expect("create alternates parent");
    fs::write(&alternates, b"/tmp/objects\n").expect("write alternates");
    let alternates_error = validate_bounded_git_text_inputs(
        &repo_path,
        repo.path(),
        repo.commondir(),
        Instant::now() + Duration::from_secs(2),
    )
    .err()
    .expect("Git object alternates must fail closed");
    assert_eq!(
        alternates_error.to_string(),
        "bounded-status rejects Git object alternates"
    );
}

#[test]
fn bounded_git_input_preflight_tolerates_nested_repository_boundaries() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::create_dir_all(repo_path.join(".worktrees/lane/src")).expect("create lane");
    fs::write(
        repo_path.join(".worktrees/lane/.git"),
        "gitdir: /tmp/fake-worktree\n",
    )
    .expect("write nested gitfile");
    fs::write(repo_path.join(".worktrees/lane/.gitignore"), "target/\n")
        .expect("write nested ignore");
    fs::create_dir_all(repo_path.join(".worktrees-quarantine-20260811/old"))
        .expect("create quarantine");
    fs::write(
        repo_path.join(".worktrees-quarantine-20260811/old/.git"),
        "gitdir: /tmp/fake-quarantine\n",
    )
    .expect("write quarantine gitfile");

    validate_bounded_git_text_inputs(
        &repo_path,
        repo.path(),
        repo.commondir(),
        Instant::now() + Duration::from_secs(2),
    )
    .expect("ignored worktree-store git markers must not fail prevalidation");

    fs::create_dir_all(repo_path.join("vendor")).expect("create vendor");
    fs::write(repo_path.join("vendor/.git"), "gitdir: /tmp/unsafe\n")
        .expect("write vendor gitfile");
    validate_bounded_git_text_inputs(
        &repo_path,
        repo.path(),
        repo.commondir(),
        Instant::now() + Duration::from_secs(2),
    )
    .expect("nested repositories outside runtime stores must be walk boundaries");
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_tolerates_nested_repository_directories_at_depth_and_as_siblings() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init outer repo");
    let outer = crate::git_repository::open(&repo_path).expect("open outer repo");
    commit_readme(&outer).expect("commit outer README");
    fs::write(repo_path.join("outer-visible.txt"), "outer\n").expect("write outer file");

    for relative in ["vendor/sdk-a", "vendor/sdk-b", "a/b/c"] {
        let nested_path = repo_path.join(relative);
        fs::create_dir_all(nested_path.parent().expect("nested parent"))
            .expect("create nested parent");
        let nested = Repository::init(&nested_path).expect("init nested repository");
        commit_readme(&nested).expect("commit nested README");
    }

    let records = bounded_worktree_records(
        &repo_path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_STATUS_TIMEOUT,
    )
    .expect("bounded status with nested repository directories");
    let visible = parse_nul_paths(&records.visible, MAX_WORKTREE_STATUS_ENTRIES)
        .expect("parse bounded visible paths");

    assert!(visible.contains(&PathBuf::from("README.md")));
    assert!(visible.contains(&PathBuf::from("outer-visible.txt")));
    for nested_file in [
        "vendor/sdk-a/README.md",
        "vendor/sdk-b/README.md",
        "a/b/c/README.md",
    ] {
        assert!(
            !visible.contains(&PathBuf::from(nested_file)),
            "nested repository content escaped the boundary: {nested_file}"
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_tolerates_nested_repository_gitfiles() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init outer repo");
    let outer = crate::git_repository::open(&repo_path).expect("open outer repo");
    commit_readme(&outer).expect("commit outer README");
    fs::write(repo_path.join("outer-visible.txt"), "outer\n").expect("write outer file");

    let nested_source = temp.path().join("nested-source");
    WorktreeManager::init_repository(&nested_source, "main").expect("init nested source");
    let nested = crate::git_repository::open(&nested_source).expect("open nested source");
    let nested_head = commit_readme(&nested).expect("commit nested README");
    let nested_commit = nested.find_commit(nested_head).expect("find nested commit");
    let nested_branch = nested
        .branch("linked", &nested_commit, false)
        .expect("create nested linked branch")
        .into_reference();
    let linked_path = repo_path.join("vendor/linked-[sdk]");
    fs::create_dir_all(linked_path.parent().expect("linked parent")).expect("create linked parent");
    fs::create_dir_all(repo_path.join("vendor/linked-s")).expect("create boundary-like sibling");
    fs::write(
        repo_path.join("vendor/linked-s/outer-sibling.txt"),
        "outer sibling\n",
    )
    .expect("write boundary-like sibling");
    let mut options = WorktreeAddOptions::new();
    options.reference(Some(&nested_branch));
    nested
        .worktree("linked-sdk", &linked_path, Some(&options))
        .expect("create linked nested worktree");
    assert!(linked_path.join(".git").is_file());

    let records = bounded_worktree_records(
        &repo_path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_STATUS_TIMEOUT,
    )
    .expect("bounded status with nested repository gitfile");
    let visible = parse_nul_paths(&records.visible, MAX_WORKTREE_STATUS_ENTRIES)
        .expect("parse bounded visible paths");

    assert!(visible.contains(&PathBuf::from("README.md")));
    assert!(visible.contains(&PathBuf::from("outer-visible.txt")));
    assert!(visible.contains(&PathBuf::from("vendor/linked-s/outer-sibling.txt")));
    assert!(!visible.contains(&PathBuf::from("vendor/linked-[sdk]/README.md")));
}

#[cfg(target_os = "linux")]
#[test]
fn bounded_status_accepts_real_gitlink_and_root_gitmodules_as_opaque_paths() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init outer repo");
    let outer = crate::git_repository::open(&repo_path).expect("open outer repo");
    commit_readme(&outer).expect("commit outer README");

    let nested_path = repo_path.join("vendor/sdk");
    fs::create_dir_all(nested_path.parent().expect("nested parent")).expect("create nested parent");
    let nested = Repository::init(&nested_path).expect("init nested repository");
    let nested_oid = commit_readme(&nested).expect("commit nested README");
    fs::write(
        repo_path.join(".gitmodules"),
        "[submodule \"vendor/sdk\"]\n\tpath = vendor/sdk\n\turl = ../sdk\n",
    )
    .expect("write root gitmodules");

    let mut index = outer.index().expect("open outer index");
    index
        .add_path(Path::new(".gitmodules"))
        .expect("add gitmodules");
    let gitlink_path = b"vendor/sdk".to_vec();
    index
        .add(&git2::IndexEntry {
            ctime: git2::IndexTime::new(0, 0),
            mtime: git2::IndexTime::new(0, 0),
            dev: 0,
            ino: 0,
            mode: 0o160000,
            uid: 0,
            gid: 0,
            file_size: 0,
            id: nested_oid,
            flags: u16::try_from(gitlink_path.len()).expect("gitlink path length"),
            flags_extended: 0,
            path: gitlink_path,
        })
        .expect("add real gitlink index entry");
    index.write().expect("write outer index");

    let records = bounded_worktree_records(
        &repo_path,
        MAX_WORKTREE_STATUS_ENTRIES,
        MAX_WORKTREE_STATUS_OUTPUT_BYTES,
        WORKTREE_STATUS_TIMEOUT,
    )
    .expect("bounded status with gitlink and root gitmodules");
    let visible = parse_nul_paths(&records.visible, MAX_WORKTREE_STATUS_ENTRIES)
        .expect("parse bounded visible paths");

    assert!(visible.contains(&PathBuf::from("README.md")));
    assert!(visible.contains(&PathBuf::from(".gitmodules")));
    assert!(visible.contains(&PathBuf::from("vendor/sdk")));
    assert!(!visible.contains(&PathBuf::from("vendor/sdk/README.md")));
}

#[cfg(unix)]
#[test]
fn bounded_git_input_preflight_does_not_follow_worktree_store_symlink() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let outside = temp.path().join("outside-store");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    fs::create_dir_all(outside.join("lane")).expect("create outside lane");
    fs::write(outside.join("lane/.git"), "gitdir: /tmp/outside\n").expect("write outside gitfile");
    symlink(&outside, repo_path.join(".worktrees")).expect("link worktree store");

    validate_bounded_git_text_inputs(
        &repo_path,
        repo.path(),
        repo.commondir(),
        Instant::now() + Duration::from_secs(2),
    )
    .expect("worktree-store symlink must be a no-follow boundary");
}

#[test]
fn bounded_status_rejects_unverified_side_effect_evidence() {
    let output = ProcessOutput {
        status: None,
        duration: Duration::ZERO,
        timed_out: false,
        process_tree: crate::process_runner::ProcessTreeEvidence::VerifiedEmpty(
            crate::process_runner::ContainmentBackend::DirectChild,
        ),
        side_effects: crate::process_runner::SideEffectConfinementEvidence::Unverified(
            crate::process_runner::SideEffectConfinementProfileKind::StrictOfflineWorkspace,
        ),
        stdout: crate::process_runner::CapturedBytes::default(),
        stderr: crate::process_runner::CapturedBytes::default(),
        process_error: None,
        stdin_error: None,
    };

    let error = require_verified_worktree_status_process(&output).unwrap_err();

    assert!(error
        .to_string()
        .contains("safety evidence was not verified"));
}

#[test]
fn initializes_repository_with_requested_initial_branch() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");

    let info = WorktreeManager::init_repository(&repo_path, "main").expect("init repo");

    assert_eq!(info.path, repo_path);
    assert_eq!(info.head, None);
    assert!(info.git_dir.ends_with(".git"));
}

#[cfg(unix)]
#[test]
fn repository_info_fails_closed_on_non_utf8_head_target() -> Result<()> {
    let temp = TempDir::new()?;
    let repository = Repository::init(temp.path())?;
    assert_eq!(repository_info(&repository)?.head, None);
    fs::write(repository.path().join("HEAD"), b"ref: refs/heads/non\xff\n")?;

    let error = repository_info(&repository).expect_err("non-UTF-8 HEAD must fail");
    assert!(error
        .to_string()
        .contains("repository HEAD symbolic target is not valid UTF-8"));
    Ok(())
}

#[test]
fn creates_lists_and_removes_worktree() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");

    let manager = WorktreeManager::new(&repo_path);
    let created = manager
        .create_for_test(WorktreeCreateOptions {
            agent_id: "agent-a".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root),
        })
        .expect("create worktree");

    assert_eq!(created.name, "agent-a");
    assert_eq!(created.branch, "maco/agent-a");
    assert!(created.path.join("README.md").exists());

    let listed = manager.list().expect("list worktrees");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].name, "agent-a");

    let removed = manager
        .remove("agent-a", true, true)
        .expect("force remove worktree");
    assert_eq!(removed.name, "agent-a");
    assert!(!removed.path.exists());
    assert!(repo.find_branch("maco/agent-a", BranchType::Local).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_defaults_to_dry_run_and_requires_apply_for_removal() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let repo_path = workspace.join("repo+name");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let worktree_root = workspace.join(".maco/worktrees/repo_name");
    let created = create_gc_worktree(
        &WorktreeManager::new(&repo_path),
        "sweep-default",
        &worktree_root,
    );

    let preview = sweep_workspace_worktrees(workspace_sweep_options(&workspace, false))
        .expect("preview workspace sweep");
    assert!(preview.dry_run);
    assert!(!preview.apply);
    assert_eq!(preview.repository_discovered_count, 1);
    assert_eq!(preview.repository_inspected_count, 1);
    assert_eq!(preview.repository_failure_count, 0);
    assert_eq!(preview.removed_count, 1);
    assert_eq!(
        preview.repositories[0].status,
        WorktreeSweepRepositoryStatus::Inspected
    );
    let preview_gc = preview.repositories[0]
        .gc_report
        .as_ref()
        .expect("preview GC report");
    assert_eq!(preview_gc.entries[0].status, WorktreeGcStatus::WouldRemove);
    assert_eq!(
        preview.apparent_considered_bytes,
        preview_gc.apparent_considered_bytes
    );
    assert_eq!(
        preview.estimated_reclaimable_bytes,
        preview_gc.estimated_reclaimable_bytes
    );
    assert_eq!(preview.estimated_reclaimed_bytes, 0);
    assert!(created.path.exists());

    let applied = sweep_workspace_worktrees(workspace_sweep_options(&workspace, true))
        .expect("apply workspace sweep");
    assert!(!applied.dry_run);
    assert!(applied.apply);
    assert_eq!(applied.removed_count, 1);
    assert_eq!(
        applied.repositories[0]
            .gc_report
            .as_ref()
            .expect("applied GC report")
            .entries[0]
            .status,
        WorktreeGcStatus::Removed
    );
    assert!(!created.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_discovers_repository_local_worktree_root() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let worktree_root = repo_path.join(".worktrees");
    let created = create_gc_worktree(
        &WorktreeManager::new(&repo_path),
        "repo-local-lane",
        &worktree_root,
    );

    let report = sweep_workspace_worktrees(workspace_sweep_options(&repo_path, false))
        .expect("sweep repository-local root");

    assert_eq!(
        report.discovery_status,
        WorktreeSweepDiscoveryStatus::RootsDiscovered
    );
    assert_eq!(report.worktree_root_discovered_count, 1);
    assert_eq!(report.repository_discovered_count, 1);
    assert_eq!(report.repository_inspected_count, 1);
    assert_eq!(report.considered_count, 1);
    assert_eq!(report.removed_count, 1, "{report:#?}");
    assert_eq!(
        report.repositories[0].root_kind,
        WorktreeSweepRootKind::RepositoryLocal
    );
    assert_eq!(report.repositories[0].worktree_root, worktree_root);
    assert!(created.path.exists(), "sweep remains dry-run by default");
}

#[cfg(target_os = "linux")]
#[test]
fn repository_local_sweep_uses_primary_hint_despite_stale_lane_metadata() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let worktree_root = repo_path.join(".worktrees");
    let created = create_gc_worktree(
        &WorktreeManager::new(&repo_path),
        "healthy-lane",
        &worktree_root,
    );
    let stale = worktree_root.join("stale-registration");
    fs::create_dir(&stale).expect("stale lane directory");
    fs::write(
        stale.join(".git"),
        "gitdir: /definitely/missing/worktree-metadata\n",
    )
    .expect("stale Git marker");

    let report = sweep_workspace_worktrees(workspace_sweep_options(&repo_path, false))
        .expect("repository-local primary hint remains authoritative");

    assert_eq!(report.repository_inspected_count, 1, "{report:#?}");
    assert_eq!(report.repository_pre_gc_skipped_count, 0, "{report:#?}");
    assert!(report.repositories[0]
        .gc_report
        .as_ref()
        .expect("GC report")
        .entries
        .iter()
        .any(|entry| {
            entry.name == created.name && entry.status == WorktreeGcStatus::WouldRemove
        }));
    assert!(created.path.exists());
    assert!(stale.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn repository_local_dry_run_previews_registered_only_untracked_lane() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = repo_path.join(".worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let oid = commit_readme(&repo).expect("initial commit");
    fs::create_dir(&worktree_root).expect("repository-local worktree root");
    let commit = repo.find_commit(oid).expect("commit");
    let branch = repo
        .branch("topic/legacy", &commit, false)
        .expect("legacy branch");
    let reference = branch.into_reference();
    let mut add = WorktreeAddOptions::new();
    add.reference(Some(&reference));
    let lane = worktree_root.join("legacy-lane");
    repo.worktree("legacy-lane", &lane, Some(&add))
        .expect("registered-only worktree");
    fs::write(lane.join("TASK.md"), "task brief\n").expect("untracked task brief");

    let state = repo.path().join("maco/state");
    fs::create_dir_all(&state).expect("legacy state directory");
    fs::set_permissions(&state, fs::Permissions::from_mode(0o755))
        .expect("legacy public state mode");

    let protected = sweep_workspace_worktrees(workspace_sweep_options(&repo_path, false))
        .expect("registered-only protected preview");
    let protected_entry = protected.repositories[0]
        .gc_report
        .as_ref()
        .expect("fallback preview")
        .entries
        .iter()
        .find(|entry| entry.name == "legacy-lane")
        .expect("legacy lane classification");
    assert_eq!(protected_entry.status, WorktreeGcStatus::Protected);
    assert_eq!(protected_entry.reason, WorktreeGcReason::UntrackedOnly);
    assert_eq!(
        protected_entry.untracked_paths,
        vec![PathBuf::from("TASK.md")]
    );

    let mut allowed = workspace_sweep_options(&repo_path, false);
    allowed.allowed_untracked_paths = vec![PathBuf::from("TASK.md")];
    let reclaimable = sweep_workspace_worktrees(allowed)
        .expect("registered-only reclaimable preview with exact override");
    let reclaimable_entry = reclaimable.repositories[0]
        .gc_report
        .as_ref()
        .expect("fallback preview")
        .entries
        .iter()
        .find(|entry| entry.name == "legacy-lane")
        .expect("legacy lane classification");
    assert_eq!(reclaimable_entry.status, WorktreeGcStatus::WouldRemove);
    assert_eq!(reclaimable_entry.reason, WorktreeGcReason::FinishedBranch);
    assert_eq!(
        reclaimable_entry.untracked_paths,
        vec![PathBuf::from("TASK.md")]
    );
    assert!(lane.exists(), "dry-run must preserve registered-only lane");
    assert!(lane.join("TASK.md").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_discovers_direct_child_repo_local_and_managed_roots_once_each() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let repo_path = workspace.join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let managed_root = workspace.join(".maco/worktrees/repo");
    let local_root = repo_path.join(".worktrees");
    let managed_old = create_gc_worktree(&manager, "managed-old-lane", &managed_root);
    fs::write(managed_old.path.join("sizing.bin"), vec![b'm'; 64 * 1024])
        .expect("managed old artifact");
    let managed_new = create_gc_worktree(&manager, "managed-new-lane", &managed_root);
    fs::write(managed_new.path.join("sizing.bin"), vec![b'n'; 64]).expect("managed new artifact");
    let local_old = create_gc_worktree(&manager, "local-old-lane", &local_root);
    fs::write(local_old.path.join("sizing.bin"), vec![b'l'; 128 * 1024])
        .expect("local old artifact");
    let local_new = create_gc_worktree(&manager, "local-new-lane", &local_root);
    fs::write(local_new.path.join("sizing.bin"), vec![b'r'; 128]).expect("local new artifact");
    let managed_old_size = gc_worktree_size_estimate(&managed_old.path).expect("managed old size");
    let managed_new_size = gc_worktree_size_estimate(&managed_new.path).expect("managed new size");
    let local_old_size = gc_worktree_size_estimate(&local_old.path).expect("local old size");
    let local_new_size = gc_worktree_size_estimate(&local_new.path).expect("local new size");
    let per_root_budget = managed_new_size
        .worktree_bytes
        .max(local_new_size.worktree_bytes);
    assert!(managed_old_size.worktree_bytes > per_root_budget);
    assert!(local_old_size.worktree_bytes > per_root_budget);

    let mut options = workspace_sweep_options(&workspace, false);
    options.remove_targets = false;
    options.retention.max_total_bytes = Some(per_root_budget);
    options.allowed_untracked_paths = vec![PathBuf::from("sizing.bin")];
    let report = sweep_workspace_worktrees(options).expect("sweep direct-child repository roots");

    assert_eq!(report.worktree_root_discovered_count, 2);
    assert_eq!(report.repository_inspected_count, 2);
    assert_eq!(report.considered_count, 4);
    assert_eq!(report.removed_count, 2, "{report:#?}");
    assert_eq!(report.retained_count, 2, "{report:#?}");
    let nested_apparent_bytes = report
        .repositories
        .iter()
        .try_fold(0u64, |total, entry| {
            total.checked_add(
                entry
                    .gc_report
                    .as_ref()
                    .expect("nested GC report")
                    .apparent_considered_bytes,
            )
        })
        .expect("nested apparent byte sum");
    let nested_reclaimable_bytes = report
        .repositories
        .iter()
        .try_fold(0u64, |total, entry| {
            total.checked_add(
                entry
                    .gc_report
                    .as_ref()
                    .expect("nested GC report")
                    .estimated_reclaimable_bytes,
            )
        })
        .expect("nested reclaimable byte sum");
    assert!(nested_apparent_bytes > 0);
    assert_eq!(report.apparent_considered_bytes, nested_apparent_bytes);
    assert_eq!(report.estimated_reclaimable_bytes, nested_reclaimable_bytes);
    assert_eq!(report.estimated_reclaimed_bytes, 0);
    assert_eq!(
        report
            .repositories
            .iter()
            .map(|entry| (
                entry.root_kind,
                entry.gc_report.as_ref().map(|gc| (
                    gc.considered_count,
                    gc.removed_count,
                    gc.retained_count,
                    gc.max_total_bytes,
                ))
            ))
            .collect::<Vec<_>>(),
        vec![
            (
                WorktreeSweepRootKind::WorkspaceManaged,
                Some((2, 1, 1, Some(per_root_budget))),
            ),
            (
                WorktreeSweepRootKind::RepositoryLocal,
                Some((2, 1, 1, Some(per_root_budget))),
            ),
        ]
    );
    for (root_kind, retained_name, expected_reclaimable) in [
        (
            WorktreeSweepRootKind::WorkspaceManaged,
            managed_new.name.as_str(),
            managed_old_size.worktree_bytes,
        ),
        (
            WorktreeSweepRootKind::RepositoryLocal,
            local_new.name.as_str(),
            local_old_size.worktree_bytes,
        ),
    ] {
        let gc = report
            .repositories
            .iter()
            .find(|entry| entry.root_kind == root_kind)
            .and_then(|entry| entry.gc_report.as_ref())
            .expect("per-root GC report");
        assert_eq!(gc.estimated_reclaimable_bytes, expected_reclaimable);
        assert!(gc.entries.iter().any(|entry| {
            entry.name == retained_name
                && entry.status == WorktreeGcStatus::Retained
                && entry.reason == WorktreeGcReason::RetentionKeep
        }));
    }
    assert!(managed_old.path.exists());
    assert!(managed_new.path.exists());
    assert!(local_old.path.exists());
    assert!(local_new.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_refuses_symlinked_repository_local_root() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let outside = temp.path().join("outside");
    fs::create_dir(&outside).expect("outside root");
    let sentinel = outside.join("sentinel");
    fs::write(&sentinel, "preserve\n").expect("outside sentinel");
    symlink(&outside, repo_path.join(".worktrees")).expect("symlink local root");

    let report = sweep_workspace_worktrees(workspace_sweep_options(&repo_path, true))
        .expect("typed symlinked root refusal");

    assert_eq!(report.worktree_root_discovered_count, 1);
    assert_eq!(report.repository_inspected_count, 0);
    assert_eq!(report.repository_pre_gc_skipped_count, 1);
    assert_eq!(
        report.repositories[0].root_kind,
        WorktreeSweepRootKind::RepositoryLocal
    );
    assert!(report.repositories[0]
        .failure
        .as_ref()
        .expect("typed refusal")
        .message
        .contains("not a plain directory"));
    assert!(sentinel.exists());
}

#[test]
fn workspace_sweep_reports_zero_roots_as_a_distinct_discovery_state() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    fs::create_dir(&workspace).expect("workspace");

    let report = sweep_workspace_worktrees(workspace_sweep_options(&workspace, false))
        .expect("empty workspace sweep");

    assert_eq!(
        report.discovery_status,
        WorktreeSweepDiscoveryStatus::NoRootsDiscovered
    );
    assert_eq!(report.worktree_root_discovered_count, 0);
    assert_eq!(report.repository_discovered_count, 0);
    assert_eq!(report.repository_inspected_count, 0);
    let json = serde_json::to_value(&report).expect("serialize sweep report");
    assert_eq!(json["discovery_status"], "no_roots_discovered");
    assert_eq!(json["worktree_root_discovered_count"], 0);

    let repo_path = temp.path().join("empty-repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init empty repo");
    let repo = crate::git_repository::open(&repo_path).expect("open empty repo");
    commit_readme(&repo).expect("initial empty repo commit");
    fs::create_dir(repo_path.join(".worktrees")).expect("empty supported root");

    let clean_empty = sweep_workspace_worktrees(workspace_sweep_options(&repo_path, false))
        .expect("sweep existing empty root");
    assert_eq!(
        clean_empty.discovery_status,
        WorktreeSweepDiscoveryStatus::RootsDiscovered
    );
    assert_eq!(clean_empty.worktree_root_discovered_count, 1);
    assert_eq!(clean_empty.repository_inspected_count, 1);
    assert_eq!(clean_empty.considered_count, 0);
    assert_eq!(clean_empty.removed_count, 0);
    assert_eq!(clean_empty.protected_count, 0);
    assert_eq!(clean_empty.retained_count, 0);
    let clean_json = serde_json::to_value(&clean_empty).expect("serialize clean empty sweep");
    assert_eq!(clean_json["discovery_status"], "roots_discovered");
    assert_ne!(json["discovery_status"], clean_json["discovery_status"]);
}

#[cfg(target_os = "linux")]
#[test]
fn gc_scopes_managed_bindings_to_the_exact_requested_root() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let local = create_gc_worktree(&manager, "local-lane", &repo_path.join(".worktrees"));
    let other = create_gc_worktree(&manager, "other-lane", &repo_path.join(".other-worktrees"));

    let report = manager
        .gc(gc_options(Some(PathBuf::from(".worktrees")), false))
        .expect("GC one relative managed root");

    assert_eq!(report.considered_count, 1);
    assert_eq!(report.removed_count, 1, "{report:#?}");
    assert!(!local.path.exists());
    assert!(other.path.exists());
    assert_eq!(manager.list().expect("remaining worktrees"), vec![other]);
}

#[cfg(target_os = "linux")]
#[test]
fn gc_without_requested_root_preserves_all_authenticated_root_scope() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let first = create_gc_worktree(&manager, "first-lane", &repo_path.join(".worktrees"));
    let second = create_gc_worktree(&manager, "second-lane", &repo_path.join(".other-worktrees"));

    let report = manager
        .gc(gc_options(None, false))
        .expect("default GC spans authenticated managed roots");

    assert_eq!(report.considered_count, 2);
    assert_eq!(report.removed_count, 2);
    assert!(!first.path.exists());
    assert!(!second.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_rejects_requested_root_beneath_intermediate_symlink() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let actual_parent = temp.path().join("actual-parent");
    fs::create_dir(&actual_parent).expect("actual parent");
    let actual_root = actual_parent.join("worktrees");
    let created = create_gc_worktree(&manager, "linked-root-lane", &actual_root);
    let linked_parent = temp.path().join("linked-parent");
    symlink(&actual_parent, &linked_parent).expect("intermediate parent symlink");

    let error = manager
        .gc(gc_options(Some(linked_parent.join("worktrees")), false))
        .expect_err("intermediate symlink must be rejected");

    assert!(error.to_string().contains("failed to bind worktree root"));
    assert!(created.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_inspects_repository_and_group_with_maco_prefix() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let repo_path = workspace.join(".maco-repository");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let worktree_root = workspace.join(".maco/worktrees/.maco-repository");
    let created = create_gc_worktree(
        &WorktreeManager::new(&repo_path),
        "prefixed-lane",
        &worktree_root,
    );

    let report = sweep_workspace_worktrees(workspace_sweep_options(&workspace, false))
        .expect("sweep prefixed repository");
    assert_eq!(report.repository_discovered_count, 1);
    assert_eq!(report.repository_inspected_count, 1);
    assert_eq!(report.repository_failure_count, 0);
    assert_eq!(report.repositories.len(), 1);
    assert_eq!(report.repositories[0].group, ".maco-repository");
    assert_eq!(
        report.repositories[0].status,
        WorktreeSweepRepositoryStatus::Inspected
    );
    assert_eq!(
        report.repositories[0].repository.as_deref(),
        Some(repo_path.as_path())
    );
    assert!(created.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_rejects_symlinked_metadata_root_before_outside_gc() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let repo_path = workspace.join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let outside_metadata = temp.path().join("outside-metadata");
    let outside_worktree_root = outside_metadata.join("worktrees/repo");
    let created = create_gc_worktree(
        &WorktreeManager::new(&repo_path),
        "outside-lane",
        &outside_worktree_root,
    );
    symlink(&outside_metadata, workspace.join(".maco")).expect("link metadata root");

    let error = sweep_workspace_worktrees(workspace_sweep_options(&workspace, true))
        .expect_err("symlinked metadata root must fail closed");
    assert!(error
        .to_string()
        .contains("workspace metadata root is not a plain directory"));
    assert!(created.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_reports_symlinked_group_and_continues_valid_group() {
    skip_without_containment!();
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let linked_repo_path = workspace.join("a-linked");
    WorktreeManager::init_repository(&linked_repo_path, "main").expect("init linked repo");
    let linked_repo = crate::git_repository::open(&linked_repo_path).expect("open linked repo");
    commit_readme(&linked_repo).expect("initial linked commit");
    let outside_group = temp.path().join("outside-group");
    let outside_lane = create_gc_worktree(
        &WorktreeManager::new(&linked_repo_path),
        "outside-lane",
        &outside_group,
    );

    let valid_repo_path = workspace.join("z-valid");
    WorktreeManager::init_repository(&valid_repo_path, "main").expect("init valid repo");
    let valid_repo = crate::git_repository::open(&valid_repo_path).expect("open valid repo");
    commit_readme(&valid_repo).expect("initial valid commit");
    let worktrees_root = workspace.join(".maco/worktrees");
    let valid_group = worktrees_root.join("z-valid");
    let valid_lane = create_gc_worktree(
        &WorktreeManager::new(&valid_repo_path),
        "valid-lane",
        &valid_group,
    );
    symlink(&outside_group, worktrees_root.join("a-linked")).expect("link group");

    let report = sweep_workspace_worktrees(workspace_sweep_options(&workspace, true))
        .expect("sweep with symlinked group");
    assert_eq!(report.repository_discovered_count, 2);
    assert_eq!(report.repository_inspected_count, 1);
    assert_eq!(report.repository_pre_gc_skipped_count, 1);
    assert_eq!(report.repository_gc_failed_count, 0);
    assert_eq!(report.repository_failure_count, 1);
    assert_eq!(
        report
            .repositories
            .iter()
            .map(|entry| entry.group.as_str())
            .collect::<Vec<_>>(),
        vec!["a-linked", "z-valid"]
    );
    let linked = &report.repositories[0];
    assert_eq!(linked.status, WorktreeSweepRepositoryStatus::Skipped);
    assert!(!linked.gc_attempted);
    assert!(!linked.effects_may_have_occurred);
    assert_eq!(
        linked.failure.as_ref().expect("typed group failure").kind,
        WorktreeSweepFailureKind::RepositoryAssociation
    );
    assert!(linked
        .failure
        .as_ref()
        .expect("group failure")
        .message
        .contains("not a plain directory"));
    assert_eq!(
        report.repositories[1].status,
        WorktreeSweepRepositoryStatus::Inspected
    );
    assert!(outside_lane.path.exists());
    assert!(!valid_lane.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_continues_after_typed_repository_open_failure() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let repo_path = workspace.join("valid+repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let valid_root = workspace.join(".maco/worktrees/valid_repo");
    let valid = create_gc_worktree(&WorktreeManager::new(&repo_path), "valid-lane", &valid_root);
    let broken_lane = workspace.join(".maco/worktrees/broken/lane");
    fs::create_dir_all(&broken_lane).expect("broken lane");
    fs::write(
        broken_lane.join(".git"),
        "gitdir: /definitely/missing/git-dir\n",
    )
    .expect("broken Git marker");

    let first = sweep_workspace_worktrees(workspace_sweep_options(&workspace, false))
        .expect("workspace sweep with broken group");
    let second = sweep_workspace_worktrees(workspace_sweep_options(&workspace, false))
        .expect("repeat deterministic workspace sweep");
    assert_eq!(
        serde_json::to_string(&first).expect("serialize first report"),
        serde_json::to_string(&second).expect("serialize second report")
    );
    assert_eq!(first.repository_discovered_count, 2);
    assert_eq!(first.repository_inspected_count, 1);
    assert_eq!(first.repository_pre_gc_skipped_count, 1);
    assert_eq!(first.repository_gc_failed_count, 0);
    assert_eq!(first.repository_failure_count, 1);
    assert_eq!(
        first
            .repositories
            .iter()
            .map(|entry| entry.group.as_str())
            .collect::<Vec<_>>(),
        vec!["broken", "valid_repo"]
    );
    let broken = &first.repositories[0];
    assert_eq!(broken.status, WorktreeSweepRepositoryStatus::Skipped);
    assert!(!broken.gc_attempted);
    assert!(!broken.effects_may_have_occurred);
    assert_eq!(
        broken.failure.as_ref().expect("typed open failure").kind,
        WorktreeSweepFailureKind::RepositoryOpen
    );
    assert_eq!(
        serde_json::to_value(broken)
            .expect("serialize broken entry")
            .get("status"),
        Some(&serde_json::json!("skipped"))
    );
    assert_eq!(
        first.repositories[1].status,
        WorktreeSweepRepositoryStatus::Inspected
    );
    assert!(valid.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_passes_retention_and_keep_target_options_to_gc() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let repo_path = workspace.join("retained+repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let worktree_root = workspace.join(".maco/worktrees/retained_repo");
    let old = create_gc_worktree(
        &WorktreeManager::new(&repo_path),
        "retention-old",
        &worktree_root,
    );
    let new = create_gc_worktree(
        &WorktreeManager::new(&repo_path),
        "retention-new",
        &worktree_root,
    );
    fs::create_dir_all(new.path.join("target/debug")).expect("new target");
    let mut options = workspace_sweep_options(&workspace, false);
    options.remove_targets = false;
    options.retention = WorktreeRetentionPolicy {
        max_age: Some(Duration::from_secs(3600)),
        max_count: Some(1),
        max_total_bytes: Some(u64::MAX),
    };

    let report = sweep_workspace_worktrees(options).expect("retained workspace sweep");
    assert_eq!(report.max_age_seconds, Some(3600));
    assert_eq!(report.max_count, Some(1));
    assert_eq!(report.max_total_bytes, Some(u64::MAX));
    assert!(!report.remove_targets);
    assert_eq!(report.removed_count, 1, "{report:#?}");
    assert_eq!(report.retained_count, 1);
    assert_eq!(report.target_removed_count, 0);
    let gc = report.repositories[0]
        .gc_report
        .as_ref()
        .expect("nested GC report");
    assert_eq!(gc.max_age_seconds, Some(3600));
    assert_eq!(gc.max_count, Some(1));
    assert_eq!(gc.max_total_bytes, Some(u64::MAX));
    assert!(!gc.remove_targets);
    assert!(gc.entries.iter().any(|entry| {
        entry.status == WorktreeGcStatus::Retained
            && entry.reason == WorktreeGcReason::RetentionKeep
    }));
    assert!(old.path.exists());
    assert!(new.path.exists());
    assert!(new.path.join("target").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_inherits_combined_active_claim_and_lease_protection() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let repo_path = workspace.join("protected+repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let worktree_root = workspace.join(".maco/worktrees/protected_repo");
    let claimed = create_gc_worktree(&manager, "claimed-lane", &worktree_root);
    let leased = create_gc_worktree(&manager, "leased-lane", &worktree_root);
    SyncStore::open(&repo_path)
        .expect("open claims")
        .claim_paths("claimed-lane", [PathBuf::from("src")])
        .expect("claim path");
    let _lease = manager
        .acquire_read_execution_lease("leased-lane")
        .expect("active lease");

    let report = sweep_workspace_worktrees(workspace_sweep_options(&workspace, true))
        .expect("protected workspace sweep");
    assert_eq!(report.repository_inspected_count, 1);
    assert_eq!(report.protected_count, 2);
    assert_eq!(report.removed_count, 0);
    let reasons = report.repositories[0]
        .gc_report
        .as_ref()
        .expect("nested GC report")
        .entries
        .iter()
        .map(|entry| entry.reason)
        .collect::<Vec<_>>();
    assert_eq!(reasons.len(), 2);
    assert!(reasons.contains(&WorktreeGcReason::ActiveClaim));
    assert!(reasons.contains(&WorktreeGcReason::ActiveLease));
    assert!(claimed.path.exists());
    assert!(leased.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn workspace_sweep_marks_gc_error_as_effectful_failure_without_clean_report() {
    let temp = TempDir::new().expect("tempdir");
    let workspace = temp.path().join("workspace");
    let repo_path = workspace.join("orphan+repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let orphan = workspace.join(".maco/worktrees/orphan_repo/plain-orphan");
    fs::create_dir_all(&orphan).expect("orphan lane");

    let report = sweep_workspace_worktrees(workspace_sweep_options(&workspace, true))
        .expect("aggregate GC failure");
    assert_eq!(report.repository_discovered_count, 1);
    assert_eq!(report.repository_inspected_count, 0);
    assert_eq!(report.repository_pre_gc_skipped_count, 0);
    assert_eq!(report.repository_gc_failed_count, 1);
    assert_eq!(report.repository_failure_count, 1);
    let failed = &report.repositories[0];
    assert_eq!(failed.status, WorktreeSweepRepositoryStatus::Failed);
    assert!(failed.gc_attempted);
    assert!(failed.effects_may_have_occurred);
    assert!(failed.gc_report.is_none());
    assert_eq!(
        failed.failure.as_ref().expect("typed GC failure").kind,
        WorktreeSweepFailureKind::GarbageCollection
    );
    assert!(orphan.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_removes_finished_clean_worktree_and_keeps_branch() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "agent-finished", &worktree_root);

    let report = manager
        .gc(gc_options(Some(worktree_root.clone()), false))
        .expect("gc finished worktree");

    assert_eq!(report.removed_count, 1, "{report:#?}");
    assert_eq!(report.entries[0].status, WorktreeGcStatus::Removed);
    assert_eq!(report.entries[0].reason, WorktreeGcReason::FinishedBranch);
    assert!(!created.path.exists());
    assert!(repo
        .find_branch("maco/agent-finished", BranchType::Local)
        .is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_protects_dirty_worktree() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "agent-dirty-gc", &worktree_root);
    fs::write(created.path.join("README.md"), "tracked local work\n")
        .expect("dirty tracked worktree");

    let report = manager
        .gc(gc_options(Some(worktree_root), false))
        .expect("gc dirty worktree");

    assert_eq!(report.removed_count, 0);
    assert_eq!(report.protected_count, 1);
    assert_eq!(report.entries[0].status, WorktreeGcStatus::Protected);
    assert_eq!(report.entries[0].reason, WorktreeGcReason::Dirty);
    assert!(report.entries[0].untracked_paths.is_empty());
    assert!(created.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_classifies_untracked_only_and_requires_exact_allowlist_for_lane_removal() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "agent-untracked-gc", &worktree_root);
    fs::write(created.path.join("TASK.md"), "task brief\n").expect("untracked task brief");

    let protected = manager
        .gc(gc_options(Some(worktree_root.clone()), false))
        .expect("classify untracked-only worktree");

    assert_eq!(protected.removed_count, 0);
    assert_eq!(protected.protected_count, 1);
    assert_eq!(protected.entries[0].status, WorktreeGcStatus::Protected);
    assert_eq!(protected.entries[0].reason, WorktreeGcReason::UntrackedOnly);
    assert_eq!(
        protected.entries[0].untracked_paths,
        vec![PathBuf::from("TASK.md")]
    );
    assert!(created.path.exists());

    fs::write(created.path.join("result.txt"), "worker output\n").expect("second untracked output");
    let mut partial = gc_options(Some(worktree_root.clone()), false);
    partial.allowed_untracked_paths = vec![PathBuf::from("TASK.md")];
    let partially_allowed = manager
        .gc(partial)
        .expect("partial allowlist remains protected");
    assert_eq!(partially_allowed.removed_count, 0);
    assert_eq!(partially_allowed.protected_count, 1);
    assert_eq!(
        partially_allowed.entries[0].reason,
        WorktreeGcReason::UntrackedOnly
    );
    assert!(partially_allowed.entries[0]
        .untracked_paths
        .contains(&PathBuf::from("result.txt")));
    assert!(created.path.exists());
    fs::remove_file(created.path.join("result.txt")).expect("remove second output");

    let mut allowed = gc_options(Some(worktree_root), false);
    allowed.allowed_untracked_paths = vec![PathBuf::from("TASK.md")];
    let reclaimed = manager
        .gc(allowed)
        .expect("reclaim explicitly allowed task brief");

    assert_eq!(reclaimed.removed_count, 1);
    assert_eq!(reclaimed.protected_count, 0);
    assert_eq!(
        reclaimed.allowed_untracked_paths,
        vec![PathBuf::from("TASK.md")]
    );
    assert_eq!(reclaimed.entries[0].status, WorktreeGcStatus::Removed);
    assert_eq!(
        reclaimed.entries[0].untracked_paths,
        vec![PathBuf::from("TASK.md")]
    );
    assert!(!created.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_protects_ignored_only_output_until_its_exact_path_is_allowed() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    commit_descendant(&repo, ".gitignore", "scratch/\n").expect("ignore scratch");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "ignored-output", &worktree_root);
    fs::create_dir(created.path.join("scratch")).expect("scratch directory");
    fs::write(created.path.join("scratch/result.bin"), "only copy\n")
        .expect("ignored worker output");

    let protected = manager
        .gc(gc_options(Some(worktree_root.clone()), false))
        .expect("ignored-only protection");
    assert_eq!(protected.removed_count, 0, "{protected:#?}");
    assert_eq!(protected.protected_count, 1, "{protected:#?}");
    assert_eq!(protected.entries[0].reason, WorktreeGcReason::UntrackedOnly);
    assert_eq!(
        protected.entries[0].untracked_paths,
        vec![PathBuf::from("scratch/result.bin")]
    );
    assert!(created.path.exists());

    let mut allowed = gc_options(Some(worktree_root), false);
    allowed.allowed_untracked_paths = vec![PathBuf::from("scratch/result.bin")];
    let reclaimed = manager.gc(allowed).expect("exact ignored path reclaim");
    assert_eq!(reclaimed.removed_count, 1, "{reclaimed:#?}");
    assert!(!created.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn hosted_runner_cgroup_is_classified_as_gc_trusted_fallback() {
    let hosted = anyhow::Error::from(ProcessRunError::EnvironmentFailure {
        label: "bounded managed-worktree index listing".to_string(),
        command: "/usr/bin/git ls-files".to_string(),
        failure: Box::new(
            crate::external_agent::EnvironmentFailure::sandbox_unavailable(
                "current cgroup /system.slice/hosted-compute-agent.service is not inside a delegated systemd user manager"
                    .to_string(),
            ),
        ),
        target_process_started: false,
    })
    .context("bounded worktree status command failed")
    .context("merged-lane worktree reaping failed");
    assert!(gc_status_failed_without_delegated_user_manager(&hosted));
    assert!(!gc_status_failed_without_delegated_user_manager(
        &anyhow::Error::msg("bounded worktree status command failed: dirty index")
    ));
}

#[cfg(target_os = "linux")]
#[test]
fn gc_refuses_late_ignored_output_after_reviewed_snapshot() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    commit_descendant(&repo, ".gitignore", "scratch/\n").expect("ignore scratch");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "late-ignored-output", &worktree_root);
    fs::create_dir(created.path.join("scratch")).expect("scratch directory");
    fs::write(created.path.join("scratch/approved.bin"), "approved\n")
        .expect("approved ignored output");
    fs::create_dir_all(created.path.join("target/debug")).expect("target");
    let mut options = gc_options(Some(worktree_root), false);
    options.allowed_untracked_paths = vec![PathBuf::from("scratch/approved.bin")];
    let report = manager
        .gc_with_target_liveness(options, |_| {
            fs::write(created.path.join("scratch/late.bin"), "only copy\n")
                .expect("late ignored output");
            WorktreeTargetLiveness::Clear
        })
        .expect("late ignored output protection");
    assert_eq!(report.removed_count, 0, "{report:#?}");
    assert_eq!(report.protected_count, 1, "{report:#?}");
    assert_eq!(report.entries[0].reason, WorktreeGcReason::UntrackedOnly);
    assert!(report.entries[0]
        .untracked_paths
        .contains(&PathBuf::from("scratch/late.bin")));
    assert!(created.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_ignored_inventory_excludes_large_runtime_categories_before_bounds() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    commit_descendant(&repo, ".gitignore", "scratch/\n").expect("ignore scratch");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "runtime-inventory", &worktree_root);
    for root in ["target/debug", ".agents/temp/runtime"] {
        fs::create_dir_all(created.path.join(root)).expect("runtime directory");
        for index in 0..3 {
            fs::write(created.path.join(root).join(index.to_string()), "runtime\n")
                .expect("runtime entry");
        }
    }
    assert!(matches!(
        gc_worktree_dirtiness(&created.path).expect("runtime-only dirtiness"),
        WorktreeGcDirtiness::Clean
    ));
    let runtime_only =
        bounded_repository_gc_status_paths(&created.path, 4, 4096, WORKTREE_GC_STATUS_TIMEOUT)
            .expect("runtime inventory must not spend ignored entry bounds");
    assert!(runtime_only.is_empty());

    fs::create_dir(created.path.join("scratch")).expect("scratch directory");
    fs::write(created.path.join("scratch/output.bin"), "only copy\n")
        .expect("arbitrary ignored output");
    let with_output =
        bounded_repository_gc_status_paths(&created.path, 4, 4096, WORKTREE_GC_STATUS_TIMEOUT)
            .expect("one arbitrary ignored path fits the bound");
    assert_eq!(
        with_output,
        vec![(PathBuf::from("scratch/output.bin"), [b'?', b'?'])]
    );
    for index in 0..5 {
        fs::write(
            created.path.join("scratch").join(format!("extra-{index}")),
            "ignored\n",
        )
        .expect("extra arbitrary ignored output");
    }
    let general_status =
        bounded_repository_status_paths(&created.path, 4, 4096, WORKTREE_GC_STATUS_TIMEOUT)
            .expect("general status must not collect or spend bounds on ignored inventory");
    assert!(general_status.is_empty());
}

#[test]
fn gc_rejects_non_exact_untracked_allowlist_paths() {
    let absolute = normalize_gc_allowed_untracked_paths(&[PathBuf::from("/tmp/TASK.md")])
        .expect_err("absolute allowlist path");
    assert!(absolute
        .to_string()
        .contains("must be an exact repository-relative path"));
    let escaping = normalize_gc_allowed_untracked_paths(&[PathBuf::from("../TASK.md")])
        .expect_err("escaping allowlist path");
    assert!(escaping
        .to_string()
        .contains("must be an exact repository-relative path"));
}

#[cfg(unix)]
#[test]
fn gc_report_serializes_non_utf8_untracked_paths_losslessly_and_escapes_human_text() {
    skip_without_containment!();
    use std::os::unix::ffi::OsStringExt;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "agent-non-utf8-gc", &worktree_root);
    let raw_name = b"odd,\n\t-\xff.txt".to_vec();
    let relative = PathBuf::from(OsString::from_vec(raw_name.clone()));
    fs::write(created.path.join(&relative), "worker output\n").expect("non-UTF-8 output");

    let report = manager
        .gc(gc_options(Some(worktree_root), true))
        .expect("classify non-UTF-8 output");
    let json = serde_json::to_value(&report).expect("lossless report JSON");
    let wire = &json["entries"][0]["untracked_paths"][0];
    assert_eq!(wire["encoding"], "unix-bytes-hex-v1");
    assert_eq!(
        wire["data"],
        raw_name
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    );
    let human = worktree_report_path_text(&relative);
    assert_eq!(human, "odd\\x2C\\n\\t-\\xFF.txt");
    assert!(!human.contains(','));
    assert!(!human.contains('\n'));
    assert!(!human.contains('\t'));
}

#[test]
fn gc_untracked_allowlist_is_bounded_before_report_cloning() {
    let too_many = vec![PathBuf::from("TASK.md"); MAX_GC_ALLOWED_UNTRACKED_PATHS + 1];
    assert!(normalize_gc_allowed_untracked_paths(&too_many)
        .expect_err("entry bound")
        .to_string()
        .contains("entry limit"));

    let oversized = PathBuf::from("x".repeat(MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES + 1));
    assert!(normalize_gc_allowed_untracked_paths(&[oversized])
        .expect_err("path byte bound")
        .to_string()
        .contains("byte limit"));

    let aggregate = vec![
        PathBuf::from("x".repeat(MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES));
        MAX_GC_ALLOWED_UNTRACKED_TOTAL_BYTES / MAX_GC_ALLOWED_UNTRACKED_PATH_BYTES
            + 1
    ];
    assert!(normalize_gc_allowed_untracked_paths(&aggregate)
        .expect_err("aggregate byte bound")
        .to_string()
        .contains("aggregate limit"));
}

#[cfg(target_os = "linux")]
#[test]
fn gc_protects_active_execution_lease() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "agent-leased-gc", &worktree_root);
    let _lease = manager
        .acquire_read_execution_lease("agent-leased-gc")
        .expect("active read lease");

    let report = manager
        .gc(gc_options(Some(worktree_root), false))
        .expect("gc leased worktree");

    assert_eq!(report.removed_count, 0);
    assert_eq!(report.protected_count, 1);
    assert_eq!(report.entries[0].status, WorktreeGcStatus::Protected);
    assert_eq!(report.entries[0].reason, WorktreeGcReason::ActiveLease);
    assert!(created.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_protects_active_path_claim_for_agent() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "agent-claimed-gc", &worktree_root);
    SyncStore::open(&repo_path)
        .expect("open claims")
        .claim_paths("agent-claimed-gc", [PathBuf::from("src")])
        .expect("claim path");

    let report = manager
        .gc(gc_options(Some(worktree_root), false))
        .expect("gc claimed worktree");

    assert_eq!(report.removed_count, 0);
    assert_eq!(report.protected_count, 1);
    assert_eq!(report.entries[0].status, WorktreeGcStatus::Protected);
    assert_eq!(report.entries[0].reason, WorktreeGcReason::ActiveClaim);
    assert!(created.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_retention_keeps_newest_and_removes_retained_target() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let old = create_gc_worktree(&manager, "agent-old-gc", &worktree_root);
    let new = create_gc_worktree(&manager, "agent-new-gc", &worktree_root);
    fs::create_dir_all(old.path.join("target/debug")).expect("old target");
    fs::create_dir_all(new.path.join("target/debug")).expect("new target");

    let report = manager
        .gc_with_target_liveness(
            WorktreeGcOptions {
                worktree_root: Some(worktree_root),
                dry_run: false,
                remove_targets: true,
                targets_only: false,
                retention: WorktreeRetentionPolicy {
                    max_age: None,
                    max_count: Some(1),
                    max_total_bytes: None,
                },
                allowed_untracked_paths: Vec::new(),
                exclude_agent_id: None,
                candidate_agent_ids: None,
                merged_into_reference: None,
                superseded_by_agent_id: BTreeMap::new(),
                machine_global_retention: None,
            },
            |_| WorktreeTargetLiveness::Clear,
        )
        .expect("gc with retention");

    assert_eq!(report.removed_count, 1, "{report:#?}");
    assert_eq!(report.retained_count, 1);
    assert_eq!(report.target_removed_count, 1, "{report:#?}");
    assert!(!old.path.exists());
    assert!(new.path.exists());
    assert!(!new.path.join("target").exists());
    assert!(report.entries.iter().any(
        |entry| entry.name == "agent-new-gc" && entry.reason == WorktreeGcReason::TargetRemoved
    ));
}

#[test]
fn retention_keep_order_prefers_higher_rebuild_cost_per_byte() {
    use std::cmp::Ordering;
    let expensive = RetentionKeepKey {
        rebuild_cost_ms: Some(35 * 60 * 1000),
        apparent_bytes: 6_900,
        created_at_unix_nanos: 1,
        name: "expensive-old",
    };
    let cheap = RetentionKeepKey {
        rebuild_cost_ms: Some(2 * 60 * 1000),
        apparent_bytes: 6_900,
        created_at_unix_nanos: 2,
        name: "cheap-new",
    };
    assert_eq!(
        cmp_retention_keep_order(&expensive, &cheap),
        Ordering::Less,
        "expensive-to-rebuild lane must sort ahead of a same-sized cheap lane"
    );
    let old = RetentionKeepKey {
        rebuild_cost_ms: None,
        apparent_bytes: 100,
        created_at_unix_nanos: 1,
        name: "old",
    };
    let new = RetentionKeepKey {
        rebuild_cost_ms: None,
        apparent_bytes: 100,
        created_at_unix_nanos: 2,
        name: "new",
    };
    assert_eq!(
        cmp_retention_keep_order(&old, &new),
        Ordering::Greater,
        "unknown cost must keep recency (newest first)"
    );
    let old_known = RetentionKeepKey {
        rebuild_cost_ms: Some(1),
        ..old
    };
    assert_eq!(
        cmp_retention_keep_order(&old_known, &new),
        Ordering::Greater,
        "mixed known/unknown cost must not invert recency"
    );
}

#[test]
fn lane_rebuild_cost_sidecar_round_trips_and_ignores_garbage() {
    let temp = TempDir::new().expect("tempdir");
    let lane = temp.path().join("lane");
    fs::create_dir(&lane).expect("lane");
    assert_eq!(load_lane_rebuild_cost(&lane), None);
    record_lane_rebuild_cost(&lane, 2_100_000).expect("record");
    assert_eq!(load_lane_rebuild_cost(&lane), Some(2_100_000));
    fs::write(lane.join(LANE_REBUILD_COST_RELATIVE), "{not-json").expect("corrupt");
    assert_eq!(load_lane_rebuild_cost(&lane), None);
}

#[cfg(target_os = "linux")]
#[test]
fn gc_size_retention_keeps_expensive_rebuild_ahead_of_newer_cheap_lane() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let expensive = create_gc_worktree(&manager, "cost-expensive", &worktree_root);
    fs::create_dir_all(expensive.path.join("target/debug")).expect("expensive target");
    fs::write(
        expensive.path.join("target/debug/artifact"),
        vec![b'e'; 32 * 1024],
    )
    .expect("expensive artifact");
    record_lane_rebuild_cost(&expensive.path, 35 * 60 * 1000).expect("expensive cost");
    let cheap = create_gc_worktree(&manager, "cost-cheap", &worktree_root);
    fs::create_dir_all(cheap.path.join("target/debug")).expect("cheap target");
    fs::write(
        cheap.path.join("target/debug/artifact"),
        vec![b'c'; 32 * 1024],
    )
    .expect("cheap artifact");
    record_lane_rebuild_cost(&cheap.path, 2 * 60 * 1000).expect("cheap cost");
    let expensive_size = gc_worktree_size_estimate(&expensive.path).expect("expensive size");
    let cheap_size = gc_worktree_size_estimate(&cheap.path).expect("cheap size");
    let budget = expensive_size.worktree_bytes.max(cheap_size.worktree_bytes);

    let mut options = gc_options(Some(worktree_root), false);
    options.remove_targets = false;
    options.retention.max_total_bytes = Some(budget);
    let report = manager
        .gc_with_target_liveness(options, |_| WorktreeTargetLiveness::Clear)
        .expect("cost-aware GC");

    assert_eq!(report.removed_count, 1, "{report:#?}");
    assert_eq!(report.retained_count, 1, "{report:#?}");
    let removed = report
        .entries
        .iter()
        .find(|entry| entry.status == WorktreeGcStatus::Removed)
        .expect("removed entry");
    assert_eq!(removed.name, cheap.name);
    assert!(expensive.path.exists());
    assert!(!cheap.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_size_retention_keeps_the_newest_prefix_and_counts_lane_bytes_once() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let protected = create_gc_worktree(&manager, "size-protected", &worktree_root);
    fs::write(protected.path.join("README.md"), vec![b'p'; 64 * 1024])
        .expect("protected tracked edit");
    let old = create_gc_worktree(&manager, "size-old", &worktree_root);
    fs::create_dir_all(old.path.join("target/debug")).expect("old target");
    fs::write(
        old.path.join("target/debug/artifact"),
        vec![b'o'; 32 * 1024],
    )
    .expect("old artifact");
    let new = create_gc_worktree(&manager, "size-new", &worktree_root);
    fs::create_dir_all(new.path.join("target/debug")).expect("new target");
    fs::write(new.path.join("target/debug/artifact"), vec![b'n'; 128]).expect("new artifact");
    let protected_size = gc_worktree_size_estimate(&protected.path).expect("protected size");
    let old_size = gc_worktree_size_estimate(&old.path).expect("old size");
    let new_size = gc_worktree_size_estimate(&new.path).expect("new size");
    assert!(old_size.worktree_bytes > new_size.worktree_bytes);

    let mut options = gc_options(Some(worktree_root), false);
    options.remove_targets = false;
    options.retention.max_total_bytes = Some(new_size.worktree_bytes);
    let report = manager
        .gc_with_target_liveness(options, |_| WorktreeTargetLiveness::Clear)
        .expect("size-retained GC");

    assert_eq!(report.max_total_bytes, Some(new_size.worktree_bytes));
    assert_eq!(report.removed_count, 1, "{report:#?}");
    assert_eq!(report.retained_count, 1, "{report:#?}");
    assert_eq!(report.protected_count, 1, "{report:#?}");
    assert_eq!(
        report.apparent_considered_bytes,
        protected_size
            .worktree_bytes
            .checked_add(old_size.worktree_bytes)
            .expect("test protected and old size sum")
            .checked_add(new_size.worktree_bytes)
            .expect("test size sum")
    );
    assert_eq!(report.estimated_reclaimable_bytes, old_size.worktree_bytes);
    assert_eq!(report.estimated_reclaimed_bytes, old_size.worktree_bytes);
    let json = serde_json::to_value(&report).expect("serialize size report");
    assert_eq!(json["max_total_bytes"], new_size.worktree_bytes);
    assert_eq!(json["estimated_reclaimable_bytes"], old_size.worktree_bytes);
    assert!(
        old_size.target_bytes.expect("old target size") < old_size.worktree_bytes,
        "full-lane bytes must include, not double-count, target bytes"
    );
    let removed = report
        .entries
        .iter()
        .find(|entry| entry.name == old.name)
        .expect("removed size entry");
    assert_eq!(
        removed.apparent_worktree_bytes,
        Some(old_size.worktree_bytes)
    );
    assert_eq!(removed.apparent_target_bytes, old_size.target_bytes);
    assert!(!old.path.exists());
    assert!(protected.path.exists());
    assert!(new.path.exists());
    assert!(new.path.join("target").exists());
    assert!(repo.find_branch(&old.branch, BranchType::Local).is_ok());
    assert_eq!(
        report
            .entries
            .iter()
            .find(|entry| entry.name == protected.name)
            .expect("protected size entry")
            .reason,
        WorktreeGcReason::Dirty
    );
}

#[cfg(target_os = "linux")]
#[test]
fn gc_late_protection_does_not_consume_count_or_size_retention() {
    skip_without_containment!();
    // Conservative retention bias: a live/dirty hold must not evict an older
    // finished lane. Protected candidates stay off the max_count / size budget.
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let old = create_gc_worktree(&manager, "late-protection-old", &worktree_root);
    fs::create_dir_all(old.path.join("target/debug")).expect("old target");
    fs::write(old.path.join("target/debug/artifact"), vec![b'o'; 64]).expect("old artifact");
    let new = create_gc_worktree(&manager, "late-protection-new", &worktree_root);
    fs::create_dir_all(new.path.join("target/debug")).expect("new target");
    fs::write(
        new.path.join("target/debug/artifact"),
        vec![b'n'; 64 * 1024],
    )
    .expect("new artifact");
    let old_size = gc_worktree_size_estimate(&old.path).expect("old size");
    let new_size = gc_worktree_size_estimate(&new.path).expect("new size");
    assert!(new_size.worktree_bytes > old_size.worktree_bytes);

    let mut options = gc_options(Some(worktree_root), false);
    options.remove_targets = false;
    options.retention = WorktreeRetentionPolicy {
        max_age: None,
        max_count: Some(1),
        max_total_bytes: Some(old_size.worktree_bytes),
    };
    let liveness_calls = std::cell::Cell::new(0usize);
    let report = manager
        .gc_with_target_liveness(options, |target| {
            liveness_calls.set(liveness_calls.get().saturating_add(1));
            assert_eq!(target.path, new.path.join("target"));
            test_live_target_liveness()
        })
        .expect("late-protected retention GC");

    assert_eq!(liveness_calls.get(), 1, "retained lane is not probed");
    assert_eq!(report.removed_count, 0, "{report:#?}");
    assert_eq!(report.retained_count, 1, "{report:#?}");
    assert_eq!(report.protected_count, 1, "{report:#?}");
    assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
    assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
    assert_eq!(
        report
            .entries
            .iter()
            .find(|entry| entry.name == new.name)
            .expect("new protected entry")
            .reason,
        WorktreeGcReason::LiveTarget
    );
    assert_eq!(
        report
            .entries
            .iter()
            .find(|entry| entry.name == old.name)
            .expect("old retained entry")
            .reason,
        WorktreeGcReason::RetentionKeep
    );
    assert!(old.path.join("target").exists());
    assert!(new.path.join("target").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_size_measurement_failure_protects_the_lane_without_byte_credit() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "size-failure", &worktree_root);
    let outside = temp.path().join("outside-target");
    fs::create_dir(&outside).expect("outside target");
    symlink(&outside, created.path.join("target")).expect("linked target");

    let report = manager
        .gc_with_target_liveness(gc_options(Some(worktree_root), false), |_| {
            panic!("a failed size binding must not reach liveness")
        })
        .expect("structured size failure");

    assert_eq!(report.removed_count, 0, "{report:#?}");
    assert_eq!(report.protected_count, 1, "{report:#?}");
    assert_eq!(report.apparent_considered_bytes, 0);
    assert_eq!(report.estimated_reclaimable_bytes, 0);
    assert_eq!(report.estimated_reclaimed_bytes, 0);
    assert_eq!(
        report.entries[0].reason,
        WorktreeGcReason::SizeMeasurementFailed
    );
    assert_eq!(report.entries[0].apparent_worktree_bytes, None);
    assert!(created.path.exists());
    assert!(outside.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_targets_only_reclaims_untracked_lane_target_and_keeps_lane_branch_and_orphan() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "target-only-lane", &worktree_root);
    fs::write(created.path.join("TASK.md"), "task brief\n").expect("untracked task brief");
    fs::create_dir_all(created.path.join("target/debug")).expect("lane target");
    fs::write(created.path.join("target/debug/artifact"), "artifact\n").expect("target artifact");
    let orphan = worktree_root.join("unregistered-orphan");
    fs::create_dir(&orphan).expect("unregistered orphan");

    let report = manager
        .gc_with_target_liveness(gc_targets_only_options(Some(worktree_root), false), |_| {
            WorktreeTargetLiveness::Clear
        })
        .expect("target-only GC");

    assert!(report.targets_only);
    assert_eq!(report.removed_count, 0);
    assert_eq!(report.target_removed_count, 1, "{report:#?}");
    assert_eq!(report.orphan_removed_count, 0);
    assert_eq!(report.entries[0].status, WorktreeGcStatus::Retained);
    assert_eq!(report.entries[0].reason, WorktreeGcReason::TargetRemoved);
    let target_bytes = report.entries[0]
        .apparent_target_bytes
        .expect("target byte estimate");
    assert_eq!(report.estimated_reclaimable_bytes, target_bytes);
    assert_eq!(report.estimated_reclaimed_bytes, target_bytes);
    assert!(report.apparent_considered_bytes >= target_bytes);
    assert_eq!(
        report.entries[0].untracked_paths,
        vec![PathBuf::from("TASK.md")]
    );
    assert!(created.path.exists());
    assert!(!created.path.join("target").exists());
    assert!(created.path.join("TASK.md").exists());
    assert!(orphan.exists());
    assert!(repo
        .find_branch("maco/target-only-lane", BranchType::Local)
        .is_ok());
    assert_eq!(manager.list().expect("retained lane"), vec![created]);
}

#[cfg(target_os = "linux")]
#[test]
fn gc_refuses_live_nested_cargo_target_for_full_and_target_only_reclaim() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "live-target-lane", &worktree_root);
    fs::create_dir_all(created.path.join("target/issue69")).expect("nested cargo target");

    let full = manager
        .gc_with_target_liveness(gc_options(Some(worktree_root.clone()), false), |_| {
            test_live_target_liveness()
        })
        .expect("full GC live-target refusal");
    assert_eq!(full.removed_count, 0);
    assert_eq!(full.protected_count, 1);
    assert_eq!(full.entries[0].reason, WorktreeGcReason::LiveTarget);
    assert!(created.path.exists());

    let target_only = manager
        .gc_with_target_liveness(
            gc_targets_only_options(Some(worktree_root.clone()), false),
            |_| test_live_target_liveness(),
        )
        .expect("target-only live-target refusal");
    assert_eq!(target_only.target_removed_count, 0);
    assert_eq!(target_only.protected_count, 1);
    assert_eq!(target_only.entries[0].reason, WorktreeGcReason::LiveTarget);
    assert!(created.path.join("target").exists());

    let reclaimed = manager
        .gc_with_target_liveness(gc_targets_only_options(Some(worktree_root), false), |_| {
            WorktreeTargetLiveness::Clear
        })
        .expect("reclaim stopped target");
    assert_eq!(reclaimed.target_removed_count, 1);
    assert!(created.path.exists());
    assert!(!created.path.join("target").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_refuses_target_replacement_between_probe_and_removal() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);

    for (root_name, targets_only) in [("full-root", false), ("target-root", true)] {
        let worktree_root = temp.path().join(root_name);
        let created = create_gc_worktree(
            &manager,
            &format!("replacement-{root_name}"),
            &worktree_root,
        );
        let target = created.path.join("target");
        let moved = created.path.join("target-original");
        fs::create_dir_all(target.join("debug")).expect("target");
        let mut options = if targets_only {
            gc_targets_only_options(Some(worktree_root), false)
        } else {
            gc_options(Some(worktree_root), false)
        };
        options.targets_only = targets_only;

        let report = manager
            .gc_with_target_liveness(options, |_| {
                fs::rename(&target, &moved).expect("move probed target");
                fs::create_dir(&target).expect("create replacement target");
                WorktreeTargetLiveness::Clear
            })
            .expect("replacement must become a structured protection");

        assert_eq!(report.removed_count, 0, "{report:#?}");
        assert_eq!(report.target_removed_count, 0, "{report:#?}");
        assert_eq!(report.protected_count, 1, "{report:#?}");
        assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
        assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
        assert_eq!(
            report.entries[0].reason,
            WorktreeGcReason::TargetIdentityChanged
        );
        assert_eq!(
            report.entries[0]
                .target_liveness
                .as_ref()
                .expect("identity evidence")
                .source,
            WorktreeTargetLivenessSource::TargetIdentity
        );
        assert!(created.path.exists());
        assert!(target.exists(), "replacement target must survive");
        assert!(moved.exists(), "original target must survive");
    }
}

#[cfg(target_os = "linux")]
#[test]
fn gc_apply_boundary_maps_file_and_symlink_target_replacements_to_identity_change() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    for replacement in ["file", "symlink"] {
        let lane = temp.path().join(format!("{replacement}-lane"));
        let target = lane.join("target");
        fs::create_dir_all(target.join("debug")).expect("preflight target");
        let preflight = gc_target_if_present(&lane)
            .expect("bind preflight target")
            .expect("preflight target exists");
        fs::remove_dir_all(&target).expect("remove preflight target");
        if replacement == "file" {
            fs::write(&target, "replacement\n").expect("file replacement");
        } else {
            let outside = temp.path().join("outside-target");
            fs::create_dir_all(&outside).expect("outside target");
            symlink(&outside, &target).expect("symlink replacement");
        }

        let boundary = gc_target_at_apply_boundary(&lane, Some(&preflight))
            .expect("replacement becomes structured absence");
        assert!(boundary.is_none());
        assert!(!worktree_gc_target_bindings_match(
            Some(&preflight),
            boundary.as_ref()
        ));
        assert!(fs::symlink_metadata(&target).is_ok());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn gc_unknown_and_live_evidence_protects_every_target_reclaim_path() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);

    for (root_name, targets_only, retained, live) in [
        ("full-unknown", false, false, false),
        ("retained-unknown", false, true, false),
        ("target-unknown", true, false, false),
        ("retained-live", false, true, true),
    ] {
        let worktree_root = temp.path().join(root_name);
        let created = create_gc_worktree(&manager, root_name, &worktree_root);
        fs::create_dir_all(created.path.join("target/debug")).expect("target");
        let mut options = if targets_only {
            gc_targets_only_options(Some(worktree_root), false)
        } else {
            gc_options(Some(worktree_root), false)
        };
        if retained {
            options.retention.max_count = Some(1);
        }
        let report = manager
            .gc_with_target_liveness(options, |_| {
                if live {
                    test_live_target_liveness()
                } else {
                    test_unknown_target_liveness()
                }
            })
            .expect("liveness refusal report");
        assert_eq!(report.removed_count, 0, "{report:#?}");
        assert_eq!(report.target_removed_count, 0, "{report:#?}");
        assert_eq!(report.protected_count, 1, "{report:#?}");
        assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
        assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
        assert_eq!(
            report.entries[0].reason,
            if live {
                WorktreeGcReason::LiveTarget
            } else {
                WorktreeGcReason::TargetLivenessUnknown
            }
        );
        let evidence = report.entries[0]
            .target_liveness
            .as_ref()
            .expect("actionable evidence");
        assert_eq!(evidence.pid, Some(if live { 42 } else { 43 }));
        let json = serde_json::to_value(&report.entries[0]).expect("serialize evidence");
        assert_eq!(
            json.pointer("/target_liveness/pid"),
            Some(&serde_json::json!(if live { 42 } else { 43 }))
        );
        assert!(json.pointer("/target_liveness/source").is_some());
        assert!(json.pointer("/target_liveness/cause").is_some());
        assert!(created.path.join("target").exists());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_target_liveness_observes_absolute_and_relative_cargo_target_dirs() {
    let temp = TempDir::new().expect("tempdir");
    let lane = temp.path().join("lane");
    let target_path = lane.join("target");
    let absolute = target_path.join("absolute");
    let relative = target_path.join("relative");
    fs::create_dir_all(&absolute).expect("absolute target");
    fs::create_dir_all(&relative).expect("relative target");

    for (configured, cwd) in [
        (absolute.as_os_str().to_owned(), None),
        (OsString::from("target/relative"), Some(lane.as_path())),
    ] {
        let mut command = std::process::Command::new("sleep");
        command.arg("60").env("CARGO_TARGET_DIR", configured);
        if let Some(cwd) = cwd {
            command.current_dir(cwd);
        }
        let mut child = command.spawn().expect("spawn target process");
        let mut observed_live = None;
        for _ in 0..100 {
            let target = gc_target_if_present(&lane)
                .expect("bind target")
                .expect("target exists");
            if let WorktreeTargetLiveness::Live(evidence) = worktree_target_liveness(&target) {
                if evidence.pid == Some(child.id()) {
                    observed_live = Some(evidence);
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        let evidence = observed_live.expect("child CARGO_TARGET_DIR must be observed");
        assert_eq!(
            evidence.source,
            WorktreeTargetLivenessSource::CargoTargetDir
        );
    }
}

#[cfg(target_os = "linux")]
#[test]
fn linux_target_liveness_skips_only_exact_user_manager_shape() {
    let temp = TempDir::new().expect("tempdir");
    fs::write(temp.path().join("comm"), "systemd\n").expect("comm");
    fs::write(
        temp.path().join("cmdline"),
        b"/run/current-system/systemd/lib/systemd/systemd\0--user\0",
    )
    .expect("cmdline");
    fs::write(
        temp.path().join("cgroup"),
        "0::/user.slice/user-1000.slice/user@1000.service/init.scope\n",
    )
    .expect("cgroup");
    assert!(linux_process_is_inert_user_manager(temp.path()));

    fs::write(temp.path().join("comm"), "(sd-pam)\n").expect("PAM helper comm");
    fs::write(temp.path().join("cmdline"), b"(sd-pam)\0").expect("PAM helper cmdline");
    assert!(linux_process_is_inert_user_manager(temp.path()));

    fs::write(
        temp.path().join("cgroup"),
        "0::/user.slice/user-1000.slice/user@1000.service/app.slice/build.service\n",
    )
    .expect("non-manager cgroup");
    assert!(!linux_process_is_inert_user_manager(temp.path()));
    assert!(linux_process_is_non_build_user_service(temp.path()));

    fs::write(
        temp.path().join("cgroup"),
        "0::/user.slice/user-1000.slice/session-1.scope\n",
    )
    .expect("interactive scope");
    assert!(!linux_process_is_non_build_user_service(temp.path()));
}

#[cfg(target_os = "linux")]
#[test]
fn linux_target_liveness_observes_default_cargo_target_from_process_cwd() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let lane = temp.path().join("lane");
    fs::create_dir_all(lane.join("target/debug")).expect("target");
    let bash = std::process::Command::new("sh")
        .args(["-c", "command -v bash"])
        .output()
        .expect("locate bash");
    assert!(bash.status.success());
    let bash = String::from_utf8(bash.stdout)
        .expect("bash path utf8")
        .trim()
        .to_string();
    let cargo = temp.path().join("cargo");
    symlink(bash, &cargo).expect("cargo-named bash shim");
    let mut child = std::process::Command::new(&cargo)
        .args(["-c", "while :; do :; done"])
        .current_dir(&lane)
        .env_remove("CARGO_TARGET_DIR")
        .spawn()
        .expect("spawn cargo-like process");
    let target = gc_target_if_present(&lane)
        .expect("bind target")
        .expect("target exists");
    let mut observed = None;
    for _ in 0..100 {
        if let WorktreeTargetLiveness::Live(evidence) = worktree_target_liveness(&target) {
            if evidence.pid == Some(child.id()) {
                observed = Some(evidence);
                break;
            }
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.kill();
    let _ = child.wait();
    let evidence = observed.expect("default cargo target must be observed");
    assert_eq!(
        evidence.source,
        WorktreeTargetLivenessSource::DefaultCargoTarget
    );
    assert_eq!(
        evidence.cause,
        WorktreeTargetLivenessCause::CargoLikeProcessInLane
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_target_liveness_parses_bounded_build_output_and_manifest_arguments() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let lane = temp.path().join("lane");
    let target_path = lane.join("target");
    let cargo_target = target_path.join("cargo");
    let rustc_out = target_path.join("rustc");
    fs::create_dir_all(&cargo_target).expect("cargo target");
    fs::create_dir_all(&rustc_out).expect("rustc out");
    fs::write(lane.join("Cargo.toml"), "[workspace]\n").expect("manifest");
    let bash = std::process::Command::new("sh")
        .args(["-c", "command -v bash"])
        .output()
        .expect("locate bash");
    assert!(bash.status.success());
    let bash = String::from_utf8(bash.stdout)
        .expect("bash path utf8")
        .trim()
        .to_string();
    let cargo = temp.path().join("cargo");
    symlink(bash, &cargo).expect("cargo-named bash shim");
    let target = gc_target_if_present(&lane)
        .expect("bind target")
        .expect("target exists");
    let cases = [
        (
            vec![
                OsString::from("--target-dir"),
                cargo_target.into_os_string(),
            ],
            WorktreeTargetLivenessSource::ProcessCommandLine,
        ),
        (
            vec![OsString::from(format!(
                "--manifest-path={}",
                lane.join("Cargo.toml").display()
            ))],
            WorktreeTargetLivenessSource::DefaultCargoTarget,
        ),
        (
            vec![OsString::from(format!("--out-dir={}", rustc_out.display()))],
            WorktreeTargetLivenessSource::ProcessCommandLine,
        ),
    ];
    for (arguments, expected_source) in cases {
        let mut child = std::process::Command::new(&cargo)
            .args(["-c", "while :; do :; done", "cargo-script"])
            .args(arguments)
            .current_dir(temp.path())
            .env_remove("CARGO_TARGET_DIR")
            .spawn()
            .expect("spawn cargo-like command line");
        let process_root = PathBuf::from("/proc").join(child.id().to_string());
        let process_view = LinuxProcessView::for_test(&process_root, true);
        let mut observed = None;
        for _ in 0..100 {
            if let WorktreeTargetLiveness::Live(evidence) =
                linux_process_cmdline_liveness(&process_view, child.id(), &target, true)
            {
                observed = Some(evidence);
                break;
            }
            std::thread::sleep(Duration::from_millis(10));
        }
        let _ = child.kill();
        let _ = child.wait();
        let evidence = observed.expect("build path argument must be observed");
        assert_eq!(evidence.pid, Some(child.id()));
        assert_eq!(evidence.source, expected_source);
    }
    assert_eq!(
        command_line_directive_value(b"--target-dir=target/debug", b"--target-dir"),
        Some(Some(b"target/debug".as_slice()))
    );
    assert_eq!(
        command_line_directive_value(b"--target-dir", b"--target-dir"),
        Some(None)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn identity_ancestry_detects_alias_containment_in_both_directions_and_bounds() {
    let target = FileIdentity {
        device: 11,
        file: 22,
    };
    let alias = FileIdentity {
        device: 33,
        file: 44,
    };
    let other = FileIdentity {
        device: 55,
        file: 66,
    };
    assert!(
        identity_ancestry_contains(&target, [Ok(other.clone()), Ok(target.clone())])
            .expect("process alias ancestry")
    );
    assert!(
        identity_ancestry_contains(&alias, [Ok(target), Ok(alias.clone())])
            .expect("target alias ancestry")
    );
    let oversized = std::iter::repeat_with(|| Ok(other.clone()))
        .take(MAX_WORKTREE_GC_IDENTITY_ANCESTORS.saturating_add(1));
    assert!(identity_ancestry_contains(&alias, oversized).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_revalidates_tracked_and_unapproved_output_after_liveness() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);

    for (root_name, tracked) in [("late-tracked", true), ("late-untracked", false)] {
        let worktree_root = temp.path().join(root_name);
        let created = create_gc_worktree(&manager, root_name, &worktree_root);
        fs::create_dir_all(created.path.join("target/debug")).expect("target");
        let report = manager
            .gc_with_target_liveness(gc_options(Some(worktree_root), false), |_| {
                if tracked {
                    fs::write(created.path.join("README.md"), "changed\n")
                        .expect("late tracked output");
                } else {
                    fs::write(created.path.join("worker-output.txt"), "only copy\n")
                        .expect("late untracked output");
                }
                WorktreeTargetLiveness::Clear
            })
            .expect("late output protection");
        assert_eq!(report.removed_count, 0, "{report:#?}");
        assert_eq!(report.protected_count, 1, "{report:#?}");
        assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
        assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
        assert_eq!(
            report.entries[0].reason,
            if tracked {
                WorktreeGcReason::Dirty
            } else {
                WorktreeGcReason::UntrackedOnly
            }
        );
        assert!(created.path.exists());
        assert!(manager
            .pending_operations()
            .expect("pending operations")
            .is_empty());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn gc_target_cleanup_rechecks_dirtiness_after_boundary_liveness() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);

    for (root_name, targets_only) in [
        ("boundary-target-only", true),
        ("boundary-retained-target", false),
    ] {
        let worktree_root = temp.path().join(root_name);
        let created = create_gc_worktree(&manager, root_name, &worktree_root);
        fs::create_dir_all(created.path.join("target/debug")).expect("target");
        fs::write(created.path.join("target/debug/artifact"), "artifact\n")
            .expect("target artifact");
        let mut options = if targets_only {
            gc_targets_only_options(Some(worktree_root), false)
        } else {
            let mut options = gc_options(Some(worktree_root), false);
            options.retention.max_count = Some(1);
            options
        };
        options.targets_only = targets_only;
        let liveness_calls = std::cell::Cell::new(0usize);

        let report = manager
            .gc_with_target_liveness(options, |_| {
                let call = liveness_calls.get();
                liveness_calls.set(call.saturating_add(1));
                if call == 1 {
                    fs::write(created.path.join("README.md"), "late tracked edit\n")
                        .expect("late tracked edit");
                }
                WorktreeTargetLiveness::Clear
            })
            .expect("boundary dirtiness protection");

        assert_eq!(liveness_calls.get(), 2, "preflight and boundary probes");
        assert_eq!(report.removed_count, 0, "{report:#?}");
        assert_eq!(report.target_removed_count, 0, "{report:#?}");
        assert_eq!(report.protected_count, 1, "{report:#?}");
        assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
        assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
        assert_eq!(report.entries[0].reason, WorktreeGcReason::Dirty);
        assert!(created.path.exists());
        assert!(created.path.join("target").exists());
        assert!(repo.find_branch(&created.branch, BranchType::Local).is_ok());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn gc_full_removal_reports_final_approved_untracked_paths() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "final-untracked", &worktree_root);
    fs::create_dir_all(created.path.join("target/debug")).expect("target");
    let final_path = PathBuf::from("late-approved.txt");
    let mut options = gc_options(Some(worktree_root), false);
    options.allowed_untracked_paths = vec![final_path.clone()];
    let liveness_calls = std::cell::Cell::new(0usize);

    let report = manager
        .gc_with_target_liveness(options, |_| {
            let call = liveness_calls.get();
            liveness_calls.set(call.saturating_add(1));
            if call == 1 {
                fs::write(created.path.join(&final_path), "late approved output\n")
                    .expect("late approved output");
            }
            WorktreeTargetLiveness::Clear
        })
        .expect("full removal with final approved output");

    assert!(liveness_calls.get() >= 2);
    assert_eq!(report.removed_count, 1, "{report:#?}");
    assert_eq!(report.protected_count, 0, "{report:#?}");
    assert_eq!(report.entries[0].status, WorktreeGcStatus::Removed);
    assert_eq!(report.entries[0].untracked_paths, vec![final_path]);
    assert!(!created.path.exists());
    assert!(repo.find_branch(&created.branch, BranchType::Local).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_boundary_protection_does_not_consume_count_or_size_retention() {
    skip_without_containment!();
    // Conservative retention bias: apply-time dirtiness must not spend the
    // budget that would otherwise keep the older finished lane.
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let old = create_gc_worktree(&manager, "boundary-protection-old", &worktree_root);
    fs::create_dir_all(old.path.join("target/debug")).expect("old target");
    fs::write(old.path.join("target/debug/artifact"), vec![b'o'; 64]).expect("old artifact");
    let new = create_gc_worktree(&manager, "boundary-protection-new", &worktree_root);
    fs::create_dir_all(new.path.join("target/debug")).expect("new target");
    fs::write(
        new.path.join("target/debug/artifact"),
        vec![b'n'; 64 * 1024],
    )
    .expect("new artifact");
    let old_size = gc_worktree_size_estimate(&old.path).expect("old size");
    let new_size = gc_worktree_size_estimate(&new.path).expect("new size");
    assert!(new_size.worktree_bytes > old_size.worktree_bytes);

    let mut options = gc_options(Some(worktree_root), false);
    options.remove_targets = false;
    options.retention = WorktreeRetentionPolicy {
        max_age: None,
        max_count: Some(1),
        max_total_bytes: Some(old_size.worktree_bytes),
    };
    let liveness_calls = std::cell::Cell::new(0usize);
    let report = manager
        .gc_with_target_liveness(options, |target| {
            let call = liveness_calls.get();
            liveness_calls.set(call.saturating_add(1));
            assert_eq!(target.path, new.path.join("target"));
            if call == 1 {
                fs::write(new.path.join("README.md"), "late tracked edit\n")
                    .expect("late tracked edit");
            }
            WorktreeTargetLiveness::Clear
        })
        .expect("boundary-protected retention GC");

    assert_eq!(liveness_calls.get(), 2, "preflight and boundary probes");
    assert_eq!(report.removed_count, 0, "{report:#?}");
    assert_eq!(report.retained_count, 1, "{report:#?}");
    assert_eq!(report.protected_count, 1, "{report:#?}");
    assert_eq!(report.estimated_reclaimable_bytes, 0, "{report:#?}");
    assert_eq!(report.estimated_reclaimed_bytes, 0, "{report:#?}");
    assert_eq!(
        report
            .entries
            .iter()
            .find(|entry| entry.name == new.name)
            .expect("new protected entry")
            .reason,
        WorktreeGcReason::Dirty
    );
    assert_eq!(
        report
            .entries
            .iter()
            .find(|entry| entry.name == old.name)
            .expect("old retained entry")
            .reason,
        WorktreeGcReason::RetentionKeep
    );
    assert!(old.path.join("target").exists());
    assert!(new.path.join("target").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn explicit_force_remove_recovery_still_refuses_live_or_unknown_target() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "recovery-live", &worktree_root);
    fs::create_dir_all(created.path.join("target/debug")).expect("target");
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
    let lock = store.lock().expect("lock");
    let mut registry = store.load(&lock).expect("registry");
    let (binding, _, _, _) = prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
    registry
        .operations
        .get_mut(&binding.name)
        .expect("prepared removal")
        .removal_safety = Some(ManagedRemovalSafety::Explicit);
    store
        .save(&lock, &mut registry)
        .expect("persist explicit removal origin");
    let operation = registry
        .operations
        .get(&binding.name)
        .cloned()
        .expect("prepared removal");

    for (label, probe) in [
        (
            "live",
            test_live_target_liveness as fn() -> WorktreeTargetLiveness,
        ),
        ("unknown", test_unknown_target_liveness),
    ] {
        let error = recover_remove_operation_with_lease_using_target_liveness(
            &repo,
            &store,
            &lock,
            &mut registry,
            operation.clone(),
            None,
            &|_| probe(),
        )
        .expect_err("recovery liveness must refuse quarantine");
        assert!(error.to_string().contains(label), "{error:#}");
        assert!(error.to_string().contains("\"pid\""), "{error:#}");
        assert!(binding.path.exists());
    }

    fs::write(
        binding.path.join("force-output.txt"),
        "explicit force output\n",
    )
    .expect("force output");
    recover_remove_operation_with_lease_using_target_liveness(
        &repo,
        &store,
        &lock,
        &mut registry,
        operation,
        None,
        &|_| WorktreeTargetLiveness::Clear,
    )
    .expect("explicit force removal bypasses dirtiness after liveness clears");
    assert!(!binding.path.exists());
    assert!(!registry.operations.contains_key(&binding.name));
}

#[cfg(target_os = "linux")]
#[test]
fn remove_prepared_gc_recovery_refuses_changed_dirtiness_snapshot() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "recovery-dirty", &worktree_root);
    fs::create_dir_all(created.path.join("target/debug")).expect("target");
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
    let lock = store.lock().expect("lock");
    let mut registry = store.load(&lock).expect("registry");
    let (binding, _, _, _) = prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
    let approved = gc_worktree_dirtiness(&binding.path).expect("approved dirtiness");
    let dirtiness = managed_gc_dirtiness_snapshot(&approved).expect("approved snapshot");
    let target = gc_target_if_present(&binding.path)
        .expect("target inspection")
        .expect("target exists");
    let operation = registry
        .operations
        .get_mut(&binding.name)
        .expect("prepared removal");
    operation.delete_branch = false;
    operation.removal_safety = Some(ManagedRemovalSafety::GarbageCollection {
        dirtiness,
        target: ManagedGcTargetSnapshot::Present {
            identity: target.identity,
        },
    });
    store
        .save(&lock, &mut registry)
        .expect("persist GC safety snapshot");
    fs::write(binding.path.join("worker-output.txt"), "only copy\n").expect("late worker output");
    let operation = registry
        .operations
        .get(&binding.name)
        .cloned()
        .expect("prepared removal");

    let error = recover_remove_operation_with_lease_using_target_liveness(
        &repo,
        &store,
        &lock,
        &mut registry,
        operation,
        None,
        &|_| WorktreeTargetLiveness::Clear,
    )
    .expect_err("changed GC snapshot must refuse quarantine");
    assert!(error.to_string().contains("dirtiness changed"), "{error:#}");
    assert!(binding.path.exists());
    assert!(registry.operations.contains_key(&binding.name));
}

#[cfg(target_os = "linux")]
#[test]
fn gc_recovery_refuses_target_presence_and_identity_changes_before_liveness() {
    for replacement in [false, true] {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        let created = create_gc_worktree(
            &manager,
            if replacement {
                "recovery-target-replacement"
            } else {
                "recovery-target-appearance"
            },
            &worktree_root,
        );
        if replacement {
            fs::create_dir_all(created.path.join("target/debug")).expect("original target");
        }
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let (binding, _, _, _) =
            prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
        let target = match gc_target_if_present(&binding.path).expect("target snapshot") {
            Some(target) => ManagedGcTargetSnapshot::Present {
                identity: target.identity,
            },
            None => ManagedGcTargetSnapshot::Absent,
        };
        let operation = registry
            .operations
            .get_mut(&binding.name)
            .expect("prepared removal");
        operation.delete_branch = false;
        operation.removal_safety = Some(ManagedRemovalSafety::GarbageCollection {
            dirtiness: ManagedGcDirtinessSnapshot::Clean,
            target,
        });
        store.save(&lock, &mut registry).expect("persist GC safety");

        if replacement {
            fs::rename(
                binding.path.join("target"),
                binding.path.join("target-original"),
            )
            .expect("move original target");
            fs::create_dir(binding.path.join("target")).expect("replacement target");
        } else {
            fs::create_dir(binding.path.join("target")).expect("new target");
        }
        let operation = registry
            .operations
            .get(&binding.name)
            .cloned()
            .expect("prepared removal");
        let liveness_calls = std::cell::Cell::new(0usize);
        let error = recover_remove_operation_with_lease_using_target_liveness(
            &repo,
            &store,
            &lock,
            &mut registry,
            operation,
            None,
            &|_| {
                liveness_calls.set(liveness_calls.get().saturating_add(1));
                WorktreeTargetLiveness::Clear
            },
        )
        .expect_err("changed target snapshot must refuse recovery");
        let message = error.to_string();
        assert!(
            message.contains("target changed from")
                || message.contains("target filesystem identity changed"),
            "{error:#}"
        );
        assert_eq!(
            liveness_calls.get(),
            0,
            "liveness ran before identity check"
        );
        assert!(binding.path.exists());
    }
}

#[cfg(target_os = "linux")]
#[test]
fn clean_legacy_remove_refuses_until_explicit_force_reauthorization() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    let created = create_gc_worktree(&manager, "legacy-removal", &worktree_root);
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
    let lock = store.lock().expect("lock");
    let mut registry = store.load(&lock).expect("registry");
    let (binding, _, _, _) = prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
    registry
        .operations
        .get_mut(&binding.name)
        .expect("prepared removal")
        .removal_safety = None;
    store
        .save(&lock, &mut registry)
        .expect("persist authenticated legacy origin");
    let operation = registry
        .operations
        .get(&binding.name)
        .cloned()
        .expect("prepared removal");
    let error = recover_remove_operation_with_lease_using_target_liveness(
        &repo,
        &store,
        &lock,
        &mut registry,
        operation,
        None,
        &|_| WorktreeTargetLiveness::Clear,
    )
    .expect_err("clean legacy removal must still require reauthorization");
    assert!(
        error.to_string().contains("ambiguous safety state"),
        "{error:#}"
    );
    assert!(binding.path.exists());
    drop(lock);
    drop(store);
    drop(repo);

    let removed = manager
        .remove(&binding.name, true, true)
        .expect("explicit force reauthorizes pending legacy removal");
    assert_eq!(removed.path, created.path);
    assert!(!binding.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn quarantined_legacy_remove_requires_reauthorization_and_adopts_exact_branch_scope() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    create_gc_worktree(&manager, "legacy-quarantined", &worktree_root);
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
    let lock = store.lock().expect("lock");
    let mut registry = store.load(&lock).expect("registry");
    let (binding, worktree_quarantine, _, _) =
        prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
    ensure_removal_worktree_lock(&repo, &binding).expect("removal lock");
    quarantine_bound_directory(
        &binding.root,
        &binding.path,
        &worktree_quarantine,
        &binding.path_identity,
    )
    .expect("quarantine worktree");
    let operation = registry
        .operations
        .get_mut(&binding.name)
        .expect("prepared removal");
    operation.phase = ManagedWorktreeOperationPhase::WorktreeQuarantined;
    operation.worktree_quarantine_identity = Some(binding.path_identity.clone());
    operation.removal_safety = None;
    assert!(
        operation.delete_branch,
        "legacy operation starts branch-destructive"
    );
    store
        .save(&lock, &mut registry)
        .expect("persist quarantined legacy operation");

    let error = recover_pending_operations(&repo, &store, &lock, &mut registry)
        .expect_err("quarantined legacy operation must require reauthorization");
    assert!(
        error.to_string().contains("worktree_quarantined"),
        "{error:#}"
    );
    assert!(worktree_quarantine.exists());
    drop(lock);
    drop(store);
    drop(repo);

    manager
        .remove(&binding.name, true, false)
        .expect("explicit force reauthorizes without branch deletion");
    assert!(!binding.path.exists());
    let repo = crate::git_repository::open(&repo_path).expect("reopen repo");
    assert!(repo.find_branch(&binding.branch, BranchType::Local).is_ok());
}

#[cfg(target_os = "linux")]
#[test]
fn f3_legacy_digest_round_trips_authenticated_and_remains_ambiguous() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let manager = WorktreeManager::new(&repo_path);
    create_gc_worktree(&manager, "f3-digest", &worktree_root);
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
    let lock = store.lock().expect("lock");
    let mut registry = store.load(&lock).expect("registry");
    let (binding, _, _, _) = prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
    let digest = stable_checksum(b"legacy-f3-reviewed-state");
    let operation = registry
        .operations
        .get_mut(&binding.name)
        .expect("prepared removal");
    operation.removal_safety = None;
    operation.gc_dirtiness_checksum = Some(digest.clone());
    store
        .save(&lock, &mut registry)
        .expect("persist f3-compatible digest field");
    drop(lock);
    drop(store);

    let store = ManagedWorktreeRegistryStore::open(&repo).expect("reopen store");
    let lock = store.lock().expect("reopen lock");
    let mut registry = store.load(&lock).expect("authenticated legacy load");
    let operation = registry
        .operations
        .get(&binding.name)
        .cloned()
        .expect("round-tripped operation");
    assert_eq!(
        operation.gc_dirtiness_checksum.as_deref(),
        Some(digest.as_str())
    );
    assert!(operation.removal_safety.is_none());
    let error = recover_remove_operation_with_lease_using_target_liveness(
        &repo,
        &store,
        &lock,
        &mut registry,
        operation,
        None,
        &|_| WorktreeTargetLiveness::Clear,
    )
    .expect_err("legacy digest must never authorize recovery");
    assert!(
        error.to_string().contains("ambiguous safety state"),
        "{error:#}"
    );
    assert!(binding.path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn gc_dirtiness_snapshot_preserves_non_utf8_paths_and_detects_exact_change() {
    skip_without_containment!();
    for changed in [false, true] {
        let temp = TempDir::new().expect("tempdir");
        let repo_path = temp.path().join("repo");
        let worktree_root = temp.path().join("worktrees");
        WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
        let repo = crate::git_repository::open(&repo_path).expect("open repo");
        commit_readme(&repo).expect("initial commit");
        let manager = WorktreeManager::new(&repo_path);
        create_gc_worktree(&manager, "non-utf8-snapshot", &worktree_root);
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("store");
        let lock = store.lock().expect("lock");
        let mut registry = store.load(&lock).expect("registry");
        let (binding, _, _, _) =
            prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
        let original = PathBuf::from(OsString::from_vec(b"worker-\xff".to_vec()));
        fs::write(binding.path.join(&original), "only copy\n").expect("non-UTF8 output");
        let approved = gc_worktree_dirtiness(&binding.path).expect("approved dirtiness");
        let snapshot = managed_gc_dirtiness_snapshot(&approved).expect("exact snapshot");
        let round_trip: ManagedGcDirtinessSnapshot = serde_json::from_slice(
            &serde_json::to_vec(&snapshot).expect("serialize exact snapshot"),
        )
        .expect("deserialize exact snapshot");
        assert_eq!(round_trip, snapshot);
        let operation = registry
            .operations
            .get_mut(&binding.name)
            .expect("prepared removal");
        operation.delete_branch = false;
        operation.removal_safety = Some(ManagedRemovalSafety::GarbageCollection {
            dirtiness: snapshot,
            target: ManagedGcTargetSnapshot::Absent,
        });
        store
            .save(&lock, &mut registry)
            .expect("persist exact GC snapshot");
        if changed {
            let changed_path = PathBuf::from(OsString::from_vec(b"worker-\xfe".to_vec()));
            fs::rename(
                binding.path.join(&original),
                binding.path.join(changed_path),
            )
            .expect("change exact non-UTF8 path");
        }
        let operation = registry
            .operations
            .get(&binding.name)
            .cloned()
            .expect("prepared removal");
        let result = recover_remove_operation_with_lease_using_target_liveness(
            &repo,
            &store,
            &lock,
            &mut registry,
            operation,
            None,
            &|_| WorktreeTargetLiveness::Clear,
        );
        if changed {
            let error = result.expect_err("exact path change must refuse removal");
            assert!(error.to_string().contains("dirtiness changed"), "{error:#}");
            assert!(binding.path.exists());
        } else {
            result.expect("unchanged exact path snapshot");
            assert!(!binding.path.exists());
        }
    }
}

#[cfg(target_os = "linux")]
#[test]
fn pseudo_file_descriptor_targets_do_not_make_liveness_unknown() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let lane = temp.path().join("lane");
    fs::create_dir_all(lane.join("target/debug")).expect("target");
    let process_root = temp.path().join("proc-entry");
    fs::create_dir_all(process_root.join("fd")).expect("fd directory");
    symlink("/", process_root.join("root")).expect("process root link");
    symlink(temp.path(), process_root.join("cwd")).expect("cwd link");
    symlink(
        std::env::current_exe().expect("current exe"),
        process_root.join("exe"),
    )
    .expect("exe link");
    for (fd, target) in [
        ("3", "pipe:[123]"),
        ("4", "socket:[456]"),
        ("5", "anon_inode:[eventpoll]"),
        ("6", "/memfd:rustc (deleted)"),
        ("7", "anon_inode:inotify"),
        ("8", "/dmabuf:"),
    ] {
        symlink(target, process_root.join("fd").join(fd)).expect("pseudo fd link");
    }
    let target = gc_target_if_present(&lane)
        .expect("bind target")
        .expect("target exists");
    let view = LinuxProcessView::for_test(&process_root, true);
    assert_eq!(
        linux_process_target_association(
            &view,
            42,
            &target,
            Instant::now() + Duration::from_secs(1),
            false,
        ),
        WorktreeTargetLiveness::Clear
    );
}

include!("tests_part2.rs");
include!("tests_part3.rs");
