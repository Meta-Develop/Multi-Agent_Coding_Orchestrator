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

#[cfg(unix)]
#[test]
fn create_checkout_gap_keeps_disjoint_mutation_and_skips_recovery() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");

    let observed = std::sync::Arc::new(std::sync::Mutex::new(
        None::<(ManagedWorktreeBinding, PathBuf)>,
    ));
    set_create_checkout_gap_hook({
        let repo_path = repo_path.clone();
        let worktree_root = worktree_root.clone();
        let observed = std::sync::Arc::clone(&observed);
        move || {
            let repo =
                crate::git_repository::open(&repo_path).expect("reopen repo in checkout gap");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
            let lock = store
                .lock_with_timeout(Duration::from_millis(500))
                .expect("registry lock must be free while checkout is paused");
            let mut registry = store.load(&lock).expect("registry during checkout gap");
            let holder = registry
                .operations
                .get("gap-holder")
                .cloned()
                .expect("holder create must still be prepared");
            assert_eq!(holder.phase, ManagedWorktreeOperationPhase::CreatePrepared);
            let reservation_identity = holder
                .prepared_path_identity
                .clone()
                .expect("prepared reservation identity");
            assert_eq!(
                identity_for_path(&holder.path).expect("reservation inode"),
                reservation_identity
            );
            assert!(
                holder
                    .staging_path
                    .as_ref()
                    .is_some_and(|path| !path.exists()),
                "checkout must not have started before the registry gap"
            );
            let branch = holder.branch.clone();
            let reservation = holder.path.clone();

            recover_pending_operations(&repo, &store, &lock, &mut registry)
                .expect("busy create lease must not fail recovery");
            let registry = store.load(&lock).expect("reload after skipped recovery");
            assert_eq!(registry.operations.get("gap-holder"), Some(&holder));
            assert!(registry.records.is_empty());
            assert_eq!(
                identity_for_path(&reservation).expect("reservation after skipped recovery"),
                reservation_identity
            );
            assert!(
                repo.find_branch(&branch, BranchType::Local).is_ok(),
                "skipped recovery must not delete the in-progress branch"
            );
            drop(lock);

            let peer = WorktreeManager::new(&repo_path)
                .create_for_test(WorktreeCreateOptions {
                    agent_id: "gap-peer".to_string(),
                    branch: None,
                    base: None,
                    worktree_root: Some(worktree_root),
                })
                .expect("disjoint create while checkout is paused");
            let lock = store
                .lock_with_timeout(Duration::from_millis(500))
                .expect("registry lock after disjoint create");
            let registry = store.load(&lock).expect("registry after disjoint create");
            assert_eq!(
                registry
                    .operations
                    .get("gap-holder")
                    .map(|operation| operation.phase),
                Some(ManagedWorktreeOperationPhase::CreatePrepared)
            );
            assert_eq!(
                registry
                    .operations
                    .get("gap-holder")
                    .and_then(|operation| operation.prepared_path_identity.clone()),
                Some(reservation_identity.clone())
            );
            let peer_binding = registry
                .records
                .get("gap-peer")
                .cloned()
                .expect("peer record must be durable before holder resumes");
            assert_eq!(peer_binding.path, peer.path);
            *observed.lock().expect("observation lock") = Some((peer_binding, reservation));
        }
    });

    let holder = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "gap-holder".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root),
        })
        .expect("holder create resumes after the gap");
    let (peer_binding, reservation) = observed
        .lock()
        .expect("observation lock")
        .take()
        .expect("checkout gap hook did not run");

    let store = ManagedWorktreeRegistryStore::open(&repo).expect("final registry store");
    let lock = store.lock().expect("final registry lock");
    let registry = store.load(&lock).expect("final registry");
    assert!(registry.operations.is_empty());
    assert_eq!(registry.records.get("gap-peer"), Some(&peer_binding));
    assert_eq!(
        registry
            .records
            .get("gap-holder")
            .map(|binding| binding.path.as_path()),
        Some(holder.path.as_path())
    );
    assert_eq!(holder.path.file_name(), reservation.file_name());
    assert!(holder.path.join("README.md").exists());
    assert!(peer_binding.path.join("README.md").exists());
    drop(lock);
    let mut listed = WorktreeManager::new(&repo_path)
        .list()
        .expect("list both managed worktrees")
        .into_iter()
        .map(|record| record.name)
        .collect::<Vec<_>>();
    listed.sort();
    assert_eq!(listed, ["gap-holder", "gap-peer"]);
}

#[cfg(unix)]
#[test]
fn abandoned_prepared_create_recovers_after_lease_release() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let oid = commit_readme(&repo).expect("initial commit");
    let commit = repo.find_commit(oid).expect("commit");
    let root = SafeRoot::open_or_create_managed(&worktree_root).expect("managed root");
    let name = "gap-abandoned".to_string();
    let reserved = root
        .reserve_direct_child_directory(&name)
        .expect("empty reservation");
    let staging = root
        .reserve_random_direct_child_directory("gap-stage")
        .expect("empty staging root");
    repo.branch("maco/gap-abandoned", &commit, false)
        .expect("preexisting branch");
    let reservation_identity = reserved.identity().clone();
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
    let lock = store.lock().expect("registry lock");
    let mut registry = store.load(&lock).expect("empty registry");
    registry.operations.insert(
        name.clone(),
        ManagedWorktreeOperation {
            kind: ManagedWorktreeOperationKind::Create,
            phase: ManagedWorktreeOperationPhase::CreatePrepared,
            name: name.clone(),
            root: root.path().to_path_buf(),
            root_identity: root.identity().clone(),
            path: reserved.path().to_path_buf(),
            prepared_path_identity: Some(reservation_identity.clone()),
            staging_root: Some(staging.path().to_path_buf()),
            staging_root_identity: Some(staging.identity().clone()),
            staging_path: Some(staging.path().join(&name)),
            staged_path_identity: None,
            staged_metadata: None,
            branch: "maco/gap-abandoned".to_string(),
            base_oid: oid.to_string(),
            branch_preexisting_oid: Some(oid.to_string()),
            branch_ownership: ManagedBranchOwnership::Preexisting,
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
    store
        .save(&lock, &mut registry)
        .expect("save prepared create");
    let lease = store
        .try_acquire_worktree_create_lease(&lock, &name)
        .expect("create lease");

    recover_pending_operations(&repo, &store, &lock, &mut registry)
        .expect("held create lease must leave recovery idle");
    let held = store.load(&lock).expect("registry while lease is held");
    let held_operation = held
        .operations
        .get(&name)
        .expect("prepared operation remains while its lease is held");
    assert_eq!(
        held_operation.phase,
        ManagedWorktreeOperationPhase::CreatePrepared
    );
    assert_eq!(
        held_operation.prepared_path_identity.as_ref(),
        Some(&reservation_identity)
    );
    assert!(held.records.is_empty());
    assert_eq!(
        identity_for_path(reserved.path()).expect("reservation while lease is held"),
        reservation_identity
    );
    assert!(staging.path().exists());
    assert_eq!(
        local_branch_oid(&repo, "maco/gap-abandoned").expect("branch during held lease"),
        Some(oid)
    );

    drop(lease);
    recover_pending_operations(&repo, &store, &lock, &mut registry)
        .expect("released lease must recover the abandoned reservation");
    let recovered = store.load(&lock).expect("registry after recovery");
    assert!(recovered.operations.is_empty());
    assert!(recovered.records.is_empty());
    assert!(!reserved.path().exists());
    assert!(!staging.path().exists());
    assert_eq!(
        local_branch_oid(&repo, "maco/gap-abandoned").expect("preexisting branch after recovery"),
        Some(oid)
    );
}

#[cfg(unix)]
#[test]
fn changed_operation_identity_refuses_publication_without_consuming_unrelated_state() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");

    let tamper = std::sync::Arc::new(std::sync::Mutex::new(
        None::<(FileIdentity, FileIdentity, String, PathBuf)>,
    ));
    set_create_checkout_gap_hook({
        let repo_path = repo_path.clone();
        let tamper = std::sync::Arc::clone(&tamper);
        move || {
            let repo = crate::git_repository::open(&repo_path).expect("reopen repo");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
            let lock = store
                .lock_with_timeout(Duration::from_millis(500))
                .expect("registry lock must be free before republish");
            let mut registry = store.load(&lock).expect("prepared registry");
            let holder = registry
                .operations
                .get("gap-holder")
                .cloned()
                .expect("holder operation");
            let original_identity = holder
                .prepared_path_identity
                .clone()
                .expect("original reservation identity");
            let reservation = holder.path.clone();
            assert_eq!(
                identity_for_path(&reservation).expect("reservation before tamper"),
                original_identity
            );

            let mut bystander = holder.clone();
            bystander.name = "gap-bystander".to_string();
            bystander.phase = ManagedWorktreeOperationPhase::CreateIntent;
            bystander.path = holder.root.join("gap-bystander");
            bystander.branch = "maco/gap-bystander".to_string();
            bystander.base_oid = "bystander-marker".to_string();
            bystander.prepared_path_identity = None;
            bystander.staging_root = None;
            bystander.staging_root_identity = None;
            bystander.staging_path = None;
            bystander.branch_preexisting_oid = None;
            bystander.branch_ownership = ManagedBranchOwnership::Unknown;
            bystander.owned_branch_oid = None;
            registry
                .operations
                .insert(bystander.name.clone(), bystander);
            registry.operations.remove("gap-holder");
            store
                .save(&lock, &mut registry)
                .expect("retire the prepared incarnation");

            let mut replaced = holder;
            let mut tampered_identity = original_identity.clone();
            tampered_identity.file = tampered_identity.file.wrapping_add(1);
            replaced.prepared_path_identity = Some(tampered_identity.clone());
            replaced.base_oid = "replaced-reservation".to_string();
            registry.operations.insert(replaced.name.clone(), replaced);
            store
                .save(&lock, &mut registry)
                .expect("save replacement operation and new incarnation");
            let incarnation = store
                .active_incarnation(&lock, "gap-holder")
                .expect("replacement incarnation");
            *tamper.lock().expect("tamper lock") = Some((
                original_identity,
                tampered_identity,
                incarnation.nonce,
                reservation,
            ));
        }
    });

    let error = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "gap-holder".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root),
        })
        .expect_err("tampered reservation identity must not publish");
    let message = format!("{error:#}");
    assert!(
        message.contains("refusing to publish"),
        "unexpected publication error: {message}"
    );
    let (original_identity, tampered_identity, nonce, reservation) = tamper
        .lock()
        .expect("tamper lock")
        .take()
        .expect("checkout gap hook did not run");

    let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
    let lock = store.lock().expect("registry lock");
    let registry = store.load(&lock).expect("registry after refusal");
    assert!(!registry.records.contains_key("gap-holder"));
    assert!(!registry.records.contains_key("gap-bystander"));
    let holder = registry
        .operations
        .get("gap-holder")
        .expect("replacement operation must remain");
    assert_eq!(holder.phase, ManagedWorktreeOperationPhase::CreatePrepared);
    assert_eq!(holder.base_oid, "replaced-reservation");
    assert_eq!(
        holder.prepared_path_identity.as_ref(),
        Some(&tampered_identity)
    );
    assert_eq!(
        registry
            .operations
            .get("gap-bystander")
            .map(|operation| operation.base_oid.as_str()),
        Some("bystander-marker")
    );
    assert_eq!(
        store
            .active_incarnation(&lock, "gap-holder")
            .expect("incarnation after refusal")
            .nonce,
        nonce
    );
    assert_eq!(reservation, holder.path);
    assert_eq!(
        identity_for_path(&reservation).expect("reservation was not replaced"),
        original_identity
    );
    assert!(!reservation.join("README.md").exists());
}

#[cfg(unix)]
#[test]
fn same_agent_create_refuses_other_root_while_create_lease_is_live() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    let other_root = temp.path().join("other-worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");

    set_create_checkout_gap_hook({
        let repo_path = repo_path.clone();
        let other_root = other_root.clone();
        move || {
            let repo = crate::git_repository::open(&repo_path).expect("reopen repo");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
            let (prepared, nonce, reservation_identity) = {
                let lock = store
                    .lock_with_timeout(Duration::from_millis(500))
                    .expect("registry lock must be free while the holder lease is live");
                let registry = store.load(&lock).expect("prepared registry");
                let prepared = registry
                    .operations
                    .get("gap-same")
                    .cloned()
                    .expect("live prepared create");
                assert_eq!(
                    prepared.phase,
                    ManagedWorktreeOperationPhase::CreatePrepared
                );
                let reservation_identity = prepared
                    .prepared_path_identity
                    .clone()
                    .expect("reservation identity");
                assert_eq!(
                    identity_for_path(&prepared.path).expect("reservation inode"),
                    reservation_identity
                );
                let nonce = store
                    .active_incarnation(&lock, "gap-same")
                    .expect("live incarnation")
                    .nonce;
                (prepared, nonce, reservation_identity)
            };

            let error = WorktreeManager::new(&repo_path)
                .create_for_test(WorktreeCreateOptions {
                    agent_id: "gap-same".to_string(),
                    branch: Some("maco/gap-same-other".to_string()),
                    base: None,
                    worktree_root: Some(other_root.clone()),
                })
                .expect_err("second create for the same agent must refuse");
            let message = format!("{error:#}");
            assert!(
                message.contains("in-progress registry operation"),
                "unexpected second-create error: {message}"
            );

            let lock = store.lock().expect("registry lock after refused create");
            let registry = store.load(&lock).expect("registry after refused create");
            assert_eq!(registry.operations.get("gap-same"), Some(&prepared));
            assert!(registry.records.is_empty());
            assert_eq!(
                store
                    .active_incarnation(&lock, "gap-same")
                    .expect("incarnation after refused create")
                    .nonce,
                nonce
            );
            assert_eq!(
                identity_for_path(&prepared.path).expect("reservation after refused create"),
                reservation_identity
            );
            assert!(!other_root.join("gap-same").exists());
        }
    });

    let created = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "gap-same".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root),
        })
        .expect("original create completes after the colliding create is refused");
    assert_eq!(created.name, "gap-same");
    assert_eq!(created.branch, "maco/gap-same");
    assert!(created.path.join("README.md").exists());
    assert!(!other_root.join("gap-same").exists());

    let store = ManagedWorktreeRegistryStore::open(&repo).expect("final registry store");
    let lock = store.lock().expect("final registry lock");
    let registry = store.load(&lock).expect("final registry");
    assert!(registry.operations.is_empty());
    assert_eq!(
        registry
            .records
            .get("gap-same")
            .map(|binding| binding.path.as_path()),
        Some(created.path.as_path())
    );
    drop(lock);
}

#[cfg(unix)]
#[test]
fn remove_refuses_live_create_without_changing_prepared_identity() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");

    set_create_checkout_gap_hook({
        let repo_path = repo_path.clone();
        move || {
            let repo = crate::git_repository::open(&repo_path).expect("reopen repo");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
            let (prepared, nonce, reservation_identity) = {
                let lock = store
                    .lock_with_timeout(Duration::from_millis(500))
                    .expect("registry lock must be free while the create lease is live");
                let registry = store.load(&lock).expect("prepared registry");
                let prepared = registry
                    .operations
                    .get("gap-remove")
                    .cloned()
                    .expect("live prepared create");
                assert_eq!(
                    prepared.phase,
                    ManagedWorktreeOperationPhase::CreatePrepared
                );
                assert_eq!(prepared.kind, ManagedWorktreeOperationKind::Create);
                let reservation_identity = prepared
                    .prepared_path_identity
                    .clone()
                    .expect("reservation identity");
                assert_eq!(
                    identity_for_path(&prepared.path).expect("reservation inode"),
                    reservation_identity
                );
                let nonce = store
                    .active_incarnation(&lock, "gap-remove")
                    .expect("live incarnation")
                    .nonce;
                (prepared, nonce, reservation_identity)
            };

            for delete_branch in [false, true] {
                let error = WorktreeManager::new(&repo_path)
                    .remove("gap-remove", true, delete_branch)
                    .expect_err("same-agent remove must refuse a live create");
                let message = format!("{error:#}");
                assert!(
                    message.contains("in-progress create operation"),
                    "delete_branch={delete_branch}: {message}"
                );
            }

            let lock = store.lock().expect("registry lock after refused removal");
            let registry = store.load(&lock).expect("registry after refused removal");
            assert_eq!(registry.operations.get("gap-remove"), Some(&prepared));
            assert!(registry.records.is_empty());
            assert_eq!(
                store
                    .active_incarnation(&lock, "gap-remove")
                    .expect("incarnation after refused removal")
                    .nonce,
                nonce
            );
            assert_eq!(
                identity_for_path(&prepared.path).expect("reservation after refused removal"),
                reservation_identity
            );
        }
    });

    let created = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "gap-remove".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root),
        })
        .expect("original create completes after refused removal");
    assert_eq!(created.name, "gap-remove");
    assert_eq!(created.branch, "maco/gap-remove");
    assert!(created.path.join("README.md").exists());

    let store = ManagedWorktreeRegistryStore::open(&repo).expect("final registry store");
    let lock = store.lock().expect("final registry lock");
    let registry = store.load(&lock).expect("final registry");
    assert!(registry.operations.is_empty());
    assert_eq!(
        registry
            .records
            .get("gap-remove")
            .map(|binding| binding.path.as_path()),
        Some(created.path.as_path())
    );
    drop(lock);
}

#[cfg(target_os = "linux")]
#[test]
fn cross_process_create_lease_blocks_pending_recovery() {
    skip_without_containment!();
    const CHILD_ENV: &str = "MACO_TEST_CREATE_LEASE_RECOVERY_CHILD";
    const REPO_ENV: &str = "MACO_TEST_CREATE_LEASE_REPO";
    const RECEIPT_ENV: &str = "MACO_TEST_CREATE_LEASE_RECEIPT";
    const COMPLETED: &[u8] = b"cross-process create lease recovery left the operation intact\n";

    if std::env::var_os(CHILD_ENV).is_some() {
        let repo_path = PathBuf::from(std::env::var(REPO_ENV).expect("child repo path"));
        let repo = crate::git_repository::open(&repo_path).expect("child repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("child registry store");
        let lock = store.lock().expect("child registry lock");
        let mut registry = store.load(&lock).expect("child registry");
        let before = registry
            .operations
            .get("gap-cross")
            .cloned()
            .expect("parent prepared create");
        assert_eq!(before.phase, ManagedWorktreeOperationPhase::CreatePrepared);
        let reservation_identity = before
            .prepared_path_identity
            .clone()
            .expect("reservation identity");
        assert_eq!(
            identity_for_path(&before.path).expect("child reservation inode"),
            reservation_identity
        );
        let nonce = store
            .active_incarnation(&lock, "gap-cross")
            .expect("child incarnation")
            .nonce;
        // Separate process: the parent's in-process lease table is not visible.
        recover_pending_operations(&repo, &store, &lock, &mut registry)
            .expect("kernel create lease must keep recovery from failing closed");
        let after = store.load(&lock).expect("child registry after recovery");
        assert_eq!(after.operations.get("gap-cross"), Some(&before));
        assert!(after.records.is_empty());
        assert_eq!(
            identity_for_path(&before.path).expect("reservation after cross-process recovery"),
            reservation_identity
        );
        assert_eq!(
            local_branch_oid(&repo, "maco/gap-cross").expect("branch after cross-process recovery"),
            Some(
                Oid::from_str(&before.owned_branch_oid.expect("owned branch oid"))
                    .expect("owned oid")
            )
        );
        assert_eq!(
            store
                .active_incarnation(&lock, "gap-cross")
                .expect("incarnation after cross-process recovery")
                .nonce,
            nonce
        );
        fs::write(
            std::env::var(RECEIPT_ENV).expect("child receipt path"),
            COMPLETED,
        )
        .expect("write child receipt");
        return;
    }

    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    let receipt = temp.path().join("child-receipt");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    let oid = commit_readme(&repo).expect("initial commit");
    let commit = repo.find_commit(oid).expect("commit");
    let root = SafeRoot::open_or_create_managed(&worktree_root).expect("managed root");
    let name = "gap-cross".to_string();
    let reserved = root
        .reserve_direct_child_directory(&name)
        .expect("empty reservation");
    let staging = root
        .reserve_random_direct_child_directory("gap-cross-stage")
        .expect("empty staging root");
    repo.branch("maco/gap-cross", &commit, false)
        .expect("owned branch");
    let reservation_identity = reserved.identity().clone();
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
    let lock = store.lock().expect("registry lock");
    let mut registry = store.load(&lock).expect("empty registry");
    registry.operations.insert(
        name.clone(),
        ManagedWorktreeOperation {
            kind: ManagedWorktreeOperationKind::Create,
            phase: ManagedWorktreeOperationPhase::CreatePrepared,
            name: name.clone(),
            root: root.path().to_path_buf(),
            root_identity: root.identity().clone(),
            path: reserved.path().to_path_buf(),
            prepared_path_identity: Some(reservation_identity.clone()),
            staging_root: Some(staging.path().to_path_buf()),
            staging_root_identity: Some(staging.identity().clone()),
            staging_path: Some(staging.path().join(&name)),
            staged_path_identity: None,
            staged_metadata: None,
            branch: "maco/gap-cross".to_string(),
            base_oid: oid.to_string(),
            branch_preexisting_oid: None,
            branch_ownership: ManagedBranchOwnership::CreatedByMaco,
            owned_branch_oid: Some(oid.to_string()),
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
    store
        .save(&lock, &mut registry)
        .expect("save prepared create");
    let lease = store
        .try_acquire_worktree_create_lease(&lock, &name)
        .expect("parent create lease");
    drop(lock);

    let environment = std::collections::BTreeMap::from([
        (CHILD_ENV.to_string(), "1".to_string()),
        (
            REPO_ENV.to_string(),
            repo_path.to_str().expect("UTF-8 repo path").to_string(),
        ),
        (
            RECEIPT_ENV.to_string(),
            receipt.to_str().expect("UTF-8 receipt path").to_string(),
        ),
    ]);
    let output = run_process(
        ProcessSpec::direct(
            "cross-process create lease recovery",
            std::env::current_exe().expect("current test executable"),
            [
                "--exact",
                "worktree::tests::cross_process_create_lease_blocks_pending_recovery",
                "--nocapture",
            ],
            std::env::current_dir().expect("current test directory"),
            64 * 1024,
        )
        .with_environment(EnvironmentMode::InheritAndSet(environment))
        .with_containment(ContainmentPolicy::TrustedBestEffort)
        .with_stdin(StdinMode::Null)
        .with_timeout(Some(Duration::from_secs(90))),
    )
    .expect("run cross-process create lease recovery");
    assert!(
        output.status.is_some_and(|status| status.success())
            && !output.timed_out
            && output.process_error.is_none()
            && output.stdin_error.is_none(),
        "cross-process helper failed: status={:?}, timed_out={}, process_error={:?}, stdin_error={:?}, stdout={}, stderr={}",
        output.status,
        output.timed_out,
        output.process_error,
        output.stdin_error,
        String::from_utf8_lossy(output.stdout.as_bytes()),
        String::from_utf8_lossy(output.stderr.as_bytes()),
    );
    assert_eq!(fs::read(&receipt).expect("child receipt"), COMPLETED);

    let lock = store.lock().expect("registry lock after child");
    let persisted = store.load(&lock).expect("registry after child");
    let operation = persisted
        .operations
        .get(&name)
        .expect("prepared operation remains after the child");
    assert_eq!(
        operation.phase,
        ManagedWorktreeOperationPhase::CreatePrepared
    );
    assert_eq!(
        operation.prepared_path_identity.as_ref(),
        Some(&reservation_identity)
    );
    assert!(persisted.records.is_empty());
    assert_eq!(
        identity_for_path(reserved.path()).expect("reservation after child"),
        reservation_identity
    );
    assert_eq!(
        local_branch_oid(&repo, "maco/gap-cross").expect("branch after child"),
        Some(oid)
    );
    drop(lease);
    let mut registry = persisted;
    recover_pending_operations(&repo, &store, &lock, &mut registry)
        .expect("released lease remains recoverable");
    let recovered = store.load(&lock).expect("registry after parent recovery");
    assert!(recovered.operations.is_empty());
    assert!(recovered.records.is_empty());
    assert!(!reserved.path().exists());
    assert_eq!(
        local_branch_oid(&repo, "maco/gap-cross").expect("owned branch cleaned after release"),
        None
    );
}

#[cfg(unix)]
#[test]
fn no_cleanliness_recovery_skips_busy_create_and_refuses_after_release() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    let removed = WorktreeManager::new(&repo_path)
        .create_for_test(WorktreeCreateOptions {
            agent_id: "life-remove".to_string(),
            branch: None,
            base: None,
            worktree_root: Some(worktree_root.clone()),
        })
        .expect("unrelated managed worktree");

    let oid = repo
        .head()
        .expect("head")
        .peel_to_commit()
        .expect("head commit")
        .id();
    let commit = repo.find_commit(oid).expect("commit");
    let root = SafeRoot::open_or_create_managed(&worktree_root).expect("managed root");
    let create_name = "life-create".to_string();
    let reserved = root
        .reserve_direct_child_directory(&create_name)
        .expect("empty create reservation");
    let staging = root
        .reserve_random_direct_child_directory("life-create-stage")
        .expect("empty staging root");
    repo.branch("maco/life-create", &commit, false)
        .expect("owned create branch");
    let reservation_identity = reserved.identity().clone();
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
    let lock = store.lock().expect("registry lock");
    let mut registry = store.load(&lock).expect("registry");
    registry.operations.insert(
        create_name.clone(),
        ManagedWorktreeOperation {
            kind: ManagedWorktreeOperationKind::Create,
            phase: ManagedWorktreeOperationPhase::CreatePrepared,
            name: create_name.clone(),
            root: root.path().to_path_buf(),
            root_identity: root.identity().clone(),
            path: reserved.path().to_path_buf(),
            prepared_path_identity: Some(reservation_identity.clone()),
            staging_root: Some(staging.path().to_path_buf()),
            staging_root_identity: Some(staging.identity().clone()),
            staging_path: Some(staging.path().join(&create_name)),
            staged_path_identity: None,
            staged_metadata: None,
            branch: "maco/life-create".to_string(),
            base_oid: oid.to_string(),
            branch_preexisting_oid: None,
            branch_ownership: ManagedBranchOwnership::CreatedByMaco,
            owned_branch_oid: Some(oid.to_string()),
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
    store.save(&lock, &mut registry).expect("save busy create");
    registry
        .records
        .get_mut("life-remove")
        .expect("removable record")
        .creation_lock_pending = true;
    store
        .save(&lock, &mut registry)
        .expect("save pending creation lock");
    let create_while_locked = registry
        .operations
        .get(&create_name)
        .cloned()
        .expect("create beside pending creation lock");
    let pending_lock_error = recover_pending_operations_without_creation_cleanliness(
        &repo,
        &store,
        &lock,
        &mut registry,
        None,
    )
    .expect_err("pending creation lock still requires cleanliness authority");
    assert!(
        pending_lock_error
            .to_string()
            .contains("capability-bound repository cleanliness"),
        "unexpected creation-lock error: {pending_lock_error:#}"
    );
    let locked = store
        .load(&lock)
        .expect("registry after creation-lock refusal");
    assert_eq!(
        locked.operations.get(&create_name),
        Some(&create_while_locked)
    );
    assert!(locked
        .records
        .get("life-remove")
        .is_some_and(|binding| binding.creation_lock_pending));
    assert_eq!(
        identity_for_path(reserved.path()).expect("reservation after creation-lock refusal"),
        reservation_identity
    );
    assert!(removed.path.exists());

    registry = locked;
    registry
        .records
        .get_mut("life-remove")
        .expect("removable record")
        .creation_lock_pending = false;
    store
        .save(&lock, &mut registry)
        .expect("clear creation lock");
    let lease = store
        .try_acquire_worktree_create_lease(&lock, &create_name)
        .expect("live create lease");
    let (remove_binding, _, _, _) =
        prepare_remove_operation_for_test(&repo, &store, &lock, &mut registry);
    let create_while_busy = registry
        .operations
        .get(&create_name)
        .cloned()
        .expect("busy create");
    recover_pending_operations_without_creation_cleanliness(
        &repo,
        &store,
        &lock,
        &mut registry,
        None,
    )
    .expect("busy create must not block unrelated removal");
    let during_lease = store.load(&lock).expect("registry during live create");
    assert_eq!(
        during_lease.operations.get(&create_name),
        Some(&create_while_busy)
    );
    assert!(!during_lease.records.contains_key("life-remove"));
    assert!(!during_lease.operations.contains_key("life-remove"));
    assert!(!remove_binding.path.exists());
    assert_eq!(
        identity_for_path(reserved.path()).expect("reservation while create lease is held"),
        reservation_identity
    );
    assert_eq!(
        local_branch_oid(&repo, "maco/life-create").expect("create branch while lease is held"),
        Some(oid)
    );

    drop(lease);
    let released_error = recover_pending_operations_without_creation_cleanliness(
        &repo,
        &store,
        &lock,
        &mut registry,
        None,
    )
    .expect_err("unleased create still requires cleanliness authority");
    assert!(
        released_error
            .to_string()
            .contains("capability-bound repository cleanliness"),
        "unexpected released-lease error: {released_error:#}"
    );
    let released = store.load(&lock).expect("registry after released lease");
    assert_eq!(
        released.operations.get(&create_name),
        Some(&create_while_busy)
    );
    assert!(released.records.is_empty());
    assert_eq!(
        identity_for_path(reserved.path()).expect("reservation after released lease"),
        reservation_identity
    );
    assert!(staging.path().exists());
    assert_eq!(
        local_branch_oid(&repo, "maco/life-create").expect("create branch after refusal"),
        Some(oid)
    );
}

#[cfg(target_os = "linux")]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(target_os = "linux")]
use std::sync::{Arc, Mutex};

#[cfg(target_os = "linux")]
const GAP_OWNER: &str = "gap-owner";
#[cfg(target_os = "linux")]
const GAP_PEER: &str = "gap-peer";
#[cfg(target_os = "linux")]
const GAP_BYSTANDER: &str = "gap-bystander";
#[cfg(target_os = "linux")]
const GAP_PEER_BRANCH: &str = "maco/gap-peer";
#[cfg(target_os = "linux")]
const GAP_BYSTANDER_BRANCH: &str = "maco/gap-bystander";

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
enum OwnedCleanlinessGap {
    Staged,
    Observed,
    Pending,
}

#[cfg(target_os = "linux")]
fn gap_hook_phase(kind: OwnedCleanlinessGap) -> CreateCleanlinessGapPhase {
    match kind {
        OwnedCleanlinessGap::Staged => {
            CreateCleanlinessGapPhase::Operation(ManagedWorktreeOperationPhase::CreateStaged)
        }
        OwnedCleanlinessGap::Observed => {
            CreateCleanlinessGapPhase::Operation(ManagedWorktreeOperationPhase::CreateObserved)
        }
        OwnedCleanlinessGap::Pending => CreateCleanlinessGapPhase::PendingCreationLock,
    }
}

#[cfg(target_os = "linux")]
fn fresh_public_create_repo(temp: &TempDir) -> (PathBuf, PathBuf) {
    let repo_path = temp.path().join("repo");
    let worktree_root = temp.path().join("worktrees");
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    commit_readme(&crate::git_repository::open(&repo_path).expect("open repo")).expect("commit");
    (repo_path, worktree_root)
}

#[cfg(target_os = "linux")]
fn public_create_record(
    repo_path: &Path,
    agent_id: &str,
    branch: Option<&str>,
    worktree_root: &Path,
) -> anyhow::Result<WorktreeRecord> {
    WorktreeManager::new(repo_path).create(WorktreeCreateOptions {
        agent_id: agent_id.to_string(),
        branch: branch.map(str::to_string),
        base: None,
        worktree_root: Some(worktree_root.to_path_buf()),
    })
}

#[cfg(target_os = "linux")]
fn assert_busy_owner(
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
) -> ManagedIncarnation {
    let incarnation = store
        .active_incarnation(lock, GAP_OWNER)
        .expect("active owner incarnation");
    assert!(incarnation.active);
    assert!(
        matches!(
            store
                .admit_create_recovery(lock, GAP_OWNER)
                .expect("admit owner create"),
            CreateRecoveryAdmission::Busy
        ),
        "owner incarnation lease must stay busy during cleanliness"
    );
    incarnation
}

#[cfg(target_os = "linux")]
fn assert_gap_durable(registry: &ManagedWorktreeRegistry, kind: OwnedCleanlinessGap) {
    match kind {
        OwnedCleanlinessGap::Staged => {
            assert_eq!(
                registry
                    .operations
                    .get(GAP_OWNER)
                    .map(|operation| operation.phase),
                Some(ManagedWorktreeOperationPhase::CreateStaged)
            );
        }
        OwnedCleanlinessGap::Observed => {
            let operation = registry
                .operations
                .get(GAP_OWNER)
                .expect("observed create operation");
            assert_eq!(
                operation.phase,
                ManagedWorktreeOperationPhase::CreateObserved
            );
            assert!(operation
                .binding
                .as_ref()
                .is_some_and(|binding| binding.creation_lock_pending));
        }
        OwnedCleanlinessGap::Pending => {
            assert!(!registry.operations.contains_key(GAP_OWNER));
            assert!(registry
                .records
                .get(GAP_OWNER)
                .is_some_and(|binding| binding.creation_lock_pending));
        }
    }
}

#[cfg(target_os = "linux")]
fn intent_bystander(
    root: &Path,
    root_identity: FileIdentity,
    base_oid: &str,
) -> ManagedWorktreeOperation {
    ManagedWorktreeOperation {
        kind: ManagedWorktreeOperationKind::Create,
        phase: ManagedWorktreeOperationPhase::CreateIntent,
        name: GAP_BYSTANDER.to_string(),
        root: root.to_path_buf(),
        root_identity,
        path: root.join(GAP_BYSTANDER),
        prepared_path_identity: None,
        staging_root: None,
        staging_root_identity: None,
        staging_path: None,
        staged_path_identity: None,
        staged_metadata: None,
        branch: GAP_BYSTANDER_BRANCH.to_string(),
        base_oid: base_oid.to_string(),
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
    }
}

#[cfg(target_os = "linux")]
fn creation_lock_is_held(repo: &git2::Repository, name: &str) -> bool {
    matches!(
        repo.find_worktree(name)
            .expect("worktree")
            .is_locked()
            .expect("creation lock"),
        git2::WorktreeLockStatus::Locked(_)
    )
}

#[cfg(target_os = "linux")]
struct PendingOwnerSnapshot {
    binding: ManagedWorktreeBinding,
    incarnation: ManagedIncarnation,
    branch_oid: Option<Oid>,
    path_identity: FileIdentity,
}

#[cfg(target_os = "linux")]
fn assert_pending_snapshot(
    repo: &git2::Repository,
    store: &ManagedWorktreeRegistryStore,
    lock: &ManagedWorktreeRegistryLock,
    snapshot: &PendingOwnerSnapshot,
) {
    let registry = store.load(lock).expect("reload pending registry");
    assert_eq!(registry.records.get(GAP_OWNER), Some(&snapshot.binding));
    assert!(!registry.operations.contains_key(GAP_OWNER));
    let incarnation = store
        .active_incarnation(lock, GAP_OWNER)
        .expect("pending incarnation");
    assert!(incarnation.active);
    assert_eq!(incarnation.generation, snapshot.incarnation.generation);
    assert_eq!(incarnation.nonce, snapshot.incarnation.nonce);
    assert_eq!(
        local_branch_oid(repo, &snapshot.binding.branch).expect("branch oid"),
        snapshot.branch_oid
    );
    assert_eq!(
        identity_for_path(&snapshot.binding.path).expect("path identity"),
        snapshot.path_identity
    );
    assert!(creation_lock_is_held(repo, GAP_OWNER));
}

#[cfg(target_os = "linux")]
struct StaleGapWitness {
    nonce: String,
    base_oid: String,
    staged_operation: Option<ManagedWorktreeOperation>,
    stamp: Option<i64>,
    preserved_record: Option<ManagedWorktreeBinding>,
    branch_oid: Option<Oid>,
    path_identity: Option<FileIdentity>,
}

#[cfg(target_os = "linux")]
#[test]
fn public_create_allows_peer_progress_at_each_owned_cleanliness_gap() {
    skip_without_containment!();
    for kind in [
        OwnedCleanlinessGap::Staged,
        OwnedCleanlinessGap::Observed,
        OwnedCleanlinessGap::Pending,
    ] {
        let temp = TempDir::new().expect("tempdir");
        let (repo_path, worktree_root) = fresh_public_create_repo(&temp);
        let calls = Arc::new(AtomicUsize::new(0));
        let seen = Arc::new(Mutex::new(
            None::<(
                ManagedIncarnation,
                ManagedWorktreeBinding,
                ManagedIncarnation,
            )>,
        ));
        set_create_cleanliness_gap_hook(gap_hook_phase(kind), {
            let repo_path = repo_path.clone();
            let worktree_root = worktree_root.clone();
            let calls = Arc::clone(&calls);
            let seen = Arc::clone(&seen);
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                let repo = crate::git_repository::open(&repo_path).expect("reopen repo");
                let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
                let owner_incarnation = {
                    let lock = store
                        .lock_with_timeout(Duration::from_millis(500))
                        .expect("registry lock must be free during cleanliness");
                    let registry = store.load(&lock).expect("registry during cleanliness");
                    assert_gap_durable(&registry, kind);
                    let incarnation = assert_busy_owner(&store, &lock);
                    drop(lock);
                    incarnation
                };
                let peer = public_create_record(
                    &repo_path,
                    GAP_PEER,
                    Some(GAP_PEER_BRANCH),
                    &worktree_root,
                )
                .unwrap_or_else(|error| panic!("{kind:?} peer create failed: {error:#}"));
                let lock = store
                    .lock_with_timeout(Duration::from_millis(500))
                    .expect("registry lock after peer create");
                let registry = store.load(&lock).expect("registry after peer");
                assert_gap_durable(&registry, kind);
                let owner_after = assert_busy_owner(&store, &lock);
                assert_eq!(owner_after.nonce, owner_incarnation.nonce);
                assert_eq!(owner_after.generation, owner_incarnation.generation);
                let peer_binding = registry
                    .records
                    .get(GAP_PEER)
                    .cloned()
                    .expect("exact peer binding");
                assert_eq!(peer_binding.path, peer.path);
                assert_eq!(peer_binding.branch, GAP_PEER_BRANCH);
                assert!(!peer_binding.creation_lock_pending);
                let peer_incarnation = store
                    .active_incarnation(&lock, GAP_PEER)
                    .expect("peer incarnation");
                assert!(peer_incarnation.active);
                drop(lock);
                *seen.lock().expect("witness") =
                    Some((owner_incarnation, peer_binding, peer_incarnation));
            }
        });

        let owner = public_create_record(&repo_path, GAP_OWNER, None, &worktree_root)
            .unwrap_or_else(|error| panic!("{kind:?} owner create failed: {error:#}"));
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{kind:?} hook count");
        let (owner_incarnation, peer_binding, peer_incarnation) = seen
            .lock()
            .expect("witness")
            .take()
            .expect("cleanliness hook fired once");
        let repo = crate::git_repository::open(&repo_path).expect("reopen final repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("final store");
        let lock = store.lock().expect("final lock");
        let registry = store.load(&lock).expect("final registry");
        assert!(registry.operations.is_empty(), "{kind:?} operations remain");
        let owner_binding = registry.records.get(GAP_OWNER).expect("owner record");
        assert_eq!(owner_binding.path, owner.path);
        assert_eq!(owner_binding.branch, "maco/gap-owner");
        assert!(!owner_binding.creation_lock_pending);
        assert_ne!(owner_binding.branch, peer_binding.branch);
        assert_eq!(registry.records.get(GAP_PEER), Some(&peer_binding));
        let owner_now = store
            .active_incarnation(&lock, GAP_OWNER)
            .expect("final owner incarnation");
        assert!(owner_now.active);
        assert_eq!(owner_now.nonce, owner_incarnation.nonce);
        assert_eq!(owner_now.generation, owner_incarnation.generation);
        let peer_now = store
            .active_incarnation(&lock, GAP_PEER)
            .expect("final peer incarnation");
        assert!(peer_now.active);
        assert_eq!(peer_now.nonce, peer_incarnation.nonce);
        assert_eq!(peer_now.generation, peer_incarnation.generation);
    }
}

#[cfg(target_os = "linux")]
#[test]
fn pending_owned_create_blocks_remove_and_skips_busy_recovery() {
    skip_without_containment!();
    let temp = TempDir::new().expect("tempdir");
    let (repo_path, worktree_root) = fresh_public_create_repo(&temp);
    let peer = public_create_record(&repo_path, GAP_PEER, Some(GAP_PEER_BRANCH), &worktree_root)
        .expect("public peer before the pending cleanliness gap");
    assert_eq!(peer.name, GAP_PEER);
    assert_eq!(peer.branch, GAP_PEER_BRANCH);
    let calls = Arc::new(AtomicUsize::new(0));
    let nonce = Arc::new(Mutex::new(None::<String>));
    set_create_cleanliness_gap_hook(CreateCleanlinessGapPhase::PendingCreationLock, {
        let repo_path = repo_path.clone();
        let peer = peer.clone();
        let calls = Arc::clone(&calls);
        let nonce = Arc::clone(&nonce);
        move || {
            calls.fetch_add(1, Ordering::SeqCst);
            let repo = crate::git_repository::open(&repo_path).expect("reopen repo");
            let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
            let snapshot = {
                let lock = store
                    .lock_with_timeout(Duration::from_millis(500))
                    .expect("registry lock must be free during pending cleanliness");
                let registry = store.load(&lock).expect("pending registry");
                assert_gap_durable(&registry, OwnedCleanlinessGap::Pending);
                let incarnation = assert_busy_owner(&store, &lock);
                let binding = registry
                    .records
                    .get(GAP_OWNER)
                    .cloned()
                    .expect("pending binding");
                let branch_oid = local_branch_oid(&repo, &binding.branch).expect("branch oid");
                let path_identity = identity_for_path(&binding.path).expect("path identity");
                assert!(creation_lock_is_held(&repo, GAP_OWNER));
                drop(lock);
                PendingOwnerSnapshot {
                    binding,
                    incarnation,
                    branch_oid,
                    path_identity,
                }
            };

            let listed = WorktreeManager::new(&repo_path)
                .list()
                .unwrap_or_else(|error| panic!("busy pending list must skip, not fail: {error:#}"));
            assert!(
                listed.iter().any(|record| {
                    record.name == peer.name
                        && record.path == peer.path
                        && record.branch == peer.branch
                }),
                "busy pending list omitted the finished peer"
            );
            assert!(
                listed.iter().all(|record| record.name != GAP_OWNER),
                "busy pending owner was listed"
            );
            for delete_branch in [false, true] {
                let error = WorktreeManager::new(&repo_path)
                    .remove(GAP_OWNER, true, delete_branch)
                    .expect_err("live create must refuse removal");
                let message = format!("{error:#}");
                assert!(
                    message.contains(GAP_OWNER),
                    "delete_branch={delete_branch}: {message}"
                );
            }

            let cleanliness = WorktreeManager::new(&repo_path)
                .acquire_repository_cleanliness()
                .expect("real cleanliness capability");
            let lock = store
                .lock_with_timeout(Duration::from_millis(500))
                .expect("registry lock after refused removal");
            assert_pending_snapshot(&repo, &store, &lock, &snapshot);
            let mut registry = store.load(&lock).expect("registry for authorized recovery");
            recover_pending_operations_with_creation_cleanliness(
                &repo,
                &store,
                &lock,
                &mut registry,
                CreationCleanliness::Bound(&cleanliness),
            )
            .expect("authorized recovery skips busy pending create");
            assert_pending_snapshot(&repo, &store, &lock, &snapshot);
            registry = store
                .load(&lock)
                .expect("registry for no-authority recovery");
            recover_pending_operations_without_creation_cleanliness(
                &repo,
                &store,
                &lock,
                &mut registry,
                None,
            )
            .expect("no-authority recovery skips busy pending create");
            assert_pending_snapshot(&repo, &store, &lock, &snapshot);
            *nonce.lock().expect("nonce") = Some(snapshot.incarnation.nonce.clone());
            drop(lock);
        }
    });

    let owner = public_create_record(&repo_path, GAP_OWNER, None, &worktree_root)
        .expect("owner finishes pending create");
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    let nonce = nonce.lock().expect("nonce").take().expect("hook fired");
    let listed = WorktreeManager::new(&repo_path)
        .list()
        .expect("list after owner finishes");
    assert!(listed.iter().any(|record| {
        record.name == GAP_OWNER && record.path == owner.path && record.branch == owner.branch
    }));
    assert!(listed.iter().any(|record| {
        record.name == peer.name && record.path == peer.path && record.branch == peer.branch
    }));
    let repo = crate::git_repository::open(&repo_path).expect("reopen finished repo");
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("finished store");
    let lock = store.lock().expect("finished lock");
    let registry = store.load(&lock).expect("finished registry");
    assert!(registry.operations.is_empty());
    assert!(
        !registry
            .records
            .get(GAP_OWNER)
            .expect("finished owner")
            .creation_lock_pending
    );
    let incarnation = store
        .active_incarnation(&lock, GAP_OWNER)
        .expect("finished incarnation");
    assert!(incarnation.active);
    assert_eq!(incarnation.nonce, nonce);
    assert!(!creation_lock_is_held(&repo, GAP_OWNER));
}

#[cfg(target_os = "linux")]
#[test]
fn public_create_refuses_stale_target_after_owned_cleanliness_gap() {
    skip_without_containment!();
    for kind in [
        OwnedCleanlinessGap::Staged,
        OwnedCleanlinessGap::Observed,
        OwnedCleanlinessGap::Pending,
    ] {
        let temp = TempDir::new().expect("tempdir");
        let (repo_path, worktree_root) = fresh_public_create_repo(&temp);
        let calls = Arc::new(AtomicUsize::new(0));
        let witness = Arc::new(Mutex::new(None::<StaleGapWitness>));
        set_create_cleanliness_gap_hook(gap_hook_phase(kind), {
            let repo_path = repo_path.clone();
            let calls = Arc::clone(&calls);
            let witness = Arc::clone(&witness);
            move || {
                calls.fetch_add(1, Ordering::SeqCst);
                let repo = crate::git_repository::open(&repo_path).expect("reopen repo");
                let store = ManagedWorktreeRegistryStore::open(&repo).expect("registry store");
                let lock = store
                    .lock_with_timeout(Duration::from_millis(500))
                    .expect("registry lock must be free during cleanliness");
                let mut registry = store.load(&lock).expect("registry");
                assert_gap_durable(&registry, kind);
                let previous_nonce = assert_busy_owner(&store, &lock).nonce;
                let proof = match kind {
                    OwnedCleanlinessGap::Staged => {
                        let holder = registry
                            .operations
                            .get(GAP_OWNER)
                            .cloned()
                            .expect("staged operation");
                        let base_oid = holder.base_oid.clone();
                        registry.operations.insert(
                            GAP_BYSTANDER.to_string(),
                            intent_bystander(
                                &holder.root,
                                holder.root_identity.clone(),
                                &holder.base_oid,
                            ),
                        );
                        registry.operations.remove(GAP_OWNER);
                        store
                            .save(&lock, &mut registry)
                            .expect("retire staged incarnation");
                        registry
                            .operations
                            .insert(GAP_OWNER.to_string(), holder.clone());
                        store
                            .save(&lock, &mut registry)
                            .expect("reinsert staged operation");
                        let nonce = store
                            .active_incarnation(&lock, GAP_OWNER)
                            .expect("replacement incarnation")
                            .nonce;
                        assert_ne!(nonce, previous_nonce);
                        StaleGapWitness {
                            nonce,
                            base_oid,
                            staged_operation: Some(holder),
                            stamp: None,
                            preserved_record: None,
                            branch_oid: None,
                            path_identity: None,
                        }
                    }
                    OwnedCleanlinessGap::Observed => {
                        let preserved_record = registry.records.get(GAP_OWNER).cloned();
                        let mut operation = registry
                            .operations
                            .get(GAP_OWNER)
                            .cloned()
                            .expect("observed operation");
                        let base_oid = operation.base_oid.clone();
                        registry.operations.insert(
                            GAP_BYSTANDER.to_string(),
                            intent_bystander(
                                &operation.root,
                                operation.root_identity.clone(),
                                &operation.base_oid,
                            ),
                        );
                        let mut binding = operation.binding.clone().expect("observed binding");
                        let stamp = binding
                            .created_at_unix_nanos
                            .expect("observed schema timestamp")
                            .saturating_sub(1);
                        assert_ne!(Some(stamp), binding.created_at_unix_nanos);
                        binding.created_at_unix_nanos = Some(stamp);
                        operation.binding = Some(binding);
                        registry.operations.insert(GAP_OWNER.to_string(), operation);
                        store
                            .save(&lock, &mut registry)
                            .expect("save observed binding timestamp");
                        let nonce = store
                            .active_incarnation(&lock, GAP_OWNER)
                            .expect("observed incarnation")
                            .nonce;
                        assert_eq!(nonce, previous_nonce);
                        StaleGapWitness {
                            nonce,
                            base_oid,
                            staged_operation: None,
                            stamp: Some(stamp),
                            preserved_record,
                            branch_oid: None,
                            path_identity: None,
                        }
                    }
                    OwnedCleanlinessGap::Pending => {
                        let mut binding = registry
                            .records
                            .get(GAP_OWNER)
                            .cloned()
                            .expect("pending binding");
                        let branch_oid =
                            local_branch_oid(&repo, &binding.branch).expect("pending branch");
                        let path_identity = identity_for_path(&binding.path).expect("pending path");
                        let base_oid = binding.base_oid.clone();
                        registry.operations.insert(
                            GAP_BYSTANDER.to_string(),
                            intent_bystander(
                                &binding.root,
                                binding.root_identity.clone(),
                                &binding.base_oid,
                            ),
                        );
                        let stamp = binding
                            .created_at_unix_nanos
                            .expect("pending schema timestamp")
                            .saturating_sub(1);
                        assert_ne!(Some(stamp), binding.created_at_unix_nanos);
                        binding.created_at_unix_nanos = Some(stamp);
                        registry.records.insert(GAP_OWNER.to_string(), binding);
                        store
                            .save(&lock, &mut registry)
                            .expect("save pending binding timestamp");
                        let nonce = store
                            .active_incarnation(&lock, GAP_OWNER)
                            .expect("pending incarnation")
                            .nonce;
                        assert_eq!(nonce, previous_nonce);
                        assert!(creation_lock_is_held(&repo, GAP_OWNER));
                        StaleGapWitness {
                            nonce,
                            base_oid,
                            staged_operation: None,
                            stamp: Some(stamp),
                            preserved_record: None,
                            branch_oid,
                            path_identity: Some(path_identity),
                        }
                    }
                };
                drop(lock);
                *witness.lock().expect("witness") = Some(proof);
            }
        });

        let error = public_create_record(&repo_path, GAP_OWNER, None, &worktree_root)
            .expect_err("stale cleanliness target must fail revalidation");
        assert_eq!(calls.load(Ordering::SeqCst), 1, "{kind:?} hook count");
        let message = format!("{error:#}");
        assert!(message.contains(GAP_OWNER), "{kind:?}: {message}");
        let proof = witness
            .lock()
            .expect("witness")
            .take()
            .expect("stale hook fired");
        let repo = crate::git_repository::open(&repo_path).expect("reopen stale repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("stale store");
        let lock = store.lock().expect("stale lock");
        let registry = store.load(&lock).expect("stale registry");
        assert_eq!(
            registry
                .operations
                .get(GAP_BYSTANDER)
                .map(|operation| operation.base_oid.as_str()),
            Some(proof.base_oid.as_str())
        );
        let incarnation = store
            .active_incarnation(&lock, GAP_OWNER)
            .expect("incarnation after refusal");
        assert!(incarnation.active);
        assert_eq!(incarnation.nonce, proof.nonce);
        match kind {
            OwnedCleanlinessGap::Staged => {
                assert_eq!(
                    registry.operations.get(GAP_OWNER),
                    proof.staged_operation.as_ref()
                );
                assert!(!registry.records.contains_key(GAP_OWNER));
            }
            OwnedCleanlinessGap::Observed => {
                let operation = registry
                    .operations
                    .get(GAP_OWNER)
                    .expect("stale observed operation");
                assert_eq!(
                    operation.phase,
                    ManagedWorktreeOperationPhase::CreateObserved
                );
                assert_eq!(
                    operation
                        .binding
                        .as_ref()
                        .and_then(|binding| binding.created_at_unix_nanos),
                    proof.stamp
                );
                assert_eq!(
                    registry.records.get(GAP_OWNER),
                    proof.preserved_record.as_ref()
                );
            }
            OwnedCleanlinessGap::Pending => {
                let binding = registry
                    .records
                    .get(GAP_OWNER)
                    .expect("stale pending record");
                assert_eq!(binding.created_at_unix_nanos, proof.stamp);
                assert!(binding.creation_lock_pending);
                assert!(!registry.operations.contains_key(GAP_OWNER));
                assert_eq!(
                    local_branch_oid(&repo, &binding.branch).expect("branch after refusal"),
                    proof.branch_oid
                );
                assert_eq!(
                    identity_for_path(&binding.path).expect("path after refusal"),
                    proof.path_identity.expect("path identity")
                );
                assert!(creation_lock_is_held(&repo, GAP_OWNER));
            }
        }
    }
}

const REGISTRY_ADMISSION_LOCK_NAME: &str = "managed_worktrees.lock";

fn registry_admission_repo(temp: &TempDir, name: &str) -> PathBuf {
    let repo_path = temp.path().join(name);
    WorktreeManager::init_repository(&repo_path, "main").expect("init repo");
    let repo = crate::git_repository::open(&repo_path).expect("open repo");
    commit_readme(&repo).expect("initial commit");
    repo_path
}

fn open_admission_store(repo_path: &Path) -> (Repository, ManagedWorktreeRegistryStore) {
    let repo = crate::git_repository::open(repo_path).expect("open repo");
    let store = ManagedWorktreeRegistryStore::open(&repo).expect("open registry store");
    (repo, store)
}

fn registry_admission_lock_path() -> &'static Path {
    Path::new(REGISTRY_ADMISSION_LOCK_NAME)
}

fn wait_for_admission_waiters(queue: &ManagedRegistryAdmission, expected: usize, bound: Duration) {
    let deadline = Instant::now() + bound;
    loop {
        let observed = queue
            .queued_waiters()
            .expect("count queued admission waiters");
        if observed == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "queued admission waiters stayed at {observed}, expected {expected}"
        );
        std::thread::sleep(Duration::from_millis(25));
    }
}

fn assert_classifiable_lock_timeout(message: &str) {
    let lower = message.to_ascii_lowercase();
    assert!(
        ["timed out", "timeout", "time limit", "deadline", "expired"]
            .iter()
            .any(|needle| lower.contains(needle)),
        "expected a classifiable registry lock timeout: {message}"
    );
}

fn assert_registry_lock_busy(store: &ManagedWorktreeRegistryStore) {
    let error = store
        .lock_existing()
        .expect_err("lock_existing must not bypass registry admission");
    let message = format!("{error:#}");
    assert!(
        message.contains("active elsewhere"),
        "expected busy registry admission, got: {message}"
    );
}

struct GatedRegistryLock {
    handle: std::thread::JoinHandle<()>,
    start: std::sync::mpsc::Sender<()>,
    ready: std::sync::mpsc::Receiver<()>,
    done: std::sync::mpsc::Receiver<std::result::Result<(), String>>,
}

fn spawn_gated_registry_lock(
    repo_path: PathBuf,
    budget: Duration,
    on_acquire: impl FnOnce() + Send + 'static,
) -> GatedRegistryLock {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (start_tx, start_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let handle = std::thread::spawn(move || {
        // git2::Repository is not Sync; each worker opens its own store.
        let repo = crate::git_repository::open(&repo_path).expect("worker repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("worker store");
        ready_tx.send(()).expect("worker ready");
        start_rx.recv().expect("worker start");
        let result = match store.lock_with_timeout(budget) {
            Ok(guard) => {
                on_acquire();
                drop(guard);
                Ok(())
            }
            Err(error) => Err(format!("{error:#}")),
        };
        let _ = done_tx.send(result);
    });
    GatedRegistryLock {
        handle,
        start: start_tx,
        ready: ready_rx,
        done: done_rx,
    }
}

impl GatedRegistryLock {
    fn wait_ready(&self) {
        self.ready
            .recv_timeout(Duration::from_secs(10))
            .expect("worker opened its repository");
    }

    fn release(&self) {
        self.start.send(()).expect("worker start gate");
    }

    fn finish(self, bound: Duration, label: &str) -> std::result::Result<(), String> {
        match self.done.recv_timeout(bound) {
            Ok(result) => {
                self.handle
                    .join()
                    .unwrap_or_else(|_| panic!("{label} worker panicked"));
                result
            }
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                panic!("{label} did not finish within {bound:?}");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => match self.handle.join() {
                Ok(()) => panic!("{label} worker ended without a lock result"),
                Err(_) => panic!("{label} worker panicked before reporting a lock result"),
            },
        }
    }
}

#[test]
fn same_root_registry_guards_admit_in_fifo_order() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = registry_admission_repo(&temp, "repo");
    let other_path = registry_admission_repo(&temp, "other-repo");
    let (_repo, store) = open_admission_store(&repo_path);
    let (_peer_repo, peer) = open_admission_store(&repo_path);
    let (_other_repo, other) = open_admission_store(&other_path);
    let queue = managed_registry_admission_queue(&store.state_root).expect("admission queue");
    let peer_queue =
        managed_registry_admission_queue(&peer.state_root).expect("peer admission queue");
    let other_queue =
        managed_registry_admission_queue(&other.state_root).expect("other admission queue");
    assert!(
        std::sync::Arc::ptr_eq(&queue, &peer_queue),
        "separate stores for one state root must share the admission queue"
    );
    assert!(
        !std::sync::Arc::ptr_eq(&queue, &other_queue),
        "unrelated state roots must not share an admission queue"
    );

    let held = store.lock().expect("hold registry guard");
    assert_eq!(queue.queued_waiters().expect("waiters"), 0);
    assert_registry_lock_busy(&peer);
    assert!(queue.try_acquire().expect("try acquire").is_none());

    let order = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let budget = Duration::from_secs(20);
    let order_b = std::sync::Arc::clone(&order);
    let order_c = std::sync::Arc::clone(&order);
    let order_a = std::sync::Arc::clone(&order);
    let waiter_b = spawn_gated_registry_lock(repo_path.clone(), budget, move || {
        order_b.lock().expect("order").push("B");
    });
    let waiter_c = spawn_gated_registry_lock(repo_path.clone(), budget, move || {
        order_c.lock().expect("order").push("C");
    });
    let waiter_a = spawn_gated_registry_lock(repo_path, budget, move || {
        order_a.lock().expect("order").push("A");
    });
    waiter_b.wait_ready();
    waiter_c.wait_ready();
    waiter_a.wait_ready();

    waiter_b.release();
    wait_for_admission_waiters(&queue, 1, Duration::from_secs(5));
    assert_registry_lock_busy(&peer);
    waiter_c.release();
    wait_for_admission_waiters(&queue, 2, Duration::from_secs(5));
    assert_registry_lock_busy(&peer);
    assert!(queue
        .try_acquire()
        .expect("try acquire behind queued waiters")
        .is_none());

    let queued_before_other = queue.queued_waiters().expect("waiters");
    let other_held = other
        .lock_with_timeout(Duration::from_secs(8))
        .expect("unrelated state root acquires while this queue is occupied");
    assert_eq!(
        queue.queued_waiters().expect("waiters"),
        queued_before_other,
        "unrelated root must not enter this admission queue"
    );
    assert_eq!(other_queue.queued_waiters().expect("other waiters"), 0);
    drop(other_held);
    drop(other.lock_existing().expect("unrelated root is not busy"));

    waiter_a.release();
    wait_for_admission_waiters(&queue, 3, Duration::from_secs(5));
    assert_registry_lock_busy(&peer);
    assert!(queue
        .try_acquire()
        .expect("try acquire cannot cut ahead of A")
        .is_none());
    drop(held);

    for (label, waiter) in [("B", waiter_b), ("C", waiter_c), ("A", waiter_a)] {
        waiter
            .finish(Duration::from_secs(10), label)
            .unwrap_or_else(|error| panic!("{label} registry guard failed: {error}"));
    }
    assert_eq!(
        order.lock().expect("order").as_slice(),
        ["B", "C", "A"],
        "immediate reacquisition must follow waiters already queued"
    );
    assert_eq!(queue.queued_waiters().expect("waiters"), 0);
    drop(
        peer.lock_existing()
            .expect("same root is free after the queue drains"),
    );
}

#[test]
fn queued_registry_timeouts_cancel_and_permit_drop_releases_successor() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = registry_admission_repo(&temp, "repo");
    let (_repo, store) = open_admission_store(&repo_path);
    let (_peer_repo, peer) = open_admission_store(&repo_path);
    drop(store.lock().expect("prime registry lock"));
    let queue = managed_registry_admission_queue(&store.state_root).expect("admission queue");
    let lock_path = registry_admission_lock_path();

    let permit = queue
        .acquire(Instant::now() + Duration::from_secs(20), lock_path)
        .expect("hold queue permit without the kernel lock");
    assert_eq!(queue.queued_waiters().expect("waiters"), 0);
    assert_registry_lock_busy(&peer);
    let successor = spawn_gated_registry_lock(repo_path.clone(), Duration::from_secs(15), || {});
    successor.wait_ready();
    successor.release();
    wait_for_admission_waiters(&queue, 1, Duration::from_secs(5));
    assert_registry_lock_busy(&peer);
    assert!(queue
        .try_acquire()
        .expect("try acquire while a waiter is queued")
        .is_none());
    let holder_error: anyhow::Result<()> = {
        let _permit = permit;
        Err(anyhow::anyhow!("admission holder failed"))
    };
    let holder_error = holder_error.expect_err("holder returns an error");
    assert!(
        format!("{holder_error:#}").contains("admission holder failed"),
        "{holder_error:#}"
    );
    successor
        .finish(Duration::from_secs(8), "error-drop successor")
        .expect("dropping the active permit on error releases the successor");
    assert_eq!(queue.queued_waiters().expect("waiters"), 0);
    drop(
        peer.lock_existing()
            .expect("admission released after error drop"),
    );

    let held = store.lock().expect("hold registry guard");
    let head = spawn_gated_registry_lock(repo_path.clone(), Duration::from_secs(5), || {});
    let middle = spawn_gated_registry_lock(repo_path.clone(), Duration::from_secs(5), || {});
    let tail = spawn_gated_registry_lock(repo_path.clone(), Duration::from_secs(20), || {});
    head.wait_ready();
    middle.wait_ready();
    tail.wait_ready();
    head.release();
    wait_for_admission_waiters(&queue, 1, Duration::from_secs(5));
    middle.release();
    wait_for_admission_waiters(&queue, 2, Duration::from_secs(5));
    tail.release();
    wait_for_admission_waiters(&queue, 3, Duration::from_secs(5));
    let head_error = head
        .finish(Duration::from_secs(12), "head timeout")
        .expect_err("head waiter must time out while the guard is held");
    let middle_error = middle
        .finish(Duration::from_secs(12), "middle timeout")
        .expect_err("middle waiter must time out while the guard is held");
    assert_classifiable_lock_timeout(&head_error);
    assert_classifiable_lock_timeout(&middle_error);
    assert_eq!(
        queue.queued_waiters().expect("waiters"),
        1,
        "cancelled head and middle waiters must not strand the successor"
    );
    assert!(
        matches!(
            tail.done.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
        ),
        "successor acquired before the holder released"
    );
    assert_registry_lock_busy(&peer);
    drop(held);
    tail.finish(Duration::from_secs(8), "tail after cancelled waiters")
        .expect("successor acquires after cancelled waiters are removed");
    assert_eq!(queue.queued_waiters().expect("waiters"), 0);

    let guard = store.lock().expect("hold guard for unwind");
    let unwind_successor = spawn_gated_registry_lock(repo_path, Duration::from_secs(15), || {});
    unwind_successor.wait_ready();
    unwind_successor.release();
    wait_for_admission_waiters(&queue, 1, Duration::from_secs(5));
    let panicked = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = guard;
        panic!("drop registry guard during unwind");
    }));
    assert!(panicked.is_err(), "unwind hook did not panic");
    unwind_successor
        .finish(Duration::from_secs(8), "unwind successor")
        .expect("unwinding the active guard releases the next waiter");
    assert_eq!(queue.queued_waiters().expect("waiters"), 0);
    drop(
        peer.lock_existing()
            .expect("admission released after unwind"),
    );
}

#[test]
fn registry_lock_uses_one_deadline_for_queue_and_kernel() {
    let temp = TempDir::new().expect("tempdir");
    let repo_path = registry_admission_repo(&temp, "repo");
    let (_repo, store) = open_admission_store(&repo_path);
    drop(store.lock().expect("prime registry lock"));
    let queue = managed_registry_admission_queue(&store.state_root).expect("admission queue");
    let lock_path = registry_admission_lock_path();

    let expired = queue
        .acquire(Instant::now() - Duration::from_secs(1), lock_path)
        .expect_err("expired deadline must refuse even when the queue is idle");
    assert_classifiable_lock_timeout(&format!("{expired:#}"));
    assert_eq!(queue.queued_waiters().expect("waiters"), 0);
    drop(
        queue
            .try_acquire()
            .expect("try after expired refusal")
            .expect("expired refusal must not keep the admission permit"),
    );

    let zero_started = Instant::now();
    let zero = store
        .lock_with_timeout(Duration::ZERO)
        .expect_err("zero budget must refuse");
    assert!(
        zero_started.elapsed() < Duration::from_secs(2),
        "zero budget blocked instead of refusing"
    );
    assert_classifiable_lock_timeout(&format!("{zero:#}"));
    assert_eq!(queue.queued_waiters().expect("waiters"), 0);
    drop(
        store
            .lock_with_timeout(Duration::from_secs(5))
            .expect("registry lock recovers after a zero-budget refusal"),
    );

    let budget = Duration::from_secs(8);
    let permit = queue
        .acquire(Instant::now() + Duration::from_secs(30), lock_path)
        .expect("queue permit delays the public lock");
    let (ready_tx, ready_rx) = std::sync::mpsc::channel();
    let (start_tx, start_rx) = std::sync::mpsc::channel::<()>();
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (done_tx, done_rx) = std::sync::mpsc::channel();
    let worker_path = repo_path.clone();
    let worker = std::thread::spawn(move || {
        let repo = crate::git_repository::open(&worker_path).expect("worker repo");
        let store = ManagedWorktreeRegistryStore::open(&repo).expect("worker store");
        ready_tx.send(()).expect("worker ready");
        start_rx.recv().expect("worker start");
        let started_at = Instant::now();
        started_tx.send(started_at).expect("started");
        let result = store.lock_with_timeout(budget);
        let finished_at = Instant::now();
        done_tx
            .send((
                finished_at,
                result.map(|_| ()).map_err(|error| format!("{error:#}")),
            ))
            .expect("done");
    });
    ready_rx
        .recv_timeout(Duration::from_secs(10))
        .expect("waiter opened its repository");
    start_tx.send(()).expect("start waiter");
    let started = started_rx
        .recv_timeout(Duration::from_secs(5))
        .expect("waiter entered lock_with_timeout");
    wait_for_admission_waiters(&queue, 1, Duration::from_secs(3));
    let release_at = started + Duration::from_secs(4);
    if let Some(pause) = release_at.checked_duration_since(Instant::now()) {
        std::thread::sleep(pause);
    }
    let elapsed_in_queue = Instant::now().saturating_duration_since(started);
    assert!(
        budget.saturating_sub(elapsed_in_queue) >= Duration::from_secs(1),
        "queue wait consumed the original budget before the kernel lock was contested: {elapsed_in_queue:?}"
    );
    assert_eq!(
        queue.queued_waiters().expect("waiters"),
        1,
        "waiter left the queue before the kernel lock contested the remaining budget"
    );
    // The raw kernel lock is independent of the queue permit and must spend only
    // the time still left on the waiter's original lock_with_timeout deadline.
    let kernel = KernelStateLock::acquire_direct_with_timeout(
        &store.state_root,
        REGISTRY_ADMISSION_LOCK_NAME,
        Duration::from_secs(5),
    )
    .expect("kernel lock while the admission permit is held separately");
    let released_at = Instant::now();
    drop(permit);
    let (finished_at, result) = done_rx.recv_timeout(Duration::from_secs(6)).unwrap_or_else(|_| {
        panic!(
            "waiter was still blocked after the original remaining budget; a fresh kernel budget may still be running"
        );
    });
    let message = result.expect_err("lock_with_timeout granted after its original deadline");
    assert_classifiable_lock_timeout(&message);
    let after_release = finished_at.saturating_duration_since(released_at);
    assert!(
        after_release < budget,
        "registry lock waited a fresh full budget after queue admission: {after_release:?}"
    );
    assert!(
        finished_at < started + budget + Duration::from_secs(3),
        "registry lock outlived the original deadline by another full budget"
    );
    assert!(
        matches!(
            done_rx.try_recv(),
            Err(std::sync::mpsc::TryRecvError::Empty)
                | Err(std::sync::mpsc::TryRecvError::Disconnected)
        ),
        "waiter produced a second, late grant"
    );
    drop(kernel);
    worker.join().expect("waiter thread");
    assert_eq!(queue.queued_waiters().expect("waiters"), 0);
    drop(
        store
            .lock_with_timeout(Duration::from_secs(5))
            .expect("registry lock recovers after the shared-deadline timeout"),
    );
}

include!("tests_part2.rs");
include!("tests_part3.rs");
