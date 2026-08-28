use super::*;
use tempfile::TempDir;

#[test]
fn signed_and_unsigned_device_id_bits_are_preserved() {
    let negative_one = device_id_bits_to_u64(-1);
    let negative_two = device_id_bits_to_u64(-2);
    let unsigned_high_bit = device_id_bits_to_u64(u64::MAX as i64);

    assert_eq!(negative_one, u64::MAX);
    assert_eq!(negative_two, u64::MAX - 1);
    assert_ne!(negative_one, negative_two);
    assert_eq!(unsigned_high_bit, u64::MAX);
}

#[cfg(unix)]
#[test]
fn stat_device_conversion_matches_metadata_ext() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("device-identity");
    fs::write(&path, b"identity").expect("write fixture");
    let file = File::open(&path).expect("open fixture");
    let stat = fstat(file.as_raw_fd()).expect("fstat fixture");

    assert_eq!(
        device_id_to_u64(stat.st_dev),
        file.metadata().expect("metadata").dev()
    );
}

#[cfg(unix)]
#[test]
fn inventory_entry_size_conversion_rejects_negative_values() {
    assert_eq!(inventory_entry_size_bytes(0).expect("zero size"), 0);
    assert!(inventory_entry_size_bytes(-1).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn quarantined_direct_child_unlink_refuses_reappeared_source_without_deleting_replacement() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("state")).expect("safe root");
    let source = root.path().join("created.lock");
    fs::write(&source, b"original").expect("original source");
    fs::set_permissions(&source, fs::Permissions::from_mode(0o600)).expect("owner-private source");
    let identity = identity_for_path(&source).expect("source identity");
    let binding = root
        .bind_owned_direct_child(
            "created.lock",
            &identity,
            DirectChildType::SingleLinkRegularFile,
        )
        .expect("direct child binding");
    set_direct_child_before_quarantine_unlink_hook({
        let source = source.clone();
        move || {
            fs::write(&source, b"replacement").expect("replacement source");
            fs::set_permissions(&source, fs::Permissions::from_mode(0o600))
                .expect("replacement mode");
        }
    });

    let error = binding
        .unlink_fenced(&root)
        .expect_err("reappeared source must refuse unlink");

    assert!(error.to_string().contains("reappeared"));
    assert_eq!(
        fs::read(&source).expect("replacement remains"),
        b"replacement"
    );
    let quarantine = root
        .path()
        .join(entry_quarantine_name(OsStr::new("created.lock"), &identity));
    assert_eq!(
        fs::read(quarantine).expect("original quarantine"),
        b"original"
    );
}

#[test]
fn atomic_writer_uses_private_regular_files_and_preserves_lock_inode() {
    let temp = TempDir::new().expect("tempdir");
    let state = temp.path().join("state").join("claims.json");
    AtomicStateWriter::write(&state, b"first\n").expect("first write");
    AtomicStateWriter::write(&state, b"second\n").expect("second write");
    assert_eq!(
        BoundedRegularReader::read_utf8(&state, 32).expect("read"),
        "second\n"
    );

    let lock_path = state.parent().expect("parent").join("claims.lock");
    let first_identity = {
        let lock = KernelStateLock::acquire(&lock_path).expect("lock");
        let identity = identity_for_path(lock.path()).expect("identity");
        drop(lock);
        identity
    };
    let second = KernelStateLock::acquire(&lock_path).expect("relock");
    assert_eq!(
        identity_for_path(second.path()).expect("second identity"),
        first_identity
    );
}

#[cfg(unix)]
#[test]
fn bounded_reader_rejects_symlink_hardlink_fifo_and_large_file() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("root");
    fs::create_dir(&root).expect("root");
    let regular = root.join("regular");
    fs::write(&regular, b"0123456789").expect("write regular");

    let link = root.join("link");
    symlink(&regular, &link).expect("symlink");
    assert!(BoundedRegularReader::read(&link, 32).is_err());

    let hard = root.join("hard");
    fs::hard_link(&regular, &hard).expect("hard link");
    assert!(BoundedRegularReader::read(&regular, 32).is_err());

    fs::remove_file(&hard).expect("remove hard");
    assert!(BoundedRegularReader::read(&regular, 4).is_err());

    let fifo = root.join("fifo");
    let fifo_name = c_string(fifo.as_os_str()).expect("fifo path");
    assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
    let fifo_started = Instant::now();
    assert!(BoundedRegularReader::read(&fifo, 32).is_err());
    assert!(
        fifo_started.elapsed() < Duration::from_secs(1),
        "no-writer FIFO open must fail without blocking"
    );
}

#[cfg(windows)]
#[test]
fn bounded_reader_rejects_windows_hard_links_and_accepts_single_link_files() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("root");
    fs::create_dir(&root).expect("root");
    let regular = root.join("regular");
    fs::write(&regular, b"single link").expect("write regular");

    assert_eq!(
        BoundedRegularReader::read(&regular, 32).expect("read single-link file"),
        b"single link"
    );
    assert_eq!(
        BoundedRegularReader::read_relative(&root, "regular", 32)
            .expect("read repository-relative single-link file"),
        b"single link"
    );

    fs::hard_link(&regular, root.join("hardlink")).expect("create hard link");

    assert!(BoundedRegularReader::read(&regular, 32).is_err());
    assert!(BoundedRegularReader::read_relative(&root, "regular", 32).is_err());
    assert!(BoundedRegularReader::read_relative_optional(&root, "hardlink", 32).is_err());
}

#[cfg(target_os = "linux")]
#[test]
fn repository_relative_reader_refuses_mount_boundary() {
    let error = BoundedRegularReader::read_relative("/", "proc/self/status", 64 * 1024)
        .expect_err("repository-relative reader must not cross into procfs");

    assert!(format!("{error:#}").contains("mount-confined"));
}

#[test]
fn repository_relative_reader_reads_regular_utf8_and_preserves_directory_scopes() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(root.join("src")).expect("create source directory");
    fs::write(root.join("src/lib.rs"), "hello\n").expect("write source");

    assert_eq!(
        BoundedRegularReader::read_relative_utf8(&root, "src/lib.rs", 64).expect("read source"),
        "hello\n"
    );
    assert_eq!(
        BoundedRegularReader::read_relative_optional_utf8(&root, "missing.rs", 64)
            .expect("missing file"),
        None
    );
    assert_eq!(
        BoundedRegularReader::read_relative_optional_utf8(&root, "src", 64)
            .expect("directory scope"),
        None
    );

    let binding = DirectoryBindingGuard::bind(&root).expect("bind repository root");
    assert_eq!(
        binding
            .read_relative(Path::new("src/lib.rs"), 64)
            .expect("bound relative read"),
        b"hello\n"
    );
    binding.verify().expect("directory binding remains stable");
}

#[cfg(target_os = "linux")]
#[test]
fn statx_mount_identity_distinguishes_procfs_boundary() {
    let root = open_unix_directory(Path::new("/")).expect("open filesystem root");
    let root_mount = linux_mount_identity_for_fd(root.as_raw_fd()).expect("root mount identity");
    let proc_name = c"proc";
    let proc_stat =
        fstatat_no_follow(root.as_raw_fd(), proc_name).expect("inspect proc mountpoint");
    let proc_mount = linux_mount_identity_at(root.as_raw_fd(), proc_name, &proc_stat)
        .expect("proc mount identity");

    assert_ne!(root_mount, proc_mount);
    assert!(
        require_linux_mount_id(root_mount.mount_id, proc_mount.mount_id, "procfs fixture",)
            .is_err()
    );
}

#[cfg(target_os = "linux")]
#[test]
fn safe_root_mount_identity_rechecks_path_and_direct_child() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("root")).expect("safe root");
    fs::write(root.path().join("child"), b"bound").expect("child");
    let mount_id = root.linux_mount_id().expect("root mount id");

    root.verify_linux_mount_id(mount_id)
        .expect("stable root mount");
    assert_eq!(
        root.direct_child_linux_mount_id("child")
            .expect("child mount id"),
        Some(mount_id)
    );
    assert!(root
        .verify_linux_mount_id(mount_id.saturating_add(1))
        .is_err());
}

#[cfg(unix)]
#[test]
fn directory_binding_guard_rejects_pathname_replacement() {
    let temp = tempfile::tempdir().expect("tempdir");
    let bound = temp.path().join("bound");
    let displaced = temp.path().join("displaced");
    fs::create_dir(&bound).expect("create bound directory");
    let guard = DirectoryBindingGuard::bind(&bound).expect("bind directory");
    fs::rename(&bound, &displaced).expect("displace bound directory");
    fs::create_dir(&bound).expect("create replacement directory");

    let error = guard
        .verify()
        .expect_err("replacement directory must fail binding verification");

    assert!(error.to_string().contains("binding changed"));
}

#[cfg(unix)]
#[test]
fn bounded_reader_rejects_same_inode_generation_change_and_truncation() {
    use std::os::unix::fs::PermissionsExt;

    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("changing-input");
    fs::write(&path, b"original").expect("write input");

    let mut changing = open_regular_no_follow(&path, false).expect("open changing input");
    let changed = read_bounded_file_with_hook(&mut changing, &path, 32, || {
        fs::write(&path, b"replaced").expect("replace same-length contents");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o400))
            .expect("change input generation");
    })
    .expect_err("same-inode generation change must fail");
    assert!(changed.to_string().contains("changed"));

    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore permissions");
    fs::write(&path, b"original").expect("restore input");
    let mut truncating = open_regular_no_follow(&path, false).expect("open truncating input");
    let truncated = read_bounded_file_with_hook(&mut truncating, &path, 32, || {
        OpenOptions::new()
            .write(true)
            .open(&path)
            .expect("open for truncate")
            .set_len(3)
            .expect("truncate input");
    })
    .expect_err("truncation during read must fail");
    assert!(truncated.to_string().contains("truncated"));
}

#[cfg(unix)]
#[test]
fn bounded_reader_metadata_validator_is_bound_to_the_open_descriptor_generation() {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("validated-input");
    fs::write(&path, b"reviewed").expect("write input");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("private input mode");
    let validator = |metadata: &fs::Metadata| -> Result<()> {
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            bail!("unsafe descriptor metadata");
        }
        Ok(())
    };
    assert_eq!(
        BoundedRegularReader::read_tree_no_follow_validated(&path, 32, validator)
            .expect("validated read"),
        b"reviewed"
    );

    let mut opened = open_regular_no_follow(&path, false).expect("open validated input");
    let mut validator = |metadata: &fs::Metadata| -> Result<()> {
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o022 != 0 {
            bail!("unsafe descriptor metadata");
        }
        Ok(())
    };
    let changed =
        read_bounded_file_with_validator_and_hook(&mut opened, &path, 32, &mut validator, || {
            fs::set_permissions(&path, fs::Permissions::from_mode(0o622))
                .expect("make descriptor unsafe");
        })
        .expect_err("permission change on the opened descriptor must fail");
    assert!(changed.to_string().contains("metadata policy"));
}

#[cfg(unix)]
#[test]
fn bounded_reader_rejects_path_replacement_during_read() {
    let temp = TempDir::new().expect("tempdir");
    let path = temp.path().join("replaceable-input");
    let displaced = temp.path().join("displaced-input");
    fs::write(&path, b"original").expect("write original input");

    let mut opened = open_regular_no_follow(&path, false).expect("open original input");
    let replaced = read_bounded_file_with_hook(&mut opened, &path, 32, || {
        fs::rename(&path, &displaced).expect("displace original path");
        fs::write(&path, b"attacker").expect("replace input path");
    })
    .expect_err("path replacement must fail closed");

    assert!(replaced.to_string().contains("identity changed"));
    assert_eq!(fs::read(&path).expect("read replacement"), b"attacker");
}

#[cfg(unix)]
#[test]
fn strict_tree_delete_rejects_link_without_touching_external_target() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("runs")).expect("safe root");
    let external = temp.path().join("external");
    fs::create_dir(&external).expect("external");
    fs::write(external.join("keep"), "keep").expect("external file");
    let run = root.path().join("run-a");
    fs::create_dir(&run).expect("run");
    symlink(&external, run.join("escape")).expect("escape link");
    let identity = identity_for_path(&run).expect("run identity");

    let error = remove_direct_child_tree(
        &root,
        "run-a",
        Some(&identity),
        TreeLinkPolicy::RejectLinksAndSpecialFiles,
    )
    .expect_err("strict delete must refuse link");
    assert!(error.to_string().contains("symbolic link"));
    assert!(external.join("keep").exists());
    assert!(!run.exists());
    let quarantine = root
        .path()
        .join(deletion_quarantine_name(OsStr::new("run-a"), &identity));
    assert_eq!(
        identity_for_path(&quarantine).expect("quarantined identity"),
        identity
    );
}

#[cfg(target_os = "linux")]
#[test]
fn existing_managed_root_accepts_0755_but_strict_state_root_does_not_chmod_it() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("managed");
    fs::create_dir(&root).expect("root");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).expect("mode");

    let error = SafeRoot::open_or_create(&root).expect_err("strict root must refuse 0755");
    assert!(error.to_string().contains("owner-private"));
    assert_eq!(
        fs::symlink_metadata(&root)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
    SafeRoot::open_or_create_managed(&root).expect("managed root accepts 0755");
}

#[cfg(unix)]
struct RestoreUnixMode {
    path: PathBuf,
    mode: u32,
}

#[cfg(unix)]
impl Drop for RestoreUnixMode {
    fn drop(&mut self) {
        let _ = fs::set_permissions(&self.path, fs::Permissions::from_mode(self.mode));
    }
}

#[cfg(target_os = "linux")]
#[test]
fn safe_root_accepts_execute_only_non_world_traversable_ancestor() {
    // Owner-execute-only (0100) is the unit-test stand-in for a 0711 ancestor
    // the caller does not own: both are traversable but not listable.
    let temp = TempDir::new().expect("tempdir");
    let ancestor = temp.path().join("restricted");
    let writable = ancestor.join("writable");
    let leaf = writable.join("state");
    fs::create_dir_all(&writable).expect("tree");
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o700)).expect("writable mode");
    let _restore = RestoreUnixMode {
        path: ancestor.clone(),
        mode: 0o700,
    };
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o100))
        .expect("execute-only ancestor");

    let created = SafeRoot::open_or_create(&leaf).expect("create through execute-only ancestor");
    created.verify().expect("verify created root");
    let existing = SafeRoot::open_existing(&leaf).expect("reopen through execute-only ancestor");
    existing.verify().expect("verify existing root");
    assert_eq!(created.identity(), existing.identity());
    assert_eq!(
        fs::symlink_metadata(&ancestor)
            .expect("ancestor metadata")
            .permissions()
            .mode()
            & 0o777,
        0o100
    );
}

#[cfg(target_os = "linux")]
#[test]
fn safe_root_refuses_non_searchable_ancestor_and_names_a_path() {
    let temp = TempDir::new().expect("tempdir");
    let ancestor = temp.path().join("blocked");
    let leaf = ancestor.join("state");
    fs::create_dir(&ancestor).expect("ancestor");
    let _restore = RestoreUnixMode {
        path: ancestor.clone(),
        mode: 0o700,
    };
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o000))
        .expect("non-searchable ancestor");

    let error = SafeRoot::open_or_create(&leaf).expect_err("non-searchable ancestor must fail");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(&ancestor.display().to_string())
            || rendered.contains(&leaf.display().to_string()),
        "error must name the failing path: {rendered}"
    );
}

#[cfg(unix)]
#[test]
fn safe_root_refuses_symlink_ancestor_and_names_the_failing_path() {
    use std::os::unix::fs::symlink;

    let temp = TempDir::new().expect("tempdir");
    let real = temp.path().join("real");
    let link = temp.path().join("link");
    fs::create_dir(&real).expect("real");
    symlink(&real, &link).expect("symlink ancestor");
    let error = SafeRoot::open_or_create(link.join("state"))
        .expect_err("symlink ancestor must fail closed");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(&link.display().to_string()),
        "error must name the failing path: {rendered}"
    );
}

#[cfg(unix)]
#[test]
fn safe_root_refuses_non_directory_ancestor_and_names_the_failing_path() {
    let temp = TempDir::new().expect("tempdir");
    let file = temp.path().join("not-a-dir");
    fs::write(&file, b"nope").expect("file ancestor");
    let error =
        SafeRoot::open_or_create(file.join("state")).expect_err("file ancestor must fail closed");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains(&file.display().to_string()),
        "error must name the failing path: {rendered}"
    );
}

#[cfg(unix)]
#[test]
fn tree_delete_refuses_renamed_substitute_identity() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create_managed(temp.path().join("root")).expect("root");
    let child = root.path().join("child");
    fs::create_dir(&child).expect("child");
    fs::write(child.join("original"), "keep").expect("original");
    let expected = identity_for_path(&child).expect("identity");
    let moved = root.path().join("moved");
    fs::rename(&child, &moved).expect("rename original");
    fs::create_dir(&child).expect("substitute");

    let error =
        remove_direct_child_tree(&root, "child", Some(&expected), TreeLinkPolicy::UnlinkLinks)
            .expect_err("substitute must not be removed");
    assert!(!error.to_string().is_empty());
    assert!(child.exists());
    assert!(moved.join("original").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn directory_quarantine_adopts_only_one_matching_binding() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create_managed(temp.path().join("root")).expect("root");
    let source = root.path().join("source");
    let quarantine = root.path().join("quarantine");
    fs::create_dir(&source).expect("source");
    let expected = identity_for_path(&source).expect("identity");

    quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
        .expect("initial quarantine");
    assert!(!source.exists());
    assert_eq!(
        identity_for_path(&quarantine).expect("quarantine identity"),
        expected
    );
    assert_eq!(
        fs::symlink_metadata(&quarantine)
            .expect("quarantine metadata")
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
        .expect("adopt prior rename");

    fs::create_dir(&source).expect("ambiguous source");
    let error = quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
        .expect_err("both-present state must fail closed");
    assert!(error.to_string().contains("both exist"));
    assert!(source.exists());
    assert!(quarantine.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn directory_quarantine_restore_is_identity_bound_and_no_replace() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create_managed(temp.path().join("root")).expect("root");
    let source = root.path().join("source");
    let quarantine = root.path().join("quarantine");
    fs::create_dir(&source).expect("source");
    fs::write(source.join("valuable"), "keep").expect("valuable file");
    let expected = identity_for_path(&source).expect("identity");

    quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
        .expect("quarantine");
    restore_quarantined_direct_child_directory(&root, "source", "quarantine", &expected)
        .expect("restore");
    assert_eq!(
        identity_for_path(&source).expect("restored identity"),
        expected
    );
    assert_eq!(
        fs::read_to_string(source.join("valuable")).expect("restored content"),
        "keep"
    );
    assert!(!quarantine.exists());
    restore_quarantined_direct_child_directory(&root, "source", "quarantine", &expected)
        .expect("idempotent restore");

    quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
        .expect("quarantine again");
    fs::create_dir(&source).expect("replacement source");
    let error =
        restore_quarantined_direct_child_directory(&root, "source", "quarantine", &expected)
            .expect_err("replacement must block restore");
    assert!(error.to_string().contains("both exist"));
    assert!(source.exists());
    assert!(quarantine.join("valuable").exists());
}

#[cfg(target_os = "linux")]
#[test]
fn quarantined_tree_cleanup_resumes_after_entry_rename_and_partial_delete() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create_managed(temp.path().join("root")).expect("root");
    let source = root.path().join("source");
    fs::create_dir(&source).expect("source");
    fs::write(source.join("first"), "first").expect("first");
    fs::write(source.join("second"), "second").expect("second");
    let expected = identity_for_path(&source).expect("source identity");
    quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
        .expect("durable quarantine");
    let quarantine = root.path().join("quarantine");
    fs::remove_file(quarantine.join("first")).expect("simulate partial cleanup");
    let second = quarantine.join("second");
    let second_identity = identity_for_path(&second).expect("second identity");
    let entry_quarantine = entry_quarantine_name(OsStr::new("second"), &second_identity);
    fs::rename(&second, quarantine.join(&entry_quarantine))
        .expect("simulate crash after child quarantine rename");
    let cleanup_name =
        quarantined_direct_child_cleanup_name("quarantine", &expected).expect("cleanup name");
    fs::rename(&quarantine, root.path().join(&cleanup_name))
        .expect("simulate crash after top-level cleanup rename");

    assert!(remove_quarantined_direct_child_tree(
        &root,
        "quarantine",
        &expected,
        TreeLinkPolicy::UnlinkLinks,
    )
    .expect("resume cleanup"));
    assert!(!quarantine.exists());
    assert!(!root.path().join(cleanup_name).exists());
    assert!(!remove_quarantined_direct_child_tree(
        &root,
        "quarantine",
        &expected,
        TreeLinkPolicy::UnlinkLinks,
    )
    .expect("idempotent completed cleanup"));
}

#[cfg(target_os = "linux")]
#[test]
fn quarantined_tree_cleanup_refuses_nested_mount_mismatch_without_removal() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create_managed(temp.path().join("root")).expect("root");
    let source = root.path().join("source");
    fs::create_dir(&source).expect("source");
    fs::write(source.join("valuable"), "keep").expect("valuable file");
    let expected = identity_for_path(&source).expect("source identity");
    quarantine_direct_child_directory(&root, "source", "quarantine", &expected)
        .expect("durable quarantine");
    let cleanup_name =
        quarantined_direct_child_cleanup_name("quarantine", &expected).expect("cleanup name");

    // Unprivileged test environments cannot create a same-device bind mount. Inject the
    // otherwise statx-backed mismatch at the first nested audit entry instead.
    inject_next_linux_mount_mismatch("quarantine tree entry during deletion audit");
    let error = remove_quarantined_direct_child_tree(
        &root,
        "quarantine",
        &expected,
        TreeLinkPolicy::UnlinkLinks,
    )
    .expect_err("nested mount mismatch must fail closed");

    assert!(error.to_string().contains("mount crossing"));
    assert!(!root.path().join(cleanup_name).exists());
    assert_eq!(
        fs::read_to_string(root.path().join("quarantine").join("valuable"))
            .expect("quarantined content survives"),
        "keep"
    );
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
fn supported_unix_errno_abi_can_be_cleared_explicitly() {
    clear_thread_errno().expect("supported errno ABI");
    assert_eq!(std::io::Error::last_os_error().raw_os_error(), Some(0));
}

#[cfg(unix)]
#[test]
fn empty_coordination_lock_accepts_synthesized_0755_without_weakening_private_locks() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create_managed(temp.path().join("claims")).expect("managed root");
    let lock_path = root.path().join("board.lock");
    fs::write(&lock_path, "").expect("empty lock");
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o755)).expect("synthesized mode");

    let lock = KernelStateLock::acquire_direct_empty_coordination(&root, "board.lock")
        .expect("empty 0755 coordination lock");
    lock.verify_direct_binding(&root)
        .expect("0755 empty coordination lock stays bound");
    drop(lock);

    let error = KernelStateLock::acquire_direct(&root, "board.lock")
        .expect_err("strict private locks must still reject 0755");
    let message = error.to_string();
    assert!(
        message.contains("unsafe mode") || message.contains("owner-private"),
        "strict lock error should mention the private-mode contract: {message}"
    );
    assert_eq!(
        fs::symlink_metadata(&lock_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o755
    );
}

#[cfg(unix)]
#[test]
fn empty_coordination_lock_rejects_group_write_and_nonempty_payload() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create_managed(temp.path().join("claims")).expect("managed root");

    let writable = root.path().join("writable.lock");
    fs::write(&writable, "").expect("empty lock");
    fs::set_permissions(&writable, fs::Permissions::from_mode(0o775)).expect("group write");
    let writable_error = KernelStateLock::acquire_direct_empty_coordination(&root, "writable.lock")
        .expect_err("group-writable coordination lock must fail");
    assert!(
        writable_error.to_string().contains("group/world write"),
        "{}",
        writable_error
    );

    let nonempty = root.path().join("nonempty.lock");
    fs::write(&nonempty, b"payload").expect("nonempty lock");
    fs::set_permissions(&nonempty, fs::Permissions::from_mode(0o755)).expect("synthesized mode");
    let nonempty_error = KernelStateLock::acquire_direct_empty_coordination(&root, "nonempty.lock")
        .expect_err("nonempty coordination lock must fail");
    assert!(
        nonempty_error.to_string().contains("must remain empty"),
        "{}",
        nonempty_error
    );
}

#[cfg(unix)]
#[test]
fn empty_coordination_lock_verify_accepts_mode_0755_after_create() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create_managed(temp.path().join("claims")).expect("managed root");
    let lock = KernelStateLock::acquire_direct_empty_coordination(&root, "board.lock")
        .expect("create coordination lock");
    fs::set_permissions(lock.path(), fs::Permissions::from_mode(0o755)).expect("synthesize 0755");
    lock.verify_direct_binding(&root)
        .expect("verify must accept synthesized 0755 on an empty coordination lock");
}

#[cfg(unix)]
#[test]
fn stable_lock_refuses_unsafe_existing_mode_without_changing_it() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
    let lock_path = root.path().join("state.lock");
    fs::write(&lock_path, "").expect("lock file");
    fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o644)).expect("unsafe mode");

    let error = KernelStateLock::acquire(&lock_path).expect_err("unsafe lock must fail");
    assert!(error.to_string().contains("unsafe mode"));
    assert_eq!(
        fs::symlink_metadata(&lock_path)
            .expect("metadata")
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
}

#[cfg(unix)]
#[test]
fn stable_lock_rejects_path_replacement_after_flock() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
    let lock_path = root.path().join("state.lock");
    let moved_path = root.path().join("state.lock.original");
    set_kernel_lock_after_flock_hook({
        let moved_path = moved_path.clone();
        move |path| {
            fs::rename(path, &moved_path).expect("move acquired lock inode");
            fs::write(path, b"").expect("create replacement lock inode");
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))
                .expect("private replacement mode");
            true
        }
    });

    let error = KernelStateLock::acquire(&lock_path)
        .expect_err("post-flock pathname replacement must fail closed");
    assert!(
        error
            .to_string()
            .contains("does not name its opened descriptor")
            || error.to_string().contains("was rebound"),
        "unexpected error: {error:#}"
    );
    assert!(lock_path.exists());
    assert!(moved_path.exists());
    assert_ne!(
        identity_for_path(&lock_path).expect("replacement identity"),
        identity_for_path(&moved_path).expect("original identity")
    );
}

#[cfg(target_os = "linux")]
#[test]
fn locked_writer_scavenges_only_safe_matching_crash_temps() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
    let _lock = KernelStateLock::acquire_direct(&root, "claims.lock").expect("lock");
    let residue_name = random_temp_name(OsStr::new("claims.json"));
    let residue = root.path().join(&residue_name);
    fs::write(&residue, "partial").expect("residue");
    fs::set_permissions(&residue, fs::Permissions::from_mode(0o600)).expect("private mode");
    let expected = BoundedRegularReader::identity(&residue).expect("residue identity");
    let quarantine = temp_quarantine_name(OsStr::new("claims.json"), &residue_name, &expected);
    quarantine_regular_file(&root, &residue_name, &quarantine, &expected)
        .expect("simulate crash after temp quarantine rename");
    assert!(!residue.exists());
    assert!(root.path().join(&quarantine).exists());

    assert_eq!(
        AtomicStateWriter::scavenge_direct_temps(&root, "claims.json").expect("scavenge"),
        1
    );
    assert!(!residue.exists());
    AtomicStateWriter::write_direct(&root, "claims.json", b"complete\n").expect("durable write");
    assert_eq!(
        BoundedRegularReader::read_direct(&root, "claims.json", 32).expect("read"),
        b"complete\n"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn root_wide_temp_scavenge_recovers_interrupted_quarantine_and_live_temp() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
    let _lock = KernelStateLock::acquire_direct(&root, "root.lock").expect("lock");
    let quarantined_target = OsString::from("locator-a.json");
    let quarantined_source = random_temp_name(&quarantined_target);
    let quarantined_path = root.path().join(&quarantined_source);
    fs::write(&quarantined_path, b"partial-a").expect("quarantined source");
    fs::set_permissions(&quarantined_path, fs::Permissions::from_mode(0o600))
        .expect("private quarantine source");
    let identity = BoundedRegularReader::identity(&quarantined_path).expect("source identity");
    let quarantine = temp_quarantine_name(&quarantined_target, &quarantined_source, &identity);
    quarantine_regular_file(&root, &quarantined_source, &quarantine, &identity)
        .expect("simulate interrupted quarantine cleanup");

    let live_target = OsString::from("locator-b.json");
    let live_source = random_temp_name(&live_target);
    let live_path = root.path().join(&live_source);
    fs::write(&live_path, b"partial-b").expect("live source");
    fs::set_permissions(&live_path, fs::Permissions::from_mode(0o600))
        .expect("private live source");

    let foreign_target = OsString::from("foreign.json");
    let foreign_source = random_temp_name(&foreign_target);
    let foreign_path = root.path().join(&foreign_source);
    fs::write(&foreign_path, b"foreign").expect("foreign source");
    fs::set_permissions(&foreign_path, fs::Permissions::from_mode(0o600))
        .expect("private foreign source");

    let removed = AtomicStateWriter::scavenge_direct_temp_namespaces_bounded(&root, 8, |_| {
        Ok(BTreeSet::from([
            quarantined_target.clone(),
            live_target.clone(),
        ]))
    })
    .expect("root-wide recovery");

    assert_eq!(removed, 2);
    assert!(!root.path().join(quarantine).exists());
    assert!(!live_path.exists());
    assert!(foreign_path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn root_wide_temp_scavenge_rejects_rebound_quarantine_identity() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
    let _lock = KernelStateLock::acquire_direct(&root, "root.lock").expect("lock");
    let target = OsString::from("locator.json");
    let source = random_temp_name(&target);
    let source_path = root.path().join(&source);
    fs::write(&source_path, b"partial").expect("source");
    fs::set_permissions(&source_path, fs::Permissions::from_mode(0o600)).expect("private source");
    let identity = BoundedRegularReader::identity(&source_path).expect("source identity");
    let forged_identity = FileIdentity {
        device: identity.device,
        file: identity.file.wrapping_add(1),
    };
    let forged = temp_quarantine_name(&target, &source, &forged_identity);
    fs::rename(&source_path, root.path().join(&forged)).expect("forge rebound quarantine");

    let error = AtomicStateWriter::scavenge_direct_temp_namespaces_bounded(&root, 4, |_| {
        Ok(BTreeSet::from([target.clone()]))
    })
    .expect_err("encoded quarantine identity must bind its inode");

    assert!(error
        .to_string()
        .contains("identity is malformed or changed"));
    assert!(root.path().join(forged).exists());
}

#[cfg(target_os = "linux")]
#[test]
fn root_wide_temp_scavenge_rejects_legacy_quarantine_format() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("state")).expect("state root");
    let _lock = KernelStateLock::acquire_direct(&root, "root.lock").expect("lock");
    let target = OsString::from("locator.json");
    let source = random_temp_name(&target);
    let legacy = OsString::from(format!(
        "{TEMP_QUARANTINE_PREFIX}{}-{}-0000000000000001-0000000000000001",
        component_checksum(&target),
        component_checksum(&source)
    ));
    let legacy_path = root.path().join(&legacy);
    fs::write(&legacy_path, b"legacy").expect("legacy quarantine");
    fs::set_permissions(&legacy_path, fs::Permissions::from_mode(0o600))
        .expect("private legacy quarantine");

    let error = AtomicStateWriter::scavenge_direct_temp_namespaces_bounded(&root, 4, |_| {
        Ok(BTreeSet::from([target.clone()]))
    })
    .expect_err("unreleased legacy quarantine format must fail closed");

    assert!(error.to_string().contains("version is unsupported"));
    assert!(legacy_path.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn caller_bounded_temp_scavenge_can_cover_a_large_finite_namespace() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("large-state")).expect("state root");
    for index in 0..=4096_u32 {
        fs::write(root.path().join(format!("filler-{index:04}")), b"").expect("filler entry");
    }
    let residue = root
        .path()
        .join(random_temp_name(OsStr::new("locator.json")));
    fs::write(&residue, b"partial").expect("temp residue");
    fs::set_permissions(&residue, fs::Permissions::from_mode(0o600)).expect("private temp");

    let legacy_error = AtomicStateWriter::scavenge_direct_temps(&root, "locator.json")
        .expect_err("legacy scan budget is intentionally too small");
    assert!(legacy_error.to_string().contains("entry budget"));
    assert_eq!(
        AtomicStateWriter::scavenge_direct_temps_bounded(&root, "locator.json", 4_100)
            .expect("caller capacity covers complete root"),
        1
    );
    assert!(!residue.exists());
}

#[cfg(target_os = "linux")]
#[test]
fn forged_or_legacy_deletion_quarantine_is_never_removed() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("residues")).expect("root");
    let _lock = KernelStateLock::acquire_direct(&root, "bounded-status.lock").expect("lock");
    let residue = root
        .reserve_random_direct_child_directory("git-status")
        .expect("residue");
    let source = residue
        .path()
        .file_name()
        .expect("source name")
        .to_os_string();
    fs::write(residue.path().join("sentinel"), b"keep").expect("sentinel");
    fs::set_permissions(
        residue.path().join("sentinel"),
        fs::Permissions::from_mode(0o600),
    )
    .expect("sentinel mode");
    let mut forged = deletion_quarantine_name(&source, residue.identity())
        .as_bytes()
        .to_vec();
    let tag_start = forged.len().checked_sub(66).expect("tag position");
    forged[tag_start] = if forged[tag_start] == b'a' {
        b'b'
    } else {
        b'a'
    };
    let forged = OsString::from_vec(forged);
    fs::rename(residue.path(), root.path().join(&forged)).expect("forge quarantine name");

    let error = scavenge_private_random_directories(
        &root,
        "bounded-status.lock",
        "git-status",
        PrivateDirectoryScavengeLimits {
            max_root_entries: 8,
            max_directories: 4,
            max_tree_entries: 16,
            max_total_bytes: 1024,
            max_duration: Duration::from_secs(5),
        },
    )
    .expect_err("forged quarantine must fail closed");
    assert!(format!("{error:#}").contains("authentication tag"));
    assert!(root.path().join(&forged).join("sentinel").exists());

    let legacy = OsStr::new(".maco-delete-maco-v1-deadbeef-0000000000000001-0000000000000002");
    assert!(deletion_quarantine_binding(legacy)
        .expect_err("legacy quarantine must be rejected")
        .to_string()
        .contains("version is unsupported"));
}

#[cfg(target_os = "linux")]
#[test]
fn deadline_interrupted_scavenge_resumes_from_authenticated_quarantine() {
    let temp = TempDir::new().expect("tempdir");
    let root = SafeRoot::open_or_create(temp.path().join("residues")).expect("root");
    let _lock = KernelStateLock::acquire_direct(&root, "bounded-status.lock").expect("lock");
    let residue = root
        .reserve_random_direct_child_directory("git-status")
        .expect("residue");
    for name in ["first", "second"] {
        fs::write(residue.path().join(name), name).expect("residue file");
        fs::set_permissions(residue.path().join(name), fs::Permissions::from_mode(0o600))
            .expect("private residue file");
    }
    let limits = PrivateDirectoryScavengeLimits {
        max_root_entries: 8,
        max_directories: 4,
        max_tree_entries: 16,
        max_total_bytes: 1024,
        max_duration: Duration::from_secs(5),
    };
    let mut child_quarantines = 0usize;
    set_scavenge_deadline_hook(move |phase| {
        if phase == "before child quarantine" {
            child_quarantines = child_quarantines.saturating_add(1);
        }
        child_quarantines == 2
    });

    let error =
        scavenge_private_random_directories(&root, "bounded-status.lock", "git-status", limits)
            .expect_err("forced deadline must interrupt cleanup");
    assert!(format!("{error:#}").contains("time budget"));
    assert!(!residue.path().exists());

    assert_eq!(
        scavenge_private_random_directories(&root, "bounded-status.lock", "git-status", limits,)
            .expect("resume authenticated cleanup"),
        1
    );
    let entries = fs::read_dir(root.path())
        .expect("root entries")
        .map(|entry| entry.expect("entry").file_name())
        .collect::<Vec<_>>();
    assert_eq!(entries, vec![OsString::from("bounded-status.lock")]);
}

#[cfg(any(unix, windows))]
fn inventory_limits(max_entries: usize) -> BoundedTreeWalkLimits {
    BoundedTreeWalkLimits {
        max_depth: 16,
        max_entries,
        max_path_bytes: 4096,
        max_total_path_bytes: 64 * 1024,
        max_duration: Duration::from_secs(5),
        same_device: true,
    }
}

#[cfg(any(unix, windows))]
fn nested_repository_options() -> BoundedTreeWalkOptions {
    BoundedTreeWalkOptions {
        stop_at_nested_repositories: true,
    }
}

#[cfg(any(unix, windows))]
#[test]
fn bounded_tree_walk_stops_at_nested_repository_markers_and_keeps_root_traversal() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(root.join(".git")).expect("root marker directory");
    fs::write(root.join(".git/root-metadata"), "root metadata\n").expect("root metadata");
    fs::write(root.join("outer.txt"), "outer\n").expect("outer file");
    fs::create_dir_all(root.join("vendor/sdk/.git")).expect("nested marker directory");
    fs::write(root.join("vendor/sdk/.git/config"), "nested config\n").expect("nested config");
    fs::write(root.join("vendor/sdk/payload.bin"), "nested payload\n").expect("nested payload");
    fs::create_dir_all(root.join("vendor/peer/.git")).expect("sibling marker directory");
    fs::write(root.join("vendor/peer/peer.bin"), "sibling payload\n").expect("sibling payload");
    fs::create_dir_all(root.join("a/b/c")).expect("deep nested repository");
    fs::write(root.join("a/b/c/.git"), "gitdir: elsewhere\n").expect("nested marker file");
    fs::write(root.join("a/b/c/deep.bin"), "deep payload\n").expect("deep payload");
    fs::write(root.join("a/b/sibling.txt"), "visible sibling\n").expect("visible sibling");

    let binding = DirectoryBindingGuard::bind(&root).expect("bind repository root");
    let result = BoundedTreeWalker::walk_bound_with_options_detailed(
        &binding,
        inventory_limits(64),
        nested_repository_options(),
        |entry| {
            Ok(if entry.kind == BoundedTreeEntryKind::Directory {
                BoundedTreeWalkAction::RecordAndDescend
            } else {
                BoundedTreeWalkAction::Record
            })
        },
    )
    .expect("bounded nested-repository inventory");
    assert_eq!(
        result.nested_repository_boundaries,
        vec![
            PathBuf::from("a/b/c"),
            PathBuf::from("vendor/peer"),
            PathBuf::from("vendor/sdk"),
        ]
    );
    let paths = result
        .entries
        .iter()
        .map(|entry| entry.relative_path.as_path())
        .collect::<Vec<_>>();

    for expected in [
        Path::new("outer.txt"),
        Path::new(".git"),
        Path::new(".git/root-metadata"),
        Path::new("vendor/sdk"),
        Path::new("vendor/peer"),
        Path::new("a/b/c"),
        Path::new("a/b/sibling.txt"),
    ] {
        assert!(paths.contains(&expected), "missing {}", expected.display());
    }
    for excluded in [
        Path::new("vendor/sdk/.git"),
        Path::new("vendor/sdk/.git/config"),
        Path::new("vendor/sdk/payload.bin"),
        Path::new("vendor/peer/.git"),
        Path::new("vendor/peer/peer.bin"),
        Path::new("a/b/c/.git"),
        Path::new("a/b/c/deep.bin"),
    ] {
        assert!(
            !paths.contains(&excluded),
            "unexpected nested path {}",
            excluded.display()
        );
    }
}

#[cfg(any(unix, windows))]
#[test]
fn bounded_tree_walk_default_still_descends_into_nested_repositories() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(root.join("vendor/sdk/.git")).expect("nested marker directory");
    fs::write(root.join("vendor/sdk/.git/config"), "nested config\n").expect("nested config");
    fs::write(root.join("vendor/sdk/payload.bin"), "nested payload\n").expect("nested payload");

    let entries =
        BoundedTreeWalker::walk(&root, inventory_limits(16)).expect("default bounded inventory");

    assert!(entries
        .iter()
        .any(|entry| entry.relative_path == Path::new("vendor/sdk/.git/config")));
    assert!(entries
        .iter()
        .any(|entry| entry.relative_path == Path::new("vendor/sdk/payload.bin")));
}

#[cfg(any(unix, windows))]
#[test]
fn bounded_tree_walk_nested_boundaries_do_not_spend_content_budgets() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("repo");
    let nested = root.join("vendor/sdk");
    fs::create_dir_all(&nested).expect("nested repository directory");
    fs::write(nested.join(".git"), "gitdir: elsewhere\n").expect("nested marker file");
    for index in 0..32 {
        fs::write(
            nested.join(format!("payload-{index:02}.bin")),
            "nested payload\n",
        )
        .expect("nested payload");
    }

    let binding = DirectoryBindingGuard::bind(&root).expect("bind repository root");
    let entry_limits = inventory_limits(2);
    let entry_result = BoundedTreeWalker::walk_bound_with_options_detailed(
        &binding,
        entry_limits,
        nested_repository_options(),
        |entry| {
            Ok(if entry.kind == BoundedTreeEntryKind::Directory {
                BoundedTreeWalkAction::RecordAndDescend
            } else {
                BoundedTreeWalkAction::Record
            })
        },
    )
    .expect("nested content must not spend the remaining entry budget");
    assert_eq!(
        entry_result.nested_repository_boundaries,
        vec![PathBuf::from("vendor/sdk")]
    );
    let default_entry_error = BoundedTreeWalker::walk(&root, entry_limits)
        .expect_err("default traversal must retain ordinary entry accounting");
    assert!(format!("{default_entry_error:#}").contains("entry limit"));

    let outer = PathBuf::from("vendor");
    let boundary = outer.join("sdk");
    let outer_path_bytes = outer
        .as_os_str()
        .len()
        .saturating_add(boundary.as_os_str().len());
    let mut path_limits = inventory_limits(64);
    path_limits.max_total_path_bytes = outer_path_bytes;
    let path_result = BoundedTreeWalker::walk_bound_with_options_detailed(
        &binding,
        path_limits,
        nested_repository_options(),
        |entry| {
            Ok(if entry.kind == BoundedTreeEntryKind::Directory {
                BoundedTreeWalkAction::RecordAndDescend
            } else {
                BoundedTreeWalkAction::Record
            })
        },
    )
    .expect("nested content must not spend the remaining path-byte budget");
    assert_eq!(
        path_result.nested_repository_boundaries,
        vec![PathBuf::from("vendor/sdk")]
    );
    let default_path_error = BoundedTreeWalker::walk(&root, path_limits)
        .expect_err("default traversal must retain ordinary path-byte accounting");
    assert!(format!("{default_path_error:#}").contains("aggregate"));
}

#[cfg(any(unix, windows))]
#[test]
fn bounded_tree_walk_probes_nested_boundary_before_enforcing_descent_depth() {
    let temp = TempDir::new().expect("tempdir");
    let boundary_root = temp.path().join("boundary-root");
    fs::create_dir_all(boundary_root.join("nested/.git")).expect("boundary at maximum depth");
    let mut limits = inventory_limits(8);
    limits.max_depth = 1;
    let binding = DirectoryBindingGuard::bind(&boundary_root).expect("bind boundary root");
    let result = BoundedTreeWalker::walk_bound_with_options_detailed(
        &binding,
        limits,
        nested_repository_options(),
        |entry| {
            Ok(if entry.kind == BoundedTreeEntryKind::Directory {
                BoundedTreeWalkAction::RecordAndDescend
            } else {
                BoundedTreeWalkAction::Record
            })
        },
    )
    .expect("boundary exactly at maximum depth must terminate successfully");
    assert_eq!(
        result.nested_repository_boundaries,
        vec![PathBuf::from("nested")]
    );

    let ordinary_root = temp.path().join("ordinary-root");
    fs::create_dir_all(ordinary_root.join("ordinary")).expect("ordinary maximum-depth directory");
    let ordinary_binding = DirectoryBindingGuard::bind(&ordinary_root).expect("bind ordinary root");
    let error = BoundedTreeWalker::walk_bound_with_options_detailed(
        &ordinary_binding,
        limits,
        nested_repository_options(),
        |entry| {
            Ok(if entry.kind == BoundedTreeEntryKind::Directory {
                BoundedTreeWalkAction::RecordAndDescend
            } else {
                BoundedTreeWalkAction::Record
            })
        },
    )
    .expect_err("ordinary descent at the maximum depth must still fail closed");
    assert!(format!("{error:#}").contains("depth"));
}

#[cfg(unix)]
#[test]
fn bounded_tree_walk_records_but_never_follows_unsafe_entries() {
    use std::os::unix::fs::{symlink, FileTypeExt};

    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("repo");
    let outside = temp.path().join("outside");
    fs::create_dir_all(root.join("src")).expect("repo tree");
    fs::create_dir_all(&outside).expect("outside tree");
    fs::write(root.join("src/lib.rs"), "pub fn ok() {}\n").expect("source");
    fs::write(outside.join("secret"), "outside\n").expect("outside secret");
    fs::hard_link(root.join("src/lib.rs"), root.join("hardlink.rs")).expect("hardlink");
    symlink(&outside, root.join("outside-link")).expect("outside symlink");
    let socket_path = root.join("socket");
    let _socket = crate::test_support::bind_test_unix_socket(&socket_path).expect("unix socket");
    assert!(
        fs::symlink_metadata(&socket_path)
            .expect("socket metadata")
            .file_type()
            .is_socket(),
        "fixture socket must remain a socket entry"
    );

    let entries = BoundedTreeWalker::walk(&root, inventory_limits(32)).expect("inventory");
    assert!(entries.iter().any(|entry| {
        entry.relative_path == Path::new("outside-link")
            && entry.kind == BoundedTreeEntryKind::Symlink
    }));
    assert!(entries.iter().any(|entry| {
        entry.relative_path == Path::new("socket") && entry.kind == BoundedTreeEntryKind::Special
    }));
    assert!(!entries
        .iter()
        .any(|entry| entry.relative_path == Path::new("outside-link/secret")));
    assert!(entries
        .iter()
        .filter(|entry| entry.kind == BoundedTreeEntryKind::RegularFile)
        .all(|entry| entry.hard_link_count == 2 && !entry.is_safe_regular_file()));
}

#[cfg(unix)]
#[test]
fn bounded_tree_walk_enforces_entry_depth_and_path_budgets() {
    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(root.join("a/b")).expect("repo tree");
    fs::write(root.join("a/b/file"), "data").expect("file");

    let error = BoundedTreeWalker::walk(&root, inventory_limits(1))
        .expect_err("entry limit must fail closed");
    assert!(format!("{error:#}").contains("entry limit"));

    let mut limits = inventory_limits(16);
    limits.max_depth = 2;
    let error = BoundedTreeWalker::walk(&root, limits).expect_err("depth limit must fail closed");
    assert!(format!("{error:#}").contains("depth"));

    limits = inventory_limits(16);
    limits.max_total_path_bytes = 2;
    let error =
        BoundedTreeWalker::walk(&root, limits).expect_err("path aggregate must fail closed");
    assert!(format!("{error:#}").contains("aggregate"));
}

#[cfg(unix)]
#[test]
fn bounded_tree_walk_checks_deadline_after_callback() {
    let root = tempfile::tempdir().expect("tempdir");
    fs::write(root.path().join("entry"), "data").expect("write entry");
    let limits = BoundedTreeWalkLimits {
        max_depth: 8,
        max_entries: 8,
        max_path_bytes: 128,
        max_total_path_bytes: 1024,
        max_duration: Duration::from_millis(1),
        same_device: true,
    };

    let error = BoundedTreeWalker::walk_with(root.path(), limits, |_entry| {
        std::thread::sleep(Duration::from_millis(5));
        Ok(BoundedTreeWalkAction::Record)
    })
    .expect_err("callback overrun must fail the hard deadline check");

    assert!(error.to_string().contains("time limit"));
}

#[cfg(unix)]
#[test]
fn optional_relative_reader_preserves_scopes_and_rejects_unsafe_files() {
    use std::os::unix::fs::{symlink, FileTypeExt};

    let temp = TempDir::new().expect("tempdir");
    let root = temp.path().join("repo");
    fs::create_dir_all(root.join("src")).expect("repo tree");
    fs::write(root.join("src/lib.rs"), "source\n").expect("source");
    fs::hard_link(root.join("src/lib.rs"), root.join("hardlink.rs")).expect("hardlink");
    symlink("src/lib.rs", root.join("link.rs")).expect("symlink");
    let socket_path = root.join("socket");
    let _socket = crate::test_support::bind_test_unix_socket(&socket_path).expect("unix socket");
    assert!(
        fs::symlink_metadata(&socket_path)
            .expect("socket metadata")
            .file_type()
            .is_socket(),
        "fixture socket must remain a socket entry"
    );

    assert_eq!(
        BoundedRegularReader::read_relative_optional_utf8(&root, "missing.rs", 64)
            .expect("missing scope"),
        None
    );
    assert_eq!(
        BoundedRegularReader::read_relative_optional_utf8(&root, "src", 64)
            .expect("directory scope"),
        None
    );
    for path in ["src/lib.rs", "hardlink.rs", "link.rs", "socket"] {
        assert!(BoundedRegularReader::read_relative_optional_utf8(&root, path, 64).is_err());
    }
}
