use super::*;
use crate::safe_state::FileIdentity;
use std::os::unix::{
    fs::{symlink, MetadataExt, OpenOptionsExt, PermissionsExt},
    io::AsRawFd,
};

// Thread-local and scoped so parallel tests and panic unwinding cannot leave
// another test using an injected syscall failure.
struct Openat2Error(Option<i32>);

impl Openat2Error {
    fn force(errno: i32) -> Self {
        Self(WORKER_JOURNAL_OPENAT2_ERROR.with(|slot| slot.replace(Some(errno))))
    }
}

impl Drop for Openat2Error {
    fn drop(&mut self) {
        WORKER_JOURNAL_OPENAT2_ERROR.with(|slot| slot.set(self.0));
    }
}

fn journal(path: &Path) -> FileIdentity {
    let file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    let metadata = file.metadata().unwrap();
    FileIdentity {
        device: metadata.dev(),
        file: metadata.ino(),
    }
}

fn entry() -> WorkerExecutionJournalEntry {
    WorkerExecutionJournalEntry {
        command: vec!["apply_patch".into(), "patch with \"quotes\"\n\\path".into()],
        cwd: PathBuf::from("/worktree"),
        start_timestamp: "2026-10-15T00:00:00Z".into(),
        end_timestamp: "2026-10-15T00:00:01Z".into(),
        changed_paths: vec![PathBuf::from("p")],
    }
}

#[test]
fn worker_journal_enosys_fallback_appends_without_replacing_file() {
    let _error = Openat2Error::force(libc::ENOSYS);
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("worker.jsonl");
    let expected = journal(&path);
    let original = b"existing immutable record\n";
    fs::write(&path, original).unwrap();

    for append in [true, false] {
        let file = open_worker_journal_no_follow(&path, append).unwrap();
        // SAFETY: fcntl reads flags from a live descriptor without pointers.
        let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
        assert!(flags >= 0);
        assert_ne!(flags & libc::O_NONBLOCK, 0);
        assert_eq!(flags & libc::O_APPEND != 0, append);
        assert_eq!(
            flags & libc::O_ACCMODE,
            if append {
                libc::O_WRONLY
            } else {
                libc::O_RDONLY
            }
        );
        // SAFETY: fcntl reads descriptor flags without pointers.
        let fd_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
        assert!(fd_flags >= 0);
        assert_ne!(fd_flags & libc::FD_CLOEXEC, 0);
    }

    let record = entry();
    let mut encoded = Vec::new();
    append_worker_execution_journal_record(&mut encoded, &record).unwrap();
    // The injection remains active for the append open and both reopens.
    append_precreated_worker_execution_journal(&path, &expected, &record).unwrap();
    append_precreated_worker_execution_journal(&path, &expected, &record).unwrap();
    assert_eq!(
        fs::read(&path).unwrap(),
        [original.as_slice(), &encoded, &encoded].concat()
    );
    verify_worker_journal_identity(&fs::metadata(&path).unwrap(), &expected).unwrap();
}

#[test]
fn worker_journal_enosys_fallback_refuses_symlink_leaf_and_ancestor() {
    let _error = Openat2Error::force(libc::ENOSYS);
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("worker.jsonl");
    let expected = journal(&path);
    let alias = root.join("alias.jsonl");
    symlink(&path, &alias).unwrap();
    let ancestor = root.join("alias-dir");
    symlink(&root, &ancestor).unwrap();

    for alias in [alias, ancestor.join("worker.jsonl")] {
        for append in [true, false] {
            assert!(open_worker_journal_no_follow(&alias, append).is_err());
        }
        assert!(append_precreated_worker_execution_journal(&alias, &expected, &entry()).is_err());
    }
    assert!(fs::read(path).unwrap().is_empty());
}

#[test]
fn worker_journal_enosys_fallback_refuses_wrong_device_and_inode() {
    let _error = Openat2Error::force(libc::ENOSYS);
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap().join("worker.jsonl");
    let expected = journal(&path);
    for wrong in [
        FileIdentity {
            device: expected.device.wrapping_add(1),
            file: expected.file,
        },
        FileIdentity {
            device: expected.device,
            file: expected.file.wrapping_add(1),
        },
    ] {
        let error =
            append_precreated_worker_execution_journal(&path, &wrong, &entry()).unwrap_err();
        assert!(error
            .to_string()
            .contains("expected current-user-owned single-link 0600 regular file"));
        assert!(fs::read(&path).unwrap().is_empty());
    }
}

#[test]
fn worker_journal_enosys_fallback_preserves_file_policy_and_existing_only_open() {
    let _error = Openat2Error::force(libc::ENOSYS);
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let path = root.join("worker.jsonl");
    let expected = journal(&path);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(append_precreated_worker_execution_journal(&path, &expected, &entry()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::hard_link(&path, root.join("hardlink.jsonl")).unwrap();
    assert!(append_precreated_worker_execution_journal(&path, &expected, &entry()).is_err());
    let missing = root.join("missing.jsonl");
    assert!(append_precreated_worker_execution_journal(&missing, &expected, &entry()).is_err());
    assert!(!missing.exists());
    assert!(append_precreated_worker_execution_journal(&root, &expected, &entry()).is_err());
    let fifo = root.join("fifo");
    let name = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    // SAFETY: name is NUL-terminated and this test owns its temporary directory.
    assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
    assert!(open_worker_journal_no_follow(&fifo, false).is_err());
    assert!(append_precreated_worker_execution_journal(&fifo, &expected, &entry()).is_err());
    assert!(fs::read(path).unwrap().is_empty());
}

#[test]
fn worker_journal_fallback_does_not_retry_other_openat2_errors() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().canonicalize().unwrap().join("worker.jsonl");
    let expected = journal(&path);
    for errno in [
        libc::EPERM,
        libc::EACCES,
        libc::EINVAL,
        libc::ELOOP,
        libc::EXDEV,
    ] {
        let _error = Openat2Error::force(errno);
        for append in [true, false] {
            let error = open_worker_journal_no_follow(&path, append).unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<std::io::Error>()
                    .unwrap()
                    .raw_os_error(),
                Some(errno)
            );
        }
        assert!(append_precreated_worker_execution_journal(&path, &expected, &entry()).is_err());
        assert!(fs::read(&path).unwrap().is_empty());
    }
}
