//! Private source bytes are materialized per launch, mounted read-only, then unlinked
//! before target release. No mutable operator pathname backs the target's input.
use super::*;

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ReadOnlyInputSnapshot {
    pub(super) path: PathBuf,
    sha256: String,
    bytes: Arc<[u8]>,
}
impl fmt::Debug for ReadOnlyInputSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReadOnlyInputSnapshot")
            .field("path", &self.path)
            .field("sha256", &self.sha256)
            .finish_non_exhaustive()
    }
}
impl ReadOnlyInputSnapshot {
    pub(crate) fn capture(path: &Path, expected_hash: &str) -> io::Result<Self> {
        let bytes = read_bounded_regular_file_nofollow(path, 1024 * 1024)?;
        if bytes.is_empty() || crate::artifacts::state_auth::sha256_hex(&bytes) != expected_hash {
            return Err(io::Error::other("source input changed before snapshot"));
        }
        Ok(Self {
            path: path.to_path_buf(),
            sha256: expected_hash.to_owned(),
            bytes: bytes.into(),
        })
    }

    #[cfg(target_os = "linux")]
    pub(super) fn materialize(&self) -> io::Result<MountedInputSnapshot> {
        use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
        // An owned 0700 directory outside every child-visible workspace. Only the
        // exact file is mounted. Close its only writable descriptor before launch.
        let root = tempfile::Builder::new()
            .prefix("maco-source-input-")
            .tempdir()?;
        let source = root.path().join("input");
        {
            let mut writer = OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&source)?;
            writer.write_all(&self.bytes)?;
            writer.set_permissions(fs::Permissions::from_mode(0o400))?;
        }
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&source)?;
        let mounted = MountedInputSnapshot {
            path: self.path.clone(),
            sha256: self.sha256.clone(),
            root,
            file,
            unlinked: AtomicBool::new(false),
        };
        mounted.verify()?;
        Ok(mounted)
    }
}

#[cfg(target_os = "linux")]
pub(super) struct MountedInputSnapshot {
    pub(super) path: PathBuf,
    sha256: String,
    root: tempfile::TempDir,
    file: File,
    unlinked: AtomicBool,
}
#[cfg(target_os = "linux")]
impl MountedInputSnapshot {
    pub(super) fn source(&self) -> PathBuf {
        self.root.path().join("input")
    }
    pub(super) fn identity(&self) -> io::Result<(u64, u64)> {
        use std::os::unix::fs::MetadataExt;
        let metadata = self.file.metadata()?;
        Ok((metadata.dev(), metadata.ino()))
    }
    pub(super) fn verify(&self) -> io::Result<()> {
        use std::os::unix::fs::{FileExt, MetadataExt};
        let metadata = self.file.metadata()?;
        if !metadata.is_file() || metadata.mode() & 0o777 != 0o400 || metadata.len() > 1024 * 1024 {
            return Err(io::Error::other("private source snapshot metadata changed"));
        }
        if self.unlinked.load(Ordering::Acquire) {
            if metadata.nlink() != 0 {
                return Err(io::Error::other(
                    "released source snapshot retained a mutable alias",
                ));
            }
        } else {
            let current = fs::symlink_metadata(self.source())?;
            if current.file_type().is_symlink()
                || current.dev() != metadata.dev()
                || current.ino() != metadata.ino()
                || metadata.nlink() != 1
            {
                return Err(io::Error::other("private source snapshot identity changed"));
            }
        }
        let mut bytes = vec![0; metadata.len() as usize];
        self.file.read_exact_at(&mut bytes, 0)?;
        if crate::artifacts::state_auth::sha256_hex(&bytes) != self.sha256 {
            return Err(io::Error::other("private source snapshot content changed"));
        }
        Ok(())
    }
    pub(super) fn unlink_before_release(&self) -> io::Result<()> {
        self.verify()?;
        if !self.unlinked.load(Ordering::Acquire) {
            fs::remove_file(self.source())?;
            self.unlinked.store(true, Ordering::Release);
        }
        self.verify()
    }
}

#[cfg(all(test, target_os = "linux"))]
#[test]
fn source_inputs_snapshot_unlinks_backing_and_outlives_source_mutation() -> io::Result<()> {
    let root = tempfile::tempdir()?;
    let path = root.path().join("source.diff");
    let content = b"-unchecked(value)\n+checked(value)?\n";
    fs::write(&path, content)?;
    let snapshot =
        ReadOnlyInputSnapshot::capture(&path, &crate::artifacts::state_auth::sha256_hex(content))?;
    fs::write(&path, b"different same-inode bytes")?;
    let mounted = snapshot.materialize()?;
    assert_eq!(fs::read(mounted.source())?, content);
    assert!(mounted.file.try_clone()?.write_all(b"unverified").is_err());
    mounted.unlink_before_release()?;
    assert!(!mounted.source().exists());
    mounted.verify()?;
    let tampered = snapshot.materialize()?;
    fs::set_permissions(
        tampered.source(),
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )?;
    fs::write(tampered.source(), b"unverified")?;
    assert!(tampered.unlink_before_release().is_err());
    let mut direct = ProcessSpec::direct(
        "uncontained snapshot",
        "/usr/bin/true",
        std::iter::empty::<&str>(),
        root.path(),
        1024,
    )
    .with_containment(ContainmentPolicy::TrustedBestEffort);
    direct.read_only_input_snapshots = vec![snapshot];
    assert!(validate_process_spec_bounds(&direct).is_err());
    Ok(())
}
