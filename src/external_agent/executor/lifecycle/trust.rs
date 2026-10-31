use super::super::checksum::Sha256;
use super::*;
use crate::executor::{ExecutorLimits, SshConfig, SshConfigInput};
use std::{
    ffi::CString,
    fs::{self, File},
    io::{Seek, SeekFrom},
    os::{
        fd::{AsRawFd, FromRawFd, RawFd},
        unix::fs::MetadataExt,
    },
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Instant,
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Document {
    version: u32,
    ssh_binary: PathBuf,
    targets: Vec<Target>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Target {
    target: SshTargetConfig,
    identity_file: PathBuf,
    known_hosts_file: PathBuf,
    limits: ExecutorLimits,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct Stamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
    mode: u32,
    owner: u32,
    links: u64,
}

impl Stamp {
    fn from_metadata(m: &fs::Metadata) -> Self {
        Self {
            device: m.dev(),
            inode: m.ino(),
            length: m.len(),
            modified: (m.mtime(), m.mtime_nsec()),
            changed: (m.ctime(), m.ctime_nsec()),
            mode: m.mode(),
            owner: m.uid(),
            links: m.nlink(),
        }
    }
}

#[derive(Clone, Copy)]
enum Role {
    Private,
    KnownHosts,
    Executable,
}

fn open_checked(path: &Path, role: Role, deadline: Option<Instant>) -> Result<(File, Stamp)> {
    check_deadline(deadline)?;
    let text = path.to_str().context("trust path must be UTF-8")?;
    if !path.is_absolute()
        || text.len() > 4096
        || text.contains(['$', '%', '~'])
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        bail!("trust path must be absolute and normalized without OpenSSH expansion syntax");
    }
    // Resolve each component relative to a held directory, never through a link.
    let mut directory = File::open("/")?;
    check_deadline(deadline)?;
    let parts: Vec<_> = path.components().skip(1).collect();
    if parts.is_empty() {
        bail!("trust path must name a file");
    }
    // SAFETY: geteuid has no preconditions.
    let uid = unsafe { libc::geteuid() };
    for (index, part) in parts.iter().enumerate() {
        check_deadline(deadline)?;
        let parent = directory.metadata()?;
        check_deadline(deadline)?;
        if !parent.is_dir()
            || ![0, uid].contains(&parent.uid())
            || (parent.mode() & 0o022 != 0 && parent.mode() & 0o1000 == 0)
        {
            bail!("trust path has an unowned or writable ancestor");
        }
        let Component::Normal(name) = part else {
            bail!("trust path is not normalized");
        };
        let name = CString::new(name.as_encoded_bytes())?;
        let last = index + 1 == parts.len();
        let flags = libc::O_NOFOLLOW
            | libc::O_CLOEXEC
            | if last {
                libc::O_RDONLY | libc::O_NONBLOCK
            } else {
                libc::O_PATH | libc::O_DIRECTORY
            };
        // SAFETY: directory is held open and name is a single NUL-terminated component.
        let fd = unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error().into());
        }
        // SAFETY: successful openat returned a new descriptor owned here.
        let file = unsafe { File::from_raw_fd(fd) };
        check_deadline(deadline)?;
        if !last {
            directory = file;
            continue;
        }
        let metadata = file.metadata()?;
        check_deadline(deadline)?;
        let owner_ok =
            metadata.uid() == uid || (matches!(role, Role::Executable) && metadata.uid() == 0);
        let mask = if matches!(role, Role::Private) {
            0o077
        } else {
            0o022
        };
        if !metadata.is_file()
            || metadata.nlink() != 1
            || !owner_ok
            || metadata.mode() & mask != 0
            || (matches!(role, Role::Executable)
                && (metadata.mode() & 0o111 == 0 || metadata.mode() & 0o6000 != 0))
        {
            bail!("trust file must be owned, regular, single-link, and permission-restricted");
        }
        return Ok((file, Stamp::from_metadata(&metadata)));
    }
    unreachable!()
}

/// Read, hash, and validate the same opened source, checking the operation's
/// absolute deadline between bounded I/O and SHA-256 chunks. Validation retains
/// only hash state; trust loading optionally collects the bytes for its snapshot.
fn inspect_source(
    path: &Path,
    role: Role,
    max: u64,
    deadline: Option<Instant>,
    mut consume: impl FnMut(&[u8]) -> Result<()>,
) -> Result<(Stamp, Digest)> {
    let (mut file, before) = open_checked(path, role, deadline)?;
    if before.length > max {
        bail!("trust file exceeds byte limit");
    }
    let mut total = 0;
    let mut hash = Sha256::new();
    let mut buffer = [0; WORK_CHUNK_BYTES];
    loop {
        check_deadline(deadline)?;
        let n = file.read(&mut buffer)?;
        check_deadline(deadline)?;
        if n == 0 {
            break;
        }
        total += n as u64;
        if total > max {
            bail!("trust file grew beyond byte limit");
        }
        hash.update(&buffer[..n]);
        check_deadline(deadline)?;
        consume(&buffer[..n])?;
    }
    check_deadline(deadline)?;
    let digest = Digest::from_sha256(hash.finish());
    check_deadline(deadline)?;
    if Stamp::from_metadata(&file.metadata()?) != before
        || open_checked(path, role, deadline)?.1 != before
    {
        bail!("trust file changed during read");
    }
    check_deadline(deadline)?;
    Ok((before, digest))
}

// Snapshot loading happens before operation deadlines start. Operation and
// preflight revalidation use inspect_source without retaining the image bytes.
fn read_source(path: &Path, role: Role, max: u64) -> Result<(Stamp, Vec<u8>, Digest)> {
    let mut bytes = Vec::new();
    let (stamp, digest) = inspect_source(path, role, max, None, |chunk| {
        bytes.try_reserve_exact(chunk.len())?;
        bytes.extend_from_slice(chunk);
        Ok(())
    })?;
    Ok((stamp, bytes, digest))
}

// Called only while loading trust, never by operation/preflight validation.
fn seal(bytes: &[u8], executable: bool) -> Result<File> {
    // SAFETY: fixed NUL-terminated name and documented memfd flags.
    let fd = unsafe {
        libc::memfd_create(
            c"maco-ssh-snapshot".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    // SAFETY: memfd_create returned a newly owned descriptor.
    let mut file = unsafe { File::from_raw_fd(fd) };
    file.write_all(bytes)?;
    // SAFETY: only changes permissions on the anonymous file we own.
    if unsafe { libc::fchmod(fd, if executable { 0o500 } else { 0o400 }) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL;
    // SAFETY: seal the owned memfd, including against later permission changes.
    if unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, seals) } != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    file.seek(SeekFrom::Start(0))?;
    Ok(file)
}

struct PinnedFile {
    path: PathBuf,
    role: Role,
    max: u64,
    stamp: Stamp,
    digest: Digest,
    snapshot: File,
}

impl PinnedFile {
    fn capture(path: PathBuf, role: Role, max: u64) -> Result<Self> {
        let (stamp, bytes, digest) = read_source(&path, role, max)?;
        Ok(Self {
            path,
            role,
            max,
            stamp,
            digest,
            snapshot: seal(&bytes, matches!(role, Role::Executable))?,
        })
    }
    fn validate(&self, deadline: Option<Instant>) -> Result<()> {
        let (stamp, digest) =
            inspect_source(&self.path, self.role, self.max, deadline, |_| Ok(()))?;
        if stamp != self.stamp || digest != self.digest {
            bail!("SSH trust file identity or content changed; reload required");
        }
        check_deadline(deadline)
    }
    fn path_for_ssh(&self) -> PathBuf {
        // OpenSSH closes inherited extra FDs. Its parent retains this sealed
        // descriptor through reaping, so closefrom cannot sever the binding.
        format!(
            "/proc/{}/fd/{}",
            std::process::id(),
            self.snapshot.as_raw_fd()
        )
        .into()
    }
}

/// Operator-owned file capabilities; snapshots contain exactly the validated
/// bytes. No credential bytes are logged, serialized into plans, or stored on disk.
pub struct OperatorTrust {
    path: PathBuf,
    document_stamp: Stamp,
    digest: Digest,
    pins: Vec<PinnedFile>,
    binary: PinnedFile,
    targets: Vec<(ExecutorSelection, SshConfig)>,
}

impl OperatorTrust {
    pub fn load(path: &Path) -> Result<Arc<Self>> {
        let (document_stamp, bytes, digest) = read_source(path, Role::Private, 1024 * 1024)?;
        let document: Document = serde_json::from_slice(&bytes)?;
        if document.version != 1 || document.targets.is_empty() || document.targets.len() > 32 {
            bail!("unsupported or empty operator SSH trust document");
        }
        let mut pins = Vec::new();
        let mut targets = Vec::new();
        let mut ids = std::collections::BTreeSet::new();
        for entry in document.targets {
            if !ids.insert(entry.target.host_id.clone()) {
                bail!("duplicate operator host ID");
            }
            let config = SshConfig::new(SshConfigInput {
                host_id: entry.target.host_id.as_str().into(),
                host: entry.target.endpoint.as_str().into(),
                user: entry.target.user.as_str().into(),
                port: entry.target.port.get(),
                remote_root: entry.target.root.as_str().into(),
                helper_path: entry.target.helper.as_str().into(),
                identity_file: entry.identity_file.clone(),
                known_hosts_file: entry.known_hosts_file.clone(),
                limits: entry.limits,
            })?;
            pins.push(PinnedFile::capture(
                entry.identity_file,
                Role::Private,
                1024 * 1024,
            )?);
            pins.push(PinnedFile::capture(
                entry.known_hosts_file,
                Role::KnownHosts,
                1024 * 1024,
            )?);
            targets.push((ExecutorSelection::ssh(entry.target), config));
        }
        let binary = PinnedFile::capture(document.ssh_binary, Role::Executable, 64 * 1024 * 1024)?;
        Ok(Arc::new(Self {
            path: path.into(),
            document_stamp,
            digest,
            pins,
            binary,
            targets,
        }))
    }

    pub fn validate(&self) -> Result<()> {
        self.validate_until(None)
    }
    pub(super) fn validate_until(&self, deadline: Option<Instant>) -> Result<()> {
        let (stamp, digest) =
            inspect_source(&self.path, Role::Private, 1024 * 1024, deadline, |_| Ok(()))?;
        if stamp != self.document_stamp || digest != self.digest {
            bail!("operator SSH trust changed; reload required");
        }
        self.binary.validate(deadline)?;
        for pin in &self.pins {
            pin.validate(deadline)?;
        }
        Ok(())
    }
    pub fn targets(&self) -> &[(ExecutorSelection, SshConfig)] {
        &self.targets
    }
    pub(super) fn binary_fd(&self) -> RawFd {
        self.binary.snapshot.as_raw_fd()
    }
    pub(super) fn binary_path(&self) -> PathBuf {
        format!("/proc/self/fd/{}", self.binary_fd()).into()
    }
    pub(super) fn credential_paths(&self, config: &SshConfig) -> Result<(PathBuf, PathBuf)> {
        let find = |path: &Path| {
            self.pins
                .iter()
                .find(|pin| pin.path == path)
                .map(PinnedFile::path_for_ssh)
                .context("credential is not pinned")
        };
        Ok((
            find(config.identity_file())?,
            find(config.known_hosts_file())?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        os::unix::{fs::PermissionsExt, process::CommandExt},
        process::{Command, Stdio},
        time::Duration,
    };

    fn source(path: &Path, bytes: &[u8], mode: u32) {
        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn credential_snapshot_survives_replacement_after_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic-identity");
        source(&path, b"validated fixture bytes", 0o600);
        let pinned = PinnedFile::capture(path.clone(), Role::Private, 1024).unwrap();
        pinned.validate(None).unwrap();
        let replacement = dir.path().join("replacement");
        source(&replacement, b"different fixture bytes", 0o600);
        fs::rename(replacement, path).unwrap();
        assert_eq!(
            fs::read(pinned.path_for_ssh()).unwrap(),
            b"validated fixture bytes"
        );
        assert!(pinned.validate(None).is_err());
        assert!(pinned
            .snapshot
            .try_clone()
            .unwrap()
            .write_all(b"mutation")
            .is_err());
    }

    #[test]
    fn executes_sealed_image_after_source_path_replacement() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("synthetic-ssh");
        let marker = dir.path().join("marker");
        source(
            &path,
            format!("#!/bin/sh\nprintf validated > '{}'\n", marker.display()).as_bytes(),
            0o700,
        );
        let pinned = PinnedFile::capture(path.clone(), Role::Executable, 4096).unwrap();
        pinned.validate(None).unwrap();
        let replacement = dir.path().join("replacement");
        source(
            &replacement,
            format!("#!/bin/sh\nprintf replaced > '{}'\n", marker.display()).as_bytes(),
            0o700,
        );
        fs::rename(replacement, path).unwrap();
        assert!(pinned.validate(None).is_err());
        let fd = pinned.snapshot.as_raw_fd();
        let mut command = Command::new(format!("/proc/self/fd/{fd}"));
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // SAFETY: preserve this immutable script descriptor for its interpreter.
        unsafe {
            command.pre_exec(move || {
                if libc::fcntl(fd, libc::F_SETFD, 0) < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command.spawn().unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            if let Some(status) = child.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                panic!("sealed fixture timed out");
            }
            std::thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(fs::read(marker).unwrap(), b"validated");
    }
}

#[cfg(test)]
mod deadline_tests {
    use super::*;

    #[test]
    fn expired_deadline_precedes_ancestor_lookup() {
        let error = open_checked(
            Path::new("/absent/trust-source"),
            Role::Private,
            Some(Instant::now()),
        )
        .unwrap_err();
        assert!(error.to_string().contains("deadline expired"));
    }
}
