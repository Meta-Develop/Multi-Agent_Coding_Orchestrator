//! One transport operation owns one delegated cgroup and one absolute deadline.
//! Pipes are nonblocking; no thread or descendant-held descriptor is joined.
use super::*;
use std::{
    fs::{self, File, OpenOptions},
    io,
    os::{
        fd::{AsRawFd, RawFd},
        unix::{fs::OpenOptionsExt, process::CommandExt},
    },
    path::{Component, Path, PathBuf},
    process::{Child, Command},
    sync::atomic::{AtomicU64, Ordering},
    thread,
    time::{Duration, Instant},
};

static NEXT_GROUP: AtomicU64 = AtomicU64::new(0);

struct Scope {
    path: PathBuf,
    attach: File,
    kill: File,
    removed: bool,
}

impl Scope {
    fn new(deadline: Instant) -> Result<Self> {
        check_deadline(Some(deadline))?;
        let membership = fs::read_to_string("/proc/self/cgroup")?;
        let relative = membership
            .lines()
            .find_map(|s| s.strip_prefix("0::"))
            .context("SSH transport requires cgroup v2")?;
        let relative = Path::new(relative).strip_prefix("/")?;
        if relative
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
        {
            bail!("invalid kernel cgroup path");
        }
        let parent = Path::new("/sys/fs/cgroup").join(relative);
        let path = parent.join(format!(
            "maco-ssh-{}-{}",
            std::process::id(),
            NEXT_GROUP.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).context("SSH transport requires a delegated local cgroup (run under systemd-run --user --scope -p Delegate=yes)")?;
        let open = |name| {
            OpenOptions::new()
                .write(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
                .open(path.join(name))
        };
        match (open("cgroup.procs"), open("cgroup.kill")) {
            (Ok(attach), Ok(kill)) => Ok(Self {
                path,
                attach,
                kill,
                removed: false,
            }),
            _ => {
                let _ = fs::remove_dir(&path);
                bail!("delegated cgroup does not support process attachment and atomic tree kill");
            }
        }
    }

    fn finish(&mut self, child: &mut Child, deadline: Instant) -> Result<()> {
        self.kill.write_all(b"1\n")?;
        loop {
            let reaped = child.try_wait()?.is_some();
            let events = fs::read_to_string(self.path.join("cgroup.events"))?;
            if reaped && events.lines().any(|line| line == "populated 0") {
                fs::remove_dir(&self.path)?;
                self.removed = true;
                return Ok(());
            }
            check_deadline(Some(deadline))
                .context("SSH transport cleanup could not be confirmed before the deadline")?;
            thread::sleep(
                Duration::from_millis(1).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
    }
}

impl Drop for Scope {
    fn drop(&mut self) {
        if !self.removed {
            // Atomic cgroup.kill includes descendants that changed process group/session.
            // A busy cgroup is retained for reconciliation rather than waited on indefinitely.
            let _ = self.kill.write_all(b"1\n");
            let _ = fs::remove_dir(&self.path);
        }
    }
}

fn nonblocking(fd: RawFd) -> Result<()> {
    // SAFETY: fd is a live pipe owned by this operation; preserve its other flags.
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

pub(super) fn preflight(deadline: Instant) -> Result<()> {
    let mut scope = Scope::new(deadline)?;
    scope.kill.write_all(b"1\n")?;
    let events = fs::read_to_string(scope.path.join("cgroup.events"))?;
    if !events.lines().any(|line| line == "populated 0") {
        bail!("new SSH transport cgroup is unexpectedly populated");
    }
    fs::remove_dir(&scope.path).context("cannot remove SSH transport preflight cgroup")?;
    scope.removed = true;
    check_deadline(Some(deadline))
}

pub(super) fn run(
    mut command: Command,
    executable: RawFd,
    payload: &[u8],
    maximum: u64,
    deadline: Instant,
    timeout: Duration,
    spawned: &mut bool,
) -> Result<Vec<u8>> {
    let reserve = (timeout / 4).min(Duration::from_millis(50));
    let io_deadline = deadline
        .checked_sub(reserve)
        .context("invalid transport deadline")?;
    check_deadline(Some(io_deadline))?;
    let mut scope = Scope::new(io_deadline)?;
    let attach = scope.attach.as_raw_fd();
    command.process_group(0);
    // SAFETY: only async-signal-safe syscalls run in the forked child. Attach
    // before exec, so even an immediately detached grandchild belongs to us.
    unsafe {
        command.pre_exec(move || {
            if libc::write(attach, b"0\n".as_ptr().cast(), 2) != 2 {
                return Err(io::Error::last_os_error());
            }
            let flags = libc::fcntl(executable, libc::F_GETFD);
            if flags < 0 || libc::fcntl(executable, libc::F_SETFD, flags & !libc::FD_CLOEXEC) < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        });
    }
    check_deadline(Some(io_deadline))?;
    let mut child = command.spawn()?;
    *spawned = true;
    let outcome = exchange(&mut child, payload, maximum, io_deadline);
    let cleanup = scope.finish(&mut child, deadline);
    cleanup?;
    outcome
}

fn exchange(child: &mut Child, payload: &[u8], maximum: u64, deadline: Instant) -> Result<Vec<u8>> {
    let mut input = child.stdin.take();
    let mut output = child.stdout.take().context("missing SSH stdout")?;
    nonblocking(input.as_ref().context("missing SSH stdin")?.as_raw_fd())?;
    nonblocking(output.as_raw_fd())?;
    let mut sent = 0;
    let mut receiver = Receiver::new(maximum);
    let mut eof = false;
    let mut buffer = [0; 8192];
    loop {
        check_deadline(Some(deadline))?;
        if let Some(pipe) = &mut input {
            match pipe.write(&payload[sent..]) {
                Ok(0) => bail!("SSH input closed before the request completed"),
                Ok(n) => sent += n,
                Err(e)
                    if e.kind() == io::ErrorKind::WouldBlock
                        || e.kind() == io::ErrorKind::Interrupted => {}
                Err(e) => return Err(e.into()),
            }
            if sent == payload.len() {
                input.take();
            }
        }
        if !eof {
            loop {
                check_deadline(Some(deadline))?;
                match output.read(&mut buffer) {
                    Ok(0) => {
                        eof = true;
                        break;
                    }
                    Ok(n) => receiver.feed(&buffer[..n])?,
                    Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e.into()),
                }
            }
        }
        if let Some(status) = child.try_wait()? {
            if !status.success() {
                bail!("SSH lifecycle helper refused request");
            }
            if eof && input.is_none() {
                return receiver.finish();
            }
        }
        let mut polls = [
            libc::pollfd {
                fd: input.as_ref().map_or(-1, AsRawFd::as_raw_fd),
                events: libc::POLLOUT,
                revents: 0,
            },
            libc::pollfd {
                fd: if eof { -1 } else { output.as_raw_fd() },
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let millis = deadline
            .saturating_duration_since(Instant::now())
            .as_millis()
            .min(10) as i32;
        // SAFETY: polls is a live array; poll never owns its descriptors.
        if unsafe { libc::poll(polls.as_mut_ptr(), polls.len() as libc::nfds_t, millis) } < 0
            && io::Error::last_os_error().kind() != io::ErrorKind::Interrupted
        {
            return Err(io::Error::last_os_error().into());
        }
    }
}

struct Receiver {
    maximum: u64,
    header: [u8; 16],
    header_len: usize,
    expected: Option<usize>,
    bytes: Vec<u8>,
}

impl Receiver {
    fn new(maximum: u64) -> Self {
        Self {
            maximum: maximum.min(MAX_FRAME),
            header: [0; 16],
            header_len: 0,
            expected: None,
            bytes: Vec::new(),
        }
    }
    fn feed(&mut self, mut bytes: &[u8]) -> Result<()> {
        if self.header_len < 16 {
            let n = bytes.len().min(16 - self.header_len);
            self.header[self.header_len..self.header_len + n].copy_from_slice(&bytes[..n]);
            self.header_len += n;
            bytes = &bytes[n..];
            if self.header_len == 16 {
                if &self.header[..8] != MAGIC {
                    bail!("invalid lifecycle protocol magic");
                }
                let size = u64::from_be_bytes(self.header[8..].try_into()?);
                if size > self.maximum {
                    bail!("lifecycle frame exceeds byte limit");
                }
                let size = usize::try_from(size)?;
                self.bytes.try_reserve_exact(size)?;
                self.expected = Some(size);
            }
        }
        if let Some(expected) = self.expected {
            if bytes.len() > expected - self.bytes.len() {
                bail!("trailing lifecycle frame bytes");
            }
            self.bytes.extend_from_slice(bytes);
        }
        Ok(())
    }
    fn finish(self) -> Result<Vec<u8>> {
        if self.expected != Some(self.bytes.len()) {
            bail!("truncated lifecycle frame");
        }
        Ok(self.bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn response_length_checked_before_buffer_allocation() {
        let mut receiver = Receiver::new(32);
        let mut header = MAGIC.to_vec();
        header.extend_from_slice(&u64::MAX.to_be_bytes());
        assert!(receiver.feed(&header).is_err());
        assert_eq!(receiver.bytes.capacity(), 0);
    }
}
