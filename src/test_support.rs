use std::{
    fs, io,
    os::unix::{
        ffi::OsStrExt,
        fs::{symlink, FileTypeExt},
        net::UnixListener,
    },
    path::{Path, PathBuf},
};
use tempfile::TempDir;

#[must_use = "the socket guard must stay alive while the fixture is inspected"]
pub(crate) struct TestUnixSocket {
    _listener: UnixListener,
    _short_bind_root: Option<TempDir>,
    path: PathBuf,
}

impl Drop for TestUnixSocket {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub(crate) fn bind_test_unix_socket(path: &Path) -> io::Result<TestUnixSocket> {
    let (short_bind_root, bind_path) = short_socket_bind_path(path)?;
    let bind_path_bytes = bind_path.as_os_str().as_bytes().len();
    let sun_path_capacity = std::mem::size_of::<libc::sockaddr_un>()
        - std::mem::offset_of!(libc::sockaddr_un, sun_path);
    assert!(
        bind_path_bytes < sun_path_capacity,
        "test socket bind path is {bind_path_bytes} bytes, but sun_path requires fewer than {sun_path_capacity}: {}",
        bind_path.display()
    );

    let listener = UnixListener::bind(&bind_path)?;
    let socket = TestUnixSocket {
        _listener: listener,
        _short_bind_root: short_bind_root,
        path: path.to_path_buf(),
    };
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() {
        return Err(io::Error::other(format!(
            "test socket bind did not create a socket at {}",
            path.display()
        )));
    }
    Ok(socket)
}

fn short_socket_bind_path(path: &Path) -> io::Result<(Option<TempDir>, PathBuf)> {
    let sun_path_capacity = std::mem::size_of::<libc::sockaddr_un>()
        - std::mem::offset_of!(libc::sockaddr_un, sun_path);
    if path.as_os_str().as_bytes().len() < sun_path_capacity {
        return Ok((None, path.to_path_buf()));
    }

    let parent_path = path.parent().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "test socket path has no parent",
        )
    })?;
    let file_name = path.file_name().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "test socket path has no file name",
        )
    })?;
    let short_bind_root = tempfile::Builder::new()
        .prefix("maco-sock-")
        .tempdir_in("/tmp")?;
    let parent_alias = short_bind_root.path().join("p");
    symlink(fs::canonicalize(parent_path)?, &parent_alias)?;
    let bind_path = parent_alias.join(file_name);
    Ok((Some(short_bind_root), bind_path))
}
