//! Shared pre-release endpoint transitions, using only isolated fixtures.

use std::fs;
use std::os::unix::{fs::symlink, net::UnixListener};
use std::path::PathBuf;

use anyhow::Result;

use super::authority_socket_config::CamAuthoritySocketTestGuard;

pub(super) fn assert_endpoint_changes_refused<A>(
    mut acquire: impl FnMut(Option<PathBuf>) -> Result<A>,
    mut verify: impl FnMut(&mut A) -> Result<()>,
) -> Result<()> {
    for entry in ["parent", "socket", "file", "dangling-symlink"] {
        let root = tempfile::tempdir()?;
        let socket = root.path().join("maco/account-authority.sock");
        let _default = CamAuthoritySocketTestGuard::install_default(socket.clone());
        assert!(super::cam_socket_for_frozen_selection(None)?.is_none());
        let mut authority = acquire(None)?;
        verify(&mut authority)?;

        fs::create_dir(socket.parent().unwrap())?;
        let _listener = match entry {
            "socket" => Some(UnixListener::bind(&socket)?),
            "file" => {
                fs::write(&socket, b"not a Unix socket")?;
                None
            }
            "dangling-symlink" => {
                symlink("missing.sock", &socket)?;
                None
            }
            "parent" => None,
            _ => unreachable!(),
        };
        let error = verify(&mut authority).expect_err(entry);
        assert!(
            format!("{error:#}").contains("authority socket configuration changed"),
            "{entry}: {error:#}"
        );
    }

    // The injected acquisition starts at registry reservation so path drift is
    // exercised independently of socket ancestry/peer authorization checks.
    let root = tempfile::tempdir()?;
    let original = root.path().join("original.sock");
    let replacement = root.path().join("replacement.sock");
    let endpoint = CamAuthoritySocketTestGuard::install(Some(original.as_os_str()));
    let mut authority = acquire(Some(original))?;
    endpoint.set(Some(replacement.as_os_str()));
    let error = verify(&mut authority).expect_err("a different endpoint must be refused");
    assert!(format!("{error:#}").contains("socket configuration changed"));
    endpoint.set(None);
    let error = verify(&mut authority).expect_err("a removed endpoint must be refused");
    assert!(format!("{error:#}").contains("refusing local fallback"));
    Ok(())
}
