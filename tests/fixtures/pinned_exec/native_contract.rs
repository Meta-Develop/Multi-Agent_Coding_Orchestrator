//! Standalone Linux exec target, compiled without the main library or libtest.

use std::{
    env,
    ffi::OsString,
    fs::File,
    io::{self, Read},
    mem::ManuallyDrop,
    os::{fd::FromRawFd, unix::fs::MetadataExt},
};

unsafe extern "C" {
    fn fcntl(fd: i32, command: i32, ...) -> i32;
}

fn main() {
    const TEST: &str = "pinned_exec::tests::mechanical_native_exec_preserves_argv_env_null_stdin_and_closes_relay_fds";
    assert_eq!(
        env::args_os().collect::<Vec<_>>(),
        [
            OsString::from("/native-contract-argv0"),
            OsString::from("--exact"),
            OsString::from(TEST),
            OsString::from("--nocapture"),
        ]
    );
    assert_eq!(env::var("MACO_NATIVE_CONTRACT_TARGET").unwrap(), "1");
    assert_eq!(
        env::var("MACO_NATIVE_CONTRACT_VALUE").expect("explicit value"),
        "bounded value"
    );
    assert!(env::var_os("MACO_NATIVE_CONTRACT_CHILD").is_none());
    assert!(env::var_os("HOME").is_none());
    let mut byte = [0];
    assert_eq!(io::stdin().read(&mut byte).expect("null stdin"), 0);
    let relay = env::var("MACO_NATIVE_CONTRACT_RELAY").expect("test image identity");
    for fd in [4, 51] {
        // Linux F_GETFD and EBADF; keep this fixture independent of libc crates.
        const F_GETFD: i32 = 1;
        const EBADF: i32 = 9;
        // SAFETY: F_GETFD reads flags for this numeric fd without accessing memory.
        if unsafe { fcntl(fd, F_GETFD) } >= 0 {
            // SAFETY: fcntl verified this fd is live. This single-threaded target
            // only borrows it for metadata; ManuallyDrop preserves its ownership.
            let file = ManuallyDrop::new(unsafe { File::from_raw_fd(fd) });
            let metadata = file.metadata().expect("inspect inherited fd");
            assert_ne!(
                format!("{}:{}", metadata.dev(), metadata.ino()),
                relay,
                "an inherited native image copy survived exec"
            );
        } else {
            assert_eq!(io::Error::last_os_error().raw_os_error(), Some(EBADF));
        }
    }
    println!("mechanical-native-contract-ok");
}
