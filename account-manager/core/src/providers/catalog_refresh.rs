//! One catalog-only vendor command for managed account setup.
//!
//! The vendor is the only writer of `models_cache.json`. The command is an
//! allowlisted argv, with a cleared environment, null stdin, discarded
//! output, and a bounded timeout. Vendor bytes are never returned.

use std::ffi::OsString;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::account_authority::{CategoryObservation, ModelsObservation, ObservationOutcome};

pub(crate) const CATALOG_REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

const TRUSTED_PATH: &str = "/run/current-system/sw/bin:/usr/bin:/bin";
#[cfg(not(test))]
const TRUSTED_VENDOR_DIRS: &[&str] = &["/run/current-system/sw/bin", "/usr/bin", "/bin"];

pub(crate) struct VendorCatalogCommand {
    pub program_name: &'static str,
    pub args: &'static [&'static str],
    pub home_env: &'static str,
}

pub(crate) fn codex_catalog_command() -> VendorCatalogCommand {
    VendorCatalogCommand {
        program_name: "codex",
        args: &["debug", "models"],
        home_env: "CODEX_HOME",
    }
}

pub(crate) fn grok_catalog_command() -> VendorCatalogCommand {
    VendorCatalogCommand {
        program_name: "grok",
        args: &["--no-auto-update", "models"],
        home_env: "GROK_HOME",
    }
}

pub(crate) fn shell_single_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\"'\"'"))
}

pub(crate) fn remediation_command(tool: &str, data_dir: &Path, account_id: &str) -> String {
    match data_dir.to_str() {
        Some(path) => format!(
            "{tool} --data-dir {} refresh-models {account_id}",
            shell_single_quote(path)
        ),
        None => format!("{tool} refresh-models {account_id}"),
    }
}

/// Human summary plus one JSON object. `preamble` is empty or already ends
/// with a newline. Vendor output is not included.
pub(crate) fn format_model_refresh_report(
    preamble: &str,
    event: &str,
    account_id: &str,
    model_count: Option<usize>,
    remediation: &str,
) -> String {
    let (summary, value) = match model_count {
        Some(count) => {
            let summary = if count == 1 {
                "Observed 1 model.".to_string()
            } else {
                format!("Observed {count} models.")
            };
            (
                summary,
                serde_json::json!({
                    "event": event,
                    "accountId": account_id,
                    "modelObservation": "observed",
                    "modelCount": count,
                }),
            )
        }
        None => (
            format!("Warning: model metadata is still unobserved. Remediation: {remediation}"),
            serde_json::json!({
                "event": event,
                "accountId": account_id,
                "modelObservation": "unobserved",
                "modelCount": null,
                "remediation": remediation,
            }),
        ),
    };
    let json = serde_json::to_string(&value).unwrap_or_else(|_| "{}".to_string());
    format!("{preamble}{summary}\n{json}\n")
}

pub(crate) fn observed_model_count(
    observation: &CategoryObservation<ModelsObservation>,
) -> Option<usize> {
    if observation.outcome != ObservationOutcome::Observed {
        return None;
    }
    let count = observation.content.as_ref()?.models.len();
    (count > 0).then_some(count)
}

pub(crate) fn managed_models_cache_is_regular_file(home: &Path) -> bool {
    fs::symlink_metadata(home.join("models_cache.json"))
        .is_ok_and(|metadata| metadata.is_file() && !metadata.file_type().is_symlink())
}

/// `true` only when the allowlisted command exits 0. Failure, timeout, and a
/// missing binary are all `false`. Nothing is written on the vendor's behalf.
pub(crate) fn vendor_catalog_exited_zero(command: &VendorCatalogCommand, home: &Path) -> bool {
    vendor_catalog_exited_zero_within(command, home, CATALOG_REFRESH_TIMEOUT)
}

fn vendor_catalog_exited_zero_within(
    command: &VendorCatalogCommand,
    home: &Path,
    timeout: Duration,
) -> bool {
    if timeout.is_zero() || !home.is_absolute() {
        return false;
    }
    let Some(program) = resolve_vendor_program(command.program_name) else {
        return false;
    };
    let mut child = Command::new(&program);
    child
        .args(command.args)
        .current_dir(home)
        .env_clear()
        .env("PATH", contained_path(&program))
        .env("LANG", "C.UTF-8")
        .env("LC_ALL", "C.UTF-8")
        .env("TERM", "dumb")
        .env("HOME", home)
        .env(command.home_env, home)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(bundle) = trusted_cert_bundle() {
        child
            .env("SSL_CERT_FILE", &bundle)
            .env("NIX_SSL_CERT_FILE", &bundle);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        child.process_group(0);
    }
    let Ok(child) = child.spawn() else {
        return false;
    };
    wait_for_exit(child, timeout)
}

fn contained_path(program: &Path) -> OsString {
    let trusted = OsString::from(TRUSTED_PATH);
    match program.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            let mut path = parent.as_os_str().to_os_string();
            path.push(":");
            path.push(&trusted);
            path
        }
        _ => trusted,
    }
}

fn trusted_cert_bundle() -> Option<PathBuf> {
    for candidate in [
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/ssl/certs/ca-bundle.crt",
        "/etc/ssl/cert.pem",
    ] {
        let path = Path::new(candidate);
        if path.is_file() {
            return Some(path.to_path_buf());
        }
    }
    None
}

fn resolve_vendor_program(name: &str) -> Option<PathBuf> {
    #[cfg(test)]
    {
        let _ = name;
        PROGRAM_OVERRIDE.with(|slot| {
            slot.borrow()
                .as_ref()
                .and_then(|path| validated_vendor_program(path))
        })
    }
    #[cfg(not(test))]
    {
        resolve_allowlisted_vendor_program(name)
    }
}

/// PATH is searched before the fixed system directories so an owner-supplied
/// test double is selected ahead of a host binary. Every candidate still has
/// to be the named program and a regular, non-writable executable.
#[cfg(not(test))]
fn resolve_allowlisted_vendor_program(name: &str) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if let Some(path) = std::env::var_os("PATH") {
        for directory in std::env::split_paths(&path) {
            if directory.is_absolute() {
                candidates.push(directory.join(name));
            }
        }
    }
    for directory in TRUSTED_VENDOR_DIRS {
        candidates.push(Path::new(directory).join(name));
    }
    candidates
        .into_iter()
        .find_map(|candidate| validated_vendor_program(&candidate))
}

fn validated_vendor_program(path: &Path) -> Option<PathBuf> {
    let listed = fs::symlink_metadata(path).ok()?;
    if !(listed.file_type().is_symlink() || listed.is_file()) {
        return None;
    }
    let canonical = fs::canonicalize(path).ok()?;
    let metadata = fs::symlink_metadata(&canonical).ok()?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return None;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = metadata.permissions().mode();
        if mode & 0o111 == 0 || mode & 0o022 != 0 {
            return None;
        }
    }
    Some(canonical)
}

fn wait_for_exit(child: Child, timeout: Duration) -> bool {
    struct OwnedChild {
        child: Child,
        reaped: bool,
    }
    impl OwnedChild {
        fn terminate(&mut self) {
            #[cfg(unix)]
            if let Ok(pid) = i32::try_from(self.child.id()) {
                // SAFETY: `pid` is the leader of a group created for this child.
                // Signaling the negated id reaches only that group.
                unsafe {
                    libc::kill(-pid, libc::SIGKILL);
                }
            }
            let _ = self.child.kill();
            let _ = self.child.wait();
            self.reaped = true;
        }
    }
    impl Drop for OwnedChild {
        fn drop(&mut self) {
            if !self.reaped {
                self.terminate();
            }
        }
    }
    let mut owned = OwnedChild {
        child,
        reaped: false,
    };
    let started = Instant::now();
    loop {
        match owned.child.try_wait() {
            Ok(Some(status)) => {
                owned.reaped = true;
                return status.success();
            }
            Ok(None) if started.elapsed() >= timeout => {
                owned.terminate();
                return false;
            }
            Ok(None) => thread::sleep(Duration::from_millis(20)),
            Err(_) => {
                owned.terminate();
                return false;
            }
        }
    }
}

#[cfg(test)]
thread_local! {
    static PROGRAM_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
pub(crate) struct ProgramOverrideGuard;

#[cfg(test)]
impl Drop for ProgramOverrideGuard {
    fn drop(&mut self) {
        PROGRAM_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(test)]
pub(crate) fn override_vendor_program_for_test(path: PathBuf) -> ProgramOverrideGuard {
    PROGRAM_OVERRIDE.with(|slot| {
        assert!(slot.borrow().is_none(), "nested vendor program override");
        *slot.borrow_mut() = Some(path);
    });
    ProgramOverrideGuard
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    fn executable(path: &Path, body: &str) {
        fs::write(path, body).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
    }

    #[test]
    fn report_contains_the_count_and_not_vendor_bytes() {
        let remediation =
            remediation_command("cam-codex-setup", Path::new("/data/CAM 'dir'"), "work");
        let report = format_model_refresh_report(
            "Completed and selected the managed Codex account.\n",
            "setup-complete",
            "work",
            Some(2),
            &remediation,
        );
        assert!(report.starts_with("Completed and selected the managed Codex account.\n"));
        assert!(report.contains("Observed 2 models."));
        assert!(!report.contains("remediation"));
        assert!(!report.contains("FAKE-SECRET"));
        let json: serde_json::Value = serde_json::from_str(report.lines().last().unwrap()).unwrap();
        assert_eq!(json["modelCount"], 2);
        assert_eq!(json["modelObservation"], "observed");
        let warning = format_model_refresh_report("", "refresh-models", "work", None, &remediation);
        assert!(warning.contains("model metadata is still unobserved"));
        assert!(warning.contains(&remediation));
        assert!(remediation.contains("refresh-models work"));
        assert!(remediation.contains("CAM '\"'\"'dir'\"'\"'"));
    }

    #[test]
    fn missing_program_does_not_create_the_cache() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        fs::create_dir(&home).unwrap();
        assert!(!vendor_catalog_exited_zero(&codex_catalog_command(), &home));
        assert!(!home.join("models_cache.json").exists());
    }

    #[test]
    fn fake_vendor_sees_the_managed_home_and_no_api_keys() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().canonicalize().unwrap().join("home");
        fs::create_dir(&home).unwrap();
        let env_file = root.path().join("env");
        let argv_file = root.path().join("argv");
        let program = root.path().join("codex");
        executable(
            &program,
            &format!(
                "#!/bin/sh\ncp /proc/self/environ '{}'\nprintf '%s\\n' \"$@\" > '{}'\nprintf 'VENDOR-STDOUT-SECRET\\n'\nexit 0\n",
                env_file.display(),
                argv_file.display()
            ),
        );
        let _guard = override_vendor_program_for_test(program);
        let exited = vendor_catalog_exited_zero(&codex_catalog_command(), &home);
        assert!(exited);
        assert!(!home.join("models_cache.json").exists());
        let argv = fs::read_to_string(argv_file).unwrap();
        assert_eq!(argv, "debug\nmodels\n");
        let environ = fs::read(env_file).unwrap();
        let text = String::from_utf8_lossy(&environ);
        assert!(!text.contains("FAKE-openai"));
        assert!(!text.contains("FAKE-xai"));
        assert!(!text.contains("FAKE-grok-auth"));
        assert!(!text.contains("OPENAI_API_KEY"));
        assert!(!text.contains("XAI_API_KEY"));
        assert!(!text.contains("GROK_AUTH_PATH"));
        assert!(text.contains(&format!("CODEX_HOME={}", home.display())));
        assert!(text.contains(&format!("HOME={}", home.display())));
    }

    #[test]
    fn timed_out_vendor_is_not_success_and_writes_nothing() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        fs::create_dir(&home).unwrap();
        let program = root.path().join("codex");
        executable(&program, "#!/bin/sh\nsleep 30\n");
        let _guard = override_vendor_program_for_test(program);
        let started = Instant::now();
        let exited = vendor_catalog_exited_zero_within(
            &codex_catalog_command(),
            &home,
            Duration::from_secs(1),
        );
        assert!(!exited);
        assert!(started.elapsed() < Duration::from_secs(10));
        assert!(!home.join("models_cache.json").exists());
    }

    #[test]
    fn world_writable_program_is_rejected() {
        let root = tempfile::tempdir().unwrap();
        let program = root.path().join("codex");
        executable(&program, "#!/bin/sh\nexit 0\n");
        fs::set_permissions(&program, fs::Permissions::from_mode(0o722)).unwrap();
        assert!(validated_vendor_program(&program).is_none());
    }
}
