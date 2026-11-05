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

use crate::account_authority::{
    model_has_selectable_efforts, CategoryObservation, ModelsObservation, ObservationOutcome,
};

pub(crate) const CATALOG_REFRESH_TIMEOUT: Duration = Duration::from_secs(30);

const TRUSTED_PATH: &str = "/run/current-system/sw/bin:/usr/bin:/bin";
#[cfg(not(all(test, unix)))]
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
    let usable = observation
        .content
        .as_ref()?
        .models
        .iter()
        .filter(|model| model_has_selectable_efforts(model))
        .count();
    (usable > 0).then_some(usable)
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
    let mut entries = Vec::new();
    if let Some(parent) = program.parent() {
        if !parent.as_os_str().is_empty() {
            entries.push(parent.to_path_buf());
        }
    }
    entries.extend(TRUSTED_PATH.split(':').map(PathBuf::from));
    std::env::join_paths(entries).unwrap_or_else(|_| OsString::from(TRUSTED_PATH))
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
    #[cfg(all(test, unix))]
    {
        let _ = name;
        PROGRAM_OVERRIDE.with(|slot| {
            slot.borrow()
                .as_ref()
                .and_then(|path| validated_vendor_program(path))
        })
    }
    #[cfg(not(all(test, unix)))]
    {
        resolve_allowlisted_vendor_program(name)
    }
}

/// Absolute PATH entries precede the fixed system directories so an
/// owner-supplied test double is selected ahead of a host binary. Every
/// candidate still has to pass the ancestor and file trust check.
#[cfg(not(all(test, unix)))]
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
    #[cfg(unix)]
    {
        resolve_trusted_executable(path)
    }
    #[cfg(not(unix))]
    {
        let listed = fs::symlink_metadata(path).ok()?;
        if listed.file_type().is_symlink() || !listed.is_file() {
            return None;
        }
        let canonical = fs::canonicalize(path).ok()?;
        let metadata = fs::symlink_metadata(&canonical).ok()?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return None;
        }
        Some(canonical)
    }
}

/// Follow every symlink and require each directory and the final file to be
/// owned by the caller or root and not group- or world-writable. A root-owned
/// sticky directory is the only writable ancestor that is accepted.
#[cfg(unix)]
fn resolve_trusted_executable(path: &Path) -> Option<PathBuf> {
    use std::os::unix::fs::PermissionsExt;

    const MAX_SYMLINKS: u8 = 16;
    let mut current = path.to_path_buf();
    for _ in 0..MAX_SYMLINKS {
        match walk_executable_path(&current)? {
            ExecutableWalk::File(resolved) => {
                let metadata = fs::symlink_metadata(&resolved).ok()?;
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return None;
                }
                let mode = metadata.permissions().mode();
                if mode & 0o111 == 0 || mode & 0o022 != 0 {
                    return None;
                }
                if crate::account_authority::reject_owner_and_mode(&resolved, &metadata).is_err() {
                    return None;
                }
                return Some(resolved);
            }
            ExecutableWalk::Follow { link, target, rest } => {
                current = normalize_symlink(&link, &target, &rest)?;
            }
        }
    }
    None
}

#[cfg(unix)]
enum ExecutableWalk {
    File(PathBuf),
    Follow {
        link: PathBuf,
        target: PathBuf,
        rest: Vec<OsString>,
    },
}

#[cfg(unix)]
fn walk_executable_path(path: &Path) -> Option<ExecutableWalk> {
    use std::path::Component;

    if !path.is_absolute() {
        return None;
    }
    let components: Vec<_> = path.components().collect();
    let mut current = PathBuf::new();
    for (index, component) in components.iter().enumerate() {
        match component {
            Component::RootDir => current.push(component.as_os_str()),
            Component::Normal(name) => current.push(name),
            Component::CurDir | Component::ParentDir | Component::Prefix(_) => return None,
        }
        let metadata = fs::symlink_metadata(&current).ok()?;
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(&current).ok()?;
            let rest = components[index + 1..]
                .iter()
                .map(|later| later.as_os_str().to_os_string())
                .collect();
            return Some(ExecutableWalk::Follow {
                link: current,
                target,
                rest,
            });
        }
        if crate::account_authority::reject_owner_and_mode(&current, &metadata).is_err() {
            return None;
        }
        let last = index + 1 == components.len();
        if last {
            return metadata.is_file().then_some(ExecutableWalk::File(current));
        }
        if !metadata.is_dir() {
            return None;
        }
    }
    None
}

#[cfg(unix)]
fn normalize_symlink(link: &Path, target: &Path, rest: &[OsString]) -> Option<PathBuf> {
    use std::path::Component;

    let mut names = Vec::new();
    if !target.is_absolute() {
        let parent = link.parent()?;
        for component in parent.components() {
            match component {
                Component::RootDir => {}
                Component::Normal(name) => names.push(name.to_os_string()),
                Component::CurDir | Component::ParentDir | Component::Prefix(_) => return None,
            }
        }
    }
    for component in target.components() {
        match component {
            Component::RootDir => names.clear(),
            Component::CurDir => {}
            Component::ParentDir => {
                names.pop()?;
            }
            Component::Normal(name) => names.push(name.to_os_string()),
            Component::Prefix(_) => return None,
        }
    }
    names.extend(rest.iter().cloned());
    let mut resolved = PathBuf::from(Component::RootDir.as_os_str());
    for name in names {
        resolved.push(name);
    }
    Some(resolved)
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

#[cfg(all(test, unix))]
thread_local! {
    static PROGRAM_OVERRIDE: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

#[cfg(all(test, unix))]
pub(crate) struct ProgramOverrideGuard;

#[cfg(all(test, unix))]
impl Drop for ProgramOverrideGuard {
    fn drop(&mut self) {
        PROGRAM_OVERRIDE.with(|slot| *slot.borrow_mut() = None);
    }
}

#[cfg(all(test, unix))]
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
                "#!/bin/sh\n/usr/bin/env > '{}'\nprintf '%s\\n' \"$@\" > '{}'\nprintf 'VENDOR-STDOUT-SECRET\\n'\nexit 0\n",
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
        let text = fs::read_to_string(env_file).unwrap();
        assert!(!text.contains("FAKE-openai"));
        assert!(!text.contains("FAKE-xai"));
        assert!(!text.contains("FAKE-grok-auth"));
        for name in ["OPENAI_API_KEY", "XAI_API_KEY", "GROK_AUTH_PATH"] {
            assert!(
                !text
                    .split(['\0', '\n'])
                    .any(|entry| entry.starts_with(&format!("{name}="))),
                "{name} was present"
            );
        }
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

    #[test]
    fn shared_writable_directory_and_symlink_target_are_rejected() {
        let root = tempfile::tempdir().unwrap();
        let untrusted = root.path().join("untrusted");
        fs::create_dir(&untrusted).unwrap();
        fs::set_permissions(&untrusted, fs::Permissions::from_mode(0o777)).unwrap();
        let planted = untrusted.join("codex");
        executable(&planted, "#!/bin/sh\nexit 0\n");
        fs::set_permissions(&planted, fs::Permissions::from_mode(0o755)).unwrap();
        assert!(validated_vendor_program(&planted).is_none());

        let safe = root.path().join("safe");
        fs::create_dir(&safe).unwrap();
        fs::set_permissions(&safe, fs::Permissions::from_mode(0o700)).unwrap();
        let link_to_untrusted = safe.join("codex");
        std::os::unix::fs::symlink(&planted, &link_to_untrusted).unwrap();
        assert!(validated_vendor_program(&link_to_untrusted).is_none());

        let real = safe.join("real");
        executable(&real, "#!/bin/sh\nexit 0\n");
        let link_in_untrusted = untrusted.join("via-link");
        std::os::unix::fs::symlink(&real, &link_in_untrusted).unwrap();
        assert!(validated_vendor_program(&link_in_untrusted).is_none());
        assert!(validated_vendor_program(&real).is_some());
    }
}

#[cfg(test)]
mod effort_metadata_tests {
    use super::*;
    use crate::account_authority::{ModelAccessOutcome, ObservedModel};

    fn model(id: &str, efforts: Option<&[&str]>) -> ObservedModel {
        ObservedModel {
            model_id: id.to_string(),
            supported_efforts: efforts
                .map(|items| items.iter().map(|item| (*item).to_string()).collect()),
            default_effort: None,
            access: ModelAccessOutcome::UnknownAccess,
        }
    }

    fn observed(models: Vec<ObservedModel>) -> CategoryObservation<ModelsObservation> {
        CategoryObservation::observed(ModelsObservation {
            models,
            provenance: None,
        })
    }

    #[test]
    fn models_without_usable_efforts_do_not_count_as_observed() {
        let missing = observed(vec![model("gpt-a", None), model("gpt-b", None)]);
        assert!(observed_model_count(&missing).is_none());
        let unknown = observed(vec![model("gpt-a", Some(&["deep"]))]);
        assert!(observed_model_count(&unknown).is_none());
        let empty = observed(vec![model("gpt-a", Some(&[]))]);
        assert!(observed_model_count(&empty).is_none());
        let mixed = observed(vec![model("gpt-a", Some(&["high"])), model("gpt-b", None)]);
        assert_eq!(observed_model_count(&mixed), Some(1));
    }
}
