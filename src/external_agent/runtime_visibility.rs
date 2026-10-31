//! Refuse package layouts whose runtime closure is not covered by our sandboxes.
//!
//! Codex locates bundled helpers and PATH entries independently of its manifest.
//! Admitting extra mounts would require binding the entire closure, not just the
//! existing executable digest. Recognition follows resource links only to refuse
//! the installation; it never confers trust or grants those paths to a child.
use super::*;

#[derive(Debug, thiserror::Error)]
#[error("packaged_codex_runtime_not_visible: package is outside supported system roots; the outer executable-parent binding omits codex-resources/bwrap and codex-path, and the inner :minimal policy omits the package executable; install the package under /usr/lib or /nix/store")]
pub(super) struct PackagedCodexRuntimeNotVisible;

#[cfg(target_os = "linux")]
pub(super) fn validate_packaged_runtime_visibility(program: &Path) -> Result<()> {
    if program.file_name() != Some(OsStr::new("codex")) {
        return Ok(());
    }
    // These system trees already have runtime visibility. Do not add any mounts
    // or inner permissions. The resolver supplies the canonical executable, so
    // aliases to a system package retain the same admission as its actual path.
    if program.starts_with("/usr") || program.starts_with("/nix/store") {
        return Ok(());
    }
    // bin may itself be an alias (for example, bin -> executables). Locate the
    // resources relative to the resolved executable directory, not its spelling.
    let Some(package) = program.parent().and_then(Path::parent) else {
        return Ok(());
    };
    let Some(resources) = resolve_runtime_resource(&package.join("codex-resources"))
        .filter(|path| fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_dir()))
    else {
        return Ok(());
    };
    // Both audited versions (0.144.4 and 0.162.0) find bwrap through resource
    // symlinks and prepend codex-path without consulting codex-package.json.
    // Inspect metadata and at most one directory entry, never resource contents.
    let helper_is_file = resolve_runtime_resource(&resources.join("bwrap"))
        .is_some_and(|path| fs::symlink_metadata(path).is_ok_and(|metadata| metadata.is_file()));
    let has_path_entries =
        resolve_runtime_resource(&package.join("codex-path")).is_some_and(|path| {
            fs::read_dir(path).is_ok_and(|mut entries| matches!(entries.next(), Some(Ok(_))))
        });
    if helper_is_file || has_path_entries {
        return Err(PackagedCodexRuntimeNotVisible.into());
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolve_runtime_resource(path: &Path) -> Option<PathBuf> {
    use std::collections::VecDeque;

    const MAX_LINKS: usize = 40;
    const MAX_COMPONENTS: usize = 4096 * (MAX_LINKS + 1);
    if !path.is_absolute() {
        return None;
    }
    let mut pending = path
        .components()
        .map(|part| part.as_os_str().to_os_string())
        .collect::<VecDeque<_>>();
    let mut resolved = PathBuf::new();
    let mut visited = BTreeSet::new();
    let mut links = 0;
    let mut components = 0;
    while let Some(part) = pending.pop_front() {
        components += 1;
        if components > MAX_COMPONENTS {
            return None;
        }
        if part == OsStr::new("/") {
            resolved = PathBuf::from("/");
        } else if part == OsStr::new("..") {
            resolved.pop();
        } else if part != OsStr::new(".") {
            let candidate = resolved.join(part);
            let metadata = fs::symlink_metadata(&candidate).ok()?;
            if metadata.file_type().is_symlink() {
                // Include the remaining components: revisiting a link with a
                // shorter suffix can be valid (link/../link/file), not a cycle.
                if links == MAX_LINKS || !visited.insert((candidate.clone(), pending.clone())) {
                    return None;
                }
                links += 1;
                let target = fs::read_link(candidate).ok()?;
                let bytes = target.as_os_str().as_encoded_bytes();
                if bytes.ends_with(b"/") || bytes.ends_with(b"/.") {
                    // Preserve the directory requirement dropped by components().
                    pending.push_front(OsString::from("."));
                }
                for part in target.components().rev() {
                    pending.push_front(part.as_os_str().to_os_string());
                }
            } else {
                if !pending.is_empty() && !metadata.is_dir() {
                    return None;
                }
                resolved = candidate;
            }
        }
    }
    Some(resolved)
}

#[cfg(not(target_os = "linux"))]
pub(super) fn validate_packaged_runtime_visibility(_program: &Path) -> Result<()> {
    Ok(())
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};

    fn executable(path: &Path) -> Result<()> {
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, b"#!/bin/sh\nexit 0\n")?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        Ok(())
    }

    #[test]
    fn review_pkgvis_unrelated_sibling_must_not_refuse_plain_install() -> Result<()> {
        for marker in ["codex-package.json", "codex-resources", "codex-path"] {
            let root = tempfile::tempdir()?;
            let p = root.path().join("bin/codex");
            executable(&p)?;
            fs::create_dir(root.path().join(marker))?;
            let result = resolve_external_program(&p, root.path());
            assert!(
                result.is_ok(),
                "unrelated empty sibling {marker} refused a plain script: {result:?}"
            );
        }
        let root = tempfile::tempdir()?;
        let program = root.path().join("bin/codex");
        executable(&program)?;
        fs::write(root.path().join("codex-package.json"), b"{}")?;
        assert!(resolve_external_program(&program, root.path()).is_ok());
        fs::create_dir(root.path().join("codex-resources"))?;
        fs::create_dir(root.path().join("codex-path"))?;
        assert!(resolve_external_program(&program, root.path()).is_ok());
        fs::create_dir(root.path().join("codex-resources/bwrap"))?;
        assert!(resolve_external_program(&program, root.path()).is_ok());
        Ok(())
    }

    #[test]
    fn review_pkgvis_symlinked_bin_must_refuse_package() -> Result<()> {
        let root = tempfile::tempdir()?;
        let real = root.path().join("executables/codex");
        executable(&real)?;
        symlink("executables", root.path().join("bin"))?;
        fs::create_dir(root.path().join("codex-resources"))?;
        fs::write(root.path().join("codex-resources/bwrap"), b"helper")?;
        fs::create_dir(root.path().join("codex-path"))?;
        fs::write(root.path().join("codex-package.json"), b"{}")?;
        let result = resolve_external_program(&root.path().join("bin/codex"), root.path());
        assert!(
            result
                .as_ref()
                .is_err_and(|e| e.is::<PackagedCodexRuntimeNotVisible>()),
            "package escaped via symlinked bin: {result:?}"
        );
        Ok(())
    }

    fn package(root: &Path) -> Result<PathBuf> {
        let program = root.join("bin/codex");
        executable(&program)?;
        fs::create_dir(root.join("codex-resources"))?;
        fs::write(root.join("codex-resources/bwrap"), b"helper")?;
        fs::write(root.join("codex-package.json"), b"{}")?;
        fs::create_dir(root.join("codex-path"))?;
        Ok(program)
    }

    fn assert_refused(program: &Path, cwd: &Path, case: &str) {
        let actual = resolve_external_program(program, cwd);
        assert!(
            actual
                .as_ref()
                .is_err_and(|error| error.is::<PackagedCodexRuntimeNotVisible>()),
            "{case}: packaged runtime lost typed refusal: {actual:?}"
        );
    }

    #[test]
    fn audit_pkgvis_symlinked_helper_still_refuses_package() -> Result<()> {
        let root = tempfile::tempdir()?;
        let program = package(root.path())?;
        fs::rename(
            root.path().join("codex-resources/bwrap"),
            root.path().join("codex-resources/bwrap-real"),
        )?;
        symlink("bwrap-real", root.path().join("codex-resources/bwrap"))?;
        assert_refused(&program, root.path(), "symlinked helper");
        Ok(())
    }

    #[test]
    fn audit_pkgvis_symlinked_resources_still_refuses_package() -> Result<()> {
        let root = tempfile::tempdir()?;
        let program = package(root.path())?;
        fs::rename(
            root.path().join("codex-resources"),
            root.path().join("real-resources"),
        )?;
        symlink("real-resources", root.path().join("codex-resources"))?;
        assert_refused(&program, root.path(), "symlinked resources");
        Ok(())
    }

    #[test]
    fn audit_pkgvis_symlinked_manifest_still_refuses_package() -> Result<()> {
        let root = tempfile::tempdir()?;
        let program = package(root.path())?;
        fs::rename(
            root.path().join("codex-package.json"),
            root.path().join("manifest-real.json"),
        )?;
        symlink("manifest-real.json", root.path().join("codex-package.json"))?;
        assert_refused(&program, root.path(), "symlinked manifest");
        Ok(())
    }

    #[test]
    fn audit_pkgvis_manifest_absent_still_refuses_resource_package() -> Result<()> {
        let root = tempfile::tempdir()?;
        let program = package(root.path())?;
        fs::remove_file(root.path().join("codex-package.json"))?;
        assert_refused(
            &program,
            root.path(),
            "absent manifest with working resources",
        );
        Ok(())
    }

    #[test]
    fn audit_pkgvis_resource_link_chains_still_refuse_package() -> Result<()> {
        let root = tempfile::tempdir()?;
        let program = package(root.path())?;
        fs::remove_file(root.path().join("codex-package.json"))?;
        let resources = root.path().join("real-resources");
        fs::rename(root.path().join("codex-resources"), &resources)?;
        fs::rename(resources.join("bwrap"), resources.join("bwrap-real"))?;
        symlink("bwrap-real", resources.join("helper-hop"))?;
        symlink(resources.join("helper-hop"), resources.join("bwrap"))?;
        symlink("./real-resources", root.path().join("resource-hop"))?;
        symlink(
            root.path().join("resource-hop"),
            root.path().join("codex-resources"),
        )?;
        assert_refused(
            &program,
            root.path(),
            "absolute and relative resource/helper chains",
        );
        Ok(())
    }

    #[test]
    fn audit_pkgvis_consumed_path_requires_resources_and_nonempty_directory() -> Result<()> {
        let root = tempfile::tempdir()?;
        let program = package(root.path())?;
        fs::remove_file(root.path().join("codex-package.json"))?;
        fs::remove_file(root.path().join("codex-resources/bwrap"))?;
        fs::rename(
            root.path().join("codex-path"),
            root.path().join("real-path"),
        )?;
        symlink("real-path", root.path().join("codex-path"))?;
        assert!(resolve_external_program(&program, root.path()).is_ok());
        fs::write(root.path().join("real-path/rg"), b"bundled path entry")?;
        assert_refused(
            &program,
            root.path(),
            "consumed nonempty path beside resources",
        );
        fs::remove_dir(root.path().join("codex-resources"))?;
        assert!(resolve_external_program(&program, root.path()).is_ok());
        Ok(())
    }

    #[test]
    fn audit_pkgvis_resource_resolution_bounds_cycles_and_preserves_path_semantics() -> Result<()> {
        let root = tempfile::tempdir()?;
        let directory = root.path().join("directory");
        fs::create_dir(&directory)?;
        let file = directory.join("file");
        fs::write(&file, b"helper")?;
        symlink("directory", root.path().join("alias"))?;
        assert_eq!(
            resolve_runtime_resource(&root.path().join("alias/../alias/file")),
            Some(file.clone())
        );
        symlink("directory/file/", root.path().join("file-as-directory"))?;
        assert!(resolve_runtime_resource(&root.path().join("file-as-directory")).is_none());
        symlink("cycle-b", root.path().join("cycle-a"))?;
        symlink("cycle-a", root.path().join("cycle-b"))?;
        assert!(resolve_runtime_resource(&root.path().join("cycle-a")).is_none());
        symlink("growing/child", root.path().join("growing"))?;
        assert!(resolve_runtime_resource(&root.path().join("growing")).is_none());
        let mut target = file.clone();
        for index in (0..40).rev() {
            let link = root.path().join(format!("chain-{index}"));
            symlink(&target, &link)?;
            target = link;
        }
        assert_eq!(resolve_runtime_resource(&target), Some(file));
        let overflow = root.path().join("overflow");
        symlink(target, &overflow)?;
        assert!(resolve_runtime_resource(&overflow).is_none());
        Ok(())
    }
}
