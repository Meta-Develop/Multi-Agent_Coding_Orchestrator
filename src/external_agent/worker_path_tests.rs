use super::*;

use std::os::unix::fs::MetadataExt;
use std::os::unix::fs::PermissionsExt;

#[test]
fn unset_or_empty_setting_appends_nothing() {
    assert!(worker_path_append_from(None).unwrap().is_empty());
    assert!(worker_path_append_from(Some("")).unwrap().is_empty());
    let mut environment = BTreeMap::from([("PATH".to_string(), TRUSTED_PATH.to_string())]);
    append_worker_path(&mut environment, &[]);
    assert_eq!(environment.get("PATH").unwrap(), TRUSTED_PATH);
}

#[test]
fn root_directory_is_appended_after_the_trusted_path() {
    let mut environment = BTreeMap::from([("PATH".to_string(), TRUSTED_PATH.to_string())]);
    append_worker_path(&mut environment, &[PathBuf::from("/")]);
    assert_eq!(
        environment.get("PATH").unwrap(),
        &format!("{TRUSTED_PATH}:/")
    );
    let uid = fs::metadata("/").unwrap().uid();
    match worker_path_append_from(Some("/")) {
        Ok(directories) => {
            assert_eq!(uid, 0);
            assert_eq!(directories, vec![PathBuf::from("/")]);
        }
        Err(error) => {
            assert_ne!(uid, 0);
            assert!(format!("{error:#}").contains("is not owned by root"));
            eprintln!(
                "root_directory_is_appended_after_the_trusted_path: / is owned by uid {uid} here (a user namespace maps root away); parser acceptance of / runs where / is owned by root"
            );
        }
    }
}

#[test]
fn malformed_entries_are_refused() {
    for (raw, reason) in [
        ("/:", "is empty"),
        (":/", "is empty"),
        ("relative/bin", "is not absolute"),
        ("/usr/bin", "is already on the trusted PATH"),
        ("/:/", "is listed more than once"),
    ] {
        let error = worker_path_append_from(Some(raw)).unwrap_err();
        let message = format!("{error:#}");
        assert!(message.contains(reason), "entry {raw:?}: {message}");
    }
}

#[test]
fn unsafe_directories_are_refused() {
    let directory = tempfile::tempdir().unwrap();
    let root = fs::canonicalize(directory.path()).unwrap();

    let missing = root.join("missing");
    let error = worker_path_append_from(Some(missing.to_str().unwrap())).unwrap_err();
    assert!(format!("{error:#}").contains("cannot be resolved"));

    let symlink = root.join("root-symlink");
    std::os::unix::fs::symlink("/", &symlink).unwrap();
    let error = worker_path_append_from(Some(symlink.to_str().unwrap())).unwrap_err();
    assert!(format!("{error:#}").contains("is not canonical"));

    let error = worker_path_append_from(Some("/.")).unwrap_err();
    assert!(format!("{error:#}").contains("is not canonical"));

    let trailing = PathBuf::from(format!("{}/", root.display()));
    let error = worker_path_append_from(Some(trailing.to_str().unwrap())).unwrap_err();
    assert!(format!("{error:#}").contains("is not canonical"));

    let file = root.join("file");
    fs::File::create(&file).unwrap();
    let error = worker_path_append_from(Some(file.to_str().unwrap())).unwrap_err();
    assert!(format!("{error:#}").contains("is not a directory"));

    let world_writable = root.join("world-writable");
    fs::create_dir(&world_writable).unwrap();
    let mut permissions = fs::metadata(&world_writable).unwrap().permissions();
    permissions.set_mode(0o777);
    fs::set_permissions(&world_writable, permissions).unwrap();
    let error = worker_path_append_from(Some(world_writable.to_str().unwrap())).unwrap_err();
    assert!(format!("{error:#}").contains("is group- or world-writable"));

    let owner_only = root.join("owner-only");
    fs::create_dir(&owner_only).unwrap();
    let mut permissions = fs::metadata(&owner_only).unwrap().permissions();
    permissions.set_mode(0o755);
    fs::set_permissions(&owner_only, permissions).unwrap();
    let uid = fs::metadata(&owner_only).unwrap().uid();
    if uid != 0 {
        let error = worker_path_append_from(Some(owner_only.to_str().unwrap())).unwrap_err();
        assert!(format!("{error:#}").contains("is not owned by root"));
    }
}
