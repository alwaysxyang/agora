use super::{normalize_path, resolve_existing_ancestor};
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;

#[test]
fn filesystem_path_helpers_normalize_and_preserve_a_missing_suffix() {
    assert_eq!(
        normalize_path(Path::new("/one/./two/../three")).unwrap(),
        Path::new("/one/three")
    );
    assert!(normalize_path(Path::new("relative/path")).is_err());

    let root = tempfile::tempdir().unwrap();
    let existing = root.path().join("existing");
    std::fs::create_dir(&existing).unwrap();
    let requested = existing.join("missing/child");
    assert_eq!(
        resolve_existing_ancestor(&requested).unwrap(),
        existing.canonicalize().unwrap().join("missing/child")
    );
}

#[test]
fn resolving_an_inaccessible_ancestor_preserves_the_io_error() {
    if unsafe { libc::geteuid() } == 0 {
        return;
    }

    let root = tempfile::tempdir().unwrap();
    let blocked = root.path().join("blocked");
    std::fs::create_dir(&blocked).unwrap();
    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o000)).unwrap();

    let error = resolve_existing_ancestor(&blocked.join("child")).unwrap_err();

    std::fs::set_permissions(&blocked, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(
        error
            .to_string()
            .contains("failed to resolve filesystem path")
    );
}
