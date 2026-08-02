use super::{backing_path, decode_name, encode_name, logical_path};
use std::ffi::OsStr;
use std::path::Path;

#[test]
fn ordinary_paths_keep_their_mirrored_layout() {
    let root = Path::new("/work/fs");
    assert_eq!(
        backing_path(root, Path::new("/usr/bin/curl")).unwrap(),
        Path::new("/work/fs/usr/bin/curl")
    );
}

#[test]
fn logical_control_names_use_a_distinct_physical_name() {
    let root = Path::new("/work/fs");
    let backing = backing_path(root, Path::new("/bin/.metadata")).unwrap();
    assert_ne!(backing, Path::new("/work/fs/bin/.metadata"));
    assert_eq!(
        logical_path(root, &backing).unwrap(),
        Path::new("/bin/.metadata")
    );
}

#[test]
fn escaping_is_injective_for_names_that_resemble_encoded_entries() {
    let reserved = encode_name(OsStr::new(".metadata"));
    let prefix = encode_name(OsStr::new(".agora-entry-Lm1ldGFkYXRh"));
    assert_ne!(reserved, prefix);
    assert_eq!(decode_name(&reserved).unwrap(), OsStr::new(".metadata"));
    assert_eq!(
        decode_name(&prefix).unwrap(),
        OsStr::new(".agora-entry-Lm1ldGFkYXRh")
    );
}

#[test]
fn namespace_rejects_relative_or_external_backing_paths() {
    assert!(backing_path(Path::new("/work/fs"), Path::new("relative")).is_err());
    assert!(
        logical_path(Path::new("/work/fs"), Path::new("/other/file"))
            .unwrap_err()
            .to_string()
            .contains("not inside")
    );
}
