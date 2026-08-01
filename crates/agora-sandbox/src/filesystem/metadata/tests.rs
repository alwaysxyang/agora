use super::{DirectoryMetadata, EntryState, METADATA_VERSION, Materializer, MetadataStore};
use std::collections::BTreeMap;
use std::os::unix::ffi::OsStringExt;
use std::path::Path;

#[test]
fn metadata_round_trips_cached_cow_and_whiteout_states() {
    let root = tempfile();
    let store = MetadataStore::new(&root).unwrap();
    let cached = Path::new("/tmp/cached");
    let cow = Path::new("/tmp/cow");
    let whiteout = Path::new("/tmp/whiteout");

    store
        .set(
            cached,
            EntryState::Cached {
                checksum: "d41d8cd98f00b204e9800998ecf8427e".to_string(),
                materializer: Materializer::Copy,
            },
        )
        .unwrap();
    store.set(cow, EntryState::Cow).unwrap();
    store.set(whiteout, EntryState::Whiteout).unwrap();

    assert!(matches!(
        store.state(cached).unwrap(),
        Some(EntryState::Cached { .. })
    ));
    assert_eq!(store.state(cow).unwrap(), Some(EntryState::Cow));
    assert_eq!(store.state(whiteout).unwrap(), Some(EntryState::Whiteout));
    assert_eq!(store.entries(Path::new("/tmp")).unwrap().len(), 3);

    store.remove(cached).unwrap();
    assert_eq!(store.state(cached).unwrap(), None);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn metadata_supports_non_utf8_names() {
    let root = tempfile();
    let store = MetadataStore::new(&root).unwrap();
    let path = Path::new("/tmp").join(std::ffi::OsString::from_vec(vec![b'f', 0x80]));

    store.set(&path, EntryState::Cow).unwrap();

    assert_eq!(store.state(&path).unwrap(), Some(EntryState::Cow));
    assert_eq!(
        store.entries(Path::new("/tmp")).unwrap()[0].0,
        path.file_name().unwrap()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn metadata_rejects_invalid_paths_and_records() {
    let root = tempfile();
    let store = MetadataStore::new(&root).unwrap();
    assert!(store.state(Path::new("relative")).is_err());
    assert!(store.entries(Path::new("relative")).is_err());

    let path = store.path(Path::new("/tmp")).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, b"not json").unwrap();
    assert!(
        store
            .entries(Path::new("/tmp"))
            .unwrap_err()
            .to_string()
            .contains("parse")
    );

    std::fs::write(
        &path,
        serde_json::to_vec(&DirectoryMetadata {
            version: METADATA_VERSION + 1,
            entries: Default::default(),
        })
        .unwrap(),
    )
    .unwrap();
    assert!(
        store
            .entries(Path::new("/tmp"))
            .unwrap_err()
            .to_string()
            .contains("unsupported")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn metadata_handles_root_entries_and_reports_storage_failures() {
    let root = tempfile();
    let store = MetadataStore::new(&root).unwrap();

    assert_eq!(store.state(Path::new("/")).unwrap(), None);
    store.remove(Path::new("/")).unwrap();

    let path = store.path(Path::new("/unreadable")).unwrap();
    std::fs::create_dir_all(&path).unwrap();
    assert!(
        store
            .entries(Path::new("/unreadable"))
            .unwrap_err()
            .to_string()
            .contains("failed to read")
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn metadata_rejects_invalid_encoded_names() {
    let root = tempfile();
    let store = MetadataStore::new(&root).unwrap();
    let path = store.path(Path::new("/tmp")).unwrap();
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(
        &path,
        serde_json::to_vec(&DirectoryMetadata {
            version: METADATA_VERSION,
            entries: BTreeMap::from([("*".to_string(), EntryState::Cow)]),
        })
        .unwrap(),
    )
    .unwrap();

    assert!(
        store
            .entries(Path::new("/tmp"))
            .unwrap_err()
            .to_string()
            .contains("invalid encoded")
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn metadata_creation_reports_a_blocked_control_directory() {
    let root = tempfile();
    std::fs::write(root.join(super::CONTROL_DIRECTORY), b"blocked").unwrap();

    assert!(
        MetadataStore::new(&root)
            .err()
            .unwrap()
            .to_string()
            .contains("failed to create")
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn metadata_publication_failure_removes_the_temporary_file() {
    let root = tempfile();
    let store = MetadataStore::new(&root).unwrap();
    let directory = Path::new("/blocked-publication");
    let path = store.path(directory).unwrap();
    std::fs::create_dir_all(&path).unwrap();

    assert!(
        store
            .write(directory, &DirectoryMetadata::default())
            .is_err()
    );
    assert_eq!(
        std::fs::read_dir(path.parent().unwrap())
            .unwrap()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().contains(".tmp"))
            .count(),
        0
    );

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn metadata_write_failure_removes_the_temporary_file() {
    use std::os::unix::fs::PermissionsExt;

    let root = tempfile();
    let store = MetadataStore::new(&root).unwrap();
    let directory = Path::new("/blocked-write");
    let path = store.path(directory).unwrap();
    let parent = path.parent().unwrap();
    std::fs::create_dir_all(parent).unwrap();
    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o500)).unwrap();

    assert!(
        store
            .set(&directory.join("entry"), EntryState::Cow)
            .unwrap_err()
            .to_string()
            .contains("failed to write filesystem metadata")
    );

    std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert_eq!(
        std::fs::read_dir(parent)
            .unwrap()
            .filter_map(Result::ok)
            .count(),
        0
    );
    std::fs::remove_dir_all(root).unwrap();
}

fn tempfile() -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("agora-metadata-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&path).unwrap();
    path
}
