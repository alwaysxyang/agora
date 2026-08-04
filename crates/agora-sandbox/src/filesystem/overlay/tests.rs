use super::OverlayStore;
use crate::filesystem::{EntryState, FileAttributes, FileCipher, Materializer};
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::sync::{Arc, mpsc};
use std::time::Duration;

struct Fixture {
    directory: PathBuf,
    lower: PathBuf,
    store: OverlayStore,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("agora-overlay-{}", uuid::Uuid::new_v4()));
        let lower = directory.join("lower");
        let root = directory.join("fs");
        std::fs::create_dir_all(&lower).unwrap();
        let store = OverlayStore::new(root).unwrap();
        Self {
            directory,
            lower,
            store,
        }
    }

    fn encrypted() -> (Self, FileCipher) {
        let directory =
            std::env::temp_dir().join(format!("agora-overlay-{}", uuid::Uuid::new_v4()));
        let lower = directory.join("lower");
        let root = directory.join("fs");
        std::fs::create_dir_all(&lower).unwrap();
        let cipher = FileCipher::derive(b"key", b"0123456789abcdef").unwrap();
        let store = OverlayStore::encrypted(root, cipher.clone()).unwrap();
        (
            Self {
                directory,
                lower,
                store,
            },
            cipher,
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn errno(error: &anyhow::Error) -> Option<i32> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .and_then(std::io::Error::raw_os_error)
}

#[test]
fn overlay_lock_serializes_threads() {
    let directory =
        std::env::temp_dir().join(format!("agora-overlay-lock-{}", uuid::Uuid::new_v4()));
    let store = Arc::new(OverlayStore::new(directory.join("fs")).unwrap());
    let (first_entered_tx, first_entered_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let first_store = Arc::clone(&store);
    let first = std::thread::spawn(move || {
        first_store
            .with_lock(|| {
                first_entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                Ok(())
            })
            .unwrap();
    });
    first_entered_rx.recv().unwrap();

    let (second_entered_tx, second_entered_rx) = mpsc::channel();
    let second_store = Arc::clone(&store);
    let second = std::thread::spawn(move || {
        second_store
            .with_lock(|| {
                second_entered_tx.send(()).unwrap();
                Ok(())
            })
            .unwrap();
    });
    let entered_while_locked = second_entered_rx
        .recv_timeout(Duration::from_millis(100))
        .is_ok();
    release_tx.send(()).unwrap();
    first.join().unwrap();
    second.join().unwrap();
    assert!(!entered_while_locked);

    drop(store);
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn sequential_overlay_transactions_reuse_the_lock_descriptor() {
    let fixture = Fixture::new();
    let initial_opens = fixture.store.lock_open_count();

    assert_eq!(fixture.store.state(&fixture.lower).unwrap(), None);
    assert_eq!(fixture.store.state(&fixture.lower).unwrap(), None);

    assert_eq!(fixture.store.lock_open_count(), initial_opens);
}

#[test]
fn read_uses_lower_without_materializing_host_files() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("file");
    std::fs::write(&source, b"first").unwrap();

    let mapped = fixture.store.prepare_read(&source).unwrap();
    assert_eq!(mapped, source);
    assert_eq!(std::fs::read(&mapped).unwrap(), b"first");
    assert_eq!(fixture.store.metadata.state(&source).unwrap(), None);
    assert_eq!(fixture.store.prepare_read(&source).unwrap(), mapped);

    std::fs::write(&source, b"second").unwrap();
    assert_eq!(fixture.store.prepare_read(&source).unwrap(), mapped);
    assert_eq!(std::fs::read(mapped).unwrap(), b"second");
}

#[test]
fn encrypted_root_reads_use_the_backing_root_without_leaf_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("fs");
    let cipher = FileCipher::derive(b"key", b"0123456789abcdef").unwrap();
    let store = OverlayStore::encrypted(&root, cipher).unwrap();

    assert_eq!(store.prepare_read(Path::new("/")).unwrap(), Path::new("/"));
}

#[test]
fn encrypted_metadata_key_matches_the_encrypted_physical_name_without_plaintext() {
    let (fixture, cipher) = Fixture::encrypted();
    let logical = Path::new("/tmp/secret.txt");
    let destination = fixture.store.prepare_write(logical, true).unwrap();
    std::fs::write(&destination, b"encrypted-placeholder").unwrap();
    let root = fixture.store.root();

    let contents = std::fs::read(root.join("tmp/.metadata")).unwrap();
    assert!(
        !contents
            .windows(b"secret.txt".len())
            .any(|part| part == b"secret.txt")
    );
    let metadata: serde_json::Value = serde_json::from_slice(&contents).unwrap();
    assert_eq!(metadata["version"], 3);
    assert!(metadata.get("backing_names").is_none());
    let alias = metadata["entries"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap();

    assert!(alias.starts_with("enc_"));
    assert_eq!(cipher.decrypt_name(alias).unwrap(), b"secret.txt");
    assert_eq!(destination, root.join("tmp").join(alias));
    assert!(destination.is_file());
    assert!(!root.join("tmp/secret.txt").exists());
    assert!(metadata["entries"][alias].get("name").is_none());
}

#[test]
fn opening_an_overlay_recursively_migrates_version_one_metadata() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("fs");
    let nested = root.join("usr/bin");
    std::fs::create_dir_all(&nested).unwrap();
    let attributes = FileAttributes::created_file(0o755);
    std::fs::write(
        root.join(".metadata"),
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "entries": {"Y2F0": {"state": "whiteout"}},
            "attributes": {},
            "backing_names": {}
        }))
        .unwrap(),
    )
    .unwrap();
    std::fs::write(
        nested.join(".metadata"),
        serde_json::to_vec(&serde_json::json!({
            "version": 1,
            "entries": {"YmFzaA": {"state": "cow"}},
            "attributes": {"YmFzaA": serde_json::to_value(&attributes).unwrap()},
            "backing_names": {}
        }))
        .unwrap(),
    )
    .unwrap();

    let store = OverlayStore::new(&root).unwrap();

    assert_eq!(
        store.state(Path::new("/cat")).unwrap(),
        Some(EntryState::Whiteout)
    );
    assert_eq!(
        store.state(Path::new("/usr/bin/bash")).unwrap(),
        Some(EntryState::Cow)
    );
    assert_eq!(
        store.attributes(Path::new("/usr/bin/bash")).unwrap(),
        Some(attributes)
    );
    let root_metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(root.join(".metadata")).unwrap()).unwrap();
    let nested_metadata: serde_json::Value =
        serde_json::from_slice(&std::fs::read(nested.join(".metadata")).unwrap()).unwrap();
    assert_eq!(root_metadata["version"], 3);
    assert!(root_metadata["entries"].get("cat").is_some());
    assert_eq!(nested_metadata["version"], 3);
    assert!(nested_metadata["entries"].get("bash").is_some());
    assert!(
        nested_metadata["entries"]["bash"]
            .get("attributes")
            .is_some()
    );
}

#[test]
fn encrypted_overlay_migrates_version_two_aliases_to_encrypted_filenames() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("fs");
    let backing = root.join("tmp");
    std::fs::create_dir_all(&backing).unwrap();
    let old_name = "c1ed24271f7440a19b1b85076d21d0ae";
    std::fs::write(backing.join(old_name), b"ciphertext").unwrap();
    std::fs::write(
        backing.join(".metadata"),
        serde_json::to_vec(&serde_json::json!({
            "version": 2,
            "entries": {"安全方案.docx": {"state": "cow"}},
            "attributes": {},
            "backing_names": {"安全方案.docx": old_name}
        }))
        .unwrap(),
    )
    .unwrap();
    let cipher = FileCipher::derive(b"key", b"0123456789abcdef").unwrap();

    let store = OverlayStore::encrypted(&root, cipher.clone()).unwrap();

    assert_eq!(
        store.state(Path::new("/tmp/安全方案.docx")).unwrap(),
        Some(EntryState::Cow)
    );
    let contents = std::fs::read(backing.join(".metadata")).unwrap();
    assert!(
        !contents
            .windows("安全方案.docx".len())
            .any(|part| { part == "安全方案.docx".as_bytes() })
    );
    let metadata: serde_json::Value = serde_json::from_slice(&contents).unwrap();
    assert_eq!(metadata["version"], 3);
    assert!(metadata.get("backing_names").is_none());
    let encrypted_name = metadata["entries"]
        .as_object()
        .unwrap()
        .keys()
        .next()
        .unwrap();
    assert_eq!(
        cipher.decrypt_name(encrypted_name).unwrap(),
        "安全方案.docx".as_bytes()
    );
    assert!(backing.join(encrypted_name).is_file());
    assert!(!backing.join(old_name).exists());
    assert_eq!(
        store.prepare_read(Path::new("/tmp/安全方案.docx")).unwrap(),
        backing.join(encrypted_name)
    );
}

#[test]
fn write_intent_copies_up_and_preserves_cow_after_host_changes() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("file");
    std::fs::write(&source, b"host").unwrap();

    let mapped = fixture.store.prepare_write(&source, false).unwrap();
    std::fs::write(&mapped, b"sandbox").unwrap();
    std::fs::write(&source, b"changed host").unwrap();

    assert_eq!(fixture.store.prepare_read(&source).unwrap(), mapped);
    assert_eq!(std::fs::read(mapped).unwrap(), b"sandbox");
    assert_eq!(std::fs::read(source).unwrap(), b"changed host");
}

#[test]
fn visible_path_prefers_cow_content_and_rejects_whiteouts() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("file");
    std::fs::write(&source, b"host").unwrap();

    assert_eq!(
        fixture.store.visible_path(&source).unwrap(),
        source.canonicalize().unwrap()
    );

    let mapped = fixture.store.prepare_write(&source, false).unwrap();
    std::fs::write(&mapped, b"sandbox").unwrap();
    assert_eq!(fixture.store.visible_path(&source).unwrap(), mapped);
    assert_eq!(fixture.store.visible_path(&mapped).unwrap(), mapped);

    fixture.store.remove(&source, false).unwrap();
    assert!(fixture.store.visible_path(&source).is_err());
}

#[test]
fn create_delete_and_recreate_use_cow_and_whiteouts() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("created");

    let mapped = fixture.store.prepare_write(&source, true).unwrap();
    std::fs::write(&mapped, b"created").unwrap();
    assert_eq!(
        fixture.store.metadata.state(&source).unwrap(),
        Some(EntryState::Cow)
    );

    fixture.store.remove(&source, false).unwrap();
    assert_eq!(
        fixture.store.metadata.state(&source).unwrap(),
        Some(EntryState::Whiteout)
    );
    assert!(fixture.store.prepare_read(&source).is_err());

    let recreated = fixture.store.prepare_write(&source, true).unwrap();
    std::fs::write(&recreated, b"recreated").unwrap();
    assert_eq!(fixture.store.prepare_read(&source).unwrap(), recreated);
}

#[test]
fn directory_view_keeps_lower_entries_lazy_and_tracks_whiteouts() {
    let fixture = Fixture::new();
    let lower_file = fixture.lower.join("lower");
    let removed_file = fixture.lower.join("removed");
    let cow_file = fixture.lower.join("cow");
    std::fs::write(&lower_file, b"lower").unwrap();
    std::fs::write(&removed_file, b"removed").unwrap();
    std::fs::write(&cow_file, b"host cow").unwrap();
    fixture.store.remove(&removed_file, false).unwrap();
    let cow = fixture.store.prepare_write(&cow_file, false).unwrap();
    std::fs::write(cow, b"sandbox cow").unwrap();

    let view = fixture.store.directory_view(&fixture.lower).unwrap();
    let upper_names = std::fs::read_dir(view.primary())
        .unwrap()
        .map(|entry| {
            let name = entry.unwrap().file_name();
            view.aliases().get(&name).cloned().unwrap_or(name)
        })
        .filter(|name| !view.hidden().contains(name))
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(upper_names.len(), 1);
    assert!(upper_names.contains(std::ffi::OsStr::new("cow")));
    assert_eq!(view.lower(), Some(fixture.lower.as_path()));
    assert!(view.hidden().contains(std::ffi::OsStr::new("removed")));

    let lower_names = std::fs::read_dir(view.lower().unwrap())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<std::collections::BTreeSet<_>>();
    assert!(lower_names.contains(std::ffi::OsStr::new("lower")));
    assert!(lower_names.contains(std::ffi::OsStr::new("cow")));
    assert!(lower_names.contains(std::ffi::OsStr::new("removed")));
}

#[test]
fn reading_a_lower_directory_does_not_materialize_an_upper_directory() {
    let fixture = Fixture::new();
    let directory = fixture.lower.join("read-only");
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o555)).unwrap();

    let visible = fixture.store.prepare_directory(&directory).unwrap();

    assert_eq!(visible, directory);
    assert!(
        !fixture
            .store
            .plain_destination(&directory)
            .unwrap()
            .exists()
    );
}

#[test]
fn removing_a_lower_directory_requires_the_merged_view_to_be_empty() {
    let fixture = Fixture::new();
    let directory = fixture.lower.join("directory");
    let child = directory.join("child");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&child, b"host").unwrap();

    let error = fixture.store.remove(&directory, true).unwrap_err();
    assert_eq!(
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error),
        Some(libc::ENOTEMPTY)
    );

    fixture.store.remove(&child, false).unwrap();
    fixture.store.remove(&directory, true).unwrap();
    assert!(fixture.store.prepare_read(&directory).is_err());
    assert!(directory.exists());
}

#[test]
fn removing_an_encrypted_upper_directory_rejects_aliased_children() {
    let (fixture, _) = Fixture::encrypted();
    let directory = fixture.lower.join("directory");
    let child = directory.join("child");
    fixture.store.create_directory(&directory, 0o700).unwrap();
    let staged = fixture.store.stage_write(&child, true).unwrap();
    std::fs::write(staged.destination(), b"child").unwrap();
    fixture.store.commit_write(staged).unwrap();

    let error = fixture.store.remove(&directory, true).unwrap_err();

    assert_eq!(errno(&error), Some(libc::ENOTEMPTY));
    assert!(fixture.store.prepare_read(&child).unwrap().is_file());
}

#[test]
fn rename_and_mkdir_never_change_lower_paths() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("source");
    let target = fixture.lower.join("target");
    std::fs::write(&source, b"host").unwrap();

    fixture.store.rename(&source, &target).unwrap();
    assert!(fixture.store.prepare_read(&source).is_err());
    assert_eq!(
        fixture.store.state(&source).unwrap(),
        Some(EntryState::Whiteout)
    );
    assert_eq!(fixture.store.state(&target).unwrap(), Some(EntryState::Cow));
    assert_eq!(
        std::fs::read(fixture.store.prepare_read(&target).unwrap()).unwrap(),
        b"host"
    );
    assert_eq!(std::fs::read(&source).unwrap(), b"host");
    assert!(!target.exists());

    let directory = fixture.lower.join("created-dir");
    let mapped = fixture.store.create_directory(&directory, 0o750).unwrap();
    assert!(mapped.is_dir());
    assert_eq!(
        mapped.metadata().unwrap().permissions().mode() & 0o777,
        0o750
    );
    assert!(!directory.exists());
}

#[test]
fn rename_preserves_sources_and_destinations_when_posix_checks_fail() {
    let fixture = Fixture::new();
    let file = fixture.lower.join("file");
    let directory = fixture.lower.join("directory");
    let child = directory.join("child");
    let other_directory = fixture.lower.join("other-directory");
    std::fs::write(&file, b"file").unwrap();
    std::fs::create_dir_all(&directory).unwrap();
    std::fs::write(&child, b"child").unwrap();
    std::fs::create_dir_all(&other_directory).unwrap();

    fixture.store.rename(&file, &file).unwrap();
    assert_eq!(std::fs::read(&file).unwrap(), b"file");
    assert_eq!(fixture.store.state(&file).unwrap(), None);

    let error = fixture.store.rename(&file, &directory).unwrap_err();
    assert_eq!(errno(&error), Some(libc::EISDIR));
    assert_eq!(std::fs::read(&file).unwrap(), b"file");
    assert_eq!(std::fs::read(&child).unwrap(), b"child");
    assert_eq!(fixture.store.state(&file).unwrap(), None);
    assert!(!fixture.store.destination(&file).unwrap().exists());

    let error = fixture.store.rename(&directory, &file).unwrap_err();
    assert_eq!(errno(&error), Some(libc::ENOTDIR));
    assert_eq!(std::fs::read(&file).unwrap(), b"file");
    assert_eq!(std::fs::read(&child).unwrap(), b"child");
    assert_eq!(fixture.store.state(&directory).unwrap(), None);
    assert!(!fixture.store.destination(&directory).unwrap().exists());

    let error = fixture
        .store
        .rename(&other_directory, &directory)
        .unwrap_err();
    assert_eq!(errno(&error), Some(libc::ENOTEMPTY));
    assert_eq!(std::fs::read(&child).unwrap(), b"child");
    assert_eq!(fixture.store.state(&other_directory).unwrap(), None);
    assert!(
        !fixture
            .store
            .destination(&other_directory)
            .unwrap()
            .exists()
    );

    let error = fixture
        .store
        .rename(&directory, &directory.join("nested"))
        .unwrap_err();
    assert_eq!(errno(&error), Some(libc::EINVAL));
    assert_eq!(std::fs::read(&child).unwrap(), b"child");
    assert_eq!(fixture.store.state(&directory).unwrap(), None);
    assert!(!fixture.store.destination(&directory).unwrap().exists());
}

#[test]
fn cached_copy_up_refreshes_from_lower_before_a_later_write() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("source");
    std::fs::write(&source, b"first").unwrap();
    let staged = fixture.store.stage_write(&source, false).unwrap();
    assert!(matches!(
        fixture.store.state(&source).unwrap(),
        Some(EntryState::Cached { .. })
    ));
    drop(staged);

    std::fs::write(&source, b"second").unwrap();
    let staged = fixture.store.stage_write(&source, false).unwrap();
    assert_eq!(std::fs::read(staged.destination()).unwrap(), b"second");
    assert_eq!(
        fixture.store.visible_path(&source).unwrap(),
        source.canonicalize().unwrap()
    );
}

#[test]
fn directory_rename_preserves_lower_symlinks() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("source");
    let target = fixture.lower.join("target");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(source.join("file"), b"contents").unwrap();
    symlink("file", source.join("link")).unwrap();

    fixture.store.rename(&source, &target).unwrap();

    let mapped = fixture.store.prepare_directory(&target).unwrap();
    let link = fixture.store.prepare_read(&target.join("link")).unwrap();
    assert_eq!(std::fs::read_link(&link).unwrap(), Path::new("file"));
    assert_eq!(std::fs::read(link).unwrap(), b"contents");
    assert!(mapped.is_dir());
}

#[test]
fn paths_are_normalized_and_logical_control_names_are_isolated() {
    let fixture = Fixture::new();
    assert!(fixture.store.prepare_read(Path::new("relative")).is_err());
    assert_eq!(
        fixture.store.normalize(Path::new("/tmp/a/../b")).unwrap(),
        Path::new("/tmp/b")
    );
    let logical = Path::new("/.metadata");
    let mapped = fixture.store.prepare_write(logical, true).unwrap();
    assert_ne!(mapped, fixture.store.root().join(".metadata"));
    assert_eq!(fixture.store.logical_path(&mapped).unwrap(), logical);
}

#[test]
fn internal_paths_bypass_overlay_state_and_control_aliases_round_trip() {
    let fixture = Fixture::new();
    let internal_file = fixture.store.root().join("internal");
    std::fs::write(&internal_file, b"internal").unwrap();
    assert_eq!(
        fixture.store.prepare_read(&internal_file).unwrap(),
        internal_file
    );
    let staged = fixture.store.stage_write(&internal_file, false).unwrap();
    assert_eq!(staged.destination(), internal_file);
    fixture.store.commit_write(staged).unwrap();
    assert_eq!(
        fixture
            .store
            .prepare_directory(fixture.store.root())
            .unwrap(),
        fixture.store.root()
    );

    let logical_control = Path::new("/.metadata");
    let encoded = fixture.store.prepare_write(logical_control, true).unwrap();
    std::fs::write(&encoded, b"logical metadata").unwrap();
    let view = fixture.store.directory_view(Path::new("/")).unwrap();
    assert_eq!(
        view.aliases().get(encoded.file_name().unwrap()),
        Some(&std::ffi::OsString::from(".metadata"))
    );
}

#[test]
fn checksum_matches_standard_md5_and_executable_publication_is_reused() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("tool");
    std::fs::write(&source, b"").unwrap();
    assert_eq!(
        OverlayStore::checksum(&source).unwrap(),
        "d41d8cd98f00b204e9800998ecf8427e"
    );

    let mut preparations = 0;
    let destination = fixture
        .store
        .prepare_executable(&source, |temporary| {
            preparations += 1;
            std::fs::write(temporary, b"prepared")?;
            std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(0o755))?;
            Ok(())
        })
        .unwrap();
    fixture
        .store
        .prepare_executable(&source, |_| {
            preparations += 1;
            Ok(())
        })
        .unwrap();
    assert_eq!(preparations, 1);
    assert_eq!(std::fs::read(destination).unwrap(), b"prepared");
}

#[test]
fn directory_rename_materializes_the_visible_tree_without_changing_the_lower_tree() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("source-directory");
    let nested = source.join("nested");
    let target = fixture.lower.join("target-directory");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(source.join("root-file"), b"root").unwrap();
    std::fs::write(nested.join("nested-file"), b"nested").unwrap();
    std::fs::write(source.join("removed"), b"removed").unwrap();
    fixture
        .store
        .remove(&source.join("removed"), false)
        .unwrap();

    fixture.store.rename(&source, &target).unwrap();

    assert!(fixture.store.prepare_read(&source).is_err());
    let mapped = fixture.store.prepare_read(&target).unwrap();
    assert_eq!(
        std::fs::read(
            fixture
                .store
                .prepare_read(&target.join("root-file"))
                .unwrap()
        )
        .unwrap(),
        b"root"
    );
    assert_eq!(
        std::fs::read(
            fixture
                .store
                .prepare_read(&target.join("nested/nested-file"))
                .unwrap()
        )
        .unwrap(),
        b"nested"
    );
    assert!(fixture.store.prepare_read(&target.join("removed")).is_err());
    assert!(mapped.is_dir());
    assert_eq!(std::fs::read(source.join("root-file")).unwrap(), b"root");
    assert_eq!(
        std::fs::read(nested.join("nested-file")).unwrap(),
        b"nested"
    );
    assert!(!target.exists());
}

#[test]
fn encrypted_directory_rename_preserves_nested_files() {
    let (fixture, cipher) = Fixture::encrypted();
    let source = fixture.lower.join("source-directory");
    let nested = source.join("nested");
    let target = fixture.lower.join("target-directory");
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(source.join("root-file"), b"root").unwrap();
    std::fs::write(nested.join("nested-file"), b"nested").unwrap();

    fixture.store.rename(&source, &target).unwrap();

    let mut root_plaintext = tempfile::tempfile().unwrap();
    cipher
        .decrypt(
            &fixture
                .store
                .prepare_read(&target.join("root-file"))
                .unwrap(),
            &mut root_plaintext,
        )
        .unwrap();
    let mut nested_plaintext = tempfile::tempfile().unwrap();
    cipher
        .decrypt(
            &fixture
                .store
                .prepare_read(&target.join("nested/nested-file"))
                .unwrap(),
            &mut nested_plaintext,
        )
        .unwrap();

    let mut root_contents = String::new();
    root_plaintext.read_to_string(&mut root_contents).unwrap();
    let mut nested_contents = String::new();
    nested_plaintext
        .read_to_string(&mut nested_contents)
        .unwrap();

    assert_eq!(root_contents, "root");
    assert_eq!(nested_contents, "nested");
    assert_eq!(std::fs::read(source.join("root-file")).unwrap(), b"root");
    assert_eq!(
        std::fs::read(nested.join("nested-file")).unwrap(),
        b"nested"
    );
    assert!(!target.exists());
}

#[test]
fn overlay_handles_missing_cached_entries_cow_ancestors_and_type_errors() {
    let fixture = Fixture::new();
    let cached = fixture.lower.join("cached");
    std::fs::write(&cached, b"host").unwrap();
    let mapped = fixture
        .store
        .prepare_executable(&cached, |temporary| {
            std::fs::write(temporary, b"prepared")?;
            std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(0o755))?;
            Ok(())
        })
        .unwrap();
    std::fs::remove_file(&mapped).unwrap();
    assert_eq!(
        fixture.store.visible_path(&cached).unwrap(),
        cached.canonicalize().unwrap()
    );
    std::fs::remove_file(&cached).unwrap();
    assert!(fixture.store.prepare_read(&cached).is_err());
    assert_eq!(fixture.store.state(&cached).unwrap(), None);

    let cow_directory = fixture.lower.join("cow-directory");
    let mapped_directory = fixture
        .store
        .create_directory(&cow_directory, 0o700)
        .unwrap();
    assert!(
        fixture
            .store
            .create_directory(&cow_directory, 0o700)
            .is_err()
    );
    let child = cow_directory.join("child");
    assert!(fixture.store.prepare_write(&child, false).is_err());
    let mapped_child = fixture.store.prepare_write(&child, true).unwrap();
    std::fs::write(&mapped_child, b"child").unwrap();
    assert_eq!(fixture.store.prepare_read(&child).unwrap(), mapped_child);
    assert_eq!(
        fixture.store.prepare_directory(&cow_directory).unwrap(),
        mapped_directory
    );
    assert!(
        fixture
            .store
            .directory_view(&cow_directory)
            .unwrap()
            .lower()
            .is_none()
    );

    let host_file = fixture.lower.join("host-file");
    let host_directory = fixture.lower.join("host-directory");
    std::fs::write(&host_file, b"file").unwrap();
    std::fs::create_dir(&host_directory).unwrap();
    assert!(fixture.store.remove(&host_file, true).is_err());
    assert!(fixture.store.remove(&host_directory, false).is_err());
    assert!(
        fixture
            .store
            .remove(&fixture.lower.join("missing"), false)
            .is_err()
    );
    assert!(fixture.store.prepare_directory(&host_file).is_err());

    let internal = fixture.store.root().join(".vfs.lock");
    assert_eq!(
        fixture.store.logical_path(&internal).unwrap(),
        Path::new("/.vfs.lock")
    );
    assert!(
        fixture
            .store
            .directory_view(Path::new("/"))
            .unwrap()
            .hidden()
            .contains(std::ffi::OsStr::new(".vfs.lock"))
    );
}

#[test]
fn executable_metadata_and_failed_publication_are_consistent() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("tool");
    std::fs::write(&source, b"tool").unwrap();
    fixture
        .store
        .prepare_executable(&source, |temporary| {
            std::fs::write(temporary, b"prepared")?;
            std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(0o755))?;
            Ok(())
        })
        .unwrap();

    fixture.store.mark_executable(&source).unwrap();
    assert!(matches!(
        fixture.store.state(&source).unwrap(),
        Some(EntryState::Cached {
            materializer: Materializer::Executable,
            ..
        })
    ));
    fixture
        .store
        .mark_executable(&fixture.lower.join("missing"))
        .unwrap();

    std::fs::write(&source, b"changed tool").unwrap();
    let failed = fixture.store.prepare_executable(&source, |temporary| {
        std::fs::write(temporary, b"partial")?;
        anyhow::bail!("preparation failed")
    });
    assert!(
        failed
            .unwrap_err()
            .to_string()
            .contains("preparation failed")
    );
    let parent = fixture
        .store
        .destination(&source)
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    assert!(std::fs::read_dir(parent).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".agora-executable-")
    }));
}

#[test]
fn unchanged_executable_identity_reuses_cache_without_rehashing_contents() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("large-tool");
    std::fs::write(&source, b"source executable").unwrap();
    let destination = fixture
        .store
        .prepare_executable(&source, |temporary| {
            std::fs::write(temporary, b"prepared executable")?;
            std::fs::set_permissions(temporary, std::fs::Permissions::from_mode(0o755))?;
            Ok(())
        })
        .unwrap();
    let Some(EntryState::Cached {
        materializer,
        source: Some(source_identity),
        ..
    }) = fixture.store.state(&source).unwrap()
    else {
        panic!("missing executable source identity");
    };
    fixture
        .store
        .set_state_for_test(
            &source,
            EntryState::Cached {
                checksum: "intentionally-invalid".to_string(),
                materializer,
                source: Some(source_identity),
            },
        )
        .unwrap();

    let reused = fixture.store.prepare_executable(&source, |_| {
        anyhow::bail!("unchanged source must not be prepared again")
    });

    assert_eq!(reused.unwrap(), destination);
}

#[test]
fn visible_symlinks_follow_overlay_state_of_their_canonical_target() {
    let fixture = Fixture::new();
    let target = fixture.lower.join("target");
    let link = fixture.lower.join("link");
    std::fs::write(&target, b"host").unwrap();
    symlink(&target, &link).unwrap();
    let target = target.canonicalize().unwrap();

    assert_eq!(fixture.store.prepare_read(&target).unwrap(), target);
    assert_eq!(fixture.store.prepare_read(&link).unwrap(), link);
    assert_eq!(fixture.store.visible_path(&link).unwrap(), target);

    let cow = fixture.store.prepare_write(&target, false).unwrap();
    std::fs::write(&cow, b"sandbox").unwrap();
    assert_eq!(fixture.store.visible_path(&link).unwrap(), cow);

    fixture.store.remove(&target, false).unwrap();
    assert!(fixture.store.visible_path(&link).is_err());
}

#[test]
fn special_files_root_children_and_upper_directories_remain_overlay_local() {
    let fixture = Fixture::new();
    let fifo = fixture.lower.join("fifo");
    let fifo_path = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
    assert_eq!(unsafe { libc::mkfifo(fifo_path.as_ptr(), 0o600) }, 0);
    assert_eq!(fixture.store.prepare_read(&fifo).unwrap(), fifo);

    let host_directory = fixture.lower.join("host-directory");
    std::fs::create_dir(&host_directory).unwrap();
    assert_eq!(
        fixture.store.prepare_write(&host_directory, false).unwrap(),
        host_directory
    );

    let root_child = Path::new("/").join(format!("agora-overlay-{}", uuid::Uuid::new_v4()));
    let mapped_root_child = fixture.store.prepare_write(&root_child, true).unwrap();
    assert_eq!(
        mapped_root_child,
        fixture
            .store
            .root()
            .join(root_child.strip_prefix("/").unwrap())
    );
    assert!(!root_child.exists());

    let directory = fixture.lower.join("upper-directory");
    fixture.store.create_directory(&directory, 0o700).unwrap();
    let child = fixture
        .store
        .prepare_write(&directory.join("child"), true)
        .unwrap();
    std::fs::write(child, b"child").unwrap();
    let error = fixture.store.remove(&directory, true).unwrap_err();
    assert_eq!(
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error),
        Some(libc::ENOTEMPTY)
    );
    assert!(!directory.exists());
}

#[test]
fn missing_cow_whiteout_and_directory_paths_remain_unavailable() {
    let fixture = Fixture::new();

    let cow_file = fixture.lower.join("cow-file");
    std::fs::write(&cow_file, b"host").unwrap();
    let mapped_cow_file = fixture.store.prepare_write(&cow_file, false).unwrap();
    std::fs::remove_file(mapped_cow_file).unwrap();
    assert!(fixture.store.prepare_write(&cow_file, false).is_err());

    let removed_file = fixture.lower.join("removed-file");
    std::fs::write(&removed_file, b"host").unwrap();
    fixture.store.remove(&removed_file, false).unwrap();
    assert!(fixture.store.prepare_write(&removed_file, false).is_err());
    assert!(fixture.store.remove(&removed_file, false).is_err());

    let missing = fixture.lower.join("missing");
    assert!(fixture.store.prepare_read(&missing).is_err());
    assert!(fixture.store.prepare_write(&missing, false).is_err());

    let removed_directory = fixture.lower.join("removed-directory");
    std::fs::create_dir(&removed_directory).unwrap();
    fixture.store.remove(&removed_directory, true).unwrap();
    assert!(fixture.store.prepare_directory(&removed_directory).is_err());

    let cow_directory = fixture.lower.join("cow-directory");
    fixture
        .store
        .create_directory(&cow_directory, 0o700)
        .unwrap();
    assert!(
        fixture
            .store
            .visible_path(&cow_directory.join("missing-child"))
            .is_err()
    );
}
