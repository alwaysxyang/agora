use super::OverlayStore;
use crate::filesystem::{EntryState, Materializer};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

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
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

#[test]
fn read_materializes_and_refreshes_host_files() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("file");
    std::fs::write(&source, b"first").unwrap();

    let mapped = fixture.store.prepare_read(&source).unwrap();
    assert_eq!(std::fs::read(&mapped).unwrap(), b"first");
    assert!(matches!(
        fixture.store.metadata.state(&source).unwrap(),
        Some(EntryState::Cached {
            materializer: Materializer::Copy,
            ..
        })
    ));
    assert_eq!(fixture.store.prepare_read(&source).unwrap(), mapped);

    std::fs::write(&source, b"second").unwrap();
    assert_eq!(fixture.store.prepare_read(&source).unwrap(), mapped);
    assert_eq!(std::fs::read(mapped).unwrap(), b"second");
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
    let upper_names = std::fs::read_dir(view.upper())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
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
fn rename_and_mkdir_never_change_lower_paths() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("source");
    let target = fixture.lower.join("target");
    std::fs::write(&source, b"host").unwrap();

    fixture.store.rename(&source, &target).unwrap();
    assert!(fixture.store.prepare_read(&source).is_err());
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
fn paths_are_normalized_and_control_namespace_is_reserved() {
    let fixture = Fixture::new();
    assert!(fixture.store.prepare_read(Path::new("relative")).is_err());
    assert!(
        fixture
            .store
            .prepare_read(Path::new("/.agora/volume.json"))
            .is_err()
    );
    assert_eq!(
        fixture.store.normalize(Path::new("/tmp/a/../b")).unwrap(),
        Path::new("/tmp/b")
    );
    let internal = fixture.store.root().join(".agora/volume.json");
    assert_eq!(fixture.store.prepare_read(&internal).unwrap(), internal);
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
    assert_eq!(std::fs::read(mapped.join("root-file")).unwrap(), b"root");
    assert_eq!(
        std::fs::read(mapped.join("nested/nested-file")).unwrap(),
        b"nested"
    );
    assert!(!mapped.join("removed").exists());
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
    let mapped = fixture.store.prepare_read(&cached).unwrap();
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

    let internal = fixture.store.root().join(".agora/overlay.lock");
    assert_eq!(
        fixture.store.prepare_write(&internal, true).unwrap(),
        internal
    );
    assert_eq!(
        fixture.store.prepare_directory(&internal).unwrap(),
        internal
    );
    assert!(
        fixture
            .store
            .directory_view(Path::new("/"))
            .unwrap()
            .hidden()
            .contains(std::ffi::OsStr::new(".agora"))
    );
}

#[test]
fn executable_metadata_and_failed_publication_are_consistent() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("tool");
    std::fs::write(&source, b"tool").unwrap();
    fixture.store.prepare_read(&source).unwrap();

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
fn visible_symlinks_follow_overlay_state_of_their_canonical_target() {
    let fixture = Fixture::new();
    let target = fixture.lower.join("target");
    let link = fixture.lower.join("link");
    std::fs::write(&target, b"host").unwrap();
    symlink(&target, &link).unwrap();
    let target = target.canonicalize().unwrap();

    let cached = fixture.store.prepare_read(&target).unwrap();
    assert_eq!(fixture.store.visible_path(&link).unwrap(), cached);
    std::fs::remove_file(&cached).unwrap();
    assert_eq!(
        fixture.store.visible_path(&link).unwrap(),
        target.canonicalize().unwrap()
    );

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
