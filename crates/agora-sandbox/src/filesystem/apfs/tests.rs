use super::{EncryptedWorkspace, MAX_KEY_SIZE, METADATA_VERSION, VolumeMetadata};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn temporary_directory(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("agora-filesystem-{label}-{}", uuid::Uuid::new_v4()))
}

fn workspace(root: &Path) -> EncryptedWorkspace {
    let mount_point = root.join("fs");
    std::fs::create_dir_all(&mount_point).unwrap();
    EncryptedWorkspace {
        mount_point,
        _lock: std::fs::File::create(root.join("lock")).unwrap(),
        mounted: false,
    }
}

#[test]
fn passphrase_validation_preserves_direct_input() {
    EncryptedWorkspace::validate_passphrase(b"secret\r\n").unwrap();
    EncryptedWorkspace::validate_passphrase(b"secret\n\n").unwrap();
}

#[test]
fn passphrase_validation_rejects_invalid_keys() {
    assert!(
        EncryptedWorkspace::validate_passphrase(b"")
            .unwrap_err()
            .to_string()
            .contains("is empty")
    );
    assert!(
        EncryptedWorkspace::validate_passphrase(b"contains\0nul")
            .unwrap_err()
            .to_string()
            .contains("NUL byte")
    );
    assert!(
        EncryptedWorkspace::validate_passphrase(&vec![b'x'; MAX_KEY_SIZE + 1])
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );
}

#[test]
fn filesystem_paths_mirror_absolute_host_paths() {
    let workdir = Path::new("/tmp/agora-workdir");
    assert_eq!(EncryptedWorkspace::mount_point(workdir), workdir.join("fs"));
    assert_eq!(
        EncryptedWorkspace::image_path(workdir),
        workdir.join("filesystem/fs.sparsebundle")
    );
    assert_eq!(
        EncryptedWorkspace::mapped_path(Path::new("/mount"), Path::new("/Users/example/project"))
            .unwrap(),
        Path::new("/mount/Users/example/project")
    );
    assert!(
        EncryptedWorkspace::mapped_path(Path::new("/mount"), Path::new("relative"))
            .unwrap_err()
            .to_string()
            .contains("is not absolute")
    );
    assert_eq!(
        EncryptedWorkspace::resolved_destination(Path::new("relative-workdir")).unwrap(),
        std::env::current_dir().unwrap().join("relative-workdir")
    );
}

#[test]
fn filesystem_lock_is_exclusive() {
    let directory = temporary_directory("lock");
    std::fs::create_dir_all(&directory).unwrap();

    let lock = EncryptedWorkspace::lock(&directory).unwrap();
    assert!(
        EncryptedWorkspace::lock(&directory)
            .unwrap_err()
            .to_string()
            .contains("already in use")
    );
    drop(lock);
    let mut reacquired = None;
    for _ in 0..20 {
        match EncryptedWorkspace::lock(&directory) {
            Ok(lock) => {
                reacquired = Some(lock);
                break;
            }
            Err(_) => std::thread::sleep(std::time::Duration::from_millis(10)),
        }
    }
    assert!(reacquired.is_some());

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn setup_rejects_plaintext_or_invalid_mount_points() {
    let directory = temporary_directory("invalid-layout");
    std::fs::create_dir_all(&directory).unwrap();

    let work_file = directory.join("work-file");
    std::fs::write(&work_file, b"not a directory").unwrap();
    assert!(
        EncryptedWorkspace::start(&work_file, b"passphrase")
            .await
            .unwrap_err()
            .to_string()
            .contains("failed to create encrypted filesystem directory")
    );

    let blocked_mount = directory.join("blocked-mount");
    std::fs::create_dir_all(&blocked_mount).unwrap();
    std::fs::write(blocked_mount.join("fs"), b"not a directory").unwrap();
    assert!(
        EncryptedWorkspace::start(&blocked_mount, b"passphrase")
            .await
            .unwrap_err()
            .to_string()
            .contains("mount point is not a directory")
    );

    let plaintext_mount = directory.join("plaintext-mount");
    std::fs::create_dir_all(plaintext_mount.join("fs")).unwrap();
    std::fs::write(plaintext_mount.join("fs/file"), b"plaintext").unwrap();
    assert!(
        EncryptedWorkspace::start(&plaintext_mount, b"passphrase")
            .await
            .unwrap_err()
            .to_string()
            .contains("unencrypted filesystem data exists")
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn volume_metadata_is_initialized_and_validated() {
    let directory = temporary_directory("metadata");
    std::fs::create_dir_all(&directory).unwrap();
    let workspace = workspace(&directory);

    workspace.initialize_volume_metadata().unwrap();
    workspace.validate_volume_metadata().unwrap();
    let original = workspace.read_volume_metadata().unwrap();
    assert_eq!(original.version, METADATA_VERSION);
    uuid::Uuid::parse_str(&original.volume_id).unwrap();
    uuid::Uuid::parse_str(&original.key_id).unwrap();

    workspace.update_key_id().unwrap();
    let updated = workspace.read_volume_metadata().unwrap();
    assert_eq!(updated.volume_id, original.volume_id);
    assert_ne!(updated.key_id, original.key_id);

    workspace
        .write_volume_metadata(&VolumeMetadata {
            version: METADATA_VERSION + 1,
            volume_id: updated.volume_id.clone(),
            key_id: updated.key_id.clone(),
        })
        .unwrap();
    assert!(
        workspace
            .validate_volume_metadata()
            .unwrap_err()
            .to_string()
            .contains("unsupported")
    );

    workspace
        .write_volume_metadata(&VolumeMetadata {
            version: METADATA_VERSION,
            volume_id: "invalid".to_string(),
            key_id: updated.key_id.clone(),
        })
        .unwrap();
    assert!(
        workspace
            .validate_volume_metadata()
            .unwrap_err()
            .to_string()
            .contains("invalid encrypted filesystem volume id")
    );

    workspace
        .write_volume_metadata(&VolumeMetadata {
            version: METADATA_VERSION,
            volume_id: updated.volume_id,
            key_id: "invalid".to_string(),
        })
        .unwrap();
    assert!(
        workspace
            .validate_volume_metadata()
            .unwrap_err()
            .to_string()
            .contains("invalid encrypted filesystem key id")
    );

    std::fs::write(workspace.volume_metadata_path(), b"not json").unwrap();
    assert!(
        workspace
            .validate_volume_metadata()
            .unwrap_err()
            .to_string()
            .contains("failed to parse")
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn volume_metadata_reports_missing_and_unwritable_storage() {
    let directory = temporary_directory("metadata-errors");
    std::fs::create_dir_all(&directory).unwrap();
    let workspace = workspace(&directory);

    assert!(
        workspace
            .read_volume_metadata()
            .unwrap_err()
            .to_string()
            .contains("failed to read encrypted filesystem metadata")
    );
    assert!(
        workspace
            .write_volume_metadata(&VolumeMetadata {
                version: METADATA_VERSION,
                volume_id: uuid::Uuid::new_v4().to_string(),
                key_id: uuid::Uuid::new_v4().to_string(),
            })
            .unwrap_err()
            .to_string()
            .contains("failed to write encrypted filesystem metadata")
    );

    let blocked = directory.join("blocked");
    std::fs::write(&blocked, b"file").unwrap();
    assert!(
        EncryptedWorkspace::prepare_directory(&blocked)
            .unwrap_err()
            .to_string()
            .contains("failed to create encrypted filesystem directory")
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn helpers_report_errors_and_unmounted_shutdown_is_idempotent() {
    let directory = temporary_directory("helpers");
    std::fs::create_dir_all(&directory).unwrap();
    let mut workspace = workspace(&directory);

    assert!(!EncryptedWorkspace::is_mount_point(&directory).unwrap());
    assert!(EncryptedWorkspace::is_mount_point(&directory.join("missing")).is_err());
    assert!(
        EncryptedWorkspace::detach(&directory.join("missing"))
            .await
            .is_err()
    );
    workspace.shutdown().await.unwrap();
    assert_eq!(
        workspace.map_host_path(Path::new("/tmp/file")).unwrap(),
        directory.join("fs/tmp/file")
    );
    assert!(
        EncryptedWorkspace::lock(&directory.join("missing-parent"))
            .unwrap_err()
            .to_string()
            .contains("failed to open encrypted filesystem lock")
    );
    assert!(
        EncryptedWorkspace::run_hdiutil(
            &[OsStr::new("invalid-operation")],
            b"passphrase\0",
            "run invalid hdiutil operation",
        )
        .await
        .unwrap_err()
        .to_string()
        .contains("run invalid hdiutil operation")
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn migration_rejects_missing_images_and_identical_keys() {
    let directory = temporary_directory("migration-errors");
    std::fs::create_dir_all(&directory).unwrap();

    assert!(
        EncryptedWorkspace::migrate_key(&directory, b"same", b"same")
            .await
            .unwrap_err()
            .to_string()
            .contains("must differ")
    );
    assert!(
        EncryptedWorkspace::migrate_key(&directory, b"old", b"new")
            .await
            .unwrap_err()
            .to_string()
            .contains("does not exist")
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn encrypted_volume_reuses_its_identity_and_migrates_its_key() {
    let directory = temporary_directory("lifecycle");
    let workdir = directory.join("workdir");
    std::fs::create_dir_all(&directory).unwrap();

    let mut first = EncryptedWorkspace::start(&workdir, b"old-passphrase")
        .await
        .unwrap();
    std::fs::write(first.root().join("persistent"), b"encrypted contents").unwrap();
    let identity = first.read_volume_metadata().unwrap();
    first.shutdown().await.unwrap();
    drop(first);

    let wrong_key = EncryptedWorkspace::start(&workdir, b"wrong-passphrase")
        .await
        .unwrap_err();
    assert!(
        wrong_key.to_string().contains("key is incorrect"),
        "{wrong_key:#}"
    );

    crate::runner::migrate_filesystem_key(&workdir, b"old-passphrase", b"new-passphrase")
        .await
        .unwrap();
    let mut migrated = EncryptedWorkspace::start(&workdir, b"new-passphrase")
        .await
        .unwrap();
    let migrated_identity = migrated.read_volume_metadata().unwrap();
    assert_eq!(migrated_identity.volume_id, identity.volume_id);
    assert_ne!(migrated_identity.key_id, identity.key_id);
    assert_eq!(
        std::fs::read(migrated.root().join("persistent")).unwrap(),
        b"encrypted contents"
    );
    migrated.shutdown().await.unwrap();
    drop(migrated);

    let old_key = EncryptedWorkspace::start(&workdir, b"old-passphrase")
        .await
        .unwrap_err();
    assert!(
        old_key.to_string().contains("key is incorrect"),
        "{old_key:#}"
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn encrypted_volume_rejects_corrupt_identity_and_detaches_before_returning() {
    let directory = temporary_directory("corrupt-identity");
    let workdir = directory.join("workdir");
    std::fs::create_dir_all(&directory).unwrap();

    let mut workspace = EncryptedWorkspace::start(&workdir, b"passphrase")
        .await
        .unwrap();
    std::fs::write(
        workspace.volume_metadata_path(),
        serde_json::to_vec(&VolumeMetadata {
            version: METADATA_VERSION,
            volume_id: "invalid".to_string(),
            key_id: uuid::Uuid::new_v4().to_string(),
        })
        .unwrap(),
    )
    .unwrap();
    workspace.shutdown().await.unwrap();
    drop(workspace);

    assert!(
        EncryptedWorkspace::start(&workdir, b"passphrase")
            .await
            .unwrap_err()
            .to_string()
            .contains("invalid encrypted filesystem volume id")
    );
    assert!(!EncryptedWorkspace::is_mount_point(&workdir.join("fs")).unwrap());

    std::fs::remove_dir_all(directory).unwrap();
}
