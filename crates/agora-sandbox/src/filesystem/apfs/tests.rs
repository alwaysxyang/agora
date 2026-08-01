use super::{EncryptedWorkspace, MAX_KEY_SIZE, METADATA_VERSION, WorkspaceMetadata};
use base64::Engine;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

fn temporary_directory(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("agora-filesystem-{label}-{}", uuid::Uuid::new_v4()))
}

fn workspace(source: PathBuf, path: PathBuf, root: &Path) -> EncryptedWorkspace {
    std::fs::create_dir_all(root).unwrap();
    EncryptedWorkspace {
        source,
        path,
        mount_point: root.join("mount"),
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
fn mapped_path_mirrors_an_absolute_source() {
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
fn workspace_lock_is_exclusive() {
    let directory = std::env::temp_dir().join(format!(
        "agora-filesystem-lock-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();

    let lock = EncryptedWorkspace::lock(&directory).unwrap();
    assert!(
        EncryptedWorkspace::lock(&directory)
            .unwrap_err()
            .to_string()
            .contains("already in use")
    );
    drop(lock);
    assert!(EncryptedWorkspace::lock(&directory).is_ok());

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn start_rejects_invalid_sources_and_inconsistent_storage() {
    let directory = temporary_directory("invalid-layout-test");
    std::fs::create_dir_all(&directory).unwrap();

    let missing_source = directory.join("missing-source");
    assert!(
        EncryptedWorkspace::start(&directory.join("work-a"), &missing_source, b"passphrase")
            .await
            .err()
            .expect("missing source must fail")
            .to_string()
            .contains("failed to resolve encrypted workspace source")
    );

    let source_file = directory.join("source-file");
    std::fs::write(&source_file, b"not a directory").unwrap();
    assert!(
        EncryptedWorkspace::start(&directory.join("work-b"), &source_file, b"passphrase")
            .await
            .err()
            .expect("file source must fail")
            .to_string()
            .contains("source is not a directory")
    );

    let source = directory.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let work_file = directory.join("work-file");
    std::fs::write(&work_file, b"not a directory").unwrap();
    assert!(
        EncryptedWorkspace::start(&work_file, &source, b"passphrase")
            .await
            .err()
            .expect("file workdir must fail")
            .to_string()
            .contains("failed to create encrypted filesystem directory")
    );

    let blocked_mount = directory.join("blocked-mount/filesystem");
    std::fs::create_dir_all(&blocked_mount).unwrap();
    std::fs::write(blocked_mount.join("mount"), b"not a directory").unwrap();
    assert!(
        EncryptedWorkspace::start(&directory.join("blocked-mount"), &source, b"passphrase",)
            .await
            .err()
            .expect("file mount point must fail")
            .to_string()
            .contains("failed to create encrypted filesystem mount point")
    );

    let metadata_only = directory.join("metadata-only/filesystem");
    std::fs::create_dir_all(&metadata_only).unwrap();
    std::fs::write(metadata_only.join("workspace.json"), b"{}").unwrap();
    assert!(
        EncryptedWorkspace::start(&directory.join("metadata-only"), &source, b"passphrase",)
            .await
            .err()
            .expect("orphaned metadata must fail")
            .to_string()
            .contains("metadata exists without its disk image")
    );

    let image_only = directory.join("image-only/filesystem");
    std::fs::create_dir_all(image_only.join("workspace.sparsebundle")).unwrap();
    assert!(
        EncryptedWorkspace::start(&directory.join("image-only"), &source, b"passphrase")
            .await
            .err()
            .expect("orphaned image must fail")
            .to_string()
            .contains("disk image exists without metadata")
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn metadata_validation_rejects_corruption_and_other_sources() {
    let directory = temporary_directory("metadata-test");
    let source = directory.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let workspace = workspace(
        source.clone(),
        directory.join("mapped"),
        &directory.join("state"),
    );
    let metadata = directory.join("workspace.json");

    assert!(
        workspace
            .validate_metadata(&metadata)
            .unwrap_err()
            .to_string()
            .contains("failed to read")
    );
    std::fs::write(&metadata, b"not json").unwrap();
    assert!(
        workspace
            .validate_metadata(&metadata)
            .unwrap_err()
            .to_string()
            .contains("failed to parse")
    );

    let write_metadata = |version, encoded_source: &str| {
        std::fs::write(
            &metadata,
            serde_json::to_vec(&WorkspaceMetadata {
                version,
                source: encoded_source.to_string(),
            })
            .unwrap(),
        )
        .unwrap();
    };
    let encoded_source =
        base64::engine::general_purpose::STANDARD.encode(source.as_os_str().as_encoded_bytes());
    write_metadata(METADATA_VERSION + 1, &encoded_source);
    assert!(
        workspace
            .validate_metadata(&metadata)
            .unwrap_err()
            .to_string()
            .contains("unsupported")
    );
    write_metadata(METADATA_VERSION, "%%%invalid-base64%%%");
    assert!(
        workspace
            .validate_metadata(&metadata)
            .unwrap_err()
            .to_string()
            .contains("invalid encrypted workspace source metadata")
    );
    write_metadata(
        METADATA_VERSION,
        &base64::engine::general_purpose::STANDARD.encode(b"/different/source"),
    );
    assert!(
        workspace
            .validate_metadata(&metadata)
            .unwrap_err()
            .to_string()
            .contains("belongs to a different source")
    );
    write_metadata(METADATA_VERSION, &encoded_source);
    workspace.validate_metadata(&metadata).unwrap();

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn helpers_report_io_failures_and_unmounted_shutdown_is_idempotent() {
    let directory = temporary_directory("helper-errors-test");
    std::fs::create_dir_all(&directory).unwrap();
    let source = directory.join("source");
    std::fs::create_dir_all(&source).unwrap();
    let mut workspace = workspace(
        source.clone(),
        directory.join("mapped"),
        &directory.join("state"),
    );

    assert!(!EncryptedWorkspace::is_mount_point(&directory).unwrap());
    assert!(EncryptedWorkspace::is_mount_point(&directory.join("missing")).is_err());
    assert!(
        EncryptedWorkspace::detach(&directory.join("missing"))
            .await
            .is_err()
    );
    workspace.shutdown().await.unwrap();
    assert_eq!(
        workspace.map_source_path(&source.join("file")),
        Some(directory.join("mapped/file"))
    );
    assert_eq!(workspace.map_source_path(Path::new("/elsewhere")), None);
    assert!(
        EncryptedWorkspace::lock(&directory.join("missing-parent"))
            .unwrap_err()
            .to_string()
            .contains("failed to open encrypted workspace lock")
    );
    assert!(
        EncryptedWorkspace::run_with_passphrase(
            &[OsStr::new("invalid-operation")],
            b"passphrase",
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
async fn initialize_reports_copy_and_metadata_write_failures() {
    let directory = temporary_directory("initialize-errors-test");
    std::fs::create_dir_all(&directory).unwrap();

    let missing_source = workspace(
        directory.join("missing-source"),
        directory.join("mapped"),
        &directory.join("missing-state"),
    );
    assert!(
        missing_source
            .initialize(&directory.join("missing.json"))
            .await
            .unwrap_err()
            .to_string()
            .contains("failed to initialize encrypted workspace")
    );

    let source = directory.join("source");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("file"), b"contents").unwrap();
    let metadata_directory = directory.join("metadata-directory");
    std::fs::create_dir_all(&metadata_directory).unwrap();
    let workspace = workspace(
        source,
        directory.join("copied"),
        &directory.join("write-state"),
    );
    assert!(
        workspace
            .initialize(&metadata_directory)
            .await
            .unwrap_err()
            .to_string()
            .contains("failed to write encrypted workspace metadata")
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn start_recovers_a_stale_mount_and_shutdown_detaches_it() {
    let directory = temporary_directory("stale-mount-test");
    let source = directory.join("source");
    let workdir = directory.join("workdir");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("file"), b"contents").unwrap();

    let mut first = EncryptedWorkspace::start(&workdir, &source, b"passphrase")
        .await
        .unwrap();
    assert!(EncryptedWorkspace::is_mount_point(&first.mount_point).unwrap());
    first.mounted = false;
    drop(first);

    let mut recovered = EncryptedWorkspace::start(&workdir, &source, b"passphrase")
        .await
        .unwrap();
    assert!(EncryptedWorkspace::is_mount_point(&recovered.mount_point).unwrap());
    recovered.shutdown().await.unwrap();
    recovered.shutdown().await.unwrap();
    assert!(!EncryptedWorkspace::is_mount_point(&recovered.mount_point).unwrap());

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn drop_detaches_a_mounted_workspace() {
    let directory = temporary_directory("drop-detach-test");
    let source = directory.join("source");
    let workdir = directory.join("workdir");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("file"), b"contents").unwrap();

    let mount_point = {
        let workspace = EncryptedWorkspace::start(&workdir, &source, b"passphrase")
            .await
            .unwrap();
        assert!(EncryptedWorkspace::is_mount_point(&workspace.mount_point).unwrap());
        workspace.mount_point.clone()
    };
    assert!(!EncryptedWorkspace::is_mount_point(&mount_point).unwrap());

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn start_rejects_an_existing_image_without_its_mapped_directory() {
    let directory = temporary_directory("missing-mapped-directory-test");
    let source = directory.join("source");
    let workdir = directory.join("workdir");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("file"), b"contents").unwrap();

    let mut workspace = EncryptedWorkspace::start(&workdir, &source, b"passphrase")
        .await
        .unwrap();
    std::fs::remove_dir_all(workspace.path()).unwrap();
    workspace.shutdown().await.unwrap();
    drop(workspace);

    let error = EncryptedWorkspace::start(&workdir, &source, b"passphrase")
        .await
        .err()
        .expect("missing mapped directory must fail");
    assert!(
        error
            .to_string()
            .contains("encrypted workspace directory is missing")
    );
    assert!(!EncryptedWorkspace::is_mount_point(&workdir.join("filesystem/mount")).unwrap());

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn initialize_reports_an_unusable_destination_parent() {
    let directory = temporary_directory("initialize-parent-error-test");
    let source = directory.join("source");
    let blocked_parent = directory.join("blocked-parent");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(&blocked_parent, b"not a directory").unwrap();
    let workspace = workspace(
        source,
        blocked_parent.join("mapped"),
        &directory.join("state"),
    );

    assert!(
        workspace
            .initialize(&directory.join("workspace.json"))
            .await
            .unwrap_err()
            .to_string()
            .contains("failed to create encrypted workspace parent")
    );

    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn start_removes_a_new_image_when_initial_copy_fails() {
    use std::os::unix::fs::PermissionsExt;

    let directory = temporary_directory("initial-copy-rollback-test");
    let source = directory.join("source");
    let workdir = directory.join("workdir");
    let unreadable = source.join("unreadable");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(&unreadable, b"contents").unwrap();
    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

    let error = EncryptedWorkspace::start(&workdir, &source, b"passphrase")
        .await
        .err()
        .expect("an unreadable source must fail initialization");
    assert!(
        error
            .to_string()
            .contains("failed to initialize encrypted workspace")
    );
    assert!(!workdir.join("filesystem/workspace.sparsebundle").exists());
    assert!(!workdir.join("filesystem/workspace.json").exists());
    assert!(!EncryptedWorkspace::is_mount_point(&workdir.join("filesystem/mount")).unwrap());

    std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::remove_dir_all(directory).unwrap();
}
