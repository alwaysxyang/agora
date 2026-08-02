use super::{FilesystemMode, FilesystemWorkspace, PlainWorkspace};

fn temporary_directory(name: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("agora-workspace-{name}-{}", uuid::Uuid::new_v4()))
}

#[tokio::test]
async fn plain_workspace_is_persistent_and_exclusive() {
    let workdir = temporary_directory("plain");
    let mut workspace = FilesystemWorkspace::start(&workdir, FilesystemMode::Plain, None)
        .await
        .unwrap();
    assert_eq!(
        workspace.root().file_name(),
        Some(std::ffi::OsStr::new("fs"))
    );
    std::fs::write(workspace.root().join("marker"), b"persisted").unwrap();

    let error = PlainWorkspace::start(&workdir).unwrap_err();
    assert!(error.to_string().contains("filesystem is already in use"));
    workspace.shutdown().await.unwrap();
    drop(workspace);

    let workspace = PlainWorkspace::start(&workdir).unwrap();
    assert_eq!(
        std::fs::read(workspace.root().join("marker")).unwrap(),
        b"persisted"
    );
    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn workspace_rejects_keys_that_do_not_match_the_mode() {
    let workdir = temporary_directory("mode");
    let missing = FilesystemWorkspace::start(&workdir, FilesystemMode::Encrypted, None)
        .await
        .unwrap_err();
    assert!(missing.to_string().contains("filesystem key is required"));

    let unexpected = FilesystemWorkspace::start(&workdir, FilesystemMode::Plain, Some(b"unused"))
        .await
        .unwrap_err();
    assert!(
        unexpected
            .to_string()
            .contains("cannot be used with plain filesystem mode")
    );
}

#[test]
fn plain_workspace_rejects_a_file_as_its_root() {
    let workdir = temporary_directory("blocked-root");
    std::fs::create_dir_all(&workdir).unwrap();
    std::fs::write(workdir.join("fs"), b"not a directory").unwrap();

    let error = PlainWorkspace::start(&workdir).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to create plain filesystem root")
    );
    std::fs::remove_dir_all(workdir).unwrap();
}
