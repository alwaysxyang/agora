use super::super::FilesystemHookRuntime;
use super::{RemoteAnchor, RemoteFilesystem};
use crate::nfs::protocol::RemoteRoute;
use std::os::unix::ffi::OsStringExt;
use std::path::{Path, PathBuf};

fn filesystem() -> RemoteFilesystem {
    RemoteFilesystem::new(
        "/tmp/remote.sock",
        "token",
        vec![
            RemoteRoute {
                root: 4,
                logical_root: "/remote/team".to_string(),
            },
            RemoteRoute {
                root: 8,
                logical_root: "/archive".to_string(),
            },
        ],
    )
    .unwrap()
}

#[test]
fn remote_routes_match_only_whole_normalized_path_prefixes() {
    let filesystem = filesystem();

    let root = filesystem.route(Path::new("/remote/team")).unwrap();
    assert_eq!(root.remote().root(), 4);
    assert_eq!(root.remote().path(), "");
    let child = filesystem
        .route(Path::new("/remote/team/docs/file.txt"))
        .unwrap();
    assert_eq!(child.remote().path(), "docs/file.txt");
    let normalized = filesystem
        .route(Path::new("/remote/team/docs/../file.txt"))
        .unwrap();
    assert_eq!(normalized.remote().path(), "file.txt");
    assert!(
        filesystem
            .route(Path::new("/remote/team/../../local/file"))
            .is_none()
    );
    assert!(filesystem.route(Path::new("/remote/teammate")).is_none());
    assert!(filesystem.route(Path::new("/local/file")).is_none());
    let archive = filesystem.route(Path::new("/archive/2026/report")).unwrap();
    assert_eq!(archive.remote().root(), 8);
    assert_eq!(archive.remote().path(), "2026/report");
}

#[test]
fn remote_routes_reject_invalid_roots_and_non_utf8_children() {
    assert!(
        RemoteFilesystem::new(
            "/tmp/remote.sock",
            "token",
            vec![RemoteRoute {
                root: 0,
                logical_root: "relative".to_string(),
            }],
        )
        .is_err()
    );
    let filesystem = filesystem();
    let invalid = PathBuf::from("/remote/team").join(std::ffi::OsString::from_vec(vec![0xff]));
    assert!(filesystem.route_result(&invalid).is_err());
}

#[test]
fn remote_route_json_contains_no_smb_endpoint_or_credentials() {
    let routes = vec![RemoteRoute {
        root: 0,
        logical_root: "/remote".to_string(),
    }];
    let encoded = serde_json::to_string(&routes).unwrap();
    let filesystem = RemoteFilesystem::from_json("/tmp/remote.sock", "token", &encoded).unwrap();

    assert!(filesystem.route(Path::new("/remote/file")).is_some());
    assert!(!encoded.contains("server"));
    assert!(!encoded.contains("password"));
}

#[test]
fn remote_current_directory_is_restored_only_from_its_broker_anchor() {
    let filesystem = RemoteFilesystem::new(
        "/tmp/agora-remote-runtime/nfs.sock",
        "token",
        vec![RemoteRoute {
            root: 0,
            logical_root: "/remote".to_string(),
        }],
    )
    .unwrap();
    let anchor =
        Path::new("/tmp/agora-remote-runtime").join("anchor-0123456789abcdef0123456789abcdef");

    assert_eq!(
        filesystem
            .restore_current_directory(&anchor, Path::new("/remote/team/docs"))
            .unwrap(),
        Some(PathBuf::from("/remote/team/docs"))
    );
    assert_eq!(
        filesystem
            .restore_current_directory(Path::new("/tmp/local"), Path::new("/remote/team/docs"))
            .unwrap(),
        None
    );
    assert!(
        filesystem
            .restore_current_directory(&anchor, Path::new("/local"))
            .is_err()
    );

    let restored = FilesystemHookRuntime::current_directory_from_native(
        anchor,
        Some(&filesystem),
        Some(Path::new("/remote/team/docs")),
    )
    .unwrap();
    assert_eq!(restored.logical, Path::new("/remote/team/docs"));
    assert!(restored.remote);
}

#[test]
fn remote_anchor_removes_its_temporary_inode_when_released() {
    let runtime = tempfile::tempdir().unwrap();
    let file = runtime
        .path()
        .join("anchor-0123456789abcdef0123456789abcdef");
    std::fs::write(&file, []).unwrap();

    drop(RemoteAnchor::adopt(&file).unwrap());

    assert!(!file.exists());
}
