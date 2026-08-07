use super::super::FilesystemHookRuntime;
use super::{RemoteAnchor, RemoteFilesystem, RemoteOpen, validate_entries};
use crate::nfs::client::RemoteClient;
use crate::nfs::protocol::{RemoteEntry, RemoteFileType, RemoteMetadata, RemoteRoute};
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

fn metadata(file_type: RemoteFileType) -> RemoteMetadata {
    RemoteMetadata {
        file_type,
        size: 1,
        modified_seconds: 2,
        modified_nanoseconds: 3,
        identity: "identity".to_string(),
    }
}

fn errno(error: &anyhow::Error) -> Option<libc::c_int> {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<std::io::Error>())
        .and_then(std::io::Error::raw_os_error)
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
fn remote_filesystem_configuration_rejects_incomplete_and_overlapping_routes() {
    let route = || RemoteRoute {
        root: 0,
        logical_root: "/remote".to_string(),
    };
    assert!(RemoteFilesystem::new("relative.sock", "token", vec![route()]).is_err());
    assert!(RemoteFilesystem::new("/tmp/remote.sock", "", vec![route()]).is_err());
    assert!(RemoteFilesystem::new("/tmp/remote.sock", "token", Vec::new()).is_err());
    assert!(RemoteFilesystem::new("/", "token", vec![route()]).is_err());
    assert!(
        RemoteFilesystem::new(
            "/tmp/remote.sock",
            "token",
            vec![
                route(),
                RemoteRoute {
                    root: 1,
                    logical_root: "/remote/team".to_string(),
                },
            ],
        )
        .is_err()
    );
    assert!(
        RemoteFilesystem::new(
            "/tmp/remote.sock",
            "token",
            vec![RemoteRoute {
                root: 0,
                logical_root: "/remote/../escape".to_string(),
            }],
        )
        .is_err()
    );
    assert!(RemoteFilesystem::from_json("/tmp/remote.sock", "token", "not-json").is_err());
}

#[test]
fn remote_routes_reject_relative_requests_cross_root_renames_and_invalid_entries() {
    let filesystem = filesystem();
    assert!(filesystem.route_result(Path::new("relative")).is_err());

    let from = filesystem.route(Path::new("/remote/team/from")).unwrap();
    let to = filesystem.route(Path::new("/archive/to")).unwrap();
    assert_eq!(
        errno(&filesystem.rename(&from, &to).unwrap_err()),
        Some(libc::EXDEV)
    );

    for name in ["", ".", "..", "nested/name", "back\\slash", "nul\0name"] {
        assert!(
            validate_entries(vec![RemoteEntry {
                name: name.to_string(),
                metadata: metadata(RemoteFileType::File),
            }])
            .is_err(),
            "entry {name:?} should be rejected"
        );
    }
    let duplicate = RemoteEntry {
        name: "duplicate".to_string(),
        metadata: metadata(RemoteFileType::File),
    };
    assert!(validate_entries(vec![duplicate.clone(), duplicate]).is_err());
}

#[test]
fn remote_metadata_rejects_invalid_anchors_and_exposes_mutable_open_targets() {
    let filesystem = filesystem();
    for anchor in ["../anchor", "nested/anchor", "/absolute"] {
        assert!(
            filesystem
                .metadata_plan(anchor, &metadata(RemoteFileType::File))
                .is_err()
        );
    }
    assert_eq!(
        filesystem
            .restore_current_directory(Path::new(""), Path::new("/remote/team"))
            .unwrap(),
        None
    );

    let mut open = RemoteOpen {
        client: RemoteClient::new("/tmp/missing-remote.sock", "token"),
        target: Some(super::super::OpenTarget::Descriptor(
            tempfile::tempfile().unwrap(),
        )),
        handle: None,
        metadata: metadata(RemoteFileType::File),
        writable: false,
    };
    assert!(matches!(
        open.target_mut(),
        super::super::OpenTarget::Descriptor(_)
    ));
    assert!(open.commit().is_err());
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
