use super::{
    FILE_ATTRIBUTE_DIRECTORY, SmbRoot, SmbStorage, build_rename_information, configured_storage,
    expect_success, metadata_from_close, metadata_from_create, metadata_from_file, remote_path,
    smb_errno, stale_file, storage_error, wire_path,
};
use crate::nfs::SmbRemoteConfig;
use crate::nfs::backend::{RemoteStorage, StorageResult};
use crate::nfs::protocol::{RemoteFileType, RemotePath};
use smb2::client::tree::FileInfo;
use smb2::msg::close::CloseResponse;
use smb2::msg::create::{CreateAction, CreateResponse};
use smb2::msg::header::Header;
use smb2::pack::FileTime;
use smb2::types::{Command, FileId, OplockLevel, TreeId, status::NtStatus};
use smb2::{Error, Frame, Tree};

fn assert_errno<T>(result: StorageResult<T>, expected: libc::c_int) {
    match result {
        Ok(_) => panic!("operation unexpectedly succeeded"),
        Err(error) => assert_eq!(error.errno(), expected),
    }
}

#[test]
fn smb_paths_are_root_relative_and_never_escape_the_configured_prefix() {
    let path = RemotePath::new(0, "child/file.txt").unwrap();
    assert_eq!(remote_path("base/team", &path), "base/team/child/file.txt");
    assert_eq!(remote_path("", &path), "child/file.txt");
    assert_eq!(
        remote_path("base/team", &RemotePath::new(0, "").unwrap()),
        "base/team"
    );
}

#[test]
fn smb_metadata_uses_stable_remote_identity_fields() {
    let info = FileInfo {
        size: 42,
        is_directory: false,
        created: FileTime(133_485_408_000_000_000),
        modified: FileTime(133_485_408_001_234_567),
        accessed: FileTime(133_485_408_002_000_000),
    };

    let metadata = metadata_from_file(&info);

    assert_eq!(metadata.file_type, RemoteFileType::File);
    assert_eq!(metadata.size, 42);
    assert_eq!(metadata.modified_seconds, 1_704_067_200);
    assert_eq!(metadata.modified_nanoseconds, 123_456_700);
    assert_eq!(
        metadata.identity,
        "file:42:133485408001234567:133485408000000000"
    );
}

#[test]
fn smb_errors_map_to_posix_errno_without_string_matching() {
    let missing = smb2::Error::Protocol {
        status: NtStatus::OBJECT_NAME_NOT_FOUND,
        command: Command::Create,
    };
    let not_empty = smb2::Error::Protocol {
        status: NtStatus::DIRECTORY_NOT_EMPTY,
        command: Command::SetInfo,
    };

    assert_eq!(smb_errno(&missing), libc::ENOENT);
    assert_eq!(smb_errno(&not_empty), libc::ENOTEMPTY);
}

#[test]
fn smb_rename_information_requests_atomic_target_replacement() {
    let buffer = build_rename_information("folder\\target.txt");

    assert_eq!(buffer[0], 1, "ReplaceIfExists must be true");
    assert_eq!(u32::from_le_bytes(buffer[16..20].try_into().unwrap()), 34);
}

#[tokio::test]
async fn smb_storage_rejects_unknown_roots_before_network_access() {
    let storage = SmbStorage::new(&[]);
    let path = RemotePath::new(0, "file.txt").unwrap();

    assert_errno(storage.connect(0).await, libc::EINVAL);
    assert_errno(storage.stat(&path).await, libc::EINVAL);
    assert_errno(storage.read(&path).await, libc::EINVAL);
    assert_errno(
        storage.write_if_unchanged(&path, None, b"data").await,
        libc::EINVAL,
    );
    assert_errno(storage.list(&path).await, libc::EINVAL);
    assert_errno(storage.create_directory(&path).await, libc::EINVAL);
    assert_errno(storage.remove(&path, false).await, libc::EINVAL);
    assert_errno(
        storage
            .rename(&path, &RemotePath::new(0, "renamed.txt").unwrap())
            .await,
        libc::EINVAL,
    );
    assert_errno(
        storage
            .rename(&path, &RemotePath::new(1, "renamed.txt").unwrap())
            .await,
        libc::EXDEV,
    );

    let configured = configured_storage(&[]);
    assert_errno(configured.connect(0).await, libc::EINVAL);
}

#[tokio::test]
async fn smb_storage_propagates_connection_failures_for_every_remote_operation() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    let config = SmbRemoteConfig::new("/remote", address.to_string(), "share").unwrap();
    let storage = SmbStorage::new(&[config]);
    let path = RemotePath::new(0, "file.txt").unwrap();
    let renamed = RemotePath::new(0, "renamed.txt").unwrap();

    assert!(storage.connect(0).await.is_err());
    assert!(storage.stat(&path).await.is_err());
    assert!(storage.read(&path).await.is_err());
    assert!(
        storage
            .write_if_unchanged(&path, None, b"data")
            .await
            .is_err()
    );
    assert!(storage.list(&path).await.is_err());
    assert!(storage.create_directory(&path).await.is_err());
    assert!(storage.remove(&path, false).await.is_err());
    assert!(storage.remove(&path, true).await.is_err());
    assert!(storage.rename(&path, &renamed).await.is_err());
}

#[test]
fn smb_root_and_wire_paths_keep_backend_details_inside_the_backend() {
    let config = SmbRemoteConfig::new("/remote", "server", "share")
        .unwrap()
        .with_remote_path("base/team")
        .unwrap();
    let root = SmbRoot::new(config);
    assert!(root.session.is_none());
    assert_eq!(
        root.path(&RemotePath::new(0, "child.txt").unwrap()),
        "base/team/child.txt"
    );

    let mut tree = Tree {
        tree_id: TreeId(7),
        share_name: "share".to_string(),
        server: "server:445".to_string(),
        is_dfs: false,
        encrypt_data: false,
    };
    assert_eq!(wire_path(&tree, "folder/file.txt"), "folder\\file.txt");
    tree.is_dfs = true;
    assert_eq!(wire_path(&tree, ""), "server\\share");
    assert_eq!(
        wire_path(&tree, "folder/file.txt"),
        "server\\share\\folder\\file.txt"
    );
}

#[test]
fn smb_create_and_close_metadata_preserve_type_size_and_creation_identity() {
    let created = CreateResponse {
        oplock_level: OplockLevel::None,
        flags: 0,
        create_action: CreateAction::FileOpened,
        creation_time: FileTime(100),
        last_access_time: FileTime(101),
        last_write_time: FileTime(102),
        change_time: FileTime(103),
        allocation_size: 16,
        end_of_file: 7,
        file_attributes: FILE_ATTRIBUTE_DIRECTORY,
        file_id: FileId::default(),
        create_contexts: Vec::new(),
    };
    let metadata = metadata_from_create(&created);
    assert_eq!(metadata.file_type, RemoteFileType::Directory);
    assert_eq!(metadata.size, 7);
    assert_eq!(metadata.modified_seconds, 0);
    assert_eq!(metadata.identity, "directory:7:102:100");

    let closed = CloseResponse {
        flags: 0,
        creation_time: FileTime(200),
        last_access_time: FileTime(201),
        last_write_time: FileTime(202),
        change_time: FileTime(203),
        allocation_size: 32,
        end_of_file: 11,
        file_attributes: 0,
    };
    let metadata = metadata_from_close(&closed);
    assert_eq!(metadata.file_type, RemoteFileType::File);
    assert_eq!(metadata.size, 11);
    assert_eq!(metadata.identity, "file:11:202:200");
}

#[test]
fn smb_frame_and_error_translation_covers_protocol_and_transport_failures() {
    let frame = Frame {
        header: Header::new_request(Command::Create),
        body: Vec::new(),
        raw: Vec::new(),
    };
    expect_success(&frame, Command::Create).unwrap();
    let mut denied = frame;
    denied.header.status = NtStatus::ACCESS_DENIED;
    assert!(expect_success(&denied, Command::Create).is_err());

    let protocol = |status| Error::Protocol {
        status,
        command: Command::Create,
    };
    let cases = vec![
        (protocol(NtStatus::ACCESS_DENIED), libc::EACCES),
        (protocol(NtStatus::OBJECT_NAME_NOT_FOUND), libc::ENOENT),
        (protocol(NtStatus::OBJECT_NAME_COLLISION), libc::EEXIST),
        (protocol(NtStatus::SHARING_VIOLATION), libc::EBUSY),
        (protocol(NtStatus::FILE_IS_A_DIRECTORY), libc::EISDIR),
        (protocol(NtStatus::NOT_A_DIRECTORY), libc::ENOTDIR),
        (protocol(NtStatus::DISK_FULL), libc::ENOSPC),
        (protocol(NtStatus::PATH_NOT_COVERED), libc::EXDEV),
        (protocol(NtStatus::OBJECT_NAME_INVALID), libc::EINVAL),
        (protocol(NtStatus::NOT_SUPPORTED), libc::ENOTSUP),
        (protocol(NtStatus::DELETE_PENDING), libc::EBUSY),
        (Error::Timeout, libc::ETIMEDOUT),
        (Error::Disconnected, libc::ENETDOWN),
        (Error::Cancelled, libc::EINTR),
        (Error::SessionExpired, libc::EIO),
        (
            Error::DfsReferralRequired {
                path: "remote".to_string(),
            },
            libc::EXDEV,
        ),
        (
            Error::FileTooLargeForSingleRead {
                size: u64::MAX,
                max_read: 1,
            },
            libc::EFBIG,
        ),
        (
            Error::Io(std::io::Error::from_raw_os_error(libc::ENOMEM)),
            libc::ENOMEM,
        ),
        (Error::invalid_data("bad frame"), libc::EPROTO),
        (protocol(NtStatus(0xDEAD_BEEF)), libc::EIO),
    ];
    for (error, expected) in cases {
        assert_eq!(smb_errno(&error), expected, "{error}");
    }

    let error = storage_error(Error::Timeout);
    assert_eq!(error.errno(), libc::ETIMEDOUT);
    assert!(error.to_string().contains("SMB operation failed"));
    assert_eq!(stale_file().errno(), libc::ESTALE);
}
