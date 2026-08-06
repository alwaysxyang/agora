use super::{metadata_from_file, remote_path, smb_errno};
use crate::nfs::protocol::{RemoteFileType, RemotePath};
use smb2::client::tree::FileInfo;
use smb2::pack::FileTime;
use smb2::types::{Command, status::NtStatus};

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
