use super::{OpenTarget, VirtualFilesystem};
use crate::filesystem::crypto::FileCipher;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::Path;

fn fixture(name: &str) -> (std::path::PathBuf, VirtualFilesystem) {
    let root = std::env::temp_dir().join(format!("agora-vfs-{name}-{}", uuid::Uuid::new_v4()));
    let cipher = FileCipher::derive(b"key", b"0123456789abcdef").unwrap();
    let filesystem = VirtualFilesystem::encrypted(&root, cipher).unwrap();
    (root, filesystem)
}

#[test]
fn encrypted_open_reads_lower_without_entering_the_vfs() {
    let (root, filesystem) = fixture("read");
    let source = root
        .parent()
        .unwrap()
        .join(format!("agora-vfs-source-{}", uuid::Uuid::new_v4()));
    let marker = b"host plaintext marker";
    std::fs::write(&source, marker).unwrap();

    let prepared = filesystem.prepare_open(&source, libc::O_RDONLY, 0).unwrap();
    let OpenTarget::Path(mapped) = prepared.target() else {
        panic!("lower file should remain outside the encrypted VFS");
    };
    assert_eq!(mapped, &source);
    assert_eq!(std::fs::read(mapped).unwrap(), marker);
    let backing = filesystem.prepare_read(&source).unwrap();
    assert_eq!(backing, source);
    assert_eq!(
        filesystem.prepare_metadata(&source, true).unwrap(),
        (source.clone(), None, source.clone())
    );

    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_file(source).unwrap();
}

#[test]
fn encrypted_writeback_publishes_ciphertext_and_restores_the_next_open() {
    let (root, filesystem) = fixture("write");
    let logical = Path::new("/tmp/agora-vfs-created");
    let marker = b"sandbox plaintext marker";
    let mut prepared = filesystem
        .prepare_open(logical, libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC, 0o600)
        .unwrap();
    let OpenTarget::Descriptor(file) = prepared.target_mut() else {
        panic!("encrypted regular file did not use an anonymous descriptor");
    };
    file.write_all(marker).unwrap();
    filesystem.commit_open(&mut prepared).unwrap();
    let (target, writeback, _) = prepared.into_parts();
    let OpenTarget::Descriptor(file) = target else {
        panic!("expected descriptor");
    };
    writeback.unwrap().commit(file.as_raw_fd()).unwrap();

    let backing = filesystem.prepare_read(logical).unwrap();
    let stored = std::fs::read(&backing).unwrap();
    assert!(!stored.windows(marker.len()).any(|window| window == marker));

    let mut reopened = filesystem.prepare_open(logical, libc::O_RDONLY, 0).unwrap();
    let OpenTarget::Descriptor(file) = reopened.target_mut() else {
        panic!("encrypted regular file did not use an anonymous descriptor");
    };
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut restored = Vec::new();
    file.read_to_end(&mut restored).unwrap();
    assert_eq!(restored, marker);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn encrypted_write_intent_copies_up_lower_content_without_changing_lower() {
    let (root, filesystem) = fixture("copy-up");
    let source = root
        .parent()
        .unwrap()
        .join(format!("agora-vfs-copy-up-{}", uuid::Uuid::new_v4()));
    std::fs::write(&source, b"lower content").unwrap();

    let mut prepared = filesystem.prepare_open(&source, libc::O_RDWR, 0).unwrap();
    let OpenTarget::Descriptor(file) = prepared.target_mut() else {
        panic!("encrypted copy-up should expose an anonymous descriptor");
    };
    let mut initial = String::new();
    file.read_to_string(&mut initial).unwrap();
    assert_eq!(initial, "lower content");
    file.seek(SeekFrom::Start(0)).unwrap();
    file.set_len(0).unwrap();
    file.write_all(b"upper content").unwrap();
    filesystem.commit_open(&mut prepared).unwrap();
    let (target, writeback, _) = prepared.into_parts();
    let OpenTarget::Descriptor(file) = target else {
        panic!("expected descriptor");
    };
    writeback.unwrap().commit(file.as_raw_fd()).unwrap();

    assert_eq!(std::fs::read(&source).unwrap(), b"lower content");
    let backing = filesystem.prepare_read(&source).unwrap();
    assert_ne!(backing, source);
    assert!(
        !std::fs::read(&backing)
            .unwrap()
            .windows(b"upper content".len())
            .any(|window| window == b"upper content")
    );

    let mut reopened = filesystem.prepare_open(&source, libc::O_RDONLY, 0).unwrap();
    let OpenTarget::Descriptor(file) = reopened.target_mut() else {
        panic!("upper encrypted file should use an anonymous descriptor");
    };
    let mut restored = String::new();
    file.read_to_string(&mut restored).unwrap();
    assert_eq!(restored, "upper content");

    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_file(source).unwrap();
}

#[test]
fn encrypted_open_honors_exclusive_create_and_truncate() {
    let (root, filesystem) = fixture("flags");
    let logical = Path::new("/tmp/agora-vfs-flags");
    let mut created = filesystem
        .prepare_open(logical, libc::O_CREAT | libc::O_RDWR, 0o600)
        .unwrap();
    filesystem.commit_open(&mut created).unwrap();
    let (target, writeback, _) = created.into_parts();
    let OpenTarget::Descriptor(file) = target else {
        panic!("expected descriptor");
    };
    writeback.unwrap().commit(file.as_raw_fd()).unwrap();

    assert!(
        filesystem
            .prepare_open(logical, libc::O_CREAT | libc::O_EXCL | libc::O_RDWR, 0o600,)
            .is_err()
    );
    let truncated = filesystem
        .prepare_open(logical, libc::O_RDWR | libc::O_TRUNC, 0)
        .unwrap();
    let OpenTarget::Descriptor(file) = truncated.target() else {
        panic!("expected descriptor");
    };
    assert_eq!(file.metadata().unwrap().len(), 0);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn encrypted_descriptors_preserve_the_requested_access_mode() {
    let (root, filesystem) = fixture("access-mode");
    let logical = Path::new("/tmp/agora-vfs-access-mode");
    let mut created = filesystem
        .prepare_open(logical, libc::O_CREAT | libc::O_WRONLY, 0o600)
        .unwrap();
    let OpenTarget::Descriptor(file) = created.target_mut() else {
        panic!("expected encrypted descriptor");
    };
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
        libc::O_WRONLY
    );
    assert_eq!(
        unsafe { libc::read(file.as_raw_fd(), std::ptr::null_mut(), 0) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
    file.write_all(b"contents").unwrap();
    filesystem.commit_open(&mut created).unwrap();
    let (target, writeback, _) = created.into_parts();
    let OpenTarget::Descriptor(file) = target else {
        panic!("expected encrypted descriptor");
    };
    writeback.unwrap().commit(file.as_raw_fd()).unwrap();

    let reopened = filesystem.prepare_open(logical, libc::O_RDONLY, 0).unwrap();
    let OpenTarget::Descriptor(file) = reopened.target() else {
        panic!("expected encrypted descriptor");
    };
    assert_eq!(
        unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE,
        libc::O_RDONLY
    );
    assert_eq!(
        unsafe { libc::write(file.as_raw_fd(), std::ptr::null(), 0) },
        -1
    );
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EBADF)
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn encrypted_write_opens_do_not_wait_for_each_other() {
    let (root, filesystem) = fixture("concurrent-write-open");
    let logical = Path::new("/tmp/agora-vfs-write-lock");
    let mut created = filesystem
        .prepare_open(logical, libc::O_CREAT | libc::O_RDWR, 0o600)
        .unwrap();
    filesystem.commit_open(&mut created).unwrap();
    let (target, writeback, _) = created.into_parts();
    let OpenTarget::Descriptor(file) = target else {
        panic!("expected descriptor");
    };
    writeback.unwrap().commit(file.as_raw_fd()).unwrap();
    let first = filesystem.prepare_open(logical, libc::O_RDWR, 0).unwrap();
    let second = filesystem.prepare_open(logical, libc::O_RDWR, 0).unwrap();
    drop(first);
    drop(second);
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn encrypted_open_rejects_missing_files_and_keeps_directories_as_paths() {
    let (root, filesystem) = fixture("types");
    assert!(
        filesystem
            .prepare_open(Path::new("/tmp/agora-vfs-missing"), libc::O_RDONLY, 0)
            .is_err()
    );

    let directory = root
        .parent()
        .unwrap()
        .join(format!("agora-vfs-directory-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let prepared = filesystem
        .prepare_open(&directory, libc::O_RDONLY, 0)
        .unwrap();
    assert!(matches!(prepared.target(), OpenTarget::Path(_)));
    std::fs::remove_dir_all(directory).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn plain_vfs_delegates_overlay_operations_without_writeback() {
    let directory = std::env::temp_dir().join(format!("agora-vfs-plain-{}", uuid::Uuid::new_v4()));
    let root = directory.join("fs");
    let lower = directory.join("lower");
    std::fs::create_dir_all(&lower).unwrap();
    let source = lower.join("source");
    std::fs::write(&source, b"plain").unwrap();
    let filesystem = VirtualFilesystem::plain(&root).unwrap();

    let prepared = filesystem.prepare_open(&source, libc::O_RDONLY, 0).unwrap();
    let OpenTarget::Path(mapped) = prepared.target() else {
        panic!("plain filesystem should expose a mapped path");
    };
    assert_eq!(mapped, &source);
    assert_eq!(std::fs::read(mapped).unwrap(), b"plain");
    assert_eq!(filesystem.prepare_metadata(&source, true).unwrap().1, None);

    let created = lower.join("created");
    let staged = filesystem.stage_write(&created, true).unwrap();
    std::fs::write(staged.destination(), b"created").unwrap();
    filesystem.commit_write(staged).unwrap();
    assert_eq!(
        std::fs::read(filesystem.prepare_read(&created).unwrap()).unwrap(),
        b"created"
    );

    let child = lower.join("directory");
    filesystem.create_directory(&child, 0o700).unwrap();
    assert!(filesystem.prepare_directory(&child).unwrap().is_dir());
    assert!(filesystem.directory_view(&child).unwrap().lower().is_none());
    let renamed = lower.join("renamed");
    filesystem.rename(&created, &renamed).unwrap();
    filesystem.remove(&renamed, false).unwrap();
    assert!(filesystem.prepare_read(&renamed).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}
