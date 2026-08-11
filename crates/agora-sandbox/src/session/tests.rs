use super::protocol::{ClientMessage, WireOsString, read_frame, write_frame};
use std::ffi::OsString;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::PermissionsExt;

#[test]
fn wire_os_string_round_trips_non_utf8_bytes() {
    let original = OsString::from_vec(vec![b'a', 0xff, b'z']);

    let encoded = serde_json::to_vec(&WireOsString::from(original.clone())).unwrap();
    let decoded: WireOsString = serde_json::from_slice(&encoded).unwrap();

    assert_eq!(decoded.into_os_string().as_bytes(), original.as_bytes());
}

#[tokio::test]
async fn session_frame_round_trips_a_typed_message() {
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let message = ClientMessage::Join {
        protocol: 1,
        build: "build-a".to_string(),
        config: "config-a".to_string(),
    };

    write_frame(&mut writer, &message).await.unwrap();
    let decoded: ClientMessage = read_frame(&mut reader).await.unwrap();

    assert_eq!(decoded, message);
}

#[tokio::test]
async fn session_frame_rejects_a_payload_over_the_control_limit() {
    let (mut writer, _reader) = tokio::io::duplex(16);
    let oversized = ClientMessage::Join {
        protocol: 1,
        build: "b".repeat(crate::ipc::MAX_FRAME_SIZE),
        config: String::new(),
    };

    let error = write_frame(&mut writer, &oversized).await.unwrap_err();

    assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
}

#[test]
fn session_paths_are_stable_short_and_owner_only() {
    let root = tempfile::tempdir().unwrap();
    let workdir = root.path().join("workspace");
    std::fs::create_dir(&workdir).unwrap();

    let first = super::startup::SessionPaths::resolve(&workdir).unwrap();
    let second = super::startup::SessionPaths::resolve(&workdir.join(".")).unwrap();

    assert_eq!(first.socket(), second.socket());
    assert!(first.socket().as_os_str().as_bytes().len() < 100);
    assert_eq!(
        first
            .socket()
            .parent()
            .unwrap()
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        first.startup_lock(),
        workdir
            .canonicalize()
            .unwrap()
            .join("runtime/session-start.lock")
    );
}

#[test]
fn session_startup_lock_excludes_a_second_daemon_candidate() {
    let root = tempfile::tempdir().unwrap();
    let workdir = root.path().join("workspace");
    std::fs::create_dir(&workdir).unwrap();
    let paths = super::startup::SessionPaths::resolve(&workdir).unwrap();

    let first = super::startup::StartupLock::try_acquire(paths.startup_lock())
        .unwrap()
        .expect("first candidate acquires the startup lock");
    assert!(
        super::startup::StartupLock::try_acquire(paths.startup_lock())
            .unwrap()
            .is_none()
    );
    drop(first);
    assert!(
        super::startup::StartupLock::try_acquire(paths.startup_lock())
            .unwrap()
            .is_some()
    );
}

#[test]
fn inherited_daemon_descriptors_are_restored_close_on_exec() {
    let descriptor = tempfile::tempfile().unwrap().into_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags & !libc::FD_CLOEXEC) },
        0
    );

    let descriptor = super::startup::inherited_descriptor(descriptor, "test").unwrap();
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
    assert_ne!(flags & libc::FD_CLOEXEC, 0);
}
