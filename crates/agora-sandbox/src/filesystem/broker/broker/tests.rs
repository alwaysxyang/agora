use super::*;
use crate::filesystem::broker::protocol::{BackingPath, ByteRange, Request, Response};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::time::{Duration, Instant};

struct Fixture {
    root: tempfile::TempDir,
    cipher: FileCipher,
    broker: LocalBroker,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let cipher = FileCipher::derive(b"key", b"0123456789abcdef").unwrap();
        let broker = LocalBroker::new(root.path(), cipher.clone()).unwrap();
        Self {
            root,
            cipher,
            broker,
        }
    }

    fn encrypted(&self, name: &str, contents: &[u8]) -> std::path::PathBuf {
        let path = self.root.path().join(name);
        let mut plaintext = tempfile::tempfile().unwrap();
        plaintext.write_all(contents).unwrap();
        self.cipher.encrypt(&mut plaintext, &path).unwrap();
        path
    }

    fn open(&self, path: &Path, contents: &[u8], writable: bool) -> (String, File) {
        let mut plaintext = tempfile::tempfile().unwrap();
        plaintext.write_all(contents).unwrap();
        let retained = plaintext.try_clone().unwrap();
        let descriptor: OwnedFd = retained.into();
        let reply = self.broker.handle(
            Request::Open {
                path: BackingPath::from_path(path),
                writable,
            },
            Some(descriptor),
        );
        let Response::Open { handle } = reply.response else {
            panic!("unexpected open response: {:?}", reply.response);
        };
        (handle, plaintext)
    }

    fn decrypt(&self, path: &Path) -> Vec<u8> {
        let mut plaintext = tempfile::tempfile().unwrap();
        self.cipher.decrypt(path, &mut plaintext).unwrap();
        plaintext.seek(SeekFrom::Start(0)).unwrap();
        let mut output = Vec::new();
        plaintext.read_to_end(&mut output).unwrap();
        output
    }
}

fn assert_error(response: Response, errno: libc::c_int) {
    assert!(
        matches!(response, Response::Error { errno: actual, .. } if actual == errno),
        "unexpected response: {response:?}"
    );
}

#[test]
fn sync_encrypts_only_reported_ranges_and_propagates_them_to_peer_handles() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("file", b"abcdef");
    let (first_id, first) = fixture.open(&path, b"abcdef", true);
    let (_second_id, second) = fixture.open(&path, b"abcdef", true);
    write_all_at(&first, b"XY", 2).unwrap();

    let reply = fixture.broker.handle(
        Request::Sync {
            handle: first_id,
            ranges: vec![ByteRange::new(2, 4).unwrap()],
            durable: true,
        },
        None,
    );

    assert_eq!(reply.response, Response::Success);
    assert_eq!(fixture.decrypt(&path), b"abXYef");
    let mut peer = [0_u8; 6];
    read_exact_at(&second, &mut peer, 0).unwrap();
    assert_eq!(&peer, b"abXYef");
}

#[test]
fn sync_ignores_ranges_beyond_eof_and_reports_plaintext_read_failures() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("range-errors", b"data");
    let (handle, _) = fixture.open(&path, b"data", true);

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle: handle.clone(),
                    ranges: vec![ByteRange::new(100, 101).unwrap()],
                    durable: false,
                },
                None,
            )
            .response,
        Response::Success
    );

    {
        let mut handles = lock(&fixture.broker.handles);
        let local = handles.get_mut(&handle).unwrap();
        local.plaintext = File::open(fixture.root.path()).unwrap();
        local.baseline = PlaintextIdentity::from_metadata(&local.plaintext.metadata().unwrap());
    }
    let response = fixture
        .broker
        .handle(
            Request::Sync {
                handle,
                ranges: vec![ByteRange::new(0, 1).unwrap()],
                durable: false,
            },
            None,
        )
        .response;
    assert!(
        matches!(response, Response::Error { message, .. } if message.contains("failed to read local plaintext range"))
    );
}

#[test]
fn broker_protocol_errors_preserve_their_message() {
    let error = BrokerError::protocol_error(anyhow::anyhow!("invalid backing path"));

    assert_eq!(error.errno, libc::EPROTO);
    assert_eq!(error.message, "invalid backing path");
}

#[test]
fn final_flush_persists_ranges_registered_by_writable_mappings() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("mapped", b"abcdef");
    let (handle, plaintext) = fixture.open(&path, b"abcdef", true);
    write_all_at(&plaintext, b"mapped", 0).unwrap();
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::PotentiallyDirty {
                    handle,
                    range: ByteRange::new(0, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );

    fixture.broker.flush_all().unwrap();

    assert_eq!(fixture.decrypt(&path), b"mapped");
}

#[test]
fn mapping_registration_survives_an_intermediate_sync_for_crash_recovery() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("mapped-twice", b"abcdef");
    let (handle, plaintext) = fixture.open(&path, b"abcdef", true);
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::PotentiallyDirty {
                    handle: handle.clone(),
                    range: ByteRange::new(0, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );
    write_all_at(&plaintext, b"first!", 0).unwrap();
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle,
                    ranges: vec![ByteRange::new(0, 6).unwrap()],
                    durable: true,
                },
                None,
            )
            .response,
        Response::Success
    );
    write_all_at(&plaintext, b"second", 0).unwrap();

    fixture.broker.flush_all().unwrap();

    assert_eq!(fixture.decrypt(&path), b"second");
}

#[test]
fn retained_handle_remains_usable_after_one_process_closes_it() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("forked", b"before");
    let (handle, plaintext) = fixture.open(&path, b"before", true);

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Retain {
                    handles: vec![handle.clone(), handle.clone()],
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Close {
                    handle: handle.clone(),
                },
                None,
            )
            .response,
        Response::Success
    );
    write_all_at(&plaintext, b"after!", 0).unwrap();
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle: handle.clone(),
                    ranges: vec![ByteRange::new(0, 6).unwrap()],
                    durable: true,
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_eq!(fixture.decrypt(&path), b"after!");
    assert_eq!(
        fixture
            .broker
            .handle(Request::Close { handle }, None)
            .response,
        Response::Success
    );
}

#[test]
fn broker_rejects_invalid_descriptors_paths_and_handle_operations() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("valid", b"data");
    assert_error(
        fixture
            .broker
            .handle(
                Request::Open {
                    path: BackingPath::from_path(&path),
                    writable: true,
                },
                None,
            )
            .response,
        libc::EPROTO,
    );

    let descriptor: OwnedFd = tempfile::tempfile().unwrap().into();
    assert_error(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle: "missing".to_string(),
                    ranges: Vec::new(),
                    durable: false,
                },
                Some(descriptor),
            )
            .response,
        libc::EPROTO,
    );
    assert_error(
        fixture
            .broker
            .handle(
                Request::PotentiallyDirty {
                    handle: "missing".to_string(),
                    range: ByteRange::new(1, 2).unwrap(),
                },
                None,
            )
            .response,
        libc::EBADF,
    );
    assert_error(
        fixture
            .broker
            .handle(
                Request::Retain {
                    handles: vec!["missing".to_string()],
                },
                None,
            )
            .response,
        libc::EBADF,
    );
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Close {
                    handle: "missing".to_string(),
                },
                None,
            )
            .response,
        Response::Success
    );

    let missing = fixture.root.path().join("missing");
    let descriptor: OwnedFd = tempfile::tempfile().unwrap().into();
    assert_error(
        fixture
            .broker
            .handle(
                Request::Open {
                    path: BackingPath::from_path(&missing),
                    writable: true,
                },
                Some(descriptor),
            )
            .response,
        libc::ENOENT,
    );

    let outside = tempfile::tempdir().unwrap();
    let outside_path = outside.path().join("encrypted");
    let mut outside_plaintext = tempfile::tempfile().unwrap();
    outside_plaintext.write_all(b"data").unwrap();
    fixture
        .cipher
        .encrypt(&mut outside_plaintext, &outside_path)
        .unwrap();
    let descriptor: OwnedFd = outside_plaintext.into();
    assert_error(
        fixture
            .broker
            .handle(
                Request::Open {
                    path: BackingPath::from_path(&outside_path),
                    writable: true,
                },
                Some(descriptor),
            )
            .response,
        libc::EACCES,
    );

    let descriptor: OwnedFd = tempfile::tempfile().unwrap().into();
    assert_error(
        fixture
            .broker
            .handle(
                Request::Open {
                    path: BackingPath::from_path(&path),
                    writable: true,
                },
                Some(descriptor),
            )
            .response,
        libc::EPROTO,
    );
}

#[test]
fn read_only_handles_reject_dirty_ranges_and_changed_snapshots() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("readonly", b"before");
    let (handle, plaintext) = fixture.open(&path, b"before", false);

    assert_error(
        fixture
            .broker
            .handle(
                Request::PotentiallyDirty {
                    handle: handle.clone(),
                    range: ByteRange::new(0, 1).unwrap(),
                },
                None,
            )
            .response,
        libc::EBADF,
    );
    assert_error(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle: handle.clone(),
                    ranges: vec![ByteRange::new(0, 1).unwrap()],
                    durable: false,
                },
                None,
            )
            .response,
        libc::EBADF,
    );

    write_all_at(&plaintext, b"after!", 0).unwrap();
    assert_error(
        fixture
            .broker
            .handle(Request::Close { handle }, None)
            .response,
        libc::EBADF,
    );
    assert_eq!(fixture.decrypt(&path), b"before");
}

#[test]
fn final_close_detects_unreported_growth_and_shrinkage() {
    let fixture = Fixture::new();
    let original = vec![b'a'; COPY_BUFFER_SIZE + 17];
    let path = fixture.encrypted("resized", &original);
    let (handle, plaintext) = fixture.open(&path, &original, true);
    let grown = original.len() as u64 + 31;
    plaintext.set_len(grown).unwrap();
    write_all_at(&plaintext, b"tail", grown - 4).unwrap();

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Close {
                    handle: handle.clone(),
                },
                None,
            )
            .response,
        Response::Success
    );
    let decrypted = fixture.decrypt(&path);
    assert_eq!(decrypted.len(), grown as usize);
    assert_eq!(&decrypted[grown as usize - 4..], b"tail");

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle: handle.clone(),
                    ranges: vec![ByteRange::new(0, 4).unwrap()],
                    durable: false,
                },
                None,
            )
            .response,
        Response::Success,
        "a lost close response can be retried through an idempotent sync"
    );
    plaintext.set_len(9).unwrap();
    assert_eq!(
        fixture
            .broker
            .handle(Request::Close { handle }, None)
            .response,
        Response::Success
    );
    assert_eq!(fixture.decrypt(&path), vec![b'a'; 9]);
}

#[test]
fn dirty_ranges_are_merged_and_expired_handles_are_reclaimed() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("ranges", b"0123456789");
    let (handle, plaintext) = fixture.open(&path, b"0123456789", true);
    write_all_at(&plaintext, b"abcdef", 1).unwrap();
    for (start, end) in [(4, 7), (1, 3), (3, 5)] {
        assert_eq!(
            fixture
                .broker
                .handle(
                    Request::PotentiallyDirty {
                        handle: handle.clone(),
                        range: ByteRange::new(start, end).unwrap(),
                    },
                    None,
                )
                .response,
            Response::Success
        );
    }
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Close {
                    handle: handle.clone(),
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_eq!(fixture.decrypt(&path), b"0abcdef789");

    let mut handles = lock(&fixture.broker.handles);
    let closed = handles.get_mut(&handle).unwrap();
    closed.closed_at = Some(Instant::now() - CLOSED_HANDLE_TTL - Duration::from_secs(1));
    drop(handles);
    fixture.broker.expire_closed();
    assert!(!lock(&fixture.broker.handles).contains_key(&handle));
}

#[test]
fn retain_overflow_is_atomic_and_internal_error_helpers_preserve_context() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("overflow", b"data");
    let (handle, _plaintext) = fixture.open(&path, b"data", true);
    lock(&fixture.broker.handles)
        .get_mut(&handle)
        .unwrap()
        .references = usize::MAX;

    assert_error(
        fixture
            .broker
            .handle(
                Request::Retain {
                    handles: vec![handle.clone()],
                },
                None,
            )
            .response,
        libc::EOVERFLOW,
    );
    assert_eq!(
        lock(&fixture.broker.handles)
            .get(&handle)
            .unwrap()
            .references,
        usize::MAX
    );

    let error = BrokerError::io("context", std::io::Error::other("failure"));
    assert_eq!(error.errno, libc::EIO);
    assert!(error.message.contains("context"));
    let chained = BrokerError::anyhow(
        "encrypt",
        anyhow::Error::new(std::io::Error::from_raw_os_error(libc::ENOSPC)),
    );
    assert_eq!(chained.errno, libc::ENOSPC);
    assert!(chained.into_io().to_string().contains("encrypt"));

    let file = tempfile::tempfile().unwrap();
    assert_eq!(
        read_exact_at(&file, &mut [0_u8; 1], 0).unwrap_err().kind(),
        std::io::ErrorKind::UnexpectedEof
    );

    let mut ranges = RangeSet::default();
    ranges.insert(ByteRange { start: 3, end: 3 });
    ranges.insert(ByteRange { start: 3, end: 6 });
    ranges.insert(ByteRange { start: 1, end: 4 });
    assert_eq!(ranges.ranges, vec![ByteRange { start: 1, end: 6 }]);
}
