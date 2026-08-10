use super::*;
use crate::filesystem::broker::protocol::{BackingPath, ByteRange, Request, Response};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::OwnedFd;
use std::sync::{Arc, Barrier, mpsc};
use std::thread;
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
fn completed_single_handle_writes_are_merged_until_the_batch_deadline() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("batched", b"abcdefgh");
    let (handle, plaintext) = fixture.open(&path, b"abcdefgh", true);
    let write_id = "11111111111111111111111111111111";
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: handle.clone(),
                    write_id: write_id.to_string(),
                    range: ByteRange::new(2, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );
    write_all_at(&plaintext, b"WXYZ", 2).unwrap();
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::FinishWrite {
                    handle: handle.clone(),
                    write_id: write_id.to_string(),
                    range: ByteRange::new(2, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );

    assert_eq!(fixture.decrypt(&path), b"abcdefgh");
    assert!(fixture.broker.writeback_pending());
    let pending_since = lock(&lock(&fixture.broker.handles).get(&handle).unwrap().handle)
        .pending_since
        .unwrap();
    fixture.broker.flush_due(pending_since).unwrap();
    assert!(fixture.broker.writeback_pending());
    fixture
        .broker
        .flush_due(Instant::now() + WRITEBACK_DELAY)
        .unwrap();
    assert!(!fixture.broker.writeback_pending());
    assert_eq!(fixture.decrypt(&path), b"abWXYZgh");
}

#[test]
fn completed_writes_are_visible_to_an_existing_peer_before_reply() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("peer-finish", b"abcdefgh");
    let (writer, plaintext) = fixture.open(&path, b"abcdefgh", true);
    let (_reader, peer) = fixture.open(&path, b"abcdefgh", false);
    let write_id = "11111111111111111111111111111111";
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: writer.clone(),
                    write_id: write_id.to_string(),
                    range: ByteRange::new(2, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );
    write_all_at(&plaintext, b"WXYZ", 2).unwrap();
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::FinishWrite {
                    handle: writer,
                    write_id: write_id.to_string(),
                    range: ByteRange::new(2, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );

    let mut contents = [0_u8; 8];
    read_exact_at(&peer, &mut contents, 0).unwrap();
    assert_eq!(&contents, b"abWXYZgh");
    assert_eq!(fixture.decrypt(&path), b"abWXYZgh");
}

#[test]
fn opening_a_peer_imports_pending_writes_before_reply() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("peer-open", b"abcdefgh");
    let (writer, plaintext) = fixture.open(&path, b"abcdefgh", true);
    let write_id = "11111111111111111111111111111111";
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: writer.clone(),
                    write_id: write_id.to_string(),
                    range: ByteRange::new(2, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );
    write_all_at(&plaintext, b"WXYZ", 2).unwrap();
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::FinishWrite {
                    handle: writer,
                    write_id: write_id.to_string(),
                    range: ByteRange::new(2, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_eq!(fixture.decrypt(&path), b"abcdefgh");

    let (_reader, peer) = fixture.open(&path, b"abcdefgh", false);

    let mut contents = [0_u8; 8];
    read_exact_at(&peer, &mut contents, 0).unwrap();
    assert_eq!(&contents, b"abWXYZgh");
    assert_eq!(fixture.decrypt(&path), b"abWXYZgh");
}

#[test]
fn concurrent_syncs_for_different_files_do_not_deadlock() {
    const FILE_COUNT: usize = 16;

    let fixture = Arc::new(Fixture::new());
    let mut handles = Vec::with_capacity(FILE_COUNT);
    for index in 0..FILE_COUNT {
        let path = fixture.encrypted(&format!("independent-{index}"), b"data");
        let (handle, _plaintext) = fixture.open(&path, b"data", true);
        handles.push(handle);
    }

    let barrier = Arc::new(Barrier::new(FILE_COUNT + 1));
    let (sender, receiver) = mpsc::channel();
    let mut threads = Vec::with_capacity(FILE_COUNT);
    for handle in handles {
        let fixture = Arc::clone(&fixture);
        let barrier = Arc::clone(&barrier);
        let sender = sender.clone();
        threads.push(thread::spawn(move || {
            barrier.wait();
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
            sender.send(response).unwrap();
        }));
    }
    drop(sender);
    barrier.wait();

    let deadline = Instant::now() + Duration::from_secs(2);
    for _ in 0..FILE_COUNT {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert_eq!(
            receiver
                .recv_timeout(remaining)
                .expect("concurrent local filesystem sync deadlocked"),
            Response::Success
        );
    }
    for thread in threads {
        thread.join().unwrap();
    }
}

#[test]
fn peer_sync_does_not_overwrite_a_reserved_plaintext_range() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("concurrent", b"abcdefgh");
    let (first_id, first) = fixture.open(&path, b"abcdefgh", true);
    let (second_id, second) = fixture.open(&path, b"abcdefgh", true);
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: second_id.clone(),
                    write_id: "11111111111111111111111111111111".to_string(),
                    range: ByteRange::new(4, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );
    write_all_at(&second, b"ZZ", 4).unwrap();
    write_all_at(&first, b"AAAAAA", 0).unwrap();

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle: first_id,
                    ranges: vec![ByteRange::new(0, 6).unwrap()],
                    durable: false,
                },
                None,
            )
            .response,
        Response::Success
    );
    let mut peer = [0_u8; 8];
    read_exact_at(&second, &mut peer, 0).unwrap();
    assert_eq!(&peer, b"AAAAZZgh");

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::FinishWrite {
                    handle: second_id.clone(),
                    write_id: "11111111111111111111111111111111".to_string(),
                    range: ByteRange::new(4, 6).unwrap(),
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
                Request::Sync {
                    handle: second_id,
                    ranges: vec![ByteRange::new(4, 6).unwrap()],
                    durable: true,
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_eq!(fixture.decrypt(&path), b"AAAAZZgh");
}

#[test]
fn cancelling_one_write_does_not_drop_another_active_reservation() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("independent-reservations", b"abcdefgh");
    let (handle, _plaintext) = fixture.open(&path, b"abcdefgh", true);
    for (write_id, range) in [
        (
            "11111111111111111111111111111111",
            ByteRange::new(0, 2).unwrap(),
        ),
        (
            "22222222222222222222222222222222",
            ByteRange::new(4, 6).unwrap(),
        ),
    ] {
        assert_eq!(
            fixture
                .broker
                .handle(
                    Request::BeginWrite {
                        handle: handle.clone(),
                        write_id: write_id.to_string(),
                        range,
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
                Request::CancelWrite {
                    handle: handle.clone(),
                    write_id: "11111111111111111111111111111111".to_string(),
                },
                None,
            )
            .response,
        Response::Success
    );

    let local = lock(&fixture.broker.handles)
        .get(&handle)
        .unwrap()
        .handle
        .clone();
    let assert_second_is_active = || {
        let local = lock(&local);
        assert_eq!(local.active_writes.len(), 1);
        assert_eq!(
            local.active_writes.get("22222222222222222222222222222222"),
            Some(&ByteRange::new(4, 6).unwrap())
        );
    };
    assert_second_is_active();

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle,
                    ranges: vec![ByteRange::new(0, 2).unwrap()],
                    durable: false,
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_second_is_active();
}

#[test]
fn overlapping_completed_write_waits_for_the_remaining_reservation() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("overlapping-reservations", b"abcdefgh");
    let (handle, plaintext) = fixture.open(&path, b"abcdefgh", true);
    for (write_id, range) in [
        (
            "11111111111111111111111111111111",
            ByteRange::new(2, 6).unwrap(),
        ),
        (
            "22222222222222222222222222222222",
            ByteRange::new(4, 8).unwrap(),
        ),
    ] {
        assert_eq!(
            fixture
                .broker
                .handle(
                    Request::BeginWrite {
                        handle: handle.clone(),
                        write_id: write_id.to_string(),
                        range,
                    },
                    None,
                )
                .response,
            Response::Success
        );
    }
    write_all_at(&plaintext, b"WXYZ", 2).unwrap();
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::FinishWrite {
                    handle: handle.clone(),
                    write_id: "11111111111111111111111111111111".to_string(),
                    range: ByteRange::new(2, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );
    write_all_at(&plaintext, b"1234", 4).unwrap();

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle: handle.clone(),
                    ranges: Vec::new(),
                    durable: false,
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_eq!(fixture.decrypt(&path), b"abWXefgh");
    let local = lock(&fixture.broker.handles)
        .get(&handle)
        .unwrap()
        .handle
        .clone();
    assert_eq!(
        lock(&local).pending_writes.ranges,
        vec![ByteRange::new(4, 6).unwrap()]
    );

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::FinishWrite {
                    handle: handle.clone(),
                    write_id: "22222222222222222222222222222222".to_string(),
                    range: ByteRange::new(4, 8).unwrap(),
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
                Request::Sync {
                    handle,
                    ranges: Vec::new(),
                    durable: true,
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_eq!(fixture.decrypt(&path), b"abWX1234");
}

#[test]
fn final_close_flushes_an_abandoned_active_write() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("abandoned-write", b"abcdefgh");
    let (handle, plaintext) = fixture.open(&path, b"abcdefgh", true);
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: handle.clone(),
                    write_id: "11111111111111111111111111111111".to_string(),
                    range: ByteRange::new(0, u64::MAX).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );
    write_all_at(&plaintext, b"XYZ", 8).unwrap();

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Close {
                    handle,
                    ranges: Vec::new()
                },
                None
            )
            .response,
        Response::Success
    );

    assert_eq!(fixture.decrypt(&path), b"abcdefghXYZ");
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
        let local = lock(&fixture.broker.handles)
            .get(&handle)
            .unwrap()
            .handle
            .clone();
        let mut local = lock(&local);
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
fn request_cache_replays_and_claims_one_open_handle() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("cached-open", b"data");
    let request = Request::Open {
        path: BackingPath::from_path(&path),
        writable: true,
    };
    let descriptor: OwnedFd = {
        let mut plaintext = tempfile::tempfile().unwrap();
        plaintext.write_all(b"data").unwrap();
        plaintext.into()
    };
    let first = fixture.broker.handle_request(
        "open-request".to_string(),
        request.clone(),
        Some(descriptor),
    );
    let descriptor: OwnedFd = {
        let mut plaintext = tempfile::tempfile().unwrap();
        plaintext.write_all(b"data").unwrap();
        plaintext.into()
    };
    let replay =
        fixture
            .broker
            .handle_request("open-request".to_string(), request, Some(descriptor));

    assert_eq!(first.response, replay.response);
    assert_eq!(lock(&fixture.broker.handles).len(), 1);
    assert!(matches!(
        fixture
            .broker
            .handle_request(
                "open-request".to_string(),
                Request::Close {
                    handle: "different".to_string(),
                    ranges: Vec::new(),
                },
                None,
            )
            .response,
        Response::Error {
            errno: libc::EPROTO,
            ..
        }
    ));
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Claim {
                    request_id: "open-request".to_string(),
                },
                None,
            )
            .response,
        Response::Success
    );
    if let Some(CachedRequest::Completed { completed_at, .. }) = lock(&fixture.broker.requests)
        .entries
        .get_mut("open-request")
    {
        *completed_at = Instant::now() - REQUEST_CACHE_TTL - Duration::from_secs(1);
    }
    fixture.broker.expire_requests();
    assert_eq!(lock(&fixture.broker.handles).len(), 1);
}

#[test]
fn expired_unclaimed_open_is_aborted_without_writeback() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("abandoned-open", b"data");
    let mut plaintext = tempfile::tempfile().unwrap();
    plaintext.write_all(b"data").unwrap();
    let response = fixture.broker.handle_request(
        "abandoned-request".to_string(),
        Request::Open {
            path: BackingPath::from_path(&path),
            writable: true,
        },
        Some(plaintext.into()),
    );
    assert!(matches!(response.response, Response::Open { .. }));
    if let Some(CachedRequest::Completed { completed_at, .. }) = lock(&fixture.broker.requests)
        .entries
        .get_mut("abandoned-request")
    {
        *completed_at = Instant::now() - REQUEST_CACHE_TTL - Duration::from_secs(1);
    }

    fixture.broker.expire_requests();

    assert!(lock(&fixture.broker.handles).is_empty());
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
                    ranges: Vec::new(),
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
            .handle(
                Request::Close {
                    handle,
                    ranges: Vec::new()
                },
                None
            )
            .response,
        Response::Success
    );
}

#[test]
fn failed_fork_retains_can_be_released_atomically() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("failed-fork", b"data");
    let (handle, _plaintext) = fixture.open(&path, b"data", true);

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Retain {
                    handles: vec![handle.clone()],
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
                Request::ReleaseRetain {
                    handles: vec![handle.clone(), handle.clone()],
                },
                None,
            )
            .response,
        Response::Success
    );
    let local = lock(&fixture.broker.handles)
        .get(&handle)
        .unwrap()
        .handle
        .clone();
    assert_eq!(lock(&local).references, 1);
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
                    ranges: Vec::new(),
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
            .handle(
                Request::Close {
                    handle,
                    ranges: Vec::new(),
                },
                None,
            )
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
                    ranges: Vec::new(),
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
            .handle(
                Request::Close {
                    handle,
                    ranges: Vec::new()
                },
                None
            )
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
                    ranges: Vec::new(),
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_eq!(fixture.decrypt(&path), b"0abcdef789");

    let closed = lock(&fixture.broker.handles)
        .get(&handle)
        .unwrap()
        .handle
        .clone();
    let mut closed = lock(&closed);
    closed.closed_at = Some(Instant::now() - CLOSED_HANDLE_TTL - Duration::from_secs(1));
    drop(closed);
    fixture.broker.expire_closed();
    assert!(!lock(&fixture.broker.handles).contains_key(&handle));
}

#[test]
fn closed_handle_retention_is_bounded_before_the_ttl_expires() {
    const EXPECTED_LIMIT: usize = 128;
    let fixture = Fixture::new();
    let path = fixture.encrypted("bounded", b"data");

    for _ in 0..=EXPECTED_LIMIT {
        let (handle, _plaintext) = fixture.open(&path, b"data", false);
        assert_eq!(
            fixture
                .broker
                .handle(
                    Request::Close {
                        handle,
                        ranges: Vec::new()
                    },
                    None
                )
                .response,
            Response::Success
        );
    }

    assert!(lock(&fixture.broker.handles).len() <= EXPECTED_LIMIT);
}

#[test]
fn retain_overflow_is_atomic_and_internal_error_helpers_preserve_context() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("overflow", b"data");
    let (handle, _plaintext) = fixture.open(&path, b"data", true);
    let local = lock(&fixture.broker.handles)
        .get(&handle)
        .unwrap()
        .handle
        .clone();
    lock(&local).references = usize::MAX;

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
    assert_eq!(lock(&local).references, usize::MAX);

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
