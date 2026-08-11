use super::*;
use crate::filesystem::broker::protocol::{BackingPath, ByteRange, Request, Response};
use crate::filesystem::crypto::CONTENT_HEADER_SIZE;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
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

    fn open(&self, path: &Path, writable: bool) -> (String, File) {
        let mut reply = self.broker.handle(
            Request::Open {
                path: BackingPath::from_path(path),
                flags: if writable {
                    libc::O_RDWR
                } else {
                    libc::O_RDONLY
                },
            },
            None,
        );
        let Response::Open { handle, .. } = reply.response else {
            panic!("unexpected open response: {:?}", reply.response);
        };
        assert_eq!(reply.descriptors.len(), 3);
        let content = reply.descriptors.remove(0);
        (handle, content)
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
    let (first_id, first) = fixture.open(&path, true);
    let (_second_id, second) = fixture.open(&path, true);
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
fn subsequent_opens_reuse_the_live_plaintext_without_decrypting_again() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("reused-plaintext", b"plaintext");
    let (_first, first) = fixture.open(&path, false);
    let ciphertext = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&path)
        .unwrap();
    let offset = CONTENT_HEADER_SIZE as u64 + 12;
    let mut byte = [0_u8; 1];
    ciphertext.read_exact_at(&mut byte, offset).unwrap();
    byte[0] ^= 0xff;
    ciphertext.write_all_at(&byte, offset).unwrap();

    let (_second, second) = fixture.open(&path, false);
    let mut contents = [0_u8; 9];
    read_exact_at(&second, &mut contents, 0).unwrap();

    assert_eq!(&contents, b"plaintext");
    let mut first_contents = [0_u8; 9];
    read_exact_at(&first, &mut first_contents, 0).unwrap();
    assert_eq!(first_contents, contents);
}

#[test]
fn truncation_remains_dirty_until_a_durable_sync() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("truncate-durability", b"plaintext");
    let reply = fixture.broker.handle(
        Request::Open {
            path: BackingPath::from_path(&path),
            flags: libc::O_RDWR | libc::O_TRUNC,
        },
        None,
    );
    let Response::Open { handle, .. } = reply.response else {
        panic!("unexpected open response: {:?}", reply.response);
    };
    let local = lock(&fixture.broker.handles).get(&handle).unwrap().clone();
    let shared = Arc::clone(&lock(&local).shared);
    assert!(lock(&shared.inner).needs_durable_sync);

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
    assert!(!lock(&shared.inner).needs_durable_sync);
    assert!(fixture.decrypt(&path).is_empty());
}

#[test]
fn independent_opens_share_content_vnode_but_not_lock_description() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("independent-locks", b"plaintext");
    let mut first = fixture.broker.handle(
        Request::Open {
            path: BackingPath::from_path(&path),
            flags: libc::O_RDWR,
        },
        None,
    );
    let mut second = fixture.broker.handle(
        Request::Open {
            path: BackingPath::from_path(&path),
            flags: libc::O_RDWR,
        },
        None,
    );
    assert!(matches!(first.response, Response::Open { .. }));
    assert!(matches!(second.response, Response::Open { .. }));
    assert_eq!(first.descriptors.len(), 3);
    assert_eq!(second.descriptors.len(), 3);

    let first_content = first.descriptors.remove(0);
    let second_content = second.descriptors.remove(0);
    let first_lock = first.descriptors.remove(1);
    let second_lock = second.descriptors.remove(1);
    let first_content = first_content.metadata().unwrap();
    let second_content = second_content.metadata().unwrap();
    assert_eq!(first_content.dev(), second_content.dev());
    assert_eq!(first_content.ino(), second_content.ino());
    let first_lock_metadata = first_lock.metadata().unwrap();
    let second_lock_metadata = second_lock.metadata().unwrap();
    assert_eq!(first_lock_metadata.dev(), second_lock_metadata.dev());
    assert_eq!(first_lock_metadata.ino(), second_lock_metadata.ino());

    assert_eq!(
        unsafe { libc::flock(first_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        0
    );
    assert_eq!(
        unsafe { libc::flock(second_lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) },
        -1
    );
    assert_eq!(unsafe { *libc::__error() }, libc::EWOULDBLOCK);
    assert_eq!(
        unsafe { libc::flock(first_lock.as_raw_fd(), libc::LOCK_UN) },
        0
    );
}

#[test]
fn completed_single_handle_writes_are_merged_until_the_batch_deadline() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("batched", b"abcdefgh");
    let (handle, plaintext) = fixture.open(&path, true);
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
    let local = lock(&fixture.broker.handles).get(&handle).unwrap().clone();
    let pending_since = lock(&local).pending_since.unwrap();
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
fn completed_writes_are_visible_to_an_existing_peer_before_writeback() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("peer-finish", b"abcdefgh");
    let (writer, plaintext) = fixture.open(&path, true);
    let (_reader, peer) = fixture.open(&path, false);
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
    assert_eq!(fixture.decrypt(&path), b"abcdefgh");
}

#[test]
fn opening_a_peer_reuses_pending_shared_plaintext_without_forcing_writeback() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("peer-open", b"abcdefgh");
    let (writer, plaintext) = fixture.open(&path, true);
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

    let (_reader, peer) = fixture.open(&path, false);

    let mut contents = [0_u8; 8];
    read_exact_at(&peer, &mut contents, 0).unwrap();
    assert_eq!(&contents, b"abWXYZgh");
    assert_eq!(fixture.decrypt(&path), b"abcdefgh");
}

#[test]
fn concurrent_syncs_for_different_files_do_not_deadlock() {
    const FILE_COUNT: usize = 16;

    let fixture = Arc::new(Fixture::new());
    let mut handles = Vec::with_capacity(FILE_COUNT);
    for index in 0..FILE_COUNT {
        let path = fixture.encrypted(&format!("independent-{index}"), b"data");
        let (handle, _plaintext) = fixture.open(&path, true);
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
fn writes_to_the_same_shared_file_are_serialized() {
    let fixture = Arc::new(Fixture::new());
    let path = fixture.encrypted("serialized", b"abcdefgh");
    let (first, _first_file) = fixture.open(&path, true);
    let (second, _second_file) = fixture.open(&path, true);
    let first_write = "11111111111111111111111111111111";
    let second_write = "22222222222222222222222222222222";
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: first.clone(),
                    write_id: first_write.to_string(),
                    range: ByteRange::new(0, 2).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );

    let (sender, receiver) = mpsc::channel();
    let waiting_fixture = Arc::clone(&fixture);
    let waiting_handle = second.clone();
    let waiter = thread::spawn(move || {
        let response = waiting_fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: waiting_handle,
                    write_id: second_write.to_string(),
                    range: ByteRange::new(4, 6).unwrap(),
                },
                None,
            )
            .response;
        sender.send(response).unwrap();
    });
    assert!(receiver.recv_timeout(Duration::from_millis(20)).is_err());

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::FinishWrite {
                    handle: first,
                    write_id: first_write.to_string(),
                    range: ByteRange::new(0, 2).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
        Response::Success
    );
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::CancelWrite {
                    handle: second,
                    write_id: second_write.to_string(),
                },
                None,
            )
            .response,
        Response::Success
    );
    waiter.join().unwrap();
}

#[test]
fn append_reserves_the_current_shared_end_of_file() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("append", b"abcdefgh");
    let (handle, plaintext) = fixture.open(&path, true);
    let write_id = "11111111111111111111111111111111";

    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginAppend {
                    handle: handle.clone(),
                    write_id: write_id.to_string(),
                },
                None,
            )
            .response,
        Response::Offset { offset: 8 }
    );
    write_all_at(&plaintext, b"XYZ", 8).unwrap();
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::FinishWrite {
                    handle: handle.clone(),
                    write_id: write_id.to_string(),
                    range: ByteRange::new(8, 11).unwrap(),
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
                Request::BeginAppend {
                    handle: handle.clone(),
                    write_id: "22222222222222222222222222222222".to_string(),
                },
                None,
            )
            .response,
        Response::Offset { offset: 11 }
    );
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::CancelWrite {
                    handle,
                    write_id: "22222222222222222222222222222222".to_string(),
                },
                None,
            )
            .response,
        Response::Success
    );
}

#[test]
fn final_close_flushes_an_abandoned_active_write() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("abandoned-write", b"abcdefgh");
    let (handle, plaintext) = fixture.open(&path, true);
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
    let (handle, _) = fixture.open(&path, true);

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
        let local = lock(&fixture.broker.handles).get(&handle).unwrap().clone();
        let shared = Arc::clone(&lock(&local).shared);
        let mut shared = lock(&shared.inner);
        shared.plaintext = File::open(fixture.root.path()).unwrap();
        shared.baseline = PlaintextIdentity::from_metadata(&shared.plaintext.metadata().unwrap());
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
        flags: libc::O_RDWR,
    };
    let first = fixture
        .broker
        .handle_request("open-request".to_string(), request.clone(), None);
    let replay = fixture
        .broker
        .handle_request("open-request".to_string(), request, None);

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
    let response = fixture.broker.handle_request(
        "abandoned-request".to_string(),
        Request::Open {
            path: BackingPath::from_path(&path),
            flags: libc::O_RDWR,
        },
        None,
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
    let (handle, plaintext) = fixture.open(&path, true);
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
fn final_flush_abandons_all_peer_writes_before_synchronizing() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("peer-active-final-flush", b"abcdefgh");
    let (first_handle, first_file) = fixture.open(&path, true);
    let (second_handle, second_file) = fixture.open(&path, true);
    let first_flushed = lock(&fixture.broker.handles)
        .keys()
        .next()
        .expect("a live handle exists")
        .clone();
    let (active_handle, active_file) = if first_flushed == first_handle {
        (second_handle, second_file)
    } else {
        (first_handle, first_file)
    };
    let write_id = "11111111111111111111111111111111";
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: active_handle,
                    write_id: write_id.to_string(),
                    range: ByteRange::new(2, 6).unwrap(),
                },
                None,
            )
            .response,
        Response::Success
    );
    write_all_at(&active_file, b"WXYZ", 2).unwrap();

    fixture.broker.flush_all().unwrap();

    assert_eq!(fixture.decrypt(&path), b"abWXYZgh");
}

#[test]
fn mapping_registration_survives_an_intermediate_sync_until_close() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("mapped-twice", b"abcdef");
    let (handle, plaintext) = fixture.open(&path, true);
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
    let (handle, plaintext) = fixture.open(&path, true);

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
    let (handle, _plaintext) = fixture.open(&path, true);

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
    let local = lock(&fixture.broker.handles).get(&handle).unwrap().clone();
    assert_eq!(lock(&local).references, 1);
}

#[test]
fn broker_rejects_invalid_descriptors_paths_and_handle_operations() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("valid", b"data");
    let (handle, _plaintext) = fixture.open(&path, true);
    let invalid_range = ByteRange { start: 1, end: 1 };
    assert_error(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: handle.clone(),
                    write_id: "11111111111111111111111111111111".to_string(),
                    range: invalid_range,
                },
                None,
            )
            .response,
        libc::EPROTO,
    );
    assert_error(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle,
                    ranges: vec![invalid_range],
                    durable: false,
                },
                None,
            )
            .response,
        libc::EPROTO,
    );
    let open_descriptor: OwnedFd = tempfile::tempfile().unwrap().into();
    assert_error(
        fixture
            .broker
            .handle(
                Request::Open {
                    path: BackingPath::from_path(&path),
                    flags: libc::O_RDWR,
                },
                Some(open_descriptor),
            )
            .response,
        libc::EPROTO,
    );
    let sync_descriptor: OwnedFd = tempfile::tempfile().unwrap().into();
    assert_error(
        fixture
            .broker
            .handle(
                Request::Sync {
                    handle: "missing".to_string(),
                    ranges: Vec::new(),
                    durable: false,
                },
                Some(sync_descriptor),
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
    assert_error(
        fixture
            .broker
            .handle(
                Request::Open {
                    path: BackingPath::from_path(&missing),
                    flags: libc::O_RDWR,
                },
                None,
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
    drop(outside_plaintext);
    assert_error(
        fixture
            .broker
            .handle(
                Request::Open {
                    path: BackingPath::from_path(&outside_path),
                    flags: libc::O_RDWR,
                },
                None,
            )
            .response,
        libc::EACCES,
    );

    assert_error(
        fixture
            .broker
            .handle(
                Request::Open {
                    path: BackingPath::from_path(&path),
                    flags: libc::O_ACCMODE,
                },
                None,
            )
            .response,
        libc::EINVAL,
    );
}

#[test]
fn read_only_handles_reject_dirty_ranges_and_changed_snapshots() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("readonly", b"before");
    let (handle, plaintext) = fixture.open(&path, false);

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
    let (handle, plaintext) = fixture.open(&path, true);
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
    let (handle, plaintext) = fixture.open(&path, true);
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

    let closed = lock(&fixture.broker.handles).get(&handle).unwrap().clone();
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
        let (handle, _plaintext) = fixture.open(&path, false);
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
    let (handle, _plaintext) = fixture.open(&path, true);
    let local = lock(&fixture.broker.handles).get(&handle).unwrap().clone();
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

#[test]
fn broker_rejects_conflicting_write_ids_and_read_only_write_protocols() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("write-protocol", b"abcdefgh");
    let (read_only, _reader) = fixture.open(&path, false);
    let range = ByteRange::new(1, 3).unwrap();
    let write_id = "11111111111111111111111111111111";

    for request in [
        Request::BeginWrite {
            handle: read_only.clone(),
            write_id: write_id.to_string(),
            range,
        },
        Request::BeginAppend {
            handle: read_only.clone(),
            write_id: write_id.to_string(),
        },
        Request::FinishWrite {
            handle: read_only,
            write_id: write_id.to_string(),
            range,
        },
    ] {
        assert_error(fixture.broker.handle(request, None).response, libc::EBADF);
    }

    let (writable, _writer) = fixture.open(&path, true);
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: writable.clone(),
                    write_id: write_id.to_string(),
                    range,
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
                Request::BeginWrite {
                    handle: writable.clone(),
                    write_id: write_id.to_string(),
                    range,
                },
                None,
            )
            .response,
        Response::Success,
        "an idempotent retry must retain the original reservation"
    );
    assert_error(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: writable.clone(),
                    write_id: write_id.to_string(),
                    range: ByteRange::new(3, 5).unwrap(),
                },
                None,
            )
            .response,
        libc::EPROTO,
    );
    assert_error(
        fixture
            .broker
            .handle(
                Request::FinishWrite {
                    handle: writable.clone(),
                    write_id: write_id.to_string(),
                    range: ByteRange::new(0, 4).unwrap(),
                },
                None,
            )
            .response,
        libc::EPROTO,
    );
    assert_error(
        fixture
            .broker
            .handle(
                Request::FinishWrite {
                    handle: writable.clone(),
                    write_id: "22222222222222222222222222222222".to_string(),
                    range,
                },
                None,
            )
            .response,
        libc::EPROTO,
    );

    let append_id = "33333333333333333333333333333333";
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginAppend {
                    handle: writable.clone(),
                    write_id: append_id.to_string(),
                },
                None,
            )
            .response,
        Response::Offset { offset: 8 }
    );
    assert_error(
        fixture
            .broker
            .handle(
                Request::BeginAppend {
                    handle: writable.clone(),
                    write_id: append_id.to_string(),
                },
                None,
            )
            .response,
        libc::EPROTO,
    );
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::CancelWrite {
                    handle: writable.clone(),
                    write_id: append_id.to_string(),
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
                Request::CancelWrite {
                    handle: writable,
                    write_id: "missing".to_string(),
                },
                None,
            )
            .response,
        Response::Success
    );
}

#[test]
fn abort_and_release_retain_clean_up_only_valid_live_handles() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("abort", b"data");
    let (handle, _writer) = fixture.open(&path, true);
    let write_id = "11111111111111111111111111111111";
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::BeginWrite {
                    handle: handle.clone(),
                    write_id: write_id.to_string(),
                    range: ByteRange::new(0, 4).unwrap(),
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
                Request::Abort {
                    handle: handle.clone(),
                },
                None,
            )
            .response,
        Response::Success
    );
    assert!(!lock(&fixture.broker.handles).contains_key(&handle));
    assert_eq!(
        fixture
            .broker
            .handle(
                Request::Abort {
                    handle: "missing".to_string(),
                },
                None,
            )
            .response,
        Response::Success
    );
    assert_error(
        fixture
            .broker
            .handle(
                Request::Claim {
                    request_id: "missing".to_string(),
                },
                None,
            )
            .response,
        libc::EPROTO,
    );

    let (released, _reader) = fixture.open(&path, false);
    let local = lock(&fixture.broker.handles)
        .get(&released)
        .unwrap()
        .clone();
    lock(&local).references = 0;
    assert_error(
        fixture
            .broker
            .handle(
                Request::ReleaseRetain {
                    handles: vec![released],
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
                Request::ReleaseRetain {
                    handles: vec!["missing".to_string()],
                },
                None,
            )
            .response,
        libc::EBADF,
    );
}

#[test]
fn request_cache_waiters_claim_rules_and_capacity_are_deterministic() {
    let completion = Arc::new(RequestCompletion::default());
    let waiting = Arc::clone(&completion);
    let (sender, receiver) = mpsc::channel();
    let waiter = thread::spawn(move || sender.send(waiting.wait()).unwrap());
    assert!(receiver.recv_timeout(Duration::from_millis(20)).is_err());
    completion.complete(Response::Success);
    assert_eq!(
        receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
        Response::Success
    );
    waiter.join().unwrap();

    let fingerprint = [1_u8; 32];
    let mut cache = RequestCache::default();
    assert!(matches!(
        cache.begin("pending".to_string(), fingerprint),
        CacheDecision::Execute
    ));
    assert!(matches!(
        cache.begin("pending".to_string(), fingerprint),
        CacheDecision::Wait(_)
    ));
    assert!(matches!(
        cache.begin("pending".to_string(), [2_u8; 32]),
        CacheDecision::Reject
    ));
    assert_eq!(cache.claim("pending"), None);
    assert!(cache
        .complete("missing".to_string(), Response::Success, Instant::now())
        .is_empty());
    assert!(cache
        .complete("pending".to_string(), Response::Success, Instant::now())
        .is_empty());
    assert_eq!(cache.claim("pending"), None);
    assert!(matches!(
        cache.begin("pending".to_string(), fingerprint),
        CacheDecision::Replay(Response::Success)
    ));

    let open_id = "unclaimed".to_string();
    assert!(matches!(
        cache.begin(open_id.clone(), fingerprint),
        CacheDecision::Execute
    ));
    let completed_at = Instant::now() - REQUEST_CACHE_TTL - Duration::from_secs(1);
    assert!(
        cache
            .complete(
            open_id,
            Response::Open {
                handle: "abandoned-handle".to_string(),
                device: 1,
                inode: 2,
                links: 1,
            },
            completed_at,
        )
            .is_empty()
    );
    assert_eq!(
        cache.prune(Instant::now()),
        vec!["abandoned-handle".to_string()]
    );

    let now = Instant::now();
    for index in 0..=REQUEST_CACHE_CAPACITY {
        cache.entries.insert(
            format!("capacity-{index}"),
            CachedRequest::Completed {
                fingerprint,
                response: Response::Success,
                completed_at: now,
                claimed: true,
            },
        );
    }
    assert!(cache.prune(now).is_empty());
    assert_eq!(
        cache
            .entries
            .values()
            .filter(|entry| matches!(entry, CachedRequest::Completed { .. }))
            .count(),
        REQUEST_CACHE_CAPACITY
    );
}

#[test]
fn truncating_a_live_shared_file_updates_every_descriptor_and_ciphertext() {
    let fixture = Fixture::new();
    let path = fixture.encrypted("live-truncate", b"plaintext");
    let (_first, first) = fixture.open(&path, true);
    let mut reply = fixture.broker.handle(
        Request::Open {
            path: BackingPath::from_path(&path),
            flags: libc::O_RDWR | libc::O_TRUNC,
        },
        None,
    );
    let Response::Open { handle, .. } = reply.response else {
        panic!("unexpected truncate response: {:?}", reply.response);
    };
    let second = reply.descriptors.remove(0);

    assert_eq!(first.metadata().unwrap().len(), 0);
    assert_eq!(second.metadata().unwrap().len(), 0);
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
    assert!(fixture.decrypt(&path).is_empty());
}
