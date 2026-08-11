use super::*;
use crate::filesystem::FileCipher;
use crate::filesystem::broker::{LocalClient, LocalController};
use std::collections::HashMap;
use std::ffi::CString;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

fn c_path(path: &Path) -> CString {
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

async fn broker_runtime(directory: &Path) -> (FilesystemHookRuntime, LocalController) {
    const KEY: &[u8] = b"broker-hook-test-key";
    const SALT: &[u8] = b"0123456789abcdef";

    let root = directory.join("workdir/fs");
    let mut runtime = FilesystemHookRuntime::new_encrypted(&root, KEY, SALT).unwrap();
    let controller = LocalController::start(
        &root,
        FileCipher::derive(KEY, SALT).unwrap(),
        &directory.join("runtime"),
    )
    .await
    .unwrap();
    runtime.local = Some(LocalClient::new(
        controller.runtime().socket(),
        controller.runtime().token(),
    ));
    (runtime, controller)
}

#[test]
fn recursive_write_hooks_delegate_to_native_vectored_and_positioned_writes() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("writes");
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&path)
        .unwrap();
    let descriptor = file.as_raw_fd();
    let first = b"ab";
    let second = b"cd";
    let vectors = [
        libc::iovec {
            iov_base: first.as_ptr().cast_mut().cast(),
            iov_len: first.len(),
        },
        libc::iovec {
            iov_base: second.as_ptr().cast_mut().cast(),
            iov_len: second.len(),
        },
    ];

    unsafe {
        let _guard = FilesystemHookGuard::enter().unwrap();
        assert_eq!(
            agora_sandbox_write(descriptor, first.as_ptr().cast(), first.len()),
            first.len() as libc::ssize_t
        );
        assert_eq!(
            agora_sandbox_pwrite(descriptor, second.as_ptr().cast(), second.len(), 4),
            second.len() as libc::ssize_t
        );
        assert_eq!(
            agora_sandbox_writev(descriptor, vectors.as_ptr(), vectors.len() as libc::c_int),
            4
        );
        assert_eq!(
            agora_sandbox_pwritev(
                descriptor,
                vectors.as_ptr(),
                vectors.len() as libc::c_int,
                8,
            ),
            4
        );
        assert_eq!(libc::lseek(descriptor, 0, libc::SEEK_SET), 0);
        let mut read_left = [0_u8; 2];
        let mut read_right = [0_u8; 2];
        let reads = [
            libc::iovec {
                iov_base: read_left.as_mut_ptr().cast(),
                iov_len: read_left.len(),
            },
            libc::iovec {
                iov_base: read_right.as_mut_ptr().cast(),
                iov_len: read_right.len(),
            },
        ];
        assert_eq!(
            agora_sandbox_readv(descriptor, reads.as_ptr(), reads.len() as libc::c_int),
            4
        );
        assert_eq!((&read_left, &read_right), (b"ab", b"ab"));
        assert_eq!(
            agora_sandbox_preadv(descriptor, reads.as_ptr(), reads.len() as libc::c_int, 8),
            4
        );
        assert_eq!((&read_left, &read_right), (b"ab", b"cd"));
    }

    assert_eq!(std::fs::read(path).unwrap(), b"ababcd\0\0abcd");
}

#[test]
fn nocancel_hooks_delegate_to_matching_native_symbols_during_recursion() {
    let file = tempfile::tempfile().unwrap();
    let descriptor = file.as_raw_fd();
    let first = b"ab";
    let left = b"c";
    let right = b"d";
    let writes = [
        libc::iovec {
            iov_base: left.as_ptr().cast_mut().cast(),
            iov_len: left.len(),
        },
        libc::iovec {
            iov_base: right.as_ptr().cast_mut().cast(),
            iov_len: right.len(),
        },
    ];

    unsafe {
        let _guard = FilesystemHookGuard::enter().unwrap();
        assert_eq!(
            agora_sandbox_write_nocancel(descriptor, first.as_ptr().cast(), first.len()),
            2
        );
        assert_eq!(
            agora_sandbox_writev_nocancel(descriptor, writes.as_ptr(), writes.len() as libc::c_int),
            2
        );
        assert_eq!(
            agora_sandbox_pwrite_nocancel(descriptor, b"ef".as_ptr().cast(), 2, 4),
            2
        );
        assert_eq!(
            agora_sandbox_pwritev_nocancel(
                descriptor,
                writes.as_ptr(),
                writes.len() as libc::c_int,
                6,
            ),
            2
        );
        assert_eq!(libc::lseek(descriptor, 0, libc::SEEK_SET), 0);

        let mut sequential = [0_u8; 2];
        assert_eq!(
            agora_sandbox_read_nocancel(descriptor, sequential.as_mut_ptr().cast(), 2),
            2
        );
        assert_eq!(&sequential, b"ab");
        let mut vector_left = [0_u8; 1];
        let mut vector_right = [0_u8; 1];
        let reads = [
            libc::iovec {
                iov_base: vector_left.as_mut_ptr().cast(),
                iov_len: vector_left.len(),
            },
            libc::iovec {
                iov_base: vector_right.as_mut_ptr().cast(),
                iov_len: vector_right.len(),
            },
        ];
        assert_eq!(
            agora_sandbox_readv_nocancel(descriptor, reads.as_ptr(), reads.len() as libc::c_int),
            2
        );
        assert_eq!((&vector_left, &vector_right), (b"c", b"d"));
        assert_eq!(
            agora_sandbox_pread_nocancel(descriptor, sequential.as_mut_ptr().cast(), 2, 4),
            2
        );
        assert_eq!(&sequential, b"ef");
        assert_eq!(
            agora_sandbox_preadv_nocancel(
                descriptor,
                reads.as_ptr(),
                reads.len() as libc::c_int,
                6,
            ),
            2
        );
        assert_eq!((&vector_left, &vector_right), (b"c", b"d"));
    }
}

#[test]
fn sequential_write_ranges_reject_invalid_descriptors_and_offsets() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("ranges");
    let file = std::fs::File::create(path).unwrap();

    assert_eq!(sequential_write_range(-1, None, 1), None);
    assert_eq!(sequential_write_range(file.as_raw_fd(), None, -1), None);
    assert_eq!(sequential_write_range(file.as_raw_fd(), None, 1), None);
}

#[test]
fn sequential_write_ranges_cover_concurrent_shared_offset_progress() {
    let file = tempfile::tempfile().unwrap();
    let descriptor = file.as_raw_fd();
    unsafe {
        assert_eq!(libc::lseek(descriptor, 20, libc::SEEK_SET), 20);
    }

    assert_eq!(
        sequential_write_range(descriptor, Some(0), 10),
        Some((0, 20))
    );
}

#[test]
fn sequential_writes_reserve_the_full_file_for_shared_offset_progress() {
    assert_eq!(
        sequential_write_reservation(4),
        LocalByteRange::new(0, u64::MAX).ok()
    );
    assert_eq!(sequential_write_reservation(0), None);
}

#[test]
fn positional_write_reservations_remain_conservative_on_length_overflow() {
    assert_eq!(
        positional_write_reservation(8, usize::MAX),
        LocalByteRange::new(8, u64::MAX).ok()
    );
    assert_eq!(positional_write_reservation(-1, 1), None);
    assert_eq!(positional_write_reservation(8, 0), None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_managed_descriptors_preserve_complete_posix_io_semantics() {
    let directory = tempfile::tempdir().unwrap();
    let (runtime, controller) = broker_runtime(directory.path()).await;
    let logical = directory.path().join("logical.txt");
    let path = c_path(&logical);

    with_test_runtime(&runtime, || unsafe {
        let descriptor = super::super::agora_sandbox_open_with_mode(
            path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o600,
        );
        assert!(descriptor >= 0);
        assert_eq!(
            agora_sandbox_write(descriptor, b"abcdefghij".as_ptr().cast(), 10),
            10
        );
        assert_eq!(agora_sandbox_lseek(descriptor, 0, libc::SEEK_SET), 0);

        let mut sequential = [0_u8; 2];
        assert_eq!(
            agora_sandbox_read(descriptor, sequential.as_mut_ptr().cast(), 2),
            2
        );
        assert_eq!(&sequential, b"ab");

        let mut vector_left = [0_u8; 2];
        let mut vector_right = [0_u8; 2];
        let reads = [
            libc::iovec {
                iov_base: vector_left.as_mut_ptr().cast(),
                iov_len: vector_left.len(),
            },
            libc::iovec {
                iov_base: vector_right.as_mut_ptr().cast(),
                iov_len: vector_right.len(),
            },
        ];
        assert_eq!(
            agora_sandbox_readv(descriptor, reads.as_ptr(), reads.len() as libc::c_int),
            4
        );
        assert_eq!((&vector_left, &vector_right), (b"cd", b"ef"));

        assert_eq!(
            agora_sandbox_pread(descriptor, sequential.as_mut_ptr().cast(), 2, 8),
            2
        );
        assert_eq!(&sequential, b"ij");
        let mut positioned_left = [0_u8; 1];
        let mut positioned_right = [0_u8; 2];
        let positioned_reads = [
            libc::iovec {
                iov_base: positioned_left.as_mut_ptr().cast(),
                iov_len: positioned_left.len(),
            },
            libc::iovec {
                iov_base: positioned_right.as_mut_ptr().cast(),
                iov_len: positioned_right.len(),
            },
        ];
        assert_eq!(
            agora_sandbox_preadv(
                descriptor,
                positioned_reads.as_ptr(),
                positioned_reads.len() as libc::c_int,
                0,
            ),
            3
        );
        assert_eq!((&positioned_left, &positioned_right), (b"a", b"bc"));

        assert_eq!(
            agora_sandbox_pwrite(descriptor, b"XY".as_ptr().cast(), 2, 2),
            2
        );
        let write_left = b"Q";
        let write_right = b"RS";
        let writes = [
            libc::iovec {
                iov_base: write_left.as_ptr().cast_mut().cast(),
                iov_len: write_left.len(),
            },
            libc::iovec {
                iov_base: write_right.as_ptr().cast_mut().cast(),
                iov_len: write_right.len(),
            },
        ];
        assert_eq!(
            agora_sandbox_pwritev(descriptor, writes.as_ptr(), writes.len() as libc::c_int, 7),
            3
        );
        assert_eq!(agora_sandbox_lseek(descriptor, -2, libc::SEEK_END), 8);
        assert_eq!(
            agora_sandbox_read_nocancel(descriptor, sequential.as_mut_ptr().cast(), 2),
            2
        );
        assert_eq!(&sequential, b"RS");
        assert_eq!(
            agora_sandbox_write_nocancel(descriptor, b"!".as_ptr().cast(), 1),
            1
        );
        assert_eq!(
            agora_sandbox_writev_nocancel(descriptor, writes.as_ptr(), writes.len() as libc::c_int,),
            3
        );
        assert_eq!(
            agora_sandbox_pwrite_nocancel(descriptor, b"A".as_ptr().cast(), 1, 0),
            1
        );
        assert_eq!(
            agora_sandbox_pwritev_nocancel(
                descriptor,
                writes.as_ptr(),
                writes.len() as libc::c_int,
                1,
            ),
            3
        );

        assert_eq!(agora_sandbox_lseek(descriptor, 0, libc::SEEK_SET), 0);
        let mut byte = [0_u8; 1];
        assert_eq!(
            agora_sandbox_read_nocancel(descriptor, byte.as_mut_ptr().cast(), 1),
            1
        );
        assert_eq!(&byte, b"A");
        assert_eq!(
            agora_sandbox_readv_nocancel(
                descriptor,
                positioned_reads.as_ptr(),
                positioned_reads.len() as libc::c_int,
            ),
            3
        );
        assert_eq!((&positioned_left, &positioned_right), (b"Q", b"RS"));
        assert_eq!(
            agora_sandbox_pread_nocancel(descriptor, byte.as_mut_ptr().cast(), 1, 4),
            1
        );
        assert_eq!(&byte, b"e");
        assert_eq!(
            agora_sandbox_preadv_nocancel(
                descriptor,
                positioned_reads.as_ptr(),
                positioned_reads.len() as libc::c_int,
                5,
            ),
            3
        );
        assert_eq!((&positioned_left, &positioned_right), (b"f", b"gQ"));

        let native_flags = libc::fcntl(descriptor, libc::F_GETFL);
        assert!(native_flags >= 0);
        assert_eq!(
            super::super::agora_sandbox_fcntl_commit_setfl(
                descriptor,
                libc::O_APPEND | libc::O_NONBLOCK,
            ),
            0
        );
        assert_eq!(
            super::super::agora_sandbox_fcntl_setfl_argument(
                descriptor,
                libc::O_APPEND | libc::O_NONBLOCK,
            ),
            0
        );
        let logical_flags = super::super::agora_sandbox_fcntl_getfl(descriptor, native_flags);
        assert_ne!(logical_flags & libc::O_APPEND, 0);
        assert_ne!(logical_flags & libc::O_NONBLOCK, 0);
        assert_eq!(agora_sandbox_lseek(descriptor, 0, libc::SEEK_SET), 0);
        assert_eq!(agora_sandbox_write(descriptor, b"Z".as_ptr().cast(), 1), 1);
        assert_eq!(local_sequential_write(descriptor, Some(0), |_| 0), Some(0));

        let duplicate = super::super::agora_sandbox_dup(descriptor);
        assert!(duplicate >= 0);
        assert_eq!(agora_sandbox_lseek(descriptor, 0, libc::SEEK_SET), 0);
        assert_eq!(
            agora_sandbox_read(duplicate, byte.as_mut_ptr().cast(), 1),
            1
        );
        assert_eq!(&byte, b"A");
        assert_eq!(
            agora_sandbox_read(descriptor, byte.as_mut_ptr().cast(), 1),
            1
        );
        assert_eq!(&byte, b"Q");
        assert_eq!(super::super::agora_sandbox_fsync(descriptor), 0);
        assert_eq!(super::super::agora_sandbox_close(duplicate), 0);
        assert_eq!(super::super::agora_sandbox_close(descriptor), 0);

        let reader = super::super::agora_sandbox_open_with_mode(path.as_ptr(), libc::O_RDONLY, 0);
        assert!(reader >= 0);
        assert_eq!(agora_sandbox_write(reader, b"x".as_ptr().cast(), 1), -1);
        assert_eq!(*libc::__error(), libc::EBADF);
        assert_ne!(super::super::agora_sandbox_lock_descriptor(reader), reader);
        assert_eq!(super::super::agora_sandbox_close(reader), 0);

        let writer = super::super::agora_sandbox_open_with_mode(path.as_ptr(), libc::O_WRONLY, 0);
        assert!(writer >= 0);
        assert_eq!(agora_sandbox_read(writer, byte.as_mut_ptr().cast(), 1), -1);
        assert_eq!(*libc::__error(), libc::EBADF);
        assert_eq!(
            agora_sandbox_pread(writer, byte.as_mut_ptr().cast(), 1, 0),
            -1
        );
        assert_eq!(*libc::__error(), libc::EBADF);
        let writer_read = libc::iovec {
            iov_base: byte.as_mut_ptr().cast(),
            iov_len: byte.len(),
        };
        assert_eq!(agora_sandbox_preadv(writer, &writer_read, 1, 0), -1);
        assert_eq!(*libc::__error(), libc::EBADF);
        assert_eq!(super::super::agora_sandbox_close(writer), 0);

        let guarded_logical = directory.path().join("guarded.txt");
        let guarded_path = c_path(&guarded_logical);
        let guard = 0xa60a_5a7d_b001_u64;
        let guarded = super::super::agora_sandbox_guarded_open_with_mode(
            guarded_path.as_ptr(),
            &guard,
            (1_u32 << 0) | (1_u32 << 1),
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o600,
        );
        assert!(guarded >= 0);
        assert_eq!(
            agora_sandbox_guarded_write(guarded, &guard, b"guard".as_ptr().cast(), 5),
            5
        );
        assert_eq!(
            agora_sandbox_guarded_writev(guarded, &guard, writes.as_ptr(), -1),
            -1
        );
        assert_eq!(*libc::__error(), libc::EINVAL);
        assert_eq!(
            super::super::agora_sandbox_guarded_close(guarded, &guard),
            0
        );
    });

    controller.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn broker_managed_io_failures_preserve_errno_and_recoverable_state() {
    let directory = tempfile::tempdir().unwrap();
    let (runtime, controller) = broker_runtime(directory.path()).await;
    let logical = directory.path().join("failures.txt");
    let path = c_path(&logical);

    with_test_runtime(&runtime, || unsafe {
        let descriptor = super::super::agora_sandbox_open_with_mode(
            path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o600,
        );
        assert!(descriptor >= 0);
        assert_eq!(
            agora_sandbox_write(descriptor, b"0123456789".as_ptr().cast(), 10),
            10
        );

        let mut byte = [0_u8; 1];
        let mut vector_byte = [0_u8; 1];
        let read_vector = libc::iovec {
            iov_base: vector_byte.as_mut_ptr().cast(),
            iov_len: vector_byte.len(),
        };
        let write_vector = libc::iovec {
            iov_base: b"x".as_ptr().cast_mut().cast(),
            iov_len: 1,
        };
        assert_eq!(
            sandbox_read_with(descriptor, byte.as_mut_ptr().cast(), 1, None, None,),
            -1
        );
        assert_eq!(
            sandbox_pread_with(descriptor, byte.as_mut_ptr().cast(), 1, 0, None),
            -1
        );
        assert_eq!(
            sandbox_readv_with(descriptor, &read_vector, 1, None, None),
            -1
        );
        assert_eq!(
            sandbox_preadv_with(descriptor, &read_vector, 1, 0, None),
            -1
        );
        assert_eq!(
            sandbox_write_with(descriptor, b"x".as_ptr().cast(), 1, None, None),
            -1
        );
        assert_eq!(
            sandbox_pwrite_with(descriptor, b"x".as_ptr().cast(), 1, 0, None),
            -1
        );
        assert_eq!(
            sandbox_writev_with(descriptor, &write_vector, 1, None, None),
            -1
        );
        assert_eq!(
            sandbox_pwritev_with(descriptor, &write_vector, 1, 0, None),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOSYS);

        assert_eq!(
            sandbox_read_with(
                descriptor,
                byte.as_mut_ptr().cast(),
                1,
                original_read(),
                None,
            ),
            -1
        );
        assert_eq!(
            sandbox_readv_with(descriptor, &read_vector, 1, original_readv(), None),
            -1
        );
        assert_eq!(
            sandbox_write_with(descriptor, b"x".as_ptr().cast(), 1, original_write(), None,),
            -1
        );
        assert_eq!(
            sandbox_writev_with(descriptor, &write_vector, 1, original_writev(), None),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOSYS);

        let reservation = LocalByteRange::new(0, 1).unwrap();
        assert_eq!(
            tracked_write(
                descriptor,
                Some(reservation),
                || {
                    set_errno(libc::EAGAIN);
                    -1
                },
                |_| None,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::EAGAIN);
        assert_eq!(
            tracked_write(descriptor, Some(reservation), || 1, |_| Some((9, 10)),),
            1
        );

        let open = runtime.tracked_open(descriptor).unwrap();
        let registration = open.local.as_ref().unwrap();
        assert_eq!(
            *lock(&registration.dirty),
            vec![LocalByteRange::new(9, 10).unwrap()]
        );
        {
            let state = registration.state.lock().unwrap();
            state.set_offset(-1).unwrap();
        }
        assert_eq!(local_sequential_io(descriptor, false, |_| 0), Some(-1));
        assert_eq!(local_sequential_write(descriptor, Some(0), |_| 0), Some(-1));
        assert_eq!(local_sequential_write(descriptor, Some(1), |_| 0), Some(-1));
        assert_eq!(agora_sandbox_lseek(descriptor, 0, libc::SEEK_CUR), -1);
        assert_eq!(*libc::__error(), libc::EINVAL);
        {
            let state = registration.state.lock().unwrap();
            state.set_offset(libc::off_t::MAX).unwrap();
        }
        assert_eq!(local_sequential_io(descriptor, false, |_| 1), Some(-1));
        assert_eq!(*libc::__error(), libc::EOVERFLOW);
        {
            let state = registration.state.lock().unwrap();
            state.set_offset(0).unwrap();
        }
        assert_eq!(agora_sandbox_lseek(descriptor, -1, libc::SEEK_SET), -1);
        assert_eq!(*libc::__error(), libc::EINVAL);
        assert_eq!(agora_sandbox_lseek(descriptor, 0, -1), -1);
        assert_eq!(*libc::__error(), libc::EINVAL);

        assert_eq!(
            super::super::agora_sandbox_validate_content_fcntl(descriptor),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            super::super::agora_sandbox_flock(descriptor, libc::LOCK_EX | libc::LOCK_NB),
            0
        );
        assert_eq!(
            super::super::agora_sandbox_flock(descriptor, libc::LOCK_UN),
            0
        );
        set_descriptor_close_on_exec(descriptor, false).unwrap();
        super::super::agora_sandbox_fcntl_commit_setfd(descriptor);
        let inherited = runtime.inheritable_local_descriptors();
        assert_eq!(inherited.len(), 3);

        assert_eq!(libc::ftruncate(registration.state.as_raw_fd(), 0), 0);
        assert_eq!(local_sequential_io(descriptor, false, |_| 0), Some(-1));
        assert_eq!(local_sequential_write(descriptor, Some(1), |_| 0), Some(-1));
        assert!(!local_access_allowed(descriptor, false));
        assert_eq!(agora_sandbox_lseek(descriptor, 0, libc::SEEK_CUR), -1);
        assert_eq!(super::super::agora_sandbox_close(descriptor), 0);
    });

    controller.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn inherited_local_descriptors_restore_aliases_and_shared_offsets() {
    let directory = tempfile::tempdir().unwrap();
    let (runtime, controller) = broker_runtime(directory.path()).await;
    let logical = directory.path().join("inherited.txt");
    let path = c_path(&logical);

    let (descriptor, alias, encoded) = with_test_runtime(&runtime, || unsafe {
        let descriptor = super::super::agora_sandbox_open_with_mode(
            path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o600,
        );
        assert!(descriptor >= 0);
        assert_eq!(
            agora_sandbox_write(descriptor, b"inherit".as_ptr().cast(), 7),
            7
        );
        let alias = super::super::agora_sandbox_dup(descriptor);
        assert!(alias >= 0);
        set_descriptor_close_on_exec(descriptor, false).unwrap();
        set_descriptor_close_on_exec(alias, false).unwrap();
        let open = runtime.tracked_open(descriptor).unwrap();
        runtime.refresh_local_state_inheritance(&open);
        let encoded = runtime.encode_inherited_local_descriptors().unwrap();
        assert_eq!(
            serde_json::from_str::<InheritedLocalDescriptors>(&encoded)
                .unwrap()
                .descriptors
                .len(),
            2
        );
        (descriptor, alias, encoded)
    });

    let retained = runtime.retain_local_files_before_fork().unwrap();
    assert_eq!(retained.len(), 1);
    let mut inherited = serde_json::from_str::<InheritedLocalDescriptors>(&encoded).unwrap();
    let mut state_descriptors = HashMap::new();
    let mut lock_descriptors = HashMap::new();
    for inherited in &mut inherited.descriptors {
        inherited.descriptor = unsafe { libc::fcntl(inherited.descriptor, libc::F_DUPFD, 0) };
        assert!(inherited.descriptor >= 0);
        inherited.state_descriptor = *state_descriptors
            .entry(inherited.state_descriptor)
            .or_insert_with(|| unsafe {
                libc::fcntl(inherited.state_descriptor, libc::F_DUPFD, 0)
            });
        inherited.lock_descriptor = *lock_descriptors
            .entry(inherited.lock_descriptor)
            .or_insert_with(|| unsafe { libc::fcntl(inherited.lock_descriptor, libc::F_DUPFD, 0) });
        assert!(inherited.state_descriptor >= 0);
        assert!(inherited.lock_descriptor >= 0);
    }
    let restored_descriptors = inherited
        .descriptors
        .iter()
        .map(|descriptor| descriptor.descriptor)
        .collect::<Vec<_>>();
    let inherited = serde_json::to_string(&inherited).unwrap();

    let mut restored = FilesystemHookRuntime::new_encrypted(
        directory.path().join("workdir/fs"),
        b"broker-hook-test-key",
        b"0123456789abcdef",
    )
    .unwrap();
    restored.local = runtime.local.clone();
    restored.restore_inherited_local_descriptors(None);
    restored.restore_inherited_local_descriptors(Some("not-json"));
    let mut wrong_version = serde_json::from_str::<InheritedLocalDescriptors>(&inherited).unwrap();
    wrong_version.version = INHERITED_LOCAL_DESCRIPTOR_VERSION + 1;
    restored
        .restore_inherited_local_descriptors(Some(&serde_json::to_string(&wrong_version).unwrap()));
    restored.restore_inherited_local_descriptors(Some(&inherited));
    assert_eq!(lock(&restored.open_files).len(), 2);
    assert!(Arc::ptr_eq(
        &restored.tracked_open(restored_descriptors[0]).unwrap(),
        &restored.tracked_open(restored_descriptors[1]).unwrap(),
    ));

    with_test_runtime(&restored, || unsafe {
        assert_eq!(
            agora_sandbox_lseek(restored_descriptors[0], 0, libc::SEEK_SET),
            0
        );
        let mut content = [0_u8; 3];
        assert_eq!(
            agora_sandbox_read(
                restored_descriptors[1],
                content.as_mut_ptr().cast(),
                content.len(),
            ),
            3
        );
        assert_eq!(&content, b"inh");
        assert_eq!(
            super::super::agora_sandbox_close(restored_descriptors[0]),
            0
        );
        assert_eq!(
            super::super::agora_sandbox_close(restored_descriptors[1]),
            0
        );
    });
    with_test_runtime(&runtime, || unsafe {
        let mut next = [0_u8; 1];
        assert_eq!(
            agora_sandbox_read(descriptor, next.as_mut_ptr().cast(), 1),
            1
        );
        assert_eq!(&next, b"e");
        assert_eq!(super::super::agora_sandbox_close(alias), 0);
        assert_eq!(super::super::agora_sandbox_close(descriptor), 0);
    });

    controller.shutdown().await.unwrap();
}
