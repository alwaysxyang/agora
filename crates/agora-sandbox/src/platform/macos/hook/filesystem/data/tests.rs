use super::*;
use std::os::fd::AsRawFd;

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
    }

    assert_eq!(std::fs::read(path).unwrap(), b"ababcd\0\0abcd");
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
fn positional_write_reservations_remain_conservative_on_length_overflow() {
    assert_eq!(
        positional_write_reservation(8, usize::MAX),
        LocalByteRange::new(8, u64::MAX).ok()
    );
    assert_eq!(positional_write_reservation(-1, 1), None);
    assert_eq!(positional_write_reservation(8, 0), None);
}
