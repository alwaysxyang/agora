use super::*;
use crate::filesystem::FileCipher;
use crate::filesystem::broker::{LocalClient, LocalController};
use crate::hook::filesystem::data::{
    agora_sandbox_pwrite, agora_sandbox_pwritev, agora_sandbox_write, agora_sandbox_writev,
};
use crate::hook::filesystem::descriptor::agora_sandbox_close;
use crate::hook::filesystem::lifecycle::agora_sandbox_fork;
use crate::hook::filesystem::open::agora_sandbox_open_with_mode;
use std::ffi::CString;
use std::path::{Path, PathBuf};

struct BrokerFixture {
    _directory: tempfile::TempDir,
    lower: PathBuf,
    runtime: FilesystemHookRuntime,
    controller: LocalController,
}

impl BrokerFixture {
    async fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let lower = directory.path().join("lower");
        let root = directory.path().join("workdir/fs");
        std::fs::create_dir(&lower).unwrap();
        let mut runtime =
            FilesystemHookRuntime::new_encrypted(&root, b"mapping-test-key", b"0123456789abcdef")
                .unwrap();
        let cipher = FileCipher::derive(b"mapping-test-key", b"0123456789abcdef").unwrap();
        let controller =
            LocalController::start(&root, cipher, &directory.path().join("broker-runtime"))
                .await
                .unwrap();
        runtime.local = Some(LocalClient::new(
            controller.runtime().socket().to_path_buf(),
            controller.runtime().token().to_string(),
        ));
        Self {
            _directory: directory,
            lower,
            runtime,
            controller,
        }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.lower.join(name)
    }

    async fn shutdown(self) {
        self.controller.shutdown().await.unwrap();
    }
}

fn c_path(path: &Path) -> CString {
    use std::os::unix::ffi::OsStrExt;
    CString::new(path.as_os_str().as_bytes()).unwrap()
}

fn page_size() -> usize {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    assert!(size > 0);
    size as usize
}

unsafe fn create_file(path: &Path, contents: &[u8]) -> libc::c_int {
    let descriptor = unsafe {
        agora_sandbox_open_with_mode(
            c_path(path).as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o600,
        )
    };
    assert!(
        descriptor >= 0,
        "open failed: {}",
        std::io::Error::last_os_error()
    );
    assert_eq!(
        unsafe { agora_sandbox_write(descriptor, contents.as_ptr().cast(), contents.len()) },
        contents.len() as isize
    );
    descriptor
}

unsafe fn read_prefix(path: &Path, length: usize) -> Vec<u8> {
    let descriptor =
        unsafe { agora_sandbox_open_with_mode(c_path(path).as_ptr(), libc::O_RDONLY, 0) };
    assert!(
        descriptor >= 0,
        "open failed: {}",
        std::io::Error::last_os_error()
    );
    let mut contents = vec![0_u8; length];
    assert_eq!(
        unsafe { libc::pread(descriptor, contents.as_mut_ptr().cast(), length, 0) },
        length as isize
    );
    assert_eq!(unsafe { agora_sandbox_close(descriptor) }, 0);
    contents
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shared_mapping_syncs_after_its_descriptor_closes() {
    let fixture = BrokerFixture::new().await;
    let path = fixture.path("shared.bin");
    let page = page_size();

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = create_file(&path, &vec![b'a'; page]);
        let mapped = agora_sandbox_mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            descriptor,
            0,
        );
        assert_ne!(mapped, libc::MAP_FAILED);
        assert_eq!(agora_sandbox_close(descriptor), 0);

        std::ptr::copy_nonoverlapping(b"mapped".as_ptr(), mapped.cast::<u8>(), 6);
        assert_eq!(agora_sandbox_msync(mapped, page, libc::MS_SYNC), 0);
        assert_eq!(read_prefix(&path, 6), b"mapped");
        assert_eq!(agora_sandbox_munmap(mapped, page), 0);
    });

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn private_mapping_never_updates_encrypted_contents() {
    let fixture = BrokerFixture::new().await;
    let path = fixture.path("private.bin");
    let page = page_size();

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = create_file(&path, &vec![b'a'; page]);
        let mapped = agora_sandbox_mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE,
            descriptor,
            0,
        );
        assert_ne!(mapped, libc::MAP_FAILED);
        std::ptr::copy_nonoverlapping(b"private".as_ptr(), mapped.cast::<u8>(), 7);
        assert_eq!(agora_sandbox_msync(mapped, page, libc::MS_SYNC), 0);
        assert_eq!(agora_sandbox_munmap(mapped, page), 0);
        assert_eq!(agora_sandbox_close(descriptor), 0);
        assert_eq!(read_prefix(&path, 7), b"aaaaaaa");
    });

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mprotect_tracks_a_mapping_that_becomes_writable() {
    let fixture = BrokerFixture::new().await;
    let path = fixture.path("mprotect.bin");
    let page = page_size();

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = create_file(&path, &vec![b'a'; page]);
        let mapped = agora_sandbox_mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_SHARED,
            descriptor,
            0,
        );
        assert_ne!(mapped, libc::MAP_FAILED);
        assert_eq!(
            agora_sandbox_mprotect(mapped, page, libc::PROT_READ | libc::PROT_WRITE),
            0
        );
        std::ptr::copy_nonoverlapping(b"protected".as_ptr(), mapped.cast::<u8>(), 9);
        assert_eq!(agora_sandbox_mprotect(mapped, page, libc::PROT_READ), 0);
        assert_eq!(read_prefix(&path, 9), b"protected");
        assert_eq!(agora_sandbox_munmap(mapped, page), 0);
        assert_eq!(agora_sandbox_close(descriptor), 0);
    });

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fixed_mapping_flushes_the_mapping_it_replaces() {
    let fixture = BrokerFixture::new().await;
    let first = fixture.path("first.bin");
    let second = fixture.path("second.bin");
    let page = page_size();

    with_test_runtime(&fixture.runtime, || unsafe {
        let first_descriptor = create_file(&first, &vec![b'a'; page]);
        let second_descriptor = create_file(&second, &vec![b'b'; page]);
        let mapped = agora_sandbox_mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            first_descriptor,
            0,
        );
        assert_ne!(mapped, libc::MAP_FAILED);
        std::ptr::copy_nonoverlapping(b"first!".as_ptr(), mapped.cast::<u8>(), 6);

        let replacement = agora_sandbox_mmap(
            mapped,
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_FIXED,
            second_descriptor,
            0,
        );
        assert_eq!(replacement, mapped);
        assert_eq!(read_prefix(&first, 6), b"first!");
        std::ptr::copy_nonoverlapping(b"second".as_ptr(), replacement.cast::<u8>(), 6);
        assert_eq!(agora_sandbox_munmap(replacement, page), 0);
        assert_eq!(read_prefix(&second, 6), b"second");
        assert_eq!(agora_sandbox_close(first_descriptor), 0);
        assert_eq!(agora_sandbox_close(second_descriptor), 0);
    });

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn explicit_mapping_flush_covers_mapping_only_handles() {
    let fixture = BrokerFixture::new().await;
    let path = fixture.path("exec-flush.bin");
    let page = page_size();

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = create_file(&path, &vec![b'a'; page]);
        let mapped = agora_sandbox_mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            descriptor,
            0,
        );
        assert_ne!(mapped, libc::MAP_FAILED);
        assert_eq!(agora_sandbox_close(descriptor), 0);
        std::ptr::copy_nonoverlapping(b"exec".as_ptr(), mapped.cast::<u8>(), 4);

        fixture.runtime.flush_memory_mappings().unwrap();

        assert_eq!(read_prefix(&path, 4), b"exec");
        assert_eq!(agora_sandbox_munmap(mapped, page), 0);
    });

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reopening_a_path_flushes_a_mapping_even_after_its_descriptor_closes() {
    let fixture = BrokerFixture::new().await;
    let path = fixture.path("reopen.bin");
    let page = page_size();

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = create_file(&path, &vec![b'a'; page]);
        let mapped = agora_sandbox_mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            descriptor,
            0,
        );
        assert_ne!(mapped, libc::MAP_FAILED);
        assert_eq!(agora_sandbox_close(descriptor), 0);
        std::ptr::copy_nonoverlapping(b"visible".as_ptr(), mapped.cast::<u8>(), 7);

        assert_eq!(read_prefix(&path, 7), b"visible");

        assert_eq!(agora_sandbox_munmap(mapped, page), 0);
    });

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forked_process_can_sync_and_release_an_inherited_mapping() {
    let fixture = BrokerFixture::new().await;
    let path = fixture.path("fork.bin");
    let page = page_size();

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = create_file(&path, &vec![b'a'; page]);
        let mapped = agora_sandbox_mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            descriptor,
            0,
        );
        assert_ne!(mapped, libc::MAP_FAILED);

        let child = agora_sandbox_fork();
        assert!(
            child >= 0,
            "fork failed: {}",
            std::io::Error::last_os_error()
        );
        if child == 0 {
            std::ptr::copy_nonoverlapping(b"forked".as_ptr(), mapped.cast::<u8>(), 6);
            let mut status = 0;
            if agora_sandbox_msync(mapped, page, libc::MS_SYNC) != 0 {
                status = 1;
            }
            if agora_sandbox_munmap(mapped, page) != 0 {
                status = 2;
            }
            if agora_sandbox_close(descriptor) != 0 {
                status = 3;
            }
            libc::_exit(status);
        }

        let mut status = 0;
        assert_eq!(libc::waitpid(child, &mut status, 0), child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
        assert_eq!(read_prefix(&path, 6), b"forked");
        assert_eq!(agora_sandbox_munmap(mapped, page), 0);
        assert_eq!(agora_sandbox_close(descriptor), 0);
    });

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn scalar_and_vectored_writes_publish_exact_ranges_for_long_open_files() {
    let fixture = BrokerFixture::new().await;
    let path = fixture.path("data-hooks.bin");

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = create_file(&path, b"............");
        assert_eq!(libc::lseek(descriptor, 0, libc::SEEK_SET), 0);
        assert_eq!(agora_sandbox_write(descriptor, b"ab".as_ptr().cast(), 2), 2);
        assert_eq!(
            agora_sandbox_pwrite(descriptor, b"cd".as_ptr().cast(), 2, 2),
            2
        );

        assert_eq!(libc::lseek(descriptor, 4, libc::SEEK_SET), 4);
        let first = b"ef";
        let second = b"gh";
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
        assert_eq!(
            agora_sandbox_writev(descriptor, vectors.as_ptr(), vectors.len() as libc::c_int),
            4
        );

        let third = b"ij";
        let fourth = b"kl";
        let positioned = [
            libc::iovec {
                iov_base: third.as_ptr().cast_mut().cast(),
                iov_len: third.len(),
            },
            libc::iovec {
                iov_base: fourth.as_ptr().cast_mut().cast(),
                iov_len: fourth.len(),
            },
        ];
        assert_eq!(
            agora_sandbox_pwritev(
                descriptor,
                positioned.as_ptr(),
                positioned.len() as libc::c_int,
                8,
            ),
            4
        );
        assert_eq!(read_prefix(&path, 12), b"abcdefghijkl");

        let native = tempfile::tempfile().unwrap();
        let guard = FilesystemHookGuard::enter().unwrap();
        assert_eq!(
            agora_sandbox_write(native.as_raw_fd(), b"native".as_ptr().cast(), 6),
            6
        );
        drop(guard);
        assert_eq!(
            agora_sandbox_pwrite(native.as_raw_fd(), b"ok".as_ptr().cast(), 2, 0),
            2,
            "an untracked descriptor remains a native file"
        );

        assert_eq!(agora_sandbox_write(-1, b"x".as_ptr().cast(), 1), -1);
        assert_eq!(
            agora_sandbox_pwrite(descriptor, b"x".as_ptr().cast(), 1, -1),
            -1
        );
        assert_eq!(agora_sandbox_writev(-1, vectors.as_ptr(), 2), -1);
        assert_eq!(
            agora_sandbox_pwritev(descriptor, positioned.as_ptr(), 2, -1),
            -1
        );
        assert_eq!(agora_sandbox_close(descriptor), 0);
    });

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn partial_mapping_protection_and_unmap_keep_remaining_slices_tracked() {
    let fixture = BrokerFixture::new().await;
    let path = fixture.path("partial-map.bin");
    let page = page_size();

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = create_file(&path, &vec![b'a'; page * 2]);
        let mapped = agora_sandbox_mmap(
            std::ptr::null_mut(),
            page * 2,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            descriptor,
            0,
        );
        assert_ne!(mapped, libc::MAP_FAILED);
        std::ptr::copy_nonoverlapping(b"left".as_ptr(), mapped.cast::<u8>(), 4);
        let right = mapped.cast::<u8>().add(page);
        std::ptr::copy_nonoverlapping(b"right".as_ptr(), right, 5);

        assert_eq!(
            agora_sandbox_mprotect(right.cast(), page, libc::PROT_READ,),
            0
        );
        assert_eq!(read_prefix(&path, 4), b"left");
        assert_eq!(
            agora_sandbox_mprotect(right.cast(), page, libc::PROT_READ | libc::PROT_WRITE,),
            0
        );
        assert_eq!(agora_sandbox_munmap(mapped, page), 0);
        assert_eq!(agora_sandbox_close(descriptor), 0);
        std::ptr::copy_nonoverlapping(b"again".as_ptr(), right, 5);
        assert_eq!(agora_sandbox_munmap(right.cast(), page), 0);

        let reopened = read_prefix(&path, page + 5);
        assert_eq!(&reopened[..4], b"left");
        assert_eq!(&reopened[page..page + 5], b"again");
    });

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mapping_argument_overflow_fails_before_native_address_mutation() {
    let fixture = BrokerFixture::new().await;

    with_test_runtime(&fixture.runtime, || unsafe {
        let address = (usize::MAX - 7) as *mut libc::c_void;
        assert_eq!(agora_sandbox_msync(address, 16, libc::MS_SYNC), -1);
        assert_eq!(agora_sandbox_munmap(address, 16), -1);
        assert_eq!(agora_sandbox_mprotect(address, 16, libc::PROT_READ), -1);
        assert_eq!(
            agora_sandbox_mmap(
                address,
                16,
                libc::PROT_READ,
                libc::MAP_FIXED | libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            ),
            libc::MAP_FAILED
        );
    });

    fixture.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn untracked_and_read_only_shared_mappings_keep_native_semantics() {
    let fixture = BrokerFixture::new().await;
    let path = fixture.path("read-only-map.bin");
    let page = page_size();

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = create_file(&path, &vec![b'a'; page]);
        let mapped = agora_sandbox_mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ,
            libc::MAP_SHARED,
            descriptor,
            0,
        );
        assert_ne!(mapped, libc::MAP_FAILED);
        assert_eq!(agora_sandbox_msync(mapped, page, libc::MS_ASYNC), 0);
        assert_eq!(agora_sandbox_munmap(mapped, page), 0);
        assert_eq!(agora_sandbox_close(descriptor), 0);

        let anonymous = agora_sandbox_mmap(
            std::ptr::null_mut(),
            page,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED | libc::MAP_ANON,
            -1,
            0,
        );
        assert_ne!(anonymous, libc::MAP_FAILED);
        assert_eq!(agora_sandbox_mprotect(anonymous, page, libc::PROT_READ), 0);
        assert_eq!(agora_sandbox_munmap(anonymous, page), 0);

        assert_eq!(
            agora_sandbox_mmap(
                std::ptr::null_mut(),
                0,
                libc::PROT_READ,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            ),
            libc::MAP_FAILED
        );
    });

    fixture.shutdown().await;
}
