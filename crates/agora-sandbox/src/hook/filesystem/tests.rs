use super::{
    DirectoryCursor, FilesystemHookGuard, FilesystemHookRuntime, PathIntent,
    agora_sandbox_access as sandbox_access, agora_sandbox_chdir as sandbox_chdir,
    agora_sandbox_chmod as sandbox_chmod, agora_sandbox_chown as sandbox_chown,
    agora_sandbox_clonefile as sandbox_clonefile, agora_sandbox_clonefileat as sandbox_clonefileat,
    agora_sandbox_close as sandbox_close, agora_sandbox_closedir as sandbox_closedir,
    agora_sandbox_copyfile as sandbox_copyfile, agora_sandbox_creat as sandbox_creat,
    agora_sandbox_fchmod as sandbox_fchmod, agora_sandbox_fchmodat as sandbox_fchmodat,
    agora_sandbox_fchown as sandbox_fchown, agora_sandbox_fchownat as sandbox_fchownat,
    agora_sandbox_fclose as sandbox_fclose, agora_sandbox_fopen as sandbox_fopen,
    agora_sandbox_fstatat as sandbox_fstatat, agora_sandbox_ftruncate as sandbox_ftruncate,
    agora_sandbox_getcwd as sandbox_getcwd, agora_sandbox_lchown as sandbox_lchown,
    agora_sandbox_link as sandbox_link, agora_sandbox_linkat as sandbox_linkat,
    agora_sandbox_lstat as sandbox_lstat, agora_sandbox_mkdir as sandbox_mkdir,
    agora_sandbox_mkdirat as sandbox_mkdirat,
    agora_sandbox_open_with_mode as sandbox_open_with_mode,
    agora_sandbox_openat_with_mode as sandbox_openat_with_mode,
    agora_sandbox_opendir as sandbox_opendir,
    agora_sandbox_posix_spawn_file_actions_addopen as sandbox_spawn_addopen,
    agora_sandbox_posix_spawn_file_actions_destroy as sandbox_spawn_actions_destroy,
    agora_sandbox_readdir as sandbox_readdir, agora_sandbox_rename as sandbox_rename,
    agora_sandbox_renameat as sandbox_renameat, agora_sandbox_rmdir as sandbox_rmdir,
    agora_sandbox_stat as sandbox_stat, agora_sandbox_symlink as sandbox_symlink,
    agora_sandbox_symlinkat as sandbox_symlinkat, agora_sandbox_truncate as sandbox_truncate,
    agora_sandbox_unlink as sandbox_unlink, agora_sandbox_unlinkat as sandbox_unlinkat,
    catch_filesystem_panic, commit_spawn_file_actions, error_errno, sandbox_descriptor_mutation,
    sandbox_unsupported_mutation, with_test_runtime,
};
use crate::audit::AuditClient;
use crate::filesystem::EntryState;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::TcpListener;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

struct Fixture {
    directory: PathBuf,
    lower: PathBuf,
    runtime: FilesystemHookRuntime,
}

impl Fixture {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("agora-filesystem-hook-{}", uuid::Uuid::new_v4()));
        let lower = directory.join("lower");
        std::fs::create_dir_all(&lower).unwrap();
        let runtime = FilesystemHookRuntime::new(directory.join("fs")).unwrap();
        Self {
            directory,
            lower,
            runtime,
        }
    }

    fn c_path(path: &Path) -> CString {
        use std::os::unix::ffi::OsStrExt;
        CString::new(path.as_os_str().as_bytes()).unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        std::fs::remove_dir_all(&self.directory).unwrap();
    }
}

fn audit_server(
    responses: Vec<&'static str>,
) -> (AuditClient, thread::JoinHandle<Vec<serde_json::Value>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let mut requests = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(1)))
                .unwrap();
            let mut prefix = [0_u8; 4];
            stream.read_exact(&mut prefix).unwrap();
            let mut frame = vec![0_u8; u32::from_be_bytes(prefix) as usize];
            stream.read_exact(&mut frame).unwrap();
            requests.push(serde_json::from_slice(&frame).unwrap());
            stream
                .write_all(&(response.len() as u32).to_be_bytes())
                .unwrap();
            stream.write_all(response.as_bytes()).unwrap();
        }
        requests
    });
    (AuditClient::new(address, "audit-token"), server)
}

#[test]
fn read_and_write_mapping_use_the_encrypted_overlay() {
    let fixture = Fixture::new();
    let lower = fixture.lower.join("file");
    std::fs::write(&lower, b"host").unwrap();
    let path = Fixture::c_path(&lower);

    let read = fixture
        .runtime
        .map(path.as_ptr(), libc::AT_FDCWD, PathIntent::Read)
        .unwrap();
    assert_eq!(
        std::fs::read(Path::new(read.to_str().unwrap())).unwrap(),
        b"host"
    );

    let write = fixture
        .runtime
        .map(
            path.as_ptr(),
            libc::AT_FDCWD,
            PathIntent::Write { create: false },
        )
        .unwrap();
    std::fs::write(Path::new(write.to_str().unwrap()), b"sandbox").unwrap();
    assert_eq!(std::fs::read(&lower).unwrap(), b"host");
    assert_eq!(
        fixture.runtime.overlay.state_for_test(&lower).unwrap(),
        Some(EntryState::Cow)
    );
}

#[test]
fn mapped_absolute_paths_are_returned_to_the_logical_namespace() {
    let fixture = Fixture::new();
    let logical = fixture.lower.join("file");
    std::fs::write(&logical, b"host").unwrap();
    let lower = Fixture::c_path(&logical);
    let mapped = fixture
        .runtime
        .map(lower.as_ptr(), libc::AT_FDCWD, PathIntent::Read)
        .unwrap();

    assert_eq!(
        unsafe {
            fixture
                .runtime
                .logical_path(mapped.as_ptr(), libc::AT_FDCWD)
        }
        .unwrap(),
        logical
    );
}

#[test]
fn open_flags_select_read_create_and_write_intents() {
    let fixture = Fixture::new();
    let lower = fixture.lower.join("file");
    std::fs::write(&lower, b"host").unwrap();
    let path = Fixture::c_path(&lower);

    let read = fixture
        .runtime
        .prepare_open(path.as_ptr(), libc::AT_FDCWD, libc::O_RDONLY)
        .unwrap();
    assert_eq!(read.file.path, lower.to_string_lossy());
    assert_eq!(read.file.mode.access, crate::callback::FileAccessMode::Read);
    assert!(!read.file.mode.create);
    let _read = fixture.runtime.map_open(read).unwrap();
    assert!(matches!(
        fixture.runtime.overlay.state_for_test(&lower).unwrap(),
        Some(EntryState::Cached { .. })
    ));

    let write = fixture
        .runtime
        .prepare_open(path.as_ptr(), libc::AT_FDCWD, libc::O_WRONLY)
        .unwrap();
    assert_eq!(
        write.file.mode.access,
        crate::callback::FileAccessMode::Write
    );
    let mut write = fixture.runtime.map_open(write).unwrap();
    assert!(matches!(
        fixture.runtime.overlay.state_for_test(&lower).unwrap(),
        Some(EntryState::Cached { .. })
    ));
    fixture.runtime.commit_open(&mut write).unwrap();
    assert_eq!(
        fixture.runtime.overlay.state_for_test(&lower).unwrap(),
        Some(EntryState::Cow)
    );

    let created = fixture.lower.join("created");
    let prepared = fixture
        .runtime
        .prepare_open(
            Fixture::c_path(&created).as_ptr(),
            libc::AT_FDCWD,
            libc::O_RDWR | libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND | libc::O_EXCL,
        )
        .unwrap();
    assert_eq!(
        prepared.file.mode.access,
        crate::callback::FileAccessMode::ReadWrite
    );
    assert!(prepared.file.mode.create);
    assert!(prepared.file.mode.truncate);
    assert!(prepared.file.mode.append);
    assert!(prepared.file.mode.exclusive);
    let mut prepared = fixture.runtime.map_open(prepared).unwrap();
    assert_eq!(
        fixture.runtime.overlay.state_for_test(&created).unwrap(),
        None
    );
    fixture.runtime.commit_open(&mut prepared).unwrap();
    assert_eq!(
        fixture.runtime.overlay.state_for_test(&created).unwrap(),
        Some(EntryState::Cow)
    );
}

#[test]
fn mutations_update_only_the_overlay_view() {
    let fixture = Fixture::new();
    let source = fixture.lower.join("source");
    let target = fixture.lower.join("target");
    std::fs::write(&source, b"host").unwrap();
    let source_path = Fixture::c_path(&source);
    let target_path = Fixture::c_path(&target);

    fixture
        .runtime
        .rename(
            libc::AT_FDCWD,
            source_path.as_ptr(),
            libc::AT_FDCWD,
            target_path.as_ptr(),
        )
        .unwrap();
    assert_eq!(std::fs::read(&source).unwrap(), b"host");
    assert!(fixture.runtime.overlay.prepare_read(&source).is_err());
    assert_eq!(
        std::fs::read(fixture.runtime.overlay.prepare_read(&target).unwrap()).unwrap(),
        b"host"
    );

    fixture
        .runtime
        .remove(libc::AT_FDCWD, target_path.as_ptr(), false)
        .unwrap();
    assert!(fixture.runtime.overlay.prepare_read(&target).is_err());
}

#[test]
fn the_control_namespace_is_not_addressable_through_the_mapped_root() {
    let fixture = Fixture::new();
    let control = fixture.runtime.overlay.root().join(".agora/volume.json");
    let control = Fixture::c_path(&control);

    assert!(
        fixture
            .runtime
            .map(control.as_ptr(), libc::AT_FDCWD, PathIntent::Read)
            .is_err()
    );
}

#[test]
fn directory_cursor_prefers_upper_entries_and_hides_whiteouts() {
    let fixture = Fixture::new();
    let lower = fixture.lower.join("directory");
    std::fs::create_dir(&lower).unwrap();
    std::fs::write(lower.join("removed"), b"host").unwrap();
    fixture
        .runtime
        .overlay
        .remove(&lower.join("removed"), false)
        .unwrap();
    let view = fixture.runtime.overlay.directory_view(&lower).unwrap();
    let mut cursor = DirectoryCursor::new(None, &view);

    assert!(cursor.include(b"same", false));
    assert!(!cursor.include(b"same", true));
    assert!(!cursor.include(b"removed", true));
    assert!(cursor.include(b"lower-only", true));
}

#[test]
fn filesystem_ffi_panics_fail_closed_with_io_error() {
    unsafe { *libc::__error() = 0 };

    let result = catch_filesystem_panic(-1, || panic!("hook failure"));

    assert_eq!(result, -1);
    assert_eq!(unsafe { *libc::__error() }, libc::EIO);
}

#[test]
fn filesystem_errors_preserve_errno_and_default_to_io_error() {
    let denied = anyhow::Error::new(std::io::Error::from_raw_os_error(libc::EACCES));
    assert_eq!(error_errno(&denied), libc::EACCES);
    for (kind, errno) in [
        (std::io::ErrorKind::NotFound, libc::ENOENT),
        (std::io::ErrorKind::PermissionDenied, libc::EACCES),
        (std::io::ErrorKind::AlreadyExists, libc::EEXIST),
        (std::io::ErrorKind::InvalidInput, libc::EINVAL),
        (std::io::ErrorKind::InvalidData, libc::EINVAL),
        (std::io::ErrorKind::Interrupted, libc::EINTR),
        (std::io::ErrorKind::Unsupported, libc::ENOTSUP),
        (std::io::ErrorKind::OutOfMemory, libc::ENOMEM),
        (std::io::ErrorKind::NotADirectory, libc::ENOTDIR),
        (std::io::ErrorKind::IsADirectory, libc::EISDIR),
        (std::io::ErrorKind::DirectoryNotEmpty, libc::ENOTEMPTY),
        (std::io::ErrorKind::Other, libc::EIO),
    ] {
        assert_eq!(error_errno(&std::io::Error::from(kind).into()), errno);
    }
    assert_eq!(error_errno(&anyhow::anyhow!("no errno")), libc::EIO);
}

#[test]
fn logical_current_directory_drives_relative_path_resolution() {
    let fixture = Fixture::new();
    let directory = fixture.lower.join("directory");
    let file = directory.join("file");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&file, b"content").unwrap();
    let directory_path = Fixture::c_path(&directory);

    let (mapped, logical) = fixture
        .runtime
        .prepare_change_directory(directory_path.as_ptr())
        .unwrap();
    assert!(Path::new(mapped.to_str().unwrap()).starts_with(fixture.runtime.overlay.root()));
    fixture.runtime.set_current_directory(logical);

    with_test_runtime(&fixture.runtime, || unsafe {
        let mut cwd = vec![0_i8; libc::PATH_MAX as usize];
        assert_eq!(
            CStr::from_ptr(sandbox_getcwd(cwd.as_mut_ptr(), cwd.len())).to_bytes(),
            directory.as_os_str().as_encoded_bytes()
        );
        let descriptor = sandbox_open_with_mode(c"file".as_ptr(), libc::O_RDONLY, 0);
        assert!(descriptor >= 0);
        assert_eq!(sandbox_close(descriptor), 0);
    });
}

#[test]
fn chdir_updates_the_logical_directory_after_the_native_change_succeeds() {
    struct RestoreDirectory(PathBuf);

    impl Drop for RestoreDirectory {
        fn drop(&mut self) {
            std::env::set_current_dir(&self.0).unwrap();
        }
    }

    let restore = RestoreDirectory(std::env::current_dir().unwrap());
    let fixture = Fixture::new();
    let directory = fixture.lower.join("directory");
    std::fs::create_dir(&directory).unwrap();

    with_test_runtime(&fixture.runtime, || unsafe {
        assert_eq!(sandbox_chdir(Fixture::c_path(&directory).as_ptr()), 0);
        let current = sandbox_getcwd(std::ptr::null_mut(), 0);
        assert!(!current.is_null());
        assert_eq!(
            CStr::from_ptr(current).to_bytes(),
            directory.as_os_str().as_encoded_bytes()
        );
        libc::free(current.cast());
    });

    drop(restore);
}

#[test]
fn recursive_filesystem_hooks_delegate_to_the_native_operations() {
    let fixture = Fixture::new();
    let file = fixture.lower.join("file");
    let renamed = fixture.lower.join("renamed");
    let directory = fixture.lower.join("directory");
    let directory_at = fixture.lower.join("directory-at");
    std::fs::write(&file, b"content").unwrap();
    let file_path = Fixture::c_path(&file);
    let renamed_path = Fixture::c_path(&renamed);
    let root_path = Fixture::c_path(&fixture.lower);

    with_test_runtime(&fixture.runtime, || unsafe {
        let _guard = FilesystemHookGuard::enter().unwrap();
        let descriptor = sandbox_open_with_mode(file_path.as_ptr(), libc::O_RDWR, 0);
        assert!(descriptor >= 0);
        assert_eq!(sandbox_descriptor_mutation(descriptor, |_| 73), 73);
        assert_eq!(sandbox_unsupported_mutation(|| 74), 74);
        assert_eq!(sandbox_close(descriptor), 0);

        assert_eq!(sandbox_truncate(file_path.as_ptr(), 5), 0);
        assert_eq!(sandbox_chmod(file_path.as_ptr(), 0o640), 0);
        assert_eq!(sandbox_chown(file_path.as_ptr(), !0, !0), 0);
        assert_eq!(sandbox_lchown(file_path.as_ptr(), !0, !0), 0);
        let stream = sandbox_fopen(file_path.as_ptr(), c"r".as_ptr());
        assert!(!stream.is_null());
        assert_eq!(sandbox_fclose(stream), 0);

        let root =
            sandbox_open_with_mode(root_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0);
        assert!(root >= 0);
        let opened = sandbox_openat_with_mode(root, c"file".as_ptr(), libc::O_RDONLY, 0);
        assert!(opened >= 0);
        assert_eq!(sandbox_close(opened), 0);
        assert_eq!(sandbox_fchmodat(root, c"file".as_ptr(), 0o600, 0), 0);
        assert_eq!(sandbox_fchownat(root, c"file".as_ptr(), !0, !0, 0), 0);

        let mut status = std::mem::zeroed();
        assert_eq!(sandbox_stat(file_path.as_ptr(), &mut status), 0);
        assert_eq!(sandbox_lstat(file_path.as_ptr(), &mut status), 0);
        assert_eq!(sandbox_fstatat(root, c"file".as_ptr(), &mut status, 0), 0);
        assert_eq!(sandbox_access(file_path.as_ptr(), libc::R_OK), 0);
        assert_eq!(
            sandbox_mkdir(Fixture::c_path(&directory).as_ptr(), 0o700),
            0
        );
        assert_eq!(sandbox_mkdirat(root, c"directory-at".as_ptr(), 0o700), 0);
        assert_eq!(sandbox_rename(file_path.as_ptr(), renamed_path.as_ptr()), 0);
        assert_eq!(
            sandbox_renameat(root, c"renamed".as_ptr(), root, c"file".as_ptr()),
            0
        );
        assert_eq!(sandbox_unlink(file_path.as_ptr()), 0);
        assert_eq!(sandbox_rmdir(Fixture::c_path(&directory).as_ptr()), 0);
        assert_eq!(
            sandbox_unlinkat(root, c"directory-at".as_ptr(), libc::AT_REMOVEDIR),
            0
        );

        let mut cwd = vec![0_i8; libc::PATH_MAX as usize];
        assert_eq!(
            sandbox_getcwd(cwd.as_mut_ptr(), cwd.len()),
            cwd.as_mut_ptr()
        );
        let handle = sandbox_opendir(root_path.as_ptr());
        assert!(!handle.is_null());
        assert!(!sandbox_readdir(handle).is_null());
        assert_eq!(sandbox_closedir(handle), 0);
        assert_eq!(sandbox_close(root), 0);
    });

    assert!(!file.exists());
    assert!(!renamed.exists());
    assert!(!directory.exists());
    assert!(!directory_at.exists());
}

#[test]
fn failed_native_opens_do_not_commit_staged_writes() {
    let fixture = Fixture::new();
    let open_file = fixture.lower.join("open-file");
    let fopen_file = fixture.lower.join("fopen-file");
    std::fs::write(&open_file, b"open").unwrap();
    std::fs::write(&fopen_file, b"fopen").unwrap();

    with_test_runtime(&fixture.runtime, || unsafe {
        assert_eq!(
            sandbox_open_with_mode(
                Fixture::c_path(&open_file).as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL,
                0o600,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::EEXIST);
        assert!(sandbox_fopen(Fixture::c_path(&fopen_file).as_ptr(), c"wx".as_ptr()).is_null());
        assert_eq!(*libc::__error(), libc::EEXIST);
    });

    for (file, contents) in [
        (&open_file, b"open".as_slice()),
        (&fopen_file, b"fopen".as_slice()),
    ] {
        assert!(matches!(
            fixture.runtime.overlay.state_for_test(file).unwrap(),
            Some(EntryState::Cached { .. })
        ));
        assert_eq!(std::fs::read(file).unwrap(), contents);
    }
}

#[test]
fn filesystem_interposers_apply_cow_metadata_and_merged_directory_views() {
    let fixture = Fixture::new();
    let writable = fixture.lower.join("writable");
    let rename_from = fixture.lower.join("rename-from");
    let rename_to = fixture.lower.join("rename-to");
    let directory = fixture.lower.join("directory");
    let created_directory = fixture.lower.join("created-directory");
    std::fs::write(&writable, b"host").unwrap();
    std::fs::write(&rename_from, b"rename").unwrap();
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(directory.join("lower"), b"lower").unwrap();
    std::fs::write(directory.join("hidden"), b"hidden").unwrap();
    std::fs::write(
        fixture
            .runtime
            .overlay
            .prepare_write(&directory.join("upper"), true)
            .unwrap(),
        b"upper",
    )
    .unwrap();
    fixture
        .runtime
        .overlay
        .remove(&directory.join("hidden"), false)
        .unwrap();

    with_test_runtime(&fixture.runtime, || unsafe {
        let writable = Fixture::c_path(&writable);
        let descriptor =
            sandbox_open_with_mode(writable.as_ptr(), libc::O_WRONLY | libc::O_TRUNC, 0);
        assert!(descriptor >= 0);
        assert_eq!(
            fixture.runtime.tracked(descriptor).unwrap().path,
            writable.to_string_lossy()
        );
        assert_eq!(libc::write(descriptor, b"sandbox".as_ptr().cast(), 7), 7);
        assert_eq!(sandbox_close(descriptor), 0);
        assert!(fixture.runtime.tracked(descriptor).is_none());

        let stream = sandbox_fopen(writable.as_ptr(), c"r".as_ptr());
        assert!(!stream.is_null());
        let descriptor = libc::fileno(stream);
        assert!(fixture.runtime.tracked(descriptor).is_some());
        assert_eq!(sandbox_fclose(stream), 0);
        assert!(fixture.runtime.tracked(descriptor).is_none());

        let mut status = std::mem::zeroed();
        assert_eq!(sandbox_stat(writable.as_ptr(), &mut status), 0);
        assert_eq!(sandbox_lstat(writable.as_ptr(), &mut status), 0);
        assert_eq!(
            sandbox_fstatat(libc::AT_FDCWD, writable.as_ptr(), &mut status, 0,),
            0
        );
        assert_eq!(sandbox_access(writable.as_ptr(), libc::R_OK), 0);

        let rename_from = Fixture::c_path(&rename_from);
        let rename_to = Fixture::c_path(&rename_to);
        assert_eq!(sandbox_rename(rename_from.as_ptr(), rename_to.as_ptr()), 0);
        assert_eq!(sandbox_access(rename_from.as_ptr(), libc::F_OK), -1);
        assert_eq!(sandbox_access(rename_to.as_ptr(), libc::F_OK), 0);
        assert_eq!(sandbox_unlink(rename_to.as_ptr()), 0);
        assert_eq!(sandbox_access(rename_to.as_ptr(), libc::F_OK), -1);

        let created_directory = Fixture::c_path(&created_directory);
        assert_eq!(sandbox_mkdir(created_directory.as_ptr(), 0o755), 0);
        assert_eq!(sandbox_stat(created_directory.as_ptr(), &mut status), 0);
        let created_handle = sandbox_opendir(created_directory.as_ptr());
        assert!(!created_handle.is_null());
        while !sandbox_readdir(created_handle).is_null() {}
        assert_eq!(sandbox_closedir(created_handle), 0);
        assert_eq!(sandbox_rmdir(created_directory.as_ptr()), 0);

        let directory = Fixture::c_path(&directory);
        let handle = sandbox_opendir(directory.as_ptr());
        assert!(!handle.is_null());
        let mut names = HashSet::new();
        loop {
            let entry = sandbox_readdir(handle);
            if entry.is_null() {
                break;
            }
            names.insert(
                CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_string_lossy()
                    .into_owned(),
            );
        }
        assert_eq!(sandbox_closedir(handle), 0);
        assert!(names.contains("lower"));
        assert!(names.contains("upper"));
        assert!(!names.contains("hidden"));
        assert!(!names.contains(".agora"));
    });

    assert_eq!(std::fs::read(&writable).unwrap(), b"host");
    assert_eq!(
        std::fs::read(fixture.runtime.overlay.prepare_read(&writable).unwrap()).unwrap(),
        b"sandbox"
    );
    assert_eq!(std::fs::read(&rename_from).unwrap(), b"rename");
    assert!(!rename_to.exists());
    assert!(!created_directory.exists());
}

#[test]
fn filesystem_interposers_cover_relative_allocation_and_error_paths() {
    let fixture = Fixture::new();
    let directory = fixture.lower.join("directory");
    let existing = directory.join("existing");
    let created = directory.join("created");
    std::fs::create_dir(&directory).unwrap();
    std::fs::write(&existing, b"existing").unwrap();
    let directory_path = Fixture::c_path(&directory);
    let directory_descriptor = unsafe { libc::open(directory_path.as_ptr(), libc::O_RDONLY) };
    assert!(directory_descriptor >= 0);

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = sandbox_openat_with_mode(
            directory_descriptor,
            c"existing".as_ptr(),
            libc::O_RDONLY,
            0,
        );
        assert!(descriptor >= 0);
        assert_eq!(sandbox_close(descriptor), 0);

        let created_path = Fixture::c_path(&created);
        let descriptor =
            sandbox_open_with_mode(created_path.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o600);
        assert!(descriptor >= 0);
        assert_eq!(sandbox_close(descriptor), 0);

        let stream = sandbox_fopen(created_path.as_ptr(), c"a+".as_ptr());
        assert!(!stream.is_null());
        assert_eq!(sandbox_fclose(stream), 0);

        let directory_handle = sandbox_opendir(directory_path.as_ptr());
        assert!(!directory_handle.is_null());
        assert_eq!(sandbox_closedir(directory_handle), 0);

        let native = libc::opendir(c"/".as_ptr());
        assert!(!native.is_null());
        assert!(!sandbox_readdir(native).is_null());
        assert_eq!(sandbox_closedir(native), 0);

        let mut cwd = vec![0_i8; libc::PATH_MAX as usize];
        assert_eq!(
            sandbox_getcwd(cwd.as_mut_ptr(), cwd.len()),
            cwd.as_mut_ptr()
        );
        let allocated = sandbox_getcwd(std::ptr::null_mut(), 0);
        assert!(!allocated.is_null());
        libc::free(allocated.cast());
        assert!(sandbox_getcwd(std::ptr::null_mut(), 1).is_null());
        assert!(sandbox_getcwd(cwd.as_mut_ptr(), 1).is_null());

        let mut status = std::mem::zeroed();
        let missing = Fixture::c_path(&directory.join("missing"));
        assert_eq!(
            sandbox_open_with_mode(missing.as_ptr(), libc::O_RDONLY, 0),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOENT);
        assert_eq!(
            sandbox_openat_with_mode(directory_descriptor, c"missing".as_ptr(), libc::O_RDONLY, 0,),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOENT);
        assert!(sandbox_fopen(missing.as_ptr(), c"r".as_ptr()).is_null());
        assert_eq!(*libc::__error(), libc::ENOENT);
        assert_eq!(sandbox_truncate(missing.as_ptr(), 0), -1);
        assert_eq!(*libc::__error(), libc::ENOENT);
        assert_eq!(sandbox_truncate(std::ptr::null(), 0), -1);
        assert_eq!(*libc::__error(), libc::EFAULT);
        assert_eq!(
            sandbox_openat_with_mode(-1, c"relative".as_ptr(), libc::O_RDONLY, 0),
            -1
        );
        assert_eq!(
            sandbox_open_with_mode(std::ptr::null(), libc::O_RDONLY, 0),
            -1
        );
        assert!(sandbox_fopen(created_path.as_ptr(), std::ptr::null()).is_null());
        assert_eq!(sandbox_stat(std::ptr::null(), &mut status), -1);
        assert_eq!(sandbox_lstat(std::ptr::null(), &mut status), -1);
        assert_eq!(
            sandbox_fstatat(libc::AT_FDCWD, std::ptr::null(), &mut status, 0),
            -1
        );
        assert_eq!(sandbox_access(std::ptr::null(), libc::F_OK), -1);
        assert_eq!(sandbox_unlink(std::ptr::null()), -1);
        assert_eq!(sandbox_unlinkat(libc::AT_FDCWD, std::ptr::null(), 0), -1);
        assert_eq!(sandbox_rmdir(std::ptr::null()), -1);
        assert_eq!(sandbox_rename(std::ptr::null(), created_path.as_ptr()), -1);
        assert_eq!(
            sandbox_renameat(
                libc::AT_FDCWD,
                std::ptr::null(),
                libc::AT_FDCWD,
                created_path.as_ptr(),
            ),
            -1
        );
        assert_eq!(sandbox_mkdir(std::ptr::null(), 0o755), -1);
        assert_eq!(sandbox_mkdirat(libc::AT_FDCWD, std::ptr::null(), 0o755), -1);
        assert_eq!(sandbox_chdir(std::ptr::null()), -1);
        assert!(sandbox_opendir(std::ptr::null()).is_null());
    });

    assert_eq!(unsafe { libc::close(directory_descriptor) }, 0);
    assert_eq!(
        fixture.runtime.overlay.state_for_test(&created).unwrap(),
        Some(EntryState::Cow)
    );
    assert!(FilesystemHookRuntime::global().is_none());
}

#[test]
fn mutation_interposers_keep_path_and_spawn_action_writes_in_the_overlay() {
    let fixture = Fixture::new();
    let existing = fixture.lower.join("existing");
    let created = fixture.lower.join("created");
    let renamed = fixture.lower.join("renamed");
    let hard_link = fixture.lower.join("hard-link");
    let hard_link_at = fixture.lower.join("hard-link-at");
    let clone = fixture.lower.join("clone");
    let clone_at = fixture.lower.join("clone-at");
    let copy = fixture.lower.join("copy");
    let directory = fixture.lower.join("directory");
    let symlink = fixture.lower.join("symlink");
    let deferred = fixture.lower.join("deferred");
    let unused_action = fixture.lower.join("unused-action");
    std::fs::write(&existing, b"original").unwrap();
    std::fs::set_permissions(&existing, std::fs::Permissions::from_mode(0o644)).unwrap();
    let directory_path = Fixture::c_path(&fixture.lower);
    let existing_path = Fixture::c_path(&existing);
    let untracked_descriptor = unsafe { libc::open(existing_path.as_ptr(), libc::O_RDWR) };
    assert!(untracked_descriptor >= 0);

    with_test_runtime(&fixture.runtime, || unsafe {
        let directory_descriptor = sandbox_open_with_mode(
            directory_path.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY,
            0,
        );
        assert!(directory_descriptor >= 0);
        assert_eq!(sandbox_ftruncate(directory_descriptor, 0), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(sandbox_fchmod(directory_descriptor, 0o700), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(sandbox_fchown(directory_descriptor, !0, !0), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        let created_path = Fixture::c_path(&created);
        let descriptor = sandbox_creat(created_path.as_ptr(), 0o600);
        assert!(descriptor >= 0);
        assert_eq!(libc::write(descriptor, b"created".as_ptr().cast(), 7), 7);
        assert_eq!(sandbox_fchmod(descriptor, 0o640), 0);
        assert_eq!(sandbox_fchown(descriptor, !0, !0), 0);
        assert_eq!(sandbox_ftruncate(descriptor, 3), 0);
        assert_eq!(sandbox_close(descriptor), 0);

        assert_eq!(sandbox_chmod(existing_path.as_ptr(), 0o600), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(sandbox_chown(existing_path.as_ptr(), !0, !0), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_fchmodat(directory_descriptor, c"existing".as_ptr(), 0o600, 0),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_fchownat(directory_descriptor, c"existing".as_ptr(), !0, !0, 0),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(sandbox_truncate(existing_path.as_ptr(), 2), 0);
        assert_eq!(sandbox_ftruncate(untracked_descriptor, 1), -1);
        assert_eq!(*libc::__error(), libc::EPERM);
        assert_eq!(sandbox_chmod(directory_path.as_ptr(), 0o700), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_fchmodat(
                directory_descriptor,
                c"existing".as_ptr(),
                0o600,
                libc::AT_SYMLINK_NOFOLLOW,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_fchownat(
                directory_descriptor,
                c"existing".as_ptr(),
                !0,
                !0,
                libc::AT_SYMLINK_NOFOLLOW,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_link(existing_path.as_ptr(), Fixture::c_path(&hard_link).as_ptr()),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_linkat(
                directory_descriptor,
                c"existing".as_ptr(),
                directory_descriptor,
                c"hard-link-at".as_ptr(),
                0,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_clonefile(existing_path.as_ptr(), Fixture::c_path(&clone).as_ptr(), 0),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_clonefileat(
                directory_descriptor,
                c"existing".as_ptr(),
                directory_descriptor,
                c"clone-at".as_ptr(),
                0,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_copyfile(
                existing_path.as_ptr(),
                Fixture::c_path(&copy).as_ptr(),
                std::ptr::null_mut(),
                libc::COPYFILE_DATA,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);

        assert_eq!(
            sandbox_mkdirat(directory_descriptor, c"directory".as_ptr(), 0o700),
            0
        );
        assert!(
            fixture
                .runtime
                .overlay
                .prepare_read(&created)
                .unwrap()
                .exists()
        );
        let result = sandbox_renameat(
            directory_descriptor,
            c"created".as_ptr(),
            directory_descriptor,
            c"renamed".as_ptr(),
        );
        assert_eq!(result, 0, "renameat errno {}", *libc::__error());
        assert_eq!(
            sandbox_unlinkat(directory_descriptor, c"renamed".as_ptr(), 0),
            0
        );

        assert_eq!(
            sandbox_symlink(c"target".as_ptr(), Fixture::c_path(&symlink).as_ptr()),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(sandbox_lchown(existing_path.as_ptr(), !0, !0), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_copyfile(
                directory_path.as_ptr(),
                Fixture::c_path(&fixture.lower.join("directory-copy")).as_ptr(),
                std::ptr::null_mut(),
                libc::COPYFILE_RECURSIVE,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            sandbox_unlinkat(directory_descriptor, c"existing".as_ptr(), 1 << 20),
            -1
        );
        assert_eq!(*libc::__error(), libc::EINVAL);
        assert_eq!(
            sandbox_symlinkat(
                c"target".as_ptr(),
                directory_descriptor,
                c"symlink-at".as_ptr()
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);

        let mut actions: libc::posix_spawn_file_actions_t = std::ptr::null_mut();
        assert_eq!(libc::posix_spawn_file_actions_init(&mut actions), 0);
        assert_eq!(
            sandbox_spawn_addopen(
                &mut actions,
                8,
                std::ptr::null(),
                libc::O_WRONLY | libc::O_CREAT,
                0o600,
            ),
            libc::EFAULT
        );
        assert_eq!(
            sandbox_spawn_addopen(
                &mut actions,
                8,
                Fixture::c_path(&fixture.lower.join("missing")).as_ptr(),
                libc::O_WRONLY,
                0,
            ),
            libc::ENOENT
        );
        assert_eq!(
            sandbox_spawn_addopen(
                &mut actions,
                9,
                Fixture::c_path(&deferred).as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o600,
            ),
            0
        );
        assert_eq!(
            fixture.runtime.overlay.state_for_test(&deferred).unwrap(),
            None
        );
        let copied_actions = actions;
        commit_spawn_file_actions(&copied_actions).unwrap();
        assert_eq!(
            fixture.runtime.overlay.state_for_test(&deferred).unwrap(),
            Some(EntryState::Cow)
        );
        assert_eq!(sandbox_spawn_actions_destroy(&mut actions), 0);

        let mut unused_actions: libc::posix_spawn_file_actions_t = std::ptr::null_mut();
        assert_eq!(libc::posix_spawn_file_actions_init(&mut unused_actions), 0);
        assert_eq!(
            sandbox_spawn_addopen(
                &mut unused_actions,
                10,
                Fixture::c_path(&unused_action).as_ptr(),
                libc::O_WRONLY | libc::O_CREAT,
                0o600,
            ),
            0
        );
        assert_eq!(sandbox_spawn_actions_destroy(&mut unused_actions), 0);
        assert_eq!(
            fixture
                .runtime
                .overlay
                .state_for_test(&unused_action)
                .unwrap(),
            None
        );
        assert_eq!(sandbox_close(directory_descriptor), 0);
    });

    assert_eq!(unsafe { libc::close(untracked_descriptor) }, 0);
    assert_eq!(std::fs::read(&existing).unwrap(), b"original");
    assert_eq!(
        existing.metadata().unwrap().permissions().mode() & 0o777,
        0o644
    );
    for path in [
        &created,
        &renamed,
        &hard_link,
        &hard_link_at,
        &clone,
        &clone_at,
        &copy,
        &directory,
        &symlink,
        &deferred,
        &unused_action,
    ] {
        assert!(!path.exists(), "host path was changed: {}", path.display());
    }
    assert_eq!(
        std::fs::read(fixture.runtime.overlay.prepare_read(&existing).unwrap()).unwrap(),
        b"or"
    );
    assert!(fixture.runtime.overlay.prepare_read(&renamed).is_err());
    assert!(
        fixture
            .runtime
            .overlay
            .prepare_directory(&directory)
            .is_ok()
    );
}

#[test]
fn filesystem_interposers_delegate_before_a_runtime_is_active() {
    let fixture = Fixture::new();
    let path = |name: &str| fixture.lower.join(name);
    let file = path("file");
    let file_path = Fixture::c_path(&file);
    let root_path = Fixture::c_path(&fixture.lower);

    unsafe {
        let descriptor = sandbox_creat(file_path.as_ptr(), 0o600);
        assert!(descriptor >= 0);
        assert_eq!(libc::write(descriptor, b"content".as_ptr().cast(), 7), 7);
        assert_eq!(sandbox_ftruncate(descriptor, 6), 0);
        assert_eq!(sandbox_fchmod(descriptor, 0o640), 0);
        assert_eq!(sandbox_fchown(descriptor, !0, !0), 0);
        assert_eq!(sandbox_close(descriptor), 0);
        assert_eq!(sandbox_truncate(file_path.as_ptr(), 5), 0);
        assert_eq!(sandbox_chmod(file_path.as_ptr(), 0o600), 0);
        assert_eq!(sandbox_chown(file_path.as_ptr(), !0, !0), 0);
        assert_eq!(sandbox_lchown(file_path.as_ptr(), !0, !0), 0);

        let directory_descriptor =
            sandbox_open_with_mode(root_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY, 0);
        assert!(directory_descriptor >= 0);
        let opened =
            sandbox_openat_with_mode(directory_descriptor, c"file".as_ptr(), libc::O_RDONLY, 0);
        assert!(opened >= 0);
        assert_eq!(sandbox_close(opened), 0);
        assert_eq!(
            sandbox_fchmodat(directory_descriptor, c"file".as_ptr(), 0o600, 0),
            0
        );
        assert_eq!(
            sandbox_fchownat(directory_descriptor, c"file".as_ptr(), !0, !0, 0),
            0
        );
        let mut status = std::mem::zeroed();
        assert_eq!(sandbox_stat(file_path.as_ptr(), &mut status), 0);
        assert_eq!(sandbox_lstat(file_path.as_ptr(), &mut status), 0);
        assert_eq!(
            sandbox_fstatat(directory_descriptor, c"file".as_ptr(), &mut status, 0),
            0
        );
        assert_eq!(sandbox_access(file_path.as_ptr(), libc::R_OK), 0);
        let stream = sandbox_fopen(file_path.as_ptr(), c"r".as_ptr());
        assert!(!stream.is_null());
        assert_eq!(sandbox_fclose(stream), 0);
        assert_eq!(sandbox_chdir(c".".as_ptr()), 0);
        let mut cwd = vec![0_i8; libc::PATH_MAX as usize];
        assert_eq!(
            sandbox_getcwd(cwd.as_mut_ptr(), cwd.len()),
            cwd.as_mut_ptr()
        );

        assert_eq!(
            sandbox_link(file_path.as_ptr(), Fixture::c_path(&path("link")).as_ptr()),
            0
        );
        assert_eq!(
            sandbox_linkat(
                directory_descriptor,
                c"file".as_ptr(),
                directory_descriptor,
                c"link-at".as_ptr(),
                0,
            ),
            0
        );
        assert_eq!(
            sandbox_symlink(c"file".as_ptr(), Fixture::c_path(&path("symlink")).as_ptr()),
            0
        );
        assert_eq!(
            sandbox_symlinkat(
                c"file".as_ptr(),
                directory_descriptor,
                c"symlink-at".as_ptr()
            ),
            0
        );
        assert_eq!(
            sandbox_clonefile(
                file_path.as_ptr(),
                Fixture::c_path(&path("clone")).as_ptr(),
                0
            ),
            0
        );
        assert_eq!(
            sandbox_clonefileat(
                directory_descriptor,
                c"file".as_ptr(),
                directory_descriptor,
                c"clone-at".as_ptr(),
                0,
            ),
            0
        );
        assert_eq!(
            sandbox_copyfile(
                file_path.as_ptr(),
                Fixture::c_path(&path("copy")).as_ptr(),
                std::ptr::null_mut(),
                libc::COPYFILE_DATA,
            ),
            0
        );

        assert_eq!(
            sandbox_mkdir(Fixture::c_path(&path("directory")).as_ptr(), 0o700),
            0
        );
        assert_eq!(
            sandbox_mkdirat(directory_descriptor, c"directory-at".as_ptr(), 0o700),
            0
        );
        let handle = sandbox_opendir(root_path.as_ptr());
        assert!(!handle.is_null());
        assert!(!sandbox_readdir(handle).is_null());
        assert_eq!(sandbox_closedir(handle), 0);
        assert_eq!(
            sandbox_rename(
                Fixture::c_path(&path("link")).as_ptr(),
                Fixture::c_path(&path("renamed")).as_ptr(),
            ),
            0
        );
        assert_eq!(
            sandbox_renameat(
                directory_descriptor,
                c"link-at".as_ptr(),
                directory_descriptor,
                c"renamed-at".as_ptr(),
            ),
            0
        );
        assert_eq!(
            sandbox_unlink(Fixture::c_path(&path("renamed")).as_ptr()),
            0
        );
        assert_eq!(
            sandbox_unlinkat(directory_descriptor, c"renamed-at".as_ptr(), 0),
            0
        );
        assert_eq!(
            sandbox_rmdir(Fixture::c_path(&path("directory")).as_ptr()),
            0
        );
        assert_eq!(
            sandbox_unlinkat(
                directory_descriptor,
                c"directory-at".as_ptr(),
                libc::AT_REMOVEDIR
            ),
            0
        );

        let mut actions: libc::posix_spawn_file_actions_t = std::ptr::null_mut();
        assert_eq!(libc::posix_spawn_file_actions_init(&mut actions), 0);
        assert_eq!(
            sandbox_spawn_addopen(&mut actions, 9, file_path.as_ptr(), libc::O_RDONLY, 0),
            0
        );
        commit_spawn_file_actions(&actions).unwrap();
        assert_eq!(sandbox_spawn_actions_destroy(&mut actions), 0);
        commit_spawn_file_actions(std::ptr::null()).unwrap();
        assert_eq!(sandbox_close(directory_descriptor), 0);
    }

    assert_eq!(std::fs::read(file).unwrap(), b"conte");
}

#[test]
fn filesystem_interposers_publish_open_and_close_audit_events() {
    let mut fixture = Fixture::new();
    let file = fixture.lower.join("audited");
    std::fs::write(&file, b"content").unwrap();
    let path = Fixture::c_path(&file);
    let (audit, server) = audit_server(vec![r#""Accepted""#, r#""Accepted""#]);
    fixture.runtime.audit = Some(audit);

    with_test_runtime(&fixture.runtime, || unsafe {
        let descriptor = sandbox_open_with_mode(path.as_ptr(), libc::O_RDONLY, 0);
        assert!(descriptor >= 0);
        assert_eq!(sandbox_close(descriptor), 0);
    });

    let requests = server.join().unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0]["event"]["type"], "file");
    assert_eq!(requests[0]["event"]["operation"], "open");
    assert_eq!(
        requests[0]["event"]["file"]["path"],
        file.to_string_lossy().as_ref()
    );
    assert_eq!(requests[0]["event"]["trace_id"], "test-trace");
    assert_eq!(requests[1]["event"]["operation"], "close");
}

#[test]
fn filesystem_interposers_fail_closed_when_audit_rejects_an_operation() {
    const ACCEPTED: &str = r#""Accepted""#;
    const DENIED: &str = r#"{"Error":{"errno":13,"message":"denied"}}"#;

    let mut fixture = Fixture::new();
    let file = fixture.lower.join("denied");
    std::fs::write(&file, b"content").unwrap();
    let path = Fixture::c_path(&file);
    let (audit, server) = audit_server(vec![
        DENIED, DENIED, DENIED, DENIED, DENIED, ACCEPTED, DENIED, ACCEPTED, DENIED,
    ]);
    fixture.runtime.audit = Some(audit);
    let mut descriptor = -1;
    let mut stream = std::ptr::null_mut();

    with_test_runtime(&fixture.runtime, || unsafe {
        assert_eq!(sandbox_open_with_mode(path.as_ptr(), libc::O_RDONLY, 0), -1);
        assert_eq!(*libc::__error(), libc::EACCES);
        assert_eq!(
            sandbox_openat_with_mode(libc::AT_FDCWD, path.as_ptr(), libc::O_RDONLY, 0),
            -1
        );
        assert_eq!(*libc::__error(), libc::EACCES);
        assert!(sandbox_fopen(path.as_ptr(), c"r".as_ptr()).is_null());
        assert_eq!(*libc::__error(), libc::EACCES);
        assert_eq!(sandbox_truncate(path.as_ptr(), 0), -1);
        assert_eq!(*libc::__error(), libc::EACCES);

        let mut actions: libc::posix_spawn_file_actions_t = std::ptr::null_mut();
        assert_eq!(libc::posix_spawn_file_actions_init(&mut actions), 0);
        assert_eq!(
            sandbox_spawn_addopen(&mut actions, 9, path.as_ptr(), libc::O_RDONLY, 0),
            libc::EACCES
        );
        assert_eq!(sandbox_spawn_actions_destroy(&mut actions), 0);

        descriptor = sandbox_open_with_mode(path.as_ptr(), libc::O_RDONLY, 0);
        assert!(descriptor >= 0);
        assert_eq!(sandbox_close(descriptor), -1);
        assert_eq!(*libc::__error(), libc::EACCES);

        stream = sandbox_fopen(path.as_ptr(), c"r".as_ptr());
        assert!(!stream.is_null());
        assert_eq!(sandbox_fclose(stream), -1);
        assert_eq!(*libc::__error(), libc::EACCES);
    });

    unsafe {
        assert_eq!(libc::close(descriptor), 0);
        assert_eq!(libc::fclose(stream), 0);
    }
    assert_eq!(server.join().unwrap().len(), 9);
}
