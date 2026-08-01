use super::{
    DirectoryCursor, FilesystemHookRuntime, PathIntent, agora_sandbox_access as sandbox_access,
    agora_sandbox_chdir as sandbox_chdir, agora_sandbox_closedir as sandbox_closedir,
    agora_sandbox_fopen as sandbox_fopen, agora_sandbox_fstatat as sandbox_fstatat,
    agora_sandbox_getcwd as sandbox_getcwd, agora_sandbox_lstat as sandbox_lstat,
    agora_sandbox_mkdir as sandbox_mkdir, agora_sandbox_open_with_mode as sandbox_open_with_mode,
    agora_sandbox_openat_with_mode as sandbox_openat_with_mode,
    agora_sandbox_opendir as sandbox_opendir, agora_sandbox_readdir as sandbox_readdir,
    agora_sandbox_rename as sandbox_rename, agora_sandbox_rmdir as sandbox_rmdir,
    agora_sandbox_stat as sandbox_stat, agora_sandbox_unlink as sandbox_unlink,
    catch_filesystem_panic, with_test_runtime,
};
use crate::filesystem::EntryState;
use std::collections::HashSet;
use std::ffi::{CStr, CString};
use std::path::{Path, PathBuf};

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

    fixture
        .runtime
        .map_open(path.as_ptr(), libc::AT_FDCWD, libc::O_RDONLY)
        .unwrap();
    assert!(matches!(
        fixture.runtime.overlay.state_for_test(&lower).unwrap(),
        Some(EntryState::Cached { .. })
    ));

    fixture
        .runtime
        .map_open(path.as_ptr(), libc::AT_FDCWD, libc::O_WRONLY)
        .unwrap();
    assert_eq!(
        fixture.runtime.overlay.state_for_test(&lower).unwrap(),
        Some(EntryState::Cow)
    );

    let created = fixture.lower.join("created");
    fixture
        .runtime
        .map_open(
            Fixture::c_path(&created).as_ptr(),
            libc::AT_FDCWD,
            libc::O_WRONLY | libc::O_CREAT,
        )
        .unwrap();
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
        .rename(source_path.as_ptr(), target_path.as_ptr())
        .unwrap();
    assert_eq!(std::fs::read(&source).unwrap(), b"host");
    assert!(fixture.runtime.overlay.prepare_read(&source).is_err());
    assert_eq!(
        std::fs::read(fixture.runtime.overlay.prepare_read(&target).unwrap()).unwrap(),
        b"host"
    );

    fixture.runtime.remove(target_path.as_ptr(), false).unwrap();
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
        assert_eq!(libc::write(descriptor, b"sandbox".as_ptr().cast(), 7), 7);
        assert_eq!(libc::close(descriptor), 0);

        let stream = sandbox_fopen(writable.as_ptr(), c"r".as_ptr());
        assert!(!stream.is_null());
        assert_eq!(libc::fclose(stream), 0);

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
        assert_eq!(libc::close(descriptor), 0);

        let created_path = Fixture::c_path(&created);
        let descriptor =
            sandbox_open_with_mode(created_path.as_ptr(), libc::O_WRONLY | libc::O_CREAT, 0o600);
        assert!(descriptor >= 0);
        assert_eq!(libc::close(descriptor), 0);

        let stream = sandbox_fopen(created_path.as_ptr(), c"a+".as_ptr());
        assert!(!stream.is_null());
        assert_eq!(libc::fclose(stream), 0);

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
        assert!(sandbox_getcwd(cwd.as_mut_ptr(), 1).is_null());

        let mut status = std::mem::zeroed();
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
        assert_eq!(sandbox_rmdir(std::ptr::null()), -1);
        assert_eq!(sandbox_rename(std::ptr::null(), created_path.as_ptr()), -1);
        assert_eq!(sandbox_mkdir(std::ptr::null(), 0o755), -1);
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
