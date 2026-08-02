#![cfg(target_os = "macos")]

use super::config;
use super::dyld::{dyld_interpose, function_from_interpose};
use super::socket::set_errno;
use crate::audit::{AuditClient, AuditError, AuditEventRequest, FileOperation};
use crate::callback::{FileAccessMode, FileContext, FileOpenMode, ProcessContext};
use crate::filesystem::{DirectoryView, OverlayStore};
use crate::trace::TraceContext;
use anyhow::{Context, Result};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};

type OpenFn = unsafe extern "C" fn(*const libc::c_char, libc::c_int, libc::mode_t) -> libc::c_int;
type OpenAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
    libc::mode_t,
) -> libc::c_int;
type FopenFn = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> *mut libc::FILE;
type CloseFn = unsafe extern "C" fn(libc::c_int) -> libc::c_int;
type FcloseFn = unsafe extern "C" fn(*mut libc::FILE) -> libc::c_int;
type StatFn = unsafe extern "C" fn(*const libc::c_char, *mut libc::stat) -> libc::c_int;
type FstatAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    *mut libc::stat,
    libc::c_int,
) -> libc::c_int;
type AccessFn = unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int;
type UnlinkFn = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;
type RenameFn = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> libc::c_int;
type MkdirFn = unsafe extern "C" fn(*const libc::c_char, libc::mode_t) -> libc::c_int;
type ChdirFn = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;
type GetcwdFn = unsafe extern "C" fn(*mut libc::c_char, libc::size_t) -> *mut libc::c_char;
type OpendirFn = unsafe extern "C" fn(*const libc::c_char) -> *mut libc::DIR;
type ReaddirFn = unsafe extern "C" fn(*mut libc::DIR) -> *mut libc::dirent;
type ClosedirFn = unsafe extern "C" fn(*mut libc::DIR) -> libc::c_int;

thread_local! {
    static INSIDE_FILESYSTEM_HOOK: Cell<bool> = const { Cell::new(false) };
    static INITIALIZING_FILESYSTEM_RUNTIME: Cell<bool> = const { Cell::new(false) };
    #[cfg(test)]
    static TEST_FILESYSTEM_RUNTIME: Cell<*const FilesystemHookRuntime> = const { Cell::new(std::ptr::null()) };
}

struct FilesystemHookGuard;

impl FilesystemHookGuard {
    fn enter() -> Option<Self> {
        if !super::interpose::initialized() && !test_runtime_is_set() {
            return None;
        }
        INSIDE_FILESYSTEM_HOOK.with(|inside| (!inside.replace(true)).then_some(Self))
    }
}

#[cfg(test)]
fn test_runtime_is_set() -> bool {
    TEST_FILESYSTEM_RUNTIME.with(|runtime| !runtime.get().is_null())
}

#[cfg(not(test))]
fn test_runtime_is_set() -> bool {
    false
}

impl Drop for FilesystemHookGuard {
    fn drop(&mut self) {
        INSIDE_FILESYSTEM_HOOK.with(|inside| inside.set(false));
    }
}

struct FilesystemHookRuntime {
    overlay: OverlayStore,
    audit: Option<AuditClient>,
    trace: TraceContext,
    open_files: Mutex<HashMap<libc::c_int, FileContext>>,
}

struct PreparedOpen {
    mapped: CString,
    file: FileContext,
}

#[derive(Clone, Copy)]
enum PathIntent {
    Read,
    Write { create: bool },
    Directory,
}

impl FilesystemHookRuntime {
    fn global() -> Option<&'static Self> {
        #[cfg(test)]
        {
            let runtime = TEST_FILESYSTEM_RUNTIME.with(Cell::get);
            if !runtime.is_null() {
                return Some(unsafe { &*runtime });
            }
        }
        static RUNTIME: OnceLock<Option<FilesystemHookRuntime>> = OnceLock::new();
        if let Some(runtime) = RUNTIME.get() {
            return runtime.as_ref();
        }
        INITIALIZING_FILESYSTEM_RUNTIME.with(|initializing| {
            if initializing.replace(true) {
                return None;
            }
            let runtime = RUNTIME.get_or_init(|| {
                config::global().and_then(|config| {
                    OverlayStore::new(config.filesystem_root())
                        .ok()
                        .map(|overlay| Self {
                            overlay,
                            audit: Some(AuditClient::new(
                                config.audit_control(),
                                config.audit_token(),
                            )),
                            trace: config.trace().clone(),
                            open_files: Mutex::new(HashMap::new()),
                        })
                })
            });
            initializing.set(false);
            runtime.as_ref()
        })
    }

    #[cfg(test)]
    fn new(root: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self {
            overlay: OverlayStore::new(root)?,
            audit: None,
            trace: TraceContext::parse("test-trace").map_err(anyhow::Error::msg)?,
            open_files: Mutex::new(HashMap::new()),
        })
    }

    fn map(
        &self,
        path: *const libc::c_char,
        directory: libc::c_int,
        intent: PathIntent,
    ) -> Result<CString> {
        let logical = unsafe { self.logical_path(path, directory) }?;
        let mapped = match intent {
            PathIntent::Read => self.overlay.prepare_read(&logical)?,
            PathIntent::Write { create } => self.overlay.prepare_write(&logical, create)?,
            PathIntent::Directory => self.overlay.prepare_directory(&logical)?,
        };
        CString::new(mapped.as_os_str().as_bytes()).context("mapped filesystem path contains NUL")
    }

    unsafe fn logical_path(
        &self,
        path: *const libc::c_char,
        directory: libc::c_int,
    ) -> Result<PathBuf> {
        if path.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EFAULT).into());
        }
        let requested = Path::new(OsStr::from_bytes(
            unsafe { CStr::from_ptr(path) }.to_bytes(),
        ));
        if requested.is_absolute() {
            return self.logical_or_host(requested);
        }
        let base = if directory == libc::AT_FDCWD {
            std::env::current_dir().context("failed to resolve current directory")?
        } else {
            Self::descriptor_path(directory)?
        };
        Ok(self.logical_or_host(&base)?.join(requested))
    }

    fn logical_or_host(&self, path: &Path) -> Result<PathBuf> {
        if self.overlay.is_internal(path) {
            self.overlay.logical_path(path)
        } else {
            Ok(path.to_path_buf())
        }
    }

    fn descriptor_path(descriptor: libc::c_int) -> Result<PathBuf> {
        let mut buffer = vec![0_u8; libc::PATH_MAX as usize];
        if unsafe { libc::fcntl(descriptor, libc::F_GETPATH, buffer.as_mut_ptr()) } == -1 {
            return Err(io::Error::last_os_error())
                .context("failed to resolve directory descriptor");
        }
        let path = CStr::from_bytes_until_nul(&buffer)
            .context("directory descriptor path is not NUL terminated")?;
        Ok(PathBuf::from(OsStr::from_bytes(path.to_bytes())))
    }

    fn prepare_open(
        &self,
        path: *const libc::c_char,
        directory: libc::c_int,
        flags: libc::c_int,
    ) -> Result<PreparedOpen> {
        let logical = unsafe { self.logical_path(path, directory) }?;
        let writes = flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_CREAT | libc::O_TRUNC) != 0;
        let intent = if flags & libc::O_DIRECTORY != 0 {
            PathIntent::Directory
        } else if writes {
            PathIntent::Write {
                create: flags & libc::O_CREAT != 0,
            }
        } else {
            PathIntent::Read
        };
        let mapped = match intent {
            PathIntent::Read => self.overlay.prepare_read(&logical)?,
            PathIntent::Write { create } => self.overlay.prepare_write(&logical, create)?,
            PathIntent::Directory => self.overlay.prepare_directory(&logical)?,
        };
        Ok(PreparedOpen {
            mapped: CString::new(mapped.as_os_str().as_bytes())
                .context("mapped filesystem path contains NUL")?,
            file: FileContext {
                path: logical.to_string_lossy().into_owned(),
                mode: FileOpenMode {
                    access: match flags & libc::O_ACCMODE {
                        libc::O_WRONLY => FileAccessMode::Write,
                        libc::O_RDWR => FileAccessMode::ReadWrite,
                        _ => FileAccessMode::Read,
                    },
                    create: flags & libc::O_CREAT != 0,
                    truncate: flags & libc::O_TRUNC != 0,
                    append: flags & libc::O_APPEND != 0,
                    exclusive: flags & libc::O_EXCL != 0,
                },
            },
        })
    }

    fn prepare_fopen(
        &self,
        path: *const libc::c_char,
        mode: *const libc::c_char,
    ) -> Result<PreparedOpen> {
        if mode.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EFAULT).into());
        }
        let mode = unsafe { CStr::from_ptr(mode) }.to_bytes();
        let writes = mode
            .first()
            .is_some_and(|value| matches!(*value, b'w' | b'a'))
            || mode.contains(&b'+');
        let logical = unsafe { self.logical_path(path, libc::AT_FDCWD) }?;
        let intent = if writes {
            PathIntent::Write {
                create: mode
                    .first()
                    .is_some_and(|value| matches!(*value, b'w' | b'a')),
            }
        } else {
            PathIntent::Read
        };
        let mapped = match intent {
            PathIntent::Read => self.overlay.prepare_read(&logical)?,
            PathIntent::Write { create } => self.overlay.prepare_write(&logical, create)?,
            PathIntent::Directory => unreachable!(),
        };
        Ok(PreparedOpen {
            mapped: CString::new(mapped.as_os_str().as_bytes())
                .context("mapped filesystem path contains NUL")?,
            file: FileContext {
                path: logical.to_string_lossy().into_owned(),
                mode: FileOpenMode {
                    access: if mode.contains(&b'+') {
                        FileAccessMode::ReadWrite
                    } else if writes {
                        FileAccessMode::Write
                    } else {
                        FileAccessMode::Read
                    },
                    create: mode
                        .first()
                        .is_some_and(|value| matches!(*value, b'w' | b'a')),
                    truncate: mode.first() == Some(&b'w'),
                    append: mode.first() == Some(&b'a'),
                    exclusive: mode.contains(&b'x'),
                },
            },
        })
    }

    fn publish(&self, operation: FileOperation, file: FileContext) -> Result<(), AuditError> {
        let Some(audit) = &self.audit else {
            return Ok(());
        };
        let executable = std::env::current_exe()
            .map(|path| path.to_string_lossy().into_owned())
            .unwrap_or_default();
        audit.publish(AuditEventRequest::File {
            trace_id: self.trace.encode(),
            process: ProcessContext {
                pid: std::process::id(),
                ppid: unsafe { libc::getppid() as u32 },
                executable,
            },
            operation,
            file,
        })
    }

    fn register(&self, descriptor: libc::c_int, file: FileContext) {
        lock(&self.open_files).insert(descriptor, file);
    }

    fn tracked(&self, descriptor: libc::c_int) -> Option<FileContext> {
        lock(&self.open_files).get(&descriptor).cloned()
    }

    fn remove_descriptor(&self, descriptor: libc::c_int) {
        lock(&self.open_files).remove(&descriptor);
    }

    fn create_directory(&self, path: *const libc::c_char, mode: libc::mode_t) -> Result<()> {
        let logical = unsafe { self.logical_path(path, libc::AT_FDCWD) }?;
        self.overlay
            .create_directory(&logical, u32::from(mode))
            .map(|_| ())
    }

    fn remove(&self, path: *const libc::c_char, directory: bool) -> Result<()> {
        let logical = unsafe { self.logical_path(path, libc::AT_FDCWD) }?;
        self.overlay.remove(&logical, directory)
    }

    fn rename(&self, from: *const libc::c_char, to: *const libc::c_char) -> Result<()> {
        let from = unsafe { self.logical_path(from, libc::AT_FDCWD) }?;
        let to = unsafe { self.logical_path(to, libc::AT_FDCWD) }?;
        self.overlay.rename(&from, &to)
    }

    fn logical_current_directory(&self, original: GetcwdFn) -> Result<CString> {
        let mut buffer = vec![0_i8; libc::PATH_MAX as usize];
        if unsafe { original(buffer.as_mut_ptr(), buffer.len()) }.is_null() {
            return Err(io::Error::last_os_error()).context("failed to read current directory");
        }
        let actual = Path::new(OsStr::from_bytes(
            unsafe { CStr::from_ptr(buffer.as_ptr()) }.to_bytes(),
        ));
        let logical = self.logical_or_host(actual)?;
        CString::new(logical.as_os_str().as_bytes()).context("current directory contains NUL")
    }

    fn directory_view(&self, path: *const libc::c_char) -> Result<DirectoryView> {
        let logical = unsafe { self.logical_path(path, libc::AT_FDCWD) }?;
        self.overlay.directory_view(&logical)
    }
}

#[cfg(test)]
fn with_test_runtime<T>(runtime: &FilesystemHookRuntime, operation: impl FnOnce() -> T) -> T {
    struct ResetTestRuntime(*const FilesystemHookRuntime);

    impl Drop for ResetTestRuntime {
        fn drop(&mut self) {
            TEST_FILESYSTEM_RUNTIME.with(|runtime| runtime.set(self.0));
        }
    }

    let previous = TEST_FILESYSTEM_RUNTIME.with(|slot| slot.replace(runtime));
    let _reset = ResetTestRuntime(previous);
    operation()
}

fn error_errno(error: &anyhow::Error) -> libc::c_int {
    error
        .chain()
        .find_map(|cause| cause.downcast_ref::<io::Error>()?.raw_os_error())
        .unwrap_or(libc::EIO)
}

unsafe fn fail<T>(error: &anyhow::Error, value: T) -> T {
    unsafe { set_errno(error_errno(error)) };
    value
}

unsafe fn fail_audit<T>(error: &AuditError, value: T) -> T {
    unsafe { set_errno(error.errno()) };
    value
}

fn catch_filesystem_panic<T: Copy>(failure: T, operation: impl FnOnce() -> T) -> T {
    catch_unwind(AssertUnwindSafe(operation)).unwrap_or_else(|_| {
        unsafe { set_errno(libc::EIO) };
        failure
    })
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct DirectoryCursor {
    lower: Option<usize>,
    reading_lower: bool,
    hidden: HashSet<Vec<u8>>,
    seen: HashSet<Vec<u8>>,
}

impl DirectoryCursor {
    fn new(lower: Option<*mut libc::DIR>, view: &DirectoryView) -> Self {
        Self {
            lower: lower.map(|directory| directory as usize),
            reading_lower: false,
            hidden: view
                .hidden()
                .iter()
                .map(|name| name.as_bytes().to_vec())
                .collect(),
            seen: HashSet::new(),
        }
    }

    fn include(&mut self, name: &[u8], lower: bool) -> bool {
        if self.hidden.contains(name) || lower && self.seen.contains(name) {
            return false;
        }
        self.seen.insert(name.to_vec());
        true
    }
}

fn directory_cursors() -> &'static Mutex<HashMap<usize, DirectoryCursor>> {
    static DIRECTORIES: OnceLock<Mutex<HashMap<usize, DirectoryCursor>>> = OnceLock::new();
    DIRECTORIES.get_or_init(|| Mutex::new(HashMap::new()))
}

unsafe fn sandbox_open_with_mode(
    path: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_open() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path, flags, mode) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path, flags, mode) };
        };
        match runtime.prepare_open(path, libc::AT_FDCWD, flags) {
            Ok(prepared) => {
                if let Err(error) = runtime.publish(FileOperation::Open, prepared.file.clone()) {
                    return unsafe { fail_audit(&error, -1) };
                }
                let descriptor = unsafe { original(prepared.mapped.as_ptr(), flags, mode) };
                if descriptor >= 0 {
                    runtime.register(descriptor, prepared.file);
                }
                descriptor
            }
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_open_with_mode(
    path: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    unsafe { sandbox_open_with_mode(path, flags, mode) }
}

unsafe fn sandbox_openat_with_mode(
    directory: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_openat() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(directory, path, flags, mode) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(directory, path, flags, mode) };
        };
        match runtime.prepare_open(path, directory, flags) {
            Ok(prepared) => {
                if let Err(error) = runtime.publish(FileOperation::Open, prepared.file.clone()) {
                    return unsafe { fail_audit(&error, -1) };
                }
                let descriptor =
                    unsafe { original(libc::AT_FDCWD, prepared.mapped.as_ptr(), flags, mode) };
                if descriptor >= 0 {
                    runtime.register(descriptor, prepared.file);
                }
                descriptor
            }
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_openat_with_mode(
    directory: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    unsafe { sandbox_openat_with_mode(directory, path, flags, mode) }
}

unsafe fn sandbox_fopen(path: *const libc::c_char, mode: *const libc::c_char) -> *mut libc::FILE {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_fopen() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path, mode) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path, mode) };
        };
        match runtime.prepare_fopen(path, mode) {
            Ok(prepared) => {
                if let Err(error) = runtime.publish(FileOperation::Open, prepared.file.clone()) {
                    return unsafe { fail_audit(&error, std::ptr::null_mut()) };
                }
                let stream = unsafe { original(prepared.mapped.as_ptr(), mode) };
                if !stream.is_null() {
                    let descriptor = unsafe { libc::fileno(stream) };
                    if descriptor >= 0 {
                        runtime.register(descriptor, prepared.file);
                    }
                }
                stream
            }
            Err(error) => unsafe { fail(&error, std::ptr::null_mut()) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fopen(
    path: *const libc::c_char,
    mode: *const libc::c_char,
) -> *mut libc::FILE {
    unsafe { sandbox_fopen(path, mode) }
}

unsafe fn sandbox_close(descriptor: libc::c_int) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_close() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(descriptor) };
        };
        if let Some(file) = runtime.tracked(descriptor)
            && let Err(error) = runtime.publish(FileOperation::Close, file)
        {
            return unsafe { fail_audit(&error, -1) };
        }
        let result = unsafe { original(descriptor) };
        if result == 0 {
            runtime.remove_descriptor(descriptor);
        }
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_close(descriptor: libc::c_int) -> libc::c_int {
    unsafe { sandbox_close(descriptor) }
}

unsafe fn sandbox_fclose(stream: *mut libc::FILE) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_fclose() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(stream) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(stream) };
        };
        let descriptor = if stream.is_null() {
            -1
        } else {
            unsafe { libc::fileno(stream) }
        };
        if let Some(file) = runtime.tracked(descriptor)
            && let Err(error) = runtime.publish(FileOperation::Close, file)
        {
            return unsafe { fail_audit(&error, -1) };
        }
        let result = unsafe { original(stream) };
        if result == 0 && descriptor >= 0 {
            runtime.remove_descriptor(descriptor);
        }
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fclose(stream: *mut libc::FILE) -> libc::c_int {
    unsafe { sandbox_fclose(stream) }
}

unsafe fn mapped_stat(
    path: *const libc::c_char,
    status: *mut libc::stat,
    original: StatFn,
) -> libc::c_int {
    let Some(_guard) = FilesystemHookGuard::enter() else {
        return unsafe { original(path, status) };
    };
    let Some(runtime) = FilesystemHookRuntime::global() else {
        return unsafe { original(path, status) };
    };
    match runtime.map(path, libc::AT_FDCWD, PathIntent::Read) {
        Ok(mapped) => unsafe { original(mapped.as_ptr(), status) },
        Err(error) => unsafe { fail(&error, -1) },
    }
}

unsafe fn sandbox_stat(path: *const libc::c_char, status: *mut libc::stat) -> libc::c_int {
    catch_filesystem_panic(-1, || match original_stat() {
        Some(original) => unsafe { mapped_stat(path, status, original) },
        None => {
            unsafe { set_errno(libc::ENOSYS) };
            -1
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_stat(
    path: *const libc::c_char,
    status: *mut libc::stat,
) -> libc::c_int {
    unsafe { sandbox_stat(path, status) }
}

unsafe fn sandbox_lstat(path: *const libc::c_char, status: *mut libc::stat) -> libc::c_int {
    catch_filesystem_panic(-1, || match original_lstat() {
        Some(original) => unsafe { mapped_stat(path, status, original) },
        None => {
            unsafe { set_errno(libc::ENOSYS) };
            -1
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_lstat(
    path: *const libc::c_char,
    status: *mut libc::stat,
) -> libc::c_int {
    unsafe { sandbox_lstat(path, status) }
}

unsafe fn sandbox_fstatat(
    directory: libc::c_int,
    path: *const libc::c_char,
    status: *mut libc::stat,
    flags: libc::c_int,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_fstatat() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(directory, path, status, flags) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(directory, path, status, flags) };
        };
        match runtime.map(path, directory, PathIntent::Read) {
            Ok(mapped) => unsafe { original(libc::AT_FDCWD, mapped.as_ptr(), status, flags) },
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fstatat(
    directory: libc::c_int,
    path: *const libc::c_char,
    status: *mut libc::stat,
    flags: libc::c_int,
) -> libc::c_int {
    unsafe { sandbox_fstatat(directory, path, status, flags) }
}

unsafe fn sandbox_access(path: *const libc::c_char, mode: libc::c_int) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_access() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path, mode) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path, mode) };
        };
        match runtime.map(path, libc::AT_FDCWD, PathIntent::Read) {
            Ok(mapped) => unsafe { original(mapped.as_ptr(), mode) },
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_access(
    path: *const libc::c_char,
    mode: libc::c_int,
) -> libc::c_int {
    unsafe { sandbox_access(path, mode) }
}

unsafe fn sandbox_unlink(path: *const libc::c_char) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_unlink() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path) };
        };
        match runtime.remove(path, false) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_unlink(path: *const libc::c_char) -> libc::c_int {
    unsafe { sandbox_unlink(path) }
}

unsafe fn sandbox_rmdir(path: *const libc::c_char) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_rmdir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path) };
        };
        match runtime.remove(path, true) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_rmdir(path: *const libc::c_char) -> libc::c_int {
    unsafe { sandbox_rmdir(path) }
}

unsafe fn sandbox_rename(from: *const libc::c_char, to: *const libc::c_char) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_rename() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(from, to) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(from, to) };
        };
        match runtime.rename(from, to) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_rename(
    from: *const libc::c_char,
    to: *const libc::c_char,
) -> libc::c_int {
    unsafe { sandbox_rename(from, to) }
}

unsafe fn sandbox_mkdir(path: *const libc::c_char, mode: libc::mode_t) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_mkdir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path, mode) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path, mode) };
        };
        match runtime.create_directory(path, mode) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_mkdir(
    path: *const libc::c_char,
    mode: libc::mode_t,
) -> libc::c_int {
    unsafe { sandbox_mkdir(path, mode) }
}

unsafe fn sandbox_chdir(path: *const libc::c_char) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_chdir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path) };
        };
        match runtime.map(path, libc::AT_FDCWD, PathIntent::Directory) {
            Ok(mapped) => unsafe { original(mapped.as_ptr()) },
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_chdir(path: *const libc::c_char) -> libc::c_int {
    unsafe { sandbox_chdir(path) }
}

unsafe fn sandbox_getcwd(buffer: *mut libc::c_char, size: libc::size_t) -> *mut libc::c_char {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_getcwd() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(buffer, size) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(buffer, size) };
        };
        let logical = match runtime.logical_current_directory(original) {
            Ok(logical) => logical,
            Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
        };
        let required = logical.as_bytes_with_nul().len();
        let (target, capacity) = if buffer.is_null() {
            let capacity = if size == 0 { required } else { size };
            let target = unsafe { libc::malloc(capacity) }.cast::<libc::c_char>();
            if target.is_null() {
                unsafe { set_errno(libc::ENOMEM) };
                return std::ptr::null_mut();
            }
            (target, capacity)
        } else {
            (buffer, size)
        };
        if capacity < required {
            if buffer.is_null() {
                unsafe { libc::free(target.cast()) };
            }
            unsafe { set_errno(libc::ERANGE) };
            return std::ptr::null_mut();
        }
        unsafe {
            std::ptr::copy_nonoverlapping(logical.as_ptr(), target, required);
        }
        target
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_getcwd(
    buffer: *mut libc::c_char,
    size: libc::size_t,
) -> *mut libc::c_char {
    unsafe { sandbox_getcwd(buffer, size) }
}

unsafe fn sandbox_opendir(path: *const libc::c_char) -> *mut libc::DIR {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_opendir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path) };
        };
        match runtime.directory_view(path) {
            Ok(view) => {
                let upper = match CString::new(view.upper().as_os_str().as_bytes()) {
                    Ok(path) => path,
                    Err(error) => return unsafe { fail(&error.into(), std::ptr::null_mut()) },
                };
                let directory = unsafe { original(upper.as_ptr()) };
                if directory.is_null() {
                    return directory;
                }
                let lower = match view.lower() {
                    Some(path) => {
                        let path = match CString::new(path.as_os_str().as_bytes()) {
                            Ok(path) => path,
                            Err(error) => {
                                unsafe { original_closedir().map(|close| close(directory)) };
                                return unsafe { fail(&error.into(), std::ptr::null_mut()) };
                            }
                        };
                        let lower = unsafe { original(path.as_ptr()) };
                        if lower.is_null() {
                            let error = io::Error::last_os_error();
                            unsafe { original_closedir().map(|close| close(directory)) };
                            return unsafe { fail(&error.into(), std::ptr::null_mut()) };
                        }
                        Some(lower)
                    }
                    None => None,
                };
                lock(directory_cursors())
                    .insert(directory as usize, DirectoryCursor::new(lower, &view));
                directory
            }
            Err(error) => unsafe { fail(&error, std::ptr::null_mut()) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_opendir(path: *const libc::c_char) -> *mut libc::DIR {
    unsafe { sandbox_opendir(path) }
}

unsafe fn sandbox_readdir(directory: *mut libc::DIR) -> *mut libc::dirent {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_readdir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        let mut cursors = lock(directory_cursors());
        let Some(cursor) = cursors.get_mut(&(directory as usize)) else {
            return unsafe { original(directory) };
        };
        loop {
            let source = if cursor.reading_lower {
                let Some(lower) = cursor.lower else {
                    return std::ptr::null_mut();
                };
                lower as *mut libc::DIR
            } else {
                directory
            };
            unsafe { set_errno(0) };
            let entry = unsafe { original(source) };
            if entry.is_null() {
                if !cursor.reading_lower && unsafe { *libc::__error() } == 0 {
                    cursor.reading_lower = true;
                    continue;
                }
                return std::ptr::null_mut();
            }
            let name = unsafe { CStr::from_ptr((*entry).d_name.as_ptr()) };
            if cursor.include(name.to_bytes(), cursor.reading_lower) {
                return entry;
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_readdir(directory: *mut libc::DIR) -> *mut libc::dirent {
    unsafe { sandbox_readdir(directory) }
}

unsafe fn sandbox_closedir(directory: *mut libc::DIR) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_closedir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let cursor = lock(directory_cursors()).remove(&(directory as usize));
        let lower_result = cursor
            .and_then(|cursor| cursor.lower)
            .map(|lower| unsafe { original(lower as *mut libc::DIR) });
        let result = unsafe { original(directory) };
        if result == 0 {
            lower_result.unwrap_or(0)
        } else {
            result
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_closedir(directory: *mut libc::DIR) -> libc::c_int {
    unsafe { sandbox_closedir(directory) }
}

fn original_open() -> Option<OpenFn> {
    (!INTERPOSE_OPEN.replacee.is_null()).then_some(call_original_open)
}

fn original_openat() -> Option<OpenAtFn> {
    (!INTERPOSE_OPENAT.replacee.is_null()).then_some(call_original_openat)
}

unsafe extern "C" fn call_original_open(
    path: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    unsafe { agora_sandbox_call_open(INTERPOSE_OPEN.replacee, path, flags, mode) }
}

unsafe extern "C" fn call_original_openat(
    directory: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    unsafe { agora_sandbox_call_openat(INTERPOSE_OPENAT.replacee, directory, path, flags, mode) }
}

fn original_fopen() -> Option<FopenFn> {
    function_from_interpose(&INTERPOSE_FOPEN)
}

fn original_close() -> Option<CloseFn> {
    function_from_interpose(&INTERPOSE_CLOSE)
}

fn original_fclose() -> Option<FcloseFn> {
    function_from_interpose(&INTERPOSE_FCLOSE)
}

fn original_stat() -> Option<StatFn> {
    function_from_interpose(&INTERPOSE_STAT)
}

fn original_lstat() -> Option<StatFn> {
    function_from_interpose(&INTERPOSE_LSTAT)
}

fn original_fstatat() -> Option<FstatAtFn> {
    function_from_interpose(&INTERPOSE_FSTATAT)
}

fn original_access() -> Option<AccessFn> {
    function_from_interpose(&INTERPOSE_ACCESS)
}

fn original_unlink() -> Option<UnlinkFn> {
    function_from_interpose(&INTERPOSE_UNLINK)
}

fn original_rmdir() -> Option<UnlinkFn> {
    function_from_interpose(&INTERPOSE_RMDIR)
}

fn original_rename() -> Option<RenameFn> {
    function_from_interpose(&INTERPOSE_RENAME)
}

fn original_mkdir() -> Option<MkdirFn> {
    function_from_interpose(&INTERPOSE_MKDIR)
}

fn original_chdir() -> Option<ChdirFn> {
    function_from_interpose(&INTERPOSE_CHDIR)
}

fn original_getcwd() -> Option<GetcwdFn> {
    function_from_interpose(&INTERPOSE_GETCWD)
}

fn original_opendir() -> Option<OpendirFn> {
    function_from_interpose(&INTERPOSE_OPENDIR)
}

fn original_readdir() -> Option<ReaddirFn> {
    function_from_interpose(&INTERPOSE_READDIR)
}

fn original_closedir() -> Option<ClosedirFn> {
    function_from_interpose(&INTERPOSE_CLOSEDIR)
}

unsafe extern "C" {
    fn agora_sandbox_call_open(
        function: *const libc::c_void,
        path: *const libc::c_char,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> libc::c_int;

    fn agora_sandbox_call_openat(
        function: *const libc::c_void,
        directory: libc::c_int,
        path: *const libc::c_char,
        flags: libc::c_int,
        mode: libc::mode_t,
    ) -> libc::c_int;

    fn agora_sandbox_open_shim(path: *const libc::c_char, flags: libc::c_int, ...) -> libc::c_int;

    fn agora_sandbox_openat_shim(
        directory: libc::c_int,
        path: *const libc::c_char,
        flags: libc::c_int,
        ...
    ) -> libc::c_int;

}

dyld_interpose!(INTERPOSE_OPEN, agora_sandbox_open_shim, libc::open);
dyld_interpose!(INTERPOSE_OPENAT, agora_sandbox_openat_shim, libc::openat);
dyld_interpose!(INTERPOSE_FOPEN, agora_sandbox_fopen, libc::fopen);
dyld_interpose!(INTERPOSE_CLOSE, agora_sandbox_close, libc::close);
dyld_interpose!(INTERPOSE_FCLOSE, agora_sandbox_fclose, libc::fclose);
dyld_interpose!(INTERPOSE_STAT, agora_sandbox_stat, libc::stat);
dyld_interpose!(INTERPOSE_LSTAT, agora_sandbox_lstat, libc::lstat);
dyld_interpose!(INTERPOSE_FSTATAT, agora_sandbox_fstatat, libc::fstatat);
dyld_interpose!(INTERPOSE_ACCESS, agora_sandbox_access, libc::access);
dyld_interpose!(INTERPOSE_UNLINK, agora_sandbox_unlink, libc::unlink);
dyld_interpose!(INTERPOSE_RMDIR, agora_sandbox_rmdir, libc::rmdir);
dyld_interpose!(INTERPOSE_RENAME, agora_sandbox_rename, libc::rename);
dyld_interpose!(INTERPOSE_MKDIR, agora_sandbox_mkdir, libc::mkdir);
dyld_interpose!(INTERPOSE_CHDIR, agora_sandbox_chdir, libc::chdir);
dyld_interpose!(INTERPOSE_GETCWD, agora_sandbox_getcwd, libc::getcwd);
dyld_interpose!(INTERPOSE_OPENDIR, agora_sandbox_opendir, libc::opendir);
dyld_interpose!(INTERPOSE_READDIR, agora_sandbox_readdir, libc::readdir);
dyld_interpose!(INTERPOSE_CLOSEDIR, agora_sandbox_closedir, libc::closedir);

#[cfg(test)]
mod tests;
