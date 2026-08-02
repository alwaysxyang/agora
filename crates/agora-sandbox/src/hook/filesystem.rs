#![cfg(target_os = "macos")]

use super::config;
use super::dyld::{dyld_interpose, function_from_interpose};
use super::socket::set_errno;
use crate::audit::{AuditClient, AuditError, AuditEventRequest, FileOperation};
use crate::callback::{FileAccessMode, FileContext, FileOpenMode, ProcessContext};
use crate::filesystem::{DirectoryView, OverlayStore, StagedWrite};
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
type UnlinkAtFn =
    unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::c_int) -> libc::c_int;
type RenameFn = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> libc::c_int;
type RenameAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
    *const libc::c_char,
) -> libc::c_int;
type MkdirFn = unsafe extern "C" fn(*const libc::c_char, libc::mode_t) -> libc::c_int;
type MkdirAtFn =
    unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::mode_t) -> libc::c_int;
type TruncateFn = unsafe extern "C" fn(*const libc::c_char, libc::off_t) -> libc::c_int;
type FtruncateFn = unsafe extern "C" fn(libc::c_int, libc::off_t) -> libc::c_int;
type ChmodFn = unsafe extern "C" fn(*const libc::c_char, libc::mode_t) -> libc::c_int;
type FchmodFn = unsafe extern "C" fn(libc::c_int, libc::mode_t) -> libc::c_int;
type ChownFn = unsafe extern "C" fn(*const libc::c_char, libc::uid_t, libc::gid_t) -> libc::c_int;
type FchownFn = unsafe extern "C" fn(libc::c_int, libc::uid_t, libc::gid_t) -> libc::c_int;
type FchmodAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    libc::mode_t,
    libc::c_int,
) -> libc::c_int;
type FchownAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    libc::uid_t,
    libc::gid_t,
    libc::c_int,
) -> libc::c_int;
type LinkFn = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> libc::c_int;
type LinkAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
) -> libc::c_int;
type SymlinkFn = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> libc::c_int;
type SymlinkAtFn =
    unsafe extern "C" fn(*const libc::c_char, libc::c_int, *const libc::c_char) -> libc::c_int;
type ClonefileFn =
    unsafe extern "C" fn(*const libc::c_char, *const libc::c_char, u32) -> libc::c_int;
type ClonefileAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
    *const libc::c_char,
    u32,
) -> libc::c_int;
type CopyfileFn = unsafe extern "C" fn(
    *const libc::c_char,
    *const libc::c_char,
    libc::copyfile_state_t,
    libc::copyfile_flags_t,
) -> libc::c_int;
type PosixSpawnAddOpenFn = unsafe extern "C" fn(
    *mut libc::posix_spawn_file_actions_t,
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
    libc::mode_t,
) -> libc::c_int;
type PosixSpawnFileActionsDestroyFn =
    unsafe extern "C" fn(*mut libc::posix_spawn_file_actions_t) -> libc::c_int;
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
        INSIDE_FILESYSTEM_HOOK.with(|inside| {
            if inside.replace(true) {
                None
            } else {
                Some(Self)
            }
        })
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
    current_directory: Mutex<PathBuf>,
    open_files: Mutex<HashMap<libc::c_int, FileContext>>,
}

struct PreparedOpen {
    mapped: CString,
    file: FileContext,
    staged_write: Option<StagedWrite>,
}

struct OpenRequest {
    logical: PathBuf,
    intent: PathIntent,
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
                        .and_then(|overlay| {
                            let current_directory =
                                Self::native_current_directory(&overlay).ok()?;
                            Some(Self {
                                overlay,
                                audit: Some(AuditClient::new(
                                    config.audit_control(),
                                    config.audit_token(),
                                )),
                                trace: config.trace().clone(),
                                current_directory: Mutex::new(current_directory),
                                open_files: Mutex::new(HashMap::new()),
                            })
                        })
                })
            });
            initializing.set(false);
            runtime.as_ref()
        })
    }

    #[cfg(test)]
    fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let overlay = OverlayStore::new(root)?;
        let current_directory = Self::native_current_directory(&overlay)?;
        Ok(Self {
            overlay,
            audit: None,
            trace: TraceContext::parse("test-trace").map_err(anyhow::Error::msg)?,
            current_directory: Mutex::new(current_directory),
            open_files: Mutex::new(HashMap::new()),
        })
    }

    fn native_current_directory(overlay: &OverlayStore) -> Result<PathBuf> {
        let directory = std::env::current_dir().context("failed to resolve current directory")?;
        if overlay.is_internal(&directory) {
            overlay.logical_path(&directory)
        } else {
            Ok(directory)
        }
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
            lock(&self.current_directory).clone()
        } else {
            self.tracked(directory)
                .map(|file| PathBuf::from(file.path))
                .map(Ok)
                .unwrap_or_else(|| Self::descriptor_path(directory))?
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
    ) -> Result<OpenRequest> {
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
        Ok(OpenRequest {
            logical: logical.clone(),
            intent,
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
    ) -> Result<OpenRequest> {
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
        Ok(OpenRequest {
            logical: logical.clone(),
            intent,
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

    fn map_open(&self, request: OpenRequest) -> Result<PreparedOpen> {
        let (mapped, staged_write) = match request.intent {
            PathIntent::Read => (self.overlay.prepare_read(&request.logical)?, None),
            PathIntent::Write { create } => {
                let staged = self.overlay.stage_write(&request.logical, create)?;
                (staged.destination().to_path_buf(), Some(staged))
            }
            PathIntent::Directory => (self.overlay.prepare_directory(&request.logical)?, None),
        };
        Ok(PreparedOpen {
            mapped: CString::new(mapped.as_os_str().as_bytes())
                .context("mapped filesystem path contains NUL")?,
            file: request.file,
            staged_write,
        })
    }

    fn commit_open(&self, prepared: &mut PreparedOpen) -> Result<()> {
        if let Some(staged) = prepared.staged_write.take() {
            self.overlay.commit_write(staged)?;
        }
        Ok(())
    }

    fn prepare_descriptor_mutation(&self, descriptor: libc::c_int) -> Result<StagedWrite> {
        let path = Self::descriptor_path(descriptor)?;
        if !self.overlay.is_internal(&path) {
            return Err(io::Error::from_raw_os_error(libc::EPERM).into());
        }
        if !path.symlink_metadata()?.is_file() {
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP).into());
        }
        let logical = self.overlay.logical_path(&path)?;
        self.overlay.stage_write(&logical, false)
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

    fn create_directory(
        &self,
        directory: libc::c_int,
        path: *const libc::c_char,
        mode: libc::mode_t,
    ) -> Result<()> {
        let logical = unsafe { self.logical_path(path, directory) }?;
        self.overlay
            .create_directory(&logical, u32::from(mode))
            .map(|_| ())
    }

    fn remove(
        &self,
        directory: libc::c_int,
        path: *const libc::c_char,
        remove_directory: bool,
    ) -> Result<()> {
        let logical = unsafe { self.logical_path(path, directory) }?;
        self.overlay.remove(&logical, remove_directory)
    }

    fn rename(
        &self,
        from_directory: libc::c_int,
        from: *const libc::c_char,
        to_directory: libc::c_int,
        to: *const libc::c_char,
    ) -> Result<()> {
        let from = unsafe { self.logical_path(from, from_directory) }?;
        let to = unsafe { self.logical_path(to, to_directory) }?;
        self.overlay.rename(&from, &to)
    }

    fn prepare_change_directory(&self, path: *const libc::c_char) -> Result<(CString, PathBuf)> {
        let logical = unsafe { self.logical_path(path, libc::AT_FDCWD) }?;
        let mapped = self.overlay.prepare_directory(&logical)?;
        let mapped = CString::new(mapped.as_os_str().as_bytes())
            .context("mapped filesystem path contains NUL")?;
        Ok((mapped, logical))
    }

    fn set_current_directory(&self, directory: PathBuf) {
        *lock(&self.current_directory) = directory;
    }

    fn logical_current_directory(&self) -> Result<CString> {
        let logical = lock(&self.current_directory);
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
        .find_map(|cause| {
            let error = cause.downcast_ref::<io::Error>()?;
            Some(error.raw_os_error().unwrap_or(match error.kind() {
                io::ErrorKind::NotFound => libc::ENOENT,
                io::ErrorKind::PermissionDenied => libc::EACCES,
                io::ErrorKind::AlreadyExists => libc::EEXIST,
                io::ErrorKind::InvalidInput | io::ErrorKind::InvalidData => libc::EINVAL,
                io::ErrorKind::Interrupted => libc::EINTR,
                io::ErrorKind::Unsupported => libc::ENOTSUP,
                io::ErrorKind::OutOfMemory => libc::ENOMEM,
                io::ErrorKind::NotADirectory => libc::ENOTDIR,
                io::ErrorKind::IsADirectory => libc::EISDIR,
                io::ErrorKind::DirectoryNotEmpty => libc::ENOTEMPTY,
                _ => libc::EIO,
            }))
        })
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

fn pending_spawn_writes() -> &'static Mutex<HashMap<usize, Vec<StagedWrite>>> {
    static WRITES: OnceLock<Mutex<HashMap<usize, Vec<StagedWrite>>>> = OnceLock::new();
    WRITES.get_or_init(|| Mutex::new(HashMap::new()))
}

unsafe fn spawn_file_actions_key(
    actions: *const libc::posix_spawn_file_actions_t,
) -> Option<usize> {
    if actions.is_null() {
        return None;
    }
    let key = unsafe { *actions } as usize;
    (key != 0).then_some(key)
}

pub(super) unsafe fn commit_spawn_file_actions(
    actions: *const libc::posix_spawn_file_actions_t,
) -> Result<()> {
    let Some(key) = (unsafe { spawn_file_actions_key(actions) }) else {
        return Ok(());
    };
    let writes = lock(pending_spawn_writes()).remove(&key);
    let Some(runtime) = FilesystemHookRuntime::global() else {
        return Ok(());
    };
    for staged in writes.into_iter().flatten() {
        runtime.overlay.commit_write(staged)?;
    }
    Ok(())
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
            Ok(request) => {
                if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
                    return unsafe { fail_audit(&error, -1) };
                }
                let mut prepared = match runtime.map_open(request) {
                    Ok(prepared) => prepared,
                    Err(error) => return unsafe { fail(&error, -1) },
                };
                let descriptor = unsafe { original(prepared.mapped.as_ptr(), flags, mode) };
                if descriptor >= 0 {
                    if let Err(error) = runtime.commit_open(&mut prepared) {
                        if let Some(close) = original_close() {
                            unsafe { close(descriptor) };
                        }
                        return unsafe { fail(&error, -1) };
                    }
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
            Ok(request) => {
                if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
                    return unsafe { fail_audit(&error, -1) };
                }
                let mut prepared = match runtime.map_open(request) {
                    Ok(prepared) => prepared,
                    Err(error) => return unsafe { fail(&error, -1) },
                };
                let descriptor =
                    unsafe { original(libc::AT_FDCWD, prepared.mapped.as_ptr(), flags, mode) };
                if descriptor >= 0 {
                    if let Err(error) = runtime.commit_open(&mut prepared) {
                        if let Some(close) = original_close() {
                            unsafe { close(descriptor) };
                        }
                        return unsafe { fail(&error, -1) };
                    }
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

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_creat(
    path: *const libc::c_char,
    mode: libc::mode_t,
) -> libc::c_int {
    unsafe { sandbox_open_with_mode(path, libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC, mode) }
}

unsafe fn sandbox_truncate(path: *const libc::c_char, length: libc::off_t) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_truncate() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path, length) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path, length) };
        };
        let request =
            match runtime.prepare_open(path, libc::AT_FDCWD, libc::O_WRONLY | libc::O_TRUNC) {
                Ok(request) => request,
                Err(error) => return unsafe { fail(&error, -1) },
            };
        if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
            return unsafe { fail_audit(&error, -1) };
        }
        let mut prepared = match runtime.map_open(request) {
            Ok(prepared) => prepared,
            Err(error) => return unsafe { fail(&error, -1) },
        };
        let result = unsafe { original(prepared.mapped.as_ptr(), length) };
        if result == 0
            && let Err(error) = runtime.commit_open(&mut prepared)
        {
            return unsafe { fail(&error, -1) };
        }
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_truncate(
    path: *const libc::c_char,
    length: libc::off_t,
) -> libc::c_int {
    unsafe { sandbox_truncate(path, length) }
}

unsafe fn sandbox_descriptor_mutation(
    descriptor: libc::c_int,
    operation: impl FnOnce(libc::c_int) -> libc::c_int,
) -> libc::c_int {
    let Some(_guard) = FilesystemHookGuard::enter() else {
        return operation(descriptor);
    };
    let Some(runtime) = FilesystemHookRuntime::global() else {
        return operation(descriptor);
    };
    let staged = match runtime.prepare_descriptor_mutation(descriptor) {
        Ok(staged) => staged,
        Err(error) => return unsafe { fail(&error, -1) },
    };
    let result = operation(descriptor);
    if result == 0
        && let Err(error) = runtime.overlay.commit_write(staged)
    {
        return unsafe { fail(&error, -1) };
    }
    result
}

unsafe fn sandbox_unsupported_mutation(operation: impl FnOnce() -> libc::c_int) -> libc::c_int {
    let Some(_guard) = FilesystemHookGuard::enter() else {
        return operation();
    };
    if FilesystemHookRuntime::global().is_none() {
        return operation();
    }
    unsafe { set_errno(libc::ENOTSUP) };
    -1
}

macro_rules! unsupported_filesystem_hook {
    (
        $sandbox:ident, $export:ident, $original:ident,
        ($($argument:ident: $argument_type:ty),* $(,)?),
        ($($call_argument:expr),* $(,)?)
    ) => {
        unsafe fn $sandbox($($argument: $argument_type),*) -> libc::c_int {
            catch_filesystem_panic(-1, || match $original() {
                Some(original) => unsafe {
                    sandbox_unsupported_mutation(|| original($($call_argument),*))
                },
                None => unsafe {
                    set_errno(libc::ENOSYS);
                    -1
                },
            })
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $export($($argument: $argument_type),*) -> libc::c_int {
            unsafe { $sandbox($($argument),*) }
        }
    }
}

macro_rules! descriptor_filesystem_hook {
    (
        $sandbox:ident, $export:ident, $original:ident, $descriptor:ident,
        ($($argument:ident: $argument_type:ty),* $(,)?),
        ($($call_argument:expr),* $(,)?)
    ) => {
        unsafe fn $sandbox($($argument: $argument_type),*) -> libc::c_int {
            catch_filesystem_panic(-1, || match $original() {
                Some(original) => unsafe {
                    sandbox_descriptor_mutation($descriptor, |$descriptor| {
                        original($($call_argument),*)
                    })
                },
                None => unsafe {
                    set_errno(libc::ENOSYS);
                    -1
                },
            })
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $export($($argument: $argument_type),*) -> libc::c_int {
            unsafe { $sandbox($($argument),*) }
        }
    }
}

descriptor_filesystem_hook!(
    sandbox_ftruncate,
    agora_sandbox_ftruncate,
    original_ftruncate,
    descriptor,
    (descriptor: libc::c_int, length: libc::off_t),
    (descriptor, length)
);

unsupported_filesystem_hook!(
    sandbox_chmod,
    agora_sandbox_chmod,
    original_chmod,
    (path: *const libc::c_char, mode: libc::mode_t),
    (path, mode)
);

descriptor_filesystem_hook!(
    sandbox_fchmod,
    agora_sandbox_fchmod,
    original_fchmod,
    descriptor,
    (descriptor: libc::c_int, mode: libc::mode_t),
    (descriptor, mode)
);

unsupported_filesystem_hook!(
    sandbox_fchmodat,
    agora_sandbox_fchmodat,
    original_fchmodat,
    (
        directory: libc::c_int,
        path: *const libc::c_char,
        mode: libc::mode_t,
        flags: libc::c_int,
    ),
    (directory, path, mode, flags)
);

unsupported_filesystem_hook!(
    sandbox_chown,
    agora_sandbox_chown,
    original_chown,
    (
        path: *const libc::c_char,
        owner: libc::uid_t,
        group: libc::gid_t,
    ),
    (path, owner, group)
);

descriptor_filesystem_hook!(
    sandbox_fchown,
    agora_sandbox_fchown,
    original_fchown,
    descriptor,
    (
        descriptor: libc::c_int,
        owner: libc::uid_t,
        group: libc::gid_t,
    ),
    (descriptor, owner, group)
);

unsupported_filesystem_hook!(
    sandbox_lchown,
    agora_sandbox_lchown,
    original_lchown,
    (
        path: *const libc::c_char,
        owner: libc::uid_t,
        group: libc::gid_t,
    ),
    (path, owner, group)
);

unsupported_filesystem_hook!(
    sandbox_fchownat,
    agora_sandbox_fchownat,
    original_fchownat,
    (
        directory: libc::c_int,
        path: *const libc::c_char,
        owner: libc::uid_t,
        group: libc::gid_t,
        flags: libc::c_int,
    ),
    (directory, path, owner, group, flags)
);

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
            Ok(request) => {
                if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
                    return unsafe { fail_audit(&error, std::ptr::null_mut()) };
                }
                let mut prepared = match runtime.map_open(request) {
                    Ok(prepared) => prepared,
                    Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
                };
                let stream = unsafe { original(prepared.mapped.as_ptr(), mode) };
                if !stream.is_null() {
                    if let Err(error) = runtime.commit_open(&mut prepared) {
                        if let Some(close) = original_fclose() {
                            unsafe { close(stream) };
                        }
                        return unsafe { fail(&error, std::ptr::null_mut()) };
                    }
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

unsafe fn sandbox_posix_spawn_file_actions_addopen(
    actions: *mut libc::posix_spawn_file_actions_t,
    descriptor: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    catch_filesystem_panic(libc::EIO, || {
        let Some(original) = original_posix_spawn_file_actions_addopen() else {
            return libc::ENOSYS;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(actions, descriptor, path, flags, mode) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(actions, descriptor, path, flags, mode) };
        };
        let request = match runtime.prepare_open(path, libc::AT_FDCWD, flags) {
            Ok(request) => request,
            Err(error) => return error_errno(&error),
        };
        if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
            return error.errno();
        }
        let mut prepared = match runtime.map_open(request) {
            Ok(prepared) => prepared,
            Err(error) => return error_errno(&error),
        };
        let result =
            unsafe { original(actions, descriptor, prepared.mapped.as_ptr(), flags, mode) };
        if result == 0
            && let Some(staged) = prepared.staged_write.take()
            && let Some(key) = (unsafe { spawn_file_actions_key(actions) })
        {
            lock(pending_spawn_writes())
                .entry(key)
                .or_default()
                .push(staged);
        }
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_posix_spawn_file_actions_addopen(
    actions: *mut libc::posix_spawn_file_actions_t,
    descriptor: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    unsafe { sandbox_posix_spawn_file_actions_addopen(actions, descriptor, path, flags, mode) }
}

unsafe fn sandbox_posix_spawn_file_actions_destroy(
    actions: *mut libc::posix_spawn_file_actions_t,
) -> libc::c_int {
    catch_filesystem_panic(libc::EIO, || {
        let Some(original) = original_posix_spawn_file_actions_destroy() else {
            return libc::ENOSYS;
        };
        let key = unsafe { spawn_file_actions_key(actions) };
        let result = unsafe { original(actions) };
        if result == 0
            && let Some(key) = key
        {
            lock(pending_spawn_writes()).remove(&key);
        }
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_posix_spawn_file_actions_destroy(
    actions: *mut libc::posix_spawn_file_actions_t,
) -> libc::c_int {
    unsafe { sandbox_posix_spawn_file_actions_destroy(actions) }
}

unsupported_filesystem_hook!(
    sandbox_link,
    agora_sandbox_link,
    original_link,
    (
        source: *const libc::c_char,
        destination: *const libc::c_char,
    ),
    (source, destination)
);

unsupported_filesystem_hook!(
    sandbox_linkat,
    agora_sandbox_linkat,
    original_linkat,
    (
        source_directory: libc::c_int,
        source: *const libc::c_char,
        destination_directory: libc::c_int,
        destination: *const libc::c_char,
        flags: libc::c_int,
    ),
    (
        source_directory,
        source,
        destination_directory,
        destination,
        flags,
    )
);

unsupported_filesystem_hook!(
    sandbox_symlink,
    agora_sandbox_symlink,
    original_symlink,
    (
        target: *const libc::c_char,
        link: *const libc::c_char,
    ),
    (target, link)
);

unsupported_filesystem_hook!(
    sandbox_symlinkat,
    agora_sandbox_symlinkat,
    original_symlinkat,
    (
        target: *const libc::c_char,
        directory: libc::c_int,
        link: *const libc::c_char,
    ),
    (target, directory, link)
);

unsupported_filesystem_hook!(
    sandbox_clonefile,
    agora_sandbox_clonefile,
    original_clonefile,
    (
        source: *const libc::c_char,
        destination: *const libc::c_char,
        flags: u32,
    ),
    (source, destination, flags)
);

unsupported_filesystem_hook!(
    sandbox_clonefileat,
    agora_sandbox_clonefileat,
    original_clonefileat,
    (
        source_directory: libc::c_int,
        source: *const libc::c_char,
        destination_directory: libc::c_int,
        destination: *const libc::c_char,
        flags: u32,
    ),
    (
        source_directory,
        source,
        destination_directory,
        destination,
        flags,
    )
);

unsupported_filesystem_hook!(
    sandbox_copyfile,
    agora_sandbox_copyfile,
    original_copyfile,
    (
        source: *const libc::c_char,
        destination: *const libc::c_char,
        state: libc::copyfile_state_t,
        flags: libc::copyfile_flags_t,
    ),
    (source, destination, state, flags)
);

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

macro_rules! overlay_mutation_hook {
    (
        $sandbox:ident, $export:ident, $original:ident,
        ($($argument:ident: $argument_type:ty),* $(,)?),
        ($($call_argument:expr),* $(,)?),
        |$runtime:ident| $operation:expr
    ) => {
        unsafe fn $sandbox($($argument: $argument_type),*) -> libc::c_int {
            catch_filesystem_panic(-1, || {
                let Some(original) = $original() else {
                    unsafe { set_errno(libc::ENOSYS) };
                    return -1;
                };
                let Some(_guard) = FilesystemHookGuard::enter() else {
                    return unsafe { original($($call_argument),*) };
                };
                let Some($runtime) = FilesystemHookRuntime::global() else {
                    return unsafe { original($($call_argument),*) };
                };
                match $operation {
                    Ok(()) => 0,
                    Err(error) => unsafe { fail(&error, -1) },
                }
            })
        }

        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn $export($($argument: $argument_type),*) -> libc::c_int {
            unsafe { $sandbox($($argument),*) }
        }
    }
}

overlay_mutation_hook!(
    sandbox_unlink,
    agora_sandbox_unlink,
    original_unlink,
    (path: *const libc::c_char),
    (path),
    |runtime| runtime.remove(libc::AT_FDCWD, path, false)
);

unsafe fn sandbox_unlinkat(
    directory: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_unlinkat() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(directory, path, flags) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(directory, path, flags) };
        };
        let supported = flags == 0 || flags == libc::AT_REMOVEDIR;
        if !supported {
            unsafe { set_errno(libc::EINVAL) };
            return -1;
        }
        match runtime.remove(directory, path, flags == libc::AT_REMOVEDIR) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_unlinkat(
    directory: libc::c_int,
    path: *const libc::c_char,
    flags: libc::c_int,
) -> libc::c_int {
    unsafe { sandbox_unlinkat(directory, path, flags) }
}

overlay_mutation_hook!(
    sandbox_rmdir,
    agora_sandbox_rmdir,
    original_rmdir,
    (path: *const libc::c_char),
    (path),
    |runtime| runtime.remove(libc::AT_FDCWD, path, true)
);

overlay_mutation_hook!(
    sandbox_rename,
    agora_sandbox_rename,
    original_rename,
    (from: *const libc::c_char, to: *const libc::c_char),
    (from, to),
    |runtime| runtime.rename(libc::AT_FDCWD, from, libc::AT_FDCWD, to)
);

overlay_mutation_hook!(
    sandbox_renameat,
    agora_sandbox_renameat,
    original_renameat,
    (
        from_directory: libc::c_int,
        from: *const libc::c_char,
        to_directory: libc::c_int,
        to: *const libc::c_char,
    ),
    (from_directory, from, to_directory, to),
    |runtime| runtime.rename(from_directory, from, to_directory, to)
);

overlay_mutation_hook!(
    sandbox_mkdir,
    agora_sandbox_mkdir,
    original_mkdir,
    (path: *const libc::c_char, mode: libc::mode_t),
    (path, mode),
    |runtime| runtime.create_directory(libc::AT_FDCWD, path, mode)
);

overlay_mutation_hook!(
    sandbox_mkdirat,
    agora_sandbox_mkdirat,
    original_mkdirat,
    (
        directory: libc::c_int,
        path: *const libc::c_char,
        mode: libc::mode_t,
    ),
    (directory, path, mode),
    |runtime| runtime.create_directory(directory, path, mode)
);

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
        match runtime.prepare_change_directory(path) {
            Ok((mapped, logical)) => {
                let result = unsafe { original(mapped.as_ptr()) };
                if result == 0 {
                    runtime.set_current_directory(logical);
                }
                result
            }
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
        let logical = match runtime.logical_current_directory() {
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

fn original_truncate() -> Option<TruncateFn> {
    function_from_interpose(&INTERPOSE_TRUNCATE)
}

fn original_ftruncate() -> Option<FtruncateFn> {
    function_from_interpose(&INTERPOSE_FTRUNCATE)
}

fn original_chmod() -> Option<ChmodFn> {
    function_from_interpose(&INTERPOSE_CHMOD)
}

fn original_fchmod() -> Option<FchmodFn> {
    function_from_interpose(&INTERPOSE_FCHMOD)
}

fn original_fchmodat() -> Option<FchmodAtFn> {
    function_from_interpose(&INTERPOSE_FCHMODAT)
}

fn original_chown() -> Option<ChownFn> {
    function_from_interpose(&INTERPOSE_CHOWN)
}

fn original_fchown() -> Option<FchownFn> {
    function_from_interpose(&INTERPOSE_FCHOWN)
}

fn original_lchown() -> Option<ChownFn> {
    function_from_interpose(&INTERPOSE_LCHOWN)
}

fn original_fchownat() -> Option<FchownAtFn> {
    function_from_interpose(&INTERPOSE_FCHOWNAT)
}

fn original_link() -> Option<LinkFn> {
    function_from_interpose(&INTERPOSE_LINK)
}

fn original_linkat() -> Option<LinkAtFn> {
    function_from_interpose(&INTERPOSE_LINKAT)
}

fn original_symlink() -> Option<SymlinkFn> {
    function_from_interpose(&INTERPOSE_SYMLINK)
}

fn original_symlinkat() -> Option<SymlinkAtFn> {
    function_from_interpose(&INTERPOSE_SYMLINKAT)
}

fn original_clonefile() -> Option<ClonefileFn> {
    function_from_interpose(&INTERPOSE_CLONEFILE)
}

fn original_clonefileat() -> Option<ClonefileAtFn> {
    function_from_interpose(&INTERPOSE_CLONEFILEAT)
}

fn original_copyfile() -> Option<CopyfileFn> {
    function_from_interpose(&INTERPOSE_COPYFILE)
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

fn original_unlinkat() -> Option<UnlinkAtFn> {
    function_from_interpose(&INTERPOSE_UNLINKAT)
}

fn original_rmdir() -> Option<UnlinkFn> {
    function_from_interpose(&INTERPOSE_RMDIR)
}

fn original_rename() -> Option<RenameFn> {
    function_from_interpose(&INTERPOSE_RENAME)
}

fn original_renameat() -> Option<RenameAtFn> {
    function_from_interpose(&INTERPOSE_RENAMEAT)
}

fn original_mkdir() -> Option<MkdirFn> {
    function_from_interpose(&INTERPOSE_MKDIR)
}

fn original_mkdirat() -> Option<MkdirAtFn> {
    function_from_interpose(&INTERPOSE_MKDIRAT)
}

fn original_posix_spawn_file_actions_addopen() -> Option<PosixSpawnAddOpenFn> {
    function_from_interpose(&INTERPOSE_POSIX_SPAWN_FILE_ACTIONS_ADDOPEN)
}

fn original_posix_spawn_file_actions_destroy() -> Option<PosixSpawnFileActionsDestroyFn> {
    function_from_interpose(&INTERPOSE_POSIX_SPAWN_FILE_ACTIONS_DESTROY)
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
dyld_interpose!(INTERPOSE_CREAT, agora_sandbox_creat, libc::creat);
dyld_interpose!(INTERPOSE_TRUNCATE, agora_sandbox_truncate, libc::truncate);
dyld_interpose!(
    INTERPOSE_FTRUNCATE,
    agora_sandbox_ftruncate,
    libc::ftruncate
);
dyld_interpose!(INTERPOSE_CHMOD, agora_sandbox_chmod, libc::chmod);
dyld_interpose!(INTERPOSE_FCHMOD, agora_sandbox_fchmod, libc::fchmod);
dyld_interpose!(INTERPOSE_FCHMODAT, agora_sandbox_fchmodat, libc::fchmodat);
dyld_interpose!(INTERPOSE_CHOWN, agora_sandbox_chown, libc::chown);
dyld_interpose!(INTERPOSE_FCHOWN, agora_sandbox_fchown, libc::fchown);
dyld_interpose!(INTERPOSE_LCHOWN, agora_sandbox_lchown, libc::lchown);
dyld_interpose!(INTERPOSE_FCHOWNAT, agora_sandbox_fchownat, libc::fchownat);
dyld_interpose!(INTERPOSE_LINK, agora_sandbox_link, libc::link);
dyld_interpose!(INTERPOSE_LINKAT, agora_sandbox_linkat, libc::linkat);
dyld_interpose!(INTERPOSE_SYMLINK, agora_sandbox_symlink, libc::symlink);
dyld_interpose!(
    INTERPOSE_SYMLINKAT,
    agora_sandbox_symlinkat,
    libc::symlinkat
);
dyld_interpose!(
    INTERPOSE_CLONEFILE,
    agora_sandbox_clonefile,
    libc::clonefile
);
dyld_interpose!(
    INTERPOSE_CLONEFILEAT,
    agora_sandbox_clonefileat,
    libc::clonefileat
);
dyld_interpose!(INTERPOSE_COPYFILE, agora_sandbox_copyfile, libc::copyfile);
dyld_interpose!(INTERPOSE_FOPEN, agora_sandbox_fopen, libc::fopen);
dyld_interpose!(
    INTERPOSE_POSIX_SPAWN_FILE_ACTIONS_ADDOPEN,
    agora_sandbox_posix_spawn_file_actions_addopen,
    libc::posix_spawn_file_actions_addopen
);
dyld_interpose!(
    INTERPOSE_POSIX_SPAWN_FILE_ACTIONS_DESTROY,
    agora_sandbox_posix_spawn_file_actions_destroy,
    libc::posix_spawn_file_actions_destroy
);
dyld_interpose!(INTERPOSE_CLOSE, agora_sandbox_close, libc::close);
dyld_interpose!(INTERPOSE_FCLOSE, agora_sandbox_fclose, libc::fclose);
dyld_interpose!(INTERPOSE_STAT, agora_sandbox_stat, libc::stat);
dyld_interpose!(INTERPOSE_LSTAT, agora_sandbox_lstat, libc::lstat);
dyld_interpose!(INTERPOSE_FSTATAT, agora_sandbox_fstatat, libc::fstatat);
dyld_interpose!(INTERPOSE_ACCESS, agora_sandbox_access, libc::access);
dyld_interpose!(INTERPOSE_UNLINK, agora_sandbox_unlink, libc::unlink);
dyld_interpose!(INTERPOSE_UNLINKAT, agora_sandbox_unlinkat, libc::unlinkat);
dyld_interpose!(INTERPOSE_RMDIR, agora_sandbox_rmdir, libc::rmdir);
dyld_interpose!(INTERPOSE_RENAME, agora_sandbox_rename, libc::rename);
dyld_interpose!(INTERPOSE_RENAMEAT, agora_sandbox_renameat, libc::renameat);
dyld_interpose!(INTERPOSE_MKDIR, agora_sandbox_mkdir, libc::mkdir);
dyld_interpose!(INTERPOSE_MKDIRAT, agora_sandbox_mkdirat, libc::mkdirat);
dyld_interpose!(INTERPOSE_CHDIR, agora_sandbox_chdir, libc::chdir);
dyld_interpose!(INTERPOSE_GETCWD, agora_sandbox_getcwd, libc::getcwd);
dyld_interpose!(INTERPOSE_OPENDIR, agora_sandbox_opendir, libc::opendir);
dyld_interpose!(INTERPOSE_READDIR, agora_sandbox_readdir, libc::readdir);
dyld_interpose!(INTERPOSE_CLOSEDIR, agora_sandbox_closedir, libc::closedir);

#[cfg(test)]
mod tests;
