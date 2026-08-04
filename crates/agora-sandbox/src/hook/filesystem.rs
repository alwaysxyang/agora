#![cfg(target_os = "macos")]

use super::config;
use super::dyld::{dyld_interpose, function_from_interpose};
use super::socket::set_errno;
use crate::audit::{AuditClient, AuditError, AuditEventRequest, FileOperation};
use crate::callback::{FileAccessMode, FileContext, FileOpenMode, ProcessContext};
use crate::filesystem::{
    Credentials, DirectoryView, FileAttributes, FileLayer, OpenTarget, PreparedFile, StagedWrite,
    VirtualFilesystem, Writeback,
};
use crate::trace::TraceContext;
use anyhow::{Context, Result, bail};
use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::FileTypeExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Once, OnceLock};

type OpenFn = unsafe extern "C" fn(*const libc::c_char, libc::c_int, libc::mode_t) -> libc::c_int;
type OpenAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
    libc::mode_t,
) -> libc::c_int;
type FopenFn = unsafe extern "C" fn(*const libc::c_char, *const libc::c_char) -> *mut libc::FILE;
type FreopenFn = unsafe extern "C" fn(
    *const libc::c_char,
    *const libc::c_char,
    *mut libc::FILE,
) -> *mut libc::FILE;
type CloseFn = unsafe extern "C" fn(libc::c_int) -> libc::c_int;
type FcloseFn = unsafe extern "C" fn(*mut libc::FILE) -> libc::c_int;
type DescriptorFn = unsafe extern "C" fn(libc::c_int) -> libc::c_int;
type Dup2Fn = unsafe extern "C" fn(libc::c_int, libc::c_int) -> libc::c_int;
type StatFn = unsafe extern "C" fn(*const libc::c_char, *mut libc::stat) -> libc::c_int;
type FstatFn = unsafe extern "C" fn(libc::c_int, *mut libc::stat) -> libc::c_int;
type FstatAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    *mut libc::stat,
    libc::c_int,
) -> libc::c_int;
type AccessFn = unsafe extern "C" fn(*const libc::c_char, libc::c_int) -> libc::c_int;
type FaccessAtFn =
    unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::c_int, libc::c_int) -> libc::c_int;
type ReadlinkFn =
    unsafe extern "C" fn(*const libc::c_char, *mut libc::c_char, libc::size_t) -> libc::ssize_t;
type ReadlinkAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    *mut libc::c_char,
    libc::size_t,
) -> libc::ssize_t;
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
type RenameXFn =
    unsafe extern "C" fn(*const libc::c_char, *const libc::c_char, libc::c_uint) -> libc::c_int;
type RenameAtXFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
    *const libc::c_char,
    libc::c_uint,
) -> libc::c_int;
type MkdirFn = unsafe extern "C" fn(*const libc::c_char, libc::mode_t) -> libc::c_int;
type MkdirAtFn =
    unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::mode_t) -> libc::c_int;
type TruncateFn = unsafe extern "C" fn(*const libc::c_char, libc::off_t) -> libc::c_int;
type FtruncateFn = unsafe extern "C" fn(libc::c_int, libc::off_t) -> libc::c_int;
type UtimesFn = unsafe extern "C" fn(*const libc::c_char, *const libc::timeval) -> libc::c_int;
type FutimesFn = unsafe extern "C" fn(libc::c_int, *const libc::timeval) -> libc::c_int;
type UtimensAtFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    *const libc::timespec,
    libc::c_int,
) -> libc::c_int;
type FutimensFn = unsafe extern "C" fn(libc::c_int, *const libc::timespec) -> libc::c_int;
type ChflagsFn = unsafe extern "C" fn(*const libc::c_char, libc::c_uint) -> libc::c_int;
type FchflagsFn = unsafe extern "C" fn(libc::c_int, libc::c_uint) -> libc::c_int;
type SetxattrFn = unsafe extern "C" fn(
    *const libc::c_char,
    *const libc::c_char,
    *const libc::c_void,
    libc::size_t,
    u32,
    libc::c_int,
) -> libc::c_int;
type FsetxattrFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::c_char,
    *const libc::c_void,
    libc::size_t,
    u32,
    libc::c_int,
) -> libc::c_int;
type RemovexattrFn =
    unsafe extern "C" fn(*const libc::c_char, *const libc::c_char, libc::c_int) -> libc::c_int;
type FremovexattrFn =
    unsafe extern "C" fn(libc::c_int, *const libc::c_char, libc::c_int) -> libc::c_int;
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
type ChdirFn = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;
type GetcwdFn = unsafe extern "C" fn(*mut libc::c_char, libc::size_t) -> *mut libc::c_char;
type RealpathFn = unsafe extern "C" fn(*const libc::c_char, *mut libc::c_char) -> *mut libc::c_char;
type OpendirFn = unsafe extern "C" fn(*const libc::c_char) -> *mut libc::DIR;
type FdopendirFn = unsafe extern "C" fn(libc::c_int) -> *mut libc::DIR;
type ReaddirFn = unsafe extern "C" fn(*mut libc::DIR) -> *mut libc::dirent;
type RewinddirFn = unsafe extern "C" fn(*mut libc::DIR);
type ClosedirFn = unsafe extern "C" fn(*mut libc::DIR) -> libc::c_int;
type FtsCompareFn =
    unsafe extern "C" fn(*const *const DarwinFtsEntry, *const *const DarwinFtsEntry) -> libc::c_int;
type FtsOpenFn = unsafe extern "C" fn(
    *const *mut libc::c_char,
    libc::c_int,
    Option<FtsCompareFn>,
) -> *mut libc::c_void;
type FtsChildrenFn = unsafe extern "C" fn(*mut libc::c_void, libc::c_int) -> *mut DarwinFtsEntry;
type FtsCloseFn = unsafe extern "C" fn(*mut libc::c_void) -> libc::c_int;
type FtsReadFn = unsafe extern "C" fn(*mut libc::c_void) -> *mut DarwinFtsEntry;
type GetattrlistbulkFn = unsafe extern "C" fn(
    libc::c_int,
    *mut libc::c_void,
    *mut libc::c_void,
    libc::size_t,
    u64,
) -> libc::c_int;

const FTS_D: libc::c_ushort = 1;
const FTS_DNR: libc::c_ushort = 4;
const FTS_DOT: libc::c_ushort = 5;
const FTS_ERR: libc::c_ushort = 7;
const FTS_F: libc::c_ushort = 8;
const FTS_NS: libc::c_ushort = 10;
const FTS_NSOK: libc::c_ushort = 11;
const FTS_SL: libc::c_ushort = 12;
const FTS_DEFAULT: libc::c_ushort = 3;
const FTS_SKIP: libc::c_int = 4;
const FTS_NOCHDIR: libc::c_int = 0x004;
const NATIVE_PASSTHROUGH_ROOTS: &[&str] = &["/dev"];

#[repr(C)]
pub(super) struct DarwinFtsEntry {
    fts_cycle: *mut DarwinFtsEntry,
    fts_parent: *mut DarwinFtsEntry,
    fts_link: *mut DarwinFtsEntry,
    fts_number: libc::c_long,
    fts_pointer: *mut libc::c_void,
    fts_accpath: *mut libc::c_char,
    fts_path: *mut libc::c_char,
    fts_errno: libc::c_int,
    fts_symfd: libc::c_int,
    fts_pathlen: libc::c_ushort,
    fts_namelen: libc::c_ushort,
    fts_ino: libc::ino_t,
    fts_dev: libc::dev_t,
    fts_nlink: libc::nlink_t,
    fts_level: libc::c_short,
    fts_info: libc::c_ushort,
    fts_flags: libc::c_ushort,
    fts_instr: libc::c_ushort,
    fts_statp: *mut libc::stat,
    fts_name: [libc::c_char; 1],
}

unsafe extern "C" {
    #[link_name = "readdir_r"]
    fn darwin_readdir_r(
        directory: *mut libc::DIR,
        entry: *mut libc::dirent,
        result: *mut *mut libc::dirent,
    ) -> libc::c_int;

    #[link_name = "fts_children"]
    fn darwin_fts_children(stream: *mut libc::c_void, options: libc::c_int) -> *mut DarwinFtsEntry;

    #[link_name = "fts_open"]
    fn darwin_fts_open(
        paths: *const *mut libc::c_char,
        options: libc::c_int,
        compare: Option<FtsCompareFn>,
    ) -> *mut libc::c_void;

    #[link_name = "fts_close"]
    fn darwin_fts_close(stream: *mut libc::c_void) -> libc::c_int;

    #[link_name = "fts_read"]
    fn darwin_fts_read(stream: *mut libc::c_void) -> *mut DarwinFtsEntry;

    #[link_name = "fts_set"]
    fn darwin_fts_set(
        stream: *mut libc::c_void,
        entry: *mut DarwinFtsEntry,
        instruction: libc::c_int,
    ) -> libc::c_int;

    #[link_name = "getattrlistbulk"]
    fn darwin_getattrlistbulk(
        directory: libc::c_int,
        attributes: *mut libc::c_void,
        buffer: *mut libc::c_void,
        size: libc::size_t,
        options: u64,
    ) -> libc::c_int;
}

thread_local! {
    static INSIDE_FILESYSTEM_HOOK: Cell<bool> = const { Cell::new(false) };
    static INITIALIZING_FILESYSTEM_RUNTIME: Cell<bool> = const { Cell::new(false) };
    static FTS_VIRTUAL_BULK_DEPTH: Cell<u32> = const { Cell::new(0) };
    static FTS_BULK_CURSORS: RefCell<HashMap<libc::c_int, FtsBulkCursor>> = RefCell::new(HashMap::new());
    #[cfg(test)]
    static TEST_FILESYSTEM_RUNTIME: Cell<*const FilesystemHookRuntime> = const { Cell::new(std::ptr::null()) };
}

struct FtsVirtualBulk;

impl FtsVirtualBulk {
    fn enter() -> Self {
        FTS_VIRTUAL_BULK_DEPTH.with(|depth| depth.set(depth.get().saturating_add(1)));
        Self
    }

    fn is_active() -> bool {
        FTS_VIRTUAL_BULK_DEPTH.with(|depth| depth.get() != 0)
    }
}

impl Drop for FtsVirtualBulk {
    fn drop(&mut self) {
        FTS_VIRTUAL_BULK_DEPTH.with(|depth| depth.set(depth.get().saturating_sub(1)));
    }
}

static FILESYSTEM_FORK_BARRIER_REGISTRATION: Once = Once::new();
static mut FILESYSTEM_FORK_BARRIER: libc::pthread_rwlock_t = libc::PTHREAD_RWLOCK_INITIALIZER;

pub(super) fn initialize_process() {
    FILESYSTEM_FORK_BARRIER_REGISTRATION.call_once(|| unsafe {
        libc::pthread_atfork(
            Some(lock_filesystem_before_fork),
            Some(unlock_filesystem_after_fork),
            Some(reset_filesystem_after_fork),
        );
    });
}

unsafe extern "C" fn lock_filesystem_before_fork() {
    unsafe {
        libc::pthread_rwlock_wrlock(&raw mut FILESYSTEM_FORK_BARRIER);
    }
}

unsafe extern "C" fn unlock_filesystem_after_fork() {
    unsafe {
        libc::pthread_rwlock_unlock(&raw mut FILESYSTEM_FORK_BARRIER);
    }
}

unsafe extern "C" fn reset_filesystem_after_fork() {
    unsafe {
        std::ptr::write(
            &raw mut FILESYSTEM_FORK_BARRIER,
            libc::PTHREAD_RWLOCK_INITIALIZER,
        );
    }
}

struct FilesystemHookGuard;

impl FilesystemHookGuard {
    fn enter() -> Option<Self> {
        if !super::interpose::initialized() && !test_runtime_is_set() {
            return None;
        }
        let entered = INSIDE_FILESYSTEM_HOOK.with(|inside| !inside.replace(true));
        if !entered {
            return None;
        }
        if unsafe { libc::pthread_rwlock_rdlock(&raw mut FILESYSTEM_FORK_BARRIER) } != 0 {
            INSIDE_FILESYSTEM_HOOK.with(|inside| inside.set(false));
            return None;
        }
        Some(Self)
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
        unsafe {
            libc::pthread_rwlock_unlock(&raw mut FILESYSTEM_FORK_BARRIER);
        }
        INSIDE_FILESYSTEM_HOOK.with(|inside| inside.set(false));
    }
}

struct FilesystemHookRuntime {
    filesystem: VirtualFilesystem,
    audit: Option<AuditClient>,
    trace: TraceContext,
    prepared_executable: Option<PathBuf>,
    current_directory: Mutex<PathBuf>,
    open_files: Mutex<HashMap<libc::c_int, Arc<OpenFile>>>,
    directory_descriptors: Mutex<HashMap<libc::c_int, PathBuf>>,
}

struct PreparedOpen {
    prepared: PreparedFile,
    file: FileContext,
    logical: PathBuf,
}

struct OpenFile {
    file: FileContext,
    logical: Mutex<PathBuf>,
    writeback: Option<Writeback>,
    layer: FileLayer,
    close_on_exec: bool,
}

static FILESYSTEM_RUNTIME: OnceLock<Option<FilesystemHookRuntime>> = OnceLock::new();

impl PreparedOpen {
    fn into_parts(
        self,
    ) -> (
        OpenTarget,
        FileContext,
        PathBuf,
        Option<Writeback>,
        FileLayer,
        bool,
    ) {
        let (target, writeback, layer) = self.prepared.into_parts();
        let close_on_exec = matches!(target, OpenTarget::Descriptor(_));
        (
            target,
            self.file,
            self.logical,
            writeback,
            layer,
            close_on_exec,
        )
    }
}

struct OpenRequest {
    logical: PathBuf,
    flags: libc::c_int,
    mode: libc::mode_t,
    file: FileContext,
    native_passthrough: bool,
    allowlisted_passthrough: bool,
}

impl OpenRequest {
    fn native_path(&self) -> Result<Option<CString>> {
        self.allowlisted_passthrough
            .then(|| {
                CString::new(self.logical.as_os_str().as_bytes())
                    .context("native passthrough path contains NUL")
            })
            .transpose()
    }
}

impl OpenFile {
    fn logical(&self) -> PathBuf {
        lock(&self.logical).clone()
    }

    fn retarget(&self, from: &Path, to: &Path) {
        let mut logical = lock(&self.logical);
        if *logical == from {
            *logical = to.to_path_buf();
        }
    }
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
        if let Some(runtime) = FILESYSTEM_RUNTIME.get() {
            return runtime.as_ref();
        }
        INITIALIZING_FILESYSTEM_RUNTIME.with(|initializing| {
            if initializing.replace(true) {
                return None;
            }
            let runtime = FILESYSTEM_RUNTIME.get_or_init(|| {
                config::global().and_then(|config| {
                    let filesystem = match config.filesystem_cipher() {
                        Some(cipher) => {
                            VirtualFilesystem::encrypted(config.filesystem_root(), cipher)
                        }
                        None => VirtualFilesystem::plain(config.filesystem_root()),
                    };
                    filesystem.ok().and_then(|filesystem| {
                        let current_directory = Self::native_current_directory(&filesystem).ok()?;
                        let prepared_executable = Self::prepared_executable(&filesystem);
                        Some(Self {
                            filesystem,
                            audit: Some(AuditClient::new(
                                config.audit_control(),
                                config.audit_token(),
                            )),
                            trace: config.trace().clone(),
                            prepared_executable,
                            current_directory: Mutex::new(current_directory),
                            open_files: Mutex::new(HashMap::new()),
                            directory_descriptors: Mutex::new(HashMap::new()),
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
        let filesystem = VirtualFilesystem::plain(root)?;
        let current_directory = Self::native_current_directory(&filesystem)?;
        Ok(Self {
            filesystem,
            audit: None,
            trace: TraceContext::parse("test-trace").map_err(anyhow::Error::msg)?,
            prepared_executable: None,
            current_directory: Mutex::new(current_directory),
            open_files: Mutex::new(HashMap::new()),
            directory_descriptors: Mutex::new(HashMap::new()),
        })
    }

    #[cfg(test)]
    fn new_encrypted(root: impl Into<PathBuf>, key: &[u8], salt: &[u8]) -> Result<Self> {
        let cipher = crate::filesystem::FileCipher::derive(key, salt)?;
        let filesystem = VirtualFilesystem::encrypted(root, cipher)?;
        let current_directory = Self::native_current_directory(&filesystem)?;
        Ok(Self {
            filesystem,
            audit: None,
            trace: TraceContext::parse("test-trace").map_err(anyhow::Error::msg)?,
            prepared_executable: None,
            current_directory: Mutex::new(current_directory),
            open_files: Mutex::new(HashMap::new()),
            directory_descriptors: Mutex::new(HashMap::new()),
        })
    }

    fn native_current_directory(filesystem: &VirtualFilesystem) -> Result<PathBuf> {
        let directory = std::env::current_dir().context("failed to resolve current directory")?;
        if filesystem.is_internal(&directory) {
            filesystem.logical_path(&directory)
        } else {
            Ok(directory)
        }
    }

    fn prepared_executable(filesystem: &VirtualFilesystem) -> Option<PathBuf> {
        std::env::current_exe()
            .ok()
            .filter(|executable| filesystem.is_internal(executable))
    }

    fn native_passthrough_path(&self, path: &Path) -> Result<Option<PathBuf>> {
        let normalized = normalize_absolute(path)?;
        Ok(NATIVE_PASSTHROUGH_ROOTS
            .iter()
            .map(Path::new)
            .any(|root| normalized.starts_with(root))
            .then_some(normalized))
    }

    unsafe fn native_passthrough_c_path(
        &self,
        path: *const libc::c_char,
        directory: libc::c_int,
    ) -> Result<Option<CString>> {
        let logical = unsafe { self.logical_path(path, directory) }?;
        self.native_passthrough_path(&logical)?
            .map(|native| {
                CString::new(native.as_os_str().as_bytes())
                    .context("native passthrough path contains NUL")
            })
            .transpose()
    }

    unsafe fn native_passthrough_pair(
        &self,
        first: *const libc::c_char,
        first_directory: libc::c_int,
        second: *const libc::c_char,
        second_directory: libc::c_int,
    ) -> Result<Option<(CString, CString)>> {
        let first = unsafe { self.native_passthrough_c_path(first, first_directory) }?;
        let second = unsafe { self.native_passthrough_c_path(second, second_directory) }?;
        Ok(first.zip(second))
    }

    fn native_passthrough_descriptor(&self, descriptor: libc::c_int) -> bool {
        if self.tracked_open(descriptor).is_some()
            || lock(&self.directory_descriptors).contains_key(&descriptor)
        {
            return false;
        }
        Self::descriptor_path(descriptor)
            .ok()
            .and_then(|path| self.native_passthrough_path(&path).ok().flatten())
            .is_some()
    }

    #[cfg(test)]
    fn map(&self, path: *const libc::c_char, directory: libc::c_int) -> Result<CString> {
        let logical = unsafe { self.logical_path(path, directory) }?;
        let mapped = self.filesystem.prepare_read(&logical)?;
        CString::new(mapped.as_os_str().as_bytes()).context("mapped filesystem path contains NUL")
    }

    fn map_metadata(
        &self,
        path: *const libc::c_char,
        directory: libc::c_int,
        follow_final: bool,
        credentials: &Credentials,
    ) -> Result<(CString, Option<libc::off_t>, Option<FileAttributes>)> {
        let logical = unsafe { self.logical_path(path, directory) }?;
        if let Some(native) = self.native_passthrough_path(&logical)? {
            let mapped = CString::new(native.as_os_str().as_bytes())
                .context("native passthrough path contains NUL")?;
            return Ok((mapped, None, None));
        }
        if self
            .filesystem
            .native_metadata_passthrough(&logical, follow_final, credentials)?
        {
            let mapped = CString::new(logical.as_os_str().as_bytes())
                .context("mapped filesystem path contains NUL")?;
            return Ok((mapped, None, None));
        }
        self.filesystem.require_search(&logical, credentials)?;
        let (mapped, plaintext_size, resolved) =
            self.filesystem.prepare_metadata(&logical, follow_final)?;
        self.logical_or_host(&resolved)?;
        if resolved != logical {
            self.filesystem.require_search(&resolved, credentials)?;
        }
        let attributes = self.filesystem.attributes(&resolved)?;
        let mapped = CString::new(mapped.as_os_str().as_bytes())
            .context("mapped filesystem path contains NUL")?;
        let plaintext_size = plaintext_size
            .map(libc::off_t::try_from)
            .transpose()
            .context("plaintext filesystem file is too large")?;
        Ok((mapped, plaintext_size, attributes))
    }

    fn chmod(
        &self,
        path: *const libc::c_char,
        directory: libc::c_int,
        mode: libc::mode_t,
        follow_final: bool,
    ) -> Result<()> {
        let requested = unsafe { self.logical_path(path, directory) }?;
        let credentials = Credentials::effective();
        let logical = if follow_final {
            self.resolve_final_path(&requested, libc::O_RDONLY, &credentials)?
        } else {
            requested
        };
        self.logical_or_host(&logical)?;
        self.filesystem
            .chmod(&logical, mode.into(), false, &credentials)
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
            self.descriptor_logical_path(directory)
                .map(Ok)
                .unwrap_or_else(|| self.resolve_descriptor_logical_path(directory))?
        };
        let candidate = self.logical_or_host(&base)?.join(requested);
        self.logical_or_host(&candidate)
    }

    fn logical_or_host(&self, path: &Path) -> Result<PathBuf> {
        if self.filesystem.is_private(path)? {
            if let Some(executable) = &self.prepared_executable
                && executable.starts_with(path)
            {
                let logical = self.filesystem.logical_path(path)?;
                if logical != Path::new("/") {
                    return Ok(logical);
                }
            }
            return Err(io::Error::from_raw_os_error(libc::EACCES).into());
        }
        Ok(path.to_path_buf())
    }

    fn resolve_final_path(
        &self,
        requested: &Path,
        flags: libc::c_int,
        credentials: &Credentials,
    ) -> Result<PathBuf> {
        self.filesystem.require_search(requested, credentials)?;
        let resolved = self.filesystem.resolve_open_path(requested, flags)?;
        self.logical_or_host(&resolved)
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
        mode: libc::mode_t,
    ) -> Result<OpenRequest> {
        let requested = unsafe { self.logical_path(path, directory) }?;
        let allowlisted = self.native_passthrough_path(&requested)?;
        let allowlisted_passthrough = allowlisted.is_some();
        let native_passthrough =
            allowlisted_passthrough || self.native_read_passthrough(&requested, flags)?;
        let credentials = Credentials::effective();
        let logical = match allowlisted {
            Some(path) => path,
            None if native_passthrough => requested.clone(),
            None => self.resolve_final_path(&requested, flags, &credentials)?,
        };
        let mut access = match flags & libc::O_ACCMODE {
            libc::O_WRONLY => libc::W_OK,
            libc::O_RDWR => libc::R_OK | libc::W_OK,
            _ => libc::R_OK,
        };
        if flags & libc::O_TRUNC != 0 {
            access |= libc::W_OK;
        }
        if !native_passthrough {
            self.filesystem
                .validate_open_permissions(&logical, flags, access, &credentials)?;
        }
        Ok(OpenRequest {
            logical,
            flags,
            mode,
            file: FileContext {
                path: requested.to_string_lossy().into_owned(),
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
            native_passthrough,
            allowlisted_passthrough,
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
        let requested = unsafe { self.logical_path(path, libc::AT_FDCWD) }?;
        let mut flags = match mode.first() {
            Some(b'w') => libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
            Some(b'a') => libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND,
            _ => libc::O_RDONLY,
        };
        if mode.contains(&b'+') {
            flags = (flags & !libc::O_ACCMODE) | libc::O_RDWR;
        }
        if mode.contains(&b'x') {
            flags |= libc::O_EXCL;
        }
        let allowlisted = self.native_passthrough_path(&requested)?;
        let allowlisted_passthrough = allowlisted.is_some();
        let native_passthrough =
            allowlisted_passthrough || self.native_read_passthrough(&requested, flags)?;
        let credentials = Credentials::effective();
        let logical = match allowlisted {
            Some(path) => path,
            None if native_passthrough => requested.clone(),
            None => self.resolve_final_path(&requested, flags, &credentials)?,
        };
        let access = if mode.contains(&b'+') {
            libc::R_OK | libc::W_OK
        } else if writes {
            libc::W_OK
        } else {
            libc::R_OK
        };
        if !native_passthrough {
            self.filesystem
                .validate_open_permissions(&logical, flags, access, &credentials)?;
        }
        Ok(OpenRequest {
            logical,
            flags,
            mode: 0o666,
            file: FileContext {
                path: requested.to_string_lossy().into_owned(),
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
            native_passthrough,
            allowlisted_passthrough,
        })
    }

    fn native_read_passthrough(&self, logical: &Path, flags: libc::c_int) -> Result<bool> {
        let mutating_or_special = libc::O_CREAT
            | libc::O_TRUNC
            | libc::O_EXCL
            | libc::O_DIRECTORY
            | libc::O_NOFOLLOW
            | libc::O_NOFOLLOW_ANY
            | libc::O_SYMLINK;
        if flags & libc::O_ACCMODE != libc::O_RDONLY || flags & mutating_or_special != 0 {
            return Ok(false);
        }
        self.filesystem
            .native_metadata_passthrough(logical, true, &Credentials::effective())
    }

    fn map_open(&self, request: OpenRequest) -> Result<PreparedOpen> {
        if request.native_passthrough {
            return Ok(PreparedOpen {
                prepared: self.filesystem.prepare_native_open(&request.logical),
                file: request.file,
                logical: request.logical,
            });
        }
        self.publish_open_writers(&request.logical)?;
        Ok(PreparedOpen {
            prepared: self.filesystem.prepare_open(
                &request.logical,
                request.flags,
                request.mode.into(),
            )?,
            file: request.file,
            logical: request.logical,
        })
    }

    fn commit_open(&self, prepared: &mut PreparedOpen) -> Result<()> {
        self.filesystem.commit_open(&mut prepared.prepared)
    }

    fn publish_open_writers(&self, logical: &Path) -> Result<()> {
        let files = lock(&self.open_files)
            .iter()
            .map(|(&descriptor, open)| (descriptor, Arc::clone(open)))
            .collect::<Vec<_>>();
        let mut seen = HashSet::new();
        for (descriptor, open) in files {
            if open.writeback.is_some()
                && open.logical() == logical
                && seen.insert(Arc::as_ptr(&open))
            {
                self.commit_open_file(descriptor, &open)?;
            }
        }
        Ok(())
    }

    fn prepare_descriptor_mutation(&self, descriptor: libc::c_int) -> Result<StagedWrite> {
        if self.tracked(descriptor).is_some() {
            return Err(io::Error::from_raw_os_error(libc::EALREADY).into());
        }
        let path = Self::descriptor_path(descriptor)?;
        if !self.filesystem.is_internal(&path) {
            return Err(io::Error::from_raw_os_error(libc::EPERM).into());
        }
        if !path.symlink_metadata()?.is_file() {
            return Err(io::Error::from_raw_os_error(libc::ENOTSUP).into());
        }
        let logical = self.filesystem.logical_path(&path)?;
        self.filesystem.stage_write(&logical, false)
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

    fn register(
        &self,
        descriptor: libc::c_int,
        file: FileContext,
        logical: PathBuf,
        writeback: Option<Writeback>,
        layer: FileLayer,
        close_on_exec: bool,
    ) {
        lock(&self.open_files).insert(
            descriptor,
            Arc::new(OpenFile {
                file,
                logical: Mutex::new(logical),
                writeback,
                layer,
                close_on_exec,
            }),
        );
    }

    fn tracked(&self, descriptor: libc::c_int) -> Option<FileContext> {
        lock(&self.open_files)
            .get(&descriptor)
            .map(|open| open.file.clone())
    }

    fn tracked_open(&self, descriptor: libc::c_int) -> Option<Arc<OpenFile>> {
        lock(&self.open_files).get(&descriptor).cloned()
    }

    fn duplicate_descriptor(&self, source: libc::c_int, destination: libc::c_int) {
        let mut files = lock(&self.open_files);
        let close_on_exec = files.get(&source).is_some_and(|open| open.close_on_exec);
        match files.get(&source).cloned() {
            Some(open) => {
                files.insert(destination, open);
            }
            None => {
                files.remove(&destination);
            }
        }
        drop(files);

        if close_on_exec {
            let flags = unsafe { libc::fcntl(destination, libc::F_GETFD) };
            if flags >= 0 {
                unsafe { libc::fcntl(destination, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
            }
        }

        let mut directories = lock(&self.directory_descriptors);
        match directories.get(&source).cloned() {
            Some(logical) => {
                directories.insert(destination, logical);
            }
            None => {
                directories.remove(&destination);
            }
        }
    }

    fn take_descriptor(&self, descriptor: libc::c_int) -> Option<(Arc<OpenFile>, bool)> {
        let mut files = lock(&self.open_files);
        let open = files.remove(&descriptor)?;
        let last_alias = !files
            .values()
            .any(|candidate| Arc::ptr_eq(candidate, &open));
        Some((open, last_alias))
    }

    fn restore_descriptor(&self, descriptor: libc::c_int, open: Arc<OpenFile>) {
        lock(&self.open_files).insert(descriptor, open);
    }

    fn writeback(&self, descriptor: libc::c_int) -> Result<()> {
        let open = lock(&self.open_files).get(&descriptor).cloned();
        if let Some(open) = open {
            self.commit_open_file(descriptor, &open)?;
        }
        Ok(())
    }

    fn commit_open_file(&self, descriptor: libc::c_int, open: &OpenFile) -> Result<()> {
        let Some(writeback) = &open.writeback else {
            return Ok(());
        };
        let Some(logical) = self.filesystem.commit_writeback(writeback)? else {
            return Ok(());
        };
        let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(descriptor, &mut status) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        self.filesystem.refresh_timestamps(&logical, &status)
    }

    fn commit_all_open_files(&self) -> Result<()> {
        let files = lock(&self.open_files);
        let mut seen = HashSet::new();
        let mut open_files = Vec::new();
        for (&descriptor, open) in files.iter() {
            if seen.insert(Arc::as_ptr(open)) {
                open_files.push((descriptor, Arc::clone(open)));
            }
        }
        drop(files);
        for (descriptor, open) in open_files {
            self.commit_open_file(descriptor, &open)?;
        }
        Ok(())
    }

    fn refresh_attributes(&self, descriptor: libc::c_int, path: &str) -> Result<()> {
        let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
        if unsafe { libc::fstat(descriptor, &mut status) } != 0 {
            return Err(io::Error::last_os_error().into());
        }
        self.filesystem
            .set_attributes(Path::new(path), FileAttributes::from_stat(&status))
    }

    fn create_directory(
        &self,
        directory: libc::c_int,
        path: *const libc::c_char,
        mode: libc::mode_t,
    ) -> Result<()> {
        let logical = unsafe { self.logical_path(path, directory) }?;
        if let Some(native) = self.native_passthrough_path(&logical)? {
            let native = CString::new(native.as_os_str().as_bytes())
                .context("native passthrough path contains NUL")?;
            let original =
                original_mkdir().ok_or_else(|| io::Error::from_raw_os_error(libc::ENOSYS))?;
            return native_operation_result(unsafe { original(native.as_ptr(), mode) });
        }
        self.filesystem
            .validate_create_directory(&logical, &Credentials::effective())?;
        self.filesystem
            .create_directory(&logical, u32::from(mode))
            .map(|_| ())
    }

    fn create_symlink(
        &self,
        target: *const libc::c_char,
        directory: libc::c_int,
        link: *const libc::c_char,
    ) -> Result<()> {
        if target.is_null() {
            return Err(io::Error::from_raw_os_error(libc::EFAULT).into());
        }
        let link = unsafe { self.logical_path(link, directory) }?;
        if let Some(native) = self.native_passthrough_path(&link)? {
            let native = CString::new(native.as_os_str().as_bytes())
                .context("native passthrough path contains NUL")?;
            let original =
                original_symlink().ok_or_else(|| io::Error::from_raw_os_error(libc::ENOSYS))?;
            return native_operation_result(unsafe { original(target, native.as_ptr()) });
        }
        self.filesystem
            .require_parent_mutation(&link, &Credentials::effective())?;
        let requested = Path::new(OsStr::from_bytes(unsafe {
            CStr::from_ptr(target).to_bytes()
        }));
        let target = if requested.is_absolute() && self.filesystem.is_internal(requested) {
            self.filesystem.logical_path(requested)?
        } else if requested.is_absolute() {
            self.logical_or_host(requested)?
        } else {
            requested.to_path_buf()
        };
        self.filesystem.create_symlink(&link, &target).map(|_| ())
    }

    fn remove(
        &self,
        directory: libc::c_int,
        path: *const libc::c_char,
        remove_directory: bool,
    ) -> Result<()> {
        let logical = unsafe { self.logical_path(path, directory) }?;
        if let Some(native) = self.native_passthrough_path(&logical)? {
            let native = CString::new(native.as_os_str().as_bytes())
                .context("native passthrough path contains NUL")?;
            let original = if remove_directory {
                original_rmdir()
            } else {
                original_unlink()
            }
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOSYS))?;
            return native_operation_result(unsafe { original(native.as_ptr()) });
        }
        self.filesystem
            .require_parent_mutation(&logical, &Credentials::effective())?;
        self.filesystem.remove(&logical, remove_directory)
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
        let native_from = self.native_passthrough_path(&from)?;
        let native_to = self.native_passthrough_path(&to)?;
        match (native_from, native_to) {
            (Some(from), Some(to)) => {
                let from = CString::new(from.as_os_str().as_bytes())
                    .context("native passthrough path contains NUL")?;
                let to = CString::new(to.as_os_str().as_bytes())
                    .context("native passthrough path contains NUL")?;
                let original =
                    original_rename().ok_or_else(|| io::Error::from_raw_os_error(libc::ENOSYS))?;
                return native_operation_result(unsafe { original(from.as_ptr(), to.as_ptr()) });
            }
            (None, None) => {}
            _ => return Err(io::Error::from_raw_os_error(libc::EXDEV).into()),
        }
        let credentials = Credentials::effective();
        self.filesystem
            .require_parent_mutation(&from, &credentials)?;
        self.filesystem.require_parent_mutation(&to, &credentials)?;
        self.filesystem.rename(&from, &to)?;
        let open_files = lock(&self.open_files).values().cloned().collect::<Vec<_>>();
        let open_files = open_files
            .into_iter()
            .filter(|open| open.logical() == from)
            .collect::<Vec<_>>();
        for open in open_files {
            open.retarget(&from, &to);
        }
        Ok(())
    }

    fn prepare_change_directory(&self, path: *const libc::c_char) -> Result<(CString, PathBuf)> {
        let requested = unsafe { self.logical_path(path, libc::AT_FDCWD) }?;
        if let Some(native) = self.native_passthrough_path(&requested)? {
            let mapped = CString::new(native.as_os_str().as_bytes())
                .context("native passthrough path contains NUL")?;
            return Ok((mapped, native));
        }
        let credentials = Credentials::effective();
        let logical =
            self.resolve_final_path(&requested, libc::O_RDONLY | libc::O_DIRECTORY, &credentials)?;
        self.filesystem.require_search(&logical, &credentials)?;
        self.filesystem
            .require_access(&logical, libc::X_OK, &credentials)?;
        let mapped = self.filesystem.prepare_directory(&logical)?;
        let mapped = CString::new(mapped.as_os_str().as_bytes())
            .context("mapped filesystem path contains NUL")?;
        Ok((mapped, logical))
    }

    fn set_current_directory(&self, directory: PathBuf) {
        *lock(&self.current_directory) = directory;
    }

    fn synchronize_current_directory(&self) -> Result<()> {
        let directory = Self::native_current_directory(&self.filesystem)?;
        self.set_current_directory(directory);
        Ok(())
    }

    fn descriptor_logical_path(&self, descriptor: libc::c_int) -> Option<PathBuf> {
        self.tracked_open(descriptor)
            .map(|open| open.logical())
            .or_else(|| lock(&self.directory_descriptors).get(&descriptor).cloned())
    }

    fn resolve_descriptor_logical_path(&self, descriptor: libc::c_int) -> Result<PathBuf> {
        if let Some(logical) = self.descriptor_logical_path(descriptor) {
            return Ok(logical);
        }
        let path = Self::descriptor_path(descriptor)?;
        if self.filesystem.is_internal(&path) {
            self.filesystem.logical_path(&path)
        } else {
            self.logical_or_host(&path)
        }
    }

    fn register_directory(&self, descriptor: libc::c_int, logical: PathBuf) {
        lock(&self.directory_descriptors).insert(descriptor, logical);
    }

    fn unregister_directory(&self, descriptor: libc::c_int) {
        lock(&self.directory_descriptors).remove(&descriptor);
    }

    fn logical_current_directory(&self) -> Result<CString> {
        let logical = lock(&self.current_directory);
        CString::new(logical.as_os_str().as_bytes()).context("current directory contains NUL")
    }

    unsafe fn canonical_path(&self, path: *const libc::c_char) -> Result<CString> {
        let logical = unsafe { self.logical_path(path, libc::AT_FDCWD) }?;
        self.filesystem
            .require_search(&logical, &Credentials::effective())?;
        let canonical = self.filesystem.canonicalize(&logical)?;
        let canonical = self.logical_or_host(&canonical)?;
        CString::new(canonical.as_os_str().as_bytes())
            .context("canonical filesystem path contains NUL")
    }

    fn directory_view(&self, path: *const libc::c_char) -> Result<DirectoryView> {
        let logical = unsafe { self.logical_path(path, libc::AT_FDCWD) }?;
        if let Some(native) = self.native_passthrough_path(&logical)? {
            return Ok(DirectoryView::passthrough(native));
        }
        let credentials = Credentials::effective();
        self.filesystem.require_search(&logical, &credentials)?;
        self.filesystem
            .require_access(&logical, libc::R_OK, &credentials)?;
        self.filesystem.directory_view(&logical)
    }

    fn descriptor_directory_view(
        &self,
        descriptor: libc::c_int,
    ) -> Result<(DirectoryView, FileLayer)> {
        let (logical, layer) = if let Some(open) = self.tracked_open(descriptor) {
            (open.logical(), open.layer)
        } else {
            let path = Self::descriptor_path(descriptor)?;
            let layer = if self.filesystem.is_internal(&path) {
                FileLayer::Upper
            } else {
                FileLayer::Lower
            };
            let logical = if layer == FileLayer::Upper {
                self.filesystem.logical_path(&path)?
            } else {
                self.logical_or_host(&path)?
            };
            (logical, layer)
        };
        if let Some(native) = self.native_passthrough_path(&logical)? {
            return Ok((DirectoryView::passthrough(native), FileLayer::Lower));
        }
        Ok((self.filesystem.directory_view(&logical)?, layer))
    }
}

fn normalize_absolute(path: &Path) -> Result<PathBuf> {
    if !path.is_absolute() {
        bail!("filesystem path is not absolute: {}", path.display());
    }
    let mut normalized = PathBuf::from("/");
    for component in path.components() {
        match component {
            Component::RootDir | Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            Component::Normal(value) => normalized.push(value),
            Component::Prefix(_) => bail!("unsupported filesystem path: {}", path.display()),
        }
    }
    Ok(normalized)
}

fn native_operation_result(result: libc::c_int) -> Result<()> {
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error().into())
    }
}

pub(super) fn tracked_current_directory() -> Option<PathBuf> {
    FilesystemHookRuntime::global().map(|runtime| lock(&runtime.current_directory).clone())
}

pub(super) fn flush_before_exec() -> Result<()> {
    let Some(_guard) = FilesystemHookGuard::enter() else {
        return Ok(());
    };
    let Some(runtime) = FILESYSTEM_RUNTIME.get().and_then(Option::as_ref) else {
        return Ok(());
    };
    runtime.commit_all_open_files()
}

pub(super) fn flush_at_exit() {
    let Some(_guard) = FilesystemHookGuard::enter() else {
        return;
    };
    unsafe {
        libc::fflush(std::ptr::null_mut());
    }
    if let Some(runtime) = FILESYSTEM_RUNTIME.get().and_then(Option::as_ref) {
        let _ = runtime.commit_all_open_files();
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

fn configure_descriptor(descriptor: libc::c_int, flags: libc::c_int) -> Result<()> {
    let descriptor_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if descriptor_flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let descriptor_flags = descriptor_flags | libc::FD_CLOEXEC;
    if unsafe { libc::fcntl(descriptor, libc::F_SETFD, descriptor_flags) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let status_flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if status_flags < 0 {
        return Err(io::Error::last_os_error().into());
    }
    let status_flags = (status_flags & !(libc::O_APPEND | libc::O_NONBLOCK))
        | (flags & (libc::O_APPEND | libc::O_NONBLOCK));
    if unsafe { libc::fcntl(descriptor, libc::F_SETFL, status_flags) } < 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(())
}

struct DirectoryCursor {
    auxiliary: Option<usize>,
    primary_layer: FileLayer,
    reading_lower: bool,
    hidden: HashSet<Vec<u8>>,
    aliases: HashMap<Vec<u8>, Vec<u8>>,
    seen: HashSet<Vec<u8>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FtsDescriptorIdentity {
    device: libc::dev_t,
    inode: libc::ino_t,
}

struct FtsBulkEntry {
    name: Vec<u8>,
    object_type: u32,
}

struct FtsBulkCursor {
    identity: FtsDescriptorIdentity,
    entries: Vec<FtsBulkEntry>,
    next: usize,
}

struct FtsRootMapping {
    physical: Vec<u8>,
    logical: Vec<u8>,
}

struct PresentedFtsEntry {
    entry: usize,
    original_path: usize,
    original_access_path: usize,
    original_path_length: libc::c_ushort,
    original_name_length: libc::c_ushort,
    original_name: Vec<libc::c_char>,
    logical_path: CString,
    logical_access_path: CString,
}

struct FtsStreamState {
    mappings: Vec<FtsRootMapping>,
    presented: Vec<PresentedFtsEntry>,
}

impl FtsStreamState {
    fn restore(&mut self) {
        for presented in self.presented.drain(..) {
            let entry = presented.entry as *mut DarwinFtsEntry;
            unsafe {
                (*entry).fts_path = presented.original_path as *mut libc::c_char;
                (*entry).fts_accpath = presented.original_access_path as *mut libc::c_char;
                (*entry).fts_pathlen = presented.original_path_length;
                (*entry).fts_namelen = presented.original_name_length;
                std::ptr::copy_nonoverlapping(
                    presented.original_name.as_ptr(),
                    (*entry).fts_name.as_mut_ptr(),
                    presented.original_name.len(),
                );
            }
        }
    }

    fn present(&mut self, entry: *mut DarwinFtsEntry) -> Result<()> {
        if entry.is_null() {
            return Ok(());
        }
        let path = unsafe { CStr::from_ptr((*entry).fts_path) }.to_bytes();
        let access_path = unsafe { CStr::from_ptr((*entry).fts_accpath) }.to_bytes();
        let Some(logical_path) = self.translate(path).or_else(|| self.translate(access_path))
        else {
            return Ok(());
        };
        let logical_access_path = self
            .translate(access_path)
            .unwrap_or_else(|| logical_path.clone());
        let original_name_length = unsafe { (*entry).fts_namelen };
        let original_name = unsafe {
            std::slice::from_raw_parts(
                (*entry).fts_name.as_ptr(),
                usize::from(original_name_length) + 1,
            )
            .to_vec()
        };
        let original_name_bytes = unsafe {
            std::slice::from_raw_parts(
                original_name.as_ptr().cast::<u8>(),
                usize::from(original_name_length),
            )
        };
        let logical_name = if original_name_bytes == path
            || original_name_bytes == logical_basename(path)
            || original_name_bytes == access_path
            || original_name_bytes == logical_basename(access_path)
        {
            logical_basename(&logical_path).to_vec()
        } else {
            original_name_bytes.to_vec()
        };
        if logical_name.len() > usize::from(original_name_length)
            || logical_name.len() > usize::from(u16::MAX)
        {
            return Err(io::Error::from_raw_os_error(libc::ENAMETOOLONG).into());
        }
        let logical_path = CString::new(logical_path).context("logical FTS path contains NUL")?;
        let logical_access_path =
            CString::new(logical_access_path).context("logical FTS access path contains NUL")?;
        let presented = PresentedFtsEntry {
            entry: entry as usize,
            original_path: unsafe { (*entry).fts_path } as usize,
            original_access_path: unsafe { (*entry).fts_accpath } as usize,
            original_path_length: unsafe { (*entry).fts_pathlen },
            original_name_length,
            original_name,
            logical_path,
            logical_access_path,
        };
        unsafe {
            (*entry).fts_path = presented.logical_path.as_ptr().cast_mut();
            (*entry).fts_accpath = presented.logical_access_path.as_ptr().cast_mut();
            (*entry).fts_pathlen = u16::try_from(presented.logical_path.as_bytes().len())?;
            (*entry).fts_namelen = u16::try_from(logical_name.len())?;
            std::ptr::copy_nonoverlapping(
                logical_name.as_ptr().cast::<libc::c_char>(),
                (*entry).fts_name.as_mut_ptr(),
                logical_name.len(),
            );
            *(*entry).fts_name.as_mut_ptr().add(logical_name.len()) = 0;
        }
        self.presented.push(presented);
        Ok(())
    }

    fn present_list(&mut self, mut entry: *mut DarwinFtsEntry) -> Result<()> {
        while !entry.is_null() {
            let next = unsafe { (*entry).fts_link };
            self.present(entry)?;
            entry = next;
        }
        Ok(())
    }

    fn translate(&self, path: &[u8]) -> Option<Vec<u8>> {
        self.mappings.iter().find_map(|mapping| {
            let suffix = path.strip_prefix(mapping.physical.as_slice())?;
            if !suffix.is_empty() && !suffix.starts_with(b"/") {
                return None;
            }
            let mut logical = mapping.logical.clone();
            logical.extend_from_slice(suffix);
            Some(logical)
        })
    }
}

fn logical_basename(path: &[u8]) -> &[u8] {
    let path = path.strip_suffix(b"/").unwrap_or(path);
    path.rsplit(|byte| *byte == b'/').next().unwrap_or(path)
}

fn fts_streams() -> &'static Mutex<HashMap<usize, FtsStreamState>> {
    static STREAMS: OnceLock<Mutex<HashMap<usize, FtsStreamState>>> = OnceLock::new();
    STREAMS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn fts_stream_may_change_current_directory(stream: *mut libc::c_void) -> bool {
    !lock(fts_streams()).contains_key(&(stream as usize))
}

fn restore_fts_stream(stream: *mut libc::c_void) {
    if let Some(state) = lock(fts_streams()).get_mut(&(stream as usize)) {
        state.restore();
    }
}

fn present_fts_entry(stream: *mut libc::c_void, entry: *mut DarwinFtsEntry) -> Result<()> {
    if let Some(state) = lock(fts_streams()).get_mut(&(stream as usize)) {
        state.present(entry)?;
    }
    Ok(())
}

fn present_fts_list(stream: *mut libc::c_void, entry: *mut DarwinFtsEntry) -> Result<()> {
    if let Some(state) = lock(fts_streams()).get_mut(&(stream as usize)) {
        state.present_list(entry)?;
    }
    Ok(())
}

impl FtsBulkCursor {
    fn new(
        runtime: &FilesystemHookRuntime,
        descriptor: libc::c_int,
        identity: FtsDescriptorIdentity,
    ) -> Result<Option<Self>> {
        let (view, _) = runtime.descriptor_directory_view(descriptor)?;
        if view.is_passthrough() {
            return Ok(None);
        }
        let mut filter = DirectoryCursor::new(None, FileLayer::Upper, &view);
        let mut entries = Vec::new();
        let primary_is_upper = runtime.filesystem.is_internal(view.primary());
        Self::extend_entries(&mut entries, &mut filter, view.primary(), !primary_is_upper)?;
        if let Some(lower) = view.lower() {
            Self::extend_entries(&mut entries, &mut filter, lower, true)?;
        }
        Ok(Some(Self {
            identity,
            entries,
            next: 0,
        }))
    }

    fn extend_entries(
        entries: &mut Vec<FtsBulkEntry>,
        filter: &mut DirectoryCursor,
        directory: &Path,
        lower: bool,
    ) -> Result<()> {
        for entry in std::fs::read_dir(directory)? {
            let entry = entry?;
            let name = entry.file_name();
            let Some(name) = filter.include(name.as_bytes(), lower) else {
                continue;
            };
            entries.push(FtsBulkEntry {
                name,
                object_type: darwin_object_type(&entry.file_type()?),
            });
        }
        Ok(())
    }
}

fn darwin_object_type(file_type: &std::fs::FileType) -> u32 {
    if file_type.is_file() {
        1 // VREG
    } else if file_type.is_dir() {
        2 // VDIR
    } else if file_type.is_block_device() {
        3 // VBLK
    } else if file_type.is_char_device() {
        4 // VCHR
    } else if file_type.is_symlink() {
        5 // VLNK
    } else if file_type.is_socket() {
        6 // VSOCK
    } else if file_type.is_fifo() {
        7 // VFIFO
    } else {
        0 // VNON
    }
}

fn fts_descriptor_identity(descriptor: libc::c_int) -> Result<FtsDescriptorIdentity> {
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(descriptor, &mut status) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    Ok(FtsDescriptorIdentity {
        device: status.st_dev,
        inode: status.st_ino,
    })
}

fn fts_attr_record(entry: &FtsBulkEntry, attributes: &libc::attrlist) -> Result<Vec<u8>> {
    const ATTRIBUTE_SET_SIZE: usize = 20;
    const ATTRIBUTE_REFERENCE_OFFSET: usize = 4 + ATTRIBUTE_SET_SIZE;
    const FULL_FIXED_SIZE: usize = 156;
    const NOSTAT_FIXED_SIZE: usize = 56;

    let nostat = attributes.commonattr & libc::ATTR_CMN_CRTIME == 0;
    let fixed_size = if nostat {
        NOSTAT_FIXED_SIZE
    } else {
        FULL_FIXED_SIZE
    };
    let unaligned_size = fixed_size
        .checked_add(entry.name.len())
        .and_then(|size| size.checked_add(1))
        .context("FTS attribute record size overflow")?;
    let record_size = unaligned_size
        .checked_add(3)
        .map(|size| size & !3)
        .context("FTS attribute record size overflow")?;
    let record_length = u32::try_from(record_size).context("FTS attribute record is too large")?;
    let name_length = u32::try_from(entry.name.len() + 1).context("FTS name is too large")?;
    let name_offset = i32::try_from(fixed_size - ATTRIBUTE_REFERENCE_OFFSET)
        .context("FTS name offset is too large")?;

    let mut record = vec![0_u8; record_size];
    record[0..4].copy_from_slice(&record_length.to_ne_bytes());
    let returned_common =
        libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_NAME | libc::ATTR_CMN_OBJTYPE;
    record[4..8].copy_from_slice(&returned_common.to_ne_bytes());
    record[24..28].copy_from_slice(&name_offset.to_ne_bytes());
    record[28..32].copy_from_slice(&name_length.to_ne_bytes());
    record[36..40].copy_from_slice(&entry.object_type.to_ne_bytes());
    record[fixed_size..fixed_size + entry.name.len()].copy_from_slice(&entry.name);
    Ok(record)
}

fn fts_attributes_supported(attributes: &libc::attrlist) -> bool {
    attributes.bitmapcount == libc::ATTR_BIT_MAP_COUNT
        && attributes.commonattr
            & (libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_NAME | libc::ATTR_CMN_OBJTYPE)
            == (libc::ATTR_CMN_RETURNED_ATTRS | libc::ATTR_CMN_NAME | libc::ATTR_CMN_OBJTYPE)
        && attributes.volattr == 0
        && attributes.dirattr == 0
        && attributes.forkattr == 0
}

impl DirectoryCursor {
    fn new(
        auxiliary: Option<*mut libc::DIR>,
        primary_layer: FileLayer,
        view: &DirectoryView,
    ) -> Self {
        Self {
            auxiliary: auxiliary.map(|directory| directory as usize),
            primary_layer,
            reading_lower: false,
            hidden: view
                .hidden()
                .iter()
                .map(|name| name.as_bytes().to_vec())
                .collect(),
            aliases: view
                .aliases()
                .iter()
                .map(|(physical, logical)| {
                    (physical.as_bytes().to_vec(), logical.as_bytes().to_vec())
                })
                .collect(),
            seen: HashSet::new(),
        }
    }

    fn source(&self, primary: *mut libc::DIR) -> Option<*mut libc::DIR> {
        match (self.reading_lower, self.primary_layer) {
            (false, FileLayer::Upper) | (true, FileLayer::Lower) => Some(primary),
            (false, FileLayer::Lower) | (true, FileLayer::Upper) => {
                self.auxiliary.map(|directory| directory as *mut libc::DIR)
            }
        }
    }

    fn include(&mut self, name: &[u8], lower: bool) -> Option<Vec<u8>> {
        let visible = self
            .aliases
            .get(name)
            .map(Vec::as_slice)
            .unwrap_or(name)
            .to_vec();
        if self.hidden.contains(name)
            || self.hidden.contains(&visible)
            || lower && self.seen.contains(&visible)
        {
            return None;
        }
        self.seen.insert(visible.clone());
        Some(visible)
    }

    fn reset(&mut self) {
        self.reading_lower = false;
        self.seen.clear();
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
        match runtime.prepare_open(path, libc::AT_FDCWD, flags, mode) {
            Ok(request) => {
                match request.native_path() {
                    Ok(Some(native)) => return unsafe { original(native.as_ptr(), flags, mode) },
                    Ok(None) => {}
                    Err(error) => return unsafe { fail(&error, -1) },
                }
                if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
                    return unsafe { fail_audit(&error, -1) };
                }
                let mut prepared = match runtime.map_open(request) {
                    Ok(prepared) => prepared,
                    Err(error) => return unsafe { fail(&error, -1) },
                };
                let target_is_path = matches!(prepared.prepared.target(), OpenTarget::Path(_));
                let descriptor = match prepared.prepared.target() {
                    OpenTarget::Path(mapped) => {
                        let mapped = match CString::new(mapped.as_os_str().as_bytes()) {
                            Ok(mapped) => mapped,
                            Err(error) => return unsafe { fail(&error.into(), -1) },
                        };
                        unsafe { original(mapped.as_ptr(), flags, mode) }
                    }
                    OpenTarget::Descriptor(file) => {
                        let descriptor = file.as_raw_fd();
                        if let Err(error) = configure_descriptor(descriptor, flags) {
                            return unsafe { fail(&error, -1) };
                        }
                        descriptor
                    }
                };
                if descriptor < 0 {
                    return descriptor;
                }
                if let Err(error) = runtime.commit_open(&mut prepared) {
                    if target_is_path && let Some(close) = original_close() {
                        unsafe { close(descriptor) };
                    }
                    return unsafe { fail(&error, -1) };
                }
                let (target, file, logical, writeback, layer, close_on_exec) =
                    prepared.into_parts();
                let descriptor = match target {
                    OpenTarget::Path(_) => descriptor,
                    OpenTarget::Descriptor(file) => file.into_raw_fd(),
                };
                runtime.register(descriptor, file, logical, writeback, layer, close_on_exec);
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
        match runtime.prepare_open(path, directory, flags, mode) {
            Ok(request) => {
                match request.native_path() {
                    Ok(Some(native)) => {
                        return unsafe { original(libc::AT_FDCWD, native.as_ptr(), flags, mode) };
                    }
                    Ok(None) => {}
                    Err(error) => return unsafe { fail(&error, -1) },
                }
                if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
                    return unsafe { fail_audit(&error, -1) };
                }
                let mut prepared = match runtime.map_open(request) {
                    Ok(prepared) => prepared,
                    Err(error) => return unsafe { fail(&error, -1) },
                };
                let target_is_path = matches!(prepared.prepared.target(), OpenTarget::Path(_));
                let descriptor = match prepared.prepared.target() {
                    OpenTarget::Path(mapped) => {
                        let mapped = match CString::new(mapped.as_os_str().as_bytes()) {
                            Ok(mapped) => mapped,
                            Err(error) => return unsafe { fail(&error.into(), -1) },
                        };
                        unsafe { original(libc::AT_FDCWD, mapped.as_ptr(), flags, mode) }
                    }
                    OpenTarget::Descriptor(file) => {
                        let descriptor = file.as_raw_fd();
                        if let Err(error) = configure_descriptor(descriptor, flags) {
                            return unsafe { fail(&error, -1) };
                        }
                        descriptor
                    }
                };
                if descriptor < 0 {
                    return descriptor;
                }
                if let Err(error) = runtime.commit_open(&mut prepared) {
                    if target_is_path && let Some(close) = original_close() {
                        unsafe { close(descriptor) };
                    }
                    return unsafe { fail(&error, -1) };
                }
                let (target, file, logical, writeback, layer, close_on_exec) =
                    prepared.into_parts();
                let descriptor = match target {
                    OpenTarget::Path(_) => descriptor,
                    OpenTarget::Descriptor(file) => file.into_raw_fd(),
                };
                runtime.register(descriptor, file, logical, writeback, layer, close_on_exec);
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
            match runtime.prepare_open(path, libc::AT_FDCWD, libc::O_WRONLY | libc::O_TRUNC, 0) {
                Ok(request) => request,
                Err(error) => return unsafe { fail(&error, -1) },
            };
        match request.native_path() {
            Ok(Some(native)) => return unsafe { original(native.as_ptr(), length) },
            Ok(None) => {}
            Err(error) => return unsafe { fail(&error, -1) },
        }
        if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
            return unsafe { fail_audit(&error, -1) };
        }
        let mut prepared = match runtime.map_open(request) {
            Ok(prepared) => prepared,
            Err(error) => return unsafe { fail(&error, -1) },
        };
        let result = match prepared.prepared.target_mut() {
            OpenTarget::Path(mapped) => {
                let mapped = match CString::new(mapped.as_os_str().as_bytes()) {
                    Ok(mapped) => mapped,
                    Err(error) => return unsafe { fail(&error.into(), -1) },
                };
                unsafe { original(mapped.as_ptr(), length) }
            }
            OpenTarget::Descriptor(file) => match u64::try_from(length) {
                Ok(length) => file.set_len(length).map(|()| 0).unwrap_or_else(|error| {
                    unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
                    -1
                }),
                Err(_) => {
                    unsafe { set_errno(libc::EINVAL) };
                    -1
                }
            },
        };
        if result != 0 {
            return result;
        }
        match runtime.commit_open(&mut prepared) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
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
    if runtime.native_passthrough_descriptor(descriptor) {
        return operation(descriptor);
    }
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { libc::fstat(descriptor, &mut status) } != 0 {
        return -1;
    }
    if status.st_mode & libc::S_IFMT != libc::S_IFREG {
        unsafe { set_errno(libc::ENOTSUP) };
        return -1;
    }
    if let Some(open) = runtime.tracked_open(descriptor) {
        if open.layer == FileLayer::Lower {
            unsafe { set_errno(libc::ENOTSUP) };
            return -1;
        }
        let result = operation(descriptor);
        if result == 0 {
            let logical = open.logical();
            if let Err(error) =
                runtime.refresh_attributes(descriptor, logical.to_string_lossy().as_ref())
            {
                return unsafe { fail(&error, -1) };
            }
            if let Err(error) = runtime.writeback(descriptor) {
                return unsafe { fail(&error, -1) };
            }
        }
        return result;
    }
    let staged = match runtime.prepare_descriptor_mutation(descriptor) {
        Ok(staged) => staged,
        Err(error) => return unsafe { fail(&error, -1) },
    };
    let result = operation(descriptor);
    if result == 0
        && let Err(error) = runtime.filesystem.commit_write(staged)
    {
        return unsafe { fail(&error, -1) };
    }
    result
}

unsafe fn sandbox_unsupported_path_mutation(
    path: *const libc::c_char,
    directory: libc::c_int,
    operation: impl FnOnce(libc::c_int, *const libc::c_char) -> libc::c_int,
) -> libc::c_int {
    let Some(_guard) = FilesystemHookGuard::enter() else {
        return operation(directory, path);
    };
    let Some(runtime) = FilesystemHookRuntime::global() else {
        return operation(directory, path);
    };
    match unsafe { runtime.native_passthrough_c_path(path, directory) } {
        Ok(Some(native)) => operation(libc::AT_FDCWD, native.as_ptr()),
        Ok(None) => {
            unsafe { set_errno(libc::ENOTSUP) };
            -1
        }
        Err(error) => unsafe { fail(&error, -1) },
    }
}

unsafe fn sandbox_unsupported_descriptor_mutation(
    descriptor: libc::c_int,
    operation: impl FnOnce(libc::c_int) -> libc::c_int,
) -> libc::c_int {
    let Some(_guard) = FilesystemHookGuard::enter() else {
        return operation(descriptor);
    };
    let Some(runtime) = FilesystemHookRuntime::global() else {
        return operation(descriptor);
    };
    if runtime.native_passthrough_descriptor(descriptor) {
        return operation(descriptor);
    }
    unsafe { set_errno(libc::ENOTSUP) };
    -1
}

unsafe fn sandbox_unsupported_pair_mutation(
    first: *const libc::c_char,
    first_directory: libc::c_int,
    second: *const libc::c_char,
    second_directory: libc::c_int,
    operation: impl FnOnce(
        libc::c_int,
        *const libc::c_char,
        libc::c_int,
        *const libc::c_char,
    ) -> libc::c_int,
) -> libc::c_int {
    let Some(_guard) = FilesystemHookGuard::enter() else {
        return operation(first_directory, first, second_directory, second);
    };
    let Some(runtime) = FilesystemHookRuntime::global() else {
        return operation(first_directory, first, second_directory, second);
    };
    match unsafe {
        runtime.native_passthrough_pair(first, first_directory, second, second_directory)
    } {
        Ok(Some((first, second))) => operation(
            libc::AT_FDCWD,
            first.as_ptr(),
            libc::AT_FDCWD,
            second.as_ptr(),
        ),
        Ok(None) => {
            unsafe { set_errno(libc::ENOTSUP) };
            -1
        }
        Err(error) => unsafe { fail(&error, -1) },
    }
}

macro_rules! unsupported_path_filesystem_hook {
    (
        $sandbox:ident, $export:ident, $original:ident,
        ($($argument:ident: $argument_type:ty),* $(,)?),
        $path:ident, $directory:expr,
        |$original_fn:ident, $native_directory:ident, $native_path:ident| $native_call:expr
    ) => {
        unsafe fn $sandbox($($argument: $argument_type),*) -> libc::c_int {
            catch_filesystem_panic(-1, || match $original() {
                Some($original_fn) => unsafe {
                    sandbox_unsupported_path_mutation(
                        $path,
                        $directory,
                        |$native_directory, $native_path| $native_call,
                    )
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

macro_rules! unsupported_descriptor_filesystem_hook {
    (
        $sandbox:ident, $export:ident, $original:ident,
        ($($argument:ident: $argument_type:ty),* $(,)?),
        $descriptor:ident,
        |$original_fn:ident, $native_descriptor:ident| $native_call:expr
    ) => {
        unsafe fn $sandbox($($argument: $argument_type),*) -> libc::c_int {
            catch_filesystem_panic(-1, || match $original() {
                Some($original_fn) => unsafe {
                    sandbox_unsupported_descriptor_mutation(
                        $descriptor,
                        |$native_descriptor| $native_call,
                    )
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

macro_rules! unsupported_pair_filesystem_hook {
    (
        $sandbox:ident, $export:ident, $original:ident,
        ($($argument:ident: $argument_type:ty),* $(,)?),
        ($first:ident, $first_directory:expr),
        ($second:ident, $second_directory:expr),
        |$original_fn:ident,
         $native_first_directory:ident, $native_first:ident,
         $native_second_directory:ident, $native_second:ident| $native_call:expr
    ) => {
        unsafe fn $sandbox($($argument: $argument_type),*) -> libc::c_int {
            catch_filesystem_panic(-1, || match $original() {
                Some($original_fn) => unsafe {
                    sandbox_unsupported_pair_mutation(
                        $first,
                        $first_directory,
                        $second,
                        $second_directory,
                        |$native_first_directory,
                         $native_first,
                         $native_second_directory,
                         $native_second| $native_call,
                    )
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

unsupported_path_filesystem_hook!(
    sandbox_utimes,
    agora_sandbox_utimes,
    original_utimes,
    (
        path: *const libc::c_char,
        times: *const libc::timeval,
    ),
    path,
    libc::AT_FDCWD,
    |original, _native_directory, native| original(native, times)
);

unsupported_path_filesystem_hook!(
    sandbox_lutimes,
    agora_sandbox_lutimes,
    original_lutimes,
    (
        path: *const libc::c_char,
        times: *const libc::timeval,
    ),
    path,
    libc::AT_FDCWD,
    |original, _native_directory, native| original(native, times)
);

unsupported_descriptor_filesystem_hook!(
    sandbox_futimes,
    agora_sandbox_futimes,
    original_futimes,
    (
        descriptor: libc::c_int,
        times: *const libc::timeval,
    ),
    descriptor,
    |original, native| original(native, times)
);

unsupported_descriptor_filesystem_hook!(
    sandbox_futimens,
    agora_sandbox_futimens,
    original_futimens,
    (
        descriptor: libc::c_int,
        times: *const libc::timespec,
    ),
    descriptor,
    |original, native| original(native, times)
);

unsupported_path_filesystem_hook!(
    sandbox_utimensat,
    agora_sandbox_utimensat,
    original_utimensat,
    (
        directory: libc::c_int,
        path: *const libc::c_char,
        times: *const libc::timespec,
        flags: libc::c_int,
    ),
    path,
    directory,
    |original, native_directory, native| original(native_directory, native, times, flags)
);

unsupported_path_filesystem_hook!(
    sandbox_chflags,
    agora_sandbox_chflags,
    original_chflags,
    (
        path: *const libc::c_char,
        flags: libc::c_uint,
    ),
    path,
    libc::AT_FDCWD,
    |original, _native_directory, native| original(native, flags)
);

unsupported_descriptor_filesystem_hook!(
    sandbox_fchflags,
    agora_sandbox_fchflags,
    original_fchflags,
    (
        descriptor: libc::c_int,
        flags: libc::c_uint,
    ),
    descriptor,
    |original, native| original(native, flags)
);

unsupported_path_filesystem_hook!(
    sandbox_setxattr,
    agora_sandbox_setxattr,
    original_setxattr,
    (
        path: *const libc::c_char,
        name: *const libc::c_char,
        value: *const libc::c_void,
        size: libc::size_t,
        position: u32,
        flags: libc::c_int,
    ),
    path,
    libc::AT_FDCWD,
    |original, _native_directory, native| original(native, name, value, size, position, flags)
);

unsupported_descriptor_filesystem_hook!(
    sandbox_fsetxattr,
    agora_sandbox_fsetxattr,
    original_fsetxattr,
    (
        descriptor: libc::c_int,
        name: *const libc::c_char,
        value: *const libc::c_void,
        size: libc::size_t,
        position: u32,
        flags: libc::c_int,
    ),
    descriptor,
    |original, native| original(native, name, value, size, position, flags)
);

unsupported_path_filesystem_hook!(
    sandbox_removexattr,
    agora_sandbox_removexattr,
    original_removexattr,
    (
        path: *const libc::c_char,
        name: *const libc::c_char,
        flags: libc::c_int,
    ),
    path,
    libc::AT_FDCWD,
    |original, _native_directory, native| original(native, name, flags)
);

unsupported_descriptor_filesystem_hook!(
    sandbox_fremovexattr,
    agora_sandbox_fremovexattr,
    original_fremovexattr,
    (
        descriptor: libc::c_int,
        name: *const libc::c_char,
        flags: libc::c_int,
    ),
    descriptor,
    |original, native| original(native, name, flags)
);

unsafe fn sandbox_chmod(path: *const libc::c_char, mode: libc::mode_t) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_chmod() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path, mode) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path, mode) };
        };
        match unsafe { runtime.native_passthrough_c_path(path, libc::AT_FDCWD) } {
            Ok(Some(native)) => return unsafe { original(native.as_ptr(), mode) },
            Ok(None) => {}
            Err(error) => return unsafe { fail(&error, -1) },
        }
        match runtime.chmod(path, libc::AT_FDCWD, mode, true) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_chmod(
    path: *const libc::c_char,
    mode: libc::mode_t,
) -> libc::c_int {
    unsafe { sandbox_chmod(path, mode) }
}

unsafe fn sandbox_fchmod(descriptor: libc::c_int, mode: libc::mode_t) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_fchmod() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, mode) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(descriptor, mode) };
        };
        if runtime.native_passthrough_descriptor(descriptor) {
            return unsafe { original(descriptor, mode) };
        }
        let Some(open) = runtime.tracked_open(descriptor) else {
            unsafe { set_errno(libc::EPERM) };
            return -1;
        };
        match runtime.filesystem.chmod(
            &open.logical(),
            mode.into(),
            false,
            &Credentials::effective(),
        ) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fchmod(
    descriptor: libc::c_int,
    mode: libc::mode_t,
) -> libc::c_int {
    unsafe { sandbox_fchmod(descriptor, mode) }
}

unsafe fn sandbox_fchmodat(
    directory: libc::c_int,
    path: *const libc::c_char,
    mode: libc::mode_t,
    flags: libc::c_int,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_fchmodat() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(directory, path, mode, flags) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(directory, path, mode, flags) };
        };
        match unsafe { runtime.native_passthrough_c_path(path, directory) } {
            Ok(Some(native)) => {
                return unsafe { original(libc::AT_FDCWD, native.as_ptr(), mode, flags) };
            }
            Ok(None) => {}
            Err(error) => return unsafe { fail(&error, -1) },
        }
        if flags & !libc::AT_SYMLINK_NOFOLLOW != 0 {
            unsafe { set_errno(libc::EINVAL) };
            return -1;
        }
        match runtime.chmod(
            path,
            directory,
            mode,
            flags & libc::AT_SYMLINK_NOFOLLOW == 0,
        ) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fchmodat(
    directory: libc::c_int,
    path: *const libc::c_char,
    mode: libc::mode_t,
    flags: libc::c_int,
) -> libc::c_int {
    unsafe { sandbox_fchmodat(directory, path, mode, flags) }
}

unsupported_path_filesystem_hook!(
    sandbox_chown,
    agora_sandbox_chown,
    original_chown,
    (
        path: *const libc::c_char,
        owner: libc::uid_t,
        group: libc::gid_t,
    ),
    path,
    libc::AT_FDCWD,
    |original, _native_directory, native| original(native, owner, group)
);

unsupported_descriptor_filesystem_hook!(
    sandbox_fchown,
    agora_sandbox_fchown,
    original_fchown,
    (
        descriptor: libc::c_int,
        owner: libc::uid_t,
        group: libc::gid_t,
    ),
    descriptor,
    |original, native| original(native, owner, group)
);

unsupported_path_filesystem_hook!(
    sandbox_lchown,
    agora_sandbox_lchown,
    original_lchown,
    (
        path: *const libc::c_char,
        owner: libc::uid_t,
        group: libc::gid_t,
    ),
    path,
    libc::AT_FDCWD,
    |original, _native_directory, native| original(native, owner, group)
);

unsupported_path_filesystem_hook!(
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
    path,
    directory,
    |original, native_directory, native| original(native_directory, native, owner, group, flags)
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
                match request.native_path() {
                    Ok(Some(native)) => return unsafe { original(native.as_ptr(), mode) },
                    Ok(None) => {}
                    Err(error) => {
                        return unsafe { fail(&error, std::ptr::null_mut()) };
                    }
                }
                let flags = request.flags;
                if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
                    return unsafe { fail_audit(&error, std::ptr::null_mut()) };
                }
                let mut prepared = match runtime.map_open(request) {
                    Ok(prepared) => prepared,
                    Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
                };
                let stream = match prepared.prepared.target() {
                    OpenTarget::Path(mapped) => {
                        let mapped = match CString::new(mapped.as_os_str().as_bytes()) {
                            Ok(mapped) => mapped,
                            Err(error) => {
                                return unsafe { fail(&error.into(), std::ptr::null_mut()) };
                            }
                        };
                        unsafe { original(mapped.as_ptr(), mode) }
                    }
                    OpenTarget::Descriptor(file) => {
                        let descriptor = file.as_raw_fd();
                        if let Err(error) = configure_descriptor(descriptor, flags) {
                            return unsafe { fail(&error, std::ptr::null_mut()) };
                        }
                        let duplicate = unsafe { libc::dup(descriptor) };
                        if duplicate < 0 {
                            return std::ptr::null_mut();
                        }
                        if let Err(error) = configure_descriptor(duplicate, flags) {
                            if let Some(close) = original_close() {
                                unsafe { close(duplicate) };
                            }
                            return unsafe { fail(&error, std::ptr::null_mut()) };
                        }
                        let stream = unsafe { libc::fdopen(duplicate, mode) };
                        if stream.is_null()
                            && let Some(close) = original_close()
                        {
                            unsafe { close(duplicate) };
                        }
                        stream
                    }
                };
                if stream.is_null() {
                    return stream;
                }
                if let Err(error) = runtime.commit_open(&mut prepared) {
                    if let Some(close) = original_fclose() {
                        unsafe { close(stream) };
                    }
                    return unsafe { fail(&error, std::ptr::null_mut()) };
                }
                let (target, file, logical, writeback, layer, close_on_exec) =
                    prepared.into_parts();
                drop(target);
                let descriptor = unsafe { libc::fileno(stream) };
                if descriptor >= 0 {
                    runtime.register(descriptor, file, logical, writeback, layer, close_on_exec);
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

unsafe fn sandbox_freopen(
    path: *const libc::c_char,
    mode: *const libc::c_char,
    stream: *mut libc::FILE,
) -> *mut libc::FILE {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_freopen() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path, mode, stream) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path, mode, stream) };
        };
        match unsafe { runtime.native_passthrough_c_path(path, libc::AT_FDCWD) } {
            Ok(Some(native)) => {
                let descriptor = if stream.is_null() {
                    -1
                } else {
                    unsafe { libc::fileno(stream) }
                };
                if descriptor >= 0
                    && let Err(error) = runtime.writeback(descriptor)
                {
                    return unsafe { fail(&error, std::ptr::null_mut()) };
                }
                let result = unsafe { original(native.as_ptr(), mode, stream) };
                if descriptor >= 0 {
                    runtime.take_descriptor(descriptor);
                    runtime.unregister_directory(descriptor);
                }
                return result;
            }
            Ok(None) => {}
            Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
        }
        unsafe { set_errno(libc::ENOTSUP) };
        std::ptr::null_mut()
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_freopen(
    path: *const libc::c_char,
    mode: *const libc::c_char,
    stream: *mut libc::FILE,
) -> *mut libc::FILE {
    unsafe { sandbox_freopen(path, mode, stream) }
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
        let request = match runtime.prepare_open(path, libc::AT_FDCWD, flags, mode) {
            Ok(request) => request,
            Err(error) => return error_errno(&error),
        };
        match request.native_path() {
            Ok(Some(native)) => {
                return unsafe { original(actions, descriptor, native.as_ptr(), flags, mode) };
            }
            Ok(None) => {}
            Err(error) => return error_errno(&error),
        }
        if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
            return error.errno();
        }
        let write_intent = flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_CREAT | libc::O_TRUNC | libc::O_APPEND) != 0;
        if write_intent {
            if flags & libc::O_CREAT == 0 {
                match runtime.filesystem.exists(&request.logical) {
                    Ok(true) => {}
                    Ok(false) => return libc::ENOENT,
                    Err(error) => return error_errno(&error),
                }
            }
            return libc::ENOTSUP;
        }
        let prepared = match runtime.map_open(request) {
            Ok(prepared) => prepared,
            Err(error) => return error_errno(&error),
        };
        let mapped = match prepared.prepared.target() {
            OpenTarget::Path(mapped) => match CString::new(mapped.as_os_str().as_bytes()) {
                Ok(mapped) => mapped,
                Err(error) => return error_errno(&error.into()),
            },
            OpenTarget::Descriptor(_) => return libc::ENOTSUP,
        };
        unsafe { original(actions, descriptor, mapped.as_ptr(), flags, mode) }
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

unsupported_pair_filesystem_hook!(
    sandbox_link,
    agora_sandbox_link,
    original_link,
    (
        source: *const libc::c_char,
        destination: *const libc::c_char,
    ),
    (source, libc::AT_FDCWD),
    (destination, libc::AT_FDCWD),
    |original,
     _native_source_directory,
     native_source,
     _native_destination_directory,
     native_destination| original(native_source, native_destination)
);

unsupported_pair_filesystem_hook!(
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
    (source, source_directory),
    (destination, destination_directory),
    |original,
     native_source_directory,
     native_source,
     native_destination_directory,
     native_destination| original(
        native_source_directory,
        native_source,
        native_destination_directory,
        native_destination,
        flags,
    )
);

unsafe fn sandbox_symlink(target: *const libc::c_char, link: *const libc::c_char) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_symlink() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(target, link) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(target, link) };
        };
        match runtime.create_symlink(target, libc::AT_FDCWD, link) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_symlink(
    target: *const libc::c_char,
    link: *const libc::c_char,
) -> libc::c_int {
    unsafe { sandbox_symlink(target, link) }
}

unsafe fn sandbox_symlinkat(
    target: *const libc::c_char,
    directory: libc::c_int,
    link: *const libc::c_char,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_symlinkat() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(target, directory, link) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(target, directory, link) };
        };
        match runtime.create_symlink(target, directory, link) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_symlinkat(
    target: *const libc::c_char,
    directory: libc::c_int,
    link: *const libc::c_char,
) -> libc::c_int {
    unsafe { sandbox_symlinkat(target, directory, link) }
}

unsupported_pair_filesystem_hook!(
    sandbox_clonefile,
    agora_sandbox_clonefile,
    original_clonefile,
    (
        source: *const libc::c_char,
        destination: *const libc::c_char,
        flags: u32,
    ),
    (source, libc::AT_FDCWD),
    (destination, libc::AT_FDCWD),
    |original,
     _native_source_directory,
     native_source,
     _native_destination_directory,
     native_destination| original(
        native_source,
        native_destination,
        flags,
    )
);

unsupported_pair_filesystem_hook!(
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
    (source, source_directory),
    (destination, destination_directory),
    |original,
     native_source_directory,
     native_source,
     native_destination_directory,
     native_destination| original(
        native_source_directory,
        native_source,
        native_destination_directory,
        native_destination,
        flags,
    )
);

unsupported_pair_filesystem_hook!(
    sandbox_copyfile,
    agora_sandbox_copyfile,
    original_copyfile,
    (
        source: *const libc::c_char,
        destination: *const libc::c_char,
        state: libc::copyfile_state_t,
        flags: libc::copyfile_flags_t,
    ),
    (source, libc::AT_FDCWD),
    (destination, libc::AT_FDCWD),
    |original,
     _native_source_directory,
     native_source,
     _native_destination_directory,
     native_destination| original(
        native_source,
        native_destination,
        state,
        flags,
    )
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
        let tracked = runtime.take_descriptor(descriptor);
        if let Some((open, true)) = &tracked
            && let Err(error) = runtime.commit_open_file(descriptor, open)
        {
            runtime.restore_descriptor(descriptor, Arc::clone(open));
            return unsafe { fail(&error, -1) };
        }
        let result = unsafe { original(descriptor) };
        if result != 0
            && let Some((open, _)) = tracked
        {
            runtime.restore_descriptor(descriptor, open);
        } else if result == 0 {
            runtime.unregister_directory(descriptor);
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
        let flush_result = if descriptor >= 0 {
            unsafe { libc::fflush(stream) }
        } else {
            0
        };
        let flush_errno = (flush_result != 0).then(|| unsafe { *libc::__error() });
        let tracked = runtime.take_descriptor(descriptor);
        let commit_error = tracked
            .as_ref()
            .filter(|(_, last_alias)| *last_alias)
            .and_then(|(open, _)| runtime.commit_open_file(descriptor, open).err());
        let result = unsafe { original(stream) };
        if let Some(error) = commit_error {
            return unsafe { fail(&error, -1) };
        }
        if result != 0 {
            return result;
        }
        if let Some(errno) = flush_errno {
            unsafe { set_errno(errno) };
            return -1;
        }
        0
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fclose(stream: *mut libc::FILE) -> libc::c_int {
    unsafe { sandbox_fclose(stream) }
}

unsafe fn sandbox_sync_descriptor(descriptor: libc::c_int, original: DescriptorFn) -> libc::c_int {
    let result = unsafe { original(descriptor) };
    if result != 0 {
        return result;
    }
    let Some(_guard) = FilesystemHookGuard::enter() else {
        return result;
    };
    let Some(runtime) = FilesystemHookRuntime::global() else {
        return result;
    };
    match runtime.writeback(descriptor) {
        Ok(()) => result,
        Err(error) => unsafe { fail(&error, -1) },
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fsync(descriptor: libc::c_int) -> libc::c_int {
    catch_filesystem_panic(-1, || match original_fsync() {
        Some(original) => unsafe { sandbox_sync_descriptor(descriptor, original) },
        None => {
            unsafe { set_errno(libc::ENOSYS) };
            -1
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_commit_synced_descriptor(
    descriptor: libc::c_int,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return 0;
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return 0;
        };
        match runtime.writeback(descriptor) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_dup(descriptor: libc::c_int) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_dup() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let result = unsafe { original(descriptor) };
        if result < 0 {
            return result;
        }
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return result;
        };
        if let Some(runtime) = FilesystemHookRuntime::global() {
            runtime.duplicate_descriptor(descriptor, result);
        }
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_dup2(
    source: libc::c_int,
    destination: libc::c_int,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_dup2() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(source, destination) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(source, destination) };
        };
        if source == destination {
            return unsafe { original(source, destination) };
        }
        if let Err(error) = runtime.writeback(destination) {
            return unsafe { fail(&error, -1) };
        }
        let result = unsafe { original(source, destination) };
        if result >= 0 {
            runtime.take_descriptor(destination);
            runtime.duplicate_descriptor(source, destination);
        }
        result
    })
}

#[unsafe(no_mangle)]
pub extern "C" fn agora_sandbox_track_fcntl_duplicate(
    source: libc::c_int,
    destination: libc::c_int,
) {
    let _ = catch_unwind(AssertUnwindSafe(|| {
        if let Some(runtime) = FilesystemHookRuntime::global() {
            runtime.duplicate_descriptor(source, destination);
        }
    }));
}

#[unsafe(no_mangle)]
pub extern "C" fn agora_sandbox_fcntl_setfd_argument(
    descriptor: libc::c_int,
    flags: libc::c_int,
) -> libc::c_int {
    catch_unwind(AssertUnwindSafe(|| {
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return flags;
        };
        if runtime
            .tracked_open(descriptor)
            .is_some_and(|open| open.close_on_exec)
        {
            flags | libc::FD_CLOEXEC
        } else {
            flags
        }
    }))
    .unwrap_or(flags | libc::FD_CLOEXEC)
}

#[unsafe(no_mangle)]
pub extern "C" fn agora_sandbox_original_fcntl() -> *const libc::c_void {
    INTERPOSE_FCNTL.replacee
}

unsafe fn mapped_stat(
    path: *const libc::c_char,
    status: *mut libc::stat,
    original: StatFn,
    follow_final: bool,
) -> libc::c_int {
    let Some(_guard) = FilesystemHookGuard::enter() else {
        return unsafe { original(path, status) };
    };
    let Some(runtime) = FilesystemHookRuntime::global() else {
        return unsafe { original(path, status) };
    };
    let caller_errno = unsafe { *libc::__error() };
    match runtime.map_metadata(
        path,
        libc::AT_FDCWD,
        follow_final,
        &Credentials::effective(),
    ) {
        Ok((mapped, plaintext_size, attributes)) => {
            let result = unsafe { original(mapped.as_ptr(), status) };
            if result == 0 && !status.is_null() {
                unsafe { patch_stat(&mut *status, plaintext_size, attributes.as_ref()) };
            }
            if result == 0 {
                unsafe { set_errno(caller_errno) };
            }
            result
        }
        Err(error) => unsafe { fail(&error, -1) },
    }
}

unsafe fn patch_stat(
    status: &mut libc::stat,
    plaintext_size: Option<libc::off_t>,
    attributes: Option<&FileAttributes>,
) {
    if let Some(size) = plaintext_size {
        status.st_size = size;
    }
    if let Some(attributes) = attributes {
        status.st_mode = attributes.mode as _;
        status.st_uid = attributes.uid;
        status.st_gid = attributes.gid;
        status.st_atime = attributes.atime;
        status.st_atime_nsec = attributes.atime_nsec;
        status.st_mtime = attributes.mtime;
        status.st_mtime_nsec = attributes.mtime_nsec;
    }
}

unsafe fn sandbox_stat(path: *const libc::c_char, status: *mut libc::stat) -> libc::c_int {
    catch_filesystem_panic(-1, || match original_stat() {
        Some(original) => unsafe { mapped_stat(path, status, original, true) },
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
        Some(original) => unsafe { mapped_stat(path, status, original, false) },
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
        let caller_errno = unsafe { *libc::__error() };
        let follow_final = flags & libc::AT_SYMLINK_NOFOLLOW == 0;
        match runtime.map_metadata(path, directory, follow_final, &Credentials::effective()) {
            Ok((mapped, plaintext_size, attributes)) => {
                let result = unsafe { original(libc::AT_FDCWD, mapped.as_ptr(), status, flags) };
                if result == 0 && !status.is_null() {
                    unsafe { patch_stat(&mut *status, plaintext_size, attributes.as_ref()) };
                }
                if result == 0 {
                    unsafe { set_errno(caller_errno) };
                }
                result
            }
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

unsafe fn sandbox_fstat(descriptor: libc::c_int, status: *mut libc::stat) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_fstat() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, status) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(descriptor, status) };
        };
        let caller_errno = unsafe { *libc::__error() };
        let result = unsafe { original(descriptor, status) };
        if result == 0
            && !status.is_null()
            && let Some(open) = runtime.tracked_open(descriptor)
        {
            let attributes = match runtime.filesystem.attributes(&open.logical()) {
                Ok(attributes) => attributes,
                Err(error) => return unsafe { fail(&error, -1) },
            };
            unsafe { patch_stat(&mut *status, None, attributes.as_ref()) };
        }
        if result == 0 {
            unsafe { set_errno(caller_errno) };
        }
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fstat(
    descriptor: libc::c_int,
    status: *mut libc::stat,
) -> libc::c_int {
    unsafe { sandbox_fstat(descriptor, status) }
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
        if !valid_access_mode(mode) {
            unsafe { set_errno(libc::EINVAL) };
            return -1;
        }
        let credentials = Credentials::real();
        match runtime.map_metadata(path, libc::AT_FDCWD, true, &credentials) {
            Ok((_mapped, _, Some(attributes))) => {
                if credentials.allows(&attributes, mode) {
                    0
                } else {
                    unsafe { set_errno(libc::EACCES) };
                    -1
                }
            }
            Ok((mapped, _, None)) => unsafe { original(mapped.as_ptr(), mode) },
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

fn valid_access_mode(mode: libc::c_int) -> bool {
    mode & !(libc::R_OK | libc::W_OK | libc::X_OK) == 0
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_access(
    path: *const libc::c_char,
    mode: libc::c_int,
) -> libc::c_int {
    unsafe { sandbox_access(path, mode) }
}

unsafe fn sandbox_faccessat(
    directory: libc::c_int,
    path: *const libc::c_char,
    mode: libc::c_int,
    flags: libc::c_int,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_faccessat() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(directory, path, mode, flags) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(directory, path, mode, flags) };
        };
        if flags & !(libc::AT_EACCESS | libc::AT_SYMLINK_NOFOLLOW) != 0 {
            unsafe { set_errno(libc::EINVAL) };
            return -1;
        }
        if !valid_access_mode(mode) {
            unsafe { set_errno(libc::EINVAL) };
            return -1;
        }
        let credentials = if flags & libc::AT_EACCESS != 0 {
            Credentials::effective()
        } else {
            Credentials::real()
        };
        match runtime.map_metadata(
            path,
            directory,
            flags & libc::AT_SYMLINK_NOFOLLOW == 0,
            &credentials,
        ) {
            Ok((_mapped, _, Some(attributes))) => {
                if credentials.allows(&attributes, mode) {
                    0
                } else {
                    unsafe { set_errno(libc::EACCES) };
                    -1
                }
            }
            Ok((mapped, _, None)) => unsafe {
                original(libc::AT_FDCWD, mapped.as_ptr(), mode, flags)
            },
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_faccessat(
    directory: libc::c_int,
    path: *const libc::c_char,
    mode: libc::c_int,
    flags: libc::c_int,
) -> libc::c_int {
    unsafe { sandbox_faccessat(directory, path, mode, flags) }
}

unsafe fn sandbox_readlink(
    path: *const libc::c_char,
    buffer: *mut libc::c_char,
    size: libc::size_t,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_readlink() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path, buffer, size) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path, buffer, size) };
        };
        match runtime.map_metadata(path, libc::AT_FDCWD, false, &Credentials::effective()) {
            Ok((mapped, _, _)) => unsafe { original(mapped.as_ptr(), buffer, size) },
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_readlink(
    path: *const libc::c_char,
    buffer: *mut libc::c_char,
    size: libc::size_t,
) -> libc::ssize_t {
    unsafe { sandbox_readlink(path, buffer, size) }
}

unsafe fn sandbox_readlinkat(
    directory: libc::c_int,
    path: *const libc::c_char,
    buffer: *mut libc::c_char,
    size: libc::size_t,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original_at) = original_readlinkat() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original_at(directory, path, buffer, size) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original_at(directory, path, buffer, size) };
        };
        let Some(original) = original_readlink() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        match runtime.map_metadata(path, directory, false, &Credentials::effective()) {
            Ok((mapped, _, _)) => unsafe { original(mapped.as_ptr(), buffer, size) },
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_readlinkat(
    directory: libc::c_int,
    path: *const libc::c_char,
    buffer: *mut libc::c_char,
    size: libc::size_t,
) -> libc::ssize_t {
    unsafe { sandbox_readlinkat(directory, path, buffer, size) }
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
        match unsafe { runtime.native_passthrough_c_path(path, directory) } {
            Ok(Some(native)) => {
                return unsafe { original(libc::AT_FDCWD, native.as_ptr(), flags) };
            }
            Ok(None) => {}
            Err(error) => return unsafe { fail(&error, -1) },
        }
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

unsafe fn sandbox_renamex_np(
    from: *const libc::c_char,
    to: *const libc::c_char,
    flags: libc::c_uint,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_renamex_np() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(from, to, flags) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(from, to, flags) };
        };
        match unsafe { runtime.native_passthrough_pair(from, libc::AT_FDCWD, to, libc::AT_FDCWD) } {
            Ok(Some((from, to))) => {
                return unsafe { original(from.as_ptr(), to.as_ptr(), flags) };
            }
            Ok(None) => {}
            Err(error) => return unsafe { fail(&error, -1) },
        }
        if flags != 0 {
            unsafe { set_errno(libc::ENOTSUP) };
            return -1;
        }
        match runtime.rename(libc::AT_FDCWD, from, libc::AT_FDCWD, to) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_renamex_np(
    from: *const libc::c_char,
    to: *const libc::c_char,
    flags: libc::c_uint,
) -> libc::c_int {
    unsafe { sandbox_renamex_np(from, to, flags) }
}

unsafe fn sandbox_renameatx_np(
    from_directory: libc::c_int,
    from: *const libc::c_char,
    to_directory: libc::c_int,
    to: *const libc::c_char,
    flags: libc::c_uint,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_renameatx_np() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(from_directory, from, to_directory, to, flags) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(from_directory, from, to_directory, to, flags) };
        };
        match unsafe { runtime.native_passthrough_pair(from, from_directory, to, to_directory) } {
            Ok(Some((from, to))) => {
                return unsafe {
                    original(
                        libc::AT_FDCWD,
                        from.as_ptr(),
                        libc::AT_FDCWD,
                        to.as_ptr(),
                        flags,
                    )
                };
            }
            Ok(None) => {}
            Err(error) => return unsafe { fail(&error, -1) },
        }
        if flags != 0 {
            unsafe { set_errno(libc::ENOTSUP) };
            return -1;
        }
        match runtime.rename(from_directory, from, to_directory, to) {
            Ok(()) => 0,
            Err(error) => unsafe { fail(&error, -1) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_renameatx_np(
    from_directory: libc::c_int,
    from: *const libc::c_char,
    to_directory: libc::c_int,
    to: *const libc::c_char,
    flags: libc::c_uint,
) -> libc::c_int {
    unsafe { sandbox_renameatx_np(from_directory, from, to_directory, to, flags) }
}

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
        let caller_errno = unsafe { *libc::__error() };
        match runtime.prepare_change_directory(path) {
            Ok((mapped, logical)) => {
                let result = unsafe { original(mapped.as_ptr()) };
                if result == 0 {
                    if runtime.synchronize_current_directory().is_err() {
                        runtime.set_current_directory(logical);
                    }
                    unsafe { set_errno(caller_errno) };
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

unsafe fn sandbox_fchdir(descriptor: libc::c_int) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_fchdir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(descriptor) };
        };
        let caller_errno = unsafe { *libc::__error() };
        if runtime.native_passthrough_descriptor(descriptor) {
            let result = unsafe { original(descriptor) };
            if result == 0 {
                let _ = runtime.synchronize_current_directory();
                unsafe { set_errno(caller_errno) };
            }
            return result;
        }
        let logical = match runtime.resolve_descriptor_logical_path(descriptor) {
            Ok(logical) => logical,
            Err(error) => return unsafe { fail(&error, -1) },
        };
        if let Err(error) =
            runtime
                .filesystem
                .require_access(&logical, libc::X_OK, &Credentials::effective())
        {
            return unsafe { fail(&error, -1) };
        }
        let result = unsafe { original(descriptor) };
        if result == 0 {
            if runtime.synchronize_current_directory().is_err() {
                runtime.set_current_directory(logical);
            }
            unsafe { set_errno(caller_errno) };
        }
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fchdir(descriptor: libc::c_int) -> libc::c_int {
    unsafe { sandbox_fchdir(descriptor) }
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

unsafe fn sandbox_realpath(
    path: *const libc::c_char,
    resolved: *mut libc::c_char,
) -> *mut libc::c_char {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_realpath() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(path, resolved) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(path, resolved) };
        };
        match unsafe { runtime.native_passthrough_c_path(path, libc::AT_FDCWD) } {
            Ok(Some(native)) => return unsafe { original(native.as_ptr(), resolved) },
            Ok(None) => {}
            Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
        }
        let canonical = match unsafe { runtime.canonical_path(path) } {
            Ok(canonical) => canonical,
            Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
        };
        let required = canonical.as_bytes_with_nul().len();
        if required > libc::PATH_MAX as usize {
            unsafe { set_errno(libc::ENAMETOOLONG) };
            return std::ptr::null_mut();
        }
        let target = if resolved.is_null() {
            let allocated = unsafe { libc::malloc(required) }.cast::<libc::c_char>();
            if allocated.is_null() {
                unsafe { set_errno(libc::ENOMEM) };
                return std::ptr::null_mut();
            }
            allocated
        } else {
            resolved
        };
        unsafe {
            std::ptr::copy_nonoverlapping(canonical.as_ptr(), target, required);
        }
        target
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_realpath(
    path: *const libc::c_char,
    resolved: *mut libc::c_char,
) -> *mut libc::c_char {
    unsafe { sandbox_realpath(path, resolved) }
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
                let primary = match CString::new(view.primary().as_os_str().as_bytes()) {
                    Ok(path) => path,
                    Err(error) => return unsafe { fail(&error.into(), std::ptr::null_mut()) },
                };
                let directory = unsafe { original(primary.as_ptr()) };
                if directory.is_null() {
                    return directory;
                }
                if view.is_passthrough() {
                    return directory;
                }
                let layer = if runtime.filesystem.is_internal(view.primary()) {
                    FileLayer::Upper
                } else {
                    FileLayer::Lower
                };
                let auxiliary = match unsafe { open_auxiliary_directory(&view, layer) } {
                    Ok(auxiliary) => auxiliary,
                    Err(error) => {
                        unsafe { original_closedir().map(|close| close(directory)) };
                        return unsafe { fail(&error, std::ptr::null_mut()) };
                    }
                };
                unsafe { register_directory_cursor(runtime, directory, auxiliary, layer, &view) };
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

unsafe fn open_auxiliary_directory(
    view: &DirectoryView,
    primary_layer: FileLayer,
) -> Result<Option<*mut libc::DIR>> {
    let path = match primary_layer {
        FileLayer::Upper => view.lower(),
        FileLayer::Lower if view.lower().is_some() => Some(view.primary()),
        FileLayer::Lower => None,
    };
    let Some(path) = path else {
        return Ok(None);
    };
    let path = CString::new(path.as_os_str().as_bytes())
        .context("auxiliary directory path contains NUL")?;
    let original = original_opendir().context("opendir is unavailable")?;
    let directory = unsafe { original(path.as_ptr()) };
    if directory.is_null() {
        return Err(io::Error::last_os_error().into());
    }
    Ok(Some(directory))
}

unsafe fn register_directory_cursor(
    runtime: &FilesystemHookRuntime,
    directory: *mut libc::DIR,
    auxiliary: Option<*mut libc::DIR>,
    primary_layer: FileLayer,
    view: &DirectoryView,
) {
    lock(directory_cursors()).insert(
        directory as usize,
        DirectoryCursor::new(auxiliary, primary_layer, view),
    );
    runtime.register_directory(unsafe { libc::dirfd(directory) }, view.logical().into());
}

unsafe fn sandbox_fdopendir(descriptor: libc::c_int) -> *mut libc::DIR {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_fdopendir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(descriptor) };
        };
        let (view, layer) = match runtime.descriptor_directory_view(descriptor) {
            Ok(view) => view,
            Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
        };
        if view.is_passthrough() && layer == FileLayer::Lower {
            return unsafe { original(descriptor) };
        }
        let auxiliary = match unsafe { open_auxiliary_directory(&view, layer) } {
            Ok(auxiliary) => auxiliary,
            Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
        };
        let directory = unsafe { original(descriptor) };
        if directory.is_null() {
            let error = unsafe { *libc::__error() };
            if let Some(auxiliary) = auxiliary {
                unsafe { original_closedir().map(|close| close(auxiliary)) };
            }
            unsafe { set_errno(error) };
            return directory;
        }
        unsafe { register_directory_cursor(runtime, directory, auxiliary, layer, &view) };
        directory
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fdopendir(descriptor: libc::c_int) -> *mut libc::DIR {
    unsafe { sandbox_fdopendir(descriptor) }
}

unsafe fn sandbox_readdir(directory: *mut libc::DIR) -> *mut libc::dirent {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_readdir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        let mut cursors = lock(directory_cursors());
        let Some(cursor) = cursors.get_mut(&(directory as usize)) else {
            unsafe { set_errno(0) };
            return unsafe { original(directory) };
        };
        loop {
            let source = match cursor.source(directory) {
                Some(source) => source,
                None if cursor.reading_lower => {
                    return std::ptr::null_mut();
                }
                None => {
                    cursor.reading_lower = true;
                    continue;
                }
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
            if let Some(visible) = cursor.include(name.to_bytes(), cursor.reading_lower) {
                if visible != name.to_bytes() {
                    if visible.len() >= unsafe { (*entry).d_name.len() } {
                        unsafe { set_errno(libc::ENAMETOOLONG) };
                        return std::ptr::null_mut();
                    }
                    unsafe {
                        std::ptr::copy_nonoverlapping(
                            visible.as_ptr().cast::<libc::c_char>(),
                            (*entry).d_name.as_mut_ptr(),
                            visible.len(),
                        );
                        (*entry).d_name[visible.len()] = 0;
                        (*entry).d_namlen = visible.len() as u16;
                    }
                }
                return entry;
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_readdir(directory: *mut libc::DIR) -> *mut libc::dirent {
    unsafe { sandbox_readdir(directory) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_readdir_r(
    directory: *mut libc::DIR,
    entry: *mut libc::dirent,
    result: *mut *mut libc::dirent,
) -> libc::c_int {
    catch_filesystem_panic(libc::EIO, || {
        if directory.is_null() || entry.is_null() || result.is_null() {
            return libc::EINVAL;
        }
        unsafe { *result = std::ptr::null_mut() };
        unsafe { set_errno(0) };
        let source = unsafe { sandbox_readdir(directory) };
        if source.is_null() {
            let error = unsafe { *libc::__error() };
            return error;
        }
        unsafe {
            std::ptr::copy_nonoverlapping(source, entry, 1);
            *result = entry;
        }
        0
    })
}

unsafe fn sandbox_rewinddir(directory: *mut libc::DIR) {
    catch_filesystem_panic((), || {
        let Some(original) = original_rewinddir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return;
        };
        let mut cursors = lock(directory_cursors());
        let Some(cursor) = cursors.get_mut(&(directory as usize)) else {
            unsafe { original(directory) };
            return;
        };
        unsafe { original(directory) };
        if let Some(auxiliary) = cursor.auxiliary {
            unsafe { original(auxiliary as *mut libc::DIR) };
        }
        cursor.reset();
    });
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_rewinddir(directory: *mut libc::DIR) {
    unsafe { sandbox_rewinddir(directory) }
}

unsafe fn sandbox_closedir(directory: *mut libc::DIR) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_closedir() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let cursor = lock(directory_cursors()).remove(&(directory as usize));
        let descriptor = unsafe { libc::dirfd(directory) };
        let result = unsafe { original(directory) };
        if let Some(auxiliary) = cursor.and_then(|cursor| cursor.auxiliary) {
            unsafe { original(auxiliary as *mut libc::DIR) };
        }
        if result == 0
            && let Some(runtime) = FilesystemHookRuntime::global()
        {
            runtime.take_descriptor(descriptor);
            runtime.unregister_directory(descriptor);
        }
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_closedir(directory: *mut libc::DIR) -> libc::c_int {
    unsafe { sandbox_closedir(directory) }
}

unsafe fn sandbox_getattrlistbulk(
    directory: libc::c_int,
    attributes: *mut libc::c_void,
    buffer: *mut libc::c_void,
    size: libc::size_t,
    options: u64,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_getattrlistbulk() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        if !FtsVirtualBulk::is_active() {
            return unsafe { original(directory, attributes, buffer, size, options) };
        }
        if attributes.is_null() || buffer.is_null() {
            unsafe { set_errno(libc::EFAULT) };
            return -1;
        }
        let attributes = unsafe { std::ptr::read(attributes.cast::<libc::attrlist>()) };
        if !fts_attributes_supported(&attributes) {
            return unsafe {
                original(
                    directory,
                    (&raw const attributes).cast_mut().cast(),
                    buffer,
                    size,
                    options,
                )
            };
        }
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe {
                original(
                    directory,
                    (&raw const attributes).cast_mut().cast(),
                    buffer,
                    size,
                    options,
                )
            };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe {
                original(
                    directory,
                    (&raw const attributes).cast_mut().cast(),
                    buffer,
                    size,
                    options,
                )
            };
        };
        let identity = match fts_descriptor_identity(directory) {
            Ok(identity) => identity,
            Err(error) => return unsafe { fail(&error, -1) },
        };
        let needs_cursor = FTS_BULK_CURSORS.with(|cursors| {
            cursors
                .borrow()
                .get(&directory)
                .is_none_or(|cursor| cursor.identity != identity)
        });
        if needs_cursor {
            if let Err(error) = runtime.synchronize_current_directory() {
                return unsafe { fail(&error, -1) };
            }
            let cursor = match FtsBulkCursor::new(runtime, directory, identity) {
                Ok(Some(cursor)) => cursor,
                Ok(None) => {
                    return unsafe {
                        original(
                            directory,
                            (&raw const attributes).cast_mut().cast(),
                            buffer,
                            size,
                            options,
                        )
                    };
                }
                Err(error) => return unsafe { fail(&error, -1) },
            };
            FTS_BULK_CURSORS.with(|cursors| {
                cursors.borrow_mut().insert(directory, cursor);
            });
        }

        let mut written = 0_usize;
        let mut count = 0_i32;
        let mut finished = false;
        let result = FTS_BULK_CURSORS.with(|cursors| -> Result<()> {
            let mut cursors = cursors.borrow_mut();
            let cursor = cursors
                .get_mut(&directory)
                .context("missing FTS bulk cursor")?;
            while let Some(entry) = cursor.entries.get(cursor.next) {
                let record = fts_attr_record(entry, &attributes)?;
                if record.len() > size.saturating_sub(written) {
                    if count == 0 {
                        return Err(io::Error::from_raw_os_error(libc::ERANGE).into());
                    }
                    break;
                }
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        record.as_ptr(),
                        buffer.cast::<u8>().add(written),
                        record.len(),
                    );
                }
                written += record.len();
                count += 1;
                cursor.next += 1;
            }
            finished = cursor.next == cursor.entries.len() && count == 0;
            Ok(())
        });
        if let Err(error) = result {
            FTS_BULK_CURSORS.with(|cursors| {
                cursors.borrow_mut().remove(&directory);
            });
            return unsafe { fail(&error, -1) };
        }
        if finished {
            FTS_BULK_CURSORS.with(|cursors| {
                cursors.borrow_mut().remove(&directory);
            });
        }
        unsafe { set_errno(0) };
        count
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_getattrlistbulk(
    directory: libc::c_int,
    attributes: *mut libc::c_void,
    buffer: *mut libc::c_void,
    size: libc::size_t,
    options: u64,
) -> libc::c_int {
    unsafe { sandbox_getattrlistbulk(directory, attributes, buffer, size, options) }
}

fn fts_entry_is_visible(runtime: &FilesystemHookRuntime, entry: *mut DarwinFtsEntry) -> bool {
    let raw_path = unsafe { (*entry).fts_accpath };
    if raw_path.is_null() {
        return true;
    }
    unsafe { trusted_fts_logical_path(runtime, raw_path) }
        .and_then(|logical| runtime.filesystem.exists(&logical))
        .unwrap_or(true)
}

unsafe fn trusted_fts_logical_path(
    runtime: &FilesystemHookRuntime,
    path: *const libc::c_char,
) -> Result<PathBuf> {
    let requested = Path::new(OsStr::from_bytes(
        unsafe { CStr::from_ptr(path) }.to_bytes(),
    ));
    if requested.is_absolute() && runtime.filesystem.is_internal(requested) {
        runtime.filesystem.logical_path(requested)
    } else {
        unsafe { runtime.logical_path(path, libc::AT_FDCWD) }
    }
}

unsafe fn sandbox_fts_open(
    paths: *const *mut libc::c_char,
    options: libc::c_int,
    compare: Option<FtsCompareFn>,
) -> *mut libc::c_void {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_fts_open() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        if paths.is_null() {
            unsafe { set_errno(libc::EFAULT) };
            return std::ptr::null_mut();
        }
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(paths, options, compare) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(paths, options, compare) };
        };
        if let Err(error) = runtime.synchronize_current_directory() {
            return unsafe { fail(&error, std::ptr::null_mut()) };
        }

        let mut mapped_paths = Vec::new();
        let mut mappings = Vec::new();
        let mut index = 0_usize;
        loop {
            let path = unsafe { *paths.add(index) };
            if path.is_null() {
                break;
            }
            let original_path = unsafe { CStr::from_ptr(path) };
            let logical = match unsafe { runtime.logical_path(path, libc::AT_FDCWD) } {
                Ok(logical) => logical,
                Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
            };
            let (mapped, _, _) = match runtime.map_metadata(
                path,
                libc::AT_FDCWD,
                false,
                &Credentials::effective(),
            ) {
                Ok(mapped) => mapped,
                Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
            };
            if mapped.to_bytes() == logical.as_os_str().as_bytes() {
                match CString::new(original_path.to_bytes()) {
                    Ok(path) => mapped_paths.push(path),
                    Err(error) => return unsafe { fail(&error.into(), std::ptr::null_mut()) },
                }
            } else {
                mappings.push(FtsRootMapping {
                    physical: mapped.to_bytes().to_vec(),
                    logical: original_path.to_bytes().to_vec(),
                });
                mapped_paths.push(mapped);
            }
            index += 1;
        }
        let mut mapped_argv = mapped_paths
            .iter_mut()
            .map(|path| path.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        mapped_argv.push(std::ptr::null_mut());
        let stream = unsafe { original(mapped_argv.as_ptr(), options | FTS_NOCHDIR, compare) };
        if !stream.is_null() {
            mappings.sort_by_key(|mapping| std::cmp::Reverse(mapping.physical.len()));
            lock(fts_streams()).insert(
                stream as usize,
                FtsStreamState {
                    mappings,
                    presented: Vec::new(),
                },
            );
        }
        stream
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fts_open(
    paths: *const *mut libc::c_char,
    options: libc::c_int,
    compare: Option<FtsCompareFn>,
) -> *mut libc::c_void {
    unsafe { sandbox_fts_open(paths, options, compare) }
}

fn repair_virtual_fts_entry(
    runtime: &FilesystemHookRuntime,
    entry: *mut DarwinFtsEntry,
) -> Result<bool> {
    let info = unsafe { (*entry).fts_info };
    if info == FTS_NSOK || (info != FTS_NS && unsafe { (*entry).fts_statp.is_null() }) {
        return Ok(false);
    }
    let path = unsafe { (*entry).fts_accpath };
    if path.is_null() {
        return Ok(false);
    }
    let logical = unsafe { trusted_fts_logical_path(runtime, path) }?;
    let logical = CString::new(logical.as_os_str().as_bytes())
        .context("logical FTS metadata path contains NUL")?;
    let (mapped, plaintext_size, attributes) = runtime.map_metadata(
        logical.as_ptr(),
        libc::AT_FDCWD,
        false,
        &Credentials::effective(),
    )?;
    if info != FTS_NS {
        unsafe {
            patch_stat(
                &mut *(*entry).fts_statp,
                plaintext_size,
                attributes.as_ref(),
            )
        };
        return Ok(false);
    }
    let original = original_lstat().context("lstat is unavailable")?;
    let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
    if unsafe { original(mapped.as_ptr(), &mut status) } != 0 {
        return Err(io::Error::last_os_error().into());
    }
    unsafe { patch_stat(&mut status, plaintext_size, attributes.as_ref()) };
    let name = unsafe { CStr::from_ptr((*entry).fts_name.as_ptr()) }.to_bytes();
    let repaired = match status.st_mode & libc::S_IFMT {
        libc::S_IFDIR if matches!(name, b"." | b"..") => FTS_DOT,
        libc::S_IFDIR => FTS_D,
        libc::S_IFREG => FTS_F,
        libc::S_IFLNK => FTS_SL,
        _ => FTS_DEFAULT,
    };
    unsafe {
        if !(*entry).fts_statp.is_null() {
            *(*entry).fts_statp = status;
        }
        (*entry).fts_errno = 0;
        (*entry).fts_info = repaired;
    }
    Ok(true)
}

unsafe fn skip_fts_directory(stream: *mut libc::c_void, entry: *mut DarwinFtsEntry) -> libc::c_int {
    if unsafe { (*entry).fts_info } == FTS_D {
        unsafe { darwin_fts_set(stream, entry, FTS_SKIP) }
    } else {
        0
    }
}

unsafe fn sandbox_fts_children(
    stream: *mut libc::c_void,
    options: libc::c_int,
) -> *mut DarwinFtsEntry {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_fts_children() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        let Some(guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(stream, options) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(stream, options) };
        };
        restore_fts_stream(stream);
        drop(guard);
        unsafe { set_errno(0) };
        let mut head = {
            let _bulk = FtsVirtualBulk::enter();
            unsafe { original(stream, options) }
        };
        let original_errno = unsafe { *libc::__error() };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            unsafe { set_errno(original_errno) };
            return head;
        };
        if fts_stream_may_change_current_directory(stream) {
            let _ = runtime.synchronize_current_directory();
        }
        let mut current = head;
        let mut previous: *mut DarwinFtsEntry = std::ptr::null_mut();
        let mut unresolved_error = false;
        while !current.is_null() {
            let next = unsafe { (*current).fts_link };
            let visible = fts_entry_is_visible(runtime, current);
            if visible {
                if let Err(error) = repair_virtual_fts_entry(runtime, current) {
                    return unsafe { fail(&error, std::ptr::null_mut()) };
                }
                unresolved_error |=
                    matches!(unsafe { (*current).fts_info }, FTS_DNR | FTS_ERR | FTS_NS);
                previous = current;
            } else {
                if unsafe { skip_fts_directory(stream, current) } != 0 {
                    return std::ptr::null_mut();
                }
                if previous.is_null() {
                    head = next;
                } else {
                    unsafe { (*previous).fts_link = next };
                }
            }
            current = next;
        }
        let successful = !head.is_null() && !unresolved_error;
        if successful {
            let parent = unsafe { (*head).fts_parent };
            if !parent.is_null() {
                unsafe { (*parent).fts_errno = 0 };
            }
        }
        unsafe { set_errno(if successful { 0 } else { original_errno }) };
        if let Err(error) = present_fts_list(stream, head) {
            return unsafe { fail(&error, std::ptr::null_mut()) };
        }
        head
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fts_children(
    stream: *mut libc::c_void,
    options: libc::c_int,
) -> *mut DarwinFtsEntry {
    unsafe { sandbox_fts_children(stream, options) }
}

unsafe fn sandbox_fts_close(stream: *mut libc::c_void) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_fts_close() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let may_change_current_directory = fts_stream_may_change_current_directory(stream);
        restore_fts_stream(stream);
        let Some(guard) = FilesystemHookGuard::enter() else {
            let result = unsafe { original(stream) };
            lock(fts_streams()).remove(&(stream as usize));
            return result;
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            let result = unsafe { original(stream) };
            lock(fts_streams()).remove(&(stream as usize));
            return result;
        };
        drop(guard);
        let result = unsafe { original(stream) };
        let original_errno = unsafe { *libc::__error() };
        lock(fts_streams()).remove(&(stream as usize));
        let Some(_guard) = FilesystemHookGuard::enter() else {
            unsafe { set_errno(original_errno) };
            return result;
        };
        if may_change_current_directory {
            let _ = runtime.synchronize_current_directory();
        }
        unsafe { set_errno(original_errno) };
        result
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fts_close(stream: *mut libc::c_void) -> libc::c_int {
    unsafe { sandbox_fts_close(stream) }
}

unsafe fn sandbox_fts_read(stream: *mut libc::c_void) -> *mut DarwinFtsEntry {
    catch_filesystem_panic(std::ptr::null_mut(), || {
        let Some(original) = original_fts_read() else {
            unsafe { set_errno(libc::ENOSYS) };
            return std::ptr::null_mut();
        };
        let Some(guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(stream) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(stream) };
        };
        restore_fts_stream(stream);
        drop(guard);
        loop {
            unsafe { set_errno(0) };
            let entry = {
                let _bulk = FtsVirtualBulk::enter();
                unsafe { original(stream) }
            };
            let original_errno = unsafe { *libc::__error() };
            let Some(_guard) = FilesystemHookGuard::enter() else {
                unsafe { set_errno(original_errno) };
                return entry;
            };
            if fts_stream_may_change_current_directory(stream) {
                let _ = runtime.synchronize_current_directory();
            }
            if entry.is_null() {
                unsafe { set_errno(original_errno) };
                return entry;
            }
            let visible = fts_entry_is_visible(runtime, entry);
            if visible {
                let repaired = match repair_virtual_fts_entry(runtime, entry) {
                    Ok(repaired) => repaired,
                    Err(error) => return unsafe { fail(&error, std::ptr::null_mut()) },
                };
                let unresolved_error =
                    matches!(unsafe { (*entry).fts_info }, FTS_DNR | FTS_ERR | FTS_NS);
                if !unresolved_error {
                    unsafe { (*entry).fts_errno = 0 };
                }
                unsafe {
                    set_errno(if repaired || !unresolved_error {
                        0
                    } else {
                        original_errno
                    })
                };
                if let Err(error) = present_fts_entry(stream, entry) {
                    return unsafe { fail(&error, std::ptr::null_mut()) };
                }
                return entry;
            }
            if unsafe { skip_fts_directory(stream, entry) } != 0 {
                return std::ptr::null_mut();
            }
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fts_read(stream: *mut libc::c_void) -> *mut DarwinFtsEntry {
    unsafe { sandbox_fts_read(stream) }
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

fn original_utimes() -> Option<UtimesFn> {
    function_from_interpose(&INTERPOSE_UTIMES)
}

fn original_lutimes() -> Option<UtimesFn> {
    function_from_interpose(&INTERPOSE_LUTIMES)
}

fn original_futimes() -> Option<FutimesFn> {
    function_from_interpose(&INTERPOSE_FUTIMES)
}

fn original_futimens() -> Option<FutimensFn> {
    function_from_interpose(&INTERPOSE_FUTIMENS)
}

fn original_utimensat() -> Option<UtimensAtFn> {
    function_from_interpose(&INTERPOSE_UTIMENSAT)
}

fn original_chflags() -> Option<ChflagsFn> {
    function_from_interpose(&INTERPOSE_CHFLAGS)
}

fn original_fchflags() -> Option<FchflagsFn> {
    function_from_interpose(&INTERPOSE_FCHFLAGS)
}

fn original_setxattr() -> Option<SetxattrFn> {
    function_from_interpose(&INTERPOSE_SETXATTR)
}

fn original_fsetxattr() -> Option<FsetxattrFn> {
    function_from_interpose(&INTERPOSE_FSETXATTR)
}

fn original_removexattr() -> Option<RemovexattrFn> {
    function_from_interpose(&INTERPOSE_REMOVEXATTR)
}

fn original_fremovexattr() -> Option<FremovexattrFn> {
    function_from_interpose(&INTERPOSE_FREMOVEXATTR)
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

fn original_freopen() -> Option<FreopenFn> {
    function_from_interpose(&INTERPOSE_FREOPEN)
}

fn original_close() -> Option<CloseFn> {
    function_from_interpose(&INTERPOSE_CLOSE)
}

fn original_fclose() -> Option<FcloseFn> {
    function_from_interpose(&INTERPOSE_FCLOSE)
}

fn original_fsync() -> Option<DescriptorFn> {
    function_from_interpose(&INTERPOSE_FSYNC)
}

fn original_dup() -> Option<DescriptorFn> {
    function_from_interpose(&INTERPOSE_DUP)
}

fn original_dup2() -> Option<Dup2Fn> {
    function_from_interpose(&INTERPOSE_DUP2)
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

fn original_fstat() -> Option<FstatFn> {
    function_from_interpose(&INTERPOSE_FSTAT)
}

fn original_access() -> Option<AccessFn> {
    function_from_interpose(&INTERPOSE_ACCESS)
}

fn original_faccessat() -> Option<FaccessAtFn> {
    function_from_interpose(&INTERPOSE_FACCESSAT)
}

fn original_readlink() -> Option<ReadlinkFn> {
    function_from_interpose(&INTERPOSE_READLINK)
}

fn original_readlinkat() -> Option<ReadlinkAtFn> {
    function_from_interpose(&INTERPOSE_READLINKAT)
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

fn original_renamex_np() -> Option<RenameXFn> {
    function_from_interpose(&INTERPOSE_RENAMEX_NP)
}

fn original_renameatx_np() -> Option<RenameAtXFn> {
    function_from_interpose(&INTERPOSE_RENAMEATX_NP)
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

fn original_chdir() -> Option<ChdirFn> {
    function_from_interpose(&INTERPOSE_CHDIR)
}

fn original_fchdir() -> Option<DescriptorFn> {
    function_from_interpose(&INTERPOSE_FCHDIR)
}

fn original_getcwd() -> Option<GetcwdFn> {
    function_from_interpose(&INTERPOSE_GETCWD)
}

fn original_realpath() -> Option<RealpathFn> {
    function_from_interpose(&INTERPOSE_REALPATH)
}

fn original_opendir() -> Option<OpendirFn> {
    function_from_interpose(&INTERPOSE_OPENDIR)
}

fn original_fdopendir() -> Option<FdopendirFn> {
    function_from_interpose(&INTERPOSE_FDOPENDIR)
}

fn original_readdir() -> Option<ReaddirFn> {
    function_from_interpose(&INTERPOSE_READDIR)
}

fn original_fts_open() -> Option<FtsOpenFn> {
    function_from_interpose(&INTERPOSE_FTS_OPEN)
}

fn original_fts_children() -> Option<FtsChildrenFn> {
    function_from_interpose(&INTERPOSE_FTS_CHILDREN)
}

fn original_fts_close() -> Option<FtsCloseFn> {
    function_from_interpose(&INTERPOSE_FTS_CLOSE)
}

fn original_fts_read() -> Option<FtsReadFn> {
    function_from_interpose(&INTERPOSE_FTS_READ)
}

fn original_getattrlistbulk() -> Option<GetattrlistbulkFn> {
    function_from_interpose(&INTERPOSE_GETATTRLISTBULK)
}

fn original_rewinddir() -> Option<RewinddirFn> {
    function_from_interpose(&INTERPOSE_REWINDDIR)
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

    fn agora_sandbox_fcntl_shim(descriptor: libc::c_int, command: libc::c_int, ...) -> libc::c_int;

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
dyld_interpose!(INTERPOSE_UTIMES, agora_sandbox_utimes, libc::utimes);
dyld_interpose!(INTERPOSE_LUTIMES, agora_sandbox_lutimes, libc::lutimes);
dyld_interpose!(INTERPOSE_FUTIMES, agora_sandbox_futimes, libc::futimes);
dyld_interpose!(INTERPOSE_FUTIMENS, agora_sandbox_futimens, libc::futimens);
dyld_interpose!(
    INTERPOSE_UTIMENSAT,
    agora_sandbox_utimensat,
    libc::utimensat
);
dyld_interpose!(INTERPOSE_CHFLAGS, agora_sandbox_chflags, libc::chflags);
dyld_interpose!(INTERPOSE_FCHFLAGS, agora_sandbox_fchflags, libc::fchflags);
dyld_interpose!(INTERPOSE_SETXATTR, agora_sandbox_setxattr, libc::setxattr);
dyld_interpose!(
    INTERPOSE_FSETXATTR,
    agora_sandbox_fsetxattr,
    libc::fsetxattr
);
dyld_interpose!(
    INTERPOSE_REMOVEXATTR,
    agora_sandbox_removexattr,
    libc::removexattr
);
dyld_interpose!(
    INTERPOSE_FREMOVEXATTR,
    agora_sandbox_fremovexattr,
    libc::fremovexattr
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
dyld_interpose!(INTERPOSE_FREOPEN, agora_sandbox_freopen, libc::freopen);
dyld_interpose!(
    INTERPOSE_POSIX_SPAWN_FILE_ACTIONS_ADDOPEN,
    agora_sandbox_posix_spawn_file_actions_addopen,
    libc::posix_spawn_file_actions_addopen
);
dyld_interpose!(INTERPOSE_CLOSE, agora_sandbox_close, libc::close);
dyld_interpose!(INTERPOSE_FCLOSE, agora_sandbox_fclose, libc::fclose);
dyld_interpose!(INTERPOSE_FSYNC, agora_sandbox_fsync, libc::fsync);
dyld_interpose!(INTERPOSE_DUP, agora_sandbox_dup, libc::dup);
dyld_interpose!(INTERPOSE_DUP2, agora_sandbox_dup2, libc::dup2);
dyld_interpose!(INTERPOSE_FCNTL, agora_sandbox_fcntl_shim, libc::fcntl);
dyld_interpose!(INTERPOSE_STAT, agora_sandbox_stat, libc::stat);
dyld_interpose!(INTERPOSE_LSTAT, agora_sandbox_lstat, libc::lstat);
dyld_interpose!(INTERPOSE_FSTATAT, agora_sandbox_fstatat, libc::fstatat);
dyld_interpose!(INTERPOSE_FSTAT, agora_sandbox_fstat, libc::fstat);
dyld_interpose!(INTERPOSE_ACCESS, agora_sandbox_access, libc::access);
dyld_interpose!(
    INTERPOSE_FACCESSAT,
    agora_sandbox_faccessat,
    libc::faccessat
);
dyld_interpose!(INTERPOSE_READLINK, agora_sandbox_readlink, libc::readlink);
dyld_interpose!(
    INTERPOSE_READLINKAT,
    agora_sandbox_readlinkat,
    libc::readlinkat
);
dyld_interpose!(INTERPOSE_UNLINK, agora_sandbox_unlink, libc::unlink);
dyld_interpose!(INTERPOSE_UNLINKAT, agora_sandbox_unlinkat, libc::unlinkat);
dyld_interpose!(INTERPOSE_RMDIR, agora_sandbox_rmdir, libc::rmdir);
dyld_interpose!(INTERPOSE_RENAME, agora_sandbox_rename, libc::rename);
dyld_interpose!(INTERPOSE_RENAMEAT, agora_sandbox_renameat, libc::renameat);
dyld_interpose!(
    INTERPOSE_RENAMEX_NP,
    agora_sandbox_renamex_np,
    libc::renamex_np
);
dyld_interpose!(
    INTERPOSE_RENAMEATX_NP,
    agora_sandbox_renameatx_np,
    libc::renameatx_np
);
dyld_interpose!(INTERPOSE_MKDIR, agora_sandbox_mkdir, libc::mkdir);
dyld_interpose!(INTERPOSE_MKDIRAT, agora_sandbox_mkdirat, libc::mkdirat);
dyld_interpose!(INTERPOSE_CHDIR, agora_sandbox_chdir, libc::chdir);
dyld_interpose!(INTERPOSE_FCHDIR, agora_sandbox_fchdir, libc::fchdir);
dyld_interpose!(INTERPOSE_GETCWD, agora_sandbox_getcwd, libc::getcwd);
dyld_interpose!(INTERPOSE_REALPATH, agora_sandbox_realpath, libc::realpath);
dyld_interpose!(INTERPOSE_OPENDIR, agora_sandbox_opendir, libc::opendir);
dyld_interpose!(
    INTERPOSE_FDOPENDIR,
    agora_sandbox_fdopendir,
    libc::fdopendir
);
dyld_interpose!(INTERPOSE_READDIR, agora_sandbox_readdir, libc::readdir);
dyld_interpose!(
    INTERPOSE_READDIR_R,
    agora_sandbox_readdir_r,
    darwin_readdir_r
);
dyld_interpose!(INTERPOSE_FTS_OPEN, agora_sandbox_fts_open, darwin_fts_open);
dyld_interpose!(
    INTERPOSE_FTS_CHILDREN,
    agora_sandbox_fts_children,
    darwin_fts_children
);
dyld_interpose!(
    INTERPOSE_FTS_CLOSE,
    agora_sandbox_fts_close,
    darwin_fts_close
);
dyld_interpose!(INTERPOSE_FTS_READ, agora_sandbox_fts_read, darwin_fts_read);
dyld_interpose!(
    INTERPOSE_GETATTRLISTBULK,
    agora_sandbox_getattrlistbulk,
    darwin_getattrlistbulk
);
dyld_interpose!(
    INTERPOSE_REWINDDIR,
    agora_sandbox_rewinddir,
    libc::rewinddir
);
dyld_interpose!(INTERPOSE_CLOSEDIR, agora_sandbox_closedir, libc::closedir);

#[cfg(test)]
mod tests;
