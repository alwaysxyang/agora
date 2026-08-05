#![cfg(target_os = "macos")]

use super::config;
use super::dyld::{dyld_interpose, function_from_interpose};
use super::socket::set_errno;
use crate::audit::{AuditClient, AuditError, AuditEventRequest, FileOperation};
use crate::callback::{FileAccessMode, FileContext, FileOpenMode, ProcessContext};
use crate::filesystem::{
    AccessPlan, AccessRequest, Credentials, DirectoryView, FileAttributes, FileLayer, MetadataPlan,
    OpenIntent, OpenTarget, PreparedFile, StagedWrite, VirtualFilesystem, Writeback,
};
use crate::trace::TraceContext;
use anyhow::{Context, Result, bail};
use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, IntoRawFd};
use std::os::unix::ffi::OsStrExt;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Component, Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, Once, OnceLock};

const NATIVE_PASSTHROUGH_ROOTS: &[&str] = &["/dev"];

thread_local! {
    static INSIDE_FILESYSTEM_HOOK: Cell<bool> = const { Cell::new(false) };
    static INITIALIZING_FILESYSTEM_RUNTIME: Cell<bool> = const { Cell::new(false) };
    #[cfg(test)]
    static TEST_FILESYSTEM_RUNTIME: Cell<*const FilesystemHookRuntime> = const { Cell::new(std::ptr::null()) };
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
    intent: OpenIntent,
    prepared: PreparedFile,
    file: FileContext,
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

    fn into_prepared(self) -> PreparedOpen {
        PreparedOpen {
            prepared: self.prepared,
            file: self.file,
            logical: self.logical,
        }
    }
}

fn intent_from_fopen_mode(mode: &[u8]) -> Result<OpenIntent> {
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
    OpenIntent::new(flags, 0o666)
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
        let plan: MetadataPlan =
            self.filesystem
                .prepare_authorized_metadata(&logical, follow_final, credentials)?;
        let (resolved, mapped, plaintext_size, attributes) = plan.into_parts();
        self.logical_or_host(&resolved)?;
        let mapped = CString::new(mapped.as_os_str().as_bytes())
            .context("mapped filesystem path contains NUL")?;
        let plaintext_size = plaintext_size
            .map(libc::off_t::try_from)
            .transpose()
            .context("plaintext filesystem file is too large")?;
        Ok((mapped, plaintext_size, attributes))
    }

    unsafe fn prepare_access(
        &self,
        path: *const libc::c_char,
        directory: libc::c_int,
        follow_final: bool,
        request: AccessRequest,
        credentials: &Credentials,
    ) -> Result<AccessPlan> {
        let logical = unsafe { self.logical_path(path, directory) }?;
        if let Some(native) = self.native_passthrough_path(&logical)? {
            return Ok(AccessPlan::Native(native));
        }
        self.filesystem
            .check_access(&logical, follow_final, request, credentials)
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
        self.filesystem
            .chmod_authorized(&requested, mode.into(), follow_final, &credentials)
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
        self.prepare_open_request(requested, OpenIntent::new(flags, mode.into())?)
    }

    fn prepare_open_request(&self, requested: PathBuf, intent: OpenIntent) -> Result<OpenRequest> {
        let flags = intent.flags();
        let allowlisted = self.native_passthrough_path(&requested)?;
        let allowlisted_passthrough = allowlisted.is_some();
        let (logical, prepared) = match allowlisted {
            Some(path) => {
                let prepared = self.filesystem.prepare_native_open(&path);
                (path, prepared)
            }
            None => {
                self.publish_open_writers(&requested)?;
                let credentials = Credentials::effective();
                let mut plan_path = requested.clone();
                let mut synchronized = None;
                loop {
                    let plan = self.filesystem.prepare_authorized_open(
                        &plan_path,
                        intent,
                        &credentials,
                    )?;
                    let logical = self.logical_or_host(plan.logical())?;
                    if logical != plan.logical() {
                        drop(plan);
                        self.publish_open_writers(&logical)?;
                        plan_path = logical;
                        continue;
                    }
                    if logical != requested
                        && synchronized.as_deref() != Some(logical.as_path())
                        && self.has_open_writer(&logical)
                    {
                        drop(plan);
                        self.publish_open_writers(&logical)?;
                        synchronized = Some(logical);
                        continue;
                    }
                    let (logical, prepared) = plan.into_parts();
                    break (logical, prepared);
                }
            }
        };
        let access = intent.access();
        Ok(OpenRequest {
            logical,
            intent,
            prepared,
            file: FileContext {
                path: requested.to_string_lossy().into_owned(),
                mode: FileOpenMode {
                    access: match (access.read, access.write) {
                        (true, true) => FileAccessMode::ReadWrite,
                        (false, true) => FileAccessMode::Write,
                        _ => FileAccessMode::Read,
                    },
                    create: flags & libc::O_CREAT != 0,
                    truncate: flags & libc::O_TRUNC != 0,
                    append: flags & libc::O_APPEND != 0,
                    exclusive: flags & libc::O_EXCL != 0,
                },
            },
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
        let requested = unsafe { self.logical_path(path, libc::AT_FDCWD) }?;
        self.prepare_open_request(requested, intent_from_fopen_mode(mode)?)
    }

    fn commit_open(&self, prepared: &mut PreparedOpen) -> Result<()> {
        self.filesystem.commit_open(&mut prepared.prepared)
    }

    fn has_open_writer(&self, logical: &Path) -> bool {
        lock(&self.open_files)
            .values()
            .any(|open| open.writeback.is_some() && open.logical() == logical)
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
            .create_directory_authorized(&logical, u32::from(mode), &Credentials::effective())
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
        self.filesystem
            .create_symlink_authorized(&link, &target, &Credentials::effective())
            .map(|_| ())
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
            .remove_authorized(&logical, remove_directory, &Credentials::effective())
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
            .rename_authorized(&from, &to, &credentials)?;
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
        let (mapped, logical) = self
            .filesystem
            .prepare_change_directory(&requested, &credentials)?;
        self.logical_or_host(&logical)?;
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
        let canonical = self
            .filesystem
            .canonicalize_authorized(&logical, &Credentials::effective())?;
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
        self.filesystem
            .directory_view_authorized(&logical, &credentials)
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

mod descriptor;
mod directory;
mod metadata;
mod namespace;
mod open;
mod unsupported;

#[cfg(not(test))]
use namespace::{
    original_mkdir, original_rename, original_rmdir, original_symlink, original_unlink,
};

#[cfg(test)]
pub(super) use descriptor::*;
#[cfg(test)]
pub(super) use directory::*;
#[cfg(test)]
pub(super) use metadata::*;
#[cfg(test)]
pub(super) use namespace::*;
#[cfg(test)]
pub(super) use open::*;
#[cfg(test)]
pub(super) use unsupported::*;

#[cfg(test)]
mod tests;
