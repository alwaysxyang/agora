mod fts;

#[cfg(test)]
pub(super) use fts::{FtsStreamState, fts_stream_may_change_current_directory, fts_streams};

use super::*;

type FchdirFn = unsafe extern "C" fn(libc::c_int) -> libc::c_int;
type ChdirFn = unsafe extern "C" fn(*const libc::c_char) -> libc::c_int;
type GetcwdFn = unsafe extern "C" fn(*mut libc::c_char, libc::size_t) -> *mut libc::c_char;
type RealpathFn = unsafe extern "C" fn(*const libc::c_char, *mut libc::c_char) -> *mut libc::c_char;
type OpendirFn = unsafe extern "C" fn(*const libc::c_char) -> *mut libc::DIR;
type FdopendirFn = unsafe extern "C" fn(libc::c_int) -> *mut libc::DIR;
type ReaddirFn = unsafe extern "C" fn(*mut libc::DIR) -> *mut libc::dirent;
type RewinddirFn = unsafe extern "C" fn(*mut libc::DIR);
type ClosedirFn = unsafe extern "C" fn(*mut libc::DIR) -> libc::c_int;

unsafe extern "C" {
    #[link_name = "readdir_r"]
    fn darwin_readdir_r(
        directory: *mut libc::DIR,
        entry: *mut libc::dirent,
        result: *mut *mut libc::dirent,
    ) -> libc::c_int;
}

pub(super) struct DirectoryCursor {
    auxiliary: Option<usize>,
    primary_layer: FileLayer,
    reading_lower: bool,
    hidden: HashSet<Vec<u8>>,
    aliases: HashMap<Vec<u8>, Vec<u8>>,
    seen: HashSet<Vec<u8>>,
}

impl DirectoryCursor {
    pub(super) fn new(
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

    pub(super) fn include(&mut self, name: &[u8], lower: bool) -> Option<Vec<u8>> {
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
        if let Err(error) = runtime.filesystem.require_descriptor_access(
            &logical,
            AccessRequest::EXECUTE,
            &Credentials::effective(),
        ) {
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

fn original_chdir() -> Option<ChdirFn> {
    function_from_interpose(&INTERPOSE_CHDIR)
}

fn original_fchdir() -> Option<FchdirFn> {
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

fn original_rewinddir() -> Option<RewinddirFn> {
    function_from_interpose(&INTERPOSE_REWINDDIR)
}

fn original_closedir() -> Option<ClosedirFn> {
    function_from_interpose(&INTERPOSE_CLOSEDIR)
}

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

dyld_interpose!(
    INTERPOSE_REWINDDIR,
    agora_sandbox_rewinddir,
    libc::rewinddir
);

dyld_interpose!(INTERPOSE_CLOSEDIR, agora_sandbox_closedir, libc::closedir);
