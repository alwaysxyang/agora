use super::descriptor::{original_close, original_fclose};
use super::*;

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
type PosixSpawnAddOpenFn = unsafe extern "C" fn(
    *mut libc::posix_spawn_file_actions_t,
    libc::c_int,
    *const libc::c_char,
    libc::c_int,
    libc::mode_t,
) -> libc::c_int;

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
                let mut prepared = request.into_prepared();
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
                let mut prepared = request.into_prepared();
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
                let flags = request.intent.flags();
                if let Err(error) = runtime.publish(FileOperation::Open, request.file.clone()) {
                    return unsafe { fail_audit(&error, std::ptr::null_mut()) };
                }
                let mut prepared = request.into_prepared();
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
            return libc::ENOTSUP;
        }
        let prepared = request.into_prepared();
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

fn original_freopen() -> Option<FreopenFn> {
    function_from_interpose(&INTERPOSE_FREOPEN)
}

fn original_posix_spawn_file_actions_addopen() -> Option<PosixSpawnAddOpenFn> {
    function_from_interpose(&INTERPOSE_POSIX_SPAWN_FILE_ACTIONS_ADDOPEN)
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

dyld_interpose!(INTERPOSE_FOPEN, agora_sandbox_fopen, libc::fopen);

dyld_interpose!(INTERPOSE_FREOPEN, agora_sandbox_freopen, libc::freopen);

dyld_interpose!(
    INTERPOSE_POSIX_SPAWN_FILE_ACTIONS_ADDOPEN,
    agora_sandbox_posix_spawn_file_actions_addopen,
    libc::posix_spawn_file_actions_addopen
);
