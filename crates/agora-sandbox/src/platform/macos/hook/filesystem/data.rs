use super::*;

type ReadFn = unsafe extern "C" fn(libc::c_int, *mut libc::c_void, usize) -> libc::ssize_t;
type PreadFn =
    unsafe extern "C" fn(libc::c_int, *mut libc::c_void, usize, libc::off_t) -> libc::ssize_t;
type ReadvFn = unsafe extern "C" fn(libc::c_int, *const libc::iovec, libc::c_int) -> libc::ssize_t;
type PreadvFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::iovec,
    libc::c_int,
    libc::off_t,
) -> libc::ssize_t;
type WriteFn = unsafe extern "C" fn(libc::c_int, *const libc::c_void, usize) -> libc::ssize_t;
type PwriteFn =
    unsafe extern "C" fn(libc::c_int, *const libc::c_void, usize, libc::off_t) -> libc::ssize_t;
type WritevFn = unsafe extern "C" fn(libc::c_int, *const libc::iovec, libc::c_int) -> libc::ssize_t;
type PwritevFn = unsafe extern "C" fn(
    libc::c_int,
    *const libc::iovec,
    libc::c_int,
    libc::off_t,
) -> libc::ssize_t;
type LseekFn = unsafe extern "C" fn(libc::c_int, libc::off_t, libc::c_int) -> libc::off_t;
type GuardedWriteFn =
    unsafe extern "C" fn(libc::c_int, *const GuardId, *const libc::c_void, usize) -> libc::ssize_t;
type GuardedPwriteFn = unsafe extern "C" fn(
    libc::c_int,
    *const GuardId,
    *const libc::c_void,
    usize,
    libc::off_t,
) -> libc::ssize_t;
type GuardedWritevFn = unsafe extern "C" fn(
    libc::c_int,
    *const GuardId,
    *const libc::iovec,
    libc::c_int,
) -> libc::ssize_t;

unsafe fn sandbox_read_with(
    descriptor: libc::c_int,
    buffer: *mut libc::c_void,
    length: usize,
    original: Option<ReadFn>,
    positioned: Option<PreadFn>,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, buffer, length) };
        };
        match unsafe {
            local_sequential_io(descriptor, false, |offset| {
                positioned
                    .map(|pread| pread(descriptor, buffer, length, offset))
                    .unwrap_or_else(|| {
                        set_errno(libc::ENOSYS);
                        -1
                    })
            })
        } {
            Some(result) => result,
            None => unsafe { original(descriptor, buffer, length) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_read(
    descriptor: libc::c_int,
    buffer: *mut libc::c_void,
    length: usize,
) -> libc::ssize_t {
    unsafe {
        sandbox_read_with(
            descriptor,
            buffer,
            length,
            original_read(),
            original_pread(),
        )
    }
}

unsafe fn sandbox_pread_with(
    descriptor: libc::c_int,
    buffer: *mut libc::c_void,
    length: usize,
    offset: libc::off_t,
    original: Option<PreadFn>,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, buffer, length, offset) };
        };
        if !local_access_allowed(descriptor, false) {
            return -1;
        }
        unsafe { original(descriptor, buffer, length, offset) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_pread(
    descriptor: libc::c_int,
    buffer: *mut libc::c_void,
    length: usize,
    offset: libc::off_t,
) -> libc::ssize_t {
    unsafe { sandbox_pread_with(descriptor, buffer, length, offset, original_pread()) }
}

unsafe fn sandbox_readv_with(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
    original: Option<ReadvFn>,
    positioned: Option<PreadvFn>,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, vectors, count) };
        };
        match unsafe {
            local_sequential_io(descriptor, false, |offset| {
                positioned
                    .map(|preadv| preadv(descriptor, vectors, count, offset))
                    .unwrap_or_else(|| {
                        set_errno(libc::ENOSYS);
                        -1
                    })
            })
        } {
            Some(result) => result,
            None => unsafe { original(descriptor, vectors, count) },
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_readv(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
) -> libc::ssize_t {
    unsafe {
        sandbox_readv_with(
            descriptor,
            vectors,
            count,
            original_readv(),
            original_preadv(),
        )
    }
}

unsafe fn sandbox_preadv_with(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
    offset: libc::off_t,
    original: Option<PreadvFn>,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, vectors, count, offset) };
        };
        if !local_access_allowed(descriptor, false) {
            return -1;
        }
        unsafe { original(descriptor, vectors, count, offset) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_preadv(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
    offset: libc::off_t,
) -> libc::ssize_t {
    unsafe { sandbox_preadv_with(descriptor, vectors, count, offset, original_preadv()) }
}

unsafe fn sandbox_write_with(
    descriptor: libc::c_int,
    buffer: *const libc::c_void,
    length: usize,
    original: Option<WriteFn>,
    positioned: Option<PwriteFn>,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, buffer, length) };
        };
        if let Some(result) = unsafe {
            local_sequential_write(descriptor, Some(length), |offset| {
                positioned
                    .map(|pwrite| pwrite(descriptor, buffer, length, offset))
                    .unwrap_or_else(|| {
                        set_errno(libc::ENOSYS);
                        -1
                    })
            })
        } {
            return result;
        }
        let before = current_offset(descriptor);
        let reserved = sequential_write_reservation(length);
        unsafe {
            tracked_write(
                descriptor,
                reserved,
                || original(descriptor, buffer, length),
                |result| sequential_write_range(descriptor, before, result),
            )
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_write(
    descriptor: libc::c_int,
    buffer: *const libc::c_void,
    length: usize,
) -> libc::ssize_t {
    unsafe {
        sandbox_write_with(
            descriptor,
            buffer,
            length,
            original_write(),
            original_pwrite(),
        )
    }
}

unsafe fn sandbox_pwrite_with(
    descriptor: libc::c_int,
    buffer: *const libc::c_void,
    length: usize,
    offset: libc::off_t,
    original: Option<PwriteFn>,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, buffer, length, offset) };
        };
        let reserved = positional_write_reservation(offset, length);
        unsafe {
            tracked_write(
                descriptor,
                reserved,
                || original(descriptor, buffer, length, offset),
                |result| positional_write_range(offset, result),
            )
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_pwrite(
    descriptor: libc::c_int,
    buffer: *const libc::c_void,
    length: usize,
    offset: libc::off_t,
) -> libc::ssize_t {
    unsafe { sandbox_pwrite_with(descriptor, buffer, length, offset, original_pwrite()) }
}

unsafe fn sandbox_writev_with(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
    original: Option<WritevFn>,
    positioned: Option<PwritevFn>,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, vectors, count) };
        };
        if let Some(result) = unsafe {
            local_sequential_write(descriptor, (count == 0).then_some(0), |offset| {
                positioned
                    .map(|pwritev| pwritev(descriptor, vectors, count, offset))
                    .unwrap_or_else(|| {
                        set_errno(libc::ENOSYS);
                        -1
                    })
            })
        } {
            return result;
        }
        let before = current_offset(descriptor);
        let reserved = sequential_write_reservation(vector_write_length(count));
        unsafe {
            tracked_write(
                descriptor,
                reserved,
                || original(descriptor, vectors, count),
                |result| sequential_write_range(descriptor, before, result),
            )
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_writev(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
) -> libc::ssize_t {
    unsafe {
        sandbox_writev_with(
            descriptor,
            vectors,
            count,
            original_writev(),
            original_pwritev(),
        )
    }
}

unsafe fn sandbox_pwritev_with(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
    offset: libc::off_t,
    original: Option<PwritevFn>,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, vectors, count, offset) };
        };
        let reserved = positional_write_reservation(offset, vector_write_length(count));
        unsafe {
            tracked_write(
                descriptor,
                reserved,
                || original(descriptor, vectors, count, offset),
                |result| positional_write_range(offset, result),
            )
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_pwritev(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
    offset: libc::off_t,
) -> libc::ssize_t {
    unsafe { sandbox_pwritev_with(descriptor, vectors, count, offset, original_pwritev()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_guarded_write(
    descriptor: libc::c_int,
    guard: *const GuardId,
    buffer: *const libc::c_void,
    length: usize,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_guarded_write() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_hook_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, guard, buffer, length) };
        };
        if let Some(result) = unsafe {
            local_sequential_write(descriptor, Some(length), |offset| {
                original_guarded_pwrite()
                    .map(|pwrite| pwrite(descriptor, guard, buffer, length, offset))
                    .unwrap_or_else(|| {
                        set_errno(libc::ENOSYS);
                        -1
                    })
            })
        } {
            return result;
        }
        let before = current_offset(descriptor);
        let reserved = sequential_write_reservation(length);
        unsafe {
            tracked_write(
                descriptor,
                reserved,
                || original(descriptor, guard, buffer, length),
                |result| sequential_write_range(descriptor, before, result),
            )
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_guarded_pwrite(
    descriptor: libc::c_int,
    guard: *const GuardId,
    buffer: *const libc::c_void,
    length: usize,
    offset: libc::off_t,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_guarded_pwrite() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_hook_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, guard, buffer, length, offset) };
        };
        let reserved = positional_write_reservation(offset, length);
        unsafe {
            tracked_write(
                descriptor,
                reserved,
                || original(descriptor, guard, buffer, length, offset),
                |result| positional_write_range(offset, result),
            )
        }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_guarded_writev(
    descriptor: libc::c_int,
    guard: *const GuardId,
    vectors: *const libc::iovec,
    count: libc::c_int,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_guarded_writev() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_hook_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, guard, vectors, count) };
        };
        if count < 0 {
            unsafe { set_errno(libc::EINVAL) };
            return -1;
        }
        if let Some(result) = unsafe {
            local_sequential_write(descriptor, (count == 0).then_some(0), |offset| {
                guarded_writev_at(descriptor, guard, vectors, count, offset)
            })
        } {
            return result;
        }
        let before = current_offset(descriptor);
        let reserved = sequential_write_reservation(vector_write_length(count));
        unsafe {
            tracked_write(
                descriptor,
                reserved,
                || original(descriptor, guard, vectors, count),
                |result| sequential_write_range(descriptor, before, result),
            )
        }
    })
}

unsafe fn local_sequential_io(
    descriptor: libc::c_int,
    write: bool,
    operation: impl FnOnce(libc::off_t) -> libc::ssize_t,
) -> Option<libc::ssize_t> {
    let runtime = FilesystemHookRuntime::global()?;
    let open = runtime.tracked_open(descriptor)?;
    let registration = open.local.as_ref()?;
    let _mutation = lock(&registration.mutation);
    let state = match registration.state.lock() {
        Ok(state) => state,
        Err(error) => {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return Some(-1);
        }
    };
    let flags = match state.flags() {
        Ok(flags) => flags,
        Err(error) => {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return Some(-1);
        }
    };
    let access = flags & libc::O_ACCMODE;
    if (!write && access == libc::O_WRONLY) || (write && access == libc::O_RDONLY) {
        unsafe { set_errno(libc::EBADF) };
        return Some(-1);
    }
    let offset = match state.offset() {
        Ok(offset) if offset >= 0 => offset,
        Ok(_) => {
            unsafe { set_errno(libc::EINVAL) };
            return Some(-1);
        }
        Err(error) => {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return Some(-1);
        }
    };
    let result = operation(offset);
    if result > 0 {
        let Some(next) = offset.checked_add(result as libc::off_t) else {
            unsafe { set_errno(libc::EOVERFLOW) };
            return Some(-1);
        };
        if let Err(error) = state.set_offset(next) {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return Some(-1);
        }
    }
    Some(result)
}

unsafe fn local_sequential_write(
    descriptor: libc::c_int,
    length: Option<usize>,
    operation: impl FnOnce(libc::off_t) -> libc::ssize_t,
) -> Option<libc::ssize_t> {
    let runtime = FilesystemHookRuntime::global()?;
    let open = runtime.tracked_open(descriptor)?;
    let registration = open.local.as_ref()?;
    if !registration.writable {
        unsafe { set_errno(libc::EBADF) };
        return Some(-1);
    }
    let _mutation = lock(&registration.mutation);
    let state = match registration.state.lock() {
        Ok(state) => state,
        Err(error) => {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return Some(-1);
        }
    };
    let flags = match state.flags() {
        Ok(flags) => flags,
        Err(error) => {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return Some(-1);
        }
    };
    if flags & libc::O_ACCMODE == libc::O_RDONLY {
        unsafe { set_errno(libc::EBADF) };
        return Some(-1);
    }
    let local = match runtime.local.as_ref() {
        Some(local) => local,
        None => {
            unsafe { set_errno(libc::EIO) };
            return Some(-1);
        }
    };
    let zero_length = length == Some(0);
    let (active, offset) = if zero_length {
        let offset = match state.offset() {
            Ok(offset) if offset >= 0 => offset,
            Ok(_) => {
                unsafe { set_errno(libc::EINVAL) };
                return Some(-1);
            }
            Err(error) => {
                unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
                return Some(-1);
            }
        };
        (None, offset)
    } else if flags & libc::O_APPEND != 0 {
        match local.begin_append(&registration.handle) {
            Ok((active, offset)) => match libc::off_t::try_from(offset) {
                Ok(offset) => (Some(active), offset),
                Err(_) => {
                    let _ = local.cancel_write(&registration.handle, &active);
                    unsafe { set_errno(libc::EOVERFLOW) };
                    return Some(-1);
                }
            },
            Err(error) => {
                unsafe { set_errno(error.errno()) };
                return Some(-1);
            }
        }
    } else {
        let offset = match state.offset() {
            Ok(offset) if offset >= 0 => offset,
            Ok(_) => {
                unsafe { set_errno(libc::EINVAL) };
                return Some(-1);
            }
            Err(error) => {
                unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
                return Some(-1);
            }
        };
        let start = offset as u64;
        let range = match length {
            Some(length) => LocalByteRange::new(start, start.saturating_add(length as u64)).ok(),
            None => LocalByteRange::new(start, u64::MAX).ok(),
        };
        let active = match range {
            Some(range) => match local.begin_write(&registration.handle, range) {
                Ok(active) => Some(active),
                Err(error) => {
                    unsafe { set_errno(error.errno()) };
                    return Some(-1);
                }
            },
            None => None,
        };
        (active, offset)
    };
    let result = operation(offset);
    if result > 0 {
        let start = offset as u64;
        let end = start.saturating_add(result as u64);
        if let Ok(range) = LocalByteRange::new(start, end) {
            let finish_failed = active.as_ref().is_none_or(|write| {
                if local
                    .finish_write(&registration.handle, write, range)
                    .is_ok()
                {
                    false
                } else {
                    let _ = local.cancel_write(&registration.handle, write);
                    true
                }
            });
            if finish_failed {
                runtime.record_local_write_locked(registration, range.start, range.end);
            }
        }
        let Ok(end) = libc::off_t::try_from(end) else {
            unsafe { set_errno(libc::EOVERFLOW) };
            return Some(-1);
        };
        if let Err(error) = state.set_offset(end) {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return Some(-1);
        }
    } else if let Some(active) = &active {
        let errno = unsafe { *libc::__error() };
        let _ = local.cancel_write(&registration.handle, active);
        unsafe { set_errno(errno) };
    }
    Some(result)
}

fn local_access_allowed(descriptor: libc::c_int, write: bool) -> bool {
    let Some(runtime) = FilesystemHookRuntime::global() else {
        return true;
    };
    let Some(open) = runtime.tracked_open(descriptor) else {
        return true;
    };
    let Some(registration) = open.local.as_ref() else {
        return true;
    };
    let _mutation = lock(&registration.mutation);
    let state = match registration.state.lock() {
        Ok(state) => state,
        Err(error) => {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return false;
        }
    };
    let flags = match state.flags() {
        Ok(flags) => flags,
        Err(error) => {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return false;
        }
    };
    let access = flags & libc::O_ACCMODE;
    if (!write && access == libc::O_WRONLY) || (write && access == libc::O_RDONLY) {
        unsafe { set_errno(libc::EBADF) };
        false
    } else {
        true
    }
}

unsafe fn sandbox_lseek(
    descriptor: libc::c_int,
    offset: libc::off_t,
    whence: libc::c_int,
) -> libc::off_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_lseek() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, offset, whence) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(descriptor, offset, whence) };
        };
        let Some(open) = runtime.tracked_open(descriptor) else {
            return unsafe { original(descriptor, offset, whence) };
        };
        let Some(registration) = open.local.as_ref() else {
            return unsafe { original(descriptor, offset, whence) };
        };
        let _mutation = lock(&registration.mutation);
        let state = match registration.state.lock() {
            Ok(state) => state,
            Err(error) => {
                unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
                return -1;
            }
        };
        let next = match whence {
            libc::SEEK_SET => Ok(Some(offset)),
            libc::SEEK_CUR => match state.offset() {
                Ok(current) => Ok(current.checked_add(offset)),
                Err(error) => Err(error),
            },
            libc::SEEK_END => {
                let mut status = unsafe { std::mem::zeroed::<libc::stat>() };
                if unsafe { libc::fstat(descriptor, &mut status) } != 0 {
                    return -1;
                }
                Ok(status.st_size.checked_add(offset))
            }
            libc::SEEK_DATA | libc::SEEK_HOLE => {
                let next = unsafe { original(descriptor, offset, whence) };
                if next < 0 {
                    return -1;
                }
                Ok(Some(next))
            }
            _ => Ok(None),
        };
        let next = match next {
            Ok(next) => next,
            Err(error) => {
                unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
                return -1;
            }
        };
        let Some(next) = next else {
            unsafe {
                set_errno(
                    if matches!(whence, libc::SEEK_SET | libc::SEEK_CUR | libc::SEEK_END) {
                        libc::EOVERFLOW
                    } else {
                        libc::EINVAL
                    },
                )
            };
            return -1;
        };
        if next < 0 {
            unsafe { set_errno(libc::EINVAL) };
            return -1;
        }
        if let Err(error) = state.set_offset(next) {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return -1;
        }
        next
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_lseek(
    descriptor: libc::c_int,
    offset: libc::off_t,
    whence: libc::c_int,
) -> libc::off_t {
    unsafe { sandbox_lseek(descriptor, offset, whence) }
}

unsafe fn guarded_writev_at(
    descriptor: libc::c_int,
    guard: *const GuardId,
    vectors: *const libc::iovec,
    count: libc::c_int,
    offset: libc::off_t,
) -> libc::ssize_t {
    let Some(writev) = original_guarded_writev() else {
        unsafe { set_errno(libc::ENOSYS) };
        return -1;
    };
    if count == 0 {
        return unsafe { writev(descriptor, guard, vectors, count) };
    }
    let Some(lseek) = original_lseek() else {
        unsafe { set_errno(libc::ENOSYS) };
        return -1;
    };
    if unsafe { lseek(descriptor, offset, libc::SEEK_SET) } < 0 {
        return -1;
    }
    unsafe { writev(descriptor, guard, vectors, count) }
}

fn current_offset(descriptor: libc::c_int) -> Option<u64> {
    let offset = unsafe { libc::lseek(descriptor, 0, libc::SEEK_CUR) };
    u64::try_from(offset).ok()
}

fn sequential_write_range(
    descriptor: libc::c_int,
    before: Option<u64>,
    written: libc::ssize_t,
) -> Option<(u64, u64)> {
    let written = u64::try_from(written).ok()?;
    let after = current_offset(descriptor);
    let after_start = after.and_then(|after| after.checked_sub(written));
    let before_end = before.and_then(|before| before.checked_add(written));
    let start = match (before, after_start) {
        (Some(before), Some(after)) => before.min(after),
        (Some(before), None) => before,
        (None, Some(after)) => after,
        (None, None) => return None,
    };
    let end = match (before_end, after) {
        (Some(before), Some(after)) => before.max(after),
        (Some(before), None) => before,
        (None, Some(after)) => after,
        (None, None) => return None,
    };
    if start >= end {
        return None;
    }
    Some((start, end))
}

fn sequential_write_reservation(length: usize) -> Option<LocalByteRange> {
    if length == 0 {
        return None;
    }
    LocalByteRange::new(0, u64::MAX).ok()
}

fn positional_write_reservation(offset: libc::off_t, length: usize) -> Option<LocalByteRange> {
    if length == 0 {
        return None;
    }
    let start = u64::try_from(offset).ok()?;
    let end = start.saturating_add(length as u64);
    LocalByteRange::new(start, end).ok()
}

fn positional_write_range(offset: libc::off_t, written: libc::ssize_t) -> Option<(u64, u64)> {
    let start = u64::try_from(offset).ok()?;
    let end = start.checked_add(u64::try_from(written).ok()?)?;
    (start < end).then_some((start, end))
}

fn vector_write_length(count: libc::c_int) -> usize {
    if count > 0 { usize::MAX } else { 0 }
}

unsafe fn tracked_write(
    descriptor: libc::c_int,
    reserved: Option<LocalByteRange>,
    operation: impl FnOnce() -> libc::ssize_t,
    written_range: impl FnOnce(libc::ssize_t) -> Option<(u64, u64)>,
) -> libc::ssize_t {
    let Some(runtime) = FilesystemHookRuntime::global() else {
        return operation();
    };
    let Some(open) = runtime.tracked_open(descriptor) else {
        return operation();
    };
    let Some(registration) = &open.local else {
        return operation();
    };
    if !registration.writable {
        unsafe { set_errno(libc::EBADF) };
        return -1;
    }
    let _mutation = lock(&registration.mutation);
    let local = match runtime.local.as_ref() {
        Some(local) => local,
        None => {
            unsafe { set_errno(libc::EIO) };
            return -1;
        }
    };
    let reservation = match reserved {
        Some(range) => match local.begin_write(&registration.handle, range) {
            Ok(reservation) => Some(reservation),
            Err(error) => {
                unsafe { set_errno(error.errno()) };
                return -1;
            }
        },
        None => None,
    };
    let result = operation();
    if result > 0 {
        let completed = written_range(result)
            .and_then(|(start, end)| LocalByteRange::new(start, end).ok())
            .or(reserved);
        if let (Some(reservation), Some(range)) = (&reservation, completed)
            && local
                .finish_write(&registration.handle, reservation, range)
                .is_err()
        {
            let _ = local.cancel_write(&registration.handle, reservation);
            runtime.record_local_write_locked(registration, range.start, range.end);
        }
    } else if let Some(reservation) = &reservation {
        let errno = unsafe { *libc::__error() };
        let _ = local.cancel_write(&registration.handle, reservation);
        unsafe { set_errno(errno) };
    }
    result
}

fn original_read() -> Option<ReadFn> {
    function_from_interpose(&INTERPOSE_READ)
}

fn original_pread() -> Option<PreadFn> {
    function_from_interpose(&INTERPOSE_PREAD)
}

fn original_readv() -> Option<ReadvFn> {
    function_from_interpose(&INTERPOSE_READV)
}

fn original_preadv() -> Option<PreadvFn> {
    function_from_interpose(&INTERPOSE_PREADV)
}

fn original_write() -> Option<WriteFn> {
    function_from_interpose(&INTERPOSE_WRITE)
}

fn original_pwrite() -> Option<PwriteFn> {
    function_from_interpose(&INTERPOSE_PWRITE)
}

fn original_writev() -> Option<WritevFn> {
    function_from_interpose(&INTERPOSE_WRITEV)
}

fn original_pwritev() -> Option<PwritevFn> {
    function_from_interpose(&INTERPOSE_PWRITEV)
}

fn original_lseek() -> Option<LseekFn> {
    function_from_interpose(&INTERPOSE_LSEEK)
}

fn original_read_nocancel() -> Option<ReadFn> {
    function_from_interpose(&INTERPOSE_READ_NOCANCEL)
}

fn original_pread_nocancel() -> Option<PreadFn> {
    function_from_interpose(&INTERPOSE_PREAD_NOCANCEL)
}

fn original_readv_nocancel() -> Option<ReadvFn> {
    function_from_interpose(&INTERPOSE_READV_NOCANCEL)
}

fn original_preadv_nocancel() -> Option<PreadvFn> {
    function_from_interpose(&INTERPOSE_PREADV_NOCANCEL)
}

fn original_write_nocancel() -> Option<WriteFn> {
    function_from_interpose(&INTERPOSE_WRITE_NOCANCEL)
}

fn original_pwrite_nocancel() -> Option<PwriteFn> {
    function_from_interpose(&INTERPOSE_PWRITE_NOCANCEL)
}

fn original_writev_nocancel() -> Option<WritevFn> {
    function_from_interpose(&INTERPOSE_WRITEV_NOCANCEL)
}

fn original_pwritev_nocancel() -> Option<PwritevFn> {
    function_from_interpose(&INTERPOSE_PWRITEV_NOCANCEL)
}

fn original_guarded_write() -> Option<GuardedWriteFn> {
    function_from_interpose(&INTERPOSE_GUARDED_WRITE)
}

fn original_guarded_pwrite() -> Option<GuardedPwriteFn> {
    function_from_interpose(&INTERPOSE_GUARDED_PWRITE)
}

fn original_guarded_writev() -> Option<GuardedWritevFn> {
    function_from_interpose(&INTERPOSE_GUARDED_WRITEV)
}

dyld_interpose!(INTERPOSE_READ, agora_sandbox_read, libc::read);
dyld_interpose!(INTERPOSE_PREAD, agora_sandbox_pread, libc::pread);
dyld_interpose!(INTERPOSE_READV, agora_sandbox_readv, libc::readv);
dyld_interpose!(INTERPOSE_PREADV, agora_sandbox_preadv, libc::preadv);
dyld_interpose!(INTERPOSE_WRITE, agora_sandbox_write, libc::write);
dyld_interpose!(INTERPOSE_PWRITE, agora_sandbox_pwrite, libc::pwrite);
dyld_interpose!(INTERPOSE_WRITEV, agora_sandbox_writev, libc::writev);
dyld_interpose!(INTERPOSE_PWRITEV, agora_sandbox_pwritev, libc::pwritev);
dyld_interpose!(INTERPOSE_LSEEK, agora_sandbox_lseek, libc::lseek);

unsafe extern "C" {
    #[link_name = "guarded_write_np"]
    fn system_guarded_write_np(
        descriptor: libc::c_int,
        guard: *const GuardId,
        buffer: *const libc::c_void,
        length: usize,
    ) -> libc::ssize_t;

    #[link_name = "guarded_pwrite_np"]
    fn system_guarded_pwrite_np(
        descriptor: libc::c_int,
        guard: *const GuardId,
        buffer: *const libc::c_void,
        length: usize,
        offset: libc::off_t,
    ) -> libc::ssize_t;

    #[link_name = "guarded_writev_np"]
    fn system_guarded_writev_np(
        descriptor: libc::c_int,
        guard: *const GuardId,
        vectors: *const libc::iovec,
        count: libc::c_int,
    ) -> libc::ssize_t;
}

dyld_interpose!(
    INTERPOSE_GUARDED_WRITE,
    agora_sandbox_guarded_write,
    system_guarded_write_np
);

dyld_interpose!(
    INTERPOSE_GUARDED_PWRITE,
    agora_sandbox_guarded_pwrite,
    system_guarded_pwrite_np
);

dyld_interpose!(
    INTERPOSE_GUARDED_WRITEV,
    agora_sandbox_guarded_writev,
    system_guarded_writev_np
);

unsafe extern "C" {
    #[link_name = "read$NOCANCEL"]
    fn read_nocancel(
        descriptor: libc::c_int,
        buffer: *mut libc::c_void,
        length: usize,
    ) -> libc::ssize_t;
    #[link_name = "pread$NOCANCEL"]
    fn pread_nocancel(
        descriptor: libc::c_int,
        buffer: *mut libc::c_void,
        length: usize,
        offset: libc::off_t,
    ) -> libc::ssize_t;
    #[link_name = "readv$NOCANCEL"]
    fn readv_nocancel(
        descriptor: libc::c_int,
        vectors: *const libc::iovec,
        count: libc::c_int,
    ) -> libc::ssize_t;
    #[link_name = "preadv$NOCANCEL"]
    fn preadv_nocancel(
        descriptor: libc::c_int,
        vectors: *const libc::iovec,
        count: libc::c_int,
        offset: libc::off_t,
    ) -> libc::ssize_t;
    #[link_name = "write$NOCANCEL"]
    fn write_nocancel(
        descriptor: libc::c_int,
        buffer: *const libc::c_void,
        length: usize,
    ) -> libc::ssize_t;
    #[link_name = "pwrite$NOCANCEL"]
    fn pwrite_nocancel(
        descriptor: libc::c_int,
        buffer: *const libc::c_void,
        length: usize,
        offset: libc::off_t,
    ) -> libc::ssize_t;
    #[link_name = "writev$NOCANCEL"]
    fn writev_nocancel(
        descriptor: libc::c_int,
        vectors: *const libc::iovec,
        count: libc::c_int,
    ) -> libc::ssize_t;
    #[link_name = "pwritev$NOCANCEL"]
    fn pwritev_nocancel(
        descriptor: libc::c_int,
        vectors: *const libc::iovec,
        count: libc::c_int,
        offset: libc::off_t,
    ) -> libc::ssize_t;
}

unsafe extern "C" fn agora_sandbox_read_nocancel(
    descriptor: libc::c_int,
    buffer: *mut libc::c_void,
    length: usize,
) -> libc::ssize_t {
    unsafe {
        sandbox_read_with(
            descriptor,
            buffer,
            length,
            original_read_nocancel(),
            original_pread_nocancel(),
        )
    }
}

unsafe extern "C" fn agora_sandbox_pread_nocancel(
    descriptor: libc::c_int,
    buffer: *mut libc::c_void,
    length: usize,
    offset: libc::off_t,
) -> libc::ssize_t {
    unsafe {
        sandbox_pread_with(
            descriptor,
            buffer,
            length,
            offset,
            original_pread_nocancel(),
        )
    }
}

unsafe extern "C" fn agora_sandbox_readv_nocancel(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
) -> libc::ssize_t {
    unsafe {
        sandbox_readv_with(
            descriptor,
            vectors,
            count,
            original_readv_nocancel(),
            original_preadv_nocancel(),
        )
    }
}

unsafe extern "C" fn agora_sandbox_preadv_nocancel(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
    offset: libc::off_t,
) -> libc::ssize_t {
    unsafe {
        sandbox_preadv_with(
            descriptor,
            vectors,
            count,
            offset,
            original_preadv_nocancel(),
        )
    }
}

unsafe extern "C" fn agora_sandbox_write_nocancel(
    descriptor: libc::c_int,
    buffer: *const libc::c_void,
    length: usize,
) -> libc::ssize_t {
    unsafe {
        sandbox_write_with(
            descriptor,
            buffer,
            length,
            original_write_nocancel(),
            original_pwrite_nocancel(),
        )
    }
}

unsafe extern "C" fn agora_sandbox_pwrite_nocancel(
    descriptor: libc::c_int,
    buffer: *const libc::c_void,
    length: usize,
    offset: libc::off_t,
) -> libc::ssize_t {
    unsafe {
        sandbox_pwrite_with(
            descriptor,
            buffer,
            length,
            offset,
            original_pwrite_nocancel(),
        )
    }
}

unsafe extern "C" fn agora_sandbox_writev_nocancel(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
) -> libc::ssize_t {
    unsafe {
        sandbox_writev_with(
            descriptor,
            vectors,
            count,
            original_writev_nocancel(),
            original_pwritev_nocancel(),
        )
    }
}

unsafe extern "C" fn agora_sandbox_pwritev_nocancel(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
    offset: libc::off_t,
) -> libc::ssize_t {
    unsafe {
        sandbox_pwritev_with(
            descriptor,
            vectors,
            count,
            offset,
            original_pwritev_nocancel(),
        )
    }
}

dyld_interpose!(
    INTERPOSE_READ_NOCANCEL,
    agora_sandbox_read_nocancel,
    read_nocancel
);
dyld_interpose!(
    INTERPOSE_PREAD_NOCANCEL,
    agora_sandbox_pread_nocancel,
    pread_nocancel
);
dyld_interpose!(
    INTERPOSE_READV_NOCANCEL,
    agora_sandbox_readv_nocancel,
    readv_nocancel
);
dyld_interpose!(
    INTERPOSE_PREADV_NOCANCEL,
    agora_sandbox_preadv_nocancel,
    preadv_nocancel
);

dyld_interpose!(
    INTERPOSE_WRITE_NOCANCEL,
    agora_sandbox_write_nocancel,
    write_nocancel
);
dyld_interpose!(
    INTERPOSE_PWRITE_NOCANCEL,
    agora_sandbox_pwrite_nocancel,
    pwrite_nocancel
);
dyld_interpose!(
    INTERPOSE_WRITEV_NOCANCEL,
    agora_sandbox_writev_nocancel,
    writev_nocancel
);
dyld_interpose!(
    INTERPOSE_PWRITEV_NOCANCEL,
    agora_sandbox_pwritev_nocancel,
    pwritev_nocancel
);

#[cfg(test)]
mod tests;
