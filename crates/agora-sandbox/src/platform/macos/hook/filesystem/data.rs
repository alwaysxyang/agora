use super::*;

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

unsafe fn sandbox_write(
    descriptor: libc::c_int,
    buffer: *const libc::c_void,
    length: usize,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_write() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, buffer, length) };
        };
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
    unsafe { sandbox_write(descriptor, buffer, length) }
}

unsafe fn sandbox_pwrite(
    descriptor: libc::c_int,
    buffer: *const libc::c_void,
    length: usize,
    offset: libc::off_t,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_pwrite() else {
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
    unsafe { sandbox_pwrite(descriptor, buffer, length, offset) }
}

unsafe fn sandbox_writev(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_writev() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, vectors, count) };
        };
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
    unsafe { sandbox_writev(descriptor, vectors, count) }
}

unsafe fn sandbox_pwritev(
    descriptor: libc::c_int,
    vectors: *const libc::iovec,
    count: libc::c_int,
    offset: libc::off_t,
) -> libc::ssize_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_pwritev() else {
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
    unsafe { sandbox_pwritev(descriptor, vectors, count, offset) }
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
        return operation();
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
            runtime.record_local_write_locked(registration, range.start, range.end);
        }
    } else if let Some(reservation) = &reservation {
        let errno = unsafe { *libc::__error() };
        let _ = local.cancel_write(&registration.handle, reservation);
        unsafe { set_errno(errno) };
    }
    result
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

fn original_guarded_write() -> Option<GuardedWriteFn> {
    function_from_interpose(&INTERPOSE_GUARDED_WRITE)
}

fn original_guarded_pwrite() -> Option<GuardedPwriteFn> {
    function_from_interpose(&INTERPOSE_GUARDED_PWRITE)
}

fn original_guarded_writev() -> Option<GuardedWritevFn> {
    function_from_interpose(&INTERPOSE_GUARDED_WRITEV)
}

dyld_interpose!(INTERPOSE_WRITE, agora_sandbox_write, libc::write);
dyld_interpose!(INTERPOSE_PWRITE, agora_sandbox_pwrite, libc::pwrite);
dyld_interpose!(INTERPOSE_WRITEV, agora_sandbox_writev, libc::writev);
dyld_interpose!(INTERPOSE_PWRITEV, agora_sandbox_pwritev, libc::pwritev);

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

dyld_interpose!(
    INTERPOSE_WRITE_NOCANCEL,
    agora_sandbox_write,
    write_nocancel
);
dyld_interpose!(
    INTERPOSE_PWRITE_NOCANCEL,
    agora_sandbox_pwrite,
    pwrite_nocancel
);
dyld_interpose!(
    INTERPOSE_WRITEV_NOCANCEL,
    agora_sandbox_writev,
    writev_nocancel
);
dyld_interpose!(
    INTERPOSE_PWRITEV_NOCANCEL,
    agora_sandbox_pwritev,
    pwritev_nocancel
);

#[cfg(test)]
mod tests;
