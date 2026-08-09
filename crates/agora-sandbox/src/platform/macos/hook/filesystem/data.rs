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
        let result = unsafe { original(descriptor, buffer, length) };
        if result > 0
            && let Some(runtime) = FilesystemHookRuntime::global()
            && let Some((start, end)) = sequential_write_range(descriptor, before, result)
        {
            runtime.record_local_write(descriptor, start, end);
        }
        result
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
        let result = unsafe { original(descriptor, buffer, length, offset) };
        if result > 0
            && offset >= 0
            && let Some(runtime) = FilesystemHookRuntime::global()
            && let Some(end) = (offset as u64).checked_add(result as u64)
        {
            runtime.record_local_write(descriptor, offset as u64, end);
        }
        result
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
        let result = unsafe { original(descriptor, vectors, count) };
        if result > 0
            && let Some(runtime) = FilesystemHookRuntime::global()
            && let Some((start, end)) = sequential_write_range(descriptor, before, result)
        {
            runtime.record_local_write(descriptor, start, end);
        }
        result
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
        let result = unsafe { original(descriptor, vectors, count, offset) };
        if result > 0
            && offset >= 0
            && let Some(runtime) = FilesystemHookRuntime::global()
            && let Some(end) = (offset as u64).checked_add(result as u64)
        {
            runtime.record_local_write(descriptor, offset as u64, end);
        }
        result
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

dyld_interpose!(INTERPOSE_WRITE, agora_sandbox_write, libc::write);
dyld_interpose!(INTERPOSE_PWRITE, agora_sandbox_pwrite, libc::pwrite);
dyld_interpose!(INTERPOSE_WRITEV, agora_sandbox_writev, libc::writev);
dyld_interpose!(INTERPOSE_PWRITEV, agora_sandbox_pwritev, libc::pwritev);

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
