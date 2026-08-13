use super::super::abi::{darwin_mach_task_self, darwin_mach_vm_read_overwrite};
use super::*;
use crate::nfs::protocol::MAX_REMOTE_IO_BYTES;

const LOCAL_READ_AHEAD_MIN_BYTES: u64 = 16 * 1024;
const LOCAL_READ_AHEAD_MAX_BYTES: u64 = 256 * 1024;
const LOCAL_READ_AHEAD_MULTIPLIER: u64 = 4;
const MAX_VECTOR_COUNT: usize = 1024;

#[derive(Clone, Copy)]
enum LocalReadOffset {
    Sequential,
    Positioned(libc::off_t),
}

#[derive(Clone, Copy)]
enum RemoteIoOffset {
    Sequential,
    Positioned(libc::off_t),
}

unsafe fn remote_read_io(
    descriptor: libc::c_int,
    requested_offset: RemoteIoOffset,
    requested_length: impl FnOnce() -> std::result::Result<usize, libc::c_int>,
    operation: impl FnOnce(libc::c_int, usize) -> libc::ssize_t,
    snapshot_operation: impl FnOnce() -> libc::ssize_t,
) -> Option<libc::ssize_t> {
    let runtime = FilesystemHookRuntime::global()?;
    let open = runtime.tracked_open(descriptor)?;
    let registration = open.remote.as_ref()?;
    let _mutation = lock(&registration.mutation);
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Some(-1);
    }
    if flags & libc::O_ACCMODE == libc::O_WRONLY {
        unsafe { set_errno(libc::EBADF) };
        return Some(-1);
    }
    if registration.snapshot.load(Ordering::Acquire) {
        return Some(snapshot_operation());
    }
    let offset = match requested_offset {
        RemoteIoOffset::Sequential => match current_offset(descriptor) {
            Some(offset) => offset,
            None => {
                unsafe { set_errno(libc::EIO) };
                return Some(-1);
            }
        },
        RemoteIoOffset::Positioned(offset) => match u64::try_from(offset) {
            Ok(offset) => offset,
            Err(_) => {
                unsafe { set_errno(libc::EINVAL) };
                return Some(-1);
            }
        },
    };
    let length = match requested_length() {
        Ok(length) => length.min(MAX_REMOTE_IO_BYTES as usize),
        Err(errno) => {
            unsafe { set_errno(errno) };
            return Some(-1);
        }
    };
    if length == 0 {
        return Some(0);
    }
    let remote = match runtime.remote.as_ref() {
        Some(remote) => remote,
        None => {
            unsafe { set_errno(libc::EIO) };
            return Some(-1);
        }
    };
    let (payload, available) = match remote.read(
        &registration.handle,
        offset,
        u32::try_from(length).expect("remote read is protocol bounded"),
    ) {
        Ok(read) => read,
        Err(error) => return Some(unsafe { fail(&error, -1) }),
    };
    let result = operation(payload.as_raw_fd(), available as usize);
    if result > 0
        && matches!(requested_offset, RemoteIoOffset::Sequential)
        && !unsafe { set_current_offset_after_io(descriptor, offset, result as u64) }
    {
        return Some(-1);
    }
    Some(result)
}

unsafe fn remote_write_io(
    descriptor: libc::c_int,
    requested_offset: RemoteIoOffset,
    requested_length: impl FnOnce() -> std::result::Result<usize, libc::c_int>,
    copy: impl FnOnce(libc::c_int, usize) -> libc::ssize_t,
    snapshot_operation: impl FnOnce() -> libc::ssize_t,
) -> Option<libc::ssize_t> {
    let runtime = FilesystemHookRuntime::global()?;
    let open = runtime.tracked_open(descriptor)?;
    let registration = open.remote.as_ref()?;
    let _mutation = lock(&registration.mutation);
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFL) };
    if flags < 0 {
        return Some(-1);
    }
    if flags & libc::O_ACCMODE == libc::O_RDONLY || !registration.writable {
        unsafe { set_errno(libc::EBADF) };
        return Some(-1);
    }
    if registration.snapshot.load(Ordering::Acquire) {
        let result = snapshot_operation();
        if result > 0 && flags & (libc::O_SYNC | libc::O_DSYNC) != 0 {
            let remote = match runtime.remote.as_ref() {
                Some(remote) => remote,
                None => {
                    unsafe { set_errno(libc::EIO) };
                    return Some(-1);
                }
            };
            match remote.sync(&registration.handle) {
                Ok(Some(metadata)) => *lock(&registration.metadata) = metadata,
                Ok(None) => {}
                Err(error) => return Some(unsafe { fail(&error, -1) }),
            }
        }
        return Some(result);
    }
    let length = match requested_length() {
        Ok(length) => length.min(MAX_REMOTE_IO_BYTES as usize),
        Err(errno) => {
            unsafe { set_errno(errno) };
            return Some(-1);
        }
    };
    if length == 0 {
        return Some(0);
    }
    let payload = match tempfile::tempfile() {
        Ok(payload) => payload,
        Err(error) => {
            unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
            return Some(-1);
        }
    };
    let copied = copy(payload.as_raw_fd(), length);
    if copied <= 0 {
        return Some(copied);
    }
    let copied = u32::try_from(copied).expect("remote write is protocol bounded");
    if let Err(error) = payload.set_len(u64::from(copied)) {
        unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
        return Some(-1);
    }
    let offset = match requested_offset {
        RemoteIoOffset::Sequential if flags & libc::O_APPEND != 0 => None,
        RemoteIoOffset::Sequential => match current_offset(descriptor) {
            Some(offset) => Some(offset),
            None => {
                unsafe { set_errno(libc::EIO) };
                return Some(-1);
            }
        },
        RemoteIoOffset::Positioned(offset) => match u64::try_from(offset) {
            Ok(offset) => Some(offset),
            Err(_) => {
                unsafe { set_errno(libc::EINVAL) };
                return Some(-1);
            }
        },
    };
    let remote = match runtime.remote.as_ref() {
        Some(remote) => remote,
        None => {
            unsafe { set_errno(libc::EIO) };
            return Some(-1);
        }
    };
    let (actual_offset, written, mut size) =
        match remote.write(&registration.handle, offset, &payload, copied) {
            Ok(result) => result,
            Err(error) => return Some(unsafe { fail(&error, -1) }),
        };
    if written > copied {
        unsafe { set_errno(libc::EIO) };
        return Some(-1);
    }
    if flags & (libc::O_SYNC | libc::O_DSYNC) != 0 {
        match remote.sync(&registration.handle) {
            Ok(Some(metadata)) => size = metadata.size,
            Ok(None) => {}
            Err(error) => return Some(unsafe { fail(&error, -1) }),
        }
    }
    let Ok(local_size) = libc::off_t::try_from(size) else {
        unsafe { set_errno(libc::EFBIG) };
        return Some(-1);
    };
    if unsafe { libc::ftruncate(descriptor, local_size) } != 0 {
        return Some(-1);
    }
    lock(&registration.metadata).size = size;
    if matches!(requested_offset, RemoteIoOffset::Sequential)
        && !unsafe { set_current_offset_after_io(descriptor, actual_offset, u64::from(written)) }
    {
        return Some(-1);
    }
    Some(written as libc::ssize_t)
}

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
type SendfileFn = unsafe extern "C" fn(
    libc::c_int,
    libc::c_int,
    libc::off_t,
    *mut libc::off_t,
    *mut libc::sf_hdtr,
    libc::c_int,
) -> libc::c_int;
type FcopyfileFn = unsafe extern "C" fn(
    libc::c_int,
    libc::c_int,
    libc::copyfile_state_t,
    libc::copyfile_flags_t,
) -> libc::c_int;
type AioFn = unsafe extern "C" fn(*mut libc::aiocb) -> libc::c_int;
type LioListioFn = unsafe extern "C" fn(
    libc::c_int,
    *const *mut libc::aiocb,
    libc::c_int,
    *mut libc::sigevent,
) -> libc::c_int;
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
        if let Some(result) = unsafe {
            remote_read_io(
                descriptor,
                RemoteIoOffset::Sequential,
                || Ok(length),
                |payload, available| {
                    positioned
                        .map(|pread| pread(payload, buffer, available, 0))
                        .unwrap_or_else(|| {
                            set_errno(libc::ENOSYS);
                            -1
                        })
                },
                || original(descriptor, buffer, length),
            )
        } {
            return result;
        }
        match unsafe {
            local_read_io(
                descriptor,
                LocalReadOffset::Sequential,
                || Ok(length),
                |offset| {
                    positioned
                        .map(|pread| pread(descriptor, buffer, length, offset))
                        .unwrap_or_else(|| {
                            set_errno(libc::ENOSYS);
                            -1
                        })
                },
            )
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
        if let Some(result) = unsafe {
            remote_read_io(
                descriptor,
                RemoteIoOffset::Positioned(offset),
                || Ok(length),
                |payload, available| original(payload, buffer, available, 0),
                || original(descriptor, buffer, length, offset),
            )
        } {
            return result;
        }
        if let Some(result) = unsafe {
            local_read_io(
                descriptor,
                LocalReadOffset::Positioned(offset),
                || Ok(length),
                |offset| original(descriptor, buffer, length, offset),
            )
        } {
            return result;
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
        if let Some(result) = unsafe {
            remote_read_io(
                descriptor,
                RemoteIoOffset::Sequential,
                || vector_read_length(vectors, count),
                |payload, _available| {
                    positioned
                        .map(|preadv| preadv(payload, vectors, count, 0))
                        .unwrap_or_else(|| {
                            set_errno(libc::ENOSYS);
                            -1
                        })
                },
                || original(descriptor, vectors, count),
            )
        } {
            return result;
        }
        match unsafe {
            local_read_io(
                descriptor,
                LocalReadOffset::Sequential,
                || vector_read_length(vectors, count),
                |offset| {
                    positioned
                        .map(|preadv| preadv(descriptor, vectors, count, offset))
                        .unwrap_or_else(|| {
                            set_errno(libc::ENOSYS);
                            -1
                        })
                },
            )
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
        if let Some(result) = unsafe {
            remote_read_io(
                descriptor,
                RemoteIoOffset::Positioned(offset),
                || vector_read_length(vectors, count),
                |payload, _available| original(payload, vectors, count, 0),
                || original(descriptor, vectors, count, offset),
            )
        } {
            return result;
        }
        if let Some(result) = unsafe {
            local_read_io(
                descriptor,
                LocalReadOffset::Positioned(offset),
                || vector_read_length(vectors, count),
                |offset| original(descriptor, vectors, count, offset),
            )
        } {
            return result;
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
            remote_write_io(
                descriptor,
                RemoteIoOffset::Sequential,
                || Ok(length),
                |payload, bounded| {
                    positioned
                        .map(|pwrite| pwrite(payload, buffer, bounded, 0))
                        .unwrap_or_else(|| {
                            set_errno(libc::ENOSYS);
                            -1
                        })
                },
                || original(descriptor, buffer, length),
            )
        } {
            return result;
        }
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
        if let Some(result) = unsafe {
            remote_write_io(
                descriptor,
                RemoteIoOffset::Positioned(offset),
                || Ok(length),
                |payload, bounded| original(payload, buffer, bounded, 0),
                || original(descriptor, buffer, length, offset),
            )
        } {
            return result;
        }
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
            remote_write_io(
                descriptor,
                RemoteIoOffset::Sequential,
                || vector_read_length(vectors, count),
                |payload, bounded| {
                    let copied = match bounded_process_vectors(vectors, count, bounded) {
                        Ok(copied) => copied,
                        Err(errno) => {
                            set_errno(errno);
                            return -1;
                        }
                    };
                    positioned
                        .map(|pwritev| {
                            pwritev(payload, copied.as_ptr(), copied.len() as libc::c_int, 0)
                        })
                        .unwrap_or_else(|| {
                            set_errno(libc::ENOSYS);
                            -1
                        })
                },
                || original(descriptor, vectors, count),
            )
        } {
            return result;
        }
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
        if let Some(result) = unsafe {
            remote_write_io(
                descriptor,
                RemoteIoOffset::Positioned(offset),
                || vector_read_length(vectors, count),
                |payload, bounded| {
                    let copied = match bounded_process_vectors(vectors, count, bounded) {
                        Ok(copied) => copied,
                        Err(errno) => {
                            set_errno(errno);
                            return -1;
                        }
                    };
                    original(payload, copied.as_ptr(), copied.len() as libc::c_int, 0)
                },
                || original(descriptor, vectors, count, offset),
            )
        } {
            return result;
        }
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
        if let Some(runtime) = FilesystemHookRuntime::global()
            && let Err(error) = materialize_remote_descriptor(runtime, descriptor)
        {
            return unsafe { fail(&error, -1) };
        }
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
        if let Some(runtime) = FilesystemHookRuntime::global()
            && let Err(error) = materialize_remote_descriptor(runtime, descriptor)
        {
            return unsafe { fail(&error, -1) };
        }
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
        if let Some(runtime) = FilesystemHookRuntime::global()
            && let Err(error) = materialize_remote_descriptor(runtime, descriptor)
        {
            return unsafe { fail(&error, -1) };
        }
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

unsafe fn local_read_io(
    descriptor: libc::c_int,
    requested_offset: LocalReadOffset,
    requested_length: impl FnOnce() -> std::result::Result<usize, libc::c_int>,
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
    if access == libc::O_WRONLY {
        unsafe { set_errno(libc::EBADF) };
        return Some(-1);
    }
    let offset = match requested_offset {
        LocalReadOffset::Sequential => match state.offset() {
            Ok(offset) if offset >= 0 => offset,
            Ok(_) => {
                unsafe { set_errno(libc::EINVAL) };
                return Some(-1);
            }
            Err(error) => {
                unsafe { set_errno(error.raw_os_error().unwrap_or(libc::EIO)) };
                return Some(-1);
            }
        },
        LocalReadOffset::Positioned(offset) if offset >= 0 => offset,
        LocalReadOffset::Positioned(_) => {
            unsafe { set_errno(libc::EINVAL) };
            return Some(-1);
        }
    };
    if registration.lazy {
        let length = match requested_length() {
            Ok(length) => length,
            Err(errno) => {
                unsafe { set_errno(errno) };
                return Some(-1);
            }
        };
        if length != 0 {
            let start = offset as u64;
            let requested = u64::try_from(length).unwrap_or(u64::MAX);
            let end = start.saturating_add(local_read_materialization_length(requested));
            let range = LocalByteRange::new(start, end).expect("non-empty read range");
            if let Err(error) = runtime.materialize_local(registration, Some(range)) {
                unsafe { set_errno(error_errno(&error)) };
                return Some(-1);
            }
        }
    }
    let result = operation(offset);
    if result > 0 && matches!(requested_offset, LocalReadOffset::Sequential) {
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

fn local_read_materialization_length(requested: u64) -> u64 {
    requested.max(
        requested
            .saturating_mul(LOCAL_READ_AHEAD_MULTIPLIER)
            .clamp(LOCAL_READ_AHEAD_MIN_BYTES, LOCAL_READ_AHEAD_MAX_BYTES),
    )
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
        if let Some(registration) = &open.remote {
            if matches!(whence, libc::SEEK_DATA | libc::SEEK_HOLE) {
                let _mutation = lock(&registration.mutation);
                if let Err(error) = runtime.materialize_remote_locked(registration) {
                    return unsafe { fail(&error, -1) };
                }
            }
            return unsafe { original(descriptor, offset, whence) };
        }
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
                if let Err(error) = runtime.materialize_local(registration, None) {
                    unsafe { set_errno(error_errno(&error)) };
                    return -1;
                }
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

unsafe fn vector_read_length(
    vectors: *const libc::iovec,
    count: libc::c_int,
) -> std::result::Result<usize, libc::c_int> {
    let count = usize::try_from(count).map_err(|_| libc::EINVAL)?;
    if count > MAX_VECTOR_COUNT {
        return Err(libc::EINVAL);
    }
    if count == 0 {
        return Ok(0);
    }
    let copied_vectors = unsafe { copy_process_slice(vectors, count) }?;
    copied_vectors
        .into_iter()
        .try_fold(0_usize, |total, vector| {
            total
                .checked_add(vector.iov_len)
                .filter(|total| *total <= libc::ssize_t::MAX as usize)
                .ok_or(libc::EINVAL)
        })
}

unsafe fn bounded_process_vectors(
    vectors: *const libc::iovec,
    count: libc::c_int,
    maximum: usize,
) -> std::result::Result<Vec<libc::iovec>, libc::c_int> {
    let count = usize::try_from(count).map_err(|_| libc::EINVAL)?;
    if count > MAX_VECTOR_COUNT {
        return Err(libc::EINVAL);
    }
    let mut vectors = unsafe { copy_process_slice(vectors, count) }?;
    let mut remaining = maximum;
    let mut retained = 0;
    for vector in &mut vectors {
        if remaining == 0 {
            break;
        }
        vector.iov_len = vector.iov_len.min(remaining);
        remaining -= vector.iov_len;
        retained += 1;
    }
    vectors.truncate(retained);
    Ok(vectors)
}

unsafe fn copy_process_value<T>(pointer: *const T) -> std::result::Result<T, libc::c_int> {
    let bytes = unsafe { copy_process_bytes(pointer.cast(), std::mem::size_of::<T>()) }?;
    Ok(unsafe { std::ptr::read_unaligned(bytes.as_ptr().cast::<T>()) })
}

unsafe fn copy_process_slice<T>(
    pointer: *const T,
    count: usize,
) -> std::result::Result<Vec<T>, libc::c_int> {
    if count == 0 {
        return Ok(Vec::new());
    }
    let item_size = std::mem::size_of::<T>();
    let size = count.checked_mul(item_size).ok_or(libc::EINVAL)?;
    let bytes = unsafe { copy_process_bytes(pointer.cast(), size) }?;
    Ok((0..count)
        .map(|index| unsafe {
            std::ptr::read_unaligned(bytes.as_ptr().add(index * item_size).cast())
        })
        .collect())
}

unsafe fn copy_process_bytes(
    pointer: *const libc::c_void,
    size: usize,
) -> std::result::Result<Vec<u8>, libc::c_int> {
    if pointer.is_null() {
        return Err(libc::EFAULT);
    }
    let mut bytes = vec![0_u8; size];
    let mut copied = 0_u64;
    let status = unsafe {
        darwin_mach_vm_read_overwrite(
            darwin_mach_task_self,
            pointer as u64,
            size as u64,
            bytes.as_mut_ptr() as u64,
            &mut copied,
        )
    };
    if status != 0 || copied != size as u64 {
        return Err(libc::EFAULT);
    }
    Ok(bytes)
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_lseek(
    descriptor: libc::c_int,
    offset: libc::off_t,
    whence: libc::c_int,
) -> libc::off_t {
    unsafe { sandbox_lseek(descriptor, offset, whence) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_sendfile(
    descriptor: libc::c_int,
    socket: libc::c_int,
    offset: libc::off_t,
    length: *mut libc::off_t,
    headers: *mut libc::sf_hdtr,
    flags: libc::c_int,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_sendfile() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(descriptor, socket, offset, length, headers, flags) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(descriptor, socket, offset, length, headers, flags) };
        };
        let Some(open) = runtime.tracked_open(descriptor) else {
            return unsafe { original(descriptor, socket, offset, length, headers, flags) };
        };
        if let Some(registration) = &open.remote {
            let _mutation = lock(&registration.mutation);
            if let Err(error) = runtime.materialize_remote_locked(registration) {
                return unsafe { fail(&error, -1) };
            }
            return unsafe { original(descriptor, socket, offset, length, headers, flags) };
        }
        let Some(registration) = &open.local else {
            return unsafe { original(descriptor, socket, offset, length, headers, flags) };
        };
        if offset < 0 {
            return unsafe { original(descriptor, socket, offset, length, headers, flags) };
        }
        let range = match unsafe { sendfile_materialization_range(offset, length, headers) } {
            Ok(range) => range,
            Err(errno) => {
                unsafe { set_errno(errno) };
                return -1;
            }
        };
        let _mutation = lock(&registration.mutation);
        if let Err(error) = runtime.materialize_local(registration, range) {
            return unsafe { fail(&error, -1) };
        }
        unsafe { original(descriptor, socket, offset, length, headers, flags) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fcopyfile(
    source: libc::c_int,
    destination: libc::c_int,
    state: libc::copyfile_state_t,
    flags: libc::copyfile_flags_t,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_fcopyfile() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(source, destination, state, flags) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(source, destination, state, flags) };
        };
        if let Err(error) = materialize_remote_descriptor(runtime, source)
            .and_then(|()| materialize_remote_descriptor(runtime, destination))
        {
            return unsafe { fail(&error, -1) };
        }
        if runtime
            .tracked_open(destination)
            .is_some_and(|open| open.local.is_some())
        {
            unsafe { set_errno(libc::ENOTSUP) };
            return -1;
        }
        if let Some(open) = runtime.tracked_open(source)
            && let Some(registration) = &open.local
        {
            let _mutation = lock(&registration.mutation);
            if let Err(error) = runtime.materialize_local(registration, None) {
                return unsafe { fail(&error, -1) };
            }
        }
        unsafe { original(source, destination, state, flags) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_aio_read(control: *mut libc::aiocb) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_aio_read() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(control) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(control) };
        };
        let copied = match unsafe { copy_process_value(control.cast_const()) } {
            Ok(copied) => copied,
            Err(errno) => {
                unsafe { set_errno(errno) };
                return -1;
            }
        };
        if let Some(range) = aio_read_range(&copied)
            && let Err(error) = materialize_descriptor(runtime, copied.aio_fildes, Some(range))
        {
            return unsafe { fail(&error, -1) };
        }
        unsafe { original(control) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_aio_write(control: *mut libc::aiocb) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_aio_write() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(control) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(control) };
        };
        let copied = match unsafe { copy_process_value(control.cast_const()) } {
            Ok(copied) => copied,
            Err(errno) => {
                unsafe { set_errno(errno) };
                return -1;
            }
        };
        if let Err(error) = materialize_remote_descriptor(runtime, copied.aio_fildes) {
            return unsafe { fail(&error, -1) };
        }
        unsafe { original(control) }
    })
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_lio_listio(
    mode: libc::c_int,
    controls: *const *mut libc::aiocb,
    count: libc::c_int,
    event: *mut libc::sigevent,
) -> libc::c_int {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_lio_listio() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return unsafe { original(mode, controls, count, event) };
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return unsafe { original(mode, controls, count, event) };
        };
        let copied = match usize::try_from(count) {
            Ok(count) if count <= MAX_VECTOR_COUNT => unsafe {
                copy_process_slice(controls, count)
            },
            _ => Err(libc::EINVAL),
        };
        let copied = match copied {
            Ok(copied) => copied,
            Err(errno) => {
                unsafe { set_errno(errno) };
                return -1;
            }
        };
        for control in copied.into_iter().filter(|control| !control.is_null()) {
            let control = match unsafe { copy_process_value(control.cast_const()) } {
                Ok(control) => control,
                Err(errno) => {
                    unsafe { set_errno(errno) };
                    return -1;
                }
            };
            let materialized = match control.aio_lio_opcode {
                libc::LIO_READ => aio_read_range(&control)
                    .map(|range| materialize_descriptor(runtime, control.aio_fildes, Some(range)))
                    .transpose(),
                libc::LIO_WRITE => {
                    Some(materialize_remote_descriptor(runtime, control.aio_fildes)).transpose()
                }
                _ => Ok(None),
            };
            if let Err(error) = materialized {
                return unsafe { fail(&error, -1) };
            }
        }
        unsafe { original(mode, controls, count, event) }
    })
}

fn materialize_descriptor(
    runtime: &FilesystemHookRuntime,
    descriptor: libc::c_int,
    range: Option<LocalByteRange>,
) -> Result<()> {
    let Some(open) = runtime.tracked_open(descriptor) else {
        return Ok(());
    };
    if let Some(registration) = &open.local {
        let _mutation = lock(&registration.mutation);
        runtime.materialize_local(registration, range)?;
    }
    if let Some(registration) = &open.remote {
        let _mutation = lock(&registration.mutation);
        runtime.materialize_remote_locked(registration)?;
    }
    Ok(())
}

fn materialize_remote_descriptor(
    runtime: &FilesystemHookRuntime,
    descriptor: libc::c_int,
) -> Result<()> {
    let Some(open) = runtime.tracked_open(descriptor) else {
        return Ok(());
    };
    let Some(registration) = &open.remote else {
        return Ok(());
    };
    let _mutation = lock(&registration.mutation);
    runtime.materialize_remote_locked(registration)
}

fn aio_read_range(control: &libc::aiocb) -> Option<LocalByteRange> {
    let start = u64::try_from(control.aio_offset).ok()?;
    let length = u64::try_from(control.aio_nbytes).unwrap_or(u64::MAX);
    LocalByteRange::new(start, start.saturating_add(length)).ok()
}

unsafe fn sendfile_materialization_range(
    offset: libc::off_t,
    length: *const libc::off_t,
    headers: *const libc::sf_hdtr,
) -> std::result::Result<Option<LocalByteRange>, libc::c_int> {
    if !headers.is_null() {
        let headers = unsafe { copy_process_value(headers) }?;
        if headers.hdr_cnt != 0 || headers.trl_cnt != 0 {
            return Ok(None);
        }
    }
    let requested = unsafe { copy_process_value(length) }?;
    let start = u64::try_from(offset).map_err(|_| libc::EINVAL)?;
    let end = if requested == 0 {
        u64::MAX
    } else {
        let requested = u64::try_from(requested).map_err(|_| libc::EINVAL)?;
        start.checked_add(requested).ok_or(libc::EOVERFLOW)?
    };
    LocalByteRange::new(start, end)
        .map(Some)
        .map_err(|_| libc::EINVAL)
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

unsafe fn set_current_offset_after_io(descriptor: libc::c_int, start: u64, length: u64) -> bool {
    let Some(next) = start.checked_add(length) else {
        unsafe { set_errno(libc::EOVERFLOW) };
        return false;
    };
    let Ok(next) = libc::off_t::try_from(next) else {
        unsafe { set_errno(libc::EOVERFLOW) };
        return false;
    };
    let Some(lseek) = original_lseek() else {
        unsafe { set_errno(libc::ENOSYS) };
        return false;
    };
    if unsafe { lseek(descriptor, next, libc::SEEK_SET) } < 0 {
        return false;
    }
    true
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

fn original_sendfile() -> Option<SendfileFn> {
    function_from_interpose(&INTERPOSE_SENDFILE)
}

fn original_fcopyfile() -> Option<FcopyfileFn> {
    function_from_interpose(&INTERPOSE_FCOPYFILE)
}

fn original_aio_read() -> Option<AioFn> {
    function_from_interpose(&INTERPOSE_AIO_READ)
}

fn original_aio_write() -> Option<AioFn> {
    function_from_interpose(&INTERPOSE_AIO_WRITE)
}

fn original_lio_listio() -> Option<LioListioFn> {
    function_from_interpose(&INTERPOSE_LIO_LISTIO)
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
dyld_interpose!(INTERPOSE_SENDFILE, agora_sandbox_sendfile, libc::sendfile);
dyld_interpose!(
    INTERPOSE_FCOPYFILE,
    agora_sandbox_fcopyfile,
    libc::fcopyfile
);
dyld_interpose!(INTERPOSE_AIO_READ, agora_sandbox_aio_read, libc::aio_read);
dyld_interpose!(
    INTERPOSE_AIO_WRITE,
    agora_sandbox_aio_write,
    libc::aio_write
);
dyld_interpose!(
    INTERPOSE_LIO_LISTIO,
    agora_sandbox_lio_listio,
    libc::lio_listio
);

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
