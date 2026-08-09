use super::*;

type ForkFn = unsafe extern "C" fn() -> libc::pid_t;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fork() -> libc::pid_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_fork() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let retained = {
            let Some(_guard) = FilesystemHookGuard::enter() else {
                return unsafe { original() };
            };
            match FilesystemHookRuntime::global() {
                Some(runtime) => match runtime.retain_local_files_before_fork() {
                    Ok(handles) => handles,
                    Err(error) => return unsafe { fail(&error, -1) },
                },
                None => Vec::new(),
            }
        };
        let result = unsafe { original() };
        if result < 0 && !retained.is_empty() {
            let errno = unsafe { *libc::__error() };
            if let Some(_guard) = FilesystemHookGuard::enter()
                && let Some(runtime) = FilesystemHookRuntime::global()
            {
                let _ = runtime.release_local_files_after_failed_fork(retained);
            }
            unsafe { set_errno(errno) };
        }
        result
    })
}

fn original_fork() -> Option<ForkFn> {
    function_from_interpose(&INTERPOSE_FORK)
}

dyld_interpose!(INTERPOSE_FORK, agora_sandbox_fork, libc::fork);
