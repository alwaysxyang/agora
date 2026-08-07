use super::*;

type ForkFn = unsafe extern "C" fn() -> libc::pid_t;

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_fork() -> libc::pid_t {
    catch_filesystem_panic(-1, || {
        let Some(original) = original_fork() else {
            unsafe { set_errno(libc::ENOSYS) };
            return -1;
        };
        let result = unsafe { original() };
        if result != 0 {
            return result;
        }
        let Some(_guard) = FilesystemHookGuard::enter() else {
            return result;
        };
        let Some(runtime) = FilesystemHookRuntime::global() else {
            return result;
        };
        let _ = runtime.retain_local_files_after_fork();
        result
    })
}

fn original_fork() -> Option<ForkFn> {
    function_from_interpose(&INTERPOSE_FORK)
}

dyld_interpose!(INTERPOSE_FORK, agora_sandbox_fork, libc::fork);
