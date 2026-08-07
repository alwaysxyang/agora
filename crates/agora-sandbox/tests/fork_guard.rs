#![cfg(target_os = "macos")]

use std::ffi::{CStr, CString, c_void};
use std::sync::atomic::{AtomicBool, AtomicPtr, AtomicUsize, Ordering};

type MprotectFn = unsafe extern "C" fn(*mut c_void, usize, libc::c_int) -> libc::c_int;

static PROBE_ACTIVE: AtomicBool = AtomicBool::new(false);
static HOOK_MPROTECT: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static MAPPING: AtomicPtr<c_void> = AtomicPtr::new(std::ptr::null_mut());
static MAPPING_LENGTH: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" fn call_hook_before_sandbox_child_reset() {
    if !PROBE_ACTIVE.load(Ordering::Relaxed) {
        return;
    }
    unsafe {
        libc::alarm(2);
    }
    let function = HOOK_MPROTECT.load(Ordering::Relaxed);
    if function.is_null() {
        unsafe { libc::_exit(2) };
    }
    let function: MprotectFn = unsafe { std::mem::transmute(function) };
    let result = unsafe {
        function(
            MAPPING.load(Ordering::Relaxed),
            MAPPING_LENGTH.load(Ordering::Relaxed),
            libc::PROT_READ,
        )
    };
    if result != 0 {
        unsafe { libc::_exit(3) };
    }
    unsafe {
        libc::alarm(0);
    }
}

#[test]
fn filesystem_hooks_bypass_the_fork_callback_window() {
    let hook = CString::new(env!("AGORA_SANDBOX_EMBEDDED_HOOK_PATH")).unwrap();
    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;
    let mapping = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            page_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANON,
            -1,
            0,
        )
    };
    assert_ne!(mapping, libc::MAP_FAILED);
    MAPPING.store(mapping, Ordering::Relaxed);
    MAPPING_LENGTH.store(page_size, Ordering::Relaxed);

    assert_eq!(
        unsafe { libc::pthread_atfork(None, None, Some(call_hook_before_sandbox_child_reset)) },
        0
    );
    let handle = unsafe { libc::dlopen(hook.as_ptr(), libc::RTLD_LOCAL | libc::RTLD_NOW) };
    assert!(
        !handle.is_null(),
        "failed to load embedded hook: {}",
        dlerror_message()
    );
    let mprotect = unsafe { libc::dlsym(handle, c"agora_sandbox_mprotect".as_ptr()) };
    assert!(
        !mprotect.is_null(),
        "failed to resolve mprotect hook: {}",
        dlerror_message()
    );
    HOOK_MPROTECT.store(mprotect, Ordering::Relaxed);
    PROBE_ACTIVE.store(true, Ordering::Release);

    let child = unsafe { libc::fork() };
    PROBE_ACTIVE.store(false, Ordering::Release);
    assert!(
        child >= 0,
        "fork failed: {}",
        std::io::Error::last_os_error()
    );
    if child == 0 {
        unsafe { libc::_exit(0) };
    }

    let mut status = 0;
    assert_eq!(
        unsafe { libc::waitpid(child, &mut status, 0) },
        child,
        "waitpid failed: {}",
        std::io::Error::last_os_error()
    );
    assert!(
        libc::WIFEXITED(status),
        "forked child deadlocked while an earlier atfork callback entered the filesystem hook"
    );
    assert_eq!(libc::WEXITSTATUS(status), 0);

    assert_eq!(unsafe { libc::munmap(mapping, page_size) }, 0);
}

fn dlerror_message() -> String {
    let error = unsafe { libc::dlerror() };
    if error.is_null() {
        "unknown dynamic loader error".to_owned()
    } else {
        unsafe { CStr::from_ptr(error) }
            .to_string_lossy()
            .into_owned()
    }
}
