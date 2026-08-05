mod config;
mod dyld;
mod filesystem;
mod network;
mod process;

use std::sync::Once;
use std::sync::atomic::{AtomicBool, Ordering};

static HOOK_INITIALIZED: AtomicBool = AtomicBool::new(false);
static EXIT_FLUSH_REGISTERED: Once = Once::new();

fn initialized() -> bool {
    HOOK_INITIALIZED.load(Ordering::Acquire)
}

extern "C" fn flush_filesystem_at_exit() {
    filesystem::flush_at_exit();
}

extern "C" fn initialize_hook() {
    config::initialize();
    filesystem::initialize_process();
    EXIT_FLUSH_REGISTERED.call_once(|| unsafe {
        libc::atexit(flush_filesystem_at_exit);
    });
    HOOK_INITIALIZED.store(true, Ordering::Release);
}

#[used]
#[unsafe(link_section = "__DATA,__mod_init_func")]
static HOOK_INITIALIZER: extern "C" fn() = initialize_hook;

#[cfg(target_os = "macos")]
unsafe fn set_errno(value: libc::c_int) {
    unsafe { *libc::__error() = value };
}

#[cfg(test)]
mod tests;
