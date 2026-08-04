use std::ffi::CStr;
use std::io;

use tokio::process::Command;

const KEYCHAIN_PROFILE: &CStr = c"(version 1)(allow default)(deny mach-lookup (global-name \"com.apple.SecurityServer\"))(deny mach-lookup (global-name \"com.apple.securityd\"))(deny mach-lookup (global-name \"com.apple.securityd.xpc\"))(deny mach-lookup (global-name \"com.apple.securityd.general\"))(deny mach-lookup (global-name \"com.apple.securityd.systemkeychain\"))";

#[link(name = "sandbox")]
unsafe extern "C" {
    fn sandbox_init(
        profile: *const libc::c_char,
        flags: u64,
        error_buffer: *mut *mut libc::c_char,
    ) -> libc::c_int;
    fn sandbox_free_error(error_buffer: *mut libc::c_char);
}

pub(super) fn configure(command: &mut Command) {
    unsafe {
        command.pre_exec(install);
    }
}

fn install() -> io::Result<()> {
    let mut error_buffer = std::ptr::null_mut();
    let result = unsafe { sandbox_init(KEYCHAIN_PROFILE.as_ptr(), 0, &mut error_buffer) };
    if !error_buffer.is_null() {
        unsafe { sandbox_free_error(error_buffer) };
    }
    if result == 0 {
        Ok(())
    } else {
        Err(io::Error::from_raw_os_error(libc::EPERM))
    }
}
