#![cfg(target_os = "macos")]

use super::config::{self, CHILD_RUNTIME_ENVIRONMENT, HookConfig};
use super::dyld::{dyld_interpose, function_from_interpose};
use super::socket::set_errno;
use crate::execution::{
    PrepareResponse, decode_prepare_response, encode_prepare_request, frame_length,
};
use std::cell::Cell;
use std::ffi::{CStr, CString, OsStr};
use std::io::{Read, Write};
use std::net::TcpStream;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::Duration;

type PosixSpawnFn = unsafe extern "C" fn(
    *mut libc::pid_t,
    *const libc::c_char,
    *const libc::posix_spawn_file_actions_t,
    *const libc::posix_spawnattr_t,
    *const *mut libc::c_char,
    *const *mut libc::c_char,
) -> libc::c_int;

type ExecveFn = unsafe extern "C" fn(
    *const libc::c_char,
    *const *const libc::c_char,
    *const *const libc::c_char,
) -> libc::c_int;

thread_local! {
    static INSIDE_PROCESS_HOOK: Cell<bool> = const { Cell::new(false) };
}

struct ProcessHookGuard;

impl ProcessHookGuard {
    fn enter() -> Option<Self> {
        INSIDE_PROCESS_HOOK.with(|inside| (!inside.replace(true)).then_some(Self))
    }
}

impl Drop for ProcessHookGuard {
    fn drop(&mut self) {
        INSIDE_PROCESS_HOOK.with(|inside| inside.set(false));
    }
}

struct ProcessHookRuntime {
    config: HookConfig,
}

struct ChildEnvironment {
    values: Vec<CString>,
    pointers: Vec<*mut libc::c_char>,
}

impl ChildEnvironment {
    unsafe fn new(environment: *const *const libc::c_char, config: &HookConfig) -> Option<Self> {
        let mut values = Vec::new();
        if !environment.is_null() {
            let mut current = environment;
            while !(unsafe { *current }).is_null() {
                let value = unsafe { CStr::from_ptr(*current) }.to_bytes();
                if !CHILD_RUNTIME_ENVIRONMENT
                    .iter()
                    .any(|key| Self::has_key(value, key))
                    && !Self::has_key(value, "DYLD_INSERT_LIBRARIES")
                {
                    values.push(CString::new(value).ok()?);
                }
                current = unsafe { current.add(1) };
            }
        }
        for (key, value) in config.child_environment() {
            let mut entry = Vec::with_capacity(key.len() + 1 + value.len());
            entry.extend_from_slice(key.as_bytes());
            entry.push(b'=');
            entry.extend_from_slice(value.as_bytes());
            values.push(CString::new(entry).ok()?);
        }
        values
            .push(CString::new(format!("DYLD_INSERT_LIBRARIES={}", config.hook_libraries())).ok()?);
        let mut pointers = values
            .iter()
            .map(|value| value.as_ptr().cast_mut())
            .collect::<Vec<_>>();
        pointers.push(std::ptr::null_mut());
        Some(Self { values, pointers })
    }

    fn as_posix_ptr(&self) -> *const *mut libc::c_char {
        debug_assert_eq!(self.values.len() + 1, self.pointers.len());
        self.pointers.as_ptr()
    }

    fn as_exec_ptr(&self) -> *const *const libc::c_char {
        self.as_posix_ptr().cast()
    }

    fn has_key(value: &[u8], key: &str) -> bool {
        value
            .strip_prefix(key.as_bytes())
            .is_some_and(|suffix| suffix.starts_with(b"="))
    }
}

impl ProcessHookRuntime {
    fn global() -> Option<&'static Self> {
        static RUNTIME: OnceLock<Option<ProcessHookRuntime>> = OnceLock::new();
        RUNTIME
            .get_or_init(|| config::global().cloned().map(|config| Self { config }))
            .as_ref()
    }

    fn prepare(&self, executable: &Path) -> std::io::Result<CString> {
        let mut stream = TcpStream::connect(self.config.execution_control())?;
        let timeout = Some(Duration::from_secs(30));
        stream.set_read_timeout(timeout)?;
        stream.set_write_timeout(timeout)?;
        stream.write_all(&encode_prepare_request(
            self.config.execution_token(),
            executable,
        )?)?;
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix)?;
        let length = frame_length(prefix)?;
        let mut frame = vec![0_u8; length];
        stream.read_exact(&mut frame)?;
        match decode_prepare_response(&frame)? {
            PrepareResponse::Ready(path) => CString::new(path.as_os_str().as_bytes())
                .map_err(|_| std::io::Error::other("prepared executable path contains NUL")),
            PrepareResponse::Error(message) => Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                message,
            )),
        }
    }
}

unsafe fn requested_executable(path: *const libc::c_char, search_path: bool) -> Option<PathBuf> {
    if path.is_null() {
        return None;
    }
    let path = OsStr::from_bytes(unsafe { CStr::from_ptr(path) }.to_bytes());
    if !search_path || path.as_bytes().contains(&b'/') {
        let path = Path::new(path);
        return Some(if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir().ok()?.join(path)
        });
    }
    let search = std::env::var_os("PATH").unwrap_or_else(|| "/usr/bin:/bin:/usr/sbin:/sbin".into());
    let current = std::env::current_dir().ok()?;
    for directory in std::env::split_paths(&search) {
        let directory = if directory.as_os_str().is_empty() {
            current.clone()
        } else if directory.is_absolute() {
            directory
        } else {
            current.join(directory)
        };
        let candidate = directory.join(path);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

unsafe fn prepared_executable(path: *const libc::c_char, search_path: bool) -> Option<CString> {
    let runtime = ProcessHookRuntime::global()?;
    let executable = unsafe { requested_executable(path, search_path) }?;
    runtime.prepare(&executable).ok()
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_posix_spawn(
    pid: *mut libc::pid_t,
    path: *const libc::c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attributes: *const libc::posix_spawnattr_t,
    arguments: *const *mut libc::c_char,
    environment: *const *mut libc::c_char,
) -> libc::c_int {
    let Some(original) = original_posix_spawn() else {
        return libc::ENOSYS;
    };
    let Some(_guard) = ProcessHookGuard::enter() else {
        return libc::EACCES;
    };
    let Some(prepared) = (unsafe { prepared_executable(path, false) }) else {
        return libc::EACCES;
    };
    let Some(runtime) = ProcessHookRuntime::global() else {
        return libc::EACCES;
    };
    let Some(environment) = (unsafe {
        ChildEnvironment::new(environment.cast::<*const libc::c_char>(), &runtime.config)
    }) else {
        return libc::EACCES;
    };
    unsafe {
        original(
            pid,
            prepared.as_ptr(),
            file_actions,
            attributes,
            arguments,
            environment.as_posix_ptr(),
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_posix_spawnp(
    pid: *mut libc::pid_t,
    file: *const libc::c_char,
    file_actions: *const libc::posix_spawn_file_actions_t,
    attributes: *const libc::posix_spawnattr_t,
    arguments: *const *mut libc::c_char,
    environment: *const *mut libc::c_char,
) -> libc::c_int {
    let Some(original) = original_posix_spawn() else {
        return libc::ENOSYS;
    };
    let Some(_guard) = ProcessHookGuard::enter() else {
        return libc::EACCES;
    };
    let Some(prepared) = (unsafe { prepared_executable(file, true) }) else {
        return libc::EACCES;
    };
    let Some(runtime) = ProcessHookRuntime::global() else {
        return libc::EACCES;
    };
    let Some(environment) = (unsafe {
        ChildEnvironment::new(environment.cast::<*const libc::c_char>(), &runtime.config)
    }) else {
        return libc::EACCES;
    };
    unsafe {
        original(
            pid,
            prepared.as_ptr(),
            file_actions,
            attributes,
            arguments,
            environment.as_posix_ptr(),
        )
    }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_execve(
    path: *const libc::c_char,
    arguments: *const *const libc::c_char,
    environment: *const *const libc::c_char,
) -> libc::c_int {
    unsafe { execute(path, false, arguments, environment) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_execv(
    path: *const libc::c_char,
    arguments: *const *const libc::c_char,
) -> libc::c_int {
    unsafe { execute(path, false, arguments, current_environment()) }
}

#[unsafe(no_mangle)]
pub unsafe extern "C" fn agora_sandbox_execvp(
    file: *const libc::c_char,
    arguments: *const *const libc::c_char,
) -> libc::c_int {
    unsafe { execute(file, true, arguments, current_environment()) }
}

unsafe fn execute(
    path: *const libc::c_char,
    search_path: bool,
    arguments: *const *const libc::c_char,
    environment: *const *const libc::c_char,
) -> libc::c_int {
    let Some(original) = original_execve() else {
        unsafe { set_errno(libc::ENOSYS) };
        return -1;
    };
    let Some(_guard) = ProcessHookGuard::enter() else {
        unsafe { set_errno(libc::EACCES) };
        return -1;
    };
    let Some(prepared) = (unsafe { prepared_executable(path, search_path) }) else {
        unsafe { set_errno(libc::EACCES) };
        return -1;
    };
    let Some(runtime) = ProcessHookRuntime::global() else {
        unsafe { set_errno(libc::EACCES) };
        return -1;
    };
    let Some(environment) = (unsafe { ChildEnvironment::new(environment, &runtime.config) }) else {
        unsafe { set_errno(libc::EACCES) };
        return -1;
    };
    unsafe { original(prepared.as_ptr(), arguments, environment.as_exec_ptr()) }
}

unsafe fn current_environment() -> *const *const libc::c_char {
    let environment = unsafe { libc::_NSGetEnviron() };
    if environment.is_null() {
        std::ptr::null()
    } else {
        unsafe { *environment }.cast()
    }
}

fn original_posix_spawn() -> Option<PosixSpawnFn> {
    function_from_interpose(&INTERPOSE_POSIX_SPAWN)
}

fn original_execve() -> Option<ExecveFn> {
    function_from_interpose(&INTERPOSE_EXECVE)
}

dyld_interpose!(
    INTERPOSE_POSIX_SPAWN,
    agora_sandbox_posix_spawn,
    libc::posix_spawn
);
dyld_interpose!(
    INTERPOSE_POSIX_SPAWNP,
    agora_sandbox_posix_spawnp,
    libc::posix_spawnp
);
dyld_interpose!(INTERPOSE_EXECVE, agora_sandbox_execve, libc::execve);
dyld_interpose!(INTERPOSE_EXECV, agora_sandbox_execv, libc::execv);
dyld_interpose!(INTERPOSE_EXECVP, agora_sandbox_execvp, libc::execvp);

#[cfg(test)]
mod tests;
