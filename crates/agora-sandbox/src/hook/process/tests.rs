use super::{
    ChildEnvironment, ProcessHookGuard, ProcessHookRuntime, agora_sandbox_execv,
    agora_sandbox_execve, agora_sandbox_execvp, agora_sandbox_posix_spawn,
    agora_sandbox_posix_spawnp, current_environment, execute, prepared_executable,
    requested_executable,
};
use crate::hook::config::HookConfig;
use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::Path;
use std::thread;

fn config() -> HookConfig {
    config_with_control("127.0.0.1:41002".parse().unwrap())
}

fn config_with_control(control: SocketAddr) -> HookConfig {
    let control = control.to_string();
    let values = HashMap::from([
        ("AGORA_SANDBOX_TOKEN", "token".to_string()),
        ("AGORA_SANDBOX_PROXY_IPV4", "127.0.0.1:41000".to_string()),
        ("AGORA_SANDBOX_PROXY_IPV6", "[::1]:41001".to_string()),
        ("AGORA_SANDBOX_EXECUTION_CONTROL", control),
        (
            "AGORA_SANDBOX_EXECUTION_TOKEN",
            "execution-token".to_string(),
        ),
        (
            "AGORA_SANDBOX_HOOK_LIBRARIES",
            "/tmp/hook.dylib".to_string(),
        ),
    ]);
    HookConfig::from_getter(|key| values.get(key).cloned()).unwrap()
}

fn response(status: u8, content: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&1_u16.to_be_bytes());
    body.push(status);
    body.extend_from_slice(&(content.len() as u32).to_be_bytes());
    body.extend_from_slice(content);
    let mut frame = Vec::new();
    frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

fn runtime_with_response(response: Vec<u8>) -> (ProcessHookRuntime, thread::JoinHandle<Vec<u8>>) {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).unwrap();
    let control = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut prefix = [0_u8; 4];
        stream.read_exact(&mut prefix).unwrap();
        let length = u32::from_be_bytes(prefix) as usize;
        let mut request = vec![0_u8; length];
        stream.read_exact(&mut request).unwrap();
        stream.write_all(&response).unwrap();
        request
    });
    (
        ProcessHookRuntime {
            config: config_with_control(control),
        },
        server,
    )
}

#[test]
fn child_environment_restores_runtime_values_after_the_caller_clears_them() {
    let path = CString::new("PATH=/usr/bin:/bin").unwrap();
    let values = [path.as_ptr(), std::ptr::null()];

    let environment = unsafe { ChildEnvironment::new(values.as_ptr(), &config()) }.unwrap();
    let entries = environment
        .values
        .iter()
        .map(|value| value.to_str().unwrap())
        .collect::<Vec<_>>();

    assert!(entries.contains(&"PATH=/usr/bin:/bin"));
    assert!(entries.contains(&"AGORA_SANDBOX_TOKEN=token"));
    assert!(entries.contains(&"AGORA_SANDBOX_EXECUTION_TOKEN=execution-token"));
    assert!(entries.contains(&"DYLD_INSERT_LIBRARIES=/tmp/hook.dylib"));
}

#[test]
fn child_environment_accepts_a_null_source_environment() {
    let environment = unsafe { ChildEnvironment::new(std::ptr::null(), &config()) }.unwrap();

    assert!(!environment.as_exec_ptr().is_null());
    assert_eq!(environment.values.len(), 7);
}

#[test]
fn child_environment_replaces_untrusted_runtime_values() {
    let stale = [
        CString::new("AGORA_SANDBOX_TOKEN=stale").unwrap(),
        CString::new("DYLD_INSERT_LIBRARIES=/tmp/untrusted.dylib").unwrap(),
    ];
    let pointers = [stale[0].as_ptr(), stale[1].as_ptr(), std::ptr::null()];

    let environment = unsafe { ChildEnvironment::new(pointers.as_ptr(), &config()) }.unwrap();
    let entries = unsafe {
        let mut current = environment.as_exec_ptr();
        let mut entries = Vec::new();
        while !(*current).is_null() {
            entries.push(CStr::from_ptr(*current).to_str().unwrap());
            current = current.add(1);
        }
        entries
    };

    assert!(!entries.contains(&"AGORA_SANDBOX_TOKEN=stale"));
    assert!(!entries.contains(&"DYLD_INSERT_LIBRARIES=/tmp/untrusted.dylib"));
    assert!(entries.contains(&"AGORA_SANDBOX_TOKEN=token"));
    assert!(entries.contains(&"DYLD_INSERT_LIBRARIES=/tmp/hook.dylib"));
}

#[test]
fn process_hook_guard_blocks_recursion_until_dropped() {
    let guard = ProcessHookGuard::enter().unwrap();
    assert!(ProcessHookGuard::enter().is_none());
    drop(guard);
    assert!(ProcessHookGuard::enter().is_some());
}

#[test]
fn requested_executable_resolves_direct_and_path_based_programs() {
    let absolute = CString::new("/bin/sh").unwrap();
    let relative = CString::new("./Cargo.toml").unwrap();
    let shell = CString::new("sh").unwrap();
    let missing = CString::new("agora-command-that-does-not-exist").unwrap();

    assert_eq!(
        unsafe { requested_executable(absolute.as_ptr(), false) }.unwrap(),
        Path::new("/bin/sh")
    );
    assert_eq!(
        unsafe { requested_executable(relative.as_ptr(), false) }.unwrap(),
        std::env::current_dir().unwrap().join("./Cargo.toml")
    );
    assert!(
        unsafe { requested_executable(shell.as_ptr(), true) }
            .unwrap()
            .ends_with("sh")
    );
    assert!(unsafe { requested_executable(missing.as_ptr(), true) }.is_none());
    assert!(unsafe { requested_executable(std::ptr::null(), false) }.is_none());
}

#[test]
fn process_runtime_returns_the_prepared_executable() {
    let (runtime, server) = runtime_with_response(response(0, b"/tmp/prepared-curl"));

    let prepared = runtime.prepare(Path::new("/usr/bin/curl")).unwrap();

    assert_eq!(prepared.to_bytes(), b"/tmp/prepared-curl");
    let request = server.join().unwrap();
    assert!(
        request
            .windows(b"execution-token".len())
            .any(|value| value == b"execution-token")
    );
    assert!(
        request
            .windows(b"/usr/bin/curl".len())
            .any(|value| value == b"/usr/bin/curl")
    );
}

#[test]
fn process_runtime_propagates_denied_and_invalid_responses() {
    let (runtime, denied_server) = runtime_with_response(response(1, b"denied"));
    let denied = runtime.prepare(Path::new("/bin/sh")).unwrap_err();
    assert_eq!(denied.kind(), std::io::ErrorKind::PermissionDenied);
    assert_eq!(denied.to_string(), "denied");
    denied_server.join().unwrap();

    let (runtime, invalid_server) = runtime_with_response(response(2, b"invalid"));
    assert_eq!(
        runtime.prepare(Path::new("/bin/sh")).unwrap_err().kind(),
        std::io::ErrorKind::InvalidData
    );
    invalid_server.join().unwrap();

    let (runtime, nul_server) = runtime_with_response(response(0, b"/tmp/a\0b"));
    assert!(runtime.prepare(Path::new("/bin/sh")).is_err());
    nul_server.join().unwrap();
}

#[test]
fn process_interposers_fail_closed_during_recursive_entry() {
    let _guard = ProcessHookGuard::enter().unwrap();

    assert_eq!(
        unsafe {
            agora_sandbox_posix_spawn(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        libc::EACCES
    );
    assert_eq!(
        unsafe {
            agora_sandbox_posix_spawnp(
                std::ptr::null_mut(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::null(),
            )
        },
        libc::EACCES
    );
    assert_eq!(
        unsafe { agora_sandbox_execve(std::ptr::null(), std::ptr::null(), std::ptr::null(),) },
        -1
    );
    assert_eq!(
        unsafe { agora_sandbox_execv(std::ptr::null(), std::ptr::null()) },
        -1
    );
    assert_eq!(
        unsafe { agora_sandbox_execvp(std::ptr::null(), std::ptr::null()) },
        -1
    );
    assert!(!unsafe { current_environment() }.is_null());
}

#[test]
fn process_runtime_and_direct_execution_fail_closed_without_configuration() {
    assert!(ProcessHookRuntime::global().is_none());
    assert!(unsafe { prepared_executable(std::ptr::null(), false) }.is_none());

    let _guard = ProcessHookGuard::enter().unwrap();
    assert_eq!(
        unsafe { execute(std::ptr::null(), false, std::ptr::null(), std::ptr::null(),) },
        -1
    );
}
