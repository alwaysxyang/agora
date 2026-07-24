use agora_sandbox::audit::{AuditEvent, AuditEventType, NoopAuditCallback};
use agora_sandbox::network::{NetworkEnforcement, TlsMode};
use agora_sandbox::runner::{Sandbox, SandboxCommand, SandboxConfig};
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
type TestAssociationId = u32;
#[cfg(target_os = "macos")]
type TestConnectionId = u32;

#[cfg(target_os = "macos")]
#[repr(C)]
struct TestSocketEndpoints {
    source_interface: libc::c_uint,
    source_address: *const libc::sockaddr,
    source_address_length: libc::socklen_t,
    destination_address: *const libc::sockaddr,
    destination_address_length: libc::socklen_t,
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn connectx(
        socket: libc::c_int,
        endpoints: *const TestSocketEndpoints,
        association_id: TestAssociationId,
        flags: libc::c_uint,
        vectors: *const libc::iovec,
        vector_count: libc::c_uint,
        bytes_written: *mut libc::size_t,
        connection_id: *mut TestConnectionId,
    ) -> libc::c_int;
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf()
}

fn hook_library() -> PathBuf {
    static HOOK: OnceLock<PathBuf> = OnceLock::new();
    HOOK.get_or_init(|| {
        let workspace = workspace_root();
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "agora-sandbox", "--lib"])
            .current_dir(&workspace)
            .status()
            .unwrap();
        assert!(status.success());
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    workspace.join(path)
                }
            })
            .unwrap_or_else(|| workspace.join("target"));
        let library = target.join("debug/libagora_sandbox.dylib");
        assert!(library.is_file(), "missing {}", library.display());
        library
    })
    .clone()
}

#[test]
fn unsupported_enforcement_and_tls_modes_fail_validation() {
    let hook = PathBuf::from("/tmp/hook.dylib");
    let mut config = SandboxConfig::new(&hook);
    config.network.enforcement = NetworkEnforcement::Strict;
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("strict network enforcement"));

    config.network.enforcement = NetworkEnforcement::Audit;
    config.network.tls = TlsMode::Require;
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("TLS termination"));
}

#[tokio::test]
async fn runner_propagates_child_exit_status() {
    let sandbox = Sandbox::new(SandboxConfig::new(hook_library()), NoopAuditCallback);
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("exits_with_seven")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_EXIT_SEVEN", "1");
    let outcome = sandbox.run(command).await.unwrap();

    assert_eq!(outcome.status().code(), Some(7));
    assert!(!outcome.sandbox_id().is_empty());
    assert!(!outcome.run_id().is_empty());
}

#[test]
fn exits_with_seven() {
    if std::env::var_os("AGORA_SANDBOX_TEST_EXIT_SEVEN").is_some() {
        std::process::exit(7);
    }
}

#[test]
fn intercepted_child_process() {
    if std::env::var_os("AGORA_SANDBOX_TEST_CHILD").is_none() {
        return;
    }

    let destination = std::env::var("AGORA_SANDBOX_TEST_DESTINATION").unwrap();
    let destination = destination.parse().unwrap();
    let mut stream = TcpStream::connect(destination).unwrap();
    let peer = stream.peer_addr().unwrap();
    assert!(peer.ip().is_loopback());
    assert_ne!(peer, destination);
    stream.write_all(b"hooked").unwrap();
    let mut echoed = [0_u8; 6];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"hooked");
}

#[cfg(target_os = "macos")]
#[test]
fn forked_intercepted_child_process() {
    if std::env::var_os("AGORA_SANDBOX_TEST_FORK_CHILD").is_none() {
        return;
    }

    let destination = std::env::var("AGORA_SANDBOX_TEST_DESTINATION")
        .unwrap()
        .parse()
        .unwrap();
    let child = unsafe { libc::fork() };
    assert!(child >= 0);
    if child == 0 {
        let succeeded = exchange_payload(destination, b"child!").is_ok();
        unsafe { libc::_exit(if succeeded { 0 } else { 1 }) };
    }

    exchange_payload(destination, b"parent").unwrap();
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert!(libc::WIFEXITED(status));
    assert_eq!(libc::WEXITSTATUS(status), 0);
}

#[cfg(target_os = "macos")]
fn exchange_payload(destination: std::net::SocketAddr, payload: &[u8; 6]) -> std::io::Result<()> {
    let mut stream = TcpStream::connect(destination)?;
    stream.write_all(payload)?;
    let mut echoed = [0_u8; 6];
    stream.read_exact(&mut echoed)?;
    if &echoed != payload {
        return Err(std::io::Error::other("unexpected echoed payload"));
    }
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
fn missing_hook_configuration_child_process() {
    if std::env::var_os("AGORA_SANDBOX_TEST_MISSING_CONFIG_CHILD").is_none() {
        return;
    }

    let destination = std::env::var("AGORA_SANDBOX_TEST_DESTINATION").unwrap();
    let error = TcpStream::connect(destination).unwrap_err();
    assert_eq!(error.raw_os_error(), Some(libc::EACCES));
}

#[cfg(target_os = "macos")]
#[test]
fn nonblocking_intercepted_child_process() {
    if std::env::var_os("AGORA_SANDBOX_TEST_NONBLOCKING_CHILD").is_none() {
        return;
    }

    run_nonblocking_intercepted_child(false);
}

#[cfg(target_os = "macos")]
#[test]
fn nonblocking_connectx_intercepted_child_process() {
    if std::env::var_os("AGORA_SANDBOX_TEST_NONBLOCKING_CONNECTX_CHILD").is_none() {
        return;
    }

    run_nonblocking_intercepted_child(true);
}

#[cfg(target_os = "macos")]
#[test]
fn unsupported_connectx_intercepted_child_process() {
    if std::env::var_os("AGORA_SANDBOX_TEST_UNSUPPORTED_CONNECTX_CHILD").is_none() {
        return;
    }

    let destination = std::env::var("AGORA_SANDBOX_TEST_DESTINATION")
        .unwrap()
        .parse::<SocketAddrV4>()
        .unwrap();
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(socket >= 0);
    let address = libc::sockaddr_in {
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: destination.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(destination.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    let endpoints = TestSocketEndpoints {
        source_interface: 0,
        source_address: std::ptr::null(),
        source_address_length: 0,
        destination_address: std::ptr::addr_of!(address).cast(),
        destination_address_length: std::mem::size_of_val(&address) as libc::socklen_t,
    };
    let payload = b"must-not-bypass";
    let vector = libc::iovec {
        iov_base: payload.as_ptr().cast_mut().cast(),
        iov_len: payload.len(),
    };
    let mut bytes_written = 0;
    let result = unsafe {
        connectx(
            socket,
            std::ptr::addr_of!(endpoints),
            0,
            0,
            std::ptr::addr_of!(vector),
            1,
            std::ptr::addr_of_mut!(bytes_written),
            std::ptr::null_mut(),
        )
    };

    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EACCES)
    );
    unsafe { libc::close(socket) };
}

#[cfg(target_os = "macos")]
fn run_nonblocking_intercepted_child(use_connectx: bool) {
    let destination = std::env::var("AGORA_SANDBOX_TEST_DESTINATION")
        .unwrap()
        .parse::<SocketAddrV4>()
        .unwrap();
    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_STREAM, 0) };
    assert!(socket >= 0);
    let flags = unsafe { libc::fcntl(socket, libc::F_GETFL) };
    assert!(flags >= 0);
    assert_eq!(
        unsafe { libc::fcntl(socket, libc::F_SETFL, flags | libc::O_NONBLOCK) },
        0
    );
    let address = libc::sockaddr_in {
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: destination.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(destination.ip().octets()),
        },
        sin_zero: [0; 8],
    };

    let started = Instant::now();
    let mut bytes_written = usize::MAX;
    let mut connection_id = u32::MAX;
    let result = if use_connectx {
        let endpoints = TestSocketEndpoints {
            source_interface: 0,
            source_address: std::ptr::null(),
            source_address_length: 0,
            destination_address: std::ptr::addr_of!(address).cast(),
            destination_address_length: std::mem::size_of_val(&address) as libc::socklen_t,
        };
        unsafe {
            connectx(
                socket,
                std::ptr::addr_of!(endpoints),
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::addr_of_mut!(bytes_written),
                std::ptr::addr_of_mut!(connection_id),
            )
        }
    } else {
        unsafe {
            libc::connect(
                socket,
                std::ptr::addr_of!(address).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        }
    };
    let elapsed = started.elapsed();
    assert_eq!(result, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::EINPROGRESS)
    );
    assert!(
        elapsed < Duration::from_millis(250),
        "nonblocking connect took {elapsed:?}",
    );
    if use_connectx {
        assert_eq!(bytes_written, 0);
        assert_eq!(connection_id, 0);
    }
    assert_ne!(
        unsafe { libc::fcntl(socket, libc::F_GETFL) } & libc::O_NONBLOCK,
        0
    );

    let mut descriptor = libc::pollfd {
        fd: socket,
        events: libc::POLLOUT,
        revents: 0,
    };
    assert_eq!(unsafe { libc::poll(&mut descriptor, 1, 3_000) }, 1);
    assert_ne!(descriptor.revents & libc::POLLOUT, 0);
    let mut socket_error = 0;
    let mut error_length = std::mem::size_of_val(&socket_error) as libc::socklen_t;
    assert_eq!(
        unsafe {
            libc::getsockopt(
                socket,
                libc::SOL_SOCKET,
                libc::SO_ERROR,
                std::ptr::addr_of_mut!(socket_error).cast(),
                &mut error_length,
            )
        },
        0
    );
    assert_eq!(socket_error, 0);

    let mut stream = unsafe { TcpStream::from_raw_fd(socket) };
    stream.set_nonblocking(false).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .unwrap();
    stream.write_all(b"hooked").unwrap();
    let mut echoed = [0_u8; 6];
    stream.read_exact(&mut echoed).unwrap();
    assert_eq!(&echoed, b"hooked");
}

#[tokio::test]
async fn injected_hook_routes_a_real_child_connection_through_the_proxy() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let destination = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0_u8; 6];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut bytes)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, &bytes)
            .await
            .unwrap();
    });
    let events = Arc::new(Mutex::new(Vec::<AuditEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    };
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("intercepted_child_process")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_CHILD", "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string());
    let outcome = Sandbox::new(SandboxConfig::new(hook_library()), callback)
        .run(command)
        .await
        .unwrap();
    assert!(
        outcome.status().success(),
        "child status: {:?}",
        outcome.status()
    );
    tokio::time::timeout(std::time::Duration::from_secs(2), echo)
        .await
        .unwrap()
        .unwrap();
    let event_types = events
        .lock()
        .unwrap()
        .iter()
        .map(|event| event.event_type)
        .collect::<Vec<_>>();
    assert_eq!(
        event_types,
        vec![
            AuditEventType::NetworkConnectAttempt,
            AuditEventType::NetworkConnectEstablished,
            AuditEventType::NetworkConnectionClosed,
        ]
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn injected_hook_refreshes_process_identity_after_fork() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let destination = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut connections = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = listener.accept().await.unwrap();
            connections.push(tokio::spawn(async move {
                let mut bytes = [0_u8; 6];
                tokio::io::AsyncReadExt::read_exact(&mut stream, &mut bytes)
                    .await
                    .unwrap();
                tokio::io::AsyncWriteExt::write_all(&mut stream, &bytes)
                    .await
                    .unwrap();
            }));
        }
        for connection in connections {
            connection.await.unwrap();
        }
    });
    let events = Arc::new(Mutex::new(Vec::<AuditEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| events.lock().unwrap().push(event)
    };
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("forked_intercepted_child_process")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_FORK_CHILD", "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string());

    let outcome = Sandbox::new(SandboxConfig::new(hook_library()), callback)
        .run(command)
        .await
        .unwrap();
    assert!(outcome.status().success());
    tokio::time::timeout(Duration::from_secs(2), echo)
        .await
        .unwrap()
        .unwrap();

    let events = events.lock().unwrap();
    let attempts = events
        .iter()
        .filter(|event| event.event_type == AuditEventType::NetworkConnectAttempt)
        .collect::<Vec<_>>();
    assert_eq!(attempts.len(), 2);
    assert_ne!(attempts[0].process.pid, attempts[1].process.pid);
    assert!(
        attempts[0].process.ppid == attempts[1].process.pid
            || attempts[1].process.ppid == attempts[0].process.pid
    );
    for event in &attempts {
        assert!(
            event
                .connection_id
                .as_deref()
                .unwrap()
                .starts_with(&format!("{}-", event.process.pid))
        );
    }
    assert_ne!(attempts[0].connection_id, attempts[1].connection_id);
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn injected_hook_preserves_nonblocking_connect_and_poll_semantics() {
    assert_injected_nonblocking_connection(
        "nonblocking_intercepted_child_process",
        "AGORA_SANDBOX_TEST_NONBLOCKING_CHILD",
    )
    .await;
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn injected_hook_preserves_nonblocking_connectx_and_poll_semantics() {
    assert_injected_nonblocking_connection(
        "nonblocking_connectx_intercepted_child_process",
        "AGORA_SANDBOX_TEST_NONBLOCKING_CONNECTX_CHILD",
    )
    .await;
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn injected_hook_blocks_unsupported_connectx_without_direct_fallback() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let destination = listener.local_addr().unwrap();
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("unsupported_connectx_intercepted_child_process")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_UNSUPPORTED_CONNECTX_CHILD", "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string());
    let outcome = Sandbox::new(SandboxConfig::new(hook_library()), NoopAuditCallback)
        .run(command)
        .await
        .unwrap();

    assert!(outcome.status().success());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn injected_hook_blocks_tcp_when_runtime_configuration_is_missing() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let destination = listener.local_addr().unwrap();
    let mut command = tokio::process::Command::new(std::env::current_exe().unwrap());
    command
        .arg("missing_hook_configuration_child_process")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_MISSING_CONFIG_CHILD", "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string())
        .env("DYLD_INSERT_LIBRARIES", hook_library())
        .env_remove("AGORA_SANDBOX_TOKEN")
        .env_remove("AGORA_SANDBOX_PROXY_IPV4")
        .env_remove("AGORA_SANDBOX_PROXY_IPV6");

    let status = command.status().await.unwrap();

    assert!(status.success(), "child status: {status:?}");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}

#[cfg(target_os = "macos")]
async fn assert_injected_nonblocking_connection(child_test: &str, child_environment: &str) {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let destination = listener.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut bytes = [0_u8; 6];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut bytes)
            .await
            .unwrap();
        tokio::io::AsyncWriteExt::write_all(&mut stream, &bytes)
            .await
            .unwrap();
    });
    let callback = |event: AuditEvent| {
        if event.event_type == AuditEventType::NetworkConnectAttempt {
            std::thread::sleep(Duration::from_millis(750));
        }
    };
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg(child_test)
        .arg("--exact")
        .arg("--nocapture")
        .env(child_environment, "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string());
    let outcome = Sandbox::new(SandboxConfig::new(hook_library()), callback)
        .run(command)
        .await
        .unwrap();

    assert!(
        outcome.status().success(),
        "child status: {:?}",
        outcome.status()
    );
    tokio::time::timeout(Duration::from_secs(2), echo)
        .await
        .unwrap()
        .unwrap();
}
