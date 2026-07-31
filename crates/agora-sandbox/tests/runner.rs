use agora_sandbox::callback::{Decision, EventType, NetworkEvent, NoopCallback};
use agora_sandbox::network::{NetworkEnforcement, TlsMode};
use agora_sandbox::runner::{Sandbox, SandboxCommand, SandboxConfig};
#[cfg(target_os = "macos")]
use base64::Engine;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream};
use std::os::fd::FromRawFd;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

#[cfg(target_os = "macos")]
const TLS_TRUST_ENVIRONMENT: [&str; 5] = [
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
];

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

#[cfg(target_os = "macos")]
fn sandbox_config() -> SandboxConfig {
    SandboxConfig::new(hook_library())
        .with_workdir(workspace_root().join("target/agora-sandbox-test-cache/runner"))
}

#[cfg(target_os = "macos")]
#[test]
fn unsupported_enforcement_fails_validation_and_default_tls_ca_is_allowed() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-default-ca-validation-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let hook = directory.join("hook.dylib");
    std::fs::write(&hook, b"hook").unwrap();
    let mut config = SandboxConfig::new(&hook);
    config.network.enforcement = NetworkEnforcement::Strict;
    let error = config.validate().unwrap_err();
    assert!(error.to_string().contains("strict network enforcement"));

    config.network.enforcement = NetworkEnforcement::Intercept;
    config.network.tls = TlsMode::Auto;
    assert!(config.validate().is_ok());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_generates_default_tls_ca_in_the_configured_workdir() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-default-ca-test-{}",
        uuid::Uuid::new_v4()
    ));
    let command_workdir = directory.join("command");
    let workdir = directory.join("sandbox");
    std::fs::create_dir_all(&command_workdir).unwrap();
    let certificate = workdir.join("ca/ca.crt");
    let private_key = workdir.join("ca/ca.key");
    let mut config = SandboxConfig::new(hook_library()).with_workdir(&workdir);
    config.network.tls = TlsMode::Auto;
    let command = SandboxCommand::new("/usr/bin/true").current_dir(&command_workdir);

    let outcome = Sandbox::new(config, NoopCallback)
        .run(command)
        .await
        .unwrap();

    assert!(outcome.status().success());
    assert!(
        std::fs::read_to_string(&certificate)
            .unwrap()
            .starts_with("-----BEGIN CERTIFICATE-----")
    );
    assert!(
        std::fs::read_to_string(&private_key)
            .unwrap()
            .starts_with("-----BEGIN PRIVATE KEY-----")
    );
    let trust_bundles = std::fs::read_dir(workdir.join("ca"))
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| {
            path.file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("trust-bundle-")
        })
        .collect::<Vec<_>>();
    assert_eq!(trust_bundles.len(), 1);
    assert!(
        rustls_pemfile::certs(&mut std::fs::read(&trust_bundles[0]).unwrap().as_slice())
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
            .len()
            > 1
    );
    assert!(!command_workdir.join("ca").exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_rejects_a_malformed_tls_ca_before_starting_the_child() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-malformed-ca-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let certificate = directory.join("ca.pem");
    let private_key = directory.join("ca-key.pem");
    let marker = directory.join("child-started");
    std::fs::write(&certificate, b"not a certificate").unwrap();
    std::fs::write(&private_key, b"not a private key").unwrap();
    let mut config = sandbox_config().with_tls_ca(&certificate, &private_key);
    config.network.tls = TlsMode::Auto;
    let command = SandboxCommand::new("/bin/sh")
        .arg("-c")
        .arg(format!("touch {}", marker.display()));

    let error = Sandbox::new(config, NoopCallback)
        .run(command)
        .await
        .unwrap_err();

    assert!(error.to_string().contains("TLS CA certificate"));
    assert!(!marker.exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[tokio::test]
async fn runner_propagates_child_exit_status() {
    let sandbox = Sandbox::new(sandbox_config(), NoopCallback);
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

#[cfg(target_os = "macos")]
#[test]
fn records_current_executable() {
    let Some(output) = std::env::var_os("AGORA_SANDBOX_TEST_CURRENT_EXE") else {
        return;
    };
    std::fs::write(
        output,
        std::env::current_exe()
            .unwrap()
            .to_string_lossy()
            .as_bytes(),
    )
    .unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn records_tls_trust_environment() {
    let Some(output) = std::env::var_os("AGORA_SANDBOX_TEST_TLS_TRUST_ENV") else {
        return;
    };
    let values = TLS_TRUST_ENVIRONMENT
        .iter()
        .map(|key| format!("{key}={}", std::env::var(key).unwrap_or_default()))
        .collect::<Vec<_>>()
        .join("\n");
    std::fs::write(output, values).unwrap();
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
    let events = Arc::new(Mutex::new(Vec::<NetworkEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| {
            events.lock().unwrap().push(event);
            std::future::ready(Decision::Allow)
        }
    };
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("intercepted_child_process")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_CHILD", "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string());
    let outcome = Sandbox::new(sandbox_config(), callback)
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
            EventType::NetworkConnectAttempt,
            EventType::NetworkConnectEstablished,
            EventType::NetworkConnectionClosed,
        ]
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_keeps_an_unrestricted_executable_at_its_original_path() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-executable-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let workdir = directory.join("cache");
    let output = directory.join("current-exe-first");
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("records_current_executable")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_CURRENT_EXE", &output);
    let config = SandboxConfig::new(hook_library()).with_workdir(&workdir);

    let outcome = Sandbox::new(config.clone(), NoopCallback)
        .run(command)
        .await
        .unwrap();

    assert!(outcome.status().success());
    let executable = PathBuf::from(std::fs::read_to_string(&output).unwrap());
    let source = std::env::current_exe().unwrap().canonicalize().unwrap();
    assert_eq!(executable, source);
    let cached = workdir
        .join("root")
        .join(source.strip_prefix(Path::new("/")).unwrap());
    assert!(!cached.exists());
    assert!(workdir.join("root/.lock").is_file());

    let second_output = directory.join("current-exe-second");
    let second = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("records_current_executable")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_CURRENT_EXE", &second_output);
    let outcome = Sandbox::new(config, NoopCallback)
        .run(second)
        .await
        .unwrap();
    assert!(outcome.status().success());
    assert_eq!(
        PathBuf::from(std::fs::read_to_string(second_output).unwrap()),
        executable
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_executes_shebang_scripts_through_a_prepared_restricted_interpreter() {
    use std::os::unix::fs::PermissionsExt;

    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-shebang-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let workdir = directory.join("cache");
    let script = directory.join("client");
    std::fs::write(
        &script,
        b"#!/usr/bin/env sh\nprintf '%s\\n%s\\n' \"$1\" \"$DYLD_INSERT_LIBRARIES\" > \"$2\"\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = SandboxConfig::new(hook_library()).with_workdir(&workdir);
    let direct_output = directory.join("direct-output");

    let direct = Sandbox::new(config.clone(), NoopCallback)
        .run(
            SandboxCommand::new(&script)
                .arg("direct")
                .arg(&direct_output),
        )
        .await
        .unwrap();

    assert!(direct.status().success());
    let direct_output = std::fs::read_to_string(direct_output).unwrap();
    assert!(direct_output.starts_with("direct\n"));
    assert!(direct_output.contains("libagora_sandbox.dylib"));

    let nested_output = directory.join("nested-output");
    let command = format!("{} nested {}", script.display(), nested_output.display());
    let nested = Sandbox::new(config, NoopCallback)
        .run(SandboxCommand::new("/bin/bash").args(["-c", &command]))
        .await
        .unwrap();

    assert!(nested.status().success());
    let nested_output = std::fs::read_to_string(nested_output).unwrap();
    assert!(nested_output.starts_with("nested\n"));
    assert!(nested_output.contains("libagora_sandbox.dylib"));
    let script = script.canonicalize().unwrap();
    assert!(workdir.join("root/usr/bin/env").is_file());
    assert!(workdir.join("root/bin/sh").is_file());
    assert!(
        !workdir
            .join("root")
            .join(script.strip_prefix(Path::new("/")).unwrap())
            .exists()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_injects_a_process_local_sec_trust_anchor() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-trust-anchor-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let anchor = directory.join("ca.der");
    let leaf = directory.join("leaf.der");
    std::fs::write(
        &anchor,
        base64::engine::general_purpose::STANDARD
            .decode(include_str!("fixtures/test-ca.der.b64").trim())
            .unwrap(),
    )
    .unwrap();
    std::fs::write(
        &leaf,
        base64::engine::general_purpose::STANDARD
            .decode(include_str!("fixtures/test-leaf.der.b64").trim())
            .unwrap(),
    )
    .unwrap();

    let command = SandboxCommand::new("/usr/bin/security")
        .arg("verify-cert")
        .arg("-c")
        .arg(&leaf)
        .arg("-p")
        .arg("ssl")
        .arg("-d")
        .arg("2026-08-01-00:00:00")
        .arg("-s")
        .arg("example.test");
    let config = sandbox_config().with_tls_trust_anchor(&anchor);

    let outcome = Sandbox::new(config, NoopCallback)
        .run(command)
        .await
        .unwrap();

    assert!(
        outcome.status().success(),
        "security verify-cert failed with {:?}",
        outcome.status()
    );
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_injects_the_configured_tls_ca_path() {
    use rcgen::{BasicConstraints, CertificateParams, IsCa, KeyPair, KeyUsagePurpose};

    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-tls-environment-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let certificate = directory.join("ca.pem");
    let private_key = directory.join("ca-key.pem");
    let output = directory.join("environment");
    let key = KeyPair::generate().unwrap();
    let mut params = CertificateParams::new(Vec::new()).unwrap();
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let ca = params.self_signed(&key).unwrap();
    std::fs::write(&certificate, ca.pem()).unwrap();
    std::fs::write(&private_key, key.serialize_pem()).unwrap();
    let mut config = sandbox_config().with_tls_ca(&certificate, &private_key);
    config.network.tls = TlsMode::Auto;
    let trust_bundle_directory = config.workdir().join("ca");
    let script = format!(
        "/usr/bin/env -i AGORA_SANDBOX_TEST_TLS_TRUST_ENV='{}' '{}' \
         records_tls_trust_environment --exact --nocapture",
        output.display(),
        std::env::current_exe().unwrap().display()
    );
    let command = SandboxCommand::new("/bin/bash").args(["-c", &script]);

    let outcome = Sandbox::new(config, NoopCallback)
        .run(command)
        .await
        .unwrap();

    assert!(outcome.status().success());
    let values = std::fs::read_to_string(&output).unwrap();
    let paths = values
        .lines()
        .map(|line| PathBuf::from(line.split_once('=').unwrap().1))
        .collect::<Vec<_>>();
    assert_eq!(paths.len(), TLS_TRUST_ENVIRONMENT.len());
    assert!(paths.iter().all(|path| !path.as_os_str().is_empty()));
    assert!(paths.iter().all(|path| path == &paths[0]));
    assert_eq!(paths[0].parent().unwrap(), trust_bundle_directory);
    assert!(
        paths[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("trust-bundle-")
    );
    let certificates = rustls_pemfile::certs(&mut std::fs::read(&paths[0]).unwrap().as_slice())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    assert!(certificates.len() > 1);
    assert_eq!(certificates[0].as_ref(), ca.der().as_ref());
    assert!(certificate.exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn copied_bash_routes_system_curl_through_the_proxy() {
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let destination = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        loop {
            let mut bytes = [0_u8; 1024];
            let read = tokio::io::AsyncReadExt::read(&mut stream, &mut bytes)
                .await
                .unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&bytes[..read]);
            if request.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        tokio::io::AsyncWriteExt::write_all(
            &mut stream,
            b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    });
    let events = Arc::new(Mutex::new(Vec::<NetworkEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| {
            events.lock().unwrap().push(event);
            std::future::ready(Decision::Allow)
        }
    };
    let script = format!(
        "/usr/bin/env -i PATH=/usr/bin:/bin curl \
         --silent --show-error --output /dev/null http://{destination}/"
    );

    let outcome = Sandbox::new(sandbox_config(), callback)
        .run(SandboxCommand::new("/bin/bash").args(["-c", &script]))
        .await
        .unwrap();

    assert!(outcome.status().success());
    tokio::time::timeout(Duration::from_secs(2), server)
        .await
        .unwrap()
        .unwrap();
    assert!(
        events
            .lock()
            .unwrap()
            .iter()
            .any(|event| event.event_type == EventType::NetworkConnectAttempt)
    );
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_terminates_background_descendants_before_returning() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-process-group-test-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&directory).unwrap();
    let output = directory.join("background-pid");
    let script = format!("/bin/sleep 30 & echo $! > {}", output.display());

    let outcome = Sandbox::new(sandbox_config(), NoopCallback)
        .run(SandboxCommand::new("/bin/bash").args(["-c", &script]))
        .await
        .unwrap();

    assert!(outcome.status().success());
    let pid = std::fs::read_to_string(&output)
        .unwrap()
        .trim()
        .parse::<libc::pid_t>()
        .unwrap();
    assert_eq!(unsafe { libc::kill(pid, 0) }, -1);
    assert_eq!(
        std::io::Error::last_os_error().raw_os_error(),
        Some(libc::ESRCH)
    );
    std::fs::remove_dir_all(directory).unwrap();
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
    let events = Arc::new(Mutex::new(Vec::<NetworkEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| {
            events.lock().unwrap().push(event);
            std::future::ready(Decision::Allow)
        }
    };
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("forked_intercepted_child_process")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_FORK_CHILD", "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string());

    let outcome = Sandbox::new(sandbox_config(), callback)
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
        .filter(|event| event.event_type == EventType::NetworkConnectAttempt)
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
    let outcome = Sandbox::new(sandbox_config(), NoopCallback)
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
    let callback = |event: NetworkEvent| async move {
        if event.event_type == EventType::NetworkConnectAttempt {
            tokio::time::sleep(Duration::from_millis(750)).await;
        }
        Decision::Allow
    };
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg(child_test)
        .arg("--exact")
        .arg("--nocapture")
        .env(child_environment, "1")
        .env("AGORA_SANDBOX_TEST_DESTINATION", destination.to_string());
    let outcome = Sandbox::new(sandbox_config(), callback)
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
