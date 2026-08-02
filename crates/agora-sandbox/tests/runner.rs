use agora_sandbox::callback::{
    Decision, Event, EventType, FileAccessMode, FileEvent, NetworkEvent, NoopCallback,
};
use agora_sandbox::network::{NetworkEnforcement, TlsMode};
use agora_sandbox::runner::{Sandbox, SandboxCommand, SandboxConfig};
#[cfg(target_os = "macos")]
use base64::Engine;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddrV4, TcpStream, UdpSocket};
use std::os::fd::FromRawFd;
#[cfg(target_os = "macos")]
use std::os::unix::fs::PermissionsExt;
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
const FILESYSTEM_KEY: &str = "test-filesystem-key";

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
        if std::env::var_os("CARGO_LLVM_COV").is_some() {
            let library = std::env::current_exe()
                .unwrap()
                .parent()
                .unwrap()
                .join("libagora_sandbox.dylib");
            assert!(library.is_file(), "missing {}", library.display());
            return library;
        }
        let workspace = workspace_root();
        let target = std::env::var_os("CARGO_TARGET_DIR")
            .map(PathBuf::from)
            .map(|path| {
                if path.is_absolute() {
                    path
                } else {
                    workspace.join(path)
                }
            })
            .unwrap_or_else(|| workspace.join("target"))
            .join("hook");
        let status = Command::new(env!("CARGO"))
            .args(["build", "-p", "agora-sandbox", "--lib", "--target-dir"])
            .arg(&target)
            .current_dir(&workspace)
            .status()
            .unwrap();
        assert!(status.success());
        let library = target.join("debug/libagora_sandbox.dylib");
        assert!(library.is_file(), "missing {}", library.display());
        library
    })
    .clone()
}

#[cfg(target_os = "macos")]
fn directory_contains(directory: &Path, needle: &[u8]) -> bool {
    std::fs::read_dir(directory).unwrap().any(|entry| {
        let path = entry.unwrap().path();
        if path.is_dir() {
            directory_contains(&path, needle)
        } else {
            std::fs::read(path)
                .map(|contents| {
                    contents
                        .windows(needle.len())
                        .any(|window| window == needle)
                })
                .unwrap_or(false)
        }
    })
}

#[cfg(target_os = "macos")]
fn sandbox_config() -> SandboxConfig {
    SandboxConfig::new(hook_library())
        .with_workdir(workspace_root().join(format!(
            "target/agora-sandbox-test-cache/runner-{}",
            uuid::Uuid::new_v4()
        )))
        .with_encrypted_workspace(FILESYSTEM_KEY)
}

#[cfg(target_os = "macos")]
fn sandbox_config_in(workdir: impl AsRef<Path>) -> SandboxConfig {
    SandboxConfig::new(hook_library())
        .with_workdir(workdir.as_ref())
        .with_encrypted_workspace(FILESYSTEM_KEY)
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
    let mut config = SandboxConfig::new(&hook).with_encrypted_workspace(FILESYSTEM_KEY);
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
    let mut config = sandbox_config_in(&workdir);
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
    assert!(trust_bundles.is_empty());
    assert!(!command_workdir.join("ca").exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_persists_an_encrypted_workspace_without_modifying_the_source() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-encrypted-workspace-test-{}",
        uuid::Uuid::new_v4()
    ));
    let source = directory.join("source");
    let workdir = directory.join("sandbox");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("input.txt"), b"original\n").unwrap();
    std::fs::write(
        source.join("verify.sh"),
        b"#!/bin/sh\ntest \"$(cat input.txt)\" = original && test \"$(cat output.txt)\" = 'encrypted workspace marker'\n",
    )
    .unwrap();
    let mut permissions = std::fs::metadata(source.join("verify.sh"))
        .unwrap()
        .permissions();
    permissions.set_mode(0o755);
    std::fs::set_permissions(source.join("verify.sh"), permissions).unwrap();
    let config = SandboxConfig::new(hook_library())
        .with_workdir(&workdir)
        .with_encrypted_workspace("correct horse battery staple");
    let create = SandboxCommand::new("/bin/sh")
        .args([
            "-c",
            "test \"$(cat input.txt)\" = original && printf 'encrypted workspace marker\\n' > output.txt",
        ])
        .current_dir(&source);
    let created = Sandbox::new(config.clone(), NoopCallback)
        .run(create)
        .await
        .unwrap();

    assert!(
        created.status().success(),
        "sandbox child exited with {}",
        created.status()
    );
    assert_eq!(
        std::fs::read(source.join("input.txt")).unwrap(),
        b"original\n"
    );
    assert!(!source.join("output.txt").exists());
    assert!(!workdir.join("filesystem").exists());
    assert!(workdir.join("fs").is_dir());
    assert!(!directory_contains(
        &workdir.join("fs"),
        b"encrypted workspace marker"
    ));

    let verify = SandboxCommand::new("./verify.sh").current_dir(&source);
    let verified = Sandbox::new(config, NoopCallback)
        .run(verify)
        .await
        .unwrap();

    assert!(verified.status().success());
    assert!(!source.join("output.txt").exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn encrypted_workspace_remains_ciphertext_while_the_child_is_running() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-runtime-ciphertext-test-{}",
        uuid::Uuid::new_v4()
    ));
    let source = directory.join("source");
    let workdir = directory.join("sandbox");
    let output = source.join("runtime-secret.txt");
    let marker = format!("runtime-secret-{}", uuid::Uuid::new_v4());
    std::fs::create_dir_all(&source).unwrap();

    let closed = Arc::new(tokio::sync::Notify::new());
    let callback = {
        let closed = Arc::clone(&closed);
        let output = output.to_string_lossy().into_owned();
        move |event| {
            if matches!(
                event,
                Event::File(ref event)
                    if event.event_type == EventType::FilesystemClose
                        && event.file.path == output
            ) {
                closed.notify_one();
            }
            std::future::ready(Decision::Allow)
        }
    };
    let config = SandboxConfig::new(hook_library())
        .with_workdir(&workdir)
        .with_encrypted_workspace(FILESYSTEM_KEY);
    let script = format!(
        "printf '%s' '{marker}' > '{}'; sleep 2; test \"$(cat '{}')\" = '{marker}'",
        output.display(),
        output.display()
    );
    let run = tokio::spawn(
        Sandbox::new(config, callback).run(
            SandboxCommand::new("/bin/bash")
                .args(["-c", script.as_str()])
                .current_dir(&source),
        ),
    );

    tokio::time::timeout(Duration::from_secs(30), closed.notified())
        .await
        .expect("sandbox child did not close the encrypted output file");
    assert!(
        !directory_contains(&workdir, marker.as_bytes()),
        "sandbox backing storage exposed plaintext while the child was running"
    );

    let outcome = run.await.unwrap().unwrap();
    assert!(outcome.status().success());
    assert!(!output.exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_persists_a_plain_workspace_without_modifying_the_source() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-plain-workspace-test-{}",
        uuid::Uuid::new_v4()
    ));
    let source = directory.join("source");
    let workdir = directory.join("sandbox");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("input.txt"), b"original\n").unwrap();
    let config = SandboxConfig::new(hook_library())
        .with_workdir(&workdir)
        .with_plain_workspace();
    let create = SandboxCommand::new("/bin/sh")
        .args([
            "-c",
            "test \"$(cat input.txt)\" = original && printf 'plain workspace marker\\n' > output.txt",
        ])
        .current_dir(&source);
    let created = Sandbox::new(config.clone(), NoopCallback)
        .run(create)
        .await
        .unwrap();

    assert!(created.status().success());
    assert_eq!(
        std::fs::read(source.join("input.txt")).unwrap(),
        b"original\n"
    );
    assert!(!source.join("output.txt").exists());
    let persisted = workdir
        .join("fs")
        .join(source.canonicalize().unwrap().strip_prefix("/").unwrap())
        .join("output.txt");
    assert_eq!(
        std::fs::read(&persisted).unwrap(),
        b"plain workspace marker\n"
    );
    let verify = SandboxCommand::new("/bin/sh")
        .args([
            "-c",
            "test \"$(cat input.txt)\" = original && test \"$(cat output.txt)\" = 'plain workspace marker'",
        ])
        .current_dir(&source);
    let verified = Sandbox::new(config, NoopCallback)
        .run(verify)
        .await
        .unwrap();

    assert!(verified.status().success());
    assert!(!source.join("output.txt").exists());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_rejects_concurrent_plain_sandboxes_in_the_same_workdir() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-plain-lock-test-{}",
        uuid::Uuid::new_v4()
    ));
    let source = directory.join("source");
    let workdir = directory.join("sandbox");
    std::fs::create_dir_all(&source).unwrap();
    let config = SandboxConfig::new(hook_library())
        .with_workdir(&workdir)
        .with_plain_workspace();
    let first = tokio::spawn(
        Sandbox::new(config.clone(), NoopCallback).run(
            SandboxCommand::new("/bin/sleep")
                .arg("1")
                .current_dir(&source),
        ),
    );
    let lock = workdir.join("fs/.fs.lock");
    let deadline = Instant::now() + Duration::from_secs(10);
    while !lock.exists() {
        assert!(
            Instant::now() < deadline,
            "plain filesystem lock was not created"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    tokio::time::sleep(Duration::from_millis(20)).await;

    let error = Sandbox::new(config, NoopCallback)
        .run(SandboxCommand::new("/usr/bin/true").current_dir(&source))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("filesystem is already in use"));
    assert!(first.await.unwrap().unwrap().status().success());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_interposes_the_complete_filesystem_operation_set() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-filesystem-hook-test-{}",
        uuid::Uuid::new_v4()
    ));
    let source = directory.join("source");
    let workdir = directory.join("sandbox");
    std::fs::create_dir_all(&source).unwrap();
    std::fs::write(source.join("source.txt"), b"host").unwrap();
    std::fs::set_permissions(
        source.join("source.txt"),
        std::fs::Permissions::from_mode(0o644),
    )
    .unwrap();
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("filesystem_interposed_child_process")
        .arg("--exact")
        .arg("--nocapture")
        .current_dir(&source)
        .env("AGORA_SANDBOX_TEST_FILESYSTEM_CHILD", &source);

    let events = Arc::new(Mutex::new(Vec::<FileEvent>::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event: Event| {
            if let Event::File(event) = event {
                events.lock().unwrap().push(event);
            }
            std::future::ready(Decision::Allow)
        }
    };
    let outcome = Sandbox::new(sandbox_config_in(&workdir), callback)
        .run(command)
        .await
        .unwrap();

    assert!(outcome.status().success());
    let source_path = source.join("source.txt").to_string_lossy().into_owned();
    let source_events = events
        .lock()
        .unwrap()
        .iter()
        .filter(|event| event.file.path == source_path)
        .cloned()
        .collect::<Vec<_>>();
    assert!(source_events.iter().any(|event| {
        event.event_type == EventType::FilesystemOpen
            && event.file.mode.access == FileAccessMode::Read
            && !event.trace_id.is_empty()
    }));
    assert!(source_events.iter().any(|event| {
        event.event_type == EventType::FilesystemClose
            && event.file.mode.access == FileAccessMode::Read
            && !event.trace_id.is_empty()
    }));
    assert_eq!(std::fs::read(source.join("source.txt")).unwrap(), b"host");
    assert_eq!(
        source
            .join("source.txt")
            .metadata()
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o644
    );
    for path in [
        "created.txt",
        "creat.txt",
        "spawn.txt",
        "renamed-at.txt",
        "created-at",
        "created",
    ] {
        assert!(!source.join(path).exists());
    }
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_rejects_a_different_encrypted_workspace_key() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-encrypted-workspace-key-test-{}",
        uuid::Uuid::new_v4()
    ));
    let source = directory.join("source");
    let workdir = directory.join("sandbox");
    std::fs::create_dir_all(&source).unwrap();

    let config = SandboxConfig::new(hook_library())
        .with_workdir(&workdir)
        .with_encrypted_workspace("original passphrase");
    let command = SandboxCommand::new("/usr/bin/true").current_dir(&source);
    assert!(
        Sandbox::new(config, NoopCallback)
            .run(command)
            .await
            .unwrap()
            .status()
            .success()
    );

    let wrong_config = SandboxConfig::new(hook_library())
        .with_workdir(&workdir)
        .with_encrypted_workspace("different passphrase");
    let error = Sandbox::new(wrong_config, NoopCallback)
        .run(SandboxCommand::new("/usr/bin/true").current_dir(&source))
        .await
        .unwrap_err();

    assert!(
        error.to_string().contains("filesystem key is incorrect"),
        "unexpected error: {error:#}"
    );
    assert!(workdir.join("fs/.key.json").is_file());
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
    let Some(expected) = std::env::var_os("AGORA_SANDBOX_TEST_CURRENT_EXE") else {
        return;
    };
    assert_eq!(
        std::env::current_exe().unwrap().canonicalize().unwrap(),
        PathBuf::from(expected).canonicalize().unwrap()
    );
}

#[cfg(target_os = "macos")]
#[test]
fn relocated_executable_spawns_its_sibling_and_preserves_missing_errno() {
    let Some(role) = std::env::var_os("AGORA_SANDBOX_TEST_RELOCATED_SIBLING") else {
        return;
    };
    if role == "sibling" {
        return;
    }
    assert_eq!(role, "primary");

    let missing = Command::new("/missing/agora-executable")
        .status()
        .unwrap_err();
    assert_eq!(missing.raw_os_error(), Some(libc::ENOENT));

    let sibling = std::env::current_exe()
        .unwrap()
        .parent()
        .unwrap()
        .join("sibling");
    let status = Command::new(sibling)
        .arg("relocated_executable_spawns_its_sibling_and_preserves_missing_errno")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_RELOCATED_SIBLING", "sibling")
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(target_os = "macos")]
#[test]
fn process_audit_does_not_reject_a_large_argument() {
    if std::env::var_os("AGORA_SANDBOX_TEST_LARGE_ARGUMENT").is_none() {
        return;
    }
    let status = Command::new("/usr/bin/true")
        .arg("x".repeat(70 * 1024))
        .status()
        .unwrap();
    assert!(status.success());
}

#[cfg(target_os = "macos")]
#[test]
fn records_tls_trust_environment() {
    let Some(private_workdir) = std::env::var_os("AGORA_SANDBOX_TEST_TLS_TRUST_ENV") else {
        return;
    };
    let values = TLS_TRUST_ENVIRONMENT
        .iter()
        .map(|key| PathBuf::from(std::env::var_os(key).unwrap()))
        .collect::<Vec<_>>();
    assert!(values.iter().all(|path| path == &values[0]));
    assert!(values[0].is_file());
    assert!(!values[0].starts_with(private_workdir));
    assert!(
        values[0]
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with("trust-bundle-")
    );
}

#[cfg(target_os = "macos")]
#[test]
fn filesystem_interposed_child_process() {
    let Some(root) = std::env::var_os("AGORA_SANDBOX_TEST_FILESYSTEM_CHILD") else {
        return;
    };
    let root = PathBuf::from(root);
    let source =
        std::ffi::CString::new(root.join("source.txt").as_os_str().as_encoded_bytes()).unwrap();
    let created =
        std::ffi::CString::new(root.join("created").as_os_str().as_encoded_bytes()).unwrap();
    let renamed = std::ffi::CString::new(
        root.join("created/renamed.txt")
            .as_os_str()
            .as_encoded_bytes(),
    )
    .unwrap();
    let creat =
        std::ffi::CString::new(root.join("creat.txt").as_os_str().as_encoded_bytes()).unwrap();
    let spawn =
        std::ffi::CString::new(root.join("spawn.txt").as_os_str().as_encoded_bytes()).unwrap();

    unsafe {
        assert_eq!(libc::access(std::ptr::null(), libc::R_OK), -1);
        assert_eq!(libc::open(std::ptr::null(), libc::O_RDONLY), -1);

        assert_eq!(libc::access(source.as_ptr(), libc::R_OK), 0);
        let mut status = std::mem::MaybeUninit::<libc::stat>::zeroed();
        assert_eq!(libc::stat(std::ptr::null(), status.as_mut_ptr()), -1);
        assert_eq!(libc::lstat(std::ptr::null(), status.as_mut_ptr()), -1);
        assert_eq!(libc::stat(source.as_ptr(), status.as_mut_ptr()), 0);
        assert_eq!(libc::lstat(source.as_ptr(), status.as_mut_ptr()), 0);

        let descriptor = libc::open(source.as_ptr(), libc::O_RDONLY);
        assert!(descriptor >= 0);
        assert_eq!(libc::close(descriptor), 0);

        let root_path = std::ffi::CString::new(root.as_os_str().as_encoded_bytes()).unwrap();
        let directory = libc::open(root_path.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY);
        assert!(directory >= 0);
        assert_eq!(
            libc::fstatat(directory, c"source.txt".as_ptr(), status.as_mut_ptr(), 0),
            0
        );
        let created_file = libc::openat(
            directory,
            c"created.txt".as_ptr(),
            libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC,
            0o600,
        );
        assert!(created_file >= 0);
        assert_eq!(libc::write(created_file, b"created".as_ptr().cast(), 7), 7);
        assert_eq!(libc::ftruncate(created_file, 4), 0);
        assert_eq!(libc::fchmod(created_file, 0o640), 0);
        assert_eq!(libc::fchown(created_file, !0, !0), 0);
        assert_eq!(libc::close(created_file), 0);
        let creat_file = libc::creat(creat.as_ptr(), 0o600);
        assert!(creat_file >= 0);
        assert_eq!(libc::write(creat_file, b"creat".as_ptr().cast(), 5), 5);
        assert_eq!(libc::close(creat_file), 0);
        assert_eq!(libc::truncate(creat.as_ptr(), 2), 0);

        assert_eq!(libc::chmod(source.as_ptr(), 0o600), 0);
        assert_eq!(libc::stat(source.as_ptr(), status.as_mut_ptr()), 0);
        assert_eq!(u32::from((*status.as_ptr()).st_mode) & 0o777, 0o600);
        assert_eq!(libc::chown(source.as_ptr(), !0, !0), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(libc::lchown(source.as_ptr(), !0, !0), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            libc::fchmodat(directory, c"source.txt".as_ptr(), 0o640, 0),
            0
        );
        assert_eq!(libc::stat(source.as_ptr(), status.as_mut_ptr()), 0);
        assert_eq!(u32::from((*status.as_ptr()).st_mode) & 0o777, 0o640);
        assert_eq!(
            libc::fchownat(directory, c"source.txt".as_ptr(), !0, !0, 0),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);

        assert_eq!(libc::mkdirat(directory, c"created-at".as_ptr(), 0o700), 0);
        assert_eq!(
            libc::renameat(
                directory,
                c"created.txt".as_ptr(),
                directory,
                c"renamed-at.txt".as_ptr(),
            ),
            0
        );
        assert_eq!(libc::unlinkat(directory, c"renamed-at.txt".as_ptr(), 0), 0);
        assert_eq!(
            libc::unlinkat(directory, c"created-at".as_ptr(), libc::AT_REMOVEDIR),
            0
        );

        assert_eq!(libc::link(source.as_ptr(), c"hard-link".as_ptr()), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            libc::linkat(
                directory,
                c"source.txt".as_ptr(),
                directory,
                c"hard-link-at".as_ptr(),
                0,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            libc::symlink(c"source.txt".as_ptr(), c"symlink".as_ptr()),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            libc::symlinkat(c"source.txt".as_ptr(), directory, c"symlink-at".as_ptr()),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(libc::clonefile(source.as_ptr(), c"clone".as_ptr(), 0), -1);
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            libc::clonefileat(
                directory,
                c"source.txt".as_ptr(),
                directory,
                c"clone-at".as_ptr(),
                0,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);
        assert_eq!(
            libc::copyfile(
                source.as_ptr(),
                c"copy".as_ptr(),
                std::ptr::null_mut(),
                libc::COPYFILE_DATA,
            ),
            -1
        );
        assert_eq!(*libc::__error(), libc::ENOTSUP);

        let mut actions: libc::posix_spawn_file_actions_t = std::ptr::null_mut();
        assert_eq!(libc::posix_spawn_file_actions_init(&mut actions), 0);
        assert_eq!(
            libc::posix_spawn_file_actions_addopen(
                &mut actions,
                9,
                spawn.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC,
                0o600,
            ),
            libc::ENOTSUP
        );
        let mut child = 0;
        let arguments = [c"/usr/bin/true".as_ptr().cast_mut(), std::ptr::null_mut()];
        assert_eq!(
            libc::posix_spawn(
                &mut child,
                c"/usr/bin/true".as_ptr(),
                &actions,
                std::ptr::null(),
                arguments.as_ptr(),
                std::ptr::null(),
            ),
            0
        );
        let mut child_status = 0;
        assert_eq!(libc::waitpid(child, &mut child_status, 0), child);
        assert_eq!(child_status, 0);
        assert_eq!(libc::posix_spawn_file_actions_destroy(&mut actions), 0);

        assert_eq!(
            libc::openat(-1, c"missing.txt".as_ptr(), libc::O_RDONLY),
            -1
        );
        assert_eq!(
            libc::fstatat(-1, c"missing.txt".as_ptr(), status.as_mut_ptr(), 0),
            -1
        );
        assert_eq!(libc::close(directory), 0);

        assert!(libc::fopen(source.as_ptr(), std::ptr::null()).is_null());
        let stream = libc::fopen(source.as_ptr(), c"r".as_ptr());
        assert!(!stream.is_null());
        assert_eq!(libc::fclose(stream), 0);

        let appended =
            std::ffi::CString::new(root.join("appended.txt").as_os_str().as_encoded_bytes())
                .unwrap();
        let stream = libc::fopen(appended.as_ptr(), c"a+".as_ptr());
        assert!(!stream.is_null());
        assert_eq!(libc::fclose(stream), 0);
        assert_eq!(libc::unlink(appended.as_ptr()), 0);

        assert_eq!(libc::mkdir(created.as_ptr(), 0o700), 0);
        assert_eq!(libc::rename(creat.as_ptr(), renamed.as_ptr()), 0);
        assert_eq!(libc::unlink(renamed.as_ptr()), 0);

        let directory = libc::opendir(root_path.as_ptr());
        assert!(!directory.is_null());
        let mut names = Vec::new();
        loop {
            let entry = libc::readdir(directory);
            if entry.is_null() {
                break;
            }
            names.push(
                std::ffi::CStr::from_ptr((*entry).d_name.as_ptr())
                    .to_bytes()
                    .to_vec(),
            );
        }
        assert!(names.iter().any(|name| name == b"source.txt"));
        assert!(names.iter().any(|name| name == b"created"));
        assert_eq!(libc::closedir(directory), 0);

        assert!(libc::opendir(std::ptr::null()).is_null());
        assert_eq!(libc::mkdir(std::ptr::null(), 0o700), -1);
        assert_eq!(libc::rename(std::ptr::null(), renamed.as_ptr()), -1);
        assert_eq!(libc::unlink(std::ptr::null()), -1);
        assert_eq!(libc::rmdir(std::ptr::null()), -1);
        assert_eq!(libc::chdir(std::ptr::null()), -1);

        assert_eq!(libc::chdir(created.as_ptr()), 0);
        assert!(libc::getcwd(std::ptr::null_mut(), 1).is_null());
        let mut small = [0_i8; 1];
        assert!(libc::getcwd(small.as_mut_ptr(), small.len()).is_null());
        let current = libc::getcwd(std::ptr::null_mut(), 0);
        assert!(!current.is_null());
        assert_eq!(
            std::ffi::CStr::from_ptr(current).to_bytes(),
            created.as_bytes()
        );
        libc::free(current.cast());
        assert_eq!(libc::chdir(root_path.as_ptr()), 0);
        assert_eq!(libc::rmdir(created.as_ptr()), 0);
    }

    exercise_interposed_process_symbols();
}

#[cfg(target_os = "macos")]
fn exercise_interposed_process_symbols() {
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
    type ExecvFn =
        unsafe extern "C" fn(*const libc::c_char, *const *const libc::c_char) -> libc::c_int;

    unsafe fn symbol(name: &std::ffi::CStr) -> *mut libc::c_void {
        let symbol = unsafe { libc::dlsym(libc::RTLD_DEFAULT, name.as_ptr()) };
        assert!(!symbol.is_null(), "missing interposed symbol {name:?}");
        symbol
    }

    let true_path = c"/usr/bin/true";
    let true_name = c"true";
    let mut direct_arguments = [true_path.as_ptr().cast_mut(), std::ptr::null_mut()];
    let mut searched_arguments = [true_name.as_ptr().cast_mut(), std::ptr::null_mut()];

    for (name, executable, arguments) in [
        (
            c"agora_sandbox_posix_spawn",
            true_path,
            direct_arguments.as_mut_ptr(),
        ),
        (
            c"agora_sandbox_posix_spawnp",
            true_name,
            searched_arguments.as_mut_ptr(),
        ),
    ] {
        let spawn = unsafe { std::mem::transmute::<*mut libc::c_void, PosixSpawnFn>(symbol(name)) };
        let mut pid = 0;
        assert_eq!(
            unsafe {
                spawn(
                    &mut pid,
                    executable.as_ptr(),
                    std::ptr::null(),
                    std::ptr::null(),
                    arguments,
                    std::ptr::null(),
                )
            },
            0
        );
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(pid, &mut status, 0) }, pid);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
    }

    for operation in ["execve", "execv", "execvp"] {
        let child = unsafe { libc::fork() };
        assert!(child >= 0);
        if child == 0 {
            let result = match operation {
                "execve" => {
                    let exec = unsafe {
                        std::mem::transmute::<*mut libc::c_void, ExecveFn>(symbol(
                            c"agora_sandbox_execve",
                        ))
                    };
                    let arguments = [true_path.as_ptr(), std::ptr::null()];
                    let environment = unsafe { *libc::_NSGetEnviron() };
                    unsafe { exec(true_path.as_ptr(), arguments.as_ptr(), environment.cast()) }
                }
                "execv" => {
                    let exec = unsafe {
                        std::mem::transmute::<*mut libc::c_void, ExecvFn>(symbol(
                            c"agora_sandbox_execv",
                        ))
                    };
                    let arguments = [true_path.as_ptr(), std::ptr::null()];
                    unsafe { exec(true_path.as_ptr(), arguments.as_ptr()) }
                }
                "execvp" => {
                    let exec = unsafe {
                        std::mem::transmute::<*mut libc::c_void, ExecvFn>(symbol(
                            c"agora_sandbox_execvp",
                        ))
                    };
                    let arguments = [true_name.as_ptr(), std::ptr::null()];
                    unsafe { exec(true_name.as_ptr(), arguments.as_ptr()) }
                }
                _ => unreachable!(),
            };
            unsafe { libc::_exit(if result == -1 { 126 } else { 127 }) };
        }
        let mut status = 0;
        assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
        assert!(libc::WIFEXITED(status));
        assert_eq!(libc::WEXITSTATUS(status), 0);
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

    let destination = destination.to_string().parse::<SocketAddrV4>().unwrap();
    let datagram = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    datagram.connect(destination).unwrap();

    let address = libc::sockaddr_in {
        sin_len: std::mem::size_of::<libc::sockaddr_in>() as u8,
        sin_family: libc::AF_INET as u8,
        sin_port: destination.port().to_be(),
        sin_addr: libc::in_addr {
            s_addr: u32::from_ne_bytes(destination.ip().octets()),
        },
        sin_zero: [0; 8],
    };
    assert_eq!(
        unsafe {
            libc::connect(
                -1,
                std::ptr::addr_of!(address).cast(),
                std::mem::size_of_val(&address) as libc::socklen_t,
            )
        },
        -1
    );

    let socket = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    assert!(socket >= 0);
    let endpoints = TestSocketEndpoints {
        source_interface: 0,
        source_address: std::ptr::null(),
        source_address_length: 0,
        destination_address: std::ptr::addr_of!(address).cast(),
        destination_address_length: std::mem::size_of_val(&address) as libc::socklen_t,
    };
    assert_eq!(
        unsafe {
            connectx(
                socket,
                std::ptr::addr_of!(endpoints),
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        0
    );
    unsafe { libc::close(socket) };
    assert_eq!(
        unsafe {
            connectx(
                -1,
                std::ptr::addr_of!(endpoints),
                0,
                0,
                std::ptr::null(),
                0,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
            )
        },
        -1
    );
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
        move |event: Event| {
            if let Some(event) = event.into_network() {
                events.lock().unwrap().push(event);
            }
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
    let source = std::env::current_exe().unwrap().canonicalize().unwrap();
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("records_current_executable")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_CURRENT_EXE", &source);
    let config = sandbox_config_in(&workdir);

    let outcome = Sandbox::new(config.clone(), NoopCallback)
        .run(command)
        .await
        .unwrap();

    assert!(outcome.status().success());
    let cached = workdir
        .join("fs")
        .join(source.strip_prefix(Path::new("/")).unwrap());
    assert!(!cached.exists());

    let second = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("records_current_executable")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_CURRENT_EXE", &source);
    let outcome = Sandbox::new(config, NoopCallback)
        .run(second)
        .await
        .unwrap();
    assert!(outcome.status().success());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_prepares_a_relocated_executable_sibling_on_demand() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-sibling-test-{}",
        uuid::Uuid::new_v4()
    ));
    let source_directory = directory.join("source");
    let workdir = directory.join("cache");
    std::fs::create_dir_all(&source_directory).unwrap();
    let primary = source_directory.join("primary");
    let sibling = source_directory.join("sibling");
    for executable in [&primary, &sibling] {
        std::fs::copy(std::env::current_exe().unwrap(), executable).unwrap();
        let output = Command::new("/usr/bin/codesign")
            .args([
                "--force",
                "--sign",
                "-",
                "--options",
                "runtime",
                "--timestamp=none",
            ])
            .arg(executable)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "codesign failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let command = SandboxCommand::new(&primary)
        .arg("relocated_executable_spawns_its_sibling_and_preserves_missing_errno")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_RELOCATED_SIBLING", "primary");
    let config = sandbox_config_in(&workdir);

    let outcome = Sandbox::new(config, NoopCallback)
        .run(command)
        .await
        .unwrap();

    assert!(outcome.status().success());
    std::fs::remove_dir_all(directory).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn runner_truncates_large_process_audit_without_rejecting_the_command() {
    let directory = std::env::temp_dir().join(format!(
        "agora-sandbox-large-argument-test-{}",
        uuid::Uuid::new_v4()
    ));
    let command = SandboxCommand::new(std::env::current_exe().unwrap())
        .arg("process_audit_does_not_reject_a_large_argument")
        .arg("--exact")
        .arg("--nocapture")
        .env("AGORA_SANDBOX_TEST_LARGE_ARGUMENT", "1");
    let config = sandbox_config_in(directory.join("cache"));

    let outcome = Sandbox::new(config, NoopCallback)
        .run(command)
        .await
        .unwrap();

    assert!(outcome.status().success());
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
        b"#!/usr/bin/env sh\ncase \"$1:$DYLD_INSERT_LIBRARIES\" in direct:*libagora_sandbox.dylib*|nested:*libagora_sandbox.dylib*) exit 0 ;; *) exit 9 ;; esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
    let config = sandbox_config_in(&workdir);

    let direct = Sandbox::new(config.clone(), NoopCallback)
        .run(SandboxCommand::new(&script).arg("direct"))
        .await
        .unwrap();

    assert!(direct.status().success());

    let command = format!("{} nested", script.display());
    let nested = Sandbox::new(config, NoopCallback)
        .run(SandboxCommand::new("/bin/bash").args(["-c", &command]))
        .await
        .unwrap();

    assert!(nested.status().success());
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
    let private_workdir = config.workdir().to_path_buf();
    let script = format!(
        "AGORA_SANDBOX_TEST_TLS_TRUST_ENV='{}' '{}' \
         records_tls_trust_environment --exact --nocapture",
        private_workdir.display(),
        std::env::current_exe().unwrap().display()
    );
    let command = SandboxCommand::new("/bin/bash").args(["-c", &script]);

    let outcome = Sandbox::new(config, NoopCallback)
        .run(command)
        .await
        .unwrap();

    assert!(outcome.status().success());
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
        move |event: Event| {
            if let Some(event) = event.into_network() {
                events.lock().unwrap().push(event);
            }
            std::future::ready(Decision::Allow)
        }
    };
    let script = format!(
        "/usr/bin/curl \
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
    let marker = format!("agora-background-{}", uuid::Uuid::new_v4());
    let script = format!("/bin/sh -c '/bin/sleep 30' {marker} &");

    let outcome = Sandbox::new(sandbox_config(), NoopCallback)
        .run(SandboxCommand::new("/bin/bash").args(["-c", &script]))
        .await
        .unwrap();

    assert!(outcome.status().success());
    assert!(
        !Command::new("/usr/bin/pgrep")
            .args(["-f", marker.as_str()])
            .status()
            .unwrap()
            .success(),
        "sandbox background process still exists"
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
        move |event: Event| {
            if let Some(event) = event.into_network() {
                events.lock().unwrap().push(event);
            }
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
    let callback = |event: Event| async move {
        if event
            .as_network()
            .is_some_and(|event| event.event_type == EventType::NetworkConnectAttempt)
        {
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
