use super::{
    FilesystemMode, Sandbox, SandboxCommand, SandboxConfig, SandboxOutcome, SecretBytes,
    process_group_exists, signal_process_group, terminate_process_group, wait_for_child_or_service,
};
use crate::audit::AuditController;
use crate::callback::{Decision, Event, EventType, NoopCallback, TlsOutcome};
use crate::execution::ExecutionController;
#[cfg(target_os = "macos")]
use crate::filesystem::EncryptedWorkspace;
use crate::network::{NetworkConfig, NetworkController, NetworkRunContext, TlsMode};
use std::ffi::OsStr;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "current_thread")]
async fn filesystem_blocking_runs_on_a_blocking_worker() {
    let caller = std::thread::current().id();

    let worker = super::filesystem_blocking(|| Ok::<_, anyhow::Error>(std::thread::current().id()))
        .await
        .unwrap();

    assert_ne!(worker, caller);
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "current_thread")]
async fn filesystem_key_migration_reports_progress_on_the_runtime_thread() {
    let workdir = std::env::temp_dir().join(format!(
        "agora-runner-key-migration-{}",
        uuid::Uuid::new_v4()
    ));
    drop(EncryptedWorkspace::start(&workdir, b"old-key").unwrap());
    let runtime_thread = std::thread::current().id();
    let stages = std::rc::Rc::new(std::cell::RefCell::new(Vec::new()));
    let observed = std::rc::Rc::clone(&stages);

    super::migrate_filesystem_key_with_progress(&workdir, b"old-key", b"new-key", |stage| {
        assert_eq!(std::thread::current().id(), runtime_thread);
        observed.borrow_mut().push(stage);
    })
    .await
    .unwrap();

    assert_eq!(
        stages.borrow().last(),
        Some(&super::FilesystemKeyMigrationProgress::Completed)
    );
    std::fs::remove_dir_all(workdir).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "current_thread")]
async fn filesystem_key_migration_runs_without_a_progress_callback() {
    let workdir = std::env::temp_dir().join(format!(
        "agora-runner-key-migration-simple-{}",
        uuid::Uuid::new_v4()
    ));
    drop(EncryptedWorkspace::start(&workdir, b"old-key").unwrap());

    super::migrate_filesystem_key(&workdir, b"old-key", b"new-key")
        .await
        .unwrap();

    drop(EncryptedWorkspace::start(&workdir, b"new-key").unwrap());
    std::fs::remove_dir_all(workdir).unwrap();
}

fn sleeping_child() -> tokio::process::Child {
    let mut command = tokio::process::Command::new("/bin/sleep");
    command.arg("30").kill_on_drop(true);
    command.as_std_mut().process_group(0);
    command.spawn().unwrap()
}

#[cfg(target_os = "macos")]
fn built_hook_library() -> PathBuf {
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
        let workspace = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap();
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
        let status = std::process::Command::new(env!("CARGO"))
            .args(["build", "-p", "agora-sandbox", "--lib", "--target-dir"])
            .arg(&target)
            .current_dir(workspace)
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
async fn local_https_origin(
    identity: &str,
) -> (
    std::net::SocketAddr,
    rustls::pki_types::CertificateDer<'static>,
    tokio::task::JoinHandle<()>,
) {
    use rcgen::{
        BasicConstraints, CertificateParams, CertifiedIssuer, ExtendedKeyUsagePurpose, IsCa,
        KeyPair, KeyUsagePurpose,
    };
    use rustls::ServerConfig;
    use rustls::pki_types::PrivatePkcs8KeyDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_rustls::TlsAcceptor;

    let root_key = KeyPair::generate().unwrap();
    let mut root_params = CertificateParams::new(vec!["Agora Origin Test CA".to_string()]).unwrap();
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.key_usages = vec![
        KeyUsagePurpose::KeyCertSign,
        KeyUsagePurpose::CrlSign,
        KeyUsagePurpose::DigitalSignature,
    ];
    let issuer = CertifiedIssuer::self_signed(root_params, root_key).unwrap();
    let origin_root = issuer.der().clone();
    let server_key = KeyPair::generate().unwrap();
    let mut server_params = CertificateParams::new(vec![identity.to_string()]).unwrap();
    server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let server_certificate = server_params.signed_by(&server_key, &issuer).unwrap();
    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![server_certificate.der().clone(), origin_root.clone()],
            PrivatePkcs8KeyDer::from(server_key.serialize_der()).into(),
        )
        .unwrap();
    server_config.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(server_config));
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap();
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut stream = acceptor.accept(stream).await.unwrap();
        let mut request = Vec::new();
        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
            let mut bytes = [0_u8; 1024];
            let read = stream.read(&mut bytes).await.unwrap();
            assert_ne!(read, 0);
            request.extend_from_slice(&bytes[..read]);
        }
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
            .await
            .unwrap();
        stream.shutdown().await.unwrap();
    });
    (address, origin_root, task)
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn system_curl_completes_the_transparent_tls_chain() {
    let identity = "origin.agora.test";
    let (origin, origin_root, origin_task) = local_https_origin(identity).await;
    let root = std::env::temp_dir().join(format!("agora-curl-tls-{}", uuid::Uuid::new_v4()));
    let source = root.join("source");
    let workdir = root.join("sandbox");
    std::fs::create_dir_all(&source).unwrap();
    let output = source.join("response.txt");
    let events = Arc::new(Mutex::new(Vec::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| {
            events.lock().unwrap().push(event);
            std::future::ready(Decision::Allow)
        }
    };
    let mut config = SandboxConfig::new(built_hook_library())
        .with_workdir(&workdir)
        .with_encrypted_workspace("test-filesystem-key")
        .with_upstream_tls_roots(vec![origin_root]);
    config.network.tls = TlsMode::Auto;
    let url = format!("https://{identity}:{}/", origin.port());
    let resolve = format!("{identity}:{}:127.0.0.1", origin.port());
    let script = format!(
        "/usr/bin/curl --silent --show-error --fail --connect-timeout 5 --max-time 10 --resolve {resolve} {url} --output {}",
        output.display()
    );
    let command = SandboxCommand::new("/bin/bash").args(["-c", script.as_str()]);

    let outcome = tokio::time::timeout(
        Duration::from_secs(60),
        Sandbox::new(config, callback).run(command),
    )
    .await
    .unwrap()
    .unwrap();

    assert!(
        outcome.status().success(),
        "curl exited with {:?}; events: {:#?}",
        outcome.status().code(),
        events.lock().unwrap()
    );
    tokio::time::timeout(Duration::from_secs(2), origin_task)
        .await
        .unwrap()
        .unwrap();
    assert!(
        !output.exists(),
        "sandbox output unexpectedly changed the host filesystem"
    );

    let events = events.lock().unwrap();
    let process = events
        .iter()
        .find_map(|event| match event {
            Event::Process(event) if event.command.executable == "/usr/bin/curl" => Some(event),
            Event::Network(_) | Event::Process(_) | Event::File(_) => None,
        })
        .expect("curl process event");
    let established = events
        .iter()
        .find_map(|event| match event {
            Event::Network(event)
                if event.event_type == EventType::NetworkConnectEstablished
                    && event
                        .network
                        .as_ref()
                        .is_some_and(|network| network.destination_port == origin.port()) =>
            {
                Some(event)
            }
            Event::Network(_) | Event::Process(_) | Event::File(_) => None,
        })
        .expect("curl TLS connection event");
    assert_eq!(process.trace_id, established.trace_id);
    assert!(process.trace_id.split(',').count() >= 2);
    assert_eq!(
        established.tls.as_ref().map(|tls| tls.outcome),
        Some(TlsOutcome::Terminated)
    );
    assert_eq!(
        established
            .network
            .as_ref()
            .and_then(|network| network.domain.as_deref()),
        Some(identity)
    );
    drop(events);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn encrypted_overlay_preserves_the_host_while_the_child_uses_cow_and_whiteouts() {
    let root = std::env::temp_dir().join(format!("agora-overlay-run-{}", uuid::Uuid::new_v4()));
    let source = root.join("source");
    let workdir = root.join("sandbox");
    std::fs::create_dir_all(&source).unwrap();
    let existing = source.join("existing");
    let removed = source.join("removed");
    let created = source.join("created");
    let directory = source.join("directory");
    std::fs::write(&existing, b"host").unwrap();
    std::fs::write(&removed, b"host removed").unwrap();
    let script = format!(
        "set -eu; test \"$(cat '{existing}')\" = host; printf sandbox > '{existing}'; test \"$(cat '{existing}')\" = sandbox; printf created > '{created}'; test \"$(cat '{created}')\" = created; rm '{removed}'; test ! -e '{removed}'; mkdir '{directory}'; printf nested > '{directory}/nested'; test \"$(cat '{directory}/nested')\" = nested",
        existing = existing.display(),
        created = created.display(),
        removed = removed.display(),
        directory = directory.display(),
    );
    let events = Arc::new(Mutex::new(Vec::new()));
    let callback = {
        let events = Arc::clone(&events);
        move |event| {
            events.lock().unwrap().push(event);
            std::future::ready(Decision::Allow)
        }
    };
    let config = SandboxConfig::new(built_hook_library())
        .with_workdir(&workdir)
        .with_encrypted_workspace("test-filesystem-key");
    let outcome = Sandbox::new(config, callback)
        .run(SandboxCommand::new("/bin/bash").args(["-c", script.as_str()]))
        .await
        .unwrap();

    assert!(
        outcome.status().success(),
        "sandbox child exited with {}",
        outcome.status()
    );
    assert_eq!(std::fs::read(&existing).unwrap(), b"host");
    assert_eq!(std::fs::read(&removed).unwrap(), b"host removed");
    assert!(!created.exists());
    assert!(!directory.exists());
    let events = events.lock().unwrap();
    let file_events = events
        .iter()
        .filter_map(|event| match event {
            Event::File(event) if event.file.path == existing.to_string_lossy() => Some(event),
            Event::Network(_) | Event::Process(_) | Event::File(_) => None,
        })
        .collect::<Vec<_>>();
    assert!(
        file_events
            .iter()
            .any(|event| event.event_type == EventType::FilesystemOpen)
    );
    assert!(
        file_events
            .iter()
            .any(|event| event.event_type == EventType::FilesystemClose)
    );
    drop(events);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn tls_interception_starts_with_native_upstream_roots() {
    let root =
        std::env::temp_dir().join(format!("agora-native-tls-roots-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let mut config = SandboxConfig::new(built_hook_library())
        .with_workdir(&root)
        .with_encrypted_workspace("test-filesystem-key");
    config.network.tls = TlsMode::Auto;

    let outcome = Sandbox::new(config, NoopCallback)
        .run(SandboxCommand::new("/usr/bin/true"))
        .await
        .unwrap();

    assert!(outcome.status().success());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn test_upstream_roots_require_tls_interception() {
    let root =
        std::env::temp_dir().join(format!("agora-roots-without-tls-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let config = SandboxConfig::new(built_hook_library())
        .with_workdir(&root)
        .with_encrypted_workspace("test-filesystem-key")
        .with_upstream_tls_roots(Vec::new());

    let error = Sandbox::new(config, NoopCallback)
        .run(SandboxCommand::new("/usr/bin/true"))
        .await
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("test upstream TLS roots require TLS interception")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sandbox_outcome_exposes_status_and_identifiers() {
    let status = std::process::Command::new("/usr/bin/true")
        .status()
        .unwrap();
    let outcome = SandboxOutcome {
        status,
        sandbox_id: "sandbox-id".to_string(),
        run_id: "run-id".to_string(),
    };

    assert!(outcome.status().success());
    assert_eq!(outcome.sandbox_id(), "sandbox-id");
    assert_eq!(outcome.run_id(), "run-id");
}

#[test]
fn sandbox_config_and_command_builders_preserve_runtime_inputs() {
    let missing_hook = std::env::temp_dir().join("agora-missing-hook.dylib");
    let config = SandboxConfig::new(&missing_hook);
    assert_eq!(config.hook_library(), missing_hook);
    let expected_workdir = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
        .join(".agora-sandbox");
    assert_eq!(config.workdir(), expected_workdir);
    assert_eq!(
        config.clone().with_workdir("/tmp/agora-cache").workdir(),
        Path::new("/tmp/agora-cache")
    );
    assert_eq!(config.tls_ca(), None);
    assert_eq!(config.filesystem_mode(), FilesystemMode::Plain);
    let encrypted = config.clone().with_encrypted_workspace("top secret");
    assert_eq!(
        encrypted.encrypted_workspace_key(),
        Some(b"top secret".as_slice())
    );
    assert!(!format!("{encrypted:?}").contains("top secret"));
    let plain = encrypted.with_plain_workspace();
    assert_eq!(plain.filesystem_mode(), FilesystemMode::Plain);
    assert_eq!(plain.encrypted_workspace_key(), None);
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("hook library does not exist")
    );

    let command = SandboxCommand::new("sh")
        .arg("-c")
        .args(["printf", "ok"])
        .env("KEY", "value")
        .current_dir("/tmp");
    assert_eq!(command.program, "sh");
    assert_eq!(command.arguments, ["-c", "printf", "ok"]);
    assert_eq!(command.environment.get(OsStr::new("KEY")).unwrap(), "value");
    assert_eq!(command.current_dir.as_deref(), Some(Path::new("/tmp")));
    assert_eq!(
        command.clone().into_command().as_std().get_current_dir(),
        Some(Path::new("/tmp"))
    );
    assert_eq!(
        SandboxCommand::from(OsStr::new("/bin/sh")).program,
        "/bin/sh"
    );
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_config_defaults_to_plain_without_a_filesystem_key() {
    let root = std::env::temp_dir().join(format!(
        "agora-required-filesystem-key-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    std::fs::write(&hook, b"hook").unwrap();

    let config = SandboxConfig::new(&hook);

    assert!(config.validate().is_ok());
    assert_eq!(config.filesystem_mode(), FilesystemMode::Plain);
    assert_eq!(config.encrypted_workspace_key(), None);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_config_allows_an_explicit_plain_workspace_without_a_key() {
    let root = std::env::temp_dir().join(format!(
        "agora-plain-filesystem-config-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    std::fs::write(&hook, b"hook").unwrap();

    let config = SandboxConfig::new(&hook).with_plain_workspace();

    assert!(config.validate().is_ok());
    assert_eq!(config.filesystem_mode(), FilesystemMode::Plain);
    assert_eq!(config.encrypted_workspace_key(), None);
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn sandbox_config_rejects_an_encrypted_key_in_plain_mode() {
    let root = std::env::temp_dir().join(format!(
        "agora-plain-filesystem-key-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    std::fs::write(&hook, b"hook").unwrap();
    let mut config = SandboxConfig::new(&hook).with_plain_workspace();
    config.encrypted_workspace_key = Some(SecretBytes::new("unexpected"));

    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("cannot be used with plain filesystem mode")
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn command_workdir_resolution_and_disabled_tls_defaults_are_explicit() {
    let current = std::env::current_dir().unwrap().canonicalize().unwrap();
    assert_eq!(
        SandboxCommand::new("/bin/true")
            .effective_current_dir()
            .unwrap(),
        current
    );
    assert_eq!(
        SandboxCommand::new("/bin/true")
            .current_dir(".")
            .effective_current_dir()
            .unwrap(),
        current
    );

    let root = std::env::temp_dir().join(format!("agora-workdir-{}", uuid::Uuid::new_v4()));
    assert!(
        SandboxCommand::new("/bin/true")
            .current_dir(&root)
            .effective_current_dir()
            .unwrap_err()
            .to_string()
            .contains("failed to resolve sandbox command workdir")
    );
    std::fs::create_dir_all(&root).unwrap();
    let file = root.join("not-a-directory");
    std::fs::write(&file, b"file").unwrap();
    assert!(
        SandboxCommand::new("/bin/true")
            .current_dir(&file)
            .effective_current_dir()
            .unwrap_err()
            .to_string()
            .contains("not a directory")
    );

    let config = SandboxConfig::new(root.join("unused-hook"));
    assert!(config.tls_ca_for_workdir().unwrap().is_none());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sandbox_config_allows_default_tls_ca_for_interception() {
    let root = std::env::temp_dir().join(format!("agora-missing-ca-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    std::fs::write(&hook, b"hook").unwrap();
    let mut config = SandboxConfig::new(&hook).with_encrypted_workspace("test-key");
    config.network.tls = TlsMode::Auto;

    assert!(config.validate().is_ok());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn configured_tls_ca_reuses_a_complete_pair_and_replaces_a_partial_pair() {
    let root =
        std::env::temp_dir().join(format!("agora-missing-ca-files-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    let certificate = root.join("ca.pem");
    let private_key = root.join("ca-key.pem");
    std::fs::write(&hook, b"hook").unwrap();
    let mut config = SandboxConfig::new(&hook)
        .with_encrypted_workspace("test-key")
        .with_tls_ca(&certificate, &private_key);
    config.network.tls = TlsMode::Auto;

    assert!(config.validate().is_ok());
    let first = config.tls_ca_for_workdir().unwrap().unwrap();
    let first_certificate = std::fs::read(&first.certificate).unwrap();
    let first_private_key = std::fs::read(&first.private_key).unwrap();
    assert!(first_certificate.starts_with(b"-----BEGIN CERTIFICATE-----"));
    assert!(first_private_key.starts_with(b"-----BEGIN PRIVATE KEY-----"));

    let reused = config.tls_ca_for_workdir().unwrap().unwrap();
    assert_eq!(
        std::fs::read(&reused.certificate).unwrap(),
        first_certificate
    );
    assert_eq!(
        std::fs::read(&reused.private_key).unwrap(),
        first_private_key
    );

    std::fs::remove_file(&reused.private_key).unwrap();
    let replaced = config.tls_ca_for_workdir().unwrap().unwrap();
    assert_ne!(
        std::fs::read(&replaced.certificate).unwrap(),
        first_certificate
    );
    assert_ne!(
        std::fs::read(&replaced.private_key).unwrap(),
        first_private_key
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn sandbox_config_preserves_tls_ca_paths() {
    let root = std::env::temp_dir().join(format!("agora-tls-ca-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    let certificate = root.join("ca.pem");
    let private_key = root.join("ca-key.pem");
    std::fs::write(&hook, b"hook").unwrap();
    std::fs::write(&certificate, b"certificate").unwrap();
    std::fs::write(&private_key, b"private key").unwrap();
    let mut config = SandboxConfig::new(&hook)
        .with_encrypted_workspace("test-key")
        .with_tls_ca(&certificate, &private_key);
    config.network.tls = TlsMode::Auto;

    assert_eq!(
        config.tls_ca(),
        Some((certificate.as_path(), private_key.as_path()))
    );
    assert!(config.validate().is_ok());
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn default_tls_ca_reuses_a_complete_pair_and_replaces_a_partial_pair() {
    let root = std::env::temp_dir().join(format!("agora-default-ca-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    std::fs::write(&hook, b"hook").unwrap();
    let mut config = SandboxConfig::new(&hook).with_workdir(&root);
    config.network.tls = TlsMode::Auto;

    let first = config.tls_ca_for_workdir().unwrap().unwrap();
    assert_eq!(first.certificate, root.join("ca/ca.crt"));
    assert_eq!(first.private_key, root.join("ca/ca.key"));
    let first_certificate = std::fs::read(&first.certificate).unwrap();
    let first_private_key = std::fs::read(&first.private_key).unwrap();

    let reused = config.tls_ca_for_workdir().unwrap().unwrap();
    assert_eq!(
        std::fs::read(&reused.certificate).unwrap(),
        first_certificate
    );
    assert_eq!(
        std::fs::read(&reused.private_key).unwrap(),
        first_private_key
    );

    std::fs::remove_file(&reused.private_key).unwrap();
    let replaced = config.tls_ca_for_workdir().unwrap().unwrap();
    assert_ne!(
        std::fs::read(&replaced.certificate).unwrap(),
        first_certificate
    );
    assert_ne!(
        std::fs::read(&replaced.private_key).unwrap(),
        first_private_key
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn tls_trust_bundles_are_stable_per_ca_and_isolated_between_cas() {
    let root = std::env::temp_dir().join(format!("agora-trust-bundle-{}", uuid::Uuid::new_v4()));
    let config = SandboxConfig::new(root.join("hook.dylib")).with_workdir(&root);

    let first = config.write_tls_trust_bundle(&root, b"first CA").unwrap();
    let reused = config.write_tls_trust_bundle(&root, b"first CA").unwrap();
    let second = config.write_tls_trust_bundle(&root, b"second CA").unwrap();

    assert_eq!(first, reused);
    assert_ne!(first, second);
    assert!(first.is_file());
    assert!(second.is_file());
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "macos")]
#[test]
fn tls_trust_bundle_reports_directory_and_write_failures() {
    use std::os::unix::fs::PermissionsExt;

    let root = std::env::temp_dir().join(format!("agora-trust-errors-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join("ca"), b"not a directory").unwrap();
    let config = SandboxConfig::new(root.join("hook.dylib")).with_workdir(&root);

    assert!(
        config
            .write_tls_trust_bundle(&root, b"CA")
            .unwrap_err()
            .to_string()
            .contains("failed to create TLS client trust bundle directory")
    );

    std::fs::remove_file(root.join("ca")).unwrap();
    std::fs::create_dir(root.join("ca")).unwrap();
    std::fs::set_permissions(root.join("ca"), std::fs::Permissions::from_mode(0o500)).unwrap();
    assert!(
        config
            .write_tls_trust_bundle(&root, b"CA")
            .unwrap_err()
            .to_string()
            .contains("failed to write TLS client trust bundle")
    );
    std::fs::set_permissions(root.join("ca"), std::fs::Permissions::from_mode(0o700)).unwrap();
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn process_group_helpers_treat_a_missing_group_as_already_stopped() {
    let missing = libc::pid_t::MAX;
    assert!(!process_group_exists(missing).unwrap());
    signal_process_group(missing, libc::SIGTERM).unwrap();
    assert!(process_group_exists(0).unwrap());
    assert!(signal_process_group(0, libc::c_int::MAX).is_err());
    assert!(process_group_exists(-1).unwrap());
}

#[tokio::test]
async fn proxy_failure_terminates_the_child_process() {
    let workdir = std::env::temp_dir().join(format!(
        "agora-proxy-failure-cache-{}",
        uuid::Uuid::new_v4()
    ));
    let mut controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox", "run"),
        NoopCallback,
    )
    .await
    .unwrap();
    let mut child = sleeping_child();
    let mut execution = ExecutionController::start(workdir.clone()).await.unwrap();
    let mut audit = AuditController::start(
        "sandbox".to_string(),
        "run".to_string(),
        NoopCallback,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    controller.abort_listener_for_test();
    let process_group = child.id().unwrap() as libc::pid_t;

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        wait_for_child_or_service(
            &mut child,
            process_group,
            &mut controller,
            &mut execution,
            &mut audit,
        ),
    )
    .await
    .unwrap();

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("sandbox network proxy failed")
    );
    assert!(child.try_wait().unwrap().is_some());
    controller.shutdown().await.unwrap();
    execution.shutdown().await.unwrap();
    audit.shutdown().await.unwrap();
    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn execution_controller_failure_terminates_the_child_process() {
    let workdir = std::env::temp_dir().join(format!(
        "agora-execution-failure-cache-{}",
        uuid::Uuid::new_v4()
    ));
    let mut controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox", "run"),
        NoopCallback,
    )
    .await
    .unwrap();
    let mut child = sleeping_child();
    let mut execution = ExecutionController::start(workdir.clone()).await.unwrap();
    let mut audit = AuditController::start(
        "sandbox".to_string(),
        "run".to_string(),
        NoopCallback,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    execution.abort_server_for_test();
    let process_group = child.id().unwrap() as libc::pid_t;

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        wait_for_child_or_service(
            &mut child,
            process_group,
            &mut controller,
            &mut execution,
            &mut audit,
        ),
    )
    .await
    .unwrap();

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("sandbox execution controller failed")
    );
    assert!(child.try_wait().unwrap().is_some());
    controller.shutdown().await.unwrap();
    assert!(execution.shutdown().await.is_ok());
    audit.shutdown().await.unwrap();
    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn audit_controller_failure_terminates_the_child_process() {
    let workdir = std::env::temp_dir().join(format!(
        "agora-audit-failure-cache-{}",
        uuid::Uuid::new_v4()
    ));
    let mut controller = NetworkController::start(
        NetworkConfig::default(),
        NetworkRunContext::new("sandbox", "run"),
        NoopCallback,
    )
    .await
    .unwrap();
    let mut child = sleeping_child();
    let mut execution = ExecutionController::start(workdir.clone()).await.unwrap();
    let mut audit = AuditController::start(
        "sandbox".to_string(),
        "run".to_string(),
        NoopCallback,
        Duration::from_secs(1),
    )
    .await
    .unwrap();
    audit.abort_server_for_test();
    let process_group = child.id().unwrap() as libc::pid_t;

    let result = tokio::time::timeout(
        Duration::from_secs(1),
        wait_for_child_or_service(
            &mut child,
            process_group,
            &mut controller,
            &mut execution,
            &mut audit,
        ),
    )
    .await
    .unwrap();

    assert!(
        result
            .unwrap_err()
            .to_string()
            .contains("sandbox audit controller failed")
    );
    assert!(child.try_wait().unwrap().is_some());
    controller.shutdown().await.unwrap();
    execution.shutdown().await.unwrap();
    assert!(audit.shutdown().await.is_ok());
    std::fs::remove_dir_all(workdir).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn child_spawn_failure_shuts_down_started_services() {
    let root = std::env::temp_dir().join(format!(
        "agora-child-spawn-failure-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&root).unwrap();
    let hook = root.join("hook.dylib");
    std::fs::write(&hook, b"hook").unwrap();
    let config = SandboxConfig::new(&hook)
        .with_workdir(&root)
        .with_plain_workspace();
    let invalid_argument = std::ffi::OsString::from_vec(b"invalid\0argument".to_vec());

    let error = Sandbox::new(config, NoopCallback)
        .run(SandboxCommand::new("/usr/bin/true").arg(invalid_argument))
        .await
        .unwrap_err();

    assert!(error.to_string().contains("failed to start sandbox child"));
    std::fs::remove_dir_all(root).unwrap();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn termination_kills_a_process_group_that_ignores_sigterm() {
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .args(["-c", "trap '' TERM; while :; do :; done"])
        .kill_on_drop(true);
    command.as_std_mut().process_group(0);
    let mut child = command.spawn().unwrap();
    let process_group = child.id().unwrap() as libc::pid_t;
    assert_eq!(unsafe { libc::getpgid(process_group) }, process_group);
    tokio::time::sleep(Duration::from_millis(50)).await;

    terminate_process_group(&mut child, process_group)
        .await
        .unwrap();

    assert!(child.try_wait().unwrap().is_some());
    assert!(!process_group_exists(process_group).unwrap());
}
