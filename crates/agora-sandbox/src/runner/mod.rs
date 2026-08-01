use crate::callback::Callback;
#[cfg(target_os = "macos")]
use crate::execution::{ExecutionController, resolve_executable, resolve_shebang};
#[cfg(target_os = "macos")]
use crate::filesystem::EncryptedWorkspace;
use crate::network::{NetworkConfig, NetworkController, NetworkRunContext, TlsMode};
use crate::trace::{TRACE_ID_ENVIRONMENT, TraceContext};
use anyhow::{Context, Result, bail};
#[cfg(target_os = "macos")]
use base64::Engine;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fmt;
#[cfg(target_os = "macos")]
use std::fs::OpenOptions;
#[cfg(target_os = "macos")]
use std::io::Write;
#[cfg(target_os = "macos")]
use std::os::unix::fs::OpenOptionsExt;
#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::ExitStatus;
#[cfg(target_os = "macos")]
use std::process::Stdio;
#[cfg(target_os = "macos")]
use std::time::Duration;
#[cfg(target_os = "macos")]
use tokio::process::Command;
use uuid::Uuid;

const TOKEN: &str = "AGORA_SANDBOX_TOKEN";
const PROXY_IPV4: &str = "AGORA_SANDBOX_PROXY_IPV4";
const PROXY_IPV6: &str = "AGORA_SANDBOX_PROXY_IPV6";
#[cfg(target_os = "macos")]
const EXECUTION_CONTROL: &str = "AGORA_SANDBOX_EXECUTION_CONTROL";
#[cfg(target_os = "macos")]
const EXECUTION_TOKEN: &str = "AGORA_SANDBOX_EXECUTION_TOKEN";
#[cfg(target_os = "macos")]
const HOOK_LIBRARIES: &str = "AGORA_SANDBOX_HOOK_LIBRARIES";
#[cfg(target_os = "macos")]
const FILESYSTEM_ROOT: &str = "AGORA_SANDBOX_FILESYSTEM_ROOT";
#[cfg(target_os = "macos")]
const TLS_TRUST_ANCHOR_DER: &str = "AGORA_SANDBOX_TLS_TRUST_ANCHOR_DER";
#[cfg(target_os = "macos")]
const TLS_TRUST_BUNDLE: &str = "AGORA_SANDBOX_TLS_TRUST_BUNDLE";
const DEFAULT_TLS_CA_CERTIFICATE: &str = "ca/ca.crt";
const DEFAULT_TLS_CA_PRIVATE_KEY: &str = "ca/ca.key";
#[cfg(target_os = "macos")]
const TLS_TRUST_BUNDLE_DIRECTORY: &str = "ca";
#[cfg(target_os = "macos")]
const TLS_CLIENT_TRUST_ENVIRONMENT: [&str; 5] = [
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
];

#[derive(Clone, Debug)]
pub struct SandboxConfig {
    pub network: NetworkConfig,
    hook_library: PathBuf,
    workdir: PathBuf,
    encrypted_workspace_key: Option<SecretBytes>,
    tls_trust_anchor: Option<PathBuf>,
    tls_ca: Option<TlsCaFiles>,
    #[cfg(test)]
    upstream_tls_roots: Option<Vec<rustls::pki_types::CertificateDer<'static>>>,
}

#[derive(Clone)]
struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn new(value: impl AsRef<[u8]>) -> Self {
        Self(value.as_ref().to_vec())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

#[derive(Clone, Debug)]
struct TlsCaFiles {
    certificate: PathBuf,
    private_key: PathBuf,
}

impl SandboxConfig {
    pub fn new(hook_library: impl Into<PathBuf>) -> Self {
        Self {
            network: NetworkConfig::default(),
            hook_library: hook_library.into(),
            workdir: Self::default_workdir(),
            encrypted_workspace_key: None,
            tls_trust_anchor: None,
            tls_ca: None,
            #[cfg(test)]
            upstream_tls_roots: None,
        }
    }

    pub fn default_workdir() -> PathBuf {
        std::env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".agora-sandbox")
    }

    pub fn hook_library(&self) -> &Path {
        &self.hook_library
    }

    pub fn with_workdir(mut self, workdir: impl Into<PathBuf>) -> Self {
        self.workdir = workdir.into();
        self
    }

    pub fn workdir(&self) -> &Path {
        &self.workdir
    }

    pub fn with_encrypted_workspace(mut self, key: impl AsRef<[u8]>) -> Self {
        self.encrypted_workspace_key = Some(SecretBytes::new(key));
        self
    }

    pub fn encrypted_workspace_key(&self) -> Option<&[u8]> {
        self.encrypted_workspace_key
            .as_ref()
            .map(SecretBytes::as_bytes)
    }

    pub fn with_tls_trust_anchor(mut self, certificate: impl Into<PathBuf>) -> Self {
        self.tls_trust_anchor = Some(certificate.into());
        self
    }

    pub fn tls_trust_anchor(&self) -> Option<&Path> {
        self.tls_trust_anchor.as_deref()
    }

    pub fn with_tls_ca(
        mut self,
        certificate: impl Into<PathBuf>,
        private_key: impl Into<PathBuf>,
    ) -> Self {
        self.tls_ca = Some(TlsCaFiles {
            certificate: certificate.into(),
            private_key: private_key.into(),
        });
        self
    }

    pub fn tls_ca(&self) -> Option<(&Path, &Path)> {
        self.tls_ca
            .as_ref()
            .map(|ca| (ca.certificate.as_path(), ca.private_key.as_path()))
    }

    #[cfg(test)]
    fn with_upstream_tls_roots(
        mut self,
        roots: Vec<rustls::pki_types::CertificateDer<'static>>,
    ) -> Self {
        self.upstream_tls_roots = Some(roots);
        self
    }

    pub fn validate(&self) -> Result<()> {
        self.network.validate()?;
        #[cfg(not(target_os = "macos"))]
        bail!("the network hook is currently supported only on macOS");
        if !self.hook_library.is_file() {
            bail!(
                "sandbox hook library does not exist: {}",
                self.hook_library.display()
            );
        }
        #[cfg(target_os = "macos")]
        match &self.encrypted_workspace_key {
            Some(key) => EncryptedWorkspace::validate_passphrase(key.as_bytes())?,
            None => bail!("sandbox filesystem key is required"),
        }
        if let Some(anchor) = &self.tls_trust_anchor
            && !anchor.is_file()
        {
            bail!(
                "sandbox TLS trust anchor does not exist: {}",
                anchor.display()
            );
        }
        #[cfg(target_os = "macos")]
        if let Some(anchor) = &self.tls_trust_anchor
            && !crate::hook::validate_trust_anchor(anchor)
        {
            bail!(
                "sandbox TLS trust anchor is not a valid DER certificate: {}",
                anchor.display()
            );
        }
        Ok(())
    }

    fn tls_ca_for_workdir(&self) -> Result<Option<TlsCaFiles>> {
        if self.network.tls == TlsMode::Off {
            return Ok(None);
        }
        let ca = self.tls_ca.clone().unwrap_or_else(|| TlsCaFiles {
            certificate: self.workdir.join(DEFAULT_TLS_CA_CERTIFICATE),
            private_key: self.workdir.join(DEFAULT_TLS_CA_PRIVATE_KEY),
        });
        if !ca.certificate.is_file() || !ca.private_key.is_file() {
            crate::network::generate_tls_ca(&ca.certificate, &ca.private_key)?;
        }
        Ok(Some(ca))
    }

    #[cfg(target_os = "macos")]
    fn write_tls_trust_bundle(&self, ca_certificate: &[u8]) -> Result<PathBuf> {
        let native = crate::network::native_root_certificates()
            .context("failed to load native TLS roots for client trust bundle")?;
        let mut bundle = ca_certificate.to_vec();
        if !bundle.ends_with(b"\n") {
            bundle.push(b'\n');
        }
        for certificate in native {
            bundle.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
            let encoded = base64::engine::general_purpose::STANDARD.encode(certificate.as_ref());
            for line in encoded.as_bytes().chunks(64) {
                bundle.extend_from_slice(line);
                bundle.push(b'\n');
            }
            bundle.extend_from_slice(b"-----END CERTIFICATE-----\n");
        }

        let mut fingerprint = 0x6c62_272e_07bb_0142_62b8_2175_6295_c58d_u128;
        for byte in ca_certificate {
            fingerprint ^= u128::from(*byte);
            fingerprint = fingerprint.wrapping_mul(309_485_009_821_345_068_724_781_371);
        }
        let path = self
            .workdir
            .join(TLS_TRUST_BUNDLE_DIRECTORY)
            .join(format!("trust-bundle-{fingerprint:032x}.crt"));
        let parent = path
            .parent()
            .context("TLS client trust bundle path has no parent")?;
        std::fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create TLS client trust bundle directory {}",
                parent.display()
            )
        })?;
        let temporary = parent.join(format!(".trust-bundle-{}.tmp", Uuid::new_v4().simple()));
        let written = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bundle)?;
            file.flush()?;
            std::fs::rename(&temporary, &path)?;
            Ok::<_, std::io::Error>(())
        })();
        if let Err(error) = written {
            let _ = std::fs::remove_file(&temporary);
            return Err(error).with_context(|| {
                format!("failed to write TLS client trust bundle {}", path.display())
            });
        }
        path.canonicalize()
            .context("failed to resolve TLS client trust bundle")
    }
}

#[derive(Clone, Debug)]
pub struct SandboxCommand {
    program: OsString,
    arguments: Vec<OsString>,
    environment: BTreeMap<OsString, OsString>,
    current_dir: Option<PathBuf>,
}

impl SandboxCommand {
    pub fn new(program: impl Into<OsString>) -> Self {
        Self {
            program: program.into(),
            arguments: Vec::new(),
            environment: BTreeMap::new(),
            current_dir: None,
        }
    }

    pub fn arg(mut self, argument: impl Into<OsString>) -> Self {
        self.arguments.push(argument.into());
        self
    }

    pub fn args<I, S>(mut self, arguments: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.arguments.extend(arguments.into_iter().map(Into::into));
        self
    }

    pub fn env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.environment.insert(key.into(), value.into());
        self
    }

    pub fn current_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(path.into());
        self
    }

    #[cfg(target_os = "macos")]
    fn into_command(self) -> Command {
        let mut command = Command::new(self.program);
        command.args(self.arguments);
        command.envs(self.environment);
        if let Some(current_dir) = self.current_dir {
            command.current_dir(current_dir);
        }
        command
    }

    #[cfg(target_os = "macos")]
    fn resolved_program(&self) -> Result<PathBuf> {
        resolve_executable(
            &self.program,
            self.current_dir.as_deref(),
            &self.environment,
        )
    }

    #[cfg(test)]
    fn effective_current_dir(&self) -> Result<PathBuf> {
        let directory = match &self.current_dir {
            Some(directory) if directory.is_absolute() => directory.clone(),
            Some(directory) => std::env::current_dir()?.join(directory),
            None => std::env::current_dir()?,
        };
        let directory = directory.canonicalize().with_context(|| {
            format!(
                "failed to resolve sandbox command workdir {}",
                directory.display()
            )
        })?;
        if !directory.is_dir() {
            bail!(
                "sandbox command workdir is not a directory: {}",
                directory.display()
            );
        }
        Ok(directory)
    }

    #[cfg(target_os = "macos")]
    fn set_program(&mut self, program: PathBuf) {
        self.program = program.into_os_string();
    }

    #[cfg(target_os = "macos")]
    fn set_script_interpreter(
        &mut self,
        interpreter: PathBuf,
        interpreter_argument: Option<OsString>,
        script: PathBuf,
    ) {
        self.program = interpreter.into_os_string();
        let mut arguments = Vec::with_capacity(self.arguments.len() + 2);
        arguments.extend(interpreter_argument);
        arguments.push(script.into_os_string());
        arguments.append(&mut self.arguments);
        self.arguments = arguments;
    }
}

pub struct Sandbox<C>
where
    C: Callback,
{
    config: SandboxConfig,
    callback: C,
}

impl<C> Sandbox<C>
where
    C: Callback,
{
    pub fn new(config: SandboxConfig, callback: C) -> Self {
        Self { config, callback }
    }

    #[cfg(target_os = "macos")]
    pub async fn run(self, mut command: SandboxCommand) -> Result<SandboxOutcome> {
        self.config.validate()?;
        let callback = std::sync::Arc::new(self.callback);
        let key = self
            .config
            .encrypted_workspace_key()
            .context("sandbox filesystem key is required")?;
        let mut encrypted_workspace = EncryptedWorkspace::start(&self.config.workdir, key).await?;
        let tls_ca_files = self.config.tls_ca_for_workdir()?;
        let hook_library = self.config.hook_library.canonicalize().with_context(|| {
            format!(
                "failed to resolve sandbox hook library {}",
                self.config.hook_library.display()
            )
        })?;
        let tls_trust_anchor_der = self
            .config
            .tls_trust_anchor
            .as_ref()
            .map(|path| {
                std::fs::read(path)
                    .with_context(|| format!("failed to read TLS trust anchor {}", path.display()))
                    .map(|der| base64::engine::general_purpose::STANDARD.encode(der))
            })
            .transpose()?;
        let tls_ca = tls_ca_files
            .as_ref()
            .map(|ca| {
                let certificate_path = ca.certificate.canonicalize().with_context(|| {
                    format!(
                        "failed to resolve TLS CA certificate {}",
                        ca.certificate.display()
                    )
                })?;
                let certificate = std::fs::read(&certificate_path).with_context(|| {
                    format!(
                        "failed to read TLS CA certificate {}",
                        certificate_path.display()
                    )
                })?;
                let private_key = std::fs::read(&ca.private_key).with_context(|| {
                    format!(
                        "failed to read TLS CA private key {}",
                        ca.private_key.display()
                    )
                })?;
                let trust_bundle = self.config.write_tls_trust_bundle(&certificate)?;
                Ok::<_, anyhow::Error>((certificate, private_key, certificate_path, trust_bundle))
            })
            .transpose()?;
        let sandbox_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let trace = TraceContext::root();
        let mut execution = {
            let execution_callback = {
                let callback = std::sync::Arc::clone(&callback);
                move |event| {
                    let callback = std::sync::Arc::clone(&callback);
                    async move { callback.on_event(event).await }
                }
            };
            let controller = ExecutionController::start_with_callback(
                encrypted_workspace.root().to_path_buf(),
                sandbox_id.clone(),
                run_id.clone(),
                execution_callback,
                self.config.network.callback_timeout,
            )
            .await?;
            let executable = command.resolved_program()?;
            let prepared = controller.prepare(executable).await?;
            if let Some(shebang) = resolve_shebang(&prepared)? {
                let interpreter = controller.prepare(shebang.interpreter).await?;
                command.set_script_interpreter(interpreter, shebang.argument, prepared);
            } else {
                command.set_program(prepared);
            }
            controller
        };
        let context = NetworkRunContext::new(&sandbox_id, &run_id);
        let network_callback = {
            let callback = std::sync::Arc::clone(&callback);
            move |event| {
                let callback = std::sync::Arc::clone(&callback);
                async move { callback.on_event(event).await }
            }
        };
        #[cfg(test)]
        let upstream_tls_roots = self.config.upstream_tls_roots.clone();
        #[cfg(test)]
        let controller = match (tls_ca.as_ref(), upstream_tls_roots) {
            (Some((certificate, private_key, _, _)), Some(roots)) => {
                NetworkController::start_with_tls_ca_and_roots(
                    self.config.network,
                    context,
                    network_callback,
                    certificate,
                    private_key,
                    roots,
                )
                .await
            }
            (tls_ca, None) => match tls_ca {
                Some((certificate, private_key, _, _)) => {
                    NetworkController::start_with_tls_ca(
                        self.config.network,
                        context,
                        network_callback,
                        certificate,
                        private_key,
                    )
                    .await
                }
                None => {
                    NetworkController::start(self.config.network, context, network_callback).await
                }
            },
            (None, Some(_)) => Err(anyhow::anyhow!(
                "test upstream TLS roots require TLS interception"
            )),
        };
        #[cfg(not(test))]
        let controller = match tls_ca.as_ref() {
            Some((certificate, private_key, _, _)) => {
                NetworkController::start_with_tls_ca(
                    self.config.network,
                    context,
                    network_callback,
                    certificate,
                    private_key,
                )
                .await
            }
            None => NetworkController::start(self.config.network, context, network_callback).await,
        };
        let mut controller = match controller {
            Ok(controller) => controller,
            Err(error) => {
                let _ = execution.shutdown().await;
                return Err(error);
            }
        };
        let runtime = controller.runtime();
        let execution_runtime = execution.runtime();
        let injected_libraries = Self::injected_libraries(&hook_library)?;
        let mut child = command.into_command();
        child
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .env(TOKEN, runtime.token())
            .env(PROXY_IPV4, runtime.proxy_ipv4().to_string())
            .env(PROXY_IPV6, runtime.proxy_ipv6().to_string())
            .env(EXECUTION_CONTROL, execution_runtime.control().to_string())
            .env(EXECUTION_TOKEN, execution_runtime.token())
            .env(HOOK_LIBRARIES, &injected_libraries)
            .env(FILESYSTEM_ROOT, encrypted_workspace.root())
            .env(TRACE_ID_ENVIRONMENT, trace.encode())
            .env("DYLD_INSERT_LIBRARIES", injected_libraries);
        let tls_trust_anchors = tls_trust_anchor_der
            .into_iter()
            .chain(
                runtime
                    .tls_trust_anchor_der()
                    .map(|der| base64::engine::general_purpose::STANDARD.encode(der)),
            )
            .collect::<Vec<_>>();
        if !tls_trust_anchors.is_empty() {
            child.env(TLS_TRUST_ANCHOR_DER, tls_trust_anchors.join(","));
        }
        if let Some((_, _, _, trust_bundle)) = &tls_ca {
            child.env(TLS_TRUST_BUNDLE, trust_bundle);
            for key in TLS_CLIENT_TRUST_ENVIRONMENT {
                child.env(key, trust_bundle);
            }
        }
        child.as_std_mut().process_group(0);
        let mut terminal = ForegroundTerminal::capture()?;

        let mut child = match child.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = controller.shutdown().await;
                let _ = execution.shutdown().await;
                return Err(error).context("failed to start sandbox child");
            }
        };
        let process_group = child
            .id()
            .and_then(|id| libc::pid_t::try_from(id).ok())
            .context("sandbox child has no valid process id")?;
        if let Some(terminal) = terminal.as_mut()
            && let Err(error) = terminal.handoff(process_group)
        {
            let _ = terminate_process_group(&mut child, process_group).await;
            let _ = controller.shutdown().await;
            let _ = execution.shutdown().await;
            return Err(error);
        }
        let status =
            wait_for_child_or_service(&mut child, process_group, &mut controller, &mut execution)
                .await;
        let terminal_restore = terminal
            .as_mut()
            .map(ForegroundTerminal::restore)
            .transpose();
        let shutdown = controller.shutdown().await;
        let execution_shutdown = execution.shutdown().await;
        let filesystem_shutdown = encrypted_workspace.shutdown().await;
        let status = status?;
        terminal_restore?;
        shutdown?;
        execution_shutdown?;
        filesystem_shutdown.with_context(|| {
            format!("sandbox child exited with status {status} before filesystem shutdown")
        })?;

        Ok(SandboxOutcome {
            status,
            sandbox_id,
            run_id,
        })
    }

    #[cfg(not(target_os = "macos"))]
    pub async fn run(self, _command: SandboxCommand) -> Result<SandboxOutcome> {
        self.config.validate()?;
        unreachable!("sandbox validation must reject unsupported platforms")
    }

    #[cfg(target_os = "macos")]
    fn injected_libraries(hook_library: &Path) -> Result<OsString> {
        let mut libraries = vec![hook_library.to_path_buf()];
        if let Some(existing) = std::env::var_os("DYLD_INSERT_LIBRARIES") {
            libraries.extend(std::env::split_paths(&existing));
        }
        std::env::join_paths(libraries).context("invalid DYLD_INSERT_LIBRARIES path")
    }
}

#[cfg(target_os = "macos")]
pub async fn migrate_filesystem_key(
    workdir: impl AsRef<Path>,
    old_key: impl AsRef<[u8]>,
    new_key: impl AsRef<[u8]>,
) -> Result<()> {
    EncryptedWorkspace::migrate_key(workdir.as_ref(), old_key.as_ref(), new_key.as_ref()).await
}

#[cfg(target_os = "macos")]
struct ForegroundTerminal {
    descriptor: libc::c_int,
    original_process_group: libc::pid_t,
    handed_off: bool,
}

#[cfg(target_os = "macos")]
impl ForegroundTerminal {
    fn capture() -> Result<Option<Self>> {
        let descriptor = libc::STDIN_FILENO;
        if unsafe { libc::isatty(descriptor) } != 1 {
            return Ok(None);
        }
        let original_process_group = unsafe { libc::tcgetpgrp(descriptor) };
        if original_process_group == -1 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect sandbox terminal process group");
        }
        if original_process_group != unsafe { libc::getpgrp() } {
            return Ok(None);
        }
        Ok(Some(Self {
            descriptor,
            original_process_group,
            handed_off: false,
        }))
    }

    fn handoff(&mut self, process_group: libc::pid_t) -> Result<()> {
        set_terminal_process_group(self.descriptor, process_group)
            .context("failed to hand terminal to sandbox child")?;
        self.handed_off = true;
        if unsafe { libc::kill(-process_group, libc::SIGCONT) } == -1 {
            let error = std::io::Error::last_os_error();
            if error.raw_os_error() != Some(libc::ESRCH) {
                return Err(error).context("failed to continue sandbox child process group");
            }
        }
        Ok(())
    }

    fn restore(&mut self) -> Result<()> {
        if !self.handed_off {
            return Ok(());
        }
        set_terminal_process_group(self.descriptor, self.original_process_group)
            .context("failed to restore sandbox terminal process group")?;
        self.handed_off = false;
        Ok(())
    }
}

#[cfg(target_os = "macos")]
impl Drop for ForegroundTerminal {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

#[cfg(target_os = "macos")]
fn set_terminal_process_group(
    descriptor: libc::c_int,
    process_group: libc::pid_t,
) -> std::io::Result<()> {
    let mut blocked = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    let mut previous = std::mem::MaybeUninit::<libc::sigset_t>::uninit();
    unsafe {
        libc::sigemptyset(blocked.as_mut_ptr());
        libc::sigaddset(blocked.as_mut_ptr(), libc::SIGTTOU);
        let blocked = blocked.assume_init();
        let block_error = libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, previous.as_mut_ptr());
        if block_error != 0 {
            return Err(std::io::Error::from_raw_os_error(block_error));
        }
        let previous = previous.assume_init();
        let result = libc::tcsetpgrp(descriptor, process_group);
        let error = (result == -1).then(std::io::Error::last_os_error);
        let restore_error =
            libc::pthread_sigmask(libc::SIG_SETMASK, &previous, std::ptr::null_mut());
        if restore_error != 0 {
            return Err(std::io::Error::from_raw_os_error(restore_error));
        }
        match error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

#[cfg(target_os = "macos")]
async fn wait_for_child_or_service(
    child: &mut tokio::process::Child,
    process_group: libc::pid_t,
    controller: &mut NetworkController,
    execution: &mut ExecutionController,
) -> Result<ExitStatus> {
    enum Completion {
        Child(std::io::Result<ExitStatus>),
        Proxy(anyhow::Error),
        Execution(anyhow::Error),
    }

    let completion = tokio::select! {
        status = child.wait() => Completion::Child(status),
        error = controller.wait_failure() => Completion::Proxy(error),
        error = execution.wait_failure() => Completion::Execution(error),
    };
    let result = match completion {
        Completion::Child(status) => status.context("sandbox child wait failed"),
        Completion::Proxy(error) => Err(error).context("sandbox network proxy failed"),
        Completion::Execution(error) => Err(error).context("sandbox execution controller failed"),
    };
    let termination = terminate_process_group(child, process_group).await;
    match result {
        Ok(status) => {
            termination?;
            Ok(status)
        }
        Err(error) => {
            let _ = termination;
            Err(error)
        }
    }
}

#[cfg(target_os = "macos")]
async fn terminate_process_group(
    child: &mut tokio::process::Child,
    process_group: libc::pid_t,
) -> Result<()> {
    signal_process_group(process_group, libc::SIGTERM)?;
    if child.try_wait()?.is_none() {
        let _ = tokio::time::timeout(Duration::from_millis(500), child.wait()).await;
    }
    for _ in 0..10 {
        if !process_group_exists(process_group)? {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    signal_process_group(process_group, libc::SIGKILL)?;
    if child.try_wait()?.is_none() {
        child.wait().await?;
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn signal_process_group(process_group: libc::pid_t, signal: libc::c_int) -> Result<()> {
    if unsafe { libc::kill(-process_group, signal) } == 0 {
        return Ok(());
    }
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ESRCH) {
        Ok(())
    } else {
        Err(error).context("failed to signal sandbox process group")
    }
}

#[cfg(target_os = "macos")]
fn process_group_exists(process_group: libc::pid_t) -> Result<bool> {
    if unsafe { libc::kill(-process_group, 0) } == 0 {
        return Ok(true);
    }
    let error = std::io::Error::last_os_error();
    match error.raw_os_error() {
        Some(libc::ESRCH) => Ok(false),
        Some(libc::EPERM) => Ok(true),
        _ => Err(error).context("failed to inspect sandbox process group"),
    }
}

#[derive(Debug)]
pub struct SandboxOutcome {
    status: ExitStatus,
    sandbox_id: String,
    run_id: String,
}

impl SandboxOutcome {
    pub fn status(&self) -> ExitStatus {
        self.status
    }

    pub fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    pub fn run_id(&self) -> &str {
        &self.run_id
    }
}

impl From<&OsStr> for SandboxCommand {
    fn from(program: &OsStr) -> Self {
        Self::new(program)
    }
}

#[cfg(test)]
mod tests;
