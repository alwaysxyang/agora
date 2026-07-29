use crate::callback::Callback;
#[cfg(target_os = "macos")]
use crate::execution::{ExecutionController, resolve_executable};
use crate::network::{NetworkConfig, NetworkController, NetworkRunContext};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
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

#[derive(Clone, Debug)]
pub struct SandboxConfig {
    pub network: NetworkConfig,
    hook_library: PathBuf,
}

impl SandboxConfig {
    pub fn new(hook_library: impl Into<PathBuf>) -> Self {
        Self {
            network: NetworkConfig::default(),
            hook_library: hook_library.into(),
        }
    }

    pub fn hook_library(&self) -> &Path {
        &self.hook_library
    }

    pub fn validate(&self) -> Result<()> {
        self.network.validate()?;
        #[cfg(not(target_os = "macos"))]
        bail!("the network hook is currently supported only on macOS");
        #[cfg(all(target_os = "macos", not(target_arch = "aarch64")))]
        bail!("sandbox executable preparation is currently supported only on arm64 macOS");
        if !self.hook_library.is_file() {
            bail!(
                "sandbox hook library does not exist: {}",
                self.hook_library.display()
            );
        }
        Ok(())
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

    #[cfg(target_os = "macos")]
    fn set_program(&mut self, program: PathBuf) {
        self.program = program.into_os_string();
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
        let hook_library = self.config.hook_library.canonicalize().with_context(|| {
            format!(
                "failed to resolve sandbox hook library {}",
                self.config.hook_library.display()
            )
        })?;
        let sandbox_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let mut execution = {
            let controller = ExecutionController::start(&run_id).await?;
            let executable = command.resolved_program()?;
            let prepared = controller.prepare(executable).await?;
            command.set_program(prepared);
            controller
        };
        let mut controller = NetworkController::start(
            self.config.network,
            NetworkRunContext::new(&sandbox_id, &run_id),
            self.callback,
        )
        .await?;
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
            .env("DYLD_INSERT_LIBRARIES", injected_libraries);
        child.as_std_mut().process_group(0);

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
        let status =
            wait_for_child_or_service(&mut child, process_group, &mut controller, &mut execution)
                .await;
        let shutdown = controller.shutdown().await;
        let execution_shutdown = execution.shutdown().await;
        let status = status?;
        shutdown?;
        execution_shutdown?;

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
