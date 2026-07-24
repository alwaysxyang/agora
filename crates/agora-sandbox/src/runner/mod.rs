use crate::audit::AuditCallback;
use crate::network::{NetworkConfig, NetworkController, NetworkRunContext};
use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use tokio::process::Command;
use uuid::Uuid;

const TOKEN: &str = "AGORA_SANDBOX_TOKEN";
const PROXY_IPV4: &str = "AGORA_SANDBOX_PROXY_IPV4";
const PROXY_IPV6: &str = "AGORA_SANDBOX_PROXY_IPV6";

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

    fn into_command(self) -> Command {
        let mut command = Command::new(self.program);
        command.args(self.arguments);
        command.envs(self.environment);
        if let Some(current_dir) = self.current_dir {
            command.current_dir(current_dir);
        }
        command
    }
}

pub struct Sandbox<C>
where
    C: AuditCallback,
{
    config: SandboxConfig,
    callback: C,
}

impl<C> Sandbox<C>
where
    C: AuditCallback,
{
    pub fn new(config: SandboxConfig, callback: C) -> Self {
        Self { config, callback }
    }

    pub async fn run(self, command: SandboxCommand) -> Result<SandboxOutcome> {
        self.config.validate()?;
        let hook_library = self.config.hook_library.canonicalize().with_context(|| {
            format!(
                "failed to resolve sandbox hook library {}",
                self.config.hook_library.display()
            )
        })?;
        let sandbox_id = Uuid::new_v4().to_string();
        let run_id = Uuid::new_v4().to_string();
        let mut controller = NetworkController::start(
            self.config.network,
            NetworkRunContext::new(&sandbox_id, &run_id),
            self.callback,
        )
        .await?;
        let runtime = controller.runtime();
        let mut child = command.into_command();
        child
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .env(TOKEN, runtime.token())
            .env(PROXY_IPV4, runtime.proxy_ipv4().to_string())
            .env(PROXY_IPV6, runtime.proxy_ipv6().to_string())
            .env(
                "DYLD_INSERT_LIBRARIES",
                Self::injected_libraries(&hook_library)?,
            );

        let mut child = match child.spawn() {
            Ok(child) => child,
            Err(error) => {
                controller.shutdown().await?;
                return Err(error).context("failed to start sandbox child");
            }
        };
        let status = wait_for_child_or_proxy(&mut child, &mut controller).await;
        let shutdown = controller.shutdown().await;
        let status = status?;
        shutdown?;

        Ok(SandboxOutcome {
            status,
            sandbox_id,
            run_id,
        })
    }

    fn injected_libraries(hook_library: &Path) -> Result<OsString> {
        let mut libraries = vec![hook_library.to_path_buf()];
        if let Some(existing) = std::env::var_os("DYLD_INSERT_LIBRARIES") {
            libraries.extend(std::env::split_paths(&existing));
        }
        std::env::join_paths(libraries).context("invalid DYLD_INSERT_LIBRARIES path")
    }
}

async fn wait_for_child_or_proxy(
    child: &mut tokio::process::Child,
    controller: &mut NetworkController,
) -> Result<ExitStatus> {
    enum Completion {
        Child(std::io::Result<ExitStatus>),
        Proxy(anyhow::Error),
    }

    let completion = tokio::select! {
        status = child.wait() => Completion::Child(status),
        error = controller.wait_failure() => Completion::Proxy(error),
    };
    match completion {
        Completion::Child(status) => status.context("sandbox child wait failed"),
        Completion::Proxy(error) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            Err(error).context("sandbox network proxy failed")
        }
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
