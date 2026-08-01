use anyhow::{Context, Result};
use std::future::{Future, ready};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::{Child, Command as TokioCommand};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

pub trait CommandOutput {
    fn stdout(&mut self, chunk: &[u8]) -> impl Future<Output = Result<()>> + Send;

    fn stderr(&mut self, chunk: &[u8]) -> impl Future<Output = Result<()>> + Send;

    fn finish(&mut self) -> impl Future<Output = Result<()>> + Send {
        ready(Ok(()))
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CommandOutcome {
    exit_code: i32,
}

impl CommandOutcome {
    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }
}

pub struct Command {
    program: String,
    args: Vec<String>,
    env: Vec<(String, String)>,
    current_dir: Option<PathBuf>,
    input: String,
}

impl Command {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
            env: Vec::new(),
            current_dir: None,
            input: String::new(),
        }
    }

    pub fn args<I, S>(mut self, args: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.args = args.into_iter().map(Into::into).collect();
        self
    }

    pub fn envs<I, K, V>(mut self, env: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: Into<String>,
        V: Into<String>,
    {
        self.env = env
            .into_iter()
            .map(|(key, value)| (key.into(), value.into()))
            .collect();
        self
    }

    pub fn current_dir(mut self, current_dir: impl Into<PathBuf>) -> Self {
        self.current_dir = Some(current_dir.into());
        self
    }

    pub fn input(mut self, input: impl Into<String>) -> Self {
        self.input = input.into();
        self
    }

    pub async fn run<O>(self, output: &mut O) -> Result<CommandOutcome>
    where
        O: CommandOutput + Send,
    {
        let mut command = TokioCommand::new(&self.program);
        command
            .args(&self.args)
            .envs(self.env.iter().map(|(key, value)| (key, value)))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(current_dir) = &self.current_dir {
            command.current_dir(current_dir);
        }
        configure_process_group(&mut command);

        let mut child = command
            .spawn()
            .with_context(|| format!("start agent command failed: {}", self.program))?;
        let mut process_group = ProcessGroupGuard::new(&child)?;
        let mut stdin = child
            .stdin
            .take()
            .context("agent command stdin is unavailable")?;
        stdin
            .write_all(self.input.as_bytes())
            .await
            .context("write agent command input failed")?;
        stdin
            .shutdown()
            .await
            .context("close agent command stdin failed")?;
        drop(stdin);

        let mut stdout = child
            .stdout
            .take()
            .context("agent command stdout is unavailable")?;
        let mut stderr = child
            .stderr
            .take()
            .context("agent command stderr is unavailable")?;
        let mut stdout_open = true;
        let mut stderr_open = true;
        let mut stdout_buffer = [0_u8; 4096];
        let mut stderr_buffer = [0_u8; 4096];

        let status = loop {
            tokio::select! {
                status = child.wait() => {
                    break status.context("wait for agent command failed")?;
                }
                result = stdout.read(&mut stdout_buffer), if stdout_open => {
                    match result.context("read agent command stdout failed")? {
                        0 => stdout_open = false,
                        size => output.stdout(&stdout_buffer[..size]).await?,
                    }
                }
                result = stderr.read(&mut stderr_buffer), if stderr_open => {
                    match result.context("read agent command stderr failed")? {
                        0 => stderr_open = false,
                        size => output.stderr(&stderr_buffer[..size]).await?,
                    }
                }
            }
        };
        process_group.terminate()?;

        while stdout_open || stderr_open {
            tokio::select! {
                result = stdout.read(&mut stdout_buffer), if stdout_open => {
                    match result.context("read agent command stdout failed")? {
                        0 => stdout_open = false,
                        size => output.stdout(&stdout_buffer[..size]).await?,
                    }
                }
                result = stderr.read(&mut stderr_buffer), if stderr_open => {
                    match result.context("read agent command stderr failed")? {
                        0 => stderr_open = false,
                        size => output.stderr(&stderr_buffer[..size]).await?,
                    }
                }
            }
        }
        output.finish().await?;

        Ok(CommandOutcome {
            exit_code: status.code().unwrap_or_default(),
        })
    }
}

#[cfg(unix)]
fn configure_process_group(command: &mut TokioCommand) {
    command.as_std_mut().process_group(0);
}

#[cfg(not(unix))]
fn configure_process_group(_command: &mut TokioCommand) {}

#[cfg(unix)]
struct ProcessGroupGuard {
    process_group: libc::pid_t,
    active: bool,
}

#[cfg(unix)]
impl ProcessGroupGuard {
    fn new(child: &Child) -> Result<Self> {
        let process_group = child
            .id()
            .and_then(|id| libc::pid_t::try_from(id).ok())
            .context("agent command has no valid process id")?;
        Ok(Self {
            process_group,
            active: true,
        })
    }

    fn terminate(&mut self) -> Result<()> {
        if !self.active {
            return Ok(());
        }
        self.active = false;
        if unsafe { libc::kill(-self.process_group, libc::SIGKILL) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ESRCH) {
            Ok(())
        } else {
            Err(error).context("terminate agent command process group failed")
        }
    }
}

#[cfg(unix)]
impl Drop for ProcessGroupGuard {
    fn drop(&mut self) {
        let _ = self.terminate();
    }
}

#[cfg(not(unix))]
struct ProcessGroupGuard;

#[cfg(not(unix))]
impl ProcessGroupGuard {
    fn new(_child: &Child) -> Result<Self> {
        Ok(Self)
    }

    fn terminate(&mut self) -> Result<()> {
        Ok(())
    }
}
