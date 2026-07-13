use anyhow::{Context, Result};
use std::future::{Future, ready};
use std::path::PathBuf;
use std::process::Stdio;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command as TokioCommand;

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
    current_dir: Option<PathBuf>,
    input: String,
}

impl Command {
    pub fn new(program: impl Into<String>) -> Self {
        Self {
            program: program.into(),
            args: Vec::new(),
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(current_dir) = &self.current_dir {
            command.current_dir(current_dir);
        }

        let mut child = command
            .spawn()
            .with_context(|| format!("start agent command failed: {}", self.program))?;
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

        let status = child
            .wait()
            .await
            .context("wait for agent command failed")?;
        Ok(CommandOutcome {
            exit_code: status.code().unwrap_or_default(),
        })
    }
}
