use agora_core::lifecycle::{
    shutdown::{ShutdownGuard, ShutdownReason},
    signal::{Signal, SignalHandlers},
};
use agora_core::logger::{self, LoggerEntry};
use agora_sandbox::{
    callback::{Callback, Decision, Event, EventType, FileOpenMode, ProcessOperation},
    hook_library,
    runner::{Sandbox, SandboxCommand},
};
use anyhow::{Context, Result};
use clap::{ColorChoice, Parser, Subcommand};
use serde::Serialize;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{ExitCode, ExitStatus};
use std::sync::{Arc, Mutex, MutexGuard};

mod config;
mod key_migration;

#[derive(Parser)]
#[command(
    name = "agora-sandbox",
    about = "Run a command with Agora sandbox network interception and auditing",
    color = ColorChoice::Auto
)]
struct Arguments {
    #[command(subcommand)]
    command: CliCommand,
}

#[derive(Subcommand)]
enum CliCommand {
    /// Run an executable inside the configured sandbox
    Run {
        /// Sandbox JSON configuration file
        #[arg(short = 'c', long)]
        config: PathBuf,

        /// Executable command line; shell operators are not interpreted
        #[arg(short = 'e', long)]
        executable: String,
    },

    /// Interactively change the passphrase of an existing encrypted filesystem
    MigrateKey {
        /// Sandbox work directory; defaults to ~/.agora-sandbox
        #[arg(long)]
        workdir: Option<PathBuf>,
    },
}

struct JsonCallback;

impl JsonCallback {
    fn new() -> Self {
        Self
    }
}

impl Callback for JsonCallback {
    fn on_event(&self, event: Event) -> impl Future<Output = Decision> + Send {
        if let Some(record) = audit_record(&event) {
            logger::info!(
                entry = LoggerEntry::new().with_entry("audit", record),
                "sandbox audit event"
            );
        }
        std::future::ready(Decision::Allow)
    }
}

fn audit_record(event: &Event) -> Option<AuditRecord> {
    match event {
        Event::Network(event) if event.event_type == EventType::NetworkConnectAttempt => {
            event.network.as_ref().map(|network| AuditRecord::Network {
                access_time: event.occurred_at.clone(),
                trace_id: event.trace_id.clone(),
                pid: event.process.pid,
                destination_ip: network.destination_ip,
                destination_port: network.destination_port,
                domain: network.domain.clone(),
            })
        }
        Event::Process(event) if event.event_type == EventType::ProcessExecAttempt => {
            Some(AuditRecord::Process {
                access_time: event.occurred_at.clone(),
                trace_id: event.trace_id.clone(),
                pid: event.process.pid,
                ppid: event.process.ppid,
                process_executable: event.process.executable.clone(),
                executable: event.command.executable.clone(),
                arguments: event.command.arguments.clone(),
                current_dir: event.command.current_dir.clone(),
                operation: event.command.operation,
            })
        }
        Event::File(event)
            if matches!(
                event.event_type,
                EventType::FilesystemOpen | EventType::FilesystemClose
            ) =>
        {
            Some(AuditRecord::Filesystem {
                access_time: event.occurred_at.clone(),
                trace_id: event.trace_id.clone(),
                pid: event.process.pid,
                operation: match event.event_type {
                    EventType::FilesystemOpen => FileOperation::Open,
                    EventType::FilesystemClose => FileOperation::Close,
                    _ => unreachable!(),
                },
                path: event.file.path.clone(),
                mode: event.file.mode,
            })
        }
        _ => None,
    }
}

enum LogOutput {
    Stderr(io::Stderr),
    File(File),
}

impl LogOutput {
    fn new(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::Stderr(io::stderr()));
        };
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create log directory {}", parent.display()))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("failed to open log file {}", path.display()))?;
        Ok(Self::File(file))
    }
}

impl Write for LogOutput {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        match self {
            Self::Stderr(writer) => writer.write(buffer),
            Self::File(writer) => writer.write(buffer),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Stderr(writer) => writer.flush(),
            Self::File(writer) => writer.flush(),
        }
    }
}

#[derive(Clone, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
enum AuditRecord {
    Network {
        access_time: String,
        trace_id: String,
        pid: u32,
        destination_ip: std::net::IpAddr,
        destination_port: u16,
        domain: Option<String>,
    },
    Process {
        access_time: String,
        trace_id: String,
        pid: u32,
        ppid: u32,
        process_executable: String,
        executable: String,
        arguments: Vec<String>,
        current_dir: String,
        operation: ProcessOperation,
    },
    Filesystem {
        access_time: String,
        trace_id: String,
        pid: u32,
        operation: FileOperation,
        path: String,
        mode: FileOpenMode,
    },
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
enum FileOperation {
    Open,
    Close,
}

async fn async_main(arguments: Arguments) -> Result<u8> {
    match arguments.command {
        CliCommand::MigrateKey { workdir } => {
            key_migration::run(workdir).await?;
            Ok(0)
        }
        CliCommand::Run { config, executable } => run(config, executable).await,
    }
}

async fn run(config_path: PathBuf, executable: String) -> Result<u8> {
    let config = config::RunConfig::load(&config_path)?;
    let command = parse_command(&executable)?;
    let hook = hook_library::materialize(config.workdir())?;
    let (config, audit_file) = config.into_runtime(hook);
    logger::init(
        LogOutput::new(audit_file.as_deref())?,
        logger::LevelFilter::Info,
    )?;
    let callback = JsonCallback::new();

    let status = Arc::new(Mutex::new(None::<ExitStatus>));
    let reason = Arc::new(Mutex::new(None::<ShutdownReason>));
    let process_status = Arc::clone(&status);
    let shutdown_reason = Arc::clone(&reason);
    let guard = ShutdownGuard::get();
    let signals = shutdown_signals(&guard)?;
    let process = async move {
        let outcome = Sandbox::new(config, callback).run(command).await?;
        *lock(&process_status) = Some(outcome.status());
        Ok(())
    };

    guard
        .run_with_shutdown(process, signals, move |reason| async move {
            *lock(&shutdown_reason) = Some(reason);
        })
        .await?;

    if let Some(status) = lock(&status).take() {
        return Ok(exit_status_code(status));
    }
    let signal = match lock(&reason).as_ref() {
        Some(ShutdownReason::Signal { signal }) => Some(*signal),
        _ => None,
    };
    Ok(signal.map(signal_exit_code).unwrap_or(1))
}

fn parse_command(command: &str) -> Result<SandboxCommand> {
    let mut words = shell_words::split(command).context("failed to parse command line")?;
    if words.is_empty() {
        anyhow::bail!("command line must contain a program");
    }
    let program = words.remove(0);
    Ok(SandboxCommand::new(program).args(words))
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn exit_status_code(status: ExitStatus) -> u8 {
    status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(1)
}

fn signal_exit_code(signal: i32) -> u8 {
    u8::try_from(128_i32.saturating_add(signal)).unwrap_or(u8::MAX)
}

#[cfg(unix)]
fn shutdown_signals(guard: &Arc<ShutdownGuard>) -> Result<SignalHandlers<Arc<ShutdownGuard>>> {
    use tokio::signal::unix::SignalKind;

    let mut signals = SignalHandlers::new();
    signals.register(
        Signal::new(SignalKind::interrupt().as_raw_value()),
        Arc::clone(guard),
    )?;
    signals.register(
        Signal::new(SignalKind::terminate().as_raw_value()),
        Arc::clone(guard),
    )?;
    Ok(signals)
}

#[cfg(not(unix))]
fn shutdown_signals(_guard: &Arc<ShutdownGuard>) -> Result<SignalHandlers<Arc<ShutdownGuard>>> {
    Ok(SignalHandlers::new())
}

fn main() -> ExitCode {
    let arguments = Arguments::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("failed to initialize Tokio runtime: {error}");
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(async_main(arguments)) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            eprintln!("{error:#}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests;
