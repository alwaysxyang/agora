use agora_core::lifecycle::{
    shutdown::{ShutdownGuard, ShutdownReason},
    signal::{Signal, SignalHandlers},
};
use agora_sandbox::{
    audit::{AuditCallback, AuditEvent, AuditEventType},
    runner::{Sandbox, SandboxCommand, SandboxConfig},
};
use anyhow::{Context, Result};
use clap::{ColorChoice, Parser};
use serde::Serialize;
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, ExitStatus};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Parser)]
#[command(
    name = "agora-sandbox",
    about = "Run a command with Agora sandbox network auditing",
    color = ColorChoice::Auto
)]
struct Arguments {
    /// Command line to run; shell operators are not interpreted
    #[arg(short = 'c', long)]
    command: String,

    /// Path to the injectable libagora_sandbox.dylib
    #[arg(long)]
    hook_library: Option<PathBuf>,

    /// Path for JSON Lines audit records; defaults to stdout
    #[arg(long)]
    audit_file: Option<PathBuf>,
}

struct JsonAuditCallback {
    state: Mutex<AuditState>,
}

impl JsonAuditCallback {
    fn new(path: Option<&Path>) -> Result<Self> {
        Ok(Self {
            state: Mutex::new(AuditState::new(path)?),
        })
    }
}

impl AuditCallback for JsonAuditCallback {
    fn on_event(&self, event: AuditEvent) {
        if let Err(error) = lock(&self.state).on_event(&event) {
            eprintln!("failed to write sandbox audit record: {error:#}");
        }
    }
}

struct AuditState {
    output: AuditOutput,
    pending: HashMap<String, AuditRecord>,
}

impl AuditState {
    fn new(path: Option<&Path>) -> Result<Self> {
        Ok(Self {
            output: AuditOutput::new(path)?,
            pending: HashMap::new(),
        })
    }

    fn on_event(&mut self, event: &AuditEvent) -> Result<()> {
        match event.event_type {
            AuditEventType::NetworkConnectAttempt => {
                let (Some(connection_id), Some(network)) =
                    (event.connection_id.as_ref(), event.network.as_ref())
                else {
                    return Ok(());
                };
                self.pending.insert(
                    connection_id.clone(),
                    AuditRecord {
                        access_time: event.occurred_at.clone(),
                        pid: event.process.pid,
                        destination_ip: network.destination_ip,
                        destination_port: network.destination_port,
                        domain: network.domain.clone(),
                    },
                );
            }
            AuditEventType::NetworkDomainObserved => {
                let (Some(connection_id), Some(network)) =
                    (event.connection_id.as_ref(), event.network.as_ref())
                else {
                    return Ok(());
                };
                if let Some(record) = self.pending.get_mut(connection_id) {
                    record.domain.clone_from(&network.domain);
                }
            }
            AuditEventType::NetworkConnectFailed | AuditEventType::NetworkConnectionClosed => {
                let Some(network) = event.network.as_ref() else {
                    return Ok(());
                };
                let mut record = event
                    .connection_id
                    .as_ref()
                    .and_then(|connection_id| self.pending.remove(connection_id))
                    .unwrap_or_else(|| AuditRecord {
                        access_time: event.occurred_at.clone(),
                        pid: event.process.pid,
                        destination_ip: network.destination_ip,
                        destination_port: network.destination_port,
                        domain: None,
                    });
                if network.domain.is_some() {
                    record.domain.clone_from(&network.domain);
                }
                self.output.write_record(&record)?;
            }
            _ => {}
        }
        Ok(())
    }
}

enum AuditOutput {
    Stdout(io::Stdout),
    File(File),
}

impl AuditOutput {
    fn new(path: Option<&Path>) -> Result<Self> {
        let Some(path) = path else {
            return Ok(Self::Stdout(io::stdout()));
        };
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).with_context(|| {
                format!("failed to create audit directory {}", parent.display())
            })?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .with_context(|| format!("failed to open audit file {}", path.display()))?;
        Ok(Self::File(file))
    }

    fn write_record(&mut self, record: &AuditRecord) -> Result<()> {
        match self {
            Self::Stdout(writer) => Self::write_json_line(writer, record),
            Self::File(writer) => Self::write_json_line(writer, record),
        }
    }

    fn write_json_line(writer: &mut impl Write, record: &AuditRecord) -> Result<()> {
        serde_json::to_writer(&mut *writer, record).context("failed to serialize audit record")?;
        writer
            .write_all(b"\n")
            .context("failed to write audit record")?;
        writer.flush().context("failed to flush audit record")
    }
}

#[derive(Serialize)]
struct AuditRecord {
    access_time: String,
    pid: u32,
    destination_ip: std::net::IpAddr,
    destination_port: u16,
    domain: Option<String>,
}

async fn async_main(arguments: Arguments) -> Result<u8> {
    let hook_library = match arguments.hook_library {
        Some(path) => path,
        None => default_hook_library()?,
    };
    let config = SandboxConfig::new(hook_library);
    let command = parse_command(&arguments.command)?;
    let audit = JsonAuditCallback::new(arguments.audit_file.as_deref())?;

    let status = Arc::new(Mutex::new(None::<ExitStatus>));
    let reason = Arc::new(Mutex::new(None::<ShutdownReason>));
    let process_status = Arc::clone(&status);
    let shutdown_reason = Arc::clone(&reason);
    let guard = ShutdownGuard::get();
    let signals = shutdown_signals(&guard)?;
    let process = async move {
        let outcome = Sandbox::new(config, audit).run(command).await?;
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

fn default_hook_library() -> Result<PathBuf> {
    let executable = std::env::current_exe().context("failed to resolve sandbox executable")?;
    let directory = executable
        .parent()
        .context("sandbox executable has no parent directory")?;
    Ok(directory.join("libagora_sandbox.dylib"))
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
