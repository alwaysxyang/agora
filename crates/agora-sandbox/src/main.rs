use agora_core::{
    lifecycle::{
        shutdown::{ShutdownGuard, ShutdownReason},
        signal::{Signal, SignalHandlers},
    },
    logger,
};
use agora_sandbox::{
    audit::{AuditCallback, AuditEvent},
    network::{NetworkEnforcement, TlsMode},
    runner::{Sandbox, SandboxCommand, SandboxConfig},
};
use anyhow::{Context, Result};
use clap::{ColorChoice, Parser, ValueEnum};
use std::io::{self, Write};
use std::path::PathBuf;
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

    /// Network enforcement mode
    #[arg(long, value_enum, default_value_t = NetworkEnforcementArgument::Audit)]
    network_enforcement: NetworkEnforcementArgument,

    /// TLS termination mode
    #[arg(long, value_enum, default_value_t = TlsArgument::Off)]
    tls: TlsArgument,
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum NetworkEnforcementArgument {
    Audit,
    Strict,
}

impl From<NetworkEnforcementArgument> for NetworkEnforcement {
    fn from(value: NetworkEnforcementArgument) -> Self {
        match value {
            NetworkEnforcementArgument::Audit => Self::Audit,
            NetworkEnforcementArgument::Strict => Self::Strict,
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum)]
enum TlsArgument {
    Off,
    Auto,
    Require,
}

impl From<TlsArgument> for TlsMode {
    fn from(value: TlsArgument) -> Self {
        match value {
            TlsArgument::Off => Self::Off,
            TlsArgument::Auto => Self::Auto,
            TlsArgument::Require => Self::Require,
        }
    }
}

struct JsonAuditCallback {
    writer: Mutex<io::Stderr>,
}

impl JsonAuditCallback {
    fn new() -> Self {
        Self {
            writer: Mutex::new(io::stderr()),
        }
    }

    fn writer(&self) -> MutexGuard<'_, io::Stderr> {
        self.writer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl AuditCallback for JsonAuditCallback {
    fn on_event(&self, event: AuditEvent) {
        let Ok(event) = serde_json::to_string(&event) else {
            return;
        };
        let _ = writeln!(self.writer(), "{event}");
    }
}

async fn async_main(arguments: Arguments) -> Result<u8> {
    let hook_library = match arguments.hook_library {
        Some(path) => path,
        None => default_hook_library()?,
    };
    let mut config = SandboxConfig::new(hook_library);
    config.network.enforcement = arguments.network_enforcement.into();
    config.network.tls = arguments.tls.into();
    let command = parse_command(&arguments.command)?;

    let status = Arc::new(Mutex::new(None::<ExitStatus>));
    let reason = Arc::new(Mutex::new(None::<ShutdownReason>));
    let process_status = Arc::clone(&status);
    let shutdown_reason = Arc::clone(&reason);
    let guard = ShutdownGuard::get();
    let signals = shutdown_signals(&guard)?;
    let process = async move {
        let outcome = Sandbox::new(config, JsonAuditCallback::new())
            .run(command)
            .await?;
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
    if let Err(error) = logger::init(io::stderr(), logger::LevelFilter::Info) {
        eprintln!("failed to initialize logger: {error}");
        return ExitCode::FAILURE;
    }
    let arguments = Arguments::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            logger::error!("failed to initialize Tokio runtime: {}", error);
            return ExitCode::FAILURE;
        }
    };

    match runtime.block_on(async_main(arguments)) {
        Ok(code) => ExitCode::from(code),
        Err(error) => {
            logger::error!("{}", error);
            ExitCode::FAILURE
        }
    }
}
