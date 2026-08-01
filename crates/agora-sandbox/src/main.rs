use agora_core::lifecycle::{
    shutdown::{ShutdownGuard, ShutdownReason},
    signal::{Signal, SignalHandlers},
};
use agora_sandbox::{
    callback::{Callback, Decision, Event, EventType, ProcessOperation},
    network::TlsMode,
    runner::{Sandbox, SandboxCommand, SandboxConfig},
};
use anyhow::{Context, Result, bail};
use clap::{ColorChoice, Parser, Subcommand, ValueEnum};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
#[cfg(unix)]
use std::os::fd::AsRawFd;
use std::path::{Component, Path, PathBuf};
use std::process::{ExitCode, ExitStatus};
use std::sync::{Arc, Mutex, MutexGuard};

#[derive(Parser)]
#[command(
    name = "agora-sandbox",
    about = "Run a command with Agora sandbox network interception and auditing",
    color = ColorChoice::Auto,
    subcommand_negates_reqs = true,
    args_conflicts_with_subcommands = true
)]
struct Arguments {
    /// Command line to run; shell operators are not interpreted
    #[arg(short = 'c', long, required = true)]
    command: Option<String>,

    #[command(subcommand)]
    subcommand: Option<CliCommand>,

    /// Path to the injectable libagora_sandbox.dylib
    #[arg(long)]
    hook_library: Option<PathBuf>,

    /// Path for JSON Lines audit records; defaults to stdout
    #[arg(long)]
    audit_file: Option<PathBuf>,

    /// Sandbox work directory; defaults to ~/.agora-sandbox
    #[arg(long)]
    workdir: Option<PathBuf>,

    /// Path to a DER CA certificate trusted by sandboxed SecTrust TLS clients
    #[arg(long)]
    tls_trust_anchor: Option<PathBuf>,

    /// TLS interception mode
    #[arg(long, value_enum, default_value_t = TlsArgument::Off)]
    tls: TlsArgument,

    /// PEM CA certificate; TLS auto defaults to <workdir>/ca/ca.crt
    #[arg(long, requires = "tls_ca_key")]
    tls_ca_cert: Option<PathBuf>,

    /// PEM CA private key; TLS auto defaults to <workdir>/ca/ca.key
    #[arg(long, requires = "tls_ca_cert")]
    tls_ca_key: Option<PathBuf>,
}

#[derive(Subcommand)]
enum CliCommand {
    /// Remove prepared executables recorded by <workdir>/fs manifests
    Clean {
        /// Sandbox work directory; defaults to ~/.agora-sandbox
        #[arg(long)]
        workdir: Option<PathBuf>,
    },
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum TlsArgument {
    #[default]
    Off,
    Auto,
}

impl From<TlsArgument> for TlsMode {
    fn from(value: TlsArgument) -> Self {
        match value {
            TlsArgument::Off => Self::Off,
            TlsArgument::Auto => Self::Auto,
        }
    }
}

struct JsonCallback {
    state: Mutex<AuditState>,
}

impl JsonCallback {
    fn new(path: Option<&Path>) -> Result<Self> {
        Ok(Self {
            state: Mutex::new(AuditState::new(path)?),
        })
    }
}

impl Callback for JsonCallback {
    fn on_event(&self, event: Event) -> impl Future<Output = Decision> + Send {
        if let Err(error) = lock(&self.state).on_event(&event) {
            eprintln!("failed to write sandbox audit record: {error:#}");
        }
        std::future::ready(Decision::Allow)
    }
}

struct AuditState {
    output: AuditOutput,
}

impl AuditState {
    fn new(path: Option<&Path>) -> Result<Self> {
        Ok(Self {
            output: AuditOutput::new(path)?,
        })
    }

    fn on_event(&mut self, event: &Event) -> Result<()> {
        let record = match event {
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
            _ => None,
        };
        if let Some(record) = record {
            self.output.write_record(&record)?;
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
}

async fn async_main(arguments: Arguments) -> Result<u8> {
    match arguments.subcommand {
        Some(CliCommand::Clean { workdir }) => {
            clean_executable_cache(workdir.as_deref())?;
            return Ok(0);
        }
        None => {}
    }
    let hook_library = match arguments.hook_library {
        Some(path) => path,
        None => default_hook_library()?,
    };
    let mut config = SandboxConfig::new(hook_library);
    if let Some(workdir) = arguments.workdir {
        config = config.with_workdir(workdir);
    }
    config.network.tls = arguments.tls.into();
    if let Some(anchor) = arguments.tls_trust_anchor {
        config = config.with_tls_trust_anchor(anchor);
    }
    if let (Some(certificate), Some(private_key)) = (arguments.tls_ca_cert, arguments.tls_ca_key) {
        config = config.with_tls_ca(certificate, private_key);
    }
    let command = parse_command(
        arguments
            .command
            .as_deref()
            .context("missing sandbox command")?,
    )?;
    let callback = JsonCallback::new(arguments.audit_file.as_deref())?;

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

fn clean_executable_cache(workdir: Option<&Path>) -> Result<()> {
    let workdir = workdir
        .map(Path::to_path_buf)
        .unwrap_or_else(SandboxConfig::default_workdir);
    let executable_cache = workdir.join("fs");
    ExecutableCacheCleaner::new(executable_cache.clone())
        .clean()
        .with_context(|| {
            format!(
                "failed to clean sandbox executable cache {}",
                executable_cache.display()
            )
        })
}

const CACHE_LOCK_FILE: &str = ".lock";
const CHECKSUM_MANIFEST_FILE: &str = "checksums.json";
const CHECKSUM_MANIFEST_VERSION: u32 = 1;

#[derive(Deserialize)]
struct ChecksumManifest {
    version: u32,
    files: BTreeMap<String, String>,
}

struct ManifestCleanup {
    path: PathBuf,
    files: Vec<PathBuf>,
}

struct ExecutableCacheCleaner {
    root: PathBuf,
}

impl ExecutableCacheCleaner {
    fn new(root: PathBuf) -> Self {
        Self { root }
    }

    fn clean(&self) -> Result<()> {
        let metadata = match fs::symlink_metadata(&self.root) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("failed to inspect executable cache"),
        };
        if !metadata.is_dir() {
            bail!("sandbox executable cache is not a directory");
        }

        let _lock = self.lock()?;
        let cleanups = self
            .manifest_paths()?
            .into_iter()
            .map(|path| self.load_cleanup(path))
            .collect::<Result<Vec<_>>>()?;

        for cleanup in cleanups {
            self.apply(cleanup)?;
        }
        self.prune_empty_directories(&self.root)
    }

    fn lock(&self) -> Result<File> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(self.root.join(CACHE_LOCK_FILE))
            .context("failed to open executable cache lock")?;
        #[cfg(unix)]
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(io::Error::last_os_error()).context("failed to lock executable cache");
        }
        Ok(file)
    }

    fn manifest_paths(&self) -> Result<Vec<PathBuf>> {
        let mut directories = vec![self.root.clone()];
        let mut manifests = Vec::new();
        while let Some(directory) = directories.pop() {
            for entry in fs::read_dir(&directory)
                .with_context(|| format!("failed to read {}", directory.display()))?
            {
                let entry = entry.with_context(|| {
                    format!("failed to read an entry in {}", directory.display())
                })?;
                let file_type = entry.file_type().with_context(|| {
                    format!("failed to inspect cache entry {}", entry.path().display())
                })?;
                if file_type.is_dir() {
                    directories.push(entry.path());
                } else if file_type.is_file()
                    && entry.path().file_name() == Some(OsStr::new(CHECKSUM_MANIFEST_FILE))
                {
                    manifests.push(entry.path());
                }
            }
        }
        manifests.sort();
        Ok(manifests)
    }

    fn load_cleanup(&self, path: PathBuf) -> Result<ManifestCleanup> {
        let contents = fs::read(&path)
            .with_context(|| format!("failed to read checksum manifest {}", path.display()))?;
        let manifest: ChecksumManifest = serde_json::from_slice(&contents)
            .with_context(|| format!("failed to parse checksum manifest {}", path.display()))?;
        if manifest.version != CHECKSUM_MANIFEST_VERSION {
            bail!(
                "unsupported sandbox executable checksum manifest version {}",
                manifest.version
            );
        }
        let directory = path
            .parent()
            .context("checksum manifest has no parent directory")?;
        let files = manifest
            .files
            .keys()
            .map(|source| self.destination(source, directory))
            .collect::<Result<Vec<_>>>()?;
        Ok(ManifestCleanup { path, files })
    }

    fn destination(&self, source: &str, manifest_directory: &Path) -> Result<PathBuf> {
        let source = Path::new(source);
        let mut components = source.components();
        if components.next() != Some(Component::RootDir) {
            bail!(
                "checksum manifest path is not absolute: {}",
                source.display()
            );
        }
        let mut relative = PathBuf::new();
        for component in components {
            match component {
                Component::Normal(component) => relative.push(component),
                _ => bail!("invalid checksum manifest path: {}", source.display()),
            }
        }
        if relative.as_os_str().is_empty() {
            bail!("invalid checksum manifest path: {}", source.display());
        }
        let destination = self.root.join(relative);
        if destination.parent() != Some(manifest_directory) {
            bail!(
                "checksum manifest entry {} does not belong to {}",
                source.display(),
                manifest_directory.display()
            );
        }
        Ok(destination)
    }

    fn apply(&self, cleanup: ManifestCleanup) -> Result<()> {
        for path in cleanup.files {
            match fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to remove prepared executable {}", path.display())
                    });
                }
            }
        }
        fs::remove_file(&cleanup.path).with_context(|| {
            format!(
                "failed to remove checksum manifest {}",
                cleanup.path.display()
            )
        })
    }

    fn prune_empty_directories(&self, directory: &Path) -> Result<()> {
        let mut children = Vec::new();
        for entry in fs::read_dir(directory)
            .with_context(|| format!("failed to read {}", directory.display()))?
        {
            let entry = entry
                .with_context(|| format!("failed to read an entry in {}", directory.display()))?;
            if entry
                .file_type()
                .with_context(|| format!("failed to inspect {}", entry.path().display()))?
                .is_dir()
            {
                children.push(entry.path());
            }
        }
        for child in children {
            self.prune_empty_directories(&child)?;
        }
        if directory != self.root && fs::read_dir(directory)?.next().is_none() {
            fs::remove_dir(directory)
                .with_context(|| format!("failed to remove empty {}", directory.display()))?;
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests;
