use agora_core::{
    lifecycle::{
        shutdown::ShutdownGuard,
        signal::{Signal, SignalHandlers},
    },
    logger,
};
use agora_node::{config, daemon::Daemon};
use clap::{ColorChoice, Parser};
use std::io::stdout;
use std::sync::Arc;

const CONFIG_HELP: &str = include_str!("usage.txt");

#[derive(Parser)]
#[command(
    name = "agora-node",
    about = "local agora agent daemon",
    color = ColorChoice::Always,
    after_long_help = CONFIG_HELP
)]
struct Opts {
    /// config file path
    #[arg(long, short)]
    config: String,
}

fn load_config(path: &str) -> anyhow::Result<config::NodeConfig> {
    let content = std::fs::read_to_string(path)?;
    let config = serde_json::from_str(&content)?;
    Ok(config)
}

async fn async_main(opts: Opts) -> anyhow::Result<()> {
    let config_path = opts.config.clone();
    let config = load_config(&config_path)?;
    logger::info!(
        "loaded {} channels and {} agents",
        config.channels.len(),
        config.agents.len()
    );
    let guard = ShutdownGuard::get();
    let signals = shutdown_signals(&guard)?;
    let daemon = Daemon::new(config)?;
    let shutdown = daemon.shutdown_handle();
    guard
        .run_with_shutdown(daemon.run(), signals, move |_reason| async move {
            shutdown.interrupt().await;
        })
        .await
}

#[cfg(unix)]
fn shutdown_signals(
    guard: &Arc<ShutdownGuard>,
) -> anyhow::Result<SignalHandlers<Arc<ShutdownGuard>>> {
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
fn shutdown_signals(
    _guard: &Arc<ShutdownGuard>,
) -> anyhow::Result<SignalHandlers<Arc<ShutdownGuard>>> {
    Ok(SignalHandlers::new())
}

fn main() {
    if let Err(err) = logger::init(stdout(), logger::LevelFilter::Info) {
        eprintln!("initialize logger failed: {err}");
        std::process::exit(1);
    }
    let opts = Opts::parse();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .worker_threads(4)
        .build()
    {
        Ok(runtime) => runtime,
        Err(err) => {
            logger::error!("initialize tokio runtime failed: {}", err);
            std::process::exit(1);
        }
    };
    if let Err(err) = runtime.block_on(async_main(opts)) {
        logger::error!("{}", err);
        std::process::exit(1);
    }
}
