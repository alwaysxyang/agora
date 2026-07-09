use agora_core::logger;
use std::io::stdout;

mod channel;
mod daemon;
mod runtime;
mod store;

fn hello() -> &'static str {
    "hello from agora-node"
}

fn main() {
    logger::init(stdout(), logger::LevelFilter::Debug).unwrap();
    logger::info!("{}", hello());
    logger::debug!("node logger initialized");
}
