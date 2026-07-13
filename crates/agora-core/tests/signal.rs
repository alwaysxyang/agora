#![cfg(unix)]

use agora_core::lifecycle::signal::{Signal, SignalHandler, SignalHandlers};
use std::sync::{Arc, Mutex};
use std::time::Duration;

struct RecordingHandler {
    received: Arc<Mutex<Option<Signal>>>,
}

impl SignalHandler for RecordingHandler {
    fn handle(&self, signal: Signal) {
        *self.received.lock().unwrap() = Some(signal);
    }
}

#[tokio::test]
async fn registered_handler_receives_the_matching_signal() {
    let received = Arc::new(Mutex::new(None));
    let signal_number = tokio::signal::unix::SignalKind::terminate().as_raw_value();
    let mut signals = SignalHandlers::new();
    signals
        .register(
            Signal::new(signal_number),
            RecordingHandler {
                received: Arc::clone(&received),
            },
        )
        .unwrap();

    tokio::spawn(async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        let status = std::process::Command::new("kill")
            .arg("-TERM")
            .arg(std::process::id().to_string())
            .status()
            .unwrap();
        assert!(status.success());
    });

    let expected = Signal::new(signal_number);
    assert_eq!(signals.run().await.unwrap(), expected);
    assert_eq!(*received.lock().unwrap(), Some(expected));
}
