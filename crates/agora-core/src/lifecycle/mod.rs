pub mod shutdown;
pub mod signal;

use anyhow::Result;
use shutdown::{ShutdownGuard, ShutdownReason};
use signal::{Signal, SignalHandler, SignalHandlers};
use std::future::Future;
use std::sync::Arc;

impl SignalHandler for Arc<ShutdownGuard> {
    fn handle(&self, signal: Signal) {
        self.shutdown(ShutdownReason::Signal {
            signal: signal.number(),
        });
    }
}

impl ShutdownGuard {
    pub async fn run<F, H>(self: Arc<Self>, process: F, signals: SignalHandlers<H>) -> Result<()>
    where
        F: Future<Output = Result<()>>,
        H: SignalHandler,
    {
        let lifecycle_error = {
            let signal = signals.run();
            tokio::pin!(process);
            tokio::pin!(signal);

            tokio::select! {
                biased;
                _reason = shutdown::wait_for_shutdown() => None,
                result = &mut signal => match result {
                    Ok(signal) => {
                        self.shutdown(ShutdownReason::Signal {
                            signal: signal.number(),
                        });
                        None
                    }
                    Err(err) => {
                        self.shutdown(ShutdownReason::Failed {
                            error: err.to_string(),
                        });
                        Some(err.into())
                    }
                },
                result = &mut process => match result {
                    Ok(()) => {
                        self.shutdown(ShutdownReason::Normal);
                        None
                    }
                    Err(err) => {
                        self.shutdown(ShutdownReason::Failed {
                            error: err.to_string(),
                        });
                        Some(err)
                    }
                },
            }
        };

        drop(self);
        match lifecycle_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}
