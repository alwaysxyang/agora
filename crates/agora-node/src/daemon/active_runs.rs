use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ActiveRunScope {
    channel_name: String,
    session_id: String,
    agent_name: String,
}

impl ActiveRunScope {
    pub(super) fn new(
        channel_name: impl Into<String>,
        session_id: impl Into<String>,
        agent_name: impl Into<String>,
    ) -> Self {
        Self {
            channel_name: channel_name.into(),
            session_id: session_id.into(),
            agent_name: agent_name.into(),
        }
    }
}

struct ActiveRunEntry {
    scope: ActiveRunScope,
    stop: watch::Sender<bool>,
}

struct ActiveRunsInner {
    next_id: AtomicU64,
    entries: Mutex<HashMap<u64, ActiveRunEntry>>,
}

#[derive(Clone)]
pub(super) struct ActiveRuns {
    inner: Arc<ActiveRunsInner>,
}

impl Default for ActiveRuns {
    fn default() -> Self {
        Self {
            inner: Arc::new(ActiveRunsInner {
                next_id: AtomicU64::new(1),
                entries: Mutex::new(HashMap::new()),
            }),
        }
    }
}

impl ActiveRuns {
    pub(super) fn register(&self, scope: ActiveRunScope) -> ActiveRun {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (stop, receiver) = watch::channel(false);
        self.entries().insert(id, ActiveRunEntry { scope, stop });
        ActiveRun {
            id,
            receiver,
            runs: self.clone(),
        }
    }

    pub(super) fn stop(
        &self,
        channel_name: &str,
        session_id: &str,
        agent_name: Option<&str>,
    ) -> Vec<String> {
        let mut stopped = BTreeSet::new();
        for entry in self.entries().values() {
            let matches_agent = agent_name
                .map(|name| name == entry.scope.agent_name)
                .unwrap_or(true);
            if entry.scope.channel_name == channel_name
                && entry.scope.session_id == session_id
                && matches_agent
                && entry.stop.send(true).is_ok()
            {
                stopped.insert(entry.scope.agent_name.clone());
            }
        }
        stopped.into_iter().collect()
    }

    fn remove(&self, id: u64) {
        self.entries().remove(&id);
    }

    fn entries(&self) -> std::sync::MutexGuard<'_, HashMap<u64, ActiveRunEntry>> {
        self.inner
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(super) struct ActiveRun {
    id: u64,
    receiver: watch::Receiver<bool>,
    runs: ActiveRuns,
}

impl ActiveRun {
    pub(super) async fn cancelled(&mut self) {
        while !*self.receiver.borrow() {
            if self.receiver.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Drop for ActiveRun {
    fn drop(&mut self) {
        self.runs.remove(self.id);
    }
}
