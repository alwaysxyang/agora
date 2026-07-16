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
    control: watch::Sender<RunControl>,
}

struct ActiveRunsInner {
    next_id: AtomicU64,
    entries: Mutex<HashMap<u64, ActiveRunEntry>>,
    active_count: watch::Sender<usize>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum RunControl {
    #[default]
    Running,
    Stop,
    Interrupt,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RunCancellation {
    Stopped,
    Interrupted,
}

#[derive(Clone)]
pub(super) struct ActiveRuns {
    inner: Arc<ActiveRunsInner>,
}

impl Default for ActiveRuns {
    fn default() -> Self {
        let (active_count, _) = watch::channel(0);
        Self {
            inner: Arc::new(ActiveRunsInner {
                next_id: AtomicU64::new(1),
                entries: Mutex::new(HashMap::new()),
                active_count,
            }),
        }
    }
}

impl ActiveRuns {
    pub(super) fn register(&self, scope: ActiveRunScope) -> ActiveRun {
        let id = self.inner.next_id.fetch_add(1, Ordering::Relaxed);
        let (control, receiver) = watch::channel(RunControl::Running);
        let mut entries = self.entries();
        entries.insert(id, ActiveRunEntry { scope, control });
        self.inner.active_count.send_replace(entries.len());
        drop(entries);
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
                && entry.control.send(RunControl::Stop).is_ok()
            {
                stopped.insert(entry.scope.agent_name.clone());
            }
        }
        stopped.into_iter().collect()
    }

    pub(super) fn interrupt_all(&self) -> usize {
        self.entries()
            .values()
            .filter(|entry| entry.control.send(RunControl::Interrupt).is_ok())
            .count()
    }

    pub(super) async fn wait_until_empty(&self) {
        let mut active_count = self.inner.active_count.subscribe();
        while *active_count.borrow() > 0 {
            if active_count.changed().await.is_err() {
                return;
            }
        }
    }

    fn remove(&self, id: u64) {
        let mut entries = self.entries();
        entries.remove(&id);
        self.inner.active_count.send_replace(entries.len());
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
    receiver: watch::Receiver<RunControl>,
    runs: ActiveRuns,
}

impl ActiveRun {
    pub(super) async fn cancelled(&mut self) -> RunCancellation {
        loop {
            match *self.receiver.borrow() {
                RunControl::Running => {}
                RunControl::Stop => return RunCancellation::Stopped,
                RunControl::Interrupt => return RunCancellation::Interrupted,
            }
            if self.receiver.changed().await.is_err() {
                return RunCancellation::Interrupted;
            }
        }
    }
}

impl Drop for ActiveRun {
    fn drop(&mut self) {
        self.runs.remove(self.id);
    }
}
