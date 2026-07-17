use crate::store::SessionKey;
use anyhow::{Result, anyhow};
use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::watch;

struct QueueEntry {
    id: u64,
    ahead: watch::Sender<usize>,
}

#[derive(Default)]
struct SessionQueueState {
    next_id: u64,
    entries: VecDeque<QueueEntry>,
}

#[derive(Default)]
struct SessionQueue {
    state: Mutex<SessionQueueState>,
}

impl SessionQueue {
    fn enqueue(self: &Arc<Self>) -> SessionQueueTicket {
        let mut state = self.state();
        let id = state.next_id;
        state.next_id = state.next_id.saturating_add(1);
        let (ahead, receiver) = watch::channel(state.entries.len());
        state.entries.push_back(QueueEntry { id, ahead });
        SessionQueueTicket {
            id,
            queue: Arc::clone(self),
            ahead: receiver,
        }
    }

    fn remove(&self, id: u64) {
        let mut state = self.state();
        let Some(index) = state.entries.iter().position(|entry| entry.id == id) else {
            return;
        };
        state.entries.remove(index);
        for (ahead, entry) in state.entries.iter().enumerate().skip(index) {
            entry.ahead.send_if_modified(|current| {
                if *current == ahead {
                    false
                } else {
                    *current = ahead;
                    true
                }
            });
        }
    }

    fn state(&self) -> std::sync::MutexGuard<'_, SessionQueueState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

pub(super) struct SessionQueueTicket {
    id: u64,
    queue: Arc<SessionQueue>,
    ahead: watch::Receiver<usize>,
}

impl SessionQueueTicket {
    pub(super) fn ahead(&self) -> usize {
        *self.ahead.borrow()
    }

    pub(super) async fn changed(&mut self) -> Result<usize> {
        self.ahead
            .changed()
            .await
            .map_err(|_| anyhow!("session queue position channel closed"))?;
        Ok(*self.ahead.borrow())
    }

    pub(super) async fn wait_until_front(&mut self) -> Result<()> {
        while self.ahead() > 0 {
            self.changed().await?;
        }
        Ok(())
    }
}

impl Drop for SessionQueueTicket {
    fn drop(&mut self) {
        self.queue.remove(self.id);
    }
}

#[derive(Clone, Default)]
pub(super) struct SessionQueues {
    queues: Arc<Mutex<HashMap<SessionKey, Weak<SessionQueue>>>>,
}

impl SessionQueues {
    pub(super) fn enqueue(&self, key: &SessionKey) -> SessionQueueTicket {
        let mut queues = self
            .queues
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        queues.retain(|_, queue| queue.strong_count() > 0);
        let queue = queues.get(key).and_then(Weak::upgrade).unwrap_or_else(|| {
            let queue = Arc::new(SessionQueue::default());
            queues.insert(key.clone(), Arc::downgrade(&queue));
            queue
        });
        queue.enqueue()
    }
}
