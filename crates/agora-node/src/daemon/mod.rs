use crate::agent::{
    AgentOutcome, AgentOutput, AgentRegistry, AgentSessionUpdate, AgentTask, ConfiguredAgent,
};
use crate::channel::{
    Channel, ChannelAgent, ChannelRun, ChannelRunContext, ChannelTask, ConfiguredChannel, RunEvent,
};
use crate::config::NodeConfig;
use crate::output::OutputEvent;
use crate::store::{SessionKey, SessionStore};
use agora_core::logger;
use anyhow::{Result, bail};
use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex, Weak};
use std::time::Duration;
use tokio::sync::Mutex as AsyncMutex;
use tokio::task::JoinSet;

const CHANNEL_RETRY_DELAY: Duration = Duration::from_secs(1);

type SessionLock = Arc<AsyncMutex<()>>;

#[derive(Clone, Default)]
struct SessionLocks {
    locks: Arc<StdMutex<HashMap<SessionKey, Weak<AsyncMutex<()>>>>>,
}

impl SessionLocks {
    fn for_key(&self, key: &SessionKey) -> SessionLock {
        let mut locks = self
            .locks
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        locks.retain(|_, lock| lock.strong_count() > 0);
        if let Some(lock) = locks.get(key).and_then(Weak::upgrade) {
            return lock;
        }
        let lock = Arc::new(AsyncMutex::new(()));
        locks.insert(key.clone(), Arc::downgrade(&lock));
        lock
    }
}

#[derive(Clone)]
pub struct AgentDispatcher {
    store: SessionStore,
    locks: SessionLocks,
}

impl AgentDispatcher {
    pub fn new(store: SessionStore) -> Self {
        Self {
            store,
            locks: SessionLocks::default(),
        }
    }

    pub async fn dispatch_channel_task<C>(
        &self,
        channel: &C,
        agents: Vec<ConfiguredAgent>,
        task: C::Task,
    ) -> Result<()>
    where
        C: Channel + Sync,
        C::Task: Send + Sync + 'static,
        C::Run: Send + Sync + 'static,
    {
        let mut runs: JoinSet<Result<()>> = JoinSet::new();
        for agent in agents {
            let run = channel
                .open_run(
                    &task,
                    ChannelRunContext {
                        agent: ChannelAgent {
                            name: agent.name().to_string(),
                        },
                    },
                )
                .await?;
            let mut output = AgentRunOutput::new(run);
            let agent_task = AgentTask::new(task.task_id(), task.session_id(), task.input());
            let key = SessionKey::new(channel.name(), task.session_id(), agent.name());
            let dispatcher = self.clone();
            runs.spawn(async move {
                output.started().await?;
                match dispatcher
                    .execute_agent(&key, &agent, agent_task, &mut output)
                    .await
                {
                    Ok(outcome) => output.completed(outcome.exit_code()).await,
                    Err(err) => {
                        output.failed(err.to_string()).await?;
                        Err(err)
                    }
                }
            });
        }

        while let Some(result) = runs.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(err)) => logger::error!("agent run failed: {}", err),
                Err(err) => logger::error!("agent task join failed: {}", err),
            }
        }
        Ok(())
    }

    async fn execute_agent<O>(
        &self,
        key: &SessionKey,
        agent: &ConfiguredAgent,
        task: AgentTask,
        output: &mut O,
    ) -> Result<AgentOutcome>
    where
        O: AgentOutput + Send,
    {
        let lock = self.locks.for_key(key);
        let _guard = lock.lock().await;
        let session_id = self.store.get(key)?;
        let mut outcome = agent.run(task.clone(), session_id.clone(), output).await?;

        if outcome.session_update() == &AgentSessionUpdate::NotFound {
            let Some(stale_session_id) = session_id else {
                bail!("agent reported a missing session without a resume session");
            };
            self.store.remove_if_matches(key, &stale_session_id)?;
            logger::info!(
                "agent session missing; starting a new session channel={} channel_session={} agent={}",
                key.channel_name(),
                key.channel_session_id(),
                key.agent_name()
            );
            outcome = agent.run(task, None, output).await?;
            if outcome.session_update() == &AgentSessionUpdate::NotFound {
                bail!("agent reported a missing session after starting without a session");
            }
        }

        if let AgentSessionUpdate::Set(session_id) = outcome.session_update() {
            self.store.save(key, session_id)?;
        }
        Ok(outcome)
    }
}

pub struct Daemon {
    config: NodeConfig,
    dispatcher: AgentDispatcher,
}

impl Daemon {
    pub fn new(config: NodeConfig) -> Result<Self> {
        Ok(Self {
            config,
            dispatcher: AgentDispatcher::new(SessionStore::open_default()?),
        })
    }

    pub async fn run(self) -> Result<()> {
        let Self { config, dispatcher } = self;
        let NodeConfig { channels, agents } = config;
        let agents = AgentRegistry::from_configs(agents)?;
        let mut tasks = JoinSet::new();

        for channel_config in channels {
            let Some(channel) = ConfiguredChannel::from_config(channel_config)? else {
                continue;
            };
            let subscribed_agents = agents.subscribed_to(channel.name());
            if subscribed_agents.is_empty() {
                continue;
            }
            let dispatcher = dispatcher.clone();
            tasks.spawn(
                async move { Self::run_channel(channel, subscribed_agents, dispatcher).await },
            );
        }

        while let Some(result) = tasks.join_next().await {
            result??;
        }
        Ok(())
    }

    async fn run_channel<C>(
        mut channel: C,
        agents: Vec<ConfiguredAgent>,
        dispatcher: AgentDispatcher,
    ) -> Result<()>
    where
        C: Channel + Send + Sync + 'static,
        C::Task: Send + Sync + 'static,
        C::Run: Send + Sync + 'static,
    {
        loop {
            match channel.recv().await {
                Ok(Some(task)) => {
                    if let Err(err) = dispatcher
                        .dispatch_channel_task(&channel, agents.clone(), task)
                        .await
                    {
                        logger::error!("channel task failed channel={}: {}", channel.name(), err);
                    }
                }
                Ok(None) => {
                    logger::error!("channel ended channel={}", channel.name());
                    tokio::time::sleep(CHANNEL_RETRY_DELAY).await;
                }
                Err(err) => {
                    logger::error!("channel receive failed channel={}: {}", channel.name(), err);
                    tokio::time::sleep(CHANNEL_RETRY_DELAY).await;
                }
            }
        }
    }
}

struct AgentRunOutput<R> {
    run: R,
}

impl<R> AgentRunOutput<R>
where
    R: ChannelRun + Send + Sync,
{
    fn new(run: R) -> Self {
        Self { run }
    }

    async fn started(&self) -> Result<()> {
        self.run
            .publish(RunEvent::Started {
                run_id: "local-run".to_string(),
            })
            .await
    }

    async fn completed(&self, exit_code: i32) -> Result<()> {
        self.run.publish(RunEvent::Completed { exit_code }).await
    }

    async fn failed(&self, message: String) -> Result<()> {
        self.run.publish(RunEvent::Failed { message }).await
    }
}

impl<R> AgentOutput for AgentRunOutput<R>
where
    R: ChannelRun + Send + Sync,
{
    async fn write(&mut self, event: OutputEvent) -> Result<()> {
        self.run.publish(RunEvent::Output(event)).await
    }
}
