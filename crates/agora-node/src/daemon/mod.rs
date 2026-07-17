use crate::agent::{
    AgentOutcome, AgentOutput, AgentRegistry, AgentSessionUpdate, AgentTask, ConfiguredAgent,
    DeleteSessionOutcome,
};
use crate::channel::{
    Channel, ChannelAgent, ChannelReply, ChannelRun, ChannelRunContext, ChannelTask,
    ConfiguredChannel, RunEvent,
};
use crate::config::NodeConfig;
use crate::store::{SessionKey, SessionStore};
use crate::task::OutputEvent;
use agora_core::logger;
use anyhow::{Result, bail};
use std::collections::VecDeque;
use std::time::Duration;
use tokio::task::{JoinError, JoinSet};

mod active_runs;
mod command;
mod session_queue;

use active_runs::{ActiveRunScope, ActiveRuns, RunCancellation};
use command::{CommandParser, CommandRoute, NodeCommand};
use session_queue::SessionQueues;

#[cfg(test)]
#[path = "../../tests/internal/daemon_command.rs"]
mod command_tests;

const CHANNEL_RETRY_DELAY: Duration = Duration::from_secs(1);
const SHUTDOWN_RUN_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone)]
pub struct AgentDispatcher {
    store: SessionStore,
    queues: SessionQueues,
    active_runs: ActiveRuns,
}

impl AgentDispatcher {
    pub fn new(store: SessionStore) -> Self {
        Self {
            store,
            queues: SessionQueues::default(),
            active_runs: ActiveRuns::default(),
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
        self.start_channel_task(channel, agents, task, &mut runs)
            .await?;

        while let Some(result) = runs.join_next().await {
            Self::log_run_result(result);
        }
        Ok(())
    }

    async fn start_channel_task<C>(
        &self,
        channel: &C,
        agents: Vec<ConfiguredAgent>,
        task: C::Task,
        runs: &mut JoinSet<Result<()>>,
    ) -> Result<()>
    where
        C: Channel + Sync,
        C::Task: Send + Sync + 'static,
        C::Run: Send + Sync + 'static,
    {
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
            let agent_task = AgentTask::new(task.content().clone());
            let isolation_scope = agent.isolation_scope(channel.name(), task.session_id());
            let key = SessionKey::new(agent.name(), isolation_scope.clone());
            let mut active_run = self.active_runs.register(ActiveRunScope::new(
                channel.name(),
                task.session_id(),
                key.clone(),
            ));
            let mut queue_ticket = self.queues.enqueue(&key);
            let dispatcher = self.clone();
            runs.spawn(async move {
                let mut ahead = queue_ticket.ahead();
                while ahead > 0 {
                    output.queued(ahead).await?;
                    ahead = tokio::select! {
                        ahead = queue_ticket.changed() => ahead?,
                        cancellation = active_run.cancelled() => {
                            return output.cancelled(cancellation).await;
                        }
                    };
                }
                output.started().await?;
                let result = tokio::select! {
                    result = dispatcher.execute_agent(
                        &key,
                        &agent,
                        agent_task,
                        &mut output,
                    ) => result,
                    cancellation = active_run.cancelled() => {
                        return output.cancelled(cancellation).await;
                    }
                };
                match result {
                    Ok(outcome) => output.completed(outcome.exit_code()).await,
                    Err(err) => {
                        output.failed(err.to_string()).await?;
                        Err(err)
                    }
                }
            });
        }
        Ok(())
    }

    fn stop_runs(
        &self,
        channel_name: &str,
        session_id: &str,
        agent_name: Option<&str>,
    ) -> Vec<String> {
        self.active_runs.stop(channel_name, session_id, agent_name)
    }

    async fn reset_sessions(
        &self,
        channel_name: &str,
        session_id: &str,
        agents: &[ConfiguredAgent],
    ) -> Vec<String> {
        let mut resets = agents
            .iter()
            .map(|agent| {
                let key = SessionKey::new(
                    agent.name(),
                    agent.isolation_scope(channel_name, session_id),
                );
                let barrier = self.queues.enqueue(&key);
                (agent.clone(), key, barrier)
            })
            .collect::<VecDeque<_>>();
        let keys = resets
            .iter()
            .map(|(_, key, _)| key.clone())
            .collect::<Vec<_>>();
        self.active_runs.stop_session_keys(&keys);

        let mut failed = Vec::new();
        while let Some((agent, key, mut barrier)) = resets.pop_front() {
            let result = async {
                barrier.wait_until_front().await?;
                self.reset_agent_session(&key, &agent).await
            }
            .await;
            if let Err(err) = result {
                logger::error!(
                    "agent session reset failed agent={} isolation={}: {}",
                    key.agent_name(),
                    key.isolation_scope().as_str(),
                    err
                );
                failed.push(key.agent_name().to_string());
            }
        }
        failed
    }

    async fn reset_agent_session(&self, key: &SessionKey, agent: &ConfiguredAgent) -> Result<()> {
        let Some(session_id) = self.store.get(key)? else {
            return Ok(());
        };

        match agent.delete_session(&session_id).await? {
            DeleteSessionOutcome::Deleted => {}
            DeleteSessionOutcome::Unsupported => logger::info!(
                "agent does not support backend session deletion agent={} isolation={}",
                key.agent_name(),
                key.isolation_scope().as_str()
            ),
        }
        if !self.store.remove_if_matches(key, &session_id)? {
            bail!("agent session mapping changed while reset was in progress");
        }
        logger::info!(
            "agent session reset agent={} isolation={}",
            key.agent_name(),
            key.isolation_scope().as_str()
        );
        Ok(())
    }

    fn log_run_result(result: std::result::Result<Result<()>, JoinError>) {
        match result {
            Ok(Ok(())) => {}
            Ok(Err(err)) => logger::error!("agent run failed: {}", err),
            Err(err) => logger::error!("agent task join failed: {}", err),
        }
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
        let session_id = self.store.get(key)?;
        let mut outcome = agent.run(task.clone(), session_id.clone(), output).await?;

        if outcome.session_update() == &AgentSessionUpdate::NotFound {
            let Some(stale_session_id) = session_id else {
                bail!("agent reported a missing session without a resume session");
            };
            self.store.remove_if_matches(key, &stale_session_id)?;
            logger::info!(
                "agent session missing; starting a new session agent={} isolation={}",
                key.agent_name(),
                key.isolation_scope().as_str()
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

#[derive(Clone)]
pub struct DaemonShutdown {
    active_runs: ActiveRuns,
}

impl DaemonShutdown {
    pub async fn interrupt(&self) {
        let interrupted = self.active_runs.interrupt_all();
        if interrupted == 0 {
            return;
        }
        logger::info!("interrupting {} agent runs before shutdown", interrupted);
        if tokio::time::timeout(SHUTDOWN_RUN_TIMEOUT, self.active_runs.wait_until_empty())
            .await
            .is_err()
        {
            logger::error!(
                "timed out waiting for agent interruption notifications after {} seconds",
                SHUTDOWN_RUN_TIMEOUT.as_secs()
            );
        }
    }
}

impl Daemon {
    pub fn new(config: NodeConfig) -> Result<Self> {
        Ok(Self {
            config,
            dispatcher: AgentDispatcher::new(SessionStore::open_default()?),
        })
    }

    pub fn shutdown_handle(&self) -> DaemonShutdown {
        DaemonShutdown {
            active_runs: self.dispatcher.active_runs.clone(),
        }
    }

    pub async fn run(self) -> Result<()> {
        let Self { config, dispatcher } = self;
        let NodeConfig { channels, agents } = config;
        let agents = AgentRegistry::from_configs(agents)?;
        let shutdown = DaemonShutdown {
            active_runs: dispatcher.active_runs.clone(),
        };
        let mut configured_channels = Vec::new();

        for channel_config in channels {
            let Some(channel) = ConfiguredChannel::from_config(channel_config)? else {
                continue;
            };
            let subscribed_agents = agents.subscribed_to(channel.name());
            if subscribed_agents.is_empty() {
                continue;
            }
            configured_channels.push((channel, subscribed_agents));
        }

        let mut tasks = JoinSet::new();
        for (channel, subscribed_agents) in configured_channels {
            let dispatcher = dispatcher.clone();
            tasks.spawn(
                async move { Self::run_channel(channel, subscribed_agents, dispatcher).await },
            );
        }

        while let Some(result) = tasks.join_next().await {
            match result {
                Ok(Ok(())) => {}
                Ok(Err(err)) => {
                    shutdown.interrupt().await;
                    return Err(err);
                }
                Err(err) => {
                    shutdown.interrupt().await;
                    return Err(err.into());
                }
            }
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
        let mut runs = JoinSet::new();
        loop {
            tokio::select! {
                received = channel.recv() => match received {
                    Ok(Some(task)) => {
                        if let Err(err) = Self::route_channel_task(
                            &channel,
                            &agents,
                            &dispatcher,
                            task,
                            &mut runs,
                        )
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
                },
                result = runs.join_next(), if !runs.is_empty() => {
                    if let Some(result) = result {
                        AgentDispatcher::log_run_result(result);
                    }
                },
            }
        }
    }

    async fn route_channel_task<C>(
        channel: &C,
        agents: &[ConfiguredAgent],
        dispatcher: &AgentDispatcher,
        task: C::Task,
        runs: &mut JoinSet<Result<()>>,
    ) -> Result<()>
    where
        C: Channel + Sync,
        C::Task: Send + Sync + 'static,
        C::Run: Send + Sync + 'static,
    {
        match CommandParser::parse(task.content().text()) {
            CommandRoute::AgentInput => {
                dispatcher
                    .start_channel_task(channel, agents.to_vec(), task, runs)
                    .await
            }
            CommandRoute::Command(NodeCommand::Stop { agent_name }) => {
                let stopped =
                    dispatcher.stop_runs(channel.name(), task.session_id(), agent_name.as_deref());
                channel
                    .reply(&task, Self::stop_reply(agent_name.as_deref(), &stopped))
                    .await
            }
            CommandRoute::Command(NodeCommand::Reset) => {
                let failed = dispatcher
                    .reset_sessions(channel.name(), task.session_id(), agents)
                    .await;
                channel.reply(&task, Self::reset_reply(&failed)).await
            }
            CommandRoute::Invalid(message) => {
                channel.reply(&task, ChannelReply::new(message)).await
            }
        }
    }

    fn stop_reply(agent_name: Option<&str>, stopped: &[String]) -> ChannelReply {
        if stopped.is_empty() {
            return match agent_name {
                Some(agent_name) => ChannelReply::new(format!(
                    "No running agent named {agent_name} in this conversation."
                )),
                None => ChannelReply::new("No running agents in this conversation."),
            };
        }

        let suffix = if stopped.len() == 1 {
            "agent"
        } else {
            "agents"
        };
        ChannelReply::new(format!(
            "Stopped {} {suffix}: {}.",
            stopped.len(),
            stopped.join(", ")
        ))
    }

    fn reset_reply(failed: &[String]) -> ChannelReply {
        if failed.is_empty() {
            ChannelReply::new("Reset successful.")
        } else {
            ChannelReply::new(format!("Reset failed for agents: {}.", failed.join(", ")))
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

    async fn queued(&self, ahead: usize) -> Result<()> {
        self.run.publish(RunEvent::Queued { ahead }).await
    }

    async fn completed(&self, exit_code: i32) -> Result<()> {
        self.run.publish(RunEvent::Completed { exit_code }).await
    }

    async fn failed(&self, message: String) -> Result<()> {
        self.run.publish(RunEvent::Failed { message }).await
    }

    async fn stopped(&self) -> Result<()> {
        self.run.publish(RunEvent::Stopped).await
    }

    async fn interrupted(&self) -> Result<()> {
        let result = self.run.publish(RunEvent::Interrupted).await;
        if let Err(err) = &result {
            logger::error!("failed to publish interrupted agent run: {}", err);
        }
        result
    }

    async fn cancelled(&self, cancellation: RunCancellation) -> Result<()> {
        match cancellation {
            RunCancellation::Stopped => self.stopped().await,
            RunCancellation::Interrupted => self.interrupted().await,
        }
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
