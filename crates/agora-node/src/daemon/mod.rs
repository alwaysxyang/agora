use crate::agent::{
    AgentOutcome, AgentOutput, AgentRegistry, AgentSessionUpdate, AgentTask, ConfiguredAgent,
    DeleteSessionOutcome,
};
use crate::channel::{
    Channel, ChannelAction, ChannelAgent, ChannelAgentStatus, ChannelReply, ChannelRun,
    ChannelRunContext, ChannelTask, ConfiguredChannel, RunEvent,
};
use crate::config::NodeConfig;
use crate::store::{ChannelSessionKey, SessionKey, SessionStore};
use crate::task::OutputEvent;
use agora_core::logger;
use anyhow::{Result, bail};
use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::{JoinError, JoinSet};

mod active_runs;
mod command;
mod session_queue;

use active_runs::{ActiveRunScope, ActiveRuns, RunCancellation};
use command::{
    CommandContext, CommandExecutor, CommandHandler, CommandRegistry, CommandResolution,
    set_agent_enabled,
};
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
                task.task_id(),
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
                            drop(queue_ticket);
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
                        drop(queue_ticket);
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

    fn stop_task(
        &self,
        channel_name: &str,
        session_id: &str,
        task_id: &str,
        agent_name: &str,
    ) -> bool {
        self.active_runs
            .stop_task(channel_name, session_id, task_id, agent_name)
    }

    fn agent_statuses(
        &self,
        channel_name: &str,
        session_id: &str,
        agents: &[ConfiguredAgent],
    ) -> Result<Vec<ChannelAgentStatus>> {
        let key = ChannelSessionKey::new(channel_name, session_id);
        let disabled = self
            .store
            .disabled_agents(&key)?
            .into_iter()
            .collect::<HashSet<_>>();
        Ok(agents
            .iter()
            .map(|agent| ChannelAgentStatus::new(agent.name(), !disabled.contains(agent.name())))
            .collect())
    }

    fn enabled_agents(
        &self,
        channel_name: &str,
        session_id: &str,
        agents: &[ConfiguredAgent],
    ) -> Result<Vec<ConfiguredAgent>> {
        let key = ChannelSessionKey::new(channel_name, session_id);
        let disabled = self
            .store
            .disabled_agents(&key)?
            .into_iter()
            .collect::<HashSet<_>>();
        Ok(agents
            .iter()
            .filter(|agent| !disabled.contains(agent.name()))
            .cloned()
            .collect())
    }

    fn set_agent_enabled(
        &self,
        channel_name: &str,
        session_id: &str,
        agent_name: &str,
        enabled: bool,
    ) -> Result<()> {
        let key = ChannelSessionKey::new(channel_name, session_id);
        if enabled {
            self.store.enable_agent(&key, agent_name)?;
        } else {
            self.store.disable_agent(&key, agent_name)?;
        }
        Ok(())
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
    commands: Arc<CommandRegistry<CommandHandler>>,
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
            commands: Arc::new(CommandRegistry::standard()?),
        })
    }

    pub fn shutdown_handle(&self) -> DaemonShutdown {
        DaemonShutdown {
            active_runs: self.dispatcher.active_runs.clone(),
        }
    }

    pub async fn run(self) -> Result<()> {
        let Self {
            config,
            dispatcher,
            commands,
        } = self;
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
            let commands = Arc::clone(&commands);
            tasks.spawn(async move {
                Self::run_channel(channel, subscribed_agents, dispatcher, commands).await
            });
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
        commands: Arc<CommandRegistry<CommandHandler>>,
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
                            &commands,
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
        commands: &CommandRegistry<CommandHandler>,
        task: C::Task,
        runs: &mut JoinSet<Result<()>>,
    ) -> Result<()>
    where
        C: Channel + Sync,
        C::Task: Send + Sync + 'static,
        C::Run: Send + Sync + 'static,
    {
        match task.action() {
            Some(ChannelAction::StopTask {
                task_id,
                agent_name,
            }) => {
                let stopped =
                    dispatcher.stop_task(channel.name(), task.session_id(), task_id, agent_name);
                logger::info!(
                    "channel stop action channel={} session={} task_id={} agent={} stopped={}",
                    channel.name(),
                    task.session_id(),
                    task_id,
                    agent_name,
                    stopped
                );
                return Ok(());
            }
            Some(ChannelAction::SetAgentEnabled {
                agent_name,
                enabled,
            }) => {
                let reply = set_agent_enabled(
                    CommandContext::new(channel.name(), task.session_id(), agents, dispatcher),
                    agent_name,
                    *enabled,
                )?;
                return channel.reply(&task, reply).await;
            }
            None => {}
        }

        match commands.route(task.content().text()) {
            CommandResolution::AgentInput => {
                let enabled =
                    dispatcher.enabled_agents(channel.name(), task.session_id(), agents)?;
                if enabled.is_empty() {
                    channel
                        .reply(
                            &task,
                            ChannelReply::new("No agents are enabled in this conversation."),
                        )
                        .await
                } else {
                    dispatcher
                        .start_channel_task(channel, enabled, task, runs)
                        .await
                }
            }
            CommandResolution::Invocation(invocation) => {
                let reply =
                    CommandExecutor::new(channel.name(), task.session_id(), agents, dispatcher)
                        .execute(invocation)
                        .await?;
                channel.reply(&task, reply).await
            }
            CommandResolution::Reply(reply) => channel.reply(&task, ChannelReply::new(reply)).await,
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
