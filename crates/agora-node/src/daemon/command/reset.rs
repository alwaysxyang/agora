use super::{CommandArguments, CommandContext, CommandHandler, CommandNode};
use crate::agent::{ConfiguredAgent, DeleteSessionOutcome};
use crate::channel::ChannelReply;
use crate::daemon::{ActiveRuns, SessionQueues};
use crate::store::{SessionKey, SessionStore};
use agora_core::logger;
use anyhow::{Result, bail};
use std::collections::VecDeque;

#[derive(Clone)]
pub(super) struct ResetCommand {
    store: SessionStore,
    queues: SessionQueues,
    active_runs: ActiveRuns,
}

impl ResetCommand {
    pub(super) fn new(store: SessionStore, queues: SessionQueues, active_runs: ActiveRuns) -> Self {
        Self {
            store,
            queues,
            active_runs,
        }
    }

    pub(super) fn command(&self) -> CommandNode<CommandHandler> {
        let command = self.clone();
        CommandNode::new("reset", "Stop tasks and reset backend agent sessions.").handler(
            CommandHandler::new(move |context, arguments| {
                let command = command.clone();
                async move { command.reset(context, arguments).await }
            }),
        )
    }

    async fn reset(
        &self,
        context: CommandContext,
        _arguments: CommandArguments,
    ) -> Result<Option<ChannelReply>> {
        let failed = self
            .reset_sessions(
                context.channel_name(),
                context.session_id(),
                context.agents(),
            )
            .await;
        Ok(Some(if failed.is_empty() {
            ChannelReply::new("Reset successful.")
        } else {
            ChannelReply::new(format!("Reset failed for agents: {}.", failed.join(", ")))
        }))
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
}
