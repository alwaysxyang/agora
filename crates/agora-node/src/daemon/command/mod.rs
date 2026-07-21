mod ask;
mod executor;
mod registry;
mod reset;
mod stop;

use crate::agent::ConfiguredAgent;
use crate::channel::{ChannelButton, ChannelReply};
use crate::daemon::{ActiveRuns, SessionQueues};
use crate::store::SessionStore;
use crate::task::ChannelTaskInput;
use anyhow::Result;
use std::collections::HashMap;

pub(super) use executor::{AgentDispatch, CommandContext, CommandExecution, CommandHandler};
pub(super) use registry::{
    Argument, CommandArguments, CommandNode, CommandRegistry, CommandResolution, CommandVisibility,
};

pub(super) enum CommandOutcome {
    PassThrough,
    Reply(Option<ChannelReply>),
    Dispatch(AgentDispatch),
}

pub(super) struct CommandRuntime {
    registry: CommandRegistry<CommandHandler>,
}

impl CommandRuntime {
    pub(super) fn new(
        store: SessionStore,
        queues: SessionQueues,
        active_runs: ActiveRuns,
    ) -> Result<Self> {
        let stop = stop::StopCommand::new(active_runs.clone());
        let reset = reset::ResetCommand::new(store.clone(), queues, active_runs);
        let ask = ask::AskCommand::new(store);
        let mut registry = CommandRegistry::new();
        registry.register(stop.command())?;
        registry.register(reset.command())?;
        registry.register(ask.command())?;
        registry.register(stop.internal_command())?;
        Ok(Self { registry })
    }

    pub(super) async fn handle(
        &self,
        channel_name: &str,
        session_id: &str,
        agents: &[ConfiguredAgent],
        input: &ChannelTaskInput,
    ) -> Result<CommandOutcome> {
        let (resolution, context) = match input {
            ChannelTaskInput::Message(content) => (
                self.registry.route_text(content.text()),
                CommandContext::text(channel_name, session_id, agents.to_vec())
                    .with_message(content.clone()),
            ),
            ChannelTaskInput::Command(request) => (
                self.registry.route_structured(request),
                CommandContext::structured(channel_name, session_id, agents.to_vec()),
            ),
        };

        match resolution {
            CommandResolution::AgentInput => Ok(CommandOutcome::PassThrough),
            CommandResolution::Reply(reply) => {
                Ok(CommandOutcome::Reply(Some(ChannelReply::new(reply))))
            }
            CommandResolution::Invocation(invocation) => {
                let (handler, arguments) = invocation.into_parts();
                Ok(match handler.execute(context, arguments).await? {
                    CommandExecution::Reply(reply) => CommandOutcome::Reply(reply),
                    CommandExecution::Dispatch(dispatch) => CommandOutcome::Dispatch(dispatch),
                })
            }
        }
    }

    pub(super) fn run_buttons(
        task_id: &str,
        agents: &[ConfiguredAgent],
    ) -> HashMap<String, Vec<ChannelButton>> {
        agents
            .iter()
            .map(|agent| {
                (
                    agent.name().to_string(),
                    vec![stop::StopCommand::run_button(task_id, agent.name())],
                )
            })
            .collect()
    }

    #[cfg(test)]
    pub(super) fn registry(&self) -> &CommandRegistry<CommandHandler> {
        &self.registry
    }
}
