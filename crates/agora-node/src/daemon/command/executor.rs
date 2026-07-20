use super::super::AgentDispatcher;
use super::{CommandArguments, CommandInvocation};
use crate::agent::ConfiguredAgent;
use crate::channel::ChannelReply;
use anyhow::Result;
use std::future::Future;
use std::pin::Pin;

pub(in crate::daemon) type CommandFuture<'a> =
    Pin<Box<dyn Future<Output = Result<ChannelReply>> + Send + 'a>>;
pub(in crate::daemon) type CommandHandler =
    for<'a> fn(CommandContext<'a>, CommandArguments) -> CommandFuture<'a>;

#[derive(Clone, Copy)]
pub(in crate::daemon) struct CommandContext<'a> {
    channel_name: &'a str,
    session_id: &'a str,
    agents: &'a [ConfiguredAgent],
    dispatcher: &'a AgentDispatcher,
}

impl<'a> CommandContext<'a> {
    pub(in crate::daemon) fn new(
        channel_name: &'a str,
        session_id: &'a str,
        agents: &'a [ConfiguredAgent],
        dispatcher: &'a AgentDispatcher,
    ) -> Self {
        Self {
            channel_name,
            session_id,
            agents,
            dispatcher,
        }
    }

    pub(super) fn channel_name(&self) -> &'a str {
        self.channel_name
    }

    pub(super) fn session_id(&self) -> &'a str {
        self.session_id
    }

    pub(super) fn agents(&self) -> &'a [ConfiguredAgent] {
        self.agents
    }

    pub(super) fn dispatcher(&self) -> &'a AgentDispatcher {
        self.dispatcher
    }
}

pub(in crate::daemon) struct CommandExecutor<'a> {
    context: CommandContext<'a>,
}

impl<'a> CommandExecutor<'a> {
    pub(in crate::daemon) fn new(
        channel_name: &'a str,
        session_id: &'a str,
        agents: &'a [ConfiguredAgent],
        dispatcher: &'a AgentDispatcher,
    ) -> Self {
        Self {
            context: CommandContext::new(channel_name, session_id, agents, dispatcher),
        }
    }

    pub(in crate::daemon) async fn execute(
        &self,
        invocation: CommandInvocation<CommandHandler>,
    ) -> Result<ChannelReply> {
        let (handler, arguments) = invocation.into_parts();
        handler(self.context, arguments).await
    }
}
