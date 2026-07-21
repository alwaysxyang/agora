use super::{Argument, CommandArguments, CommandContext, CommandHandler, CommandNode};
use crate::channel::ChannelReply;
use crate::daemon::ExecutionScheduler;

#[derive(Clone)]
pub(super) struct StopCommand {
    scheduler: ExecutionScheduler,
}

impl StopCommand {
    pub(super) fn new(scheduler: ExecutionScheduler) -> Self {
        Self { scheduler }
    }

    pub(super) fn command(&self) -> CommandNode<CommandHandler> {
        let command = self.clone();
        CommandNode::new(
            "stop",
            "Stop running or queued agent tasks in the current conversation.",
        )
        .argument(Argument::optional(
            "agent_name",
            "Configured agent name. Omit it to stop every agent.",
        ))
        .handler(CommandHandler::new(move |context, arguments| {
            let command = command.clone();
            async move { command.stop(context, arguments).await }
        }))
    }

    async fn stop(
        &self,
        context: CommandContext,
        arguments: CommandArguments,
    ) -> anyhow::Result<Option<ChannelReply>> {
        let agent_name = arguments.argument("agent_name");
        let stopped = self
            .scheduler
            .stop(context.channel_name(), context.session_id(), agent_name);
        Ok(Some(Self::reply(agent_name, &stopped)))
    }

    fn reply(agent_name: Option<&str>, stopped: &[String]) -> ChannelReply {
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
}
