use super::{
    Argument, CommandArguments, CommandContext, CommandFuture, CommandHandler, CommandNode,
};
use crate::channel::ChannelReply;

pub(super) fn command() -> CommandNode<CommandHandler> {
    CommandNode::new(
        "stop",
        "Stop running or queued agent tasks in the current conversation.",
    )
    .argument(Argument::optional(
        "agent_name",
        "Configured agent name. Omit it to stop every agent.",
    ))
    .handler(handle as CommandHandler)
}

fn handle(context: CommandContext, arguments: CommandArguments) -> CommandFuture {
    Box::pin(async move {
        let agent_name = arguments.argument("agent_name");
        let stopped = context.dispatcher().stop_runs(
            context.channel_name(),
            context.session_id(),
            agent_name,
        );
        Ok(reply(agent_name, &stopped))
    })
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
