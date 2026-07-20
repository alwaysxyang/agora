use super::{CommandArguments, CommandContext, CommandFuture, CommandHandler, CommandNode};
use crate::channel::ChannelReply;

pub(super) fn command() -> CommandNode<CommandHandler> {
    CommandNode::new("reset", "Stop tasks and reset backend agent sessions.")
        .handler(handle as CommandHandler)
}

fn handle(context: CommandContext, _arguments: CommandArguments) -> CommandFuture {
    Box::pin(async move {
        let failed = context
            .dispatcher()
            .reset_sessions(
                context.channel_name(),
                context.session_id(),
                context.agents(),
            )
            .await;
        Ok(if failed.is_empty() {
            ChannelReply::new("Reset successful.")
        } else {
            ChannelReply::new(format!("Reset failed for agents: {}.", failed.join(", ")))
        })
    })
}
