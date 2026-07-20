use super::{
    Argument, CommandArguments, CommandContext, CommandFuture, CommandHandler, CommandNode,
};
use crate::channel::{ChannelAgentStatus, ChannelReply};
use crate::store::ChannelSessionKey;
use anyhow::{Result, bail};

const AGENT_NAME_DESCRIPTION: &str = "Configured agent name in this conversation.";

pub(super) fn command() -> CommandNode<CommandHandler> {
    CommandNode::new(
        "ask",
        "Control which agents receive messages in the current conversation.",
    )
    .subcommand(
        CommandNode::new(
            "list",
            "List all subscribed agents and their current status.",
        )
        .handler(list as CommandHandler),
    )
    .subcommand(agent_command(
        "status",
        "Show one agent's current status.",
        status,
    ))
    .subcommand(agent_command(
        "disable",
        "Disable an agent for subsequent messages.",
        disable,
    ))
    .subcommand(agent_command(
        "enable",
        "Enable an agent for subsequent messages.",
        enable,
    ))
}

pub(in crate::daemon) fn set_agent_enabled(
    context: CommandContext<'_>,
    agent_name: &str,
    enabled: bool,
) -> Result<ChannelReply> {
    if update_agent(context, agent_name, enabled)?.is_none() {
        return Ok(unknown_agent_reply(agent_name));
    }
    Ok(ChannelReply::agent_list(
        context.dispatcher().agent_statuses(
            context.channel_name(),
            context.session_id(),
            context.agents(),
        )?,
    ))
}

fn agent_command(
    name: &'static str,
    description: &'static str,
    handler: CommandHandler,
) -> CommandNode<CommandHandler> {
    CommandNode::new(name, description)
        .argument(Argument::required("agent_name", AGENT_NAME_DESCRIPTION))
        .handler(handler)
}

fn list(context: CommandContext, _arguments: CommandArguments) -> CommandFuture {
    Box::pin(async move {
        Ok(ChannelReply::agent_list(
            context.dispatcher().agent_statuses(
                context.channel_name(),
                context.session_id(),
                context.agents(),
            )?,
        ))
    })
}

fn status(context: CommandContext, arguments: CommandArguments) -> CommandFuture {
    Box::pin(async move {
        let agent_name = required_argument(&arguments, "agent_name")?;
        let Some(agent) = context
            .agents()
            .iter()
            .find(|agent| agent.name() == agent_name)
        else {
            return Ok(unknown_agent_reply(agent_name));
        };
        let key = ChannelSessionKey::new(context.channel_name(), context.session_id());
        Ok(ChannelReply::agent_status(ChannelAgentStatus::new(
            agent.name(),
            context
                .dispatcher()
                .store
                .is_agent_enabled(&key, agent.name())?,
        )))
    })
}

fn disable(context: CommandContext, arguments: CommandArguments) -> CommandFuture {
    Box::pin(async move {
        let agent_name = required_argument(&arguments, "agent_name")?;
        update_agent_status(context, agent_name, false)
    })
}

fn enable(context: CommandContext, arguments: CommandArguments) -> CommandFuture {
    Box::pin(async move {
        let agent_name = required_argument(&arguments, "agent_name")?;
        update_agent_status(context, agent_name, true)
    })
}

fn update_agent_status(
    context: CommandContext<'_>,
    agent_name: &str,
    enabled: bool,
) -> Result<ChannelReply> {
    Ok(update_agent(context, agent_name, enabled)?
        .map(ChannelReply::agent_status)
        .unwrap_or_else(|| unknown_agent_reply(agent_name)))
}

fn update_agent(
    context: CommandContext<'_>,
    agent_name: &str,
    enabled: bool,
) -> Result<Option<ChannelAgentStatus>> {
    let Some(agent) = context
        .agents()
        .iter()
        .find(|agent| agent.name() == agent_name)
    else {
        return Ok(None);
    };
    context.dispatcher().set_agent_enabled(
        context.channel_name(),
        context.session_id(),
        agent.name(),
        enabled,
    )?;
    Ok(Some(ChannelAgentStatus::new(agent.name(), enabled)))
}

fn required_argument<'a>(arguments: &'a CommandArguments, name: &str) -> Result<&'a str> {
    let Some(value) = arguments.argument(name) else {
        bail!("validated command invocation is missing argument: {name}");
    };
    Ok(value)
}

fn unknown_agent_reply(agent_name: &str) -> ChannelReply {
    ChannelReply::new(format!("Unknown agent in this conversation: {agent_name}."))
}
