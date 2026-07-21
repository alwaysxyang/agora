use super::{
    Argument, CommandArguments, CommandContext, CommandHandler, CommandNode, CommandVisibility,
};
use crate::channel::{ChannelButton, ChannelButtonStyle, ChannelReply};
use crate::daemon::ActiveRuns;
use crate::task::CommandRequest;

#[derive(Clone)]
pub(super) struct StopCommand {
    active_runs: ActiveRuns,
}

impl StopCommand {
    pub(super) fn new(active_runs: ActiveRuns) -> Self {
        Self { active_runs }
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

    pub(super) fn internal_command(&self) -> CommandNode<CommandHandler> {
        let command = self.clone();
        CommandNode::new("run", "Internal run controls.")
            .visibility(CommandVisibility::Internal)
            .subcommand(
                CommandNode::new("stop", "Stop one agent run.")
                    .argument(Argument::required("task_id", "Channel task id."))
                    .argument(Argument::required("agent_name", "Configured agent name."))
                    .handler(CommandHandler::new(move |context, arguments| {
                        let command = command.clone();
                        async move { command.stop_run(context, arguments).await }
                    })),
            )
    }

    pub(super) fn run_button(task_id: &str, agent_name: &str) -> ChannelButton {
        ChannelButton::new(
            "结束任务",
            ChannelButtonStyle::Danger,
            CommandRequest::new(["run", "stop"])
                .with_argument("task_id", task_id)
                .with_argument("agent_name", agent_name),
        )
    }

    async fn stop(
        &self,
        context: CommandContext,
        arguments: CommandArguments,
    ) -> anyhow::Result<Option<ChannelReply>> {
        let agent_name = arguments.argument("agent_name");
        let stopped =
            self.active_runs
                .stop(context.channel_name(), context.session_id(), agent_name);
        Ok(Some(Self::reply(agent_name, &stopped)))
    }

    async fn stop_run(
        &self,
        context: CommandContext,
        arguments: CommandArguments,
    ) -> anyhow::Result<Option<ChannelReply>> {
        let task_id = Self::required_argument(&arguments, "task_id")?;
        let agent_name = Self::required_argument(&arguments, "agent_name")?;
        let stopped = self.active_runs.stop_task(
            context.channel_name(),
            context.session_id(),
            &task_id,
            &agent_name,
        );
        agora_core::logger::info!(
            "channel stop command channel={} session={} task_id={} agent={} stopped={}",
            context.channel_name(),
            context.session_id(),
            task_id,
            agent_name,
            stopped
        );
        Ok(None)
    }

    fn required_argument(arguments: &CommandArguments, name: &str) -> anyhow::Result<String> {
        arguments.argument(name).map(str::to_string).ok_or_else(|| {
            anyhow::anyhow!("validated command invocation is missing argument: {name}")
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
}
