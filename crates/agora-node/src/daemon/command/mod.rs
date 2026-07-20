mod ask;
mod executor;
mod registry;
mod reset;
mod stop;

pub(super) use ask::set_agent_enabled;
pub(super) use executor::{CommandContext, CommandExecutor, CommandFuture, CommandHandler};
pub(super) use registry::{
    Argument, CommandArguments, CommandInvocation, CommandNode, CommandRegistry, CommandResolution,
};

impl CommandRegistry<CommandHandler> {
    pub(super) fn standard() -> anyhow::Result<Self> {
        let mut registry = Self::new();
        registry.register(stop::command())?;
        registry.register(reset::command())?;
        registry.register(ask::command())?;
        Ok(registry)
    }
}
