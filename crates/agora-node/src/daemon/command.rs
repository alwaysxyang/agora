#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum NodeCommand {
    Stop { agent_name: Option<String> },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum CommandRoute {
    AgentInput,
    Command(NodeCommand),
    Invalid(String),
}

pub(super) struct CommandParser;

impl CommandParser {
    pub(super) fn parse(input: &str) -> CommandRoute {
        let input = input.trim();
        if !input.starts_with('/') {
            return CommandRoute::AgentInput;
        }

        let mut parts = input.split_whitespace();
        let command = parts.next().unwrap_or_default();
        match command {
            "/stop" => {
                let agent_name = parts.next().map(str::to_string);
                if parts.next().is_some() {
                    CommandRoute::Invalid("Usage: /stop [agent_name]".to_string())
                } else {
                    CommandRoute::Command(NodeCommand::Stop { agent_name })
                }
            }
            _ => CommandRoute::Invalid(format!("Unknown command: {command}")),
        }
    }
}
