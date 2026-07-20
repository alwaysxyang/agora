use anyhow::{Result, bail};
use std::collections::HashSet;

const HELP: &str = "help";

#[derive(Clone, Debug)]
pub(in crate::daemon) struct Argument {
    name: &'static str,
    description: &'static str,
    required: bool,
}

impl Argument {
    pub(in crate::daemon) fn required(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            required: true,
        }
    }

    pub(in crate::daemon) fn optional(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            required: false,
        }
    }

    fn syntax(&self) -> String {
        if self.required {
            format!("{{{}}}", self.name)
        } else {
            format!("[{{{}}}]", self.name)
        }
    }

    fn help(&self) -> String {
        let requirement = if self.required {
            "required"
        } else {
            "optional"
        };
        format!("{} ({requirement}) - {}", self.name, self.description)
    }
}

#[derive(Clone, Debug)]
pub(in crate::daemon) struct CommandNode<H> {
    name: &'static str,
    description: &'static str,
    arguments: Vec<Argument>,
    handler: Option<H>,
    subcommands: Vec<CommandNode<H>>,
}

impl<H> CommandNode<H> {
    pub(in crate::daemon) fn new(name: &'static str, description: &'static str) -> Self {
        Self {
            name,
            description,
            arguments: Vec::new(),
            handler: None,
            subcommands: Vec::new(),
        }
    }

    pub(in crate::daemon) fn argument(mut self, argument: Argument) -> Self {
        self.arguments.push(argument);
        self
    }

    pub(in crate::daemon) fn handler(mut self, handler: H) -> Self {
        self.handler = Some(handler);
        self
    }

    pub(in crate::daemon) fn subcommand(mut self, subcommand: CommandNode<H>) -> Self {
        self.subcommands.push(subcommand);
        self
    }

    fn validate(&self, parent: &str) -> Result<()> {
        let path = if parent.is_empty() {
            self.name.to_string()
        } else {
            format!("{parent} {}", self.name)
        };
        if !Self::valid_name(self.name) {
            bail!("invalid command name: {path}");
        }
        if self.name == HELP {
            bail!("command name is reserved: {path}");
        }
        if self.description.trim().is_empty() {
            bail!("command description is empty: {path}");
        }
        if self.handler.is_none() && !self.arguments.is_empty() {
            bail!("command without a handler has arguments: {path}");
        }
        if self.handler.is_none() && self.subcommands.is_empty() {
            bail!("command has neither a handler nor subcommands: {path}");
        }

        let mut optional_seen = false;
        let mut argument_names = HashSet::new();
        for argument in &self.arguments {
            if !Self::valid_name(argument.name) {
                bail!("invalid argument name in /{path}: {}", argument.name);
            }
            if !argument_names.insert(argument.name) {
                bail!("duplicate argument in /{path}: {}", argument.name);
            }
            if optional_seen && argument.required {
                bail!("required argument follows an optional argument in /{path}");
            }
            optional_seen |= !argument.required;
        }

        let mut subcommand_names = HashSet::new();
        for subcommand in &self.subcommands {
            if !subcommand_names.insert(subcommand.name) {
                bail!("duplicate subcommand in /{path}: {}", subcommand.name);
            }
            subcommand.validate(&path)?;
        }
        Ok(())
    }

    fn valid_name(name: &str) -> bool {
        !name.is_empty()
            && name.chars().all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '-' | '_')
            })
    }

    fn syntax(&self, path: &[&str]) -> String {
        let mut syntax = format!("/{}", path.join(" "));
        for argument in &self.arguments {
            syntax.push(' ');
            syntax.push_str(&argument.syntax());
        }
        syntax
    }

    fn help(&self, path: &[&str]) -> String {
        let command_path = format!("/{}", path.join(" "));
        let mut lines = vec![format!("{command_path} - {}", self.description)];

        if self.handler.is_some() {
            lines.push(String::new());
            lines.push("Usage:".to_string());
            lines.push(self.syntax(path));
            if !self.arguments.is_empty() {
                lines.push(String::new());
                lines.push("Arguments:".to_string());
                lines.extend(self.arguments.iter().map(Argument::help));
            }
        }

        if !self.subcommands.is_empty() {
            lines.push(String::new());
            lines.push("Subcommands:".to_string());
            for subcommand in &self.subcommands {
                let mut subcommand_path = path.to_vec();
                subcommand_path.push(subcommand.name);
                lines.push(subcommand.syntax(&subcommand_path));
                lines.push(format!("  {}", subcommand.description));
                lines.extend(
                    subcommand
                        .arguments
                        .iter()
                        .map(|argument| format!("  {}", argument.help())),
                );
            }
            lines.push(String::new());
            lines.push(format!(
                "Use {command_path} {{subcommand}} help for details."
            ));
        }

        lines.join("\n")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ParsedArgument {
    name: &'static str,
    value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::daemon) struct CommandArguments {
    values: Vec<ParsedArgument>,
}

impl CommandArguments {
    pub(in crate::daemon) fn argument(&self, name: &str) -> Option<&str> {
        self.values
            .iter()
            .find(|argument| argument.name == name)
            .map(|argument| argument.value.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::daemon) struct CommandInvocation<H> {
    handler: H,
    arguments: CommandArguments,
}

impl<H> CommandInvocation<H> {
    pub(in crate::daemon) fn into_parts(self) -> (H, CommandArguments) {
        (self.handler, self.arguments)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::daemon) enum CommandResolution<H> {
    AgentInput,
    Invocation(CommandInvocation<H>),
    Reply(String),
}

pub(in crate::daemon) struct CommandRegistry<H> {
    commands: Vec<CommandNode<H>>,
}

impl<H> CommandRegistry<H>
where
    H: Clone,
{
    pub(in crate::daemon) fn new() -> Self {
        Self {
            commands: Vec::new(),
        }
    }

    pub(in crate::daemon) fn register(&mut self, command: CommandNode<H>) -> Result<()> {
        command.validate("")?;
        if self
            .commands
            .iter()
            .any(|current| current.name == command.name)
        {
            bail!("duplicate root command: {}", command.name);
        }
        self.commands.push(command);
        Ok(())
    }

    pub(in crate::daemon) fn route(&self, input: &str) -> CommandResolution<H> {
        let input = input.trim();
        if !input.starts_with('/') {
            return CommandResolution::AgentInput;
        }

        let mut parts = input.split_whitespace();
        let token = parts.next().unwrap_or_default();
        let command_name = token.strip_prefix('/').unwrap_or_default();
        let remaining = parts.collect::<Vec<_>>();

        if command_name == HELP {
            return if remaining.is_empty() {
                CommandResolution::Reply(self.help())
            } else {
                CommandResolution::Reply("Usage: /help".to_string())
            };
        }

        let Some(command) = self
            .commands
            .iter()
            .find(|command| command.name == command_name)
        else {
            return CommandResolution::Reply(format!(
                "Unknown command: {token}\nUse /help to list commands."
            ));
        };

        let mut path = vec![command.name];
        Self::resolve(command, &mut path, &remaining)
    }

    fn resolve(
        command: &CommandNode<H>,
        path: &mut Vec<&'static str>,
        remaining: &[&str],
    ) -> CommandResolution<H> {
        if let Some(token) = remaining.first() {
            if *token == HELP {
                return if remaining.len() == 1 {
                    CommandResolution::Reply(command.help(path))
                } else {
                    CommandResolution::Reply(format!("Usage: /{} help", path.join(" ")))
                };
            }
            if let Some(subcommand) = command
                .subcommands
                .iter()
                .find(|subcommand| subcommand.name == *token)
            {
                path.push(subcommand.name);
                return Self::resolve(subcommand, path, &remaining[1..]);
            }
        }

        let Some(handler) = &command.handler else {
            return if remaining.is_empty() {
                CommandResolution::Reply(command.help(path))
            } else {
                let command_path = format!("/{}", path.join(" "));
                CommandResolution::Reply(format!(
                    "Unknown subcommand: {command_path} {}\nUse {command_path} help for usage.",
                    remaining[0]
                ))
            };
        };

        let required = command
            .arguments
            .iter()
            .filter(|argument| argument.required)
            .count();
        if remaining.len() < required || remaining.len() > command.arguments.len() {
            return CommandResolution::Reply(format!("Usage: {}", command.syntax(path)));
        }

        let arguments = CommandArguments {
            values: command
                .arguments
                .iter()
                .zip(remaining)
                .map(|(definition, value)| ParsedArgument {
                    name: definition.name,
                    value: (*value).to_string(),
                })
                .collect(),
        };
        CommandResolution::Invocation(CommandInvocation {
            handler: handler.clone(),
            arguments,
        })
    }

    fn help(&self) -> String {
        let mut lines = vec!["Agora commands:".to_string()];
        lines.extend(
            self.commands
                .iter()
                .map(|command| format!("/{} - {}", command.name, command.description)),
        );
        lines.push("/help - Show all commands.".to_string());
        lines.push(String::new());
        lines.push("Use /{command} help for details.".to_string());
        lines.join("\n")
    }
}
