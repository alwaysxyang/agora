use super::command::{Command, CommandOutput};
use super::{Agent, AgentOutcome, AgentOutput, AgentRequest, AgentSessionUpdate};
use crate::output::OutputEvent;
use anyhow::Result;

#[derive(Clone)]
pub(super) struct CustomAgent {
    path: String,
}

impl CustomAgent {
    pub(super) fn new(path: String) -> Self {
        Self { path }
    }
}

impl Agent for CustomAgent {
    async fn run<O>(&self, request: AgentRequest, output: &mut O) -> Result<AgentOutcome>
    where
        O: AgentOutput + Send,
    {
        let (workdir, input, _) = request.into_parts();
        let command = Command::new(&self.path).current_dir(workdir).input(input);
        let mut command_output = RawCommandOutput::new(output);
        let outcome = command.run(&mut command_output).await?;
        Ok(AgentOutcome::new(
            outcome.exit_code(),
            AgentSessionUpdate::Unchanged,
        ))
    }
}

struct RawCommandOutput<'a, O> {
    output: &'a mut O,
}

impl<'a, O> RawCommandOutput<'a, O> {
    fn new(output: &'a mut O) -> Self {
        Self { output }
    }
}

impl<O> CommandOutput for RawCommandOutput<'_, O>
where
    O: AgentOutput + Send,
{
    async fn stdout(&mut self, chunk: &[u8]) -> Result<()> {
        self.output
            .write(OutputEvent::Answer {
                text: String::from_utf8_lossy(chunk).into_owned(),
            })
            .await
    }

    async fn stderr(&mut self, chunk: &[u8]) -> Result<()> {
        self.output
            .write(OutputEvent::Answer {
                text: String::from_utf8_lossy(chunk).into_owned(),
            })
            .await
    }
}
