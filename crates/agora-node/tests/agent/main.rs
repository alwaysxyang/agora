use agora_node::agent::{
    AgentOutcome, AgentOutput, AgentRunCancellation, AgentRunControl, AgentRunOutcome,
    AgentSessionUpdate, AgentTask, ConfiguredAgent, DeleteSessionOutcome,
};
use agora_node::config::{AgentConfig, AgentSandbox, AgentType, IsolateMode};
use agora_node::task::{OutputEvent, ProgressStatus, TaskAttachment, TaskContent, TokenUsage};
use anyhow::Result;

#[derive(Default)]
struct VecAgentOutput {
    events: Vec<OutputEvent>,
}

impl AgentOutput for VecAgentOutput {
    async fn write(&mut self, event: OutputEvent) -> Result<()> {
        self.events.push(event);
        Ok(())
    }
}

impl VecAgentOutput {
    fn answer_text(&self) -> String {
        self.events
            .iter()
            .filter_map(|event| match event {
                OutputEvent::Answer { text } => Some(text.as_str()),
                _ => None,
            })
            .collect()
    }
}

fn completed(outcome: AgentRunOutcome) -> AgentOutcome {
    let AgentRunOutcome::Completed(outcome) = outcome else {
        panic!("agent run should complete");
    };
    outcome
}

mod codex;
mod control;
mod custom;

fn agent(
    agent_type: AgentType,
    path: impl AsRef<std::path::Path>,
    workspace: impl AsRef<std::path::Path>,
) -> AgentConfig {
    AgentConfig {
        name: "codex-dev".to_string(),
        isolate: IsolateMode::None,
        workspace: workspace.as_ref().to_string_lossy().into_owned(),
        agent_type,
        path: path.as_ref().to_string_lossy().into_owned(),
        model: None,
        effort: None,
        agent_sandbox: None,
        env: Default::default(),
        subscribe: Vec::new(),
    }
}
