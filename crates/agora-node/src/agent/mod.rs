use crate::config::{AgentConfig, AgentType};
use crate::output::OutputEvent;
use anyhow::{Result, anyhow};
use std::future::Future;
use std::path::PathBuf;

pub mod command;

mod codex;
mod custom;

use codex::CodexAgent;
use custom::CustomAgent;

pub trait AgentOutput {
    fn write(&mut self, event: OutputEvent) -> impl Future<Output = Result<()>> + Send;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentTask {
    task_id: String,
    session_id: String,
    input: String,
}

impl AgentTask {
    pub fn new(
        task_id: impl Into<String>,
        session_id: impl Into<String>,
        input: impl Into<String>,
    ) -> Self {
        Self {
            task_id: task_id.into(),
            session_id: session_id.into(),
            input: input.into(),
        }
    }

    fn into_request(
        self,
        config: &AgentConfig,
        agent_session_id: Option<String>,
    ) -> Result<AgentRequest> {
        let workdir = config.workdir(
            &Self::safe_segment(&self.task_id),
            &Self::safe_segment(&self.session_id),
        );
        std::fs::create_dir_all(&workdir)?;
        Ok(AgentRequest {
            workdir,
            input: self.input,
            session_id: agent_session_id,
        })
    }

    fn safe_segment(value: &str) -> String {
        let segment = value
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
                    ch
                } else {
                    '_'
                }
            })
            .collect::<String>();
        if segment.is_empty() {
            "unknown".to_string()
        } else {
            segment
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentRequest {
    workdir: PathBuf,
    input: String,
    session_id: Option<String>,
}

impl AgentRequest {
    pub(crate) fn into_parts(self) -> (PathBuf, String, Option<String>) {
        (self.workdir, self.input, self.session_id)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AgentSessionUpdate {
    Unchanged,
    Set(String),
    NotFound,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AgentOutcome {
    exit_code: i32,
    session_update: AgentSessionUpdate,
}

impl AgentOutcome {
    pub(crate) fn new(exit_code: i32, session_update: AgentSessionUpdate) -> Self {
        Self {
            exit_code,
            session_update,
        }
    }

    pub fn exit_code(&self) -> i32 {
        self.exit_code
    }

    pub fn session_update(&self) -> &AgentSessionUpdate {
        &self.session_update
    }
}

pub trait Agent {
    fn run<O>(
        &self,
        request: AgentRequest,
        output: &mut O,
    ) -> impl Future<Output = Result<AgentOutcome>> + Send
    where
        O: AgentOutput + Send;
}

#[derive(Clone)]
enum AgentBackend {
    Codex(CodexAgent),
    Custom(CustomAgent),
}

impl Agent for AgentBackend {
    async fn run<O>(&self, request: AgentRequest, output: &mut O) -> Result<AgentOutcome>
    where
        O: AgentOutput + Send,
    {
        match self {
            AgentBackend::Codex(agent) => agent.run(request, output).await,
            AgentBackend::Custom(agent) => agent.run(request, output).await,
        }
    }
}

#[derive(Clone)]
pub struct ConfiguredAgent {
    config: AgentConfig,
    backend: AgentBackend,
}

impl ConfiguredAgent {
    pub fn from_config(config: AgentConfig) -> Result<Self> {
        let backend = match config.agent_type {
            AgentType::Codex => AgentBackend::Codex(CodexAgent::new(
                config.name.clone(),
                config.path.clone(),
                config.model.clone(),
                config.effort.clone(),
            )),
            AgentType::Custom => AgentBackend::Custom(CustomAgent::new(config.path.clone())),
            AgentType::Coco => {
                return Err(anyhow!("one-shot coco agent execution is not implemented"));
            }
            AgentType::ClaudeCode => {
                return Err(anyhow!(
                    "one-shot claude code agent execution is not implemented"
                ));
            }
        };
        Ok(Self { config, backend })
    }

    pub fn name(&self) -> &str {
        &self.config.name
    }

    pub fn subscribes_to(&self, channel_name: &str) -> bool {
        self.config
            .subscribe
            .iter()
            .any(|subscription| subscription.channel == channel_name)
    }

    pub async fn run<O>(
        &self,
        task: AgentTask,
        session_id: Option<String>,
        output: &mut O,
    ) -> Result<AgentOutcome>
    where
        O: AgentOutput + Send,
    {
        self.backend
            .run(task.into_request(&self.config, session_id)?, output)
            .await
    }
}

pub struct AgentRegistry {
    agents: Vec<ConfiguredAgent>,
}

impl AgentRegistry {
    pub fn from_configs(configs: Vec<AgentConfig>) -> Result<Self> {
        let agents = configs
            .into_iter()
            .map(ConfiguredAgent::from_config)
            .collect::<Result<Vec<_>>>()?;
        Ok(Self { agents })
    }

    pub fn subscribed_to(&self, channel_name: &str) -> Vec<ConfiguredAgent> {
        self.agents
            .iter()
            .filter(|agent| agent.subscribes_to(channel_name))
            .cloned()
            .collect()
    }
}
