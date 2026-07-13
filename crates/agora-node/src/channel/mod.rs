use crate::channel::lark::{LarkAgentCard, LarkChannel, LarkMessageEvent};
use crate::config::ChannelConfig;
use anyhow::Result;
use std::future::Future;

pub mod lark;

pub trait Channel {
    type Task: ChannelTask;
    type Run: ChannelRun;

    fn name(&self) -> &str;

    fn recv(&mut self) -> impl Future<Output = Result<Option<Self::Task>>> + Send;

    fn open_run(
        &self,
        task: &Self::Task,
        context: ChannelRunContext,
    ) -> impl Future<Output = Result<Self::Run>> + Send;
}

pub trait ChannelTask: Clone {
    fn task_id(&self) -> &str;

    fn session_id(&self) -> &str;

    fn input(&self) -> &str;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelRunContext {
    pub agent: ChannelAgent,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ChannelAgent {
    pub name: String,
}

pub trait ChannelRun: Clone {
    fn publish(&self, event: RunEvent) -> impl Future<Output = Result<()>> + Send;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConfiguredTask {
    Lark(LarkMessageEvent),
}

impl ChannelTask for ConfiguredTask {
    fn task_id(&self) -> &str {
        match self {
            ConfiguredTask::Lark(task) => task.task_id(),
        }
    }

    fn session_id(&self) -> &str {
        match self {
            ConfiguredTask::Lark(task) => task.session_id(),
        }
    }

    fn input(&self) -> &str {
        match self {
            ConfiguredTask::Lark(task) => task.input(),
        }
    }
}

#[derive(Clone)]
pub enum ConfiguredRun {
    Lark(LarkAgentCard),
}

impl ChannelRun for ConfiguredRun {
    async fn publish(&self, event: RunEvent) -> Result<()> {
        match self {
            ConfiguredRun::Lark(run) => run.publish(event).await,
        }
    }
}

pub enum ConfiguredChannel {
    Lark(LarkChannel),
}

impl ConfiguredChannel {
    pub fn from_config(config: ChannelConfig) -> Result<Option<Self>> {
        match config {
            ChannelConfig::Lark(config) => Ok(Some(Self::Lark(LarkChannel::new(config)?))),
            ChannelConfig::Local(_) | ChannelConfig::Http(_) | ChannelConfig::Telegram(_) => {
                Ok(None)
            }
        }
    }
}

impl Channel for ConfiguredChannel {
    type Task = ConfiguredTask;
    type Run = ConfiguredRun;

    fn name(&self) -> &str {
        match self {
            ConfiguredChannel::Lark(channel) => channel.name(),
        }
    }

    async fn recv(&mut self) -> Result<Option<Self::Task>> {
        match self {
            ConfiguredChannel::Lark(channel) => Ok(channel.recv().await?.map(ConfiguredTask::Lark)),
        }
    }

    async fn open_run(&self, task: &Self::Task, context: ChannelRunContext) -> Result<Self::Run> {
        match (self, task) {
            (ConfiguredChannel::Lark(channel), ConfiguredTask::Lark(task)) => {
                Ok(ConfiguredRun::Lark(channel.open_run(task, context).await?))
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RunEvent {
    Started { run_id: String },
    OutputChunk { text: String },
    Completed { exit_code: i32 },
    Failed { message: String },
}
