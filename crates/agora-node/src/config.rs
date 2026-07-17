use serde::Deserialize;
use serde_json::Value;
use std::collections::HashMap;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct NodeConfig {
    pub channels: Vec<ChannelConfig>,
    pub agents: Vec<AgentConfig>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AgentConfig {
    pub name: String,
    pub isolate: IsolateMode,
    #[serde(default = "default_workspace")]
    pub workspace: String,
    #[serde(rename = "type")]
    pub agent_type: AgentType,
    pub path: String,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub effort: Option<String>,
    #[serde(default)]
    pub agent_sandbox: Option<AgentSandbox>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    pub subscribe: Vec<AgentSubscription>,
}

fn default_workspace() -> String {
    let home = std::env::var_os("HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."));
    home.join(".agora")
        .join("workspace")
        .to_string_lossy()
        .into_owned()
}

impl AgentConfig {
    pub fn isolation_scope(
        &self,
        channel_name: impl Into<String>,
        session_id: impl Into<String>,
    ) -> IsolationScope {
        match self.isolate {
            IsolateMode::None => IsolationScope::Shared,
            IsolateMode::Session => IsolationScope::session(channel_name, session_id),
        }
    }

    pub fn workdir(&self) -> PathBuf {
        PathBuf::from(&self.workspace)
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AgentSubscription {
    pub channel: String,
    #[serde(default)]
    pub filter: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ChannelConfig {
    Lark(LarkChannelConfig),
    Local(NamedChannelConfig),
    Http(NamedChannelConfig),
    Telegram(NamedChannelConfig),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct LarkChannelConfig {
    pub name: String,
    pub app_id: String,
    pub secret: String,
}

impl ChannelConfig {
    pub fn name(&self) -> &str {
        match self {
            ChannelConfig::Lark(config) => &config.name,
            ChannelConfig::Local(config)
            | ChannelConfig::Http(config)
            | ChannelConfig::Telegram(config) => &config.name,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct NamedChannelConfig {
    pub name: String,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum IsolateMode {
    None,
    Session,
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum IsolationScope {
    Shared,
    Session {
        channel_name: String,
        session_id: String,
    },
}

impl IsolationScope {
    pub fn session(channel_name: impl Into<String>, session_id: impl Into<String>) -> Self {
        Self::Session {
            channel_name: channel_name.into(),
            session_id: session_id.into(),
        }
    }

    pub fn channel_name(&self) -> Option<&str> {
        match self {
            Self::Shared => None,
            Self::Session { channel_name, .. } => Some(channel_name),
        }
    }

    pub fn session_id(&self) -> Option<&str> {
        match self {
            Self::Shared => None,
            Self::Session { session_id, .. } => Some(session_id),
        }
    }

    pub(crate) fn as_str(&self) -> &'static str {
        match self {
            Self::Shared => "shared",
            Self::Session { .. } => "session",
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    Codex,
    Coco,
    ClaudeCode,
    Custom,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum AgentSandbox {
    ReadOnly,
    WorkspaceWrite,
    DangerFullAccess,
}

impl AgentSandbox {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ReadOnly => "read-only",
            Self::WorkspaceWrite => "workspace-write",
            Self::DangerFullAccess => "danger-full-access",
        }
    }
}
