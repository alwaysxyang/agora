use crate::channel::lark::LarkChannelConfig;
use serde::Deserialize;
use serde_json::Value;
use std::collections::BTreeMap;
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
    pub card: AgentCard,
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
    pub fn workdir(&self, task_id: &str, session_key: &str) -> PathBuf {
        let workspace = PathBuf::from(&self.workspace);
        match self.isolate {
            IsolateMode::None => workspace,
            IsolateMode::Session => workspace.join(&self.name).join(session_key),
            IsolateMode::Task => workspace.join(&self.name).join(task_id),
        }
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
    Task,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AgentType {
    Codex,
    Coco,
    ClaudeCode,
    Custom,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCard {
    pub name: String,
    pub description: String,
    pub supported_interfaces: Vec<AgentInterface>,
    #[serde(default)]
    pub provider: Option<AgentProvider>,
    pub version: String,
    #[serde(default)]
    pub documentation_url: Option<String>,
    pub capabilities: AgentCapabilities,
    #[serde(default)]
    pub security_schemes: BTreeMap<String, Value>,
    #[serde(default, alias = "security")]
    pub security_requirements: Vec<Value>,
    pub default_input_modes: Vec<String>,
    pub default_output_modes: Vec<String>,
    pub skills: Vec<AgentSkill>,
    #[serde(default)]
    pub signatures: Vec<AgentCardSignature>,
    #[serde(default)]
    pub icon_url: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentInterface {
    pub url: String,
    pub protocol_binding: String,
    #[serde(default)]
    pub tenant: Option<String>,
    pub protocol_version: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AgentProvider {
    pub url: String,
    pub organization: String,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentCapabilities {
    #[serde(default)]
    pub streaming: Option<bool>,
    #[serde(default)]
    pub push_notifications: Option<bool>,
    #[serde(default)]
    pub extensions: Vec<AgentExtension>,
    #[serde(default)]
    pub extended_agent_card: Option<bool>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Eq)]
pub struct AgentExtension {
    #[serde(default)]
    pub uri: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub required: Option<bool>,
    #[serde(default)]
    pub params: Option<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AgentSkill {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    #[serde(default)]
    pub examples: Vec<String>,
    #[serde(default)]
    pub input_modes: Vec<String>,
    #[serde(default)]
    pub output_modes: Vec<String>,
    #[serde(default, alias = "security")]
    pub security_requirements: Vec<Value>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct AgentCardSignature {
    pub protected: String,
    pub signature: String,
    #[serde(default)]
    pub header: Option<Value>,
}
