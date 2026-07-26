use serde::Deserialize;
use serde::de::Error as _;
use serde_json::Value;
use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct NodeConfig {
    #[serde(default)]
    pub proxy: Option<HttpProxy>,
    pub channels: Vec<ChannelConfig>,
    pub agents: Vec<AgentConfig>,
}

impl NodeConfig {
    pub(crate) fn apply_proxy_defaults(&mut self) {
        let Some(proxy) = &self.proxy else {
            return;
        };
        for agent in &mut self.agents {
            agent.proxy.get_or_insert_with(|| proxy.clone());
        }
        for channel in &mut self.channels {
            channel.proxy_mut().get_or_insert_with(|| proxy.clone());
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
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
    pub proxy: Option<HttpProxy>,
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
    Telegram(TelegramChannelConfig),
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct LarkChannelConfig {
    pub name: String,
    pub app_id: String,
    pub secret: String,
    #[serde(default)]
    pub proxy: Option<HttpProxy>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct TelegramChannelConfig {
    pub name: String,
    pub token: String,
    #[serde(default)]
    pub proxy: Option<HttpProxy>,
}

impl ChannelConfig {
    pub fn name(&self) -> &str {
        match self {
            ChannelConfig::Lark(config) => &config.name,
            ChannelConfig::Telegram(config) => &config.name,
            ChannelConfig::Local(config) | ChannelConfig::Http(config) => &config.name,
        }
    }

    fn proxy_mut(&mut self) -> &mut Option<HttpProxy> {
        match self {
            ChannelConfig::Lark(config) => &mut config.proxy,
            ChannelConfig::Telegram(config) => &mut config.proxy,
            ChannelConfig::Local(config) | ChannelConfig::Http(config) => &mut config.proxy,
        }
    }
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct NamedChannelConfig {
    pub name: String,
    #[serde(default)]
    pub proxy: Option<HttpProxy>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct HttpProxy {
    address: String,
    credentials: Option<(String, String)>,
}

impl HttpProxy {
    pub fn environment_value(&self) -> String {
        match &self.credentials {
            Some((username, password)) => {
                format!("http://{username}:{password}@{}", self.address)
            }
            None => format!("http://{}", self.address),
        }
    }

    pub(crate) fn address(&self) -> &str {
        &self.address
    }

    pub(crate) fn credentials(&self) -> Option<(&str, &str)> {
        self.credentials
            .as_ref()
            .map(|(username, password)| (username.as_str(), password.as_str()))
    }
}

impl fmt::Debug for HttpProxy {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpProxy")
            .field("address", &self.address)
            .field("authenticated", &self.credentials.is_some())
            .finish()
    }
}

impl FromStr for HttpProxy {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.strip_prefix("http://").unwrap_or(value);
        if value.contains("://") {
            return Err("proxy must use HTTP".to_string());
        }
        let (credentials, address) = match value.rsplit_once('@') {
            Some((credentials, address)) => {
                let (username, password) = credentials
                    .split_once(':')
                    .ok_or_else(|| "proxy credentials must use user:password".to_string())?;
                (Some((username.to_string(), password.to_string())), address)
            }
            None => (None, value),
        };
        let (host, port) = address
            .rsplit_once(':')
            .ok_or_else(|| "proxy address must include a port".to_string())?;
        let valid_host = !host.is_empty()
            && !host.chars().any(char::is_whitespace)
            && !host.contains('/')
            && !host.contains('@')
            && (host.starts_with('[') == host.ends_with(']'))
            && (!host.contains(':') || (host.starts_with('[') && host.ends_with(']')));
        if !valid_host {
            return Err("proxy host is invalid".to_string());
        }
        if port.parse::<u16>().ok().filter(|port| *port > 0).is_none() {
            return Err("proxy port is invalid".to_string());
        }
        Ok(Self {
            address: address.to_string(),
            credentials,
        })
    }
}

impl<'de> Deserialize<'de> for HttpProxy {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_proxy_accepts_optional_credentials_and_rejects_invalid_addresses() {
        for (value, expected) in [
            ("proxy.local:8080", "http://proxy.local:8080"),
            (
                "http://user:password@proxy.local:8080",
                "http://user:password@proxy.local:8080",
            ),
            (
                ":password@proxy.local:8080",
                "http://:password@proxy.local:8080",
            ),
            ("user:@proxy.local:8080", "http://user:@proxy.local:8080"),
            (":@proxy.local:8080", "http://:@proxy.local:8080"),
            ("[::1]:8080", "http://[::1]:8080"),
        ] {
            assert_eq!(
                value.parse::<HttpProxy>().unwrap().environment_value(),
                expected
            );
        }

        for invalid in [
            "https://proxy.local:8080",
            "proxy.local",
            "proxy.local:0",
            "proxy.local:invalid",
            "user@proxy.local:8080",
            "bad host:8080",
            "::1:8080",
            "[::1:8080",
        ] {
            assert!(invalid.parse::<HttpProxy>().is_err(), "accepted {invalid}");
        }
    }

    #[test]
    fn component_proxies_override_the_global_default() {
        let mut config: NodeConfig = serde_json::from_str(
            r#"{
                "proxy":"global:8000",
                "channels":[
                    {"type":"lark","name":"lark","app_id":"id","secret":"secret"},
                    {"type":"telegram","name":"telegram","token":"token","proxy":"tg:8001"},
                    {"type":"local","name":"local"},
                    {"type":"http","name":"http","proxy":"http:8002"}
                ],
                "agents":[
                    {"name":"global","isolate":"none","type":"custom","path":"agent","subscribe":[]},
                    {"name":"own","isolate":"none","type":"custom","path":"agent","proxy":"agent:8003","subscribe":[]}
                ]
            }"#,
        )
        .unwrap();

        config.apply_proxy_defaults();

        assert_eq!(
            config.agents[0].proxy.as_ref().unwrap().environment_value(),
            "http://global:8000"
        );
        assert_eq!(
            config.agents[1].proxy.as_ref().unwrap().environment_value(),
            "http://agent:8003"
        );
        let channel_proxies = config
            .channels
            .iter_mut()
            .map(|channel| channel.proxy_mut().as_ref().unwrap().environment_value())
            .collect::<Vec<_>>();
        assert_eq!(
            channel_proxies,
            [
                "http://global:8000",
                "http://tg:8001",
                "http://global:8000",
                "http://http:8002",
            ]
        );
    }

    #[test]
    fn absent_global_proxy_leaves_components_unconfigured() {
        let mut config: NodeConfig =
            serde_json::from_str(r#"{"channels":[],"agents":[]}"#).unwrap();

        config.apply_proxy_defaults();

        assert_eq!(config.proxy, None);
    }

    #[test]
    fn isolation_scope_and_sandbox_strings_cover_all_variants() {
        assert_eq!(IsolationScope::Shared.channel_name(), None);
        assert_eq!(IsolationScope::Shared.session_id(), None);
        assert_eq!(IsolationScope::Shared.as_str(), "shared");

        let session = IsolationScope::session("telegram", "chat-1");
        assert_eq!(session.channel_name(), Some("telegram"));
        assert_eq!(session.session_id(), Some("chat-1"));
        assert_eq!(session.as_str(), "session");

        assert_eq!(AgentSandbox::ReadOnly.as_str(), "read-only");
        assert_eq!(AgentSandbox::WorkspaceWrite.as_str(), "workspace-write");
        assert_eq!(
            AgentSandbox::DangerFullAccess.as_str(),
            "danger-full-access"
        );
    }
}
