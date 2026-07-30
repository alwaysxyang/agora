use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

const TOKEN: &str = "AGORA_SANDBOX_TOKEN";
const PROXY_IPV4: &str = "AGORA_SANDBOX_PROXY_IPV4";
const PROXY_IPV6: &str = "AGORA_SANDBOX_PROXY_IPV6";
const EXECUTION_CONTROL: &str = "AGORA_SANDBOX_EXECUTION_CONTROL";
const EXECUTION_TOKEN: &str = "AGORA_SANDBOX_EXECUTION_TOKEN";
const HOOK_LIBRARIES: &str = "AGORA_SANDBOX_HOOK_LIBRARIES";
const TLS_TRUST_ANCHOR_DER: &str = "AGORA_SANDBOX_TLS_TRUST_ANCHOR_DER";

pub(super) const CHILD_RUNTIME_ENVIRONMENT: [&str; 7] = [
    TOKEN,
    PROXY_IPV4,
    PROXY_IPV6,
    EXECUTION_CONTROL,
    EXECUTION_TOKEN,
    HOOK_LIBRARIES,
    TLS_TRUST_ANCHOR_DER,
];

#[derive(Clone, Debug)]
pub(super) struct HookConfig {
    token: String,
    proxy_ipv4: SocketAddr,
    proxy_ipv6: SocketAddr,
    execution_control: SocketAddr,
    execution_token: String,
    hook_libraries: String,
    tls_trust_anchor_der: Option<String>,
}

impl HookConfig {
    pub(super) fn from_environment() -> Result<Self, String> {
        Self::from_getter(|key| std::env::var(key).ok())
    }

    pub(super) fn from_getter(mut get: impl FnMut(&str) -> Option<String>) -> Result<Self, String> {
        let token = Self::required(&mut get, TOKEN)?;
        let proxy_ipv4 = Self::required(&mut get, PROXY_IPV4)?
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid {PROXY_IPV4}: {error}"))?;
        let proxy_ipv6 = Self::required(&mut get, PROXY_IPV6)?
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid {PROXY_IPV6}: {error}"))?;
        let execution_control = Self::required(&mut get, EXECUTION_CONTROL)?
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid {EXECUTION_CONTROL}: {error}"))?;
        let execution_token = Self::required(&mut get, EXECUTION_TOKEN)?;
        let hook_libraries = Self::required(&mut get, HOOK_LIBRARIES)?;
        let tls_trust_anchor_der = get(TLS_TRUST_ANCHOR_DER).filter(|value| !value.is_empty());
        if !proxy_ipv4.ip().is_loopback() || !matches!(proxy_ipv4.ip(), IpAddr::V4(_)) {
            return Err(format!("{PROXY_IPV4} must be an IPv4 loopback address"));
        }
        if !proxy_ipv6.ip().is_loopback() || !matches!(proxy_ipv6.ip(), IpAddr::V6(_)) {
            return Err(format!("{PROXY_IPV6} must be an IPv6 loopback address"));
        }
        if !execution_control.ip().is_loopback() || !matches!(execution_control.ip(), IpAddr::V4(_))
        {
            return Err(format!(
                "{EXECUTION_CONTROL} must be an IPv4 loopback address"
            ));
        }
        Ok(Self {
            token,
            proxy_ipv4,
            proxy_ipv6,
            execution_control,
            execution_token,
            hook_libraries,
            tls_trust_anchor_der,
        })
    }

    pub(super) fn token(&self) -> &str {
        &self.token
    }

    pub(super) fn proxy_for(&self, destination: SocketAddr) -> SocketAddr {
        match destination {
            SocketAddr::V4(_) => self.proxy_ipv4,
            SocketAddr::V6(_) => self.proxy_ipv6,
        }
    }

    pub(super) fn execution_control(&self) -> SocketAddr {
        self.execution_control
    }

    pub(super) fn execution_token(&self) -> &str {
        &self.execution_token
    }

    pub(super) fn hook_libraries(&self) -> &str {
        &self.hook_libraries
    }

    pub(super) fn tls_trust_anchor_der(&self) -> Option<&str> {
        self.tls_trust_anchor_der.as_deref()
    }

    pub(super) fn child_environment(&self) -> Vec<(&'static str, String)> {
        let mut environment = vec![
            (TOKEN, self.token.clone()),
            (PROXY_IPV4, self.proxy_ipv4.to_string()),
            (PROXY_IPV6, self.proxy_ipv6.to_string()),
            (EXECUTION_CONTROL, self.execution_control.to_string()),
            (EXECUTION_TOKEN, self.execution_token.clone()),
            (HOOK_LIBRARIES, self.hook_libraries.clone()),
        ];
        if let Some(anchor) = &self.tls_trust_anchor_der {
            environment.push((TLS_TRUST_ANCHOR_DER, anchor.clone()));
        }
        environment
    }

    pub(super) fn is_internal(&self, destination: SocketAddr) -> bool {
        destination == self.proxy_ipv4
            || destination == self.proxy_ipv6
            || destination == self.execution_control
    }

    fn required(get: &mut impl FnMut(&str) -> Option<String>, key: &str) -> Result<String, String> {
        get(key)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing {key}"))
    }
}

pub(super) fn initialize() {
    let _ = global();
}

pub(super) fn global() -> Option<&'static HookConfig> {
    static CONFIG: OnceLock<Option<HookConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| HookConfig::from_environment().ok())
        .as_ref()
}
