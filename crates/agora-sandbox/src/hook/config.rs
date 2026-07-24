use std::net::{IpAddr, SocketAddr};

const TOKEN: &str = "AGORA_SANDBOX_TOKEN";
const PROXY_IPV4: &str = "AGORA_SANDBOX_PROXY_IPV4";
const PROXY_IPV6: &str = "AGORA_SANDBOX_PROXY_IPV6";

#[derive(Clone, Debug)]
pub(super) struct HookConfig {
    token: String,
    proxy_ipv4: SocketAddr,
    proxy_ipv6: SocketAddr,
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
        if !proxy_ipv4.ip().is_loopback() || !matches!(proxy_ipv4.ip(), IpAddr::V4(_)) {
            return Err(format!("{PROXY_IPV4} must be an IPv4 loopback address"));
        }
        if !proxy_ipv6.ip().is_loopback() || !matches!(proxy_ipv6.ip(), IpAddr::V6(_)) {
            return Err(format!("{PROXY_IPV6} must be an IPv6 loopback address"));
        }
        Ok(Self {
            token,
            proxy_ipv4,
            proxy_ipv6,
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

    pub(super) fn is_proxy(&self, destination: SocketAddr) -> bool {
        destination == self.proxy_ipv4 || destination == self.proxy_ipv6
    }

    fn required(get: &mut impl FnMut(&str) -> Option<String>, key: &str) -> Result<String, String> {
        get(key)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing {key}"))
    }
}
