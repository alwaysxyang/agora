use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

const CONTROL_SOCKET: &str = "AGORA_SANDBOX_CONTROL_SOCKET";
const TOKEN: &str = "AGORA_SANDBOX_TOKEN";
const SANDBOX_ID: &str = "AGORA_SANDBOX_ID";
const RUN_ID: &str = "AGORA_SANDBOX_RUN_ID";
const PROXY_IPV4: &str = "AGORA_SANDBOX_PROXY_IPV4";
const PROXY_IPV6: &str = "AGORA_SANDBOX_PROXY_IPV6";
const FAIL_OPEN: &str = "AGORA_SANDBOX_FAIL_OPEN";

#[derive(Clone, Debug)]
pub(super) struct HookConfig {
    control_socket: PathBuf,
    token: String,
    sandbox_id: String,
    run_id: String,
    proxy_ipv4: SocketAddr,
    proxy_ipv6: SocketAddr,
    fail_open: bool,
}

impl HookConfig {
    pub(super) fn from_environment() -> Result<Self, String> {
        Self::from_getter(|key| std::env::var(key).ok())
    }

    pub(super) fn from_getter(mut get: impl FnMut(&str) -> Option<String>) -> Result<Self, String> {
        let control_socket = PathBuf::from(Self::required(&mut get, CONTROL_SOCKET)?);
        let token = Self::required(&mut get, TOKEN)?;
        let sandbox_id = Self::required(&mut get, SANDBOX_ID)?;
        let run_id = Self::required(&mut get, RUN_ID)?;
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
        let fail_open = match Self::required(&mut get, FAIL_OPEN)?.as_str() {
            "1" | "true" => true,
            "0" | "false" => false,
            value => return Err(format!("invalid {FAIL_OPEN}: {value}")),
        };

        Ok(Self {
            control_socket,
            token,
            sandbox_id,
            run_id,
            proxy_ipv4,
            proxy_ipv6,
            fail_open,
        })
    }

    pub(super) fn control_socket(&self) -> &Path {
        &self.control_socket
    }

    pub(super) fn token(&self) -> &str {
        &self.token
    }

    pub(super) fn sandbox_id(&self) -> &str {
        &self.sandbox_id
    }

    pub(super) fn run_id(&self) -> &str {
        &self.run_id
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

    pub(super) fn fail_open(&self) -> bool {
        self.fail_open
    }

    fn required(get: &mut impl FnMut(&str) -> Option<String>, key: &str) -> Result<String, String> {
        get(key)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing {key}"))
    }
}
