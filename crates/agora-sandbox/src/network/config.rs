use anyhow::{Result, bail};
use std::time::Duration;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum NetworkEnforcement {
    #[default]
    Audit,
    Strict,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum TlsMode {
    #[default]
    Off,
    Auto,
    Require,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkConfig {
    pub enforcement: NetworkEnforcement,
    pub tls: TlsMode,
    pub route_ttl: Duration,
    pub upstream_connect_timeout: Duration,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enforcement: NetworkEnforcement::Audit,
            tls: TlsMode::Off,
            route_ttl: Duration::from_secs(30),
            upstream_connect_timeout: Duration::from_secs(10),
        }
    }
}

impl NetworkConfig {
    pub fn validate(self) -> Result<()> {
        if self.enforcement == NetworkEnforcement::Strict {
            bail!("strict network enforcement is unavailable until native egress denial is active");
        }
        if self.tls != TlsMode::Off {
            bail!("TLS termination is not implemented; use tls=off");
        }
        if self.route_ttl.is_zero() {
            bail!("route_ttl must be greater than zero");
        }
        if self.upstream_connect_timeout.is_zero() {
            bail!("upstream_connect_timeout must be greater than zero");
        }
        Ok(())
    }
}
