use anyhow::{Result, bail};
use std::time::Duration;

const DEFAULT_MAX_CONNECTIONS: usize = 256;

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
    pub upstream_connect_timeout: Duration,
    pub max_connections: usize,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            enforcement: NetworkEnforcement::Audit,
            tls: TlsMode::Off,
            upstream_connect_timeout: Duration::from_secs(10),
            max_connections: DEFAULT_MAX_CONNECTIONS,
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
        if self.upstream_connect_timeout.is_zero() {
            bail!("upstream_connect_timeout must be greater than zero");
        }
        if self.max_connections == 0 {
            bail!("max_connections must be greater than zero");
        }
        Ok(())
    }
}
