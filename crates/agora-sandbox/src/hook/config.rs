use crate::trace::{TRACE_ID_ENVIRONMENT, TraceContext};
use base64::Engine;
use std::net::{IpAddr, SocketAddr};
use std::sync::OnceLock;

const TOKEN: &str = "AGORA_SANDBOX_TOKEN";
const PROXY_IPV4: &str = "AGORA_SANDBOX_PROXY_IPV4";
const PROXY_IPV6: &str = "AGORA_SANDBOX_PROXY_IPV6";
const EXECUTION_CONTROL: &str = "AGORA_SANDBOX_EXECUTION_CONTROL";
const EXECUTION_TOKEN: &str = "AGORA_SANDBOX_EXECUTION_TOKEN";
const AUDIT_CONTROL: &str = "AGORA_SANDBOX_AUDIT_CONTROL";
const AUDIT_TOKEN: &str = "AGORA_SANDBOX_AUDIT_TOKEN";
const HOOK_LIBRARIES: &str = "AGORA_SANDBOX_HOOK_LIBRARIES";
const FILESYSTEM_ROOT: &str = "AGORA_SANDBOX_FILESYSTEM_ROOT";
const FILESYSTEM_MODE: &str = "AGORA_SANDBOX_FILESYSTEM_MODE";
const FILESYSTEM_KEY: &str = "AGORA_SANDBOX_FILESYSTEM_KEY";
const FILESYSTEM_SALT: &str = "AGORA_SANDBOX_FILESYSTEM_SALT";
const TLS_TRUST_ANCHOR_DER: &str = "AGORA_SANDBOX_TLS_TRUST_ANCHOR_DER";
const TLS_TRUST_BUNDLE: &str = "AGORA_SANDBOX_TLS_TRUST_BUNDLE";

const TLS_CLIENT_TRUST_ENVIRONMENT: [&str; 5] = [
    "SSL_CERT_FILE",
    "CURL_CA_BUNDLE",
    "REQUESTS_CA_BUNDLE",
    "NODE_EXTRA_CA_CERTS",
    "GIT_SSL_CAINFO",
];

pub(super) const CHILD_RUNTIME_ENVIRONMENT: [&str; 20] = [
    TOKEN,
    PROXY_IPV4,
    PROXY_IPV6,
    EXECUTION_CONTROL,
    EXECUTION_TOKEN,
    AUDIT_CONTROL,
    AUDIT_TOKEN,
    HOOK_LIBRARIES,
    FILESYSTEM_ROOT,
    FILESYSTEM_MODE,
    FILESYSTEM_KEY,
    FILESYSTEM_SALT,
    TLS_TRUST_ANCHOR_DER,
    TLS_TRUST_BUNDLE,
    TRACE_ID_ENVIRONMENT,
    TLS_CLIENT_TRUST_ENVIRONMENT[0],
    TLS_CLIENT_TRUST_ENVIRONMENT[1],
    TLS_CLIENT_TRUST_ENVIRONMENT[2],
    TLS_CLIENT_TRUST_ENVIRONMENT[3],
    TLS_CLIENT_TRUST_ENVIRONMENT[4],
];

#[derive(Clone, Debug)]
pub(super) struct HookConfig {
    token: String,
    proxy_ipv4: SocketAddr,
    proxy_ipv6: SocketAddr,
    execution_control: SocketAddr,
    execution_token: String,
    audit_control: SocketAddr,
    audit_token: String,
    hook_libraries: String,
    filesystem_root: String,
    filesystem_mode: String,
    filesystem_key: Option<String>,
    filesystem_salt: Option<String>,
    filesystem_cipher: Option<crate::filesystem::FileCipher>,
    tls_trust_anchor_der: Option<String>,
    tls_trust_bundle: Option<String>,
    trace: TraceContext,
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
        let audit_control = Self::required(&mut get, AUDIT_CONTROL)?
            .parse::<SocketAddr>()
            .map_err(|error| format!("invalid {AUDIT_CONTROL}: {error}"))?;
        let audit_token = Self::required(&mut get, AUDIT_TOKEN)?;
        let hook_libraries = Self::required(&mut get, HOOK_LIBRARIES)?;
        let filesystem_root = Self::required(&mut get, FILESYSTEM_ROOT)?;
        let filesystem_mode = Self::required(&mut get, FILESYSTEM_MODE)?;
        let filesystem_key = get(FILESYSTEM_KEY).filter(|value| !value.is_empty());
        let filesystem_salt = get(FILESYSTEM_SALT).filter(|value| !value.is_empty());
        match filesystem_mode.as_str() {
            "plain" if filesystem_key.is_none() && filesystem_salt.is_none() => {}
            "encrypted" if filesystem_key.is_some() && filesystem_salt.is_some() => {}
            "plain" => return Err("plain filesystem mode cannot include a key or salt".into()),
            "encrypted" => {
                return Err("encrypted filesystem mode requires a key and salt".into());
            }
            _ => return Err(format!("invalid {FILESYSTEM_MODE}: {filesystem_mode}")),
        }
        let filesystem_cipher = Self::decode_filesystem_cipher(
            &filesystem_mode,
            filesystem_key.as_deref(),
            filesystem_salt.as_deref(),
        )?;
        let tls_trust_anchor_der = get(TLS_TRUST_ANCHOR_DER).filter(|value| !value.is_empty());
        let tls_trust_bundle = get(TLS_TRUST_BUNDLE).filter(|value| !value.is_empty());
        let trace = TraceContext::parse(&Self::required(&mut get, TRACE_ID_ENVIRONMENT)?)
            .map_err(|error| format!("invalid {TRACE_ID_ENVIRONMENT}: {error}"))?;
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
        if !audit_control.ip().is_loopback() || !matches!(audit_control.ip(), IpAddr::V4(_)) {
            return Err(format!("{AUDIT_CONTROL} must be an IPv4 loopback address"));
        }
        Ok(Self {
            token,
            proxy_ipv4,
            proxy_ipv6,
            execution_control,
            execution_token,
            audit_control,
            audit_token,
            hook_libraries,
            filesystem_root,
            filesystem_mode,
            filesystem_key,
            filesystem_salt,
            filesystem_cipher,
            tls_trust_anchor_der,
            tls_trust_bundle,
            trace,
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

    pub(super) fn audit_control(&self) -> SocketAddr {
        self.audit_control
    }

    pub(super) fn audit_token(&self) -> &str {
        &self.audit_token
    }

    pub(super) fn hook_libraries(&self) -> &str {
        &self.hook_libraries
    }

    pub(super) fn filesystem_root(&self) -> &str {
        &self.filesystem_root
    }

    pub(super) fn filesystem_cipher(&self) -> Option<crate::filesystem::FileCipher> {
        self.filesystem_cipher.clone()
    }

    fn decode_filesystem_cipher(
        mode: &str,
        key: Option<&str>,
        salt: Option<&str>,
    ) -> Result<Option<crate::filesystem::FileCipher>, String> {
        if mode == "plain" {
            return Ok(None);
        }
        let key = base64::engine::general_purpose::STANDARD
            .decode(key.unwrap_or_default())
            .map_err(|error| format!("invalid {FILESYSTEM_KEY}: {error}"))?;
        let salt = base64::engine::general_purpose::STANDARD
            .decode(salt.unwrap_or_default())
            .map_err(|error| format!("invalid {FILESYSTEM_SALT}: {error}"))?;
        crate::filesystem::FileCipher::derive(&key, &salt)
            .map(Some)
            .map_err(|error| format!("invalid encrypted filesystem configuration: {error:#}"))
    }

    pub(super) fn tls_trust_anchor_der(&self) -> Option<&str> {
        self.tls_trust_anchor_der.as_deref()
    }

    #[cfg(test)]
    pub(super) fn tls_trust_bundle(&self) -> Option<&str> {
        self.tls_trust_bundle.as_deref()
    }

    pub(super) fn trace(&self) -> &TraceContext {
        &self.trace
    }

    #[cfg(test)]
    pub(super) fn child_environment(&self) -> Vec<(&'static str, String)> {
        self.child_environment_for(&self.trace)
    }

    pub(super) fn child_environment_for(
        &self,
        trace: &TraceContext,
    ) -> Vec<(&'static str, String)> {
        let mut environment = vec![
            (TOKEN, self.token.clone()),
            (PROXY_IPV4, self.proxy_ipv4.to_string()),
            (PROXY_IPV6, self.proxy_ipv6.to_string()),
            (EXECUTION_CONTROL, self.execution_control.to_string()),
            (EXECUTION_TOKEN, self.execution_token.clone()),
            (AUDIT_CONTROL, self.audit_control.to_string()),
            (AUDIT_TOKEN, self.audit_token.clone()),
            (HOOK_LIBRARIES, self.hook_libraries.clone()),
            (FILESYSTEM_ROOT, self.filesystem_root.clone()),
            (FILESYSTEM_MODE, self.filesystem_mode.clone()),
            (TRACE_ID_ENVIRONMENT, trace.encode()),
        ];
        if let Some(key) = &self.filesystem_key {
            environment.push((FILESYSTEM_KEY, key.clone()));
        }
        if let Some(salt) = &self.filesystem_salt {
            environment.push((FILESYSTEM_SALT, salt.clone()));
        }
        if let Some(anchor) = &self.tls_trust_anchor_der {
            environment.push((TLS_TRUST_ANCHOR_DER, anchor.clone()));
        }
        if let Some(bundle) = &self.tls_trust_bundle {
            environment.push((TLS_TRUST_BUNDLE, bundle.clone()));
            environment.extend(
                TLS_CLIENT_TRUST_ENVIRONMENT
                    .into_iter()
                    .map(|key| (key, bundle.clone())),
            );
        }
        environment
    }

    pub(super) fn is_internal(&self, destination: SocketAddr) -> bool {
        destination == self.proxy_ipv4
            || destination == self.proxy_ipv6
            || destination == self.execution_control
            || destination == self.audit_control
    }

    fn required(get: &mut impl FnMut(&str) -> Option<String>, key: &str) -> Result<String, String> {
        get(key)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| format!("missing {key}"))
    }
}

pub(super) fn initialize() {
    if global().is_some() {
        for key in [
            FILESYSTEM_ROOT,
            FILESYSTEM_MODE,
            FILESYSTEM_KEY,
            FILESYSTEM_SALT,
        ] {
            unsafe { std::env::remove_var(key) };
        }
    }
}

pub(super) fn global() -> Option<&'static HookConfig> {
    static CONFIG: OnceLock<Option<HookConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| HookConfig::from_environment().ok())
        .as_ref()
}
