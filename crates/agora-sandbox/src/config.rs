//! Configuration adapter for the `agora-sandbox` binary.

use agora_sandbox::network::TlsMode;
use agora_sandbox::runner::{SandboxConfig, SmbRemoteConfig};
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

const DEFAULT_LOG_FILE: &str = "runtime/logs/sandbox.log";

pub(super) struct RunConfig {
    workdir: PathBuf,
    tls: TlsMode,
    local: LocalFilesystem,
    remotes: Vec<SmbRemoteConfig>,
    log_file: PathBuf,
}

impl RunConfig {
    pub(super) fn load(path: &Path) -> Result<Self> {
        let path = absolute_path(path)?;
        let file = open_config(&path)?;
        let stored: StoredConfig = serde_json::from_reader(file)
            .with_context(|| format!("failed to parse sandbox config {}", path.display()))?;
        let directory = path.parent().unwrap_or(Path::new("/"));
        stored.resolve(directory)
    }

    pub(super) fn workdir(&self) -> &Path {
        &self.workdir
    }

    pub(super) fn log_file(&self) -> &Path {
        &self.log_file
    }

    pub(super) fn into_runtime(self, hook: PathBuf) -> SandboxConfig {
        let mut config = SandboxConfig::new(hook).with_workdir(&self.workdir);
        config.network.tls = self.tls;
        config = match self.local {
            LocalFilesystem::Plain => config.with_plain_workspace(),
            LocalFilesystem::Encrypted(key) => config.with_encrypted_workspace(key),
        };
        for remote in self.remotes {
            config = config.with_smb_remote(remote);
        }
        config
    }
}

enum LocalFilesystem {
    Plain,
    Encrypted(String),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredConfig {
    #[serde(default)]
    workdir: Option<PathBuf>,
    #[serde(default)]
    tls: StoredTlsMode,
    #[serde(default)]
    filesystem: StoredFilesystem,
    #[serde(default)]
    log: StoredLog,
}

impl StoredConfig {
    fn resolve(self, directory: &Path) -> Result<RunConfig> {
        let local = match (self.filesystem.local.encrypt, self.filesystem.local.key) {
            (StoredEncryption::Plain, None) => LocalFilesystem::Plain,
            (StoredEncryption::Plain, Some(_)) => {
                bail!("filesystem.local.key is not allowed when encrypt is plain")
            }
            (StoredEncryption::Encrypted, Some(key)) if !key.is_empty() => {
                LocalFilesystem::Encrypted(key)
            }
            (StoredEncryption::Encrypted, _) => {
                bail!("filesystem.local.key is required when encrypt is encrypted")
            }
        };
        let remotes = self
            .filesystem
            .nfs
            .into_iter()
            .map(StoredRemote::resolve)
            .collect::<Result<Vec<_>>>()?;
        let workdir = self
            .workdir
            .map(|path| resolve_path(directory, &path))
            .transpose()?
            .unwrap_or_else(SandboxConfig::default_workdir);
        let log_file = self
            .log
            .file
            .map(|path| resolve_path(&workdir, &path))
            .transpose()?
            .unwrap_or_else(|| workdir.join(DEFAULT_LOG_FILE));
        Ok(RunConfig {
            workdir,
            tls: self.tls.into(),
            local,
            remotes,
            log_file,
        })
    }
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StoredTlsMode {
    #[default]
    Off,
    Auto,
}

impl From<StoredTlsMode> for TlsMode {
    fn from(value: StoredTlsMode) -> Self {
        match value {
            StoredTlsMode::Off => Self::Off,
            StoredTlsMode::Auto => Self::Auto,
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredFilesystem {
    #[serde(default)]
    local: StoredLocalFilesystem,
    #[serde(default)]
    nfs: Vec<StoredRemote>,
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLocalFilesystem {
    #[serde(default)]
    encrypt: StoredEncryption,
    #[serde(default)]
    key: Option<String>,
}

#[derive(Clone, Copy, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StoredEncryption {
    #[default]
    Plain,
    Encrypted,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "lowercase", deny_unknown_fields)]
enum StoredRemote {
    Smb {
        dir: PathBuf,
        server: String,
        #[serde(default)]
        username: String,
        #[serde(default)]
        password: String,
    },
}

impl StoredRemote {
    fn resolve(self) -> Result<SmbRemoteConfig> {
        match self {
            Self::Smb {
                dir,
                server,
                username,
                password,
            } => smb_remote(dir, &server, username, password),
        }
    }
}

#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct StoredLog {
    #[serde(default)]
    file: Option<PathBuf>,
}

fn smb_remote(
    dir: PathBuf,
    uri: &str,
    username: String,
    password: String,
) -> Result<SmbRemoteConfig> {
    let location = uri
        .strip_prefix("smb://")
        .context("filesystem.nfs SMB server must start with 'smb://'")?;
    if location.contains(['?', '#', '@']) {
        bail!("filesystem.nfs SMB server contains unsupported URI components");
    }
    let (server, path) = location
        .split_once('/')
        .context("filesystem.nfs SMB server must include a share")?;
    if server.is_empty() {
        bail!("filesystem.nfs SMB server endpoint is empty");
    }
    let (share, remote_path) = path.split_once('/').unwrap_or((path, ""));
    if share.is_empty() {
        bail!("filesystem.nfs SMB share is empty");
    }
    Ok(SmbRemoteConfig::new(dir, server, share)?
        .with_remote_path(remote_path)?
        .with_credentials(username, password))
}

fn absolute_path(path: &Path) -> Result<PathBuf> {
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }
    Ok(std::env::current_dir()
        .context("failed to resolve current directory")?
        .join(path))
}

fn resolve_path(directory: &Path, path: &Path) -> Result<PathBuf> {
    if path == Path::new("~") || path.starts_with("~/") {
        let home = std::env::var_os("HOME").context("HOME is required to expand '~'")?;
        let suffix = path.strip_prefix("~").expect("checked tilde prefix");
        return Ok(PathBuf::from(home).join(suffix));
    }
    if path.is_absolute() {
        Ok(path.to_path_buf())
    } else {
        Ok(directory.join(path))
    }
}

fn open_config(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .with_context(|| format!("failed to open sandbox config {}", path.display()))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("failed to verify sandbox config {}", path.display()))?;
    if !metadata.is_file() {
        bail!("sandbox config is not a regular file: {}", path.display());
    }
    Ok(file)
}

#[cfg(test)]
mod tests;
