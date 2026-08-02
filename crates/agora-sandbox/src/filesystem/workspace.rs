use super::{EncryptedWorkspace, FilesystemMode};
use anyhow::{Context, Result, bail};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

const FILESYSTEM_DIRECTORY: &str = "filesystem";
const ROOT_DIRECTORY: &str = "fs";
const LOCK_FILE: &str = "fs.lock";

#[derive(Debug)]
pub(crate) enum FilesystemWorkspace {
    Encrypted(EncryptedWorkspace),
    Plain(PlainWorkspace),
}

impl FilesystemWorkspace {
    pub(crate) async fn start(
        workdir: &Path,
        mode: FilesystemMode,
        encrypted_key: Option<&[u8]>,
    ) -> Result<Self> {
        match (mode, encrypted_key) {
            (FilesystemMode::Encrypted, Some(key)) => EncryptedWorkspace::start(workdir, key)
                .await
                .map(Self::Encrypted),
            (FilesystemMode::Encrypted, None) => bail!("sandbox filesystem key is required"),
            (FilesystemMode::Plain, None) => PlainWorkspace::start(workdir).map(Self::Plain),
            (FilesystemMode::Plain, Some(_)) => {
                bail!("encrypted filesystem key cannot be used with plain filesystem mode")
            }
        }
    }

    pub(crate) fn root(&self) -> &Path {
        match self {
            Self::Encrypted(workspace) => workspace.root(),
            Self::Plain(workspace) => workspace.root(),
        }
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        match self {
            Self::Encrypted(workspace) => workspace.shutdown().await,
            Self::Plain(_) => Ok(()),
        }
    }
}

#[derive(Debug)]
pub(crate) struct PlainWorkspace {
    root: PathBuf,
    _lock: File,
}

impl PlainWorkspace {
    fn start(workdir: &Path) -> Result<Self> {
        let workdir = EncryptedWorkspace::resolved_destination(workdir)?;
        let directory = workdir.join(FILESYSTEM_DIRECTORY);
        Self::prepare_directory(&directory, "filesystem state")?;
        let lock = Self::lock(&directory)?;
        let root = workdir.join(ROOT_DIRECTORY);
        Self::prepare_directory(&root, "plain filesystem root")?;
        Ok(Self { root, _lock: lock })
    }

    fn root(&self) -> &Path {
        &self.root
    }

    fn prepare_directory(directory: &Path, description: &str) -> Result<()> {
        fs::create_dir_all(directory)
            .with_context(|| format!("failed to create {description} {}", directory.display()))?;
        if !directory.is_dir() {
            bail!("{description} is not a directory: {}", directory.display());
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700))
            .with_context(|| format!("failed to secure {description} {}", directory.display()))
    }

    fn lock(directory: &Path) -> Result<File> {
        let path = directory.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| format!("failed to open filesystem lock {}", path.display()))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("filesystem is already in use: {}", directory.display()));
        }
        Ok(lock)
    }
}

#[cfg(test)]
mod tests;
