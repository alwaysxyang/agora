use super::SmbRemoteConfig;
use crate::nfs::backend::{RemoteStorage, StorageError, StorageResult};
use crate::nfs::protocol::{RemoteEntry, RemoteFileType, RemoteMetadata, RemotePath};
use smb2::{ClientConfig, ErrorKind, SmbClient, Tree};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::Mutex;

struct SmbStorage {
    roots: Vec<Mutex<SmbRoot>>,
}

pub(in crate::nfs) fn configured_storage(
    remotes: &[SmbRemoteConfig],
) -> Arc<impl RemoteStorage + use<>> {
    Arc::new(SmbStorage::new(remotes))
}

impl SmbStorage {
    fn new(remotes: &[SmbRemoteConfig]) -> Self {
        Self {
            roots: remotes
                .iter()
                .cloned()
                .map(SmbRoot::new)
                .map(Mutex::new)
                .collect(),
        }
    }

    async fn root_by_index(
        &self,
        root: u32,
    ) -> StorageResult<tokio::sync::MutexGuard<'_, SmbRoot>> {
        let root = self
            .roots
            .get(root as usize)
            .ok_or_else(|| StorageError::new(libc::EINVAL, "unknown SMB root"))?;
        Ok(root.lock().await)
    }

    async fn root(&self, path: &RemotePath) -> StorageResult<tokio::sync::MutexGuard<'_, SmbRoot>> {
        self.root_by_index(path.root()).await
    }
}

impl RemoteStorage for SmbStorage {
    async fn connect(&self, root: u32) -> StorageResult<()> {
        self.root_by_index(root).await?.session().await?;
        Ok(())
    }

    async fn stat(&self, path: &RemotePath) -> StorageResult<RemoteMetadata> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        let info = session
            .client
            .stat(&mut session.tree, &remote)
            .await
            .map_err(storage_error)?;
        Ok(metadata_from_file(&info))
    }

    async fn read(&self, path: &RemotePath) -> StorageResult<(Vec<u8>, RemoteMetadata)> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        let data = session
            .client
            .read_file_pipelined(&mut session.tree, &remote)
            .await
            .map_err(storage_error)?;
        let info = session
            .client
            .stat(&mut session.tree, &remote)
            .await
            .map_err(storage_error)?;
        Ok((data, metadata_from_file(&info)))
    }

    async fn write(&self, path: &RemotePath, data: &[u8]) -> StorageResult<RemoteMetadata> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        session
            .client
            .write_file_pipelined(&mut session.tree, &remote, data)
            .await
            .map_err(storage_error)?;
        let info = session
            .client
            .stat(&mut session.tree, &remote)
            .await
            .map_err(storage_error)?;
        Ok(metadata_from_file(&info))
    }

    async fn list(&self, path: &RemotePath) -> StorageResult<Vec<RemoteEntry>> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        let entries = session
            .client
            .list_directory(&mut session.tree, &remote)
            .await
            .map_err(storage_error)?;
        Ok(entries
            .into_iter()
            .filter(|entry| entry.name != "." && entry.name != "..")
            .map(|entry| {
                let file_type = if entry.is_directory {
                    RemoteFileType::Directory
                } else {
                    RemoteFileType::File
                };
                RemoteEntry {
                    name: entry.name,
                    metadata: metadata(file_type, entry.size, entry.modified),
                }
            })
            .collect())
    }

    async fn create_directory(&self, path: &RemotePath) -> StorageResult<()> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        session
            .client
            .create_directory(&mut session.tree, &remote)
            .await
            .map_err(storage_error)
    }

    async fn remove(&self, path: &RemotePath, directory: bool) -> StorageResult<()> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        if directory {
            session
                .client
                .delete_directory(&mut session.tree, &remote)
                .await
                .map_err(storage_error)
        } else {
            session
                .client
                .delete_file(&mut session.tree, &remote)
                .await
                .map_err(storage_error)
        }
    }

    async fn rename(&self, from: &RemotePath, to: &RemotePath) -> StorageResult<()> {
        if from.root() != to.root() {
            return Err(StorageError::new(libc::EXDEV, "cross-root SMB rename"));
        }
        let mut root = self.root(from).await?;
        let from = root.path(from);
        let to = root.path(to);
        let session = root.session().await?;
        session
            .client
            .rename(&mut session.tree, &from, &to)
            .await
            .map_err(storage_error)
    }
}

struct SmbRoot {
    config: SmbRemoteConfig,
    session: Option<SmbSession>,
}

impl SmbRoot {
    fn new(config: SmbRemoteConfig) -> Self {
        Self {
            config,
            session: None,
        }
    }

    fn path(&self, path: &RemotePath) -> String {
        remote_path(self.config.remote_path(), path)
    }

    async fn session(&mut self) -> StorageResult<&mut SmbSession> {
        if self.session.is_none() {
            let mut client = SmbClient::connect(ClientConfig {
                addr: self.config.server().to_string(),
                timeout: Duration::from_secs(5),
                username: self.config.username().to_string(),
                password: self.config.password().to_string(),
                domain: self.config.domain().to_string(),
                auto_reconnect: true,
                compression: true,
                dfs_enabled: true,
                dfs_target_overrides: HashMap::new(),
            })
            .await
            .map_err(storage_error)?;
            let tree = client
                .connect_share(self.config.share())
                .await
                .map_err(storage_error)?;
            self.session = Some(SmbSession { client, tree });
        }
        self.session
            .as_mut()
            .ok_or_else(|| StorageError::new(libc::EIO, "SMB session was not initialized"))
    }
}

struct SmbSession {
    client: SmbClient,
    tree: Tree,
}

fn remote_path(base: &str, path: &RemotePath) -> String {
    match (base.is_empty(), path.path().is_empty()) {
        (true, _) => path.path().to_string(),
        (_, true) => base.to_string(),
        (false, false) => format!("{base}/{}", path.path()),
    }
}

fn metadata_from_file(info: &smb2::FileInfo) -> RemoteMetadata {
    let mut metadata = metadata(
        if info.is_directory {
            RemoteFileType::Directory
        } else {
            RemoteFileType::File
        },
        info.size,
        info.modified,
    );
    metadata.identity = format!("{}:{}", metadata.identity, info.created.0);
    metadata
}

fn metadata(
    file_type: RemoteFileType,
    size: u64,
    modified: smb2::pack::FileTime,
) -> RemoteMetadata {
    let (modified_seconds, modified_nanoseconds) = modified
        .to_system_time()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|duration| (duration.as_secs() as i64, duration.subsec_nanos()))
        .unwrap_or((0, 0));
    let kind = match file_type {
        RemoteFileType::File => "file",
        RemoteFileType::Directory => "directory",
    };
    RemoteMetadata {
        file_type,
        size,
        modified_seconds,
        modified_nanoseconds,
        identity: format!("{kind}:{size}:{}", modified.0),
    }
}

fn storage_error(error: smb2::Error) -> StorageError {
    StorageError::new(smb_errno(&error), format!("SMB operation failed: {error}"))
}

fn smb_errno(error: &smb2::Error) -> libc::c_int {
    if error.status() == Some(smb2::types::status::NtStatus::DIRECTORY_NOT_EMPTY) {
        return libc::ENOTEMPTY;
    }
    if error.status() == Some(smb2::types::status::NtStatus::DELETE_PENDING) {
        return libc::EBUSY;
    }
    match error.kind() {
        ErrorKind::AuthRequired | ErrorKind::SigningRequired | ErrorKind::AccessDenied => {
            libc::EACCES
        }
        ErrorKind::NotFound => libc::ENOENT,
        ErrorKind::AlreadyExists => libc::EEXIST,
        ErrorKind::SharingViolation => libc::EBUSY,
        ErrorKind::IsADirectory => libc::EISDIR,
        ErrorKind::NotADirectory => libc::ENOTDIR,
        ErrorKind::DiskFull => libc::ENOSPC,
        ErrorKind::ConnectionLost => libc::ENETDOWN,
        ErrorKind::TimedOut => libc::ETIMEDOUT,
        ErrorKind::Cancelled => libc::EINTR,
        ErrorKind::SessionExpired => libc::EIO,
        ErrorKind::DfsReferral => libc::EXDEV,
        ErrorKind::InvalidData => libc::EPROTO,
        ErrorKind::TooLarge => libc::EFBIG,
        ErrorKind::Io => match error {
            smb2::Error::Io(error) => error.raw_os_error().unwrap_or(libc::EIO),
            _ => libc::EIO,
        },
        ErrorKind::InvalidName => libc::EINVAL,
        ErrorKind::Unsupported => libc::ENOTSUP,
        _ => libc::EIO,
    }
}

#[cfg(test)]
mod tests;
