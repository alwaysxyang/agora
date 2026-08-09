#[cfg(all(not(agora_sandbox_hook_build), any(feature = "remote-smb", test)))]
use crate::nfs::protocol::{RemoteEntry, RemoteMetadata, RemotePath};
#[cfg(all(not(agora_sandbox_hook_build), any(feature = "remote-smb", test)))]
use std::fmt;
#[cfg(all(not(agora_sandbox_hook_build), any(feature = "remote-smb", test)))]
use std::fs::File;
#[cfg(all(not(agora_sandbox_hook_build), any(feature = "remote-smb", test)))]
use std::future::Future;

mod smb;

pub use smb::SmbRemoteConfig;
#[cfg(all(feature = "remote-smb", not(agora_sandbox_hook_build)))]
pub(super) use smb::configured_storage;

#[cfg(all(not(agora_sandbox_hook_build), any(feature = "remote-smb", test)))]
pub(crate) type StorageResult<T> = Result<T, StorageError>;

#[cfg(all(not(agora_sandbox_hook_build), any(feature = "remote-smb", test)))]
pub(crate) trait RemoteStorage: Send + Sync + 'static {
    /// Drops backend state after the Broker cancels an operation at its
    /// deadline, so protocol handles from the abandoned future cannot leak.
    fn reset(&self, root: u32) -> impl Future<Output = ()> + Send;
    fn connect(&self, root: u32) -> impl Future<Output = StorageResult<()>> + Send;
    fn stat(&self, path: &RemotePath)
    -> impl Future<Output = StorageResult<RemoteMetadata>> + Send;
    fn read_into(
        &self,
        path: &RemotePath,
        destination: &mut File,
        max_length: u64,
    ) -> impl Future<Output = StorageResult<RemoteMetadata>> + Send;
    /// Replaces `path` only when its current identity still matches `expected`.
    /// Implementations must keep the comparison and mutation in one backend
    /// critical section so an external writer cannot race between them.
    fn write_from_if_unchanged(
        &self,
        path: &RemotePath,
        expected: Option<&RemoteMetadata>,
        source: &mut File,
        length: u64,
    ) -> impl Future<Output = StorageResult<RemoteMetadata>> + Send;
    fn list(
        &self,
        path: &RemotePath,
        emit: &mut (impl FnMut(RemoteEntry) -> StorageResult<()> + Send),
    ) -> impl Future<Output = StorageResult<()>> + Send;
    fn create_directory(&self, path: &RemotePath)
    -> impl Future<Output = StorageResult<()>> + Send;
    fn remove(
        &self,
        path: &RemotePath,
        directory: bool,
    ) -> impl Future<Output = StorageResult<()>> + Send;
    fn rename(
        &self,
        from: &RemotePath,
        to: &RemotePath,
    ) -> impl Future<Output = StorageResult<()>> + Send;
}

#[derive(Debug)]
#[cfg(all(not(agora_sandbox_hook_build), any(feature = "remote-smb", test)))]
pub(crate) struct StorageError {
    pub(super) errno: libc::c_int,
    pub(super) message: String,
}

#[cfg(all(not(agora_sandbox_hook_build), any(feature = "remote-smb", test)))]
impl StorageError {
    pub(crate) fn new(errno: libc::c_int, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
        }
    }

    pub(crate) fn not_found() -> Self {
        Self::new(libc::ENOENT, "remote path does not exist")
    }

    pub(crate) fn errno(&self) -> libc::c_int {
        self.errno
    }
}

#[cfg(all(not(agora_sandbox_hook_build), any(feature = "remote-smb", test)))]
impl fmt::Display for StorageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

#[cfg(all(not(agora_sandbox_hook_build), any(feature = "remote-smb", test)))]
impl std::error::Error for StorageError {}
