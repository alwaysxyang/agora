#[cfg(target_os = "macos")]
mod crypto;
#[cfg(target_os = "macos")]
mod encrypted;
#[cfg(target_os = "macos")]
mod metadata;
#[cfg(target_os = "macos")]
mod namespace;
#[cfg(target_os = "macos")]
mod overlay;
#[cfg(target_os = "macos")]
mod vfs;
#[cfg(target_os = "macos")]
mod workspace;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FilesystemMode {
    Encrypted,
    #[default]
    Plain,
}

#[cfg(target_os = "macos")]
pub(crate) use crypto::FileCipher;
#[cfg(target_os = "macos")]
pub(crate) use encrypted::{EncryptedWorkspace, KeyMigrationStage};
#[cfg(target_os = "macos")]
pub(crate) use metadata::{EntryState, FileAttributes, Materializer};
#[cfg(target_os = "macos")]
pub(crate) use overlay::{DirectoryView, OverlayStore, StagedWrite};
#[cfg(target_os = "macos")]
pub(crate) use vfs::{
    Credentials, FileLayer, OpenTarget, PreparedFile, VirtualFilesystem, Writeback,
};
#[cfg(target_os = "macos")]
pub(crate) use workspace::FilesystemWorkspace;
