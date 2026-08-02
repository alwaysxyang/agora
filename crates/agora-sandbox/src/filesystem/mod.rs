#[cfg(target_os = "macos")]
mod apfs;
#[cfg(target_os = "macos")]
mod metadata;
#[cfg(target_os = "macos")]
mod overlay;
#[cfg(target_os = "macos")]
mod workspace;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FilesystemMode {
    Encrypted,
    #[default]
    Plain,
}

#[cfg(target_os = "macos")]
pub(crate) use apfs::{EncryptedWorkspace, KeyMigrationStage};
#[cfg(target_os = "macos")]
pub(crate) use metadata::{EntryState, Materializer};
#[cfg(target_os = "macos")]
pub(crate) use overlay::{DirectoryView, OverlayStore, StagedWrite};
#[cfg(target_os = "macos")]
pub(crate) use workspace::FilesystemWorkspace;
