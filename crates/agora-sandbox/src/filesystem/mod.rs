#[cfg(target_os = "macos")]
mod apfs;
#[cfg(target_os = "macos")]
mod metadata;
#[cfg(target_os = "macos")]
mod overlay;

#[cfg(target_os = "macos")]
pub(crate) use apfs::EncryptedWorkspace;
#[cfg(target_os = "macos")]
pub(crate) use metadata::{EntryState, Materializer};
#[cfg(target_os = "macos")]
pub(crate) use overlay::{DirectoryView, OverlayStore};
