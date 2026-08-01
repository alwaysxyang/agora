#[cfg(target_os = "macos")]
mod apfs;

#[cfg(target_os = "macos")]
pub(crate) use apfs::EncryptedWorkspace;
