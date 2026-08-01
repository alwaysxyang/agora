use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

const FILESYSTEM_DIRECTORY: &str = "filesystem";
const IMAGE_NAME: &str = "workspace.sparsebundle";
const MOUNT_DIRECTORY: &str = "mount";
const LOCK_FILE: &str = ".lock";
const METADATA_FILE: &str = "workspace.json";
const METADATA_VERSION: u32 = 1;
const IMAGE_CAPACITY: &str = "100g";
const MAX_KEY_SIZE: usize = 64 * 1024;

#[derive(Deserialize, Serialize)]
struct WorkspaceMetadata {
    version: u32,
    source: String,
}

pub(crate) struct EncryptedWorkspace {
    source: PathBuf,
    path: PathBuf,
    mount_point: PathBuf,
    _lock: File,
    mounted: bool,
}

impl EncryptedWorkspace {
    pub(crate) async fn start(workdir: &Path, source: &Path, passphrase: &[u8]) -> Result<Self> {
        Self::validate_passphrase(passphrase)?;
        let source = source.canonicalize().with_context(|| {
            format!(
                "failed to resolve encrypted workspace source {}",
                source.display()
            )
        })?;
        if !source.is_dir() {
            bail!(
                "encrypted workspace source is not a directory: {}",
                source.display()
            );
        }
        let workdir = Self::resolved_destination(workdir)?;
        if workdir.starts_with(&source) {
            bail!(
                "sandbox work directory must not be inside encrypted workspace source {}",
                source.display()
            );
        }

        let directory = workdir.join(FILESYSTEM_DIRECTORY);
        fs::create_dir_all(&directory).with_context(|| {
            format!(
                "failed to create encrypted filesystem directory {}",
                directory.display()
            )
        })?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "failed to secure encrypted filesystem directory {}",
                directory.display()
            )
        })?;
        let lock = Self::lock(&directory)?;
        let image = directory.join(IMAGE_NAME);
        let metadata = directory.join(METADATA_FILE);
        let mount_point = directory.join(MOUNT_DIRECTORY);
        fs::create_dir_all(&mount_point).with_context(|| {
            format!(
                "failed to create encrypted filesystem mount point {}",
                mount_point.display()
            )
        })?;
        if Self::is_mount_point(&mount_point)? {
            Self::detach(&mount_point)
                .await
                .context("failed to detach stale encrypted workspace mount")?;
        }
        fs::set_permissions(&mount_point, fs::Permissions::from_mode(0o700)).with_context(
            || {
                format!(
                    "failed to secure encrypted filesystem mount point {}",
                    mount_point.display()
                )
            },
        )?;

        let image_exists = image.exists();
        let metadata_exists = metadata.exists();
        match (image_exists, metadata_exists) {
            (false, true) => bail!(
                "encrypted workspace metadata exists without its disk image: {}",
                metadata.display()
            ),
            (true, false) => bail!(
                "encrypted workspace disk image exists without metadata: {}",
                image.display()
            ),
            _ => {}
        }
        if !image_exists {
            Self::create_image(&image, passphrase).await?;
        }

        let mut workspace = Self {
            source: source.clone(),
            path: Self::mapped_path(&mount_point, &source)?,
            mount_point,
            _lock: lock,
            mounted: false,
        };
        if let Err(error) = workspace.attach(&image, passphrase).await {
            if !image_exists {
                let _ = fs::remove_dir_all(&image);
            }
            return Err(error);
        }

        let initialized = if metadata_exists {
            workspace.validate_metadata(&metadata)?;
            if !workspace.path.is_dir() {
                bail!(
                    "encrypted workspace directory is missing: {}",
                    workspace.path.display()
                );
            }
            Ok(())
        } else {
            workspace.initialize(&metadata).await
        };
        if let Err(error) = initialized {
            let _ = workspace.shutdown().await;
            if !image_exists {
                let _ = fs::remove_dir_all(&image);
                let _ = fs::remove_file(&metadata);
            }
            return Err(error);
        }
        Ok(workspace)
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn map_source_path(&self, path: &Path) -> Option<PathBuf> {
        path.strip_prefix(&self.source)
            .ok()
            .map(|relative| self.path.join(relative))
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        if !self.mounted {
            return Ok(());
        }
        Self::detach(&self.mount_point).await?;
        self.mounted = false;
        Ok(())
    }

    async fn detach(mount_point: &Path) -> Result<()> {
        let output = Command::new("/usr/bin/hdiutil")
            .arg("detach")
            .arg(mount_point)
            .output()
            .await
            .context("failed to run hdiutil detach")?;
        if !output.status.success() {
            bail!(
                "failed to detach encrypted workspace: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    fn is_mount_point(path: &Path) -> Result<bool> {
        let path_bytes = path.as_os_str().as_bytes();
        let path = CString::new(path_bytes).context("encrypted workspace path contains NUL")?;
        let mut status = MaybeUninit::<libc::statfs>::zeroed();
        if unsafe { libc::statfs(path.as_ptr(), status.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect encrypted workspace mount point");
        }
        let status = unsafe { status.assume_init() };
        let mounted_at = unsafe { CStr::from_ptr(status.f_mntonname.as_ptr()) };
        Ok(mounted_at.to_bytes() == path_bytes)
    }

    fn resolved_destination(path: &Path) -> Result<PathBuf> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut missing = Vec::new();
        let mut ancestor = absolute.as_path();
        while !ancestor.exists() {
            let name = ancestor.file_name().with_context(|| {
                format!(
                    "encrypted workspace path cannot be resolved: {}",
                    path.display()
                )
            })?;
            missing.push(name.to_os_string());
            ancestor = ancestor.parent().with_context(|| {
                format!(
                    "encrypted workspace path cannot be resolved: {}",
                    path.display()
                )
            })?;
        }
        let mut resolved = ancestor.canonicalize().with_context(|| {
            format!(
                "failed to resolve encrypted workspace parent {}",
                ancestor.display()
            )
        })?;
        for component in missing.into_iter().rev() {
            resolved.push(component);
        }
        Ok(resolved)
    }

    fn lock(directory: &Path) -> Result<File> {
        let path = directory.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .with_context(|| {
                format!("failed to open encrypted workspace lock {}", path.display())
            })?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "encrypted workspace is already in use: {}",
                    directory.display()
                )
            });
        }
        Ok(lock)
    }

    pub(crate) fn validate_passphrase(passphrase: &[u8]) -> Result<()> {
        if passphrase.is_empty() {
            bail!("encrypted workspace key is empty");
        }
        if passphrase.len() > MAX_KEY_SIZE {
            bail!("encrypted workspace key exceeds {MAX_KEY_SIZE} bytes");
        }
        if passphrase.contains(&0) {
            bail!("encrypted workspace key contains a NUL byte");
        }
        Ok(())
    }

    async fn create_image(image: &Path, passphrase: &[u8]) -> Result<()> {
        let arguments = [
            OsStr::new("create"),
            OsStr::new("-size"),
            OsStr::new(IMAGE_CAPACITY),
            OsStr::new("-fs"),
            OsStr::new("APFS"),
            OsStr::new("-type"),
            OsStr::new("SPARSEBUNDLE"),
            OsStr::new("-volname"),
            OsStr::new("AgoraSandbox"),
            OsStr::new("-encryption"),
            OsStr::new("AES-256"),
            OsStr::new("-stdinpass"),
            image.as_os_str(),
        ];
        Self::run_with_passphrase(&arguments, passphrase, "create encrypted workspace").await?;
        fs::set_permissions(image, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "failed to secure encrypted workspace image {}",
                image.display()
            )
        })
    }

    async fn attach(&mut self, image: &Path, passphrase: &[u8]) -> Result<()> {
        let arguments = [
            OsStr::new("attach"),
            OsStr::new("-nobrowse"),
            OsStr::new("-owners"),
            OsStr::new("on"),
            OsStr::new("-mountpoint"),
            self.mount_point.as_os_str(),
            OsStr::new("-stdinpass"),
            image.as_os_str(),
        ];
        Self::run_with_passphrase(&arguments, passphrase, "attach encrypted workspace").await?;
        self.mounted = true;
        Ok(())
    }

    async fn run_with_passphrase(
        arguments: &[&OsStr],
        passphrase: &[u8],
        operation: &'static str,
    ) -> Result<()> {
        let mut child = Command::new("/usr/bin/hdiutil")
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to {operation}"))?;
        let mut input = child
            .stdin
            .take()
            .context("hdiutil passphrase input is unavailable")?;
        input.write_all(passphrase).await?;
        input.write_all(&[0]).await?;
        drop(input);
        let output = child
            .wait_with_output()
            .await
            .with_context(|| format!("failed to {operation}"))?;
        if !output.status.success() {
            bail!(
                "failed to {operation}: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        Ok(())
    }

    async fn initialize(&self, metadata_path: &Path) -> Result<()> {
        let parent = self
            .path
            .parent()
            .context("encrypted workspace path has no parent")?;
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create encrypted workspace parent {}",
                parent.display()
            )
        })?;
        let output = Command::new("/usr/bin/ditto")
            .arg("--noqtn")
            .arg(&self.source)
            .arg(&self.path)
            .output()
            .await
            .context("failed to run ditto while initializing encrypted workspace")?;
        if !output.status.success() {
            bail!(
                "failed to initialize encrypted workspace: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            );
        }
        let metadata = WorkspaceMetadata {
            version: METADATA_VERSION,
            source: base64::engine::general_purpose::STANDARD
                .encode(self.source.as_os_str().as_bytes()),
        };
        let contents = serde_json::to_vec_pretty(&metadata)
            .context("failed to serialize encrypted workspace metadata")?;
        fs::write(metadata_path, contents).with_context(|| {
            format!(
                "failed to write encrypted workspace metadata {}",
                metadata_path.display()
            )
        })
    }

    fn validate_metadata(&self, metadata_path: &Path) -> Result<()> {
        let contents = fs::read(metadata_path).with_context(|| {
            format!(
                "failed to read encrypted workspace metadata {}",
                metadata_path.display()
            )
        })?;
        let metadata: WorkspaceMetadata = serde_json::from_slice(&contents).with_context(|| {
            format!(
                "failed to parse encrypted workspace metadata {}",
                metadata_path.display()
            )
        })?;
        if metadata.version != METADATA_VERSION {
            bail!(
                "unsupported encrypted workspace metadata version {}",
                metadata.version
            );
        }
        let source = base64::engine::general_purpose::STANDARD
            .decode(metadata.source)
            .context("invalid encrypted workspace source metadata")?;
        if source != self.source.as_os_str().as_bytes() {
            bail!(
                "encrypted workspace belongs to a different source directory: {}",
                self.source.display()
            );
        }
        Ok(())
    }

    fn mapped_path(mount_point: &Path, source: &Path) -> Result<PathBuf> {
        let relative = source.strip_prefix(Path::new("/")).with_context(|| {
            format!(
                "encrypted workspace source is not absolute: {}",
                source.display()
            )
        })?;
        Ok(mount_point.join(relative))
    }

    fn detach_blocking(&mut self) {
        if !self.mounted {
            return;
        }
        let status = std::process::Command::new("/usr/bin/hdiutil")
            .arg("detach")
            .arg(&self.mount_point)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();
        if status.is_ok_and(|status| status.success()) {
            self.mounted = false;
        }
    }
}

impl Drop for EncryptedWorkspace {
    fn drop(&mut self) {
        self.detach_blocking();
    }
}

#[cfg(test)]
mod tests;
