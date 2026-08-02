use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::ffi::{CStr, CString, OsStr};
use std::fs::{self, File, OpenOptions};
use std::mem::MaybeUninit;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use uuid::Uuid;

const FILESYSTEM_DIRECTORY: &str = "filesystem";
const IMAGE_NAME: &str = "fs.sparsebundle";
const MOUNT_DIRECTORY: &str = "fs";
const LOCK_FILE: &str = "fs.lock";
const CONTROL_DIRECTORY: &str = ".agora";
const VOLUME_METADATA_FILE: &str = "volume.json";
const METADATA_VERSION: u32 = 1;
const IMAGE_CAPACITY: &str = "100g";
const MAX_KEY_SIZE: usize = 64 * 1024;
const DETACH_ATTEMPTS: usize = 200;
const DETACH_RETRY_DELAY: Duration = Duration::from_millis(50);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyMigrationStage {
    Validating,
    AcquiringLock,
    ChangingPassphrase,
    VerifyingNewKey,
    UpdatingMetadata,
    Completed,
}

#[derive(Debug, Deserialize, Serialize)]
struct VolumeMetadata {
    version: u32,
    volume_id: String,
    key_id: String,
}

#[derive(Debug)]
pub(crate) struct EncryptedWorkspace {
    mount_point: PathBuf,
    _lock: File,
    mounted: bool,
}

impl EncryptedWorkspace {
    pub(crate) async fn start(workdir: &Path, passphrase: &[u8]) -> Result<Self> {
        Self::validate_passphrase(passphrase)?;
        let workdir = Self::resolved_destination(workdir)?;
        let directory = workdir.join(FILESYSTEM_DIRECTORY);
        Self::prepare_directory(&directory)?;
        let lock = Self::lock(&directory)?;
        let image = Self::image_path(&workdir);
        let mount_point = Self::mount_point(&workdir);
        Self::prepare_mount_point(&mount_point).await?;

        let image_exists = image.exists();
        if !image_exists {
            Self::create_image(&image, passphrase).await?;
        }

        let mut workspace = Self {
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

        let initialized = if image_exists {
            workspace.validate_volume_metadata()
        } else {
            workspace.initialize_volume_metadata()
        };
        if let Err(error) = initialized {
            let _ = workspace.shutdown().await;
            if !image_exists {
                let _ = fs::remove_dir_all(&image);
            }
            return Err(error);
        }
        Ok(workspace)
    }

    pub(crate) fn root(&self) -> &Path {
        &self.mount_point
    }

    #[cfg(test)]
    pub(crate) fn map_host_path(&self, path: &Path) -> Result<PathBuf> {
        Self::mapped_path(&self.mount_point, path)
    }

    pub(crate) async fn migrate_key(
        workdir: &Path,
        old_passphrase: &[u8],
        new_passphrase: &[u8],
    ) -> Result<()> {
        Self::migrate_key_with_progress(workdir, old_passphrase, new_passphrase, |_| {}).await
    }

    pub(crate) async fn migrate_key_with_progress(
        workdir: &Path,
        old_passphrase: &[u8],
        new_passphrase: &[u8],
        mut on_progress: impl FnMut(KeyMigrationStage),
    ) -> Result<()> {
        on_progress(KeyMigrationStage::Validating);
        Self::validate_passphrase(old_passphrase)?;
        Self::validate_passphrase(new_passphrase)?;
        if old_passphrase == new_passphrase {
            bail!("new filesystem key must differ from the current key");
        }
        on_progress(KeyMigrationStage::AcquiringLock);
        let workdir = Self::resolved_destination(workdir)?;
        let directory = workdir.join(FILESYSTEM_DIRECTORY);
        Self::prepare_directory(&directory)?;
        let lock = Self::lock(&directory)?;
        let image = Self::image_path(&workdir);
        if !image.exists() {
            bail!(
                "encrypted filesystem image does not exist: {}",
                image.display()
            );
        }
        let mount_point = Self::mount_point(&workdir);
        Self::prepare_mount_point(&mount_point).await?;
        let arguments = [
            OsStr::new("chpass"),
            OsStr::new("-oldstdinpass"),
            OsStr::new("-newstdinpass"),
            image.as_os_str(),
        ];
        let mut input = Vec::with_capacity(old_passphrase.len() + new_passphrase.len() + 2);
        input.extend_from_slice(old_passphrase);
        input.push(0);
        input.extend_from_slice(new_passphrase);
        input.push(0);
        on_progress(KeyMigrationStage::ChangingPassphrase);
        Self::run_hdiutil(&arguments, &input, "change encrypted filesystem key").await?;

        let mut workspace = Self {
            mount_point,
            _lock: lock,
            mounted: false,
        };
        on_progress(KeyMigrationStage::VerifyingNewKey);
        workspace
            .attach(&image, new_passphrase)
            .await
            .context("filesystem key changed but new key verification failed")?;
        on_progress(KeyMigrationStage::UpdatingMetadata);
        let migrated = workspace.update_key_id();
        let shutdown = workspace.shutdown().await;
        migrated?;
        shutdown?;
        on_progress(KeyMigrationStage::Completed);
        Ok(())
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        if !self.mounted {
            return Ok(());
        }
        Self::detach(&self.mount_point).await?;
        self.mounted = false;
        Ok(())
    }

    pub(crate) fn mount_point(workdir: &Path) -> PathBuf {
        workdir.join(MOUNT_DIRECTORY)
    }

    pub(crate) fn image_path(workdir: &Path) -> PathBuf {
        workdir.join(FILESYSTEM_DIRECTORY).join(IMAGE_NAME)
    }

    fn volume_metadata_path(&self) -> PathBuf {
        self.mount_point
            .join(CONTROL_DIRECTORY)
            .join(VOLUME_METADATA_FILE)
    }

    fn prepare_directory(directory: &Path) -> Result<()> {
        fs::create_dir_all(directory).with_context(|| {
            format!(
                "failed to create encrypted filesystem directory {}",
                directory.display()
            )
        })?;
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "failed to secure encrypted filesystem directory {}",
                directory.display()
            )
        })
    }

    async fn prepare_mount_point(mount_point: &Path) -> Result<()> {
        if mount_point.exists() && Self::is_mount_point(mount_point)? {
            Self::detach(mount_point)
                .await
                .context("failed to detach stale encrypted filesystem mount")?;
        }
        match fs::symlink_metadata(mount_point) {
            Ok(metadata) if !metadata.is_dir() => bail!(
                "encrypted filesystem mount point is not a directory: {}",
                mount_point.display()
            ),
            Ok(_) => {
                if fs::read_dir(mount_point)?.next().is_some() {
                    bail!(
                        "unencrypted filesystem data exists at {}; move or remove it before starting the sandbox",
                        mount_point.display()
                    );
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(mount_point).with_context(|| {
                    format!(
                        "failed to create encrypted filesystem mount point {}",
                        mount_point.display()
                    )
                })?;
            }
            Err(error) => return Err(error).context("failed to inspect filesystem mount point"),
        }
        fs::set_permissions(mount_point, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "failed to secure encrypted filesystem mount point {}",
                mount_point.display()
            )
        })
    }

    async fn detach(mount_point: &Path) -> Result<()> {
        for attempt in 0..DETACH_ATTEMPTS {
            let output = Command::new("/usr/bin/hdiutil")
                .arg("detach")
                .arg(mount_point)
                .output()
                .await
                .context("failed to run hdiutil detach")?;
            if output.status.success() {
                return Ok(());
            }
            let stderr = String::from_utf8_lossy(&output.stderr);
            if !stderr.contains("Resource busy") || attempt + 1 == DETACH_ATTEMPTS {
                bail!("failed to detach encrypted filesystem: {}", stderr.trim());
            }
            tokio::time::sleep(DETACH_RETRY_DELAY).await;
        }
        unreachable!("detach retry loop always returns")
    }

    fn is_mount_point(path: &Path) -> Result<bool> {
        let path_bytes = path.as_os_str().as_bytes();
        let path = CString::new(path_bytes).context("encrypted filesystem path contains NUL")?;
        let mut status = MaybeUninit::<libc::statfs>::zeroed();
        if unsafe { libc::statfs(path.as_ptr(), status.as_mut_ptr()) } != 0 {
            return Err(std::io::Error::last_os_error())
                .context("failed to inspect encrypted filesystem mount point");
        }
        let status = unsafe { status.assume_init() };
        let mounted_at = unsafe { CStr::from_ptr(status.f_mntonname.as_ptr()) };
        Ok(mounted_at.to_bytes() == path_bytes)
    }

    pub(super) fn resolved_destination(path: &Path) -> Result<PathBuf> {
        let absolute = if path.is_absolute() {
            path.to_path_buf()
        } else {
            std::env::current_dir()?.join(path)
        };
        let mut missing = Vec::new();
        let mut ancestor = absolute.as_path();
        while !ancestor.exists() {
            let name = ancestor.file_name().with_context(|| {
                format!("filesystem path cannot be resolved: {}", path.display())
            })?;
            missing.push(name.to_os_string());
            ancestor = ancestor.parent().with_context(|| {
                format!("filesystem path cannot be resolved: {}", path.display())
            })?;
        }
        let mut resolved = ancestor.canonicalize().with_context(|| {
            format!("failed to resolve filesystem parent {}", ancestor.display())
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
                format!(
                    "failed to open encrypted filesystem lock {}",
                    path.display()
                )
            })?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error()).with_context(|| {
                format!(
                    "encrypted filesystem is already in use: {}",
                    directory.display()
                )
            });
        }
        Ok(lock)
    }

    pub(crate) fn validate_passphrase(passphrase: &[u8]) -> Result<()> {
        if passphrase.is_empty() {
            bail!("encrypted filesystem key is empty");
        }
        if passphrase.len() > MAX_KEY_SIZE {
            bail!("encrypted filesystem key exceeds {MAX_KEY_SIZE} bytes");
        }
        if passphrase.contains(&0) {
            bail!("encrypted filesystem key contains a NUL byte");
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
        let mut input = passphrase.to_vec();
        input.push(0);
        Self::run_hdiutil(&arguments, &input, "create encrypted filesystem").await?;
        fs::set_permissions(image, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "failed to secure encrypted filesystem image {}",
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
        let mut input = passphrase.to_vec();
        input.push(0);
        Self::run_hdiutil(&arguments, &input, "attach encrypted filesystem")
            .await
            .map_err(|error| {
                anyhow::anyhow!(
                    "encrypted filesystem key is incorrect or the image is unavailable; use migrate-key to change an existing key: {error:#}"
                )
            })?;
        self.mounted = true;
        Ok(())
    }

    async fn run_hdiutil(
        arguments: &[&OsStr],
        input: &[u8],
        operation: &'static str,
    ) -> Result<()> {
        let mut child = Command::new("/usr/bin/hdiutil")
            .args(arguments)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("failed to {operation}"))?;
        let mut stdin = child
            .stdin
            .take()
            .context("hdiutil passphrase input is unavailable")?;
        stdin.write_all(input).await?;
        drop(stdin);
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

    fn initialize_volume_metadata(&self) -> Result<()> {
        let control = self.mount_point.join(CONTROL_DIRECTORY);
        fs::create_dir_all(&control).with_context(|| {
            format!(
                "failed to create encrypted filesystem control directory {}",
                control.display()
            )
        })?;
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700))?;
        self.write_volume_metadata(&VolumeMetadata {
            version: METADATA_VERSION,
            volume_id: Uuid::new_v4().to_string(),
            key_id: Uuid::new_v4().to_string(),
        })
    }

    fn validate_volume_metadata(&self) -> Result<()> {
        let metadata = self.read_volume_metadata()?;
        if metadata.version != METADATA_VERSION {
            bail!(
                "unsupported encrypted filesystem metadata version {}",
                metadata.version
            );
        }
        Uuid::parse_str(&metadata.volume_id).context("invalid encrypted filesystem volume id")?;
        Uuid::parse_str(&metadata.key_id).context("invalid encrypted filesystem key id")?;
        Ok(())
    }

    fn update_key_id(&self) -> Result<()> {
        let mut metadata = self.read_volume_metadata()?;
        metadata.key_id = Uuid::new_v4().to_string();
        self.write_volume_metadata(&metadata)
    }

    fn read_volume_metadata(&self) -> Result<VolumeMetadata> {
        let path = self.volume_metadata_path();
        let contents = fs::read(&path).with_context(|| {
            format!(
                "failed to read encrypted filesystem metadata {}",
                path.display()
            )
        })?;
        serde_json::from_slice(&contents).with_context(|| {
            format!(
                "failed to parse encrypted filesystem metadata {}",
                path.display()
            )
        })
    }

    fn write_volume_metadata(&self, metadata: &VolumeMetadata) -> Result<()> {
        let path = self.volume_metadata_path();
        let contents = serde_json::to_vec_pretty(metadata)
            .context("failed to serialize encrypted filesystem metadata")?;
        fs::write(&path, contents).with_context(|| {
            format!(
                "failed to write encrypted filesystem metadata {}",
                path.display()
            )
        })
    }

    #[cfg(test)]
    fn mapped_path(mount_point: &Path, source: &Path) -> Result<PathBuf> {
        let relative = source.strip_prefix(Path::new("/")).with_context(|| {
            format!(
                "filesystem source path is not absolute: {}",
                source.display()
            )
        })?;
        Ok(mount_point.join(relative))
    }

    fn detach_blocking(&mut self) {
        if !self.mounted {
            return;
        }
        for attempt in 0..DETACH_ATTEMPTS {
            let status = std::process::Command::new("/usr/bin/hdiutil")
                .arg("detach")
                .arg(&self.mount_point)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
            if status.is_ok_and(|status| status.success()) {
                self.mounted = false;
                return;
            }
            if attempt + 1 < DETACH_ATTEMPTS {
                std::thread::sleep(DETACH_RETRY_DELAY);
            }
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
