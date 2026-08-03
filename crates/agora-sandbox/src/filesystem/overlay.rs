use super::crypto::FileCipher;
use super::metadata::{EntryState, FileAttributes, Materializer, MetadataStore};
use super::namespace;
use anyhow::{Context, Result};
use md5::{Digest, Md5};
use std::collections::{BTreeSet, HashMap};
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub(crate) struct OverlayStore {
    root: PathBuf,
    canonical_root: PathBuf,
    metadata: MetadataStore,
    lock_path: PathBuf,
    cipher: Option<FileCipher>,
}

pub(crate) struct DirectoryView {
    logical: PathBuf,
    primary: PathBuf,
    lower: Option<PathBuf>,
    hidden: BTreeSet<OsString>,
    aliases: HashMap<OsString, OsString>,
}

pub(crate) struct StagedWrite {
    logical: PathBuf,
    destination: PathBuf,
    reservation: Option<WriteReservation>,
}

struct WriteReservation {
    file: File,
    lock_path: PathBuf,
}

impl StagedWrite {
    pub(crate) fn destination(&self) -> &Path {
        &self.destination
    }

    fn commit(&mut self) {
        drop(self.reservation.take());
    }
}

impl Drop for StagedWrite {
    fn drop(&mut self) {
        let Some(reservation) = self.reservation.take() else {
            return;
        };
        let Ok(lock) = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&reservation.lock_path)
        else {
            return;
        };
        if OverlayStore::flock(&lock, libc::LOCK_EX).is_err() {
            return;
        }
        let reserved = reservation
            .file
            .metadata()
            .ok()
            .map(|metadata| (metadata.dev(), metadata.ino()));
        let current = self
            .destination
            .symlink_metadata()
            .ok()
            .map(|metadata| (metadata.dev(), metadata.ino()));
        if reserved.is_some() && reserved == current {
            let _ = fs::remove_file(&self.destination);
        }
        let _ = OverlayStore::flock(&lock, libc::LOCK_UN);
    }
}

fn is_private_path_with_roots(root: &Path, canonical_root: &Path, path: &Path) -> Result<bool> {
    let path = namespace::normalize(path)?;
    if root
        .parent()
        .is_some_and(|workdir| path.starts_with(workdir))
        || canonical_root
            .parent()
            .is_some_and(|workdir| path.starts_with(workdir))
    {
        return Ok(true);
    }
    let resolved = OverlayStore::resolve_existing_ancestor(&path)?;
    Ok(canonical_root
        .parent()
        .is_some_and(|workdir| resolved.starts_with(workdir)))
}

impl DirectoryView {
    pub(crate) fn logical(&self) -> &Path {
        &self.logical
    }

    pub(crate) fn primary(&self) -> &Path {
        &self.primary
    }

    pub(crate) fn lower(&self) -> Option<&Path> {
        self.lower.as_deref()
    }

    pub(crate) fn hidden(&self) -> &BTreeSet<OsString> {
        &self.hidden
    }

    pub(crate) fn aliases(&self) -> &HashMap<OsString, OsString> {
        &self.aliases
    }

    pub(crate) fn is_passthrough(&self) -> bool {
        self.primary == self.logical
            && self.lower.is_none()
            && self.hidden.is_empty()
            && self.aliases.is_empty()
    }
}

impl OverlayStore {
    pub(crate) fn new(root: impl Into<PathBuf>) -> Result<Self> {
        Self::with_cipher(root, None)
    }

    pub(crate) fn encrypted(root: impl Into<PathBuf>, cipher: FileCipher) -> Result<Self> {
        Self::with_cipher(root, Some(cipher))
    }

    fn with_cipher(root: impl Into<PathBuf>, cipher: Option<FileCipher>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create filesystem root {}", root.display()))?;
        let canonical_root = root
            .canonicalize()
            .with_context(|| format!("failed to resolve filesystem root {}", root.display()))?;
        let metadata = MetadataStore::new(&canonical_root)?;
        let lock_path = canonical_root.join(namespace::VFS_LOCK_FILE);
        OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .with_context(|| format!("failed to open overlay lock {}", lock_path.display()))?;
        Ok(Self {
            root,
            canonical_root,
            metadata,
            lock_path,
            cipher,
        })
    }

    #[cfg(test)]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn is_internal(&self, path: &Path) -> bool {
        path.starts_with(&self.root) || path.starts_with(&self.canonical_root)
    }

    pub(crate) fn is_private(&self, path: &Path) -> Result<bool> {
        is_private_path_with_roots(&self.root, &self.canonical_root, path)
    }

    pub(crate) fn logical_path(&self, path: &Path) -> Result<PathBuf> {
        let logical = namespace::logical_path(&self.root, path)
            .or_else(|_| namespace::logical_path(&self.canonical_root, path))?;
        let Some(backing_name) = path.file_name() else {
            return Ok(logical);
        };
        let Some(parent) = logical.parent() else {
            return Ok(logical);
        };
        if let Some((logical_name, _)) = self
            .metadata
            .backing_names(parent)?
            .into_iter()
            .find(|(_, backing)| backing == backing_name)
        {
            return Ok(parent.join(logical_name));
        }
        Ok(logical)
    }

    pub(crate) fn prepare_read(&self, path: &Path) -> Result<PathBuf> {
        let path = self.normalize(path)?;
        if self.is_internal(&path) {
            return Ok(path);
        }
        self.with_lock(|| self.prepare_read_locked(&path))
    }

    pub(crate) fn resolve_final(&self, path: &Path, allow_missing: bool) -> Result<PathBuf> {
        let path = self.normalize(path)?;
        self.with_lock(|| self.resolve_final_locked(path, allow_missing))
    }

    pub(crate) fn visible_path(&self, path: &Path) -> Result<PathBuf> {
        let path = if self.is_internal(path) {
            self.logical_path(path)?
        } else {
            self.normalize(path)?
        };
        self.with_lock(|| self.visible_path_locked(&path))
    }

    pub(crate) fn state(&self, path: &Path) -> Result<Option<EntryState>> {
        let path = if self.is_internal(path) {
            self.logical_path(path)?
        } else {
            self.normalize(path)?
        };
        self.with_lock(|| self.metadata.state(&path))
    }

    pub(crate) fn attributes(&self, path: &Path) -> Result<Option<FileAttributes>> {
        let path = if self.is_internal(path) {
            self.logical_path(path)?
        } else {
            self.normalize(path)?
        };
        self.with_lock(|| match self.metadata.state(&path)? {
            Some(EntryState::Cow) => self.metadata.attributes(&path),
            None => self.metadata.attributes(&path),
            Some(EntryState::Cached { .. } | EntryState::Whiteout) => Ok(None),
        })
    }

    pub(crate) fn set_attributes(&self, path: &Path, attributes: FileAttributes) -> Result<()> {
        let path = if self.is_internal(path) {
            self.logical_path(path)?
        } else {
            self.normalize(path)?
        };
        self.with_lock(|| self.metadata.set_attributes(&path, attributes))
    }

    pub(crate) fn cipher(&self) -> Option<&FileCipher> {
        self.cipher.as_ref()
    }

    pub(crate) fn exists(&self, path: &Path) -> Result<bool> {
        let path = self.normalize(path)?;
        self.with_lock(|| self.visible_exists_locked(&path))
    }

    pub(crate) fn mark_executable(&self, path: &Path) -> Result<()> {
        let path = if self.is_internal(path) {
            self.logical_path(path)?
        } else {
            self.normalize(path)?
        };
        self.with_lock(|| {
            if let Some(EntryState::Cached { checksum, .. }) = self.metadata.state(&path)? {
                self.metadata.set(
                    &path,
                    EntryState::Cached {
                        checksum,
                        materializer: Materializer::Executable,
                    },
                )?;
            }
            Ok(())
        })
    }

    #[cfg(test)]
    pub(crate) fn prepare_write(&self, path: &Path, create: bool) -> Result<PathBuf> {
        let staged = self.stage_write(path, create)?;
        let destination = staged.destination.clone();
        self.commit_write(staged)?;
        Ok(destination)
    }

    pub(crate) fn stage_write(&self, path: &Path, create: bool) -> Result<StagedWrite> {
        let path = self.normalize(path)?;
        if self.is_internal(&path) {
            return Ok(StagedWrite {
                destination: path.clone(),
                logical: path,
                reservation: None,
            });
        }
        let destination = self.with_lock(|| self.stage_write_locked(&path, create))?;
        Ok(StagedWrite {
            logical: path,
            destination,
            reservation: None,
        })
    }

    pub(crate) fn stage_file_open(
        &self,
        path: &Path,
        create: bool,
        exclusive: bool,
    ) -> Result<(StagedWrite, bool, Option<File>)> {
        let path = self.normalize(path)?;
        if self.is_internal(&path) {
            return Ok((
                StagedWrite {
                    destination: path.clone(),
                    logical: path,
                    reservation: None,
                },
                true,
                None,
            ));
        }
        self.with_lock(|| {
            let existed = self.visible_exists_locked(&path)?;
            if create && exclusive && existed {
                return Err(std::io::Error::from_raw_os_error(libc::EEXIST).into());
            }
            let destination = self.stage_write_locked(&path, create)?;
            let reserve = self.cipher.is_some() && create && exclusive && !existed;
            let reservation = reserve
                .then(|| {
                    OpenOptions::new()
                        .write(true)
                        .create_new(true)
                        .mode(0o600)
                        .open(&destination)
                        .map_err(|error| {
                            if error.kind() == std::io::ErrorKind::AlreadyExists {
                                std::io::Error::from_raw_os_error(libc::EEXIST)
                            } else {
                                error
                            }
                        })
                })
                .transpose()?;
            let lease = match self.acquire_write_lease(&destination, libc::LOCK_SH) {
                Ok(lease) => lease,
                Err(error) => {
                    if reserve {
                        let _ = fs::remove_file(&destination);
                    }
                    return Err(error);
                }
            };
            let staged = StagedWrite {
                logical: path,
                destination,
                reservation: reservation.map(|file| WriteReservation {
                    file,
                    lock_path: self.lock_path.clone(),
                }),
            };
            Ok((staged, existed, lease))
        })
    }

    pub(crate) fn commit_write(&self, mut staged: StagedWrite) -> Result<()> {
        if self.is_internal(&staged.logical) {
            staged.commit();
            return Ok(());
        }
        self.with_lock(|| self.metadata.set(&staged.logical, EntryState::Cow))?;
        staged.commit();
        Ok(())
    }

    pub(crate) fn commit_created_file(&self, mut staged: StagedWrite, mode: u32) -> Result<()> {
        if self.is_internal(&staged.logical) {
            staged.commit();
            return Ok(());
        }
        self.with_lock(|| {
            self.metadata.set_with_attributes(
                &staged.logical,
                EntryState::Cow,
                Some(FileAttributes::created_file(mode)),
            )
        })?;
        staged.commit();
        Ok(())
    }

    pub(crate) fn publish_encrypted(&self, plaintext: &mut File, destination: &Path) -> Result<()> {
        let cipher = self
            .cipher
            .as_ref()
            .context("encrypted writeback requires a filesystem cipher")?;
        self.with_lock(|| cipher.encrypt(plaintext, destination))
    }

    pub(crate) fn prepare_directory(&self, path: &Path) -> Result<PathBuf> {
        let path = self.normalize(path)?;
        if self.is_internal(&path) {
            return Ok(path);
        }
        self.with_lock(|| self.prepare_directory_locked(&path))
    }

    pub(crate) fn directory_view(&self, path: &Path) -> Result<DirectoryView> {
        let path = self.normalize(path)?;
        self.with_lock(|| self.directory_view_locked(&path))
    }

    pub(crate) fn create_directory(&self, path: &Path, mode: u32) -> Result<PathBuf> {
        let path = self.normalize(path)?;
        self.with_lock(|| {
            let destination = self.plain_destination(&path)?;
            if self.visible_exists_locked(&path)? {
                return Err(std::io::Error::from_raw_os_error(libc::EEXIST).into());
            }
            self.ensure_parent_locked(&path)?;
            fs::create_dir(&destination)?;
            Self::secure_backing_directory(&destination, mode)?;
            self.metadata.set_with_attributes(
                &path,
                EntryState::Cow,
                Some(FileAttributes::created_directory(mode)),
            )?;
            Ok(destination)
        })
    }

    pub(crate) fn remove(&self, path: &Path, directory: bool) -> Result<()> {
        let path = self.normalize(path)?;
        self.with_lock(|| self.remove_locked(&path, directory))
    }

    pub(crate) fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        let from = self.normalize(from)?;
        let to = self.normalize(to)?;
        self.with_lock(|| self.rename_locked(&from, &to))
    }

    pub(crate) fn prepare_executable<F>(&self, source: &Path, prepare: F) -> Result<PathBuf>
    where
        F: FnOnce(&Path) -> Result<()>,
    {
        let source = self.normalize(source)?;
        self.with_lock(|| {
            let destination = self.plain_destination(&source)?;
            let checksum = Self::checksum(&source)?;
            if destination.is_file()
                && destination.metadata()?.mode() & 0o111 != 0
                && matches!(
                    self.metadata.state(&source)?,
                    Some(EntryState::Cached {
                        checksum: ref cached,
                        materializer: Materializer::Executable,
                    }) if cached == &checksum
                )
            {
                return Ok(destination);
            }
            let parent = destination
                .parent()
                .context("executable destination has no parent")?;
            fs::create_dir_all(parent)?;
            let temporary =
                parent.join(format!(".agora-executable-{}.tmp", Uuid::new_v4().simple()));
            let result = (|| {
                prepare(&temporary)?;
                Self::remove_existing(&destination)?;
                fs::rename(&temporary, &destination)?;
                self.metadata.set(
                    &source,
                    EntryState::Cached {
                        checksum,
                        materializer: Materializer::Executable,
                    },
                )?;
                Ok(destination.clone())
            })();
            if result.is_err() {
                let _ = fs::remove_file(temporary);
            }
            result
        })
    }

    pub(crate) fn checksum(path: &Path) -> Result<String> {
        let mut file = File::open(path)
            .with_context(|| format!("failed to open {} for checksum", path.display()))?;
        let mut digest = Md5::new();
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            digest.update(&buffer[..read]);
        }
        Ok(Self::hex_digest(digest.finalize().as_slice()))
    }

    #[cfg(test)]
    pub(crate) fn state_for_test(&self, path: &Path) -> Result<Option<EntryState>> {
        self.state(path)
    }

    #[cfg(test)]
    pub(crate) fn remove_state_for_test(&self, path: &Path) -> Result<()> {
        self.metadata.remove(path)
    }

    fn prepare_read_locked(&self, path: &Path) -> Result<PathBuf> {
        let destination = self.destination(path)?;
        if self.cow_ancestor_locked(path)? {
            return destination
                .symlink_metadata()
                .map(|_| destination)
                .map_err(Into::into);
        }
        match self.metadata.state(path)? {
            Some(EntryState::Whiteout) => Self::not_found(path),
            Some(EntryState::Cow) => destination
                .symlink_metadata()
                .map(|_| destination)
                .map_err(Into::into),
            Some(EntryState::Cached { .. }) => match path.symlink_metadata() {
                Ok(_) => Ok(path.to_path_buf()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    Self::remove_existing(&destination)?;
                    self.metadata.remove(path)?;
                    Err(error.into())
                }
                Err(error) => Err(error.into()),
            },
            None => path
                .symlink_metadata()
                .map(|_| path.to_path_buf())
                .map_err(Into::into),
        }
    }

    fn resolve_final_locked(&self, mut logical: PathBuf, allow_missing: bool) -> Result<PathBuf> {
        for _ in 0..40 {
            let visible = match self.prepare_read_locked(&logical) {
                Ok(visible) => visible,
                Err(error) if allow_missing && Self::is_not_found(&error) => return Ok(logical),
                Err(error) => return Err(error),
            };
            if !visible.symlink_metadata()?.file_type().is_symlink() {
                return Ok(logical);
            }
            let target = fs::read_link(&visible)?;
            let target = if target.is_absolute() {
                target
            } else {
                logical
                    .parent()
                    .context("filesystem symlink has no parent")?
                    .join(target)
            };
            logical = self.normalize(&target)?;
        }
        Err(std::io::Error::from_raw_os_error(libc::ELOOP).into())
    }

    fn visible_path_locked(&self, path: &Path) -> Result<PathBuf> {
        let destination = self.destination(path)?;
        match self.metadata.state(path)? {
            Some(EntryState::Whiteout) => Self::not_found(path),
            Some(EntryState::Cow) => destination
                .symlink_metadata()
                .map(|_| destination)
                .map_err(Into::into),
            Some(EntryState::Cached { .. }) => path
                .canonicalize()
                .with_context(|| format!("failed to resolve visible path {}", path.display())),
            None if self.cow_ancestor_locked(path)? => destination
                .symlink_metadata()
                .map(|_| destination)
                .map_err(Into::into),
            None => {
                let canonical = path.canonicalize().with_context(|| {
                    format!("failed to resolve visible path {}", path.display())
                })?;
                match self.metadata.state(&canonical)? {
                    Some(EntryState::Whiteout) => Self::not_found(&canonical),
                    Some(EntryState::Cow) => {
                        let destination = self.destination(&canonical)?;
                        destination
                            .symlink_metadata()
                            .map(|_| destination)
                            .map_err(Into::into)
                    }
                    Some(EntryState::Cached { .. }) => Ok(canonical),
                    None if self.cow_ancestor_locked(&canonical)? => {
                        let destination = self.destination(&canonical)?;
                        destination
                            .symlink_metadata()
                            .map(|_| destination)
                            .map_err(Into::into)
                    }
                    None => Ok(canonical),
                }
            }
        }
    }

    fn stage_write_locked(&self, path: &Path, create: bool) -> Result<PathBuf> {
        if self.cow_ancestor_locked(path)? {
            let destination = match self.metadata.backing_name(path)? {
                Some(_) => self.destination(path)?,
                None if self.plain_destination(path)?.is_dir() => self.plain_destination(path)?,
                None => self.file_destination(path, create)?,
            };
            if !destination.exists() && !create {
                return Self::not_found(path);
            }
            self.ensure_parent_locked(path)?;
            return Ok(destination);
        }
        match self.metadata.state(path)? {
            Some(EntryState::Cow) => {
                let destination = self.destination(path)?;
                if !destination.exists() && !create {
                    return Self::not_found(path);
                }
                Ok(destination)
            }
            Some(EntryState::Whiteout) if !create => Self::not_found(path),
            Some(EntryState::Whiteout) => {
                self.ensure_parent_locked(path)?;
                self.file_destination(path, true)
            }
            Some(EntryState::Cached {
                checksum,
                materializer,
            }) => match path.symlink_metadata() {
                Ok(metadata) if metadata.is_file() => {
                    let destination = self.destination(path)?;
                    let reusable = destination.exists()
                        && materializer == Materializer::Copy
                        && Self::checksum(path).is_ok_and(|current| current == checksum);
                    if !reusable {
                        return self.materialize_file_locked(path, Materializer::Copy);
                    }
                    Ok(destination)
                }
                Ok(_) => Ok(path.to_path_buf()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && create => {
                    let destination = self.destination(path)?;
                    Self::remove_existing(&destination)?;
                    self.metadata.remove(path)?;
                    self.ensure_parent_locked(path)?;
                    self.file_destination(path, true)
                }
                Err(error) => Err(error.into()),
            },
            None if path.exists() => {
                let metadata = path.metadata()?;
                if !metadata.is_file() {
                    return Ok(path.to_path_buf());
                }
                self.materialize_file_locked(path, Materializer::Copy)
            }
            None if create => {
                self.ensure_parent_locked(path)?;
                self.file_destination(path, true)
            }
            None => Self::not_found(path),
        }
    }

    fn prepare_directory_locked(&self, path: &Path) -> Result<PathBuf> {
        let destination = self.destination(path)?;
        if matches!(self.metadata.state(path)?, Some(EntryState::Whiteout)) {
            return Self::not_found(path);
        }
        let cow = self.cow_ancestor_locked(path)?
            || matches!(self.metadata.state(path)?, Some(EntryState::Cow));
        if cow {
            return destination
                .is_dir()
                .then_some(destination)
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT).into());
        }
        if destination.is_dir() {
            return Ok(destination);
        }
        path.is_dir()
            .then(|| path.to_path_buf())
            .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT).into())
    }

    fn ensure_directory_locked(&self, path: &Path) -> Result<PathBuf> {
        let destination = self.destination(path)?;
        if matches!(self.metadata.state(path)?, Some(EntryState::Whiteout)) {
            return Self::not_found(path);
        }
        let cow = self.cow_ancestor_locked(path)?
            || matches!(self.metadata.state(path)?, Some(EntryState::Cow));
        if !cow && !path.is_dir() {
            return Self::not_found(path);
        }
        fs::create_dir_all(&destination)?;
        if !cow && path.is_dir() {
            let metadata = path.metadata()?;
            Self::secure_backing_directory(&destination, metadata.mode())?;
        } else {
            Self::secure_backing_directory(&destination, 0o700)?;
        }
        Ok(destination)
    }

    fn directory_view_locked(&self, path: &Path) -> Result<DirectoryView> {
        if matches!(self.metadata.state(path)?, Some(EntryState::Whiteout)) {
            return Self::not_found(path);
        }
        let upper = self.plain_destination(path)?;
        let cow = self.cow_ancestor_locked(path)?
            || matches!(self.metadata.state(path)?, Some(EntryState::Cow));
        let lower = (!cow && path.is_dir()).then(|| path.to_path_buf());
        let upper_exists = upper.is_dir();
        let (primary, lower) = if upper_exists {
            (upper.clone(), lower)
        } else if let Some(lower) = lower {
            (lower, None)
        } else {
            return Self::not_found(path);
        };
        let mut hidden = self
            .metadata
            .entries(path)?
            .into_iter()
            .filter_map(|(name, state)| matches!(state, EntryState::Whiteout).then_some(name))
            .collect::<BTreeSet<_>>();
        let mut aliases = HashMap::new();
        aliases.extend(
            self.metadata
                .backing_names(path)?
                .into_iter()
                .map(|(logical, backing)| (backing, logical)),
        );
        if upper_exists {
            for entry in fs::read_dir(&upper)? {
                let name = entry?.file_name();
                if namespace::is_control_name(&name) && !aliases.contains_key(&name) {
                    hidden.insert(name);
                    continue;
                }
                let logical = aliases
                    .get(&name)
                    .cloned()
                    .unwrap_or(namespace::decode_name(&name)?);
                if logical != name {
                    aliases.insert(name, logical);
                }
            }
        }
        Ok(DirectoryView {
            logical: path.to_path_buf(),
            primary,
            lower,
            hidden,
            aliases,
        })
    }

    fn materialize_file_locked(
        &self,
        source: &Path,
        materializer: Materializer,
    ) -> Result<PathBuf> {
        let destination = self.file_destination(source, true)?;
        let parent = destination
            .parent()
            .context("filesystem destination has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".agora-copy-{}.tmp", Uuid::new_v4().simple()));
        let result = (|| {
            let mut input = File::open(source)?;
            let source_metadata = input.metadata()?;
            let mut digest = Md5::new();
            if let Some(cipher) = &self.cipher {
                let mut plaintext = tempfile::tempfile()
                    .context("failed to create anonymous filesystem materialization file")?;
                let mut buffer = [0_u8; 64 * 1024];
                loop {
                    let read = input.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    digest.update(&buffer[..read]);
                    plaintext.write_all(&buffer[..read])?;
                }
                cipher.encrypt(&mut plaintext, &temporary)?;
            } else {
                let mut output = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .open(&temporary)?;
                let mut buffer = [0_u8; 64 * 1024];
                loop {
                    let read = input.read(&mut buffer)?;
                    if read == 0 {
                        break;
                    }
                    digest.update(&buffer[..read]);
                    output.write_all(&buffer[..read])?;
                }
                output.sync_all()?;
            }
            if self.cipher.is_none() {
                fs::set_permissions(
                    &temporary,
                    fs::Permissions::from_mode(source_metadata.mode()),
                )?;
            }
            Self::remove_existing(&destination)?;
            fs::rename(&temporary, &destination)?;
            let plain_destination = self.plain_destination(source)?;
            if plain_destination != destination {
                Self::remove_existing(&plain_destination)?;
            }
            self.metadata.set_with_attributes(
                source,
                EntryState::Cached {
                    checksum: Self::hex_digest(digest.finalize().as_slice()),
                    materializer,
                },
                Some(FileAttributes::from_metadata(&source_metadata)),
            )?;
            Ok(destination.clone())
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn remove_locked(&self, path: &Path, directory: bool) -> Result<()> {
        if !self.visible_exists_locked(path)? {
            return Self::not_found(path);
        }
        let destination = self.destination(path)?;
        let metadata = destination
            .symlink_metadata()
            .or_else(|_| path.symlink_metadata())?;
        if directory {
            if !metadata.is_dir() {
                return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR).into());
            }
            if !self.directory_is_empty_locked(path)? {
                return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY).into());
            }
        } else if metadata.is_dir() {
            return Err(std::io::Error::from_raw_os_error(libc::EISDIR).into());
        }
        let _leases = self.acquire_namespace_leases(&destination, metadata.is_dir())?;
        Self::remove_existing(&destination)?;
        self.metadata
            .set_with_attributes(path, EntryState::Whiteout, None)
    }

    fn directory_is_empty_locked(&self, path: &Path) -> Result<bool> {
        let hidden = self
            .metadata
            .entries(path)?
            .into_iter()
            .filter_map(|(name, state)| matches!(state, EntryState::Whiteout).then_some(name))
            .collect::<BTreeSet<_>>();
        let upper = self.destination(path)?;
        if upper.is_dir() {
            let aliases = self
                .metadata
                .backing_names(path)?
                .into_iter()
                .map(|(logical, backing)| (backing, logical))
                .collect::<HashMap<_, _>>();
            for entry in fs::read_dir(&upper)? {
                let name = entry?.file_name();
                let logical = aliases.get(&name);
                if logical.is_some_and(|logical| !hidden.contains(logical))
                    || (logical.is_none()
                        && !namespace::is_control_name(&name)
                        && !hidden.contains(&name))
                {
                    return Ok(false);
                }
            }
        }
        let cow = self.cow_ancestor_locked(path)?
            || matches!(self.metadata.state(path)?, Some(EntryState::Cow));
        if !cow && path.is_dir() {
            for entry in fs::read_dir(path)? {
                if !hidden.contains(&entry?.file_name()) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn rename_locked(&self, from: &Path, to: &Path) -> Result<()> {
        if from == to {
            return self
                .visible_exists_locked(from)?
                .then_some(())
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT).into());
        }
        let from_visible = self.prepare_read_locked(from)?;
        let from_visible_metadata = from_visible.symlink_metadata()?;
        if from_visible_metadata.is_dir() && to.starts_with(from) {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL).into());
        }
        let mut namespace_leases = Vec::new();
        if self.visible_exists_locked(to)? {
            let to_visible = self.prepare_read_locked(to)?;
            let to_metadata = to_visible.symlink_metadata()?;
            if from_visible_metadata.is_dir() && !to_metadata.is_dir() {
                return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR).into());
            }
            if !from_visible_metadata.is_dir() && to_metadata.is_dir() {
                return Err(std::io::Error::from_raw_os_error(libc::EISDIR).into());
            }
            if to_metadata.is_dir() && !self.directory_is_empty_locked(to)? {
                return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY).into());
            }
            namespace_leases
                .extend(self.acquire_namespace_leases(&to_visible, to_metadata.is_dir())?);
        }
        if !self.is_internal(&from_visible) && from_visible_metadata.is_dir() {
            self.validate_materializable_tree_locked(from)?;
        }
        let from_destination = if self.is_internal(&from_visible) {
            from_visible
        } else if from_visible_metadata.is_dir() {
            self.materialize_tree_locked(from)?;
            self.destination(from)?
        } else if from_visible_metadata.is_file() {
            self.materialize_file_locked(from, Materializer::Copy)?
        } else if from_visible_metadata.file_type().is_symlink() {
            self.materialize_symlink_locked(from)?
        } else {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP).into());
        };
        namespace_leases.extend(
            self.acquire_namespace_leases(&from_destination, from_visible_metadata.is_dir())?,
        );
        self.ensure_parent_locked(to)?;
        let to_destination = if from_visible_metadata.is_dir() {
            self.plain_destination(to)?
        } else {
            self.file_destination(to, true)?
        };
        Self::remove_existing(&to_destination)?;
        fs::rename(&from_destination, &to_destination)?;
        let attributes = self.metadata.attributes(from)?;
        self.metadata
            .set_with_attributes(from, EntryState::Whiteout, None)?;
        self.metadata
            .set_with_attributes(to, EntryState::Cow, attributes)
    }

    fn materialize_tree_locked(&self, source: &Path) -> Result<()> {
        let destination = self.plain_destination(source)?;
        fs::create_dir_all(&destination)?;
        let source_metadata = source.symlink_metadata()?;
        Self::secure_backing_directory(&destination, source_metadata.mode())?;
        self.metadata
            .set_attributes(source, FileAttributes::from_metadata(&source_metadata))?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let path = entry.path();
            if matches!(self.metadata.state(&path)?, Some(EntryState::Whiteout)) {
                continue;
            }
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                self.materialize_tree_locked(&path)?;
            } else if file_type.is_symlink() {
                if !self.destination(&path)?.exists() {
                    self.materialize_symlink_locked(&path)?;
                }
            } else if !self.destination(&path)?.exists() {
                self.materialize_file_locked(&path, Materializer::Copy)?;
            }
        }
        Ok(())
    }

    fn validate_materializable_tree_locked(&self, source: &Path) -> Result<()> {
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let path = entry.path();
            if matches!(self.metadata.state(&path)?, Some(EntryState::Whiteout)) {
                continue;
            }
            let file_type = entry.file_type()?;
            if file_type.is_dir() {
                self.validate_materializable_tree_locked(&path)?;
            } else if !file_type.is_file() && !file_type.is_symlink() {
                return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP).into());
            }
        }
        Ok(())
    }

    fn materialize_symlink_locked(&self, source: &Path) -> Result<PathBuf> {
        use std::os::unix::fs::symlink;

        let destination = self.destination(source)?;
        let parent = destination
            .parent()
            .context("filesystem symlink destination has no parent")?;
        fs::create_dir_all(parent)?;
        Self::remove_existing(&destination)?;
        symlink(fs::read_link(source)?, &destination)?;
        let attributes = FileAttributes::from_metadata(&source.symlink_metadata()?);
        self.metadata
            .set_with_attributes(source, EntryState::Cow, Some(attributes))?;
        Ok(destination)
    }

    fn ensure_parent_locked(&self, path: &Path) -> Result<()> {
        let parent = path.parent().context("filesystem path has no parent")?;
        if parent == Path::new("/") {
            return Ok(());
        }
        self.ensure_directory_locked(parent).map(|_| ())
    }

    fn visible_exists_locked(&self, path: &Path) -> Result<bool> {
        match self.metadata.state(path)? {
            Some(EntryState::Whiteout) => Ok(false),
            Some(EntryState::Cow) => Ok(self.destination(path)?.symlink_metadata().is_ok()),
            Some(EntryState::Cached { .. }) => Ok(path.symlink_metadata().is_ok()),
            None if self.cow_ancestor_locked(path)? => {
                Ok(self.destination(path)?.symlink_metadata().is_ok())
            }
            None => Ok(path.symlink_metadata().is_ok()),
        }
    }

    fn cow_ancestor_locked(&self, path: &Path) -> Result<bool> {
        let mut current = path.parent();
        while let Some(parent) = current {
            if parent == Path::new("/") {
                break;
            }
            if matches!(self.metadata.state(parent)?, Some(EntryState::Cow)) {
                return Ok(true);
            }
            current = parent.parent();
        }
        Ok(false)
    }

    fn destination(&self, path: &Path) -> Result<PathBuf> {
        if self.cipher.is_none() || path == Path::new("/") {
            return self.plain_destination(path);
        }
        match self.metadata.backing_name(path)? {
            Some(name) => {
                let parent = path.parent().context("filesystem path has no parent")?;
                Ok(namespace::backing_path(&self.root, parent)?.join(name))
            }
            None => self.plain_destination(path),
        }
    }

    fn file_destination(&self, path: &Path, create: bool) -> Result<PathBuf> {
        if self.cipher.is_none() {
            return self.plain_destination(path);
        }
        let parent = path.parent().context("filesystem path has no parent")?;
        let name = if create {
            self.metadata.ensure_backing_name(path)?
        } else {
            self.metadata
                .backing_name(path)?
                .ok_or_else(|| std::io::Error::from_raw_os_error(libc::ENOENT))?
        };
        Ok(namespace::backing_path(&self.root, parent)?.join(name))
    }

    fn plain_destination(&self, path: &Path) -> Result<PathBuf> {
        namespace::backing_path(&self.root, path)
    }

    fn normalize(&self, path: &Path) -> Result<PathBuf> {
        namespace::normalize(path)
    }

    fn resolve_existing_ancestor(path: &Path) -> Result<PathBuf> {
        let mut existing = path.to_path_buf();
        let mut suffix = Vec::new();
        loop {
            match existing.canonicalize() {
                Ok(mut resolved) => {
                    for component in suffix.iter().rev() {
                        resolved.push(component);
                    }
                    return Ok(resolved);
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory
                    ) =>
                {
                    let name = existing.file_name().with_context(|| {
                        format!("failed to resolve filesystem path {}", path.display())
                    })?;
                    suffix.push(name.to_os_string());
                    existing.pop();
                }
                Err(error) => {
                    return Err(error).with_context(|| {
                        format!("failed to resolve filesystem path {}", path.display())
                    });
                }
            }
        }
    }

    fn remove_existing(path: &Path) -> Result<()> {
        match path.symlink_metadata() {
            Ok(metadata) if metadata.is_dir() => fs::remove_dir_all(path)?,
            Ok(_) => fs::remove_file(path)?,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        Ok(())
    }

    fn secure_backing_directory(path: &Path, logical_mode: u32) -> Result<()> {
        fs::set_permissions(
            path,
            fs::Permissions::from_mode((logical_mode & 0o7777) | 0o700),
        )?;
        Ok(())
    }

    fn write_lease_path(destination: &Path) -> Result<PathBuf> {
        let name = destination
            .file_name()
            .context("encrypted filesystem destination has no file name")?;
        let mut lease = namespace::WRITE_LEASE_PREFIX.to_vec();
        lease.extend_from_slice(name.as_bytes());
        Ok(destination.with_file_name(OsString::from_vec(lease)))
    }

    fn acquire_write_lease(
        &self,
        destination: &Path,
        operation: libc::c_int,
    ) -> Result<Option<File>> {
        if self.cipher.is_none() || !self.is_internal(destination) {
            return Ok(None);
        }
        let path = Self::write_lease_path(destination)?;
        let lease = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("failed to open write lease {}", path.display()))?;
        if let Err(error) = Self::flock(&lease, operation) {
            if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                return Err(std::io::Error::from_raw_os_error(libc::EBUSY).into());
            }
            return Err(error)
                .with_context(|| format!("failed to acquire write lease {}", path.display()));
        }
        Ok(Some(lease))
    }

    fn acquire_namespace_leases(&self, destination: &Path, directory: bool) -> Result<Vec<File>> {
        if self.cipher.is_none() || !self.is_internal(destination) {
            return Ok(Vec::new());
        }
        if !directory {
            return self
                .acquire_write_lease(destination, libc::LOCK_EX | libc::LOCK_NB)
                .map(|lease| lease.into_iter().collect());
        }
        let mut pending = vec![destination.to_path_buf()];
        let mut leases = Vec::new();
        while let Some(current) = pending.pop() {
            for entry in fs::read_dir(current)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    pending.push(entry.path());
                    continue;
                }
                if !entry
                    .file_name()
                    .as_bytes()
                    .starts_with(namespace::WRITE_LEASE_PREFIX)
                {
                    continue;
                }
                let lease = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(entry.path())?;
                if let Err(error) = Self::flock(&lease, libc::LOCK_EX | libc::LOCK_NB) {
                    if error.raw_os_error() == Some(libc::EWOULDBLOCK) {
                        return Err(std::io::Error::from_raw_os_error(libc::EBUSY).into());
                    }
                    return Err(error.into());
                }
                leases.push(lease);
            }
        }
        Ok(leases)
    }

    fn with_lock<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.lock_path)
            .with_context(|| format!("failed to open overlay lock {}", self.lock_path.display()))?;
        Self::flock(&lock, libc::LOCK_EX)?;
        let result = operation();
        let unlock = Self::flock(&lock, libc::LOCK_UN);
        drop(lock);
        match result {
            Ok(value) => {
                unlock?;
                Ok(value)
            }
            Err(error) => {
                let _ = unlock;
                Err(error)
            }
        }
    }

    fn flock(file: &File, operation: libc::c_int) -> std::io::Result<()> {
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn hex_digest(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }

    fn not_found<T>(path: &Path) -> Result<T> {
        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("filesystem path is not visible: {}", path.display()),
        )
        .into())
    }

    fn is_not_found(error: &anyhow::Error) -> bool {
        error
            .downcast_ref::<std::io::Error>()
            .is_some_and(|error| error.kind() == std::io::ErrorKind::NotFound)
    }
}

#[cfg(test)]
mod tests;
