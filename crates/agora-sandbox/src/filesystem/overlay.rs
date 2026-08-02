use super::metadata::{CONTROL_DIRECTORY, EntryState, Materializer, MetadataStore};
use anyhow::{Context, Result, bail};
use md5::{Digest, Md5};
use std::collections::BTreeSet;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

const OVERLAY_LOCK_FILE: &str = "overlay.lock";

pub(crate) struct OverlayStore {
    root: PathBuf,
    canonical_root: PathBuf,
    metadata: MetadataStore,
    lock: File,
}

pub(crate) struct DirectoryView {
    upper: PathBuf,
    lower: Option<PathBuf>,
    hidden: BTreeSet<OsString>,
}

pub(crate) struct StagedWrite {
    logical: PathBuf,
    destination: PathBuf,
}

impl StagedWrite {
    pub(crate) fn destination(&self) -> &Path {
        &self.destination
    }
}

impl DirectoryView {
    pub(crate) fn upper(&self) -> &Path {
        &self.upper
    }

    pub(crate) fn lower(&self) -> Option<&Path> {
        self.lower.as_deref()
    }

    pub(crate) fn hidden(&self) -> &BTreeSet<OsString> {
        &self.hidden
    }
}

impl OverlayStore {
    pub(crate) fn new(root: impl Into<PathBuf>) -> Result<Self> {
        let root = root.into();
        fs::create_dir_all(&root)
            .with_context(|| format!("failed to create filesystem root {}", root.display()))?;
        let canonical_root = root
            .canonicalize()
            .with_context(|| format!("failed to resolve filesystem root {}", root.display()))?;
        let metadata = MetadataStore::new(&canonical_root)?;
        let lock_path = canonical_root
            .join(CONTROL_DIRECTORY)
            .join(OVERLAY_LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&lock_path)
            .with_context(|| format!("failed to open overlay lock {}", lock_path.display()))?;
        Ok(Self {
            root,
            canonical_root,
            metadata,
            lock,
        })
    }

    #[cfg(test)]
    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn is_internal(&self, path: &Path) -> bool {
        path.starts_with(&self.root) || path.starts_with(&self.canonical_root)
    }

    pub(crate) fn logical_path(&self, path: &Path) -> Result<PathBuf> {
        let relative = path
            .strip_prefix(&self.root)
            .or_else(|_| path.strip_prefix(&self.canonical_root))
            .with_context(|| format!("path is not inside filesystem root: {}", path.display()))?;
        Ok(Path::new("/").join(relative))
    }

    pub(crate) fn prepare_read(&self, path: &Path) -> Result<PathBuf> {
        let path = self.normalize(path)?;
        if self.is_internal(&path) {
            return Ok(path);
        }
        self.with_lock(|| self.prepare_read_locked(&path))
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
            });
        }
        let destination = self.with_lock(|| self.stage_write_locked(&path, create))?;
        Ok(StagedWrite {
            logical: path,
            destination,
        })
    }

    pub(crate) fn commit_write(&self, staged: StagedWrite) -> Result<()> {
        if self.is_internal(&staged.logical) {
            return Ok(());
        }
        self.with_lock(|| self.metadata.set(&staged.logical, EntryState::Cow))
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
            let destination = self.destination(&path)?;
            if self.visible_exists_locked(&path)? {
                return Err(std::io::Error::from_raw_os_error(libc::EEXIST).into());
            }
            self.ensure_parent_locked(&path)?;
            fs::create_dir(&destination)?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(mode))?;
            self.metadata.set(&path, EntryState::Cow)?;
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
            let destination = self.destination(&source)?;
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
            Some(EntryState::Cached {
                checksum,
                materializer,
            }) => {
                if !path.exists() {
                    Self::remove_existing(&destination)?;
                    self.metadata.remove(path)?;
                    return Self::not_found(path);
                }
                if destination.exists() && Self::checksum(path).is_ok_and(|value| value == checksum)
                {
                    return Ok(destination);
                }
                self.materialize_file_locked(path, materializer)
            }
            None => self.materialize_locked(path),
        }
    }

    fn visible_path_locked(&self, path: &Path) -> Result<PathBuf> {
        let destination = self.destination(path)?;
        match self.metadata.state(path)? {
            Some(EntryState::Whiteout) => Self::not_found(path),
            Some(EntryState::Cow) => destination
                .symlink_metadata()
                .map(|_| destination)
                .map_err(Into::into),
            Some(EntryState::Cached { .. }) if destination.exists() => Ok(destination),
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
                    Some(EntryState::Cached { .. }) => {
                        let destination = self.destination(&canonical)?;
                        if destination.exists() {
                            Ok(destination)
                        } else {
                            Ok(canonical)
                        }
                    }
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
        let destination = self.destination(path)?;
        if self.cow_ancestor_locked(path)? {
            if !destination.exists() && !create {
                return Self::not_found(path);
            }
            self.ensure_parent_locked(path)?;
            return Ok(destination);
        }
        match self.metadata.state(path)? {
            Some(EntryState::Cow) => {
                if !destination.exists() && !create {
                    return Self::not_found(path);
                }
            }
            Some(EntryState::Whiteout) if !create => return Self::not_found(path),
            Some(EntryState::Whiteout) => self.ensure_parent_locked(path)?,
            Some(EntryState::Cached { .. }) => {}
            None if path.exists() => {
                let metadata = path.metadata()?;
                if !metadata.is_file() {
                    return Ok(path.to_path_buf());
                }
                self.materialize_file_locked(path, Materializer::Copy)?;
            }
            None if create => self.ensure_parent_locked(path)?,
            None => return Self::not_found(path),
        }
        Ok(destination)
    }

    fn prepare_directory_locked(&self, path: &Path) -> Result<PathBuf> {
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
            fs::set_permissions(
                &destination,
                fs::Permissions::from_mode(path.metadata()?.mode()),
            )?;
        }
        Ok(destination)
    }

    fn directory_view_locked(&self, path: &Path) -> Result<DirectoryView> {
        let upper = self.prepare_directory_locked(path)?;
        let cow = self.cow_ancestor_locked(path)?
            || matches!(self.metadata.state(path)?, Some(EntryState::Cow));
        let lower = (!cow && path.is_dir()).then(|| path.to_path_buf());
        let mut hidden = self
            .metadata
            .entries(path)?
            .into_iter()
            .filter_map(|(name, state)| matches!(state, EntryState::Whiteout).then_some(name))
            .collect::<BTreeSet<_>>();
        if path == Path::new("/") {
            hidden.insert(OsString::from(CONTROL_DIRECTORY));
        }
        Ok(DirectoryView {
            upper,
            lower,
            hidden,
        })
    }

    fn materialize_locked(&self, path: &Path) -> Result<PathBuf> {
        let metadata = path.metadata().map_err(|error| {
            anyhow::Error::new(error).context(format!("failed to inspect {}", path.display()))
        })?;
        if metadata.is_dir() {
            let destination = self.destination(path)?;
            fs::create_dir_all(&destination)?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(metadata.mode()))?;
            return Ok(destination);
        }
        if metadata.is_file() {
            return self.materialize_file_locked(path, Materializer::Copy);
        }
        Ok(path.to_path_buf())
    }

    fn materialize_file_locked(
        &self,
        source: &Path,
        materializer: Materializer,
    ) -> Result<PathBuf> {
        let destination = self.destination(source)?;
        let parent = destination
            .parent()
            .context("filesystem destination has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".agora-copy-{}.tmp", Uuid::new_v4().simple()));
        let result = (|| {
            let mut input = File::open(source)?;
            let source_metadata = input.metadata()?;
            let mut output = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)?;
            let mut digest = Md5::new();
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
            fs::set_permissions(
                &temporary,
                fs::Permissions::from_mode(source_metadata.mode()),
            )?;
            Self::remove_existing(&destination)?;
            fs::rename(&temporary, &destination)?;
            self.metadata.set(
                source,
                EntryState::Cached {
                    checksum: Self::hex_digest(digest.finalize().as_slice()),
                    materializer,
                },
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
        Self::remove_existing(&destination)?;
        self.metadata.set(path, EntryState::Whiteout)
    }

    fn directory_is_empty_locked(&self, path: &Path) -> Result<bool> {
        let view = self.directory_view_locked(path)?;
        for entry in fs::read_dir(&view.upper)? {
            let name = entry?.file_name();
            if !view.hidden.contains(&name) {
                return Ok(false);
            }
        }
        if let Some(lower) = view.lower {
            for entry in fs::read_dir(lower)? {
                if !view.hidden.contains(&entry?.file_name()) {
                    return Ok(false);
                }
            }
        }
        Ok(true)
    }

    fn rename_locked(&self, from: &Path, to: &Path) -> Result<()> {
        let from_destination = self.prepare_read_locked(from)?;
        if from == to {
            return Ok(());
        }
        let from_metadata = from_destination.symlink_metadata()?;
        if from_metadata.is_dir() && to.starts_with(from) {
            return Err(std::io::Error::from_raw_os_error(libc::EINVAL).into());
        }
        if self.visible_exists_locked(to)? {
            let to_visible = self.prepare_read_locked(to)?;
            let to_metadata = to_visible.symlink_metadata()?;
            if from_metadata.is_dir() && !to_metadata.is_dir() {
                return Err(std::io::Error::from_raw_os_error(libc::ENOTDIR).into());
            }
            if !from_metadata.is_dir() && to_metadata.is_dir() {
                return Err(std::io::Error::from_raw_os_error(libc::EISDIR).into());
            }
            if to_metadata.is_dir() && !self.directory_is_empty_locked(to)? {
                return Err(std::io::Error::from_raw_os_error(libc::ENOTEMPTY).into());
            }
        }
        if from_metadata.is_dir() && !self.cow_ancestor_locked(from)? {
            self.materialize_tree_locked(from)?;
        }
        self.ensure_parent_locked(to)?;
        let to_destination = self.destination(to)?;
        Self::remove_existing(&to_destination)?;
        fs::rename(&from_destination, &to_destination)?;
        self.metadata.set(from, EntryState::Whiteout)?;
        self.metadata.set(to, EntryState::Cow)
    }

    fn materialize_tree_locked(&self, source: &Path) -> Result<()> {
        let destination = self.destination(source)?;
        fs::create_dir_all(&destination)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            let path = entry.path();
            if matches!(self.metadata.state(&path)?, Some(EntryState::Whiteout)) {
                continue;
            }
            if entry.file_type()?.is_dir() {
                self.materialize_tree_locked(&path)?;
            } else if !self.destination(&path)?.exists() {
                self.materialize_file_locked(&path, Materializer::Copy)?;
            }
        }
        Ok(())
    }

    fn ensure_parent_locked(&self, path: &Path) -> Result<()> {
        let parent = path.parent().context("filesystem path has no parent")?;
        if parent == Path::new("/") {
            return Ok(());
        }
        self.prepare_directory_locked(parent).map(|_| ())
    }

    fn visible_exists_locked(&self, path: &Path) -> Result<bool> {
        match self.metadata.state(path)? {
            Some(EntryState::Whiteout) => Ok(false),
            Some(EntryState::Cow | EntryState::Cached { .. }) => {
                Ok(self.destination(path)?.exists())
            }
            None if self.cow_ancestor_locked(path)? => Ok(self.destination(path)?.exists()),
            None => Ok(path.exists()),
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
        let relative = path
            .strip_prefix(Path::new("/"))
            .with_context(|| format!("filesystem path is not absolute: {}", path.display()))?;
        Ok(self.root.join(relative))
    }

    fn normalize(&self, path: &Path) -> Result<PathBuf> {
        if !path.is_absolute() {
            bail!("filesystem path is not absolute: {}", path.display());
        }
        let mut normalized = PathBuf::from("/");
        for component in path.components() {
            match component {
                Component::RootDir | Component::CurDir => {}
                Component::ParentDir => {
                    normalized.pop();
                }
                Component::Normal(value) => normalized.push(value),
                Component::Prefix(_) => bail!("unsupported filesystem path: {}", path.display()),
            }
        }
        if normalized
            .strip_prefix(Path::new("/"))?
            .components()
            .next()
            .is_some_and(|component| component.as_os_str() == CONTROL_DIRECTORY)
        {
            return Err(std::io::Error::from_raw_os_error(libc::EACCES).into());
        }
        Ok(normalized)
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

    fn with_lock<T>(&self, operation: impl FnOnce() -> Result<T>) -> Result<T> {
        Self::flock(&self.lock, libc::LOCK_EX)?;
        let result = operation();
        let unlock = Self::flock(&self.lock, libc::LOCK_UN);
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
}

#[cfg(test)]
mod tests;
