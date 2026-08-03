use super::namespace::{self, METADATA_FILE};
use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use uuid::Uuid;

const METADATA_VERSION: u32 = 1;
const METADATA_CACHE_CAPACITY: usize = 1024;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Materializer {
    Copy,
    Executable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub(crate) enum EntryState {
    Cached {
        checksum: String,
        materializer: Materializer,
    },
    Cow,
    Whiteout,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub(crate) struct FileAttributes {
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) atime: i64,
    pub(crate) atime_nsec: i64,
    pub(crate) mtime: i64,
    pub(crate) mtime_nsec: i64,
}

impl FileAttributes {
    pub(crate) fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            mode: metadata.mode(),
            uid: metadata.uid(),
            gid: metadata.gid(),
            atime: metadata.atime(),
            atime_nsec: metadata.atime_nsec(),
            mtime: metadata.mtime(),
            mtime_nsec: metadata.mtime_nsec(),
        }
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn from_stat(status: &libc::stat) -> Self {
        Self {
            mode: u32::from(status.st_mode),
            uid: status.st_uid,
            gid: status.st_gid,
            atime: status.st_atime,
            atime_nsec: status.st_atime_nsec,
            mtime: status.st_mtime,
            mtime_nsec: status.st_mtime_nsec,
        }
    }

    pub(crate) fn created_file(mode: u32) -> Self {
        Self::created(u32::from(libc::S_IFREG), mode)
    }

    pub(crate) fn created_directory(mode: u32) -> Self {
        Self::created(u32::from(libc::S_IFDIR), mode)
    }

    #[cfg(target_os = "macos")]
    pub(crate) fn refresh_timestamps(&mut self, status: &libc::stat) {
        self.atime = status.st_atime;
        self.atime_nsec = status.st_atime_nsec;
        self.mtime = status.st_mtime;
        self.mtime_nsec = status.st_mtime_nsec;
    }

    fn created(kind: u32, mode: u32) -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        Self {
            mode: kind | mode & 0o7777,
            uid: unsafe { libc::geteuid() },
            gid: unsafe { libc::getegid() },
            atime: i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
            atime_nsec: i64::from(now.subsec_nanos()),
            mtime: i64::try_from(now.as_secs()).unwrap_or(i64::MAX),
            mtime_nsec: i64::from(now.subsec_nanos()),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct DirectoryMetadata {
    version: u32,
    entries: BTreeMap<String, EntryState>,
    #[serde(default)]
    attributes: BTreeMap<String, FileAttributes>,
    #[serde(default)]
    backing_names: BTreeMap<String, String>,
}

impl Default for DirectoryMetadata {
    fn default() -> Self {
        Self {
            version: METADATA_VERSION,
            entries: BTreeMap::new(),
            attributes: BTreeMap::new(),
            backing_names: BTreeMap::new(),
        }
    }
}

pub(super) struct MetadataStore {
    root: PathBuf,
    cache: Mutex<HashMap<PathBuf, CachedDirectoryMetadata>>,
    #[cfg(test)]
    parse_count: AtomicUsize,
}

#[derive(Clone)]
struct CachedDirectoryMetadata {
    identity: MetadataIdentity,
    metadata: DirectoryMetadata,
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct MetadataIdentity {
    device: u64,
    inode: u64,
    size: u64,
    modified: i64,
    modified_nsec: i64,
}

impl MetadataIdentity {
    fn from_metadata(metadata: &fs::Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.size(),
            modified: metadata.mtime(),
            modified_nsec: metadata.mtime_nsec(),
        }
    }
}

impl MetadataStore {
    pub(super) fn new(root: &Path) -> Result<Self> {
        fs::create_dir_all(root).with_context(|| {
            format!(
                "failed to create sandbox filesystem root {}",
                root.display()
            )
        })?;
        Ok(Self {
            root: root.to_path_buf(),
            cache: Mutex::new(HashMap::new()),
            #[cfg(test)]
            parse_count: AtomicUsize::new(0),
        })
    }

    pub(super) fn state(&self, path: &Path) -> Result<Option<EntryState>> {
        if path == Path::new("/") {
            return Ok(None);
        }
        let (parent, name) = Self::split(path)?;
        Ok(self.load(parent)?.entries.get(&Self::encode(name)).cloned())
    }

    pub(super) fn set(&self, path: &Path, state: EntryState) -> Result<()> {
        let (parent, name) = Self::split(path)?;
        let mut metadata = self.load(parent)?;
        let name = Self::encode(name);
        metadata.entries.insert(name.clone(), state.clone());
        if matches!(state, EntryState::Whiteout) {
            metadata.backing_names.remove(&name);
        }
        self.write(parent, &metadata)
    }

    pub(super) fn set_with_attributes(
        &self,
        path: &Path,
        state: EntryState,
        attributes: Option<FileAttributes>,
    ) -> Result<()> {
        let (parent, name) = Self::split(path)?;
        let mut metadata = self.load(parent)?;
        let name = Self::encode(name);
        metadata.entries.insert(name.clone(), state);
        if matches!(metadata.entries.get(&name), Some(EntryState::Whiteout)) {
            metadata.backing_names.remove(&name);
        }
        match attributes {
            Some(attributes) => {
                metadata.attributes.insert(name, attributes);
            }
            None => {
                metadata.attributes.remove(&name);
            }
        }
        self.write(parent, &metadata)
    }

    pub(super) fn attributes(&self, path: &Path) -> Result<Option<FileAttributes>> {
        if path == Path::new("/") {
            return Ok(None);
        }
        let (parent, name) = Self::split(path)?;
        Ok(self
            .load(parent)?
            .attributes
            .get(&Self::encode(name))
            .cloned())
    }

    pub(super) fn set_attributes(&self, path: &Path, attributes: FileAttributes) -> Result<()> {
        if path == Path::new("/") {
            return Ok(());
        }
        let (parent, name) = Self::split(path)?;
        let mut metadata = self.load(parent)?;
        let name = Self::encode(name);
        if metadata.attributes.get(&name) == Some(&attributes) {
            return Ok(());
        }
        metadata.attributes.insert(name, attributes);
        self.write(parent, &metadata)
    }

    pub(super) fn remove(&self, path: &Path) -> Result<()> {
        if path == Path::new("/") {
            return Ok(());
        }
        let (parent, name) = Self::split(path)?;
        let mut metadata = self.load(parent)?;
        let name = Self::encode(name);
        metadata.entries.remove(&name);
        metadata.attributes.remove(&name);
        metadata.backing_names.remove(&name);
        self.write(parent, &metadata)
    }

    pub(super) fn entries(&self, directory: &Path) -> Result<Vec<(OsString, EntryState)>> {
        self.load(directory)?
            .entries
            .into_iter()
            .map(|(name, state)| Ok((Self::decode(&name)?, state)))
            .collect()
    }

    pub(super) fn backing_name(&self, path: &Path) -> Result<Option<OsString>> {
        let (parent, name) = Self::split(path)?;
        Ok(self
            .load(parent)?
            .backing_names
            .get(&Self::encode(name))
            .map(OsString::from))
    }

    pub(super) fn ensure_backing_name(&self, path: &Path) -> Result<OsString> {
        let (parent, name) = Self::split(path)?;
        let mut metadata = self.load(parent)?;
        let name = Self::encode(name);
        if let Some(backing) = metadata.backing_names.get(&name) {
            return Ok(OsString::from(backing));
        }
        let backing = Uuid::new_v4().simple().to_string();
        metadata.backing_names.insert(name, backing.clone());
        self.write(parent, &metadata)?;
        Ok(OsString::from(backing))
    }

    pub(super) fn backing_names(&self, directory: &Path) -> Result<Vec<(OsString, OsString)>> {
        self.load(directory)?
            .backing_names
            .into_iter()
            .map(|(logical, backing)| Ok((Self::decode(&logical)?, OsString::from(backing))))
            .collect()
    }

    fn split(path: &Path) -> Result<(&Path, &OsStr)> {
        if !path.is_absolute() {
            bail!(
                "filesystem metadata path is not absolute: {}",
                path.display()
            );
        }
        let parent = path
            .parent()
            .context("filesystem metadata path has no parent")?;
        let name = path
            .file_name()
            .context("filesystem metadata path has no file name")?;
        Ok((parent, name))
    }

    fn load(&self, directory: &Path) -> Result<DirectoryMetadata> {
        let path = self.path(directory)?;
        let mut file = match File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                self.cache().remove(&path);
                return Ok(DirectoryMetadata::default());
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to read filesystem metadata {}", path.display())
                });
            }
        };
        let identity = MetadataIdentity::from_metadata(&file.metadata()?);
        if let Some(cached) = self.cache().get(&path)
            && cached.identity == identity
        {
            return Ok(cached.metadata.clone());
        }

        let mut contents = Vec::with_capacity(usize::try_from(identity.size).unwrap_or(0));
        file.read_to_end(&mut contents)
            .with_context(|| format!("failed to read filesystem metadata {}", path.display()))?;
        let metadata: DirectoryMetadata = serde_json::from_slice(&contents)
            .with_context(|| format!("failed to parse filesystem metadata {}", path.display()))?;
        #[cfg(test)]
        self.parse_count.fetch_add(1, Ordering::Relaxed);
        if metadata.version != METADATA_VERSION {
            bail!(
                "unsupported filesystem metadata version {} in {}",
                metadata.version,
                path.display()
            );
        }
        let mut backing_names = HashSet::new();
        for backing in metadata.backing_names.values() {
            if !namespace::is_file_backing_name(backing.as_bytes())
                || !backing_names.insert(backing)
            {
                bail!(
                    "invalid filesystem backing name {backing:?} in {}",
                    path.display()
                );
            }
        }
        let mut cache = self.cache();
        if cache.len() >= METADATA_CACHE_CAPACITY && !cache.contains_key(&path) {
            cache.clear();
        }
        cache.insert(
            path,
            CachedDirectoryMetadata {
                identity,
                metadata: metadata.clone(),
            },
        );
        Ok(metadata)
    }

    fn write(&self, directory: &Path, metadata: &DirectoryMetadata) -> Result<()> {
        let path = self.path(directory)?;
        let parent = path.parent().context("metadata path has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!("{METADATA_FILE}.{}.tmp", Uuid::new_v4().simple()));
        let contents = serde_json::to_vec_pretty(metadata)
            .context("failed to serialize filesystem metadata")?;
        let result = (|| {
            let mut file = File::create(&temporary).with_context(|| {
                format!(
                    "failed to create filesystem metadata {}",
                    temporary.display()
                )
            })?;
            file.write_all(&contents).with_context(|| {
                format!(
                    "failed to write filesystem metadata {}",
                    temporary.display()
                )
            })?;
            file.sync_all().with_context(|| {
                format!("failed to sync filesystem metadata {}", temporary.display())
            })?;
            fs::rename(&temporary, &path).with_context(|| {
                format!("failed to publish filesystem metadata {}", path.display())
            })?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .with_context(|| {
                    format!(
                        "failed to sync filesystem metadata directory {}",
                        parent.display()
                    )
                })
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        self.cache().remove(&path);
        result
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<PathBuf, CachedDirectoryMetadata>> {
        self.cache.lock().unwrap_or_else(|error| error.into_inner())
    }

    fn path(&self, directory: &Path) -> Result<PathBuf> {
        if !directory.is_absolute() {
            bail!(
                "filesystem metadata directory is not absolute: {}",
                directory.display()
            );
        }
        Ok(namespace::backing_path(&self.root, directory)?.join(METADATA_FILE))
    }

    fn encode(value: &OsStr) -> String {
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes())
    }

    fn decode(value: &str) -> Result<OsString> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(value)
            .context("invalid encoded filesystem metadata name")?;
        Ok(OsString::from_vec(bytes))
    }

    #[cfg(test)]
    fn parse_count(&self) -> usize {
        self.parse_count.load(Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests;
