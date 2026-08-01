use anyhow::{Context, Result, bail};
use base64::Engine;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub(super) const CONTROL_DIRECTORY: &str = ".agora";
const METADATA_DIRECTORY: &str = "metadata";
const METADATA_FILE: &str = "metadata.json";
const METADATA_VERSION: u32 = 1;

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

#[derive(Debug, Deserialize, Serialize)]
pub(super) struct DirectoryMetadata {
    version: u32,
    entries: BTreeMap<String, EntryState>,
}

impl Default for DirectoryMetadata {
    fn default() -> Self {
        Self {
            version: METADATA_VERSION,
            entries: BTreeMap::new(),
        }
    }
}

pub(super) struct MetadataStore {
    directory: PathBuf,
}

impl MetadataStore {
    pub(super) fn new(root: &Path) -> Result<Self> {
        let directory = root.join(CONTROL_DIRECTORY).join(METADATA_DIRECTORY);
        fs::create_dir_all(&directory).with_context(|| {
            format!(
                "failed to create sandbox filesystem metadata directory {}",
                directory.display()
            )
        })?;
        Ok(Self { directory })
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
        metadata.entries.insert(Self::encode(name), state);
        self.write(parent, &metadata)
    }

    pub(super) fn remove(&self, path: &Path) -> Result<()> {
        if path == Path::new("/") {
            return Ok(());
        }
        let (parent, name) = Self::split(path)?;
        let mut metadata = self.load(parent)?;
        metadata.entries.remove(&Self::encode(name));
        self.write(parent, &metadata)
    }

    pub(super) fn entries(&self, directory: &Path) -> Result<Vec<(OsString, EntryState)>> {
        self.load(directory)?
            .entries
            .into_iter()
            .map(|(name, state)| Ok((Self::decode(&name)?, state)))
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
        let contents = match fs::read(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(DirectoryMetadata::default());
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!("failed to read filesystem metadata {}", path.display())
                });
            }
        };
        let metadata: DirectoryMetadata = serde_json::from_slice(&contents)
            .with_context(|| format!("failed to parse filesystem metadata {}", path.display()))?;
        if metadata.version != METADATA_VERSION {
            bail!(
                "unsupported filesystem metadata version {} in {}",
                metadata.version,
                path.display()
            );
        }
        Ok(metadata)
    }

    fn write(&self, directory: &Path, metadata: &DirectoryMetadata) -> Result<()> {
        let path = self.path(directory)?;
        let parent = path.parent().context("metadata path has no parent")?;
        fs::create_dir_all(parent)?;
        let temporary = parent.join(format!(".{METADATA_FILE}.{}.tmp", Uuid::new_v4().simple()));
        let contents = serde_json::to_vec_pretty(metadata)
            .context("failed to serialize filesystem metadata")?;
        let result = (|| {
            fs::write(&temporary, contents).with_context(|| {
                format!(
                    "failed to write filesystem metadata {}",
                    temporary.display()
                )
            })?;
            fs::rename(&temporary, &path).with_context(|| {
                format!("failed to publish filesystem metadata {}", path.display())
            })
        })();
        if result.is_err() {
            let _ = fs::remove_file(temporary);
        }
        result
    }

    fn path(&self, directory: &Path) -> Result<PathBuf> {
        if !directory.is_absolute() {
            bail!(
                "filesystem metadata directory is not absolute: {}",
                directory.display()
            );
        }
        Ok(self
            .directory
            .join(Self::encode(directory.as_os_str()))
            .join(METADATA_FILE))
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
}

#[cfg(test)]
mod tests;
