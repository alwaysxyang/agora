use super::crypto::FileCipher;
use super::metadata::{EntryState, MetadataStore};
use super::namespace;
use anyhow::{Context, Result, bail};
use base64::Engine;
use ring::rand::{SecureRandom, SystemRandom};
use serde::{Deserialize, Serialize};
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use uuid::Uuid;

const ROOT_DIRECTORY: &str = "fs";
const LOCK_FILE: &str = ".fs.lock";
const KEY_FILE: &str = ".key.json";
const VFS_LOCK_FILE: &str = ".vfs.lock";
const DIRECTORY_METADATA_FILE: &str = ".metadata";
const REKEY_JOURNAL_FILE: &str = ".rekey.json";
const KEY_METADATA_VERSION: u32 = 1;
const REKEY_JOURNAL_VERSION: u32 = 1;
const SALT_SIZE: usize = 16;
const MAX_KEY_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyMigrationStage {
    Validating,
    AcquiringLock,
    ReencryptingFiles,
    VerifyingNewKey,
    UpdatingMetadata,
    Completed,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
struct KeyMetadata {
    version: u32,
    salt: String,
    key_id: String,
}

#[derive(Debug, Deserialize, Serialize)]
struct RekeyJournal {
    version: u32,
    old_key: KeyMetadata,
    new_key: KeyMetadata,
    entries: Vec<RekeyEntry>,
}

#[derive(Debug, Deserialize, Serialize)]
struct RekeyEntry {
    destination: String,
    staged: String,
    backup: String,
}

pub(crate) struct EncryptedWorkspace {
    root: PathBuf,
    _lock: File,
    cipher: FileCipher,
    salt: Vec<u8>,
    key: Vec<u8>,
}

impl std::fmt::Debug for EncryptedWorkspace {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("EncryptedWorkspace")
            .field("root", &self.root)
            .field("cipher", &self.cipher)
            .field("salt", &self.salt)
            .field("key", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl EncryptedWorkspace {
    pub(crate) async fn start(workdir: &Path, passphrase: &[u8]) -> Result<Self> {
        Self::validate_passphrase(passphrase)?;
        let workdir = Self::resolved_destination(workdir)?;
        let root = workdir.join(ROOT_DIRECTORY);
        Self::prepare_directory(&root)?;
        let lock = Self::lock(&root)?;
        Self::recover_migration(&root)?;
        let metadata = if root.join(KEY_FILE).exists() {
            Self::read_key_metadata(&root)?
        } else {
            if Self::contains_unmanaged_data(&root)? {
                bail!(
                    "unencrypted filesystem data exists at {}; move or remove it before starting encrypted mode",
                    root.display()
                );
            }
            let metadata = Self::new_key_metadata(passphrase)?;
            Self::write_key_metadata(&root, &metadata)?;
            metadata
        };
        let salt = Self::decode_salt(&metadata)?;
        let cipher = FileCipher::derive(passphrase, &salt)?;
        if cipher.key_id() != metadata.key_id {
            bail!("sandbox filesystem key is incorrect");
        }
        Ok(Self {
            root,
            _lock: lock,
            cipher,
            salt,
            key: passphrase.to_vec(),
        })
    }

    pub(crate) fn root(&self) -> &Path {
        &self.root
    }

    pub(crate) fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub(crate) fn key(&self) -> &[u8] {
        &self.key
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        Ok(())
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
        let root = workdir.join(ROOT_DIRECTORY);
        if !root.join(KEY_FILE).is_file() {
            bail!(
                "encrypted filesystem key metadata does not exist: {}",
                root.join(KEY_FILE).display()
            );
        }
        let _lock = Self::lock(&root)?;
        Self::recover_migration(&root)?;
        let metadata = Self::read_key_metadata(&root)?;
        let old_salt = Self::decode_salt(&metadata)?;
        let old_cipher = FileCipher::derive(old_passphrase, &old_salt)?;
        if old_cipher.key_id() != metadata.key_id {
            bail!("sandbox filesystem key is incorrect");
        }
        let new_salt = Self::random_salt()?;
        let new_cipher = FileCipher::derive(new_passphrase, &new_salt)?;
        let new_metadata = KeyMetadata {
            version: KEY_METADATA_VERSION,
            salt: base64::engine::general_purpose::STANDARD.encode(&new_salt),
            key_id: new_cipher.key_id().to_string(),
        };

        on_progress(KeyMigrationStage::ReencryptingFiles);
        let sources = Self::encrypted_files(&root)?;
        let mut entries = Vec::with_capacity(sources.len());
        let prepared = (|| {
            for source in sources {
                let mut plaintext = tempfile::tempfile()
                    .context("failed to create anonymous filesystem migration file")?;
                old_cipher.decrypt(&source, &mut plaintext)?;
                let parent = source
                    .parent()
                    .context("encrypted filesystem file has no parent")?;
                let temporary =
                    parent.join(format!(".agora-rekey-{}.tmp", Uuid::new_v4().simple()));
                let backup = parent.join(format!(".agora-rekey-old-{}", Uuid::new_v4().simple()));
                new_cipher.encrypt(&mut plaintext, &temporary)?;
                entries.push((source, temporary, backup));
            }
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = prepared {
            for (_, temporary, _) in entries {
                let _ = fs::remove_file(temporary);
            }
            return Err(error);
        }

        on_progress(KeyMigrationStage::VerifyingNewKey);
        let verified = (|| {
            for (_, temporary, _) in &entries {
                let mut verified = tempfile::tempfile()
                    .context("failed to create anonymous filesystem verification file")?;
                new_cipher.decrypt(temporary, &mut verified)?;
            }
            Ok::<_, anyhow::Error>(())
        })();
        if let Err(error) = verified {
            for (_, staged, _) in entries {
                let _ = fs::remove_file(staged);
            }
            return Err(error);
        }

        let journal_entries = entries
            .iter()
            .map(|(destination, staged, backup)| {
                Ok(RekeyEntry {
                    destination: Self::encode_relative_path(&root, destination)?,
                    staged: Self::encode_relative_path(&root, staged)?,
                    backup: Self::encode_relative_path(&root, backup)?,
                })
            })
            .collect::<Result<Vec<_>>>();
        let journal_entries = match journal_entries {
            Ok(entries) => entries,
            Err(error) => {
                for (_, staged, _) in entries {
                    let _ = fs::remove_file(staged);
                }
                return Err(error);
            }
        };
        let journal = RekeyJournal {
            version: REKEY_JOURNAL_VERSION,
            old_key: metadata,
            new_key: new_metadata.clone(),
            entries: journal_entries,
        };
        if let Err(error) = Self::write_journal(&root, &journal) {
            for (_, staged, _) in entries {
                let _ = fs::remove_file(staged);
            }
            return Err(error);
        }
        let migration = (|| {
            for (destination, temporary, backup) in &entries {
                fs::rename(destination, backup).with_context(|| {
                    format!(
                        "failed to preserve encrypted file {}",
                        destination.display()
                    )
                })?;
                fs::rename(temporary, destination).with_context(|| {
                    format!(
                        "failed to publish re-encrypted filesystem file {}",
                        destination.display()
                    )
                })?;
            }
            on_progress(KeyMigrationStage::UpdatingMetadata);
            Self::write_key_metadata(&root, &new_metadata)?;
            Self::recover_migration(&root)
        })();
        if let Err(error) = migration {
            let recovery = Self::recover_migration(&root);
            return match recovery {
                Ok(()) => Err(error),
                Err(recovery) => Err(error.context(format!(
                    "filesystem key migration recovery also failed: {recovery:#}"
                ))),
            };
        }
        on_progress(KeyMigrationStage::Completed);
        Ok(())
    }

    pub(crate) fn validate_passphrase(passphrase: &[u8]) -> Result<()> {
        if passphrase.is_empty() {
            bail!("sandbox filesystem key is empty");
        }
        if passphrase.len() > MAX_KEY_SIZE {
            bail!("sandbox filesystem key exceeds {MAX_KEY_SIZE} bytes");
        }
        Ok(())
    }

    pub(crate) fn resolved_destination(workdir: &Path) -> Result<PathBuf> {
        if workdir.is_absolute() {
            Ok(workdir.to_path_buf())
        } else {
            Ok(std::env::current_dir()
                .context("failed to resolve current directory")?
                .join(workdir))
        }
    }

    fn prepare_directory(directory: &Path) -> Result<()> {
        fs::create_dir_all(directory).with_context(|| {
            format!(
                "failed to create encrypted filesystem root {}",
                directory.display()
            )
        })?;
        if !directory.is_dir() {
            bail!(
                "encrypted filesystem root is not a directory: {}",
                directory.display()
            );
        }
        fs::set_permissions(directory, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "failed to secure encrypted filesystem root {}",
                directory.display()
            )
        })
    }

    fn lock(root: &Path) -> Result<File> {
        let path = root.join(LOCK_FILE);
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("failed to open filesystem lock {}", path.display()))?;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("filesystem is already in use: {}", root.display()));
        }
        Ok(lock)
    }

    fn new_key_metadata(passphrase: &[u8]) -> Result<KeyMetadata> {
        let salt = Self::random_salt()?;
        let cipher = FileCipher::derive(passphrase, &salt)?;
        Ok(KeyMetadata {
            version: KEY_METADATA_VERSION,
            salt: base64::engine::general_purpose::STANDARD.encode(salt),
            key_id: cipher.key_id().to_string(),
        })
    }

    fn random_salt() -> Result<Vec<u8>> {
        let mut salt = vec![0_u8; SALT_SIZE];
        SystemRandom::new()
            .fill(&mut salt)
            .map_err(|_| anyhow::anyhow!("failed to generate filesystem salt"))?;
        Ok(salt)
    }

    fn decode_salt(metadata: &KeyMetadata) -> Result<Vec<u8>> {
        if metadata.version != KEY_METADATA_VERSION {
            bail!(
                "unsupported encrypted filesystem key metadata version {}",
                metadata.version
            );
        }
        let salt = base64::engine::general_purpose::STANDARD
            .decode(&metadata.salt)
            .context("invalid encrypted filesystem salt")?;
        if salt.len() != SALT_SIZE {
            bail!("invalid encrypted filesystem salt length");
        }
        Ok(salt)
    }

    fn read_key_metadata(root: &Path) -> Result<KeyMetadata> {
        let path = root.join(KEY_FILE);
        let contents = fs::read(&path).with_context(|| {
            format!(
                "failed to read encrypted filesystem key metadata {}",
                path.display()
            )
        })?;
        serde_json::from_slice(&contents).with_context(|| {
            format!(
                "failed to parse encrypted filesystem key metadata {}",
                path.display()
            )
        })
    }

    fn write_key_metadata(root: &Path, metadata: &KeyMetadata) -> Result<()> {
        let path = root.join(KEY_FILE);
        let temporary = root.join(format!(".key.json.{}.tmp", Uuid::new_v4().simple()));
        let contents = serde_json::to_vec_pretty(metadata)
            .context("failed to serialize encrypted filesystem key metadata")?;
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            std::io::Write::write_all(&mut file, &contents)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.with_context(|| {
            format!(
                "failed to write encrypted filesystem key metadata {}",
                path.display()
            )
        })
    }

    fn contains_unmanaged_data(root: &Path) -> Result<bool> {
        for entry in fs::read_dir(root)? {
            let entry = entry?;
            if entry.file_name() != LOCK_FILE {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn encrypted_files(root: &Path) -> Result<Vec<PathBuf>> {
        let metadata = MetadataStore::new(root)?;
        let mut files = Vec::new();
        let mut directories = vec![root.to_path_buf()];
        while let Some(directory) = directories.pop() {
            let logical_directory = namespace::logical_path(root, &directory)?;
            let aliases = metadata
                .backing_names(&logical_directory)?
                .into_iter()
                .map(|(logical, backing)| (backing, logical))
                .collect::<std::collections::HashMap<_, _>>();
            for entry in fs::read_dir(&directory)? {
                let entry = entry?;
                let file_type = entry.file_type()?;
                if file_type.is_dir() {
                    directories.push(entry.path());
                } else if file_type.is_file() && !Self::is_control_file(&entry.path()) {
                    let physical_name = entry.file_name();
                    let logical_name = aliases
                        .get(&physical_name)
                        .cloned()
                        .unwrap_or(namespace::decode_name(&physical_name)?);
                    if !matches!(
                        metadata.state(&logical_directory.join(logical_name))?,
                        Some(EntryState::Cached { .. } | EntryState::Whiteout)
                    ) {
                        files.push(entry.path());
                    }
                }
            }
        }
        Ok(files)
    }

    fn is_control_file(path: &Path) -> bool {
        let Some(name) = path.file_name().map(|name| name.as_bytes()) else {
            return false;
        };
        name == LOCK_FILE.as_bytes()
            || name == KEY_FILE.as_bytes()
            || name == VFS_LOCK_FILE.as_bytes()
            || name == REKEY_JOURNAL_FILE.as_bytes()
            || name == DIRECTORY_METADATA_FILE.as_bytes()
            || name.starts_with(b".key.json.")
            || name.starts_with(b".rekey.json.")
            || name.starts_with(b".metadata.")
            || name.starts_with(b".agora-encrypted-")
            || name.starts_with(b".agora-rekey-")
    }

    fn write_journal(root: &Path, journal: &RekeyJournal) -> Result<()> {
        let path = root.join(REKEY_JOURNAL_FILE);
        let temporary = root.join(format!(
            "{REKEY_JOURNAL_FILE}.{}.tmp",
            Uuid::new_v4().simple()
        ));
        let contents = serde_json::to_vec_pretty(journal)
            .context("failed to serialize filesystem key migration journal")?;
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            std::io::Write::write_all(&mut file, &contents)?;
            file.sync_all()?;
            fs::rename(&temporary, &path)
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result.with_context(|| format!("failed to write key migration journal {}", path.display()))
    }

    fn recover_migration(root: &Path) -> Result<()> {
        let path = root.join(REKEY_JOURNAL_FILE);
        let contents = match fs::read(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("failed to read key migration journal"),
        };
        let journal: RekeyJournal =
            serde_json::from_slice(&contents).context("failed to parse key migration journal")?;
        if journal.version != REKEY_JOURNAL_VERSION {
            bail!(
                "unsupported key migration journal version {}",
                journal.version
            );
        }
        let current = Self::read_key_metadata(root)?;
        let committed = current == journal.new_key;
        if !committed && current != journal.old_key {
            bail!("key migration journal does not match current key metadata");
        }
        for entry in &journal.entries {
            let destination = Self::decode_relative_path(root, &entry.destination)?;
            let staged = Self::decode_relative_path(root, &entry.staged)?;
            let backup = Self::decode_relative_path(root, &entry.backup)?;
            if committed {
                Self::remove_file_if_exists(&backup)?;
                Self::remove_file_if_exists(&staged)?;
            } else {
                if backup.exists() {
                    Self::remove_file_if_exists(&destination)?;
                    fs::rename(&backup, &destination).with_context(|| {
                        format!("failed to restore encrypted file {}", destination.display())
                    })?;
                }
                Self::remove_file_if_exists(&staged)?;
            }
        }
        fs::remove_file(&path)
            .with_context(|| format!("failed to remove key migration journal {}", path.display()))
    }

    fn encode_relative_path(root: &Path, path: &Path) -> Result<String> {
        let relative = path.strip_prefix(root).with_context(|| {
            format!(
                "migration path is outside filesystem root: {}",
                path.display()
            )
        })?;
        Ok(
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(relative.as_os_str().as_bytes()),
        )
    }

    fn decode_relative_path(root: &Path, encoded: &str) -> Result<PathBuf> {
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(encoded)
            .context("invalid migration path encoding")?;
        let relative = PathBuf::from(std::ffi::OsString::from_vec(bytes));
        if relative
            .components()
            .any(|component| !matches!(component, Component::Normal(_)))
        {
            bail!("invalid path in key migration journal");
        }
        Ok(root.join(relative))
    }

    fn remove_file_if_exists(path: &Path) -> Result<()> {
        match fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error)
                .with_context(|| format!("failed to remove migration file {}", path.display())),
        }
    }
}

#[cfg(test)]
mod tests;
