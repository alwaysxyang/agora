use crate::nfs::backend::{RemoteStorage, StorageError, StorageResult};
use crate::nfs::protocol::{RemoteEntry, RemoteFileType, RemoteMetadata, RemotePath};
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard};

#[derive(Clone)]
struct MemoryEntry {
    data: Option<Vec<u8>>,
    generation: u64,
}

#[derive(Default)]
pub(crate) struct MemoryStorage {
    entries: Mutex<HashMap<(u32, String), MemoryEntry>>,
    connection_errors: Mutex<HashMap<u32, (libc::c_int, String)>>,
    connections_blocked: AtomicBool,
    connection_release: tokio::sync::Notify,
    yield_operations: AtomicBool,
    stat_operations: AtomicUsize,
}

impl MemoryStorage {
    pub(crate) fn insert_file(&self, root: u32, path: &str, data: &[u8]) {
        lock(&self.entries).insert(
            (root, path.to_string()),
            MemoryEntry {
                data: Some(data.to_vec()),
                generation: 1,
            },
        );
    }

    pub(crate) fn insert_directory(&self, root: u32, path: &str) {
        lock(&self.entries).insert(
            (root, path.to_string()),
            MemoryEntry {
                data: None,
                generation: 1,
            },
        );
    }

    pub(crate) fn data(&self, root: u32, path: &str) -> Option<Vec<u8>> {
        lock(&self.entries)
            .get(&(root, path.to_string()))
            .and_then(|entry| entry.data.clone())
    }

    pub(crate) fn exists(&self, root: u32, path: &str) -> bool {
        lock(&self.entries).contains_key(&(root, path.to_string()))
    }

    pub(crate) fn replace(&self, root: u32, path: &str, data: &[u8]) {
        let mut entries = lock(&self.entries);
        let entry = entries.get_mut(&(root, path.to_string())).unwrap();
        entry.data = Some(data.to_vec());
        entry.generation += 1;
    }

    pub(crate) fn yield_operations(&self) {
        self.yield_operations.store(true, Ordering::Relaxed);
    }

    pub(crate) fn stat_operations(&self) -> usize {
        self.stat_operations.load(Ordering::Relaxed)
    }

    pub(crate) fn fail_connection(
        &self,
        root: u32,
        errno: libc::c_int,
        message: impl Into<String>,
    ) {
        lock(&self.connection_errors).insert(root, (errno, message.into()));
    }

    pub(crate) fn block_connections(&self) {
        self.connections_blocked.store(true, Ordering::Release);
    }

    pub(crate) fn release_connections(&self) {
        self.connections_blocked.store(false, Ordering::Release);
        self.connection_release.notify_waiters();
    }

    pub(crate) async fn connection_result(&self, root: u32) -> StorageResult<()> {
        loop {
            let released = self.connection_release.notified();
            if !self.connections_blocked.load(Ordering::Acquire) {
                break;
            }
            released.await;
        }
        match lock(&self.connection_errors).get(&root).cloned() {
            Some((errno, message)) => Err(StorageError::new(errno, message)),
            None => Ok(()),
        }
    }

    async fn yield_if_requested(&self) {
        if self.yield_operations.load(Ordering::Relaxed) {
            tokio::task::yield_now().await;
        }
    }

    fn metadata(entry: &MemoryEntry) -> RemoteMetadata {
        RemoteMetadata {
            file_type: if entry.data.is_some() {
                RemoteFileType::File
            } else {
                RemoteFileType::Directory
            },
            size: entry.data.as_ref().map_or(0, |data| data.len() as u64),
            modified_seconds: entry.generation as i64,
            modified_nanoseconds: 0,
            identity: entry.generation.to_string(),
        }
    }
}

impl RemoteStorage for MemoryStorage {
    async fn connect(&self, root: u32) -> StorageResult<()> {
        self.connection_result(root).await
    }

    async fn stat(&self, path: &RemotePath) -> StorageResult<RemoteMetadata> {
        self.stat_operations.fetch_add(1, Ordering::Relaxed);
        self.yield_if_requested().await;
        lock(&self.entries)
            .get(&(path.root(), path.path().to_string()))
            .map(Self::metadata)
            .ok_or_else(StorageError::not_found)
    }

    async fn read(&self, path: &RemotePath) -> StorageResult<(Vec<u8>, RemoteMetadata)> {
        let entries = lock(&self.entries);
        let entry = entries
            .get(&(path.root(), path.path().to_string()))
            .ok_or_else(StorageError::not_found)?;
        let data = entry
            .data
            .clone()
            .ok_or_else(|| StorageError::new(libc::EISDIR, "path is a directory"))?;
        Ok((data, Self::metadata(entry)))
    }

    async fn write(&self, path: &RemotePath, data: &[u8]) -> StorageResult<RemoteMetadata> {
        self.yield_if_requested().await;
        let mut entries = lock(&self.entries);
        let key = (path.root(), path.path().to_string());
        let generation = entries.get(&key).map_or(1, |entry| entry.generation + 1);
        let entry = MemoryEntry {
            data: Some(data.to_vec()),
            generation,
        };
        let metadata = Self::metadata(&entry);
        entries.insert(key, entry);
        Ok(metadata)
    }

    async fn list(&self, path: &RemotePath) -> StorageResult<Vec<RemoteEntry>> {
        let entries = lock(&self.entries);
        let directory = entries
            .get(&(path.root(), path.path().to_string()))
            .ok_or_else(StorageError::not_found)?;
        if directory.data.is_some() {
            return Err(StorageError::new(libc::ENOTDIR, "path is not a directory"));
        }
        let prefix = if path.path().is_empty() {
            String::new()
        } else {
            format!("{}/", path.path())
        };
        Ok(entries
            .iter()
            .filter_map(|((root, child), entry)| {
                (*root == path.root())
                    .then(|| child.strip_prefix(&prefix))
                    .flatten()
                    .filter(|suffix| !suffix.is_empty() && !suffix.contains('/'))
                    .map(|name| RemoteEntry {
                        name: name.to_string(),
                        metadata: Self::metadata(entry),
                    })
            })
            .collect())
    }

    async fn create_directory(&self, path: &RemotePath) -> StorageResult<()> {
        let mut entries = lock(&self.entries);
        let key = (path.root(), path.path().to_string());
        if entries.contains_key(&key) {
            return Err(StorageError::new(libc::EEXIST, "path already exists"));
        }
        entries.insert(
            key,
            MemoryEntry {
                data: None,
                generation: 1,
            },
        );
        Ok(())
    }

    async fn remove(&self, path: &RemotePath, directory: bool) -> StorageResult<()> {
        let mut entries = lock(&self.entries);
        let key = (path.root(), path.path().to_string());
        let entry = entries.get(&key).ok_or_else(StorageError::not_found)?;
        if directory != entry.data.is_none() {
            return Err(StorageError::new(
                if directory {
                    libc::ENOTDIR
                } else {
                    libc::EISDIR
                },
                "entry type does not match remove operation",
            ));
        }
        if directory {
            let prefix = format!("{}/", path.path());
            if entries
                .keys()
                .any(|(root, child)| *root == path.root() && child.starts_with(&prefix))
            {
                return Err(StorageError::new(libc::ENOTEMPTY, "directory is not empty"));
            }
        }
        entries.remove(&key);
        Ok(())
    }

    async fn rename(&self, from: &RemotePath, to: &RemotePath) -> StorageResult<()> {
        if from.root() != to.root() {
            return Err(StorageError::new(libc::EXDEV, "cross-root rename"));
        }
        let mut entries = lock(&self.entries);
        let entry = entries
            .remove(&(from.root(), from.path().to_string()))
            .ok_or_else(StorageError::not_found)?;
        let descendants = if entry.data.is_none() {
            let prefix = format!("{}/", from.path());
            entries
                .keys()
                .filter(|(root, path)| *root == from.root() && path.starts_with(&prefix))
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        entries.insert((to.root(), to.path().to_string()), entry);
        for (root, source) in descendants {
            let entry = entries.remove(&(root, source.clone())).unwrap();
            let suffix = source.strip_prefix(from.path()).unwrap();
            entries.insert((root, format!("{}{}", to.path(), suffix)), entry);
        }
        Ok(())
    }
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
