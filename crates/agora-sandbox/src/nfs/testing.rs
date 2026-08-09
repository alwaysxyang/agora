use crate::nfs::backend::{RemoteStorage, StorageError, StorageResult};
use crate::nfs::protocol::{RemoteEntry, RemoteFileType, RemoteMetadata, RemotePath};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
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
    reset_operations: AtomicUsize,
    resets_blocked: AtomicBool,
    reset_release: tokio::sync::Notify,
    stats_blocked: AtomicBool,
    stat_release: tokio::sync::Notify,
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

    pub(crate) fn reset_operations(&self) -> usize {
        self.reset_operations.load(Ordering::Relaxed)
    }

    pub(crate) fn block_resets(&self) {
        self.resets_blocked.store(true, Ordering::Release);
    }

    pub(crate) fn release_resets(&self) {
        self.resets_blocked.store(false, Ordering::Release);
        self.reset_release.notify_waiters();
    }

    pub(crate) fn block_stats(&self) {
        self.stats_blocked.store(true, Ordering::Release);
    }

    pub(crate) fn release_stats(&self) {
        self.stats_blocked.store(false, Ordering::Release);
        self.stat_release.notify_waiters();
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

    async fn wait_for_stat_release(&self) {
        loop {
            let released = self.stat_release.notified();
            if !self.stats_blocked.load(Ordering::Acquire) {
                break;
            }
            released.await;
        }
    }

    async fn wait_for_reset_release(&self) {
        loop {
            let released = self.reset_release.notified();
            if !self.resets_blocked.load(Ordering::Acquire) {
                break;
            }
            released.await;
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
    async fn reset(&self, _root: u32) {
        self.reset_operations.fetch_add(1, Ordering::Relaxed);
        self.wait_for_reset_release().await;
    }

    async fn connect(&self, root: u32) -> StorageResult<()> {
        self.connection_result(root).await
    }

    async fn stat(&self, path: &RemotePath) -> StorageResult<RemoteMetadata> {
        self.stat_operations.fetch_add(1, Ordering::Relaxed);
        self.wait_for_stat_release().await;
        self.yield_if_requested().await;
        lock(&self.entries)
            .get(&(path.root(), path.path().to_string()))
            .map(Self::metadata)
            .ok_or_else(StorageError::not_found)
    }

    async fn read_into(
        &self,
        path: &RemotePath,
        destination: &mut File,
        max_length: u64,
    ) -> StorageResult<RemoteMetadata> {
        let entries = lock(&self.entries);
        let entry = entries
            .get(&(path.root(), path.path().to_string()))
            .ok_or_else(StorageError::not_found)?;
        let data = entry
            .data
            .as_deref()
            .ok_or_else(|| StorageError::new(libc::EISDIR, "path is a directory"))?;
        if data.len() as u64 > max_length {
            return Err(StorageError::new(
                libc::EFBIG,
                "remote file exceeds the sandbox snapshot limit",
            ));
        }
        destination
            .set_len(0)
            .and_then(|()| destination.seek(SeekFrom::Start(0)).map(|_| ()))
            .and_then(|()| destination.write_all(data))
            .map_err(|error| memory_io("failed to stream memory file", error))?;
        Ok(Self::metadata(entry))
    }

    async fn write_from_if_unchanged(
        &self,
        path: &RemotePath,
        expected: Option<&RemoteMetadata>,
        source: &mut File,
        length: u64,
    ) -> StorageResult<RemoteMetadata> {
        self.yield_if_requested().await;
        source
            .seek(SeekFrom::Start(0))
            .map_err(|error| memory_io("failed to rewind memory file", error))?;
        let mut data = Vec::new();
        source
            .take(length)
            .read_to_end(&mut data)
            .map_err(|error| memory_io("failed to stream memory file", error))?;
        if data.len() as u64 != length {
            return Err(StorageError::new(
                libc::EIO,
                "memory file ended before its declared length",
            ));
        }
        let mut entries = lock(&self.entries);
        let key = (path.root(), path.path().to_string());
        let current = entries.get(&key).map(Self::metadata);
        let unchanged = match (expected, current.as_ref()) {
            (None, None) => true,
            (Some(expected), Some(current)) => expected.identity == current.identity,
            _ => false,
        };
        if !unchanged {
            return Err(StorageError::new(
                libc::ESTALE,
                "remote file changed since it was opened",
            ));
        }
        let generation = entries.get(&key).map_or(1, |entry| entry.generation + 1);
        let entry = MemoryEntry {
            data: Some(data),
            generation,
        };
        let metadata = Self::metadata(&entry);
        entries.insert(key, entry);
        Ok(metadata)
    }

    async fn list(&self, path: &RemotePath, max_entries: usize) -> StorageResult<Vec<RemoteEntry>> {
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
        let entries = entries
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
            .collect::<Vec<_>>();
        if entries.len() > max_entries {
            return Err(StorageError::new(
                libc::EOVERFLOW,
                "remote directory exceeds the sandbox listing limit",
            ));
        }
        Ok(entries)
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

fn memory_io(context: &str, error: std::io::Error) -> StorageError {
    StorageError::new(
        error.raw_os_error().unwrap_or(libc::EIO),
        format!("{context}: {error}"),
    )
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_with_contents(contents: &[u8]) -> File {
        let mut file = tempfile::tempfile().unwrap();
        file.write_all(contents).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file
    }

    fn assert_errno<T>(result: StorageResult<T>, expected: libc::c_int) {
        match result {
            Ok(_) => panic!("operation unexpectedly succeeded"),
            Err(error) => assert_eq!(error.errno(), expected),
        }
    }

    #[tokio::test]
    async fn memory_storage_preserves_posix_conflict_type_and_directory_errors() {
        let storage = MemoryStorage::default();
        storage.insert_file(0, "file", b"data");
        storage.insert_directory(0, "directory");
        storage.insert_file(0, "directory/child", b"child");

        assert_errno(
            storage
                .create_directory(&RemotePath::new(0, "file").unwrap())
                .await,
            libc::EEXIST,
        );
        assert_errno(
            storage
                .remove(&RemotePath::new(0, "file").unwrap(), true)
                .await,
            libc::ENOTDIR,
        );
        assert_errno(
            storage
                .remove(&RemotePath::new(0, "directory").unwrap(), false)
                .await,
            libc::EISDIR,
        );
        assert_errno(
            storage
                .remove(&RemotePath::new(0, "directory").unwrap(), true)
                .await,
            libc::ENOTEMPTY,
        );
        assert_errno(
            storage
                .rename(
                    &RemotePath::new(0, "file").unwrap(),
                    &RemotePath::new(1, "file").unwrap(),
                )
                .await,
            libc::EXDEV,
        );

        let path = RemotePath::new(0, "file").unwrap();
        let expected = storage.stat(&path).await.unwrap();
        storage.replace(0, "file", b"outside");
        let mut source = file_with_contents(b"sandbox");
        assert_errno(
            storage
                .write_from_if_unchanged(&path, Some(&expected), &mut source, 7)
                .await,
            libc::ESTALE,
        );
        let mut source = file_with_contents(b"sandbox");
        assert_errno(
            storage
                .write_from_if_unchanged(&path, None, &mut source, 7)
                .await,
            libc::ESTALE,
        );
    }

    #[tokio::test]
    async fn memory_storage_transfers_file_contents_through_streams() {
        let storage = MemoryStorage::default();
        let path = RemotePath::new(0, "file").unwrap();
        storage.insert_file(0, "file", b"remote");

        let mut downloaded = tempfile::tempfile().unwrap();
        let baseline = storage
            .read_into(&path, &mut downloaded, u64::MAX)
            .await
            .unwrap();
        downloaded.seek(SeekFrom::Start(0)).unwrap();
        let mut contents = String::new();
        downloaded.read_to_string(&mut contents).unwrap();
        assert_eq!(contents, "remote");

        let mut uploaded = tempfile::tempfile().unwrap();
        uploaded.write_all(b"sandbox").unwrap();
        uploaded.seek(SeekFrom::Start(0)).unwrap();
        storage
            .write_from_if_unchanged(&path, Some(&baseline), &mut uploaded, 7)
            .await
            .unwrap();
        assert_eq!(storage.data(0, "file").unwrap(), b"sandbox");
    }
}
