use crate::nfs::backend::{RemoteStorage, StorageError, StorageResult};
use crate::nfs::protocol::{RemoteFileType, RemoteMetadata, RemotePath, Request, Response};
use md5::{Digest, Md5};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;

pub(crate) struct BrokerReply {
    pub(crate) response: Response,
    pub(crate) descriptor: Option<OwnedFd>,
}

pub(crate) struct Broker<S>
where
    S: RemoteStorage,
{
    storage: Arc<S>,
    staging: PathBuf,
    anchors: Mutex<HashMap<(RemotePath, RemoteFileType), String>>,
    handles: Mutex<HashMap<String, Arc<Mutex<RemoteHandle>>>>,
    root_mutations: Mutex<HashMap<u32, Arc<Mutex<()>>>>,
}

struct RemoteHandle {
    path: RemotePath,
    file: Option<File>,
    publishable: bool,
    force_publish: bool,
    checksum: [u8; 16],
    baseline: Option<RemoteMetadata>,
}

impl<S> Broker<S>
where
    S: RemoteStorage,
{
    pub(crate) fn new(storage: Arc<S>, staging: impl AsRef<Path>) -> std::io::Result<Self> {
        let staging = staging.as_ref().to_path_buf();
        std::fs::create_dir_all(&staging)?;
        Ok(Self {
            storage,
            staging,
            anchors: Mutex::new(HashMap::new()),
            handles: Mutex::new(HashMap::new()),
            root_mutations: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) async fn handle(&self, request: Request) -> BrokerReply {
        match self.dispatch(request).await {
            Ok(reply) => reply,
            Err(error) => BrokerReply {
                response: Response::Error {
                    errno: error.errno,
                    message: error.message,
                },
                descriptor: None,
            },
        }
    }

    async fn dispatch(&self, request: Request) -> StorageResult<BrokerReply> {
        match request {
            Request::Open { path, flags, mode } => self.open(path, flags, mode).await,
            Request::Stat { path } => self.stat(path).await,
            Request::List { path } => self.list(path).await,
            Request::Access { path, mode } => {
                if mode & !(libc::R_OK | libc::W_OK | libc::X_OK) != 0 {
                    return Err(StorageError::new(libc::EINVAL, "invalid access mode"));
                }
                let metadata = self.storage.stat(&path).await?;
                if mode & libc::X_OK != 0 && metadata.file_type == RemoteFileType::File {
                    return Err(StorageError::new(
                        libc::EACCES,
                        "remote regular files are not executable",
                    ));
                }
                Ok(success())
            }
            Request::Sync { handle } => {
                self.sync(&handle).await?;
                Ok(success())
            }
            Request::Close { handle } => {
                self.close(&handle).await?;
                Ok(success())
            }
            Request::Abort { handle } => {
                self.abort(&handle).await?;
                Ok(success())
            }
            Request::CreateDirectory { path, mode: _ } => {
                if path.path().is_empty() {
                    return Err(StorageError::new(
                        libc::EEXIST,
                        "remote filesystem root already exists",
                    ));
                }
                let _mutation = self.lock_root(path.root()).await;
                self.storage.create_directory(&path).await?;
                Ok(success())
            }
            Request::Remove { path, directory } => {
                if path.path().is_empty() {
                    return Err(StorageError::new(
                        libc::EACCES,
                        "cannot remove the remote filesystem root",
                    ));
                }
                let _mutation = self.lock_root(path.root()).await;
                self.storage.remove(&path, directory).await?;
                self.discard_handles(&path).await;
                Ok(success())
            }
            Request::Rename { from, to } => {
                if from.path().is_empty() || to.path().is_empty() {
                    return Err(StorageError::new(
                        libc::EBUSY,
                        "cannot rename the remote filesystem root",
                    ));
                }
                if from.root() != to.root() {
                    return Err(StorageError::new(
                        libc::EXDEV,
                        "cannot rename across remote roots",
                    ));
                }
                let _mutation = self.lock_root(from.root()).await;
                self.storage.rename(&from, &to).await?;
                self.retarget_handles(&from, &to).await;
                Ok(success())
            }
        }
    }

    async fn open(
        &self,
        path: RemotePath,
        flags: libc::c_int,
        _mode: u32,
    ) -> StorageResult<BrokerReply> {
        let access = flags & libc::O_ACCMODE;
        let (readable, writable) = match access {
            libc::O_RDONLY => (true, false),
            libc::O_WRONLY => (false, true),
            libc::O_RDWR => (true, true),
            _ => return Err(StorageError::new(libc::EINVAL, "invalid open access mode")),
        };
        if flags & libc::O_TRUNC != 0 && !writable {
            return Err(StorageError::new(
                libc::EINVAL,
                "O_TRUNC requires write access",
            ));
        }
        let existing = match self.storage.stat(&path).await {
            Ok(metadata) => Some(metadata),
            Err(error) if error.errno() == libc::ENOENT => None,
            Err(error) => return Err(error),
        };
        if existing.is_some()
            && flags & (libc::O_CREAT | libc::O_EXCL) == libc::O_CREAT | libc::O_EXCL
        {
            return Err(StorageError::new(
                libc::EEXIST,
                "remote path already exists",
            ));
        }
        if existing.is_none() && flags & libc::O_CREAT == 0 {
            return Err(StorageError::not_found());
        }
        if let Some(metadata) = existing.as_ref()
            && metadata.file_type == RemoteFileType::Directory
        {
            if writable || flags & (libc::O_CREAT | libc::O_TRUNC) != 0 {
                return Err(StorageError::new(
                    libc::EISDIR,
                    "remote path is a directory",
                ));
            }
            return self.open_directory(path, metadata.clone()).await;
        }
        if flags & libc::O_DIRECTORY != 0 {
            return Err(StorageError::new(
                if existing.is_some() {
                    libc::ENOTDIR
                } else {
                    libc::ENOENT
                },
                "remote path is not a directory",
            ));
        }
        let force_publish = existing.is_none() || flags & libc::O_TRUNC != 0;
        let (data, mut metadata, baseline) = if force_publish {
            let metadata = existing.clone().unwrap_or_else(empty_file_metadata);
            (
                Vec::new(),
                RemoteMetadata {
                    size: 0,
                    ..metadata
                },
                existing,
            )
        } else {
            let (data, metadata) = self.storage.read(&path).await?;
            (data, metadata.clone(), Some(metadata))
        };
        let mut temporary = tempfile::NamedTempFile::new_in(&self.staging)
            .map_err(|error| storage_io("failed to create anonymous remote file", error))?;
        let retained = temporary
            .reopen()
            .map_err(|error| storage_io("failed to retain anonymous remote file", error))?;
        let mut options = OpenOptions::new();
        options
            .read(readable)
            .write(writable)
            .append(flags & libc::O_APPEND != 0)
            .custom_flags(libc::O_CLOEXEC);
        let application = options
            .open(temporary.path())
            .map_err(|error| storage_io("failed to open anonymous remote file", error))?;
        std::fs::remove_file(temporary.path())
            .map_err(|error| storage_io("failed to unlink anonymous remote file", error))?;
        temporary
            .write_all(&data)
            .map_err(|error| storage_io("failed to populate anonymous remote file", error))?;
        temporary
            .flush()
            .map_err(|error| storage_io("failed to flush anonymous remote file", error))?;
        drop(temporary);
        set_close_on_exec(&application)?;
        metadata.size = data.len() as u64;
        let handle = Uuid::new_v4().simple().to_string();
        self.handles.lock().await.insert(
            handle.clone(),
            Arc::new(Mutex::new(RemoteHandle {
                path,
                file: Some(retained),
                publishable: writable || force_publish,
                force_publish,
                checksum: Md5::digest(&data).into(),
                baseline,
            })),
        );
        Ok(BrokerReply {
            response: Response::Open { handle, metadata },
            descriptor: Some(application.into()),
        })
    }

    async fn open_directory(
        &self,
        path: RemotePath,
        metadata: RemoteMetadata,
    ) -> StorageResult<BrokerReply> {
        let anchor = self.anchor(&path, RemoteFileType::Directory).await?;
        let application = File::open(self.staging.join(anchor))
            .map_err(|error| storage_io("failed to open remote directory anchor", error))?;
        set_close_on_exec(&application)?;
        let handle = Uuid::new_v4().simple().to_string();
        self.handles.lock().await.insert(
            handle.clone(),
            Arc::new(Mutex::new(RemoteHandle {
                path,
                file: None,
                publishable: false,
                force_publish: false,
                checksum: Md5::digest([]).into(),
                baseline: Some(metadata.clone()),
            })),
        );
        Ok(BrokerReply {
            response: Response::Open { handle, metadata },
            descriptor: Some(application.into()),
        })
    }

    async fn stat(&self, path: RemotePath) -> StorageResult<BrokerReply> {
        let metadata = self.storage.stat(&path).await?;
        let anchor = self.anchor(&path, metadata.file_type).await?;
        Ok(BrokerReply {
            response: Response::Stat { metadata, anchor },
            descriptor: None,
        })
    }

    async fn list(&self, path: RemotePath) -> StorageResult<BrokerReply> {
        let entries = self.storage.list(&path).await?;
        let anchor = self.anchor(&path, RemoteFileType::Directory).await?;
        Ok(BrokerReply {
            response: Response::List { entries, anchor },
            descriptor: None,
        })
    }

    async fn anchor(&self, path: &RemotePath, file_type: RemoteFileType) -> StorageResult<String> {
        let key = (path.clone(), file_type);
        let mut anchors = self.anchors.lock().await;
        if let Some(anchor) = anchors.get(&key) {
            return Ok(anchor.clone());
        }
        let anchor = format!("anchor-{}", Uuid::new_v4().simple());
        let physical = self.staging.join(&anchor);
        match file_type {
            RemoteFileType::File => {
                OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&physical)
                    .map_err(|error| storage_io("failed to create remote file anchor", error))?;
            }
            RemoteFileType::Directory => {
                std::fs::create_dir(&physical).map_err(|error| {
                    storage_io("failed to create remote directory anchor", error)
                })?;
            }
        }
        anchors.insert(key, anchor.clone());
        Ok(anchor)
    }

    async fn sync(&self, id: &str) -> StorageResult<()> {
        let handle = self
            .handles
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::new(libc::EBADF, "unknown remote handle"))?;
        self.sync_handle(&handle).await
    }

    async fn sync_handle(&self, handle: &Arc<Mutex<RemoteHandle>>) -> StorageResult<()> {
        let root = handle.lock().await.path.root();
        let _mutation = self.lock_root(root).await;
        let mut handle = handle.lock().await;
        self.sync_locked(&mut handle).await
    }

    async fn sync_locked(&self, handle: &mut RemoteHandle) -> StorageResult<()> {
        if !handle.publishable {
            return Ok(());
        }
        let file = handle
            .file
            .as_ref()
            .ok_or_else(|| StorageError::new(libc::EBADF, "remote file handle is closed"))?;
        let mut snapshot = file
            .try_clone()
            .map_err(|error| storage_io("failed to clone anonymous remote file", error))?;
        snapshot
            .seek(SeekFrom::Start(0))
            .map_err(|error| storage_io("failed to rewind anonymous remote file", error))?;
        let mut data = Vec::new();
        snapshot
            .read_to_end(&mut data)
            .map_err(|error| storage_io("failed to read anonymous remote file", error))?;
        let checksum: [u8; 16] = Md5::digest(&data).into();
        if !handle.force_publish && checksum == handle.checksum {
            return Ok(());
        }
        let current = match self.storage.stat(&handle.path).await {
            Ok(metadata) => Some(metadata),
            Err(error) if error.errno() == libc::ENOENT => None,
            Err(error) => return Err(error),
        };
        let unchanged = match (&handle.baseline, &current) {
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
        let metadata = self.storage.write(&handle.path, &data).await?;
        handle.baseline = Some(metadata);
        handle.checksum = checksum;
        handle.force_publish = false;
        Ok(())
    }

    async fn close(&self, id: &str) -> StorageResult<()> {
        let handle = self
            .handles
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::new(libc::EBADF, "unknown remote handle"))?;
        self.sync_handle(&handle).await?;
        let mut handles = self.handles.lock().await;
        if handles
            .get(id)
            .is_some_and(|current| Arc::ptr_eq(current, &handle))
        {
            handles.remove(id);
        }
        Ok(())
    }

    async fn abort(&self, id: &str) -> StorageResult<()> {
        self.handles
            .lock()
            .await
            .remove(id)
            .map(|_| ())
            .ok_or_else(|| StorageError::new(libc::EBADF, "unknown remote handle"))
    }

    async fn retarget_handles(&self, from: &RemotePath, to: &RemotePath) {
        let handles = self
            .handles
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for handle in handles {
            let mut handle = handle.lock().await;
            if let Some(retargeted) = retarget_path(&handle.path, from, to) {
                handle.path = retargeted;
            }
        }
    }

    async fn discard_handles(&self, path: &RemotePath) {
        let handles = self
            .handles
            .lock()
            .await
            .values()
            .cloned()
            .collect::<Vec<_>>();
        for handle in handles {
            let mut handle = handle.lock().await;
            if handle.path == *path {
                handle.publishable = false;
                handle.force_publish = false;
            }
        }
    }

    async fn lock_root(&self, root: u32) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self
            .root_mutations
            .lock()
            .await
            .entry(root)
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();
        lock.lock_owned().await
    }
}

fn retarget_path(path: &RemotePath, from: &RemotePath, to: &RemotePath) -> Option<RemotePath> {
    if path.root() != from.root() || from.root() != to.root() {
        return None;
    }
    if path == from {
        return Some(to.clone());
    }
    let suffix = path.path().strip_prefix(from.path())?;
    if !suffix.starts_with('/') {
        return None;
    }
    let target = format!("{}{}", to.path(), suffix);
    RemotePath::new(to.root(), target).ok()
}

fn success() -> BrokerReply {
    BrokerReply {
        response: Response::Success,
        descriptor: None,
    }
}

fn empty_file_metadata() -> RemoteMetadata {
    RemoteMetadata {
        file_type: RemoteFileType::File,
        size: 0,
        modified_seconds: 0,
        modified_nanoseconds: 0,
        identity: String::new(),
    }
}

fn set_close_on_exec(file: &File) -> StorageResult<()> {
    let descriptor = file.as_raw_fd();
    let flags = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
    if flags < 0 || unsafe { libc::fcntl(descriptor, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0
    {
        return Err(storage_io(
            "failed to protect anonymous remote descriptor",
            std::io::Error::last_os_error(),
        ));
    }
    Ok(())
}

fn storage_io(context: &str, error: std::io::Error) -> StorageError {
    StorageError::new(
        error.raw_os_error().unwrap_or(libc::EIO),
        format!("{context}: {error}"),
    )
}

#[cfg(test)]
mod tests;
