use crate::nfs::backend::{RemoteStorage, StorageError, StorageResult};
use crate::nfs::protocol::{
    RemoteFileType, RemoteMetadata, RemotePath, Request, RequestId, Response,
};
use md5::{Digest, Md5};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tokio::sync::oneshot;
use uuid::Uuid;

const REQUEST_CACHE_CAPACITY: usize = 4_096;
const REQUEST_CACHE_TTL: Duration = Duration::from_secs(120);
const CLOSED_HANDLE_CAPACITY: usize = 4_096;

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
    handles: Mutex<HashMap<String, Arc<Mutex<RemoteHandle>>>>,
    requests: Mutex<RequestCache>,
    closed_handles: Mutex<HandleTombstones>,
    list_payloads: Mutex<HashMap<String, File>>,
    root_mutations: Mutex<HashMap<u32, Arc<Mutex<()>>>>,
}

struct RemoteHandle {
    path: RemotePath,
    file: Option<File>,
    application: File,
    publishable: bool,
    unlinked: bool,
    force_publish: bool,
    checksum: [u8; 16],
    baseline: Option<RemoteMetadata>,
}

#[derive(Default)]
struct RequestCache {
    entries: HashMap<RequestId, CachedRequest>,
}

enum CachedRequest {
    Pending {
        request: Request,
        waiters: Vec<oneshot::Sender<Response>>,
    },
    Completed {
        request: Request,
        response: Response,
        completed_at: Instant,
        claimed: bool,
    },
}

enum CacheDecision {
    Execute,
    Wait(oneshot::Receiver<Response>),
    Replay(Response),
    Reject,
}

enum AbandonedResource {
    Handle(String),
    Anchor(String),
}

#[derive(Default)]
struct HandleTombstones {
    entries: HashSet<String>,
    order: VecDeque<String>,
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
            handles: Mutex::new(HashMap::new()),
            requests: Mutex::new(RequestCache::default()),
            closed_handles: Mutex::new(HandleTombstones::default()),
            list_payloads: Mutex::new(HashMap::new()),
            root_mutations: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) async fn handle_request(
        &self,
        request_id: RequestId,
        request: Request,
    ) -> BrokerReply {
        let decision = self
            .requests
            .lock()
            .await
            .begin(request_id.clone(), request.clone());
        match decision {
            CacheDecision::Execute => {
                let reply = self.handle(request).await;
                let abandoned = self
                    .requests
                    .lock()
                    .await
                    .complete(request_id, reply.response.clone());
                self.discard_abandoned_resources(abandoned).await;
                reply
            }
            CacheDecision::Wait(receiver) => match receiver.await {
                Ok(response) => self.reply_for_response(response).await,
                Err(_) => protocol_reply("remote request was cancelled"),
            },
            CacheDecision::Replay(response) => self.reply_for_response(response).await,
            CacheDecision::Reject => {
                protocol_reply("remote request ID was reused for a different operation")
            }
        }
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
                let metadata = self.sync(&handle).await?;
                Ok(BrokerReply {
                    response: Response::Synced { metadata },
                    descriptor: None,
                })
            }
            Request::Close { handle } => {
                self.close(&handle).await?;
                Ok(success())
            }
            Request::Abort { handle } => {
                self.abort(&handle).await?;
                Ok(success())
            }
            Request::Claim { request_id } => {
                self.claim_request(&request_id).await?;
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

    pub(crate) async fn expire_requests(&self) {
        let abandoned = self.requests.lock().await.expire();
        self.discard_abandoned_resources(abandoned).await;
    }

    async fn claim_request(&self, request_id: &RequestId) -> StorageResult<()> {
        let list_payload = self
            .requests
            .lock()
            .await
            .claim(request_id)
            .ok_or_else(|| {
                StorageError::new(
                    libc::EPROTO,
                    "remote resource request is not available to claim",
                )
            })?;
        if let Some(anchor) = list_payload {
            self.list_payloads.lock().await.remove(&anchor);
        }
        Ok(())
    }

    async fn reply_for_response(&self, response: Response) -> BrokerReply {
        let descriptor = match &response {
            Response::Open { handle, .. } => match self.application_descriptor(handle).await {
                Ok(descriptor) => Some(descriptor),
                Err(error) => {
                    return BrokerReply {
                        response: Response::Error {
                            errno: error.errno,
                            message: error.message,
                        },
                        descriptor: None,
                    };
                }
            },
            Response::List { anchor } => match self.list_descriptor(anchor).await {
                Ok(descriptor) => Some(descriptor),
                Err(error) => {
                    return BrokerReply {
                        response: Response::Error {
                            errno: error.errno,
                            message: error.message,
                        },
                        descriptor: None,
                    };
                }
            },
            _ => None,
        };
        BrokerReply {
            response,
            descriptor,
        }
    }

    async fn application_descriptor(&self, id: &str) -> StorageResult<OwnedFd> {
        let handle = self
            .handles
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::new(libc::EBADF, "unknown remote handle"))?;
        let descriptor = handle
            .lock()
            .await
            .application
            .try_clone()
            .map_err(|error| storage_io("failed to duplicate remote descriptor", error))?;
        Ok(descriptor.into())
    }

    async fn list_descriptor(&self, anchor: &str) -> StorageResult<OwnedFd> {
        self.list_payloads
            .lock()
            .await
            .get(anchor)
            .ok_or_else(|| StorageError::new(libc::EPROTO, "remote list payload is unavailable"))?
            .try_clone()
            .map(Into::into)
            .map_err(|error| storage_io("failed to duplicate remote list payload", error))
    }

    async fn discard_abandoned_resources(&self, resources: Vec<AbandonedResource>) {
        let mut open = self.handles.lock().await;
        let mut closed = self.closed_handles.lock().await;
        let mut list_payloads = self.list_payloads.lock().await;
        for resource in resources {
            match resource {
                AbandonedResource::Handle(handle) => {
                    if open.remove(&handle).is_some() {
                        closed.insert(handle);
                    }
                }
                AbandonedResource::Anchor(anchor) => {
                    list_payloads.remove(&anchor);
                    let path = self.staging.join(anchor);
                    let removed = std::fs::remove_file(&path)
                        .or_else(|file_error| std::fs::remove_dir(&path).map_err(|_| file_error));
                    if let Err(error) = removed
                        && error.kind() != std::io::ErrorKind::NotFound
                    {
                        // Cleanup is best effort; the staging directory is removed
                        // when the controller exits.
                    }
                }
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn handle_count_for_test(&self) -> usize {
        self.handles.lock().await.len()
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
        let mut temporary = tempfile::NamedTempFile::new_in(&self.staging)
            .map_err(|error| storage_io("failed to create anonymous remote file", error))?;
        let (mut metadata, baseline) = if force_publish {
            let metadata = existing.clone().unwrap_or_else(empty_file_metadata);
            (
                RemoteMetadata {
                    size: 0,
                    ..metadata
                },
                existing,
            )
        } else {
            let metadata = self
                .storage
                .read_into(&path, temporary.as_file_mut())
                .await?;
            (metadata.clone(), Some(metadata))
        };
        temporary
            .flush()
            .map_err(|error| storage_io("failed to flush anonymous remote file", error))?;
        metadata.size = temporary
            .as_file()
            .metadata()
            .map_err(|error| storage_io("failed to inspect anonymous remote file", error))?
            .len();
        let checksum = checksum_file(temporary.as_file_mut())?;
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
        drop(temporary);
        set_close_on_exec(&application)?;
        let replay = application
            .try_clone()
            .map_err(|error| storage_io("failed to retain remote descriptor", error))?;
        let handle = Uuid::new_v4().simple().to_string();
        self.handles.lock().await.insert(
            handle.clone(),
            Arc::new(Mutex::new(RemoteHandle {
                path,
                file: Some(retained),
                application: replay,
                publishable: writable || force_publish,
                unlinked: false,
                force_publish,
                checksum,
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
        let physical = self.staging.join(&anchor);
        let application = File::open(&physical)
            .map_err(|error| storage_io("failed to open remote directory anchor", error))?;
        std::fs::remove_dir(&physical)
            .map_err(|error| storage_io("failed to unlink remote directory anchor", error))?;
        set_close_on_exec(&application)?;
        let replay = application
            .try_clone()
            .map_err(|error| storage_io("failed to retain remote directory descriptor", error))?;
        let handle = Uuid::new_v4().simple().to_string();
        self.handles.lock().await.insert(
            handle.clone(),
            Arc::new(Mutex::new(RemoteHandle {
                path,
                file: None,
                application: replay,
                publishable: false,
                unlinked: false,
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
        let mut payload = tempfile::tempfile_in(&self.staging)
            .map_err(|error| storage_io("failed to create remote list payload", error))?;
        serde_json::to_writer(&mut payload, &entries).map_err(|error| {
            StorageError::new(
                libc::EIO,
                format!("failed to serialize remote list: {error}"),
            )
        })?;
        payload
            .flush()
            .and_then(|()| payload.seek(SeekFrom::Start(0)).map(|_| ()))
            .map_err(|error| storage_io("failed to prepare remote list payload", error))?;
        let anchor = self.anchor(&path, RemoteFileType::Directory).await?;
        let descriptor = payload
            .try_clone()
            .map_err(|error| storage_io("failed to duplicate remote list payload", error))?;
        self.list_payloads
            .lock()
            .await
            .insert(anchor.clone(), payload);
        Ok(BrokerReply {
            response: Response::List { anchor },
            descriptor: Some(descriptor.into()),
        })
    }

    async fn anchor(&self, path: &RemotePath, file_type: RemoteFileType) -> StorageResult<String> {
        let _ = path;
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
        Ok(anchor)
    }

    async fn sync(&self, id: &str) -> StorageResult<Option<RemoteMetadata>> {
        let handle = self
            .handles
            .lock()
            .await
            .get(id)
            .cloned()
            .ok_or_else(|| StorageError::new(libc::EBADF, "unknown remote handle"))?;
        self.sync_handle(&handle).await
    }

    async fn sync_handle(
        &self,
        handle: &Arc<Mutex<RemoteHandle>>,
    ) -> StorageResult<Option<RemoteMetadata>> {
        let root = handle.lock().await.path.root();
        let _mutation = self.lock_root(root).await;
        let mut handle = handle.lock().await;
        self.sync_locked(&mut handle).await
    }

    async fn sync_locked(
        &self,
        handle: &mut RemoteHandle,
    ) -> StorageResult<Option<RemoteMetadata>> {
        if handle.unlinked {
            return Ok(None);
        }
        if !handle.publishable {
            return Ok(handle.baseline.clone());
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
        let length = snapshot
            .metadata()
            .map_err(|error| storage_io("failed to inspect anonymous remote file", error))?
            .len();
        let checksum = checksum_file(&mut snapshot)?;
        if !handle.force_publish && checksum == handle.checksum {
            return Ok(handle.baseline.clone());
        }
        let metadata = self
            .storage
            .write_from_if_unchanged(
                &handle.path,
                handle.baseline.as_ref(),
                &mut snapshot,
                length,
            )
            .await?;
        handle.baseline = Some(metadata.clone());
        handle.checksum = checksum;
        handle.force_publish = false;
        Ok(Some(metadata))
    }

    async fn close(&self, id: &str) -> StorageResult<()> {
        let handle = match self.handles.lock().await.get(id).cloned() {
            Some(handle) => handle,
            None if self.closed_handles.lock().await.contains(id) => return Ok(()),
            None => return Err(StorageError::new(libc::EBADF, "unknown remote handle")),
        };
        self.sync_handle(&handle).await?;
        let mut handles = self.handles.lock().await;
        if handles
            .get(id)
            .is_some_and(|current| Arc::ptr_eq(current, &handle))
        {
            handles.remove(id);
            self.closed_handles.lock().await.insert(id.to_string());
        }
        Ok(())
    }

    async fn abort(&self, id: &str) -> StorageResult<()> {
        if self.handles.lock().await.remove(id).is_some() {
            self.closed_handles.lock().await.insert(id.to_string());
            return Ok(());
        }
        if self.closed_handles.lock().await.contains(id) {
            Ok(())
        } else {
            Err(StorageError::new(libc::EBADF, "unknown remote handle"))
        }
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
            if path_is_at_or_below(&handle.path, to) {
                handle.publishable = false;
                handle.unlinked = true;
                handle.force_publish = false;
            } else if let Some(retargeted) = retarget_path(&handle.path, from, to) {
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
                handle.unlinked = true;
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

fn checksum_file(file: &mut File) -> StorageResult<[u8; 16]> {
    file.seek(SeekFrom::Start(0))
        .map_err(|error| storage_io("failed to rewind anonymous remote file", error))?;
    let mut digest = Md5::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file
            .read(&mut buffer)
            .map_err(|error| storage_io("failed to read anonymous remote file", error))?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    file.seek(SeekFrom::Start(0))
        .map_err(|error| storage_io("failed to rewind anonymous remote file", error))?;
    Ok(digest.finalize().into())
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

fn path_is_at_or_below(path: &RemotePath, parent: &RemotePath) -> bool {
    if path.root() != parent.root() {
        return false;
    }
    path == parent
        || path
            .path()
            .strip_prefix(parent.path())
            .is_some_and(|suffix| suffix.starts_with('/'))
}

impl RequestCache {
    fn begin(&mut self, request_id: RequestId, request: Request) -> CacheDecision {
        match self.entries.get_mut(&request_id) {
            Some(CachedRequest::Pending {
                request: cached,
                waiters,
            }) if cached == &request => {
                let (sender, receiver) = oneshot::channel();
                waiters.push(sender);
                CacheDecision::Wait(receiver)
            }
            Some(CachedRequest::Completed {
                request: cached,
                response,
                ..
            }) if cached == &request => CacheDecision::Replay(response.clone()),
            Some(_) => CacheDecision::Reject,
            None => {
                self.entries.insert(
                    request_id,
                    CachedRequest::Pending {
                        request,
                        waiters: Vec::new(),
                    },
                );
                CacheDecision::Execute
            }
        }
    }

    fn complete(&mut self, request_id: RequestId, response: Response) -> Vec<AbandonedResource> {
        let Some(CachedRequest::Pending { request, waiters }) = self.entries.remove(&request_id)
        else {
            return Vec::new();
        };
        for waiter in waiters {
            let _ = waiter.send(response.clone());
        }
        self.entries.insert(
            request_id,
            CachedRequest::Completed {
                request,
                claimed: !response_has_resource(&response),
                response,
                completed_at: Instant::now(),
            },
        );
        self.prune(Instant::now())
    }

    fn claim(&mut self, request_id: &RequestId) -> Option<Option<String>> {
        let Some(CachedRequest::Completed {
            response, claimed, ..
        }) = self.entries.get_mut(request_id)
        else {
            return None;
        };
        if !response_has_resource(response) {
            return None;
        }
        *claimed = true;
        Some(match response {
            Response::List { anchor } => Some(anchor.clone()),
            _ => None,
        })
    }

    fn expire(&mut self) -> Vec<AbandonedResource> {
        self.prune(Instant::now())
    }

    fn prune(&mut self, now: Instant) -> Vec<AbandonedResource> {
        let mut remove = self
            .entries
            .iter()
            .filter_map(|(request_id, entry)| match entry {
                CachedRequest::Completed { completed_at, .. }
                    if now.saturating_duration_since(*completed_at) >= REQUEST_CACHE_TTL =>
                {
                    Some(request_id.clone())
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        let completed = self
            .entries
            .len()
            .saturating_sub(remove.len())
            .saturating_sub(
                self.entries
                    .values()
                    .filter(|entry| matches!(entry, CachedRequest::Pending { .. }))
                    .count(),
            );
        if completed > REQUEST_CACHE_CAPACITY {
            let mut oldest = self
                .entries
                .iter()
                .filter_map(|(request_id, entry)| match entry {
                    CachedRequest::Completed { completed_at, .. }
                        if !remove.contains(request_id) =>
                    {
                        Some((request_id.clone(), *completed_at))
                    }
                    _ => None,
                })
                .collect::<Vec<_>>();
            oldest.sort_by_key(|(_, completed_at)| *completed_at);
            remove.extend(
                oldest
                    .into_iter()
                    .take(completed - REQUEST_CACHE_CAPACITY)
                    .map(|(request_id, _)| request_id),
            );
        }
        remove
            .into_iter()
            .filter_map(|request_id| match self.entries.remove(&request_id) {
                Some(CachedRequest::Completed {
                    response,
                    claimed: false,
                    ..
                }) => response_resource(&response),
                _ => None,
            })
            .collect()
    }
}

fn response_has_resource(response: &Response) -> bool {
    response_resource(response).is_some()
}

fn response_resource(response: &Response) -> Option<AbandonedResource> {
    match response {
        Response::Open { handle, .. } => Some(AbandonedResource::Handle(handle.clone())),
        Response::Stat { anchor, .. } | Response::List { anchor } => {
            Some(AbandonedResource::Anchor(anchor.clone()))
        }
        _ => None,
    }
}

impl HandleTombstones {
    fn contains(&self, handle: &str) -> bool {
        self.entries.contains(handle)
    }

    fn insert(&mut self, handle: String) {
        if !self.entries.insert(handle.clone()) {
            return;
        }
        self.order.push_back(handle);
        while self.order.len() > CLOSED_HANDLE_CAPACITY {
            if let Some(expired) = self.order.pop_front() {
                self.entries.remove(&expired);
            }
        }
    }
}

fn success() -> BrokerReply {
    BrokerReply {
        response: Response::Success,
        descriptor: None,
    }
}

fn protocol_reply(message: &str) -> BrokerReply {
    BrokerReply {
        response: Response::Error {
            errno: libc::EPROTO,
            message: message.to_string(),
        },
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
