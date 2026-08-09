use super::protocol::{ByteRange, Request, Response};
use crate::filesystem::{EncryptedFile, FileCipher};
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant};
use uuid::Uuid;

const COPY_BUFFER_SIZE: usize = 64 * 1024;
const CLOSED_HANDLE_TTL: Duration = Duration::from_secs(120);
const CLOSED_HANDLE_CAPACITY: usize = 128;

pub(crate) struct BrokerReply {
    pub(crate) response: Response,
}

pub(crate) struct LocalBroker {
    root: PathBuf,
    cipher: FileCipher,
    handles: Mutex<HashMap<String, Arc<Mutex<LocalHandle>>>>,
    files: Mutex<HashMap<FileIdentity, Weak<Mutex<()>>>>,
}

struct LocalHandle {
    identity: FileIdentity,
    plaintext: File,
    encrypted: EncryptedFile,
    writable: bool,
    potentially_dirty: RangeSet,
    baseline: PlaintextIdentity,
    references: usize,
    closed_at: Option<Instant>,
    file_lock: Arc<Mutex<()>>,
}

struct PeerHandle {
    handle: Arc<Mutex<LocalHandle>>,
    plaintext: File,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlaintextIdentity {
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
}

#[derive(Default)]
struct RangeSet {
    ranges: Vec<ByteRange>,
}

struct BrokerError {
    errno: libc::c_int,
    message: String,
}

impl LocalBroker {
    pub(crate) fn new(root: &Path, cipher: FileCipher) -> std::io::Result<Self> {
        Ok(Self {
            root: root.canonicalize()?,
            cipher,
            handles: Mutex::new(HashMap::new()),
            files: Mutex::new(HashMap::new()),
        })
    }

    pub(crate) fn handle(&self, request: Request, descriptor: Option<OwnedFd>) -> BrokerReply {
        match self.dispatch(request, descriptor) {
            Ok(response) => BrokerReply { response },
            Err(error) => BrokerReply {
                response: Response::Error {
                    errno: error.errno,
                    message: error.message,
                },
            },
        }
    }

    pub(crate) fn flush_all(&self) -> std::io::Result<()> {
        let handles = lock(&self.handles)
            .iter()
            .map(|(id, handle)| (id.clone(), Arc::clone(handle)))
            .collect::<Vec<_>>();
        let ids = handles
            .into_iter()
            .filter_map(|(id, handle)| (lock(&handle).references != 0).then_some(id))
            .collect::<Vec<_>>();
        for id in ids {
            self.sync_handle(&id, Vec::new(), true, true)
                .map_err(BrokerError::into_io)?;
        }
        Ok(())
    }

    pub(crate) fn expire_closed(&self) {
        self.prune_closed(Instant::now());
    }

    fn dispatch(
        &self,
        request: Request,
        descriptor: Option<OwnedFd>,
    ) -> Result<Response, BrokerError> {
        match request {
            Request::Open { path, writable } => {
                let descriptor = descriptor
                    .ok_or_else(|| BrokerError::protocol("local open requires a descriptor"))?;
                self.open(
                    &path.to_path().map_err(BrokerError::protocol_error)?,
                    descriptor,
                    writable,
                )
            }
            Request::Sync {
                handle,
                ranges,
                durable,
            } => {
                Self::reject_descriptor(descriptor)?;
                self.activate(&handle)?;
                self.sync_handle(&handle, ranges, durable, false)?;
                Ok(Response::Success)
            }
            Request::PotentiallyDirty { handle, range } => {
                Self::reject_descriptor(descriptor)?;
                self.activate(&handle)?;
                let handle = self.lookup_handle(&handle)?;
                let mut handle = lock(&handle);
                if !handle.writable {
                    return Err(BrokerError::new(
                        libc::EBADF,
                        "local filesystem handle is not writable",
                    ));
                }
                handle.potentially_dirty.insert(range);
                Ok(Response::Success)
            }
            Request::Retain {
                handles: mut retained,
            } => {
                Self::reject_descriptor(descriptor)?;
                retained.sort_unstable();
                retained.dedup();
                let handles = lock(&self.handles);
                let retained_handles = retained
                    .iter()
                    .map(|id| {
                        handles
                            .get(id)
                            .cloned()
                            .ok_or_else(BrokerError::bad_descriptor)
                    })
                    .collect::<Result<Vec<_>, _>>()?;
                for handle in &retained_handles {
                    let handle = lock(handle);
                    handle.references.checked_add(1).ok_or_else(|| {
                        BrokerError::new(libc::EOVERFLOW, "local filesystem reference overflow")
                    })?;
                }
                for handle in retained_handles {
                    let mut handle = lock(&handle);
                    handle.references += 1;
                    handle.closed_at = None;
                }
                drop(handles);
                Ok(Response::Success)
            }
            Request::Close { handle } => {
                Self::reject_descriptor(descriptor)?;
                let Some(local) = lock(&self.handles).get(&handle).cloned() else {
                    return Ok(Response::Success);
                };
                self.sync_handle(&handle, Vec::new(), true, true)?;
                let mut local = lock(&local);
                if local.references > 0 {
                    local.references -= 1;
                }
                if local.references == 0 {
                    local.closed_at = Some(Instant::now());
                }
                drop(local);
                self.prune_closed(Instant::now());
                Ok(Response::Success)
            }
        }
    }

    fn open(
        &self,
        path: &Path,
        descriptor: OwnedFd,
        writable: bool,
    ) -> Result<Response, BrokerError> {
        let canonical = path
            .canonicalize()
            .map_err(|error| BrokerError::io("failed to resolve encrypted backing file", error))?;
        if !canonical.starts_with(&self.root) {
            return Err(BrokerError::new(
                libc::EACCES,
                "encrypted backing file is outside the workspace",
            ));
        }
        let plaintext = File::from(descriptor);
        let plaintext_metadata = plaintext
            .metadata()
            .map_err(|error| BrokerError::io("failed to inspect local plaintext file", error))?;
        let encrypted = self
            .cipher
            .open_file(&canonical)
            .map_err(|error| BrokerError::anyhow("failed to open encrypted backing file", error))?;
        if plaintext_metadata.len() != encrypted.len() {
            return Err(BrokerError::protocol(
                "local plaintext length does not match encrypted backing file",
            ));
        }
        let metadata = encrypted
            .backing_file()
            .metadata()
            .map_err(|error| BrokerError::io("failed to inspect encrypted backing file", error))?;
        let identity = FileIdentity {
            device: metadata.dev(),
            inode: metadata.ino(),
        };
        let file_lock = {
            let mut files = lock(&self.files);
            files.retain(|_, file| file.strong_count() != 0);
            if let Some(file) = files.get(&identity).and_then(Weak::upgrade) {
                file
            } else {
                let file = Arc::new(Mutex::new(()));
                files.insert(identity, Arc::downgrade(&file));
                file
            }
        };
        let id = Uuid::new_v4().simple().to_string();
        lock(&self.handles).insert(
            id.clone(),
            Arc::new(Mutex::new(LocalHandle {
                identity,
                plaintext,
                encrypted,
                writable,
                potentially_dirty: RangeSet::default(),
                baseline: PlaintextIdentity::from_metadata(&plaintext_metadata),
                references: 1,
                closed_at: None,
                file_lock,
            })),
        );
        Ok(Response::Open { handle: id })
    }

    fn sync_handle(
        &self,
        id: &str,
        mut ranges: Vec<ByteRange>,
        durable: bool,
        include_potential: bool,
    ) -> Result<(), BrokerError> {
        let handle = self.lookup_handle(id)?;
        let file_lock = lock(&handle).file_lock.clone();
        let _file_guard = lock(&file_lock);
        let peer_handles = lock(&self.handles)
            .iter()
            .filter(|(other_id, _)| other_id.as_str() != id)
            .map(|(_, peer)| Arc::clone(peer))
            .collect::<Vec<_>>();
        let mut handle = lock(&handle);
        let metadata = handle
            .plaintext
            .metadata()
            .map_err(|error| BrokerError::io("failed to inspect local plaintext file", error))?;
        let current = PlaintextIdentity::from_metadata(&metadata);
        let potential = include_potential.then(|| handle.potentially_dirty.ranges.clone());
        if let Some(potential) = &potential {
            ranges.extend(potential.iter().copied());
        }
        if include_potential
            && ranges.is_empty()
            && current != handle.baseline
            && current.length > 0
        {
            ranges.push(ByteRange {
                start: 0,
                end: current.length,
            });
        }
        let ranges = RangeSet::from_ranges(ranges).ranges;
        let length = current.length;
        if (!ranges.is_empty() || length != handle.encrypted.len()) && !handle.writable {
            return Err(BrokerError::new(
                libc::EBADF,
                "local filesystem handle is not writable",
            ));
        }
        let identity = handle.identity;
        let mut peers = Vec::new();
        for peer in peer_handles {
            let local = lock(&peer);
            if local.identity != identity || local.references == 0 {
                continue;
            }
            let plaintext = local
                .plaintext
                .try_clone()
                .map_err(|error| BrokerError::io("failed to clone peer plaintext file", error))?;
            drop(local);
            peers.push(PeerHandle {
                handle: peer,
                plaintext,
            });
        }
        let mut buffer = vec![0_u8; COPY_BUFFER_SIZE];
        for range in ranges {
            let start = range.start.min(length);
            let end = range.end.min(length);
            if start >= end {
                continue;
            }
            let mut offset = start;
            while offset < end {
                let count = usize::try_from((end - offset).min(buffer.len() as u64))
                    .expect("copy chunk length fits usize");
                read_exact_at(&handle.plaintext, &mut buffer[..count], offset).map_err(
                    |error| BrokerError::io("failed to read local plaintext range", error),
                )?;
                handle
                    .encrypted
                    .write_at(&buffer[..count], offset)
                    .map_err(|error| {
                        BrokerError::anyhow("failed to encrypt local file range", error)
                    })?;
                for peer in &peers {
                    write_all_at(&peer.plaintext, &buffer[..count], offset).map_err(|error| {
                        BrokerError::io("failed to update peer plaintext file", error)
                    })?;
                }
                offset += count as u64;
            }
        }
        if handle.encrypted.len() != length {
            handle.encrypted.set_len(length).map_err(|error| {
                BrokerError::anyhow("failed to resize encrypted local file", error)
            })?;
        }
        if durable {
            handle.encrypted.sync_all().map_err(|error| {
                BrokerError::anyhow("failed to sync encrypted local file", error)
            })?;
        }
        if include_potential {
            handle.potentially_dirty.ranges.clear();
        }
        handle.baseline = current;
        for peer in peers {
            peer.plaintext
                .set_len(length)
                .map_err(|error| BrokerError::io("failed to resize peer plaintext file", error))?;
            let metadata = peer
                .plaintext
                .metadata()
                .map_err(|error| BrokerError::io("failed to inspect peer plaintext file", error))?;
            lock(&peer.handle).baseline = PlaintextIdentity::from_metadata(&metadata);
        }
        Ok(())
    }

    fn activate(&self, id: &str) -> Result<(), BrokerError> {
        let handles = lock(&self.handles);
        let handle = handles.get(id).ok_or_else(BrokerError::bad_descriptor)?;
        let mut handle = lock(handle);
        if handle.references == 0 {
            handle.references = 1;
            handle.closed_at = None;
        }
        Ok(())
    }

    fn lookup_handle(&self, id: &str) -> Result<Arc<Mutex<LocalHandle>>, BrokerError> {
        lock(&self.handles)
            .get(id)
            .cloned()
            .ok_or_else(BrokerError::bad_descriptor)
    }

    fn reject_descriptor(descriptor: Option<OwnedFd>) -> Result<(), BrokerError> {
        if descriptor.is_some() {
            Err(BrokerError::protocol(
                "local filesystem request unexpectedly included a descriptor",
            ))
        } else {
            Ok(())
        }
    }

    fn prune_closed(&self, now: Instant) {
        let mut handles = lock(&self.handles);
        let mut expired = Vec::new();
        let mut retained = Vec::new();
        for (id, handle) in handles.iter() {
            let (references, closed_at) = {
                let local = lock(handle);
                (local.references, local.closed_at)
            };
            if references != 0 {
                continue;
            }
            if closed_at.is_none_or(|closed| now.duration_since(closed) >= CLOSED_HANDLE_TTL) {
                expired.push(id.clone());
            } else {
                retained.push((id.clone(), closed_at));
            }
        }
        retained.sort_unstable_by_key(|(_, closed_at)| *closed_at);
        let excess = retained.len().saturating_sub(CLOSED_HANDLE_CAPACITY);
        expired.extend(retained.into_iter().take(excess).map(|(id, _)| id));
        for id in expired {
            handles.remove(&id);
        }
    }
}

impl PlaintextIdentity {
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            length: metadata.len(),
            modified_seconds: metadata.mtime(),
            modified_nanoseconds: metadata.mtime_nsec(),
            changed_seconds: metadata.ctime(),
            changed_nanoseconds: metadata.ctime_nsec(),
        }
    }
}

impl RangeSet {
    fn from_ranges(ranges: Vec<ByteRange>) -> Self {
        let mut set = Self::default();
        for range in ranges {
            set.insert(range);
        }
        set
    }

    fn insert(&mut self, range: ByteRange) {
        if range.start >= range.end {
            return;
        }
        self.ranges.push(range);
        self.ranges.sort_unstable_by_key(|range| range.start);
        let mut merged: Vec<ByteRange> = Vec::with_capacity(self.ranges.len());
        for range in self.ranges.drain(..) {
            if let Some(last) = merged.last_mut()
                && range.start <= last.end
            {
                last.end = last.end.max(range.end);
            } else {
                merged.push(range);
            }
        }
        self.ranges = merged;
    }
}

impl BrokerError {
    fn new(errno: libc::c_int, message: impl Into<String>) -> Self {
        Self {
            errno,
            message: message.into(),
        }
    }

    fn bad_descriptor() -> Self {
        Self::new(libc::EBADF, "unknown local filesystem handle")
    }

    fn protocol(message: impl Into<String>) -> Self {
        Self::new(libc::EPROTO, message)
    }

    fn protocol_error(error: anyhow::Error) -> Self {
        Self::protocol(error.to_string())
    }

    fn io(context: &str, error: std::io::Error) -> Self {
        Self::new(
            error.raw_os_error().unwrap_or(libc::EIO),
            format!("{context}: {error}"),
        )
    }

    fn anyhow(context: &str, error: anyhow::Error) -> Self {
        let errno = error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error)
            .unwrap_or(libc::EIO);
        Self::new(errno, format!("{context}: {error:#}"))
    }

    fn into_io(self) -> std::io::Error {
        std::io::Error::other(self.message)
    }
}

fn read_exact_at(file: &File, mut buffer: &mut [u8], mut offset: u64) -> std::io::Result<()> {
    while !buffer.is_empty() {
        let read = file.read_at(buffer, offset)?;
        if read == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "local plaintext range is incomplete",
            ));
        }
        offset += read as u64;
        buffer = &mut buffer[read..];
    }
    Ok(())
}

fn write_all_at(file: &File, mut buffer: &[u8], mut offset: u64) -> std::io::Result<()> {
    while !buffer.is_empty() {
        let written = file.write_at(buffer, offset)?;
        if written == 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "failed to update peer plaintext file",
            ));
        }
        offset += written as u64;
        buffer = &buffer[written..];
    }
    Ok(())
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(test)]
#[path = "broker/tests.rs"]
mod tests;
