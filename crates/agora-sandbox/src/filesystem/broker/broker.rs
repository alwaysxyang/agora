use super::protocol::{ByteRange, Request, Response};
use crate::filesystem::{EncryptedFile, FileCipher};
use std::collections::HashMap;
use std::fs::File;
use std::os::fd::OwnedFd;
use std::os::unix::fs::{FileExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};
use uuid::Uuid;

const COPY_BUFFER_SIZE: usize = 64 * 1024;
const CLOSED_HANDLE_TTL: Duration = Duration::from_secs(120);

pub(crate) struct BrokerReply {
    pub(crate) response: Response,
}

pub(crate) struct LocalBroker {
    root: PathBuf,
    cipher: FileCipher,
    handles: Mutex<HashMap<String, LocalHandle>>,
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
        let mut handles = lock(&self.handles);
        let ids = handles
            .iter()
            .filter(|(_, handle)| handle.references != 0)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>();
        for id in ids {
            Self::sync_locked(&mut handles, &id, Vec::new(), true, true)
                .map_err(BrokerError::into_io)?;
        }
        Ok(())
    }

    pub(crate) fn expire_closed(&self) {
        let now = Instant::now();
        lock(&self.handles).retain(|_, handle| {
            handle.references != 0
                || handle
                    .closed_at
                    .is_some_and(|closed| now.duration_since(closed) < CLOSED_HANDLE_TTL)
        });
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
                let mut handles = lock(&self.handles);
                Self::activate(&mut handles, &handle)?;
                Self::sync_locked(&mut handles, &handle, ranges, durable, false)?;
                Ok(Response::Success)
            }
            Request::PotentiallyDirty { handle, range } => {
                Self::reject_descriptor(descriptor)?;
                let mut handles = lock(&self.handles);
                Self::activate(&mut handles, &handle)?;
                let handle = handles
                    .get_mut(&handle)
                    .ok_or_else(BrokerError::bad_descriptor)?;
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
                let mut handles = lock(&self.handles);
                for id in &retained {
                    let handle = handles.get(id).ok_or_else(BrokerError::bad_descriptor)?;
                    handle.references.checked_add(1).ok_or_else(|| {
                        BrokerError::new(libc::EOVERFLOW, "local filesystem reference overflow")
                    })?;
                }
                for id in retained {
                    let handle = handles.get_mut(&id).expect("retained handle was checked");
                    handle.references += 1;
                    handle.closed_at = None;
                }
                Ok(Response::Success)
            }
            Request::Close { handle } => {
                Self::reject_descriptor(descriptor)?;
                let mut handles = lock(&self.handles);
                if !handles.contains_key(&handle) {
                    return Ok(Response::Success);
                }
                Self::sync_locked(&mut handles, &handle, Vec::new(), true, true)?;
                let handle = handles
                    .get_mut(&handle)
                    .expect("local handle existed before close");
                if handle.references > 0 {
                    handle.references -= 1;
                }
                if handle.references == 0 {
                    handle.closed_at = Some(Instant::now());
                }
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
        let id = Uuid::new_v4().simple().to_string();
        lock(&self.handles).insert(
            id.clone(),
            LocalHandle {
                identity,
                plaintext,
                encrypted,
                writable,
                potentially_dirty: RangeSet::default(),
                baseline: PlaintextIdentity::from_metadata(&plaintext_metadata),
                references: 1,
                closed_at: None,
            },
        );
        Ok(Response::Open { handle: id })
    }

    fn sync_locked(
        handles: &mut HashMap<String, LocalHandle>,
        id: &str,
        mut ranges: Vec<ByteRange>,
        durable: bool,
        include_potential: bool,
    ) -> Result<(), BrokerError> {
        let handle = handles
            .get_mut(id)
            .ok_or_else(BrokerError::bad_descriptor)?;
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
        let mut updates = Vec::new();
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
                updates.push((offset, buffer[..count].to_vec()));
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
        for (other_id, other) in handles.iter_mut() {
            if other_id == id || other.identity != identity || other.references == 0 {
                continue;
            }
            other
                .plaintext
                .set_len(length)
                .map_err(|error| BrokerError::io("failed to resize peer plaintext file", error))?;
            for (offset, data) in &updates {
                write_all_at(&other.plaintext, data, *offset).map_err(|error| {
                    BrokerError::io("failed to update peer plaintext file", error)
                })?;
            }
            let metadata = other
                .plaintext
                .metadata()
                .map_err(|error| BrokerError::io("failed to inspect peer plaintext file", error))?;
            other.baseline = PlaintextIdentity::from_metadata(&metadata);
        }
        Ok(())
    }

    fn activate(handles: &mut HashMap<String, LocalHandle>, id: &str) -> Result<(), BrokerError> {
        let handle = handles
            .get_mut(id)
            .ok_or_else(BrokerError::bad_descriptor)?;
        if handle.references == 0 {
            handle.references = 1;
            handle.closed_at = None;
        }
        Ok(())
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
