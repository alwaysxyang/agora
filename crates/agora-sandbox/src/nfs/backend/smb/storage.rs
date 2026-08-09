use super::SmbRemoteConfig;
use crate::nfs::backend::{RemoteStorage, StorageError, StorageResult};
use crate::nfs::protocol::{RemoteEntry, RemoteFileType, RemoteMetadata, RemotePath};
use smb2::msg::close::{CloseRequest, CloseResponse, SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB};
use smb2::msg::create::{
    CreateDisposition, CreateRequest, CreateResponse, ImpersonationLevel, ShareAccess,
};
use smb2::msg::flush::FlushRequest;
use smb2::msg::read::{ReadRequest, ReadResponse, SMB2_CHANNEL_NONE};
use smb2::msg::set_info::{InfoType, SetInfoRequest};
use smb2::msg::write::{WriteRequest, WriteResponse};
use smb2::pack::{ReadCursor, Unpack};
use smb2::types::flags::FileAccessMask;
use smb2::types::status::NtStatus;
use smb2::types::{Command, FileId, OplockLevel};
use smb2::{ClientConfig, ErrorKind, SmbClient, Tree};
use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::sync::Arc;
use std::time::{Duration, UNIX_EPOCH};
use tokio::sync::Mutex;
use uuid::Uuid;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;
const FILE_ATTRIBUTE_NORMAL: u32 = 0x0000_0080;
const FILE_NON_DIRECTORY_FILE: u32 = 0x0000_0040;
const FILE_END_OF_FILE_INFORMATION: u8 = 20;
const FILE_RENAME_INFORMATION: u8 = 10;
const TRANSFER_CHUNK_SIZE: usize = 64 * 1024;

struct SmbStorage {
    roots: Vec<Mutex<SmbRoot>>,
}

pub(in crate::nfs) fn configured_storage(
    remotes: &[SmbRemoteConfig],
) -> Arc<impl RemoteStorage + use<>> {
    Arc::new(SmbStorage::new(remotes))
}

impl SmbStorage {
    fn new(remotes: &[SmbRemoteConfig]) -> Self {
        Self {
            roots: remotes
                .iter()
                .cloned()
                .map(SmbRoot::new)
                .map(Mutex::new)
                .collect(),
        }
    }

    async fn root_by_index(
        &self,
        root: u32,
    ) -> StorageResult<tokio::sync::MutexGuard<'_, SmbRoot>> {
        let root = self
            .roots
            .get(root as usize)
            .ok_or_else(|| StorageError::new(libc::EINVAL, "unknown SMB root"))?;
        Ok(root.lock().await)
    }

    async fn root(&self, path: &RemotePath) -> StorageResult<tokio::sync::MutexGuard<'_, SmbRoot>> {
        self.root_by_index(path.root()).await
    }
}

impl RemoteStorage for SmbStorage {
    async fn reset(&self, root: u32) {
        if let Some(root) = self.roots.get(root as usize) {
            root.lock().await.session = None;
        }
    }

    async fn connect(&self, root: u32) -> StorageResult<()> {
        let mut root = self.root_by_index(root).await?;
        let remote_path = root.config.remote_path().to_string();
        let session = root.session().await?;
        if remote_path.is_empty() {
            return Ok(());
        }
        let result = session.client.stat(&mut session.tree, &remote_path).await;
        validate_remote_root(result)
    }

    async fn stat(&self, path: &RemotePath) -> StorageResult<RemoteMetadata> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        let info = session
            .client
            .stat(&mut session.tree, &remote)
            .await
            .map_err(storage_error)?;
        Ok(metadata_from_file(&info))
    }

    async fn read_into(
        &self,
        path: &RemotePath,
        destination: &mut File,
        max_length: u64,
    ) -> StorageResult<RemoteMetadata> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        read_locked_file(session, &remote, destination, max_length)
            .await
            .map_err(storage_error)
    }

    async fn write_from_if_unchanged(
        &self,
        path: &RemotePath,
        expected: Option<&RemoteMetadata>,
        source: &mut File,
        length: u64,
    ) -> StorageResult<RemoteMetadata> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        write_locked_file(session, &remote, expected, source, length).await
    }

    async fn list(&self, path: &RemotePath, max_entries: usize) -> StorageResult<Vec<RemoteEntry>> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        let entries = session
            .client
            .list_directory(&mut session.tree, &remote)
            .await
            .map_err(storage_error)?;
        validate_directory_entry_count(
            entries
                .iter()
                .filter(|entry| entry.name != "." && entry.name != "..")
                .count(),
            max_entries,
        )?;
        Ok(entries
            .into_iter()
            .filter(|entry| entry.name != "." && entry.name != "..")
            .map(|entry| {
                let file_type = if entry.is_directory {
                    RemoteFileType::Directory
                } else {
                    RemoteFileType::File
                };
                RemoteEntry {
                    name: entry.name,
                    metadata: metadata(file_type, entry.size, entry.modified),
                }
            })
            .collect())
    }

    async fn create_directory(&self, path: &RemotePath) -> StorageResult<()> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        session
            .client
            .create_directory(&mut session.tree, &remote)
            .await
            .map_err(storage_error)
    }

    async fn remove(&self, path: &RemotePath, directory: bool) -> StorageResult<()> {
        let mut root = self.root(path).await?;
        let remote = root.path(path);
        let session = root.session().await?;
        if directory {
            session
                .client
                .delete_directory(&mut session.tree, &remote)
                .await
                .map_err(storage_error)
        } else {
            session
                .client
                .delete_file(&mut session.tree, &remote)
                .await
                .map_err(storage_error)
        }
    }

    async fn rename(&self, from: &RemotePath, to: &RemotePath) -> StorageResult<()> {
        if from.root() != to.root() {
            return Err(StorageError::new(libc::EXDEV, "cross-root SMB rename"));
        }
        let mut root = self.root(from).await?;
        let from = root.path(from);
        let to = root.path(to);
        let session = root.session().await?;
        rename_replacing(session, &from, &to)
            .await
            .map_err(storage_error)
    }
}

fn validate_directory_entry_count(count: usize, maximum: usize) -> StorageResult<()> {
    if count > maximum {
        return Err(StorageError::new(
            libc::EOVERFLOW,
            "remote directory exceeds the sandbox listing limit",
        ));
    }
    Ok(())
}

async fn rename_replacing(
    session: &mut SmbSession,
    from: &str,
    to: &str,
) -> Result<(), smb2::Error> {
    rename_path(session, from, to, true).await
}

async fn rename_path(
    session: &mut SmbSession,
    from: &str,
    to: &str,
    replace: bool,
) -> Result<(), smb2::Error> {
    let opened = open_path(
        session,
        from,
        CreateDisposition::FileOpen,
        FileAccessMask::new(FileAccessMask::DELETE | FileAccessMask::FILE_READ_ATTRIBUTES),
        ShareAccess(
            ShareAccess::FILE_SHARE_READ
                | ShareAccess::FILE_SHARE_WRITE
                | ShareAccess::FILE_SHARE_DELETE,
        ),
        0,
    )
    .await?;
    let request = SetInfoRequest {
        info_type: InfoType::File,
        file_info_class: FILE_RENAME_INFORMATION,
        additional_information: 0,
        file_id: opened.file_id,
        buffer: build_rename_information(&smb2::encode_path(to), replace),
    };
    let renamed = session
        .client
        .connection_mut()
        .execute(Command::SetInfo, &request, Some(session.tree.tree_id))
        .await
        .and_then(|frame| {
            expect_success(&frame, Command::SetInfo)?;
            Ok(())
        });
    let _ = close_handle(session, opened.file_id, false).await;
    match renamed {
        Ok(()) => Ok(()),
        Err(error) => Err(error),
    }
}

fn build_rename_information(target: &str, replace: bool) -> Vec<u8> {
    let target = target.encode_utf16().collect::<Vec<_>>();
    let mut buffer = Vec::with_capacity(20 + target.len() * 2);
    buffer.push(u8::from(replace));
    buffer.extend_from_slice(&[0; 7]);
    buffer.extend_from_slice(&0_u64.to_le_bytes());
    buffer.extend_from_slice(
        &u32::try_from(target.len() * 2)
            .unwrap_or(u32::MAX)
            .to_le_bytes(),
    );
    for unit in target {
        buffer.extend_from_slice(&unit.to_le_bytes());
    }
    buffer
}

fn staging_path(target: &str, identifier: &str) -> String {
    let name = format!(".agora-write-{identifier}.tmp");
    target
        .rsplit_once('/')
        .map_or(name.clone(), |(parent, _)| format!("{parent}/{name}"))
}

async fn read_locked_file(
    session: &mut SmbSession,
    path: &str,
    destination: &mut File,
    max_length: u64,
) -> Result<RemoteMetadata, smb2::Error> {
    destination.set_len(0)?;
    destination.seek(SeekFrom::Start(0))?;
    let opened = open_locked_file(
        session,
        path,
        CreateDisposition::FileOpen,
        FileAccessMask::new(
            FileAccessMask::FILE_READ_DATA
                | FileAccessMask::FILE_READ_ATTRIBUTES
                | FileAccessMask::SYNCHRONIZE,
        ),
    )
    .await?;
    let metadata = metadata_from_create(&opened);
    let result = match validate_transfer_size(opened.end_of_file, max_length) {
        Ok(()) => read_handle(session, opened.file_id, opened.end_of_file, destination).await,
        Err(error) => Err(error),
    };
    let closed = close_handle(session, opened.file_id, false).await;
    match result {
        Ok(()) => {
            closed?;
            Ok(metadata)
        }
        Err(error) => {
            let _ = closed;
            Err(error)
        }
    }
}

fn validate_transfer_size(length: u64, maximum: u64) -> Result<(), smb2::Error> {
    if length > maximum {
        return Err(std::io::Error::from_raw_os_error(libc::EFBIG).into());
    }
    Ok(())
}

async fn write_locked_file(
    session: &mut SmbSession,
    path: &str,
    expected: Option<&RemoteMetadata>,
    source: &mut File,
    length: u64,
) -> StorageResult<RemoteMetadata> {
    source
        .seek(SeekFrom::Start(0))
        .map_err(|error| storage_error(error.into()))?;
    let temporary = staging_path(path, &Uuid::new_v4().simple().to_string());
    let staged = write_staged_file(session, &temporary, source, length).await;
    let metadata = match staged {
        Ok(metadata) => metadata,
        Err(error) => return Err(storage_error(error)),
    };

    let locked = match lock_expected_target(session, path, expected).await {
        Ok(locked) => locked,
        Err(error) => {
            cleanup_staging(session, &temporary).await;
            return Err(error);
        }
    };
    let published = rename_path(session, &temporary, path, expected.is_some()).await;
    if let Some(file_id) = locked {
        let _ = close_handle(session, file_id, false).await;
    }
    match published {
        Ok(()) => Ok(metadata),
        Err(error) => {
            cleanup_staging(session, &temporary).await;
            if expected.is_none() && error.kind() == ErrorKind::AlreadyExists {
                Err(stale_file())
            } else {
                Err(storage_error(error))
            }
        }
    }
}

async fn write_staged_file(
    session: &mut SmbSession,
    path: &str,
    source: &mut File,
    length: u64,
) -> Result<RemoteMetadata, smb2::Error> {
    let opened = open_file(
        session,
        path,
        CreateDisposition::FileCreate,
        FileAccessMask::new(
            FileAccessMask::FILE_WRITE_DATA
                | FileAccessMask::FILE_WRITE_ATTRIBUTES
                | FileAccessMask::SYNCHRONIZE,
        ),
        ShareAccess(0),
    )
    .await?;
    let operation = async {
        write_handle(session, opened.file_id, source, length).await?;
        set_handle_length(session, opened.file_id, length).await?;
        flush_handle(session, opened.file_id).await?;
        close_handle(session, opened.file_id, true)
            .await?
            .ok_or_else(|| smb2::Error::invalid_data("SMB close omitted post-query attributes"))
    }
    .await;
    match operation {
        Ok(closed) => Ok(metadata_from_close(&closed)),
        Err(error) => {
            let _ = close_handle(session, opened.file_id, false).await;
            cleanup_staging(session, path).await;
            Err(error)
        }
    }
}

async fn lock_expected_target(
    session: &mut SmbSession,
    path: &str,
    expected: Option<&RemoteMetadata>,
) -> StorageResult<Option<FileId>> {
    let Some(expected) = expected else {
        return Ok(None);
    };
    let opened = match open_file(
        session,
        path,
        CreateDisposition::FileOpen,
        FileAccessMask::new(FileAccessMask::FILE_READ_ATTRIBUTES | FileAccessMask::SYNCHRONIZE),
        ShareAccess(ShareAccess::FILE_SHARE_READ | ShareAccess::FILE_SHARE_DELETE),
    )
    .await
    {
        Ok(opened) => opened,
        Err(error) if error.kind() == ErrorKind::NotFound => return Err(stale_file()),
        Err(error) => return Err(storage_error(error)),
    };
    if expected.identity != metadata_from_create(&opened).identity {
        let _ = close_handle(session, opened.file_id, false).await;
        return Err(stale_file());
    }
    Ok(Some(opened.file_id))
}

async fn cleanup_staging(session: &mut SmbSession, path: &str) {
    let _ = session.client.delete_file(&mut session.tree, path).await;
}

async fn open_locked_file(
    session: &mut SmbSession,
    path: &str,
    disposition: CreateDisposition,
    desired_access: FileAccessMask,
) -> Result<CreateResponse, smb2::Error> {
    open_file(
        session,
        path,
        disposition,
        desired_access,
        ShareAccess(ShareAccess::FILE_SHARE_READ),
    )
    .await
}

async fn open_file(
    session: &mut SmbSession,
    path: &str,
    disposition: CreateDisposition,
    desired_access: FileAccessMask,
    share_access: ShareAccess,
) -> Result<CreateResponse, smb2::Error> {
    open_path(
        session,
        path,
        disposition,
        desired_access,
        share_access,
        FILE_NON_DIRECTORY_FILE,
    )
    .await
}

async fn open_path(
    session: &mut SmbSession,
    path: &str,
    disposition: CreateDisposition,
    desired_access: FileAccessMask,
    share_access: ShareAccess,
    create_options: u32,
) -> Result<CreateResponse, smb2::Error> {
    let request = build_open_request(
        &session.tree,
        path,
        disposition,
        desired_access,
        share_access,
        create_options,
    );
    let frame = session
        .client
        .connection_mut()
        .execute(Command::Create, &request, Some(session.tree.tree_id))
        .await?;
    expect_success(&frame, Command::Create)?;
    CreateResponse::unpack(&mut ReadCursor::new(&frame.body))
}

fn build_open_request(
    tree: &Tree,
    path: &str,
    disposition: CreateDisposition,
    desired_access: FileAccessMask,
    share_access: ShareAccess,
    create_options: u32,
) -> CreateRequest {
    CreateRequest {
        requested_oplock_level: OplockLevel::None,
        impersonation_level: ImpersonationLevel::Impersonation,
        desired_access,
        file_attributes: FILE_ATTRIBUTE_NORMAL,
        share_access,
        create_disposition: disposition,
        create_options,
        name: wire_path(tree, path),
        create_contexts: Vec::new(),
    }
}

async fn read_handle(
    session: &mut SmbSession,
    file_id: FileId,
    length: u64,
    destination: &mut File,
) -> Result<(), smb2::Error> {
    let mut offset = 0_u64;
    while offset < length {
        let remaining = length - offset;
        let chunk = remaining.min(TRANSFER_CHUNK_SIZE as u64) as u32;
        let request = ReadRequest {
            padding: 0x50,
            flags: 0,
            length: chunk,
            offset,
            file_id,
            minimum_count: 0,
            channel: SMB2_CHANNEL_NONE,
            remaining_bytes: 0,
            read_channel_info: Vec::new(),
        };
        let frame = session
            .client
            .connection_mut()
            .execute(Command::Read, &request, Some(session.tree.tree_id))
            .await?;
        if frame.header.status == NtStatus::END_OF_FILE {
            return Err(smb2::Error::invalid_data(
                "SMB file ended before its advertised length",
            ));
        }
        expect_success(&frame, Command::Read)?;
        let response = ReadResponse::unpack(&mut ReadCursor::new(&frame.body))?;
        offset += validate_read_response_size(chunk, remaining, response.data.len())?;
        destination.write_all(&response.data)?;
    }
    Ok(())
}

fn validate_read_response_size(
    requested: u32,
    remaining: u64,
    received: usize,
) -> Result<u64, smb2::Error> {
    let received = u64::try_from(received)
        .map_err(|_| smb2::Error::invalid_data("SMB read response is too large"))?;
    if received == 0 {
        return Err(smb2::Error::invalid_data(
            "SMB read returned no data before the advertised end of file",
        ));
    }
    if received > u64::from(requested) || received > remaining {
        return Err(smb2::Error::invalid_data(
            "SMB read response exceeds the requested length",
        ));
    }
    Ok(received)
}

async fn write_handle(
    session: &mut SmbSession,
    file_id: FileId,
    source: &mut File,
    length: u64,
) -> Result<(), smb2::Error> {
    let mut offset = 0_u64;
    let mut buffer = vec![0_u8; TRANSFER_CHUNK_SIZE];
    while offset < length {
        let chunk = usize::try_from((length - offset).min(TRANSFER_CHUNK_SIZE as u64))
            .map_err(|_| smb2::Error::invalid_data("SMB write chunk is too large"))?;
        source.read_exact(&mut buffer[..chunk])?;
        let request = WriteRequest {
            data_offset: 0x70,
            offset,
            file_id,
            channel: 0,
            remaining_bytes: 0,
            write_channel_info_offset: 0,
            write_channel_info_length: 0,
            flags: 0,
            data: buffer[..chunk].to_vec(),
        };
        let frame = session
            .client
            .connection_mut()
            .execute(Command::Write, &request, Some(session.tree.tree_id))
            .await?;
        expect_success(&frame, Command::Write)?;
        let response = WriteResponse::unpack(&mut ReadCursor::new(&frame.body))?;
        if response.count as usize != chunk {
            return Err(smb2::Error::invalid_data(
                "SMB write returned a short count",
            ));
        }
        offset += chunk as u64;
    }
    Ok(())
}

async fn set_handle_length(
    session: &mut SmbSession,
    file_id: FileId,
    length: u64,
) -> Result<(), smb2::Error> {
    let request = SetInfoRequest {
        info_type: InfoType::File,
        file_info_class: FILE_END_OF_FILE_INFORMATION,
        additional_information: 0,
        file_id,
        buffer: length.to_le_bytes().to_vec(),
    };
    let frame = session
        .client
        .connection_mut()
        .execute(Command::SetInfo, &request, Some(session.tree.tree_id))
        .await?;
    expect_success(&frame, Command::SetInfo)
}

async fn flush_handle(session: &mut SmbSession, file_id: FileId) -> Result<(), smb2::Error> {
    let frame = session
        .client
        .connection_mut()
        .execute(
            Command::Flush,
            &FlushRequest { file_id },
            Some(session.tree.tree_id),
        )
        .await?;
    expect_success(&frame, Command::Flush)
}

async fn close_handle(
    session: &mut SmbSession,
    file_id: FileId,
    attributes: bool,
) -> Result<Option<CloseResponse>, smb2::Error> {
    let flags = if attributes {
        SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB
    } else {
        0
    };
    let frame = session
        .client
        .connection_mut()
        .execute(
            Command::Close,
            &CloseRequest { flags, file_id },
            Some(session.tree.tree_id),
        )
        .await?;
    expect_success(&frame, Command::Close)?;
    attributes
        .then(|| CloseResponse::unpack(&mut ReadCursor::new(&frame.body)))
        .transpose()
}

fn expect_success(frame: &smb2::Frame, command: Command) -> Result<(), smb2::Error> {
    if frame.header.status == NtStatus::SUCCESS {
        Ok(())
    } else {
        Err(smb2::Error::Protocol {
            status: frame.header.status,
            command,
        })
    }
}

fn wire_path(tree: &Tree, path: &str) -> String {
    let path = smb2::encode_path(path);
    if !tree.is_dfs {
        return path;
    }
    let server = tree.server.split(':').next().unwrap_or(&tree.server);
    if path.is_empty() {
        format!("{server}\\{}", tree.share_name)
    } else {
        format!("{server}\\{}\\{path}", tree.share_name)
    }
}

fn stale_file() -> StorageError {
    StorageError::new(libc::ESTALE, "remote file changed since it was opened")
}

struct SmbRoot {
    config: SmbRemoteConfig,
    session: Option<SmbSession>,
}

impl SmbRoot {
    fn new(config: SmbRemoteConfig) -> Self {
        Self {
            config,
            session: None,
        }
    }

    fn path(&self, path: &RemotePath) -> String {
        remote_path(self.config.remote_path(), path)
    }

    async fn session(&mut self) -> StorageResult<&mut SmbSession> {
        if self.session.is_none() {
            let mut client = SmbClient::connect(ClientConfig {
                addr: self.config.server().to_string(),
                timeout: Duration::from_secs(5),
                username: self.config.username().to_string(),
                password: self.config.password().to_string(),
                domain: self.config.domain().to_string(),
                auto_reconnect: true,
                compression: true,
                dfs_enabled: true,
                dfs_target_overrides: HashMap::new(),
            })
            .await
            .map_err(storage_error)?;
            let tree = client
                .connect_share(self.config.share())
                .await
                .map_err(storage_error)?;
            self.session = Some(SmbSession { client, tree });
        }
        self.session
            .as_mut()
            .ok_or_else(|| StorageError::new(libc::EIO, "SMB session was not initialized"))
    }
}

struct SmbSession {
    client: SmbClient,
    tree: Tree,
}

fn remote_path(base: &str, path: &RemotePath) -> String {
    match (base.is_empty(), path.path().is_empty()) {
        (true, _) => path.path().to_string(),
        (_, true) => base.to_string(),
        (false, false) => format!("{base}/{}", path.path()),
    }
}

fn metadata_from_file(info: &smb2::FileInfo) -> RemoteMetadata {
    let mut metadata = metadata(
        if info.is_directory {
            RemoteFileType::Directory
        } else {
            RemoteFileType::File
        },
        info.size,
        info.modified,
    );
    metadata.identity = format!("{}:{}", metadata.identity, info.created.0);
    metadata
}

fn validate_remote_root(result: Result<smb2::FileInfo, smb2::Error>) -> StorageResult<()> {
    let info = result.map_err(storage_error)?;
    if !info.is_directory {
        return Err(StorageError::new(
            libc::ENOTDIR,
            "configured SMB root is not a directory",
        ));
    }
    Ok(())
}

fn metadata_from_create(response: &CreateResponse) -> RemoteMetadata {
    metadata_with_creation(
        response.file_attributes,
        response.end_of_file,
        response.last_write_time,
        response.creation_time,
    )
}

fn metadata_from_close(response: &CloseResponse) -> RemoteMetadata {
    metadata_with_creation(
        response.file_attributes,
        response.end_of_file,
        response.last_write_time,
        response.creation_time,
    )
}

fn metadata_with_creation(
    attributes: u32,
    size: u64,
    modified: smb2::pack::FileTime,
    created: smb2::pack::FileTime,
) -> RemoteMetadata {
    let mut metadata = metadata(
        if attributes & FILE_ATTRIBUTE_DIRECTORY != 0 {
            RemoteFileType::Directory
        } else {
            RemoteFileType::File
        },
        size,
        modified,
    );
    metadata.identity = format!("{}:{}", metadata.identity, created.0);
    metadata
}

fn metadata(
    file_type: RemoteFileType,
    size: u64,
    modified: smb2::pack::FileTime,
) -> RemoteMetadata {
    let (modified_seconds, modified_nanoseconds) = modified
        .to_system_time()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|duration| (duration.as_secs() as i64, duration.subsec_nanos()))
        .unwrap_or((0, 0));
    let kind = match file_type {
        RemoteFileType::File => "file",
        RemoteFileType::Directory => "directory",
    };
    RemoteMetadata {
        file_type,
        size,
        modified_seconds,
        modified_nanoseconds,
        identity: format!("{kind}:{size}:{}", modified.0),
    }
}

fn storage_error(error: smb2::Error) -> StorageError {
    StorageError::new(smb_errno(&error), format!("SMB operation failed: {error}"))
}

fn smb_errno(error: &smb2::Error) -> libc::c_int {
    if error.status() == Some(smb2::types::status::NtStatus::DIRECTORY_NOT_EMPTY) {
        return libc::ENOTEMPTY;
    }
    if error.status() == Some(smb2::types::status::NtStatus::DELETE_PENDING) {
        return libc::EBUSY;
    }
    match error.kind() {
        ErrorKind::AuthRequired | ErrorKind::SigningRequired | ErrorKind::AccessDenied => {
            libc::EACCES
        }
        ErrorKind::NotFound => libc::ENOENT,
        ErrorKind::AlreadyExists => libc::EEXIST,
        ErrorKind::SharingViolation => libc::EBUSY,
        ErrorKind::IsADirectory => libc::EISDIR,
        ErrorKind::NotADirectory => libc::ENOTDIR,
        ErrorKind::DiskFull => libc::ENOSPC,
        ErrorKind::ConnectionLost => libc::ENETDOWN,
        ErrorKind::TimedOut => libc::ETIMEDOUT,
        ErrorKind::Cancelled => libc::EINTR,
        ErrorKind::SessionExpired => libc::EIO,
        ErrorKind::DfsReferral => libc::EXDEV,
        ErrorKind::InvalidData => libc::EPROTO,
        ErrorKind::TooLarge => libc::EFBIG,
        ErrorKind::Io => match error {
            smb2::Error::Io(error) => error.raw_os_error().unwrap_or(libc::EIO),
            _ => libc::EIO,
        },
        ErrorKind::InvalidName => libc::EINVAL,
        ErrorKind::Unsupported => libc::ENOTSUP,
        _ => libc::EIO,
    }
}

#[cfg(test)]
mod tests;
