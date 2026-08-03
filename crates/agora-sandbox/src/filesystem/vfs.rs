#[cfg(test)]
use super::EntryState;
use super::{DirectoryView, FileCipher, OverlayStore, StagedWrite};
use anyhow::{Context, Result, bail};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) struct VirtualFilesystem {
    overlay: OverlayStore,
}

pub(crate) struct Credentials {
    uid: libc::uid_t,
    gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
}

pub(crate) enum OpenTarget {
    Path(PathBuf),
    Descriptor(File),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileLayer {
    Lower,
    Upper,
}

pub(crate) struct PreparedFile {
    target: OpenTarget,
    staged: Option<StagedWrite>,
    writeback: Option<Writeback>,
    created_mode: Option<u32>,
    layer: FileLayer,
}

pub(crate) struct Writeback {
    destination: PathBuf,
    plaintext: Mutex<File>,
    _lease: File,
}

impl PreparedFile {
    pub(crate) fn target(&self) -> &OpenTarget {
        &self.target
    }

    pub(crate) fn target_mut(&mut self) -> &mut OpenTarget {
        &mut self.target
    }

    pub(crate) fn into_parts(self) -> (OpenTarget, Option<Writeback>, FileLayer) {
        (self.target, self.writeback, self.layer)
    }
}

impl Credentials {
    pub(crate) fn real() -> Self {
        Self::current(unsafe { libc::getuid() }, unsafe { libc::getgid() })
    }

    pub(crate) fn effective() -> Self {
        Self::current(unsafe { libc::geteuid() }, unsafe { libc::getegid() })
    }

    fn current(uid: libc::uid_t, gid: libc::gid_t) -> Self {
        let count = unsafe { libc::getgroups(0, std::ptr::null_mut()) };
        let mut groups = if count > 0 {
            vec![0; count as usize]
        } else {
            Vec::new()
        };
        if count > 0 {
            let actual = unsafe { libc::getgroups(count, groups.as_mut_ptr()) };
            if actual >= 0 {
                groups.truncate(actual as usize);
            } else {
                groups.clear();
            }
        }
        Self { uid, gid, groups }
    }

    #[cfg(test)]
    fn for_test(uid: libc::uid_t, gid: libc::gid_t, groups: &[libc::gid_t]) -> Self {
        Self {
            uid,
            gid,
            groups: groups.to_vec(),
        }
    }

    pub(crate) fn allows(
        &self,
        attributes: &super::FileAttributes,
        requested: libc::c_int,
    ) -> bool {
        if requested == libc::F_OK {
            return true;
        }
        if self.uid == 0 {
            return requested & libc::X_OK == 0 || attributes.mode & 0o111 != 0;
        }
        let shift = if self.uid == attributes.uid {
            6
        } else if self.gid == attributes.gid || self.groups.contains(&attributes.gid) {
            3
        } else {
            0
        };
        let allowed = (attributes.mode >> shift) & 0o7;
        (requested & libc::R_OK == 0 || allowed & 0o4 != 0)
            && (requested & libc::W_OK == 0 || allowed & 0o2 != 0)
            && (requested & libc::X_OK == 0 || allowed & 0o1 != 0)
    }

    fn can_chmod(&self, attributes: &super::FileAttributes) -> bool {
        self.uid == 0 || self.uid == attributes.uid
    }
}

impl VirtualFilesystem {
    pub(crate) fn plain(root: impl Into<PathBuf>) -> Result<Self> {
        Ok(Self {
            overlay: OverlayStore::new(root)?,
        })
    }

    pub(crate) fn encrypted(root: impl Into<PathBuf>, cipher: FileCipher) -> Result<Self> {
        Ok(Self {
            overlay: OverlayStore::encrypted(root, cipher)?,
        })
    }

    pub(crate) fn prepare_open(
        &self,
        logical: &Path,
        flags: libc::c_int,
        mode: u32,
    ) -> Result<PreparedFile> {
        Self::validate_open_flags(flags)?;
        if flags & libc::O_DIRECTORY != 0 {
            let target = self.overlay.prepare_directory(logical)?;
            let layer = if self.overlay.is_internal(&target) {
                FileLayer::Upper
            } else {
                FileLayer::Lower
            };
            return Ok(PreparedFile {
                target: OpenTarget::Path(target),
                staged: None,
                writeback: None,
                created_mode: None,
                layer,
            });
        }
        let writes = flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_CREAT | libc::O_TRUNC) != 0;
        let create = flags & libc::O_CREAT != 0;
        let (mapped, staged, existed, lease) = if writes {
            let (staged, existed, lease) =
                self.overlay
                    .stage_file_open(logical, create, flags & libc::O_EXCL != 0)?;
            (
                staged.destination().to_path_buf(),
                Some(staged),
                existed,
                lease,
            )
        } else {
            let mapped = self.overlay.prepare_read(logical)?;
            if !self.overlay.is_internal(&mapped) {
                return Ok(PreparedFile {
                    target: OpenTarget::Path(mapped),
                    staged: None,
                    writeback: None,
                    created_mode: None,
                    layer: FileLayer::Lower,
                });
            }
            (mapped, None, true, None)
        };
        if !self.overlay.is_internal(&mapped) {
            return Ok(PreparedFile {
                target: OpenTarget::Path(mapped),
                staged,
                writeback: None,
                created_mode: None,
                layer: FileLayer::Lower,
            });
        }
        let Some(cipher) = self.overlay.cipher().cloned() else {
            return Ok(PreparedFile {
                target: OpenTarget::Path(mapped),
                staged,
                writeback: None,
                created_mode: None,
                layer: FileLayer::Upper,
            });
        };
        if mapped.exists() && !mapped.symlink_metadata()?.is_file() {
            return Ok(PreparedFile {
                target: OpenTarget::Path(mapped),
                staged,
                writeback: None,
                created_mode: None,
                layer: FileLayer::Upper,
            });
        }

        let created_mode = (create && !existed)
            .then(|| Self::effective_creation_mode(mode))
            .transpose()?;
        let plaintext = tempfile::NamedTempFile::new()?;
        let access = flags & libc::O_ACCMODE;
        let mut exposed = OpenOptions::new();
        exposed
            .read(access != libc::O_WRONLY)
            .write(access != libc::O_RDONLY)
            .append(flags & libc::O_APPEND != 0)
            .custom_flags(libc::O_CLOEXEC);
        let exposed = exposed.open(plaintext.path())?;
        let mut plaintext = plaintext.into_file();
        if existed && mapped.is_file() {
            cipher.decrypt(&mapped, &mut plaintext)?;
        } else if !create {
            bail!("filesystem path is not visible: {}", logical.display());
        }
        if flags & libc::O_TRUNC != 0 {
            plaintext.set_len(0)?;
        }
        if flags & libc::O_APPEND != 0 {
            plaintext.seek(SeekFrom::End(0))?;
        } else {
            plaintext.seek(SeekFrom::Start(0))?;
        }
        Ok(PreparedFile {
            target: OpenTarget::Descriptor(exposed),
            staged,
            writeback: if writes {
                Some(Writeback {
                    destination: mapped,
                    plaintext: Mutex::new(plaintext),
                    _lease: lease.context("encrypted write open did not acquire a lease")?,
                })
            } else {
                None
            },
            created_mode,
            layer: FileLayer::Upper,
        })
    }

    pub(crate) fn resolve_open_path(&self, logical: &Path, flags: libc::c_int) -> Result<PathBuf> {
        Self::validate_open_flags(flags)?;
        let no_follow = flags & libc::O_NOFOLLOW != 0
            || flags & (libc::O_CREAT | libc::O_EXCL) == (libc::O_CREAT | libc::O_EXCL);
        if no_follow {
            Ok(logical.to_path_buf())
        } else {
            self.overlay
                .resolve_final(logical, flags & libc::O_CREAT != 0)
        }
    }

    pub(crate) fn commit_open(&self, prepared: &mut PreparedFile) -> Result<()> {
        if let Some(writeback) = &prepared.writeback {
            self.commit_writeback(writeback)?;
        }
        if let Some(staged) = prepared.staged.take() {
            if let Some(mode) = prepared.created_mode.take() {
                self.overlay.commit_created_file(staged, mode)?;
            } else {
                self.overlay.commit_write(staged)?;
            }
        }
        Ok(())
    }

    pub(crate) fn commit_writeback(&self, writeback: &Writeback) -> Result<()> {
        let mut plaintext = writeback
            .plaintext
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.overlay
            .publish_encrypted(&mut plaintext, &writeback.destination)
    }

    #[cfg(test)]
    pub(crate) fn root(&self) -> &Path {
        self.overlay.root()
    }

    pub(crate) fn is_internal(&self, path: &Path) -> bool {
        self.overlay.is_internal(path)
    }

    pub(crate) fn is_private(&self, path: &Path) -> Result<bool> {
        self.overlay.is_private(path)
    }

    pub(crate) fn logical_path(&self, path: &Path) -> Result<PathBuf> {
        self.overlay.logical_path(path)
    }

    #[cfg(test)]
    pub(crate) fn prepare_read(&self, path: &Path) -> Result<PathBuf> {
        self.overlay.prepare_read(path)
    }

    pub(crate) fn prepare_metadata(
        &self,
        path: &Path,
        follow_final: bool,
    ) -> Result<(PathBuf, Option<u64>, PathBuf)> {
        let logical = if follow_final {
            self.overlay.resolve_final(path, false)?
        } else {
            path.to_path_buf()
        };
        let mapped = self.overlay.prepare_read(&logical)?;
        let Some(cipher) = self
            .overlay
            .cipher()
            .filter(|_| self.overlay.is_internal(&mapped))
        else {
            return Ok((mapped, None, logical));
        };
        if !mapped.symlink_metadata()?.is_file() {
            return Ok((mapped, None, logical));
        }

        let mut plaintext = tempfile::tempfile()?;
        cipher.decrypt(&mapped, &mut plaintext)?;
        let size = plaintext.metadata()?.len();
        Ok((mapped, Some(size), logical))
    }

    pub(crate) fn attributes(&self, path: &Path) -> Result<Option<super::FileAttributes>> {
        self.overlay.attributes(path)
    }

    pub(crate) fn exists(&self, path: &Path) -> Result<bool> {
        self.overlay.exists(path)
    }

    fn is_symlink(&self, path: &Path) -> Result<bool> {
        Ok(self
            .overlay
            .prepare_read(path)?
            .symlink_metadata()?
            .file_type()
            .is_symlink())
    }

    fn effective_attributes(&self, path: &Path) -> Result<super::FileAttributes> {
        let logical = self.overlay.resolve_final(path, false)?;
        if let Some(attributes) = self.overlay.attributes(&logical)? {
            return Ok(attributes);
        }
        let mapped = self.overlay.prepare_read(&logical)?;
        Ok(super::FileAttributes::from_metadata(&mapped.metadata()?))
    }

    pub(crate) fn require_access(
        &self,
        path: &Path,
        requested: libc::c_int,
        credentials: &Credentials,
    ) -> Result<()> {
        let attributes = self.effective_attributes(path)?;
        if credentials.allows(&attributes, requested) {
            Ok(())
        } else {
            Err(std::io::Error::from_raw_os_error(libc::EACCES).into())
        }
    }

    pub(crate) fn require_search(&self, path: &Path, credentials: &Credentials) -> Result<()> {
        let Some(parent) = path.parent() else {
            return Ok(());
        };
        for ancestor in parent.ancestors().collect::<Vec<_>>().into_iter().rev() {
            self.require_access(ancestor, libc::X_OK, credentials)?;
        }
        Ok(())
    }

    pub(crate) fn require_parent_mutation(
        &self,
        path: &Path,
        credentials: &Credentials,
    ) -> Result<()> {
        let parent = path
            .parent()
            .context("filesystem mutation path has no parent")?;
        self.require_search(parent, credentials)?;
        self.require_access(parent, libc::W_OK | libc::X_OK, credentials)
    }

    pub(crate) fn validate_open_permissions(
        &self,
        logical: &Path,
        flags: libc::c_int,
        requested: libc::c_int,
        credentials: &Credentials,
    ) -> Result<()> {
        self.require_search(logical, credentials)?;
        if self.exists(logical)? {
            if flags & (libc::O_CREAT | libc::O_EXCL) == libc::O_CREAT | libc::O_EXCL {
                return Err(std::io::Error::from_raw_os_error(libc::EEXIST).into());
            }
            if flags & libc::O_NOFOLLOW == 0 || !self.is_symlink(logical)? {
                self.require_access(logical, requested, credentials)?;
            }
        } else if flags & libc::O_CREAT != 0 {
            self.require_parent_mutation(logical, credentials)?;
        }
        Ok(())
    }

    pub(crate) fn chmod(
        &self,
        path: &Path,
        mode: u32,
        follow_final: bool,
        credentials: &Credentials,
    ) -> Result<()> {
        self.require_search(path, credentials)?;
        let logical = if follow_final {
            self.overlay.resolve_final(path, false)?
        } else {
            path.to_path_buf()
        };
        let mapped = self.overlay.prepare_read(&logical)?;
        let mut attributes = match self.overlay.attributes(&logical)? {
            Some(attributes) => attributes,
            None => super::FileAttributes::from_metadata(&mapped.symlink_metadata()?),
        };
        if !credentials.can_chmod(&attributes) {
            return Err(std::io::Error::from_raw_os_error(libc::EPERM).into());
        }
        attributes.mode = attributes.mode & !0o7777 | mode & 0o7777;
        self.overlay.set_attributes(&logical, attributes)
    }

    pub(crate) fn set_attributes(
        &self,
        path: &Path,
        attributes: super::FileAttributes,
    ) -> Result<()> {
        self.overlay.set_attributes(path, attributes)
    }

    pub(crate) fn refresh_timestamps(&self, path: &Path, status: &libc::stat) -> Result<()> {
        let mut attributes = match self.overlay.attributes(path)? {
            Some(attributes) => attributes,
            None => super::FileAttributes::from_stat(status),
        };
        attributes.refresh_timestamps(status);
        self.overlay.set_attributes(path, attributes)
    }

    #[cfg(test)]
    pub(crate) fn prepare_write(&self, path: &Path, create: bool) -> Result<PathBuf> {
        self.overlay.prepare_write(path, create)
    }

    pub(crate) fn stage_write(&self, path: &Path, create: bool) -> Result<StagedWrite> {
        self.overlay.stage_write(path, create)
    }

    pub(crate) fn commit_write(&self, staged: StagedWrite) -> Result<()> {
        self.overlay.commit_write(staged)
    }

    pub(crate) fn prepare_directory(&self, path: &Path) -> Result<PathBuf> {
        self.overlay.prepare_directory(path)
    }

    pub(crate) fn directory_view(&self, path: &Path) -> Result<DirectoryView> {
        self.overlay.directory_view(path)
    }

    pub(crate) fn create_directory(&self, path: &Path, mode: u32) -> Result<PathBuf> {
        self.overlay
            .create_directory(path, Self::effective_creation_mode(mode)?)
    }

    pub(crate) fn remove(&self, path: &Path, directory: bool) -> Result<()> {
        self.overlay.remove(path, directory)
    }

    pub(crate) fn rename(&self, from: &Path, to: &Path) -> Result<()> {
        self.overlay.rename(from, to)
    }

    fn validate_open_flags(flags: libc::c_int) -> Result<()> {
        if flags & (libc::O_NOFOLLOW_ANY | libc::O_SYMLINK) != 0 {
            return Err(std::io::Error::from_raw_os_error(libc::ENOTSUP).into());
        }
        Ok(())
    }

    fn effective_creation_mode(mode: u32) -> Result<u32> {
        let probe = tempfile::Builder::new()
            .permissions(std::fs::Permissions::from_mode(mode))
            .tempfile()?;
        Ok(probe.as_file().metadata()?.permissions().mode() & 0o7777)
    }

    #[cfg(test)]
    pub(crate) fn state_for_test(&self, path: &Path) -> Result<Option<EntryState>> {
        self.overlay.state_for_test(path)
    }
}

#[cfg(test)]
mod tests;
