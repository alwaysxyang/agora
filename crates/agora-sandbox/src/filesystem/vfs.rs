#[cfg(test)]
use super::EntryState;
use super::{DirectoryView, FileCipher, OverlayStore, StagedWrite};
use anyhow::{Result, bail};
use std::fs::{File, OpenOptions};
use std::io::{Seek, SeekFrom};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

pub(crate) struct VirtualFilesystem {
    overlay: OverlayStore,
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
    cipher: FileCipher,
    plaintext: Mutex<File>,
}

impl PreparedFile {
    pub(crate) fn target(&self) -> &OpenTarget {
        &self.target
    }

    pub(crate) fn target_mut(&mut self) -> &mut OpenTarget {
        &mut self.target
    }

    pub(crate) fn take_staged(&mut self) -> Option<StagedWrite> {
        self.staged.take()
    }

    pub(crate) fn into_parts(self) -> (OpenTarget, Option<Writeback>, FileLayer) {
        (self.target, self.writeback, self.layer)
    }
}

impl Writeback {
    pub(crate) fn commit(&self, descriptor: libc::c_int) -> Result<()> {
        let _ = descriptor;
        let mut plaintext = self
            .plaintext
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        self.cipher.encrypt(&mut plaintext, &self.destination)
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
        if flags & libc::O_DIRECTORY != 0 {
            return Ok(PreparedFile {
                target: OpenTarget::Path(self.overlay.prepare_directory(logical)?),
                staged: None,
                writeback: None,
                created_mode: None,
                layer: FileLayer::Upper,
            });
        }
        let writes = flags & libc::O_ACCMODE != libc::O_RDONLY
            || flags & (libc::O_CREAT | libc::O_TRUNC) != 0;
        let create = flags & libc::O_CREAT != 0;
        let (mapped, staged, existed) = if writes {
            let existed = self.overlay.exists(logical)?;
            if create && flags & libc::O_EXCL != 0 && existed {
                return Err(std::io::Error::from_raw_os_error(libc::EEXIST).into());
            }
            let staged = self.overlay.stage_write(logical, create)?;
            (staged.destination().to_path_buf(), Some(staged), existed)
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
            (mapped, None, true)
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
            .append(flags & libc::O_APPEND != 0);
        let exposed = exposed.open(plaintext.path())?;
        let mut plaintext = plaintext.into_file();
        if mapped.is_file() {
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
            writeback: writes.then_some(Writeback {
                destination: mapped,
                cipher,
                plaintext: Mutex::new(plaintext),
            }),
            created_mode,
            layer: FileLayer::Upper,
        })
    }

    pub(crate) fn resolve_open_path(&self, logical: &Path, flags: libc::c_int) -> Result<PathBuf> {
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
        if let (OpenTarget::Descriptor(file), Some(writeback)) =
            (&prepared.target, &prepared.writeback)
        {
            writeback.commit(file.as_raw_fd())?;
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

    pub(crate) fn chmod(&self, path: &Path, mode: u32, follow_final: bool) -> Result<()> {
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

    pub(crate) fn rollback_write(&self, staged: StagedWrite) -> Result<()> {
        self.overlay.rollback_write(staged)
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
