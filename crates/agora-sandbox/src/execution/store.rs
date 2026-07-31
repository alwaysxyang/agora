use anyhow::{Context, Result, bail};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use uuid::Uuid;

const MACH_64_MAGIC: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const CACHE_ENTRY_PREFIX: &str = "cache-v1-";
const CACHE_ENTRY_LIMIT: usize = 10;
const CACHE_LOCK_FILE: &str = ".lock";

#[derive(Debug, PartialEq, Eq)]
struct ArchitectureSelection {
    slice: String,
    rewrite_arm64e: bool,
}

pub(super) struct ExecutableStore {
    directory: PathBuf,
    lock: File,
    shared_lock_held: bool,
}

impl ExecutableStore {
    pub(super) fn new(directory: PathBuf) -> Result<Self> {
        fs::create_dir_all(&directory).with_context(|| {
            format!(
                "failed to create sandbox executable directory {}",
                directory.display()
            )
        })?;
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).with_context(|| {
            format!(
                "failed to secure sandbox executable directory {}",
                directory.display()
            )
        })?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join(CACHE_LOCK_FILE))
            .with_context(|| {
                format!(
                    "failed to open sandbox executable cache lock {}",
                    directory.display()
                )
            })?;
        Self::flock(&lock, libc::LOCK_SH).with_context(|| {
            format!(
                "failed to lock sandbox executable cache {}",
                directory.display()
            )
        })?;
        Ok(Self {
            directory,
            lock,
            shared_lock_held: true,
        })
    }

    pub(super) fn prepare(&mut self, source: &Path) -> Result<PathBuf> {
        let source = source
            .canonicalize()
            .with_context(|| format!("failed to resolve executable {}", source.display()))?;
        let metadata = Self::validate_source(&source)?;
        let destination = self.destination(&source, &metadata);
        match destination.symlink_metadata() {
            Ok(metadata) if metadata.is_file() && metadata.mode() & 0o111 != 0 => {
                return Ok(destination);
            }
            Ok(metadata) if metadata.is_file() => {
                fs::remove_file(&destination).with_context(|| {
                    format!(
                        "failed to replace invalid sandbox executable cache entry {}",
                        destination.display()
                    )
                })?;
            }
            Ok(_) => {
                bail!(
                    "sandbox executable cache entry is not a file: {}",
                    destination.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect sandbox executable cache entry {}",
                        destination.display()
                    )
                });
            }
        }

        let architectures = Self::architectures(&source)?;
        let selected = Self::select_architecture(Self::native_architecture(), &architectures)
            .with_context(|| {
                format!(
                    "executable {} is incompatible with sandbox build target {}",
                    source.display(),
                    Self::native_architecture()
                )
            })?;
        let temporary = self
            .directory
            .join(format!(".tmp-{}", Uuid::new_v4().simple()));
        let prepared: Result<PathBuf> = (|| {
            if architectures.len() == 1 {
                fs::copy(&source, &temporary).with_context(|| {
                    format!(
                        "failed to copy executable {} to {}",
                        source.display(),
                        temporary.display()
                    )
                })?;
            } else {
                Self::run_tool(
                    "/usr/bin/lipo",
                    [
                        source.as_os_str(),
                        OsStr::new("-thin"),
                        OsStr::new(&selected.slice),
                        OsStr::new("-output"),
                        temporary.as_os_str(),
                    ],
                    "failed to extract native executable architecture",
                )?;
            }
            let source_mode = source.metadata()?.mode();
            fs::set_permissions(&temporary, fs::Permissions::from_mode(source_mode | 0o200))?;
            if selected.rewrite_arm64e {
                Self::rewrite_arm64e_subtype(&temporary)?;
            }
            Self::run_tool(
                "/usr/bin/codesign",
                [
                    OsStr::new("--force"),
                    OsStr::new("--sign"),
                    OsStr::new("-"),
                    OsStr::new("--timestamp=none"),
                    temporary.as_os_str(),
                ],
                "failed to ad-hoc sign executable copy",
            )?;
            fs::set_permissions(&temporary, fs::Permissions::from_mode(source_mode))?;
            fs::rename(&temporary, &destination).with_context(|| {
                format!(
                    "failed to publish sandbox executable cache entry {}",
                    destination.display()
                )
            })?;
            Ok(destination.clone())
        })();
        if prepared.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        prepared
    }

    pub(super) fn finish(&mut self) -> Result<()> {
        if !self.shared_lock_held {
            return Ok(());
        }
        Self::flock(&self.lock, libc::LOCK_UN).with_context(|| {
            format!(
                "failed to unlock sandbox executable cache {}",
                self.directory.display()
            )
        })?;
        self.shared_lock_held = false;

        match Self::flock(&self.lock, libc::LOCK_EX | libc::LOCK_NB) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect sandbox executable cache activity {}",
                        self.directory.display()
                    )
                });
            }
        }
        let prune = self.prune();
        let unlock = Self::flock(&self.lock, libc::LOCK_UN).with_context(|| {
            format!(
                "failed to unlock sandbox executable cache cleanup {}",
                self.directory.display()
            )
        });
        prune.and(unlock)
    }

    fn validate_source(source: &Path) -> Result<Metadata> {
        let metadata = source
            .metadata()
            .with_context(|| format!("failed to inspect executable {}", source.display()))?;
        if !metadata.is_file() {
            bail!("sandbox executable is not a file: {}", source.display());
        }
        if metadata.mode() & 0o111 == 0 {
            bail!("sandbox executable is not executable: {}", source.display());
        }
        Ok(metadata)
    }

    fn destination(&self, source: &Path, metadata: &Metadata) -> PathBuf {
        let name = source
            .file_name()
            .unwrap_or_else(|| OsStr::new("executable"))
            .to_string_lossy()
            .chars()
            .map(|value| {
                if value.is_ascii_alphanumeric() || matches!(value, '.' | '-' | '_') {
                    value
                } else {
                    '_'
                }
            })
            .take(48)
            .collect::<String>();
        self.directory.join(format!(
            "{CACHE_ENTRY_PREFIX}{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{:x}-{}-{name}",
            metadata.dev(),
            metadata.ino(),
            metadata.size(),
            metadata.mtime() as u64,
            metadata.mtime_nsec() as u64,
            metadata.ctime() as u64,
            metadata.ctime_nsec() as u64,
            Self::native_architecture(),
        ))
    }

    fn prune(&self) -> Result<()> {
        let mut entries = fs::read_dir(&self.directory)
            .with_context(|| {
                format!(
                    "failed to read sandbox executable cache {}",
                    self.directory.display()
                )
            })?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| name.starts_with(CACHE_ENTRY_PREFIX))
                    && entry.file_type().is_ok_and(|file_type| file_type.is_file())
            })
            .collect::<Vec<_>>();
        if entries.len() <= CACHE_ENTRY_LIMIT {
            return Ok(());
        }
        entries.sort_by_cached_key(|_| Uuid::new_v4());
        let remove = entries.len() - CACHE_ENTRY_LIMIT;
        for entry in entries.into_iter().take(remove) {
            fs::remove_file(entry.path()).with_context(|| {
                format!(
                    "failed to prune sandbox executable cache entry {}",
                    entry.path().display()
                )
            })?;
        }
        Ok(())
    }

    fn flock(file: &File, operation: libc::c_int) -> std::io::Result<()> {
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            Ok(())
        } else {
            Err(std::io::Error::last_os_error())
        }
    }

    fn architectures(source: &Path) -> Result<Vec<String>> {
        let output = Command::new("/usr/bin/lipo")
            .arg("-archs")
            .arg(source)
            .output()
            .with_context(|| format!("failed to inspect Mach-O file {}", source.display()))?;
        let architectures =
            Self::check_output(output, "failed to inspect executable architectures")?;
        Ok(architectures
            .split_ascii_whitespace()
            .map(ToString::to_string)
            .collect())
    }

    fn native_architecture() -> &'static str {
        match std::env::consts::ARCH {
            "aarch64" => "arm64",
            architecture => architecture,
        }
    }

    fn select_architecture(
        target: &str,
        architectures: &[String],
    ) -> Result<ArchitectureSelection> {
        if architectures.iter().any(|value| value == target) {
            return Ok(ArchitectureSelection {
                slice: target.to_string(),
                rewrite_arm64e: false,
            });
        }
        if target == "arm64" && architectures.iter().any(|value| value == "arm64e") {
            return Ok(ArchitectureSelection {
                slice: "arm64e".to_string(),
                rewrite_arm64e: true,
            });
        }
        bail!("no architecture compatible with build target {target}")
    }

    fn rewrite_arm64e_subtype(path: &Path) -> Result<()> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .with_context(|| format!("failed to open executable copy {}", path.display()))?;
        let mut header = [0_u8; 12];
        file.read_exact(&mut header)
            .with_context(|| format!("failed to read Mach-O header {}", path.display()))?;
        let magic = u32::from_le_bytes(header[0..4].try_into().unwrap());
        let cpu_type = u32::from_le_bytes(header[4..8].try_into().unwrap());
        let cpu_subtype = u32::from_le_bytes(header[8..12].try_into().unwrap());
        if magic != MACH_64_MAGIC
            || cpu_type != CPU_TYPE_ARM64
            || cpu_subtype & 0x00ff_ffff != CPU_SUBTYPE_ARM64E
        {
            bail!("extracted executable is not an arm64e Mach-O file");
        }
        file.seek(SeekFrom::Start(8))?;
        file.write_all(&0_u32.to_le_bytes())?;
        file.flush()?;
        Ok(())
    }

    fn run_tool<'a>(
        program: &str,
        arguments: impl IntoIterator<Item = &'a OsStr>,
        context: &'static str,
    ) -> Result<()> {
        let output = Command::new(program)
            .args(arguments)
            .output()
            .with_context(|| context)?;
        Self::check_output(output, context).map(|_| ())
    }

    fn check_output(output: Output, context: &'static str) -> Result<String> {
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
            bail!("{context}: {stderr}");
        }
        String::from_utf8(output.stdout).with_context(|| context)
    }
}

pub(crate) fn resolve_executable(
    program: &OsStr,
    current_dir: Option<&Path>,
    environment: &BTreeMap<OsString, OsString>,
) -> Result<PathBuf> {
    let base = current_dir
        .map(Path::to_path_buf)
        .map(Ok)
        .unwrap_or_else(std::env::current_dir)?;
    if program.as_bytes().contains(&b'/') {
        let path = Path::new(program);
        return Ok(if path.is_absolute() {
            path.to_path_buf()
        } else {
            base.join(path)
        });
    }

    let path = environment
        .get(OsStr::new("PATH"))
        .cloned()
        .or_else(|| std::env::var_os("PATH"))
        .unwrap_or_else(|| OsString::from("/usr/bin:/bin:/usr/sbin:/sbin"));
    for directory in std::env::split_paths(&path) {
        let directory = if directory.as_os_str().is_empty() {
            base.clone()
        } else if directory.is_absolute() {
            directory
        } else {
            base.join(directory)
        };
        let candidate = directory.join(program);
        if candidate
            .metadata()
            .is_ok_and(|metadata| metadata.is_file() && metadata.mode() & 0o111 != 0)
        {
            return Ok(candidate);
        }
    }
    bail!("sandbox executable was not found in PATH: {:?}", program)
}

#[cfg(test)]
mod tests;
