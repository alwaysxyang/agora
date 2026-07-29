use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, HashMap};
use std::ffi::{OsStr, OsString};
use std::fs::{self, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const MACH_64_MAGIC: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64E: u32 = 2;

pub(super) struct ExecutableStore {
    directory: PathBuf,
    prepared: HashMap<PathBuf, PathBuf>,
    next_id: u64,
}

impl ExecutableStore {
    pub(super) fn new(directory: PathBuf) -> Result<Self> {
        fs::create_dir(&directory).with_context(|| {
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
        Ok(Self {
            directory,
            prepared: HashMap::new(),
            next_id: 1,
        })
    }

    pub(super) fn prepare(&mut self, source: &Path) -> Result<PathBuf> {
        let source = source
            .canonicalize()
            .with_context(|| format!("failed to resolve executable {}", source.display()))?;
        Self::validate_source(&source)?;
        if let Some(prepared) = self.prepared.get(&source) {
            return Ok(prepared.clone());
        }

        let architectures = Self::architectures(&source)?;
        let selected = if architectures.iter().any(|value| value == "arm64") {
            "arm64"
        } else if architectures.iter().any(|value| value == "arm64e") {
            "arm64e"
        } else {
            bail!(
                "executable {} has no supported arm64 architecture",
                source.display()
            );
        };
        let destination = self.destination(&source);
        let prepared: Result<PathBuf> = (|| {
            if architectures.len() == 1 {
                fs::copy(&source, &destination).with_context(|| {
                    format!(
                        "failed to copy executable {} to {}",
                        source.display(),
                        destination.display()
                    )
                })?;
            } else {
                Self::run_tool(
                    "/usr/bin/lipo",
                    [
                        source.as_os_str(),
                        OsStr::new("-thin"),
                        OsStr::new(selected),
                        OsStr::new("-output"),
                        destination.as_os_str(),
                    ],
                    "failed to extract native executable architecture",
                )?;
            }
            let source_mode = source.metadata()?.mode();
            fs::set_permissions(
                &destination,
                fs::Permissions::from_mode(source_mode | 0o200),
            )?;
            if selected == "arm64e" {
                Self::rewrite_arm64e_subtype(&destination)?;
            }
            Self::run_tool(
                "/usr/bin/codesign",
                [
                    OsStr::new("--force"),
                    OsStr::new("--sign"),
                    OsStr::new("-"),
                    OsStr::new("--timestamp=none"),
                    destination.as_os_str(),
                ],
                "failed to ad-hoc sign executable copy",
            )?;
            fs::set_permissions(&destination, fs::Permissions::from_mode(source_mode))?;
            Ok(destination.clone())
        })();
        if prepared.is_err() {
            let _ = fs::remove_file(&destination);
        }
        let prepared = prepared?;
        self.prepared.insert(source, prepared.clone());
        Ok(prepared)
    }

    pub(super) fn cleanup(&self) -> Result<()> {
        match fs::remove_dir_all(&self.directory) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error).with_context(|| {
                format!(
                    "failed to remove sandbox executable directory {}",
                    self.directory.display()
                )
            }),
        }
    }

    fn validate_source(source: &Path) -> Result<()> {
        let metadata = source
            .metadata()
            .with_context(|| format!("failed to inspect executable {}", source.display()))?;
        if !metadata.is_file() {
            bail!("sandbox executable is not a file: {}", source.display());
        }
        if metadata.mode() & 0o111 == 0 {
            bail!("sandbox executable is not executable: {}", source.display());
        }
        Ok(())
    }

    fn destination(&mut self, source: &Path) -> PathBuf {
        let id = self.next_id;
        self.next_id += 1;
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
            .collect::<String>();
        self.directory.join(format!("{id:08}-{name}"))
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
