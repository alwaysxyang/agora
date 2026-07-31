use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs::{self, File, Metadata, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::os::macos::fs::MetadataExt as MacMetadataExt;
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::OnceLock;
use uuid::Uuid;

const MACH_64_MAGIC: u32 = 0xfeed_facf;
const CPU_TYPE_ARM64: u32 = 0x0100_000c;
const CPU_SUBTYPE_ARM64E: u32 = 2;
const SF_RESTRICTED: u32 = 0x0008_0000;
const CSR_ALLOW_UNRESTRICTED_FS: libc::c_uint = 1 << 1;
const CS_RESTRICT: u32 = 0x0000_0800;
const CS_REQUIRE_LV: u32 = 0x0000_2000;
const CS_RUNTIME: u32 = 0x0001_0000;
const CS_DYLD_RESTRICTED: u32 = CS_RESTRICT | CS_REQUIRE_LV | CS_RUNTIME;
const MAX_SHEBANG_LINE_SIZE: usize = 1024;
const CACHE_LOCK_FILE: &str = ".lock";
const CHECKSUM_MANIFEST_FILE: &str = "checksums.json";
const CHECKSUM_MANIFEST_TEMP_FILE: &str = ".checksums.json.tmp";
const CHECKSUM_MANIFEST_VERSION: u32 = 1;

#[derive(Debug, PartialEq, Eq)]
struct ArchitectureSelection {
    slice: String,
    rewrite_arm64e: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Shebang {
    pub(crate) interpreter: PathBuf,
    pub(crate) argument: Option<OsString>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ChecksumManifest {
    version: u32,
    files: BTreeMap<String, String>,
}

impl Default for ChecksumManifest {
    fn default() -> Self {
        Self {
            version: CHECKSUM_MANIFEST_VERSION,
            files: BTreeMap::new(),
        }
    }
}

pub(super) struct ExecutableStore {
    directory: PathBuf,
    lock: File,
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
        Ok(Self { directory, lock })
    }

    pub(super) fn prepare(&self, source: &Path) -> Result<PathBuf> {
        let source = source
            .canonicalize()
            .with_context(|| format!("failed to resolve executable {}", source.display()))?;
        let metadata = Self::validate_source(&source)?;
        if resolve_shebang(&source)?.is_some() || !Self::requires_copy(&source, &metadata)? {
            return Ok(source);
        }
        self.prepare_copy(&source, &metadata)
    }

    fn requires_copy(source: &Path, metadata: &Metadata) -> Result<bool> {
        let sip_restricted =
            metadata.st_flags() & SF_RESTRICTED != 0 && sip_restricts_protected_files();
        Ok(sip_restricted || Self::code_signing_flags(source)? & CS_DYLD_RESTRICTED != 0)
    }

    fn code_signing_flags(source: &Path) -> Result<u32> {
        let output = Command::new("/usr/bin/codesign")
            .args(["--display", "--verbose=4"])
            .arg(source)
            .output()
            .context("failed to run codesign while inspecting an executable signature")?;
        if !output.status.success() {
            return Ok(0);
        }
        Self::parse_code_signing_flags(&output.stderr)
            .context("failed to parse executable code signature")
    }

    fn parse_code_signing_flags(details: &[u8]) -> Result<u32> {
        let details = std::str::from_utf8(details)?;
        let flags = details
            .lines()
            .find_map(|line| line.split_once(" flags=0x").map(|(_, flags)| flags))
            .context("codesign output has no CodeDirectory flags")?;
        let end = flags
            .find(|byte: char| !byte.is_ascii_hexdigit())
            .unwrap_or(flags.len());
        u32::from_str_radix(&flags[..end], 16).context("invalid CodeDirectory flags")
    }

    fn prepare_copy(&self, source: &Path, metadata: &Metadata) -> Result<PathBuf> {
        let checksum = Self::checksum(source)?;
        Self::flock(&self.lock, libc::LOCK_EX).with_context(|| {
            format!(
                "failed to lock sandbox executable root {}",
                self.directory.display()
            )
        })?;
        let prepared = self.prepare_locked(source, metadata, &checksum);
        let unlock = Self::flock(&self.lock, libc::LOCK_UN).with_context(|| {
            format!(
                "failed to unlock sandbox executable root {}",
                self.directory.display()
            )
        });
        match prepared {
            Ok(destination) => {
                unlock?;
                Ok(destination)
            }
            Err(error) => {
                let _ = unlock;
                Err(error)
            }
        }
    }

    #[cfg(test)]
    fn prepare_copy_for_test(&self, source: &Path) -> Result<PathBuf> {
        let source = source
            .canonicalize()
            .with_context(|| format!("failed to resolve executable {}", source.display()))?;
        let metadata = Self::validate_source(&source)?;
        self.prepare_copy(&source, &metadata)
    }

    fn prepare_locked(
        &self,
        source: &Path,
        metadata: &Metadata,
        checksum: &str,
    ) -> Result<PathBuf> {
        let destination = self.destination(source)?;
        let parent = destination
            .parent()
            .context("executable destination has no parent")?;
        let key = source.to_string_lossy().into_owned();
        let mut manifest = self.load_manifest(parent)?;
        match destination.symlink_metadata() {
            Ok(metadata) if metadata.is_file() && metadata.mode() & 0o111 != 0 => {
                if manifest
                    .files
                    .get(&key)
                    .is_some_and(|cached| cached == checksum)
                {
                    return Ok(destination);
                }
            }
            Ok(metadata) if metadata.is_file() => {}
            Ok(_) => {
                bail!(
                    "sandbox executable root entry is not a file: {}",
                    destination.display()
                );
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to inspect sandbox executable root entry {}",
                        destination.display()
                    )
                });
            }
        }

        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create sandbox executable mapping directory {}",
                parent.display()
            )
        })?;
        let architectures = Self::architectures(source)?;
        let selected = Self::select_architecture(Self::native_architecture(), &architectures)
            .with_context(|| {
                format!(
                    "executable {} is incompatible with sandbox build target {}",
                    source.display(),
                    Self::native_architecture()
                )
            })?;
        let temporary_id = Uuid::new_v4().simple();
        let temporary = parent.join(format!(".agora-executable-{temporary_id}.tmp"));
        let prepared: Result<PathBuf> = (|| {
            if architectures.len() == 1 {
                fs::copy(source, &temporary).with_context(|| {
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
            let source_mode = metadata.mode();
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
                    "failed to publish sandbox executable {}",
                    destination.display()
                )
            })?;
            manifest.files.insert(key, checksum.to_string());
            self.write_manifest(parent, &manifest)?;
            Ok(destination.clone())
        })();
        if prepared.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        prepared
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

    fn destination(&self, source: &Path) -> Result<PathBuf> {
        let relative = source.strip_prefix(Path::new("/")).with_context(|| {
            format!(
                "sandbox executable path is not absolute: {}",
                source.display()
            )
        })?;
        Ok(self.directory.join(relative))
    }

    fn load_manifest(&self, directory: &Path) -> Result<ChecksumManifest> {
        let path = directory.join(CHECKSUM_MANIFEST_FILE);
        let contents = match fs::read(&path) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(ChecksumManifest::default());
            }
            Err(error) => {
                return Err(error).with_context(|| {
                    format!(
                        "failed to read sandbox executable checksum manifest {}",
                        path.display()
                    )
                });
            }
        };
        let manifest: ChecksumManifest = serde_json::from_slice(&contents).with_context(|| {
            format!(
                "failed to parse sandbox executable checksum manifest {}",
                path.display()
            )
        })?;
        if manifest.version != CHECKSUM_MANIFEST_VERSION {
            bail!(
                "unsupported sandbox executable checksum manifest version {}",
                manifest.version
            );
        }
        Ok(manifest)
    }

    fn write_manifest(&self, directory: &Path, manifest: &ChecksumManifest) -> Result<()> {
        let path = directory.join(CHECKSUM_MANIFEST_FILE);
        let temporary = directory.join(CHECKSUM_MANIFEST_TEMP_FILE);
        let contents = serde_json::to_vec_pretty(manifest)
            .context("failed to serialize sandbox executable checksum manifest")?;
        let written = (|| {
            fs::write(&temporary, contents).with_context(|| {
                format!(
                    "failed to write sandbox executable checksum manifest {}",
                    temporary.display()
                )
            })?;
            fs::rename(&temporary, &path).with_context(|| {
                format!(
                    "failed to publish sandbox executable checksum manifest {}",
                    path.display()
                )
            })?;
            Ok(())
        })();
        if written.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        written
    }

    fn checksum(source: &Path) -> Result<String> {
        let output = Command::new("/sbin/md5")
            .arg("-q")
            .arg(source)
            .output()
            .with_context(|| format!("failed to calculate executable MD5 {}", source.display()))?;
        let checksum = Self::check_output(output, "failed to calculate executable MD5")?;
        let checksum = checksum.trim();
        if checksum.len() != 32 || !checksum.bytes().all(|value| value.is_ascii_hexdigit()) {
            bail!("invalid executable MD5 output for {}", source.display());
        }
        Ok(checksum.to_ascii_lowercase())
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

pub(crate) fn resolve_shebang(path: &Path) -> Result<Option<Shebang>> {
    let mut file = File::open(path)
        .with_context(|| format!("failed to open executable {}", path.display()))?;
    let mut line = [0_u8; MAX_SHEBANG_LINE_SIZE];
    let length = file
        .read(&mut line)
        .with_context(|| format!("failed to read executable {}", path.display()))?;
    let line = &line[..length];
    if !line.starts_with(b"#!") {
        return Ok(None);
    }
    let end = match line.iter().position(|byte| *byte == b'\n') {
        Some(end) => end,
        None if length < MAX_SHEBANG_LINE_SIZE => length,
        None => bail!("executable shebang is too long: {}", path.display()),
    };
    let mut command = &line[2..end];
    if command.last() == Some(&b'\r') {
        command = &command[..command.len() - 1];
    }
    command = trim_ascii_whitespace(command);
    if command.is_empty() {
        bail!("executable shebang has no interpreter: {}", path.display());
    }
    let interpreter_end = command
        .iter()
        .position(|byte| byte.is_ascii_whitespace())
        .unwrap_or(command.len());
    let interpreter = PathBuf::from(OsString::from_vec(command[..interpreter_end].to_vec()));
    if !interpreter.is_absolute() {
        bail!(
            "executable shebang interpreter is not absolute: {}",
            path.display()
        );
    }
    let argument = trim_ascii_whitespace(&command[interpreter_end..]);
    let argument = (!argument.is_empty()).then(|| OsString::from_vec(argument.to_vec()));
    Ok(Some(Shebang {
        interpreter,
        argument,
    }))
}

fn trim_ascii_whitespace(mut value: &[u8]) -> &[u8] {
    while value.first().is_some_and(u8::is_ascii_whitespace) {
        value = &value[1..];
    }
    while value.last().is_some_and(u8::is_ascii_whitespace) {
        value = &value[..value.len() - 1];
    }
    value
}

fn sip_restricts_protected_files() -> bool {
    static RESTRICTED: OnceLock<bool> = OnceLock::new();
    *RESTRICTED.get_or_init(|| unsafe { csr_check(CSR_ALLOW_UNRESTRICTED_FS) != 0 })
}

unsafe extern "C" {
    fn csr_check(mask: libc::c_uint) -> libc::c_int;
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
