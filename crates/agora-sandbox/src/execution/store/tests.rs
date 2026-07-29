use super::{CPU_SUBTYPE_ARM64E, CPU_TYPE_ARM64, ExecutableStore, MACH_64_MAGIC};
use crate::execution::resolve_executable;
use std::collections::BTreeMap;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::Read;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use uuid::Uuid;

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("agora-store-test-{}", Uuid::new_v4()));
        fs::create_dir(&path).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn executable_store_prepares_and_caches_a_native_copy() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let mut store = ExecutableStore::new(directory.clone()).unwrap();

    let first = store.prepare(Path::new("/bin/sh")).unwrap();
    let second = store.prepare(Path::new("/bin/sh")).unwrap();

    assert_eq!(first, second);
    assert!(first.starts_with(&directory));
    assert!(first.is_file());
    assert_ne!(first, Path::new("/bin/sh"));
    assert_eq!(
        directory.metadata().unwrap().permissions().mode() & 0o777,
        0o700
    );

    store.cleanup().unwrap();
    assert!(!directory.exists());
    store.cleanup().unwrap();
}

#[test]
fn executable_store_rejects_non_files_and_non_executable_files() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let mut store = ExecutableStore::new(directory).unwrap();
    let plain = root.path().join("plain");
    fs::write(&plain, b"not executable").unwrap();

    assert!(
        store
            .prepare(root.path())
            .unwrap_err()
            .to_string()
            .contains("not a file")
    );
    assert!(
        store
            .prepare(&plain)
            .unwrap_err()
            .to_string()
            .contains("not executable")
    );
}

#[test]
fn executable_store_rewrites_a_single_arm64e_slice() {
    let root = TestDirectory::new();
    let source = root.path().join("arm64e-sh");
    let status = Command::new("/usr/bin/lipo")
        .args(["/bin/sh", "-thin", "arm64e", "-output"])
        .arg(&source)
        .status()
        .unwrap();
    assert!(status.success());
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let mut store = ExecutableStore::new(root.path().join("prepared")).unwrap();

    let prepared = store.prepare(&source).unwrap();

    assert_eq!(
        ExecutableStore::architectures(&prepared).unwrap(),
        ["arm64"]
    );
}

#[test]
fn executable_store_rejects_an_x86_only_slice() {
    let root = TestDirectory::new();
    let source = root.path().join("x86-sh");
    let status = Command::new("/usr/bin/lipo")
        .args(["/bin/sh", "-thin", "x86_64", "-output"])
        .arg(&source)
        .status()
        .unwrap();
    assert!(status.success());
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let mut store = ExecutableStore::new(root.path().join("prepared")).unwrap();

    let error = store.prepare(&source).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("no supported arm64 architecture")
    );
}

#[test]
fn executable_store_reports_directory_creation_and_cleanup_errors() {
    let root = TestDirectory::new();
    let missing_parent = root.path().join("missing").join("prepared");
    assert!(ExecutableStore::new(missing_parent).is_err());

    let directory = root.path().join("prepared");
    let store = ExecutableStore::new(directory.clone()).unwrap();
    fs::remove_dir(&directory).unwrap();
    fs::write(&directory, b"not a directory").unwrap();
    assert!(
        store
            .cleanup()
            .unwrap_err()
            .to_string()
            .contains("failed to remove")
    );
}

#[test]
fn tool_output_errors_include_stderr_and_reject_invalid_utf8() {
    let failed = Command::new("/bin/sh")
        .args(["-c", "printf denied >&2; exit 7"])
        .output()
        .unwrap();
    assert_eq!(
        ExecutableStore::check_output(failed, "tool failed")
            .unwrap_err()
            .to_string(),
        "tool failed: denied"
    );

    let invalid = Command::new("/bin/sh")
        .args(["-c", "printf '\\377'"])
        .output()
        .unwrap();
    assert!(ExecutableStore::check_output(invalid, "invalid output").is_err());
    assert!(
        ExecutableStore::run_tool(
            "/missing/agora-tool",
            std::iter::empty::<&OsStr>(),
            "missing tool",
        )
        .is_err()
    );
}

#[test]
fn arm64e_rewrite_validates_and_updates_the_mach_header() {
    let root = TestDirectory::new();
    let valid = root.path().join("valid");
    let invalid = root.path().join("invalid");
    let mut header = Vec::new();
    header.extend_from_slice(&MACH_64_MAGIC.to_le_bytes());
    header.extend_from_slice(&CPU_TYPE_ARM64.to_le_bytes());
    header.extend_from_slice(&(0x8000_0000 | CPU_SUBTYPE_ARM64E).to_le_bytes());
    fs::write(&valid, &header).unwrap();
    fs::write(&invalid, [0_u8; 12]).unwrap();

    ExecutableStore::rewrite_arm64e_subtype(&valid).unwrap();
    let mut rewritten = Vec::new();
    fs::File::open(&valid)
        .unwrap()
        .read_to_end(&mut rewritten)
        .unwrap();
    assert_eq!(&rewritten[8..12], &0_u32.to_le_bytes());
    assert!(ExecutableStore::rewrite_arm64e_subtype(&invalid).is_err());
}

#[test]
fn destination_names_are_unique_and_sanitized() {
    let root = TestDirectory::new();
    let mut store = ExecutableStore::new(root.path().join("prepared")).unwrap();

    let first = store.destination(Path::new("/tmp/a name!"));
    let second = store.destination(Path::new("/tmp/a name!"));

    assert_eq!(first.file_name().unwrap(), "00000001-a_name_");
    assert_eq!(second.file_name().unwrap(), "00000002-a_name_");
}

#[test]
fn executable_resolution_supports_direct_relative_and_path_lookup() {
    let root = TestDirectory::new();
    let bin = root.path().join("bin");
    fs::create_dir(&bin).unwrap();
    let executable = bin.join("tool");
    fs::write(&executable, b"tool").unwrap();
    fs::set_permissions(&executable, fs::Permissions::from_mode(0o755)).unwrap();
    let environment = BTreeMap::from([(OsString::from("PATH"), OsString::from("bin:"))]);

    assert_eq!(
        resolve_executable(OsStr::new("tool"), Some(root.path()), &environment).unwrap(),
        executable
    );
    assert_eq!(
        resolve_executable(OsStr::new("./bin/tool"), Some(root.path()), &environment).unwrap(),
        root.path().join("./bin/tool")
    );
    assert_eq!(
        resolve_executable(executable.as_os_str(), None, &environment).unwrap(),
        executable
    );
    assert!(
        resolve_executable(OsStr::new("missing"), Some(root.path()), &environment)
            .unwrap_err()
            .to_string()
            .contains("not found in PATH")
    );
}
