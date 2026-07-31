use super::{
    CACHE_ENTRY_LIMIT, CACHE_ENTRY_PREFIX, CACHE_LOCK_FILE, CPU_SUBTYPE_ARM64E, CPU_TYPE_ARM64,
    ExecutableStore, MACH_64_MAGIC,
};
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
    assert_eq!(
        first.file_name(),
        Path::new("/bin/sh").canonicalize().unwrap().file_name()
    );
    assert!(first.is_file());
    assert_ne!(first, Path::new("/bin/sh"));
    assert_eq!(
        ExecutableStore::architectures(&first).unwrap(),
        [ExecutableStore::native_architecture()]
    );
    assert_eq!(
        directory.metadata().unwrap().permissions().mode() & 0o777,
        0o700
    );

    store.finish().unwrap();
    assert!(directory.is_dir());
    assert!(first.is_file());

    let mut reused_store = ExecutableStore::new(directory).unwrap();
    assert_eq!(reused_store.prepare(Path::new("/bin/sh")).unwrap(), first);
    reused_store.finish().unwrap();
    reused_store.finish().unwrap();
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
#[cfg(target_arch = "aarch64")]
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
fn architecture_selection_matches_the_build_target() {
    let architectures = vec!["arm64".to_string(), "x86_64".to_string()];

    let x86 = ExecutableStore::select_architecture("x86_64", &architectures).unwrap();
    let arm = ExecutableStore::select_architecture("arm64", &architectures).unwrap();

    assert_eq!(x86.slice, "x86_64");
    assert!(!x86.rewrite_arm64e);
    assert_eq!(arm.slice, "arm64");
    assert!(!arm.rewrite_arm64e);
}

#[test]
fn arm64e_is_only_an_arm64_fallback() {
    let architectures = vec!["arm64e".to_string()];

    let arm = ExecutableStore::select_architecture("arm64", &architectures).unwrap();

    assert_eq!(arm.slice, "arm64e");
    assert!(arm.rewrite_arm64e);
    assert!(ExecutableStore::select_architecture("x86_64", &architectures).is_err());
}

#[test]
fn executable_store_rejects_a_slice_incompatible_with_the_build_target() {
    let root = TestDirectory::new();
    let source = root.path().join("incompatible-sh");
    let architectures = ExecutableStore::architectures(Path::new("/bin/sh")).unwrap();
    let Some(incompatible) = architectures.into_iter().find(|architecture| {
        ExecutableStore::select_architecture(
            ExecutableStore::native_architecture(),
            std::slice::from_ref(architecture),
        )
        .is_err()
    }) else {
        return;
    };
    let status = Command::new("/usr/bin/lipo")
        .args(["/bin/sh", "-thin", &incompatible, "-output"])
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
            .contains("incompatible with sandbox build target")
    );
}

#[test]
fn executable_store_reports_directory_creation_and_finish_errors() {
    let root = TestDirectory::new();
    let parent_file = root.path().join("not-a-directory");
    fs::write(&parent_file, b"file").unwrap();
    assert!(ExecutableStore::new(parent_file.join("prepared")).is_err());

    let directory = root.path().join("prepared");
    let mut store = ExecutableStore::new(directory.clone()).unwrap();
    fs::remove_file(directory.join(CACHE_LOCK_FILE)).unwrap();
    fs::remove_dir(&directory).unwrap();
    fs::write(&directory, b"not a directory").unwrap();
    assert!(
        store
            .finish()
            .unwrap_err()
            .to_string()
            .contains("failed to read")
    );
}

#[test]
fn executable_store_reports_cache_entry_access_errors() {
    let root = TestDirectory::new();
    let lock_directory = root.path().join("lock-directory");
    fs::create_dir(&lock_directory).unwrap();
    fs::create_dir(lock_directory.join(CACHE_LOCK_FILE)).unwrap();
    assert!(
        ExecutableStore::new(lock_directory)
            .err()
            .unwrap()
            .to_string()
            .contains("failed to open sandbox executable cache lock")
    );

    let source = Path::new("/bin/sh").canonicalize().unwrap();
    let directory = root.path().join("remove-error");
    let mut store = ExecutableStore::new(directory.clone()).unwrap();
    let destination = store.destination(&source, &source.metadata().unwrap());
    fs::create_dir(destination.parent().unwrap()).unwrap();
    fs::write(&destination, b"invalid").unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();
    assert!(
        store
            .prepare(&source)
            .unwrap_err()
            .to_string()
            .contains("failed to replace invalid sandbox executable cache entry")
    );
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();

    let directory = root.path().join("inspect-error");
    let mut store = ExecutableStore::new(directory.clone()).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o000)).unwrap();
    assert!(
        store
            .prepare(&source)
            .unwrap_err()
            .to_string()
            .contains("failed to inspect sandbox executable cache entry")
    );
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn executable_store_reports_temporary_directory_creation_failure_without_artifacts() {
    let root = TestDirectory::new();
    let source = root.path().join("native-sh");
    let architectures = ExecutableStore::architectures(Path::new("/bin/sh")).unwrap();
    let selected = ExecutableStore::select_architecture(
        ExecutableStore::native_architecture(),
        &architectures,
    )
    .unwrap();
    let status = Command::new("/usr/bin/lipo")
        .args(["/bin/sh", "-thin", &selected.slice, "-output"])
        .arg(&source)
        .status()
        .unwrap();
    assert!(status.success());
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let directory = root.path().join("copy-error");
    let mut store = ExecutableStore::new(directory.clone()).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();

    assert!(
        store
            .prepare(&source)
            .unwrap_err()
            .to_string()
            .contains("failed to create temporary sandbox executable directory")
    );
    assert_eq!(fs::read_dir(&directory).unwrap().count(), 1);
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
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
fn destination_names_are_stable_and_preserve_the_basename() {
    let root = TestDirectory::new();
    let store = ExecutableStore::new(root.path().join("prepared")).unwrap();
    let source = root.path().join("a name!");
    fs::write(&source, b"executable").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let metadata = source.metadata().unwrap();

    let first = store.destination(&source, &metadata);
    let second = store.destination(&source, &metadata);

    assert_eq!(first, second);
    assert_eq!(first.file_name().unwrap(), "a name!");
    assert!(
        first
            .parent()
            .unwrap()
            .file_name()
            .unwrap()
            .to_string_lossy()
            .starts_with(CACHE_ENTRY_PREFIX)
    );
}

#[test]
fn executable_store_replaces_invalid_cache_files_and_rejects_non_files() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let mut store = ExecutableStore::new(directory).unwrap();
    let source = Path::new("/bin/sh").canonicalize().unwrap();
    let destination = store.destination(&source, &source.metadata().unwrap());
    fs::create_dir(destination.parent().unwrap()).unwrap();
    fs::write(&destination, b"invalid").unwrap();

    assert_eq!(store.prepare(&source).unwrap(), destination);
    assert_ne!(fs::read(&destination).unwrap(), b"invalid");

    fs::remove_file(&destination).unwrap();
    assert_eq!(store.prepare(&source).unwrap(), destination);
    assert!(destination.is_file());

    fs::remove_dir_all(destination.parent().unwrap()).unwrap();
    fs::create_dir_all(&destination).unwrap();
    assert!(
        store
            .prepare(&source)
            .unwrap_err()
            .to_string()
            .contains("cache entry is not a file")
    );
}

#[test]
fn executable_store_prunes_only_after_the_last_running_store_finishes() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let mut first = ExecutableStore::new(directory.clone()).unwrap();
    let mut second = ExecutableStore::new(directory.clone()).unwrap();
    for index in 0..CACHE_ENTRY_LIMIT + 2 {
        fs::create_dir(directory.join(format!("{CACHE_ENTRY_PREFIX}test-{index}"))).unwrap();
    }
    fs::write(directory.join("unrelated"), b"keep").unwrap();

    first.finish().unwrap();
    assert_eq!(cache_entry_count(&directory), CACHE_ENTRY_LIMIT + 2);

    second.finish().unwrap();
    assert_eq!(cache_entry_count(&directory), CACHE_ENTRY_LIMIT);
    assert!(directory.join("unrelated").is_file());
}

#[test]
fn executable_store_reports_cache_pruning_errors() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let mut store = ExecutableStore::new(directory.clone()).unwrap();
    for index in 0..CACHE_ENTRY_LIMIT + 1 {
        fs::create_dir(directory.join(format!("{CACHE_ENTRY_PREFIX}test-{index}"))).unwrap();
    }
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();

    assert!(
        store
            .finish()
            .unwrap_err()
            .to_string()
            .contains("failed to prune sandbox executable cache entry")
    );
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
}

fn cache_entry_count(directory: &Path) -> usize {
    fs::read_dir(directory)
        .unwrap()
        .filter_map(Result::ok)
        .filter(|entry| {
            entry
                .file_name()
                .to_str()
                .is_some_and(|name| name.starts_with(CACHE_ENTRY_PREFIX))
        })
        .count()
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
    let absolute_path = BTreeMap::from([(OsString::from("PATH"), OsString::from("/bin"))]);
    assert_eq!(
        resolve_executable(OsStr::new("sh"), Some(root.path()), &absolute_path).unwrap(),
        PathBuf::from("/bin/sh")
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
