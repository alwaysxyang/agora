use super::{
    CACHE_LOCK_FILE, CHECKSUM_MANIFEST_FILE, CHECKSUM_MANIFEST_TEMP_FILE, CPU_SUBTYPE_ARM64E,
    CPU_TYPE_ARM64, CS_DYLD_RESTRICTED, CS_RUNTIME, ExecutableStore, MACH_64_MAGIC,
    resolve_shebang,
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
    let store = ExecutableStore::new(directory.clone()).unwrap();

    let first = store.prepare(Path::new("/bin/sh")).unwrap();
    let second = store.prepare(Path::new("/bin/sh")).unwrap();

    assert_eq!(first, second);
    assert_eq!(first, directory.join("bin/sh"));
    assert!(manifest_path(&directory, Path::new("/bin/sh")).is_file());
    assert!(!directory.join(CHECKSUM_MANIFEST_FILE).exists());
    assert_eq!(
        manifest_checksum(&directory, Path::new("/bin/sh")),
        ExecutableStore::checksum(&Path::new("/bin/sh").canonicalize().unwrap()).unwrap()
    );
    assert!(!first.with_extension("md5").exists());
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

    assert!(directory.is_dir());
    assert!(first.is_file());

    let reused_store = ExecutableStore::new(directory).unwrap();
    assert_eq!(reused_store.prepare(Path::new("/bin/sh")).unwrap(), first);
}

#[test]
fn executable_store_keeps_unrestricted_binaries_and_scripts_at_their_original_paths() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let store = ExecutableStore::new(directory.clone()).unwrap();
    let binary = std::env::current_exe().unwrap().canonicalize().unwrap();

    assert_eq!(store.prepare(&binary).unwrap(), binary);

    let script = root.path().join("client");
    fs::write(&script, b"#!/usr/bin/env node\r\nconsole.log('ok')\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
    let script = script.canonicalize().unwrap();
    let shebang = resolve_shebang(&script).unwrap().unwrap();

    assert_eq!(shebang.interpreter, Path::new("/usr/bin/env"));
    assert_eq!(shebang.argument.as_deref(), Some(OsStr::new("node")));
    assert_eq!(store.prepare(&script).unwrap(), script);
    assert!(!store.destination(&script).unwrap().exists());
    assert_eq!(fs::read_dir(directory).unwrap().count(), 1);
}

#[test]
fn executable_store_copies_hardened_runtime_binaries() {
    let root = TestDirectory::new();
    let source = root.path().join("hardened-sh");
    fs::copy("/bin/sh", &source).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let status = Command::new("/usr/bin/codesign")
        .args(["--force", "--sign", "-", "--options", "runtime"])
        .arg(&source)
        .status()
        .unwrap();
    assert!(status.success());
    assert_ne!(
        ExecutableStore::code_signing_flags(&source).unwrap() & CS_DYLD_RESTRICTED,
        0
    );
    let store = ExecutableStore::new(root.path().join("prepared")).unwrap();

    let prepared = store.prepare(&source).unwrap();

    assert_ne!(prepared, source);
    assert_eq!(
        ExecutableStore::code_signing_flags(&prepared).unwrap() & CS_DYLD_RESTRICTED,
        0
    );
}

#[test]
fn code_signing_flags_parser_reads_the_runtime_bit() {
    assert_eq!(
        ExecutableStore::parse_code_signing_flags(
            b"CodeDirectory v=20500 size=42 flags=0x10002(adhoc,runtime) hashes=1+0\n"
        )
        .unwrap(),
        CS_RUNTIME | 2
    );
    assert!(ExecutableStore::parse_code_signing_flags(b"unsigned").is_err());
}

#[test]
fn shebang_parser_handles_optional_arguments_and_rejects_invalid_interpreters() {
    let root = TestDirectory::new();
    let script = root.path().join("script");

    fs::write(&script, b"plain text\n").unwrap();
    assert!(resolve_shebang(&script).unwrap().is_none());

    fs::write(&script, b"#!  /bin/sh  \t").unwrap();
    let shebang = resolve_shebang(&script).unwrap().unwrap();
    assert_eq!(shebang.interpreter, Path::new("/bin/sh"));
    assert!(shebang.argument.is_none());

    fs::write(&script, b"#!\n").unwrap();
    assert!(
        resolve_shebang(&script)
            .unwrap_err()
            .to_string()
            .contains("has no interpreter")
    );

    fs::write(&script, b"#!env node\n").unwrap();
    assert!(
        resolve_shebang(&script)
            .unwrap_err()
            .to_string()
            .contains("interpreter is not absolute")
    );

    let mut long = b"#!".to_vec();
    long.resize(super::MAX_SHEBANG_LINE_SIZE, b'x');
    fs::write(&script, long).unwrap();
    assert!(
        resolve_shebang(&script)
            .unwrap_err()
            .to_string()
            .contains("shebang is too long")
    );
}

#[test]
fn executable_store_rejects_non_files_and_non_executable_files() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let store = ExecutableStore::new(directory.clone()).unwrap();
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
    let store = ExecutableStore::new(root.path().join("prepared")).unwrap();

    let prepared = store.prepare_copy_for_test(&source).unwrap();

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
    let store = ExecutableStore::new(root.path().join("prepared")).unwrap();

    let error = store.prepare_copy_for_test(&source).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("incompatible with sandbox build target")
    );
}

#[test]
fn executable_store_reports_directory_creation_errors() {
    let root = TestDirectory::new();
    let parent_file = root.path().join("not-a-directory");
    fs::write(&parent_file, b"file").unwrap();
    assert!(ExecutableStore::new(parent_file.join("prepared")).is_err());
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
    let store = ExecutableStore::new(directory.clone()).unwrap();
    let destination = store.destination(&source).unwrap();
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::write(&destination, b"invalid").unwrap();
    fs::set_permissions(
        destination.parent().unwrap(),
        fs::Permissions::from_mode(0o500),
    )
    .unwrap();
    let error = store.prepare(&source).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to extract native executable architecture"),
        "{error:#}"
    );
    fs::set_permissions(
        destination.parent().unwrap(),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();

    let directory = root.path().join("inspect-error");
    let store = ExecutableStore::new(directory.clone()).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o000)).unwrap();
    let error = store.prepare(&source).unwrap_err();
    assert!(
        error
            .to_string()
            .contains("failed to read sandbox executable checksum manifest"),
        "{error:#}"
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
    let store = ExecutableStore::new(directory.clone()).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o500)).unwrap();

    assert!(
        store
            .prepare_copy_for_test(&source)
            .unwrap_err()
            .to_string()
            .contains("failed to create sandbox executable mapping directory")
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
fn destination_mirrors_the_absolute_source_path() {
    let root = TestDirectory::new();
    let store = ExecutableStore::new(root.path().join("prepared")).unwrap();
    let source = root.path().join("a name!");
    fs::write(&source, b"executable").unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let first = store.destination(&source).unwrap();
    let second = store.destination(&source).unwrap();

    assert_eq!(first, second);
    assert_eq!(
        first,
        store
            .directory
            .join(source.strip_prefix(Path::new("/")).unwrap())
    );
}

#[test]
fn missing_cached_executable_maps_back_to_its_original_source() {
    let root = TestDirectory::new();
    let store = ExecutableStore::new(root.path().join("prepared")).unwrap();
    let cached = store.directory.join("bin/sh");
    assert!(!cached.exists());

    let prepared = store.prepare(&cached).unwrap();

    assert_eq!(prepared, cached);
    assert!(prepared.is_file());
    assert_eq!(
        manifest_file_count(&manifest_path(&store.directory, Path::new("/bin/sh"))),
        1
    );
}

#[test]
fn executable_store_preserves_non_missing_resolution_errors() {
    let root = TestDirectory::new();
    let store = ExecutableStore::new(root.path().join("prepared")).unwrap();
    let looped = root.path().join("loop");
    std::os::unix::fs::symlink(&looped, &looped).unwrap();

    let error = store.resolve_source(&looped).unwrap_err();

    assert_eq!(
        error
            .chain()
            .find_map(|cause| cause.downcast_ref::<std::io::Error>())
            .and_then(std::io::Error::raw_os_error),
        Some(libc::ELOOP)
    );
    assert!(error.to_string().contains("failed to resolve executable"));
}

#[test]
fn executable_store_keeps_a_checksum_manifest_in_each_mapped_directory() {
    let root = TestDirectory::new();
    let source_a = root.path().join("source-a/tool");
    let source_b = root.path().join("source-b/tool");
    fs::create_dir_all(source_a.parent().unwrap()).unwrap();
    fs::create_dir_all(source_b.parent().unwrap()).unwrap();
    fs::copy("/bin/sh", &source_a).unwrap();
    fs::copy("/bin/sh", &source_b).unwrap();
    fs::set_permissions(&source_a, fs::Permissions::from_mode(0o755)).unwrap();
    fs::set_permissions(&source_b, fs::Permissions::from_mode(0o755)).unwrap();
    let directory = root.path().join("prepared");
    let store = ExecutableStore::new(directory.clone()).unwrap();

    store.prepare_copy_for_test(&source_a).unwrap();
    store.prepare_copy_for_test(&source_b).unwrap();

    let manifest_a = manifest_path(&directory, &source_a);
    let manifest_b = manifest_path(&directory, &source_b);
    assert_ne!(manifest_a, manifest_b);
    assert!(manifest_a.is_file());
    assert!(manifest_b.is_file());
    assert!(!directory.join(CHECKSUM_MANIFEST_FILE).exists());
    assert_eq!(manifest_file_count(&manifest_a), 1);
    assert_eq!(manifest_file_count(&manifest_b), 1);
}

#[test]
fn executable_store_rebuilds_when_the_copy_or_manifest_is_missing() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let store = ExecutableStore::new(directory.clone()).unwrap();
    let destination = store.prepare(Path::new("/bin/sh")).unwrap();
    let manifest = manifest_path(&directory, Path::new("/bin/sh"));

    fs::remove_file(&manifest).unwrap();
    fs::write(&destination, b"stale executable").unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(store.prepare(Path::new("/bin/sh")).unwrap(), destination);
    assert_ne!(fs::read(&destination).unwrap(), b"stale executable");
    assert!(manifest.is_file());

    fs::remove_file(&destination).unwrap();
    assert_eq!(store.prepare(Path::new("/bin/sh")).unwrap(), destination);
    assert!(destination.is_file());
    assert!(manifest.is_file());
}

#[test]
fn executable_store_rebuilds_when_the_source_checksum_changes() {
    let root = TestDirectory::new();
    let source = root.path().join("tool");
    fs::copy("/bin/sh", &source).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    let store = ExecutableStore::new(root.path().join("prepared")).unwrap();
    let destination = store.prepare_copy_for_test(&source).unwrap();
    let first_checksum = manifest_checksum(store.directory.as_path(), &source);
    let first_copy = fs::read(&destination).unwrap();

    fs::copy("/bin/cat", &source).unwrap();
    fs::set_permissions(&source, fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(store.prepare_copy_for_test(&source).unwrap(), destination);

    assert_ne!(
        manifest_checksum(store.directory.as_path(), &source),
        first_checksum
    );
    assert_ne!(fs::read(destination).unwrap(), first_copy);
}

#[test]
fn executable_store_reuses_the_copy_when_the_source_checksum_matches() {
    let root = TestDirectory::new();
    let store = ExecutableStore::new(root.path().join("prepared")).unwrap();
    let destination = store.prepare(Path::new("/bin/sh")).unwrap();
    fs::set_permissions(&destination, fs::Permissions::from_mode(0o700)).unwrap();

    assert_eq!(store.prepare(Path::new("/bin/sh")).unwrap(), destination);
    assert_eq!(
        destination.metadata().unwrap().permissions().mode() & 0o777,
        0o700
    );
}

#[test]
fn executable_store_reports_unreadable_checksum_manifest() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let store = ExecutableStore::new(directory.clone()).unwrap();
    store.prepare(Path::new("/bin/sh")).unwrap();
    let manifest = manifest_path(&directory, Path::new("/bin/sh"));
    fs::remove_file(&manifest).unwrap();
    fs::create_dir(&manifest).unwrap();

    let error = store.prepare(Path::new("/bin/sh")).unwrap_err();

    assert!(
        error
            .to_string()
            .contains("failed to read sandbox executable checksum manifest"),
        "{error:#}"
    );
}

#[test]
fn executable_store_rejects_invalid_checksum_manifests() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let store = ExecutableStore::new(directory.clone()).unwrap();
    let manifest = manifest_path(&directory, Path::new("/bin/sh"));
    fs::create_dir_all(manifest.parent().unwrap()).unwrap();

    fs::write(&manifest, b"not json").unwrap();
    let malformed = store.prepare(Path::new("/bin/sh")).unwrap_err();
    assert!(
        malformed
            .to_string()
            .contains("failed to parse sandbox executable checksum manifest"),
        "{malformed:#}"
    );

    fs::write(&manifest, br#"{"version":2,"files":{}}"#).unwrap();
    let unsupported = store.prepare(Path::new("/bin/sh")).unwrap_err();
    assert!(
        unsupported
            .to_string()
            .contains("unsupported sandbox executable checksum manifest version 2"),
        "{unsupported:#}"
    );
}

#[test]
fn executable_store_reports_checksum_manifest_publication_errors() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let store = ExecutableStore::new(directory.clone()).unwrap();
    let manifest_directory = directory.join("bin");
    fs::create_dir_all(&manifest_directory).unwrap();
    fs::create_dir(manifest_directory.join(CHECKSUM_MANIFEST_FILE)).unwrap();

    let error = store
        .write_manifest(&manifest_directory, &super::ChecksumManifest::default())
        .unwrap_err();

    assert!(
        error
            .to_string()
            .contains("failed to publish sandbox executable checksum manifest"),
        "{error:#}"
    );
    assert!(
        !manifest_directory
            .join(CHECKSUM_MANIFEST_TEMP_FILE)
            .exists()
    );
}

#[test]
fn executable_store_replaces_invalid_cache_files_and_rejects_non_files() {
    let root = TestDirectory::new();
    let directory = root.path().join("prepared");
    let store = ExecutableStore::new(directory).unwrap();
    let source = Path::new("/bin/sh").canonicalize().unwrap();
    let destination = store.destination(&source).unwrap();
    fs::create_dir_all(destination.parent().unwrap()).unwrap();
    fs::write(&destination, b"invalid").unwrap();

    assert_eq!(store.prepare(&source).unwrap(), destination);
    assert_ne!(fs::read(&destination).unwrap(), b"invalid");

    fs::remove_file(&destination).unwrap();
    assert_eq!(store.prepare(&source).unwrap(), destination);
    assert!(destination.is_file());

    fs::remove_file(manifest_path(&store.directory, &source)).unwrap();
    fs::remove_file(&destination).unwrap();
    fs::create_dir_all(&destination).unwrap();
    assert!(
        store
            .prepare(&source)
            .unwrap_err()
            .to_string()
            .contains("root entry is not a file")
    );
}

fn manifest_path(directory: &Path, source: &Path) -> PathBuf {
    let source = source.canonicalize().unwrap();
    let relative_parent = source
        .parent()
        .unwrap()
        .strip_prefix(Path::new("/"))
        .unwrap();
    directory.join(relative_parent).join(CHECKSUM_MANIFEST_FILE)
}

fn manifest_checksum(directory: &Path, source: &Path) -> String {
    let manifest: serde_json::Value =
        serde_json::from_slice(&fs::read(manifest_path(directory, source)).unwrap()).unwrap();
    assert_eq!(manifest["version"], 1);
    manifest["files"][source.canonicalize().unwrap().to_string_lossy().as_ref()]
        .as_str()
        .unwrap()
        .to_string()
}

fn manifest_file_count(path: &Path) -> usize {
    let manifest: serde_json::Value = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
    manifest["files"].as_object().unwrap().len()
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
