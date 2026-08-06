use super::*;
use agora_sandbox::runner::FilesystemMode;
use std::os::unix::fs::{PermissionsExt, symlink};

fn write_config(root: &Path, contents: &str) -> PathBuf {
    let path = root.join("sandbox.json");
    std::fs::write(&path, contents).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    path
}

fn load_error(path: &Path) -> String {
    RunConfig::load(path)
        .err()
        .expect("configuration must be rejected")
        .to_string()
}

#[test]
fn unified_config_resolves_runtime_settings_and_redacts_secrets() {
    let root = tempfile::tempdir().unwrap();
    let path = write_config(
        root.path(),
        r#"{
          "workdir": "state",
          "tls": "auto",
          "filesystem": {
            "local": { "encrypt": "encrypted", "key": "local-secret" },
            "nfs": [
              {
                "type": "smb",
                "dir": "/smb",
                "server": "smb://127.0.0.1:10445/workspace/projects/current",
                "username": "openclaw",
                "password": "remote-secret"
              },
              {
                "type": "smb",
                "dir": "/archive",
                "server": "smb://127.0.0.2/archive"
              }
            ]
          },
          "audit": { "file": "logs/audit.jsonl" }
        }"#,
    );

    let loaded = RunConfig::load(&path).unwrap();
    assert_eq!(loaded.workdir(), root.path().join("state"));
    let (runtime, audit) = loaded.into_runtime(PathBuf::from("/tmp/hook.dylib"));

    assert!(matches!(runtime.network.tls, TlsMode::Auto));
    assert_eq!(runtime.filesystem_mode(), FilesystemMode::Encrypted);
    assert_eq!(
        runtime.encrypted_workspace_key(),
        Some(&b"local-secret"[..])
    );
    assert_eq!(runtime.smb_remotes().len(), 2);
    let remote = &runtime.smb_remotes()[0];
    assert_eq!(remote.logical_root(), Path::new("/smb"));
    assert_eq!(remote.server(), "127.0.0.1:10445");
    assert_eq!(remote.share(), "workspace");
    assert_eq!(remote.remote_path(), "projects/current");
    assert_eq!(remote.username(), "openclaw");
    assert_eq!(
        runtime.smb_remotes()[1].logical_root(),
        Path::new("/archive")
    );
    let debug = format!("{runtime:?}");
    assert!(!debug.contains("local-secret"));
    assert!(!debug.contains("remote-secret"));
    assert_eq!(audit, Some(root.path().join("logs/audit.jsonl")));
}

#[test]
fn config_paths_expand_home_and_resolve_relative_to_the_config() {
    let root = tempfile::tempdir().unwrap();
    assert_eq!(
        resolve_path(root.path(), Path::new("nested/state")).unwrap(),
        root.path().join("nested/state")
    );
    let home = PathBuf::from(std::env::var_os("HOME").unwrap());
    assert_eq!(
        resolve_path(root.path(), Path::new("~/.agora-sandbox")).unwrap(),
        home.join(".agora-sandbox")
    );
}

#[test]
fn empty_config_uses_all_runtime_defaults() {
    let root = tempfile::tempdir().unwrap();
    let path = write_config(root.path(), "{}");

    let loaded = RunConfig::load(&path).unwrap();
    assert_eq!(loaded.workdir(), SandboxConfig::default_workdir());
    let (runtime, audit) = loaded.into_runtime(PathBuf::from("/tmp/hook.dylib"));
    assert!(matches!(runtime.network.tls, TlsMode::Off));
    assert_eq!(runtime.filesystem_mode(), FilesystemMode::Plain);
    assert!(runtime.encrypted_workspace_key().is_none());
    assert!(runtime.smb_remotes().is_empty());
    assert!(audit.is_none());
}

#[test]
fn config_rejects_unknown_fields_and_invalid_local_encryption() {
    let root = tempfile::tempdir().unwrap();
    let unknown = write_config(
        root.path(),
        r#"{
          "workdir": "state",
          "tls": "off",
          "filesystem": { "local": { "encrypt": "plain" } },
          "unexpected": true
        }"#,
    );
    assert!(load_error(&unknown).contains("failed to parse sandbox config"));

    let invalid = write_config(
        root.path(),
        r#"{
          "workdir": "state",
          "tls": "off",
          "filesystem": { "local": { "encrypt": "plain", "key": "unused" } }
        }"#,
    );
    assert!(load_error(&invalid).contains("key is not allowed"));

    let missing = write_config(
        root.path(),
        r#"{
          "workdir": "state",
          "tls": "off",
          "filesystem": { "local": { "encrypt": "encrypted" } }
        }"#,
    );
    assert!(load_error(&missing).contains("key is required"));
}

#[test]
fn config_rejects_malformed_smb_uris() {
    for server in [
        "files.example.com/share",
        "smb:///share",
        "smb://files.example.com",
        "smb://user@files.example.com/share",
        "smb://files.example.com/",
    ] {
        let error =
            smb_remote(PathBuf::from("/smb"), server, String::new(), String::new()).unwrap_err();
        assert!(!error.to_string().is_empty(), "{server} must be rejected");
    }
}

#[test]
fn config_file_must_be_owner_only_and_not_a_symlink() {
    let root = tempfile::tempdir().unwrap();
    let path = write_config(
        root.path(),
        r#"{
          "workdir": "state",
          "tls": "off",
          "filesystem": { "local": { "encrypt": "plain" } }
        }"#,
    );
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(load_error(&path).contains("permissions"));

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(load_error(&path).contains("permissions"));

    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    let link = root.path().join("sandbox-link.json");
    symlink(&path, &link).unwrap();
    assert!(load_error(&link).contains("symbolic link"));
}
