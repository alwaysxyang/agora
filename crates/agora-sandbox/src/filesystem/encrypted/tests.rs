use super::{
    EncryptedWorkspace, KEY_METADATA_VERSION, KeyMetadata, REKEY_JOURNAL_VERSION, RekeyEntry,
    RekeyJournal,
};
use crate::filesystem::crypto::FileCipher;
use crate::filesystem::metadata::{EntryState, Materializer, MetadataStore};
use crate::filesystem::{OpenTarget, VirtualFilesystem};
use base64::Engine;
use std::io::{Read, Seek, SeekFrom, Write};
use std::os::fd::AsRawFd;
use std::path::PathBuf;

fn temporary_directory(label: &str) -> PathBuf {
    std::env::temp_dir().join(format!("agora-filesystem-{label}-{}", uuid::Uuid::new_v4()))
}

#[test]
fn passphrase_validation_preserves_direct_input() {
    EncryptedWorkspace::validate_passphrase(b"secret\r\n").unwrap();
    EncryptedWorkspace::validate_passphrase(b"contains\0nul").unwrap();
}

#[test]
fn passphrase_validation_rejects_invalid_keys() {
    assert!(
        EncryptedWorkspace::validate_passphrase(b"")
            .unwrap_err()
            .to_string()
            .contains("is empty")
    );
    assert!(
        EncryptedWorkspace::validate_passphrase(&vec![b'x'; 64 * 1024 + 1])
            .unwrap_err()
            .to_string()
            .contains("exceeds")
    );
}

#[tokio::test]
async fn encrypted_workspace_uses_fs_as_its_backing_root_and_validates_the_key() {
    let workdir = temporary_directory("lifecycle");
    let mut first = EncryptedWorkspace::start(&workdir, b"old-key")
        .await
        .unwrap();
    assert_eq!(first.root(), workdir.join("fs"));
    assert!(first.root().join(".fs.lock").is_file());
    assert!(first.root().join(".key.json").is_file());
    assert!(!workdir.join("filesystem").exists());
    let salt = first.salt().to_vec();
    first.shutdown().await.unwrap();
    drop(first);

    let wrong = EncryptedWorkspace::start(&workdir, b"wrong-key")
        .await
        .unwrap_err();
    assert!(wrong.to_string().contains("key is incorrect"), "{wrong:#}");

    let mut reopened = EncryptedWorkspace::start(&workdir, b"old-key")
        .await
        .unwrap();
    assert_eq!(reopened.salt(), salt);
    reopened.shutdown().await.unwrap();
    drop(reopened);
    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn encrypted_workspace_lock_is_exclusive_and_shutdown_is_immediate() {
    let workdir = temporary_directory("lock");
    let mut first = EncryptedWorkspace::start(&workdir, b"key").await.unwrap();
    assert!(
        EncryptedWorkspace::start(&workdir, b"key")
            .await
            .unwrap_err()
            .to_string()
            .contains("already in use")
    );
    first.shutdown().await.unwrap();
    drop(first);
    let mut second = EncryptedWorkspace::start(&workdir, b"key").await.unwrap();
    second.shutdown().await.unwrap();
    drop(second);
    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn key_migration_reencrypts_existing_backing_files() {
    let workdir = temporary_directory("migration");
    let mut workspace = EncryptedWorkspace::start(&workdir, b"old-key")
        .await
        .unwrap();
    let path = workspace.root().join("project/secret");
    let mut plaintext = tempfile::tempfile().unwrap();
    plaintext.write_all(b"secret contents").unwrap();
    FileCipher::derive(b"old-key", workspace.salt())
        .unwrap()
        .encrypt(&mut plaintext, &path)
        .unwrap();
    let old_salt = workspace.salt().to_vec();
    workspace.shutdown().await.unwrap();
    drop(workspace);

    EncryptedWorkspace::migrate_key(&workdir, b"old-key", b"new-key")
        .await
        .unwrap();
    let mut migrated = EncryptedWorkspace::start(&workdir, b"new-key")
        .await
        .unwrap();
    assert_ne!(migrated.salt(), old_salt);
    let mut decrypted = tempfile::tempfile().unwrap();
    FileCipher::derive(b"new-key", migrated.salt())
        .unwrap()
        .decrypt(&path, &mut decrypted)
        .unwrap();
    decrypted.seek(SeekFrom::Start(0)).unwrap();
    let mut contents = Vec::new();
    decrypted.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, b"secret contents");
    migrated.shutdown().await.unwrap();
    drop(migrated);

    assert!(
        EncryptedWorkspace::start(&workdir, b"old-key")
            .await
            .unwrap_err()
            .to_string()
            .contains("key is incorrect")
    );
    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn key_migration_ignores_persistent_executable_caches() {
    let workdir = temporary_directory("migration-cache");
    let workspace = EncryptedWorkspace::start(&workdir, b"old-key")
        .await
        .unwrap();
    let cached = workspace.root().join("usr/bin/tool");
    std::fs::create_dir_all(cached.parent().unwrap()).unwrap();
    std::fs::write(&cached, b"prepared executable").unwrap();
    MetadataStore::new(workspace.root())
        .unwrap()
        .set(
            std::path::Path::new("/usr/bin/tool"),
            EntryState::Cached {
                checksum: "checksum".to_string(),
                materializer: Materializer::Executable,
            },
        )
        .unwrap();
    drop(workspace);

    EncryptedWorkspace::migrate_key(&workdir, b"old-key", b"new-key")
        .await
        .unwrap();

    assert_eq!(std::fs::read(cached).unwrap(), b"prepared executable");
    drop(
        EncryptedWorkspace::start(&workdir, b"new-key")
            .await
            .unwrap(),
    );
    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn key_migration_reencrypts_logical_names_that_resemble_control_files() {
    let workdir = temporary_directory("migration-control-name");
    let workspace = EncryptedWorkspace::start(&workdir, b"old-key")
        .await
        .unwrap();
    let root = workspace.root().to_path_buf();
    let lower = temporary_directory("migration-control-name-lower");
    std::fs::create_dir_all(&lower).unwrap();
    let old_cipher = FileCipher::derive(b"old-key", workspace.salt()).unwrap();
    let filesystem = VirtualFilesystem::encrypted(&root, old_cipher).unwrap();
    let logical = lower.join(".metadata.user");
    let mut prepared = filesystem
        .prepare_open(
            &logical,
            libc::O_CREAT | libc::O_RDWR | libc::O_TRUNC,
            0o600,
        )
        .unwrap();
    let OpenTarget::Descriptor(file) = prepared.target_mut() else {
        panic!("encrypted file did not use an anonymous descriptor");
    };
    file.write_all(b"control-like contents").unwrap();
    filesystem.commit_open(&mut prepared).unwrap();
    let (target, writeback, _) = prepared.into_parts();
    let OpenTarget::Descriptor(file) = target else {
        panic!("encrypted file did not use an anonymous descriptor");
    };
    writeback.unwrap().commit(file.as_raw_fd()).unwrap();
    drop(filesystem);
    drop(workspace);

    EncryptedWorkspace::migrate_key(&workdir, b"old-key", b"new-key")
        .await
        .unwrap();

    let workspace = EncryptedWorkspace::start(&workdir, b"new-key")
        .await
        .unwrap();
    let filesystem = VirtualFilesystem::encrypted(
        workspace.root(),
        FileCipher::derive(b"new-key", workspace.salt()).unwrap(),
    )
    .unwrap();
    let mut reopened = filesystem
        .prepare_open(&logical, libc::O_RDONLY, 0)
        .unwrap();
    let OpenTarget::Descriptor(file) = reopened.target_mut() else {
        panic!("encrypted file did not use an anonymous descriptor");
    };
    let mut contents = Vec::new();
    file.read_to_end(&mut contents).unwrap();
    assert_eq!(contents, b"control-like contents");
    drop(filesystem);
    drop(workspace);
    std::fs::remove_dir_all(lower).unwrap();
    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn startup_recovers_interrupted_key_migration_before_opening_the_workspace() {
    let workdir = temporary_directory("migration-recovery");
    let workspace = EncryptedWorkspace::start(&workdir, b"old-key")
        .await
        .unwrap();
    let root = workspace.root().to_path_buf();
    let destination = root.join("project/secret");
    let backup = root.join("project/.agora-rekey-old-test");
    let staged = root.join("project/.agora-rekey-test.tmp");
    let old_key = EncryptedWorkspace::read_key_metadata(&root).unwrap();
    write_encrypted(
        &FileCipher::derive(b"old-key", workspace.salt()).unwrap(),
        &destination,
        b"secret contents",
    );
    drop(workspace);

    let new_key = EncryptedWorkspace::new_key_metadata(b"new-key").unwrap();
    let new_salt = EncryptedWorkspace::decode_salt(&new_key).unwrap();
    std::fs::rename(&destination, &backup).unwrap();
    write_encrypted(
        &FileCipher::derive(b"new-key", &new_salt).unwrap(),
        &destination,
        b"secret contents",
    );
    EncryptedWorkspace::write_journal(
        &root,
        &RekeyJournal {
            version: REKEY_JOURNAL_VERSION,
            old_key: old_key.clone(),
            new_key: new_key.clone(),
            entries: vec![RekeyEntry {
                destination: EncryptedWorkspace::encode_relative_path(&root, &destination).unwrap(),
                staged: EncryptedWorkspace::encode_relative_path(&root, &staged).unwrap(),
                backup: EncryptedWorkspace::encode_relative_path(&root, &backup).unwrap(),
            }],
        },
    )
    .unwrap();

    let workspace = EncryptedWorkspace::start(&workdir, b"old-key")
        .await
        .unwrap();
    assert!(!root.join(".rekey.json").exists());
    assert!(!backup.exists());
    assert_eq!(
        decrypt(
            &FileCipher::derive(b"old-key", workspace.salt()).unwrap(),
            &destination
        ),
        b"secret contents"
    );
    drop(workspace);

    std::fs::rename(&destination, &backup).unwrap();
    write_encrypted(
        &FileCipher::derive(b"new-key", &new_salt).unwrap(),
        &destination,
        b"secret contents",
    );
    EncryptedWorkspace::write_journal(
        &root,
        &RekeyJournal {
            version: REKEY_JOURNAL_VERSION,
            old_key,
            new_key: new_key.clone(),
            entries: vec![RekeyEntry {
                destination: EncryptedWorkspace::encode_relative_path(&root, &destination).unwrap(),
                staged: EncryptedWorkspace::encode_relative_path(&root, &staged).unwrap(),
                backup: EncryptedWorkspace::encode_relative_path(&root, &backup).unwrap(),
            }],
        },
    )
    .unwrap();
    EncryptedWorkspace::write_key_metadata(&root, &new_key).unwrap();

    let workspace = EncryptedWorkspace::start(&workdir, b"new-key")
        .await
        .unwrap();
    assert!(!root.join(".rekey.json").exists());
    assert!(!backup.exists());
    assert_eq!(
        decrypt(
            &FileCipher::derive(b"new-key", workspace.salt()).unwrap(),
            &destination
        ),
        b"secret contents"
    );
    drop(workspace);
    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn encrypted_workspace_rejects_existing_plaintext_data() {
    let workdir = temporary_directory("plaintext");
    std::fs::create_dir_all(workdir.join("fs/project")).unwrap();
    std::fs::write(workdir.join("fs/project/plaintext"), b"visible").unwrap();

    let error = EncryptedWorkspace::start(&workdir, b"key")
        .await
        .unwrap_err();
    assert!(
        error.to_string().contains("unencrypted filesystem data"),
        "{error:#}"
    );
    std::fs::remove_dir_all(workdir).unwrap();
}

#[test]
fn cipher_key_identity_is_stable_for_the_same_key_and_salt() {
    let first = FileCipher::derive(b"key", b"0123456789abcdef").unwrap();
    let second = FileCipher::derive(b"key", b"0123456789abcdef").unwrap();
    assert_eq!(first.key_id(), second.key_id());
}

#[test]
fn encrypted_workspace_debug_redacts_the_key_and_resolves_relative_destinations() {
    let workdir = temporary_directory("debug");
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let workspace = runtime
        .block_on(EncryptedWorkspace::start(&workdir, b"very-secret"))
        .unwrap();
    let debug = format!("{workspace:?}");
    assert!(debug.contains("EncryptedWorkspace"));
    assert!(debug.contains("[REDACTED]"));
    assert!(!debug.contains("very-secret"));
    assert_eq!(workspace.key(), b"very-secret");

    let relative = PathBuf::from("relative-workdir");
    assert_eq!(
        EncryptedWorkspace::resolved_destination(&relative).unwrap(),
        std::env::current_dir().unwrap().join(relative)
    );
    drop(workspace);
    std::fs::remove_dir_all(workdir).unwrap();
}

#[test]
fn key_metadata_validation_rejects_unsupported_or_malformed_salts() {
    let metadata = |version, salt: String| KeyMetadata {
        version,
        salt,
        key_id: "unused".to_string(),
    };

    assert!(
        EncryptedWorkspace::decode_salt(&metadata(
            KEY_METADATA_VERSION + 1,
            base64::engine::general_purpose::STANDARD.encode([0_u8; 16]),
        ))
        .is_err()
    );
    assert!(
        EncryptedWorkspace::decode_salt(&metadata(KEY_METADATA_VERSION, "%%%".to_string()))
            .is_err()
    );
    assert!(
        EncryptedWorkspace::decode_salt(&metadata(
            KEY_METADATA_VERSION,
            base64::engine::general_purpose::STANDARD.encode([0_u8; 15]),
        ))
        .is_err()
    );
}

#[tokio::test]
async fn encrypted_workspace_reports_invalid_roots_and_key_metadata() {
    let workdir = temporary_directory("invalid-root");
    std::fs::create_dir_all(&workdir).unwrap();
    std::fs::write(workdir.join("fs"), b"not a directory").unwrap();
    assert!(EncryptedWorkspace::start(&workdir, b"key").await.is_err());
    std::fs::remove_dir_all(&workdir).unwrap();

    let workdir = temporary_directory("invalid-metadata");
    let root = workdir.join("fs");
    std::fs::create_dir_all(&root).unwrap();
    std::fs::write(root.join(".key.json"), b"not json").unwrap();
    assert!(EncryptedWorkspace::start(&workdir, b"key").await.is_err());

    let metadata = KeyMetadata {
        version: KEY_METADATA_VERSION,
        salt: base64::engine::general_purpose::STANDARD.encode([0_u8; 16]),
        key_id: "id".to_string(),
    };
    assert!(EncryptedWorkspace::write_key_metadata(&workdir.join("missing"), &metadata).is_err());
    std::fs::remove_dir_all(workdir).unwrap();
}

#[tokio::test]
async fn key_migration_rejects_invalid_requests_and_cleans_staged_files() {
    let missing = temporary_directory("migration-missing");
    assert!(
        EncryptedWorkspace::migrate_key(&missing, b"old", b"new")
            .await
            .is_err()
    );

    let workdir = temporary_directory("migration-errors");
    let workspace = EncryptedWorkspace::start(&workdir, b"old-key")
        .await
        .unwrap();
    assert!(
        EncryptedWorkspace::migrate_key(&workdir, b"old-key", b"old-key")
            .await
            .is_err()
    );
    drop(workspace);
    assert!(
        EncryptedWorkspace::migrate_key(&workdir, b"wrong-key", b"new-key")
            .await
            .is_err()
    );

    let workspace = EncryptedWorkspace::start(&workdir, b"old-key")
        .await
        .unwrap();
    let valid = workspace.root().join("valid");
    let mut plaintext = tempfile::tempfile().unwrap();
    plaintext.write_all(b"valid").unwrap();
    FileCipher::derive(b"old-key", workspace.salt())
        .unwrap()
        .encrypt(&mut plaintext, &valid)
        .unwrap();
    let corrupt_directory = workspace.root().join("nested");
    std::fs::create_dir(&corrupt_directory).unwrap();
    std::fs::write(corrupt_directory.join("corrupt"), b"not ciphertext").unwrap();
    drop(workspace);

    assert!(
        EncryptedWorkspace::migrate_key(&workdir, b"old-key", b"new-key")
            .await
            .is_err()
    );
    assert!(directory_tree_has_no_rekey_files(&workdir.join("fs")));
    assert!(!EncryptedWorkspace::is_control_file(
        PathBuf::new().as_path()
    ));
    std::fs::remove_dir_all(workdir).unwrap();
}

fn directory_tree_has_no_rekey_files(root: &std::path::Path) -> bool {
    let mut directories = vec![root.to_path_buf()];
    while let Some(directory) = directories.pop() {
        for entry in std::fs::read_dir(directory).unwrap() {
            let entry = entry.unwrap();
            if entry.file_type().unwrap().is_dir() {
                directories.push(entry.path());
            } else if entry
                .file_name()
                .to_string_lossy()
                .starts_with(".agora-rekey-")
            {
                return false;
            }
        }
    }
    true
}

fn write_encrypted(cipher: &FileCipher, path: &std::path::Path, contents: &[u8]) {
    let mut plaintext = tempfile::tempfile().unwrap();
    plaintext.write_all(contents).unwrap();
    cipher.encrypt(&mut plaintext, path).unwrap();
}

fn decrypt(cipher: &FileCipher, path: &std::path::Path) -> Vec<u8> {
    let mut plaintext = tempfile::tempfile().unwrap();
    cipher.decrypt(path, &mut plaintext).unwrap();
    plaintext.seek(SeekFrom::Start(0)).unwrap();
    let mut contents = Vec::new();
    plaintext.read_to_end(&mut contents).unwrap();
    contents
}
