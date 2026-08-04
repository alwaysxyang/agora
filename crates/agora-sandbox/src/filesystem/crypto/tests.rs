use super::{CHUNK_SIZE, DATA_RECORD, FileCipher, MAGIC, VERSION};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};

fn temporary_directory(name: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!(
        "agora-filesystem-crypto-{name}-{}",
        uuid::Uuid::new_v4()
    ));
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[test]
fn encrypted_file_round_trip_never_writes_plaintext_to_the_backing_file() {
    let root = temporary_directory("round-trip");
    let encrypted = root.join("encrypted");
    let marker = b"plaintext marker that must not reach backing storage";
    let cipher = FileCipher::derive(b"workspace key", b"0123456789abcdef").unwrap();
    let mut plaintext = tempfile::tempfile().unwrap();
    plaintext.write_all(marker).unwrap();
    plaintext.seek(SeekFrom::Start(0)).unwrap();

    cipher.encrypt(&mut plaintext, &encrypted).unwrap();

    let stored = std::fs::read(&encrypted).unwrap();
    assert!(!stored.windows(marker.len()).any(|window| window == marker));
    let mut decrypted = tempfile::tempfile().unwrap();
    cipher.decrypt(&encrypted, &mut decrypted).unwrap();
    decrypted.seek(SeekFrom::Start(0)).unwrap();
    let mut restored = Vec::new();
    decrypted.read_to_end(&mut restored).unwrap();
    assert_eq!(restored, marker);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn encrypted_file_rejects_the_wrong_key_without_returning_plaintext() {
    let root = temporary_directory("wrong-key");
    let encrypted = root.join("encrypted");
    let cipher = FileCipher::derive(b"workspace key", b"0123456789abcdef").unwrap();
    let wrong = FileCipher::derive(b"wrong key", b"0123456789abcdef").unwrap();
    let mut plaintext = tempfile::tempfile().unwrap();
    plaintext.write_all(b"secret").unwrap();
    plaintext.seek(SeekFrom::Start(0)).unwrap();
    cipher.encrypt(&mut plaintext, &encrypted).unwrap();
    let mut decrypted = tempfile::tempfile().unwrap();

    assert!(wrong.decrypt(&encrypted, &mut decrypted).is_err());
    assert_eq!(decrypted.metadata().unwrap().len(), 0);

    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn cipher_rejects_invalid_derivation_inputs_and_redacts_debug_output() {
    assert!(FileCipher::derive(b"", b"0123456789abcdef").is_err());
    assert!(FileCipher::derive(b"key", b"short").is_err());

    let cipher = FileCipher::derive(b"secret key", b"0123456789abcdef").unwrap();
    let debug = format!("{cipher:?}");
    assert!(debug.contains("FileCipher"));
    assert!(!debug.contains("secret key"));
    assert!(!debug.contains(cipher.key_id()));
}

#[test]
fn cipher_key_material_can_be_reused_without_repeating_pbkdf2() {
    let derived = FileCipher::derive(b"secret key", b"0123456789abcdef").unwrap();
    let restored = FileCipher::from_key(derived.key_material()).unwrap();

    assert_eq!(restored.key_id(), derived.key_id());
    assert!(FileCipher::from_key(b"short").is_err());
}

#[test]
fn filename_encryption_is_randomized_authenticated_and_byte_preserving() {
    let cipher = FileCipher::derive(b"workspace key", b"0123456789abcdef").unwrap();
    let wrong = FileCipher::derive(b"wrong key", b"0123456789abcdef").unwrap();
    let name = b"\xe5\xae\x89\xe5\x85\xa8-\x80.docx";

    let first = cipher.encrypt_name(name).unwrap();
    let second = cipher.encrypt_name(name).unwrap();

    assert_ne!(first, second);
    assert_eq!(cipher.decrypt_name(&first).unwrap(), name);
    assert_eq!(cipher.decrypt_name(&second).unwrap(), name);
    assert!(wrong.decrypt_name(&first).is_err());
    assert!(cipher.decrypt_name("").is_err());

    let mut corrupted = first.into_bytes();
    let last = corrupted.last_mut().unwrap();
    *last = if *last == b'A' { b'B' } else { b'A' };
    assert!(
        cipher
            .decrypt_name(std::str::from_utf8(&corrupted).unwrap())
            .is_err()
    );
}

#[test]
fn encryption_failures_remove_temporary_ciphertext_files() {
    let root = temporary_directory("publish-failure");
    let destination = root.join("occupied");
    std::fs::create_dir(&destination).unwrap();
    let mut plaintext = tempfile::tempfile().unwrap();
    plaintext.write_all(b"secret").unwrap();
    let cipher = FileCipher::derive(b"key", b"0123456789abcdef").unwrap();

    assert!(cipher.encrypt(&mut plaintext, &destination).is_err());
    assert!(destination.is_dir());
    assert!(std::fs::read_dir(&root).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".agora-encrypted-")
    }));

    let blocked_parent = root.join("blocked");
    std::fs::write(&blocked_parent, b"file").unwrap();
    assert!(
        cipher
            .encrypt(&mut plaintext, &blocked_parent.join("child"))
            .is_err()
    );
    std::fs::remove_dir_all(root).unwrap();
}

#[test]
fn decryption_rejects_malformed_record_shapes_and_trailing_data() {
    let root = temporary_directory("malformed");
    let cipher = FileCipher::derive(b"key", b"0123456789abcdef").unwrap();
    let decrypt = |path: &std::path::Path| {
        let mut plaintext = tempfile::tempfile().unwrap();
        cipher
            .decrypt(path, &mut plaintext)
            .unwrap_err()
            .to_string()
    };

    assert!(decrypt(&root.join("missing")).contains("failed to open"));

    let incomplete_header = root.join("incomplete-header");
    std::fs::write(&incomplete_header, b"short").unwrap();
    assert!(decrypt(&incomplete_header).contains("failed to decrypt"));

    let invalid_format = root.join("invalid-format");
    let mut invalid_header = [0_u8; 17];
    invalid_header[..MAGIC.len()].copy_from_slice(b"INVALID\0");
    invalid_header[MAGIC.len()] = VERSION;
    std::fs::write(&invalid_format, invalid_header).unwrap();
    assert!(decrypt(&invalid_format).contains("failed to decrypt"));

    let incomplete_record = root.join("incomplete-record");
    write_header(&incomplete_record, [1; 8]);
    assert!(decrypt(&incomplete_record).contains("failed to decrypt"));

    let oversized_record = root.join("oversized-record");
    let mut oversized = write_header(&oversized_record, [2; 8]);
    oversized.write_all(&[DATA_RECORD]).unwrap();
    oversized
        .write_all(&((CHUNK_SIZE as u32) + 1).to_be_bytes())
        .unwrap();
    drop(oversized);
    assert!(decrypt(&oversized_record).contains("failed to decrypt"));

    let invalid_record = root.join("invalid-record");
    let prefix = [3; 8];
    let mut invalid = write_header(&invalid_record, prefix);
    cipher
        .write_record(&mut invalid, prefix, 0, 9, Vec::new())
        .unwrap();
    drop(invalid);
    assert!(decrypt(&invalid_record).contains("failed to decrypt"));

    let trailing = root.join("trailing");
    let mut plaintext = tempfile::tempfile().unwrap();
    plaintext.write_all(b"secret").unwrap();
    cipher.encrypt(&mut plaintext, &trailing).unwrap();
    OpenOptions::new()
        .append(true)
        .open(&trailing)
        .unwrap()
        .write_all(b"x")
        .unwrap();
    assert!(decrypt(&trailing).contains("failed to decrypt"));

    std::fs::remove_dir_all(root).unwrap();
}

fn write_header(path: &std::path::Path, nonce_prefix: [u8; 8]) -> File {
    let mut file = File::create(path).unwrap();
    file.write_all(MAGIC).unwrap();
    file.write_all(&[VERSION]).unwrap();
    file.write_all(&nonce_prefix).unwrap();
    file
}
