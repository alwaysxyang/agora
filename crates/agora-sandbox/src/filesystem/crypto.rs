use anyhow::{Context, Result, bail};
use ring::{
    aead::{self, Aad, LessSafeKey, Nonce, UnboundKey},
    digest, pbkdf2,
    rand::{SecureRandom, SystemRandom},
};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::NonZeroU32;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use uuid::Uuid;

const MAGIC: &[u8; 8] = b"AGORAFS\0";
const VERSION: u8 = 1;
const NONCE_PREFIX_SIZE: usize = 8;
const HEADER_SIZE: usize = MAGIC.len() + 1 + NONCE_PREFIX_SIZE;
const CHUNK_SIZE: usize = 64 * 1024;
const TAG_SIZE: usize = 16;
const FINAL_RECORD: u8 = 0;
const DATA_RECORD: u8 = 1;
const PBKDF2_ITERATIONS: u32 = 100_000;

#[derive(Clone)]
pub(crate) struct FileCipher {
    key: LessSafeKey,
    key_id: String,
}

impl std::fmt::Debug for FileCipher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.debug_struct("FileCipher").finish_non_exhaustive()
    }
}

impl FileCipher {
    pub(crate) fn derive(passphrase: &[u8], salt: &[u8]) -> Result<Self> {
        if passphrase.is_empty() {
            bail!("sandbox filesystem key cannot be empty");
        }
        if salt.len() < 16 {
            bail!("sandbox filesystem salt must contain at least 16 bytes");
        }
        let iterations = NonZeroU32::new(PBKDF2_ITERATIONS).expect("iteration count is non-zero");
        let mut key = [0_u8; 32];
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            iterations,
            salt,
            passphrase,
            &mut key,
        );
        let key_id = Self::hex(digest::digest(&digest::SHA256, &key).as_ref());
        let key = UnboundKey::new(&aead::AES_256_GCM, &key)
            .map_err(|_| anyhow::anyhow!("failed to initialize filesystem cipher"))?;
        Ok(Self {
            key: LessSafeKey::new(key),
            key_id,
        })
    }

    pub(crate) fn key_id(&self) -> &str {
        &self.key_id
    }

    pub(crate) fn encrypt(&self, plaintext: &mut File, destination: &Path) -> Result<()> {
        let parent = destination
            .parent()
            .context("encrypted filesystem destination has no parent")?;
        fs::create_dir_all(parent).with_context(|| {
            format!(
                "failed to create encrypted filesystem directory {}",
                parent.display()
            )
        })?;
        let temporary = parent.join(format!(".agora-encrypted-{}.tmp", Uuid::new_v4().simple()));
        let result = (|| {
            let mut encrypted = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .with_context(|| {
                    format!(
                        "failed to create encrypted filesystem file {}",
                        temporary.display()
                    )
                })?;
            self.encrypt_to(plaintext, &mut encrypted)?;
            encrypted
                .set_permissions(fs::Permissions::from_mode(0o600))
                .context("failed to secure encrypted filesystem file")?;
            encrypted
                .sync_all()
                .context("failed to sync encrypted filesystem file")?;
            fs::rename(&temporary, destination).with_context(|| {
                format!(
                    "failed to publish encrypted filesystem file {}",
                    destination.display()
                )
            })?;
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .with_context(|| {
                    format!(
                        "failed to sync encrypted filesystem directory {}",
                        parent.display()
                    )
                })
        })();
        if result.is_err() {
            let _ = fs::remove_file(&temporary);
        }
        result
    }

    pub(crate) fn decrypt(&self, source: &Path, plaintext: &mut File) -> Result<()> {
        let mut encrypted = File::open(source).with_context(|| {
            format!(
                "failed to open encrypted filesystem file {}",
                source.display()
            )
        })?;
        let mut verified =
            tempfile::tempfile().context("failed to create anonymous filesystem plaintext file")?;
        self.decrypt_to(&mut encrypted, &mut verified)
            .with_context(|| {
                format!(
                    "failed to decrypt encrypted filesystem file {}",
                    source.display()
                )
            })?;
        verified.seek(SeekFrom::Start(0))?;
        plaintext.set_len(0)?;
        plaintext.seek(SeekFrom::Start(0))?;
        std::io::copy(&mut verified, plaintext)?;
        plaintext.seek(SeekFrom::Start(0))?;
        Ok(())
    }

    fn encrypt_to(&self, plaintext: &mut File, encrypted: &mut File) -> Result<()> {
        let mut nonce_prefix = [0_u8; NONCE_PREFIX_SIZE];
        SystemRandom::new()
            .fill(&mut nonce_prefix)
            .map_err(|_| anyhow::anyhow!("failed to generate filesystem nonce"))?;
        encrypted.write_all(MAGIC)?;
        encrypted.write_all(&[VERSION])?;
        encrypted.write_all(&nonce_prefix)?;
        plaintext.seek(SeekFrom::Start(0))?;

        let mut index = 0_u32;
        let mut buffer = vec![0_u8; CHUNK_SIZE];
        loop {
            let read = plaintext.read(&mut buffer)?;
            if read == 0 {
                self.write_record(encrypted, nonce_prefix, index, FINAL_RECORD, Vec::new())?;
                break;
            }
            self.write_record(
                encrypted,
                nonce_prefix,
                index,
                DATA_RECORD,
                buffer[..read].to_vec(),
            )?;
            index = index
                .checked_add(1)
                .context("encrypted filesystem file is too large")?;
        }
        Ok(())
    }

    fn decrypt_to(&self, encrypted: &mut File, plaintext: &mut File) -> Result<()> {
        let mut header = [0_u8; HEADER_SIZE];
        encrypted
            .read_exact(&mut header)
            .context("encrypted filesystem header is incomplete")?;
        if &header[..MAGIC.len()] != MAGIC || header[MAGIC.len()] != VERSION {
            bail!("unsupported encrypted filesystem file format");
        }
        let mut nonce_prefix = [0_u8; NONCE_PREFIX_SIZE];
        nonce_prefix.copy_from_slice(&header[MAGIC.len() + 1..]);

        let mut index = 0_u32;
        loop {
            let mut record_header = [0_u8; 5];
            encrypted
                .read_exact(&mut record_header)
                .context("encrypted filesystem record header is incomplete")?;
            let kind = record_header[0];
            let length = u32::from_be_bytes(record_header[1..].try_into().unwrap()) as usize;
            if length > CHUNK_SIZE {
                bail!("encrypted filesystem record exceeds the supported chunk size");
            }
            let mut sealed = vec![0_u8; length + TAG_SIZE];
            encrypted
                .read_exact(&mut sealed)
                .context("encrypted filesystem record is incomplete")?;
            let nonce = Self::nonce(nonce_prefix, index);
            let aad = Self::aad(index, kind, length);
            let opened = self
                .key
                .open_in_place(nonce, Aad::from(&aad), &mut sealed)
                .map_err(|_| anyhow::anyhow!("encrypted filesystem authentication failed"))?;
            match kind {
                DATA_RECORD if !opened.is_empty() => plaintext.write_all(opened)?,
                FINAL_RECORD if opened.is_empty() => {
                    let mut trailing = [0_u8; 1];
                    if encrypted.read(&mut trailing)? != 0 {
                        bail!("encrypted filesystem file contains trailing data");
                    }
                    plaintext.seek(SeekFrom::Start(0))?;
                    return Ok(());
                }
                _ => bail!("invalid encrypted filesystem record"),
            }
            index = index
                .checked_add(1)
                .context("encrypted filesystem file is too large")?;
        }
    }

    fn write_record(
        &self,
        encrypted: &mut File,
        nonce_prefix: [u8; NONCE_PREFIX_SIZE],
        index: u32,
        kind: u8,
        mut plaintext: Vec<u8>,
    ) -> Result<()> {
        let length = u32::try_from(plaintext.len()).context("filesystem chunk is too large")?;
        let nonce = Self::nonce(nonce_prefix, index);
        let aad = Self::aad(index, kind, plaintext.len());
        self.key
            .seal_in_place_append_tag(nonce, Aad::from(&aad), &mut plaintext)
            .map_err(|_| anyhow::anyhow!("failed to encrypt filesystem chunk"))?;
        encrypted.write_all(&[kind])?;
        encrypted.write_all(&length.to_be_bytes())?;
        encrypted.write_all(&plaintext)?;
        Ok(())
    }

    fn nonce(prefix: [u8; NONCE_PREFIX_SIZE], index: u32) -> Nonce {
        let mut nonce = [0_u8; 12];
        nonce[..NONCE_PREFIX_SIZE].copy_from_slice(&prefix);
        nonce[NONCE_PREFIX_SIZE..].copy_from_slice(&index.to_be_bytes());
        Nonce::assume_unique_for_key(nonce)
    }

    fn aad(index: u32, kind: u8, length: usize) -> [u8; 18] {
        let mut aad = [0_u8; 18];
        aad[..MAGIC.len()].copy_from_slice(MAGIC);
        aad[8] = VERSION;
        aad[9..13].copy_from_slice(&index.to_be_bytes());
        aad[13] = kind;
        aad[14..].copy_from_slice(&(length as u32).to_be_bytes());
        aad
    }

    fn hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut output = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            output.push(HEX[(byte >> 4) as usize] as char);
            output.push(HEX[(byte & 0x0f) as usize] as char);
        }
        output
    }
}

#[cfg(test)]
mod tests;
