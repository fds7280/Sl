//! Vault file persistence.
//!
//! # File layout
//!
//! ```text
//! [4 bytes]  magic "SL01"
//! [32 bytes] vault_salt  — salt for the outer vault key
//! [12 bytes] nonce       — AES-GCM nonce for the outer layer
//! [N bytes]  ciphertext  — AES-GCM over the JSON payload (Vec<EncryptedEntry>)
//! ```
//!
//! Two independent layers protect the data: the outer layer key comes from
//! Argon2id(master password, vault_salt), and each entry's fields are
//! individually keyed via HKDF (see [`crate::crypto`]). Writes are atomic
//! (temp file + rename) and owner-only (0o600 on Unix).

use std::fs;
use std::path::Path;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use serde::{Deserialize, Serialize};

use crate::crypto::{EncryptedEntry, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{Error, Result};

const SL_MAGIC: [u8; 4] = *b"SL01";

const SALT_OFFSET: usize = 4;
const NONCE_OFFSET: usize = SALT_OFFSET + SALT_LEN;
const PAYLOAD_OFFSET: usize = NONCE_OFFSET + NONCE_LEN;

/// The decrypted contents of a vault — a list of still-encrypted entries.
///
/// The outer JSON payload only ever contains [`EncryptedEntry`] values;
/// per-field plaintext is never serialized to disk.
#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub entries: Vec<EncryptedEntry>,
}

/// A parsed-but-still-encrypted vault file (header split off, no crypto done).
pub struct VaultFile {
    pub salt: [u8; SALT_LEN],
    pub nonce: [u8; NONCE_LEN],
    pub ciphertext: Vec<u8>,
}

// ── Reading ────────────────────────────────────────────────────────────────

/// Read and validate the header of a vault file without decrypting anything.
pub fn read_file(path: &str) -> Result<VaultFile> {
    let bytes = fs::read(path)?;

    if bytes.len() < PAYLOAD_OFFSET {
        return Err(Error::corrupt("file too small to be a Statelock vault"));
    }
    if bytes[0..4] != SL_MAGIC {
        return Err(Error::corrupt("not a Statelock vault file (bad magic)"));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&bytes[SALT_OFFSET..NONCE_OFFSET]);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&bytes[NONCE_OFFSET..PAYLOAD_OFFSET]);

    let ciphertext = bytes[PAYLOAD_OFFSET..].to_vec();

    Ok(VaultFile {
        salt,
        nonce,
        ciphertext,
    })
}

/// Decrypt and parse a [`VaultFile`] with a pre-derived key. No Argon2id here.
pub fn decrypt(vf: &VaultFile, key: &[u8; KEY_LEN]) -> Result<Vault> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&vf.nonce), vf.ciphertext.as_slice())
        .map_err(|_| Error::crypto("decryption failed — wrong password or corrupt file"))?;
    Ok(serde_json::from_slice(&plaintext)?)
}

// ── Writing ────────────────────────────────────────────────────────────────

/// Serialize + encrypt the vault and write it atomically to `path`.
pub fn save_vault(
    vault: &Vault,
    key: &[u8; KEY_LEN],
    vault_salt: &[u8; SALT_LEN],
    path: &str,
) -> Result<()> {
    let json = serde_json::to_vec(vault)?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, json.as_slice())
        .map_err(|_| Error::crypto("vault encryption failed"))?;

    let mut bytes = Vec::with_capacity(PAYLOAD_OFFSET + ciphertext.len());
    bytes.extend_from_slice(&SL_MAGIC);
    bytes.extend_from_slice(vault_salt);
    bytes.extend_from_slice(&nonce);
    bytes.extend_from_slice(&ciphertext);

    atomic_write(path, &bytes)
}

/// Write `bytes` to `path` atomically (temp file + rename) so a crash
/// mid-write can never corrupt an existing vault, then restrict permissions.
fn atomic_write(path: &str, bytes: &[u8]) -> Result<()> {
    let tmp = format!("{path}.tmp");
    fs::write(&tmp, bytes)?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e.into());
    }
    restrict_permissions(path);
    Ok(())
}

/// Owner-only permissions on Unix (0o600).
fn restrict_permissions(path: &str) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    }
}

// ── Paths ──────────────────────────────────────────────────────────────────

/// The default vault path, creating the parent directory if needed.
pub fn default_vault_path() -> Result<String> {
    let dir = dirs::data_dir()
        .ok_or_else(|| Error::invalid("cannot determine data directory"))?
        .join("statelock");
    fs::create_dir_all(&dir)?;
    Ok(dir.join("vault.sl").to_string_lossy().into_owned())
}

pub fn vault_exists(path: &str) -> bool {
    Path::new(path).exists()
}
