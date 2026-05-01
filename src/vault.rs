use std::fs;
use std::path::Path;
use serde::{Serialize, Deserialize};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key,
};
use zeroize::Zeroize;

use crate::enc::{EncryptedEntry, derive_key, SALT_LEN};
// ── Magic header ───────────────────────────────────────────────────────────
const SL_MAGIC: &[u8] = b"SL01";

// ── Vault file layout ──────────────────────────────────────────────────────
// [4  bytes] magic "SL01"
// [32 bytes] vault_salt   — salt for outer vault key (separate from field salts)
// [12 bytes] nonce        — AES-GCM nonce
// [N  bytes] ciphertext   — encrypted JSON payload
//
// Two independent salt layers:
//   vault_salt  → outer key  → encrypts the whole JSON blob
//   field_salt  → field key  → encrypts each field inside every EncryptedEntry
// Cracking the outer layer still leaves every field encrypted with its own key.

// ── Vault struct ───────────────────────────────────────────────────────────
#[derive(Serialize, Deserialize)]
pub struct Vault {
    pub entries: Vec<EncryptedEntry>,
}

// ── Save ───────────────────────────────────────────────────────────────────
pub fn save_vault(
    vault: &Vault,
    master_pass: &str,
    vault_salt: &[u8; SALT_LEN],
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Serialize vault to JSON
    let json = serde_json::to_vec(vault)?;

    // 2. Derive outer key — zeroize after use
    let mut key    = derive_key(master_pass, vault_salt);
    let cipher     = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    key.zeroize();

    // 3. Encrypt
    let nonce      = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, json.as_slice())
        .map_err(|e| format!("vault encryption failed: {e}"))?;

    // 4. Build file bytes
    let mut file_bytes = Vec::new();
    file_bytes.extend_from_slice(SL_MAGIC);
    file_bytes.extend_from_slice(vault_salt);
    file_bytes.extend_from_slice(&nonce);
    file_bytes.extend_from_slice(&ciphertext);

    // 5. Atomic write — write to .tmp then rename
    //    prevents a crash mid-write from corrupting the vault
    let tmp_path = format!("{}.tmp", path);
    fs::write(&tmp_path, &file_bytes)?;
    fs::rename(&tmp_path, path)?;

    // 6. Owner-only permissions on Unix (0o600)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }

    Ok(())
}

// ── Save (key-based, no Argon2id) ─────────────────────────────────────────
/// Like save_vault but accepts a pre-derived key directly.
/// Used by SessionCache so Argon2id never runs during a live session.
pub fn save_vault_with_key(
    vault: &Vault,
    key: &[u8; 32],
    vault_salt: &[u8; SALT_LEN],
    path: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let json      = serde_json::to_vec(vault)?;
    let cipher    = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce     = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, json.as_slice())
        .map_err(|e| format!("vault encryption failed: {e}"))?;

    let mut file_bytes = Vec::new();
    file_bytes.extend_from_slice(SL_MAGIC);
    file_bytes.extend_from_slice(vault_salt);
    file_bytes.extend_from_slice(&nonce);
    file_bytes.extend_from_slice(&ciphertext);

    let tmp_path = format!("{}.tmp", path);
    fs::write(&tmp_path, &file_bytes)?;
    fs::rename(&tmp_path, path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

// ── Load ───────────────────────────────────────────────────────────────────
pub fn load_vault(
    master_pass: &str,
    path: &str,
) -> Result<(Vault, [u8; SALT_LEN]), Box<dyn std::error::Error>> {
    let file_bytes = fs::read(path)?;

    // Minimum: 4 magic + 32 salt + 12 nonce = 48 bytes
    if file_bytes.len() < 48 {
        return Err("file too small to be a valid .sl vault".into());
    }

    if &file_bytes[0..4] != SL_MAGIC {
        return Err("not a valid .sl vault file".into());
    }

    let vault_salt: [u8; SALT_LEN] = file_bytes[4..36].try_into()?;
    let nonce_bytes: [u8; 12]      = file_bytes[36..48].try_into()?;
    let ciphertext                 = &file_bytes[48..];

    let mut key = derive_key(master_pass, &vault_salt);
    let cipher  = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    key.zeroize();

    let nonce     = Nonce::from_slice(&nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "decryption failed — wrong password or corrupted file")?;

    let vault = serde_json::from_slice(&plaintext)?;
    Ok((vault, vault_salt))
}

// ── Helpers ────────────────────────────────────────────────────────────────
pub fn vault_exists(path: &str) -> bool {
    Path::new(path).exists()
}

pub fn default_vault_path() -> String {
    // dirs::data_dir() returns the correct path per platform:
    //   Linux:   ~/.local/share
    //   Windows: C:\Users\name\AppData\Roaming
    //   macOS:   ~/Library/Application Support
    let dir = dirs::data_dir()
        .expect("cannot determine data directory")
        .join("statelock");
    fs::create_dir_all(&dir).expect("cannot create vault directory");
    dir.join("vault.sl").to_string_lossy().to_string()
}
