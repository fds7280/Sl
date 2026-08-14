//! Cryptographic primitives.
//!
//! # Layering
//!
//! * **Outer layer** — the whole vault file is encrypted under a key derived
//!   from the master password + vault salt via **Argon2id** (deliberately
//!   slow; runs exactly once per unlock). AES-256-GCM over the JSON payload.
//! * **Inner layer** — every entry carries its own random 32-byte
//!   `field_salt`. A per-entry key is derived with **HKDF-SHA256** from the
//!   vault key + `field_salt`, and each field (username / password /
//!   description) is encrypted under that key with its own random nonce.
//!
//! Because each field is encrypted independently, the sidebar can decrypt
//! *only* the username column — passwords are never read while building the
//! entry list (see [`decrypt_username`]).

use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, AeadCore, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use hkdf::Hkdf;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroize;

use crate::entry::Entry;
use crate::error::{Error, Result};

/// Length of generated salts, in bytes.
pub const SALT_LEN: usize = 32;

/// Length of the AES-256 key, in bytes.
pub const KEY_LEN: usize = 32;

/// Length of the AES-GCM nonce, in bytes.
pub const NONCE_LEN: usize = 12;

/// HKDF domain-separation label for the per-entry key derivation.
const ENTRY_KEY_INFO: &[u8] = b"statelock entry key v1";

// ── Argon2id ───────────────────────────────────────────────────────────────
// 64 MiB memory, 3 iterations, 1 lane — the OWASP-recommended minimum.
// Deliberately slow to resist offline brute-force; called ONCE per unlock.
fn argon2() -> Argon2<'static> {
    let params = Params::new(65_536, 3, 1, Some(KEY_LEN)).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Generate a cryptographically random salt.
pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

/// Derive the 256-bit vault key from the master password + salt.
///
/// Runs Argon2id. Call **once** on unlock and cache the result; never call
/// this inside the render or event loop.
pub fn derive_key(password: &str, salt: &[u8]) -> [u8; KEY_LEN] {
    let mut key = [0u8; KEY_LEN];
    argon2()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("key derivation failed");
    key
}

// ── Per-entry key derivation ───────────────────────────────────────────────

/// Derive the per-entry AES key from the vault key + the entry's random salt.
///
/// HKDF-SHA256 expands `(vault_key, salt=field_salt)` into an independent key.
/// The `field_salt` is stored in plaintext and is *not* secret — that is fine:
/// HKDF is a PRF, so without the vault key the per-entry key is unpredictable.
/// (This replaces the previous `vault_key ^ field_salt` XOR, which added no
/// real separation because the salt is public and XOR is trivially reversed.)
fn entry_key(vault_key: &[u8; KEY_LEN], field_salt: &[u8]) -> Result<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::new(Some(field_salt), vault_key);
    let mut okm = [0u8; KEY_LEN];
    hk.expand(ENTRY_KEY_INFO, &mut okm)
        .map_err(|_| Error::crypto("HKDF expansion failed"))?;
    Ok(okm)
}

// ── Encrypted entry ────────────────────────────────────────────────────────

/// Encrypted form of a single entry. Every field is encrypted independently
/// so the username can be revealed without ever touching the password.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedEntry {
    /// Random per-entry salt (public — used as the HKDF salt).
    pub field_salt: [u8; SALT_LEN],
    pub username: Vec<u8>,
    pub username_nonce: [u8; NONCE_LEN],
    pub password: Vec<u8>,
    pub password_nonce: [u8; NONCE_LEN],
    pub description: Vec<u8>,
    pub description_nonce: [u8; NONCE_LEN],
}

// ── Field-level helpers ────────────────────────────────────────────────────

fn encrypt_field(cipher: &Aes256Gcm, plaintext: &str) -> Result<(Vec<u8>, [u8; NONCE_LEN])> {
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|_| Error::crypto("AES-GCM encryption failed"))?;
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(&nonce);
    Ok((ciphertext, nonce_arr))
}

fn decrypt_field(cipher: &Aes256Gcm, ciphertext: &[u8], nonce: &[u8; NONCE_LEN]) -> Result<String> {
    let plaintext = cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| Error::crypto("field decryption failed — wrong key or corrupt data"))?;
    String::from_utf8(plaintext).map_err(|_| Error::corrupt("field is not valid UTF-8"))
}

// ── Public API (key-based — fast, use during a live session) ───────────────

/// Encrypt an entry using a pre-derived vault key. No Argon2id.
pub fn encrypt_entry(entry: &Entry, vault_key: &[u8; KEY_LEN]) -> Result<EncryptedEntry> {
    let field_salt = generate_salt();
    let mut key = entry_key(vault_key, &field_salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let (username, username_nonce) = encrypt_field(&cipher, &entry.username)?;
    let (password, password_nonce) = encrypt_field(&cipher, &entry.password)?;
    let (description, description_nonce) = encrypt_field(&cipher, &entry.description)?;

    key.zeroize();

    Ok(EncryptedEntry {
        field_salt,
        username,
        username_nonce,
        password,
        password_nonce,
        description,
        description_nonce,
    })
}

/// Decrypt an entry using a pre-derived vault key. No Argon2id.
pub fn decrypt_entry(enc: &EncryptedEntry, vault_key: &[u8; KEY_LEN]) -> Result<Entry> {
    let mut key = entry_key(vault_key, &enc.field_salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let entry = Entry::new(
        decrypt_field(&cipher, &enc.username, &enc.username_nonce)?,
        decrypt_field(&cipher, &enc.password, &enc.password_nonce)?,
        decrypt_field(&cipher, &enc.description, &enc.description_nonce)?,
    );

    key.zeroize();
    Ok(entry)
}

/// Decrypt **only** the username field.
///
/// Used to build the sidebar list: the password and description ciphertexts
/// are never read, let alone decrypted.
pub fn decrypt_username(enc: &EncryptedEntry, vault_key: &[u8; KEY_LEN]) -> Result<String> {
    let mut key = entry_key(vault_key, &enc.field_salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
    let username = decrypt_field(&cipher, &enc.username, &enc.username_nonce)?;
    key.zeroize();
    Ok(username)
}

// ── Password generator ─────────────────────────────────────────────────────

/// Generate a 32-character password from the 94 printable-ASCII characters.
///
/// Uses rejection sampling so every character is uniformly distributed (no
/// modulo bias).
pub fn generate_password() -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`";
    const LEN: usize = 32;
    // Accept only values below the largest multiple of 94 that fits a u8
    // (94 * 2 = 188), so the `% 94` index stays unbiased.
    let limit: u8 = (256 - (256 % CHARS.len())) as u8;

    let mut out = String::with_capacity(LEN);
    let mut buf = [0u8; 1];
    while out.len() < LEN {
        OsRng.fill_bytes(&mut buf);
        if buf[0] < limit {
            out.push(CHARS[(buf[0] as usize) % CHARS.len()] as char);
        }
    }
    out
}
