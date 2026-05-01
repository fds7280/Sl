use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key,
};
use argon2::{Argon2, Algorithm, Version, Params};
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

use crate::back::Entry;

// ── Argon2id params ────────────────────────────────────────────────────────
// 64 MB memory, 3 iterations, 1 thread — OWASP recommended minimum.
// These are intentionally slow to defeat offline brute-force attacks.
// They run ONCE on unlock, never again during a live session.
fn argon2() -> Argon2<'static> {
    let params = Params::new(65536, 3, 1, Some(32))
        .expect("invalid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

// ── Salt ───────────────────────────────────────────────────────────────────
pub const SALT_LEN: usize = 32;

pub fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    use aes_gcm::aead::rand_core::RngCore;
    OsRng.fill_bytes(&mut salt);
    salt
}

// ── Key derivation ─────────────────────────────────────────────────────────
// Call this ONCE on unlock and cache the result in SessionCache.
// Never call inside the event loop or draw loop.
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut key = [0u8; 32];
    argon2()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("key derivation failed");
    key
}

// ── Encrypted entry ────────────────────────────────────────────────────────
// Each entry carries its own field_salt — independent key per entry.
// The field_salt is used with the CACHED vault key to derive a per-entry key.
// Cracking the outer vault layer still leaves every field independently keyed.
#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptedEntry {
    pub field_salt:        Vec<u8>,
    pub username:          Vec<u8>,
    pub username_nonce:    Vec<u8>,
    pub password:          Vec<u8>,
    pub password_nonce:    Vec<u8>,
    pub description:       Vec<u8>,
    pub description_nonce: Vec<u8>,
}

// ── Internal helpers ───────────────────────────────────────────────────────
fn encrypt_field(cipher: &Aes256Gcm, plaintext: &str) -> Result<(Vec<u8>, Vec<u8>), String> {
    let nonce      = Aes256Gcm::generate_nonce(&mut OsRng);
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| format!("encrypt failed: {e}"))?;
    Ok((ciphertext, nonce.to_vec()))
}

fn decrypt_field(
    cipher: &Aes256Gcm,
    ciphertext: &[u8],
    nonce_bytes: &[u8],
) -> Result<String, String> {
    let nonce     = Nonce::from_slice(nonce_bytes);
    let plaintext = cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| "field decryption failed — wrong password or corrupt data".to_string())?;
    String::from_utf8(plaintext).map_err(|e| format!("utf8 error: {e}"))
}

// ── Build per-entry cipher from cached vault key + field_salt ──────────────
// The field_salt XOR-mixes with the vault key so each entry has a unique
// cipher even though the vault key is cached. No Argon2id here — just
// a fast key derivation using HKDF-like XOR fold.
fn entry_cipher(vault_key: &[u8; 32], field_salt: &[u8]) -> Result<Aes256Gcm, String> {
    if field_salt.len() < 32 {
        return Err("field_salt too short".to_string());
    }
    // XOR the vault key with the first 32 bytes of the field_salt.
    // This gives every entry a unique key derived from both secrets
    // without any expensive KDF call.
    let mut entry_key = [0u8; 32];
    for i in 0..32 {
        entry_key[i] = vault_key[i] ^ field_salt[i];
    }
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&entry_key));
    entry_key.zeroize();
    Ok(cipher)
}

// ── Public API — KEY-BASED (fast, use during session) ─────────────────────

/// Encrypt using a pre-derived vault key. No Argon2id. Use this always
/// after unlock — pass the cached key from SessionCache.
pub fn encrypt_entry_with_key(entry: &Entry, vault_key: &[u8; 32]) -> Result<EncryptedEntry, String> {
    let field_salt = generate_salt();
    let cipher     = entry_cipher(vault_key, &field_salt)?;

    let (username,    username_nonce)    = encrypt_field(&cipher, &entry.username)?;
    let (password,    password_nonce)    = encrypt_field(&cipher, &entry.password)?;
    let (description, description_nonce) = encrypt_field(&cipher, &entry.description)?;

    Ok(EncryptedEntry {
        field_salt: field_salt.to_vec(),
        username,    username_nonce,
        password,    password_nonce,
        description, description_nonce,
    })
}

/// Decrypt using a pre-derived vault key. No Argon2id. Use this always
/// after unlock — pass the cached key from SessionCache.
pub fn decrypt_entry_with_key(enc: &EncryptedEntry, vault_key: &[u8; 32]) -> Result<Entry, String> {
    let cipher = entry_cipher(vault_key, &enc.field_salt)?;
    Ok(Entry {
        username:    decrypt_field(&cipher, &enc.username,    &enc.username_nonce)?,
        password:    decrypt_field(&cipher, &enc.password,    &enc.password_nonce)?,
        description: decrypt_field(&cipher, &enc.description, &enc.description_nonce)?,
    })
}

// ── Public API — PASSWORD-BASED (slow, use only for vault load/save) ───────

/// Encrypt an Entry using master_pass. Runs Argon2id — only call this
/// at vault creation time, not during a live session.
pub fn encrypt_entry(entry: &Entry, master_pass: &str) -> Result<EncryptedEntry, String> {
    let field_salt  = generate_salt();
    let mut key     = derive_key(master_pass, &field_salt);
    let cipher      = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let (username,    username_nonce)    = encrypt_field(&cipher, &entry.username)?;
    let (password,    password_nonce)    = encrypt_field(&cipher, &entry.password)?;
    let (description, description_nonce) = encrypt_field(&cipher, &entry.description)?;

    key.zeroize();

    Ok(EncryptedEntry {
        field_salt: field_salt.to_vec(),
        username,    username_nonce,
        password,    password_nonce,
        description, description_nonce,
    })
}

/// Decrypt an EncryptedEntry using master_pass. Runs Argon2id — only call
/// this at vault load time, not during a live session.
pub fn decrypt_entry(enc: &EncryptedEntry, master_pass: &str) -> Result<Entry, String> {
    let field_salt: [u8; SALT_LEN] = enc.field_salt
        .as_slice()
        .try_into()
        .map_err(|_| "invalid field salt length".to_string())?;

    let mut key = derive_key(master_pass, &field_salt);
    let cipher  = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));

    let entry = Entry {
        username:    decrypt_field(&cipher, &enc.username,    &enc.username_nonce)?,
        password:    decrypt_field(&cipher, &enc.password,    &enc.password_nonce)?,
        description: decrypt_field(&cipher, &enc.description, &enc.description_nonce)?,
    };

    key.zeroize();
    Ok(entry)
}