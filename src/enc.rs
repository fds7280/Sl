use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key,
};
use argon2::{Argon2, Algorithm, Version, Params};
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;

use crate::back::Entry;

// ── Argon2id params ────────────────────────────────────────────────────────
// 64 MB memory, 3 iterations, 1 thread — OWASP recommended minimum
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
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> [u8; 32] {
    let mut key = [0u8; 32];
    argon2()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("key derivation failed");
    key
}

// ── Encrypted entry ────────────────────────────────────────────────────────
// Each entry carries its own field_salt — independent key per entry
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

// ── Public API ─────────────────────────────────────────────────────────────

/// Encrypt an Entry using master_pass. Generates a fresh field_salt per entry.
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

/// Decrypt an EncryptedEntry. Returns Err on wrong password or corrupt data.
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
