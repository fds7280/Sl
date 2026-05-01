//! Session cache — created once on unlock, lives until the app exits.
//!
//!
//! # Lazy entry cache
//!
//! `usernames` is always populated eagerly on load (it is a single pass
//! that decrypts just the username field — fast).  Full `Entry` objects
//! are loaded lazily into `entry_cache` the first time the user opens or
//! navigates to that entry.  Subsequent views are instant (no crypto at
//! all).  The cache is invalidated on edit so stale data is never shown.

use zeroize::{Zeroize, Zeroizing};
use crate::back::Entry;
use crate::enc::{
    EncryptedEntry, SALT_LEN,
    derive_key, generate_salt,
    encrypt_entry_with_key, decrypt_entry_with_key,
};
use crate::vault::{Vault, default_vault_path};

// ── Session cache ──────────────────────────────────────────────────────────
pub struct SessionCache {
    /// AES-256 vault key derived from master password + vault salt.
    /// Zeroizing<T> overwrites memory on drop automatically.
    key: Zeroizing<[u8; 32]>,

    /// Salt that was used (or will be used) for the outer vault layer.
    pub vault_salt: [u8; SALT_LEN],

    /// Encrypted entries — source of truth, always in sync with disk.
    pub encrypted: Vec<EncryptedEntry>,

    /// Usernames extracted from every entry — used for the sidebar list.
    /// Always kept up to date; no Argon2id, just the fast key-based path.
    pub usernames: Vec<String>,

    /// Lazily-populated full entry cache.  `None` means not yet decrypted.
    /// Invalidated (set back to None) whenever an entry is edited.
    entry_cache: Vec<Option<Entry>>,
}

impl SessionCache {
    // ── Construct from a freshly loaded vault ─────────────────────────────

    /// Build a SessionCache from a loaded vault and the master password.
    /// Runs Argon2id ONCE here.  All subsequent crypto uses `self.key`.
    pub fn from_vault(
        master_pass: &str,
        vault_salt: [u8; SALT_LEN],
        encrypted: Vec<EncryptedEntry>,
    ) -> Result<Self, String> {
        let key = Zeroizing::new(derive_key(master_pass, &vault_salt));

        let mut cache = SessionCache {
            key,
            vault_salt,
            encrypted,
            usernames:   Vec::new(),
            entry_cache: Vec::new(),
        };

        cache.rebuild_usernames()?;
        Ok(cache)
    }

    /// Build an empty SessionCache for a brand-new vault.
    /// Runs Argon2id ONCE here.
    pub fn new_vault(master_pass: &str) -> Self {
        let vault_salt = generate_salt();
        let key        = Zeroizing::new(derive_key(master_pass, &vault_salt));
        SessionCache {
            key,
            vault_salt,
            encrypted:   Vec::new(),
            usernames:   Vec::new(),
            entry_cache: Vec::new(),
        }
    }

    // ── Sidebar usernames ──────────────────────────────────────────────────

    /// Re-decrypt all usernames from the encrypted list.
    /// Fast — no Argon2id, just AES-GCM + XOR key mix.
    fn rebuild_usernames(&mut self) -> Result<(), String> {
        self.usernames = self.encrypted
            .iter()
            .map(|enc| {
                decrypt_entry_with_key(enc, &self.key)
                    .map(|e| e.username)
                    .unwrap_or_else(|_| "‹error›".to_string())
            })
            .collect();
        Ok(())
    }

    // ── Lazy entry access ──────────────────────────────────────────────────

    /// Return the full decrypted Entry for index `i`, decrypting and caching
    /// it on first access.  Subsequent calls are zero-cost (clone from cache).
    pub fn get_entry(&mut self, i: usize) -> Option<Entry> {
        // Grow cache to match encrypted list
        if self.entry_cache.len() < self.encrypted.len() {
            self.entry_cache.resize(self.encrypted.len(), None);
        }

        if i >= self.encrypted.len() { return None; }

        if self.entry_cache[i].is_none() {
            self.entry_cache[i] = decrypt_entry_with_key(&self.encrypted[i], &self.key).ok();
        }

        self.entry_cache[i].clone()
    }

    // ── Mutations ──────────────────────────────────────────────────────────

    /// Add a new entry and save vault to disk.
    pub fn add_entry(&mut self, entry: &Entry) -> Result<(), String> {
        let enc = encrypt_entry_with_key(entry, &self.key)?;
        self.encrypted.push(enc);
        self.entry_cache.push(Some(entry.clone()));
        self.usernames.push(entry.username.clone());
        self.flush()
    }

    /// Replace entry at index `i` and save vault to disk.
    pub fn update_entry(&mut self, i: usize, entry: &Entry) -> Result<(), String> {
        if i >= self.encrypted.len() { return Err("index out of range".into()); }
        let enc = encrypt_entry_with_key(entry, &self.key)?;
        self.encrypted[i]   = enc;
        self.entry_cache[i] = Some(entry.clone()); // update cache in place
        self.usernames[i]   = entry.username.clone();
        self.flush()
    }

    /// Number of entries.
    pub fn len(&self) -> usize { self.encrypted.len() }

    // ── Persistence ────────────────────────────────────────────────────────

    /// Write the vault to disk using the cached key — no Argon2id.
    fn flush(&self) -> Result<(), String> {
        let vault = Vault { entries: self.encrypted.clone() };
        crate::vault::save_vault_with_key(&vault, &self.key, &self.vault_salt, &default_vault_path())
            .map_err(|e| format!("save failed: {e}"))
    }
}

impl Drop for SessionCache {
    fn drop(&mut self) {
        // entry_cache contains plaintext passwords — wipe them
        for slot in &mut self.entry_cache {
            if let Some(e) = slot {
                e.username.zeroize();
                e.password.zeroize();
                e.description.zeroize();
            }
        }
        self.usernames.iter_mut().for_each(|s| s.zeroize());
        // self.key is Zeroizing<_> — auto-wiped on drop
    }
}
