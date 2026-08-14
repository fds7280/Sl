//! In-memory session state — built once on unlock, alive until the app exits.
//!
//! # Lazy entry cache
//!
//! `usernames` is populated eagerly on load (a single pass that decrypts just
//! the username field — fast, and passwords are never read). Full [`Entry`]
//! objects are loaded lazily into `entry_cache` the first time the user opens
//! or navigates to that entry; subsequent views are zero-copy clones. The
//! cache is invalidated on edit so stale data is never shown.

use zeroize::{Zeroize, Zeroizing};

use crate::crypto::{self, EncryptedEntry, KEY_LEN, SALT_LEN};
use crate::entry::Entry;
use crate::error::Result;
use crate::vault::{self, Vault};

/// The live session: derived key + encrypted entries + lazy plaintext cache.
pub struct SessionCache {
    /// AES-256 vault key derived from the master password + vault salt.
    /// `Zeroizing<_>` overwrites the buffer on drop automatically.
    key: Zeroizing<[u8; KEY_LEN]>,

    /// Salt used for the outer vault layer.
    vault_salt: [u8; SALT_LEN],

    /// Where the vault is persisted.
    path: String,

    /// Encrypted entries — source of truth, always in sync with disk.
    encrypted: Vec<EncryptedEntry>,

    /// Usernames extracted from every entry — used for the sidebar list.
    usernames: Vec<String>,

    /// Lazily-populated full-entry cache. `None` means "not yet decrypted".
    /// Invalidated on edit so stale data is never shown.
    entry_cache: Vec<Option<Entry>>,
}

impl SessionCache {
    /// Unlock an existing vault at `path`. Argon2id runs **exactly once**.
    pub fn unlock(master_pass: &str, path: &str) -> Result<Self> {
        let vf = vault::read_file(path)?;
        let key = Zeroizing::new(crypto::derive_key(master_pass, &vf.salt));
        let vault = vault::decrypt(&vf, &key)?;
        Self::from_parts(key, vf.salt, path.to_string(), vault.entries)
    }

    /// Create a brand-new (empty) vault at `path`. Argon2id runs **exactly
    /// once**, and the empty vault is persisted immediately so it is a real
    /// file on disk from the start.
    pub fn create(master_pass: &str, path: &str) -> Result<Self> {
        let salt = crypto::generate_salt();
        let key = Zeroizing::new(crypto::derive_key(master_pass, &salt));
        let cache = Self::from_parts(key, salt, path.to_string(), Vec::new())?;
        cache.flush()?;
        Ok(cache)
    }

    fn from_parts(
        key: Zeroizing<[u8; KEY_LEN]>,
        vault_salt: [u8; SALT_LEN],
        path: String,
        encrypted: Vec<EncryptedEntry>,
    ) -> Result<Self> {
        let mut cache = Self {
            key,
            vault_salt,
            path,
            encrypted,
            usernames: Vec::new(),
            entry_cache: Vec::new(),
        };
        cache.rebuild_usernames()?;
        Ok(cache)
    }

    // ── Sidebar usernames ──────────────────────────────────────────────────

    /// Re-derive the sidebar usernames. Decrypts *only* the username field of
    /// each entry — passwords are never read while building the list.
    fn rebuild_usernames(&mut self) -> Result<()> {
        self.usernames = self
            .encrypted
            .iter()
            .map(|e| {
                crypto::decrypt_username(e, &self.key).unwrap_or_else(|_| "‹error›".to_string())
            })
            .collect();
        Ok(())
    }

    // ── Lazy entry access ──────────────────────────────────────────────────

    /// Return the full decrypted [`Entry`] at index `i`, decrypting and
    /// caching it on first access. Subsequent calls are zero-cost clones.
    pub fn get_entry(&mut self, i: usize) -> Option<Entry> {
        if i >= self.encrypted.len() {
            return None;
        }
        if self.entry_cache.len() < self.encrypted.len() {
            self.entry_cache.resize(self.encrypted.len(), None);
        }
        if self.entry_cache[i].is_none() {
            self.entry_cache[i] = crypto::decrypt_entry(&self.encrypted[i], &self.key).ok();
        }
        self.entry_cache[i].clone()
    }

    // ── Mutations ──────────────────────────────────────────────────────────

    /// Add a new entry and save the vault to disk.
    pub fn add_entry(&mut self, entry: &Entry) -> Result<()> {
        let enc = crypto::encrypt_entry(entry, &self.key)?;
        self.encrypted.push(enc);
        self.entry_cache.push(Some(entry.clone()));
        self.usernames.push(entry.username.clone());
        self.flush()
    }

    /// Replace the entry at index `i` and save the vault to disk.
    pub fn update_entry(&mut self, i: usize, entry: &Entry) -> Result<()> {
        let enc = crypto::encrypt_entry(entry, &self.key)?;
        if i >= self.encrypted.len() {
            return Err(crate::error::Error::invalid("entry index out of range"));
        }
        self.encrypted[i] = enc;
        self.entry_cache[i] = Some(entry.clone());
        self.usernames[i] = entry.username.clone();
        self.flush()
    }

    /// Remove the entry at index `i` and save the vault to disk.
    pub fn delete_entry(&mut self, i: usize) -> Result<()> {
        if i >= self.encrypted.len() {
            return Err(crate::error::Error::invalid("entry index out of range"));
        }
        self.encrypted.remove(i);
        self.entry_cache.remove(i);
        self.usernames.remove(i);
        self.flush()
    }

    // ── Accessors ──────────────────────────────────────────────────────────

    pub fn len(&self) -> usize {
        self.encrypted.len()
    }

    pub fn is_empty(&self) -> bool {
        self.encrypted.is_empty()
    }

    pub fn usernames(&self) -> &[String] {
        &self.usernames
    }

    // ── Persistence ────────────────────────────────────────────────────────

    /// Write the vault to disk using the cached key — no Argon2id.
    fn flush(&self) -> Result<()> {
        let vault = Vault {
            entries: self.encrypted.clone(),
        };
        vault::save_vault(&vault, &self.key, &self.vault_salt, &self.path)
    }
}

impl Drop for SessionCache {
    fn drop(&mut self) {
        // `usernames` are the only sensitive plaintext here that is not
        // already handled by a zeroizing wrapper.
        for u in &mut self.usernames {
            u.zeroize();
        }
        // `key` is `Zeroizing<[u8;32]>` and `entry_cache` holds `Entry`
        // (which is `ZeroizeOnDrop`) — both wipe themselves on drop.
    }
}
