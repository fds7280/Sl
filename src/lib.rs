//! Statelock — a local, encrypted terminal password manager.
//!
//! # Architecture
//!
//! * [`entry`] — the plaintext `Entry` model (`ZeroizeOnDrop`).
//! * [`crypto`] — Argon2id key derivation, HKDF per-entry keys, AES-256-GCM,
//!   and the password generator. No terminal I/O.
//! * [`vault`] — the on-disk vault file format (magic + salt + nonce +
//!   ciphertext) with atomic, owner-only writes.
//! * [`cache`] — the in-memory `SessionCache`: holds the derived key and the
//!   encrypted entries, lazily decrypting full entries.
//! * [`app`] — the UI-independent state machine (fully unit-testable).
//! * [`ui`] — the ratatui/crossterm rendering and event loop.
//! * [`clipboard`] — a small clipboard abstraction so [`app`] stays testable.
//! * [`error`] — the unified [`error::Error`] type.

pub mod app;
pub mod cache;
pub mod clipboard;
pub mod crypto;
pub mod entry;
pub mod error;
pub mod ui;
pub mod vault;
