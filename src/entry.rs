//! Plaintext entry model.

use zeroize::{Zeroize, ZeroizeOnDrop};

/// A single stored credential.
///
/// Fields are plaintext only while in memory; `ZeroizeOnDrop` guarantees the
/// strings are overwritten the moment an `Entry` is freed, so cached or
/// transient copies never linger.
#[derive(Debug, Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Entry {
    pub username: String,
    pub password: String,
    pub description: String,
}

impl Entry {
    pub fn new(
        username: impl Into<String>,
        password: impl Into<String>,
        description: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
            description: description.into(),
        }
    }
}
