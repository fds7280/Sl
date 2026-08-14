//! UI-independent application state machine.
//!
//! All input handling lives here and is fully unit-testable: feed it [`Key`]s
//! and assert on the resulting state. Rendering (in [`crate::ui`]) is a pure
//! function of `&App` and never mutates state.

use std::time::{Duration, Instant};

use zeroize::{Zeroize, Zeroizing};

use crate::cache::SessionCache;
use crate::clipboard::Clipboard;
use crate::crypto;
use crate::entry::Entry;
use crate::vault;

/// How long a copied password stays on the clipboard before auto-clear.
const CLIP_TIMEOUT: Duration = Duration::from_secs(30);

/// Keys the app understands — decoupled from crossterm so the logic is
/// testable without a terminal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Key {
    Char(char),
    /// A character typed while holding Ctrl (used for Ctrl+G → generate).
    Ctrl(char),
    Enter,
    Esc,
    Tab,
    Backspace,
    Up,
    Down,
    Left,
    Right,
    Space,
}

/// Which input field is focused in the Add/Edit forms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputMode {
    Username,
    Password,
    Description,
}

impl InputMode {
    fn next(self) -> Self {
        match self {
            InputMode::Username => InputMode::Password,
            InputMode::Password => InputMode::Description,
            InputMode::Description => InputMode::Username,
        }
    }
}

/// The high-level screen the app is on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    Locked,
    Browse,
    View,
    Add,
    Edit,
    /// Confirmation dialog before deleting the entry at the given index.
    ConfirmDelete(usize),
}

/// Application state.
pub struct App {
    pub mode: Mode,

    /// The unlocked session, or `None` while locked.
    pub cache: Option<SessionCache>,

    /// Currently selected entry index (into the full list).
    pub selected: Option<usize>,

    /// The entry currently being viewed (plaintext, lazily loaded).
    pub entry: Option<Entry>,

    /// Master-password input buffer (only used while locked).
    pub master_pass: Zeroizing<String>,

    /// Add/Edit form buffers.
    pub username: Zeroizing<String>,
    pub password: Zeroizing<String>,
    pub description: Zeroizing<String>,

    /// Which field the Add/Edit form is editing.
    pub focus: InputMode,

    /// Whether the password field is shown in cleartext.
    pub show_password: bool,

    /// Live search filter for the sidebar.
    pub search: String,

    /// Whether search input is active (typed chars go to `search`).
    pub searching: bool,

    /// One-line status message.
    pub status: String,

    /// Seconds until the clipboard auto-clears (for display), if a copy is
    /// pending.
    pub clip_remaining: Option<u64>,

    /// Where the vault lives (overridable for tests).
    pub vault_path: String,

    /// Quit flag — the event loop breaks when this is set.
    pub quit: bool,

    clipboard: Box<dyn Clipboard>,
    clip_timer: Option<Instant>,
}

impl App {
    pub fn new(clipboard: Box<dyn Clipboard>) -> Self {
        let vault_path = vault::default_vault_path().unwrap_or_else(|_| "vault.sl".to_string());
        Self {
            mode: Mode::Locked,
            cache: None,
            selected: None,
            entry: None,
            master_pass: Zeroizing::new(String::new()),
            username: Zeroizing::new(String::new()),
            password: Zeroizing::new(String::new()),
            description: Zeroizing::new(String::new()),
            focus: InputMode::Username,
            show_password: false,
            search: String::new(),
            searching: false,
            status: String::new(),
            clip_remaining: None,
            vault_path,
            quit: false,
            clipboard,
            clip_timer: None,
        }
    }

    /// Override the vault path (used by tests).
    pub fn with_vault_path(mut self, path: impl Into<String>) -> Self {
        self.vault_path = path.into();
        self
    }

    /// Number of entries in the unlocked session.
    pub fn len(&self) -> usize {
        self.cache.as_ref().map_or(0, |c| c.len())
    }

    pub fn is_empty(&self) -> bool {
        self.cache.as_ref().is_none_or(|c| c.is_empty())
    }

    // ── Search / selection helpers ─────────────────────────────────────────

    /// Indices of the entries that match the current search filter.
    pub fn visible_indices(&self) -> Vec<usize> {
        let q = self.search.to_lowercase();
        self.cache.as_ref().map_or(Vec::new(), |c| {
            c.usernames()
                .iter()
                .enumerate()
                .filter(|(_, name)| q.is_empty() || name.to_lowercase().contains(&q))
                .map(|(i, _)| i)
                .collect()
        })
    }

    /// Move the selection within the currently visible entries, wrapping.
    fn move_selection(&mut self, dir: i32) {
        let visible = self.visible_indices();
        if visible.is_empty() {
            return;
        }
        let cur = self
            .selected
            .and_then(|s| visible.iter().position(|&i| i == s));
        let next = match cur {
            None => 0,
            Some(i) => {
                let n = visible.len();
                let j = i as i32 + dir;
                if j < 0 {
                    n - 1
                } else {
                    (j as usize) % n
                }
            }
        };
        self.selected = Some(visible[next]);
    }

    /// Ensure the selection points at a visible entry (e.g. after filtering
    /// or deleting).
    fn clamp_selection(&mut self) {
        let visible = self.visible_indices();
        if visible.is_empty() {
            self.selected = None;
        } else if self.selected.is_none_or(|s| !visible.contains(&s)) {
            self.selected = Some(visible[0]);
        }
    }

    // ── Clipboard ──────────────────────────────────────────────────────────

    /// Auto-clear the clipboard once the timeout elapses. Called every tick
    /// and before handling each key.
    pub fn maybe_clear_clipboard(&mut self) {
        match self.clip_timer {
            Some(t) if t.elapsed() >= CLIP_TIMEOUT => {
                self.clipboard.clear();
                self.clip_timer = None;
                self.clip_remaining = None;
                self.status = "clipboard cleared".to_string();
            }
            Some(t) => {
                self.clip_remaining = Some(CLIP_TIMEOUT.as_secs() - t.elapsed().as_secs());
            }
            None => self.clip_remaining = None,
        }
    }

    fn copy_to_clipboard(&mut self, text: Option<String>) {
        if let Some(t) = text {
            if self.clipboard.set_text(&t).is_ok() {
                self.clip_timer = Some(Instant::now());
                self.clip_remaining = Some(CLIP_TIMEOUT.as_secs());
                self.status = "copied — clears in 30s".to_string();
            } else {
                self.status = "clipboard unavailable".to_string();
            }
        }
    }

    // ── Entry points ───────────────────────────────────────────────────────

    /// Handle a single key press.
    pub fn handle_key(&mut self, key: Key) {
        self.maybe_clear_clipboard();
        match self.mode {
            Mode::Locked => self.handle_locked(key),
            Mode::Browse => self.handle_browse(key),
            Mode::View => self.handle_view(key),
            Mode::Add => self.handle_add(key),
            Mode::Edit => self.handle_edit(key),
            Mode::ConfirmDelete(i) => self.handle_confirm_delete(key, i),
        }
    }

    // ── Locked ─────────────────────────────────────────────────────────────

    fn handle_locked(&mut self, key: Key) {
        match key {
            Key::Esc => self.quit = true,
            Key::Char(c) => self.master_pass.push(c),
            Key::Backspace => {
                self.master_pass.pop();
            }
            Key::Enter => self.unlock(),
            _ => {}
        }
    }

    fn unlock(&mut self) {
        if self.master_pass.is_empty() {
            return;
        }

        if vault::vault_exists(&self.vault_path) {
            match SessionCache::unlock(&self.master_pass, &self.vault_path) {
                Ok(cache) => {
                    let n = cache.len();
                    self.cache = Some(cache);
                    self.status = format!("{n} entr{} loaded", if n == 1 { "y" } else { "ies" });
                    self.selected = if n > 0 { Some(0) } else { None };
                    self.mode = Mode::Browse;
                }
                Err(e) => {
                    self.status = format!("unlock failed: {e}");
                }
            }
        } else {
            match SessionCache::create(&self.master_pass, &self.vault_path) {
                Ok(cache) => {
                    self.cache = Some(cache);
                    self.status = "new vault created — press a to add entries".to_string();
                    self.mode = Mode::Browse;
                }
                Err(e) => self.status = format!("create failed: {e}"),
            }
        }

        // The master password is no longer needed; wipe it immediately.
        self.master_pass.zeroize();
    }

    // ── Browse ─────────────────────────────────────────────────────────────

    fn handle_browse(&mut self, key: Key) {
        if self.search_input(key) {
            return;
        }
        match key {
            Key::Esc => self.quit = true,
            Key::Char('/') => self.searching = true,
            Key::Char('a') | Key::Char('A') => self.start_add(),
            Key::Char('d') | Key::Char('D') => {
                if let Some(i) = self.selected {
                    self.mode = Mode::ConfirmDelete(i);
                }
            }
            Key::Enter => {
                if let Some(i) = self.selected {
                    self.open_entry(i);
                }
            }
            Key::Up => self.move_selection(-1),
            Key::Down => self.move_selection(1),
            _ => {}
        }
    }

    // ── View ───────────────────────────────────────────────────────────────

    fn handle_view(&mut self, key: Key) {
        if self.search_input(key) {
            return;
        }
        match key {
            Key::Esc => {
                self.entry = None;
                self.show_password = false;
                self.mode = Mode::Browse;
            }
            Key::Space => self.show_password = !self.show_password,
            Key::Char('c') | Key::Char('C') => {
                let text = self.entry.as_ref().map(|e| e.password.clone());
                self.copy_to_clipboard(text);
            }
            Key::Char('u') | Key::Char('U') => {
                let text = self.entry.as_ref().map(|e| e.username.clone());
                self.copy_to_clipboard(text);
            }
            Key::Char('d') | Key::Char('D') => {
                if let Some(i) = self.selected {
                    self.mode = Mode::ConfirmDelete(i);
                }
            }
            Key::Right => self.start_edit(),
            Key::Up => {
                self.move_selection(-1);
                self.refresh_entry();
            }
            Key::Down => {
                self.move_selection(1);
                self.refresh_entry();
            }
            Key::Char('/') => self.searching = true,
            _ => {}
        }
    }

    // ── Add ────────────────────────────────────────────────────────────────

    fn handle_add(&mut self, key: Key) {
        match key {
            Key::Esc => {
                self.show_password = false;
                self.mode = Mode::Browse;
            }
            Key::Tab => self.focus = self.focus.next(),
            Key::Enter => self.commit_add(),
            Key::Backspace => self.edit_backspace(),
            Key::Space => self.edit_space(),
            Key::Ctrl('g') | Key::Ctrl('G') => self.generate_password(),
            Key::Char(c) => self.edit_char(c),
            _ => {}
        }
    }

    // ── Edit ───────────────────────────────────────────────────────────────

    fn handle_edit(&mut self, key: Key) {
        match key {
            Key::Esc => self.cancel_edit(),
            Key::Tab => self.focus = self.focus.next(),
            Key::Enter => self.commit_edit(),
            Key::Backspace => self.edit_backspace(),
            Key::Space => self.edit_space(),
            Key::Ctrl('g') | Key::Ctrl('G') => self.generate_password(),
            Key::Char(c) => self.edit_char(c),
            _ => {}
        }
    }

    // ── Search input ───────────────────────────────────────────────────────

    /// Handle search-mode input. Returns `true` if the key was consumed.
    fn search_input(&mut self, key: Key) -> bool {
        if !self.searching {
            return false;
        }
        match key {
            Key::Esc => {
                self.searching = false;
                self.search.clear();
            }
            Key::Enter => self.searching = false,
            Key::Backspace => {
                self.search.pop();
            }
            Key::Space => self.search.push(' '),
            Key::Char(c) => self.search.push(c),
            _ => {}
        }
        self.clamp_selection();
        true
    }

    // ── Form helpers (Add & Edit share these) ──────────────────────────────

    fn edit_char(&mut self, c: char) {
        match self.focus {
            InputMode::Username => self.username.push(c),
            InputMode::Password => self.password.push(c),
            InputMode::Description => self.description.push(c),
        }
    }

    fn edit_backspace(&mut self) {
        match self.focus {
            InputMode::Username => {
                self.username.pop();
            }
            InputMode::Password => {
                self.password.pop();
            }
            InputMode::Description => {
                self.description.pop();
            }
        }
    }

    fn edit_space(&mut self) {
        if matches!(self.focus, InputMode::Password) {
            self.show_password = !self.show_password;
        } else {
            self.edit_char(' ');
        }
    }

    fn generate_password(&mut self) {
        self.password = Zeroizing::new(crypto::generate_password());
        self.show_password = true;
        self.status = "password generated — space to hide".to_string();
    }

    // ── Transitions ────────────────────────────────────────────────────────

    fn start_add(&mut self) {
        self.username.clear();
        self.password.clear();
        self.description.clear();
        self.focus = InputMode::Username;
        self.show_password = false;
        self.status.clear();
        self.mode = Mode::Add;
    }

    fn open_entry(&mut self, i: usize) {
        if let Some(cache) = self.cache.as_mut() {
            if let Some(e) = cache.get_entry(i) {
                self.entry = Some(e);
                self.show_password = false;
                self.mode = Mode::View;
            }
        }
    }

    fn refresh_entry(&mut self) {
        if let Some(i) = self.selected {
            if let Some(cache) = self.cache.as_mut() {
                self.entry = cache.get_entry(i);
                self.show_password = false;
            }
        }
    }

    fn start_edit(&mut self) {
        if let Some(e) = self.entry.clone() {
            self.username = Zeroizing::new(e.username.clone());
            self.password = Zeroizing::new(e.password.clone());
            self.description = Zeroizing::new(e.description.clone());
            self.focus = InputMode::Username;
            self.show_password = false;
            self.status.clear();
            self.mode = Mode::Edit;
        }
    }

    fn cancel_edit(&mut self) {
        // Restore the cached entry (no decrypt needed if already cached).
        self.refresh_entry();
        self.show_password = false;
        self.mode = Mode::View;
    }

    fn commit_add(&mut self) {
        if self.username.is_empty() {
            self.status = "username cannot be empty".to_string();
            return;
        }
        let new_entry = Entry::new(
            self.username.to_string(),
            self.password.to_string(),
            self.description.to_string(),
        );
        if let Some(cache) = self.cache.as_mut() {
            match cache.add_entry(&new_entry) {
                Ok(()) => {
                    self.selected = Some(cache.len() - 1);
                    let n = cache.len();
                    self.status = format!("saved — {n} entr{}", if n == 1 { "y" } else { "ies" });
                    self.username.clear();
                    self.password.clear();
                    self.description.clear();
                    self.show_password = false;
                    self.focus = InputMode::Username;
                    self.mode = Mode::Browse;
                }
                Err(e) => self.status = format!("save error: {e}"),
            }
        }
    }

    fn commit_edit(&mut self) {
        if self.username.is_empty() {
            self.status = "username cannot be empty".to_string();
            return;
        }
        let i = match self.selected {
            Some(i) => i,
            None => return,
        };
        let updated = Entry::new(
            self.username.to_string(),
            self.password.to_string(),
            self.description.to_string(),
        );
        if let Some(cache) = self.cache.as_mut() {
            match cache.update_entry(i, &updated) {
                Ok(()) => {
                    self.entry = Some(updated);
                    self.status = "entry updated".to_string();
                    self.show_password = false;
                    self.mode = Mode::View;
                }
                Err(e) => self.status = format!("save error: {e}"),
            }
        }
    }

    fn handle_confirm_delete(&mut self, key: Key, i: usize) {
        match key {
            Key::Char('y') | Key::Char('Y') => self.do_delete(i),
            _ => {
                self.mode = Mode::Browse;
                self.status = "delete cancelled".to_string();
            }
        }
    }

    fn do_delete(&mut self, i: usize) {
        if let Some(cache) = self.cache.as_mut() {
            match cache.delete_entry(i) {
                Ok(()) => self.status = "entry deleted".to_string(),
                Err(e) => self.status = format!("delete failed: {e}"),
            }
        }
        self.entry = None;
        self.show_password = false;
        self.mode = Mode::Browse;
        self.clamp_selection();
    }
}
