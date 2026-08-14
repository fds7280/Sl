//! Clipboard abstraction, so the app logic stays testable without a display.

/// Minimal clipboard backend.
pub trait Clipboard {
    fn set_text(&mut self, text: &str) -> Result<(), String>;

    fn clear(&mut self) {
        let _ = self.set_text("");
    }
}

/// Real system clipboard via `arboard`, held open for the whole session so
/// X11/Wayland does not drop the selection immediately after it is set.
pub struct SystemClipboard(Option<arboard::Clipboard>);

impl SystemClipboard {
    pub fn new() -> Self {
        // Headless/wayland-less environments yield `None`; the app then
        // reports "clipboard unavailable" instead of crashing.
        Self(arboard::Clipboard::new().ok())
    }
}

impl Default for SystemClipboard {
    fn default() -> Self {
        Self::new()
    }
}

impl Clipboard for SystemClipboard {
    fn set_text(&mut self, text: &str) -> Result<(), String> {
        self.0
            .as_mut()
            .ok_or_else(|| "no clipboard available".to_string())?
            .set_text(text)
            .map_err(|e| e.to_string())
    }
}

/// Clipboard that always fails — used in tests and headless environments.
#[derive(Default)]
pub struct NullClipboard;

impl Clipboard for NullClipboard {
    fn set_text(&mut self, _text: &str) -> Result<(), String> {
        Err("clipboard unavailable".to_string())
    }
}
