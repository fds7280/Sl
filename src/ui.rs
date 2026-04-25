use ratatui::{
    backend::CrosstermBackend,
    Terminal,
    widgets::{Block, Borders, BorderType, Paragraph, List, ListItem, ListState},
    layout::{Layout, Constraint, Direction},
    style::{Style, Color, Modifier},
};
use crossterm::{
    event::{self, EnableMouseCapture, DisableMouseCapture, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use std::io;
use std::time::{Instant, Duration};
use crate::back::Entry;
use crate::enc::{generate_salt, encrypt_entry, decrypt_entry, EncryptedEntry, SALT_LEN};
use zeroize::Zeroize;

// ── Palette ────────────────────────────────────────────────────────────────
fn col_lime() -> Color { Color::Rgb(0xE6, 0xF0, 0x82) }
fn col_gold() -> Color { Color::Rgb(0xD8, 0xD3, 0x65) }
fn col_warm() -> Color { Color::Rgb(0x60, 0x5B, 0x51) }
fn col_dark() -> Color { Color::Rgb(0x45, 0x40, 0x40) }

fn active_block(title: &str) -> Block<'_> {
    Block::default()
        .title(format!(" {} ", title))
        .title_style(Style::default().fg(col_gold()).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(col_gold()))
        .style(Style::default().bg(col_dark()))
}

fn inactive_block(title: &str) -> Block<'_> {
    Block::default()
        .title(format!(" {} ", title))
        .title_style(Style::default().fg(col_warm()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(col_warm()))
        .style(Style::default().bg(col_dark()))
}

fn hint_style() -> Style { Style::default().fg(col_warm()) }
fn text_style() -> Style { Style::default().fg(col_lime()) }
fn dim_style()  -> Style { Style::default().fg(col_warm()) }

fn vault_path() -> String { crate::vault::default_vault_path() }

// ── Password generator ─────────────────────────────────────────────────────
// 32 chars, 94-char printable-ASCII charset, rejection-sampled (unbiased).
fn gen_password() -> String {
    use aes_gcm::aead::rand_core::RngCore;
    use aes_gcm::aead::OsRng;
    // Full printable ASCII minus space (0x21–0x7E) = 94 symbols.
    // Covers every category: lower, upper, digit, all common specials.
    const CHARS: &[u8] =
        b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ\
          0123456789!@#$%^&*()-_=+[]{}|;:,.<>?/~`";
    const LEN: usize   = CHARS.len();           // 94
    const CAP: usize   = 32;                    // output length
    // Rejection sampling: discard values that would cause modulo bias.
    // Largest multiple of LEN that fits in u8: 256 - (256 % LEN)
    const LIMIT: u8    = (256 - (256 % LEN)) as u8;
    let mut rng  = OsRng;
    let mut out  = String::with_capacity(CAP);
    let mut buf  = [0u8; 1];
    while out.len() < CAP {
        rng.fill_bytes(&mut buf);
        if buf[0] < LIMIT {
            out.push(CHARS[buf[0] as usize % LEN] as char);
        }
    }
    out
}

// ── Clipboard ─────────────────────────────────────────────────────────────
// On Linux (X11/Wayland) arboard requires the owner process to keep the
// Clipboard object alive — the moment it is dropped the selection is cleared.
// We therefore open it once, reuse it for every write, and keep it alive for
// the duration of the TUI session.  The Option lets us degrade gracefully if
// the clipboard server is unavailable (e.g. inside a headless container).
struct ClipboardOwner(Option<arboard::Clipboard>);

impl ClipboardOwner {
    fn new() -> Self { Self(arboard::Clipboard::new().ok()) }

    fn set(&mut self, text: &str) -> bool {
        match &mut self.0 {
            Some(cb) => cb.set_text(text).is_ok(),
            None     => false,
        }
    }

    fn clear(&mut self) { let _ = self.set(""); }
}

// ── Modes ──────────────────────────────────────────────────────────────────
enum InputMode { Username, Password, Description }
enum AppMode   { Outside, Browsing, Viewing, Adding, Editing }

pub fn init_tui() -> Result<(), Box<dyn std::error::Error>> {

    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let mut username    = String::new();
    let mut password    = String::new();
    let mut description = String::new();
    let mut master_pass = String::new();

    let mut clipboard     = ClipboardOwner::new();
    let mut saved_entries: Vec<EncryptedEntry> = Vec::new();
    let mut vault_salt: Option<[u8; SALT_LEN]> = None;
    let mut status_msg                         = String::new();
    let mut display_names: Vec<String>         = Vec::new();
    let mut selected_entry: Option<Entry>      = None;
    let mut editing_index: Option<usize>       = None;
    let mut show_password                      = false;
    let mut clip_timer: Option<Instant>        = None;

    let mut list_state   = ListState::default();
    let mut current_mode = InputMode::Username;
    let mut app_mode     = AppMode::Outside;

    // Rebuilds username list for the sidebar — never called in draw loop
    macro_rules! rebuild_display {
        () => {
            display_names = saved_entries
                .iter()
                .filter_map(|enc| decrypt_entry(enc, &master_pass).ok())
                .map(|e| e.username)
                .collect();
        };
    }

    // Saves vault to disk — used after add/edit
    macro_rules! save_vault {
        () => {
            let salt  = vault_salt.get_or_insert_with(generate_salt);
            let vault = crate::vault::Vault { entries: saved_entries.clone() };
            match crate::vault::save_vault(&vault, &master_pass, salt, &vault_path()) {
                Ok(_)  => {}
                Err(e) => status_msg = format!("save failed: {e}"),
            }
        };
    }

    loop {
        // ── Auto-clear clipboard after 30s ────────────────────────────────
        if let Some(t) = clip_timer {
            if t.elapsed() > Duration::from_secs(30) {
                clipboard.clear();
                clip_timer = None;
                status_msg = "clipboard cleared".to_string();
            }
        }

        terminal.draw(|f| {
            let bg = Block::default().style(Style::default().bg(col_dark()));
            f.render_widget(bg, f.area());

            match app_mode {

                // ── Outside ───────────────────────────────────────────────
                AppMode::Outside => {
                    let vchunks = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Percentage(38),
                            Constraint::Length(1),
                            Constraint::Length(3),
                            Constraint::Length(1),
                            Constraint::Length(1),
                            Constraint::Percentage(38),
                        ])
                        .split(f.area());

                    let mp = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([
                            Constraint::Percentage(25),
                            Constraint::Percentage(50),
                            Constraint::Percentage(25),
                        ])
                        .split(vchunks[2]);

                    f.render_widget(
                        Paragraph::new("◈  S T A T E L O C K  ◈")
                            .style(Style::default().fg(col_gold()).add_modifier(Modifier::BOLD))
                            .alignment(ratatui::layout::Alignment::Center),
                        vchunks[1],
                    );

                    let stars: String = master_pass.chars().map(|_| '•').collect();
                    f.render_widget(
                        Paragraph::new(stars).style(text_style())
                            .block(active_block("Master Password — Enter to unlock")),
                        mp[1],
                    );

                    let hint_text = if crate::vault::vault_exists(&vault_path()) {
                        "vault.sl found — enter password to unlock"
                    } else {
                        "no vault found — enter password to create one"
                    };
                    f.render_widget(
                        Paragraph::new(hint_text).style(hint_style())
                            .alignment(ratatui::layout::Alignment::Center),
                        vchunks[4],
                    );
                }

                // ── Browsing ──────────────────────────────────────────────
                AppMode::Browsing => {
                    let chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
                        .split(f.area());

                    let items: Vec<ListItem> = display_names.iter()
                        .map(|n| ListItem::new(format!("  {}  ", n)).style(Style::default().fg(col_lime())))
                        .collect();

                    let t = format!("Entries ({})", saved_entries.len());
                    let list = List::new(items).block(active_block(&t))
                        .highlight_style(Style::default().bg(col_gold()).fg(col_dark()).add_modifier(Modifier::BOLD))
                        .highlight_symbol("▶ ");
                    f.render_stateful_widget(list, chunks[0], &mut list_state.clone());

                    let rc = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([Constraint::Min(1), Constraint::Length(3)])
                        .split(chunks[1]);

                    let body = if saved_entries.is_empty() {
                        "\n  No entries yet.\n\n  Press A to add your first entry.".to_string()
                    } else {
                        format!("\n  {}\n\n  ↑↓ navigate   Enter view   A add   Esc quit", status_msg)
                    };
                    f.render_widget(Paragraph::new(body).style(text_style()).block(inactive_block("Details")), rc[0]);
                    f.render_widget(
                        Paragraph::new("  ↑↓ navigate   Enter view   A add   Esc quit").style(hint_style()),
                        rc[1],
                    );
                }

                // ── Viewing ───────────────────────────────────────────────
                AppMode::Viewing => {
                    let chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
                        .split(f.area());

                    let items: Vec<ListItem> = display_names.iter()
                        .map(|n| ListItem::new(format!("  {}  ", n)).style(Style::default().fg(col_lime())))
                        .collect();

                    let t2 = format!("Entries ({})", saved_entries.len());
                    let list = List::new(items).block(inactive_block(&t2))
                        .highlight_style(Style::default().bg(col_gold()).fg(col_dark()).add_modifier(Modifier::BOLD))
                        .highlight_symbol("▶ ");
                    f.render_stateful_widget(list, chunks[0], &mut list_state.clone());

                    if let Some(ref e) = selected_entry {
                        let rc = Layout::default()
                            .direction(Direction::Vertical)
                            .constraints([
                                Constraint::Length(3),
                                Constraint::Length(3),
                                Constraint::Length(3),
                                Constraint::Length(3),
                                Constraint::Min(1),
                            ])
                            .split(chunks[1]);

                        let pass_text = if show_password { format!("  {}", e.password) }
                                        else { format!("  {}", "•".repeat(e.password.len())) };

                        let clip_info = if let Some(t) = clip_timer {
                            let secs = 30u64.saturating_sub(t.elapsed().as_secs());
                            format!("  clipboard clears in {}s", secs)
                        } else {
                            format!("  {}", status_msg)
                        };

                        let pass_title = if show_password { "Password  [Space] hide  [C] copy" }
                                         else             { "Password  [Space] reveal  [C] copy" };

                        f.render_widget(Paragraph::new(format!("  {}", e.username)).style(text_style()).block(inactive_block("Username")), rc[0]);
                        f.render_widget(Paragraph::new(pass_text).style(text_style()).block(inactive_block(pass_title)), rc[1]);
                        f.render_widget(Paragraph::new(format!("  {}", e.description)).style(text_style()).block(inactive_block("Description")), rc[2]);
                        f.render_widget(Paragraph::new(clip_info).style(hint_style()).block(inactive_block("Status")), rc[3]);
                        f.render_widget(
                            Paragraph::new("  ↑↓ navigate   → edit   Space toggle   C copy password   Esc back")
                                .style(hint_style()),
                            rc[4],
                        );
                    }
                }

                // ── Adding ────────────────────────────────────────────────
                AppMode::Adding => {
                    let chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
                        .split(f.area());

                    f.render_widget(
                        List::new(display_names.iter()
                            .map(|n| ListItem::new(format!("  {}  ", n)).style(dim_style()))
                            .collect::<Vec<_>>())
                        .block(inactive_block("Entries")),
                        chunks[0],
                    );

                    let rc = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Min(1),
                        ])
                        .split(chunks[1]);

                    let pass_label = match current_mode {
                        InputMode::Password if show_password => "Password ◀  [Space] hide  [G] generate",
                        InputMode::Password                  => "Password ◀  [Space] reveal  [G] generate",
                        _                                    => "Password  [G] generate",
                    };
                    let (ub, pb, db) = match current_mode {
                        InputMode::Username    => (active_block("Username ◀"),    inactive_block(pass_label),  inactive_block("Description")),
                        InputMode::Password    => (inactive_block("Username"),    active_block(pass_label),    inactive_block("Description")),
                        InputMode::Description => (inactive_block("Username"),    inactive_block(pass_label),  active_block("Description ◀")),
                    };

                    let pass_display: String = if show_password {
                        format!("  {}", password)
                    } else {
                        format!("  {}", "•".repeat(password.len()))
                    };
                    f.render_widget(Paragraph::new(format!("  {}", username)).style(text_style()).block(ub), rc[0]);
                    f.render_widget(Paragraph::new(pass_display).style(text_style()).block(pb), rc[1]);
                    f.render_widget(Paragraph::new(format!("  {}", description)).style(text_style()).block(db), rc[2]);
                    f.render_widget(
                        Paragraph::new(format!("  {}  │  Tab switch   G generate   Space toggle   Enter save   Esc cancel", status_msg))
                            .style(hint_style()).block(inactive_block("New Entry")),
                        rc[3],
                    );
                }

                // ── Editing ───────────────────────────────────────────────
                AppMode::Editing => {
                    let chunks = Layout::default()
                        .direction(Direction::Horizontal)
                        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
                        .split(f.area());

                    let list = List::new(display_names.iter()
                        .map(|n| ListItem::new(format!("  {}  ", n)).style(dim_style()))
                        .collect::<Vec<_>>())
                        .block(inactive_block("Entries"))
                        .highlight_style(Style::default().bg(col_warm()).fg(col_lime()).add_modifier(Modifier::BOLD))
                        .highlight_symbol("▶ ");
                    f.render_stateful_widget(list, chunks[0], &mut list_state.clone());

                    let rc = Layout::default()
                        .direction(Direction::Vertical)
                        .constraints([
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Length(3),
                            Constraint::Min(1),
                        ])
                        .split(chunks[1]);

                    let pass_display = if show_password { format!("  {}", password) }
                                       else { format!("  {}", "•".repeat(password.len())) };
                    let pass_title   = if show_password { "Password ◀  [Space] hide" }
                                       else { "Password ◀  [Space] reveal" };

                    let (ub, db) = match current_mode {
                        InputMode::Username    => (active_block("Username ◀ editing"), inactive_block("Description")),
                        InputMode::Password    => (inactive_block("Username"),          inactive_block("Description")),
                        InputMode::Description => (inactive_block("Username"),          active_block("Description ◀ editing")),
                    };
                    let pb = match current_mode {
                        InputMode::Password => active_block(pass_title),
                        _                  => inactive_block(pass_title),
                    };

                    f.render_widget(Paragraph::new(format!("  {}", username)).style(text_style()).block(ub), rc[0]);
                    f.render_widget(Paragraph::new(pass_display).style(text_style()).block(pb), rc[1]);
                    f.render_widget(Paragraph::new(format!("  {}", description)).style(text_style()).block(db), rc[2]);
                    f.render_widget(
                        Paragraph::new(format!("  {}  │  Tab switch   G generate   Space toggle   Enter save   Esc cancel", status_msg))
                            .style(hint_style()).block(active_block("✎ Editing Entry")),
                        rc[3],
                    );
                }
            }
        })?;

        // ── Event loop ────────────────────────────────────────────────────
        if event::poll(std::time::Duration::from_millis(100))? {
            if let Event::Key(key) = event::read()? {
                match app_mode {

                    // ── Outside ───────────────────────────────────────────
                    AppMode::Outside => match key.code {
                        KeyCode::Esc => break,

                        KeyCode::Enter => {
                            if master_pass.is_empty() { continue; }
                            if crate::vault::vault_exists(&vault_path()) {
                                match crate::vault::load_vault(&master_pass, &vault_path()) {
                                    Ok((vault, salt)) => {
                                        saved_entries = vault.entries;
                                        vault_salt    = Some(salt);
                                        rebuild_display!();
                                        status_msg = format!("{} entries loaded", saved_entries.len());
                                        if !saved_entries.is_empty() { list_state.select(Some(0)); }
                                        app_mode = AppMode::Browsing;
                                    }
                                    Err(_) => {
                                        master_pass.clear();
                                        status_msg = "wrong password — try again".to_string();
                                    }
                                }
                            } else {
                                vault_salt = Some(generate_salt());
                                status_msg = "new vault created — press A to add entries".to_string();
                                app_mode   = AppMode::Browsing;
                            }
                        }

                        KeyCode::Char(c)   => master_pass.push(c),
                        KeyCode::Backspace => { master_pass.pop(); }
                        _ => {}
                    },

                    // ── Browsing ──────────────────────────────────────────
                    AppMode::Browsing => match key.code {
                        KeyCode::Esc => break,

                        KeyCode::Char('a') | KeyCode::Char('A') => {
                            username.clear(); password.clear(); description.clear();
                            status_msg = String::new(); show_password = false;
                            current_mode = InputMode::Username;
                            app_mode     = AppMode::Adding;
                        }

                        KeyCode::Up => {
                            let len = saved_entries.len();
                            if len == 0 { continue; }
                            let i = match list_state.selected() {
                                Some(i) => if i == 0 { len - 1 } else { i - 1 },
                                None    => 0,
                            };
                            list_state.select(Some(i));
                        }

                        KeyCode::Down => {
                            let len = saved_entries.len();
                            if len == 0 { continue; }
                            let i = match list_state.selected() {
                                Some(i) => if i >= len - 1 { 0 } else { i + 1 },
                                None    => 0,
                            };
                            list_state.select(Some(i));
                        }

                        KeyCode::Enter => {
                            if let Some(i) = list_state.selected() {
                                if let Some(enc) = saved_entries.get(i) {
                                    match decrypt_entry(enc, &master_pass) {
                                        Ok(entry) => {
                                            selected_entry = Some(entry);
                                            show_password  = false;
                                            app_mode       = AppMode::Viewing;
                                        }
                                        Err(e) => status_msg = format!("decrypt error: {e}"),
                                    }
                                }
                            }
                        }

                        _ => {}
                    },

                    // ── Viewing ───────────────────────────────────────────
                    AppMode::Viewing => match key.code {
                        KeyCode::Esc => {
                            selected_entry = None;
                            show_password  = false;
                            app_mode       = AppMode::Browsing;
                        }

                        KeyCode::Char(' ') => show_password = !show_password,

                        // C — copy password, start 30s auto-clear timer
                        KeyCode::Char('c') | KeyCode::Char('C') => {
                            if let Some(ref e) = selected_entry {
                                if clipboard.set(&e.password) {
                                    clip_timer = Some(Instant::now());
                                    status_msg = "password copied — clears in 30s".to_string();
                                } else {
                                    status_msg = "clipboard unavailable".to_string();
                                }
                            }
                        }

                        KeyCode::Right => {
                            if let Some(i) = list_state.selected() {
                                if let Some(ref e) = selected_entry.clone() {
                                    username      = e.username.clone();
                                    password      = e.password.clone();
                                    description   = e.description.clone();
                                    editing_index = Some(i);
                                    current_mode  = InputMode::Username;
                                    show_password = false;
                                    status_msg    = String::new();
                                    app_mode      = AppMode::Editing;
                                }
                            }
                        }

                        KeyCode::Up => {
                            let len = saved_entries.len();
                            if len == 0 { continue; }
                            let i = match list_state.selected() {
                                Some(i) => if i == 0 { len - 1 } else { i - 1 },
                                None    => 0,
                            };
                            list_state.select(Some(i));
                            if let Some(enc) = saved_entries.get(i) {
                                selected_entry = decrypt_entry(enc, &master_pass).ok();
                                show_password  = false;
                            }
                        }

                        KeyCode::Down => {
                            let len = saved_entries.len();
                            if len == 0 { continue; }
                            let i = match list_state.selected() {
                                Some(i) => if i >= len - 1 { 0 } else { i + 1 },
                                None    => 0,
                            };
                            list_state.select(Some(i));
                            if let Some(enc) = saved_entries.get(i) {
                                selected_entry = decrypt_entry(enc, &master_pass).ok();
                                show_password  = false;
                            }
                        }

                        _ => {}
                    },

                    // ── Editing ───────────────────────────────────────────
                    AppMode::Editing => match key.code {
                        KeyCode::Esc => {
                            if let Some(i) = editing_index {
                                if let Some(enc) = saved_entries.get(i) {
                                    selected_entry = decrypt_entry(enc, &master_pass).ok();
                                }
                            }
                            editing_index = None;
                            show_password = false;
                            app_mode      = AppMode::Viewing;
                        }

                        // G — generate random password
                        KeyCode::Char('g') | KeyCode::Char('G') => {
                            password   = gen_password();
                            status_msg = "password generated".to_string();
                        }

                        KeyCode::Char(' ') => {
                            if matches!(current_mode, InputMode::Password) {
                                show_password = !show_password;
                            } else {
                                match current_mode {
                                    InputMode::Username    => username.push(' '),
                                    InputMode::Description => description.push(' '),
                                    InputMode::Password    => {}
                                }
                            }
                        }

                        KeyCode::Tab => {
                            current_mode = match current_mode {
                                InputMode::Username    => InputMode::Password,
                                InputMode::Password    => InputMode::Description,
                                InputMode::Description => InputMode::Username,
                            };
                        }

                        KeyCode::Enter => {
                            if username.is_empty() { status_msg = "username cannot be empty".to_string(); continue; }
                            if let Some(idx) = editing_index {
                                let updated = Entry {
                                    username:    username.clone(),
                                    password:    password.clone(),
                                    description: description.clone(),
                                };
                                match encrypt_entry(&updated, &master_pass) {
                                    Ok(enc) => {
                                        if idx < saved_entries.len() { saved_entries[idx] = enc; }
                                        rebuild_display!();
                                        save_vault!();
                                        status_msg     = "entry updated".to_string();
                                        selected_entry = Some(updated);
                                        editing_index  = None;
                                        show_password  = false;
                                        app_mode       = AppMode::Viewing;
                                    }
                                    Err(e) => status_msg = format!("encrypt error: {e}"),
                                }
                            }
                        }

                        KeyCode::Char(c) => match current_mode {
                            InputMode::Username    => username.push(c),
                            InputMode::Password    => password.push(c),
                            InputMode::Description => description.push(c),
                        },

                        KeyCode::Backspace => match current_mode {
                            InputMode::Username    => { username.pop(); }
                            InputMode::Password    => { password.pop(); }
                            InputMode::Description => { description.pop(); }
                        },

                        _ => {}
                    },

                    // ── Adding ────────────────────────────────────────────
                    AppMode::Adding => match key.code {
                        KeyCode::Esc => {
                            show_password = false;
                            app_mode = AppMode::Browsing;
                        }

                        // G — generate random password (only when focused on password field)
                        KeyCode::Char(c @ ('g' | 'G')) => {
                            if matches!(current_mode, InputMode::Password) {
                                password      = gen_password();
                                show_password = true;   // reveal so the user can see what was generated
                                status_msg    = "password generated — Space to hide".to_string();
                            } else {
                                match current_mode {
                                    InputMode::Username    => username.push(c),
                                    InputMode::Description => description.push(c),
                                    InputMode::Password    => {}
                                }
                            }
                        }

                        // Space — toggle visibility on password field, insert space elsewhere
                        KeyCode::Char(' ') => {
                            if matches!(current_mode, InputMode::Password) {
                                show_password = !show_password;
                            } else {
                                match current_mode {
                                    InputMode::Username    => username.push(' '),
                                    InputMode::Description => description.push(' '),
                                    InputMode::Password    => {}
                                }
                            }
                        }

                        KeyCode::Tab => {
                            current_mode = match current_mode {
                                InputMode::Username    => InputMode::Password,
                                InputMode::Password    => InputMode::Description,
                                InputMode::Description => InputMode::Username,
                            };
                        }

                        KeyCode::Enter => {
                            if username.is_empty() { status_msg = "username cannot be empty".to_string(); continue; }
                            let new_entry = Entry {
                                username:    username.clone(),
                                password:    password.clone(),
                                description: description.clone(),
                            };
                            match encrypt_entry(&new_entry, &master_pass) {
                                Ok(enc) => {
                                    saved_entries.push(enc);
                                    list_state.select(Some(saved_entries.len() - 1));
                                    rebuild_display!();
                                    save_vault!();
                                    status_msg = format!("saved — {} entries", saved_entries.len());
                                    username.clear(); password.clear(); description.clear();
                                    show_password = false;
                                    current_mode = InputMode::Username;
                                    app_mode     = AppMode::Browsing;
                                }
                                Err(e) => status_msg = format!("encrypt error: {e}"),
                            }
                        }

                        KeyCode::Char(c) => match current_mode {
                            InputMode::Username    => username.push(c),
                            InputMode::Password    => password.push(c),
                            InputMode::Description => description.push(c),
                        },

                        KeyCode::Backspace => match current_mode {
                            InputMode::Username    => { username.pop(); }
                            InputMode::Password    => { password.pop(); }
                            InputMode::Description => { description.pop(); }
                        },

                        _ => {}
                    },
                }
            }
        }
    }

    master_pass.zeroize();
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen, DisableMouseCapture)?;
    terminal.show_cursor()?;
    Ok(())
}
