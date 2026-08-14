//! Terminal rendering and the event loop.
//!
//! This module is deliberately thin: it translates crossterm events into
//! [`Key`]s, forwards them to [`App`], and renders a pure snapshot of the
//! app's state. All decision-making lives in [`crate::app`].

use std::io;
use std::time::Duration;

use crossterm::{
    event::{
        self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEvent, KeyModifiers,
    },
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Alignment, Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    widgets::{Block, BorderType, Borders, List, ListItem, ListState, Paragraph},
    Frame, Terminal,
};

use crate::app::{App, InputMode, Key, Mode};
use crate::clipboard::SystemClipboard;

// ── Palette ────────────────────────────────────────────────────────────────
fn col_lime() -> Color {
    Color::Rgb(0xE6, 0xF0, 0x82)
}
fn col_gold() -> Color {
    Color::Rgb(0xD8, 0xD3, 0x65)
}
fn col_warm() -> Color {
    Color::Rgb(0x60, 0x5B, 0x51)
}
fn col_dark() -> Color {
    Color::Rgb(0x45, 0x40, 0x40)
}

fn active_block(title: &str) -> Block<'static> {
    Block::default()
        .title(format!(" {title} "))
        .title_style(Style::default().fg(col_gold()).add_modifier(Modifier::BOLD))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(col_gold()))
        .style(Style::default().bg(col_dark()))
}

fn inactive_block(title: &str) -> Block<'static> {
    Block::default()
        .title(format!(" {title} "))
        .title_style(Style::default().fg(col_warm()))
        .borders(Borders::ALL)
        .border_type(BorderType::Rounded)
        .border_style(Style::default().fg(col_warm()))
        .style(Style::default().bg(col_dark()))
}

fn hint_style() -> Style {
    Style::default().fg(col_warm())
}
fn text_style() -> Style {
    Style::default().fg(col_lime())
}
fn dim_style() -> Style {
    Style::default().fg(col_warm())
}

const HELP: &str = "  ↑↓ navigate   enter view   a add   d delete   / search   esc quit";
const HELP_VIEW: &str =
    "  ↑↓ navigate   → edit   space toggle   c copy pw   u copy user   esc back";

// ── Entry point ────────────────────────────────────────────────────────────

/// Run the TUI until the user quits.
pub fn run() -> Result<(), Box<dyn std::error::Error>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    let res = run_loop(&mut terminal);

    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    res
}

fn run_loop(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut app = App::new(Box::new(SystemClipboard::new()));

    loop {
        app.maybe_clear_clipboard();
        terminal.draw(|f| draw(f, &app))?;

        // 16ms poll ≈ 60 fps ceiling — snappy without busy-looping.
        if event::poll(Duration::from_millis(16))? {
            if let Event::Key(ev) = event::read()? {
                if let Some(key) = map_key(ev) {
                    app.handle_key(key);
                }
            }
        }

        if app.quit {
            break;
        }
    }
    Ok(())
}

/// Translate a crossterm [`KeyEvent`] into an app [`Key`], if it is one we
/// care about.
fn map_key(ev: KeyEvent) -> Option<Key> {
    use KeyCode::*;
    match ev.code {
        Char(c) => {
            let ctrl = ev.modifiers.contains(KeyModifiers::CONTROL);
            match c {
                ' ' if !ctrl => Some(Key::Space),
                'g' | 'G' if ctrl => Some(Key::Ctrl('g')),
                _ if ctrl => None, // ignore other Ctrl combos (Ctrl+C etc.)
                _ => Some(Key::Char(c)),
            }
        }
        Enter => Some(Key::Enter),
        Esc => Some(Key::Esc),
        Tab => Some(Key::Tab),
        Backspace => Some(Key::Backspace),
        Up => Some(Key::Up),
        Down => Some(Key::Down),
        Left => Some(Key::Left),
        Right => Some(Key::Right),
        _ => None,
    }
}

// ── Layout helpers ─────────────────────────────────────────────────────────

fn two_col(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(28), Constraint::Percentage(72)])
        .split(area)
        .to_vec()
}

/// Build the sidebar list from the app's *visible* (filtered) indices.
fn entry_list<'a>(app: &'a App, active: bool) -> List<'a> {
    let names: Vec<String> = app
        .visible_indices()
        .iter()
        .filter_map(|&i| {
            app.cache
                .as_ref()
                .and_then(|c| c.usernames().get(i))
                .cloned()
        })
        .collect();

    let count = app.len();
    let title = format!(" Entries ({count}) ");
    let block = if active {
        active_block(&title)
    } else {
        inactive_block(&title)
    };

    List::new(
        names
            .iter()
            .map(|n| ListItem::new(format!("  {n}  ")).style(text_style())),
    )
    .block(block)
    .highlight_style(
        Style::default()
            .bg(col_gold())
            .fg(col_dark())
            .add_modifier(Modifier::BOLD),
    )
    .highlight_symbol("▶ ")
}

/// Map the app's selected *entry index* to a position in the filtered list.
fn list_state(app: &App) -> ListState {
    let mut st = ListState::default();
    let visible = app.visible_indices();
    if let Some(sel) = app.selected {
        if let Some(pos) = visible.iter().position(|&i| i == sel) {
            st.select(Some(pos));
        }
    }
    st
}

fn render_list(f: &mut Frame, app: &App, area: Rect, active: bool) {
    let list = entry_list(app, active);
    let mut st = list_state(app);
    f.render_stateful_widget(list, area, &mut st);
}

// ── Root draw ──────────────────────────────────────────────────────────────

fn draw(f: &mut Frame, app: &App) {
    let bg = Block::default().style(Style::default().bg(col_dark()));
    f.render_widget(bg, f.area());

    match app.mode {
        Mode::Locked => draw_locked(f, app),
        Mode::Browse => draw_browse(f, app),
        Mode::View => draw_view(f, app),
        Mode::Add => draw_add(f, app),
        Mode::Edit => draw_edit(f, app),
        Mode::ConfirmDelete(i) => {
            draw_browse(f, app);
            draw_confirm(f, app, i);
        }
    }
}

fn draw_locked(f: &mut Frame, app: &App) {
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
            .alignment(Alignment::Center),
        vchunks[1],
    );

    let stars: String = app.master_pass.chars().map(|_| '•').collect();
    f.render_widget(
        Paragraph::new(stars)
            .style(text_style())
            .block(active_block("Master Password — Enter to unlock")),
        mp[1],
    );

    let hint = if vault_exists(&app.vault_path) {
        "vault.sl found — enter password to unlock"
    } else {
        "no vault found — enter password to create one"
    };
    f.render_widget(
        Paragraph::new(hint)
            .style(hint_style())
            .alignment(Alignment::Center),
        vchunks[4],
    );
}

fn draw_browse(f: &mut Frame, app: &App) {
    let chunks = two_col(f.area());
    render_list(f, app, chunks[0], true);

    let rc = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(1), Constraint::Length(3)])
        .split(chunks[1]);

    let body = if app.is_empty() {
        "\n  No entries yet.\n\n  Press a to add your first entry.".to_string()
    } else {
        let s = if app.status.is_empty() {
            "select an entry"
        } else {
            &app.status
        };
        format!("\n  {s}\n\n  {HELP}")
    };
    f.render_widget(
        Paragraph::new(body)
            .style(text_style())
            .block(inactive_block("Details")),
        rc[0],
    );

    let hint = if app.searching {
        format!("  search: {}▌  (esc clears, enter done)", app.search)
    } else {
        HELP.to_string()
    };
    f.render_widget(Paragraph::new(hint).style(hint_style()), rc[1]);
}

fn draw_view(f: &mut Frame, app: &App) {
    let chunks = two_col(f.area());
    render_list(f, app, chunks[0], false);

    let Some(e) = &app.entry else {
        return;
    };

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

    let pass_text = if app.show_password {
        format!("  {}", e.password)
    } else {
        format!("  {}", "•".repeat(e.password.len()))
    };

    let clip_info = match app.clip_remaining {
        Some(s) => format!("  clipboard clears in {s}s"),
        None => format!("  {}", app.status),
    };

    let pass_title = if app.show_password {
        "Password  [space] hide  [c] copy"
    } else {
        "Password  [space] reveal  [c] copy"
    };

    f.render_widget(
        Paragraph::new(format!("  {}", e.username))
            .style(text_style())
            .block(inactive_block("Username")),
        rc[0],
    );
    f.render_widget(
        Paragraph::new(pass_text)
            .style(text_style())
            .block(inactive_block(pass_title)),
        rc[1],
    );
    f.render_widget(
        Paragraph::new(format!("  {}", e.description))
            .style(text_style())
            .block(inactive_block("Description")),
        rc[2],
    );
    f.render_widget(
        Paragraph::new(clip_info)
            .style(hint_style())
            .block(inactive_block("Status")),
        rc[3],
    );
    f.render_widget(Paragraph::new(HELP_VIEW).style(hint_style()), rc[4]);
}

/// The three-field form shared by Add and Edit modes.
fn draw_form(f: &mut Frame, app: &App, title: &str) {
    let chunks = two_col(f.area());

    // Sidebar is dimmed during form editing.
    let names: Vec<String> = app
        .cache
        .as_ref()
        .map(|c| c.usernames().to_vec())
        .unwrap_or_default();
    let list = List::new(
        names
            .iter()
            .map(|n| ListItem::new(format!("  {n}  ")).style(dim_style())),
    )
    .block(inactive_block("Entries"));
    f.render_widget(list, chunks[0]);

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

    let pass_label = if matches!(app.focus, InputMode::Password) {
        if app.show_password {
            "Password ◀  [space] hide  [ctrl+g] generate"
        } else {
            "Password ◀  [space] reveal  [ctrl+g] generate"
        }
    } else {
        "Password  [ctrl+g] generate"
    };

    let (ub, pb, db) = match app.focus {
        InputMode::Username => (
            active_block("Username ◀"),
            inactive_block(pass_label),
            inactive_block("Description"),
        ),
        InputMode::Password => (
            inactive_block("Username"),
            active_block(pass_label),
            inactive_block("Description"),
        ),
        InputMode::Description => (
            inactive_block("Username"),
            inactive_block(pass_label),
            active_block("Description ◀"),
        ),
    };

    let pass_display = if app.show_password {
        format!("  {}", app.password.as_str())
    } else {
        format!("  {}", "•".repeat(app.password.len()))
    };

    f.render_widget(
        Paragraph::new(format!("  {}", app.username.as_str()))
            .style(text_style())
            .block(ub),
        rc[0],
    );
    f.render_widget(
        Paragraph::new(pass_display).style(text_style()).block(pb),
        rc[1],
    );
    f.render_widget(
        Paragraph::new(format!("  {}", app.description.as_str()))
            .style(text_style())
            .block(db),
        rc[2],
    );

    let status = if app.status.is_empty() {
        "  tab switch   ctrl+g generate   space toggle   enter save   esc cancel".to_string()
    } else {
        format!(
            "  {}  │  tab switch   ctrl+g generate   enter save   esc cancel",
            app.status
        )
    };
    f.render_widget(
        Paragraph::new(status)
            .style(hint_style())
            .block(active_block(title)),
        rc[3],
    );
}

fn draw_add(f: &mut Frame, app: &App) {
    draw_form(f, app, "New Entry");
}

fn draw_edit(f: &mut Frame, app: &App) {
    draw_form(f, app, "✎ Editing Entry");
}

fn draw_confirm(f: &mut Frame, app: &App, i: usize) {
    let name = app
        .cache
        .as_ref()
        .and_then(|c| c.usernames().get(i))
        .cloned()
        .unwrap_or_default();

    let area = centered_rect(60, 5, f.area());
    let text = format!("Delete entry \"{name}\"?\n\n  [y]es  /  anything else cancels");
    f.render_widget(
        Paragraph::new(text)
            .style(text_style())
            .block(active_block("Confirm delete"))
            .alignment(Alignment::Center),
        area,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let v = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    let h = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(v[1]);
    h[1]
}

fn vault_exists(path: &str) -> bool {
    crate::vault::vault_exists(path)
}
