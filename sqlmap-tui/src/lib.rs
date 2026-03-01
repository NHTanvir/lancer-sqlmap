//! sqlmap-tui
//!
//! Interactive REPL surfaces for `--sql-shell` and `--os-shell`. ratatui
//! renders a three-row layout:
//!
//! ```text
//!   ┌─ history ─────────────────────────────────┐
//!   │ > SELECT user(); → root@localhost          │
//!   │ > SHOW DATABASES; → mysql, information_…   │
//!   └────────────────────────────────────────────┘
//!   ┌─ log ───────────────────────────────────────┐
//!   │ [info] 5 queries, 1.2s avg                 │
//!   └────────────────────────────────────────────┘
//!   sql> █
//! ```
//!
//! The actual SQL execution is delegated to a `QueryRunner` callback so the
//! TUI stays decoupled from `sqlmap-techniques`.

use crossterm::event::{Event, KeyCode, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Modifier, Style};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};
use ratatui::Terminal;
use std::future::Future;
use std::io;
use std::pin::Pin;

/// Kind of shell this session is.
#[derive(Debug, Clone, Copy)]
pub enum ShellKind {
    Sql,
    Os,
}

impl ShellKind {
    fn prompt(self) -> &'static str {
        match self {
            Self::Sql => "sql> ",
            Self::Os => "os> ",
        }
    }
    fn title(self) -> &'static str {
        match self {
            Self::Sql => "SQL Shell",
            Self::Os => "OS Shell",
        }
    }
}

/// Pluggable query runner. Returns the displayable response string.
pub type QueryRunner =
    Box<dyn for<'a> Fn(&'a str) -> Pin<Box<dyn Future<Output = anyhow::Result<String>> + Send + 'a>> + Send + Sync>;

pub struct Repl {
    kind: ShellKind,
    history: Vec<(String, String)>,
    log: Vec<String>,
    input: String,
}

impl Repl {
    pub fn new(kind: ShellKind) -> Self {
        Self {
            kind,
            history: Vec::new(),
            log: vec!["press Ctrl-C or :exit to quit".into()],
            input: String::new(),
        }
    }

    pub async fn run(&mut self, runner: QueryRunner) -> anyhow::Result<()> {
        enable_raw_mode()?;
        let mut stdout = io::stdout();
        crossterm::execute!(stdout, EnterAlternateScreen)?;
        let backend = CrosstermBackend::new(stdout);
        let mut terminal = Terminal::new(backend)?;

        loop {
            terminal.draw(|f| self.render(f))?;
            if crossterm::event::poll(std::time::Duration::from_millis(100))? {
                if let Event::Key(k) = crossterm::event::read()? {
                    match (k.code, k.modifiers) {
                        (KeyCode::Char('c'), KeyModifiers::CONTROL) => break,
                        (KeyCode::Esc, _) => break,
                        (KeyCode::Enter, _) => {
                            let q = self.input.trim().to_string();
                            self.input.clear();
                            if q.is_empty() {
                                continue;
                            }
                            if q == ":exit" || q == ":quit" || q == ":q" {
                                break;
                            }
                            self.log.push(format!("running: {}", q));
                            match runner(&q).await {
                                Ok(out) => self.history.push((q, out)),
                                Err(e) => self.log.push(format!("error: {e}")),
                            }
                        }
                        (KeyCode::Backspace, _) => {
                            self.input.pop();
                        }
                        (KeyCode::Char(c), _) => self.input.push(c),
                        _ => {}
                    }
                }
            }
        }

        disable_raw_mode()?;
        crossterm::execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
        terminal.show_cursor()?;
        Ok(())
    }

    fn render<B: ratatui::backend::Backend>(&self, f: &mut ratatui::Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Min(5),
                Constraint::Length(5),
                Constraint::Length(3),
            ])
            .split(f.size());

        let hist_items: Vec<ListItem> = self
            .history
            .iter()
            .map(|(q, a)| ListItem::new(format!("> {q}\n→ {a}")))
            .collect();
        let hist = List::new(hist_items).block(Block::default().borders(Borders::ALL).title(self.kind.title()));
        f.render_widget(hist, chunks[0]);

        let log_items: Vec<ListItem> = self.log.iter().map(|l| ListItem::new(l.as_str())).collect();
        let logw = List::new(log_items).block(Block::default().borders(Borders::ALL).title("log"));
        f.render_widget(logw, chunks[1]);

        let prompt = format!("{}{}", self.kind.prompt(), self.input);
        let input = Paragraph::new(prompt)
            .style(Style::default().add_modifier(Modifier::BOLD))
            .block(Block::default().borders(Borders::ALL).title("input"));
        f.render_widget(input, chunks[2]);
    }
}
