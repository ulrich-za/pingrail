//! A single-line text input for TUI forms.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use ratatui::style::Style;
use ratatui::text::{Line, Span};

#[derive(Debug, Clone, Default)]
pub struct Input {
    pub value: String,
    /// Cursor position in characters.
    cursor: usize,
    pub masked: bool,
}

impl Input {
    pub fn new(value: &str) -> Input {
        Input { value: value.to_string(), cursor: value.chars().count(), masked: false }
    }

    pub fn masked() -> Input {
        Input { masked: true, ..Input::default() }
    }

    fn byte_idx(&self, chars: usize) -> usize {
        self.value.char_indices().nth(chars).map(|(i, _)| i).unwrap_or(self.value.len())
    }

    /// Handle an editing key; returns true if it was consumed.
    pub fn handle(&mut self, k: KeyEvent) -> bool {
        let len = self.value.chars().count();
        match k.code {
            KeyCode::Char('u') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                self.value.clear();
                self.cursor = 0;
            }
            KeyCode::Char('w') if k.modifiers.contains(KeyModifiers::CONTROL) => {
                let before: String = self.value.chars().take(self.cursor).collect();
                let trimmed = before.trim_end();
                let cut = trimmed.rfind(|c: char| c.is_whitespace() || c == '.' || c == '/').map(|i| i + 1).unwrap_or(0);
                let keep: String = before[..cut].to_string();
                let rest: String = self.value.chars().skip(self.cursor).collect();
                self.cursor = keep.chars().count();
                self.value = keep + &rest;
            }
            KeyCode::Char(c) if !k.modifiers.contains(KeyModifiers::CONTROL) => {
                let i = self.byte_idx(self.cursor);
                self.value.insert(i, c);
                self.cursor += 1;
            }
            KeyCode::Backspace if self.cursor > 0 => {
                let i = self.byte_idx(self.cursor - 1);
                self.value.remove(i);
                self.cursor -= 1;
            }
            KeyCode::Delete if self.cursor < len => {
                let i = self.byte_idx(self.cursor);
                self.value.remove(i);
            }
            KeyCode::Left if self.cursor > 0 => self.cursor -= 1,
            KeyCode::Right if self.cursor < len => self.cursor += 1,
            KeyCode::Home => self.cursor = 0,
            KeyCode::End => self.cursor = len,
            KeyCode::Backspace | KeyCode::Delete | KeyCode::Left | KeyCode::Right => {}
            _ => return false,
        }
        true
    }

    /// Render as a line, fitting `width` columns, with a cursor when focused.
    pub fn line(&self, width: usize, focused: bool, placeholder: &str) -> Line<'static> {
        let shown: String = if self.masked { "•".repeat(self.value.chars().count()) } else { self.value.clone() };
        if shown.is_empty() && !focused {
            return Line::from(Span::styled(placeholder.to_string(), Style::new().dark_gray().italic()));
        }
        let chars: Vec<char> = shown.chars().collect();
        let width = width.max(2);
        let start = self.cursor.saturating_sub(width - 1);
        let visible: Vec<char> = chars.iter().skip(start).take(width).copied().collect();
        let cur = self.cursor - start;
        let mut spans = Vec::new();
        let before: String = visible.iter().take(cur).collect();
        spans.push(Span::raw(before));
        if focused {
            let at = visible.get(cur).copied().unwrap_or(' ');
            spans.push(Span::styled(at.to_string(), Style::new().reversed()));
            let after: String = visible.iter().skip(cur + 1).collect();
            spans.push(Span::raw(after));
        } else {
            let after: String = visible.iter().skip(cur).collect();
            spans.push(Span::raw(after));
        }
        if shown.is_empty() && focused {
            spans.push(Span::styled(placeholder.to_string(), Style::new().dark_gray().italic()));
        }
        Line::from(spans)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::crossterm::event::KeyEvent;

    fn key(c: KeyCode) -> KeyEvent {
        KeyEvent::new(c, KeyModifiers::NONE)
    }

    #[test]
    fn editing() {
        let mut i = Input::new("8.8.8");
        i.handle(key(KeyCode::Char('.')));
        i.handle(key(KeyCode::Char('8')));
        assert_eq!(i.value, "8.8.8.8");
        i.handle(key(KeyCode::Home));
        i.handle(key(KeyCode::Delete));
        assert_eq!(i.value, ".8.8.8");
        i.handle(key(KeyCode::End));
        i.handle(key(KeyCode::Backspace));
        assert_eq!(i.value, ".8.8.");
    }
}
