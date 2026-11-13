//! Reading agent config files as their agents do: JSON, or JSON with comments and trailing commas
//! (VS Code's `settings.json` and `tasks.json`, Zed, OpenCode's `.jsonc`), possibly behind a
//! byte-order mark, and finding where in the file a given setting was written.

use std::collections::HashMap;

/// `text` without a leading byte-order mark. Windows editors write one, every agent reads past it,
/// and a parser that does not sees a file that "is not JSON": a settings file with hooks behind a
/// BOM used to produce no finding and no error.
pub(crate) fn strip_bom(text: &str) -> &str {
    text.strip_prefix('\u{feff}').unwrap_or(text)
}

/// Parses JSON, or failing that JSON with `//` and `/* */` comments and trailing commas. Strict
/// JSON parses on the first try, so a well-formed file never goes through the comment stripper.
/// The error returned is the one for the comment-stripped text, whose line numbers are the file's.
pub(crate) fn parse(content: &str) -> Result<serde_json::Value, serde_json::Error> {
    let content = strip_bom(content);
    serde_json::from_str(content).or_else(|_| serde_json::from_str(&strip_jsonc(content)))
}

/// Removes `//` and `/* */` comments and trailing commas, leaving string literals alone: a `//`
/// inside `"http://…"` and a `,]` inside `"a,]"` both stay. Works on characters, so text outside
/// ASCII comes through unchanged (it used to be copied byte by byte, which turned `données` into
/// `donnÃ©es` in every finding that quoted it). Line breaks inside a block comment are kept, so a
/// line number in the result is a line number in the file.
pub(crate) fn strip_jsonc(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    let mut in_string = false;
    while let Some(c) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                '\\' => out.extend(chars.next()),
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            '/' if chars.peek() == Some(&'/') => while chars.next_if(|n| *n != '\n').is_some() {},
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                let mut previous = '\0';
                for n in chars.by_ref() {
                    if n == '\n' {
                        out.push('\n');
                    }
                    if previous == '*' && n == '/' {
                        break;
                    }
                    previous = n;
                }
                // A comment separates the tokens on either side of it.
                out.push(' ');
            }
            _ => out.push(c),
        }
    }
    drop_trailing_commas(&out)
}

fn drop_trailing_commas(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.char_indices();
    let mut in_string = false;
    while let Some((at, c)) = chars.next() {
        if in_string {
            out.push(c);
            match c {
                '\\' => out.extend(chars.next().map(|(_, n)| n)),
                '"' => in_string = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
            }
            ',' if text[at + 1..].trim_start().starts_with(['}', ']']) => {}
            _ => out.push(c),
        }
    }
    out
}

/// 1-based line of a byte offset.
pub(crate) fn line_of(text: &str, offset: usize) -> usize {
    text.as_bytes()[..offset.min(text.len())]
        .iter()
        .filter(|&&b| b == b'\n')
        .count()
        + 1
}

/// Where each key and each value of a JSON (or JSONC) document starts, by path.
///
/// A finding points at a line. Searching the text for a server's name finds the first line that
/// *mentions* it: a server called `git` was reported on the line of an earlier server whose
/// arguments contained the word. This records where the key itself is written.
pub(crate) struct Positions {
    keys: HashMap<String, usize>,
    values: HashMap<String, usize>,
}

/// Separates path segments in the maps' keys. A control character, so no real key contains it
/// unescaped.
const SEGMENT: char = '\u{1f}';

/// The most positions recorded for one file. A document with more keys than this is not a config
/// anyone wrote; lookups past it fall back to a text search.
const MAX_POSITIONS: usize = 50_000;

/// Nesting deeper than this is not recorded.
const MAX_DEPTH: usize = 64;

enum Frame {
    Object {
        key: Option<String>,
        wants_key: bool,
    },
    Array {
        index: usize,
    },
}

fn path_of(stack: &[Frame]) -> String {
    let mut path = String::new();
    for (i, frame) in stack.iter().enumerate() {
        if i > 0 {
            path.push(SEGMENT);
        }
        match frame {
            Frame::Object { key, .. } => path.push_str(key.as_deref().unwrap_or("")),
            Frame::Array { index } => path.push_str(&index.to_string()),
        }
    }
    path
}

impl Positions {
    /// Scans `src`. Never fails: text that is not JSON yields whatever was recognisable, and a
    /// lookup that misses falls back to the caller's text search.
    pub(crate) fn scan(src: &str) -> Positions {
        let mut found = Positions {
            keys: HashMap::new(),
            values: HashMap::new(),
        };
        let bytes = src.as_bytes();
        let mut stack: Vec<Frame> = Vec::new();
        let mut i = 0;
        while i < bytes.len() && found.keys.len() + found.values.len() < MAX_POSITIONS {
            let b = bytes[i];
            match b {
                b'/' if bytes.get(i + 1) == Some(&b'/') => {
                    i = src[i..].find('\n').map_or(bytes.len(), |n| i + n);
                    continue;
                }
                b'/' if bytes.get(i + 1) == Some(&b'*') => {
                    i = src[i + 2..]
                        .find("*/")
                        .map_or(bytes.len(), |n| i + 2 + n + 2);
                    continue;
                }
                b'{' | b'[' => {
                    if stack.len() >= MAX_DEPTH {
                        break;
                    }
                    found.value_at(&stack, i);
                    stack.push(if b == b'{' {
                        Frame::Object {
                            key: None,
                            wants_key: true,
                        }
                    } else {
                        Frame::Array { index: 0 }
                    });
                }
                b'}' | b']' => {
                    stack.pop();
                }
                b',' => match stack.last_mut() {
                    Some(Frame::Object { wants_key, .. }) => *wants_key = true,
                    Some(Frame::Array { index }) => *index += 1,
                    None => {}
                },
                b'"' => {
                    let end = string_end(bytes, i);
                    let token = &src[i..end];
                    match stack.last_mut() {
                        Some(Frame::Object { key, wants_key }) if *wants_key => {
                            *key = Some(
                                serde_json::from_str::<String>(token)
                                    .unwrap_or_else(|_| token.trim_matches('"').to_string()),
                            );
                            *wants_key = false;
                            found.keys.insert(path_of(&stack), i);
                        }
                        _ => found.value_at(&stack, i),
                    }
                    i = end;
                    continue;
                }
                b':' => {}
                _ if b.is_ascii_whitespace() => {}
                _ => {
                    // A number, `true`, `false` or `null`.
                    found.value_at(&stack, i);
                    while i < bytes.len()
                        && !bytes[i].is_ascii_whitespace()
                        && !matches!(bytes[i], b',' | b'}' | b']' | b'/')
                    {
                        i += 1;
                    }
                    continue;
                }
            }
            i += 1;
        }
        found
    }

    fn value_at(&mut self, stack: &[Frame], offset: usize) {
        if !stack.is_empty() {
            self.values.entry(path_of(stack)).or_insert(offset);
        }
    }

    /// Offset of the key at `path` (object keys and array indexes, outermost first).
    pub(crate) fn key(&self, path: &[String]) -> Option<usize> {
        self.keys.get(&path.join(&SEGMENT.to_string())).copied()
    }

    /// Offset of the value at `path`.
    pub(crate) fn value(&self, path: &[String]) -> Option<usize> {
        self.values.get(&path.join(&SEGMENT.to_string())).copied()
    }
}

/// Index just past the string literal that opens at `start`.
fn string_end(bytes: &[u8], start: usize) -> usize {
    let mut i = start + 1;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 2,
            b'"' => return i + 1,
            _ => i += 1,
        }
    }
    bytes.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|p| p.to_string()).collect()
    }

    #[test]
    fn comments_and_trailing_commas_go_and_strings_stay() {
        let src = "{\n  // a \"quoted\" note, with http://example.invalid/x\n  \"url\": \"http://h/a,]//b\", /* block\n comment */ \"list\": [1, 2,],\n}";
        let v: serde_json::Value = serde_json::from_str(&strip_jsonc(src)).unwrap();
        assert_eq!(v["url"], "http://h/a,]//b");
        assert_eq!(v["list"], serde_json::json!([1, 2]));
        // Line numbers survive: the block comment's line break is kept.
        assert_eq!(strip_jsonc(src).lines().count(), src.lines().count());
    }

    #[test]
    fn text_outside_ascii_comes_through_unchanged() {
        let src = "{\n  // données — 日本語\n  \"note\": \"données 日本語 👍\",\n}";
        let v = parse(src).unwrap();
        assert_eq!(v["note"], "données 日本語 👍");
        assert!(strip_jsonc(src).contains("données 日本語 👍"));
    }

    #[test]
    fn a_byte_order_mark_is_read_past() {
        let v = parse("\u{feff}{\"a\": 1}").unwrap();
        assert_eq!(v["a"], 1);
        assert_eq!(strip_bom("\u{feff}x"), "x");
        assert_eq!(strip_bom("x"), "x");
    }

    #[test]
    fn broken_json_is_an_error_with_a_place() {
        let e = parse("{\n  \"hooks\": {\"SessionStart\": [\n").unwrap_err();
        assert!(e.line() >= 2, "{e}");
        // An unterminated string or comment ends the scan without panicking.
        let _ = Positions::scan("{\"a\": \"unterminated");
        let _ = Positions::scan("{\"a\": 1 /* never closed");
        let _ = Positions::scan("]]]}}}");
    }

    #[test]
    fn a_key_is_found_where_it_is_written_not_where_it_is_mentioned() {
        let src = "{\n  \"mcpServers\": {\n    \"first\": {\"command\": \"uvx\", \"args\": [\"git\"]},\n    // \"git\": commented out\n    \"git\": {\"command\": \"node\"}\n  }\n}";
        let positions = Positions::scan(src);
        let at = positions.key(&path(&["mcpServers", "git"])).unwrap();
        assert_eq!(line_of(src, at), 5);
        assert_eq!(
            line_of(src, positions.key(&path(&["mcpServers", "first"])).unwrap()),
            3
        );
        // Values, including array elements, by index.
        let arg = positions
            .value(&path(&["mcpServers", "first", "args", "0"]))
            .unwrap();
        assert_eq!(&src[arg..arg + 5], "\"git\"");
        assert!(positions.key(&path(&["mcpServers", "absent"])).is_none());
    }

    #[test]
    fn escaped_keys_and_dotted_keys_are_matched_as_written_in_the_value() {
        let src =
            r#"{"a\"b": {"chat.tools.autoApprove": true}, "list": [{"name": "x"}, {"name": "y"}]}"#;
        let positions = Positions::scan(src);
        assert!(positions
            .key(&path(&["a\"b", "chat.tools.autoApprove"]))
            .is_some());
        let second = positions.key(&path(&["list", "1", "name"])).unwrap();
        assert!(src[second..].starts_with("\"name\": \"y\""));
    }
}
