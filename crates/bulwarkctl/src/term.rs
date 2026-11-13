//! What every command needs to know about the terminal it prints to: what is safe to print, how
//! wide it is, whether it can show anything beyond ASCII, and what to do when the reader leaves.

/// Characters that are invisible or reorder the text around them: bidirectional controls (a
/// right-to-left override makes `gnp.exe` read as `exe.png`), zero-width characters, the Unicode
/// line and paragraph separators, soft hyphen and the invisible "tag" block.
fn is_invisible(c: char) -> bool {
    matches!(
        c,
        '\u{00AD}'
            | '\u{061C}'
            | '\u{180E}'
            | '\u{200B}'..='\u{200F}'
            | '\u{2028}'..='\u{202E}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{2069}'
            | '\u{FEFF}'
            | '\u{E0000}'..='\u{E007F}'
    )
}

fn safe_char(c: char, keep_newlines: bool) -> char {
    match c {
        '\n' if keep_newlines => '\n',
        // A line break or tab inside one field becomes a space, so the words on either side stay
        // apart and nothing can start a line of its own.
        '\n' | '\r' | '\t' | '\u{2028}' | '\u{2029}' => ' ',
        c if c.is_control() || is_invisible(c) => '\u{FFFD}',
        c => c,
    }
}

/// Text that did not come from this program (a finding's title or place, an error message, a
/// monitored machine's answer), made safe to print as **one line**.
///
/// Nothing in it can start a new line, move the cursor, reorder the text or hide in it: line
/// breaks and tabs become a space; every other control character (escape sequences, the C1 set),
/// bidirectional control and zero-width character becomes U+FFFD. A monitored machine that put a
/// newline in a title used to get a line of its own in `hosts show`, which could say anything.
///
/// This is the one function every report field goes through. Text that is meant to span lines
/// uses [`term_safe_lines`]; pick a step out of a multi-line fix *before* calling either.
pub(crate) fn term_safe(s: &str) -> String {
    s.chars().map(|c| safe_char(c, false)).collect()
}

/// Like [`term_safe`], but line breaks survive: for text Bulwark itself lays out over several
/// lines (a connection hint with numbered steps). Print anything from elsewhere line by line with
/// [`term_safe`] instead, so each line keeps the indentation that marks where it came from.
pub(crate) fn term_safe_lines(s: &str) -> String {
    s.chars().map(|c| safe_char(c, true)).collect()
}

/// Whether the terminal's locale can show characters beyond ASCII. POSIX order: `LC_ALL`, then
/// `LC_CTYPE`, then `LANG`; the first one set decides, and none set means the "C" locale. Windows
/// consoles are written to as Unicode whatever these say.
pub(crate) fn utf8_output() -> bool {
    if cfg!(windows) {
        return true;
    }
    locale_is_utf8(|name| std::env::var(name).ok())
}

fn locale_is_utf8(var: impl Fn(&str) -> Option<String>) -> bool {
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .find_map(|name| var(name).filter(|v| !v.is_empty()))
        .is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("utf-8") || v.contains("utf8")
        })
}

/// The symbols Bulwark's own text uses, in ASCII, for a terminal whose locale is not UTF-8 —
/// there they print as `M-bM-^WM-^O` or as question marks. Text from files and other machines is
/// left as it is: it is theirs, and a path must stay the path.
pub(crate) fn ascii_symbols(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '●' | '•' => out.push('*'),
            '→' => out.push_str("->"),
            '✓' => out.push_str("ok:"),
            '·' => out.push('-'),
            '×' => out.push('x'),
            '…' => out.push_str("..."),
            '—' | '–' => out.push('-'),
            '⚠' => out.push('!'),
            '\u{FFFD}' => out.push('?'),
            c => out.push(c),
        }
    }
    out
}

/// [`ascii_symbols`] when the locale needs it, otherwise the text unchanged.
pub(crate) fn for_locale(s: &str) -> std::borrow::Cow<'_, str> {
    if utf8_output() {
        std::borrow::Cow::Borrowed(s)
    } else {
        std::borrow::Cow::Owned(ascii_symbols(s))
    }
}

/// How many columns the terminal on stdout has, or `None` when stdout is not a terminal (a pipe
/// or a file gets the fixed layout, so saved reports don't depend on the window they were made
/// in) or the size can't be read.
pub(crate) fn stdout_columns() -> Option<usize> {
    use std::io::IsTerminal;
    if !std::io::stdout().is_terminal() {
        return None;
    }
    terminal_columns()
}

#[cfg(unix)]
fn terminal_columns() -> Option<usize> {
    // SAFETY: `winsize` is plain data, and TIOCGWINSZ only writes into the struct it is given.
    let mut size: libc::winsize = unsafe { std::mem::zeroed() };
    let ok = unsafe { libc::ioctl(libc::STDOUT_FILENO, libc::TIOCGWINSZ, &mut size) } == 0;
    (ok && size.ws_col > 0).then_some(size.ws_col as usize)
}

#[cfg(not(unix))]
fn terminal_columns() -> Option<usize> {
    None
}

/// Makes `bulwarkctl … | head -1` end the way every other command-line tool does, instead of with
/// `thread 'main' panicked … failed printing to stdout: Broken pipe` and exit code 101.
///
/// Rust ignores SIGPIPE, so a write to a pipe nobody reads returns an error, and `println!` turns
/// that error into a panic. The signal's default action is deliberately *not* restored for the
/// whole run: this program also writes to pipes of its own (a secret to `curl`'s stdin, a command
/// to `ssh`), and one of those children exiting early must stay an error it can report, not a
/// silent death half way through a scan of several machines. Instead, the one panic that means
/// "the reader of stdout or stderr went away" ends the process quietly — on Unix by the signal
/// itself, so a shell sees the usual 141; elsewhere with that same number.
pub(crate) fn exit_quietly_when_the_reader_goes_away() {
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let payload = info.payload();
        let message = payload
            .downcast_ref::<String>()
            .map(String::as_str)
            .or_else(|| payload.downcast_ref::<&str>().copied())
            .unwrap_or_default();
        if is_closed_pipe_panic(message) {
            reader_went_away();
        }
        default_hook(info);
    }));
}

/// True for the panic `print!`/`eprintln!` raise when the other end of the pipe is gone. Any other
/// failure to print (a full disk behind a redirect) stays a visible error.
fn is_closed_pipe_panic(message: &str) -> bool {
    message.starts_with("failed printing to std")
        && (message.contains("Broken pipe")
            || message.contains("os error 32")
            // Windows: ERROR_BROKEN_PIPE and ERROR_NO_DATA ("The pipe is being closed").
            || message.contains("os error 109")
            || message.contains("os error 232"))
}

/// Ends the process the way a closed pipe ends any Unix program.
pub(crate) fn reader_went_away() -> ! {
    #[cfg(unix)]
    // SAFETY: restoring a signal's default action and raising it are async-signal-safe calls with
    // no memory involved; the process ends here.
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
        libc::raise(libc::SIGPIPE);
    }
    std::process::exit(141)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn remote_text_cannot_drive_the_terminal() {
        let hostile = "Title\x1b]0;pwned\x07 \x1b[2Jtext\u{9b}31m";
        let safe = term_safe(hostile);
        assert!(!safe.contains('\x1b') && !safe.contains('\x07') && !safe.contains('\u{9b}'));
        assert!(safe.starts_with("Title") && safe.contains("text"));
    }

    /// A monitored machine returned a title holding a newline and a right-to-left override; both
    /// were printed as they came, so the machine could add lines to `hosts show`.
    #[test]
    fn one_field_can_never_become_a_second_line_or_hide_or_reorder_text() {
        let hostile = "ok\nCRITICAL: all clear\rover\u{202e}gnp.exe\u{2066}x\u{200b}y\u{200d}z\
                       \u{feff}\u{2028}new\u{2029}para\ttab\u{e0041}";
        let safe = term_safe(hostile);
        assert_eq!(safe.lines().count(), 1, "{safe:?}");
        for c in safe.chars() {
            assert!(!c.is_control(), "control {c:?} survived in {safe:?}");
            assert!(!is_invisible(c), "invisible {c:?} survived in {safe:?}");
        }
        // The words stay apart and stay readable.
        assert!(safe.starts_with("ok CRITICAL: all clear over"), "{safe:?}");
        assert!(safe.contains("new para tab"), "{safe:?}");
        // Ordinary text in other scripts is left alone.
        assert_eq!(term_safe("café 日本語 — ok"), "café 日本語 — ok");
    }

    #[test]
    fn text_bulwark_lays_out_itself_keeps_its_lines_and_nothing_else() {
        let hint = "Try this:\n  1. first\n  2. second\x1b[2J\u{202e}";
        let safe = term_safe_lines(hint);
        assert_eq!(safe.lines().count(), 3);
        assert!(safe.contains("\n  2. second"));
        assert!(!safe.contains('\x1b') && !safe.contains('\u{202e}'));
        assert!(!term_safe_lines("a\rb").contains('\r'));
    }

    #[test]
    fn only_a_closed_pipe_ends_the_run_quietly() {
        assert!(is_closed_pipe_panic(
            "failed printing to stdout: Broken pipe (os error 32)"
        ));
        assert!(is_closed_pipe_panic(
            "failed printing to stderr: Broken pipe (os error 32)"
        ));
        assert!(is_closed_pipe_panic(
            "failed printing to stdout: The pipe is being closed. (os error 232)"
        ));
        assert!(!is_closed_pipe_panic(
            "failed printing to stdout: No space left on device (os error 28)"
        ));
        assert!(!is_closed_pipe_panic("index out of bounds"));
    }

    #[test]
    fn the_locale_decides_whether_symbols_are_ascii() {
        let env = |pairs: &'static [(&'static str, &'static str)]| {
            move |name: &str| {
                pairs
                    .iter()
                    .find(|(k, _)| *k == name)
                    .map(|(_, v)| v.to_string())
            }
        };
        assert!(locale_is_utf8(env(&[("LANG", "en_US.UTF-8")])));
        assert!(locale_is_utf8(env(&[("LC_CTYPE", "C.utf8")])));
        // LC_ALL wins over everything, an empty value does not count, and nothing set is "C".
        assert!(!locale_is_utf8(env(&[
            ("LC_ALL", "C"),
            ("LANG", "en_US.UTF-8")
        ])));
        assert!(locale_is_utf8(env(&[
            ("LC_ALL", ""),
            ("LANG", "de_DE.UTF-8")
        ])));
        assert!(!locale_is_utf8(env(&[("LANG", "POSIX")])));
        assert!(!locale_is_utf8(env(&[])));

        let plain = ascii_symbols("  ● High  title  ×2\n   → fix … — done ✓ · x \u{FFFD}");
        assert!(plain.is_ascii(), "{plain}");
        assert!(plain.contains("* High  title  x2") && plain.contains("-> fix ..."));
        // Text that is not ours is not transliterated.
        assert_eq!(ascii_symbols("/home/josé/.ssh"), "/home/josé/.ssh");
    }
}
