//! Reading a whole file a piece at a time, so a key anywhere in a large transcript is seen without
//! holding the transcript in memory.
//!
//! A file is read in **windows** of about [`WINDOW_BYTES`]. Each window ends at the end of a line
//! (JSONL transcripts are one record per line), and the next one starts [`OVERLAP_BYTES`] before
//! that, again at the start of a line. So a key on one line is never cut in two, and a key that
//! covers several lines (a PEM block) is whole in at least one window. Where a single line is
//! longer than a window, the cut falls on a space or a quote instead — characters no key contains.
//!
//! Memory is one window per file being read, whatever the file's size. The work is bounded too:
//! at most `limit` bytes are read from one file, and the caller is told when that left part of the
//! file unread, so the gap is reported and never silent.

use std::borrow::Cow;
use std::io::Read;

/// How much of a file is held in memory at once.
pub(super) const WINDOW_BYTES: usize = 4 * 1024 * 1024;

/// How far a window reaches back into the one before it. Larger than any key and the context a
/// rule reads around it (the longest are PEM private keys, a few kilobytes).
pub(super) const OVERLAP_BYTES: usize = 64 * 1024;

/// One piece of a file.
pub(super) struct Window<'a> {
    /// The text, with invalid UTF-8 replaced.
    pub text: Cow<'a, str>,
    /// The 1-based line number, in the whole file, of the line this window starts on.
    pub first_line: usize,
    /// Where in the file this window starts, in bytes. (Read by the tests, which check each
    /// window against the file.)
    #[cfg_attr(not(test), allow(dead_code))]
    pub offset: u64,
    /// 0 for the first window.
    pub index: usize,
    /// True for the window that reaches the end of what is read from this file.
    pub last: bool,
}

/// What reading a file covered.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(super) struct Coverage {
    /// Bytes read from the file.
    pub bytes: u64,
    /// True when the file holds more than the limit allowed to be read.
    pub truncated: bool,
    /// False when any byte read was not valid UTF-8.
    pub valid_utf8: bool,
}

/// Calls `each` with every window of `reader`, reading at most `limit` bytes in all. `size` is
/// how large the file is expected to be (its length when opened), used only to set aside the
/// right amount of memory up front.
pub(super) fn for_each_window(
    mut reader: impl Read,
    size: u64,
    limit: u64,
    mut each: impl FnMut(&Window<'_>),
) -> std::io::Result<Coverage> {
    let mut buf = Vec::new();
    // One byte more than the file, so the read that discovers the end needs no further room.
    let expected = size.min(limit).min(WINDOW_BYTES as u64) as usize;
    buf.reserve_exact(expected.saturating_add(1).min(WINDOW_BYTES));
    for_each_window_in(
        &mut reader,
        buf,
        limit,
        WINDOW_BYTES,
        OVERLAP_BYTES,
        &mut each,
    )
}

/// [`for_each_window`] with the sizes given, so tests can use windows of a few bytes.
#[cfg(test)]
pub(super) fn for_each_window_sized(
    reader: &mut dyn Read,
    limit: u64,
    window: usize,
    overlap: usize,
    each: &mut dyn FnMut(&Window<'_>),
) -> std::io::Result<Coverage> {
    for_each_window_in(reader, Vec::new(), limit, window, overlap, each)
}

fn for_each_window_in(
    reader: &mut dyn Read,
    mut buf: Vec<u8>,
    limit: u64,
    window: usize,
    overlap: usize,
    each: &mut dyn FnMut(&Window<'_>),
) -> std::io::Result<Coverage> {
    let mut cover = Coverage {
        valid_utf8: true,
        ..Coverage::default()
    };
    let mut eof = false;
    let mut lines_before = 0usize;
    let mut offset = 0u64;
    let mut index = 0usize;
    loop {
        let room = limit.saturating_sub(cover.bytes);
        let want = window
            .saturating_sub(buf.len())
            .min(usize::try_from(room).unwrap_or(usize::MAX));
        if !eof && want > 0 {
            let got = fill(reader, &mut buf, want)?;
            cover.bytes += got as u64;
            eof = got < want;
        }
        let out_of_budget = !eof && cover.bytes >= limit;
        if out_of_budget {
            // Is there really more, or did the file end exactly at the limit?
            let mut probe = [0u8; 1];
            cover.truncated = read_some(reader, &mut probe)? > 0;
        }
        let at_end = eof || out_of_budget;
        if buf.is_empty() {
            break;
        }
        let cut = if at_end {
            if cover.truncated {
                floor_char_boundary(&buf, buf.len())
            } else {
                buf.len()
            }
        } else {
            cut_point(&buf)
        };
        let text = String::from_utf8_lossy(&buf[..cut]);
        if matches!(text, Cow::Owned(_)) {
            cover.valid_utf8 = false;
        }
        each(&Window {
            text,
            first_line: lines_before + 1,
            offset,
            index,
            last: at_end,
        });
        if at_end {
            break;
        }
        let next = next_start(&buf, cut, overlap);
        lines_before += count_newlines(&buf[..next]);
        buf.drain(..next);
        offset += next as u64;
        index += 1;
    }
    Ok(cover)
}

/// Appends up to `want` bytes from `reader` to `buf`; fewer only at the end of the file.
///
/// Reads into the buffer's spare room as it grows, and never prepares more memory than the file
/// turns out to have: clearing a whole 4 MiB window before reading a 3 KB transcript, twenty
/// thousand times over, once made a scan six times slower.
pub(super) fn fill(
    reader: &mut dyn Read,
    buf: &mut Vec<u8>,
    want: usize,
) -> std::io::Result<usize> {
    reader.take(want as u64).read_to_end(buf)
}

fn read_some(reader: &mut dyn Read, into: &mut [u8]) -> std::io::Result<usize> {
    loop {
        match reader.read(into) {
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            other => return other,
        }
    }
}

pub(super) fn count_newlines(bytes: &[u8]) -> usize {
    bytes.iter().filter(|b| **b == b'\n').count()
}

/// A byte no single-token key contains, so cutting just after one never cuts a key.
fn is_delimiter(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\r' | b'"')
}

/// The largest position `<= at` that does not split a UTF-8 character.
pub(super) fn floor_char_boundary(buf: &[u8], at: usize) -> usize {
    let at = at.min(buf.len());
    // Step back over continuation bytes to the character's first byte, then keep the character
    // only if all of it is before `at`.
    let mut lead = at;
    let mut steps = 0;
    while lead > 0 && steps < 3 && buf[lead - 1] & 0xC0 == 0x80 {
        lead -= 1;
        steps += 1;
    }
    if lead == 0 {
        return at;
    }
    let first = buf[lead - 1];
    let need = match first {
        b if b & 0x80 == 0 => 1,
        b if b & 0xE0 == 0xC0 => 2,
        b if b & 0xF0 == 0xE0 => 3,
        b if b & 0xF8 == 0xF0 => 4,
        _ => return at, // not valid UTF-8 here anyway; any cut will do
    };
    if steps + 1 >= need {
        at
    } else {
        lead - 1
    }
}

/// The smallest position `>= at` that does not split a UTF-8 character.
fn ceil_char_boundary(buf: &[u8], at: usize) -> usize {
    let mut at = at.min(buf.len());
    let mut steps = 0;
    while at < buf.len() && steps < 3 && buf[at] & 0xC0 == 0x80 {
        at += 1;
        steps += 1;
    }
    at
}

/// Where a full window ends: after the last line end in its second half, else after the last
/// space or quote there, else at the last whole character.
pub(super) fn cut_point(buf: &[u8]) -> usize {
    let half = buf.len() / 2;
    if let Some(i) = buf[half..].iter().rposition(|b| *b == b'\n') {
        return half + i + 1;
    }
    if let Some(i) = buf[half..].iter().rposition(|b| is_delimiter(*b)) {
        return half + i + 1;
    }
    floor_char_boundary(buf, buf.len()).max(1)
}

/// Where the window after one ending at `cut` starts: up to `overlap` bytes back, at the start of
/// a line when there is one, else after a space or quote, else at a whole character. Always after
/// position 0, so every window moves forward.
pub(super) fn next_start(buf: &[u8], cut: usize, overlap: usize) -> usize {
    let lo = cut.saturating_sub(overlap);
    let back = &buf[lo..cut];
    let start = if let Some(i) = back.iter().position(|b| *b == b'\n') {
        lo + i + 1
    } else if let Some(i) = back.iter().position(|b| is_delimiter(*b)) {
        lo + i + 1
    } else {
        ceil_char_boundary(buf, lo)
    };
    start.clamp(1, cut.max(1))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every window of `text` as (first line, text), read with tiny windows.
    fn windows(
        text: &str,
        window: usize,
        overlap: usize,
    ) -> (Vec<(usize, String, bool)>, Coverage) {
        let mut out = Vec::new();
        let mut reader = text.as_bytes();
        let cover = for_each_window_sized(&mut reader, u64::MAX, window, overlap, &mut |w| {
            out.push((w.first_line, w.text.to_string(), w.last));
        })
        .unwrap();
        (out, cover)
    }

    #[test]
    fn a_small_file_is_one_window() {
        let (w, cover) = windows("one\ntwo\n", 1024, 16);
        assert_eq!(w, vec![(1, "one\ntwo\n".to_string(), true)]);
        assert_eq!(
            (cover.bytes, cover.truncated, cover.valid_utf8),
            (8, false, true)
        );
        let (w, cover) = windows("", 1024, 16);
        assert!(w.is_empty());
        assert_eq!(cover.bytes, 0);
    }

    #[test]
    fn windows_end_on_lines_overlap_and_number_lines_from_the_whole_file() {
        let text: String = (1..=40).map(|i| format!("line number {i:02}\n")).collect();
        let (w, cover) = windows(&text, 64, 20);
        assert!(w.len() > 5, "{}", w.len());
        assert!(cover.valid_utf8 && !cover.truncated);
        let mut covered = 0usize; // lines seen so far
        for (first_line, piece, _) in &w {
            // Every window is whole lines, and starts on the line its number says.
            assert!(piece.ends_with('\n'), "{piece:?}");
            assert!(
                piece.starts_with(&format!("line number {first_line:02}\n")),
                "{piece:?}"
            );
            // It starts at or before the first line not yet seen: nothing is skipped.
            assert!(*first_line <= covered + 1, "gap before line {first_line}");
            covered = first_line - 1 + piece.lines().count();
        }
        assert_eq!(covered, 40);
        assert!(w.last().unwrap().2 && w.iter().rev().skip(1).all(|x| !x.2));
    }

    #[test]
    fn every_stretch_shorter_than_the_overlap_is_whole_in_some_window() {
        // The guarantee the scanner relies on: a key (plus the text a rule reads around it) is
        // never seen only in halves. Checked for every position in a file of varied line lengths,
        // including a line far longer than a window and a run with nowhere good to cut.
        let mut text = String::new();
        for i in 0..60 {
            text.push_str(&format!(
                "{i} alpha-bravo-charlie-delta-{i} {}\n",
                "echo-foxtrot-golf ".repeat(i % 7)
            ));
        }
        text.push_str(&"hotel-india-juliett-kilo ".repeat(30)); // one 750-byte line
        text.push('\n');
        text.push_str(&"x".repeat(300));
        text.push_str(" tail\n");
        let (window, overlap) = (96, 32);
        let mut spans = Vec::new();
        let mut reader = text.as_bytes();
        for_each_window_sized(&mut reader, u64::MAX, window, overlap, &mut |w| {
            let at = w.offset as usize;
            assert_eq!(&text[at..at + w.text.len()], w.text.as_ref());
            spans.push((at, at + w.text.len()));
        })
        .unwrap();
        let needle = 12; // well under the overlap
        let mut checked = 0;
        for start in 0..text.len() - needle {
            let end = start + needle;
            // Only stretches a key could be: no line break, space or quote inside.
            if text.as_bytes()[start..end]
                .iter()
                .any(|b| *b == b'\n' || is_delimiter(*b))
            {
                continue;
            }
            checked += 1;
            assert!(
                spans.iter().any(|(a, b)| *a <= start && end <= *b),
                "bytes {start}..{end} are in no single window"
            );
        }
        assert!(checked > 500, "{checked}");
        // Line numbers stay true across cuts that fall inside a line.
        let mut reader = text.as_bytes();
        for_each_window_sized(&mut reader, u64::MAX, window, overlap, &mut |w| {
            let before = &text[..w.offset as usize];
            assert_eq!(w.first_line, before.matches('\n').count() + 1);
        })
        .unwrap();
    }

    #[test]
    fn the_limit_is_honoured_and_reported() {
        let text = "0123456789\n".repeat(20); // 220 bytes
        let mut seen = 0usize;
        let mut reader = text.as_bytes();
        let cover = for_each_window_sized(&mut reader, 100, 64, 16, &mut |w| {
            seen = seen.max(w.first_line + w.text.lines().count() - 1);
        })
        .unwrap();
        assert_eq!(cover.bytes, 100);
        assert!(cover.truncated);
        assert!(seen <= 10);
        // A file that ends exactly at the limit is not "cut short".
        let mut reader = text.as_bytes();
        let cover = for_each_window_sized(&mut reader, 220, 64, 16, &mut |_| {}).unwrap();
        assert!(!cover.truncated);
    }

    #[test]
    fn a_character_is_never_split_and_invalid_bytes_are_noticed() {
        // No line ends, spaces or quotes: the cut has to respect character boundaries alone.
        let text = "é".repeat(200);
        let (w, cover) = windows(&text, 63, 9);
        assert!(
            cover.valid_utf8,
            "valid text must not be reported as invalid"
        );
        assert!(w.iter().all(|(_, piece, _)| !piece.contains('\u{FFFD}')));
        let mut bad = b"ok line\n".to_vec();
        bad.extend_from_slice(&[0xFF, 0xFE, b'\n']);
        let mut reader = bad.as_slice();
        let cover = for_each_window_sized(&mut reader, u64::MAX, 64, 8, &mut |_| {}).unwrap();
        assert!(!cover.valid_utf8);
    }

    #[test]
    fn char_boundaries() {
        let s = "aé€😀".as_bytes(); // 1 + 2 + 3 + 4 bytes
        assert_eq!(floor_char_boundary(s, 1), 1);
        assert_eq!(floor_char_boundary(s, 2), 1);
        assert_eq!(floor_char_boundary(s, 3), 3);
        assert_eq!(floor_char_boundary(s, 5), 3);
        assert_eq!(floor_char_boundary(s, 6), 6);
        assert_eq!(floor_char_boundary(s, 9), 6);
        assert_eq!(floor_char_boundary(s, 10), 10);
        assert_eq!(ceil_char_boundary(s, 2), 3);
        assert_eq!(ceil_char_boundary(s, 7), 10);
    }
}
