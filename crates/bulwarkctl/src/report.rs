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
}

impl ReportOptions {
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
        let shared = all[0]
            .iter()
            .find(|s| all[1..].iter().all(|other| other.contains(s)));
        let start = if self.items.len() == 1 {
            0
        } else {
            shared
                .and_then(|s| all[0].iter().position(|x| x == s))
                .unwrap_or(0)
        };
        // A short opening sentence is usually the bare fact ("This project settings file defines
        // hooks.", "X11Forwarding is set to \"yes\"."); the sentence after it says why that matters.
        const SHORT: usize = 60;
        let mut why = String::new();
        for s in all[0].iter().skip(start) {
            if !why.is_empty() {
                // Only keep extending with sentences every place shares.
                if why.chars().count() >= SHORT || !all[1..].iter().all(|o| o.contains(s)) {
                    break;
                }
                why.push(' ');
            }
            why.push_str(s);
        }
        why
    }

    /// The shared title. Rules that put the place in their title ("… (~/.npmrc)", "…: usb-storage")
    /// would otherwise show one place's title for all of them, so differing titles are cut back to
    /// what they have in common.
    fn title(&self) -> String {
        let first = self.items[0].title;
        if self.items.iter().all(|f| f.title == first) {
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
        let trimmed = common.trim_end_matches([' ', ',', '-', '—']).trim_end();
        if trimmed.chars().count() >= 12 {
            trimmed.to_string()
        } else {
            first.to_string()
        }
    }
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

/// Body text column width: with the 13-column indent, lines stay under ~92 columns.
const TEXT_WIDTH: usize = 78;

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
        *last = clip(&format!("{last} …"), width);
    }
    lines.into_iter().map(|l| clip(&l, width)).collect()
}

/// The places a problem was found, on one line that fits the text column: as many as fit (each
/// cut from the start, so the file name survives), then "+N more".
fn place_line(places: &[String]) -> String {
    const LABEL: usize = 4; // "in: "
    let budget = TEXT_WIDTH - LABEL;
    if places.len() == 1 {
        return clip_start(&places[0], budget);
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
        let item = clip_start(place, width);
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

/// Like [`clip`] but keeps the end — for a path, the file name is the part worth seeing.
fn clip_start(s: &str, max: usize) -> String {
    let n = s.chars().count();
    if n <= max {
        s.to_string()
    } else if max == 0 {
        String::new()
    } else {
        let tail: String = s.chars().skip(n - (max - 1)).collect();
        format!("…{tail}")
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
    clean: &'a str,
    /// One-line next steps after the list (e.g. the redaction command).
    actions: Vec<String>,
    /// What this scan could not tell you.
    gaps: Vec<String>,
}

fn render_body(body: Body<'_>, opts: &ReportOptions) -> String {
    let st = Style { on: opts.color };
    let safe = crate::term_safe;
    let mut out = String::new();
    let problems = &body.problems;
    let (main, minor): (Vec<&Problem>, Vec<&Problem>) = problems
        .iter()
        .partition(|p| opts.all || p.severity >= Severity::Medium);

    // ---- header -----------------------------------------------------------------------------
    let _ = writeln!(
        out,
        "{} {}",
        st.bold(&format!("Bulwark {}", env!("CARGO_PKG_VERSION"))),
        st.dim(&format!("· {}", safe(&body.subtitle)))
    );
    let _ = writeln!(out);

    // ---- the list ---------------------------------------------------------------------------
    if problems.is_empty() {
        let _ = writeln!(out, "{} {}", st.green("✓"), st.bold(body.clean));
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
        let _ = writeln!(
            out,
            "{}  {}",
            st.bold(&format!("{n} {} to fix", plural(n, "problem", "problems"))),
            counts.join(st.dim(" · ").as_str())
        );
        for p in &main {
            let times = if p.items.len() > 1 {
                st.dim(&format!("  ×{}", p.items.len()))
            } else {
                String::new()
            };
            let _ = writeln!(out);
            let _ = writeln!(
                out,
                "  {} {:<8} {}{}",
                st.severity(p.severity, "●"),
                st.severity(p.severity, sev_word(p.severity)),
                st.bold(&safe(&p.title())),
                times
            );
            let pad = "             ";
            let max_lines = if opts.all { usize::MAX } else { 2 };
            for line in wrap(&safe(&p.why()), TEXT_WIDTH, max_lines) {
                let _ = writeln!(out, "{pad}{line}");
            }
            let step = first_step(&safe(p.items[0].fix_hint));
            for (i, line) in wrap(&step, TEXT_WIDTH - 2, max_lines)
                .into_iter()
                .enumerate()
            {
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
                    let mut line = format!("· {}", safe(&item.place));
                    if let Some(ev) = item.evidence.filter(|e| !e.is_empty()) {
                        let _ = write!(line, "  {}", clip(&safe(ev), 60));
                    }
                    let _ = writeln!(out, "{pad}{}", st.dim(&line));
                }
            } else if p.items.len() > 1 || !p.title().contains(p.items[0].place.as_str()) {
                let places =
                    place_line(&p.items.iter().map(|i| safe(&i.place)).collect::<Vec<_>>());
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
            let _ = writeln!(
                out,
                "  {}",
                st.dim(&format!(
                    "and {} low-priority {} — run with --all to see {}",
                    minor.len(),
                    plural(minor.len(), "suggestion", "suggestions"),
                    plural(minor.len(), "it", "them")
                ))
            );
        }
    }

    if !body.actions.is_empty() {
        let _ = writeln!(out);
        for a in &body.actions {
            let _ = writeln!(out, "{} {a}", st.green("→"));
        }
    }

    if !body.gaps.is_empty() {
        let _ = writeln!(out);
        let _ = writeln!(out, "{}", st.dim("Not covered by this scan:"));
        for g in &body.gaps {
            let _ = writeln!(out, "  {} {g}", st.dim("·"));
        }
    }
    out
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
    let n = scan.privileged_collectors_skipped.len();
    if n > 0 {
        gaps.push(format!(
            "{n} {} admin rights — run {}",
            plural(n, "check area needs", "check areas need"),
            st.bold("sudo bulwarkctl scan --privileged")
        ));
    }
    let undecided = scan
        .rules_loaded
        .saturating_sub(scan.rules_evaluated.len() + scan.rules_not_applicable.len());
    if undecided > 0 {
        gaps.push(format!(
            "{undecided} {} couldn't run here (a tool that isn't installed, or a file it couldn't read) — not counted as passing",
            plural(undecided, "check", "checks")
        ));
    }
    for e in &scan.collector_errors {
        gaps.push(st.yellow(&format!(
            "{} failed: {}",
            e.collector,
            clip(&safe(&e.message), 140)
        )));
    }
    for e in &scan.rule_load_errors {
        gaps.push(st.yellow(&format!(
            "rule {} didn't load: {}",
            safe(&e.path),
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
            clean: "Nothing to fix from the checks that ran.",
            actions: Vec::new(),
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
        gaps.push(st.yellow(&format!(
            "{n} {} couldn't be read{}",
            plural(n, "file", "files"),
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
            clean: "No leaked secrets or risky agent settings in the files checked.",
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
            "rules_loaded": 10, "rule_load_errors": [], "collector_errors": [],
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
        // Honest footer: admin-only areas, and checks that couldn't run (10 - 7 - 1 = 2).
        assert!(r.contains("1 check area needs admin rights"), "{r}");
        assert!(r.contains("2 checks couldn't run here"), "{r}");
        assert!(!r.contains('\x1b'), "no colour when not asked");

        let all = render(&s, &Ignores::default(), &opts(true));
        assert!(all.contains("No banner") && all.contains("· /k/a") && all.contains("· /k/b"));
        assert!(r.contains("in: /k/a, /k/b"), "{r}");
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
        assert_eq!(
            t("Key unprotected in alpha", "Key unprotected in alpine"),
            "Key unprotected in"
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
        assert!(r.contains("1 file couldn't be read — --all lists them"));
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
        let line = place_line(&long);
        assert!(line.chars().count() <= TEXT_WIDTH - 4, "{line}");
        assert!(
            line.contains(".jsonl:1131") && line.ends_with("more"),
            "{line}"
        );
        // Hundreds of places: the "+N more" suffix is long, the first place still shows.
        let many: Vec<String> = (0..100_000)
            .map(|i| format!("/a/very/long/path/number/{i}/file.jsonl"))
            .collect();
        let line = place_line(&many);
        assert!(
            line.contains("file.jsonl") && line.chars().count() <= TEXT_WIDTH - 4,
            "{line}"
        );
        assert_eq!(clip("abc", 0), "");
        assert_eq!(clip_start("abc", 0), "");
        let short: Vec<String> = ["port 1", "port 2", "port 3", "port 4"]
            .map(String::from)
            .to_vec();
        assert_eq!(place_line(&short), "port 1, port 2, port 3, port 4");
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
}
