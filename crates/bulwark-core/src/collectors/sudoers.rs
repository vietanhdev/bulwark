//! The sudo policy, read the way sudo reads it (`sudoers(5)`), so that what is reported as
//! passwordless matches what `sudo -l` would say.
//!
//! The first version of this collector asked one question of every line: does it contain the
//! letters `NOPASSWD`? That was wrong in both directions. It reported files sudo never reads (a
//! `.bak` copy or an editor's `~` backup in `/etc/sudoers.d`) and comments that merely mention the
//! word, and it missed a rule in a folder named by `@includedir` and the other way to switch the
//! password off, `Defaults !authenticate`.

use super::Collector;
use crate::homefs::HomeFile;
use crate::models::Fact;
use serde_json::Value;
use std::collections::HashSet;
use std::path::{Path, PathBuf};

pub struct SudoersCollector;

/// How deep `@include` may nest before the rest is reported as not checked. sudo's own limit is
/// 128; a real policy uses one or two levels.
const MAX_INCLUDE_DEPTH: usize = 16;

/// The most of one logical line kept in a finding. A policy line is short; this only stops a
/// megabyte-long line from being stored whole.
const MAX_LINE_CHARS: usize = 400;

/// What one logical sudoers line is.
#[derive(Debug, PartialEq, Eq)]
enum Entry {
    /// `@include file` / `#include file`
    Include(String),
    /// `@includedir dir` / `#includedir dir`
    IncludeDir(String),
    /// A `Defaults` line. `scope` is what follows the keyword up to the first blank
    /// (`""`, `:carol`, `@host`, `>root`, `!/usr/bin/su`); `authenticate` is `Some(false)` for
    /// `!authenticate`, `Some(true)` for `authenticate`, `None` when the line does not set it.
    Defaults {
        scope: String,
        authenticate: Option<bool>,
    },
    /// `User_Alias`, `Runas_Alias`, `Host_Alias`, `Cmnd_Alias`: names only, no permission.
    Alias,
    /// `who where = (as whom) what`. `nopasswd` when a command carries the `NOPASSWD:` tag.
    UserSpec { nopasswd: bool },
    /// Anything else (sudo would call it a syntax error).
    Other,
}

/// One logical line with what it means.
#[derive(Debug)]
struct Line {
    source: String,
    text: String,
    entry: Entry,
}

/// Removes a comment from one logical line. Per `sudoers(5)` a `#` starts a comment unless it
/// begins an include directive or is followed by digits (a user or group ID such as `#1000` or
/// `%#27`). A `#` inside double quotes or after a backslash is ordinary text.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_quotes = false;
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => i += 1,
            b'"' => in_quotes = !in_quotes,
            b'#' if !in_quotes => {
                let rest = &line[i + 1..];
                let directive = line[..i].trim().is_empty()
                    && (rest.starts_with("include ")
                        || rest.starts_with("include\t")
                        || rest.starts_with("includedir ")
                        || rest.starts_with("includedir\t"));
                let id = rest
                    .strip_prefix('-')
                    .unwrap_or(rest)
                    .starts_with(|c: char| c.is_ascii_digit());
                if !directive && !id {
                    return &line[..i];
                }
            }
            _ => {}
        }
        i += 1;
    }
    line
}

/// Splits sudoers text into logical lines: a line ending in a backslash continues on the next,
/// comments are removed, blank lines dropped.
fn logical_lines(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending = String::new();
    for raw in text.lines() {
        let raw = raw.trim_end_matches('\r');
        // A comment ends at the end of its physical line, so strip before joining.
        let part = strip_comment(raw);
        let commented = part.len() != raw.len();
        if !commented {
            if let Some(head) = part.strip_suffix('\\') {
                // An escaped backslash (`\\`) at the end is not a continuation.
                if !head.ends_with('\\') {
                    pending.push_str(head);
                    pending.push(' ');
                    continue;
                }
            }
        }
        pending.push_str(part);
        if !pending.trim().is_empty() {
            out.push(pending.trim().to_string());
        }
        pending.clear();
    }
    if !pending.trim().is_empty() {
        out.push(pending.trim().to_string());
    }
    out
}

/// The path of an include directive: quotes removed, `\ ` unescaped.
fn include_target(arg: &str) -> String {
    let arg = arg.trim();
    match arg.strip_prefix('"').and_then(|a| a.strip_suffix('"')) {
        Some(quoted) => quoted.to_string(),
        None => arg.replace("\\ ", " "),
    }
}

fn nopasswd_tag_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    // A tag is the word followed by a colon, where a command could start: after the `=`, a
    // closing `)`, a comma, another tag's colon, or a blank.
    RE.get_or_init(|| regex::Regex::new(r"(?:^|[\s,=:)])NOPASSWD\s*:").expect("valid regex"))
}

fn authenticate_param_re() -> &'static regex::Regex {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    // One parameter of a comma-separated Defaults list: `authenticate` or `!authenticate`.
    RE.get_or_init(|| {
        regex::Regex::new(r"(?:^|[\s,])(?P<not>!\s*)?authenticate\s*(?:,|$)").expect("valid regex")
    })
}

/// What one logical line (comment already removed) is.
fn classify(line: &str) -> Entry {
    for (keyword, dir) in [
        ("@includedir", true),
        ("#includedir", true),
        ("@include", false),
        ("#include", false),
    ] {
        if let Some(rest) = line.strip_prefix(keyword) {
            if rest.starts_with(char::is_whitespace) {
                let target = include_target(rest);
                return if dir {
                    Entry::IncludeDir(target)
                } else {
                    Entry::Include(target)
                };
            }
        }
    }
    if let Some(rest) = line.strip_prefix("Defaults") {
        if rest.is_empty() || rest.starts_with([' ', '\t', ':', '@', '>', '!']) {
            let (scope, params) = match rest.split_once(char::is_whitespace) {
                Some((scope, params)) => (scope, params),
                None => (rest, ""),
            };
            // The last mention on the line wins, as it does for sudo.
            let authenticate = authenticate_param_re()
                .captures_iter(params)
                .last()
                .map(|c| c.name("not").is_none());
            return Entry::Defaults {
                scope: scope.to_string(),
                authenticate,
            };
        }
    }
    let first = line.split_whitespace().next().unwrap_or_default();
    if matches!(
        first,
        "User_Alias" | "Runas_Alias" | "Host_Alias" | "Cmnd_Alias" | "Cmd_Alias"
    ) {
        return Entry::Alias;
    }
    match line.split_once('=') {
        Some((_, commands)) => Entry::UserSpec {
            nopasswd: nopasswd_tag_re().is_match(commands),
        },
        None => Entry::Other,
    }
}

/// Whether `@includedir` reads a file of this name. `sudoers(5)`: "sudo will read each file in
/// /etc/sudoers.d, skipping file names that end in '~' or contain a '.' character to avoid causing
/// problems with package manager or editor temporary/backup files."
pub fn includedir_reads(name: &str) -> bool {
    !name.is_empty() && !name.ends_with('~') && !name.contains('.')
}

/// Reads sudoers files through a function, so the include logic is tested without `/etc`.
struct Reader<'a> {
    read: &'a dyn Fn(&Path) -> HomeFile<super::CappedText>,
    list: &'a dyn Fn(&Path) -> Option<Vec<String>>,
    hostname: &'a str,
    seen: HashSet<PathBuf>,
    lines: Vec<Line>,
    unread: Vec<Fact>,
}

impl Reader<'_> {
    fn file(&mut self, path: &Path, depth: usize, required: bool) {
        if depth > MAX_INCLUDE_DEPTH {
            self.unread.push(super::unread_row(
                path,
                "the sudoers files include each other too deeply to follow",
            ));
            return;
        }
        // A file included twice (or a loop) is read once: its lines mean the same each time.
        if !self.seen.insert(path.to_path_buf()) {
            return;
        }
        let read = match (self.read)(path) {
            HomeFile::Found(read) => read,
            // sudo warns about a missing include and carries on; there is nothing in it to check.
            HomeFile::Missing if !required => return,
            HomeFile::Missing => {
                self.unread
                    .push(super::unread_row(path, "it could not be opened"));
                return;
            }
            HomeFile::Refused => {
                self.unread
                    .push(super::unread_row(path, super::refused_reason(path)));
                return;
            }
        };
        if read.truncated {
            self.unread.push(super::unread_row(path, super::TOO_LARGE));
        }
        let source = path.display().to_string();
        let base = path.parent().unwrap_or(Path::new("/")).to_path_buf();
        let hostname = self.hostname;
        // A relative include is looked for beside the file that names it; `%h` is the host name.
        let resolve = |target: &str| base.join(target.replace("%h", hostname));
        for text in logical_lines(&read.text) {
            let entry = classify(&text);
            match &entry {
                Entry::Include(target) => {
                    let target = resolve(target);
                    self.file(&target, depth + 1, false);
                }
                Entry::IncludeDir(target) => {
                    let dir = resolve(target);
                    self.dir(&dir, depth + 1);
                }
                _ => {}
            }
            self.lines.push(Line {
                source: source.clone(),
                text,
                entry,
            });
        }
    }

    fn dir(&mut self, dir: &Path, depth: usize) {
        let Some(mut names) = (self.list)(dir) else {
            return;
        };
        // sudo reads them in sorted order, which decides which `Defaults` line is the last.
        names.sort();
        for name in names.into_iter().filter(|n| includedir_reads(n)) {
            self.file(&dir.join(name), depth, false);
        }
    }
}

/// Reads the policy starting at `root` and returns one row per logical line, each with `source`,
/// `line` and `nopasswd`. `nopasswd` is true for a user specification with a `NOPASSWD:` tag and
/// for a `Defaults` line that leaves `authenticate` switched off. A file that could not be read,
/// or was only partly read, adds a row saying so (see [`super::unread_row`]).
fn collect_policy(
    root: &Path,
    read: &dyn Fn(&Path) -> HomeFile<super::CappedText>,
    list: &dyn Fn(&Path) -> Option<Vec<String>>,
    hostname: &str,
) -> Vec<Fact> {
    let mut reader = Reader {
        read,
        list,
        hostname,
        seen: HashSet::new(),
        lines: Vec::new(),
        unread: Vec::new(),
    };
    reader.file(root, 0, true);

    // `Defaults` are applied in order and a later line overrides an earlier one of the same
    // scope, so `!authenticate` counts only where nothing after it switches the prompt back on.
    let reenabled_later = |index: usize, scope: &str| {
        reader.lines[index + 1..].iter().any(|later| {
            matches!(&later.entry, Entry::Defaults { scope: s, authenticate: Some(true) } if s == scope)
        })
    };
    let mut rows: Vec<Fact> = reader
        .lines
        .iter()
        .enumerate()
        .filter_map(|(index, line)| {
            let (passwordless, how) = match &line.entry {
                Entry::UserSpec { nopasswd } => (*nopasswd, "the NOPASSWD tag"),
                Entry::Defaults {
                    scope,
                    authenticate: Some(false),
                } => (
                    !reenabled_later(index, scope),
                    "the setting 'Defaults !authenticate'",
                ),
                Entry::Defaults { .. } => (false, ""),
                // Includes and aliases grant nothing themselves.
                Entry::Include(_) | Entry::IncludeDir(_) | Entry::Alias | Entry::Other => {
                    return None
                }
            };
            let mut fact = Fact::new();
            fact.insert("source".to_string(), Value::String(line.source.clone()));
            fact.insert(
                "line".to_string(),
                Value::String(line.text.chars().take(MAX_LINE_CHARS).collect()),
            );
            fact.insert("nopasswd".to_string(), Value::Bool(passwordless));
            fact.insert(
                "how".to_string(),
                Value::String(if passwordless { how } else { "" }.to_string()),
            );
            Some(fact)
        })
        .collect();
    rows.append(&mut reader.unread);
    rows
}

fn list_dir(dir: &Path) -> Option<Vec<String>> {
    Some(
        std::fs::read_dir(dir)
            .ok()?
            .flatten()
            .filter_map(|e| e.file_name().into_string().ok())
            .collect(),
    )
}

/// The short host name, for `%h` in an include path.
fn short_hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .and_then(|h| h.trim().split('.').next().map(str::to_string))
        .unwrap_or_default()
}

impl Collector for SudoersCollector {
    fn name(&self) -> &'static str {
        "sudoers"
    }

    /// `/etc/sudoers` is normally `0440 root:root` — unreadable without elevation. This is
    /// exactly the collector the architecture doc's privileged path (§4, §8) exists for: skipped
    /// cleanly and reported as "N checks skipped (no privilege)" rather than erroring.
    fn requires_privilege(&self) -> bool {
        true
    }

    fn is_applicable(&self) -> bool {
        Path::new("/etc/sudoers").exists()
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        // Size-capped and never waiting on a pipe, like every other read: a policy file is a few
        // kilobytes, and one grown to hundreds of megabytes was read whole.
        Ok(collect_policy(
            Path::new("/etc/sudoers"),
            &|path| super::read_system(path),
            &list_dir,
            &short_hostname(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    /// One row per rule in sudoers text, without following includes.
    fn parse_sudoers(text: &str, source: &str) -> Vec<Fact> {
        let text = text.to_string();
        let root = PathBuf::from(source);
        let read = |path: &Path| {
            if path == root {
                HomeFile::Found(crate::collectors::CappedText {
                    text: text.clone(),
                    truncated: false,
                })
            } else {
                HomeFile::Missing
            }
        };
        collect_policy(&root, &read, &|_| None, "localhost")
    }

    fn nopasswd_lines(rows: &[Fact]) -> Vec<(String, String)> {
        rows.iter()
            .filter(|r| r.get("nopasswd") == Some(&Value::Bool(true)))
            .map(|r| {
                (
                    r["source"].as_str().unwrap().to_string(),
                    r["line"].as_str().unwrap().to_string(),
                )
            })
            .collect()
    }

    /// A policy made of in-memory files; folders are derived from the file paths.
    fn policy(files: &[(&str, &str)]) -> Vec<Fact> {
        let map: HashMap<PathBuf, String> = files
            .iter()
            .map(|(p, t)| (PathBuf::from(p), t.to_string()))
            .collect();
        let read = |path: &Path| match map.get(path) {
            Some(text) => HomeFile::Found(crate::collectors::CappedText {
                text: text.clone(),
                truncated: false,
            }),
            None => HomeFile::Missing,
        };
        let list = |dir: &Path| {
            let names: Vec<String> = map
                .keys()
                .filter(|p| p.parent() == Some(dir))
                .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
                .collect();
            (!names.is_empty()).then_some(names)
        };
        collect_policy(Path::new("/etc/sudoers"), &read, &list, "web1")
    }

    #[test]
    fn flags_nopasswd_entries() {
        let text = "root ALL=(ALL:ALL) ALL\n%admin ALL=(ALL) NOPASSWD: ALL\n";
        let rows = parse_sudoers(text, "/etc/sudoers");
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].get("nopasswd").unwrap(), &Value::Bool(false));
        assert_eq!(rows[1].get("nopasswd").unwrap(), &Value::Bool(true));
        assert_eq!(rows[1]["line"], "%admin ALL=(ALL) NOPASSWD: ALL");
    }

    #[test]
    fn the_word_in_a_comment_is_not_a_rule() {
        // Each of these mentions NOPASSWD and grants nothing without a password.
        for text in [
            "alice ALL=(ALL) ALL # NOPASSWD removed\n",
            "# %wheel ALL=(ALL) NOPASSWD: ALL\n",
            "## Same thing without a password (NOPASSWD: ALL)\n",
            "Cmnd_Alias NOPASSWD_TOOLS = /usr/bin/true\n",
            "Defaults secure_path=\"/usr/local/sbin:/usr/bin\"\n",
            "Defaults:alice passprompt=\"NOPASSWD: is not set, type it#\"\n",
            "bob ALL=(ALL) PASSWD: ALL\n",
        ] {
            assert!(
                nopasswd_lines(&parse_sudoers(text, "/etc/sudoers")).is_empty(),
                "must not be reported: {text:?}"
            );
        }
    }

    #[test]
    fn the_tag_is_found_however_the_rule_is_written() {
        for text in [
            "x ALL=(ALL) NOPASSWD: ALL\n",
            "x ALL=NOPASSWD:ALL\n",
            "x ALL = (root) NOPASSWD : /usr/bin/systemctl\n",
            "x ALL=(ALL) SETENV:NOPASSWD: ALL\n",
            "x ALL=(ALL) /usr/bin/id, NOPASSWD: /usr/bin/apt\n",
            "#1000 ALL=(ALL) NOPASSWD: ALL\n",
            "%#27 ALL=(ALL) NOPASSWD: ALL\n",
            "x ALL=(ALL) \\\n    NOPASSWD: \\\n    ALL\n",
            "x ALL=(ALL) NOPASSWD: ALL # deploy user\n",
        ] {
            assert_eq!(
                nopasswd_lines(&parse_sudoers(text, "/etc/sudoers")).len(),
                1,
                "must be reported: {text:?}"
            );
        }
    }

    #[test]
    fn authenticate_switched_off_counts_as_passwordless() {
        for text in [
            "Defaults !authenticate\n",
            "Defaults:carol !authenticate\n",
            "Defaults@web1 !authenticate\n",
            "Defaults>root !authenticate\n",
            "Defaults!/usr/bin/apt !authenticate\n",
            "Defaults env_reset, !authenticate, mail_badpass\n",
        ] {
            let rows = parse_sudoers(text, "/etc/sudoers");
            assert_eq!(nopasswd_lines(&rows).len(), 1, "must be reported: {text:?}");
            assert_eq!(rows[0]["how"], "the setting 'Defaults !authenticate'");
        }
        // Left on, set on, or switched back on later for the same scope.
        for text in [
            "Defaults authenticate\n",
            "Defaults env_reset\n",
            "Defaults:carol !authenticate\nDefaults:carol authenticate\n",
            "Defaults !authenticate, authenticate\n",
        ] {
            assert!(
                nopasswd_lines(&parse_sudoers(text, "/etc/sudoers")).is_empty(),
                "must not be reported: {text:?}"
            );
        }
        // Switching it back on for someone else does not undo it for carol.
        assert_eq!(
            nopasswd_lines(&parse_sudoers(
                "Defaults:carol !authenticate\nDefaults:dave authenticate\n",
                "/etc/sudoers"
            ))
            .len(),
            1
        );
    }

    #[test]
    fn includedir_skips_backup_names_and_reads_the_rest() {
        let rule = "x ALL=(ALL) NOPASSWD: ALL\n";
        let rows = policy(&[
            (
                "/etc/sudoers",
                "root ALL=(ALL:ALL) ALL\n@includedir /etc/sudoers.d\n",
            ),
            ("/etc/sudoers.d/90-deploy.bak", rule),
            ("/etc/sudoers.d/old~", rule),
            ("/etc/sudoers.d/README.dpkg-old", rule),
            ("/etc/sudoers.d/90-deploy", rule),
        ]);
        assert_eq!(
            nopasswd_lines(&rows),
            [(
                "/etc/sudoers.d/90-deploy".to_string(),
                "x ALL=(ALL) NOPASSWD: ALL".to_string()
            )]
        );
        assert!(includedir_reads("90-cloud-init-users"));
        assert!(!includedir_reads("README.rpmnew"));
        assert!(!includedir_reads(".hidden"));
    }

    #[test]
    fn every_include_form_is_followed() {
        let rule = "x ALL=(ALL) NOPASSWD: ALL\n";
        let rows = policy(&[
            (
                "/etc/sudoers",
                "#includedir /etc/sudoers.d\n@includedir /etc/sudoers.local.d\n\
                 @include /etc/sudoers.site\n#include extra/%h\n@include \"/etc/with space\"\n",
            ),
            ("/etc/sudoers.d/a", rule),
            ("/etc/sudoers.local.d/b", rule),
            ("/etc/sudoers.site", "@include /etc/sudoers.nested\n"),
            ("/etc/sudoers.nested", rule),
            // A relative path is taken from the including file's folder; %h is the host name.
            ("/etc/extra/web1", rule),
            ("/etc/with space", rule),
        ]);
        let mut sources: Vec<String> = nopasswd_lines(&rows).into_iter().map(|(s, _)| s).collect();
        sources.sort();
        assert_eq!(
            sources,
            [
                "/etc/extra/web1",
                "/etc/sudoers.d/a",
                "/etc/sudoers.local.d/b",
                "/etc/sudoers.nested",
                "/etc/with space",
            ]
        );
    }

    #[test]
    fn an_include_loop_ends_and_a_missing_include_is_not_an_error() {
        let rows = policy(&[
            (
                "/etc/sudoers",
                "@include /etc/a\n@include /etc/absent\nx ALL=(ALL) NOPASSWD: ALL\n",
            ),
            ("/etc/a", "@include /etc/sudoers\n@include /etc/a\n"),
        ]);
        assert_eq!(nopasswd_lines(&rows).len(), 1);
        assert!(rows
            .iter()
            .all(|r| !r.contains_key(crate::homefs::COULD_NOT_READ)));
    }

    #[test]
    fn a_file_that_was_cut_or_could_not_be_opened_is_reported() {
        let read = |path: &Path| match path.to_str().unwrap() {
            "/etc/sudoers" => HomeFile::Found(crate::collectors::CappedText {
                text: "@include /etc/pipe\nroot ALL=(ALL:ALL) ALL\n".into(),
                truncated: true,
            }),
            _ => HomeFile::Refused,
        };
        let rows = collect_policy(Path::new("/etc/sudoers"), &read, &|_| None, "h");
        let unread: Vec<(&str, &str)> = rows
            .iter()
            .filter_map(|r| {
                Some((
                    r.get("path")?.as_str()?,
                    r.get(crate::homefs::COULD_NOT_READ)?.as_str()?,
                ))
            })
            .collect();
        assert_eq!(unread.len(), 2, "{rows:?}");
        assert!(unread.contains(&("/etc/sudoers", crate::collectors::TOO_LARGE)));
        assert!(unread.iter().any(|(p, _)| *p == "/etc/pipe"));
        // Such a row has none of the fields the rule reads, so the rule is not counted as passed.
        assert!(rows
            .iter()
            .filter(|r| r.contains_key(crate::homefs::COULD_NOT_READ))
            .all(|r| !r.contains_key("nopasswd")));
    }

    #[cfg(unix)]
    #[test]
    fn a_large_file_is_read_up_to_the_cap_and_a_pipe_is_not_waited_on() {
        let dir = tempfile::tempdir().unwrap();
        let big = dir.path().join("sudoers");
        let mut text = "x ALL=(ALL) NOPASSWD: ALL\n".to_string();
        text.push_str(&"# padding\n".repeat(500_000)); // 5 MB
        text.push_str("late ALL=(ALL) NOPASSWD: ALL\n");
        std::fs::write(&big, text).unwrap();
        let fifo = dir.path().join("pipe");
        let c = std::ffi::CString::new(fifo.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        let (big2, fifo2) = (big.clone(), fifo.clone());
        std::thread::spawn(move || {
            let rows = collect_policy(
                &big2,
                &|p| crate::collectors::read_system(p),
                &|_| None,
                "h",
            );
            let piped = collect_policy(
                &fifo2,
                &|p| crate::collectors::read_system(p),
                &|_| None,
                "h",
            );
            let _ = tx.send((rows, piped));
        });
        let (rows, piped) = rx
            .recv_timeout(std::time::Duration::from_secs(20))
            .expect("reading a pipe or a large file must not block");
        assert_eq!(nopasswd_lines(&rows).len(), 1, "the part that was read");
        assert!(rows.iter().any(|r| {
            r.get(crate::homefs::COULD_NOT_READ).and_then(Value::as_str)
                == Some(crate::collectors::TOO_LARGE)
        }));
        assert_eq!(piped.len(), 1);
        assert!(piped[0].contains_key(crate::homefs::COULD_NOT_READ));
    }
}
