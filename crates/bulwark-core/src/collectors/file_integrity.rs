//! File integrity monitoring: baseline-and-diff over a curated set of security-critical
//! paths, the same category of check AIDE exists for and Lynis explicitly flags as missing
//! when no such tool is installed (`FINT-4350`) — see the Lynis benchmark report. Two
//! collectors, not one: `/etc/passwd`, PAM configs, and `sshd_config` are world-readable on
//! a real machine, but `/etc/shadow` and `/etc/sudoers` are root-only (verified against this
//! project's own dev machine — `640` and `440` respectively). Bundling everything into one
//! privileged-only collector would mean FIM never runs during periodic/file-watcher
//! monitoring (which never runs privileged collectors, per ADR-0004) — exactly the
//! "continuous" value this feature exists for. Splitting keeps the freely-readable paths
//! covered continuously and only gates the two genuinely root-only ones.
//!
//! The baseline itself is a plain `sha256sum`-format text file (`<hex-hash>  <path>` per
//! line) — literally `sha256sum`'s own output, not a custom format, so it's inspectable and
//! diffable with any standard tool. Established explicitly via `bulwarkctl fim baseline`
//! (`--privileged` to include the root-only paths), never automatically — an
//! automatically-established "baseline" recorded *after* a compromise would just enshrine
//! the compromised state as "known good."

use super::Collector;
use crate::homefs::HomeFile;
use crate::models::Fact;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

/// World-readable on a stock install — verified against this project's own dev machine.
/// `/etc/ssh/sshd_config` isn't installed here (no sshd on this dev box) but is `644` on any
/// real sshd install, consistent with the existing `sshd_config` collector also not
/// requiring privilege.
pub const UNPRIVILEGED_WATCHED_PATHS: &[&str] = &[
    "/etc/passwd",
    "/etc/ssh/sshd_config",
    "/etc/pam.d/common-auth",
    "/etc/pam.d/sshd",
    "/etc/crontab",
    "/etc/login.defs",
    "/usr/bin/sudo",
    "/bin/su",
    "/usr/bin/su",
];

/// Root-only on a stock install (`/etc/shadow` `640`, `/etc/sudoers` `440` — verified, not
/// assumed) — see the module doc for why these are a separate collector.
pub const PRIVILEGED_WATCHED_PATHS: &[&str] = &["/etc/shadow", "/etc/sudoers"];

fn baseline_path() -> PathBuf {
    if let Ok(p) = std::env::var("BULWARK_FIM_BASELINE") {
        return PathBuf::from(p);
    }
    let home = crate::paths::home_var().unwrap_or_default();
    PathBuf::from(home).join(".local/share/bulwark/fim-baseline.txt")
}

/// Parses `sha256sum`-format text (`<64-hex-char hash>  <path>` per line, two spaces) into a
/// path→hash map. Pure/testable against fixture text — both the on-disk baseline file and
/// `sha256sum`'s own live stdout are parsed with this same function, so a format assumption
/// bug would be caught by feeding it either.
pub fn parse_hash_lines(text: &str) -> HashMap<String, String> {
    text.lines()
        .filter_map(|line| {
            let (hash, path) = line.split_once("  ")?;
            if hash.len() != 64 || !hash.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            Some((path.to_string(), hash.to_string()))
        })
        .collect()
}

/// Shells out to `sha256sum` rather than reimplementing SHA-256 — same "shell out, don't
/// reimplement" precedent as `av_scan.rs`'s use of `clamscan`. Only ever called against the
/// small, curated watched-path lists above, so this is a handful of fast reads, not a
/// filesystem walk — safe to run on every periodic monitoring tick, unlike `av_scan`.
fn compute_hashes(paths: &[PathBuf]) -> HashMap<String, String> {
    if paths.is_empty() {
        return HashMap::new();
    }
    // `--` ends option parsing. Today these paths are curated constants, but keeping the
    // separator means a future caller that passes a path beginning with `-` (or the `-`
    // stdin sentinel) can't accidentally turn a watched path into a flag for sha256sum.
    let Ok(output) = crate::sandbox::quiet_command("sha256sum")
        .arg("--")
        .args(paths)
        .output()
    else {
        return HashMap::new();
    };
    parse_hash_lines(&String::from_utf8_lossy(&output.stdout))
}

/// True when this process is not root and the system refuses to let it open `path` for reading.
/// Root is never "denied": if root could not hash a file, something else is wrong with it.
fn denied_to_this_user(path: &Path) -> bool {
    if crate::platform::is_root() {
        return false;
    }
    matches!(
        std::fs::File::open(path),
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied
    )
}

/// Shared by both collectors: for every path in `watched` that either currently exists or
/// has a recorded baseline entry (so a since-deleted-but-previously-baselined file still
/// gets reported, not silently dropped), produce one fact row describing whether it's
/// changed since the baseline. Takes `baseline_file` as a parameter (rather than resolving
/// it internally) so tests can point at an isolated tempdir path directly instead of
/// mutating the process-wide `BULWARK_FIM_BASELINE` env var, which `cargo test`'s default
/// parallel execution would otherwise turn into a real race between tests.
/// With no baseline recorded at all, `with_summary` adds one `kind: "summary"` row (rule
/// BLWK-FIM-009) so that state is reported once, rather than as one "not covered" finding per
/// watched file — nine identical rows that said one thing. It carries every field the per-file
/// rules read, set so none of them fire on it, because a condition over a missing field is an error.
fn collect_for(watched: &[&str], baseline_file: &Path, with_summary: bool) -> Vec<Fact> {
    // The baseline normally lives in the home folder, so it is opened under the rules of
    // `homefs`: a named pipe put in its place used to hold every scan forever. One that exists
    // and cannot be read leaves every file-integrity rule undecided, and says so, where it used
    // to be read as an empty baseline ("nothing is covered").
    let (read, refused) = match super::home_of(baseline_file) {
        Some(home) => (
            super::read_home(&home, baseline_file),
            crate::homefs::REFUSED,
        ),
        None => (
            super::read_system(baseline_file),
            super::refused_reason(baseline_file),
        ),
    };
    let (baseline_exists, baseline, cut) = match read {
        HomeFile::Missing => (false, HashMap::new(), false),
        HomeFile::Found(read) => (true, parse_hash_lines(&read.text), read.truncated),
        HomeFile::Refused => return vec![super::unread_row(baseline_file, refused)],
    };

    let mut paths: Vec<String> = watched
        .iter()
        .map(|s| s.to_string())
        .filter(|p| Path::new(p).exists())
        .collect();
    for baselined_path in baseline.keys() {
        if watched.contains(&baselined_path.as_str()) && !paths.contains(baselined_path) {
            paths.push(baselined_path.clone());
        }
    }

    let existing: Vec<PathBuf> = paths
        .iter()
        .filter(|p| Path::new(p).exists())
        .map(PathBuf::from)
        .collect();
    let current = compute_hashes(&existing);

    let mut rows = paths
        .into_iter()
        .map(|path| {
            let present = Path::new(&path).exists();
            let in_baseline = baseline.contains_key(&path);
            let current_hash = current.get(&path);
            // "Unreadable" is the state that used to be silently miscategorised as "changed": the
            // file is present and we needed its hash, but `sha256sum` produced none (the binary is
            // missing, or it couldn't read this particular file — an EACCES under a partial
            // privilege set, an I/O error). "I could not compute the hash" is emphatically not
            // "the hash differs", and reporting it as a CRITICAL "modified since baseline" is a
            // false alarm of exactly the kind this project keeps finding — absence of evidence
            // dressed up as evidence. It is surfaced as its own state instead.
            let unreadable = present && current_hash.is_none();
            // A file only an administrator may read is a different case from one that could not
            // be hashed: nothing is wrong with it, this scan simply is not allowed to look. On a
            // system that ships `/etc/ssh/sshd_config` as `600 root`, reporting that as "could not
            // verify" raised the same medium finding on every ordinary scan, for a file that is
            // better protected than the default. The rules use this flag to say "needs an
            // administrator scan" instead, unless the file was readable when the baseline was
            // recorded, in which case losing access to it is itself worth reporting.
            let needs_admin = unreadable && denied_to_this_user(Path::new(&path));
            let changed = match (in_baseline, present) {
                (true, false) => true, // baselined then deleted — a real, knowable change
                // Only a hash we actually computed and that actually differs counts as changed.
                (true, true) => current_hash.is_some() && current_hash != baseline.get(&path),
                (false, _) => false,
            };
            let mut fact = Fact::new();
            fact.insert("path".to_string(), Value::String(path));
            fact.insert("baseline_exists".to_string(), Value::Bool(baseline_exists));
            fact.insert("in_baseline".to_string(), Value::Bool(in_baseline));
            fact.insert("currently_present".to_string(), Value::Bool(present));
            fact.insert("changed".to_string(), Value::Bool(changed));
            fact.insert("unreadable".to_string(), Value::Bool(unreadable));
            fact.insert("needs_admin".to_string(), Value::Bool(needs_admin));
            fact.insert("kind".to_string(), Value::String("file".into()));
            fact
        })
        .collect::<Vec<_>>();
    if cut {
        rows.push(super::unread_row(baseline_file, super::TOO_LARGE));
    }
    if with_summary && !baseline_exists {
        let mut summary = Fact::new();
        summary.insert("path".to_string(), Value::String("(no baseline)".into()));
        summary.insert("baseline_exists".to_string(), Value::Bool(false));
        summary.insert("in_baseline".to_string(), Value::Bool(false));
        summary.insert("currently_present".to_string(), Value::Bool(false));
        summary.insert("changed".to_string(), Value::Bool(false));
        summary.insert("unreadable".to_string(), Value::Bool(false));
        summary.insert("needs_admin".to_string(), Value::Bool(false));
        summary.insert("kind".to_string(), Value::String("summary".into()));
        summary.insert("watched".to_string(), Value::from(rows.len()));
        rows.push(summary);
    }
    rows
}

pub struct FileIntegrityCollector;

impl Collector for FileIntegrityCollector {
    fn name(&self) -> &'static str {
        "file_integrity"
    }

    fn is_applicable(&self) -> bool {
        UNPRIVILEGED_WATCHED_PATHS
            .iter()
            .any(|p| Path::new(p).exists())
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        Ok(collect_for(
            UNPRIVILEGED_WATCHED_PATHS,
            &baseline_path(),
            true,
        ))
    }
}

pub struct FileIntegrityPrivilegedCollector;

impl Collector for FileIntegrityPrivilegedCollector {
    fn name(&self) -> &'static str {
        "file_integrity_privileged"
    }

    fn is_applicable(&self) -> bool {
        PRIVILEGED_WATCHED_PATHS
            .iter()
            .any(|p| Path::new(p).exists())
    }

    fn requires_privilege(&self) -> bool {
        true
    }

    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        Ok(collect_for(
            PRIVILEGED_WATCHED_PATHS,
            &baseline_path(),
            false,
        ))
    }
}

/// Computes and writes a fresh baseline for `paths` to `baseline_file` (overwriting any
/// existing one) — the explicit, user-triggered "this is what good looks like right now"
/// action. Overwrite rather than merge: a baseline's job is to describe the current
/// known-good snapshot, not accumulate history, and merge logic that silently keeps stale
/// entries around is a subtler bug than just always recomputing the full set (which is fast
/// — see `compute_hashes`). Takes `baseline_file` explicitly for the same testability reason
/// as `collect_for`.
pub fn establish_baseline_at(paths: &[&str], baseline_file: &Path) -> anyhow::Result<usize> {
    let existing: Vec<PathBuf> = paths
        .iter()
        .map(PathBuf::from)
        .filter(|p| p.exists())
        .collect();
    let hashes = compute_hashes(&existing);

    let mut lines: Vec<String> = hashes
        .iter()
        .map(|(path, hash)| format!("{hash}  {path}"))
        .collect();
    lines.sort();

    if let Some(parent) = baseline_file.parent() {
        std::fs::create_dir_all(parent)?;
    }
    write_no_follow(baseline_file, (lines.join("\n") + "\n").as_bytes())?;
    Ok(hashes.len())
}

/// Writes `content` to `path` *atomically*, refusing to follow a symlink at the final component.
///
/// Two properties, both load-bearing:
///   * `O_NOFOLLOW`: the baseline is written by `bulwarkctl fim baseline` which, with `--privileged`,
///     runs as root; a pre-planted symlink at the resolved path would otherwise let root clobber the
///     symlink's target. `O_NOFOLLOW` on the temp `open` makes that fail instead.
///   * Temp-then-rename: the old truncate-in-place could leave the baseline empty or half-written if
///     the process died (crash, kill, ENOSPC) mid-write — destroying the previous known-good
///     baseline. Writing a sibling temp, fsyncing it, and renaming over the target means the
///     baseline is only ever the complete old file or the complete new one, never a torn one. Same
///     atomic-swap discipline `ai_scan::redact` already uses.
#[cfg(unix)]
fn write_no_follow(path: &Path, content: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "baseline".to_string());
    let tmp = dir.join(format!(".{file_name}.bulwark-fim.tmp"));
    let _ = std::fs::remove_file(&tmp);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true) // O_EXCL: a raced temp is a failure, not a silent overwrite
        .custom_flags(libc::O_NOFOLLOW)
        .open(&tmp)?;
    let write_result = f.write_all(content).and_then(|_| f.sync_all());
    if let Err(e) = write_result {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    match std::fs::rename(&tmp, path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

#[cfg(not(unix))]
fn write_no_follow(path: &Path, content: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, content)
}

/// Resolves the real, on-disk baseline path and delegates to [`establish_baseline_at`] — the
/// entry point `bulwarkctl`'s `fim baseline` subcommand actually calls.
pub fn establish_baseline(paths: &[&str]) -> anyhow::Result<usize> {
    establish_baseline_at(paths, &baseline_path())
}

/// Resolves the real, on-disk baseline path — exposed so front-doors (CLI/GUI) can report
/// where it lives without duplicating the env-var-or-default resolution logic.
pub fn resolve_baseline_path() -> PathBuf {
    baseline_path()
}

/// What happened to a watched file's baseline entry after one of Bulwark's own fixers rewrote the
/// file. Returned by [`update_baseline_after_fix`]; `None` from there means there was nothing to
/// do (the file is not watched, no baseline is recorded, or the baseline has no entry for it).
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BaselineUpdate {
    /// The entry now records the file as the fix left it, so the next scan does not report
    /// Bulwark's own edit as tampering.
    Updated { path: String },
    /// The file no longer matched its entry *before* the fix touched it. Recording the new hash
    /// would hide that earlier, unexplained change, so the baseline is left exactly as it was and
    /// the next scan still reports the file.
    AlreadyDiffered { path: String },
    /// The entry should have been updated and could not be.
    Failed { path: String, reason: String },
}

impl BaselineUpdate {
    /// One plain line for a fixer's output.
    pub fn message(&self) -> String {
        match self {
            BaselineUpdate::Updated { path } => format!(
                "file-integrity baseline updated for {path}, so this change is not reported as tampering"
            ),
            BaselineUpdate::AlreadyDiffered { path } => format!(
                "{path} already differed from its file-integrity baseline before this fix, so the \
                 baseline was not updated. Check what else changed in the file, then record a new \
                 baseline with: {}",
                rebaseline_command()
            ),
            BaselineUpdate::Failed { path, reason } => format!(
                "the file-integrity baseline for {path} could not be updated ({reason}). The next \
                 scan will report the file as changed until a new baseline is recorded: run \
                 `bulwarkctl fim baseline` as the account whose baseline it is (with sudo and \
                 --privileged if that is how it was recorded)"
            ),
        }
    }
}

/// The command that records a fresh baseline for the account this process runs as.
fn rebaseline_command() -> &'static str {
    if crate::platform::is_root() {
        "sudo bulwarkctl fim baseline --privileged"
    } else {
        "bulwarkctl fim baseline"
    }
}

/// The hash of `path` as it is right now, in the form the baseline stores. A fixer calls this
/// *before* it rewrites a file and hands the result to [`update_baseline_after_fix`]. `None` when
/// the file can't be hashed.
pub fn hash_before_fix(path: &Path) -> Option<String> {
    let key = path.to_str()?;
    compute_hashes(&[path.to_path_buf()]).remove(key)
}

/// Call after a fixer has rewritten `path`: if the file is on the watch list and the baseline this
/// account uses has an entry for it, bring that entry up to date — but only when `hash_before`
/// (from [`hash_before_fix`], taken before the rewrite) equalled the entry. A file that had
/// already drifted from its baseline keeps its old entry, so the earlier change is still reported.
///
/// Returns `None` when there is nothing to say: the file is not watched, there is no baseline, the
/// baseline has no entry for it, or the fix left the file's contents as they were.
pub fn update_baseline_after_fix(path: &Path, hash_before: Option<&str>) -> Option<BaselineUpdate> {
    let watched: Vec<&str> = UNPRIVILEGED_WATCHED_PATHS
        .iter()
        .chain(PRIVILEGED_WATCHED_PATHS)
        .copied()
        .collect();
    update_baseline_after_fix_at(path, hash_before, &baseline_path(), &watched)
}

/// Why root must leave the baseline at `baseline_file` alone, if it must: the file or its folder
/// belongs to another account. `None` for any other user, who can only reach their own files.
#[cfg(unix)]
fn not_roots_own(baseline_file: &Path) -> Option<String> {
    use std::os::unix::fs::MetadataExt;
    if !crate::platform::is_root() {
        return None;
    }
    let file_ok = std::fs::symlink_metadata(baseline_file)
        .is_ok_and(|m| m.file_type().is_file() && m.uid() == 0);
    let dir_ok = baseline_file
        .parent()
        .and_then(|d| std::fs::symlink_metadata(d).ok())
        .is_some_and(|m| m.file_type().is_dir() && m.uid() == 0);
    (!(file_ok && dir_ok)).then(|| {
        format!(
            "{} belongs to another account, and root does not rewrite another account's files",
            baseline_file.display()
        )
    })
}

#[cfg(not(unix))]
fn not_roots_own(_baseline_file: &Path) -> Option<String> {
    None
}

/// Testable core of [`update_baseline_after_fix`]: explicit baseline file and watch list.
fn update_baseline_after_fix_at(
    path: &Path,
    hash_before: Option<&str>,
    baseline_file: &Path,
    watched: &[&str],
) -> Option<BaselineUpdate> {
    let key = path.to_str()?;
    if !watched.contains(&key) {
        return None;
    }
    let path_string = key.to_string();
    if !baseline_file.exists() {
        return None;
    }
    // Root only reads and rewrites a baseline that is root's own. With a preserved `HOME`
    // (`sudo -E`, or macOS) the baseline path is inside another account's home: a file that
    // account can swap for a pipe or a link, in a folder it can point anywhere.
    if let Some(reason) = not_roots_own(baseline_file) {
        return Some(BaselineUpdate::Failed {
            path: path_string,
            reason,
        });
    }
    let text = std::fs::read_to_string(baseline_file).ok()?;
    let recorded = parse_hash_lines(&text).remove(key)?;
    let Some(before) = hash_before else {
        return Some(BaselineUpdate::Failed {
            path: path_string,
            reason: "the file could not be read before the fix".into(),
        });
    };
    if before != recorded {
        return Some(BaselineUpdate::AlreadyDiffered { path: path_string });
    }
    let Some(now) = compute_hashes(&[path.to_path_buf()]).remove(key) else {
        return Some(BaselineUpdate::Failed {
            path: path_string,
            reason: "the file could not be read after the fix".into(),
        });
    };
    if now == recorded {
        return None;
    }
    // Only this file's line changes; every other entry stays exactly as it was recorded.
    let mut next = String::with_capacity(text.len());
    for line in text.lines() {
        match line.split_once("  ") {
            Some((_, p)) if p == key => next.push_str(&format!("{now}  {key}")),
            _ => next.push_str(line),
        }
        next.push('\n');
    }
    match write_no_follow(baseline_file, next.as_bytes()) {
        Ok(()) => Some(BaselineUpdate::Updated { path: path_string }),
        Err(e) => Some(BaselineUpdate::Failed {
            path: path_string,
            reason: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_real_sha256sum_output_format() {
        // Two spaces, exactly the real `sha256sum` output shape (verified against a real
        // invocation on this dev machine before writing this parser).
        let text = "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03  /tmp/a.txt\n\
                     77a326a66263a187a517af0b4ec65d40e286ca72c227de47d002e18addc87bb4  /etc/hostname\n";
        let map = parse_hash_lines(text);
        assert_eq!(map.len(), 2);
        assert_eq!(
            map.get("/tmp/a.txt").unwrap(),
            "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03"
        );
    }

    #[test]
    fn ignores_malformed_lines() {
        let text = "not-a-valid-hash-at-all  /etc/x\n\ntoo short  /etc/y\n";
        assert!(parse_hash_lines(text).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn detects_a_modified_file_against_a_real_baseline() {
        let tmp = tempfile::tempdir().unwrap();
        let watched_file = tmp.path().join("watched.conf");
        std::fs::write(&watched_file, "original content\n").unwrap();
        let watched_path = watched_file.to_str().unwrap().to_string();
        let baseline_file = tmp.path().join("baseline.txt");
        let watched: &[&str] = &[watched_path.as_str()];

        let n = establish_baseline_at(watched, &baseline_file).unwrap();
        assert_eq!(n, 1);

        let rows = collect_for(watched, &baseline_file, false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("changed").unwrap(), &Value::Bool(false));
        assert_eq!(rows[0].get("in_baseline").unwrap(), &Value::Bool(true));

        std::fs::write(&watched_file, "tampered content\n").unwrap();
        let rows = collect_for(watched, &baseline_file, false);
        assert_eq!(rows[0].get("changed").unwrap(), &Value::Bool(true));
        assert_eq!(
            rows[0].get("currently_present").unwrap(),
            &Value::Bool(true)
        );
    }

    #[cfg(unix)]
    #[test]
    fn detects_a_deleted_baselined_file() {
        let tmp = tempfile::tempdir().unwrap();
        let watched_file = tmp.path().join("watched.conf");
        std::fs::write(&watched_file, "content\n").unwrap();
        let watched_path = watched_file.to_str().unwrap().to_string();
        let baseline_file = tmp.path().join("baseline.txt");
        let watched: &[&str] = &[watched_path.as_str()];

        establish_baseline_at(watched, &baseline_file).unwrap();
        std::fs::remove_file(&watched_file).unwrap();

        let rows = collect_for(watched, &baseline_file, false);
        assert_eq!(
            rows.len(),
            1,
            "a vanished-but-baselined path must still be reported"
        );
        assert_eq!(rows[0].get("changed").unwrap(), &Value::Bool(true));
        assert_eq!(
            rows[0].get("currently_present").unwrap(),
            &Value::Bool(false)
        );
    }

    #[cfg(unix)]
    #[test]
    fn a_pipe_in_place_of_the_baseline_is_reported_and_never_waited_on() {
        let tmp = tempfile::tempdir().unwrap();
        let watched_file = tmp.path().join("watched.conf");
        std::fs::write(&watched_file, "content\n").unwrap();
        let watched_path = watched_file.to_str().unwrap().to_string();
        let baseline_file = tmp.path().join("fim-baseline.txt");
        let c = std::ffi::CString::new(baseline_file.to_str().unwrap()).unwrap();
        // SAFETY: a valid NUL-terminated path and a plain mode.
        assert_eq!(unsafe { libc::mkfifo(c.as_ptr(), 0o600) }, 0);

        let (tx, rx) = std::sync::mpsc::channel();
        let baseline = baseline_file.clone();
        std::thread::spawn(move || {
            let _ = tx.send(collect_for(&[watched_path.as_str()], &baseline, true));
        });
        let rows = rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .expect("a pipe named fim-baseline.txt must not block the scan");
        // One row that says the baseline could not be read, and no verdict on any file: an
        // unreadable baseline is neither "no baseline yet" nor "nothing changed".
        assert_eq!(rows.len(), 1, "{rows:?}");
        assert_eq!(rows[0]["path"], baseline_file.display().to_string());
        assert!(rows[0].contains_key(crate::homefs::COULD_NOT_READ));
        for field in ["changed", "baseline_exists", "kind", "unreadable"] {
            assert!(!rows[0].contains_key(field), "{field}");
        }
    }

    #[test]
    fn a_path_with_no_baseline_yet_is_reported_but_not_flagged_as_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let watched_file = tmp.path().join("new.conf");
        std::fs::write(&watched_file, "content\n").unwrap();
        let watched_path = watched_file.to_str().unwrap().to_string();
        // A baseline file that doesn't exist at all yet.
        let baseline_file = tmp.path().join("no-baseline-here.txt");

        let rows = collect_for(&[watched_path.as_str()], &baseline_file, false);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("baseline_exists").unwrap(), &Value::Bool(false));
        assert_eq!(rows[0].get("in_baseline").unwrap(), &Value::Bool(false));
        assert_eq!(
            rows[0].get("changed").unwrap(),
            &Value::Bool(false),
            "no baseline to compare against must not read as a false positive"
        );
    }

    #[test]
    fn a_present_file_absent_from_an_existing_baseline_is_flagged_as_uncovered() {
        // The false-clean that shipped: once *any* baseline exists, a watched file that was never
        // recorded (the /etc/shadow-baselined-without-privilege case) used to read as verified. It
        // must now be visibly "not in baseline", which BLWK-FIM-003/006 turn into a finding.
        let tmp = tempfile::tempdir().unwrap();
        let baselined = tmp.path().join("covered.conf");
        let uncovered = tmp.path().join("never-recorded.conf");
        std::fs::write(&baselined, "a\n").unwrap();
        std::fs::write(&uncovered, "b\n").unwrap();
        let baseline_file = tmp.path().join("baseline.txt");

        // Baseline records ONLY the first file.
        establish_baseline_at(&[baselined.to_str().unwrap()], &baseline_file).unwrap();

        let rows = collect_for(
            &[baselined.to_str().unwrap(), uncovered.to_str().unwrap()],
            &baseline_file,
            false,
        );
        let uncovered_row = rows
            .iter()
            .find(|r| {
                r.get("path")
                    .unwrap()
                    .as_str()
                    .unwrap()
                    .ends_with("never-recorded.conf")
            })
            .unwrap();
        assert_eq!(
            uncovered_row.get("baseline_exists").unwrap(),
            &Value::Bool(true),
            "a baseline does exist globally — which is exactly why the old rule missed this file"
        );
        assert_eq!(
            uncovered_row.get("in_baseline").unwrap(),
            &Value::Bool(false),
            "but THIS file was never recorded, and that must be visible"
        );
        assert_eq!(uncovered_row.get("changed").unwrap(), &Value::Bool(false));
    }

    #[test]
    fn an_unhashable_present_file_is_unreadable_not_changed() {
        // A baselined, present file whose hash can't be computed must NOT read as a critical
        // "modified". We simulate "couldn't hash it" by pointing the baseline at a path we then
        // make unreadable to the hasher via a bogus PATH — but the deterministic unit-level check
        // is simpler: build the fact state directly from a baseline that has an entry the current
        // hash set lacks.
        let tmp = tempfile::tempdir().unwrap();
        let watched_file = tmp.path().join("secret.conf");
        std::fs::write(&watched_file, "content\n").unwrap();
        let path = watched_file.to_str().unwrap().to_string();
        let baseline_file = tmp.path().join("baseline.txt");
        establish_baseline_at(&[path.as_str()], &baseline_file).unwrap();

        // Make the file unreadable to sha256sum (0 permissions). On a system where the test runs
        // as root this wouldn't block the read, so tolerate either outcome but assert the
        // invariant: if we couldn't hash it, it's `unreadable` and NOT `changed`.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&watched_file, std::fs::Permissions::from_mode(0o000))
                .unwrap();
        }
        let rows = collect_for(&[path.as_str()], &baseline_file, false);
        let row = &rows[0];
        let unreadable = row.get("unreadable").unwrap().as_bool().unwrap();
        let changed = row.get("changed").unwrap().as_bool().unwrap();
        assert!(
            !(unreadable && changed),
            "a file we could not hash must never be reported as changed"
        );
        if unreadable {
            assert!(!changed, "unreadable file is not a modification");
            // Mode 000 on a file we own: the system refuses us, so this is the "needs an
            // administrator" case and the rules treat it as such (root never gets here).
            assert_eq!(row.get("needs_admin"), Some(&Value::Bool(true)));
        } else {
            assert_eq!(row.get("needs_admin"), Some(&Value::Bool(false)));
        }
        // Restore perms so tempdir cleanup works.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&watched_file, std::fs::Permissions::from_mode(0o644));
        }
    }

    #[test]
    fn no_baseline_is_one_summary_row_not_one_per_file() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a");
        let b = dir.path().join("b");
        std::fs::write(&a, "x").unwrap();
        std::fs::write(&b, "y").unwrap();
        let baseline_file = dir.path().join("baseline");
        let watched = [a.to_str().unwrap(), b.to_str().unwrap()];

        let rows = collect_for(&watched, &baseline_file, true);
        let summaries: Vec<_> = rows
            .iter()
            .filter(|r| r.get("kind") == Some(&Value::String("summary".into())))
            .collect();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0].get("watched"), Some(&Value::from(2)));
        // Every field the per-file rules read is present on the summary row (a missing field
        // would be a condition error), and set so none of them fire on it.
        for k in [
            "baseline_exists",
            "in_baseline",
            "currently_present",
            "changed",
            "unreadable",
            "needs_admin",
        ] {
            assert!(summaries[0].contains_key(k), "{k}");
        }

        // Once a baseline exists, no summary row.
        establish_baseline_at(&watched, &baseline_file).unwrap();
        let rows = collect_for(&watched, &baseline_file, true);
        assert!(rows
            .iter()
            .all(|r| r.get("kind") == Some(&Value::String("file".into()))));
    }

    /// A fixer's own edit must not come back as "modified since baseline" — but only its own edit.
    #[test]
    fn a_fix_updates_only_its_own_baseline_entry() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.conf");
        let b = dir.path().join("b.conf");
        std::fs::write(&a, "one\n").unwrap();
        std::fs::write(&b, "other\n").unwrap();
        let baseline = dir.path().join("baseline.txt");
        let watched = [a.to_str().unwrap(), b.to_str().unwrap()];
        establish_baseline_at(&watched, &baseline).unwrap();
        let b_line_before = std::fs::read_to_string(&baseline)
            .unwrap()
            .lines()
            .find(|l| l.ends_with("b.conf"))
            .unwrap()
            .to_string();

        let before = hash_before_fix(&a);
        assert!(
            before.is_some(),
            "sha256sum must be available for this test"
        );
        std::fs::write(&a, "one, fixed\n").unwrap();
        let outcome = update_baseline_after_fix_at(&a, before.as_deref(), &baseline, &watched);
        assert_eq!(
            outcome,
            Some(BaselineUpdate::Updated {
                path: a.to_str().unwrap().to_string()
            })
        );

        let rows = collect_for(&watched, &baseline, false);
        assert!(
            rows.iter()
                .all(|r| r.get("changed") == Some(&Value::Bool(false))),
            "the fixed file must not read as changed: {rows:?}"
        );
        let text = std::fs::read_to_string(&baseline).unwrap();
        assert!(text.contains(&b_line_before), "other entries are untouched");
        assert_eq!(text.lines().count(), 2);
    }

    /// The laundering case: the file had already changed before the fix. The baseline must keep
    /// its old entry so that earlier change is still reported.
    #[test]
    fn a_fix_never_hides_a_change_made_before_it() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.conf");
        std::fs::write(&a, "one\n").unwrap();
        let baseline = dir.path().join("baseline.txt");
        let watched = [a.to_str().unwrap()];
        establish_baseline_at(&watched, &baseline).unwrap();
        let recorded = std::fs::read_to_string(&baseline).unwrap();

        // Someone else edits the file, then the fixer runs.
        std::fs::write(&a, "one\nbackdoor\n").unwrap();
        let before = hash_before_fix(&a);
        std::fs::write(&a, "one\nbackdoor\nfixed\n").unwrap();
        let outcome = update_baseline_after_fix_at(&a, before.as_deref(), &baseline, &watched);
        assert_eq!(
            outcome,
            Some(BaselineUpdate::AlreadyDiffered {
                path: a.to_str().unwrap().to_string()
            })
        );
        assert_eq!(std::fs::read_to_string(&baseline).unwrap(), recorded);
        let rows = collect_for(&watched, &baseline, false);
        assert_eq!(rows[0].get("changed"), Some(&Value::Bool(true)));
        assert!(outcome.unwrap().message().contains("not updated"));
    }

    #[test]
    fn a_fix_says_nothing_about_a_file_the_baseline_does_not_cover() {
        let dir = tempfile::tempdir().unwrap();
        let a = dir.path().join("a.conf");
        let other = dir.path().join("unwatched.conf");
        std::fs::write(&a, "one\n").unwrap();
        std::fs::write(&other, "x\n").unwrap();
        let baseline = dir.path().join("baseline.txt");
        let watched = [a.to_str().unwrap()];

        // No baseline recorded at all: a fixer must not create one.
        let before = hash_before_fix(&a);
        std::fs::write(&a, "two\n").unwrap();
        assert_eq!(
            update_baseline_after_fix_at(&a, before.as_deref(), &baseline, &watched),
            None
        );
        assert!(!baseline.exists());

        // A baseline exists, but the file is not on the watch list.
        establish_baseline_at(&watched, &baseline).unwrap();
        let recorded = std::fs::read_to_string(&baseline).unwrap();
        assert_eq!(
            update_baseline_after_fix_at(&other, Some("0"), &baseline, &watched),
            None
        );
        // Watched, baselined, but the "fix" changed nothing.
        let before = hash_before_fix(&a);
        assert_eq!(
            update_baseline_after_fix_at(&a, before.as_deref(), &baseline, &watched),
            None
        );
        // Watched and baselined, but its state before the fix is unknown: never updated.
        std::fs::write(&a, "three\n").unwrap();
        assert!(matches!(
            update_baseline_after_fix_at(&a, None, &baseline, &watched),
            Some(BaselineUpdate::Failed { .. })
        ));
        assert_eq!(std::fs::read_to_string(&baseline).unwrap(), recorded);
    }
}
