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
//! diffable with any standard tool. Established explicitly via `bulwark fim baseline`
//! (`--privileged` to include the root-only paths), never automatically — an
//! automatically-established "baseline" recorded *after* a compromise would just enshrine
//! the compromised state as "known good."

use super::Collector;
use crate::models::Fact;
use serde_json::Value;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    let home = std::env::var("HOME").unwrap_or_default();
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
    let Ok(output) = Command::new("sha256sum").args(paths).output() else {
        return HashMap::new();
    };
    parse_hash_lines(&String::from_utf8_lossy(&output.stdout))
}

/// Shared by both collectors: for every path in `watched` that either currently exists or
/// has a recorded baseline entry (so a since-deleted-but-previously-baselined file still
/// gets reported, not silently dropped), produce one fact row describing whether it's
/// changed since the baseline. Takes `baseline_file` as a parameter (rather than resolving
/// it internally) so tests can point at an isolated tempdir path directly instead of
/// mutating the process-wide `BULWARK_FIM_BASELINE` env var, which `cargo test`'s default
/// parallel execution would otherwise turn into a real race between tests.
fn collect_for(watched: &[&str], baseline_file: &Path) -> Vec<Fact> {
    let baseline_exists = baseline_file.exists();
    let baseline = if baseline_exists {
        std::fs::read_to_string(baseline_file)
            .map(|t| parse_hash_lines(&t))
            .unwrap_or_default()
    } else {
        HashMap::new()
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

    paths
        .into_iter()
        .map(|path| {
            let present = Path::new(&path).exists();
            let in_baseline = baseline.contains_key(&path);
            let changed = match (in_baseline, present) {
                (true, false) => true,
                (true, true) => current.get(&path) != baseline.get(&path),
                (false, _) => false,
            };
            let mut fact = Fact::new();
            fact.insert("path".to_string(), Value::String(path));
            fact.insert("baseline_exists".to_string(), Value::Bool(baseline_exists));
            fact.insert("in_baseline".to_string(), Value::Bool(in_baseline));
            fact.insert("currently_present".to_string(), Value::Bool(present));
            fact.insert("changed".to_string(), Value::Bool(changed));
            fact
        })
        .collect()
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
        Ok(collect_for(UNPRIVILEGED_WATCHED_PATHS, &baseline_path()))
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
        Ok(collect_for(PRIVILEGED_WATCHED_PATHS, &baseline_path()))
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
    std::fs::write(baseline_file, lines.join("\n") + "\n")?;
    Ok(hashes.len())
}

/// Resolves the real, on-disk baseline path and delegates to [`establish_baseline_at`] — the
/// entry point `bulwark-cli`'s `fim baseline` subcommand actually calls.
pub fn establish_baseline(paths: &[&str]) -> anyhow::Result<usize> {
    establish_baseline_at(paths, &baseline_path())
}

/// Resolves the real, on-disk baseline path — exposed so front-doors (CLI/GUI) can report
/// where it lives without duplicating the env-var-or-default resolution logic.
pub fn resolve_baseline_path() -> PathBuf {
    baseline_path()
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

        let rows = collect_for(watched, &baseline_file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("changed").unwrap(), &Value::Bool(false));
        assert_eq!(rows[0].get("in_baseline").unwrap(), &Value::Bool(true));

        std::fs::write(&watched_file, "tampered content\n").unwrap();
        let rows = collect_for(watched, &baseline_file);
        assert_eq!(rows[0].get("changed").unwrap(), &Value::Bool(true));
        assert_eq!(
            rows[0].get("currently_present").unwrap(),
            &Value::Bool(true)
        );
    }

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

        let rows = collect_for(watched, &baseline_file);
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

    #[test]
    fn a_path_with_no_baseline_yet_is_reported_but_not_flagged_as_changed() {
        let tmp = tempfile::tempdir().unwrap();
        let watched_file = tmp.path().join("new.conf");
        std::fs::write(&watched_file, "content\n").unwrap();
        let watched_path = watched_file.to_str().unwrap().to_string();
        // A baseline file that doesn't exist at all yet.
        let baseline_file = tmp.path().join("no-baseline-here.txt");

        let rows = collect_for(&[watched_path.as_str()], &baseline_file);
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].get("baseline_exists").unwrap(), &Value::Bool(false));
        assert_eq!(rows[0].get("in_baseline").unwrap(), &Value::Bool(false));
        assert_eq!(
            rows[0].get("changed").unwrap(),
            &Value::Bool(false),
            "no baseline to compare against must not read as a false positive"
        );
    }
}
