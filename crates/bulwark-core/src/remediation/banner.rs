//! Write a legal warning banner to `/etc/issue` and `/etc/issue.net` — the fix for `BLWK-BANN-001`.
//!
//! The rule is **list-shaped**: the `banners` collector emits one fact per file, so a host can be
//! flagged for `/etc/issue`, `/etc/issue.net`, or both, and each is an independent finding. This
//! fixer therefore treats each file independently — it reports and rewrites only the files that
//! actually still look like the distro default, and one file being fine never suppresses the other.
//!
//! **On the getty-escape asymmetry.** `/etc/issue` is expanded by getty, which substitutes `\s`
//! (OS name), `\n` (hostname), `\r` (kernel release) and friends; `/etc/issue.net` is read by sshd
//! and gets no such expansion. That difference has already caused a real bug in this project — the
//! banner heuristic originally keyed on escape codes alone and missed `/etc/issue.net` entirely,
//! because Ubuntu's stock `issue.net` is a bare `"Ubuntu 26.04 LTS"` with no escapes in it.
//!
//! The consequence for *this* module is the opposite of what it first looks like. The temptation is
//! to write an escape-bearing banner to `/etc/issue` (since it supports them) and a plain one to
//! `issue.net`. That would be actively wrong: `looks_like_default_banner` treats the presence of
//! **any** getty escape as evidence the file is still the untouched default, so a banner containing
//! `\n` would be written, and then re-flagged by the very rule it was supposed to clear. The
//! correct banner contains no escape sequences at all — which makes identical content correct for
//! both files, not by coincidence but because the escape-free intersection is the only text that
//! satisfies both readers. `the_written_banner_is_not_flagged_as_default` pins that against the
//! collector's real classifier rather than against this reasoning.

use crate::collectors::banners::looks_like_default_banner;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The banner written when a file is still at the distro default.
///
/// Deliberately generic and jurisdiction-neutral: it asserts authorization is required and that use
/// may be monitored, which is what the control is actually for, and it names no organization —
/// inventing a company name on a user's behalf would be worse than saying nothing. It contains no
/// backslash escapes (see the module doc) and no OS version, which is half the point of replacing
/// the default.
pub const DEFAULT_BANNER: &str = "\
WARNING: Authorized access only.

This system is restricted to authorized users. Unauthorized access is prohibited
and may be subject to legal action. Use of this system may be monitored and
recorded. By continuing, you consent to such monitoring.
";

const TARGETS: &[(&str, &str)] = &[
    ("/etc/issue", "local login banner"),
    ("/etc/issue.net", "remote (ssh) login banner"),
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum BannerOutcome {
    /// Still the distro default; would be replaced (dry run).
    WouldWrite,
    /// Replaced with the warning banner.
    Written,
    /// Already a real custom warning — left exactly as the user wrote it.
    AlreadyCustom,
    /// The file doesn't exist on this host.
    Missing,
    Failed {
        reason: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BannerResult {
    pub path: String,
    pub label: String,
    pub outcome: BannerOutcome,
    /// Where the previous contents were copied before being overwritten.
    pub backup_path: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BannerReport {
    pub results: Vec<BannerResult>,
    pub written: usize,
    pub would_write: usize,
    pub already_custom: usize,
    pub missing: usize,
    pub failed: usize,
    pub applied: bool,
}

impl BannerReport {
    pub fn pending_count(&self) -> usize {
        self.written + self.would_write
    }
}

/// The rule ids this fixer clears.
#[cfg(test)]
pub(crate) fn managed_rule_ids() -> Vec<&'static str> {
    vec!["BLWK-BANN-001"]
}

/// Public entry point. Dry run unless `apply`.
pub fn write_banners(backup_dir: &Path, apply: bool) -> BannerReport {
    let targets: Vec<(PathBuf, &str)> = TARGETS
        .iter()
        .map(|(p, l)| (PathBuf::from(p), *l))
        .collect();
    write_banners_to(&targets, DEFAULT_BANNER, backup_dir, apply)
}

/// Testable core — takes explicit paths so a unit test never touches the real `/etc`.
fn write_banners_to(
    targets: &[(PathBuf, &str)],
    banner: &str,
    backup_dir: &Path,
    apply: bool,
) -> BannerReport {
    let mut report = BannerReport {
        applied: apply,
        ..Default::default()
    };

    for (path, label) in targets {
        let mut result = BannerResult {
            path: path.display().to_string(),
            label: label.to_string(),
            outcome: BannerOutcome::Missing,
            backup_path: None,
        };

        let existing = match std::fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                report.missing += 1;
                report.results.push(result);
                continue;
            }
            Err(e) => {
                result.outcome = BannerOutcome::Failed {
                    reason: e.to_string(),
                };
                report.failed += 1;
                report.results.push(result);
                continue;
            }
        };

        // Judged by the collector's own classifier, so the fixer fires exactly where the rule
        // does — and, just as importantly, never overwrites a banner a human already wrote.
        if !looks_like_default_banner(&existing) {
            result.outcome = BannerOutcome::AlreadyCustom;
            report.already_custom += 1;
            report.results.push(result);
            continue;
        }

        if !apply {
            result.outcome = BannerOutcome::WouldWrite;
            report.would_write += 1;
            report.results.push(result);
            continue;
        }

        match backup_and_write(path, &existing, banner, backup_dir) {
            Ok(backup) => {
                result.backup_path = Some(backup);
                result.outcome = BannerOutcome::Written;
                report.written += 1;
            }
            Err(e) => {
                result.outcome = BannerOutcome::Failed {
                    reason: e.to_string(),
                };
                report.failed += 1;
            }
        }
        report.results.push(result);
    }

    report
}

fn backup_and_write(
    path: &Path,
    existing: &str,
    banner: &str,
    backup_dir: &Path,
) -> anyhow::Result<String> {
    std::fs::create_dir_all(backup_dir)?;
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "issue".to_string());
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let backup = backup_dir.join(format!("{name}.{stamp}.bak"));
    std::fs::write(&backup, existing)?;
    std::fs::write(path, banner)?;
    Ok(backup.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn targets(dir: &Path) -> Vec<(PathBuf, &'static str)> {
        vec![
            (dir.join("issue"), "local login banner"),
            (dir.join("issue.net"), "remote (ssh) login banner"),
        ]
    }

    /// The single most important assertion in this file: the banner we write must not itself be
    /// classified as a default banner, or the fix would leave the finding firing forever. Checked
    /// against the collector's real classifier, not against a restatement of its rules here.
    #[test]
    fn the_written_banner_is_not_flagged_as_default() {
        assert!(
            !looks_like_default_banner(DEFAULT_BANNER),
            "the banner this fixer writes would still be reported as the distro default"
        );
        // Non-vacuous: the classifier does flag real default content.
        assert!(looks_like_default_banner("Ubuntu 26.04 LTS \\n \\l"));
        assert!(looks_like_default_banner("Ubuntu 26.04 LTS"));
    }

    /// A getty escape anywhere in the banner is what would break it — pinned explicitly, because
    /// "let's use \\n for the hostname in /etc/issue since it supports escapes" is the natural
    /// next edit and it would silently reintroduce the finding.
    #[test]
    fn the_banner_contains_no_getty_escapes() {
        assert!(
            !DEFAULT_BANNER.contains('\\'),
            "a getty escape in the banner makes the collector read it as the distro default"
        );
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        std::fs::write(dir.path().join("issue"), "Ubuntu 26.04 LTS \\n \\l\n").unwrap();
        std::fs::write(dir.path().join("issue.net"), "Ubuntu 26.04 LTS\n").unwrap();

        let r = write_banners_to(&targets(dir.path()), DEFAULT_BANNER, &backups, false);
        assert_eq!(
            r.would_write, 2,
            "both files must be seen as needing a banner"
        );
        assert_eq!(r.written, 0);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("issue")).unwrap(),
            "Ubuntu 26.04 LTS \\n \\l\n",
            "a dry run must not rewrite /etc/issue"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("issue.net")).unwrap(),
            "Ubuntu 26.04 LTS\n",
            "a dry run must not rewrite /etc/issue.net"
        );
        assert!(!backups.exists(), "a dry run must not write a backup");
    }

    #[test]
    fn apply_writes_both_files_backs_them_up_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        std::fs::write(dir.path().join("issue"), "Ubuntu 26.04 LTS \\n \\l\n").unwrap();
        std::fs::write(dir.path().join("issue.net"), "Ubuntu 26.04 LTS\n").unwrap();

        let r = write_banners_to(&targets(dir.path()), DEFAULT_BANNER, &backups, true);
        assert_eq!(r.written, 2);
        for f in ["issue", "issue.net"] {
            assert_eq!(
                std::fs::read_to_string(dir.path().join(f)).unwrap(),
                DEFAULT_BANNER
            );
        }
        assert!(r.results.iter().all(|x| x.backup_path.is_some()));

        // Re-running finds a real custom banner and leaves it alone — no second backup, no rewrite.
        let again = write_banners_to(&targets(dir.path()), DEFAULT_BANNER, &backups, true);
        assert_eq!(again.already_custom, 2);
        assert_eq!(again.written, 0);
    }

    /// A hand-written banner is the user's own work and must survive the fixer untouched.
    #[test]
    fn a_custom_banner_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let custom = "ACME Corp - unauthorized access prohibited, activity is monitored.\n";
        std::fs::write(dir.path().join("issue"), custom).unwrap();
        std::fs::write(dir.path().join("issue.net"), "Ubuntu 26.04 LTS\n").unwrap();

        let r = write_banners_to(
            &targets(dir.path()),
            DEFAULT_BANNER,
            &dir.path().join("b"),
            true,
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("issue")).unwrap(),
            custom,
            "an existing custom banner must not be replaced"
        );
        // …and the other file, which was still default, is fixed independently. This is the
        // list-shaped part: one file being fine must not suppress the other.
        assert_eq!(r.written, 1);
        assert_eq!(r.already_custom, 1);
        assert_eq!(
            std::fs::read_to_string(dir.path().join("issue.net")).unwrap(),
            DEFAULT_BANNER
        );
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("issue"), "Ubuntu 26.04 LTS\n").unwrap();
        let r = write_banners_to(
            &targets(dir.path()),
            DEFAULT_BANNER,
            &dir.path().join("b"),
            true,
        );
        assert_eq!(r.missing, 1);
        assert_eq!(r.failed, 0);
        assert_eq!(r.written, 1);
    }
}
