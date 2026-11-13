//! Write a legal warning banner to `/etc/issue` and `/etc/issue.net` — the fix for `BLWK-BANN-001`.
//!
//! The rule is **list-shaped**: the `banners` collector emits one fact per file, so a host can be
//! flagged for `/etc/issue`, `/etc/issue.net`, or both, and each is an independent finding. This
//! fixer therefore treats each file independently, and one file being fine never suppresses the
//! other.
//!
//! **It replaces the distribution's default text and nothing else.** The rule also fires for an
//! emptied file and for text somebody wrote that carries no warning ("Welcome to prod-db-1") —
//! there is still no warning there — but those are a person's choice, and this fixer reports them
//! as left alone. It once treated everything without a warning word as "the default" and
//! overwrote both. The classification is the collector's own ([`classify_banner`]), so the fixer
//! and the scan cannot disagree about what a file holds.
//!
//! **It never writes through a symbolic link.** Fedora ships `/etc/issue -> ../usr/lib/issue`;
//! writing through that changed a package-owned file under `/usr/lib` (and `rpm -V` said so). The
//! link is replaced by a regular file in `/etc`, in one rename, and the link's target is not
//! touched — which is also how an administrator overrides a `/usr/lib` default by hand.
//!
//! **On the getty-escape asymmetry.** `/etc/issue` is expanded by getty, which substitutes `\s`
//! (OS name), `\n` (hostname), `\r` (kernel release) and friends; `/etc/issue.net` is read by sshd
//! and gets no such expansion. The banner written here contains no escape sequences at all, which
//! makes identical content correct for both files. `the_written_banner_reads_as_a_warning` pins
//! that against the collector's real classifier rather than against this reasoning.

use crate::collectors::banners::{classify_banner, read_os_release, BannerKind};
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
    /// Already a warning — left exactly as the user wrote it.
    AlreadyCustom,
    /// Text somebody wrote that carries no warning, or a file somebody emptied. The finding stays
    /// open, and the file is left exactly as it is: `empty` tells the two apart.
    CustomisedLeftAlone {
        empty: bool,
    },
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
    /// Set when the path was a symbolic link: where it pointed. The link is replaced by a regular
    /// file and the file it pointed at is not changed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub was_link_to: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct BannerReport {
    pub results: Vec<BannerResult>,
    pub written: usize,
    pub would_write: usize,
    pub already_custom: usize,
    /// Files holding somebody's own text (or emptied on purpose) without a warning: not changed.
    #[serde(default)]
    pub left_customised: usize,
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
    write_banners_to(
        &targets,
        DEFAULT_BANNER,
        read_os_release().as_deref(),
        backup_dir,
        apply,
    )
}

/// Testable core — takes explicit paths so a unit test never touches the real `/etc`.
fn write_banners_to(
    targets: &[(PathBuf, &str)],
    banner: &str,
    os_release: Option<&str>,
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
            was_link_to: None,
        };

        // Read through a link (the content decides what the file is), but remember that it is
        // one: the write below replaces the link, never what it points at.
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
        result.was_link_to = std::fs::read_link(path)
            .ok()
            .map(|t| t.display().to_string());

        // Judged by the collector's own classifier, so the fixer and the scan agree on what the
        // file holds — and only the distribution's own text is ever replaced.
        match classify_banner(&existing, os_release) {
            BannerKind::DistroDefault => {}
            BannerKind::Warning => {
                result.was_link_to = None;
                result.outcome = BannerOutcome::AlreadyCustom;
                report.already_custom += 1;
                report.results.push(result);
                continue;
            }
            kind @ (BannerKind::Customised | BannerKind::Empty) => {
                result.was_link_to = None;
                result.outcome = BannerOutcome::CustomisedLeftAlone {
                    empty: kind == BannerKind::Empty,
                };
                report.left_customised += 1;
                report.results.push(result);
                continue;
            }
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
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| "issue".to_string());
    let backup = super::write_backup(backup_dir, &name, existing.as_bytes())?;
    // A regular file in the banner's own directory, swapped in with one rename: a symbolic link
    // at `path` is replaced, not followed.
    super::replace_file(path, banner.as_bytes(), 0o644)?;
    Ok(backup.display().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    const OS: &str =
        "NAME=\"Ubuntu\"\nPRETTY_NAME=\"Ubuntu 26.04 LTS\"\nVERSION_ID=\"26.04\"\nID=ubuntu\n";

    fn targets(dir: &Path) -> Vec<(PathBuf, &'static str)> {
        vec![
            (dir.join("issue"), "local login banner"),
            (dir.join("issue.net"), "remote (ssh) login banner"),
        ]
    }

    fn run(dir: &Path, backups: &Path, apply: bool) -> BannerReport {
        write_banners_to(&targets(dir), DEFAULT_BANNER, Some(OS), backups, apply)
    }

    /// The single most important assertion in this file: the banner we write must itself read as
    /// a warning, or the fix would leave the finding firing forever (and a second run would see
    /// its own output as something to act on). Checked against the collector's real classifier,
    /// not against a restatement of its rules here.
    #[test]
    fn the_written_banner_reads_as_a_warning() {
        assert_eq!(
            classify_banner(DEFAULT_BANNER, Some(OS)),
            BannerKind::Warning,
            "the banner this fixer writes would still be reported"
        );
        // Non-vacuous: the classifier does flag real default content.
        assert_eq!(
            classify_banner("Ubuntu 26.04 LTS \\n \\l", Some(OS)),
            BannerKind::DistroDefault
        );
        assert_eq!(
            classify_banner("Ubuntu 26.04 LTS", Some(OS)),
            BannerKind::DistroDefault
        );
    }

    /// The same text goes to `/etc/issue` (getty expands escapes) and `/etc/issue.net` (sshd
    /// does not), so it must contain none.
    #[test]
    fn the_banner_contains_no_getty_escapes() {
        assert!(!DEFAULT_BANNER.contains('\\'));
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("backups");
        std::fs::write(dir.path().join("issue"), "Ubuntu 26.04 LTS \\n \\l\n").unwrap();
        std::fs::write(dir.path().join("issue.net"), "Ubuntu 26.04 LTS\n").unwrap();

        let r = run(dir.path(), &backups, false);
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

        let r = run(dir.path(), &backups, true);
        assert_eq!(r.written, 2);
        for f in ["issue", "issue.net"] {
            assert_eq!(
                std::fs::read_to_string(dir.path().join(f)).unwrap(),
                DEFAULT_BANNER
            );
        }
        assert!(r.results.iter().all(|x| x.backup_path.is_some()));
        assert_eq!(
            std::fs::read_to_string(r.results[0].backup_path.as_ref().unwrap()).unwrap(),
            "Ubuntu 26.04 LTS \\n \\l\n"
        );

        // Running it again changes nothing: no second backup, no rewrite.
        let backups_before = std::fs::read_dir(&backups).unwrap().count();
        let again = run(dir.path(), &backups, true);
        assert_eq!(again.already_custom, 2);
        assert_eq!(again.written, 0);
        assert_eq!(std::fs::read_dir(&backups).unwrap().count(), backups_before);
    }

    /// A hand-written banner is the user's own work and must survive the fixer untouched.
    #[test]
    fn a_custom_banner_is_never_overwritten() {
        let dir = tempfile::tempdir().unwrap();
        let custom = "ACME Corp - unauthorized access prohibited, activity is monitored.\n";
        std::fs::write(dir.path().join("issue"), custom).unwrap();
        std::fs::write(dir.path().join("issue.net"), "Ubuntu 26.04 LTS\n").unwrap();

        let r = run(dir.path(), &dir.path().join("b"), true);
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

    /// The tester's two cases: a greeting with no warning words, and an emptied file. Both used
    /// to count as "the default" and were overwritten. They are still without a warning (the
    /// finding stays), and they are somebody's choice: byte-for-byte unchanged, no backup made.
    #[test]
    fn text_someone_wrote_and_an_emptied_file_survive_byte_for_byte() {
        let dir = tempfile::tempdir().unwrap();
        let backups = dir.path().join("b");
        let greeting = "Welcome to prod-db-1!\n";
        std::fs::write(dir.path().join("issue"), greeting).unwrap();
        std::fs::write(dir.path().join("issue.net"), "").unwrap();

        for _ in 0..2 {
            let r = run(dir.path(), &backups, true);
            assert_eq!((r.written, r.left_customised, r.failed), (0, 2, 0));
            assert_eq!(
                r.results[0].outcome,
                BannerOutcome::CustomisedLeftAlone { empty: false }
            );
            assert_eq!(
                r.results[1].outcome,
                BannerOutcome::CustomisedLeftAlone { empty: true }
            );
            assert_eq!(
                std::fs::read(dir.path().join("issue")).unwrap(),
                greeting.as_bytes()
            );
            assert_eq!(std::fs::read(dir.path().join("issue.net")).unwrap(), b"");
            assert!(
                !backups.exists(),
                "nothing was changed, so nothing is backed up"
            );
        }
        // The preview says the same, so `fix list` never promises a write it won't make.
        assert_eq!(run(dir.path(), &backups, false).pending_count(), 0);
    }

    /// Fedora: `/etc/issue -> ../usr/lib/issue`, and the target belongs to a package. The link is
    /// replaced by a regular file; what it pointed at is not written to.
    #[cfg(unix)]
    #[test]
    fn a_symlinked_banner_is_replaced_not_written_through() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let etc = dir.path().join("etc");
        let lib = dir.path().join("usr/lib");
        std::fs::create_dir_all(&etc).unwrap();
        std::fs::create_dir_all(&lib).unwrap();
        let stock = "\\S\nKernel \\r on \\m (\\l)\n";
        std::fs::write(lib.join("issue"), stock).unwrap();
        std::os::unix::fs::symlink("../usr/lib/issue", etc.join("issue")).unwrap();
        let fedora = "NAME=\"Fedora Linux\"\nVERSION_ID=43\nID=fedora\n";
        let targets = vec![(etc.join("issue"), "local login banner")];

        let r = write_banners_to(
            &targets,
            DEFAULT_BANNER,
            Some(fedora),
            &dir.path().join("b"),
            true,
        );
        assert_eq!(r.written, 1, "{:?}", r.results);
        assert_eq!(
            std::fs::read_to_string(lib.join("issue")).unwrap(),
            stock,
            "the package's file under /usr/lib must not be written to"
        );
        let meta = std::fs::symlink_metadata(etc.join("issue")).unwrap();
        assert!(meta.file_type().is_file(), "the link is now a regular file");
        assert_eq!(meta.permissions().mode() & 0o777, 0o644);
        assert_eq!(
            std::fs::read_to_string(etc.join("issue")).unwrap(),
            DEFAULT_BANNER
        );
        assert_eq!(
            r.results[0].was_link_to.as_deref(),
            Some("../usr/lib/issue")
        );
        // No temporary file is left behind.
        assert_eq!(std::fs::read_dir(&etc).unwrap().count(), 1);
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("issue"), "Ubuntu 26.04 LTS\n").unwrap();
        let r = run(dir.path(), &dir.path().join("b"), true);
        assert_eq!(r.missing, 1);
        assert_eq!(r.failed, 0);
        assert_eq!(r.written, 1);
    }
}
