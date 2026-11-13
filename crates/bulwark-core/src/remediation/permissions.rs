//! Tighten over-permissive file modes — the safest, most mechanical class of autofix.
//!
//! Two families of target are built here: the invoking user's `~/.ssh` tree (user-scoped, needs no
//! privilege) and a fixed set of sensitive `/etc` files (root-scoped). Both flow through one
//! [`tighten_permissions`] engine so the safety rules live in exactly one place:
//!
//!   * **Only ever removes permission bits, never adds one.** A target is changed only when its
//!     current mode grants bits *beyond* the desired mode (`current & !desired & 0o777 != 0`), and
//!     the new mode is `current & desired` — the bits both have — never `desired` itself. Setting
//!     `desired` outright used to turn a `660` `known_hosts` into `644` (everyone gains read) and
//!     a `440` key into `600`. A file already at or stricter than the target (e.g. a `600`
//!     `/etc/passwd` where `644` is expected) is left untouched.
//!   * **Never follows a symlink.** `symlink_metadata` classifies the entry; a symlink is reported
//!     and skipped, so a planted link in `~/.ssh` can't redirect a `chmod` onto an arbitrary file.
//!   * **Records the prior mode** in the result. A `chmod` is trivially reversible, so no content
//!     backup is needed — the report tells the user the exact `chmod` to undo any change.
//!
//! Dry-run is the default everywhere: nothing is written unless the caller passes `apply = true`.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// One path we want at a specific mode, with a human label for the report.
#[derive(Debug, Clone)]
pub struct PermTarget {
    pub path: PathBuf,
    /// The canonical secure mode (permission bits only, e.g. `0o600`). The most access the file
    /// may keep: bits outside it are removed, bits inside it are never added.
    pub desired: u32,
    /// Short description of what this file is, e.g. "private key" — shown in output.
    pub label: &'static str,
    /// True for a file a scan without admin rights reads (`sshd_config`). Taking read access away
    /// from other accounts is still the right fix, but those scans then lose the checks that read
    /// it, and the result says so instead of leaving the user to work it out.
    pub read_by_ordinary_scans: bool,
}

impl PermTarget {
    pub fn new(path: impl Into<PathBuf>, desired: u32, label: &'static str) -> Self {
        Self {
            path: path.into(),
            desired,
            label,
            read_by_ordinary_scans: false,
        }
    }

    /// Marks a file that scans without admin rights read — see the field.
    pub fn read_by_ordinary_scans(mut self) -> Self {
        self.read_by_ordinary_scans = true;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum PermOutcome {
    /// Was too permissive; tightened from `from` to `to` (octal strings). Only set when applied.
    Tightened { from: String, to: String },
    /// Would be tightened, but this was a dry run. Carries the same before/after preview.
    WouldTighten { from: String, to: String },
    /// Already at or stricter than the desired mode — left untouched.
    AlreadyOk,
    /// The path doesn't exist on this host — skipped, not an error.
    Missing,
    /// A symlink — refused, never chmod'd through.
    SkippedSymlink,
    /// The chmod (or a stat) failed.
    Failed { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PermResult {
    pub path: String,
    pub label: String,
    /// Current mode as an octal string (e.g. "644"), or `None` if the path is missing/unreadable.
    pub current_mode: Option<String>,
    pub desired_mode: String,
    pub outcome: PermOutcome,
    /// Something the user should know about this change, in plain words: the file can no longer
    /// be read by scans without admin rights, or its owner still has no read access.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PermReport {
    pub results: Vec<PermResult>,
    pub tightened: usize,
    pub would_tighten: usize,
    pub already_ok: usize,
    pub missing: usize,
    pub skipped_symlink: usize,
    pub failed: usize,
}

impl PermReport {
    /// Total number of paths that are (or would be) changed — the headline count.
    pub fn changes(&self) -> usize {
        self.tightened + self.would_tighten
    }
}

/// True when `current` grants any permission bit the `desired` mode does not — i.e. the file is more
/// permissive than we want. Compares only the low 9 bits so setuid/gid/sticky never enter into it.
fn is_too_permissive(current: u32, desired: u32) -> bool {
    (current & 0o777) & !(desired & 0o777) != 0
}

/// Run the tightener over `targets`. With `apply = false` (the default) it only previews.
pub fn tighten_permissions(targets: &[PermTarget], apply: bool) -> PermReport {
    let mut report = PermReport::default();
    for t in targets {
        let desired_mode = format!("{:o}", t.desired & 0o777);
        let mut result = PermResult {
            path: t.path.display().to_string(),
            label: t.label.to_string(),
            current_mode: None,
            desired_mode,
            outcome: PermOutcome::Missing,
            note: None,
        };

        // symlink_metadata does NOT follow the final symlink, so we can tell a link apart from a
        // real file and refuse to chmod through it.
        let meta = match std::fs::symlink_metadata(&t.path) {
            Ok(m) => m,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                report.missing += 1;
                report.results.push(result);
                continue;
            }
            Err(e) => {
                result.outcome = PermOutcome::Failed {
                    reason: e.to_string(),
                };
                report.failed += 1;
                report.results.push(result);
                continue;
            }
        };

        if meta.file_type().is_symlink() {
            result.outcome = PermOutcome::SkippedSymlink;
            report.skipped_symlink += 1;
            report.results.push(result);
            continue;
        }

        let Some(current) = crate::platform::file_mode(&meta).map(|m| m & 0o777) else {
            result.outcome = PermOutcome::Failed {
                reason: "file modes are not supported on this platform".into(),
            };
            report.failed += 1;
            report.results.push(result);
            continue;
        };
        result.current_mode = Some(format!("{current:o}"));

        if !is_too_permissive(current, t.desired) {
            result.outcome = PermOutcome::AlreadyOk;
            report.already_ok += 1;
            report.results.push(result);
            continue;
        }

        // The bits both modes have. Never `desired` itself: that would add whatever `desired` has
        // and the file lacks (a `660` known_hosts would gain world read on its way to `644`).
        let tightened = current & t.desired & 0o777;
        let from = format!("{current:o}");
        let to = format!("{tightened:o}");
        result.note = change_note(t, current, tightened, apply);
        if !apply {
            result.outcome = PermOutcome::WouldTighten { from, to };
            report.would_tighten += 1;
            report.results.push(result);
            continue;
        }

        match crate::platform::set_file_mode(&t.path, tightened) {
            Ok(()) => {
                result.outcome = PermOutcome::Tightened { from, to };
                report.tightened += 1;
            }
            Err(e) => {
                result.note = None;
                result.outcome = PermOutcome::Failed {
                    reason: e.to_string(),
                };
                report.failed += 1;
            }
        }
        report.results.push(result);
    }
    report
}

/// What the user should know about a change beyond the two modes.
fn change_note(t: &PermTarget, current: u32, tightened: u32, apply: bool) -> Option<String> {
    let path = t.path.display();
    // Removing bits can't take read away from an owner who had it (every target keeps owner
    // read), but it can't give it back either. A key at `044` ends at `000`: say so, because the
    // fix is the owner's to make and this tool only ever removes access.
    if tightened & 0o400 == 0 {
        return Some(format!(
            "the owner of {path} has no read access (it had none before either). Bulwark only \
             removes access, so add it yourself if you need it: chmod u+r {path}"
        ));
    }
    if t.read_by_ordinary_scans && current & 0o004 != 0 && tightened & 0o004 == 0 {
        return Some(format!(
            "{} only an administrator can read {path}, so scans without sudo can no longer check \
             it. `sudo bulwarkctl scan --privileged` still covers it.",
            if apply { "From now on" } else { "After this" }
        ));
    }
    None
}

/// Build the `~/.ssh` permission targets for a given ssh directory. Each entry is classified so we
/// only demand `600` on things that are actually secrets (private keys, `authorized_keys`, `config`)
/// and `644` on public artifacts — never demanding a mode that would break normal use.
///
/// Symlinked entries are still listed (as targets); the engine refuses them at chmod time, so they
/// surface in the report as skipped rather than silently vanishing.
pub fn ssh_permission_targets(ssh_dir: &Path) -> Vec<PermTarget> {
    let mut targets = Vec::new();
    if !ssh_dir.exists() {
        return targets;
    }
    // The directory itself must be 700 — a group/world-accessible ~/.ssh lets others enumerate and
    // in the worst case replace its contents.
    targets.push(PermTarget::new(
        ssh_dir.to_path_buf(),
        0o700,
        ".ssh directory",
    ));

    let Ok(entries) = std::fs::read_dir(ssh_dir) else {
        return targets;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();

        // Read content (capped) only to classify private keys; a symlink/dir read just fails and
        // falls through to the name-based rules, which is fine — the engine skips symlinks anyway.
        let (desired, label): (u32, &'static str) = if name == "config" {
            (0o600, "ssh client config")
        } else if name.starts_with("authorized_keys") {
            (0o600, "authorized_keys")
        } else if name.starts_with("known_hosts") {
            (0o644, "known_hosts")
        } else if name.ends_with(".pub") {
            (0o644, "public key")
        } else if is_private_key_file(&path) {
            (0o600, "private key")
        } else {
            continue; // unknown file — don't presume a mode for it
        };
        targets.push(PermTarget::new(path, desired, label));
    }
    targets
}

/// Whether `path` is a private SSH key, by content — reuses the collector's header classifier so
/// this agrees exactly with what the scan reports as a key.
fn is_private_key_file(path: &Path) -> bool {
    let Ok(content) = super::super::collectors::read_capped(path) else {
        return false;
    };
    super::super::collectors::ssh_keys::classify_private_key(&content).is_some()
}

/// The sensitive `/etc` files worth pinning to a canonical mode, matching what the
/// `file_permissions` collector watches (research report §7). Root-scoped: chmod here needs
/// privilege, which the CLI enforces before calling. Each mode is the most access the file may
/// keep, so a file is changed whenever it grants anything beyond it — a stock `644` `sshd_config`
/// included, not only a group- or world-writable one.
pub fn etc_permission_targets() -> Vec<PermTarget> {
    vec![
        PermTarget::new("/etc/shadow", 0o640, "/etc/shadow (password hashes)"),
        PermTarget::new("/etc/gshadow", 0o640, "/etc/gshadow (group hashes)"),
        PermTarget::new("/etc/passwd", 0o644, "/etc/passwd"),
        PermTarget::new("/etc/group", 0o644, "/etc/group"),
        PermTarget::new("/etc/sudoers", 0o440, "/etc/sudoers"),
        // 600 is what CIS asks for. A stock install ships it 644 and the `sshd_config` collector
        // reads it without admin rights, hence the flag: the change is reported together with
        // what it costs an ordinary scan.
        PermTarget::new("/etc/ssh/sshd_config", 0o600, "sshd_config").read_by_ordinary_scans(),
    ]
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    fn mode_of(p: &Path) -> u32 {
        fs::symlink_metadata(p).unwrap().permissions().mode() & 0o777
    }

    #[test]
    fn tightens_only_when_too_permissive() {
        assert!(is_too_permissive(0o644, 0o600)); // world+group read beyond 600
        assert!(is_too_permissive(0o755, 0o700));
        assert!(is_too_permissive(0o666, 0o644)); // group/world write beyond 644
        assert!(!is_too_permissive(0o600, 0o600));
        assert!(!is_too_permissive(0o400, 0o600)); // stricter than desired — leave alone
        assert!(!is_too_permissive(0o644, 0o644));
        assert!(!is_too_permissive(0o600, 0o644)); // stricter than desired — never loosen
    }

    #[test]
    fn dry_run_changes_nothing_apply_tightens() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        fs::write(&key, "x").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        let targets = vec![PermTarget::new(key.clone(), 0o600, "private key")];

        let preview = tighten_permissions(&targets, false);
        assert_eq!(preview.would_tighten, 1);
        assert_eq!(preview.tightened, 0);
        assert_eq!(mode_of(&key), 0o644, "dry run must not change the file");

        let applied = tighten_permissions(&targets, true);
        assert_eq!(applied.tightened, 1);
        assert_eq!(mode_of(&key), 0o600, "apply must tighten to desired");

        // Second apply is a no-op (already ok).
        let again = tighten_permissions(&targets, true);
        assert_eq!(again.already_ok, 1);
        assert_eq!(again.tightened, 0);
    }

    #[test]
    fn never_loosens_a_stricter_file() {
        let dir = tempfile::tempdir().unwrap();
        let f = dir.path().join("passwd");
        fs::write(&f, "x").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o600)).unwrap();
        // Desired 644 is *more* permissive; a stricter 600 must be left exactly as-is.
        let targets = vec![PermTarget::new(f.clone(), 0o644, "/etc/passwd")];
        let r = tighten_permissions(&targets, true);
        assert_eq!(r.already_ok, 1);
        assert_eq!(mode_of(&f), 0o600);
    }

    /// The tester's cases: the old code set `desired` outright, so a `660` known_hosts became
    /// `644` (everyone gained read), a `440` key became `600` (the owner gained write) and a
    /// `604` shadow became `640` (the group gained read).
    #[test]
    fn a_fix_never_adds_a_permission_bit() {
        let dir = tempfile::tempdir().unwrap();
        for (name, current, desired, expected) in [
            ("known_hosts", 0o660, 0o644, 0o640),
            ("key", 0o440, 0o600, 0o400),
            ("shadow", 0o604, 0o640, 0o600),
            ("sudoers", 0o666, 0o440, 0o440),
            ("dir-like", 0o751, 0o700, 0o700),
        ] {
            let f = dir.path().join(name);
            fs::write(&f, "x").unwrap();
            fs::set_permissions(&f, fs::Permissions::from_mode(current)).unwrap();
            let targets = vec![PermTarget::new(f.clone(), desired, "x")];

            let preview = tighten_permissions(&targets, false);
            assert_eq!(
                preview.results[0].outcome,
                PermOutcome::WouldTighten {
                    from: format!("{current:o}"),
                    to: format!("{expected:o}"),
                },
                "{name}: the preview must show the mode that will really be set"
            );

            let r = tighten_permissions(&targets, true);
            assert_eq!(r.tightened, 1, "{name}");
            let after = mode_of(&f);
            assert_eq!(
                after, expected,
                "{name}: {current:o} with target {desired:o}"
            );
            assert_eq!(
                after & !current,
                0,
                "{name}: {current:o} → {after:o} added a permission bit"
            );

            // Running it again changes nothing.
            let again = tighten_permissions(&targets, true);
            assert_eq!((again.tightened, again.already_ok), (0, 1), "{name}");
            assert_eq!(mode_of(&f), expected);
        }
    }

    /// Every pair of modes, not just the ones someone thought of.
    #[test]
    fn no_pair_of_modes_can_add_a_bit() {
        for desired in [0o600u32, 0o644, 0o640, 0o440, 0o700] {
            for current in 0..=0o777u32 {
                if !is_too_permissive(current, desired) {
                    continue;
                }
                let tightened = current & desired & 0o777;
                assert_eq!(tightened & !current, 0);
                assert_eq!(tightened & !desired, 0);
                assert!(
                    !is_too_permissive(tightened, desired),
                    "second run is a no-op"
                );
            }
        }
    }

    /// The one result that is not usable: an owner who could not read the file still cannot.
    /// The fix removes what others had, adds nothing, and says what is left to do.
    #[test]
    fn an_owner_without_read_access_is_told_and_not_given_it() {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("id_ed25519");
        fs::write(&key, "x").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o044)).unwrap();
        let targets = vec![PermTarget::new(key.clone(), 0o600, "private key")];
        let r = tighten_permissions(&targets, true);
        assert_eq!(r.tightened, 1);
        assert_eq!(
            mode_of(&key),
            0o000,
            "group and world read removed, nothing added"
        );
        let note = r.results[0].note.as_deref().unwrap_or_default();
        assert!(note.contains("chmod u+r"), "{note}");
        // An ordinary tightening carries no note.
        fs::set_permissions(&key, fs::Permissions::from_mode(0o644)).unwrap();
        let r = tighten_permissions(&targets, true);
        assert_eq!(r.results[0].note, None);
    }

    /// `sshd_config` going from 644 to 600 is correct and costs ordinary scans their SSH checks.
    /// The result says so, in the preview and after applying, and only for a file marked as read
    /// by those scans.
    #[test]
    fn hiding_a_file_from_ordinary_scans_is_said_out_loud() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("sshd_config");
        fs::write(&cfg, "x").unwrap();
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o644)).unwrap();
        let marked =
            vec![PermTarget::new(cfg.clone(), 0o600, "sshd_config").read_by_ordinary_scans()];

        let preview = tighten_permissions(&marked, false);
        let note = preview.results[0].note.clone().unwrap_or_default();
        assert!(note.contains("sudo bulwarkctl scan --privileged"), "{note}");

        let applied = tighten_permissions(&marked, true);
        assert_eq!(mode_of(&cfg), 0o600);
        assert!(applied.results[0]
            .note
            .as_deref()
            .is_some_and(|n| n.contains("scans without sudo can no longer check")));

        // Group-readable only (640 → 600): ordinary scans could not read it before either.
        fs::set_permissions(&cfg, fs::Permissions::from_mode(0o640)).unwrap();
        assert_eq!(tighten_permissions(&marked, true).results[0].note, None);
        // The real target list marks sshd_config, and nothing whose exposure was the problem.
        let etc = etc_permission_targets();
        let flagged: Vec<_> = etc.iter().filter(|t| t.read_by_ordinary_scans).collect();
        assert_eq!(flagged.len(), 1);
        assert_eq!(flagged[0].path, Path::new("/etc/ssh/sshd_config"));
    }

    #[test]
    fn symlink_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let real = dir.path().join("real");
        fs::write(&real, "x").unwrap();
        fs::set_permissions(&real, fs::Permissions::from_mode(0o600)).unwrap();
        let link = dir.path().join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();
        let targets = vec![PermTarget::new(link, 0o600, "private key")];
        let r = tighten_permissions(&targets, true);
        assert_eq!(r.skipped_symlink, 1);
        assert_eq!(
            mode_of(&real),
            0o600,
            "the symlink target must be untouched"
        );
    }

    #[test]
    fn missing_path_is_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let targets = vec![PermTarget::new(dir.path().join("nope"), 0o600, "x")];
        let r = tighten_permissions(&targets, true);
        assert_eq!(r.missing, 1);
        assert_eq!(r.failed, 0);
    }

    #[test]
    fn ssh_targets_classify_by_name_and_content() {
        let dir = tempfile::tempdir().unwrap();
        let ssh = dir.path().join(".ssh");
        fs::create_dir(&ssh).unwrap();
        fs::write(ssh.join("config"), "Host x").unwrap();
        fs::write(ssh.join("authorized_keys"), "ssh-ed25519 AAAA").unwrap();
        fs::write(ssh.join("id_ed25519.pub"), "ssh-ed25519 AAAA").unwrap();
        fs::write(ssh.join("known_hosts"), "h ssh-ed25519 AAAA").unwrap();
        fs::write(
            ssh.join("id_ed25519"),
            "-----BEGIN OPENSSH PRIVATE KEY-----\nabc\n-----END OPENSSH PRIVATE KEY-----\n",
        )
        .unwrap();
        fs::write(ssh.join("random.txt"), "not a key").unwrap();

        let targets = ssh_permission_targets(&ssh);
        let by_name = |n: &str| {
            targets
                .iter()
                .find(|t| {
                    t.path
                        .file_name()
                        .map(|f| f.to_string_lossy() == n)
                        .unwrap_or(false)
                })
                .map(|t| t.desired)
        };
        assert_eq!(by_name("config"), Some(0o600));
        assert_eq!(by_name("authorized_keys"), Some(0o600));
        assert_eq!(by_name("id_ed25519"), Some(0o600));
        assert_eq!(by_name("id_ed25519.pub"), Some(0o644));
        assert_eq!(by_name("known_hosts"), Some(0o644));
        assert_eq!(by_name("random.txt"), None, "unknown files get no target");
        // The directory itself is targeted at 700.
        assert!(targets.iter().any(|t| t.path == ssh && t.desired == 0o700));
    }
}
