//! Set password-aging policy in `/etc/login.defs` — the fix for `BLWK-ACCT-002`/`BLWK-ACCT-003`.
//!
//! Structurally this is `sshd.rs`'s sibling (back up, edit idempotently, only touch directives the
//! matching rule would actually flag), but the *editing strategy* is deliberately different, and
//! the difference is worth stating because copying `sshd.rs` blindly would be wrong.
//!
//! `sshd.rs` inserts a block at the **top** of the file, because sshd is first-value-wins and
//! `Include` drop-ins are expanded inline — being first is the only way to guarantee your value is
//! the effective one. `login.defs` is the opposite: shadow's `getdef` loads the file line by line
//! and each assignment overwrites the previous, so the **last** occurrence wins, and this project's
//! `login_defs` collector reproduces that (its parse loop `insert`s on every match, overwriting).
//!
//! Rather than depend on either reading, this fixer **replaces the existing directive in place**
//! and only appends when the key is absent entirely. That is correct under first-wins and
//! last-wins alike, and it leaves a file with one line per key instead of a growing pile of
//! duplicates. The failure mode it avoids is the one CLAUDE.md calls out: blindly appending
//! `PASS_MAX_DAYS 90` after an existing uncommented `PASS_MAX_DAYS 99999` is silently ignored
//! under first-wins semantics — a fix that writes a file, reports success, and changes nothing.
//!
//! A commented-out `#PASS_MIN_DAYS 0` is left as a comment and the real directive appended, since
//! uncommenting someone's annotation is a different edit from setting a value.

use serde::{Deserialize, Serialize};
use std::path::Path;

const MAIN_CONFIG: &str = "/etc/login.defs";

/// One managed key. `is_insecure` mirrors the corresponding rule's condition exactly, so the fixer
/// fires where — and only where — the scanner does.
struct Directive {
    key: &'static str,
    rule_id: &'static str,
    desired: &'static str,
    why: &'static str,
    /// The rule's own condition, as a predicate on the currently-set value.
    is_insecure: fn(i64) -> bool,
    /// What to assume when the key is absent from the file. `None` means "absent is fine" —
    /// never invent a finding for a key the rule couldn't have read either.
    default_when_absent: Option<i64>,
}

const DIRECTIVES: &[Directive] = &[
    Directive {
        key: "PASS_MAX_DAYS",
        rule_id: "BLWK-ACCT-002",
        desired: "90",
        why: "a password that never effectively expires keeps a leaked credential valid forever (BLWK-ACCT-002)",
        // Rule: pass_max_days > 365.
        is_insecure: |v| v > 365,
        // Absent means shadow's built-in default (99999) applies — which is insecure, but the
        // collector reports no field at all, so the rule cannot fire and neither will we.
        default_when_absent: None,
    },
    Directive {
        key: "PASS_MIN_DAYS",
        rule_id: "BLWK-ACCT-003",
        desired: "1",
        why: "a zero minimum age lets a user cycle straight back to the compromised password (BLWK-ACCT-003)",
        // Rule: pass_min_days == 0.
        is_insecure: |v| v == 0,
        default_when_absent: None,
    },
];

/// The rule ids this fixer clears.
#[cfg(test)]
pub(crate) fn managed_rule_ids() -> Vec<&'static str> {
    DIRECTIVES.iter().map(|d| d.rule_id).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum LoginDefsChangeStatus {
    WouldSet,
    Set,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginDefsChange {
    pub key: String,
    pub current: String,
    pub desired: String,
    pub why: String,
    pub status: LoginDefsChangeStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LoginDefsReport {
    pub config_path: String,
    pub changes: Vec<LoginDefsChange>,
    pub applied: bool,
    pub backup_path: Option<String>,
    pub note: Option<String>,
}

impl LoginDefsReport {
    pub fn pending_count(&self) -> usize {
        self.changes.len()
    }
}

/// Public entry point. `rules` selects which directives to consider, so a per-issue fix touches
/// only its own key. Dry run unless `apply`.
pub fn harden_login_defs(
    rules: &[&str],
    config_path: Option<&Path>,
    backup_dir: &Path,
    apply: bool,
) -> anyhow::Result<LoginDefsReport> {
    let path = config_path.unwrap_or_else(|| Path::new(MAIN_CONFIG));
    let mut report = LoginDefsReport {
        config_path: path.display().to_string(),
        ..Default::default()
    };
    if !path.exists() {
        anyhow::bail!("{} does not exist", path.display());
    }
    let original = std::fs::read_to_string(path)?;

    for d in DIRECTIVES.iter().filter(|d| rules.contains(&d.rule_id)) {
        let current = effective_value(&original, d.key).or(d.default_when_absent);
        let Some(v) = current else { continue };
        if !(d.is_insecure)(v) {
            continue;
        }
        report.changes.push(LoginDefsChange {
            key: d.key.to_string(),
            current: v.to_string(),
            desired: d.desired.to_string(),
            why: d.why.to_string(),
            status: LoginDefsChangeStatus::WouldSet,
        });
    }

    if !apply || report.changes.is_empty() {
        return Ok(report);
    }

    std::fs::create_dir_all(backup_dir)?;
    let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
    let backup = backup_dir.join(format!("login.defs.{stamp}.bak"));
    std::fs::write(&backup, &original)?;
    report.backup_path = Some(backup.display().to_string());

    let mut text = original.clone();
    for change in &mut report.changes {
        text = set_directive(&text, &change.key, &change.desired);
        change.status = LoginDefsChangeStatus::Set;
    }
    std::fs::write(path, &text)?;
    report.applied = true;

    // Re-read through the same parser the rules use. Writing a file is not evidence the value is
    // now what we intended — a botched replace would otherwise be reported as a success.
    for change in &report.changes {
        let now = effective_value(&text, &change.key);
        if now.map(|n| n.to_string()).as_deref() != Some(change.desired.as_str()) {
            report.note = Some(format!(
                "{} did not read back as {} after the edit — check {} by hand",
                change.key,
                change.desired,
                path.display()
            ));
        }
    }

    Ok(report)
}

/// The value shadow (and this project's collector) would end up with: scan every uncommented
/// `KEY value` line, last one wins.
fn effective_value(text: &str, key: &str) -> Option<i64> {
    let mut found = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        if parts.next() != Some(key) {
            continue;
        }
        if let Ok(n) = parts.next().unwrap_or_default().trim().parse::<i64>() {
            found = Some(n);
        }
    }
    found
}

/// Replace every uncommented occurrence of `key` with `key <value>`, preserving position; append
/// the directive if it was absent. Comments are untouched.
fn set_directive(text: &str, key: &str, value: &str) -> String {
    let mut out = String::with_capacity(text.len() + 64);
    let mut replaced = false;
    for line in text.lines() {
        let trimmed = line.trim();
        let is_target = !trimmed.starts_with('#')
            && trimmed
                .split(char::is_whitespace)
                .next()
                .is_some_and(|k| k == key);
        if is_target {
            // Replace in place rather than appending a second line: under shadow's last-wins
            // *and* under a first-wins reading this is the value that takes effect, and the file
            // keeps one line per key however many times the fixer runs.
            if !replaced {
                out.push_str(&format!("{key} {value}\n"));
                replaced = true;
            }
            // Any further duplicates of the same key are dropped — they could only shadow the
            // value we just set.
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    if !replaced {
        if !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&format!("\n# set by bulwark\n{key} {value}\n"));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const STOCK: &str = "# /etc/login.defs\n\
                         PASS_MAX_DAYS\t99999\n\
                         PASS_MIN_DAYS\t0\n\
                         PASS_WARN_AGE\t7\n\
                         UMASK\t022\n";

    fn all_rules() -> Vec<&'static str> {
        managed_rule_ids()
    }

    #[test]
    fn dry_run_writes_nothing() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("login.defs");
        std::fs::write(&cfg, STOCK).unwrap();
        let backups = dir.path().join("backups");

        let r = harden_login_defs(&all_rules(), Some(&cfg), &backups, false).unwrap();
        assert_eq!(r.changes.len(), 2, "fixture must have both keys to fix");
        assert!(r
            .changes
            .iter()
            .all(|c| c.status == LoginDefsChangeStatus::WouldSet));
        assert!(!r.applied);
        assert_eq!(
            std::fs::read_to_string(&cfg).unwrap(),
            STOCK,
            "a dry run must leave the file byte-for-byte unchanged"
        );
        assert!(!backups.exists(), "a dry run must not write a backup");
    }

    #[test]
    fn apply_replaces_in_place_and_is_idempotent() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("login.defs");
        std::fs::write(&cfg, STOCK).unwrap();
        let backups = dir.path().join("backups");

        let r = harden_login_defs(&all_rules(), Some(&cfg), &backups, true).unwrap();
        assert!(r.applied);
        assert!(r.note.is_none(), "the values must read back as intended");
        let text = std::fs::read_to_string(&cfg).unwrap();
        assert_eq!(effective_value(&text, "PASS_MAX_DAYS"), Some(90));
        assert_eq!(effective_value(&text, "PASS_MIN_DAYS"), Some(1));
        // Unrelated directives survive untouched.
        assert_eq!(effective_value(&text, "PASS_WARN_AGE"), Some(7));
        assert!(text.contains("UMASK\t022"));

        // The backup holds the original.
        assert_eq!(
            std::fs::read_to_string(r.backup_path.unwrap()).unwrap(),
            STOCK
        );

        // Second run has nothing to do — the values are now compliant.
        let again = harden_login_defs(&all_rules(), Some(&cfg), &backups, true).unwrap();
        assert!(again.changes.is_empty());
        assert_eq!(text.matches("PASS_MAX_DAYS").count(), 1);
    }

    /// The exact bug CLAUDE.md warns about: appending after an existing uncommented directive is
    /// silently ignored under first-occurrence-wins. Asserting that the file ends up with ONE
    /// occurrence of the key is what proves we replaced rather than appended.
    #[test]
    fn the_directive_is_replaced_not_appended() {
        let out = set_directive(
            "PASS_MAX_DAYS\t99999\nPASS_WARN_AGE 7\n",
            "PASS_MAX_DAYS",
            "90",
        );
        assert_eq!(
            out.matches("PASS_MAX_DAYS").count(),
            1,
            "appending a second PASS_MAX_DAYS would be ignored under first-wins semantics"
        );
        assert!(
            out.starts_with("PASS_MAX_DAYS 90\n"),
            "position is preserved"
        );
        assert!(out.contains("PASS_WARN_AGE 7"));
    }

    /// Duplicated keys must collapse to the one we set — leaving a later duplicate would shadow it
    /// under shadow's actual last-wins loading.
    #[test]
    fn a_later_duplicate_cannot_shadow_the_new_value() {
        let out = set_directive(
            "PASS_MIN_DAYS 0\nPASS_WARN_AGE 7\nPASS_MIN_DAYS 0\n",
            "PASS_MIN_DAYS",
            "1",
        );
        assert_eq!(out.matches("PASS_MIN_DAYS").count(), 1);
        assert_eq!(effective_value(&out, "PASS_MIN_DAYS"), Some(1));
    }

    #[test]
    fn an_absent_key_is_appended_and_comments_are_left_alone() {
        let out = set_directive(
            "# PASS_MIN_DAYS 0 is the default\nUMASK 022\n",
            "PASS_MIN_DAYS",
            "1",
        );
        assert!(
            out.contains("# PASS_MIN_DAYS 0 is the default"),
            "a commented annotation must not be rewritten"
        );
        assert_eq!(effective_value(&out, "PASS_MIN_DAYS"), Some(1));
    }

    /// A host already inside policy must not be edited at all — the fixer fires exactly where the
    /// rule's condition does (`> 365` and `== 0`), not wherever a value merely differs from ours.
    #[test]
    fn a_compliant_file_is_left_alone() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("login.defs");
        let compliant = "PASS_MAX_DAYS 180\nPASS_MIN_DAYS 7\n";
        std::fs::write(&cfg, compliant).unwrap();
        let r = harden_login_defs(&all_rules(), Some(&cfg), &dir.path().join("b"), true).unwrap();
        assert!(r.changes.is_empty());
        assert_eq!(std::fs::read_to_string(&cfg).unwrap(), compliant);
        // 180 is not our 90, but it is inside the rule's threshold — changing it would be us
        // imposing a policy the scan never objected to.
    }

    /// Selecting one rule must not drag the other's directive along — the per-issue Fix button
    /// promises to fix that issue, not everything nearby.
    #[test]
    fn selecting_one_rule_touches_only_its_own_key() {
        let dir = tempfile::tempdir().unwrap();
        let cfg = dir.path().join("login.defs");
        std::fs::write(&cfg, STOCK).unwrap();
        let r =
            harden_login_defs(&["BLWK-ACCT-003"], Some(&cfg), &dir.path().join("b"), true).unwrap();
        assert_eq!(r.changes.len(), 1);
        assert_eq!(r.changes[0].key, "PASS_MIN_DAYS");
        let text = std::fs::read_to_string(&cfg).unwrap();
        assert_eq!(effective_value(&text, "PASS_MIN_DAYS"), Some(1));
        assert_eq!(
            effective_value(&text, "PASS_MAX_DAYS"),
            Some(99999),
            "the other rule's directive must be untouched"
        );
    }

    #[test]
    fn effective_value_is_last_wins_matching_the_collector() {
        assert_eq!(
            effective_value("PASS_MAX_DAYS 99999\nPASS_MAX_DAYS 30\n", "PASS_MAX_DAYS"),
            Some(30)
        );
        assert_eq!(
            effective_value("# PASS_MAX_DAYS 30\n", "PASS_MAX_DAYS"),
            None
        );
    }
}
