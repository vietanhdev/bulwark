//! Persist kernel network hardening knobs — the fix for the `sysctl_kernel` rules.
//!
//! **This writes `/etc/sysctl.d/`, not `/proc/sys`, and the distinction is the whole point.**
//! `sysctl -w net.ipv4.conf.all.send_redirects=0` changes the running kernel and is gone at the
//! next reboot. A user who clicks "Fix" and sees the finding disappear would get a green scan
//! today and a silently-regressed host tomorrow — worse than not offering the fix, because it
//! teaches them the issue is handled. So the durable file is written first, and the running
//! kernel is only updated afterwards to make the change take effect now as well.
//!
//! **Per-interface keys must be written per interface.** `send_redirects` and `log_martians` are
//! not single values: the kernel folds `conf/all`, `conf/default` and each real interface's own
//! value together (`OR` for both of these — see the `sysctl` collector's `PER_IFACE` table), and
//! the collector reports that folded value. Writing only `conf.all.send_redirects=0` therefore
//! fixes nothing on a host where `eth0` has it set to 1: `OR(0, 1)` is still 1, the scan still
//! fires, and the fix looks broken. Every existing interface gets its own line, plus `all` and
//! `default` so interfaces that appear later inherit the safe value.
//!
//! Safety rails match `sshd.rs`: dry-run by default, the prior file backed up before any rewrite,
//! an idempotent sentinel-delimited block rather than blind appending, and a post-write read-back
//! of `/proc/sys` to confirm the kernel actually took the value rather than assuming it did.

use serde::{Deserialize, Serialize};
use std::path::Path;

/// Where the persistent drop-in lives. `99-` so it sorts last and wins over distro defaults —
/// `sysctl --system` applies files in lexical order and the last assignment of a key takes effect.
const CONF_FILE: &str = "/etc/sysctl.d/99-bulwark-hardening.conf";
const BEGIN_MARKER: &str = "# BEGIN bulwark-hardening";
const END_MARKER: &str = "# END bulwark-hardening";

/// One kernel knob this module manages, tied to the rule it clears.
struct Knob {
    rule_id: &'static str,
    /// The leaf name under `net/ipv4/conf/<scope>/`, e.g. `send_redirects`.
    field: &'static str,
    desired: i64,
    /// True when the *insecure* state is a high value (so the rule fires on `== 1`); false when
    /// the insecure state is a low one (rule fires on `== 0`). Mirrors the collector's `Risk`.
    insecure_when_high: bool,
    why: &'static str,
}

const KNOBS: &[Knob] = &[
    Knob {
        rule_id: "BLWK-KERNEL-016",
        field: "send_redirects",
        desired: 0,
        insecure_when_high: true,
        why: "a non-router host has no reason to send ICMP redirects (BLWK-KERNEL-016)",
    },
    Knob {
        rule_id: "BLWK-KERNEL-017",
        field: "log_martians",
        desired: 1,
        insecure_when_high: false,
        why: "spoofed/impossible source addresses should be logged, not silently dropped (BLWK-KERNEL-017)",
    },
];

/// The rule ids this fixer can clear.
#[cfg(test)]
pub(crate) fn managed_rule_ids() -> Vec<&'static str> {
    KNOBS.iter().map(|k| k.rule_id).collect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SysctlChangeStatus {
    /// Would be written (dry run).
    WouldSet,
    /// Written to the drop-in file and accepted by the running kernel.
    Set,
    /// Written to the drop-in, but the running kernel did not report the new value back.
    /// Surfaced rather than swallowed — the persistent fix is in place but the live one isn't.
    SetButNotLive,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysctlChange {
    /// Full dotted sysctl key, e.g. `net.ipv4.conf.eth0.send_redirects`.
    pub key: String,
    pub current: String,
    pub desired: String,
    pub why: String,
    pub status: SysctlChangeStatus,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SysctlHardeningReport {
    pub conf_path: String,
    pub changes: Vec<SysctlChange>,
    pub applied: bool,
    pub backup_path: Option<String>,
    /// `Some(true)` when every written key read back at its desired value from `/proc/sys`.
    pub verified: Option<bool>,
    pub note: Option<String>,
}

impl SysctlHardeningReport {
    pub fn pending_count(&self) -> usize {
        self.changes.len()
    }
}

/// Public entry point. `rules` selects which knobs to consider (so a per-issue fix touches only
/// its own rule's key); pass every managed id for the bulk path. Dry run unless `apply`.
pub fn harden_sysctl(
    rules: &[&str],
    backup_dir: &Path,
    apply: bool,
) -> anyhow::Result<SysctlHardeningReport> {
    harden_with(
        rules,
        Path::new("/proc/sys"),
        Path::new(CONF_FILE),
        backup_dir,
        apply,
        true,
    )
}

/// Testable core. `proc_root` and `conf_path` are injected so a unit test can drive the whole
/// thing against a temp directory, and `live` disables the `sysctl --system` call and the
/// read-back (a test must not, and cannot, change the machine's real kernel settings).
fn harden_with(
    rules: &[&str],
    proc_root: &Path,
    conf_path: &Path,
    backup_dir: &Path,
    apply: bool,
    live: bool,
) -> anyhow::Result<SysctlHardeningReport> {
    let mut report = SysctlHardeningReport {
        conf_path: conf_path.display().to_string(),
        ..Default::default()
    };

    let interfaces = real_interfaces(proc_root);
    for knob in KNOBS.iter().filter(|k| rules.contains(&k.rule_id)) {
        // `all` and `default` are always written: `default` is what a later-created interface
        // inherits, so omitting it fixes today's interfaces and none of tomorrow's.
        let mut scopes: Vec<String> = vec!["all".into(), "default".into()];
        scopes.extend(interfaces.iter().cloned());

        for scope in scopes {
            let path = proc_root.join(format!("net/ipv4/conf/{scope}/{}", knob.field));
            let current = read_i64(&path);
            // A scope already at (or safer than) the desired value is left out of the report
            // entirely — the preview should list changes, not every knob that was already fine.
            if let Some(c) = current {
                let already_ok = if knob.insecure_when_high {
                    c <= knob.desired
                } else {
                    c >= knob.desired
                };
                if already_ok {
                    continue;
                }
            } else {
                // Unreadable knob: skip rather than guess. Never write a key we can't observe.
                continue;
            }
            report.changes.push(SysctlChange {
                key: format!("net.ipv4.conf.{scope}.{}", knob.field),
                current: current.map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                desired: knob.desired.to_string(),
                why: knob.why.to_string(),
                status: SysctlChangeStatus::WouldSet,
            });
        }
    }

    if !apply || report.changes.is_empty() {
        return Ok(report);
    }

    // Back up an existing drop-in before rewriting it. A chmod is reversible from the report
    // alone; a file rewrite is not, so this one keeps a copy.
    if conf_path.exists() {
        std::fs::create_dir_all(backup_dir)?;
        let stamp = chrono::Utc::now().format("%Y%m%dT%H%M%SZ");
        let backup = backup_dir.join(format!("99-bulwark-hardening.conf.{stamp}.bak"));
        std::fs::copy(conf_path, &backup)?;
        report.backup_path = Some(backup.display().to_string());
    }

    let existing = std::fs::read_to_string(conf_path).unwrap_or_default();
    let body = render_block(&report.changes);
    let next = format!("{}{body}", strip_managed_block(&existing));
    if let Some(parent) = conf_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(conf_path, next)?;
    report.applied = true;

    if !live {
        report.note = Some("running kernel not reloaded (test mode)".into());
        return Ok(report);
    }

    // Persisted; now make it effective immediately too. A failure here is a note, not an error:
    // the durable fix is already written and will apply at boot regardless.
    let reload = std::process::Command::new("sysctl")
        .arg("--system")
        .output();
    match reload {
        Ok(o) if !o.status.success() => {
            report.note = Some(format!(
                "the settings were saved to {} but `sysctl --system` failed: {}",
                conf_path.display(),
                String::from_utf8_lossy(&o.stderr).trim()
            ));
        }
        Err(e) => {
            report.note = Some(format!(
                "the settings were saved to {} but `sysctl` could not be run ({e}); they will \
                 take effect at the next boot",
                conf_path.display()
            ));
        }
        _ => {}
    }

    // Read back from /proc/sys rather than trusting the write. This is the only evidence the
    // kernel actually accepted the value.
    let mut all_live = true;
    for change in &mut report.changes {
        let leaf = change
            .key
            .trim_start_matches("net.ipv4.conf.")
            .replace('.', "/");
        let live_value = read_i64(&proc_root.join(format!("net/ipv4/conf/{leaf}")));
        if live_value.map(|v| v.to_string()) == Some(change.desired.clone()) {
            change.status = SysctlChangeStatus::Set;
        } else {
            change.status = SysctlChangeStatus::SetButNotLive;
            all_live = false;
        }
    }
    report.verified = Some(all_live);
    Ok(report)
}

fn render_block(changes: &[SysctlChange]) -> String {
    let mut out = String::new();
    out.push_str(BEGIN_MARKER);
    out.push_str(" (managed) — remove this block to revert\n");
    for c in changes {
        out.push_str(&format!("# {}\n{} = {}\n", c.why, c.key, c.desired));
    }
    out.push_str(END_MARKER);
    out.push('\n');
    out
}

/// Remove any previously-written bulwark block, so re-running rebuilds rather than stacking.
fn strip_managed_block(text: &str) -> String {
    let mut out = String::new();
    let mut in_block = false;
    for line in text.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with(BEGIN_MARKER) {
            in_block = true;
            continue;
        }
        if in_block {
            if trimmed.starts_with(END_MARKER) {
                in_block = false;
            }
            continue;
        }
        out.push_str(line);
        out.push('\n');
    }
    out
}

fn read_i64(path: &Path) -> Option<i64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Real interfaces under `net/ipv4/conf`, excluding the `all`/`default` pseudo-entries — the same
/// exclusion the collector makes, so the fixer writes exactly the scopes the scan folds over.
fn real_interfaces(proc_root: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(proc_root.join("net/ipv4/conf"))
        .map(|entries| {
            entries
                .flatten()
                .filter_map(|e| e.file_name().into_string().ok())
                .filter(|n| n != "all" && n != "default")
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a fake `/proc/sys` tree with `all`, `default` and two interfaces.
    fn fake_proc(dir: &Path, field: &str, values: &[(&str, i64)]) {
        for (scope, v) in values {
            let d = dir.join(format!("net/ipv4/conf/{scope}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join(field), format!("{v}\n")).unwrap();
        }
    }

    #[test]
    fn dry_run_writes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fake_proc(
            &proc_root,
            "send_redirects",
            &[("all", 1), ("default", 1), ("eth0", 1)],
        );
        let conf = tmp.path().join("etc/sysctl.d/99-bulwark-hardening.conf");
        let backups = tmp.path().join("backups");

        let r = harden_with(
            &["BLWK-KERNEL-016"],
            &proc_root,
            &conf,
            &backups,
            false,
            false,
        )
        .unwrap();

        assert!(
            !r.changes.is_empty(),
            "fixture must have something to fix or this test proves nothing"
        );
        assert!(r
            .changes
            .iter()
            .all(|c| c.status == SysctlChangeStatus::WouldSet));
        assert!(!r.applied);
        assert!(!conf.exists(), "a dry run must not create the drop-in file");
        assert!(
            !backups.exists(),
            "a dry run must not write a backup either"
        );
    }

    /// The bug this fixer exists to avoid: writing only `conf.all` leaves an OR-folded key at 1
    /// on an interface that has it set, so the finding would survive its own fix.
    #[test]
    fn every_interface_gets_its_own_key_not_just_all() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fake_proc(
            &proc_root,
            "send_redirects",
            &[("all", 1), ("default", 1), ("eth0", 1), ("wlan0", 1)],
        );
        let r = harden_with(
            &["BLWK-KERNEL-016"],
            &proc_root,
            &tmp.path().join("conf"),
            &tmp.path().join("b"),
            false,
            false,
        )
        .unwrap();
        let keys: Vec<&str> = r.changes.iter().map(|c| c.key.as_str()).collect();
        assert!(keys.contains(&"net.ipv4.conf.all.send_redirects"));
        assert!(keys.contains(&"net.ipv4.conf.default.send_redirects"));
        assert!(keys.contains(&"net.ipv4.conf.eth0.send_redirects"));
        assert!(keys.contains(&"net.ipv4.conf.wlan0.send_redirects"));
    }

    #[test]
    fn a_scope_already_safe_is_not_reported_as_a_change() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        // eth0 already 0; all/default still 1.
        fake_proc(
            &proc_root,
            "send_redirects",
            &[("all", 1), ("default", 1), ("eth0", 0)],
        );
        let r = harden_with(
            &["BLWK-KERNEL-016"],
            &proc_root,
            &tmp.path().join("conf"),
            &tmp.path().join("b"),
            false,
            false,
        )
        .unwrap();
        let keys: Vec<&str> = r.changes.iter().map(|c| c.key.as_str()).collect();
        assert!(!keys.contains(&"net.ipv4.conf.eth0.send_redirects"));
        assert_eq!(keys.len(), 2);
    }

    /// `log_martians` is insecure when *low* — the opposite direction to `send_redirects`. A
    /// fixer that only understood "high is bad" would report nothing here.
    #[test]
    fn log_martians_is_fixed_in_the_low_direction() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fake_proc(&proc_root, "log_martians", &[("all", 0), ("default", 0)]);
        let r = harden_with(
            &["BLWK-KERNEL-017"],
            &proc_root,
            &tmp.path().join("conf"),
            &tmp.path().join("b"),
            false,
            false,
        )
        .unwrap();
        assert_eq!(r.changes.len(), 2);
        assert!(r.changes.iter().all(|c| c.desired == "1"));
    }

    #[test]
    fn apply_writes_a_persistent_drop_in_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fake_proc(&proc_root, "send_redirects", &[("all", 1), ("default", 1)]);
        let conf = tmp.path().join("etc/sysctl.d/99-bulwark-hardening.conf");
        let backups = tmp.path().join("backups");

        let r = harden_with(
            &["BLWK-KERNEL-016"],
            &proc_root,
            &conf,
            &backups,
            true,
            false,
        )
        .unwrap();
        assert!(r.applied);
        let text = std::fs::read_to_string(&conf).unwrap();
        // The fix is durable: it lives in a file sysctl reads at boot, not only in /proc/sys.
        assert!(text.contains("net.ipv4.conf.all.send_redirects = 0"));
        assert_eq!(text.matches(BEGIN_MARKER).count(), 1);

        // Second run rebuilds the block rather than stacking a duplicate.
        let _ = harden_with(
            &["BLWK-KERNEL-016"],
            &proc_root,
            &conf,
            &backups,
            true,
            false,
        )
        .unwrap();
        let text2 = std::fs::read_to_string(&conf).unwrap();
        assert_eq!(text2.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(text2.matches("net.ipv4.conf.all.send_redirects").count(), 1);
    }

    #[test]
    fn an_existing_drop_in_is_backed_up_before_being_rewritten() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fake_proc(&proc_root, "send_redirects", &[("all", 1)]);
        let conf = tmp.path().join("etc/sysctl.d/99-bulwark-hardening.conf");
        std::fs::create_dir_all(conf.parent().unwrap()).unwrap();
        std::fs::write(&conf, "# hand written\nvm.swappiness = 10\n").unwrap();
        let backups = tmp.path().join("backups");

        let r = harden_with(
            &["BLWK-KERNEL-016"],
            &proc_root,
            &conf,
            &backups,
            true,
            false,
        )
        .unwrap();
        let backup = r.backup_path.expect("an existing file must be backed up");
        assert_eq!(
            std::fs::read_to_string(backup).unwrap(),
            "# hand written\nvm.swappiness = 10\n"
        );
        // …and the unrelated hand-written setting survives the rewrite.
        assert!(std::fs::read_to_string(&conf)
            .unwrap()
            .contains("vm.swappiness = 10"));
    }
}
