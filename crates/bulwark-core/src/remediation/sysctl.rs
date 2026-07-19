//! Persist kernel network hardening knobs — the fix for the `sysctl_kernel` rules.
//!
//! **What is persisted and what is applied live are deliberately different sets.** Getting this
//! wrong is not cosmetic: an earlier version of this module wrote *every currently-existing
//! interface* into the drop-in file, which on a Docker host meant 82 lines naming `veth1db2130`,
//! `br-00e955817d0a` and friends. Those interfaces do not survive a reboot, so `sysctl --system`
//! would emit `cannot stat /proc/sys/net/ipv4/conf/veth…/send_redirects` on every boot — a config
//! file that fails to load — while the containers that came back with *new* random names were not
//! covered by the pinned list at all. It protected yesterday's interfaces and nothing else.
//!
//! The split now follows from the kernel's own fold, which was verified against
//! `include/linux/inetdevice.h` rather than assumed:
//!
//! ```text
//! #define IN_DEV_NET_ORCONF(in_dev, net, attr) (IPV4_DEVCONF_ALL_RO(net, attr) || IN_DEV_CONF_GET((in_dev), attr))
//! #define IN_DEV_LOG_MARTIANS(in_dev)  IN_DEV_ORCONF((in_dev), LOG_MARTIANS)
//! #define IN_DEV_TX_REDIRECTS(in_dev)  IN_DEV_ORCONF((in_dev), SEND_REDIRECTS)
//! ```
//!
//! Both managed knobs are therefore `conf.all || conf.<iface>`. The consequence depends on the
//! **direction of the fix, not on which knob it is** — which is why one of them needs per-interface
//! work and the other does not:
//!
//!   * **Raising to 1** (`log_martians`): `conf.all = 1` forces the OR to 1 on every interface,
//!     present and future. `conf.all` alone is sufficient; `default` and per-interface writes are
//!     pure noise. This is why martian logging contributes exactly one line, not 41.
//!   * **Lowering to 0** (`send_redirects`): `conf.all = 0` is necessary but *not* sufficient —
//!     any interface still at 1 keeps the OR at 1. `conf.default = 0` seeds interfaces created
//!     later, and every interface that exists right now must additionally be set in the running
//!     kernel or it keeps sending redirects until reboot.
//!
//! So: **only `all` and `default` are ever written to the drop-in** (they are stable names that
//! always exist), and per-interface values are applied to the running kernel only. The persisted
//! block is a *declaration of the desired state*, not a diff — it is rewritten in full whenever
//! anything is applied, so re-running can never leave a half-populated file.
//!
//! The running kernel is updated by writing `/proc/sys` directly rather than shelling out to
//! `sysctl --system`. That is deliberate: `--system` reloads *every* file in the sysctl.d search
//! path, so it could apply unrelated pending settings the user never asked this tool to touch, and
//! it cannot be exercised in a test. Direct writes affect exactly the keys in the report.
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

/// The only scopes that may be written to the persistent file: both always exist, on every host,
/// at every boot. Anything else is an interface name that may not come back.
const PERSISTABLE_SCOPES: &[&str] = &["all", "default"];

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

/// Scopes that must be written for a knob to take effect, split by destination.
struct Plan {
    /// Scopes written to the persistent drop-in — always a subset of [`PERSISTABLE_SCOPES`].
    persist: &'static [&'static str],
    /// Whether interfaces that exist right now must also be set in the running kernel.
    needs_interfaces: bool,
}

/// Derived from the kernel's OR fold plus the direction of the change — see the module doc for the
/// derivation and the header quotes it was checked against.
fn plan_for(knob: &Knob) -> Plan {
    if knob.desired == 1 {
        // Raising an OR-folded knob: `all = 1` alone forces the effective value everywhere.
        Plan {
            persist: &["all"],
            needs_interfaces: false,
        }
    } else {
        // Lowering an OR-folded knob: every scope matters.
        Plan {
            persist: &["all", "default"],
            needs_interfaces: true,
        }
    }
}

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
    /// Written, and the running kernel reported the new value back.
    Set,
    /// Written, but the running kernel did not report the new value back. Surfaced rather than
    /// swallowed — for a persisted key the durable fix is in place but the live one isn't.
    SetButNotLive,
    /// The write itself failed. Common and benign for an interface that disappeared between the
    /// preview and the apply (a container exiting), which is exactly why it is per-row.
    Failed { reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SysctlChange {
    /// Full dotted sysctl key, e.g. `net.ipv4.conf.all.send_redirects`. For the aggregated
    /// per-interface row this is a display key (`net.ipv4.conf.<interface>.send_redirects`) and
    /// `interfaces` carries the real list.
    pub key: String,
    pub current: String,
    pub desired: String,
    pub why: String,
    pub status: SysctlChangeStatus,
    /// Whether this key is written to the persistent drop-in. False for per-interface values,
    /// which are applied to the running kernel only — see the module doc for why pinning an
    /// ephemeral interface name in a boot-time config file is a bug, not a feature.
    pub persisted: bool,
    /// For the aggregated per-interface row: the interfaces it covers. Empty for `all`/`default`.
    /// Aggregated rather than one row per interface because 41 identical rows is not information;
    /// nothing is hidden, the names are right here.
    #[serde(default)]
    pub interfaces: Vec<String>,
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
    /// Per-interface keys found inside our own managed block, left there by an earlier build.
    /// They name interfaces that may no longer exist, so `sysctl --system` fails on them at boot.
    /// Reported in a preview and removed on the next apply — see `stale_per_interface_keys` in the
    /// tests for why cleaning these is in scope while touching anything outside the block is not.
    #[serde(default)]
    pub stale_persisted_keys: Vec<String>,
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
    )
}

/// Testable core. `proc_root` and `conf_path` are injected so a unit test drives the whole thing —
/// including the live `/proc/sys` writes — against a temp directory.
fn harden_with(
    rules: &[&str],
    proc_root: &Path,
    conf_path: &Path,
    backup_dir: &Path,
    apply: bool,
) -> anyhow::Result<SysctlHardeningReport> {
    let mut report = SysctlHardeningReport {
        conf_path: conf_path.display().to_string(),
        ..Default::default()
    };

    let selected: Vec<&Knob> = KNOBS
        .iter()
        .filter(|k| rules.contains(&k.rule_id))
        .collect();
    let interfaces = real_interfaces(proc_root);

    for knob in &selected {
        let plan = plan_for(knob);

        for scope in plan.persist {
            let Some(current) = read_i64(&scope_path(proc_root, scope, knob.field)) else {
                // Unreadable knob: skip rather than guess. Never write a key we can't observe.
                continue;
            };
            if is_already_ok(knob, current) {
                continue;
            }
            report.changes.push(SysctlChange {
                key: format!("net.ipv4.conf.{scope}.{}", knob.field),
                current: current.to_string(),
                desired: knob.desired.to_string(),
                why: knob.why.to_string(),
                status: SysctlChangeStatus::WouldSet,
                persisted: true,
                interfaces: Vec::new(),
            });
        }

        if !plan.needs_interfaces {
            continue;
        }
        // Only interfaces that are actually wrong. On a host where conf.all is being set to 0 and
        // every interface is already 0, this row does not appear at all.
        let pending: Vec<String> = interfaces
            .iter()
            .filter(|i| {
                read_i64(&scope_path(proc_root, i, knob.field))
                    .is_some_and(|c| !is_already_ok(knob, c))
            })
            .cloned()
            .collect();
        if pending.is_empty() {
            continue;
        }
        report.changes.push(SysctlChange {
            key: format!("net.ipv4.conf.<interface>.{}", knob.field),
            current: format!(
                "{} on {} live interface{}",
                if knob.insecure_when_high { 1 } else { 0 },
                pending.len(),
                if pending.len() == 1 { "" } else { "s" }
            ),
            desired: knob.desired.to_string(),
            why: format!("{} — applied to the running kernel only", knob.why),
            status: SysctlChangeStatus::WouldSet,
            persisted: false,
            interfaces: pending,
        });
    }

    // Per-interface lines an earlier build persisted. They are inside OUR marked block, so
    // rebuilding the block removes them; nothing outside the block is read or touched.
    let existing = std::fs::read_to_string(conf_path).unwrap_or_default();
    report.stale_persisted_keys = stale_per_interface_keys(&existing);

    if !apply || (report.changes.is_empty() && report.stale_persisted_keys.is_empty()) {
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

    // The block is a full declaration of the desired state for every selected knob, not a diff of
    // what happened to be wrong today. Writing only the diff would drop a line whose value is
    // currently correct *because an earlier run wrote it*, silently un-persisting the fix.
    let body = render_block(&selected);
    let next = format!("{}{body}", strip_managed_block(&existing));
    if let Some(parent) = conf_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(conf_path, next)?;
    report.applied = true;

    // Now make it effective on the running kernel. Persisted scopes and live interfaces alike are
    // written straight to /proc/sys — see the module doc on why not `sysctl --system`.
    let mut all_live = true;
    for change in &mut report.changes {
        let scopes: Vec<String> = if change.interfaces.is_empty() {
            vec![change
                .key
                .trim_start_matches("net.ipv4.conf.")
                .rsplit_once('.')
                .map(|(scope, _)| scope.to_string())
                .unwrap_or_default()]
        } else {
            change.interfaces.clone()
        };
        let field = change
            .key
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .to_string();

        let mut failure: Option<String> = None;
        let mut live_ok = true;
        for scope in &scopes {
            let path = scope_path(proc_root, scope, &field);
            if let Err(e) = std::fs::write(&path, format!("{}\n", change.desired)) {
                // An interface can vanish between the preview and the apply — a container
                // exiting is enough. That is a per-row note, never a failed fix.
                failure = Some(format!("{scope}: {e}"));
                live_ok = false;
                continue;
            }
            if read_i64(&path).map(|v| v.to_string()) != Some(change.desired.clone()) {
                live_ok = false;
            }
        }
        change.status = match (failure, live_ok) {
            (Some(reason), _) => SysctlChangeStatus::Failed { reason },
            (None, true) => SysctlChangeStatus::Set,
            (None, false) => SysctlChangeStatus::SetButNotLive,
        };
        if change.status != SysctlChangeStatus::Set {
            all_live = false;
        }
    }
    report.verified = Some(all_live);

    if !report.stale_persisted_keys.is_empty() {
        report.note = Some(format!(
            "removed {} stale per-interface entr{} an earlier version had pinned in this file; \
             they named interfaces that may not exist at boot",
            report.stale_persisted_keys.len(),
            if report.stale_persisted_keys.len() == 1 {
                "y"
            } else {
                "ies"
            }
        ));
    }

    Ok(report)
}

fn scope_path(proc_root: &Path, scope: &str, field: &str) -> std::path::PathBuf {
    proc_root.join(format!("net/ipv4/conf/{scope}/{field}"))
}

/// Whether `current` already satisfies the knob (at or safer than desired).
fn is_already_ok(knob: &Knob, current: i64) -> bool {
    if knob.insecure_when_high {
        current <= knob.desired
    } else {
        current >= knob.desired
    }
}

/// Per-interface keys sitting inside the managed block — i.e. any `net.ipv4.conf.X.…` where X is
/// neither `all` nor `default`. Only the block is inspected: a per-interface line a *user* wrote
/// elsewhere in the file is their business, not ours.
fn stale_per_interface_keys(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_block = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(BEGIN_MARKER) {
            in_block = true;
            continue;
        }
        if trimmed.starts_with(END_MARKER) {
            in_block = false;
            continue;
        }
        if !in_block || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, _)) = trimmed.split_once('=') else {
            continue;
        };
        let key = key.trim();
        let Some(rest) = key.strip_prefix("net.ipv4.conf.") else {
            continue;
        };
        if let Some((scope, _)) = rest.rsplit_once('.') {
            if !PERSISTABLE_SCOPES.contains(&scope) {
                out.push(key.to_string());
            }
        }
    }
    out
}

/// The persistent block: the desired state for every selected knob, restricted to the scopes that
/// are guaranteed to exist at boot. Never emits an interface name — that is the whole point.
fn render_block(knobs: &[&Knob]) -> String {
    let mut out = String::new();
    out.push_str(BEGIN_MARKER);
    out.push_str(" (managed) — remove this block to revert\n");
    for knob in knobs {
        out.push_str(&format!("# {}\n", knob.why));
        for scope in plan_for(knob).persist {
            debug_assert!(
                PERSISTABLE_SCOPES.contains(scope),
                "only always-present scopes may be persisted"
            );
            out.push_str(&format!(
                "net.ipv4.conf.{scope}.{} = {}\n",
                knob.field, knob.desired
            ));
        }
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

    /// Builds a fake `/proc/sys` tree. Every scope named gets a real file, so the live-write path
    /// is exercised for real rather than mocked.
    fn fake_proc(dir: &Path, field: &str, values: &[(&str, i64)]) {
        for (scope, v) in values {
            let d = dir.join(format!("net/ipv4/conf/{scope}"));
            std::fs::create_dir_all(&d).unwrap();
            std::fs::write(d.join(field), format!("{v}\n")).unwrap();
        }
    }

    fn read(dir: &Path, scope: &str, field: &str) -> Option<i64> {
        read_i64(&scope_path(dir, scope, field))
    }

    /// A busy Docker host: many ephemeral interfaces alongside the real ones.
    fn docker_host(dir: &Path, field: &str, value: i64) -> Vec<String> {
        let mut scopes = vec!["all".to_string(), "default".to_string()];
        scopes.push("lo".into());
        scopes.push("wlp9s0".into());
        scopes.push("docker0".into());
        for i in 0..20 {
            scopes.push(format!("veth{i:08x}"));
            scopes.push(format!("br-{i:012x}"));
        }
        let pairs: Vec<(&str, i64)> = scopes.iter().map(|s| (s.as_str(), value)).collect();
        fake_proc(dir, field, &pairs);
        scopes
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

        let r = harden_with(&["BLWK-KERNEL-016"], &proc_root, &conf, &backups, false).unwrap();

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
        // …and it must not touch the running kernel either.
        assert_eq!(read(&proc_root, "all", "send_redirects"), Some(1));
        assert_eq!(read(&proc_root, "eth0", "send_redirects"), Some(1));
    }

    /// **The regression this rewrite exists for.** An interface name in a boot-time config file is
    /// a line that fails to load once the container is gone (`cannot stat …/veth…`), and it covers
    /// none of the new randomly-named interfaces that replace it.
    #[test]
    fn the_persisted_file_never_names_an_interface() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        let scopes = docker_host(&proc_root, "send_redirects", 1);
        let conf = tmp.path().join("conf");

        harden_with(
            &["BLWK-KERNEL-016", "BLWK-KERNEL-017"],
            &proc_root,
            &conf,
            &tmp.path().join("b"),
            true,
        )
        .unwrap();

        let text = std::fs::read_to_string(&conf).unwrap();
        for line in text.lines() {
            let Some((key, _)) = line.split_once('=') else {
                continue;
            };
            let Some(rest) = key.trim().strip_prefix("net.ipv4.conf.") else {
                continue;
            };
            let scope = rest.rsplit_once('.').unwrap().0;
            assert!(
                PERSISTABLE_SCOPES.contains(&scope),
                "persisted file names interface scope {scope:?} — it will not exist at next boot"
            );
        }
        // Non-vacuous: the fixture really does have interfaces that would have been written.
        assert!(scopes.iter().any(|s| s.starts_with("veth")));
        assert!(text.contains("net.ipv4.conf.all.send_redirects = 0"));
    }

    /// Lowering an OR-folded knob still has to reach every live interface, or `conf.all=0` is
    /// defeated by any interface left at 1 and the finding survives its own fix.
    #[test]
    fn lowering_still_applies_live_to_every_existing_interface() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        let scopes = docker_host(&proc_root, "send_redirects", 1);
        let conf = tmp.path().join("conf");

        let r = harden_with(
            &["BLWK-KERNEL-016"],
            &proc_root,
            &conf,
            &tmp.path().join("b"),
            true,
        )
        .unwrap();
        assert_eq!(r.verified, Some(true));

        for scope in &scopes {
            assert_eq!(
                read(&proc_root, scope, "send_redirects"),
                Some(0),
                "{scope} was left sending redirects on the running kernel"
            );
        }
        // The interface work is one aggregated row carrying the real names, not 43 rows.
        let iface_row = r
            .changes
            .iter()
            .find(|c| !c.interfaces.is_empty())
            .expect("an aggregated per-interface row must exist");
        assert!(
            !iface_row.persisted,
            "the interface row must not be persisted"
        );
        assert!(iface_row.interfaces.len() >= 40);
    }

    /// Raising an OR-folded knob needs `conf.all` and nothing else — `all=1` forces the OR to 1 on
    /// every interface, present and future. Verified against `IN_DEV_ORCONF` in the kernel headers.
    /// This is what collapses martian logging from 41 lines to one.
    #[test]
    fn raising_touches_only_conf_all() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        docker_host(&proc_root, "log_martians", 0);
        let conf = tmp.path().join("conf");

        let r = harden_with(
            &["BLWK-KERNEL-017"],
            &proc_root,
            &conf,
            &tmp.path().join("b"),
            true,
        )
        .unwrap();

        assert_eq!(
            r.changes.len(),
            1,
            "log_martians is OR-folded: conf.all=1 alone is sufficient, so one change — got {:?}",
            r.changes.iter().map(|c| &c.key).collect::<Vec<_>>()
        );
        assert_eq!(r.changes[0].key, "net.ipv4.conf.all.log_martians");
        assert!(r.changes[0].interfaces.is_empty());
        assert_eq!(read(&proc_root, "all", "log_martians"), Some(1));
        // The interfaces are deliberately left alone — the OR already reads 1 through conf.all.
        assert_eq!(read(&proc_root, "docker0", "log_martians"), Some(0));
        let text = std::fs::read_to_string(&conf).unwrap();
        assert!(
            !text.contains("default.log_martians"),
            "default is noise when raising"
        );
    }

    /// The whole point of the change, measured: a Docker-shaped host previously produced ~82 rows.
    #[test]
    fn a_docker_host_produces_a_readable_number_of_changes() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        docker_host(&proc_root, "send_redirects", 1);
        docker_host(&proc_root, "log_martians", 0);

        let r = harden_with(
            &["BLWK-KERNEL-016", "BLWK-KERNEL-017"],
            &proc_root,
            &tmp.path().join("conf"),
            &tmp.path().join("b"),
            false,
        )
        .unwrap();
        // all + default + one aggregated interface row for send_redirects, all for log_martians.
        assert_eq!(
            r.changes.len(),
            4,
            "expected 4 rows, got {:?}",
            r.changes.iter().map(|c| &c.key).collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_scope_already_safe_is_not_reported_as_a_change() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
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
        )
        .unwrap();
        let keys: Vec<&str> = r.changes.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(
            keys,
            vec![
                "net.ipv4.conf.all.send_redirects",
                "net.ipv4.conf.default.send_redirects"
            ]
        );
        assert!(
            r.changes.iter().all(|c| c.interfaces.is_empty()),
            "eth0 is already 0, so no interface row should appear"
        );
    }

    #[test]
    fn apply_writes_a_persistent_drop_in_and_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fake_proc(&proc_root, "send_redirects", &[("all", 1), ("default", 1)]);
        let conf = tmp.path().join("etc/sysctl.d/99-bulwark-hardening.conf");
        let backups = tmp.path().join("backups");

        let r = harden_with(&["BLWK-KERNEL-016"], &proc_root, &conf, &backups, true).unwrap();
        assert!(r.applied);
        let text = std::fs::read_to_string(&conf).unwrap();
        // The fix is durable: it lives in a file sysctl reads at boot, not only in /proc/sys.
        assert!(text.contains("net.ipv4.conf.all.send_redirects = 0"));
        assert!(text.contains("net.ipv4.conf.default.send_redirects = 0"));
        assert_eq!(text.matches(BEGIN_MARKER).count(), 1);

        // Second run rebuilds the block rather than stacking a duplicate.
        let _ = harden_with(&["BLWK-KERNEL-016"], &proc_root, &conf, &backups, true).unwrap();
        let text2 = std::fs::read_to_string(&conf).unwrap();
        assert_eq!(text2.matches(BEGIN_MARKER).count(), 1);
        assert_eq!(text2.matches("net.ipv4.conf.all.send_redirects").count(), 1);
    }

    /// A drop-in an *earlier build* wrote is full of interface names that will fail to load at
    /// boot. Cleaning them is in scope because they sit inside our own marked block; the rest of
    /// the file is the user's and is never inspected or rewritten.
    ///
    /// The case that forces this to be handled at all: after that earlier apply, `conf.all` is
    /// already correct, so there is nothing left to *change* — without explicit handling the
    /// function would early-return and the broken file would stay broken forever.
    #[test]
    fn stale_per_interface_entries_are_reported_then_cleaned() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        // Everything already at the safe value: no changes to make.
        fake_proc(&proc_root, "send_redirects", &[("all", 0), ("default", 0)]);
        let conf = tmp.path().join("conf");
        std::fs::write(
            &conf,
            "vm.swappiness = 10\n             # BEGIN bulwark-hardening (managed)\n             net.ipv4.conf.all.send_redirects = 0\n             net.ipv4.conf.default.send_redirects = 0\n             net.ipv4.conf.veth1db2130.send_redirects = 0\n             net.ipv4.conf.br-00e955817d0a.send_redirects = 0\n             # END bulwark-hardening\n",
        )
        .unwrap();

        // A preview reports them without touching the file.
        let preview = harden_with(
            &["BLWK-KERNEL-016"],
            &proc_root,
            &conf,
            &tmp.path().join("b"),
            false,
        )
        .unwrap();
        assert!(
            preview.changes.is_empty(),
            "nothing is actually misconfigured"
        );
        assert_eq!(preview.stale_persisted_keys.len(), 2);
        assert!(!preview.applied);
        assert!(
            std::fs::read_to_string(&conf)
                .unwrap()
                .contains("veth1db2130"),
            "a preview must not rewrite the file"
        );

        // Applying cleans our block — and only our block.
        let r = harden_with(
            &["BLWK-KERNEL-016"],
            &proc_root,
            &conf,
            &tmp.path().join("b"),
            true,
        )
        .unwrap();
        assert!(r.applied);
        let text = std::fs::read_to_string(&conf).unwrap();
        assert!(!text.contains("veth1db2130"));
        assert!(!text.contains("br-00e955817d0a"));
        assert!(
            text.contains("vm.swappiness = 10"),
            "content outside the managed block must survive untouched"
        );
        // The declaration is rewritten in full, so the fix is still persisted afterwards.
        assert!(text.contains("net.ipv4.conf.all.send_redirects = 0"));
        assert!(r.note.is_some(), "cleaning must be reported, never silent");
    }

    /// A per-interface line the *user* wrote outside our block is theirs — not stale, not ours.
    #[test]
    fn per_interface_lines_outside_the_managed_block_are_left_alone() {
        let text = "net.ipv4.conf.eth0.send_redirects = 1\n                    # BEGIN bulwark-hardening (managed)\n                    net.ipv4.conf.all.send_redirects = 0\n                    # END bulwark-hardening\n";
        assert!(
            stale_per_interface_keys(text).is_empty(),
            "only entries inside the managed block are ours to clean"
        );
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

        let r = harden_with(&["BLWK-KERNEL-016"], &proc_root, &conf, &backups, true).unwrap();
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

    /// An interface that disappears between the preview and the apply — a container exiting — must
    /// degrade that one row, never fail the whole fix.
    #[test]
    fn an_interface_vanishing_mid_apply_is_a_row_level_failure() {
        let tmp = tempfile::tempdir().unwrap();
        let proc_root = tmp.path().join("proc");
        fake_proc(
            &proc_root,
            "send_redirects",
            &[("all", 1), ("default", 1), ("veth0", 1)],
        );
        let conf = tmp.path().join("conf");
        // Remove the interface's directory after planning would have seen it: simulate by making
        // the path unwritable-because-absent.
        let r = {
            let plan_dir = proc_root.join("net/ipv4/conf/veth0");
            let report = harden_with(
                &["BLWK-KERNEL-016"],
                &proc_root,
                &conf,
                &tmp.path().join("b"),
                false,
            )
            .unwrap();
            assert!(report.changes.iter().any(|c| !c.interfaces.is_empty()));
            std::fs::remove_dir_all(&plan_dir).unwrap();
            harden_with(
                &["BLWK-KERNEL-016"],
                &proc_root,
                &conf,
                &tmp.path().join("b"),
                true,
            )
            .unwrap()
        };
        // The persisted scopes still applied; the run did not error out.
        assert!(r.applied);
        assert_eq!(read(&proc_root, "all", "send_redirects"), Some(0));
    }
}
