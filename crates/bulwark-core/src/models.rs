use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use uuid::Uuid;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingStatus {
    Open,
    Acknowledged,
    Resolved,
}

/// A user's explicit, reasoned decision to accept the risk a rule reports.
///
/// Note what this is *not*: it is not a switch that stops the rule running. A suppressed rule is
/// evaluated on every scan exactly as before and its findings are still written to the database —
/// suppression only changes how they are presented and counted. Two reasons that matters, and both
/// are the difference between a risk-acceptance workflow and a mute button:
///
///   * Lifting a suppression must reveal the *current* truth, not a stale snapshot from whenever
///     the rule was last allowed to run.
///   * A suppression must never quietly decay into a blind spot. The check keeps running, so the
///     answer to "is this still true?" is always one click away.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Suppression {
    pub rule_id: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
    pub created_by: String,
}

/// What happened to a suppression. Recorded append-only, so the history survives the suppression
/// itself being lifted — that is the entire point of keeping an audit log separate from state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SuppressionAction {
    Suppressed,
    Unsuppressed,
}

impl SuppressionAction {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Suppressed => "suppressed",
            Self::Unsuppressed => "unsuppressed",
        }
    }
}

/// One immutable entry in the suppression audit trail: who accepted (or withdrew) a risk, when,
/// and — crucially — why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SuppressionEvent {
    pub id: Uuid,
    pub rule_id: String,
    pub action: SuppressionAction,
    pub reason: String,
    pub actor: String,
    pub at: DateTime<Utc>,
}

/// The operating system(s) a rule or collector targets. Everything in this project has been
/// Linux-only through v0.1 — this exists so that support for another OS is "add a collector
/// and tag some rules," not "redesign the rule/collector model." See docs/guide/architecture.md.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum OperatingSystem {
    Linux,
    Macos,
    Windows,
}

impl OperatingSystem {
    /// The OS this binary is actually running on, or `None` on a target `std::env::consts::OS`
    /// doesn't recognize — treated as "matches nothing" by rule/collector filtering rather than
    /// defaulting to Linux, so an unrecognized host fails closed (no rules silently run) instead
    /// of silently assuming Linux on a platform nobody has actually validated this against.
    pub fn current() -> Option<Self> {
        match std::env::consts::OS {
            "linux" => Some(Self::Linux),
            "macos" => Some(Self::Macos),
            "windows" => Some(Self::Windows),
            _ => None,
        }
    }
}

fn default_rule_os() -> Vec<OperatingSystem> {
    vec![OperatingSystem::Linux]
}

/// One fact row produced by a collector. Most collectors produce exactly one row;
/// list-shaped collectors (listening ports, cron entries, ...) produce one row per item,
/// and each row is evaluated against the rule's condition independently.
pub type Fact = BTreeMap<String, serde_json::Value>;

/// A rule as authored in YAML. See docs/guide/architecture.md §5.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: String,
    pub title: String,
    pub category: String,
    pub severity: Severity,
    pub collector: String,
    pub condition: String,
    pub explain: String,
    pub fix: String,
    #[serde(default)]
    pub references: Vec<String>,
    /// Which OS(es) this rule applies to. Defaults to `[linux]` so all pre-existing rule
    /// files need no change — every rule authored before this field existed was implicitly
    /// Linux-only anyway. A rule should list every OS its collector can produce facts on;
    /// see `Collector::supported_os` for the collector-level half of this same gate.
    #[serde(default = "default_rule_os")]
    pub os: Vec<OperatingSystem>,
    /// Free-form "need" tags (e.g. "desktop", "server", "developer") a profile opts into.
    /// Empty (the default) means universal — the rule runs regardless of which needs are
    /// selected. A non-empty list means "only run this when the active profile has opted
    /// into at least one of these needs" — e.g. a process-accounting check is real but
    /// mostly a server-hardening concern, not something a laptop user needs surfaced by
    /// default. No fixed enum of valid tags on purpose: adding a new need is "write it in a
    /// YAML file," matching this project's "no Rust required to add a rule" philosophy.
    #[serde(default)]
    pub profiles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: Uuid,
    pub rule_id: String,
    pub severity: Severity,
    pub title: String,
    pub explanation: String,
    pub fix_hint: String,
    pub context: Fact,
    pub first_seen: DateTime<Utc>,
    pub last_seen: DateTime<Utc>,
    pub status: FindingStatus,
    pub scan_run_id: Uuid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CollectorError {
    pub collector: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleLoadError {
    pub path: String,
    pub message: String,
}

/// Round-trips through JSON (see `bulwark-app`'s privileged-scan path: the GUI shells out
/// to `bulwarkctl scan --privileged --json` via pkexec and deserializes its stdout rather
/// than duplicating collector logic — the CLI and GUI stay two front-doors over one engine
/// even for the privileged path).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRun {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub host_fingerprint: String,
    pub rules_loaded: usize,
    pub rule_load_errors: Vec<RuleLoadError>,
    pub collector_errors: Vec<CollectorError>,
    /// Collectors that needed elevation and were skipped because this run wasn't
    /// privileged — never silent (architecture doc §8, "N checks skipped (no privilege)").
    pub privileged_collectors_skipped: Vec<String>,
    /// The rule IDs that *demonstrably ran* in this scan — i.e. whose collector was applicable,
    /// had the privilege it needed, and returned facts without erroring. This is what makes
    /// "absent from this scan" interpretable: a rule in this list that produced no finding
    /// genuinely passed (the issue is fixed), whereas a rule *not* in this list tells us nothing
    /// either way and its existing findings must be left alone. Without this distinction
    /// `Store::persist_and_reconcile` could only ever add findings and never close them, so a
    /// fixed issue stayed on the dashboard forever — a real bug (a recorded FIM baseline still
    /// showed "no baseline yet" indefinitely).
    #[serde(default)]
    pub rules_evaluated: Vec<String>,
    /// True when the user stopped the scan before it finished. A cancelled run's findings are
    /// partial and must not be persisted as the host's current picture.
    #[serde(default)]
    pub cancelled: bool,
    pub findings: Vec<Finding>,
}

impl ScanRun {
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `bulwark-app`'s privileged-scan path (see `apps/bulwark-app/src-tauri/src/lib.rs`)
    /// depends entirely on `bulwarkctl scan --json`'s stdout deserializing back into a
    /// real `ScanRun` — this is the contract that makes that wiring trustworthy rather
    /// than something that only happened to work in one manual test run.
    #[test]
    fn scan_run_survives_a_json_round_trip() {
        let mut context = Fact::new();
        context.insert("port".to_string(), serde_json::Value::from(5900));

        let scan_run_id = Uuid::new_v4();
        let now = Utc::now();
        let original = ScanRun {
            id: scan_run_id,
            started_at: now,
            finished_at: Some(now),
            host_fingerprint: "test-host/6.8.0".to_string(),
            rules_loaded: 3,
            rule_load_errors: vec![RuleLoadError {
                path: "bad.yaml".into(),
                message: "oops".into(),
            }],
            collector_errors: vec![CollectorError {
                collector: "sudoers".into(),
                message: "denied".into(),
            }],
            privileged_collectors_skipped: vec!["sudoers".into()],
            rules_evaluated: vec!["BLWK-NET-001".into()],
            cancelled: false,
            findings: vec![Finding {
                id: Uuid::new_v4(),
                rule_id: "BLWK-NET-001".into(),
                severity: Severity::High,
                title: "A VNC port is listening".into(),
                explanation: "explanation text".into(),
                fix_hint: "fix it".into(),
                context,
                first_seen: now,
                last_seen: now,
                status: FindingStatus::Open,
                scan_run_id,
            }],
        };

        let json = serde_json::to_string(&original).unwrap();
        let round_tripped: ScanRun = serde_json::from_str(&json).unwrap();

        assert_eq!(round_tripped.id, original.id);
        assert_eq!(round_tripped.findings.len(), 1);
        assert_eq!(round_tripped.findings[0].rule_id, "BLWK-NET-001");
        assert_eq!(round_tripped.findings[0].severity, Severity::High);
        assert_eq!(round_tripped.privileged_collectors_skipped, vec!["sudoers"]);
    }

    fn finding_with(severity: Severity) -> Finding {
        let now = Utc::now();
        Finding {
            id: Uuid::new_v4(),
            rule_id: "BLWK-TEST-000".into(),
            severity,
            title: "t".into(),
            explanation: "e".into(),
            fix_hint: "f".into(),
            context: Fact::new(),
            first_seen: now,
            last_seen: now,
            status: FindingStatus::Open,
            scan_run_id: Uuid::new_v4(),
        }
    }

    fn scan_run_with(findings: Vec<Finding>) -> ScanRun {
        let now = Utc::now();
        ScanRun {
            id: Uuid::new_v4(),
            started_at: now,
            finished_at: Some(now),
            host_fingerprint: "test-host/6.8.0".into(),
            rules_loaded: findings.len(),
            rule_load_errors: vec![],
            collector_errors: vec![],
            privileged_collectors_skipped: vec![],
            rules_evaluated: vec![],
            cancelled: false,
            findings,
        }
    }

    /// `bulwarkctl`'s process exit code is driven entirely by this — a wrong ordering
    /// here would mean the CLI reports "clean" (exit 0) on a run that actually found a
    /// critical issue, silently breaking any script/CI job gating on the exit code.
    #[test]
    fn worst_severity_picks_the_highest_of_mixed_findings() {
        let scan = scan_run_with(vec![
            finding_with(Severity::Low),
            finding_with(Severity::Critical),
            finding_with(Severity::Medium),
        ]);
        assert_eq!(scan.worst_severity(), Some(Severity::Critical));
    }

    #[test]
    fn worst_severity_is_none_with_no_findings() {
        assert_eq!(scan_run_with(vec![]).worst_severity(), None);
    }
}
