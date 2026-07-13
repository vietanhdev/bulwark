//! The log-analysis pipeline: **decode → detect → correlate**.
//!
//! Where the config-scan engine ([`crate::engine`]) answers "is this machine's *state* wrong
//! right now," this pipeline answers "what *happened* over time" — SSH brute force, sudo abuse,
//! invalid-user scans. It reads a stream of [`RawEvent`](event::RawEvent)s from a
//! [`LogSource`](source::LogSource), turns each into a [`Fact`](crate::models::Fact) with a
//! [`decoder`], matches decoded facts with the shared condition DSL, and raises findings either
//! per-event or when a [`correlate`] threshold is crossed.
//!
//! This slice runs as a one-shot batch ([`run_log_scan`]); a follow-mode daemon (the eventual
//! `bulwark-agent`) is just this function driven by a following `JournaldSource`.

pub mod correlate;
pub mod decoder;
pub mod event;
pub mod rule;
pub mod source;

use crate::condition::{Condition, ConditionError};
use crate::models::{Fact, RuleLoadError, Severity};
use chrono::{DateTime, Utc};
use correlate::CorrelationState;
use serde::{Deserialize, Serialize};
use std::path::Path;
use uuid::Uuid;

pub use decoder::{load_decoders, DecodedEvent, Decoder};
pub use event::RawEvent;
pub use rule::{load_log_rules, LogRule};
pub use source::{JournalRange, JournaldSource, LogSource, SyslogLinesSource};

/// One raised log finding. Distinct from the config-scan [`Finding`](crate::models::Finding):
/// it's timestamped at the triggering event and carries the correlation key/count, reflecting
/// its event-shaped (not state-shaped) nature.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogFinding {
    pub id: Uuid,
    pub rule_id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub explanation: String,
    pub fix_hint: String,
    /// The group-by key that triggered this (e.g. the source IP), or empty for an ungrouped
    /// rule. Together with `rule_id` it's the reconciliation identity in the store.
    pub group_key: String,
    /// How many events were in the window when the rule fired (`1` for a per-event rule).
    pub match_count: u32,
    /// The decoded fact of the triggering event, plus injected `group_key`/`match_count` so the
    /// context alone is enough to render the finding.
    pub context: Fact,
    /// When the triggering event occurred (event time, not scan time).
    pub observed_at: DateTime<Utc>,
    pub references: Vec<String>,
}

/// The outcome of one [`run_log_scan`], analogous to [`ScanRun`](crate::models::ScanRun) and
/// JSON-serializable for the `--json` / GUI path. Every error surface is explicit — decoders or
/// rules that failed to load, lines that failed to read, conditions that errored at runtime —
/// so a scan is never silently partial.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogScanRun {
    pub id: Uuid,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub host_fingerprint: String,
    pub events_read: u64,
    pub events_decoded: u64,
    pub decoders_loaded: usize,
    pub rules_loaded: usize,
    pub decoder_load_errors: Vec<RuleLoadError>,
    pub rule_load_errors: Vec<RuleLoadError>,
    /// Non-fatal per-line read errors from the source (a malformed journald JSON line, etc.).
    pub read_errors: Vec<String>,
    /// Rules whose condition errored at evaluation time (e.g. an invalid `matches` regex that
    /// only fails once it's actually run) — recorded, and the rule treated as non-matching for
    /// that event, never crashing the scan.
    pub rule_eval_errors: Vec<String>,
    /// Conditions that make an empty finding list *untrustworthy* rather than reassuring: no
    /// decoders/rules loaded (nothing could match), or lines read but none understood (a format
    /// this scanner doesn't parse — ISO-timestamped syslog, a compressed or binary file). A caller
    /// must surface these; "0 findings" with a warning here is "couldn't analyze", not "clean".
    #[serde(default)]
    pub warnings: Vec<String>,
    pub findings: Vec<LogFinding>,
}

impl LogScanRun {
    /// Builds the `warnings` list from the run's own counters — the health signals that separate a
    /// genuine clean result from a scan that never actually analyzed anything.
    fn compute_warnings(&self) -> Vec<String> {
        let mut w = Vec::new();
        if self.decoders_loaded == 0 {
            w.push(
                "no log decoders were loaded — no line can be parsed, so no intrusion can be found"
                    .to_string(),
            );
        }
        if self.rules_loaded == 0 {
            w.push("no log rules were loaded — nothing is being checked for".to_string());
        }
        if self.events_read > 0 && self.events_decoded == 0 {
            w.push(format!(
                "read {} log line(s) but understood 0 of them — this is likely a format Bulwark \
                 doesn't parse (ISO-timestamped syslog, or a compressed/binary file), not a clean log",
                self.events_read
            ));
        }
        // The source failed (e.g. journalctl exited non-zero / permission denied) and produced no
        // events at all — a total-analysis failure, not a clean journal. The source surfaces its
        // failure as a read error at end-of-stream (see JournaldSource::check_exit).
        if self.events_read == 0 && !self.read_errors.is_empty() {
            w.push(
                "the log source failed and no events were read — this scan analyzed nothing, so it \
                 is not a clean result"
                    .to_string(),
            );
        }
        w
    }
}

impl LogScanRun {
    pub fn worst_severity(&self) -> Option<Severity> {
        self.findings.iter().map(|f| f.severity).max()
    }
}

/// Evaluates a log rule's condition against a decoded fact, treating a reference to a field the
/// event simply doesn't have as a non-match rather than an error. Log events are heterogeneous
/// (a rule may reference `srcip`, which only auth-failure lines carry), so `MissingField` is the
/// normal "this rule doesn't apply to this line" signal, not a fault — unlike in the config
/// engine, where a collector always produces every field its rules reference.
fn eval_lenient(cond: &Condition, fact: &Fact) -> Result<bool, ConditionError> {
    match cond.eval(fact) {
        Err(ConditionError::MissingField(_)) => Ok(false),
        other => other,
    }
}

/// Runs the pipeline over one batch of events from `source`, using the decoders in
/// `decoders_dir` and the rules in `rules_dir`. Events are processed in source order, and all
/// time-based correlation uses each event's own timestamp, so the result is a pure function of
/// the input stream (plus the run's wall-clock metadata) — fully reproducible and testable.
pub fn run_log_scan(
    decoders_dir: &Path,
    rules_dir: &Path,
    source: &mut dyn LogSource,
) -> LogScanRun {
    let started_at = Utc::now();
    let id = Uuid::new_v4();

    let (decoders, decoder_load_errors) = load_decoders(decoders_dir);
    let (rules, rule_load_errors) = load_log_rules(rules_dir);

    let mut state = CorrelationState::new();
    let mut findings = Vec::new();
    let mut read_errors = Vec::new();
    let mut rule_eval_errors = Vec::new();
    let mut events_read: u64 = 0;
    let mut events_decoded: u64 = 0;

    while let Some(next) = source.next_event() {
        let raw = match next {
            Ok(raw) => raw,
            Err(e) => {
                read_errors.push(e.to_string());
                continue;
            }
        };
        events_read += 1;

        let Some(decoded) = decoder::decode(&decoders, &raw) else {
            continue;
        };
        events_decoded += 1;
        let now_epoch = raw.timestamp.timestamp();

        for loaded in &rules {
            if let Some(scope) = &loaded.rule.decoder {
                if scope != &decoded.decoder_id {
                    continue;
                }
            }
            match eval_lenient(&loaded.condition, &decoded.fact) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    rule_eval_errors.push(format!("rule {}: {}", loaded.rule.id, e));
                    continue;
                }
            }

            // Matched. Decide whether to raise a finding now.
            let (should_fire, group_key, match_count) = match &loaded.rule.correlate {
                Some(spec) => {
                    let key = correlate::group_key(&spec.by, &decoded.fact);
                    let fired = state.observe(&loaded.rule.id, spec, &key, now_epoch);
                    (fired, key, spec.count)
                }
                None => (true, String::new(), 1),
            };

            if should_fire && loaded.rule.alert {
                findings.push(build_finding(
                    loaded,
                    &decoded,
                    &raw,
                    group_key,
                    match_count,
                ));
            }
        }
    }

    let mut run = LogScanRun {
        id,
        started_at,
        finished_at: Some(Utc::now()),
        host_fingerprint: crate::engine::host_fingerprint(),
        events_read,
        events_decoded,
        decoders_loaded: decoders.len(),
        rules_loaded: rules.len(),
        decoder_load_errors,
        rule_load_errors,
        read_errors,
        rule_eval_errors,
        warnings: Vec::new(),
        findings,
    };
    run.warnings = run.compute_warnings();
    run
}

fn build_finding(
    loaded: &rule::LoadedLogRule,
    decoded: &DecodedEvent,
    raw: &RawEvent,
    group_key: String,
    match_count: u32,
) -> LogFinding {
    // Context = the decoded fact plus the correlation metadata, so a stored finding renders
    // without needing the rule or the original event alongside it.
    let mut context = decoded.fact.clone();
    context.insert(
        "group_key".to_string(),
        serde_json::Value::String(group_key.clone()),
    );
    context.insert(
        "match_count".to_string(),
        serde_json::Value::Number(match_count.into()),
    );

    LogFinding {
        id: Uuid::new_v4(),
        rule_id: loaded.rule.id.clone(),
        severity: loaded.rule.severity,
        category: loaded.rule.category.clone(),
        title: crate::engine::render_template(&loaded.rule.title, &context),
        explanation: crate::engine::render_template(&loaded.rule.explain, &context),
        fix_hint: crate::engine::render_template(&loaded.rule.fix, &context),
        group_key,
        match_count,
        context,
        observed_at: raw.timestamp,
        references: loaded.rule.references.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::Severity;
    use std::io::Cursor;
    use std::path::PathBuf;

    /// The real bundled pack dirs at the workspace root, resolved from this crate's manifest —
    /// so these tests protect the shipped decoders/rules, not a fixture copy (matching how
    /// `engine.rs`'s bundled-pack tests work).
    fn bundled(dir: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join(dir)
    }

    fn syslog_source(text: &str) -> SyslogLinesSource<Cursor<Vec<u8>>> {
        SyslogLinesSource::new(Cursor::new(text.as_bytes().to_vec()), 2026)
    }

    fn scan_bundled(text: &str) -> LogScanRun {
        let mut src = syslog_source(text);
        run_log_scan(&bundled("decoders"), &bundled("log-rules"), &mut src)
    }

    #[test]
    fn bundled_pack_loads_and_every_rule_targets_a_real_decoder() {
        let (decoders, derr) = load_decoders(&bundled("decoders"));
        assert!(derr.is_empty(), "decoder load errors: {derr:?}");
        let (rules, rerr) = load_log_rules(&bundled("log-rules"));
        assert!(rerr.is_empty(), "rule load errors: {rerr:?}");
        assert!(!rules.is_empty(), "bundled pack should have rules");

        let ids: std::collections::HashSet<&str> = decoders.iter().map(|d| d.id.as_str()).collect();
        for r in &rules {
            if let Some(dec) = &r.rule.decoder {
                assert!(
                    ids.contains(dec.as_str()),
                    "{} targets unknown decoder '{dec}'",
                    r.rule.id
                );
            }
        }
    }

    #[test]
    fn brute_force_burst_fires_ssh_001_once_high() {
        let mut burst = String::new();
        for i in 0..8 {
            burst.push_str(&format!(
                "Jul 12 09:15:0{i} h sshd[1]: Failed password for root from 203.0.113.7 port 4{i} ssh2\n"
            ));
        }
        let scan = scan_bundled(&burst);
        assert_eq!(scan.events_decoded, 8);
        let ssh001: Vec<_> = scan
            .findings
            .iter()
            .filter(|f| f.rule_id == "BLWK-LOG-SSH-001")
            .collect();
        assert_eq!(ssh001.len(), 1, "brute force should fire exactly once");
        assert_eq!(ssh001[0].severity, Severity::High);
        assert_eq!(ssh001[0].group_key, "203.0.113.7");
        assert_eq!(ssh001[0].match_count, 8);
    }

    #[test]
    fn same_failures_spread_beyond_the_window_do_not_fire() {
        // 8 failures 30s apart span 3.5 minutes — never 8 inside the 60s window.
        let mut spread = String::new();
        for i in 0..8 {
            let secs = i * 30;
            let mm = 15 + secs / 60;
            let ss = secs % 60;
            spread.push_str(&format!(
                "Jul 12 09:{mm:02}:{ss:02} h sshd[1]: Failed password for root from 203.0.113.7 port 40 ssh2\n"
            ));
        }
        let scan = scan_bundled(&spread);
        assert!(
            scan.findings
                .iter()
                .all(|f| f.rule_id != "BLWK-LOG-SSH-001"),
            "should not fire when spread beyond the window"
        );
    }

    #[test]
    fn quiet_log_produces_no_findings() {
        let quiet = "Jul 12 09:20:01 h sshd[1]: Accepted password for alice from 10.0.0.2 port 22 ssh2\n\
                     Jul 12 09:20:05 h sshd[2]: Accepted publickey for bob from 10.0.0.3 port 22 ssh2\n";
        let scan = scan_bundled(quiet);
        assert!(scan.findings.is_empty(), "got: {:?}", scan.findings);
    }

    #[test]
    fn successful_root_login_fires_but_a_normal_user_login_does_not() {
        let scan = scan_bundled(
            "Jul 12 09:21:01 h sshd[1]: Accepted password for root from 10.0.0.9 port 22 ssh2\n\
             Jul 12 09:21:05 h sshd[2]: Accepted password for alice from 10.0.0.2 port 22 ssh2\n",
        );
        let root: Vec<_> = scan
            .findings
            .iter()
            .filter(|f| f.rule_id == "BLWK-LOG-SSH-003")
            .collect();
        assert_eq!(root.len(), 1);
        assert_eq!(root[0].group_key, ""); // uncorrelated, per-event
    }

    #[test]
    fn a_rule_referencing_an_absent_field_is_a_non_match_not_an_error() {
        // Minimal temp pack: a decoder that emits only `x`, and a rule keyed on `srcip`, which
        // the decoded event never has — must silently not match, with no eval error recorded.
        let dtmp = tempfile::tempdir().unwrap();
        std::fs::write(
            dtmp.path().join("d.yaml"),
            "id: t\nprogram: sshd\npatterns:\n  - regex: '^hi (?P<x>\\S+)'\n    tags: [t]\n",
        )
        .unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        std::fs::write(
            rtmp.path().join("r.yaml"),
            "id: R\ntitle: t\ncategory: c\nseverity: low\ndecoder: t\ncondition: 'srcip == \"1.2.3.4\"'\nexplain: e\nfix: f\n",
        )
        .unwrap();
        let mut src = syslog_source("Jul 12 09:15:00 h sshd[1]: hi there\n");
        let scan = run_log_scan(dtmp.path(), rtmp.path(), &mut src);
        assert_eq!(scan.events_decoded, 1);
        assert!(scan.findings.is_empty());
        assert!(
            scan.rule_eval_errors.is_empty(),
            "MissingField must not be an error"
        );
    }

    #[test]
    fn a_scan_that_understood_nothing_is_warned_not_reported_clean() {
        // Lines read but none decoded (a format Bulwark doesn't parse) must not read as "clean".
        let dtmp = tempfile::tempdir().unwrap();
        std::fs::write(
            dtmp.path().join("d.yaml"),
            "id: sshd\nprogram: sshd\npatterns:\n  - regex: '^Failed'\n    tags: [t]\n",
        )
        .unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        std::fs::write(
            rtmp.path().join("r.yaml"),
            "id: R\ntitle: t\ncategory: c\nseverity: low\ndecoder: sshd\ncondition: 'x == 1'\nexplain: e\nfix: f\n",
        )
        .unwrap();
        // A line the syslog source parses but the sshd decoder doesn't match.
        let mut src = syslog_source("Jul 12 09:15:00 h sshd[1]: Connection closed by 1.2.3.4\n");
        let scan = run_log_scan(dtmp.path(), rtmp.path(), &mut src);
        assert!(scan.findings.is_empty());
        assert!(
            scan.warnings.iter().any(|w| w.contains("understood 0")),
            "read-but-undecoded must warn, got {:?}",
            scan.warnings
        );
    }

    #[test]
    fn zero_decoders_is_a_warning_not_a_clean_result() {
        let dtmp = tempfile::tempdir().unwrap(); // empty — no decoders
        let rtmp = tempfile::tempdir().unwrap();
        std::fs::write(
            rtmp.path().join("r.yaml"),
            "id: R\ntitle: t\ncategory: c\nseverity: low\ndecoder: sshd\ncondition: 'x == 1'\nexplain: e\nfix: f\n",
        )
        .unwrap();
        let mut src = syslog_source(
            "Jul 12 09:15:00 h sshd[1]: Failed password for root from 1.2.3.4 port 2 ssh2\n",
        );
        let scan = run_log_scan(dtmp.path(), rtmp.path(), &mut src);
        assert!(scan.warnings.iter().any(|w| w.contains("no log decoders")));
    }

    #[test]
    fn a_bad_matches_regex_is_rejected_at_load_not_fatal() {
        let dtmp = tempfile::tempdir().unwrap();
        std::fs::write(
            dtmp.path().join("d.yaml"),
            "id: t\nprogram: sshd\npatterns:\n  - regex: '^hi (?P<x>\\S+)'\n    tags: [t]\n",
        )
        .unwrap();
        let rtmp = tempfile::tempdir().unwrap();
        // `matches` now compiles its regex at PARSE time, so an invalid pattern (`[`) makes the
        // rule fail to load — caught up front (and by `logs rules validate`) rather than lurking as
        // a per-event eval error. The scan stays non-fatal and records the load failure.
        std::fs::write(
            rtmp.path().join("r.yaml"),
            "id: R\ntitle: t\ncategory: c\nseverity: low\ndecoder: t\ncondition: 'x matches \"[\"'\nexplain: e\nfix: f\n",
        )
        .unwrap();
        let mut src = syslog_source("Jul 12 09:15:00 h sshd[1]: hi there\n");
        let scan = run_log_scan(dtmp.path(), rtmp.path(), &mut src);
        assert!(scan.findings.is_empty());
        assert_eq!(
            scan.rule_load_errors.len(),
            1,
            "an invalid regex should be a load error, caught before any scan"
        );
    }
}
