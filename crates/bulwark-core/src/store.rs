use crate::models::{Finding, FindingStatus, ScanRun, Severity};
use chrono::{DateTime, Utc};
use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;

pub struct Store {
    conn: Connection,
}

impl Store {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        Self::migrate(&conn)?;
        Ok(Store { conn })
    }

    pub fn open_in_memory() -> anyhow::Result<Self> {
        let conn = Connection::open_in_memory()?;
        Self::migrate(&conn)?;
        Ok(Store { conn })
    }

    fn migrate(conn: &Connection) -> anyhow::Result<()> {
        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS scan_runs (
                id                 TEXT PRIMARY KEY,
                started_at         TEXT NOT NULL,
                finished_at        TEXT,
                host_fingerprint   TEXT NOT NULL,
                rules_loaded       INTEGER NOT NULL,
                rules_failed       INTEGER NOT NULL,
                collectors_failed  INTEGER NOT NULL,
                rule_load_errors   TEXT NOT NULL,
                collector_errors   TEXT NOT NULL,
                privileged_skipped TEXT NOT NULL,
                total_findings     INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS findings (
                id            TEXT PRIMARY KEY,
                scan_run_id   TEXT NOT NULL REFERENCES scan_runs(id),
                rule_id       TEXT NOT NULL,
                severity      TEXT NOT NULL,
                title         TEXT NOT NULL,
                explanation   TEXT NOT NULL,
                fix_hint      TEXT NOT NULL,
                context       TEXT NOT NULL,
                first_seen    TEXT NOT NULL,
                last_seen     TEXT NOT NULL,
                status        TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_findings_rule_status ON findings(rule_id, status);
            CREATE INDEX IF NOT EXISTS idx_findings_scan_run ON findings(scan_run_id);
            "#,
        )?;
        // `total_findings` was added after scan_runs already shipped. `CREATE TABLE IF NOT
        // EXISTS` above only applies to a brand-new DB (which already gets the column from
        // the definition itself); a DB created by an earlier Bulwark build needs this ALTER
        // to pick it up. SQLite has no `ADD COLUMN IF NOT EXISTS`, so this errors with
        // "duplicate column name" on every DB that already has it — which is expected and
        // safe to ignore, not a real failure.
        let _ = conn.execute(
            "ALTER TABLE scan_runs ADD COLUMN total_findings INTEGER NOT NULL DEFAULT 0",
            [],
        );
        Ok(())
    }

    /// Persists a `ScanRun` as-is: every finding becomes a new row, with no relationship
    /// to findings from earlier runs. Fine for a one-off `bulwark scan`, but a periodic
    /// monitoring loop that calls this on every tick would insert a fresh duplicate row
    /// for every persisting issue every time — see [`Self::persist_and_reconcile`], which
    /// is what continuous monitoring actually needs.
    pub fn persist(&mut self, scan: &ScanRun) -> anyhow::Result<()> {
        let tx = self.conn.transaction()?;
        Self::insert_scan_run(&tx, scan)?;
        for f in &scan.findings {
            Self::insert_finding(&tx, f)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Persists a `ScanRun` the way continuous monitoring needs: a finding matching an
    /// already-*open* finding from a previous run gets its `last_seen` (and stored context)
    /// updated in place rather than becoming a duplicate row, and keeps its original
    /// `first_seen`. Anything left over — genuinely new, or a rule_id+context that was
    /// previously `resolved`/`acknowledged` and has now reappeared — is inserted fresh and
    /// returned as "newly appeared," which is what should actually trigger a notification.
    /// Deliberately does *not* auto-resolve findings that are simply absent from this run:
    /// absence could mean "fixed," or it could mean the relevant collector was skipped (e.g.
    /// a privileged one during an unprivileged periodic run) — conflating those would be a
    /// worse bug than not auto-resolving at all, so resolving stays an explicit user action.
    ///
    /// "Same underlying issue" is *not* exact-string equality on the serialized context —
    /// a real bug caught live in this project's own dashboard: extending `login_defs.rs` to
    /// add two new always-present fields changed the context JSON shape for the *existing*
    /// `BLWK-ACCT-002` rule (which doesn't even read those fields), which broke the old
    /// exact-match query and produced a second row for the same real-world issue on the very
    /// next scan. A collector's fact shape evolving over time is routine, not exceptional —
    /// the identity check has to tolerate it. A stored context now matches if it's a *subset*
    /// of the newly observed context (every key the old row already had still has the same
    /// value) — new fields a collector has since started reporting don't break continuity for
    /// rules that never cared about them, but two genuinely different rows for a list-shaped
    /// collector (e.g. `module_blacklist`'s five rows, one per module) still can't cross-match
    /// each other, since their *shared* discriminating field (e.g. `module`) would differ.
    pub fn persist_and_reconcile(&mut self, scan: &ScanRun) -> anyhow::Result<Vec<Finding>> {
        let tx = self.conn.transaction()?;
        Self::insert_scan_run(&tx, scan)?;

        let mut newly_appeared = Vec::new();
        for f in &scan.findings {
            let mut stmt = tx.prepare(
                "SELECT id, context FROM findings WHERE rule_id = ?1 AND status = 'open'",
            )?;
            let candidates: Vec<(String, String)> = stmt
                .query_map(params![f.rule_id], |r| Ok((r.get(0)?, r.get(1)?)))?
                .collect::<Result<_, _>>()?;
            drop(stmt);

            let existing_id = candidates.into_iter().find_map(|(id, context_json)| {
                let old_context: crate::models::Fact = serde_json::from_str(&context_json).ok()?;
                is_context_subset(&old_context, &f.context).then_some(id)
            });

            match existing_id {
                Some(existing_id) => {
                    let context_json = serde_json::to_string(&f.context)?;
                    tx.execute(
                        "UPDATE findings SET last_seen = ?1, scan_run_id = ?2, context = ?3 WHERE id = ?4",
                        params![
                            f.last_seen.to_rfc3339(),
                            f.scan_run_id.to_string(),
                            context_json,
                            existing_id
                        ],
                    )?;
                }
                None => {
                    Self::insert_finding(&tx, f)?;
                    newly_appeared.push(f.clone());
                }
            }
        }
        tx.commit()?;
        Ok(newly_appeared)
    }

    fn insert_scan_run(tx: &rusqlite::Transaction, scan: &ScanRun) -> anyhow::Result<()> {
        tx.execute(
            "INSERT INTO scan_runs (id, started_at, finished_at, host_fingerprint, rules_loaded, rules_failed, collectors_failed, rule_load_errors, collector_errors, privileged_skipped, total_findings)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                scan.id.to_string(),
                scan.started_at.to_rfc3339(),
                scan.finished_at.map(|t| t.to_rfc3339()),
                scan.host_fingerprint,
                scan.rules_loaded as i64,
                scan.rule_load_errors.len() as i64,
                scan.collector_errors.len() as i64,
                serde_json::to_string(&scan.rule_load_errors)?,
                serde_json::to_string(&scan.collector_errors)?,
                serde_json::to_string(&scan.privileged_collectors_skipped)?,
                // The full count the engine produced for *this* scan, independent of how
                // persist_and_reconcile later reassigns individual findings' scan_run_id to
                // whichever run most recently observed them — that reassignment is about
                // "what does the dashboard show right now," this column is about "what did
                // this specific point in time look like," which is what a history/timeline
                // view needs and `count_findings_for_run` can't answer after reconciliation
                // has moved rows off of older runs.
                scan.findings.len() as i64,
            ],
        )?;
        Ok(())
    }

    fn insert_finding(tx: &rusqlite::Transaction, f: &Finding) -> anyhow::Result<()> {
        tx.execute(
            "INSERT INTO findings (id, scan_run_id, rule_id, severity, title, explanation, fix_hint, context, first_seen, last_seen, status)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)",
            params![
                f.id.to_string(),
                f.scan_run_id.to_string(),
                f.rule_id,
                severity_str(f.severity),
                f.title,
                f.explanation,
                f.fix_hint,
                serde_json::to_string(&f.context)?,
                f.first_seen.to_rfc3339(),
                f.last_seen.to_rfc3339(),
                status_str(f.status),
            ],
        )?;
        Ok(())
    }

    pub fn count_scan_runs(&self) -> anyhow::Result<i64> {
        Ok(self
            .conn
            .query_row("SELECT COUNT(*) FROM scan_runs", [], |r| r.get(0))?)
    }

    pub fn count_findings_for_run(&self, scan_run_id: &str) -> anyhow::Result<i64> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*) FROM findings WHERE scan_run_id = ?1",
            params![scan_run_id],
            |r| r.get(0),
        )?)
    }

    /// The state a freshly-opened window should actually show: everything currently open,
    /// regardless of whether it was last touched by a manual scan or a background monitoring
    /// tick. Reconciliation (`persist_and_reconcile`) is what makes `status = 'open'` mean
    /// "the current picture" rather than "whatever the single latest run happened to see" —
    /// a privileged finding only ever observed by an earlier manual privileged scan is still
    /// legitimately open even if the most recent tick was unprivileged-only.
    pub fn open_findings(&self) -> anyhow::Result<Vec<Finding>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, scan_run_id, rule_id, severity, title, explanation, fix_hint, context, first_seen, last_seen, status
             FROM findings WHERE status = 'open' ORDER BY last_seen DESC",
        )?;
        let rows = stmt.query_map([], row_to_finding)?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    /// Metadata for the most recent scan run — host fingerprint, when it started, and which
    /// collectors it had to skip for lack of privilege — so a freshly-opened window can show
    /// "last checked ..." and the privileged-checks banner without the user re-scanning first.
    pub fn latest_scan_run_meta(&self) -> anyhow::Result<Option<LatestScanMeta>> {
        self.conn
            .query_row(
                "SELECT host_fingerprint, started_at, privileged_skipped
                 FROM scan_runs ORDER BY started_at DESC LIMIT 1",
                [],
                |r| {
                    let skipped_json: String = r.get(2)?;
                    Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?, skipped_json))
                },
            )
            .optional()?
            .map(|(host_fingerprint, started_at, skipped_json)| {
                Ok(LatestScanMeta {
                    host_fingerprint,
                    started_at: DateTime::parse_from_rfc3339(&started_at)?.with_timezone(&Utc),
                    privileged_collectors_skipped: serde_json::from_str(&skipped_json)?,
                })
            })
            .transpose()
    }

    /// The most recent `limit` scan runs, newest first — backs the History timeline view.
    /// `total_findings` reflects what that specific scan actually produced (see the doc
    /// comment on [`Self::insert_scan_run`]'s last param), not a live re-derived count, so
    /// the trend line stays accurate even as later runs reconcile individual finding rows
    /// onto themselves.
    pub fn list_scan_runs(&self, limit: i64) -> anyhow::Result<Vec<ScanRunSummary>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, started_at, finished_at, host_fingerprint, rules_loaded, rules_failed, collectors_failed, privileged_skipped, total_findings
             FROM scan_runs ORDER BY started_at DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit], |r| {
            let privileged_skipped_json: String = r.get(7)?;
            let privileged_collectors_skipped: Vec<String> =
                serde_json::from_str(&privileged_skipped_json).unwrap_or_default();
            let started_at_s: String = r.get(1)?;
            let finished_at_s: Option<String> = r.get(2)?;
            Ok(ScanRunSummary {
                id: r.get(0)?,
                started_at: DateTime::parse_from_rfc3339(&started_at_s)
                    .map(|t| t.with_timezone(&Utc))
                    .unwrap_or_else(|_| Utc::now()),
                finished_at: finished_at_s.and_then(|s| {
                    DateTime::parse_from_rfc3339(&s)
                        .ok()
                        .map(|t| t.with_timezone(&Utc))
                }),
                host_fingerprint: r.get(3)?,
                rules_loaded: r.get(4)?,
                rules_failed: r.get(5)?,
                collectors_failed: r.get(6)?,
                privileged_collectors_skipped,
                total_findings: r.get(8)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }
}

/// True if every key `old` has is present in `new` with an equal value — `old` doesn't need
/// to be a *proper* subset (equal maps count), and `new` is free to carry extra keys `old`
/// never had. This is `persist_and_reconcile`'s actual identity check for "the same
/// underlying issue": exact equality on the full context would mean a collector gaining a
/// new field (routine — see that method's doc comment) breaks continuity for every existing
/// rule reading that collector, even ones that never touch the new field.
fn is_context_subset(old: &crate::models::Fact, new: &crate::models::Fact) -> bool {
    old.iter().all(|(k, v)| new.get(k) == Some(v))
}

#[derive(serde::Serialize)]
pub struct ScanRunSummary {
    pub id: String,
    pub started_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub host_fingerprint: String,
    pub rules_loaded: i64,
    pub rules_failed: i64,
    pub collectors_failed: i64,
    pub privileged_collectors_skipped: Vec<String>,
    pub total_findings: i64,
}

#[derive(serde::Serialize)]
pub struct LatestScanMeta {
    pub host_fingerprint: String,
    pub started_at: DateTime<Utc>,
    pub privileged_collectors_skipped: Vec<String>,
}

fn row_to_finding(r: &rusqlite::Row) -> rusqlite::Result<Finding> {
    let context_json: String = r.get(7)?;
    let severity_s: String = r.get(3)?;
    let status_s: String = r.get(10)?;
    let first_seen_s: String = r.get(8)?;
    let last_seen_s: String = r.get(9)?;
    Ok(Finding {
        id: r.get::<_, String>(0)?.parse().map_err(|_| {
            rusqlite::Error::InvalidColumnType(0, "id".into(), rusqlite::types::Type::Text)
        })?,
        scan_run_id: r.get::<_, String>(1)?.parse().map_err(|_| {
            rusqlite::Error::InvalidColumnType(1, "scan_run_id".into(), rusqlite::types::Type::Text)
        })?,
        rule_id: r.get(2)?,
        severity: parse_severity(&severity_s),
        title: r.get(4)?,
        explanation: r.get(5)?,
        fix_hint: r.get(6)?,
        context: serde_json::from_str(&context_json).unwrap_or_default(),
        first_seen: DateTime::parse_from_rfc3339(&first_seen_s)
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        last_seen: DateTime::parse_from_rfc3339(&last_seen_s)
            .map(|t| t.with_timezone(&Utc))
            .unwrap_or_else(|_| Utc::now()),
        status: parse_status(&status_s),
    })
}

fn parse_severity(s: &str) -> Severity {
    match s {
        "critical" => Severity::Critical,
        "high" => Severity::High,
        "medium" => Severity::Medium,
        "low" => Severity::Low,
        _ => Severity::Info,
    }
}

fn parse_status(s: &str) -> FindingStatus {
    match s {
        "acknowledged" => FindingStatus::Acknowledged,
        "resolved" => FindingStatus::Resolved,
        _ => FindingStatus::Open,
    }
}

fn severity_str(s: Severity) -> &'static str {
    match s {
        Severity::Info => "info",
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}

fn status_str(s: FindingStatus) -> &'static str {
    match s {
        FindingStatus::Open => "open",
        FindingStatus::Acknowledged => "acknowledged",
        FindingStatus::Resolved => "resolved",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CollectorError, RuleLoadError};
    use chrono::Utc;
    use uuid::Uuid;

    fn sample_scan() -> ScanRun {
        let scan_run_id = Uuid::new_v4();
        let now = Utc::now();
        ScanRun {
            id: scan_run_id,
            started_at: now,
            finished_at: Some(now),
            host_fingerprint: "test-host/6.8.0".to_string(),
            rules_loaded: 1,
            rule_load_errors: vec![RuleLoadError {
                path: "x.yaml".into(),
                message: "boom".into(),
            }],
            collector_errors: vec![CollectorError {
                collector: "sshd_config".into(),
                message: "denied".into(),
            }],
            privileged_collectors_skipped: vec!["sudoers".into()],
            findings: vec![Finding {
                id: Uuid::new_v4(),
                rule_id: "BLWK-SSH-001".into(),
                severity: Severity::Critical,
                title: "t".into(),
                explanation: "e".into(),
                fix_hint: "f".into(),
                context: Default::default(),
                first_seen: now,
                last_seen: now,
                status: FindingStatus::Open,
                scan_run_id,
            }],
        }
    }

    #[test]
    fn persists_and_counts_round_trip() {
        let mut store = Store::open_in_memory().unwrap();
        let scan = sample_scan();
        store.persist(&scan).unwrap();
        assert_eq!(store.count_scan_runs().unwrap(), 1);
        assert_eq!(
            store.count_findings_for_run(&scan.id.to_string()).unwrap(),
            1
        );
    }

    /// The behavior continuous monitoring actually depends on: the same underlying issue,
    /// seen again on a later periodic run, must not (a) duplicate as a new row or (b) be
    /// reported as "newly appeared" a second time — otherwise every monitoring tick would
    /// both bloat the findings table and re-notify for something already known about.
    #[test]
    fn reconcile_dedupes_a_persisting_finding_across_runs() {
        let mut store = Store::open_in_memory().unwrap();

        let first_run = sample_scan();
        let first_seen_at = first_run.findings[0].first_seen;
        let new_in_first_run = store.persist_and_reconcile(&first_run).unwrap();
        assert_eq!(
            new_in_first_run.len(),
            1,
            "first sighting must be reported as new"
        );

        // A later run: same rule_id + same context (the identity of "the same issue"),
        // but a fresh scan_run_id/id/timestamps, exactly as a periodic re-scan would produce.
        let mut second_run = sample_scan();
        second_run.id = Uuid::new_v4();
        second_run.findings[0].id = Uuid::new_v4();
        second_run.findings[0].scan_run_id = second_run.id;
        second_run.findings[0].first_seen = Utc::now();
        second_run.findings[0].last_seen = Utc::now();

        let new_in_second_run = store.persist_and_reconcile(&second_run).unwrap();
        assert!(
            new_in_second_run.is_empty(),
            "a persisting issue must not be reported as new again"
        );
        // scan_run_id tracks the *most recent* run that observed the finding, not the one
        // that first discovered it (first_seen covers that) — so "findings for the latest
        // run" reads as the full current state, carried-over issues included, which is what
        // a continuous-monitoring dashboard actually wants to query.
        assert_eq!(
            store
                .count_findings_for_run(&second_run.id.to_string())
                .unwrap(),
            1,
            "reconciliation must move the existing row onto the latest run, not insert a duplicate"
        );
        assert_eq!(
            store.count_findings_for_run(&first_run.id.to_string()).unwrap(),
            0,
            "the row no longer belongs to the run that first found it once a later run re-observes it"
        );

        let stored_first_seen: String = store
            .conn
            .query_row(
                "SELECT first_seen FROM findings WHERE rule_id = ?1",
                params!["BLWK-SSH-001"],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(
            stored_first_seen,
            first_seen_at.to_rfc3339(),
            "first_seen must be preserved from the original sighting, not overwritten"
        );
    }

    /// Regression test for a real bug reported live against this project's own dashboard:
    /// extending `login_defs.rs` to add two new always-present fields to its fact map (see
    /// `BLWK-ACCT-004`/`005`) changed the context JSON shape for the pre-existing
    /// `BLWK-ACCT-002` rule too, even though that rule never reads the new fields — under the
    /// old exact-string-match reconciliation, this silently produced a second row for the
    /// same real-world issue on the very next scan after the collector changed.
    #[test]
    fn reconcile_tolerates_a_collector_gaining_new_context_fields() {
        let mut store = Store::open_in_memory().unwrap();

        let mut first_run = sample_scan();
        first_run.findings[0].context =
            [("pass_max_days".to_string(), serde_json::Value::from(99999))]
                .into_iter()
                .collect();
        store.persist_and_reconcile(&first_run).unwrap();

        // Same underlying issue, same rule, but the collector has since started reporting
        // two more fields that this rule doesn't care about — exactly what happened when
        // login_defs.rs was extended for SHA_CRYPT_MIN_ROUNDS/UMASK.
        let mut second_run = sample_scan();
        second_run.id = Uuid::new_v4();
        second_run.findings[0].id = Uuid::new_v4();
        second_run.findings[0].scan_run_id = second_run.id;
        second_run.findings[0].context = [
            ("pass_max_days".to_string(), serde_json::Value::from(99999)),
            (
                "sha_crypt_min_rounds_configured".to_string(),
                serde_json::Value::Bool(false),
            ),
            (
                "umask_configured".to_string(),
                serde_json::Value::Bool(false),
            ),
        ]
        .into_iter()
        .collect();

        let newly_appeared = store.persist_and_reconcile(&second_run).unwrap();
        assert!(
            newly_appeared.is_empty(),
            "a collector gaining unrelated fields must not read as a new finding"
        );
        assert_eq!(
            store.open_findings().unwrap().len(),
            1,
            "must still be exactly one open row for this rule, not two"
        );
    }

    /// The other side of the same fix: two genuinely different findings from a list-shaped
    /// collector (e.g. `module_blacklist`'s one row per module) must still never merge into
    /// each other just because they share a rule_id — the subset check only matches when the
    /// *old* row's fields are fully present in the *new* one, and two different modules'
    /// context maps don't satisfy that in either direction.
    #[test]
    fn reconcile_does_not_merge_distinct_findings_from_a_list_shaped_collector() {
        let mut store = Store::open_in_memory().unwrap();

        let mut scan = sample_scan();
        let now = Utc::now();
        scan.findings = vec![
            Finding {
                context: [
                    ("module".to_string(), serde_json::Value::from("dccp")),
                    ("blacklisted".to_string(), serde_json::Value::Bool(false)),
                ]
                .into_iter()
                .collect(),
                ..scan.findings[0].clone()
            },
            Finding {
                id: Uuid::new_v4(),
                context: [
                    ("module".to_string(), serde_json::Value::from("sctp")),
                    ("blacklisted".to_string(), serde_json::Value::Bool(false)),
                ]
                .into_iter()
                .collect(),
                first_seen: now,
                last_seen: now,
                ..scan.findings[0].clone()
            },
        ];

        let newly_appeared = store.persist_and_reconcile(&scan).unwrap();
        assert_eq!(
            newly_appeared.len(),
            2,
            "two distinct modules must both be new"
        );
        assert_eq!(store.open_findings().unwrap().len(), 2);
    }

    #[test]
    fn reconcile_reports_a_genuinely_new_finding() {
        let mut store = Store::open_in_memory().unwrap();
        let mut scan = sample_scan();
        scan.findings[0].rule_id = "BLWK-NET-001".into();

        let newly_appeared = store.persist_and_reconcile(&scan).unwrap();
        assert_eq!(newly_appeared.len(), 1);
        assert_eq!(newly_appeared[0].rule_id, "BLWK-NET-001");
    }

    /// The exact query a freshly-opened window needs: regression test for a real bug caught
    /// by actually looking at the running app — the GUI showed "Not scanned yet" with an
    /// empty dashboard while the sidebar's own history count proved scans (from the
    /// monitoring loop) had genuinely happened. `open_findings` is what a freshly-opened
    /// window should load on mount instead of starting from blank local state.
    #[test]
    fn open_findings_reflects_prior_runs_on_a_fresh_store_read() {
        let mut store = Store::open_in_memory().unwrap();
        let scan = sample_scan();
        store.persist_and_reconcile(&scan).unwrap();

        let open = store.open_findings().unwrap();
        assert_eq!(open.len(), 1);
        assert_eq!(open[0].rule_id, "BLWK-SSH-001");

        let meta = store.latest_scan_run_meta().unwrap().expect("a run exists");
        assert_eq!(meta.host_fingerprint, "test-host/6.8.0");
        assert_eq!(
            meta.privileged_collectors_skipped,
            vec!["sudoers".to_string()]
        );
    }

    #[test]
    fn list_scan_runs_returns_newest_first_with_total_findings_per_run() {
        let mut store = Store::open_in_memory().unwrap();

        let first_run = sample_scan();
        store.persist_and_reconcile(&first_run).unwrap();

        // A second run with a different, additional finding — a realistic "something new
        // showed up" tick, not just a re-observation of the same issue.
        let mut second_run = sample_scan();
        second_run.id = Uuid::new_v4();
        second_run.findings[0].id = Uuid::new_v4();
        second_run.findings[0].scan_run_id = second_run.id;
        second_run.findings.push(Finding {
            id: Uuid::new_v4(),
            rule_id: "BLWK-NET-001".into(),
            severity: Severity::High,
            title: "t2".into(),
            explanation: "e2".into(),
            fix_hint: "f2".into(),
            context: Default::default(),
            first_seen: Utc::now(),
            last_seen: Utc::now(),
            status: FindingStatus::Open,
            scan_run_id: second_run.id,
        });
        store.persist_and_reconcile(&second_run).unwrap();

        let runs = store.list_scan_runs(10).unwrap();
        assert_eq!(runs.len(), 2);
        // Newest first.
        assert_eq!(runs[0].id, second_run.id.to_string());
        assert_eq!(runs[1].id, first_run.id.to_string());
        // Each run's total_findings reflects what that scan actually produced, not the
        // post-reconciliation live count (which would show 0 for the first run once its
        // one finding gets reassigned onto the second run).
        assert_eq!(runs[0].total_findings, 2);
        assert_eq!(runs[1].total_findings, 1);
    }

    #[test]
    fn list_scan_runs_respects_the_limit() {
        let mut store = Store::open_in_memory().unwrap();
        for _ in 0..3 {
            let mut scan = sample_scan();
            scan.id = Uuid::new_v4();
            scan.findings[0].scan_run_id = scan.id;
            store.persist_and_reconcile(&scan).unwrap();
        }
        assert_eq!(store.list_scan_runs(2).unwrap().len(), 2);
        assert_eq!(store.list_scan_runs(10).unwrap().len(), 3);
    }

    /// A DB created before `total_findings` existed must not crash `migrate()` on reopen —
    /// regression test for the defensive `ALTER TABLE` in `migrate()`. Simulates that by
    /// creating the table without the column, then reopening through the real `Store::open`
    /// path against the same file.
    #[test]
    fn migrate_tolerates_a_db_created_before_total_findings_existed() {
        let tmp = tempfile::tempdir().unwrap();
        let db_path = tmp.path().join("old.db");
        {
            let conn = Connection::open(&db_path).unwrap();
            conn.execute_batch(
                "CREATE TABLE scan_runs (
                    id TEXT PRIMARY KEY, started_at TEXT NOT NULL, finished_at TEXT,
                    host_fingerprint TEXT NOT NULL, rules_loaded INTEGER NOT NULL,
                    rules_failed INTEGER NOT NULL, collectors_failed INTEGER NOT NULL,
                    rule_load_errors TEXT NOT NULL, collector_errors TEXT NOT NULL,
                    privileged_skipped TEXT NOT NULL
                );",
            )
            .unwrap();
        }
        // Reopening through Store::open must succeed and the new column must be usable.
        let mut store = Store::open(&db_path).unwrap();
        store.persist_and_reconcile(&sample_scan()).unwrap();
        assert_eq!(store.list_scan_runs(10).unwrap()[0].total_findings, 1);
    }

    /// Every `Severity`/`FindingStatus` variant, round-tripped through real SQLite storage
    /// and back — the existing tests only ever exercise `Critical`/`Open`, so a typo in one
    /// of the other match arms of `parse_severity`/`severity_str`/`parse_status`/`status_str`
    /// (e.g. a stray "hgih") would silently coerce every other severity to `Info` and every
    /// other status to `Open` without any test catching it.
    #[test]
    fn every_severity_and_status_round_trips_through_storage() {
        let mut store = Store::open_in_memory().unwrap();
        let severities = [
            Severity::Info,
            Severity::Low,
            Severity::Medium,
            Severity::High,
            Severity::Critical,
        ];
        let statuses = [
            FindingStatus::Open,
            FindingStatus::Acknowledged,
            FindingStatus::Resolved,
        ];

        let mut scan = sample_scan();
        scan.findings.clear();
        for (i, (&severity, &status)) in severities.iter().zip(statuses.iter().cycle()).enumerate()
        {
            let now = Utc::now();
            scan.findings.push(Finding {
                id: Uuid::new_v4(),
                rule_id: format!("BLWK-TEST-{i:03}"),
                severity,
                title: "t".into(),
                explanation: "e".into(),
                fix_hint: "f".into(),
                context: Default::default(),
                first_seen: now,
                last_seen: now,
                status,
                scan_run_id: scan.id,
            });
        }
        store.persist(&scan).unwrap();

        let mut stmt = store
            .conn
            .prepare("SELECT id, scan_run_id, rule_id, severity, title, explanation, fix_hint, context, first_seen, last_seen, status FROM findings ORDER BY rule_id")
            .unwrap();
        let rows: Vec<Finding> = stmt
            .query_map([], row_to_finding)
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap();

        assert_eq!(rows.len(), severities.len());
        for (row, &expected_severity) in rows.iter().zip(severities.iter()) {
            assert_eq!(row.severity, expected_severity);
        }
        assert_eq!(rows[0].status, FindingStatus::Open);
        assert_eq!(rows[1].status, FindingStatus::Acknowledged);
        assert_eq!(rows[2].status, FindingStatus::Resolved);
    }

    /// A row with a corrupted `id`/`scan_run_id` (never written by Bulwark itself, but not
    /// a scenario this test should just assume can't happen — see AGENTS.md's "no silent
    /// failures" rule) must surface as a query error, not panic and not silently produce a
    /// nil/garbage UUID.
    #[test]
    fn a_row_with_a_malformed_uuid_is_a_query_error_not_a_panic() {
        let mut store = Store::open_in_memory().unwrap();
        let scan = sample_scan();
        let scan_run_id = scan.id.to_string();
        store.persist(&scan).unwrap();

        // findings.id has no FK constraint (only scan_run_id references scan_runs), so a
        // corrupted id alone is enough to exercise the parse-error branch without also
        // needing a real scan_runs row for it to point at.
        store
            .conn
            .execute(
                "INSERT INTO findings (id, scan_run_id, rule_id, severity, title, explanation, fix_hint, context, first_seen, last_seen, status)
                 VALUES ('not-a-uuid', ?1, 'BLWK-TEST-001', 'high', 't', 'e', 'f', '{}', ?2, ?2, 'open')",
                params![scan_run_id, Utc::now().to_rfc3339()],
            )
            .unwrap();

        assert!(store.open_findings().is_err());
    }

    /// Same as above but for the `scan_run_id` column specifically (a valid `id` with a
    /// malformed `scan_run_id`) — the two fields are parsed by separate `map_err` branches
    /// in `row_to_finding`, and struct-field evaluation order means a bad `id` alone never
    /// reaches the `scan_run_id` branch.
    #[test]
    fn a_row_with_a_malformed_scan_run_id_is_a_query_error_not_a_panic() {
        let store = Store::open_in_memory().unwrap();
        // A scan_runs row whose own id is the same malformed string, so the FK on
        // findings.scan_run_id is satisfied without needing a well-formed UUID anywhere.
        store
            .conn
            .execute(
                "INSERT INTO scan_runs (id, started_at, finished_at, host_fingerprint, rules_loaded, rules_failed, collectors_failed, rule_load_errors, collector_errors, privileged_skipped, total_findings)
                 VALUES ('not-a-uuid-either', ?1, ?1, 'h', 0, 0, 0, '[]', '[]', '[]', 0)",
                params![Utc::now().to_rfc3339()],
            )
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO findings (id, scan_run_id, rule_id, severity, title, explanation, fix_hint, context, first_seen, last_seen, status)
                 VALUES (?1, 'not-a-uuid-either', 'BLWK-TEST-001', 'high', 't', 'e', 'f', '{}', ?2, ?2, 'open')",
                params![Uuid::new_v4().to_string(), Utc::now().to_rfc3339()],
            )
            .unwrap();

        assert!(store.open_findings().is_err());
    }

    #[test]
    fn open_findings_does_not_duplicate_across_reconciled_runs() {
        let mut store = Store::open_in_memory().unwrap();
        store.persist_and_reconcile(&sample_scan()).unwrap();

        let mut second_run = sample_scan();
        second_run.id = Uuid::new_v4();
        second_run.findings[0].scan_run_id = second_run.id;
        store.persist_and_reconcile(&second_run).unwrap();

        assert_eq!(
            store.open_findings().unwrap().len(),
            1,
            "a finding seen across multiple monitoring ticks must still appear once, not once per tick"
        );
    }
}
